package io.kamax.mxisd.auth;

import com.google.gson.JsonObject;
import io.kamax.matrix.MatrixID;
import io.kamax.matrix.json.GsonUtil;
import io.kamax.mxisd.config.AccountConfig;
import io.kamax.mxisd.config.MatrixConfig;
import io.kamax.mxisd.config.PolicyConfig;
import io.kamax.mxisd.exception.BadRequestException;
import io.kamax.mxisd.exception.InvalidCredentialsException;
import io.kamax.mxisd.exception.NotFoundException;
import io.kamax.mxisd.matrix.HomeserverFederationResolver;
import io.kamax.mxisd.matrix.HomeserverVerifier;
import io.kamax.mxisd.storage.IStorage;
import io.kamax.mxisd.storage.ormlite.dao.AccountDao;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;

public class AccountManager {

    private static final Logger LOGGER = Logger.getLogger(AccountManager.class.getName());
    private final IStorage storage;
    private final HomeserverFederationResolver resolver;
    private final AccountConfig accountConfig;
    private final MatrixConfig matrixConfig;
    private final HomeserverVerifier homeserverVerifier; // new dependency

    public AccountManager(IStorage storage, HomeserverFederationResolver resolver, AccountConfig accountConfig, MatrixConfig matrixConfig, HomeserverVerifier homeserverVerifier) {
        this.storage = storage;
        this.resolver = resolver;
        this.accountConfig = accountConfig;
        this.matrixConfig = matrixConfig;
        this.homeserverVerifier = homeserverVerifier;
    }

    public String register(OpenIdToken openIdToken) {
        Objects.requireNonNull(openIdToken.getAccessToken(), "Missing required access_token");
        Objects.requireNonNull(openIdToken.getTokenType(), "Missing required token type");
        Objects.requireNonNull(openIdToken.getMatrixServerName(), "Missing required matrix domain");

        LOGGER.info("Registration from the server: " + openIdToken.getMatrixServerName());
        String userId = getUserId(openIdToken);
        LOGGER.info("UserId: " + userId);

        String token = UUID.randomUUID().toString();
        AccountDao account = new AccountDao(
                openIdToken.getAccessToken(), 
                openIdToken.getTokenType(),
                openIdToken.getMatrixServerName(), 
                openIdToken.getExpiresIn(),
                Instant.now().getEpochSecond(), 
                userId, 
                token
        );
        storage.insertToken(account);

        LOGGER.info("User " + userId + " registered");

        return token;
    }

    private String getUserId(OpenIdToken openIdToken) {
        String matrixServerName = openIdToken.getMatrixServerName();
        HomeserverFederationResolver.HomeserverTarget homeserverTarget = resolver.resolve(matrixServerName);
        String homeserverURL = homeserverTarget.getUrl().toString();
        LOGGER.info("Domain resolved: " + matrixServerName + " => " + homeserverURL);
        String requestUrl = homeserverURL + "/_matrix/federation/v1/openid/userinfo?access_token=" + openIdToken.getAccessToken();

        try {
            HttpClient client = HttpClient.newBuilder()
                    // Build a custom SSLContext that leverages HomeserverVerifier.
                    .sslContext(createCustomSSLContext())
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(requestUrl))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            String userId;
            if (response.statusCode() == HttpURLConnection.HTTP_OK) {
                String content = response.body();
                LOGGER.fine("Response: " + content);
                JsonObject body = GsonUtil.parseObj(content);
                userId = GsonUtil.getStringOrThrow(body, "sub");
            } else {
                LOGGER.severe("Wrong response status: " + response.statusCode());
                throw new InvalidCredentialsException();
            }
            checkMXID(userId);
            return userId;
        } catch (IOException | InterruptedException | NoSuchAlgorithmException | KeyManagementException | CertificateException | KeyStoreException e) {
            LOGGER.log(Level.SEVERE, "Unable to get user info.", e);
            throw new InvalidCredentialsException();
        }
    }

    private void checkMXID(String userId) {
        MatrixID mxid;
        try {
            mxid = MatrixID.asValid(userId);
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.SEVERE, "Wrong MXID: " + userId, e);
            throw new BadRequestException("Wrong MXID");
        }

        if (getAccountConfig().isAllowOnlyTrustDomains()) {
            LOGGER.info("Allow registration only for trust domain.");
            if (getMatrixConfig().getDomain().equals(mxid.getDomain())) {
                LOGGER.info("Allow user " + userId + " to registration");
            } else {
                LOGGER.severe("Deny user " + userId + " to registration");
                throw new InvalidCredentialsException();
            }
        } else {
            LOGGER.info("Allow registration from any server.");
        }
    }

    public String getUserId(String token) {
        return storage.findAccount(token).orElseThrow(NotFoundException::new).getUserId();
    }

    public AccountDao findAccount(String token) {
        AccountDao accountDao = storage.findAccount(token).orElse(null);

        if (accountDao != null) {
            LOGGER.info("Found account for user: " + accountDao.getUserId());
        } else {
            LOGGER.warning("Account not found.");
        }
        return accountDao;
    }

    public void logout(String token) {
        String userId = storage.findAccount(token).orElseThrow(InvalidCredentialsException::new).getUserId();
        LOGGER.info("Logout: " + userId);
        deleteAccount(token);
    }

    public void deleteAccount(String token) {
        storage.deleteAccepts(token);
        storage.deleteToken(token);
    }

    public void acceptTerm(String token, String url) {
        storage.acceptTerm(token, url);
    }

    public boolean isTermAccepted(String token, List<PolicyConfig.PolicyObject> policies) {
        return policies.isEmpty() || storage.isTermAccepted(token, policies);
    }

    public AccountConfig getAccountConfig() {
        return accountConfig;
    }

    public MatrixConfig getMatrixConfig() {
        return matrixConfig;
    }

    /**
     * Creates an SSLContext with a custom TrustManager that performs the default checks
     * and then applies additional hostname verification via HomeserverVerifier.
     */
    private SSLContext createCustomSSLContext() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, IOException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        TrustManager[] defaultTMs = getDefaultTrustManagers();
        TrustManager customTM = new X509TrustManager() {
            private final X509TrustManager defaultTM = (X509TrustManager) defaultTMs[0];

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                defaultTM.checkClientTrusted(chain, authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                defaultTM.checkServerTrusted(chain, authType);
                String hostname = "extracted_hostname"; // adjust logic to extract hostname

                // Create a dummy SSLSession for hostname verification.
                javax.net.ssl.SSLSession dummySession = new javax.net.ssl.SSLSession() {
                    @Override public byte[] getId() { return new byte[0]; }
                    @Override public SSLSessionContext getSessionContext() { return null; }
                    @Override public long getCreationTime() { return 0; }
                    @Override public long getLastAccessedTime() { return 0; }
                    @Override public void invalidate() {}
                    @Override public boolean isValid() { return true; }
                    @Override public void putValue(String name, Object value) {}
                    @Override public Object getValue(String name) { return null; }
                    @Override public void removeValue(String name) {}
                    @Override public String[] getValueNames() { return new String[0]; }
                    @Override public Certificate[] getPeerCertificates() { return chain; }
                    @Override public Certificate[] getLocalCertificates() { return null; }
                    @Override public Principal getPeerPrincipal() { return null; }
                    @Override public Principal getLocalPrincipal() { return null; }
                    @Override public String getCipherSuite() { return ""; }
                    @Override public String getProtocol() { return ""; }
                    @Override public String getPeerHost() { return hostname; }
                    @Override public int getPeerPort() { return 0; }
                    @Override public int getPacketBufferSize() { return 0; }
                    @Override public int getApplicationBufferSize() { return 0; }
                };

                // Use the injected HomeserverVerifier instance.
                if (!homeserverVerifier.verify(hostname, dummySession)) {
                    throw new CertificateException("Custom hostname verification failed for " + hostname);
                }
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return defaultTM.getAcceptedIssuers();
            }
        };

        sslContext.init(null, new TrustManager[]{customTM}, new SecureRandom());
        return sslContext;
    }

    private TrustManager[] getDefaultTrustManagers() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        return tmf.getTrustManagers();
    }
}