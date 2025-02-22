/*
 * mxisd - Matrix Identity Server Daemon
 * Copyright (C) 2017 Kamax Sarl
 *
 * https://www.kamax.io/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package io.kamax.mxisd.auth;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;
import io.kamax.matrix.MatrixID;
import io.kamax.matrix.ThreePid;
import io.kamax.matrix._MatrixID;
import io.kamax.matrix._ThreePid;
import io.kamax.matrix.json.GsonUtil;
import io.kamax.mxisd.UserIdType;
import io.kamax.mxisd.auth.provider.AuthenticatorProvider;
import io.kamax.mxisd.auth.provider.BackendAuthResult;
import io.kamax.mxisd.config.AuthenticationConfig;
import io.kamax.mxisd.config.MatrixConfig;
import io.kamax.mxisd.config.MxisdConfig;
import io.kamax.mxisd.dns.ClientDnsOverwrite;
import io.kamax.mxisd.exception.RemoteLoginException;
import io.kamax.mxisd.invitation.InvitationManager;
import io.kamax.mxisd.lookup.ThreePidMapping;
import io.kamax.mxisd.lookup.strategy.LookupStrategy;
//import io.kamax.mxisd.util.RestClientUtils;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.net.URISyntaxException;

public class AuthManager {

    private static final Logger log = Logger.getLogger(AuthManager.class.getName());

    private static final String TypeKey = "type";
    private static final String UserKey = "user";
    private static final String IdentifierKey = "identifier";
    private static final String ThreepidMediumKey = "medium";
    private static final String ThreepidAddressKey = "address";
    private static final String UserIdTypeValue = "m.id.user";
    private static final String ThreepidTypeValue = "m.id.thirdparty";

    private final Gson gson = GsonUtil.get();

    private List<AuthenticatorProvider> providers;
    private MatrixConfig mxCfg;
    private AuthenticationConfig cfg;
    private InvitationManager invMgr;
    private ClientDnsOverwrite dns;
    private LookupStrategy strategy;
    // Swapped out CloseableHttpClient with Java's native HttpClient.
    private HttpClient client;

    public AuthManager(
            MxisdConfig cfg,
            List<? extends AuthenticatorProvider> providers,
            LookupStrategy strategy,
            InvitationManager invMgr,
            ClientDnsOverwrite dns,
            HttpClient client
    ) {
        this.cfg = cfg.getAuth();
        this.mxCfg = cfg.getMatrix();
        this.providers = new ArrayList<>(providers);
        this.strategy = strategy;
        this.invMgr = invMgr;
        this.dns = dns;
        this.client = client;
    }

    // Uses the native URI transformation (assuming dns.transform now returns a URIBuilder)
    public String resolveProxyUrl(URI target) {
        try {
            var transformed = dns.transform(target).build(); 
            String urlToLogin = transformed.toString();
            log.log(Level.INFO, "Proxy resolution: {0} to {1}", new Object[] { target, urlToLogin });
            return urlToLogin;
        } catch (URISyntaxException e) {
            throw new RuntimeException("Failed to resolve proxy URL", e);
        }
    }

    public UserAuthResult authenticate(String id, String password) {
        _MatrixID mxid = MatrixID.asAcceptable(id);
        for (AuthenticatorProvider provider : providers) {
            if (!provider.isEnabled()) {
                continue;
            }

            log.log(Level.INFO, "Attempting authentication with store {0}", provider.getClass().getSimpleName());

            BackendAuthResult result = provider.authenticate(mxid, password);
            if (result.isSuccess()) {
                String mxId;
                if (UserIdType.Localpart.is(result.getId().getType())) {
                    mxId = MatrixID.from(result.getId().getValue(), mxCfg.getDomain()).acceptable().getId();
                } else if (UserIdType.MatrixID.is(result.getId().getType())) {
                    mxId = MatrixID.asAcceptable(result.getId().getValue()).getId();
                } else {
                    log.log(Level.WARNING, "Unsupported User ID type {0} for backend {1}", new Object[]{result.getId().getType(), provider.getClass().getSimpleName()});
                    continue;
                }

                UserAuthResult authResult = new UserAuthResult().success(result.getProfile().getDisplayName());
                for (_ThreePid pid : result.getProfile().getThreePids()) {
                    authResult.withThreePid(pid.getMedium(), pid.getAddress());
                }
                log.log(Level.INFO, "{0} was authenticated by {1}, publishing 3PID mappings, if any", new Object[] { id, provider.getClass().getSimpleName() });
                for (ThreePid pid : authResult.getThreePids()) {
                    log.log(Level.INFO, "Processing {0} for {1}", new Object[] { pid, id });
                    invMgr.publishMappingIfInvited(new ThreePidMapping(pid, mxId));
                }

                try {
                    MatrixID.asAcceptable(mxId);
                } catch (IllegalArgumentException e) {
                    log.log(Level.WARNING, "The returned User ID {0} is not a valid Matrix ID. Login might fail at the Homeserver level", mxId);
                }

                invMgr.lookupMappingsForInvites();

                return authResult;
            }
        }

        return new UserAuthResult().failure();
    }

    public String proxyLogin(URI target, String body) {
        JsonObject reqJsonObject = GsonUtil.parseObj(body);

        // Process rewriting of login info for User ID types and third party identifiers
        GsonUtil.findObj(reqJsonObject, IdentifierKey).ifPresent(obj -> {
            GsonUtil.findString(obj, TypeKey).ifPresent(type -> {
                if (UserIdTypeValue.equals(type)) {
                    log.info("Login request is User ID type");
                    if (cfg.getRewrite().getUser().getRules().isEmpty()) {
                        log.info("No User ID rewrite rules to apply");
                    } else {
                        log.info("User ID rewrite rules: checking for a match");
                        String userId = GsonUtil.getStringOrThrow(obj, UserKey);
                        for (AuthenticationConfig.Rule m : cfg.getRewrite().getUser().getRules()) {
                            if (m.getPattern().matcher(userId).matches()) {
                                log.info(String.format("Found matching pattern, resolving to 3PID with medium %s", m.getMedium()));
                                reqJsonObject.remove(UserKey);
                                obj.addProperty(TypeKey, ThreepidTypeValue);
                                obj.addProperty(ThreepidMediumKey, m.getMedium());
                                obj.addProperty(ThreepidAddressKey, userId);
                                log.info("Rewrite to 3PID done");
                            }
                        }
                        log.info("User ID rewrite rules: done checking rules");
                    }
                }
            });
        });

        GsonUtil.findObj(reqJsonObject, IdentifierKey).ifPresent(obj -> {
            GsonUtil.findString(obj, TypeKey).ifPresent(type -> {
                if (ThreepidTypeValue.equals(type)) {
                    reqJsonObject.remove(ThreepidMediumKey);
                    reqJsonObject.remove(ThreepidAddressKey);
                    GsonUtil.findPrimitive(obj, ThreepidMediumKey).ifPresent(medium -> {
                        GsonUtil.findPrimitive(obj, ThreepidAddressKey).ifPresent(address -> {
                            log.log(Level.INFO, "Login request with medium '{0}' and address '{1}'", new Object[]{medium.getAsString(), address.getAsString()});
                            strategy.findLocal(medium.getAsString(), address.getAsString()).ifPresent(lookupDataOpt -> {
                                obj.remove(ThreepidMediumKey);
                                obj.remove(ThreepidAddressKey);
                                obj.addProperty(TypeKey, UserIdTypeValue);
                                obj.addProperty(UserKey, lookupDataOpt.getMxid().getLocalPart());
                            });
                        });
                    });
                }

                if ("m.id.phone".equals(type)) {
                    reqJsonObject.remove(ThreepidMediumKey);
                    reqJsonObject.remove(ThreepidAddressKey);
                    GsonUtil.findPrimitive(obj, "number").ifPresent(number -> {
                        GsonUtil.findPrimitive(obj, "country").ifPresent(country -> {
                            log.log(Level.INFO, "Login request with phone '{0}'-'{1}'", new Object[]{country.getAsString(), number.getAsString()});
                            try {
                                PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();
                                Phonenumber.PhoneNumber phoneNumber = phoneUtil.parse(number.getAsString(), country.getAsString());
                                String msisdn = phoneUtil.format(phoneNumber, PhoneNumberUtil.PhoneNumberFormat.E164).replace("+", "");
                                String medium = "msisdn";
                                strategy.findLocal(medium, msisdn).ifPresent(lookupDataOpt -> {
                                    obj.remove("country");
                                    obj.remove("number");
                                    obj.addProperty(TypeKey, UserIdTypeValue);
                                    obj.addProperty(UserKey, lookupDataOpt.getMxid().getLocalPart());
                                });
                            } catch (NumberParseException e) {
                                log.log(Level.SEVERE, "Not a valid phone number");
                                throw new RuntimeException(e);
                            }
                        });
                    });
                }
            });
        });

        // Build a native HttpRequest using the resolved proxy URL and the JSON body
        URI proxyUri = URI.create(resolveProxyUrl(target));
        HttpRequest request = HttpRequest.newBuilder(proxyUri)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(reqJsonObject)))
                .build();

        try {
            HttpResponse<InputStream> httpResponse = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            int status = httpResponse.statusCode();
            log.log(Level.INFO, "http status = {0}", status);
            if (status != 200) {
                String errcode = String.valueOf(status);
                // Read the error response using InputStream.readAllBytes()
                String error = new String(httpResponse.body().readAllBytes(), StandardCharsets.UTF_8);
                try {
                    JsonObject bodyJson = JsonParser.parseString(error).getAsJsonObject();
                    if (bodyJson.has("errcode")) {
                        errcode = bodyJson.get("errcode").getAsString();
                    }
                    if (bodyJson.has("error")) {
                        error = bodyJson.get("error").getAsString();
                    }
                    throw new RemoteLoginException(status, errcode, error, bodyJson);
                } catch (JsonSyntaxException e) {
                    log.log(Level.WARNING, "Response body is not JSON");
                }
                throw new RemoteLoginException(status, errcode, error);
            }

            InputStream entityStream = httpResponse.body();
            if (entityStream == null) {
                log.log(Level.WARNING, "Expected HS to return data but got nothing");
                return "";
            } else {
                return new String(entityStream.readAllBytes(), StandardCharsets.UTF_8);
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}