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

package io.kamax.mxisd.exception;


import org.apache.hc.core5.http.HttpStatus;

public class NotAllowedException extends HttpMatrixException {

    public static final String ErrCode = "M_FORBIDDEN";

    public NotAllowedException(int code, String s) {
        super(code, ErrCode, s);
    }

    public NotAllowedException(String s) {
        super(HttpStatus.SC_FORBIDDEN, ErrCode, s);
    }

}
