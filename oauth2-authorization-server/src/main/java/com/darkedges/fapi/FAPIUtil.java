/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.darkedges.fapi;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;

/**
 * Internal class to help with FAPI Enablement
 *
 * @author Nicholas Irving
 * @since 1.0.0
 */
public class FAPIUtil {
	private static final Log logger = LogFactory.getLog(FAPIUtil.class);
	private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";
	static AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();

	private FAPIUtil() {
	}

	/**
	 * Returns true if FAPI Processing is enabled
	 *
	 * @return true if FAPI Processing is enabled
	 */
	public static boolean isEnabled() {
		return authorizationServerContext.getAuthorizationServerSettings().isFAPIEnabled();
	}

	/**
	 * Return the {@code client_id} - the client identifier of the JWT.
	 * 
	 * @param jwtAssertion
	 * @return {@code client_id} - the client identifier
	 */
	public static String getClientId(String jwtAssertion) {
		try {
			JWT jwt = JWTParser.parse(jwtAssertion);
			return jwt.getJWTClaimsSet().getIssuer();
		} catch (Exception ex) {
			logger.trace("Failed to parse token", ex);
			throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
	}
}
