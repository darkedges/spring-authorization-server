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
package org.springframework.security.oauth2.server.authorization.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PushedAuthorizationRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2PushedAuthorizationRequestEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Attempts to extract an Introspection Request from {@link HttpServletRequest}
 * and then converts it to an {@link OAuth2PushedAuthorizationRequestAuthenticationToken} used for authenticating the request.
 *
 * @author Nicholas Irving
 * @see AuthenticationConverter
 * @see OAuth2PushedAuthorizationRequestAuthenticationToken
 * @see OAuth2PushedAuthorizationRequestEndpointFilter
 * @since 1.0.0
 */
public final class OAuth2PushedAuthorizationRequestAuthenticationConverter implements AuthenticationConverter {

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Pushed Authorization Request Parameter: " + parameterName,
				"https://www.rfc-editor.org/rfc/rfc9126#name-request");
		throw new OAuth2AuthenticationException(error);
	}

	@Override
	public Authentication convert(HttpServletRequest httpServletRequest) {
		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(httpServletRequest);

		// request (REQUIRED)
		String request = parameters.getFirst(com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST);
		if (!StringUtils.hasText(request) ||
				parameters.get(com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST);
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST)) {
				additionalParameters.put(key, value.get(0));
			}
		});

		return new OAuth2PushedAuthorizationRequestAuthenticationToken(
				request, clientPrincipal, additionalParameters);
	}

}
