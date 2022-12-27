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
package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2PushedAuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * An {@link Authentication} implementation used for OAuth 2.0 Pushed Authenitcation
 * Request.
 *
 * @author Nicholas Irving
 * @see AbstractAuthenticationToken
 * @see OAuth2PushedAuthorizationRequest
 * @since 1.0.0
 */
public class OAuth2PushedAuthorizationRequestAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;

	private final String request;

	private final Authentication clientPrincipal;

	private final Map<String, Object> additionalParameters;

	private final OAuth2PushedAuthorizationRequest pushedAuthorizationRequestClaims;

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionAuthenticationToken} using the
	 * provided parameters.
	 * @param request the request
	 * @param clientPrincipal the authenticated client principal
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2PushedAuthorizationRequestAuthenticationToken(String request, Authentication clientPrincipal,
			Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.hasText(request, "request cannot be empty");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		this.request = request;
		this.clientPrincipal = clientPrincipal;
		this.additionalParameters = Collections.unmodifiableMap(
				additionalParameters != null ? new HashMap<>(additionalParameters) : Collections.emptyMap());
		this.pushedAuthorizationRequestClaims = OAuth2PushedAuthorizationRequest.builder().build();
	}

	@Override
	public Object getPrincipal() {
		return this.clientPrincipal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the token.
	 * @return the token
	 */
	public String getRequest() {
		return this.request;
	}

	/**
	 * Returns the additional parameters.
	 * @return the additional parameters
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * Returns the token claims.
	 * @return the {@link OAuth2TokenIntrospection}
	 */
	public OAuth2PushedAuthorizationRequest getPushedAuthorizationRequestClaims() {
		return this.pushedAuthorizationRequestClaims;
	}

}
