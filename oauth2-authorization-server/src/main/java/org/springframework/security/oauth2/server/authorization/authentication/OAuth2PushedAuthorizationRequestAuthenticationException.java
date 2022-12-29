/*
 * Copyright 2020-2021 the original author or authors.
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

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * This exception is thrown by {@link OAuth2PushedAuthorizationRequestAuthenticationProvider}
 * when an attempt to authenticate the OAuth 2.0 Authorization Request (or Consent) fails.
 *
 * @author Nicholas Irving
 * @see OAuth2PushedAuthorizationRequestAuthenticationToken
 * @see OAuth2PushedAuthorizationRequestAuthenticationProvider
 * @since 1.0.0
 */
public class OAuth2PushedAuthorizationRequestAuthenticationException extends OAuth2AuthenticationException {
	private final OAuth2PushedAuthorizationRequestAuthenticationToken PushedAuthorizationRequestAuthentication;

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestAuthenticationException} using the provided parameters.
	 *
	 * @param error                                    the {@link OAuth2Error OAuth 2.0 Error}
	 * @param PushedAuthorizationRequestAuthentication the {@link Authentication} instance of the OAuth 2.0 Authorization Request (or Consent)
	 */
	public OAuth2PushedAuthorizationRequestAuthenticationException(OAuth2Error error,
			@Nullable OAuth2PushedAuthorizationRequestAuthenticationToken PushedAuthorizationRequestAuthentication) {
		super(error);
		this.PushedAuthorizationRequestAuthentication = PushedAuthorizationRequestAuthentication;
	}

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestAuthenticationException} using the provided parameters.
	 *
	 * @param error                                    the {@link OAuth2Error OAuth 2.0 Error}
	 * @param cause                                    the root cause
	 * @param PushedAuthorizationRequestAuthentication the {@link Authentication} instance of the OAuth 2.0 Authorization Request (or Consent)
	 */
	public OAuth2PushedAuthorizationRequestAuthenticationException(OAuth2Error error, Throwable cause,
			@Nullable OAuth2PushedAuthorizationRequestAuthenticationToken PushedAuthorizationRequestAuthentication) {
		super(error, cause);
		this.PushedAuthorizationRequestAuthentication = PushedAuthorizationRequestAuthentication;
	}

	/**
	 * Returns the {@link Authentication} instance of the OAuth 2.0 Authorization Request (or Consent), or {@code null} if not available.
	 *
	 * @return the {@link OAuth2PushedAuthorizationRequestAuthenticationToken}
	 */
	@Nullable
	public OAuth2PushedAuthorizationRequestAuthenticationToken getPushedAuthorizationRequestAuthentication() {
		return this.PushedAuthorizationRequestAuthentication;
	}
}
