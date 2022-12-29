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
package org.springframework.security.oauth2.server.authorization.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2PushedAuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2RequestUri;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2PushedAuthorizationRequestHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2TokenIntrospectionHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.Writer;

public class OAuth2PushedAuthorizationRequestEndpointFilter extends OncePerRequestFilter {
	private static final String DEFAULT_PUSHED_AUTHORIZATION_REQUEST_ENDPOINT_URI = "/oauth2/par";
	private final RequestMatcher pushedAuthorizationRequestEndpointMatcher;
	private final AuthenticationManager authenticationManager;
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
	private final HttpMessageConverter<OAuth2PushedAuthorizationRequest> pushedAuthorizationRequestHttpResponseConverter =
			new OAuth2PushedAuthorizationRequestHttpMessageConverter();
	private boolean requirePushedAuthorizationRequests;
	private AuthenticationConverter authenticationConverter;
	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendPushedAuthorizationRequestResponse;
	private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestEndpointFilter} using the default parameters.
	 *
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2PushedAuthorizationRequestEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_PUSHED_AUTHORIZATION_REQUEST_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestEndpointFilter} using the provided parameters.
	 *
	 * @param pushedAuthorizationRequestEndpointUri the endpoint {@code URI} for pushed authorization request requests
	 */
	public OAuth2PushedAuthorizationRequestEndpointFilter(AuthenticationManager authenticationManager, String pushedAuthorizationRequestEndpointUri) {
		Assert.hasText(pushedAuthorizationRequestEndpointUri, "pushedAuthorizationRequestEndpointUri cannot be empty");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
		this.pushedAuthorizationRequestEndpointMatcher = createDefaultRequestMatcher(pushedAuthorizationRequestEndpointUri);
	}

	private static RequestMatcher createDefaultRequestMatcher(String authorizationEndpointUri) {
		RequestMatcher pushedAuthorizationRequestRequestGetMatcher = new AntPathRequestMatcher(
				authorizationEndpointUri, HttpMethod.GET.name());
		RequestMatcher pushedAuthorizationRequestRequestPostMatcher = new AntPathRequestMatcher(
				authorizationEndpointUri, HttpMethod.POST.name());
		return new OrRequestMatcher(pushedAuthorizationRequestRequestGetMatcher, pushedAuthorizationRequestRequestPostMatcher);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		if (!this.pushedAuthorizationRequestEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		try {
			Authentication authentication = this.authenticationConverter.convert(request);
			if (authentication instanceof AbstractAuthenticationToken) {
				((AbstractAuthenticationToken) authentication)
						.setDetails(this.authenticationDetailsSource.buildDetails(request));
			}
			Authentication authenticationResult = this.authenticationManager.authenticate(authentication);
			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authenticationResult);
		} catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Pushed Authorization Request request failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}

	public void setRequirePushedAuthorizationRequests(boolean requirePushedAuthorizationRequests) {
		this.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests;
	}

	/**
	 * Sets the {@link AuthenticationDetailsSource} used for building an authentication details instance from {@link HttpServletRequest}.
	 *
	 * @param authenticationDetailsSource the {@link AuthenticationDetailsSource} used for building an authentication details instance from {@link HttpServletRequest}
	 * @since 0.3.1
	 */
	public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	private void sendPushedAuthorizationRequestResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {
		OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthentication =
				(OAuth2PushedAuthorizationRequestAuthenticationToken) authentication;
		OAuth2PushedAuthorizationRequest pushedAuthorizationRequest = pushedAuthorizationRequestAuthentication.getRequestClaims();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.pushedAuthorizationRequestHttpResponseConverter.write(pushedAuthorizationRequest, null, httpResponse);
	}

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException {
		OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2AuthorizationCodeRequestAuthenticationToken} or {@link OAuth2AuthorizationConsentAuthenticationToken}
	 * used for authenticating the request.
	 *
	 * @param authenticationConverter the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 * and returning the {@link OAuth2AuthorizationResponse Authorization Response}.
	 *
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}
}
