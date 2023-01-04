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
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2RequestUri;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

/**
 * Attempts to extract an Authorization Request from {@link HttpServletRequest}
 * for the OAuth 2.0 Authorization Code Grant and then converts it to
 * an {@link OAuth2AuthorizationCodeRequestAuthenticationToken} used for authenticating the request.
 *
 * @author Joe Grandja
 * @see AuthenticationConverter
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationEndpointFilter
 * @since 0.1.2
 */
public final class OAuth2AuthorizationCodeRequestAuthenticationConverter implements AuthenticationConverter {
	private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
	private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";
	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
			"anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	private static final RequestMatcher OIDC_REQUEST_MATCHER = createOidcRequestMatcher();

	private static final OAuth2TokenType REQUEST_TOKEN_TYPE =
			new OAuth2TokenType(com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST);
	private final OAuth2AuthorizationService authorizationService;

	public OAuth2AuthorizationCodeRequestAuthenticationConverter(OAuth2AuthorizationService authorizationService) {
		this.authorizationService = authorizationService;
	}

	private static RequestMatcher createOidcRequestMatcher() {
		RequestMatcher postMethodMatcher = request -> "POST".equals(request.getMethod());
		RequestMatcher responseTypeParameterMatcher = request ->
				request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;
		RequestMatcher openidScopeMatcher = request -> {
			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
			return StringUtils.hasText(scope) && scope.contains(OidcScopes.OPENID);
		};
		return new AndRequestMatcher(
				postMethodMatcher, responseTypeParameterMatcher, openidScopeMatcher);
	}

	private static void throwError(String errorCode, String parameterName) {
		throwError(errorCode, parameterName, DEFAULT_ERROR_URI);
	}

	private static void throwError(String errorCode, String parameterName, String errorUri) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
		throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		if (!"GET".equals(request.getMethod()) && !OIDC_REQUEST_MATCHER.matches(request)) {
			return null;
		}

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);
		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (principal == null) {
			principal = ANONYMOUS_AUTHENTICATION;
		}

		// request_uri (OPTIONAL)
		String requestUri = request.getParameter(com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST_URI);
		if (StringUtils.hasText(requestUri) &&
				parameters.get(com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST_URI).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST_URI);
		}
		if (StringUtils.hasText(requestUri) && !requestUri.startsWith(com.darkedges.org.springframework.security.oauth2.core.RedirectUriMethod.URN)) {
			throwError(com.darkedges.org.springframework.security.oauth2.core.OAuth2ErrorCodes.UNSUPPORTED_REQUEST_URI, com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST_URI);
		}
		// Need to clean this up
		// need to work out a better way to restore the Token with the correct values.
		// this is a hack till a better solution can be found
		MultiValueMap<String, String> pushedAuthenticationRequestParameters = new LinkedMultiValueMap<>();
		if (StringUtils.hasText(requestUri) && principal != ANONYMOUS_AUTHENTICATION) {
			OAuth2Authorization token = this.authorizationService.findByToken(requestUri, REQUEST_TOKEN_TYPE);
			if (token != null) {
				OAuth2AuthorizationRequest authorizationRequest = token.getAttribute(OAuth2AuthorizationRequest.class.getName());
				if (authorizationRequest != null) {
					OAuth2Authorization.Token<OAuth2RequestUri> requestUri2 = token.getToken(OAuth2RequestUri.class);
					if (!requestUri2.isInvalidated()) {
						authorizationRequest.getAdditionalParameters().forEach((key, value) -> pushedAuthenticationRequestParameters.put(key, Collections.singletonList(value.toString())));
						// Invalidate the request_uri as it can only be used once
						token = OAuth2AuthenticationProviderUtils.invalidate(token, requestUri2.getToken());
						this.authorizationService.save(token);
					} else {
						throwError(OAuth2ErrorCodes.INVALID_REQUEST, com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST);
					}
				} else {
					throwError(OAuth2ErrorCodes.INVALID_REQUEST, com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST);
				}
			} else {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST);
			}
		}
		for (MultiValueMap.Entry<String, List<String>> entry : pushedAuthenticationRequestParameters.entrySet()) {
			parameters.merge(entry.getKey(), entry.getValue(), (v1, v2) -> v1);
		}

		// response_type (REQUIRED)
		String responseType = request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE);
		if (!StringUtils.hasText(responseType) ||
				parameters.get(OAuth2ParameterNames.RESPONSE_TYPE).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESPONSE_TYPE);
		} else if (!responseType.equals(OAuth2AuthorizationResponseType.CODE.getValue()) && !responseType.equals(com.darkedges.org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType.CODE_ID_TOKEN.getValue())) {
			throwError(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, OAuth2ParameterNames.RESPONSE_TYPE);
		}

		String authorizationUri = request.getRequestURL().toString();

		// client_id (REQUIRED)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId) ||
				parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
		}

		// redirect_uri (OPTIONAL)
		String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
		if (StringUtils.hasText(redirectUri) &&
				parameters.get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI);
		}

		// scope (OPTIONAL)
		Set<String> scopes = null;
		String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
		if (StringUtils.hasText(scope) &&
				parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE);
		}
		if (StringUtils.hasText(scope)) {
			scopes = new HashSet<>(
					Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}

		// state (RECOMMENDED)
		String state = parameters.getFirst(OAuth2ParameterNames.STATE);
		if (StringUtils.hasText(state) &&
				parameters.get(OAuth2ParameterNames.STATE).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
		}

		// code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
		String codeChallenge = parameters.getFirst(PkceParameterNames.CODE_CHALLENGE);
		if (StringUtils.hasText(codeChallenge) &&
				parameters.get(PkceParameterNames.CODE_CHALLENGE).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI);
		}

		// code_challenge_method (OPTIONAL for public clients) - RFC 7636 (PKCE)
		String codeChallengeMethod = parameters.getFirst(PkceParameterNames.CODE_CHALLENGE_METHOD);
		if (StringUtils.hasText(codeChallengeMethod) &&
				parameters.get(PkceParameterNames.CODE_CHALLENGE_METHOD).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI);
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.RESPONSE_TYPE) &&
					!key.equals(OAuth2ParameterNames.CLIENT_ID) &&
					!key.equals(OAuth2ParameterNames.REDIRECT_URI) &&
					!key.equals(OAuth2ParameterNames.SCOPE) &&
					!key.equals(OAuth2ParameterNames.STATE)) {
				additionalParameters.put(key, value.get(0));
			}
		});

		return new OAuth2AuthorizationCodeRequestAuthenticationToken(authorizationUri, clientId, principal,
				redirectUri, state, scopes, additionalParameters);
	}

}
