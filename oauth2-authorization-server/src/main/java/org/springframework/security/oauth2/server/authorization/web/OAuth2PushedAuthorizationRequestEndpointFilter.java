package org.springframework.security.oauth2.server.authorization.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.web.util.matcher.*;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.Writer;

public class OAuth2PushedAuthorizationRequestEndpointFilter extends OncePerRequestFilter {
	private static final String DEFAULT_PUSHED_AUTHORIZATION_REQUEST_ENDPOINT_URI = "/oauth2/par";
	private final RequestMatcher pushedAuthorizationRequestEndpointMatcher;
	private boolean requirePushedAuthorizationRequests;

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestEndpointFilter} using the default parameters.
	 *
		 */
	public OAuth2PushedAuthorizationRequestEndpointFilter() {
		this(DEFAULT_PUSHED_AUTHORIZATION_REQUEST_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestEndpointFilter} using the provided parameters.
	 *
	 * @param pushedAuthorizationRequestEndpointUri the endpoint {@code URI} for pushed authorization request requests
	 */
	public OAuth2PushedAuthorizationRequestEndpointFilter(String pushedAuthorizationRequestEndpointUri) {
		Assert.hasText(pushedAuthorizationRequestEndpointUri, "pushedAuthorizationRequestEndpointUri cannot be empty");
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
		System.out.println("doFilterInternal");
		if (!this.pushedAuthorizationRequestEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		try (Writer writer = response.getWriter()) {
			writer.write("{}");	// toString() excludes private keys
		}
	}

	public void setRequirePushedAuthorizationRequests(boolean requirePushedAuthorizationRequests) {
		this.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests;
	}
}
