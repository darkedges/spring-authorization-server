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
 * An {@link Authentication} implementation used for OAuth 2.0 Pushed Authenitcation Request.
 *
 * @author Nicholas Irving
 * @see AbstractAuthenticationToken
 * @see OAuth2PushedAuthorizationRequest
 * @see OAuth2PushedAuthorizationRequestProvider
 * @since 1.0.0
 */
public class OAuth2PushedAuthorzationRequestAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
	private final String token;
	private final Authentication clientPrincipal;
	private final Map<String, Object> additionalParameters;
	private final OAuth2PushedAuthorizationRequest pushedAuthorizationRequestClaims;

	public OAuth2PushedAuthorzationRequestAuthenticationToken(String token, Authentication clientPrincipal, Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.hasText(token, "token cannot be empty");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		this.token = token;
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
	 *
	 * @return the token
	 */
	public String getToken() {
		return this.token;
	}


	/**
	 * Returns the additional parameters.
	 *
	 * @return the additional parameters
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * Returns the token claims.
	 *
	 * @return the {@link OAuth2TokenIntrospection}
	 */
	public OAuth2PushedAuthorizationRequest getPushedAuthorizationRequestClaims() {
		return this.pushedAuthorizationRequestClaims;
	}
}
