package org.springframework.security.oauth2.server.authorization;

import com.darkedges.org.springframework.security.oauth2.core.OAuth2PushedAuthorizationRequestClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A representation of the claims returned in an OAuth 2.0 Pushed Authorization Request Response.
 *
 * @author Nicholas Irving
 * @since 1.0.0
 * @see OAuth2PushedAuthorizationRequestClaimAccessor
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.2">Section 2.2 Introspection Response</a>
 */
public final class OAuth2PushedAuthorizationRequest implements OAuth2PushedAuthorizationRequestClaimAccessor, Serializable {
	private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
	private final Map<String, Object> claims;

	private OAuth2PushedAuthorizationRequest(Map<String, Object> claims) {
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	/**
	 * Returns the claims in the Token Introspection Response.
	 *
	 * @return a {@code Map} of the claims
	 */
	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	/**
	 * Constructs a new {@link OAuth2TokenIntrospection.Builder} initialized with the {@link #isActive() active} claim to {@code false}.
	 *
	 * @return the {@link OAuth2TokenIntrospection.Builder}
	 */
	public static OAuth2PushedAuthorizationRequest.Builder builder() {
		return builder(false);
	}

	/**
	 * Constructs a new {@link OAuth2TokenIntrospection.Builder} initialized with the provided {@link #isActive() active} claim.
	 *
	 * @param active {@code true} if the token is currently active, {@code false} otherwise
	 * @return the {@link OAuth2TokenIntrospection.Builder}
	 */
	public static OAuth2PushedAuthorizationRequest.Builder builder(boolean active) {
		return new OAuth2PushedAuthorizationRequest.Builder(active);
	}

	/**
	 * A builder for {@link OAuth2PushedAuthorizationRequest}.
	 */
	public static class Builder {
		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder(boolean active) {
			active(active);
		}

		/**
		 * Sets the indicator of whether or not the presented token is currently active, REQUIRED.
		 *
		 * @param active {@code true} if the token is currently active, {@code false} otherwise
		 * @return the {@link OAuth2PushedAuthorizationRequest.Builder} for further configuration
		 */
		public OAuth2PushedAuthorizationRequest.Builder active(boolean active) {
			return claim(OAuth2TokenIntrospectionClaimNames.ACTIVE, active);
		}
		/**
		 * Sets the claim.
		 *
		 * @param name the claim name
		 * @param value the claim value
		 * @return the {@link OAuth2PushedAuthorizationRequest.Builder} for further configuration
		 */
		public OAuth2PushedAuthorizationRequest.Builder claim(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.put(name, value);
			return this;
		}

		/**
		 * Validate the claims and build the {@link OAuth2TokenIntrospection}.
		 * <p>
		 * The following claims are REQUIRED: {@code active}
		 *
		 * @return the {@link OAuth2TokenIntrospection}
		 */
		public OAuth2PushedAuthorizationRequest build() {
			validate();
			return new OAuth2PushedAuthorizationRequest(this.claims);
		}

		private void validate() {
			Assert.notNull(this.claims.get(OAuth2TokenIntrospectionClaimNames.ACTIVE), "active cannot be null");
		}
	}
}
