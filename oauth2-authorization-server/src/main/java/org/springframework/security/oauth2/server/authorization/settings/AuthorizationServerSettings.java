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
package org.springframework.security.oauth2.server.authorization.settings;

import org.springframework.security.oauth2.server.authorization.OAuth2PushedAuthorizationRequest;
import org.springframework.util.Assert;

import java.util.Map;

/**
 * A facility for authorization server configuration settings.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 * @see AbstractSettings
 * @see ConfigurationSettingNames.AuthorizationServer
 * @since 0.1.0
 */
public final class AuthorizationServerSettings extends AbstractSettings {

	private AuthorizationServerSettings(Map<String, Object> settings) {
		super(settings);
	}

	/**
	 * Constructs a new {@link Builder} with the default settings.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder()
				.authorizationEndpoint("/oauth2/authorize")
				.tokenEndpoint("/oauth2/token")
				.jwkSetEndpoint("/oauth2/jwks")
				.tokenRevocationEndpoint("/oauth2/revoke")
				.tokenIntrospectionEndpoint("/oauth2/introspect")
				.pushedAuthorizationRequestEndpoint("/oauth2/par")
				.requirePushedAuthorizationRequests(false)
				.oidcClientRegistrationEndpoint("/connect/register")
				.oidcUserInfoEndpoint("/userinfo");
	}

	/**
	 * Constructs a new {@link Builder} with the provided settings.
	 *
	 * @param settings the settings to initialize the builder
	 * @return the {@link Builder}
	 */
	public static Builder withSettings(Map<String, Object> settings) {
		Assert.notEmpty(settings, "settings cannot be empty");
		return new Builder()
				.settings(s -> s.putAll(settings));
	}

	/**
	 * Returns the URL of the Authorization Server's Issuer Identifier
	 *
	 * @return the URL of the Authorization Server's Issuer Identifier
	 */
	public String getIssuer() {
		return getSetting(ConfigurationSettingNames.AuthorizationServer.ISSUER);
	}

	/**
	 * Returns the OAuth 2.0 Authorization endpoint. The default is {@code /oauth2/authorize}.
	 *
	 * @return the Authorization endpoint
	 */
	public String getAuthorizationEndpoint() {
		return getSetting(ConfigurationSettingNames.AuthorizationServer.AUTHORIZATION_ENDPOINT);
	}

	/**
	 * Returns the OAuth 2.0 Token endpoint. The default is {@code /oauth2/token}.
	 *
	 * @return the Token endpoint
	 */
	public String getTokenEndpoint() {
		return getSetting(ConfigurationSettingNames.AuthorizationServer.TOKEN_ENDPOINT);
	}

	/**
	 * Returns the JWK Set endpoint. The default is {@code /oauth2/jwks}.
	 *
	 * @return the JWK Set endpoint
	 */
	public String getJwkSetEndpoint() {
		return getSetting(ConfigurationSettingNames.AuthorizationServer.JWK_SET_ENDPOINT);
	}

	/**
	 * Returns the OAuth 2.0 Token Revocation endpoint. The default is {@code /oauth2/revoke}.
	 *
	 * @return the Token Revocation endpoint
	 */
	public String getTokenRevocationEndpoint() {
		return getSetting(ConfigurationSettingNames.AuthorizationServer.TOKEN_REVOCATION_ENDPOINT);
	}

	/**
	 * Returns the OAuth 2.0 Token Introspection endpoint. The default is {@code /oauth2/introspect}.
	 *
	 * @return the Token Introspection endpoint
	 */
	public String getTokenIntrospectionEndpoint() {
		return getSetting(ConfigurationSettingNames.AuthorizationServer.TOKEN_INTROSPECTION_ENDPOINT);
	}

	/**
	 * Returns the OAuth 2.0 Pushed Authorization Request endpoint. The default is {@code /oauth2/token}.
	 *
	 * @return the Pushed Authorization Request endpoint
	 */
	public String getPushedAuthorizationRequestEndpoint() {
		return getSetting(ConfigurationSettingNames.AuthorizationServer.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT);
	}

	/**
	 * Returns if Require Pushed Authorization Requests  are required. The default is {@code false}.
	 *
	 * @return0 if Require Pushed Authorization Requests are required
	 */
	public Boolean getRequirePushedAuthorizationRequests() {
		return getSetting(ConfigurationSettingNames.AuthorizationServer.REQUIRE_PUSHED_AUTHORIZATION_REQUEST);
	}

	/**
	 * Returns the OpenID Connect 1.0 Client Registration endpoint. The default is {@code /connect/register}.
	 *
	 * @return the OpenID Connect 1.0 Client Registration endpoint
	 */
	public String getOidcClientRegistrationEndpoint() {
		return getSetting(ConfigurationSettingNames.AuthorizationServer.OIDC_CLIENT_REGISTRATION_ENDPOINT);
	}

	/**
	 * Returns the OpenID Connect 1.0 UserInfo endpoint. The default is {@code /userinfo}.
	 *
	 * @return the OpenID Connect 1.0 UserInfo endpoint
	 */
	public String getOidcUserInfoEndpoint() {
		return getSetting(ConfigurationSettingNames.AuthorizationServer.OIDC_USER_INFO_ENDPOINT);
	}

	/**
	 * Returns the OAuth 2.0 TLS Client Certificate Bound Access Tokens value. The default is {@code /oauth2/token}.
	 *
	 * @return the Auth 2.0 TLS Client Certificate Bound Access Tokens value
	 */
	public boolean getTlsClientCertificateBoundAccessTokens() {
		return getSetting(ConfigurationSettingNames.AuthorizationServer.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS)!=null?getSetting(ConfigurationSettingNames.AuthorizationServer.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS):false;
	}

	/**
	 * Returns the OAuth 2.0 TLS Client Certificate Bound Access Tokens value. The default is {@code /oauth2/token}.
	 *
	 * @return the Auth 2.0 TLS Client Certificate Bound Access Tokens value
	 */
	public boolean isFAPIEnabled() {
		return getSetting(ConfigurationSettingNames.AuthorizationServer.FAPI_ENABLED)!=null?getSetting(ConfigurationSettingNames.AuthorizationServer.FAPI_ENABLED):false;
	}

	/**
	 * A builder for {@link AuthorizationServerSettings}.
	 */
	public final static class Builder extends AbstractBuilder<AuthorizationServerSettings, Builder> {

		private Builder() {
		}

		/**
		 * Sets the URL the Authorization Server uses as its Issuer Identifier.
		 *
		 * @param issuer the URL the Authorization Server uses as its Issuer Identifier.
		 * @return the {@link Builder} for further configuration
		 */
		public Builder issuer(String issuer) {
			return setting(ConfigurationSettingNames.AuthorizationServer.ISSUER, issuer);
		}

		/**
		 * Sets the OAuth 2.0 Authorization endpoint.
		 *
		 * @param authorizationEndpoint the Authorization endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorizationEndpoint(String authorizationEndpoint) {
			return setting(ConfigurationSettingNames.AuthorizationServer.AUTHORIZATION_ENDPOINT, authorizationEndpoint);
		}

		/**
		 * Sets the OAuth 2.0 Token endpoint.
		 *
		 * @param tokenEndpoint the Token endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenEndpoint(String tokenEndpoint) {
			return setting(ConfigurationSettingNames.AuthorizationServer.TOKEN_ENDPOINT, tokenEndpoint);
		}

		/**
		 * Sets the JWK Set endpoint.
		 *
		 * @param jwkSetEndpoint the JWK Set endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder jwkSetEndpoint(String jwkSetEndpoint) {
			return setting(ConfigurationSettingNames.AuthorizationServer.JWK_SET_ENDPOINT, jwkSetEndpoint);
		}

		/**
		 * Sets the OAuth 2.0 Token Revocation endpoint.
		 *
		 * @param tokenRevocationEndpoint the Token Revocation endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenRevocationEndpoint(String tokenRevocationEndpoint) {
			return setting(ConfigurationSettingNames.AuthorizationServer.TOKEN_REVOCATION_ENDPOINT, tokenRevocationEndpoint);
		}

		/**
		 * Sets the OAuth 2.0 Token Introspection endpoint.
		 *
		 * @param tokenIntrospectionEndpoint the Token Introspection endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenIntrospectionEndpoint(String tokenIntrospectionEndpoint) {
			return setting(ConfigurationSettingNames.AuthorizationServer.TOKEN_INTROSPECTION_ENDPOINT, tokenIntrospectionEndpoint);
		}

		/**
		 * Sets the OAuth 2.0 Pushed Authorization Request endpoint.
		 *
		 * @param pushedAuthorizationRequestEndpoint the Pushed Authorization Request endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder pushedAuthorizationRequestEndpoint(String pushedAuthorizationRequestEndpoint) {
			return setting(ConfigurationSettingNames.AuthorizationServer.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT, pushedAuthorizationRequestEndpoint);
		}

		/**
		 * Sets if OAuth 2.0 Pushed Authorization Requests are required.
		 *
		 * @param requirePushedAuthorizationRequests the Token Introspection endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder requirePushedAuthorizationRequests(Boolean requirePushedAuthorizationRequests) {
			return setting(ConfigurationSettingNames.AuthorizationServer.REQUIRE_PUSHED_AUTHORIZATION_REQUEST, requirePushedAuthorizationRequests);
		}

		public Builder enableFAPI() {
			return setting(ConfigurationSettingNames.AuthorizationServer.FAPI_ENABLED, true);
		}

		/**
		 * Sets the OpenID Connect 1.0 Client Registration endpoint.
		 *
		 * @param oidcClientRegistrationEndpoint the OpenID Connect 1.0 Client Registration endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder oidcClientRegistrationEndpoint(String oidcClientRegistrationEndpoint) {
			return setting(ConfigurationSettingNames.AuthorizationServer.OIDC_CLIENT_REGISTRATION_ENDPOINT, oidcClientRegistrationEndpoint);
		}

		/**
		 * Sets the OpenID Connect 1.0 UserInfo endpoint.
		 *
		 * @param oidcUserInfoEndpoint the OpenID Connect 1.0 UserInfo endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder oidcUserInfoEndpoint(String oidcUserInfoEndpoint) {
			return setting(ConfigurationSettingNames.AuthorizationServer.OIDC_USER_INFO_ENDPOINT, oidcUserInfoEndpoint);
		}

		/**
		 * Builds the {@link AuthorizationServerSettings}.
		 *
		 * @return the {@link AuthorizationServerSettings}
		 */
		@Override
		public AuthorizationServerSettings build() {
			return new AuthorizationServerSettings(getSettings());
		}
	}

}
