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
package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2PushedAuthorizationRequestEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2PushedAuthorizationRequestAuthenticationConverter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Configurer for the OAuth 2.0 Pushed Authorization Requests Endpoint.
 *
 * @author Nicholas Irving
 * @since 1.0.0
 */
public class OAuth2PushedAuthorizationRequestEndpointConfigurer extends AbstractOAuth2Configurer {
	private final List<AuthenticationConverter> authorizationRequestConverters = new ArrayList<>();
	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
	private RequestMatcher requestMatcher;
	private boolean requirePushedAuthorizationRequests = false;
	private final Consumer<List<AuthenticationConverter>> authorizationRequestConvertersConsumer = (authorizationRequestConverters) -> {
	};
	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
	};

	private Consumer<OAuth2PushedAuthorizationRequestAuthenticationContext> pushedAuthorizationRequestAuthenticationValidator;
	private AuthenticationSuccessHandler authorizationResponseHandler;
	private AuthenticationFailureHandler errorResponseHandler;
	private RegisteredClientRepository registeredClientRepository;

	/**
	 * Restrict for internal use only.
	 */
	OAuth2PushedAuthorizationRequestEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters(HttpSecurity httpSecurity) {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();
		RegisteredClientRepository registeredClientRepository = OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity);
		JwtDecoderFactory<RegisteredClient> jwtDecoderFactory = new JwtPushedAuthorizationRequestDecoderFactory();
		authenticationConverters.add(new OAuth2PushedAuthorizationRequestAuthenticationConverter(registeredClientRepository, jwtDecoderFactory));

		return authenticationConverters;
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
				.getAuthorizationServerSettings(httpSecurity);
		this.requestMatcher = new OrRequestMatcher(
				new AntPathRequestMatcher(authorizationServerSettings.getPushedAuthorizationRequestEndpoint(),
						HttpMethod.GET.name()),
				new AntPathRequestMatcher(authorizationServerSettings.getPushedAuthorizationRequestEndpoint(),
						HttpMethod.POST.name()));
		List<AuthenticationProvider> authenticationProviders = createDefaultAuthenticationProviders(httpSecurity);
		if (!this.authenticationProviders.isEmpty()) {
			authenticationProviders.addAll(0, this.authenticationProviders);
		}
		this.authenticationProvidersConsumer.accept(authenticationProviders);
		authenticationProviders.forEach(authenticationProvider ->
				httpSecurity.authenticationProvider(postProcess(authenticationProvider)));
	}

	@Override
	void configure(HttpSecurity httpSecurity) {
		AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);

		OAuth2PushedAuthorizationRequestEndpointFilter pushedAuthorizationRequestEndpointFilter =
				new OAuth2PushedAuthorizationRequestEndpointFilter(
						authenticationManager,
						authorizationServerSettings.getPushedAuthorizationRequestEndpoint());
		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters(httpSecurity);
		if (!this.authorizationRequestConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.authorizationRequestConverters);
		}
		this.authorizationRequestConvertersConsumer.accept(authenticationConverters);
		pushedAuthorizationRequestEndpointFilter.setAuthenticationConverter(
				new DelegatingAuthenticationConverter(authenticationConverters));
		if (this.authorizationResponseHandler != null) {
			pushedAuthorizationRequestEndpointFilter.setAuthenticationSuccessHandler(this.authorizationResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			pushedAuthorizationRequestEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		pushedAuthorizationRequestEndpointFilter.setRequirePushedAuthorizationRequests(this.requirePushedAuthorizationRequests);
		httpSecurity.addFilterAfter(postProcess(pushedAuthorizationRequestEndpointFilter), AuthorizationFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	public OAuth2PushedAuthorizationRequestEndpointConfigurer requirePushedAuthorizationRequests(boolean requirePushedAuthorizationRequests) {
		this.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests;
		return this;
	}

	void addPushedAuthorizationRequestAuthenticationValidator(
			Consumer<OAuth2PushedAuthorizationRequestAuthenticationContext> authenticationValidator) {
		this.pushedAuthorizationRequestAuthenticationValidator =
				this.pushedAuthorizationRequestAuthenticationValidator == null ?
						authenticationValidator :
						this.pushedAuthorizationRequestAuthenticationValidator.andThen(authenticationValidator);
	}

	private List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
		OAuth2PushedAuthorizationRequestAuthenticationProvider pushedAuthorizationRequestAuthenticationProvider =
				new OAuth2PushedAuthorizationRequestAuthenticationProvider(
						OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
						OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity));
		if (this.pushedAuthorizationRequestAuthenticationValidator != null) {
			pushedAuthorizationRequestAuthenticationProvider.setAuthenticationValidator(
					new OAuth2PushedAuthorizationRequestAuthenticationValidator()
							.andThen(this.pushedAuthorizationRequestAuthenticationValidator));
		}
		authenticationProviders.add(pushedAuthorizationRequestAuthenticationProvider);
		return authenticationProviders;
	}
	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating an {@link OAuth2PushedAuthorizationRequestEndpointConfigurer}.
	 *
	 * @param authenticationProvider an {@link AuthenticationProvider} used for authenticating an {@link OAuth2PushedAuthorizationRequestAuthenticationToken}
	 * @return the {@link OAuth2PushedAuthorizationRequestEndpointConfigurer} for further configuration
	 */
	public OAuth2PushedAuthorizationRequestEndpointConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
		Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}
	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default
	 * and (optionally) added {@link #authenticationProvider(AuthenticationProvider) AuthenticationProvider}'s
	 * allowing the ability to add, remove, or customize a specific {@link AuthenticationProvider}.
	 *
	 * @param authenticationProvidersConsumer the {@code Consumer} providing access to the {@code List} of default and (optionally) added {@link AuthenticationProvider}'s
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 * @since 0.4.0
	 */
	public OAuth2PushedAuthorizationRequestEndpointConfigurer authenticationProviders(
			Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer) {
		Assert.notNull(authenticationProvidersConsumer, "authenticationProvidersConsumer cannot be null");
		this.authenticationProvidersConsumer = authenticationProvidersConsumer;
		return this;
	}

}
