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
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2PushedAuthorizationRequestEndpointFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Configurer for the OAuth 2.0 Pushed Authorization Requests Endpoint.
 *
 * @author Nicholas Irving
 * @since 1.0.0
 */
public class OAuth2PushedAuthorizationRequestEndpointConfigurer extends AbstractOAuth2Configurer {
	private RequestMatcher requestMatcher;
	private boolean requirePushedAuthorizationRequests = false;

	/**
	 * Restrict for internal use only.
	 */
	OAuth2PushedAuthorizationRequestEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
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
	}

	@Override
	void configure(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);
		OAuth2PushedAuthorizationRequestEndpointFilter pushedAuthorizationRequestEndpointFilter =
				new OAuth2PushedAuthorizationRequestEndpointFilter(
						authorizationServerSettings.getPushedAuthorizationRequestEndpoint()
				);
		pushedAuthorizationRequestEndpointFilter.setRequirePushedAuthorizationRequests(this.requirePushedAuthorizationRequests);
		httpSecurity.addFilterBefore(postProcess(pushedAuthorizationRequestEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	public OAuth2PushedAuthorizationRequestEndpointConfigurer requirePushedAuthorizationRequests(boolean requirePushedAuthorizationRequests) {
		this.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests;
		return this;
	}
}
