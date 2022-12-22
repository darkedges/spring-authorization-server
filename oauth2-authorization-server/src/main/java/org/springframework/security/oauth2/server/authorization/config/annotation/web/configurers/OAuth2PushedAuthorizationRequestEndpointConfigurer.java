package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
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
