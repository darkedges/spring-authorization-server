package org.springframework.security.oauth2.server.authorization.authentication;

import com.darkedges.org.springframework.security.oauth2.core.RedirectUriMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2RequestUri;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.util.Base64;

public class OAuth2PushedAuthorizationRequestGenerator implements OAuth2TokenGenerator<OAuth2RequestUri>  {
	private final StringKeyGenerator authorizationCodeGenerator =
			new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 32);

	@Nullable
	@Override
	public OAuth2RequestUri generate(OAuth2TokenContext context) {

		if (context.getTokenType() == null ||
				!OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
			return null;
		}
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getAuthorizationCodeTimeToLive());
		return new OAuth2RequestUri(RedirectUriMethod.REQUEST_URI.getValue(this.authorizationCodeGenerator.generateKey()), issuedAt, expiresAt);
	}
}
