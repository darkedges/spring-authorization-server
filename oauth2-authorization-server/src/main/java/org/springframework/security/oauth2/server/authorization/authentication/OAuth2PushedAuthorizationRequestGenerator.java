/*
 * Copyright 2020-2021 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.authentication;

import com.darkedges.org.springframework.security.oauth2.core.RedirectUriMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.server.authorization.OAuth2RequestUri;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.util.Base64;

/**
 * @author Nicholas Irving
 * @since 1.0.0
 */
public class OAuth2PushedAuthorizationRequestGenerator implements OAuth2TokenGenerator<OAuth2RequestUri> {
	private final StringKeyGenerator authorizationCodeGenerator =
			new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 32);

	@Nullable
	@Override
	public OAuth2RequestUri generate(OAuth2TokenContext context) {
		if (context.getTokenType() == null ||
				!com.darkedges.org.springframework.security.oauth2.core.OAuth2ParameterNames.REQUEST.equals(context.getTokenType().getValue())) {
			return null;
		}
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getAuthorizationCodeTimeToLive());
		return new OAuth2RequestUri(RedirectUriMethod.REQUEST_URI.getValue(this.authorizationCodeGenerator.generateKey()), issuedAt, expiresAt);
	}
}
