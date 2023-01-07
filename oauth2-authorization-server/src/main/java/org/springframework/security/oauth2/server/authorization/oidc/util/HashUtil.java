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
package org.springframework.security.oauth2.server.authorization.oidc.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import com.nimbusds.openid.connect.sdk.claims.StateHash;

/**
 *
 * Compute Hashes for use with ID Tokens
 *
 * @author Nicholas Irving
 * @since 1.0.0
 */
public class HashUtil {
	/**
	 *
	 * @param value - The state. Must not be null.
	 * @param jwsAlgorithm  – The reference JWS algorithm. Must not be null.
	 * @param crv – The JWK curve used with the JWS algorithm, null if not applicable.
	 * @return The state hash, or null if the JWS algorithm is not supported.
	 */
	public static String state(String value, JWSAlgorithm jwsAlgorithm, Curve crv) {
		State state = new State(value);
		return StateHash.compute(state, jwsAlgorithm, crv).getValue();
	}

	/**
	 *
	 * @param value - The state. Must not be null.
	 * @param jwsAlgorithm  – The reference JWS algorithm. Must not be null.
	 * @param crv – The JWK curve used with the JWS algorithm, null if not applicable.
	 * @return The code hash, or null if the JWS algorithm is not supported.
	 */
	public static String code(String value, JWSAlgorithm jwsAlgorithm, Curve crv) {
		AuthorizationCode code = new AuthorizationCode(value);
		return CodeHash.compute(code, jwsAlgorithm, crv).getValue();
	}
}
