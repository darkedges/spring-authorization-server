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
package com.darkedges.org.springframework.security.oauth2.core.endpoint;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import java.io.Serializable;

/**
 * @author Nicholas Irving
 * @since 1.0.0
 */
public class OAuth2AuthorizationResponseType implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	public static final OAuth2AuthorizationResponseType CODE = new OAuth2AuthorizationResponseType("code");

	public static final OAuth2AuthorizationResponseType CODE_ID_TOKEN = new OAuth2AuthorizationResponseType(
			"code id_token");

	private final String value;

	public OAuth2AuthorizationResponseType(String value) {
		Assert.hasText(value, "value cannot be empty");
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}

	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}
		org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType that = (org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType) obj;
		return this.getValue().equals(that.getValue());
	}

	@Override
	public int hashCode() {
		return this.getValue().hashCode();
	}

}
