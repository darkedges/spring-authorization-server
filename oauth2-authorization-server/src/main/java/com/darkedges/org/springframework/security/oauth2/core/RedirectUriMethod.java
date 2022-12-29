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
package com.darkedges.org.springframework.security.oauth2.core;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import java.io.Serializable;

/**
 * @author Nicholas Irving
 * @since 1.0.0
 */
public class RedirectUriMethod implements Serializable {

	public static final RedirectUriMethod REQUEST_URI = new RedirectUriMethod(
			"urn:ietf:params:oauth:request_uri");
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final String type;

	public RedirectUriMethod(String value) {
		Assert.hasText(value, "value cannot be empty");
		this.type = value;
	}

	public String getValue(String value) {
		return this.type + ":" + value;
	}
}
