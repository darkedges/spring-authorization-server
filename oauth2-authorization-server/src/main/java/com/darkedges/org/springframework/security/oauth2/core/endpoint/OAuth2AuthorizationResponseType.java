package com.darkedges.org.springframework.security.oauth2.core.endpoint;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import java.io.Serializable;

public class OAuth2AuthorizationResponseType  implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	public static final OAuth2AuthorizationResponseType CODE = new OAuth2AuthorizationResponseType("code");
	public static final OAuth2AuthorizationResponseType CODE_ID_TOKEN = new OAuth2AuthorizationResponseType("code id_token");
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
