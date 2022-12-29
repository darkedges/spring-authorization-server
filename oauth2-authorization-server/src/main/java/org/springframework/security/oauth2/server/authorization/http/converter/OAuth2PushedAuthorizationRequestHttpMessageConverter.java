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
package org.springframework.security.oauth2.server.authorization.http.converter;

import com.darkedges.org.springframework.security.oauth2.core.OAuth2PushedAuthorizationRequestClaimNames;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.*;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2PushedAuthorizationRequest;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.net.URL;
import java.time.Instant;
import java.util.*;

/**
 * A {@link HttpMessageConverter} for an {@link OAuth2PushedAuthorizationRequest OAuth 2.0 Token Introspection Response}.
 *
 * @author Nicholas Irving
 * @see AbstractHttpMessageConverter
 * @see OAuth2PushedAuthorizationRequest
 * @since 1.0.0
 */
public class OAuth2PushedAuthorizationRequestHttpMessageConverter extends AbstractHttpMessageConverter<OAuth2PushedAuthorizationRequest> {
	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<Map<String, Object>>() {
	};

	private final GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters.getJsonMessageConverter();

	private Converter<Map<String, Object>, OAuth2PushedAuthorizationRequest> pushedAuthorizationRequestConverter = new OAuth2PushedAuthorizationRequestHttpMessageConverter.MapOAuth2PushedAuthorizationRequestConverter();
	private Converter<OAuth2PushedAuthorizationRequest, Map<String, Object>> pushedAuthorizationRequestParametersConverter = new OAuth2PushedAuthorizationRequestHttpMessageConverter.OAuth2PushedAuthorizationRequestMapConverter();

	public OAuth2PushedAuthorizationRequestHttpMessageConverter() {
		super(MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OAuth2PushedAuthorizationRequest.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OAuth2PushedAuthorizationRequest readInternal(Class<? extends OAuth2PushedAuthorizationRequest> clazz, HttpInputMessage inputMessage)
			throws HttpMessageNotReadableException {
		try {
			Map<String, Object> PushedAuthorizationRequestParameters = (Map<String, Object>) this.jsonMessageConverter
					.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
			return this.pushedAuthorizationRequestConverter.convert(PushedAuthorizationRequestParameters);
		} catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the Token Introspection Response: " + ex.getMessage(), ex, inputMessage);
		}
	}

	@Override
	protected void writeInternal(OAuth2PushedAuthorizationRequest PushedAuthorizationRequest, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {
		try {
			Map<String, Object> PushedAuthorizationRequestResponseParameters = this.pushedAuthorizationRequestParametersConverter
					.convert(PushedAuthorizationRequest);
			this.jsonMessageConverter.write(PushedAuthorizationRequestResponseParameters, STRING_OBJECT_MAP.getType(),
					MediaType.APPLICATION_JSON, outputMessage);
		} catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the Token Introspection Response: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the Token Introspection Response parameters to an {@link OAuth2PushedAuthorizationRequest}.
	 *
	 * @param PushedAuthorizationRequestConverter the {@link Converter} used for converting to an {@link OAuth2PushedAuthorizationRequest}
	 */
	public final void setPushedAuthorizationRequestConverter(
			Converter<Map<String, Object>, OAuth2PushedAuthorizationRequest> PushedAuthorizationRequestConverter) {
		Assert.notNull(PushedAuthorizationRequestConverter, "PushedAuthorizationRequestConverter cannot be null");
		this.pushedAuthorizationRequestConverter = PushedAuthorizationRequestConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting an {@link OAuth2PushedAuthorizationRequest}
	 * to a {@code Map} representation of the Token Introspection Response parameters.
	 *
	 * @param PushedAuthorizationRequestParametersConverter the {@link Converter} used for converting to a
	 *                                                      {@code Map} representation of the Token Introspection Response parameters
	 */
	public final void setPushedAuthorizationRequestParametersConverter(
			Converter<OAuth2PushedAuthorizationRequest, Map<String, Object>> PushedAuthorizationRequestParametersConverter) {
		Assert.notNull(PushedAuthorizationRequestParametersConverter, "PushedAuthorizationRequestParametersConverter cannot be null");
		this.pushedAuthorizationRequestParametersConverter = PushedAuthorizationRequestParametersConverter;
	}

	private static final class MapOAuth2PushedAuthorizationRequestConverter
			implements Converter<Map<String, Object>, OAuth2PushedAuthorizationRequest> {

		private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService.getSharedInstance();
		private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);
		private static final TypeDescriptor BOOLEAN_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Boolean.class);
		private static final TypeDescriptor STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String.class);
		private static final TypeDescriptor INSTANT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Instant.class);
		private static final TypeDescriptor URL_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(URL.class);
		private final ClaimTypeConverter claimTypeConverter;

		private MapOAuth2PushedAuthorizationRequestConverter() {
			Converter<Object, ?> booleanConverter = getConverter(BOOLEAN_TYPE_DESCRIPTOR);
			Converter<Object, ?> stringConverter = getConverter(STRING_TYPE_DESCRIPTOR);
			Converter<Object, ?> instantConverter = getConverter(INSTANT_TYPE_DESCRIPTOR);
			Converter<Object, ?> collectionStringConverter = getConverter(
					TypeDescriptor.collection(Collection.class, STRING_TYPE_DESCRIPTOR));
			Converter<Object, ?> urlConverter = getConverter(URL_TYPE_DESCRIPTOR);

			Map<String, Converter<Object, ?>> claimConverters = new HashMap<>();
			claimConverters.put(OAuth2PushedAuthorizationRequestClaimNames.EXPIRES_IN, instantConverter);
			claimConverters.put(OAuth2PushedAuthorizationRequestClaimNames.REQUEST_URI, stringConverter);
			this.claimTypeConverter = new ClaimTypeConverter(claimConverters);
		}

		private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
			return (source) -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
		}

		private static List<String> convertScope(Object scope) {
			if (scope == null) {
				return Collections.emptyList();
			}
			return Arrays.asList(StringUtils.delimitedListToStringArray(scope.toString(), " "));
		}

		@Override
		public OAuth2PushedAuthorizationRequest convert(Map<String, Object> source) {
			Map<String, Object> parsedClaims = this.claimTypeConverter.convert(source);
			return OAuth2PushedAuthorizationRequest.withClaims(parsedClaims).build();
		}
	}

	private static final class OAuth2PushedAuthorizationRequestMapConverter
			implements Converter<OAuth2PushedAuthorizationRequest, Map<String, Object>> {

		@Override
		public Map<String, Object> convert(OAuth2PushedAuthorizationRequest source) {
			Map<String, Object> responseClaims = new LinkedHashMap<>(source.getClaims());
			if (source.getExpiresIn() != null) {
				responseClaims.put(OAuth2PushedAuthorizationRequestClaimNames.EXPIRES_IN, source.getExpiresIn().getEpochSecond());
			}
			return responseClaims;
		}
	}
}
