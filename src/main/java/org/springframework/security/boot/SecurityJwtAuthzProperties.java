/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot;


import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityHeaderCorsProperties;
import org.springframework.security.boot.biz.property.SecurityHeaderCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityHeadersProperties;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProcessingFilter;
import org.springframework.security.core.Authentication;

@ConfigurationProperties(prefix = SecurityJwtAuthzProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityJwtAuthzProperties {

	public static final String PREFIX = "spring.security.jwt.authz";
	
	/** Whether Enable JWT Authorization. */
	private boolean enabled = false;
	private boolean checkExpiry = false;
	private boolean checkPrincipal = false;
	/** Authorization Path Pattern */
	private String pathPattern = "/**";
	private String[] ignorePatterns = new String[] {"/login/jwt"};
	
	/**
	 * Specifies the name of the header on where to find the token (i.e. X-Authorization).
	 */
	private String authorizationHeaderName = JwtAuthorizationProcessingFilter.AUTHORIZATION_HEADER;
	private String authorizationParamName = JwtAuthorizationProcessingFilter.AUTHORIZATION_PARAM;
	private String authorizationCookieName = JwtAuthorizationProcessingFilter.AUTHORIZATION_PARAM;
	/**
	 * Indicates if the filter chain should be continued prior to delegation to
	 * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication)}
	 * , which may be useful in certain environment (such as Tapestry applications).
	 * Defaults to <code>false</code>.
	 */
	private boolean continueChainBeforeSuccessfulAuthentication = true;

	@NestedConfigurationProperty
	private SecurityHeadersProperties headers = new SecurityHeadersProperties();

	@NestedConfigurationProperty
	private SecurityHeaderCorsProperties cros = new SecurityHeaderCorsProperties();
	
	@NestedConfigurationProperty
	private SecurityHeaderCsrfProperties csrf = new SecurityHeaderCsrfProperties();

}
