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
package org.springframework.security.boot.jwt.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.boot.biz.authentication.AuthenticationProcessingFilter;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Jwt授权 (authorization)过滤器
 * 
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@Slf4j
public class JwtAuthorizationProcessingFilter extends AuthenticationProcessingFilter {
	
	/**
	 * HTTP Authorization Param, equal to <code>token</code>
	 */
	public static final String AUTHORIZATION_PARAM = "token";
	/**
	 * HTTP Authorization header, equal to <code>X-Authorization</code>
	 */
	public static final String AUTHORIZATION_HEADER = "X-Authorization";
	
	private String authorizationHeaderName = AUTHORIZATION_HEADER;
	private String authorizationParamName = AUTHORIZATION_PARAM;
	private String authorizationCookieName = AUTHORIZATION_PARAM;
	
	private List<RequestMatcher> ignoreRequestMatchers;
	
	private SessionAuthenticationStrategy sessionStrategy = new NullAuthenticatedSessionStrategy();
	
	public JwtAuthorizationProcessingFilter() {
		super(new AntPathRequestMatcher("/**"));
	}
	
	public JwtAuthorizationProcessingFilter(List<String> ignorePatterns) {
		super(new AntPathRequestMatcher("/**"));
		this.setIgnoreRequestMatcher(ignorePatterns);
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		// 忽略部分请求
		if(!CollectionUtils.isEmpty(ignoreRequestMatchers)) {
			for (RequestMatcher requestMatcher : ignoreRequestMatchers) {
				if(requestMatcher.matches(request)) {
					return false;
				}
			}
		}
		// 登录获取JWT的请求不拦截
		return super.requiresAuthentication(request, response);
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		ServletRequestAttributes requestAttributes = new ServletRequestAttributes(request, response);
		RequestContextHolder.setRequestAttributes(requestAttributes, true);
		
		if (!requiresAuthentication(request, response)) {
			chain.doFilter(request, response);
			return;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Request is to process authentication");
		}

		Authentication authResult;

		try {
			authResult = attemptAuthentication(request, response);
			if (authResult == null) {
				// return immediately as subclass has indicated that it hasn't completed
				// authentication
				return;
			}
			sessionStrategy.onAuthentication(authResult, request, response);
		}
		catch (InternalAuthenticationServiceException failed) {
			logger.error(
					"An internal error occurred while trying to authenticate the user.",
					failed);
			unsuccessfulAuthentication(request, response, failed);

			return;
		}
		catch (AuthenticationException failed) {
			// Authentication failed
			unsuccessfulAuthentication(request, response, failed);

			return;
		}
		
		successfulAuthentication(request, response, chain, authResult);

		// Authorization success
		chain.doFilter(request, response);
		
	}
	
	@Override
	public void setSessionAuthenticationStrategy(
			SessionAuthenticationStrategy sessionStrategy) {
		super.setSessionAuthenticationStrategy(sessionStrategy);
		this.sessionStrategy = sessionStrategy;
	}
	
	@Override
	public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		String token = this.obtainToken(request);

		if (token == null) {
			token = "";
		}

		token = token.trim();
		
		if(StringUtils.isBlank(token)) {
			throw new AuthenticationJwtNotFoundException("JWT not provided");
		}
		
		JwtAuthorizationToken authRequest = new JwtAuthorizationToken(this.obtainUid(request), token);
		authRequest.setLongitude(this.obtainLongitude(request));
		authRequest.setLatitude(this.obtainLatitude(request));
		authRequest.setSign(this.obtainSign(request));
		
		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);
		
		return this.getAuthenticationManager().authenticate(authRequest);
	}

	protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}

	protected String obtainToken(HttpServletRequest request) {
		//	从header中获取token
		String token = request.getHeader(getAuthorizationHeaderName());
		if(!StringUtils.isEmpty(token)){
			log.info("obtain token from header : {}", token);
		}
		//	如果header中不存在token，则从参数中获取token
		if (StringUtils.isEmpty(token)) {
			token = request.getParameter(getAuthorizationParamName());
			if(!StringUtils.isEmpty(token)){
				log.info("obtain token from param : {}", token);
			}
		}
		//	从 cookie 获取 token
		if (StringUtils.isEmpty(token)) {
			// 从 cookie 获取 token
			Cookie[] cookies = request.getCookies();
			if (ArrayUtils.isEmpty(cookies)) {
				return null;
			}
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(getAuthorizationCookieName())) {
					token = cookie.getValue();
					if(!StringUtils.isEmpty(token)){
						log.info("obtain token from cookie : {}", token);
					}
					break;
				}
			}
		}
		return token;
	}
	
	public void setIgnoreRequestMatcher(List<String> ignorePatterns) {
		if(!CollectionUtils.isEmpty(ignorePatterns)) {
			this.ignoreRequestMatchers = ignorePatterns.stream().map(pattern -> {
				return new AntPathRequestMatcher(pattern);
			}).collect(Collectors.toList());
		}
	}
	
	public void setIgnoreRequestMatchers(RequestMatcher ...ignoreRequestMatchers) {
		this.ignoreRequestMatchers = Arrays.asList(ignoreRequestMatchers);
	}

	public String getAuthorizationHeaderName() {
		return authorizationHeaderName;
	}

	public void setAuthorizationHeaderName(String authorizationHeaderName) {
		this.authorizationHeaderName = authorizationHeaderName;
	}

	public String getAuthorizationParamName() {
		return authorizationParamName;
	}

	public void setAuthorizationParamName(String authorizationParamName) {
		this.authorizationParamName = authorizationParamName;
	}

	public String getAuthorizationCookieName() {
		return authorizationCookieName;
	}

	public void setAuthorizationCookieName(String authorizationCookieName) {
		this.authorizationCookieName = authorizationCookieName;
	}

}