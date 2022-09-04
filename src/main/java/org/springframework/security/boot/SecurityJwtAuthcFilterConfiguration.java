package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = SecurityJwtAuthcProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class })
public class SecurityJwtAuthcFilterConfiguration {

	@Bean
	public JwtAuthenticationProvider jwtAuthenticationProvider(
			ObjectProvider<UserDetailsServiceAdapter> userDetailsServiceProvider,
			ObjectProvider<PasswordEncoder> passwordEncoderProvider) {
		return new JwtAuthenticationProvider(userDetailsServiceProvider.getIfAvailable(), passwordEncoderProvider.getIfAvailable());
	}

	@Configuration
	@ConditionalOnProperty(prefix = SecurityJwtAuthcProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class })
	static class JwtAuthcWebSecurityConfigurerAdapter extends SecurityFilterChainConfigurer {

		private final SecurityJwtAuthcProperties authcProperties;

		private final AuthenticatingFailureCounter authenticatingFailureCounter;
		private final AuthenticationEntryPoint authenticationEntryPoint;
		private final AuthenticationSuccessHandler authenticationSuccessHandler;
		private final AuthenticationFailureHandler authenticationFailureHandler;
		private final CaptchaResolver captchaResolver;
		private final LocaleContextFilter localeContextFilter;
		private final LogoutHandler logoutHandler;
		private final LogoutSuccessHandler logoutSuccessHandler;
		private final ObjectMapper objectMapper;
		private final RequestCache requestCache;
		private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;

		public JwtAuthcWebSecurityConfigurerAdapter(

				SecurityBizProperties bizProperties,
   				SecurityJwtAuthcProperties authcProperties,

				ObjectProvider<AuthenticationProvider> authenticationProvider,
				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
				ObjectProvider<CaptchaResolver> captchaResolverProvider,
				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
				ObjectProvider<LocaleContextFilter> localeContextProvider,
				ObjectProvider<LogoutHandler> logoutHandlerProvider,
				ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
				ObjectProvider<ObjectMapper> objectMapperProvider,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider

   			) {

			super(bizProperties, authcProperties, authenticationProvider.stream().collect(Collectors.toList()));

   			this.authcProperties = authcProperties;

			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
			this.authenticatingFailureCounter = super.authenticatingFailureCounter();
			this.authenticationEntryPoint = super.authenticationEntryPoint(authenticationEntryPointProvider.stream().collect(Collectors.toList()));
			this.authenticationSuccessHandler = super.authenticationSuccessHandler(authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
			this.authenticationFailureHandler = super.authenticationFailureHandler(authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
			this.captchaResolver = captchaResolverProvider.getIfAvailable();
			this.localeContextFilter = localeContextProvider.getIfAvailable();
			this.logoutHandler = super.logoutHandler(logoutHandlerProvider.stream().collect(Collectors.toList()));
			this.logoutSuccessHandler = logoutSuccessHandlerProvider.getIfAvailable();
			this.objectMapper = objectMapperProvider.getIfAvailable();
			this.requestCache = super.requestCache();
			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
			this.sessionAuthenticationStrategy = super.sessionAuthenticationStrategy();

		}

		public JwtAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {

	        JwtAuthenticationProcessingFilter authenticationFilter = new JwtAuthenticationProcessingFilter(objectMapper);

	        /**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();

			map.from(authcProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);

			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);

			map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);

			map.from(authcProperties.getCaptcha().getParamName()).to(authenticationFilter::setCaptchaParameter);
			// 是否验证码必填
			map.from(authcProperties.getCaptcha().isRequired()).to(authenticationFilter::setCaptchaRequired);
			// 验证码解析器
			map.from(captchaResolver).to(authenticationFilter::setCaptchaResolver);
			// 认证失败计数器
			map.from(authenticatingFailureCounter).to(authenticationFilter::setFailureCounter);

			map.from(authcProperties.getUsernameParameter()).to(authenticationFilter::setUsernameParameter);
			map.from(authcProperties.getPasswordParameter()).to(authenticationFilter::setPasswordParameter);
			map.from(authcProperties.isPostOnly()).to(authenticationFilter::setPostOnly);
			// 登陆失败重试次数，超出限制需要输入验证码
			map.from(authcProperties.getRetry().getRetryTimesKeyAttribute()).to(authenticationFilter::setRetryTimesKeyAttribute);
			map.from(authcProperties.getRetry().getRetryTimesWhenAccessDenied()).to(authenticationFilter::setRetryTimesWhenAccessDenied);

			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);

	        return authenticationFilter;
	    }

		@Bean
		@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 9)
		public SecurityFilterChain jwtAuthcSecurityFilterChain(HttpSecurity http) throws Exception {
			// new DefaultSecurityFilterChain(new AntPathRequestMatcher(authcProperties.getPathPattern()), localeContextFilter, authenticationProcessingFilter());
			http.antMatcher(authcProperties.getPathPattern())
					// 请求鉴权配置
					.authorizeRequests(this.authorizeRequestsCustomizer())
					// 跨站请求配置
					.csrf(this.csrfCustomizer(authcProperties.getCsrf()))
					// 跨域配置
					.cors(this.corsCustomizer(authcProperties.getCors()))
					// 异常处理
					.exceptionHandling((configurer) -> configurer.authenticationEntryPoint(authenticationEntryPoint))
					// 请求头配置
					.headers(this.headersCustomizer(authcProperties.getHeaders()))
					// Request 缓存配置
					.requestCache((request) -> request.requestCache(requestCache))
					// Session 注销配置
					.logout(this.logoutCustomizer(authcProperties.getLogout(), logoutHandler, logoutSuccessHandler))
					// 禁用 Http Basic
					.httpBasic((basic) -> basic.disable())
					// Filter 配置
					.addFilterBefore(localeContextFilter, UsernamePasswordAuthenticationFilter.class)
					.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

			return http.build();
		}

	}

}
