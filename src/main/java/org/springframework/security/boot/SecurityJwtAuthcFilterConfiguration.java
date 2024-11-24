package org.springframework.security.boot;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProvider;
import org.springframework.security.boot.utils.WebSecurityUtils;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.CompositeAccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.util.List;
import java.util.stream.Collectors;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = SecurityJwtAuthcProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class })
public class SecurityJwtAuthcFilterConfiguration {

	@Bean
	public JwtAuthenticationProvider jwtAuthenticationProvider(ObjectProvider<UserDetailsServiceAdapter> userDetailsServiceProvider,
															   ObjectProvider<PasswordEncoder> passwordEncoderProvider) {
		return new JwtAuthenticationProvider(userDetailsServiceProvider.getIfAvailable(), passwordEncoderProvider.getIfAvailable());
	}
	
	@Configuration
	@ConditionalOnProperty(prefix = SecurityJwtAuthcProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class })
	static class JwtAuthcWebSecurityCustomizerAdapter extends WebSecurityCustomizerAdapter {
    	
		private final SecurityJwtAuthcProperties authcProperties;

		private final AccessDeniedHandler accessDeniedHandler;
    	private final LocaleContextFilter localeContextFilter;
		private final AuthenticatingFailureCounter authenticatingFailureCounter;
	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
	    private final CaptchaResolver captchaResolver;
	    private final ObjectMapper objectMapper;
    	private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		
		
		public JwtAuthcWebSecurityCustomizerAdapter(
				
				SecurityBizProperties bizProperties,
   				SecurityJwtAuthcProperties authcProperties,
   				SecuritySessionMgtProperties sessionMgtProperties,

				ObjectProvider<AccessDeniedHandler> accessDeniedHandlerProvider,
   				ObjectProvider<LocaleContextFilter> localeContextProvider,
   				ObjectProvider<AuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<AuthenticatingFailureCounter> authenticatingFailureCounter,
   				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
   				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider
				
   			) {
		    
			super(bizProperties, sessionMgtProperties, authenticationProvider.stream().collect(Collectors.toList()));
   			
   			this.authcProperties = authcProperties;
   			
   			this.captchaResolver = captchaResolverProvider.getIfAvailable();

			this.accessDeniedHandler = new CompositeAccessDeniedHandler(accessDeniedHandlerProvider.stream().collect(Collectors.toList()));
			this.localeContextFilter = localeContextProvider.getIfAvailable();
   			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
   			this.authenticatingFailureCounter = WebSecurityUtils.authenticatingFailureCounter(authcProperties);
   			this.authenticationEntryPoint = WebSecurityUtils.authenticationEntryPoint(authcProperties, sessionMgtProperties, authenticationEntryPointProvider.stream().collect(Collectors.toList()));
   			this.authenticationSuccessHandler = WebSecurityUtils.authenticationSuccessHandler(authcProperties, sessionMgtProperties, authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
   			this.authenticationFailureHandler = WebSecurityUtils.authenticationFailureHandler(authcProperties, sessionMgtProperties, authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
		}

		public JwtAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
	    	
	        JwtAuthenticationProcessingFilter authenticationFilter = new JwtAuthenticationProcessingFilter(objectMapper);
	        
	        /**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(getSessionMgtProperties().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
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

			http.securityMatcher(authcProperties.getPathPattern())
					.exceptionHandling(configurer -> {
						configurer.authenticationEntryPoint(authenticationEntryPoint)
								.accessDeniedHandler(accessDeniedHandler)
								.accessDeniedPage(authcProperties.getAccessDeniedUrl());
					});
			http.httpBasic(AbstractHttpConfigurer::disable);
			http.addFilterBefore(localeContextFilter, UsernamePasswordAuthenticationFilter.class)
					.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

			super.configure(http, authcProperties.getCors());
			super.configure(http, authcProperties.getCsrf());
			super.configure(http, authcProperties.getHeaders());
			super.configure(http);

			return http.build();
		}

		@Override
		public void customize(WebSecurity web) {
			super.customize(web);
		}
		
	}

}
