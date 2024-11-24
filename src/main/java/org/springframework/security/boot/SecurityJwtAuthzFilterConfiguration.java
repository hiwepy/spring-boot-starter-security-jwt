package org.springframework.security.boot;

import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProvider;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationSuccessHandler;
import org.springframework.security.boot.utils.WebSecurityUtils;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.CompositeAccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.util.CollectionUtils;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = SecurityJwtAuthzProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class, SecurityJwtAuthzProperties.class })
public class SecurityJwtAuthzFilterConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public JwtAuthorizationProvider jwtAuthorizationProvider(JwtPayloadRepository payloadRepository, SecurityJwtAuthzProperties jwtAuthzProperties) {
		JwtAuthorizationProvider jwtAuthorizationProvider = new JwtAuthorizationProvider(payloadRepository);
		jwtAuthorizationProvider.setCheckExpiry(jwtAuthzProperties.isCheckExpiry());
		jwtAuthorizationProvider.setCheckPrincipal(jwtAuthzProperties.isCheckPrincipal());
		return jwtAuthorizationProvider;
	}
	
	
    @Configuration
    @ConditionalOnProperty(prefix = SecurityJwtAuthzProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class, SecurityJwtAuthzProperties.class })
	static class JwtAuthzWebSecurityCustomizerAdapter extends WebSecurityCustomizerAdapter {

    	private final SecurityBizProperties bizProperties;
    	private final SecurityJwtAuthcProperties authcProperties;
    	private final SecurityJwtAuthzProperties authzProperties;

		private final AccessDeniedHandler accessDeniedHandler;
    	private final LocaleContextFilter localeContextFilter;
	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
    	private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		
		public JwtAuthzWebSecurityCustomizerAdapter(
				
				SecurityBizProperties bizProperties,
				SecuritySessionMgtProperties sessionMgtProperties,
   				SecurityJwtAuthcProperties authcProperties,
   				SecurityJwtAuthzProperties authzProperties,

				ObjectProvider<AccessDeniedHandler> accessDeniedHandlerProvider,
   				ObjectProvider<LocaleContextFilter> localeContextProvider,
   				ObjectProvider<AuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
   				
				ObjectProvider<RequestCache> requestCacheProvider,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionRegistry> sessionRegistryProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider
				
			) {
			
			super(bizProperties, sessionMgtProperties, authenticationProvider.stream().collect(Collectors.toList()));
			
   			this.bizProperties = bizProperties;
   			this.authcProperties = authcProperties;
   			this.authzProperties = authzProperties;

			this.accessDeniedHandler = new CompositeAccessDeniedHandler(accessDeniedHandlerProvider.stream().collect(Collectors.toList()));
   			this.localeContextFilter = localeContextProvider.getIfAvailable();
   			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
   			this.authenticationEntryPoint = WebSecurityUtils.authenticationEntryPoint(authcProperties, sessionMgtProperties, authenticationEntryPointProvider.stream().collect(Collectors.toList()));
   			this.authenticationSuccessHandler = new JwtAuthorizationSuccessHandler();
   			this.authenticationFailureHandler = WebSecurityUtils.authenticationFailureHandler(authcProperties, sessionMgtProperties, authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
		}

	    public JwtAuthorizationProcessingFilter authenticationProcessingFilter() throws Exception {
	    	
	    	JwtAuthorizationProcessingFilter authenticationFilter = new JwtAuthorizationProcessingFilter();
			
	    	/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(getSessionMgtProperties().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			map.from(authzProperties.getAuthorizationCookieName()).to(authenticationFilter::setAuthorizationCookieName);
			map.from(authzProperties.getAuthorizationHeaderName()).to(authenticationFilter::setAuthorizationHeaderName);
			map.from(authzProperties.getAuthorizationParamName()).to(authenticationFilter::setAuthorizationParamName);
			map.from(authzProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authzProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			
			// 对过滤链按过滤器名称进行分组
			List<Entry<String, String>> noneEntries = bizProperties.getFilterChainDefinitionMap().entrySet().stream()
					.filter(predicate -> {
						return "anon".equalsIgnoreCase(predicate.getValue());
					}).collect(Collectors.toList());
   			
   			List<String> ignorePatterns = new ArrayList<String>();
   			if (!CollectionUtils.isEmpty(noneEntries)) {
   				ignorePatterns = noneEntries.stream().map(mapper -> {
   					return mapper.getKey();
   				}).collect(Collectors.toList());
   			}
   			// 登录地址不拦截 
   			ignorePatterns.add(authcProperties.getPathPattern());
			authenticationFilter.setIgnoreRequestMatcher(ignorePatterns);
			
	        return authenticationFilter;
	    }

		@Bean
		@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 80)
		public SecurityFilterChain jwtAuthzSecurityFilterChain(HttpSecurity http) throws Exception {

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
