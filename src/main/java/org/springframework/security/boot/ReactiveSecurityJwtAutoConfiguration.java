package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.authentication.server.*;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;

@Configuration
@AutoConfigureBefore({ ReactiveSecurityAutoConfiguration.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class, SecurityJwtAuthzProperties.class })
public class ReactiveSecurityJwtAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedServerAuthenticationEntryPoint jwtMatchedServerAuthenticationEntryPoint() {
		return new JwtMatchedServerAuthenticationEntryPoint();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedServerAuthenticationFailureHandler jwtMatchedServerAuthenticationFailureHandler() {
		return new JwtMatchedServerAuthenticationFailureHandler();
	}

	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedServerAuthenticationSuccessHandler jwtMatchedServerAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new JwtMatchedServerAuthenticationSuccessHandler(payloadRepository, true);
	}

	@Bean
	@ConditionalOnMissingBean
	public JwtPayloadRepository payloadRepository() {
		return new JwtPayloadRepository() {};
	}
	
	/**
	 * 1、JWT Authorization Security Context Repository For Reactive （负责提取Token，构造 SecurityContext 对象）
	 * @param authenticationManager
	 * @return
	 */
	@Bean
	@ConditionalOnMissingBean
	public ServerSecurityContextRepository jwtServerSecurityContextRepository(ReactiveAuthenticationManager authenticationManager) {
		return new JwtServerAuthorizationSecurityContextRepository(authenticationManager, "/webjars/**");
	}
	
	/**
	 * 2、JWT Authentication Converter For Reactive  （负责提取Token）
	 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
	 * @return
	 */
	@Bean
	@ConditionalOnMissingBean
	public ServerAuthenticationConverter jwtServerAuthenticationConverter() {
		return new JwtServerAuthenticationConverter();
	}
	
	 /**
	  * 3、JWT Authentication Manager For Reactive （负责校验 Authentication 对象）
	  * TODO
	  * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
	  * @param payloadRepository
	  * @return
	  */
	@Bean
	@ConditionalOnMissingBean
	public ReactiveAuthenticationManager jwtReactiveAuthenticationManager(JwtPayloadRepository payloadRepository, SecurityJwtAuthzProperties jwtAuthzProperties) {
		JwtReactiveAuthenticationManager jwtAuthenticationManager = new JwtReactiveAuthenticationManager(payloadRepository);
		jwtAuthenticationManager.setCheckExpiry(jwtAuthzProperties.isCheckExpiry());
		jwtAuthenticationManager.setCheckPrincipal(jwtAuthzProperties.isCheckPrincipal());
		return  jwtAuthenticationManager;
	}
	
	/* @Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
			ReactiveAuthenticationManager authenticationManager,
			ServerSecurityContextRepository securityContextRepository,
			ServerAuthenticationConverter authenticationConverter,
			ServerAuthenticationSuccessHandler authenticationSuccessHandler, 
			ServerAuthenticationFailureHandler authenticationFailureHandler,
			ServerLogoutSuccessHandler logoutHandler) {
    	
		
		JwtAuthenticationWebFilter jwtFilter = new JwtAuthenticationWebFilter(authenticationManager);
		
		jwtFilter.setServerAuthenticationConverter(authenticationConverter);
		jwtFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
		jwtFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
		jwtFilter.setSecurityContextRepository(securityContextRepository);
		
		return http
				.csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .securityContextRepository(securityContextRepository)
                .authorizeExchange() 
                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                .pathMatchers(AUTH_WHITELIST).permitAll()
                //.anyExchange().permitAll()
                .anyExchange().authenticated()
               .and()
               .addFilterAfter(jwtFilter, SecurityWebFiltersOrder.FIRST)  // 这里注意执行位置一定要在securityContextRepository
               .logout()
               .logoutUrl("/authz/logout")
               .logoutSuccessHandler(logoutHandler)
               .and()
               .build();
	}*/

}
