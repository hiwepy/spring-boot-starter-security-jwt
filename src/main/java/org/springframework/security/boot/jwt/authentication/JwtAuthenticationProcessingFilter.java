package org.springframework.security.boot.jwt.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Jwt认证 (authentication)过滤器
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class JwtAuthenticationProcessingFilter extends PostRequestAuthenticationProcessingFilter {
	
	public JwtAuthenticationProcessingFilter(ObjectMapper objectMapper) {
		super(objectMapper, new AntPathRequestMatcher("/login/jwt", "POST"));
	}
	
	@Override
	protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
		super.setDetails(request, authRequest);
		JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authRequest;
		jwtToken.setLongitude(this.obtainLongitude(request));
		jwtToken.setLatitude(this.obtainLatitude(request));
		jwtToken.setSign(this.obtainSign(request));
	}
	
	@Override
	protected AbstractAuthenticationToken authenticationToken(String username, String password) {
		return new JwtAuthenticationToken( username, password);
	}
	
}
