package org.springframework.security.boot.jwt.authentication;

import com.github.hiwepy.jwt.JwtClaims;
import com.github.hiwepy.jwt.JwtPayload;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtExpiredException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * 
 * Jwt授权 (authorization)处理器
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class JwtAuthorizationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
	private final JwtPayloadRepository payloadRepository;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private boolean checkExpiry = false;
    private boolean checkPrincipal = false;
    
    public JwtAuthorizationProvider(final JwtPayloadRepository payloadRepository) {
        this.payloadRepository = payloadRepository;
    }

    /**
     * 
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author 		：<a href="https://github.com/hiwepy">wandl</a>
     * @param authentication  {@link JwtAuthenticationToken} 对象
     * @return 认证结果{@link JwtAuthenticationToken}对象
     * @throws AuthenticationException 认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
    	
    	//String uid = (String) authentication.getPrincipal();
        String token = (String) authentication.getCredentials();

        if (StringUtils.isBlank(token)) {
			logger.debug("No JWT found in request.");
			throw new AuthenticationJwtNotFoundException("No JWT found in request.");
		}
		
		JwtAuthorizationToken jwtToken = (JwtAuthorizationToken) authentication;
		
		// 检查token有效性
		if(isCheckExpiry() && !getPayloadRepository().verify(jwtToken, isCheckExpiry())) {
			throw new AuthenticationJwtExpiredException("Token Expired");
		}
		
		// 解析Token载体信息
		JwtPayload payload = getPayloadRepository().getPayload(jwtToken, checkExpiry);

		// 检查token有效性
		if(this.isCheckExpiry() && !getPayloadRepository().verify(jwtToken, isCheckExpiry())) {
			throw new AuthenticationJwtExpiredException("Token Expired");
		}
		
		Set<GrantedAuthority> grantedAuthorities = new HashSet<GrantedAuthority>();
		
		// 角色必须是ROLE_开头，可以在数据库中设置
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_"+ payload.getRkey());
        grantedAuthorities.add(grantedAuthority);
   		
   		// 用户权限标记集合
   		Set<String> perms = payload.getPerms();
		for (String perm : perms ) {
			GrantedAuthority authority = new SimpleGrantedAuthority(perm);
            grantedAuthorities.add(authority);
		}
		
		Map<String, Object> claims = payload.getClaims();
		
		String uid = StringUtils.defaultString(MapUtils.getString(claims, JwtClaims.UID), payload.getSubject());
		
		SecurityPrincipal principal = new SecurityPrincipal(uid, payload.getTokenId(), payload.isEnabled(),
				payload.isAccountNonExpired(), payload.isCredentialsNonExpired(), payload.isAccountNonLocked(),
				grantedAuthorities);
	
		principal.setUid(uid);
		principal.setUuid(payload.getUuid());
		principal.setUkey(payload.getUkey());
		principal.setUcode(payload.getUcode());
		principal.setPerms(new HashSet<String>(perms));
		principal.setRid(payload.getRid());
		principal.setRkey(payload.getRkey());
		principal.setRoles(payload.getRoles());
		principal.setBound(payload.isBound());
		principal.setInitial(payload.isInitial());
		principal.setProfile(payload.getProfile());
		principal.setSign(jwtToken.getSign());
		principal.setLongitude(jwtToken.getLongitude());
		principal.setLatitude(jwtToken.getLatitude());
		
        // User Status Check
        getUserDetailsChecker().check(principal);
        
        JwtAuthorizationToken authenticationToken = new JwtAuthorizationToken(principal, payload, principal.getAuthorities());        	
        authenticationToken.setDetails(authentication.getDetails());
        
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthorizationToken.class.isAssignableFrom(authentication));
    }
    
    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	public JwtPayloadRepository getPayloadRepository() {
		return payloadRepository;
	}

	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}

	public boolean isCheckPrincipal() {
		return checkPrincipal;
	}

	public void setCheckPrincipal(boolean checkPrincipal) {
		this.checkPrincipal = checkPrincipal;
	}
    
}
