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
package org.springframework.security.boot.jwt.authentication.server;

import com.github.hiwepy.jwt.JwtClaims;
import com.github.hiwepy.jwt.JwtPayload;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationToken;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtExpiredException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtInvalidException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * 3、JWT Authentication Manager For Reactive （负责校验 Authentication 对象）
 */
public class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager  {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
	private final JwtPayloadRepository payloadRepository;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private boolean checkExpiry = false;
    private boolean checkPrincipal = false;
    
    public JwtReactiveAuthenticationManager(final JwtPayloadRepository payloadRepository) {
        this.payloadRepository = payloadRepository;
    }
    
	@Override
    public Mono<Authentication> authenticate(Authentication authentication) {
		
		Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
    	
    	String xuid = (String) authentication.getPrincipal();
        String token = (String) authentication.getCredentials();

		if (StringUtils.isBlank(token)) {
			logger.debug("No JWT found in request.");
			throw new AuthenticationJwtNotFoundException("No JWT found in request.");
		}
		
		JwtAuthorizationToken jwtToken = (JwtAuthorizationToken) authentication;
		
		// 检查token有效性
		if(this.isCheckExpiry() && !getPayloadRepository().verify(jwtToken, isCheckExpiry())) {
			throw new AuthenticationJwtExpiredException("Token Expired");
		}
		
		// 解析Token载体信息
		JwtPayload payload = getPayloadRepository().getPayload(jwtToken, checkExpiry);
		
		// 如果 checkPrincipal = true; 则需要验证 X-Uid 值是否有效即传递的值是否和Token中的值相同
		if(this.isCheckPrincipal() && !StringUtils.equals(xuid, payload.getSubject())) {
			throw new AuthenticationJwtInvalidException("Token Invalid");
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
        
        return Mono.justOrEmpty(authenticationToken);
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
