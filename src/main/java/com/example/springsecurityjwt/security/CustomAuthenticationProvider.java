package com.example.springsecurityjwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final CustomUserDetailsService customUserDetailsService;

    public CustomAuthenticationProvider(@Qualifier("customUserDetailsService") CustomUserDetailsService customUserDetailsService) {
        this.customUserDetailsService = customUserDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String name = authentication.getName();
        String password = authentication.getCredentials().toString();
//        System.out.println(name + " " + password);
//        password = new BCryptPasswordEncoder().encode(password);

        CustomUserDetails customUserDetails = (CustomUserDetails) customUserDetailsService.loadUserByUsername(name);
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        /*
            UsernameNotFoundException
            BaUsernameNotFoundException
            AccountExpiredException
            CredentialsExpiredException
            DisabledException
            LockedException
        */

        if (customUserDetails == null) {
            throw new UsernameNotFoundException("계정 정보가 없습니다.");
        }
        if (!passwordEncoder.matches(password, customUserDetails.getPassword())) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
        }

        return new UsernamePasswordAuthenticationToken(customUserDetails, authentication.getCredentials(), customUserDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
