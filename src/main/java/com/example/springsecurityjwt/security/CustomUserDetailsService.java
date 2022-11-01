package com.example.springsecurityjwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final CustomUserDetailsDAO customUserDetailsDAO;

    @Autowired
    public CustomUserDetailsService(@Qualifier("customUserDetailsDAO") CustomUserDetailsDAO customUserDetailsDAO) {
        this.customUserDetailsDAO = customUserDetailsDAO;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        try {
            return this.customUserDetailsDAO.loadUserByUsername(username);
        } catch (Exception e) {
            return null;
        }
    }
}
