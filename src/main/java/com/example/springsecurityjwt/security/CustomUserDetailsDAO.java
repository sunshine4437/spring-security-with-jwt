package com.example.springsecurityjwt.security;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface CustomUserDetailsDAO {
    public CustomUserDetails loadUserByUsername(String username);
}
