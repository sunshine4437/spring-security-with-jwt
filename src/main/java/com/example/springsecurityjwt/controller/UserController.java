package com.example.springsecurityjwt.controller;

import com.example.springsecurityjwt.dto.Member;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.security.jwt.JwtTokenProvider;
import com.example.springsecurityjwt.security.jwt.TokenInfo;
import com.example.springsecurityjwt.service.RedisService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    private final Logger logger = LogManager.getLogger(UserController.class);
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RedisService redisService;

    public UserController(JwtTokenProvider jwtTokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder, RedisService redisService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.redisService = redisService;
    }

    @PostMapping(value = "/sign-in")
    public TokenInfo signIn(@RequestBody CustomUserDetails customUserDetails) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(customUserDetails.getUsername(), customUserDetails.getPassword());
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        TokenInfo token = jwtTokenProvider.generateToken(authentication);
        Member member = Member.builder()
                .userId(authentication.getName())
                .token(token.getRefreshToken())
                .build();
        this.redisService.setRefreshToken(member.getUserId(), member);
        Member test = (Member) this.redisService.getRefreshToken(member.getUserId());
        System.out.println(test.getUserId() + " : " + test.getToken());
        return token;
    }

    @GetMapping(value = "/sign-in")
    public String getSignIn() {
        return "sign-in";
    }
}
