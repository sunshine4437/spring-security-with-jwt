package com.example.springsecurityjwt.security.config;

import com.example.springsecurityjwt.security.jwt.JwtAccessDeniedHandler;
import com.example.springsecurityjwt.security.jwt.JwtAuthenticationEntryPoint;
import com.example.springsecurityjwt.security.jwt.JwtAuthenticationFilter;
import com.example.springsecurityjwt.security.jwt.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    private final List<String> admin = List.of("/index");
    private final List<String> user = List.of("/main");
    private final List<String> excludeUrlList = new ArrayList<>();

    public SecurityConfig(JwtTokenProvider jwtTokenProvider, JwtAccessDeniedHandler jwtAccessDeniedHandler, JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;

        this.excludeUrlList.addAll(admin);
        this.excludeUrlList.addAll(user);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {


        httpSecurity
                .httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        httpSecurity
                .requestMatchers()
                .antMatchers(excludeUrlList.toArray(String[]::new));

        httpSecurity
                .authorizeHttpRequests()
                .antMatchers(user.toArray(String[]::new)).hasRole("USER")
                .antMatchers(admin.toArray(String[]::new)).hasRole("ADMIN")
                .anyRequest().permitAll();

        httpSecurity
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);


//        httpSecurity
//                .formLogin()
//                .usernameParameter("id")
//                .passwordParameter("pwd")
//                .loginPage("/sign-in")
//                .loginProcessingUrl("/auth/sign-in")
//                .defaultSuccessUrl("/index", true)
//                .failureUrl("/sign-in")
//                .successHandler(new CustomSuccessHandler())
//                .failureHandler(new CustomFailureHandler());

//        httpSecurity
//                .logout()
//                .logoutUrl("/sign-out")
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID")
//                .logoutSuccessUrl("/sign-in");
//        httpSecurity
//                .exceptionHandling().accessDeniedPage("/sign-in");

        httpSecurity
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler);

        return httpSecurity.build();
    }


}
