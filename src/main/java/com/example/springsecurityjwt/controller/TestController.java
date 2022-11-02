package com.example.springsecurityjwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

@RestController
public class TestController {
    @GetMapping(value = "/auth/test")
    public String test(HttpServletResponse response) {
        Cookie cookie = new Cookie("token", "token");
        response.addCookie(cookie);
        return "test";
    }

    @GetMapping(value = "/test1")
    public String test1() {
        return "test1";
    }
    @GetMapping(value = "/test/test2")
    public String test2() {
        return "test2";
    }
}
