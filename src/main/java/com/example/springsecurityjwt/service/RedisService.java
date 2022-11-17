package com.example.springsecurityjwt.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class RedisService {

    private final Long REFRESH_TOKEN_EXPIRE;
    private final RedisTemplate<String, Object> redisTemplate;


    public RedisService(@Value("${jwt.refreshTokenExpire}") Long refreshTokenExpire, RedisTemplate<String, Object> redisTemplate) {
        REFRESH_TOKEN_EXPIRE = refreshTokenExpire;
        this.redisTemplate = redisTemplate;
    }

    public void setRefreshToken(String key, Object value) {
        redisTemplate.opsForValue().set(key, value, REFRESH_TOKEN_EXPIRE, TimeUnit.MILLISECONDS);
    }

    public Object getRefreshToken(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    public void deleteData(String key) {
        redisTemplate.delete(key);
    }
}
