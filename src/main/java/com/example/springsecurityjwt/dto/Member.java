package com.example.springsecurityjwt.dto;

import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.io.Serializable;
import java.time.LocalDateTime;

@Getter
@RedisHash(value = "members", timeToLive = 30)
public class Member implements Serializable {
    @Id
    private String userId;

    public Member(String userId) {
        this.userId = userId;
    }
}
