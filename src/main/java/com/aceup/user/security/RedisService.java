package com.aceup.user.security;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class RedisService {

	@Value("${jwt.refresh-expiration}")
	private long REFRESH_EXPIRATION;

	@Value("${jwt.access-expiration}")
	private long ACCESS_EXPIRATION;

	private final RedisTemplate<String, String> redisTemplate;

	private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";

	public RedisService(RedisTemplate<String, String> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}

	public void storeRefreshToken(String username, String refreshToken) {
		redisTemplate.opsForValue().set(REFRESH_TOKEN_PREFIX + username, refreshToken, REFRESH_EXPIRATION,
				TimeUnit.MILLISECONDS);
	}

	public String getRefreshToken(String username) {
		return redisTemplate.opsForValue().get(REFRESH_TOKEN_PREFIX + username);
	}

	public boolean isRefreshTokenValid(String username, String token) {
		String storedToken = redisTemplate.opsForValue().get(username);
		return token.equals(storedToken);
	}

	public void removeRefreshToken(String username) {
		redisTemplate.delete(REFRESH_TOKEN_PREFIX + username);
	}

}
