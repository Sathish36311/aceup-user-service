package com.aceup.user.security;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	@Value("${jwt.secret}")
	private String secretKey;

	@Value("${jwt.expiration}")
	private long EXPIRATION;

	private Key getSigningKey() {
		return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
	}

	public String generateToken(String email) {
		return Jwts.builder().setSubject(email).setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION)).signWith(getSigningKey()).compact();
	}

	public String extractEmail(String token) {
		return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody().getSubject();
	}

	public boolean isValid(String token, String email) {
		try {
			return extractEmail(token).equals(email);
		} catch (Exception e) {
			return false;
		}
	}
}
