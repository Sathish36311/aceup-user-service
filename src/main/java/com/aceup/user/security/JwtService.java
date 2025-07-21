package com.aceup.user.security;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	@Value("${jwt.secret}")
	private String secretKey;

	@Value("${jwt.access-expiration}")
	private long ACCESS_EXPIRATION;

	@Value("${jwt.refresh-expiration}")
	private long REFRESH_EXPIRATION;

	private Key getSigningKey() {
		return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
	}

	private String buildToken(UserDetails user, long expiration) {
		return Jwts.builder().setSubject(user.getUsername()).setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + expiration)).signWith(getSigningKey()).compact();
	}

	public String generateAccessToken(UserDetails user) {
		return buildToken(user, ACCESS_EXPIRATION);
	}

	public String generateRefreshToken(UserDetails user) {
		return buildToken(user, REFRESH_EXPIRATION);
	}

	public String getUsername(String token) {
		return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody().getSubject();
	}

	public boolean isTokenExpired(String token) {
		return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody()
				.getExpiration().before(new Date());
	}

	public boolean isTokenValid(String token, UserDetails user) {
		final String username = getUsername(token);
		return username.equals(user.getUsername()) && !isTokenExpired(token);
	}

}
