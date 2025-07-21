package com.aceup.user.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class CookieService {

	@Value("${jwt.access-expiration}")
	private long ACCESS_EXPIRATION;

	@Value("${jwt.refresh-expiration}")
	private long REFRESH_EXPIRATION;

	public void setAccessTokenCookie(HttpServletResponse response, String token) {
		ResponseCookie cookie = ResponseCookie.from("access_token", token).httpOnly(true).path("/")
				.maxAge(ACCESS_EXPIRATION / 1000).build();
		response.addHeader("Set-Cookie", cookie.toString());
	}

	public void setRefreshTokenCookie(HttpServletResponse response, String token) {
		ResponseCookie cookie = ResponseCookie.from("refresh_token", token).httpOnly(true).path("/")
				.maxAge(REFRESH_EXPIRATION / 1000).build();
		response.addHeader("Set-Cookie", cookie.toString());
	}

	public void clearAuthCookies(HttpServletResponse response) {
		ResponseCookie access = ResponseCookie.from("access_token", "").httpOnly(true).path("/").maxAge(0).build();
		ResponseCookie refresh = ResponseCookie.from("refresh_token", "").httpOnly(true).path("/").maxAge(0).build();

		response.addHeader("Set-Cookie", access.toString());
		response.addHeader("Set-Cookie", refresh.toString());
	}

	public String getTokenFromCookies(HttpServletRequest request, String cookieName) {
		if (request.getCookies() == null)
			return null;
		for (Cookie cookie : request.getCookies()) {
			if (cookieName.equals(cookie.getName())) {
				return cookie.getValue();
			}
		}
		return null;
	}
}
