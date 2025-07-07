package com.aceup.user.config;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.aceup.user.security.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {

	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;

	public JwtFilter(JwtService jwtService, UserDetailsService userDetailsService) {
		this.jwtService = jwtService;
		this.userDetailsService = userDetailsService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		final String authHeader = request.getHeader("Authorization");
		final String token;
		final String email;

		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}

		// Step 3: Extract token and email
		token = authHeader.substring(7); // Remove "Bearer "
		email = jwtService.extractEmail(token);

		// Step 4: If user not yet authenticated
		if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			var userDetails = userDetailsService.loadUserByUsername(email);

			if (jwtService.isValid(token, email)) {
				// Step 5: Set Authentication
				var authToken = new UsernamePasswordAuthenticationToken(userDetails, null,
						userDetails.getAuthorities());

				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}

		// Step 6: Continue filter chain
		filterChain.doFilter(request, response);
	}

}
