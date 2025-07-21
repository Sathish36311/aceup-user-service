package com.aceup.user.service_impl;

import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.aceup.user.dto.LoginRequest;
import com.aceup.user.dto.LoginResponse;
import com.aceup.user.dto.RegisterRequest;
import com.aceup.user.model.User;
import com.aceup.user.repository.UserRepository;
import com.aceup.user.security.CookieService;
import com.aceup.user.security.JwtService;
import com.aceup.user.security.RedisService;
import com.aceup.user.security.Role;
import com.aceup.user.service.UserService;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final CookieService cookieService;
	private final RedisService redisService;

	public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService,
			CookieService cookieService, RedisService redisTokenService) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.cookieService = cookieService;
		this.redisService = redisTokenService;
	}

	@Override
	public Optional<User> findByEmail(String email) {
		return userRepository.findByEmail(email);
	}

	@PostConstruct
	public void seedAdmin() {
		if (userRepository.findByEmail("sathishkrishnan369@gmail.com").isEmpty()) {
			User admin = User.builder().username("Sathish").email("sathishkrishnan369@gmail.com")
					.password(passwordEncoder.encode("Sathish7*")).role(Role.ROLE_ADMIN).build();
			userRepository.save(admin);
		}
	}

//	@Override
//	@CacheEvict(value = "users", key = "#id")
//	public User updateUserRole(Long id, Role newRole) {
//		User user = userRepository.findById(id).orElseThrow(() -> new UsernameNotFoundException("User not found!"));
//		user.setRole(newRole);
//		return userRepository.save(user);
//	}
//
//	@Override
//	@Cacheable(value = "users", key = "#id")
//	public UserDTO getUserById(Long id) {
//		User user = userRepository.findById(id).orElseThrow(() -> new UsernameNotFoundException("User not found!"));
//		return new UserDTO(user.getId(), user.getUsername(), user.getEmail());
//	}

	@Override
	public LoginResponse register(RegisterRequest request, HttpServletResponse response) {
		if (userRepository.existsByEmail(request.email())) {
			throw new RuntimeException("Email already in use");
		}
		User user = User.builder().username(request.name()).email(request.email())
				.password(passwordEncoder.encode(request.password()))
				.role(Role.valueOf(request.role() != null ? request.role() : "ROLE_FAN")).build();

		userRepository.save(user);

		// Generate tokens
		String accessToken = jwtService.generateAccessToken(user);
		String refreshToken = jwtService.generateRefreshToken(user);

		// Store refresh token in Redis
		redisService.storeRefreshToken(user.getUsername(), refreshToken);

		// Set cookies
		cookieService.setRefreshTokenCookie(response, refreshToken);

		return new LoginResponse(accessToken, user.getUsername(), user.getEmail(), user.getRole());
	}

	@Override
	public LoginResponse login(LoginRequest request, HttpServletResponse response) {

		User user = userRepository.findByEmail(request.email())
				.orElseThrow(() -> new RuntimeException("Invalid Email Id"));

		if (!passwordEncoder.matches(request.password(), user.getPassword())) {
			System.out.println("Error Should be handled properly");
			throw new RuntimeException("Invalid Password");
		}

		// Generate tokens
		String accessToken = jwtService.generateAccessToken(user);
		String refreshToken = jwtService.generateRefreshToken(user);

		// Store refresh token in Redis
		redisService.storeRefreshToken(user.getUsername(), refreshToken);

		// Set cookies
		cookieService.setRefreshTokenCookie(response, refreshToken);

		return new LoginResponse(accessToken, user.getUsername(), user.getEmail(), user.getRole());
	}

	@Override
	public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
		try {
			// 1. Extract refresh token from cookie
			String refreshToken = cookieService.getTokenFromCookies(request, "refresh_token");
			if (refreshToken == null) {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token is missing");
			}

			// 2. Extract email (subject) from token
			String username = jwtService.getUsername(refreshToken);
			if (username == null) {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token - cannot extract user");
			}

			// 3. Load user
			User user = userRepository.findByUsername(username)
					.orElseThrow(() -> new UsernameNotFoundException("User not found"));

			// 4. Validate refresh token from Redis
			String storedRefreshToken = redisService.getRefreshToken(user.getUsername());
			if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is not valid or has been rotated");
			}

			// 5. Validate token (signature, expiry, etc.)
			if (!jwtService.isTokenValid(refreshToken, user)) {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
			}

			// 6. Generate new access token and refresh token
			String newAccessToken = jwtService.generateAccessToken(user);
			String newRefreshToken = jwtService.generateRefreshToken(user);

			redisService.storeRefreshToken(user.getUsername(), newRefreshToken);
			cookieService.setRefreshTokenCookie(response, newRefreshToken);

			return ResponseEntity.ok().body(Map.of("accessToken", newAccessToken));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("Failed to refresh token: " + e.getMessage());
		}
	}

	@Override
	public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
		String refreshToken = cookieService.getTokenFromCookies(request, "refresh_token");
		if (refreshToken == null) {
			return ResponseEntity.badRequest().body("Refresh token missing");
		}

		String username;
		try {
			username = jwtService.getUsername(refreshToken);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
		}

		// Remove refresh token from Redis
		redisService.removeRefreshToken(username);

		// Clear cookies (optional but recommended)
		cookieService.clearAuthCookies(response);

		return ResponseEntity.ok().body(Map.of("message", "Logout Successfully"));
	}

}
