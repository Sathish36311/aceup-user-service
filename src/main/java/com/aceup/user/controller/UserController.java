package com.aceup.user.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.aceup.user.dto.LoginRequest;
import com.aceup.user.dto.LoginResponse;
import com.aceup.user.dto.RegisterRequest;
import com.aceup.user.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
public class UserController {

	private final UserService userService;

	public UserController(UserService userService) {
		this.userService = userService;
	}

	@PostMapping("/register")
	public ResponseEntity<LoginResponse> register(@RequestBody @Valid RegisterRequest request, HttpServletResponse response) {
		LoginResponse registerResponse = userService.register(request, response);
		return ResponseEntity.ok(registerResponse);
	}

	@PostMapping("/login")
	public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest request, HttpServletResponse response) {
		LoginResponse loginResponse = userService.login(request, response);
		return ResponseEntity.ok(loginResponse);
	}
		
	@PostMapping("/refresh-token")
	public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
		ResponseEntity<?> refreshToken = userService.refreshToken(request, response);
		return ResponseEntity.ok(refreshToken);
	}

	@PostMapping("/logout")
	public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
		ResponseEntity<?> logout = userService.logout(request, response);
		return ResponseEntity.ok(logout);
	}
//

//
//	@PutMapping("/update-role/{id}")
//	@PreAuthorize("hasRole('ROLE_ADMIN')")
//	public ResponseEntity<?> updateRole(@PathVariable Long id, @RequestBody RoleUpdateRequest request) {
//		return ResponseEntity.ok(userService.updateUserRole(id, request.role()));
//	}
//
//	@GetMapping("/{id}")
//	@PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_COACH', 'ROLE_PLAYER')")
//	public ResponseEntity<?> getUserById(@PathVariable Long id) {
//		UserDTO user = userService.getUserById(id);
//		return ResponseEntity.ok(user);
//	}
}
