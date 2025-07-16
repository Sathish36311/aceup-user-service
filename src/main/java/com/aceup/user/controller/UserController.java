package com.aceup.user.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.aceup.user.dto.LoginRequest;
import com.aceup.user.dto.LoginResponse;
import com.aceup.user.dto.RegisterRequest;
import com.aceup.user.dto.RegisterResponse;
import com.aceup.user.dto.RoleUpdateRequest;
import com.aceup.user.dto.UserDTO;
import com.aceup.user.service.UserService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/users")
public class UserController {

	private final UserService userService;

	public UserController(UserService userService) {
		this.userService = userService;
	}

	@PostMapping("/register")
	public RegisterResponse register(@RequestBody @Valid RegisterRequest user) {
		return userService.register(user);
	}

	@PostMapping("/login")
	public LoginResponse login(@RequestBody @Valid LoginRequest request) {
		return userService.login(request);
	}

	@PutMapping("/update-role/{id}")
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	public ResponseEntity<?> updateRole(@PathVariable Long id, @RequestBody RoleUpdateRequest request) {
		return ResponseEntity.ok(userService.updateUserRole(id, request.role()));
	}

	@GetMapping("/{id}")
	@PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_COACH', 'ROLE_PLAYER')")
	public ResponseEntity<?> getUserById(@PathVariable Long id) {
		UserDTO user = userService.getUserById(id);
		return ResponseEntity.ok(user);
	}
}
