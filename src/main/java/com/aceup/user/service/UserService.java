package com.aceup.user.service;

import java.util.Optional;

import org.springframework.http.ResponseEntity;

import com.aceup.user.dto.LoginRequest;
import com.aceup.user.dto.LoginResponse;
import com.aceup.user.dto.RegisterRequest;
import com.aceup.user.model.User;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface UserService {
	Optional<User> findByEmail(String email);

	LoginResponse register(RegisterRequest request, HttpServletResponse response);

	LoginResponse login(LoginRequest request, HttpServletResponse response);

	ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response);

	ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response);

//	void logout(HttpServletRequest request, HttpServletResponse response);
//
//	User updateUserRole(Long id, Role newRole);
//
//	UserDTO getUserById(Long id);
//
//	LoginResponse refreshToken(HttpServletRequest request, HttpServletResponse response);
}
