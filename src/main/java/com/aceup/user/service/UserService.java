package com.aceup.user.service;

import java.util.Optional;

import com.aceup.user.dto.LoginRequest;
import com.aceup.user.dto.LoginResponse;
import com.aceup.user.dto.RegisterRequest;
import com.aceup.user.dto.RegisterResponse;
import com.aceup.user.model.User;
import com.aceup.user.security.Role;

public interface UserService {
	Optional<User> findByEmail(String email);

	RegisterResponse register(RegisterRequest user);

	LoginResponse login(LoginRequest request);

	User updateUserRole(Long id, Role newRole);

	User getUserById(Long id);

}
