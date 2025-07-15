package com.aceup.user.service_impl;

import java.util.Optional;

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.aceup.user.dto.LoginRequest;
import com.aceup.user.dto.LoginResponse;
import com.aceup.user.dto.RegisterRequest;
import com.aceup.user.dto.RegisterResponse;
import com.aceup.user.model.User;
import com.aceup.user.repository.UserRepository;
import com.aceup.user.security.JwtService;
import com.aceup.user.security.Role;
import com.aceup.user.service.UserService;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;

	public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
	}

	@Override
	public Optional<User> findByEmail(String email) {
		return userRepository.findByEmail(email);
	}

	@Override
	public RegisterResponse register(RegisterRequest request) {
		User user = User.builder().name(request.name()).email(request.email())
				.password(passwordEncoder.encode(request.password()))
				.role(Role.valueOf(request.role() != null ? request.role() : "ROLE_FAN")).build();

		userRepository.save(user);
		String token = jwtService.generateToken(request.email());
		return new RegisterResponse(token, user.getName(), user.getEmail(), user.getRole().name());

	}

	@Override
	public LoginResponse login(LoginRequest request) {
		User user = userRepository.findByEmail(request.email())
				.orElseThrow(() -> new RuntimeException("Invalid email"));

		if (!passwordEncoder.matches(request.password(), user.getPassword())) {
			throw new BadCredentialsException("Invalid password");
		}
		String token = jwtService.generateToken(request.email());
		return new LoginResponse(token, user.getName(), user.getEmail(), user.getRole().name());
	}

	@PostConstruct
	public void seedAdmin() {
		if (userRepository.findByEmail("sathishkrishnan369@gmail.com").isEmpty()) {
			User admin = User.builder().name("Sathish").email("sathishkrishnan369@gmail.com")
					.password(passwordEncoder.encode("Sathish7*")).role(Role.ROLE_ADMIN).build();
			userRepository.save(admin);
		}
	}

	@Override
	@CacheEvict(value = "users", key = "#id")
	public User updateUserRole(Long id, Role newRole) {
		User user = userRepository.findById(id).orElseThrow(() -> new UsernameNotFoundException("User not found!"));
		user.setRole(newRole);
		return userRepository.save(user);
	}

	@Override
	@Cacheable(value = "users", key = "#id")
	public User getUserById(Long id) {
		log.info("Fetching from DB");
		return userRepository.findById(id).orElseThrow(() -> new UsernameNotFoundException("User not found!"));
	}

}
