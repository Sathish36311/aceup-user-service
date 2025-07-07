package com.aceup.user.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.aceup.user.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByEmail(String email);
}
