package com.aceup.user.dto;

public record RegisterResponse(String token, String name, String email, String role) {
}
