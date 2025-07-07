package com.aceup.user.dto;

public record RegisterRequest(String name, String email, String password, String role) {
}
