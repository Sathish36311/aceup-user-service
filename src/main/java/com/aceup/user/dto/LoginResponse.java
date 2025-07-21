package com.aceup.user.dto;

import com.aceup.user.security.Role;

public record LoginResponse(String accessToken, String username, String email, Role role) {}
