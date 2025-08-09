package com.hanniel.finwise.domains.auth;

public record LoginRequest(
        String email,
        String password
) {
}
