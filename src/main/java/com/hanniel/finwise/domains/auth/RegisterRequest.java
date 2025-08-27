package com.hanniel.finwise.domains.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Email é obrigatório")
        @Size(min=10, message = "Email não válido")
        @Email(message = "Precisa ser um Email")
        String email,

        @NotBlank()
        @Size(min=8, message = "Senha precisa ter no mínimo 8 characters")
        String password,

        String role
) {
}
