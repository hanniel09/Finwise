package com.hanniel.finwise.services.auth;

import com.hanniel.finwise.domains.auth.*;
import com.hanniel.finwise.exceptions.auth.AuthenticationFailedException;
import com.hanniel.finwise.exceptions.auth.UsernameExistsException;
import com.hanniel.finwise.repositories.auth.UserCredentialsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserCredentialsRepository userCredentialsRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authManager;
    private final PasswordEncoder passwordEncoder;

    public AuthResponse register(RegisterRequest request){

        if (userCredentialsRepository.findByEmail(request.email()).isPresent()) {
            throw new UsernameExistsException("Email already in use, please try another email");
        }

        UserCredentials user = new UserCredentials();
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));

        Role role;
        try {
            role = request.role() != null ? Role.valueOf(request.role()) : Role.USER;
        } catch (IllegalArgumentException e) {
            role = Role.USER;
        }

        user.setRole(role);
        userCredentialsRepository.save(user);

        return new AuthResponse(jwtService.generateRegistrationToken(user));
    }

    public AuthResponse login(LoginRequest request) {
        try {
            authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password())
            );
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException("Invalid email or password");
        }

        UserCredentials user = userCredentialsRepository.findByEmail(request.email()).orElseThrow();
        return new AuthResponse(jwtService.generateAccessToken(user));
    }

}
