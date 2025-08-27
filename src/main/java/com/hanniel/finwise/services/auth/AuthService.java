package com.hanniel.finwise.services.auth;

import com.hanniel.finwise.domains.auth.*;
import com.hanniel.finwise.exceptions.auth.AuthenticationFailedException;
import com.hanniel.finwise.exceptions.auth.UsernameExistsException;
import com.hanniel.finwise.repositories.auth.UserCredentialsRepository;
import com.hanniel.finwise.repositories.users.UserProfileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserProfileRepository userProfileRepository;
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

        Role role = Role.USER;
        if (request.role() != null && !request.role().isBlank()) {
            String raw = request.role().trim();
            try {
                role = Role.valueOf(raw.toUpperCase());
            } catch (IllegalArgumentException ex) {
                role = Arrays.stream(Role.values())
                        .filter(r -> r.getRole().equalsIgnoreCase(raw))
                        .findFirst()
                        .orElse(Role.USER);
            }
        }

        user.setRole(role);
        userCredentialsRepository.save(user);

        return new AuthResponse(jwtService.generateRegistrationToken(user), false);
    }

    public AuthResponse login(LoginRequest request) {
        try {
            authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password())
            );
        } catch (AuthenticationException e) {
            throw new AuthenticationFailedException("Invalid email or password");
        }

        UserCredentials user = userCredentialsRepository.findByEmail(request.email()).orElseThrow(
                () -> new UsernameNotFoundException("User not found")
        );

        boolean profileComplete = userProfileRepository.findByCredentialsId(user.getId()).isPresent();

        String token = jwtService.generateAccessToken(user);
        return new AuthResponse(token, profileComplete);
    }

}
