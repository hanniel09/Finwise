package com.hanniel.finwise.services.auth;

import com.hanniel.finwise.domains.auth.*;
import com.hanniel.finwise.exceptions.auth.AuthenticationFailedException;
import com.hanniel.finwise.exceptions.auth.UsernameExistsException;
import com.hanniel.finwise.repositories.auth.RefreshTokenRepository;
import com.hanniel.finwise.repositories.auth.UserCredentialsRepository;
import com.hanniel.finwise.repositories.users.UserProfileRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserProfileRepository userProfileRepository;
    private final UserCredentialsRepository userCredentialsRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authManager;
    private final PasswordEncoder passwordEncoder;

    private final PersistentTokenRepository persistentTokenRepository;
    private final RefreshTokenService refreshTokenService;

    @Value("${security.remember-me.token-validity-seconds}")
    private int rememberMeTokenValiditySeconds;

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

    public AuthResponse login(LoginRequest request, boolean remember, HttpServletResponse response) {
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

        if(remember) {
            createPersistentLoginCookie(user.getEmail(), response);
        }

        refreshTokenService.createAndSetRefreshToken(user, response, remember);

        return new AuthResponse(token, profileComplete);
    }

    private void createPersistentLoginCookie(String username, HttpServletResponse response) {
        String series = UUID.randomUUID().toString();
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        String tokenValue = Base64.getUrlEncoder().withoutPadding().encodeToString(random);

        PersistentRememberMeToken persistentToken =
                new PersistentRememberMeToken(username, series, tokenValue, new Date());
        persistentTokenRepository.createNewToken(persistentToken);

        String cookieValue = series + ":" + tokenValue;
        Cookie cookie = new Cookie("remember-me", cookieValue);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(rememberMeTokenValiditySeconds);
        cookie.setSecure(true);
        response.addCookie(cookie);
    }

    public void logoutAndRemoveRememberMe(String username, String rawRefresh, boolean allSessions, HttpServletResponse response) {

        if (rawRefresh != null && !rawRefresh.isBlank()) {
            refreshTokenService.revokeByRaw(rawRefresh);
        }

        if (allSessions && username != null) {
            userCredentialsRepository.findByEmail(username).ifPresent(user ->
                    refreshTokenService.revokeAllForUser(user.getId()));
        }

        ResponseCookie cookie = ResponseCookie.from("remember-me", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(Duration.ZERO)
                .sameSite("Strict")
                .build();

        if(username != null) {
            try {
                persistentTokenRepository.removeUserTokens(username);
            } catch (Exception ignored){

            }
        }
    }
}
