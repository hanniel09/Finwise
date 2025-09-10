package com.hanniel.finwise.services.auth;

import com.hanniel.finwise.domains.auth.RefreshToken;
import com.hanniel.finwise.domains.auth.RefreshTokenType;
import com.hanniel.finwise.domains.auth.UserCredentials;
import com.hanniel.finwise.repositories.auth.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${security.refresh-token-validity-seconds}")
    private long refreshTokenValiditySeconds;

    @Value("${security.remember-me.cookie-name}")
    private String cookieName;

    @Value("${security.remember-me.secure}")
    private boolean cookieSecure;

    @Value("${security.remember-me.same-site}")
    private String sameSite;

    @Transactional
    public void createAndSetRefreshToken(UserCredentials user, HttpServletResponse response, boolean remember)  {
        RefreshTokenType type = remember ? RefreshTokenType.REMEMBER : RefreshTokenType.SESSION;
        long ttlSeconds = remember ? refreshTokenValiditySeconds : 8L * 3600;
        String raw = UUID.randomUUID().toString();
        String hash = hashToken(raw);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUuid(UUID.randomUUID());
        refreshToken.setUser(user);
        refreshToken.setTokenHash(hash);
        refreshToken.setExpiresAt(Instant.now().plusSeconds(ttlSeconds));
        refreshToken.setRevoked(false);
        refreshToken.setType(type);
        refreshTokenRepository.save(refreshToken);

        ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie.from(cookieName, raw)
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/");
        if(type == RefreshTokenType.REMEMBER) {
            cookieBuilder.maxAge(Duration.ofSeconds(ttlSeconds));
            cookieBuilder.sameSite(sameSite);
        } else {
            cookieBuilder.sameSite(sameSite);
        }

        response.addHeader(HttpHeaders.SET_COOKIE, cookieBuilder.build().toString());
    }

    public UserCredentials validateAndGetUserFromRawToken(String rawToken) {
        String hash = hashToken(rawToken);
        return refreshTokenRepository.findByTokenHash(hash)
                .filter(rt -> !rt.isRevoked() && rt.getExpiresAt().isAfter(Instant.now()))
                .map(RefreshToken::getUser)
                .orElse(null);
    }

    @Transactional
    public void revokeByRaw(String rawToken) {
        String hash = hashToken(rawToken);
        refreshTokenRepository.findByTokenHash(hash).ifPresent(rt -> {
            rt.setRevoked(true);
            refreshTokenRepository.save(rt);
        });
    }

    @Transactional
    public void revokeAllForUser(UUID userId) {
        var tokens = refreshTokenRepository.findByUserIdAndRevokedFalse(userId);
        tokens.forEach(t -> t.setRevoked(true));
        refreshTokenRepository.saveAll(tokens);
    }

    public Optional<RefreshToken> findByRaw(String rawToken){
        String hashed = hashToken(rawToken);
        return refreshTokenRepository.findByTokenHash(hashed);
    }

    private String hashToken(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
