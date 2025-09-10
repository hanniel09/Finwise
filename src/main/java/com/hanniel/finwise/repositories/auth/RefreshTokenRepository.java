package com.hanniel.finwise.repositories.auth;

import com.hanniel.finwise.domains.auth.RefreshToken;
import com.hanniel.finwise.domains.auth.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);
    List<RefreshToken> findByUserIdAndRevokedFalse(UUID userId);
}
