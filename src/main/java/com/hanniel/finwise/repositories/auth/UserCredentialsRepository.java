package com.hanniel.finwise.repositories.auth;

import com.hanniel.finwise.domains.auth.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserCredentialsRepository extends JpaRepository<UserCredentials, UUID> {

    Optional<UserCredentials> findByEmail(String email);
}
