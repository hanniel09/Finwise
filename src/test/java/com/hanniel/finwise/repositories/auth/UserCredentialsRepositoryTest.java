package com.hanniel.finwise.repositories.auth;

import com.hanniel.finwise.domains.auth.RegisterRequest;
import com.hanniel.finwise.domains.auth.Role;
import com.hanniel.finwise.domains.auth.UserCredentials;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Optional;

@DataJpaTest
@ActiveProfiles("test")
class UserCredentialsRepositoryTest {

    @Autowired
    EntityManager entityManager;

    @Autowired
    UserCredentialsRepository userCredentialsRepository;

    @Test
    @DisplayName("Find a UserCredentials by email and return true if exists in database")
    void findByEmail() {
        RegisterRequest data = new RegisterRequest("johndoe@email.com", "123456",  "USER");
        this.createUserCredentials(data);

        Optional<UserCredentials> result = this.userCredentialsRepository.findByEmail(data.email());

        assertThat(result.isPresent()).isTrue();
    }

    @Test
    @DisplayName("Failed to find a userCredentials by email that doesn't exits in database")
    void findByEmailAndFail() {
        RegisterRequest data = new RegisterRequest("johndoe@email.com", "123456",  "USER");

        Optional<UserCredentials> result = this.userCredentialsRepository.findByEmail(data.email());

        assertThat(result.isPresent()).isFalse();
    }


    private void createUserCredentials(RegisterRequest data){
        UserCredentials newUser = new UserCredentials();
        newUser.setEmail(data.email());
        newUser.setPassword(data.password());
        newUser.setRole(Role.valueOf(data.role().toUpperCase()));
        this.entityManager.persist(newUser);
    }
}