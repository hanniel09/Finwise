package com.hanniel.finwise.services.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private JwtService jwtService;

    @Mock
    private UserDetails mockUser;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();


        ReflectionTestUtils.setField(jwtService, "secretKey", "test-secret-abc-123");
        ReflectionTestUtils.setField(jwtService, "accessExpiration", 360_000L);
        ReflectionTestUtils.setField(jwtService, "registrationExpiration", 600_000L);
    }

  @Test
  @DisplayName("Should generate a registration token with successfully.")
    void generateRegistrationToken_and_validate_with_successfully(){
        User user = new User("johndoe", "pw", Collections.emptyList());

        String token = jwtService.generateRegistrationToken(user);
        assertThat(token).isNotBlank();


        assertThat(jwtService.isValidRegistrationToken(token, user)).isTrue();
        assertThat(jwtService.isValidAccessToken(token, user)).isFalse();
  }

  @Test
    void generateAccessToken_and_validate_with_successfully(){
      User user = new User("johndoe", "pw",
              List.of(new SimpleGrantedAuthority("ROLE_USER")));

      String token = jwtService.generateAccessToken(user);
      assertThat(token).isNotBlank();

      assertThat(jwtService.extractUsername(token)).isEqualTo("johndoe");
      assertThat(jwtService.isValidAccessToken(token, user)).isTrue();
      assertThat(jwtService.isValidRegistrationToken(token, user)).isFalse();
  }

  @Test
    void token_with_invalid_signature_should_be_invalid(){
        String otherToken = JWT.create()
                .withSubject("johndoe")
                .sign(Algorithm.HMAC256("other-secret"));
        assertThat(jwtService.isValidAccessToken(otherToken, mockUser)).isFalse();
  }

  @Test
    void registration_token_expired_should_be_invalid() throws InterruptedException {
        ReflectionTestUtils.setField(jwtService, "registrationExpiration", 1);
        String token = jwtService.generateRegistrationToken(mockUser);

        Thread.sleep(1000);
        assertThat(jwtService.isValidRegistrationToken(token, mockUser)).isFalse();
  }

  @Test
    void malformed_token_extractUsername_should_throw(){
        String malformed = "this.is.not.a.valid.token";

        assertThatThrownBy(() -> jwtService.extractUsername(malformed))
                .isInstanceOf(Exception.class);
  }
}