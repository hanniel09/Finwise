package com.hanniel.finwise.services.auth;

import com.hanniel.finwise.domains.auth.*;
import com.hanniel.finwise.exceptions.auth.AuthenticationFailedException;
import com.hanniel.finwise.exceptions.auth.UsernameExistsException;
import com.hanniel.finwise.repositories.auth.UserCredentialsRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserCredentialsRepository userCredentialsRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuthenticationManager authManager;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    private final String email = "johndoe@test.com";

    @BeforeEach
    void setup() {}

    @Test
    @DisplayName("Should register a new UserCredentials in database and return a registration token.")
    void register_credentials_with_successfully() {
        RegisterRequest request = new RegisterRequest(email, "rawPass123", null);
        when(userCredentialsRepository.findByEmail(email)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("rawPass123")).thenReturn("encoded-pass");

        when(userCredentialsRepository.save(any(UserCredentials.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(jwtService.generateRegistrationToken(any(UserCredentials.class))).thenReturn("reg-token-xyz");

        AuthResponse response = authService.register(request);

        assertThat(response).isNotNull();
        assertThat(response.token()).isEqualTo("reg-token-xyz");

        ArgumentCaptor<UserCredentials> captor = ArgumentCaptor.forClass(UserCredentials.class);
        verify(userCredentialsRepository).save(captor.capture());
        UserCredentials saved = captor.getValue();

        assertThat(saved.getEmail()).isEqualTo(email);
        assertThat(saved.getPassword()).isEqualTo("encoded-pass");
        assertThat(saved.getRole()).isEqualTo(Role.USER);
    }

    @Test
    @DisplayName("Should failed to create a new UserCredentials in database when email already exists.")
    void register_credentials_should_throw_error_when_role_invalid() {
        RegisterRequest request = new RegisterRequest(email, "x", null);
        when(userCredentialsRepository.findByEmail(email)).thenReturn(Optional.of(new UserCredentials()));

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(UsernameExistsException.class)
                .hasMessageContaining("Email already in use");
        verify(userCredentialsRepository, never()).save(any());
    }

    @Test
    @DisplayName("Should return a fallback when role to userCredentials is invalid or not exists.")
    void register_should_fallback_to_user_role_when_role_invalid() {
        RegisterRequest request = new RegisterRequest(email, "pw", "INVALID_ROLE");
        when(userCredentialsRepository.findByEmail(email)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("pw")).thenReturn("enc");
        when(userCredentialsRepository.save(any(UserCredentials.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(jwtService.generateRegistrationToken(any(UserCredentials.class))).thenReturn("t");

        AuthResponse result = authService.register(request);

        assertThat(result.token()).isEqualTo("t");
        ArgumentCaptor<UserCredentials> captor = ArgumentCaptor.forClass(UserCredentials.class);
        verify(userCredentialsRepository).save(captor.capture());
        assertThat(captor.getValue().getRole()).isEqualTo(Role.USER);
    }


    @Test
    @DisplayName("Should authentication the userCredentials and return a access token.")
    void login_with_successfully_and_return_access_token() {
        LoginRequest login = new LoginRequest(email, "pw123");
        UserCredentials user = new UserCredentials();
        user.setId(UUID.randomUUID());
        user.setEmail(email);
        user.setPassword("enc");
        user.setRole(Role.USER);

        when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(new UsernamePasswordAuthenticationToken("user", "password"));
        when(userCredentialsRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(jwtService.generateAccessToken(user)).thenReturn("access-token");

        AuthResponse rsp = authService.login(login);

        assertThat(rsp).isNotNull();
        assertThat(rsp.token()).isEqualTo("access-token");
        verify(authManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    @DisplayName("Should throw a AuthenticationFailedException when email or password is incorrect.")
    void login_should_throw_when_authentication_fails(){
        LoginRequest login = new LoginRequest(email, "bad");
        doThrow(new AuthenticationFailedException("invalid")).when(authManager)
                .authenticate(any(UsernamePasswordAuthenticationToken.class));

        assertThatThrownBy(() -> authService.login(login))
                .isInstanceOf(AuthenticationFailedException.class)
                .hasMessageContaining("Invalid email or password");
    }
}