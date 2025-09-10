package com.hanniel.finwise.controllers.auth;

import com.hanniel.finwise.domains.auth.*;
import com.hanniel.finwise.services.auth.AuthService;
import com.hanniel.finwise.services.auth.JwtService;
import com.hanniel.finwise.services.auth.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

@Controller
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request,
                                              @RequestParam(name = "remember", defaultValue = "false") boolean remember,
                                              HttpServletResponse response) {
        return ResponseEntity.ok(authService.login(request, remember, response));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @CookieValue(name = "${security.remember-me.cookie-name}", required = false) String rawRefresh,
            @RequestParam(name = "allSessions", defaultValue = "false") boolean allSessions,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String username = null;
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            try {
                username = auth.getName();
            } catch (Exception ignored) {
            }
        }

        authService.logoutAndRemoveRememberMe(username, rawRefresh, allSessions, response);

        SecurityContextHolder.clearContext();
        return ResponseEntity.noContent().build();
    }


    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

        String raw = Arrays.stream(cookies)
                .filter(c -> "refresh_token".equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

       if (raw == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

       var refresh = refreshTokenService.findByRaw(raw).orElse(null);
       if(refresh == null || refresh.isRevoked()) {
           return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
       }

       var user = refresh.getUser();
       String access = jwtService.generateAccessToken(user);
       return ResponseEntity.ok(Map.of("accessToken", access));
    }
}
