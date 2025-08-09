package com.hanniel.finwise.services.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long accessExpiration;

    @Value("${jwt.registrationExpiration}")
    private long registrationExpiration;

    public String generateRegistrationToken(UserDetails user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withClaim("type", "REGISTRATION")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + registrationExpiration))
                .sign(Algorithm.HMAC256(secretKey));
    }


    public String generateAccessToken(UserDetails user) {
        String role = user.getAuthorities()
                .stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .orElse("ROLE_USER")
                .replace("ROLE_", "");

        return JWT.create()
                .withSubject(user.getUsername())
                .withClaim("role", role)
                .withClaim("type", "ACCESS")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + accessExpiration))
                .sign(Algorithm.HMAC256(secretKey));
    }

    private DecodedJWT decodeToken(String token){
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secretKey)).build();
        return verifier.verify(token);
    }

    public String extractUsername(String token){
        return decodeToken(token).getSubject();
    }

    public boolean isValidAccessToken(String token, UserDetails user) {
        try {
            DecodedJWT decodedToken = decodeToken(token);
           return "ACCESS".equals(decodedToken.getClaim("type").asString()) &&
                   decodedToken.getSubject().equals(user.getUsername()) &&
                   !decodedToken.getExpiresAt().before(new Date());
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    public boolean isValidRegistrationToken(String token, UserDetails user) {
        try {
            DecodedJWT decodedJWT = decodeToken(token);
            return "REGISTRATION".equals(decodedJWT.getClaim("type").asString()) &&
                    decodedJWT.getSubject().equals(user.getUsername()) &&
                    !decodedJWT.getExpiresAt().before(new Date());
        } catch (JWTVerificationException e) {
            return false;
        }
    }

}
