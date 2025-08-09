package com.hanniel.finwise.exceptions.auth;

public class AuthenticationFailedException extends RuntimeException {
    public AuthenticationFailedException(String message){
        super(message);
    }
}
