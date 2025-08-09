package com.hanniel.finwise.exceptions.auth;

public class UsernameExistsException extends RuntimeException {
    public UsernameExistsException(String message){
        super(message);
    }
}
