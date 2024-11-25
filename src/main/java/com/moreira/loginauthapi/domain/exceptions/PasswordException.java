package com.moreira.loginauthapi.domain.exceptions;

public class PasswordException extends RuntimeException {
    public PasswordException(String message) {
        super(message);
    }
}
