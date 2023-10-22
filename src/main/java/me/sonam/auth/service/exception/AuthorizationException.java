package me.sonam.auth.service.exception;

public class AuthorizationException extends RuntimeException{
    public AuthorizationException(String msg) {
        super(msg);
    }
}
