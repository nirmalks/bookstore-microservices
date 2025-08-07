package com.nirmalks.bookstore.auth_server.security;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public final class PasswordGrantType {
    public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");

    private PasswordGrantType() {
    }
}
