package com.nirmalks.bookstore.auth_server.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class CustomAccessTokenResponseHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public CustomAccessTokenResponseHandler() {
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        if (!(authentication instanceof OAuth2AccessTokenAuthenticationToken)) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        OAuth2AccessTokenAuthenticationToken tokenAuth =
                (OAuth2AccessTokenAuthenticationToken) authentication;
        OAuth2AccessToken accessToken = tokenAuth.getAccessToken();

        Map<String, Object> output = new HashMap<>();
        output.put("access_token", accessToken.getTokenValue());
        output.put("token_type", TokenType.BEARER.getValue());

        if (accessToken.getExpiresAt() != null && accessToken.getIssuedAt() != null) {
            long expiresIn = accessToken.getExpiresAt().getEpochSecond()
                    - accessToken.getIssuedAt().getEpochSecond();
            output.put("expires_in", expiresIn);
        }
        System.out.println("after epirty");
        // Add custom claims from the provider's additional parameters
        Map<String, Object> additionalParameters = tokenAuth.getAdditionalParameters();
        output.putAll(additionalParameters);

        if (tokenAuth.getRefreshToken() != null) {
            output.put("refresh_token", tokenAuth.getRefreshToken().getTokenValue());
        }
        System.out.println("before resp set" + output);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json;charset=UTF-8");
        objectMapper.writeValue(response.getOutputStream(), output);
    }
}
