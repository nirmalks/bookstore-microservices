package com.nirmalks.bookstore.auth_server.security;

import dto.LoginRequest;
import dto.UserDto;
import dto.UserRole;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class PasswordAuthenticationProvider implements AuthenticationProvider {

    private final WebClient webClient;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    public PasswordAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                          OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
                                          @Qualifier("userServiceWebClient") WebClient webClient) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.webClient = webClient;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2PasswordAuthenticationToken passwordAuth = (OAuth2PasswordAuthenticationToken) authentication;
        Map<String, Object> parameters = passwordAuth.getAdditionalParameters();
        RegisteredClient registeredClient = passwordAuth.getRegisteredClient();
        Authentication clientPrincipal = passwordAuth.getClientPrincipal();

        String username = (String) parameters.get("username");
        String password = (String) parameters.get("password");

        try {
            LoginRequest loginRequest = new LoginRequest();
            loginRequest.setUsername(username);
            loginRequest.setPassword(password);

            UserDto userDto = webClient.post()
                    .uri("/api/internal/users/auth")
                    .attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId("auth-server-client-id"))
                    .bodyValue(loginRequest)
                    .retrieve()
                    .bodyToMono(UserDto.class)
                    .block();
            System.out.println("userdto" + userDto);
            if (userDto == null || userDto.getId() == null || userDto.getUsername() == null) {
                throw new BadCredentialsException("User authentication failed: Incomplete user data.");
            }

            UserRole role = userDto.getRole();
            List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));
            CustomUserDetails customUserDetails = new CustomUserDetails(
                    userDto.getId(),
                    userDto.getUsername(),
                    userDto.getHashedPassword(),
                    authorities
            );

            UsernamePasswordAuthenticationToken customPrincipal = new UsernamePasswordAuthenticationToken(
                    customUserDetails,
                    password,
                    authorities
            );

            OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(customPrincipal)
                    .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                    .authorizationGrantType(new AuthorizationGrantType("password"))
                    .authorizationGrant(passwordAuth)
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                    .build();

            OAuth2Token token = this.tokenGenerator.generate(tokenContext);

            if (token == null) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the access token.", null);
                throw new OAuth2AuthenticationException(error);
            }

            Set<String> scopes = registeredClient.getScopes();
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    token.getTokenValue(),
                    token.getIssuedAt(),
                    token.getExpiresAt(),
                    scopes
            );

            Map<String, Object> metadata = Map.of(
                    "username", userDto.getUsername(),
                    "userId", userDto.getId(),
                    "role", userDto.getRole().name()
            );

            OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                    .principalName(username)
                    .authorizationGrantType(new AuthorizationGrantType("password"))
                    .token(accessToken, (tokenMetadata) -> tokenMetadata.putAll(metadata))
                    .build();

            this.authorizationService.save(authorization);

            return new OAuth2AccessTokenAuthenticationToken(
                    registeredClient,
                    clientPrincipal,
                    accessToken,
                    null,
                    metadata
            );
        } catch (WebClientResponseException e) {
            System.err.println("WebClient call to user service failed: " + e.getStatusCode() + " - " + e.getResponseBodyAsString());
            throw new BadCredentialsException("Invalid credentials: User service authentication failed.", e);
        } catch (Exception e) {
            System.err.println("An unexpected error occurred during password authentication: " + e.getMessage());
            throw new BadCredentialsException("Invalid credentials", e);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
