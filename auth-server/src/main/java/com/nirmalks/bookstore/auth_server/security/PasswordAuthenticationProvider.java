package com.nirmalks.bookstore.auth_server.security;

import dto.LoginRequest;
import dto.UserDto;
import dto.UserRole;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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

import java.util.List;
import java.util.Map;

public class PasswordAuthenticationProvider implements AuthenticationProvider {

    private final WebClient webClient;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    public PasswordAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                          OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.webClient = WebClient.builder()
                .baseUrl("http://localhost:8081") // user-service
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer internal-token")
                .build();
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
                    .bodyValue(loginRequest)
                    .retrieve()
                    .bodyToMono(UserDto.class)
                    .block();
            if (userDto != null) {
                UserRole role = userDto.getRole();
                List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));

                Map<String, Object> customClaims = Map.of(
                        "username", userDto.getUsername(),
                        "role", role.name()
                );

                OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                        .registeredClient(registeredClient)
                        .principal(new UsernamePasswordAuthenticationToken(username, password, authorities))
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

                OAuth2AccessToken accessToken =  new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                        token.getTokenValue(), token.getIssuedAt(),
                        token.getExpiresAt(), null);

                System.out.println("accestok" + accessToken);
                OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                        .principalName(username)
                        .authorizationGrantType(new AuthorizationGrantType("password"))
                        .token(accessToken)
                        .build();

                this.authorizationService.save(authorization);

                return new OAuth2AccessTokenAuthenticationToken(
                        registeredClient,
                        clientPrincipal,
                        accessToken
                );
            } else {
                throw new BadCredentialsException("UserDto is null");
            }
        } catch (Exception e) {
            throw new BadCredentialsException("Invalid credentials", e);
        }
    }

//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        OAuth2PasswordAuthenticationToken passwordAuth = (OAuth2PasswordAuthenticationToken) authentication;
//        Map<String, Object> parameters = passwordAuth.getAdditionalParameters();
//        RegisteredClient registeredClient = passwordAuth.getRegisteredClient();
//        Authentication clientPrincipal = passwordAuth.getClientPrincipal();
//
//        String username = (String) parameters.get("username");
//        String password = (String) parameters.get("password");
//
//        try {
//            // Call user-service
//            LoginRequest loginRequest = new LoginRequest();
//            loginRequest.setUsername(username);
//            loginRequest.setPassword(password);
//
//            UserDto userDto = webClient.post()
//                    .uri("/api/internal/users/auth")
//                    .bodyValue(loginRequest)
//                    .retrieve()
//                    .bodyToMono(UserDto.class)
//                    .block();
//
//            if (userDto == null) throw new BadCredentialsException("User not found");
//
//            // Prepare authorities and claims
//            UserRole role = userDto.getRole();
//            List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));
//            Map<String, Object> customClaims = new HashMap<>();
//            customClaims.put("username", userDto.getUsername());
//            customClaims.put("role", role.toString());
//            UsernamePasswordAuthenticationToken userPrincipal =
//                    new UsernamePasswordAuthenticationToken(username, null, authorities);
//            // Token context
//            OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
//                    .registeredClient(registeredClient)
//                    .principal(userPrincipal)
//                    .authorizationServerContext(AuthorizationServerContextHolder.getContext())
//                    .authorizationGrantType(new AuthorizationGrantType("password"))
//                    .authorizationGrant(passwordAuth)
//                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)
//                    .build();
//
//            // Generate token
//            OAuth2Token generatedToken = this.tokenGenerator.generate(tokenContext);
//            if (generatedToken == null) {
//                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
//                        "The token generator failed to generate the access token.", null);
//                throw new OAuth2AuthenticationException(error);
//            }
//
//            OAuth2AccessToken accessToken = new OAuth2AccessToken(
//                    OAuth2AccessToken.TokenType.BEARER,
//                    generatedToken.getTokenValue(),
//                    generatedToken.getIssuedAt(),
//                    generatedToken.getExpiresAt(),
//                    null
//            );
//            System.out.println("custom claims " + customClaims);
//            // Authorization with custom claims
//            OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
//                    .principalName(username)
//                    .attribute(Principal.class.getName(), userPrincipal)
//                    .authorizationGrantType(new AuthorizationGrantType("password"))
//                    .token(accessToken, metadata -> {
//                        metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, customClaims);
//                    })
//                    .build();
//
//            this.authorizationService.save(authorization);
//
//            return new OAuth2AccessTokenAuthenticationToken(
//                    registeredClient,
//                    clientPrincipal,
//                    accessToken
//            );
//
//        } catch (Exception e) {
//            throw new BadCredentialsException("Invalid credentials", e);
//        }
//    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
