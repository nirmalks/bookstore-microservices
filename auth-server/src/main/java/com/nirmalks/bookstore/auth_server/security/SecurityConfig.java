package com.nirmalks.bookstore.auth_server.security;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          PasswordAuthenticationProvider passwordAuthProvider,
                                                          PasswordAuthenticationConverter passwordAuthenticationConverter) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint ->
                tokenEndpoint
                        .accessTokenRequestConverter(passwordAuthenticationConverter)
                        .authenticationProvider(passwordAuthProvider)
                        .accessTokenResponseHandler(new CustomAccessTokenResponseHandler())
        );


        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .authorizeHttpRequests(authorize -> authorize.requestMatchers("/api/oauth2/token").permitAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/oauth2/token"))
                .with(authorizationServerConfigurer, customizer -> {});

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(PasswordAuthenticationProvider provider) {
        return new ProviderManager(provider);
    }

    @Bean
    public PasswordAuthenticationProvider passwordAuthenticationProvider(WebClient webClient, OAuth2AuthorizationService authorizationService,
                                                                         OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        return new PasswordAuthenticationProvider(authorizationService, tokenGenerator, webClient);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId("local-client-id")
                .clientId("local-client")
                .clientSecret(passwordEncoder().encode("secret"))
                .authorizationGrantType(new AuthorizationGrantType("password"))
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("read")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .build())
                .build();

        RegisteredClient internalClient = RegisteredClient.withId("auth-server-client-id")
                .clientId("auth-server-client")
                .clientSecret(passwordEncoder().encode("auth-server-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("internal_api")
                .build();
        return new InMemoryRegisteredClientRepository(client, internalClient);
    }

    @Bean
    public PasswordAuthenticationConverter passwordAuthenticationConverter(
            RegisteredClientRepository registeredClientRepository) {
        return new PasswordAuthenticationConverter(registeredClientRepository);
    }
    @Bean
    public OAuth2AuthorizationService authorizationService(RegisteredClientRepository registeredClientRepository) {
        return new InMemoryOAuth2AuthorizationService();
    }
    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder, OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator,
                new OAuth2AccessTokenGenerator(),
                new OAuth2RefreshTokenGenerator()
        );
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Authentication principal = context.getPrincipal();
                if (principal instanceof UsernamePasswordAuthenticationToken) {
                    CustomUserDetails userDetails = (CustomUserDetails) principal.getPrincipal();

                    Long userId = userDetails.getId();
                    String username = userDetails.getUsername();
                    if (userId != null && username != null) {
                        context.getClaims().subject(userId.toString());
                        context.getClaims().claim("username", username);

                        List<String> roles = userDetails.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toList());
                        context.getClaims().claim("roles", roles);
                    } else {
                        System.err.println("Cannot create JWT: userId or username is null for authenticated user.");
                    }
                }
                // Case for internal client authentication (client credentials grant)
                else if (principal instanceof OAuth2ClientAuthenticationToken) {
                    String clientId = principal.getName();
                    context.getClaims().claim("client_id", clientId);
                    Set<String> scopes = context.getRegisteredClient().getScopes();
                    System.out.println("JWT custom claims injected for internal client: " + clientId + " with scopes: " + scopes);
                }
            }
        };
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .tokenEndpoint("/api" + "/oauth2/token")
                .build();
    }
}
