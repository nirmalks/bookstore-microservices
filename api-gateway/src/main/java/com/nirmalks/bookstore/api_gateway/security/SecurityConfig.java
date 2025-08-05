package com.nirmalks.bookstore.api_gateway.security;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered; // Import Ordered
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) // Explicitly set order for the security filter chain
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        // Publicly accessible paths for user registration and login (frontend calls directly)
                        .pathMatchers("/api/users/register").permitAll()
                        .pathMatchers("/api/users/admin/register").permitAll() // If you have this
                        .pathMatchers("/api/login").permitAll()
                        // Allow Eureka discovery endpoints
                        .pathMatchers("/eureka/**").permitAll()
                        // Allow Swagger UI and API docs
                        .pathMatchers("/swagger-ui/**", "/v3/api-docs/**", "/error").permitAll()
                        // Allow public access to catalog-related endpoints (GET methods)
                        // Note: For POST/PUT/DELETE on these, they will require authentication
                        .pathMatchers("/api/books/**", "/api/genres/**", "/api/authors/**").permitAll()
                        // All other requests must be authenticated (JWT validation by Gateway)
                        .anyExchange().authenticated()
                )
                // Configure OAuth2 Resource Server to validate JWTs
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));



        return http.build();
    }

    @Bean
    public JwtHeaderPropagationFilter jwtHeaderPropagationFilter() {
        return new JwtHeaderPropagationFilter();
    }

    /**
     * Defines routes programmatically for Spring Cloud Gateway.
     * This method creates and configures the routing rules for various microservices.
     *
     * @param builder A builder for creating RouteLocator instances.
     * @return A configured RouteLocator.
     */
    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // --- User Service Login/Register Route ---
                // Separate route for login and registration to ensure clear path matching
                .route("user-auth-route", r -> r.path("/api/login", "/api/register/**")
                        .and().method("GET", "POST", "PUT", "DELETE")
                        .filters(f -> f.rewritePath("/api/(?<segment>.*)", "/api/${segment}"))
                        .uri("lb://user-service"))

                // --- User Service General API Route ---
                // Separate route for general user operations
                .route("user-api-route", r -> r.path("/api/users/**")
                        .and().method("GET", "POST", "PUT", "DELETE")
                        .filters(f -> f.rewritePath("/api/(?<segment>.*)", "/api/${segment}"))
                        .uri("lb://user-service"))

                // --- Catalog Service Route ---
                .route("catalog-service-route", r -> r.path("/api/books/**", "/api/authors/**", "/api/genres/**")
                        .and().method("GET", "POST", "PUT", "DELETE")
                        .filters(f -> f.rewritePath("/api/(?<segment>.*)", "/api/${segment}"))
                        .uri("lb://catalog-service"))

                // --- Checkout Service Route ---
                .route("checkout-service-route", r -> r.path("/api/carts/**", "/api/orders/**")
                        .and().method("GET", "POST", "PUT", "DELETE")
                        .filters(f -> f.rewritePath("/api/(?<segment>.*)", "/api/${segment}"))
                        .uri("lb://checkout-service"))
                .build();
    }
}
