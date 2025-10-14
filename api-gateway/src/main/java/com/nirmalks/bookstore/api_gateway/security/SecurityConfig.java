package com.nirmalks.bookstore.api_gateway.security;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

	@Bean
	public SecurityWebFilterChain mainSecurityFilterChain(ServerHttpSecurity http) {
		http.csrf(ServerHttpSecurity.CsrfSpec::disable)
			.authorizeExchange(exchanges -> exchanges.pathMatchers("/api/users/register")
				.permitAll()
				.pathMatchers("/api/users/admin/register")
				.permitAll()
				.pathMatchers("/api/internal/**")
				.permitAll()
				.pathMatchers("/api/login", "/api/oauth2/token")
				.permitAll()
				.pathMatchers("/eureka/**")
				.permitAll()
				.pathMatchers("/actuator/**")
				.permitAll()
				.pathMatchers("/swagger-ui/**", "/v3/api-docs/**", "/error")
				.permitAll()
				.pathMatchers("/api/books/**", "/api/genres/**", "/api/authors/**")
				.permitAll()
				.anyExchange()
				.authenticated())
			.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
		return http.build();
	}

	@Bean
	public JwtHeaderPropagationFilter jwtHeaderPropagationFilter() {
		return new JwtHeaderPropagationFilter();
	}

	/**
	 * Defines routes programmatically for Spring Cloud Gateway. This method creates and
	 * configures the routing rules for various microservices.
	 * @param builder A builder for creating RouteLocator instances.
	 * @return A configured RouteLocator.
	 */
	@Bean
	public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
		return builder.routes()
			// --- User Service Login/Register Route ---
			.route("user-auth-route",
					r -> r.path("/api/login", "/api/register/**")
						.and()
						.method("GET", "POST", "PUT", "DELETE")
						.filters(f -> f.rewritePath("/api/(?<segment>.*)", "/api/${segment}")
							.circuitBreaker(c -> c.setName("userAuthCB").setFallbackUri("forward:/fallback/userauth")))
						.uri("lb://user-service"))

			// --- User Service General API Route ---
			.route("user-api-route",
					r -> r.path("/api/users/**", "/api/internal/**")
						.and()
						.method("GET", "POST", "PUT", "DELETE")
						.filters(f -> f.rewritePath("/api/(?<segment>.*)", "/api/${segment}")
							.circuitBreaker(c -> c.setName("userApiCB").setFallbackUri("forward:/fallback/user")))
						.uri("lb://user-service"))

			// --- Catalog Service Route ---
			.route("catalog-service-route",
					r -> r.path("/api/books/**", "/api/authors/**", "/api/genres/**")
						.and()
						.method("GET", "POST", "PUT", "DELETE")
						.filters(f -> f.rewritePath("/api/(?<segment>.*)", "/api/${segment}")
							.circuitBreaker(c -> c.setName("catalogCB").setFallbackUri("forward:/fallback/catalog")))
						.uri("lb://catalog-service"))

			// --- Checkout Service Route ---
			.route("checkout-service-route",
					r -> r.path("/api/carts/**", "/api/orders/**")
						.and()
						.method("GET", "POST", "PUT", "DELETE")
						.filters(f -> f.rewritePath("/api/(?<segment>.*)", "/api/${segment}")
							.circuitBreaker(c -> c.setName("checkoutCB").setFallbackUri("forward:/fallback/checkout")))
						.uri("lb://checkout-service"))

			// auth server route
			.route("auth-server-route",
					r -> r.path("/api/oauth2/token", "/api/oauth/**")
						.and()
						.method("GET", "POST", "PUT", "DELETE")
						.filters(f -> f.rewritePath("/api/(?<segment>.*)", "/api/${segment}")
							.circuitBreaker(c -> c.setName("authServerCB").setFallbackUri("forward:/fallback/auth")))
						.uri("lb://auth-server"))
			.build();
	}

}
