package com.nirmalks.bookstore.api_gateway.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import org.springframework.security.core.GrantedAuthority;

import java.util.stream.Collectors;

public class JwtHeaderPropagationFilter implements GlobalFilter, Ordered {
	private final Logger logger = LoggerFactory.getLogger(JwtHeaderPropagationFilter.class);
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		logger.debug("JwtHeaderPropagationFilter: Processing path: " + exchange.getRequest().getPath());

		return ReactiveSecurityContextHolder.getContext()
			.filter(context -> context.getAuthentication() != null && context.getAuthentication().isAuthenticated())
			.map(context -> context.getAuthentication())
			.cast(Authentication.class)
			.map(authentication -> {
				ServerHttpRequest.Builder builder = exchange.getRequest().mutate();

				if (authentication.getPrincipal() instanceof Jwt jwt) {
					String userId = jwt.getSubject();
					if (userId != null) {
						builder.header("X-User-ID", userId);
						logger.debug("Added User ID header in gateway: " + userId);
					}

					String rolesClaim = "roles";
					if (jwt.hasClaim(rolesClaim)) {
						String roles = jwt.getClaimAsString(rolesClaim);
						logger.debug("roles str in gateway" + roles);
						if (roles != null) {
							String rolesWithoutBrackets = roles.trim().replace("[", "").replace("]", "");
							builder.header("X-User-Roles", rolesWithoutBrackets);
						}
					}
					else {
						String authorities = authentication.getAuthorities()
							.stream()
							.map(GrantedAuthority::getAuthority)
							.collect(Collectors.joining(","));
						if (!authorities.isEmpty()) {
							builder.header("X-User-Roles", authorities);
						}
					}
				}
				return exchange.mutate().request(builder.build()).build();
			})
			.defaultIfEmpty(exchange)
			.flatMap(chain::filter);
	}

	@Override
	public int getOrder() {
		return Ordered.LOWEST_PRECEDENCE;
	}

}