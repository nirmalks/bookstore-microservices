package com.nirmalks.bookstore.api_gateway;

import exceptions.ServiceUnavailableException;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/fallback")
public class FallbackController {

	private Mono<String> handleFallback(ServerHttpRequest request, String message) {
		if (request.getMethod() == HttpMethod.GET) {
			return Mono.just(message);
		}
		return Mono.error(new ServiceUnavailableException("Service unavailable and no fallback for non-GET methods."));
	}

	@RequestMapping("/userauth")
	public Mono<String> userAuthFallback(ServerHttpRequest request) {
		return handleFallback(request, "User Auth Service is unavailable. Please try again later.");
	}

	@RequestMapping("/user")
	public Mono<String> userFallback(ServerHttpRequest request) {
		return handleFallback(request, "User Service is unavailable. Please try again later.");
	}

	@RequestMapping("/catalog")
	public Mono<String> catalogFallback(ServerHttpRequest request) {
		return handleFallback(request, "Catalog Service is unavailable. Please try again later.");
	}

	@RequestMapping("/checkout")
	public Mono<String> checkoutFallback(ServerHttpRequest request) {
		return handleFallback(request, "Checkout Service is unavailable. Please try again later.");
	}

	@RequestMapping("/auth")
	public Mono<String> authFallback(ServerHttpRequest request) {
		return handleFallback(request, "Auth Server is unavailable. Please try again later.");
	}

}
