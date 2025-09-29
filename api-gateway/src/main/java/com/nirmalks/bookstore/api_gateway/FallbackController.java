package com.nirmalks.bookstore.api_gateway;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class FallbackController {
    @GetMapping("/fallback/userauth")
    public Mono<String> userAuthFallback() {
        return Mono.just("User Auth Service is unavailable. Please try again later.");
    }

    @GetMapping("/fallback/user")
    public Mono<String> userFallback() {
        return Mono.just("User Service is unavailable. Please try again later.");
    }

    @GetMapping("/fallback/catalog")
    public Mono<String> catalogFallback() {
        return Mono.just("Catalog Service is unavailable. Please try again later.");
    }

    @GetMapping("/fallback/checkout")
    public Mono<String> checkoutFallback() {
        return Mono.just("Checkout Service is unavailable. Please try again later.");
    }

    @GetMapping("/fallback/auth")
    public Mono<String> authFallback() {
        return Mono.just("Auth Server is unavailable. Please try again later.");
    }
}