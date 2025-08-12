package com.nirmalks.checkout_service.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.stream.Collectors;

/**
 * Configuration class for creating and configuring WebClient instances.
 * This class provides beans for communicating with the user service and
 * catalog service, and includes a filter to propagate authentication
 * headers for seamless service-to-service communication on behalf of a user.
 */
@Configuration
public class WebClientConfig {

    @Value("${user-service.base-url}")
    private String userServiceBaseUrl;

    @Value("${catalog-service.base-url}")
    private String catalogServiceBaseUrl;

    /**
     * Creates a WebClient bean for communicating with the user service.
     * The client is configured with a filter to automatically add
     * 'X-User-ID' and 'X-User-Roles' headers to outgoing requests.
     *
     * @return a WebClient instance for the user service.
     */
    @Bean("userServiceWebClient")
    @LoadBalanced
    public WebClient userServiceWebClient() {
        return WebClient.builder()
                .baseUrl(userServiceBaseUrl)
                .filter(addAuthHeadersFilter())
                .build();
    }

    /**
     * Creates a WebClient bean for communicating with the catalog service.
     * This client is also configured with the authentication header filter.
     *
     * @return a WebClient instance for the catalog service.
     */
    @Bean("catalogServiceWebClient")
    @LoadBalanced
    public WebClient catalogServiceWebClient() {
        return WebClient.builder()
                .baseUrl(catalogServiceBaseUrl)
                .filter(addAuthHeadersFilter())
                .build();
    }

    /**
     * An ExchangeFilterFunction to add user authentication headers to requests.
     * It retrieves the user ID and roles from the SecurityContextHolder
     * and adds them as headers to the outgoing WebClient request.
     *
     * @return an ExchangeFilterFunction for header propagation.
     */
    private ExchangeFilterFunction addAuthHeadersFilter() {
        return (request, next) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && authentication.isAuthenticated()) {
                String userId = (String) authentication.getPrincipal();
                String roles = authentication.getAuthorities().stream()
                        .map(Object::toString)
                        .collect(Collectors.joining(","));

                // Build a new request with the headers added
                ClientRequest newRequest = ClientRequest.from(request)
                        .header("X-User-ID", userId)
                        .header("X-User-Roles", roles)
                        .build();

                // Proceed with the modified request
                return next.exchange(newRequest);
            }

            // If no user is authenticated, proceed with the original request
            return next.exchange(request);
        };
    }
}
