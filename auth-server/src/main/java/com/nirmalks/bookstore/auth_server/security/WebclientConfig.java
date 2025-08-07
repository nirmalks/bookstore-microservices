package com.nirmalks.bookstore.auth_server.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@Configuration
public class WebclientConfig {
//    @Bean("customReactiveClientRegistration")
//    public ReactiveClientRegistrationRepository clientRegistrations() {
//        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("auth-server-client")
//                .tokenUri("http://localhost:9000/oauth2/token")
//                .clientId("auth-server-client")
//                .clientSecret("{noop}auth-server-secret")
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .scope("internal_api")
//                .build();
//
//        return new InMemoryReactiveClientRegistrationRepository(clientRegistration);
//    }
//

        @Bean
        public WebClient userServiceWebClient(@Value("${user-service.base-url}") String userServiceBaseUrl) {
            return WebClient.builder()
                    .baseUrl(userServiceBaseUrl)
                    .defaultHeader("X-Internal-Service", "auth-server")
                    .build();
        }
}
