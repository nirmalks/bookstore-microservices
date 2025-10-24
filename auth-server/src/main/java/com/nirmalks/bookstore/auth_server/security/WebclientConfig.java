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

	@Value("${auth-server.token-uri}")
	String tokenUri;

	@Bean("userServiceClientRegistration")
	public ReactiveClientRegistrationRepository clientRegistrations() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("auth-server-client-id")
			.tokenUri(tokenUri)
			.clientId("auth-server-client")
			.clientSecret("auth-server-secret")
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.scope("internal_api")
			.build();

		return new InMemoryReactiveClientRegistrationRepository(clientRegistration);
	}

	@Bean
	public InMemoryReactiveOAuth2AuthorizedClientService authorizedClientService(
			ReactiveClientRegistrationRepository clientRegistrations) {
		return new InMemoryReactiveOAuth2AuthorizedClientService(clientRegistrations);
	}

	@Bean
	public AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager(
			ReactiveClientRegistrationRepository clientRegistrations,
			InMemoryReactiveOAuth2AuthorizedClientService authorizedClientService) {
		return new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(clientRegistrations,
				authorizedClientService);
	}

	@Bean("userServiceWebClient")
	public WebClient userServiceWebClient(@Value("${user-service.base-url}") String userServiceBaseUrl,
			AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager) {

		ServerOAuth2AuthorizedClientExchangeFilterFunction oauth2 = new ServerOAuth2AuthorizedClientExchangeFilterFunction(
				authorizedClientManager);

		oauth2.setDefaultClientRegistrationId("auth-server-client-id");

		return WebClient.builder().baseUrl(userServiceBaseUrl).filter(oauth2).build();
	}

}
