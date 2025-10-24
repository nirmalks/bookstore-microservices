package com.nirmalks.bookstore.auth_server.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Map;

public class OAuth2PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	private final RegisteredClient registeredClient;

	private final Authentication clientPrincipal;

	private final Map<String, Object> additionalParameters;

	public OAuth2PasswordAuthenticationToken(RegisteredClient registeredClient, Authentication clientPrincipal,
			Map<String, Object> additionalParameters) {
		super(new AuthorizationGrantType("password"), clientPrincipal, additionalParameters);
		this.registeredClient = registeredClient;
		this.clientPrincipal = clientPrincipal;
		this.additionalParameters = additionalParameters;
	}

	public RegisteredClient getRegisteredClient() {
		return registeredClient;
	}

	public Authentication getClientPrincipal() {
		return clientPrincipal;
	}

	public Map<String, Object> getAdditionalParameters() {
		return additionalParameters;
	}

}
