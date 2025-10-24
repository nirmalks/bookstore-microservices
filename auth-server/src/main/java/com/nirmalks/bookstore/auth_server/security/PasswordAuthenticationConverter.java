package com.nirmalks.bookstore.auth_server.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.HashMap;
import java.util.Map;

public class PasswordAuthenticationConverter implements AuthenticationConverter {

	private final RegisteredClientRepository registeredClientRepository;

	public PasswordAuthenticationConverter(RegisteredClientRepository registeredClientRepository) {
		this.registeredClientRepository = registeredClientRepository;
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		if (!"password".equals(request.getParameter("grant_type"))) {
			return null;
		}
		Authentication clientPrincipal = (Authentication) request.getUserPrincipal();

		String clientId = clientPrincipal.getName();

		RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("username", request.getParameter("username"));
		additionalParameters.put("password", request.getParameter("password"));

		return new OAuth2PasswordAuthenticationToken(registeredClient, clientPrincipal, additionalParameters);
	}

}
