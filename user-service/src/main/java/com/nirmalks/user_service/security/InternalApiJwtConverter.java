package com.nirmalks.user_service.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Collection;

public class InternalApiJwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {

	@Override
	public AbstractAuthenticationToken convert(Jwt jwt) {
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
			.getRequest();
		System.out.println(request.getRequestURI());
		if (request.getRequestURI().startsWith("/api/internal/")) {
			String clientId = jwt.getClaimAsString("client_id");
			System.out.println("client id" + clientId);
			if (!"auth-server-client".equals(clientId)) {
				throw new RuntimeException("Not authorized for internal endpoint");
			}
		}

		Collection<GrantedAuthority> authorities = jwt.getClaimAsStringList("scope")
			.stream()
			// Map each scope to a GrantedAuthority with the "SCOPE_" prefix,
			// which is required by the .hasAuthority("SCOPE_internal_api") check.
			.map(s -> (GrantedAuthority) () -> "SCOPE_" + s)
			.toList();

		return new JwtAuthenticationToken(jwt, authorities);
	}

}
