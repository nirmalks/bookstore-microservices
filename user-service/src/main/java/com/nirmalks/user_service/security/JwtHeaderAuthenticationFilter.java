package com.nirmalks.user_service.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

public class JwtHeaderAuthenticationFilter extends OncePerRequestFilter {

	private static final Logger logger = LoggerFactory.getLogger(JwtHeaderAuthenticationFilter.class);

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return request.getRequestURI().startsWith("/api/internal/")
				|| request.getRequestURI().startsWith("/v3/api-docs")
				|| request.getRequestURI().startsWith("/swagger-ui/**");
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		logger.debug("JwtHeaderAuthenticationFilter called for: {}", request.getRequestURI());

		String userIdHeader = request.getHeader("X-User-ID");
		String userRolesHeader = request.getHeader("X-User-Roles");

		// Check if both user ID and roles headers are present and not empty.
		// If they are, it signifies that the request has been authenticated by the
		// Gateway.
		if (userIdHeader != null && !userIdHeader.isEmpty() && userRolesHeader != null && !userRolesHeader.isEmpty()) {
			try {
				Long userId = Long.parseLong(userIdHeader);
				logger.debug("User ID: {}", userId);
				logger.debug("User roles: {}", userRolesHeader);

				// Parse the roles string (e.g., "ROLE_ADMIN,ROLE_CUSTOMER") into a
				// collection
				// of Spring Security's GrantedAuthority objects.
				Collection<? extends GrantedAuthority> authorities = Arrays.stream(userRolesHeader.split(","))
					.map(String::trim)
					.map(SimpleGrantedAuthority::new)
					.collect(Collectors.toList());
				logger.debug("Granted Authorities: {}", authorities);

				// Create an Authentication object.
				// UsernamePasswordAuthenticationToken is used here, with the userId as
				// the principal.
				// Credentials are set to null as the actual password authentication
				// occurred at the Auth Server.
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userId,
						null, authorities);

				// Set the authentication object in the SecurityContextHolder.
				// This makes the user authenticated for the duration of this request
				// within this service,
				// allowing @PreAuthorize and other Spring Security features to work.
				SecurityContextHolder.getContext().setAuthentication(authentication);

			}
			catch (NumberFormatException e) {
				logger.error("Invalid 'X-User-ID' header format: {}", userIdHeader, e);
			}
		}
		else {
			logger.debug("Missing 'X-User-ID' or 'X-User-Roles' header. Request not authenticated by Gateway.");
		}

		filterChain.doFilter(request, response);
	}

}
