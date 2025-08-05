package com.nirmalks.user_service.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        System.out.println("JwtHeaderAuthenticationFilter called for: " + request.getRequestURI());

        String userId = request.getHeader("X-User-ID");
        System.out.println("user id " + userId);
        String userRolesHeader = request.getHeader("X-User-Roles");
        System.out.println("user roles" + userRolesHeader);

        // Check if both user ID and roles headers are present and not empty.
        // If they are, it signifies that the request has been authenticated by the Gateway.
        if (userId != null && !userId.isEmpty() && userRolesHeader != null && !userRolesHeader.isEmpty()) {
            // Parse the roles string (e.g., "ROLE_ADMIN,ROLE_CUSTOMER") into a collection
            // of Spring Security's GrantedAuthority objects.
            Collection<? extends GrantedAuthority> authorities = Arrays.stream(userRolesHeader.split(","))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            // Create an Authentication object.
            // UsernamePasswordAuthenticationToken is used here, with the userId as the principal.
            // Credentials are set to null as the actual password authentication occurred at the Auth Server.
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);

            // Set the authentication object in the SecurityContextHolder.
            // This makes the user authenticated for the duration of this request within this service,
            // allowing @PreAuthorize and other Spring Security features to work.
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        // Continue the filter chain to allow the request to proceed to other filters or controllers.
        filterChain.doFilter(request, response);
    }
}
