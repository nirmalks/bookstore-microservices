package com.nirmalks.checkout_service.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

public class JwtHeaderAuthenticationFilter extends OncePerRequestFilter {
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/api/internal/")|| path.startsWith("/v3/api-docs") ||
                path.startsWith("/swagger-ui/**") || path.startsWith("/actuator/");
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        System.out.println("JwtHeaderAuthenticationFilter called for: " + request.getRequestURI());

        String userId = request.getHeader("X-User-ID");
        System.out.println("user id " + userId);
        String userRolesHeader = request.getHeader("X-User-Roles");
        System.out.println("user roles" + userRolesHeader);

        if (userId != null && !userId.isEmpty() && userRolesHeader != null && !userRolesHeader.isEmpty()) {

            Collection<? extends GrantedAuthority> authorities = Arrays.stream(userRolesHeader.split(","))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }
}
