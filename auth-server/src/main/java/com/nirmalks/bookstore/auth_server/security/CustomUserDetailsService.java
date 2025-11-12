package com.nirmalks.bookstore.auth_server.security;

import dto.UserDto;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	private final WebClient webClient;

	private final String userServiceBaseUrl;

	public CustomUserDetailsService(WebClient webClient, @Value("${user-service.base-url}") String userServiceBaseUrl) {
		this.webClient = webClient;
		this.userServiceBaseUrl = userServiceBaseUrl;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		String url = userServiceBaseUrl + "/api/internal/users/by-username/{username}";
		Optional<UserDto> userDtoOptional = webClient.get()
			.uri(url, username)
			.retrieve()
			.bodyToMono(UserDto.class)
			.onErrorResume(e -> Mono.empty())
			.blockOptional();

		UserDto userDto = userDtoOptional
			.orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
		GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + userDto.getRole().name());
		return new CustomUserDetails(userDto.getId(), userDto.getUsername(), userDto.getHashedPassword(),
				List.of(authority));
	}

}
