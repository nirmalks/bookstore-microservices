package com.nirmalks.user_service.user.controller;

import com.nirmalks.user_service.auth.api.LoginRequest;
import com.nirmalks.user_service.user.service.UserService;
import dto.UserDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/internal/users")
public class InternalUsersController {

	@Autowired
	private UserService userService;

	@Autowired
	private AuthenticationManager authenticationManager;

	public InternalUsersController(UserService userService, AuthenticationManager authenticationManager) {
		this.userService = userService;
		this.authenticationManager = authenticationManager;
	}

	@PostMapping("/auth")
	public ResponseEntity<UserDto> internalAuth(@RequestBody LoginRequest loginRequest) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		if (authentication.isAuthenticated()) {
			UserDto user = userService.internalAuthenticate(loginRequest.getUsername(), loginRequest.getPassword());
			return ResponseEntity.ok(user);
		}
		throw new BadCredentialsException("Invalid credentials");
	}

}
