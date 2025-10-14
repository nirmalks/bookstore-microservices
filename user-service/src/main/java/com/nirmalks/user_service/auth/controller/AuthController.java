package com.nirmalks.user_service.auth.controller;

import com.nirmalks.user_service.auth.api.LoginRequest;
import com.nirmalks.user_service.auth.api.LoginResponse;
import com.nirmalks.user_service.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@Tag(name = "Authentication", description = "User login and authentication operations") // Added
																						// Tag
public class AuthController {

	@Autowired
	private UserService userService;

	@Autowired
	private AuthenticationManager authenticationManager;

	@PostMapping("/login")
	@Operation(summary = "User login",
			description = "Authenticates a user and returns a JWT token upon successful login.") // Added
																									// Operation
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Login successful, returns JWT token"),
			@ApiResponse(responseCode = "401", description = "Invalid credentials") })
	public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest loginRequest) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		if (authentication.isAuthenticated()) {
			LoginResponse loginResponse = userService.authenticate(loginRequest.getUsername(),
					loginRequest.getPassword());
			return ResponseEntity.ok(loginResponse);
		}
		throw new BadCredentialsException("Invalid credentials");
	}

}