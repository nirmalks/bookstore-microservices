package com.nirmalks.user_service.user.controller;

import com.nirmalks.user_service.user.api.CreateUserRequest;
import com.nirmalks.user_service.user.api.UpdateUserRequest;
import com.nirmalks.user_service.user.api.UserResponse;
import com.nirmalks.user_service.user.service.UserService;
import dto.AddressDto;
import dto.AddressRequestWithUserId;
import dto.PageRequestDto;
import dto.UserRole;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@RestController
@RequestMapping("/api/users")
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "User Management", description = "Operations related to user accounts and profiles")
public class UserController {

	@Autowired
	private UserService userService;

	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping()
	@Operation(summary = "Get all users",
			description = "Retrieves a paginated list of all users. Accessible by ADMIN role only.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "List of users returned successfully") })
	public Page<UserResponse> getUsers(PageRequestDto pageRequestDto) {
		return userService.getUsers(pageRequestDto);
	}

	@GetMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN') or @securityUtils.isSameUser(#id)")
	@Operation(summary = "Get user by ID",
			description = "Retrieves user details for a given user ID. Accessible by ADMIN role or the user themselves.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "User found"),
			@ApiResponse(responseCode = "404", description = "User not found"),
			@ApiResponse(responseCode = "403", description = "Forbidden: Not authorized to access this user's data") })
	public UserResponse getUser(@PathVariable Long id) {
		return userService.getUserById(id);
	}

	@PostMapping()
	@Operation(summary = "Add a new customer user",
			description = "Registers a new customer user. This endpoint is public.")
	@ApiResponses(value = { @ApiResponse(responseCode = "201", description = "User created successfully"),
			@ApiResponse(responseCode = "400", description = "Invalid input or user already exists") })
	public ResponseEntity<UserResponse> addUser(@RequestBody @Valid CreateUserRequest userRequest) {
		var userResponse = userService.createUser(userRequest, UserRole.CUSTOMER);
		var location = ServletUriComponentsBuilder.fromCurrentRequest()
			.path("/{id}")
			.buildAndExpand(userResponse.getId())
			.toUri();
		return ResponseEntity.status(HttpStatus.CREATED)
			.header(HttpHeaders.LOCATION, String.valueOf(location))
			.body(userResponse);
	}

	@PutMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN') or @securityUtils.isSameUser(#id)")
	@Operation(summary = "Update user details",
			description = "Updates details of an existing user. Accessible by ADMIN role or the user themselves.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "User updated successfully"),
			@ApiResponse(responseCode = "400", description = "Invalid input"),
			@ApiResponse(responseCode = "404", description = "User not found"),
			@ApiResponse(responseCode = "403", description = "Forbidden: Not authorized to update this user's data") })
	public ResponseEntity<UserResponse> updateUser(@RequestBody @Valid UpdateUserRequest userRequest,
			@PathVariable Long id) {
		var userResponse = userService.updateUser(id, userRequest);
		return ResponseEntity.status(HttpStatus.OK).body(userResponse);
	}

	@PreAuthorize("hasRole('ADMIN')")
	@DeleteMapping("/{id}")
	@Operation(summary = "Delete a user", description = "Deletes a user by ID. Accessible by ADMIN role only.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "User deleted successfully"),
			@ApiResponse(responseCode = "404", description = "User not found") })
	public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
		userService.deleteUser(id);
		return ResponseEntity.status(HttpStatus.OK).build();
	}

	@PostMapping("/register")
	@Operation(summary = "Register a new customer",
			description = "Registers a new customer user. This is a public endpoint for self-registration.")
	@ApiResponses(value = { @ApiResponse(responseCode = "201", description = "Customer registered successfully"),
			@ApiResponse(responseCode = "400", description = "Invalid input or username/email already exists") })
	public ResponseEntity<UserResponse> registerUser(@RequestBody @Valid CreateUserRequest userRequest) {
		var userResponse = userService.createUser(userRequest, UserRole.CUSTOMER);

		var location = ServletUriComponentsBuilder.fromCurrentRequest()
			.path("/{id}")
			.buildAndExpand(userResponse.getId())
			.toUri();
		return ResponseEntity.status(HttpStatus.CREATED)
			.header(HttpHeaders.LOCATION, String.valueOf(location))
			.body(userResponse);
	}

	@PostMapping("/admin/register")
	@PreAuthorize("hasRole('ADMIN')")
	@Operation(summary = "Register a new admin user",
			description = "Registers a new admin user. Accessible by ADMIN role only.")
	@ApiResponses(value = { @ApiResponse(responseCode = "201", description = "Admin user registered successfully"),
			@ApiResponse(responseCode = "400", description = "Invalid input or username/email already exists") })
	public ResponseEntity<UserResponse> registerAdminUser(@RequestBody @Valid CreateUserRequest userRequest) {
		var userResponse = userService.createUser(userRequest, UserRole.ADMIN);
		var location = ServletUriComponentsBuilder.fromCurrentRequest()
			.path("/{id}")
			.buildAndExpand(userResponse.getId())
			.toUri();
		return ResponseEntity.status(HttpStatus.CREATED)
			.header(HttpHeaders.LOCATION, String.valueOf(location))
			.body(userResponse);
	}

	@PostMapping("/address")
	@Operation(summary = "Update user address", description = "Update user address during order")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Address updated successfully"),
			@ApiResponse(responseCode = "400", description = "Invalid input or username/email already exists") })
	public ResponseEntity<AddressDto> updateAddress(@RequestBody @Valid AddressRequestWithUserId addressRequest) {
		var address = userService.updateAddress(addressRequest);
		return ResponseEntity.status(HttpStatus.OK).body(address);
	}

}
