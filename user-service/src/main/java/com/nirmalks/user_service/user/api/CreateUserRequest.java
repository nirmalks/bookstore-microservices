package com.nirmalks.user_service.user.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class CreateUserRequest {

	@NotNull(message = "Password is required")
	@Size(min = 6, message = "Password must be at least 6 characters long")
	private String password;

	@NotNull(message = "Username is required")
	@Size(max = 32, message = "User can be max of 32 characters long")
	private String username;

	public @NotNull(message = "Username is required") @Size(max = 32,
			message = "User can be max of 32 characters long") String getUsername() {
		return username;
	}

	public void setUsername(@NotNull(message = "Username is required") @Size(max = 32,
			message = "User can be max of 32 characters long") String username) {
		this.username = username;
	}

	@Email(message = "Invalid email address")
	private String email;

	public @NotNull(message = "Password is required") @Size(min = 6,
			message = "Password must be at least 6 characters long") String getPassword() {
		return password;
	}

	public void setPassword(@NotNull(message = "Password is required") @Size(min = 6,
			message = "Password must be at least 6 characters long") String password) {
		this.password = password;
	}

	public @Email(message = "Invalid email address") String getEmail() {
		return email;
	}

	public void setEmail(@Email(message = "Invalid email address") String email) {
		this.email = email;
	}

	@Override
	public String toString() {
		return "CreateUserRequest{" + ", username='" + username + '\'' + ", email='" + email + '\'' + '}';
	}

}
