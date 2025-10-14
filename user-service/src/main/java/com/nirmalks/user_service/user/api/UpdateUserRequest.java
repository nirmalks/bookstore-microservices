package com.nirmalks.user_service.user.api;

import dto.UserRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class UpdateUserRequest {

	@NotNull(message = "Password is required")
	@Size(min = 6, message = "Password must be at least 6 characters long")
	private String password;

	private UserRole role;

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

	public UserRole getRole() {
		return role;
	}

	public void setRole(UserRole role) {
		this.role = role;
	}

	public @Email(message = "Invalid email address") String getEmail() {
		return email;
	}

	public void setEmail(@Email(message = "Invalid email address") String email) {
		this.email = email;
	}

	@Override
	public String toString() {
		return "UpdateUserRequest{" + "password='" + password + '\'' + ", role=" + role + ", email='" + email + '\''
				+ '}';
	}

}
