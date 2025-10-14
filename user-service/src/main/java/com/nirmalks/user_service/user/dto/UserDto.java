package com.nirmalks.user_service.user.dto;

import dto.UserRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;

public class UserDto {

	@NotNull(message = "Username is required")
	private String username;

	private Long id;

	@NotNull(message = "Role is required")
	private UserRole role;

	@Email(message = "Invalid email address")
	private String email;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public UserRole getRole() {
		return role;
	}

	public void setRole(UserRole role) {
		this.role = role;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	@Override
	public String toString() {
		return "UserDto{" + "username='" + username + '\'' + ", id=" + id + ", role=" + role + ", email='" + email
				+ '\'' + '}';
	}

}
