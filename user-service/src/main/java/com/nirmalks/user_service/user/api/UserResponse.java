package com.nirmalks.user_service.user.api;

import dto.UserRole;

public class UserResponse {

	private Long id;

	private String username;

	private String email;

	private UserRole userRole;

	public UserRole getUserRole() {
		return userRole;
	}

	public void setUserRole(UserRole userRole) {
		this.userRole = userRole;
	}

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

	@Override
	public String toString() {
		return "UserResponse{" + "id=" + id + ", username='" + username + '\'' + ", email='" + email + '\''
				+ ", userRole=" + userRole + '}';
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

}
