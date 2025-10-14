package com.nirmalks.user_service.auth.api;

public class LoginResponse {

	private String token;

	private String username;

	private Long userId;

	private String role;

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

	@Override
	public String toString() {
		return "LoginResponse{" + ", username='" + username + '\'' + ", userId=" + userId + ", role='" + role + '\''
				+ '}';
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public Long getUserId() {
		return userId;
	}

	public void setUserId(Long userId) {
		this.userId = userId;
	}

}
