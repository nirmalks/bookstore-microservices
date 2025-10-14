package com.nirmalks.user_service.user.dto;

import com.nirmalks.user_service.user.api.CreateUserRequest;
import com.nirmalks.user_service.user.api.UpdateUserRequest;
import com.nirmalks.user_service.user.api.UserResponse;
import com.nirmalks.user_service.user.entity.User;
import dto.UserRole;

public class UserMapper {

	public static UserDto toDto(User user) {
		UserDto dto = new UserDto();
		dto.setId(user.getId());
		dto.setUsername(user.getUsername());
		dto.setEmail(user.getEmail());
		dto.setRole(user.getRole());
		return dto;
	}

	public static User toEntity(UserDto dto) {
		User user = new User();
		user.setUsername(dto.getUsername());
		user.setEmail(dto.getEmail());
		user.setRole(dto.getRole());
		return user;
	}

	public static User toEntity(CreateUserRequest request, UserRole userRole) {
		User user = new User();
		user.setPassword(request.getPassword());
		user.setUsername(request.getUsername());
		user.setEmail(request.getEmail());
		user.setRole(userRole);
		return user;
	}

	public static User toEntity(User existingUser, UpdateUserRequest request) {
		existingUser.setPassword(request.getPassword());
		existingUser.setEmail(request.getEmail());
		existingUser.setRole(request.getRole());
		return existingUser;
	}

	public static UserResponse toResponse(User user) {
		UserResponse response = new UserResponse();
		response.setId(user.getId());
		response.setUsername(user.getUsername());
		response.setEmail(user.getEmail());
		response.setUserRole(user.getRole());
		return response;
	}

}