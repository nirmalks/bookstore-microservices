package com.nirmalks.user_service.user.service;

import com.nirmalks.user_service.auth.api.LoginResponse;
import com.nirmalks.user_service.user.api.CreateUserRequest;
import com.nirmalks.user_service.user.api.UpdateUserRequest;
import com.nirmalks.user_service.user.api.UserResponse;
import com.nirmalks.user_service.user.entity.User;
import dto.*;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

@Service
public interface UserService {

	Page<UserResponse> getUsers(PageRequestDto pageRequestDto);

	UserResponse createUser(CreateUserRequest userRequest, UserRole userRole);

	UserResponse getUserById(Long id);

	UserResponse updateUser(Long id, UpdateUserRequest userRequest);

	void deleteUser(Long userId);

	LoginResponse authenticate(String username, String password);

	AddressDto updateAddress(AddressRequestWithUserId addressRequest);

	UserDto internalAuthenticate(String username, String password);

	User findByUsername(String username);

}
