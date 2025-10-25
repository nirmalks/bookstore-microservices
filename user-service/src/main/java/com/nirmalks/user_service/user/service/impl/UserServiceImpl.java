package com.nirmalks.user_service.user.service.impl;

import com.nirmalks.user_service.address.mapper.AddressMapper;
import com.nirmalks.user_service.address.repository.AddressRepository;
import com.nirmalks.user_service.auth.api.LoginResponse;
import com.nirmalks.user_service.user.api.CreateUserRequest;
import com.nirmalks.user_service.user.api.UpdateUserRequest;
import com.nirmalks.user_service.user.api.UserResponse;
import com.nirmalks.user_service.user.dto.UserMapper;
import com.nirmalks.user_service.user.entity.User;
import com.nirmalks.user_service.user.repository.UserRepository;
import com.nirmalks.user_service.user.service.UserService;
import dto.*;
import exceptions.ResourceNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import security.JwtUtils;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;
import security.SecurityUtils;

import static common.RequestUtils.getPageable;

@Service
@Transactional
public class UserServiceImpl implements UserService {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private AddressRepository addressRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	public Page<UserResponse> getUsers(PageRequestDto pageRequestDto) {
		return userRepository.findAll(getPageable(pageRequestDto)).map(UserMapper::toResponse);
	}

	@Override
	public UserResponse createUser(CreateUserRequest userRequest, UserRole role) {
		if (userRepository.findByUsername(userRequest.getUsername()).isPresent()) {
			throw new IllegalArgumentException("Username already exists");
		}
		String encryptedPassword = SecurityUtils.encode(userRequest.getPassword(), passwordEncoder);
		userRequest.setPassword(encryptedPassword);
		User user = UserMapper.toEntity(userRequest, role);
		userRepository.save(user);
		return UserMapper.toResponse(user);
	}

	@Override
	public UserResponse getUserById(Long id) {
		User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User not found"));
		return UserMapper.toResponse(user);
	}

	@Override
	public UserResponse updateUser(Long id, UpdateUserRequest userRequest) {
		User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User not found"));
		User updatedUser = userRepository.save(UserMapper.toEntity(user, userRequest));
		return UserMapper.toResponse(updatedUser);
	}

	@Override
	public void deleteUser(Long userId) {
		User user = userRepository.findById(userId).orElseThrow(() -> new ResourceNotFoundException("User not found"));
		userRepository.deleteById(userId);
	}

	@Override
	public LoginResponse authenticate(String username, String password) {
		var user = userRepository.findByUsername(username)
			.orElseThrow(() -> new ResourceNotFoundException("user not found"));
		String token = JwtUtils.generateToken(user.getUsername(), user.getAuthorities());
		if (!SecurityUtils.matches(password, user.getPassword(), passwordEncoder)) {
			throw new IllegalArgumentException("Invalid username or password");
		}
		LoginResponse loginResponse = new LoginResponse();
		loginResponse.setToken(token);
		loginResponse.setUsername(user.getUsername());
		loginResponse.setUserId(user.getId());
		loginResponse.setRole(user.getRole().name());
		return loginResponse;
	}

	@Override
	public UserDto internalAuthenticate(String username, String password) {
		var user = userRepository.findByUsername(username)
			.orElseThrow(() -> new ResourceNotFoundException("user not found"));

		if (!SecurityUtils.matches(password, user.getPassword(), passwordEncoder)) {
			throw new IllegalArgumentException("Invalid username or password");
		}
		UserDto userDto = new UserDto();
		userDto.setUsername(user.getUsername());
		userDto.setHashedPassword(user.getPassword());
		userDto.setRole(user.getRole());
		userDto.setId(user.getId());
		return userDto;
	}

	@Override
	public AddressDto updateAddress(AddressRequestWithUserId addressRequest) {
		var user = userRepository.findById(addressRequest.getUserId())
			.orElseThrow(() -> new ResourceNotFoundException("User not found"));
		var address = AddressMapper.toEntity(addressRequest);
		address.setUser(user);
		return AddressMapper.toDto(addressRepository.save(address));
	}

	@Override
	public User findByUsername(String username) {
		return userRepository.findByUsername(username)
			.orElseThrow(() -> new ResourceNotFoundException("User not found"));
	}

}
