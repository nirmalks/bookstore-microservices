package com.nirmalks.user_service.security;

import com.nirmalks.user_service.user.entity.User;
import com.nirmalks.user_service.user.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component("securityUtils")
public class SecurityUtils {

	private final UserService userService;

	public SecurityUtils(UserService userService) {
		this.userService = userService;
	}

	public boolean isSameUser(Long id) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		System.out.println("auth " + authentication);
		if (authentication != null && authentication.getPrincipal() != null) {
			Long authenticatedUserId = (Long) authentication.getPrincipal();
			System.out.println("Authenticated user ID in sec utils: " + authenticatedUserId);

			return authenticatedUserId.equals(id);

			// if (principal instanceof Long) {
			// // Case 1: The principal is already the user's ID as a Long
			// authenticatedUserId = (Long) principal;
			// } else if (principal instanceof String) {
			// // Case 2: The principal is a String (e.g., username)
			// String principalString = (String) principal;
			// try {
			// // Try to find the user by username to get their ID
			// User authenticatedUser = userService.findByUsername(principalString);
			// authenticatedUserId = authenticatedUser.getId();
			// System.out.println("Authenticated user ID in sec utils: " +
			// authenticatedUserId);
			// } catch (Exception e) {
			// System.err.println("Error finding authenticated user by principal: " +
			// principalString + " | " + e.getMessage());
			// return false;
			// }
			// }
			// return authenticatedUserId != null && authenticatedUserId.equals(id);
		}
		return false;
	}

}
