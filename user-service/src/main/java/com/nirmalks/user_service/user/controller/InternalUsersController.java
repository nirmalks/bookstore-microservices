package com.nirmalks.user_service.user.controller;
import dto.UserDto;
import com.nirmalks.user_service.user.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequestMapping("/api/internal/users")
public class InternalUsersController {
        private final UserRepository userRepository;

        public InternalUsersController(UserRepository userRepository) {
            this.userRepository = userRepository;
        }

        @GetMapping("/by-username/{username}")
        public ResponseEntity<UserDto> getUserByUsername(@PathVariable String username) {
            return userRepository.findByUsername(username)
                    .map(user -> {
                        UserDto dto = new UserDto();
                        dto.setUsername(user.getUsername());
                        dto.setHashedPassword(user.getPassword());
                        dto.setRole(user.getRole());
                        return ResponseEntity.ok(dto);
                    })
                    .orElse(ResponseEntity.notFound().build());
        }
}
