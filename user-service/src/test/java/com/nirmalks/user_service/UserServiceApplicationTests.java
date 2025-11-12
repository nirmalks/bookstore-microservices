package com.nirmalks.user_service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
class UserServiceApplicationTests {

	@MockitoBean
	private org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder;

	@Test
	void contextLoads() {
	}

}
