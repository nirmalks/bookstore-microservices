package com.nirmalks.bookstore.auth_server;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = { "auth-server.token-uri=http://localhost:8080/oauth/token",
		"user-service.base-url=http://localhost:8081" })
class AuthServerApplicationTests {

	@Test
	void contextLoads() {
	}

}
