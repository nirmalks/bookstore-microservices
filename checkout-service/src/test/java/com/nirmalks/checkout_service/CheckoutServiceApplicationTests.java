package com.nirmalks.checkout_service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = { "user-service.base-url=http://localhost:8081",
		"catalog-service.base-url=http://localhost:8082" })
class CheckoutServiceApplicationTests {

	@Test
	void contextLoads() {
	}

}
