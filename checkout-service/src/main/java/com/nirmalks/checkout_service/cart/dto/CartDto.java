package com.nirmalks.checkout_service.cart.dto;

import java.math.BigDecimal;

public class CartDto {

	private Long id;

	private Long userId;

	private BigDecimal totalPrice;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Long getUserId() {
		return userId;
	}

	public void setUserId(Long userId) {
		this.userId = userId;
	}

	public BigDecimal getTotalPrice() {
		return totalPrice;
	}

	public void setTotalPrice(BigDecimal totalPrice) {
		this.totalPrice = totalPrice;
	}

	@Override
	public String toString() {
		return "CartDto{" + "id=" + id + ", userId=" + userId + ", totalPrice=" + totalPrice + '}';
	}

}
