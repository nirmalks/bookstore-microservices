package com.nirmalks.checkout_service.cart.api;

import com.nirmalks.checkout_service.cart.dto.CartItemDto;

import java.util.List;

public class CartResponse {

	private Long id;

	private List<CartItemDto> items;

	private double totalPrice;

	public List<CartItemDto> getItems() {
		return items;
	}

	public void setItems(List<CartItemDto> items) {
		this.items = items;
	}

	public double getTotalPrice() {
		return totalPrice;
	}

	public void setTotalPrice(double totalPrice) {
		this.totalPrice = totalPrice;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	@Override
	public String toString() {
		return "CartResponse{" + "id=" + id + ", items=" + items + ", totalPrice=" + totalPrice + '}';
	}

}
