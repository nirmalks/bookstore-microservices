package com.nirmalks.checkout_service.cart.dto;

import com.nirmalks.checkout_service.cart.api.CartItemRequest;
import com.nirmalks.checkout_service.cart.api.CartResponse;
import com.nirmalks.checkout_service.cart.entity.Cart;
import com.nirmalks.checkout_service.cart.entity.CartItem;
import com.nirmalks.checkout_service.common.BookDto;

import java.util.Optional;

public class CartMapper {

	public static CartResponse toResponse(Cart cart) {
		CartResponse response = new CartResponse();
		response.setItems(cart.getCartItems().stream().map(CartMapper::toCartItemDto).toList());
		response.setTotalPrice(cart.getTotalPrice());
		return response;
	}

	public static CartItemDto toCartItemDto(CartItem item) {
		return new CartItemDto(item.getId(), item.getBookId(), item.getQuantity(), item.getPrice());
	}

	public static Cart toEntity(BookDto book, Cart cart, CartItemRequest cartItemRequest) {
		Optional<CartItem> existingCartItem = cart.getCartItems()
			.stream()
			.filter(item -> item.getBookId().equals(book.getId()))
			.findFirst();

		if (existingCartItem.isPresent()) {
			CartItem cartItem = existingCartItem.get();
			cartItem.setQuantity(cartItem.getQuantity() + cartItemRequest.getQuantity());
			cartItem.setPrice(book.getPrice());
		}
		else {
			CartItem newCartItem = new CartItem();
			newCartItem.setBookId(book.getId());
			newCartItem.setQuantity(cartItemRequest.getQuantity());
			newCartItem.setPrice(book.getPrice());
			newCartItem.setCart(cart);
			cart.getCartItems().add(newCartItem);
		}
		cart.setTotalPrice(cart.calculateTotalPrice());
		return cart;
	}

	public static CartItem toCartItemEntity(BookDto book, CartItemDto itemDto) {
		CartItem cartItem = new CartItem();
		cartItem.setBookId(book.getId());
		cartItem.setPrice(itemDto.getPrice());
		cartItem.setQuantity(itemDto.getQuantity());
		return cartItem;
	}

}
