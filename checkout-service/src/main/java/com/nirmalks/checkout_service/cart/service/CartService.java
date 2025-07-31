package com.nirmalks.checkout_service.cart.service;


import com.nirmalks.checkout_service.cart.api.CartItemRequest;
import com.nirmalks.checkout_service.cart.api.CartResponse;

public interface CartService {
    CartResponse getCart(Long userId);

    CartResponse addToCart(Long userId, CartItemRequest cartItemRequest);

    void clearCart(Long userId);

    void removeItemFromCart(Long cartId, Long itemId);
}
