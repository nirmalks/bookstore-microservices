package com.nirmalks.checkout_service.order.api;

import dto.AddressRequest;
import jakarta.validation.constraints.NotNull;

public class OrderFromCartRequest {
    @NotNull
    Long cartId;
    @NotNull
    Long userId;

    @NotNull
    private AddressRequest shippingAddress;

    public Long getCartId() {
        return cartId;
    }

    public void setCartId(Long cartId) {
        this.cartId = cartId;
    }

    public Long getUserId() {
        return userId;
    }

    public @NotNull AddressRequest getShippingAddress() {
        return shippingAddress;
    }

    public void setShippingAddress(@NotNull AddressRequest shippingAddress) {
        this.shippingAddress = shippingAddress;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    @Override
    public String toString() {
        return "OrderFromCartRequest{" +
                "cartId=" + cartId +
                ", userId=" + userId +
                '}';
    }
}
