package com.nirmalks.checkout_service.order.api;

import dto.AddressRequest;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public class DirectOrderRequest {
    @NotNull
    Long userId;
    @NotNull
    List<OrderItemRequest> items;
    @NotNull
    AddressRequest address;

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public @NotNull List<OrderItemRequest> getItems() {
        return items;
    }

    public void setItems(@NotNull List<OrderItemRequest> items) {
        this.items = items;
    }

    public @NotNull AddressRequest getAddress() {
        return address;
    }

    public void setAddress(@NotNull AddressRequest address) {
        this.address = address;
    }

    @Override
    public String toString() {
        return "DirectOrderRequest{" +
                "userId=" + userId +
                ", items=" + items +
                '}';
    }
}
