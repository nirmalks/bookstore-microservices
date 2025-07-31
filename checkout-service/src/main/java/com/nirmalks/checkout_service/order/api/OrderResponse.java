package com.nirmalks.checkout_service.order.api;

import com.nirmalks.checkout_service.common.UserDto;
import com.nirmalks.checkout_service.order.dto.OrderSummaryDto;

public class OrderResponse {

    private String message;
    private OrderSummaryDto order;

    public UserDto getUser() {
        return user;
    }

    public void setUser(UserDto user) {
        this.user = user;
    }

    private UserDto user;

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public OrderSummaryDto getOrder() {
        return order;
    }

    public void setOrder(OrderSummaryDto order) {
        this.order = order;
    }


    @Override
    public String toString() {
        return "OrderResponseDto{" +
                "message='" + message + '\'' +
                ", order=" + order +
                ", user=" + user +
                '}';
    }
}
