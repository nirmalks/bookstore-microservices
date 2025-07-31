package com.nirmalks.checkout_service.order.service;

import com.nirmalks.checkout_service.order.api.DirectOrderRequest;
import com.nirmalks.checkout_service.order.api.OrderFromCartRequest;
import com.nirmalks.checkout_service.order.api.OrderResponse;
import com.nirmalks.checkout_service.order.dto.OrderSummaryDto;
import com.nirmalks.checkout_service.order.entity.Order;
import com.nirmalks.checkout_service.order.entity.OrderStatus;
import dto.PageRequestDto;
import org.springframework.data.domain.Page;

public interface OrderService {
    OrderResponse createOrder(DirectOrderRequest directOrderRequest);

    OrderResponse createOrder(OrderFromCartRequest orderFromCartRequest);

    Page<OrderSummaryDto> getOrdersByUser(Long userId, PageRequestDto pageRequestDto);

    Order getOrder(Long orderId);

    void updateOrderStatus(Long orderId, OrderStatus status);
}
