package com.nirmalks.checkout_service.order.dto;

import com.nirmalks.checkout_service.cart.entity.CartItem;
import com.nirmalks.checkout_service.order.entity.ShippingAddress;
import com.nirmalks.checkout_service.common.BookDto;
import com.nirmalks.checkout_service.common.UserDto;
import com.nirmalks.checkout_service.order.api.OrderItemRequest;
import com.nirmalks.checkout_service.order.api.OrderResponse;
import com.nirmalks.checkout_service.order.entity.Order;
import com.nirmalks.checkout_service.order.entity.OrderItem;
import com.nirmalks.checkout_service.order.entity.OrderStatus;
import dto.AddressDto;
import dto.AddressRequest;

import java.time.LocalDateTime;

public class OrderMapper {

    public static ShippingAddress toShippingAddressEntity(AddressRequest addressRequest) {
        if (addressRequest == null) {
            return null;
        }
        ShippingAddress shippingAddress = new ShippingAddress();
        shippingAddress.setAddress(addressRequest.getAddress());
        shippingAddress.setCity(addressRequest.getCity());
        shippingAddress.setState(addressRequest.getState());
        shippingAddress.setPinCode(addressRequest.getPinCode());
        shippingAddress.setCountry(addressRequest.getCountry());
        return shippingAddress;
    }
    public static AddressDto toAddressDto(ShippingAddress shippingAddress) {
        if (shippingAddress == null) {
            return null;
        }
        AddressDto addressDto = new AddressDto();
        addressDto.setAddress(shippingAddress.getAddress());
        addressDto.setCity(shippingAddress.getCity());
        addressDto.setState(shippingAddress.getState());
        addressDto.setPinCode(shippingAddress.getPinCode());
        addressDto.setCountry(shippingAddress.getCountry());

        return addressDto;
    }

    public static Order toOrderEntity(UserDto user, AddressRequest addressRequest) {
        Order order = new Order();
        order.setUserId(user.getId());
        order.setOrderStatus(OrderStatus.PENDING);
        order.setPlacedDate(LocalDateTime.now());
        order.setTotalCost(0.0);
        order.setShippingAddress(OrderMapper.toShippingAddressEntity(addressRequest));
        return order;
    }

    public static OrderItem toOrderItemEntity(BookDto book, CartItem cartItem, Order order) {
        var orderItem = new OrderItem();
        orderItem.setBookId(cartItem.getBookId());
        orderItem.setQuantity(cartItem.getQuantity());
        orderItem.setPrice(book.getPrice());
        orderItem.setBookTitle(book.getTitle());
        orderItem.setOrder(order);
        return orderItem;
    }

    public static OrderItem toOrderItemEntity(BookDto book, OrderItemRequest itemDto, Order order) {
        var orderItem = new OrderItem();
        orderItem.setBookId(book.getId());
        orderItem.setQuantity(itemDto.getQuantity());
        orderItem.setPrice(book.getPrice());
        orderItem.setBookTitle(book.getTitle());
        orderItem.setOrder(order);
        return orderItem;
    }

    public static OrderResponse toResponse(UserDto user, Order order, String message) {
        OrderResponse response = new OrderResponse();
        response.setMessage(message);
        response.setOrder(toOrderSummary(order, user));
        response.setUser(user);
        return response;
    }


    public static OrderSummaryDto toOrderSummary(Order order, UserDto user) {
        OrderSummaryDto orderSummary = new OrderSummaryDto();
        orderSummary.setId(order.getId());
        orderSummary.setStatus(order.getOrderStatus().toString());
        orderSummary.setPlacedDate(order.getPlacedDate());
        orderSummary.setTotalCost(order.getTotalCost());
        orderSummary.setItems(order.getItems().stream().map(OrderMapper::toOrderItemDto).toList());
        orderSummary.setAddress(OrderMapper.toAddressDto(order.getShippingAddress()));

        return orderSummary;
    }

    public static OrderItemDto toOrderItemDto(OrderItem orderItem) {
        var orderItemDto = new OrderItemDto();
        if (orderItem.getOrder() != null) {
            orderItemDto.setOrderId(orderItem.getOrder().getId());
        }
        orderItemDto.setBookId(orderItem.getBookId());
        orderItemDto.setQuantity(orderItem.getQuantity());
        orderItemDto.setId(orderItem.getId());
        orderItemDto.setPrice(orderItem.getPrice());
        orderItemDto.setName(orderItem.getBookTitle());
        return orderItemDto;
    }
}