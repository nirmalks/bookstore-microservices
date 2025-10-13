package com.nirmalks.checkout_service.order.service.impl;


import com.nirmalks.checkout_service.cart.entity.Cart;
import com.nirmalks.checkout_service.cart.entity.CartItem;
import com.nirmalks.checkout_service.cart.repository.CartRepository;
import com.nirmalks.checkout_service.common.BookDto;
import com.nirmalks.checkout_service.common.UserDto;
import com.nirmalks.checkout_service.order.api.DirectOrderRequest;
import com.nirmalks.checkout_service.order.api.OrderFromCartRequest;
import com.nirmalks.checkout_service.order.api.OrderResponse;
import com.nirmalks.checkout_service.order.dto.OrderMapper;
import com.nirmalks.checkout_service.order.dto.OrderSummaryDto;
import com.nirmalks.checkout_service.order.entity.Order;
import com.nirmalks.checkout_service.order.entity.OrderItem;
import com.nirmalks.checkout_service.order.entity.OrderStatus;
import com.nirmalks.checkout_service.order.repository.OrderItemRepository;
import com.nirmalks.checkout_service.order.repository.OrderRepository;
import com.nirmalks.checkout_service.order.service.OrderService;
import common.RequestUtils;
import dto.PageRequestDto;
import exceptions.ResourceNotFoundException;
import exceptions.ServiceUnavailableException;
import io.github.resilience4j.bulkhead.annotation.Bulkhead;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import io.github.resilience4j.retry.annotation.Retry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class OrderServiceImpl implements OrderService {

    private OrderRepository orderRepository;

    private OrderItemRepository orderItemRepository;
    private final CartRepository cartRepository;
    private final WebClient catalogServiceWebClient;
    private final WebClient userServiceWebClient;
    @Autowired
    public OrderServiceImpl(OrderRepository orderRepository, OrderItemRepository orderItemRepository,
                            CartRepository cartRepository, @Qualifier("catalogServiceWebClient") WebClient catalogServiceWebClient,
                            @Qualifier("userServiceWebClient") WebClient userServiceWebClient) {
        this.orderRepository = orderRepository;
        this.orderItemRepository = orderItemRepository;
        this.cartRepository = cartRepository;
        this.catalogServiceWebClient = catalogServiceWebClient;
        this.userServiceWebClient = userServiceWebClient;
    }

    @Override
    public OrderResponse createOrder(DirectOrderRequest directOrderRequest) {
        var user = getUserDtoFromUserService(directOrderRequest.getUserId()).block();

        var itemDtos = directOrderRequest.getItems();
        var order = OrderMapper.toOrderEntity(user, directOrderRequest.getAddress());
        var orderItems = itemDtos.stream().map(itemDto -> {
            var book = getBookDtoFromCatalogService(itemDto.getBookId()).block();
            return OrderMapper.toOrderItemEntity(book, itemDto, order);
        }).toList();
        order.setItems(orderItems);
        order.setTotalCost(order.calculateTotalCost());
        var savedOrder = orderRepository.save(order);
        orderItemRepository.saveAll(orderItems);
        return OrderMapper.toResponse(user, savedOrder,"Order placed successfully.");
    }

    @Override
    public OrderResponse createOrder(OrderFromCartRequest orderFromCartRequest) {
        Cart cart = cartRepository.findById(orderFromCartRequest.getCartId()).orElseThrow(() -> new ResourceNotFoundException("Cart not found"));
        List<OrderItem> orderItems = new ArrayList<>();
        UserDto user = getUserDtoFromUserService(orderFromCartRequest.getUserId()).block();
        Order order = OrderMapper.toOrderEntity(user, orderFromCartRequest.getShippingAddress());

        for(CartItem cartItem: cart.getCartItems()) {
            BookDto book = getBookDtoFromCatalogService(cartItem.getBookId()).block();

            var orderItem = OrderMapper.toOrderItemEntity(book, cartItem, order);
            orderItems.add(orderItem);
        }

        order.setUserId(orderFromCartRequest.getUserId());
        order.setItems(orderItems);
        order.setTotalCost(cart.getTotalPrice());
        order.setOrderStatus(OrderStatus.PENDING);
        order.setPlacedDate(LocalDateTime.now());
        Order savedOrder = orderRepository.save(order);

        for (OrderItem item : orderItems) {
            item.setOrder(savedOrder);
            orderItemRepository.save(item);
        }
        return OrderMapper.toResponse(user, savedOrder, "Order placed successfully.");
    }

    public Page<OrderSummaryDto> getOrdersByUser(Long userId, PageRequestDto pageRequestDto) {
        var user = getUserDtoFromUserService(userId).block();
        var pageable = RequestUtils.getPageable(pageRequestDto);
        var orders = orderRepository.findAllByUserId(userId, pageable);
        return orders.map(order -> OrderMapper.toOrderSummary(order, user));
    }

    @Override
    public Order getOrder(Long orderId) {
        return orderRepository.findById(orderId).orElseThrow(() -> new ResourceNotFoundException("Order not found"));
    }

    public void updateOrderStatus(Long orderId, OrderStatus status) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new IllegalArgumentException("Order not found"));
        order.setOrderStatus(status);
        orderRepository.save(order);
    }

    @Retry(name = "userService", fallbackMethod = "getUserDtoFallback")
    @CircuitBreaker(name = "userService", fallbackMethod = "getUserDtoFallback")
    @Bulkhead(name = "userService")
    @RateLimiter(name = "userService", fallbackMethod = "getUserDtoFallback")
    public Mono<UserDto> getUserDtoFromUserService(Long userId) {
        return userServiceWebClient.get()
                .uri("/api/users/{id}", userId)
                .retrieve()
                .bodyToMono(UserDto.class)
                .onErrorMap(ex -> {
                    if (ex instanceof WebClientResponseException wcEx &&
                            wcEx.getStatusCode() == HttpStatus.NOT_FOUND) {
                        return new ResourceNotFoundException("User not found for ID: " + userId);
                    }
                    return ex;
                });
    }

    @Bulkhead(name = "catalogService")
    @CircuitBreaker(name = "catalogService", fallbackMethod = "getBookDtoFallback")
    @Retry(name = "catalogService", fallbackMethod = "getBookDtoFallback")
    @RateLimiter(name = "catalogService", fallbackMethod = "getBookDtoFallback")
    public Mono<BookDto> getBookDtoFromCatalogService(Long bookId) {
        return catalogServiceWebClient.get().uri("/api/books/{id}", bookId)
                .retrieve()
                .bodyToMono(BookDto.class)
                .onErrorMap(ex -> {
                    if (ex instanceof WebClientResponseException wcEx && wcEx.getStatusCode() == HttpStatus.NOT_FOUND) {
                        return new ResourceNotFoundException("Book not found for ID: " + bookId);
                    }
                    return ex;
                })
        .onErrorResume(throwable -> getBookDtoFallback(bookId, throwable));
    }

    private UserDto getUserDtoFallback(Long userId, Throwable t) {
        System.err.println("User Service call failed after retries/bulkhead limit. Error: " + t.getMessage());
        throw new ServiceUnavailableException("Cannot retrieve User details. System is currently unavailable.");
    }

    private Mono<BookDto> getBookDtoFallback(Long bookId, Throwable t) {
        System.err.println("Catalog Service call failed due to rate limit/bulkhead. Error: " + t.getMessage());
        throw new ServiceUnavailableException("Cannot verify Book details. System is currently unavailable.");
    }

}
