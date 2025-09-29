package com.nirmalks.checkout_service.cart.service;

import com.nirmalks.checkout_service.cart.api.CartItemRequest;
import com.nirmalks.checkout_service.cart.api.CartResponse;
import com.nirmalks.checkout_service.cart.dto.CartMapper;
import com.nirmalks.checkout_service.cart.entity.Cart;
import com.nirmalks.checkout_service.cart.entity.CartItem;
import com.nirmalks.checkout_service.cart.repository.CartItemRepository;
import com.nirmalks.checkout_service.cart.repository.CartRepository;
import com.nirmalks.checkout_service.common.BookDto;
import com.nirmalks.checkout_service.common.UserDto;
import exceptions.ResourceNotFoundException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@Service
public class CartServiceImpl implements CartService {
    @Autowired
    private CartRepository cartRepository;

    @Autowired
    private CartItemRepository cartItemRepository;

    private final WebClient catalogServiceWebClient;

    public CartServiceImpl(
            @Qualifier("catalogServiceWebClient") WebClient catalogServiceWebClient) {
        this.catalogServiceWebClient = catalogServiceWebClient;
    }
    public CartResponse getCart(Long userId) {
        Cart cart = cartRepository.findByUserId(userId)
                .orElseThrow(() -> new ResourceNotFoundException("Cart not found for user"));
        return CartMapper.toResponse(cart);
    }

    public BookDto catalogServiceUnavailableFallback(Long bookId, Throwable ex) {
        throw new RuntimeException("Catalog service unavailable, cannot add book to cart");
    }

    @CircuitBreaker(name = "catalogServiceCB", fallbackMethod = "catalogServiceUnavailableFallback")
    public Mono<BookDto> getBookDto(Long bookId) {
        return catalogServiceWebClient.get().uri("/api/books/{id}", bookId)
                .retrieve()
                .bodyToMono(BookDto.class)
                .onErrorMap(ex -> {
                    if (ex instanceof WebClientResponseException wcEx && wcEx.getStatusCode().is4xxClientError()) {
                        return new ResourceNotFoundException("Book not found for ID: " + bookId);
                    }
                    return ex;
                });
    }
    public CartResponse addToCart(Long userId, CartItemRequest cartItemRequest) {
        BookDto book = getBookDto(cartItemRequest.getBookId()).block();
        Cart cart = cartRepository.findByUserId(userId)
                .orElseGet(() -> createCartForUser(userId));

        Cart updatedCart = cartRepository.save(CartMapper.toEntity(book,cart,cartItemRequest));
        return CartMapper.toResponse(updatedCart);
    }

    public void clearCart(Long userId) {
        Cart cart = cartRepository.findByUserId(userId)
                .orElseThrow(() -> new ResourceNotFoundException("Cart not found for user"));
        cart.getCartItems().clear();
        cartRepository.save(cart);
    }

    private Cart createCartForUser(Long userId) {
        Cart cart = new Cart();
        cart.setUserId(userId);
        return cartRepository.save(cart);
    }

    public void removeItemFromCart(Long cartId, Long itemId) {
        Cart cart = cartRepository.findById(cartId)
                .orElseThrow(() -> new ResourceNotFoundException("Cart not found"));

        List<CartItem> updatedItems = cart.getCartItems().stream()
                .filter(item -> !item.getId().equals(itemId))
                .toList();

        cart.setCartItems(updatedItems);
        cart.setTotalPrice(updatedItems.stream().mapToDouble(item -> item.getPrice() * item.getQuantity()).sum());

        cartRepository.save(cart);
    }
}
