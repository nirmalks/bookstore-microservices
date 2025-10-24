package com.nirmalks.checkout_service.cart.controller;

import com.nirmalks.checkout_service.cart.api.CartItemRequest;
import com.nirmalks.checkout_service.cart.api.CartResponse;
import com.nirmalks.checkout_service.cart.service.CartService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/cart")
@SecurityRequirement(name = "bearerAuth") // Assuming cart operations require
											// authentication
@Tag(name = "Shopping Cart", description = "Operations related to user shopping carts") // Added
																						// Tag
public class CartController {

	@Autowired
	private CartService cartService;

	@GetMapping("/{userId}")
	@Operation(summary = "Get user's shopping cart", description = "Retrieves the shopping cart for a specific user.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Shopping cart retrieved successfully"),
			@ApiResponse(responseCode = "404", description = "User or cart not found") })
	public CartResponse getCart(@PathVariable Long userId) {
		return cartService.getCart(userId);
	}

	@PostMapping("/{userId}")
	@Operation(summary = "Add item to cart", description = "Adds a book to the specified user's shopping cart.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Item added to cart successfully"),
			@ApiResponse(responseCode = "400", description = "Invalid input or book not available"),
			@ApiResponse(responseCode = "404", description = "User or book not found") })
	public CartResponse addToCart(@PathVariable Long userId, @RequestBody CartItemRequest cartItemRequest) {
		return cartService.addToCart(userId, cartItemRequest);
	}

	@DeleteMapping("/{userId}")
	@Operation(summary = "Clear user's shopping cart",
			description = "Removes all items from the specified user's shopping cart.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Cart cleared successfully"),
			@ApiResponse(responseCode = "404", description = "User or cart not found") })
	public void clearCart(@PathVariable Long userId) {
		cartService.clearCart(userId);
	}

	@DeleteMapping("/{cartId}/item/{itemId}")
	@Operation(summary = "Remove item from cart", description = "Removes a specific item from a user's shopping cart.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Item removed from cart successfully"),
			@ApiResponse(responseCode = "404", description = "Cart or item not found") })
	public ResponseEntity<String> removeItemFromCart(@PathVariable Long cartId, @PathVariable Long itemId) {
		cartService.removeItemFromCart(cartId, itemId);
		return ResponseEntity.ok("Item removed from cart");
	}

}
