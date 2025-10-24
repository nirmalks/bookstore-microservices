package com.nirmalks.checkout_service.order.dto;

public class OrderItemDto {

	private Long id;

	private Long orderId;

	private Long bookId;

	private int quantity;

	private double price;

	private String name;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Long getOrderId() {
		return orderId;
	}

	public void setOrderId(Long orderId) {
		this.orderId = orderId;
	}

	public Long getBookId() {
		return bookId;
	}

	public void setBookId(Long bookId) {
		this.bookId = bookId;
	}

	public int getQuantity() {
		return quantity;
	}

	public void setQuantity(int quantity) {
		this.quantity = quantity;
	}

	public double getPrice() {
		return price;
	}

	public void setPrice(double price) {
		this.price = price;
	}

	@Override
	public String toString() {
		return "OrderItemDto{" + "id=" + id + ", orderId=" + orderId + ", bookId=" + bookId + ", quantity=" + quantity
				+ ", price=" + price + '}';
	}

}
