package com.nirmalks.checkout_service.cart.dto;


public class CartItemDto {
    private Long id;
    private Long bookId;
    private int quantity;
    private double price;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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

    public CartItemDto(Long id, Long bookId, int quantity, double price) {
        this.id = id;
        this.bookId = bookId;
        this.quantity = quantity;
        this.price = price;
    }

    @Override
    public String toString() {
        return "CartItemDto{" +
                "id=" + id +
                ", bookId=" + bookId +
                ", quantity=" + quantity +
                ", price=" + price +
                '}';
    }
}
