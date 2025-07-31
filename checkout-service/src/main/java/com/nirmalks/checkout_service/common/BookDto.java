package com.nirmalks.checkout_service.common;

import java.time.LocalDate;
import java.util.List;

public class BookDto {
    private Long id;
    private String title;
    private List<Long> authorIds;
    private Double price;
    private int stock;
    private String isbn;
    private LocalDate publishedDate;
    private List<Long> genreIds;
    private String description;
    private String imagePath;

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getImagePath() {
        return imagePath;
    }

    public void setImagePath(String imagePath) {
        this.imagePath = imagePath;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public List<Long> getAuthorIds() {
        return authorIds;
    }

    public void setAuthorIds(List<Long> authorIds) {
        this.authorIds = authorIds;
    }

    public List<Long> getGenreIds() {
        return genreIds;
    }

    public void setGenreIds(List<Long> genreIds) {
        this.genreIds = genreIds;
    }

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
        this.price = price;
    }

    public int getStock() {
        return stock;
    }

    public void setStock(int stock) {
        this.stock = stock;
    }

    public String getIsbn() {
        return isbn;
    }

    public void setIsbn(String isbn) {
        this.isbn = isbn;
    }

    public LocalDate getPublishedDate() {
        return publishedDate;
    }

    public void setPublishedDate(LocalDate publishedDate) {
        this.publishedDate = publishedDate;
    }

    public BookDto(Long id, String title, List<Long> authorIds, Double price, int stock, String isbn, LocalDate publishedDate, List<Long> genreIds,
                   String description, String imagePath) {
        this.id = id;
        this.title = title;
        this.authorIds = authorIds;
        this.price = price;
        this.stock = stock;
        this.isbn = isbn;
        this.publishedDate = publishedDate;
        this.genreIds = genreIds;
        this.description = description;
        this.imagePath = imagePath;
    }
    public BookDto() {}

    @Override
    public String toString() {
        return "BookDto{" +
                "id=" + id +
                ", title='" + title + '\'' +
                ", authorIds=" + authorIds +
                ", price=" + price +
                ", stock=" + stock +
                ", isbn='" + isbn + '\'' +
                ", publishedDate=" + publishedDate +
                ", genreIds=" + genreIds +
                ", description='" + description + '\'' +
                ", imagePath='" + imagePath + '\'' +
                '}';
    }
}
