package com.nirmalks.catalog_service.book.api;

import jakarta.validation.constraints.NotNull;

import java.time.LocalDate;
import java.util.List;

public class BookRequest {

	@NotNull
	private String title;

	@NotNull
	private List<Long> authorIds;

	@NotNull
	private Double price;

	@NotNull
	private int stock;

	@NotNull
	private String isbn;

	@NotNull
	private LocalDate publishedDate;

	@NotNull
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

	public List<Long> getGenreIds() {
		return genreIds;
	}

	public void setGenreIds(List<Long> genreIds) {
		this.genreIds = genreIds;
	}

	@Override
	public String toString() {
		return "BookRequest{" + "title='" + title + '\'' + ", authorIds=" + authorIds + ", price=" + price + ", stock="
				+ stock + ", isbn='" + isbn + '\'' + ", publishedDate=" + publishedDate + ", genreIds=" + genreIds
				+ '}';
	}

}
