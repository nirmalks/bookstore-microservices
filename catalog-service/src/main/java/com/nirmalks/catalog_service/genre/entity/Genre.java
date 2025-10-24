package com.nirmalks.catalog_service.genre.entity;

import com.nirmalks.catalog_service.book.entity.Book;
import jakarta.persistence.*;

import java.util.List;
import java.util.Objects;

@Entity
public class Genre {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String name;

	@ManyToMany(mappedBy = "genres")
	private List<Book> books;

	public List<Book> getBooks() {
		return books;
	}

	public void setBooks(List<Book> books) {
		this.books = books;
	}

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

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		Genre genre = (Genre) o;
		return Objects.equals(id, genre.id);
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(id);
	}

}
