package com.nirmalks.catalog_service.genre.dto;

public class GenreDto {

	private Long id;

	private String name;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Override
	public String toString() {
		return "GenreDto{" + "id=" + id + ", name='" + name + '\'' + '}';
	}

}
