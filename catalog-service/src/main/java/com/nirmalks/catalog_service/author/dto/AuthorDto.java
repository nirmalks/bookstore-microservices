package com.nirmalks.catalog_service.author.dto;

public class AuthorDto {

	private Long id;

	private String name;

	private String bio;

	public AuthorDto(Long id, String name, String bio) {
		this.id = id;
		this.name = name;
		this.bio = bio;
	}

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

	public String getBio() {
		return bio;
	}

	public void setBio(String bio) {
		this.bio = bio;
	}

	@Override
	public String toString() {
		return "AuthorDto{" + "id=" + id + ", name='" + name + '\'' + ", bio='" + bio + '\'' + '}';
	}

}
