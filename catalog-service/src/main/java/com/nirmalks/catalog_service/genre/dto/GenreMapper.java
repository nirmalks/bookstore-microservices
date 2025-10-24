package com.nirmalks.catalog_service.genre.dto;

import com.nirmalks.catalog_service.genre.api.GenreRequest;
import com.nirmalks.catalog_service.genre.entity.Genre;

public class GenreMapper {

	public static GenreDto toDto(Genre genre) {
		GenreDto dto = new GenreDto();
		dto.setId(genre.getId());
		dto.setName(genre.getName());
		return dto;
	}

	public static Genre toEntity(Genre genre, GenreRequest genreRequest) {
		genre.setName(genreRequest.getName());
		return genre;
	}

	public static Genre toEntity(GenreRequest genreRequest) {
		Genre genre = new Genre();
		genre.setName(genreRequest.getName());
		return genre;
	}

}
