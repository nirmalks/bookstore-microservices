package com.nirmalks.catalog_service.genre.service;

import com.nirmalks.catalog_service.genre.api.GenreRequest;
import com.nirmalks.catalog_service.genre.dto.GenreDto;
import com.nirmalks.catalog_service.genre.entity.Genre;
import dto.PageRequestDto;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface GenreService {
    GenreDto createGenre(GenreRequest genreRequest);

    GenreDto updateGenre(Long id, GenreRequest genreRequest);

    GenreDto getGenreById(Long id);

    Page<GenreDto> getAllGenres(PageRequestDto pageRequestDto);

    void deleteGenreById(Long id);

    List<Genre> getGenresByIds(List<Long> ids);

    void validateGenreName(String name);
}

