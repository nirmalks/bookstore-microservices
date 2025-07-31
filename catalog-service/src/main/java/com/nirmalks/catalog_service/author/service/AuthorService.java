package com.nirmalks.catalog_service.author.service;


import com.nirmalks.catalog_service.author.api.AuthorRequest;
import com.nirmalks.catalog_service.author.dto.AuthorDto;
import com.nirmalks.catalog_service.author.entity.Author;
import dto.PageRequestDto;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface AuthorService {
    AuthorDto createAuthor(AuthorRequest authorRequest);
    AuthorDto updateAuthor(Long id, AuthorRequest authorRequest);
    AuthorDto getAuthorById(Long id);
    Page<AuthorDto> getAllAuthors(PageRequestDto pageRequestDto);
    void deleteAuthorById(Long id);
    List<Author> getAuthorsByIds(List<Long> ids);
}
