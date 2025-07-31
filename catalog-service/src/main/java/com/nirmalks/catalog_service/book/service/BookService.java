package com.nirmalks.catalog_service.book.service;

import com.nirmalks.catalog_service.book.api.BookRequest;
import com.nirmalks.catalog_service.book.dto.BookDto;
import common.RestPage;
import dto.PageRequestDto;
import org.springframework.data.domain.Page;

import java.time.LocalDate;

public interface BookService {
    RestPage<BookDto> getAllBooks(PageRequestDto pageRequestDto);
    BookDto getBookById(Long id);
    BookDto createBook(BookRequest bookRequest);
    BookDto updateBook(Long id, BookRequest bookRequest);
    void deleteBookById(Long id);
    Page<BookDto> getBooksByGenre(String genre, PageRequestDto pageRequestDto);
    Page<BookDto> getBooksByAuthor(Long authorId, PageRequestDto pageRequestDto);
    void updateBookStock(Long bookId, int quantity);

    Page<BookDto> getFilteredBooks(String search, String genre, LocalDate startDate, LocalDate endDate, Double minPrice, Double maxPrice, String sortBy, String sortOrder, int page, int size);
}
