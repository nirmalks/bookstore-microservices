package com.nirmalks.catalog_service.book.service;

import com.nirmalks.catalog_service.author.service.AuthorService;
import com.nirmalks.catalog_service.book.BookSpecification;
import com.nirmalks.catalog_service.book.api.BookRequest;
import com.nirmalks.catalog_service.book.dto.BookDto;
import com.nirmalks.catalog_service.book.dto.BookMapper;
import com.nirmalks.catalog_service.book.entity.Book;
import com.nirmalks.catalog_service.book.repository.BookRepository;
import com.nirmalks.catalog_service.genre.service.GenreService;
import common.RequestUtils;
import common.RestPage;
import dto.PageRequestDto;
import exceptions.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.time.LocalDate;


@Service
public class BookServiceImpl implements BookService {
    @Autowired
    private BookRepository bookRepository;

    @Autowired
    private AuthorService authorService;

    @Autowired
    private GenreService genreService;

    @Override
    @Cacheable(value = "books", key = "#pageRequestDto.page")
    public RestPage<BookDto> getAllBooks(PageRequestDto pageRequestDto) {
        Pageable pageable = RequestUtils.getPageable(pageRequestDto);
        return new RestPage<>(bookRepository.findAll(pageable).map(BookMapper::toDTO));
    }

    @Override
    @Cacheable(value = "book", key = "#id")
    public BookDto getBookById(Long id) {
        return bookRepository.findById(id).map(BookMapper::toDTO)
                .orElseThrow(() -> new ResourceNotFoundException("Book not found"));
    }

    @Override
    @CacheEvict(value = {"books", "book"}, allEntries = true)
    public BookDto createBook(BookRequest bookRequest) {
        var authors = authorService.getAuthorsByIds(bookRequest.getAuthorIds());
        var genres = genreService.getGenresByIds(bookRequest.getGenreIds());
        return BookMapper.toDTO(bookRepository.save(BookMapper.toEntity(bookRequest, authors, genres)));
    }

    @Override
    @CacheEvict(value = {"books", "book"}, key = "#id")
    public BookDto updateBook(Long id, BookRequest bookRequest) {
        var existingBook = bookRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("book not found"));
        var authors = authorService.getAuthorsByIds(bookRequest.getAuthorIds());
        var genres = genreService.getGenresByIds(bookRequest.getGenreIds());
        return BookMapper.toDTO(bookRepository.save(BookMapper.toEntity(existingBook, bookRequest, authors, genres)));
    }

    @Override
    @CacheEvict(value = {"books", "book"}, key = "#id")
    public void deleteBookById(Long id) {
        bookRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("book not found"));
        bookRepository.deleteById(id);
    }

    @Override
    public Page<BookDto> getBooksByGenre(String genre, PageRequestDto pageRequestDto) {
        genreService.validateGenreName(genre);
        var pageable = RequestUtils.getPageable(pageRequestDto);
        var books = bookRepository.findAllByGenresName(genre, pageable);
        return books.map(BookMapper::toDTO);
    }

    @Override
    public Page<BookDto> getBooksByAuthor(Long authorId, PageRequestDto pageRequestDto) {
        authorService.getAuthorById(authorId);
        var pageable = RequestUtils.getPageable(pageRequestDto);
        var books = bookRepository.findAllByAuthorsId(authorId, pageable);
        return books.map(BookMapper::toDTO);
    }

    @Override
    public void updateBookStock(Long bookId, int quantity) {
        var book = bookRepository.findById(bookId)
                .orElseThrow(() -> new ResourceNotFoundException("Book not found with ID: " + bookId));
        book.setStock(quantity);
        bookRepository.save(book);
    }

    @Override
    public Page<BookDto> getFilteredBooks(String search,
                                                    String genre,
                                                    LocalDate startDate,
                                                    LocalDate endDate,
                                                    Double minPrice,
                                                    Double maxPrice,
                                                    String sortBy,
                                                    String sortOrder,
                                                    int page,
                                                    int size) {
        Pageable pageable = PageRequest.of(page, size);
        Specification<Book> specification = BookSpecification.filterBy(search, genre,
                startDate, endDate, minPrice, maxPrice, sortBy, sortOrder);
        return bookRepository.findAll(specification, pageable).map(BookMapper::toDTO);

    }
}
