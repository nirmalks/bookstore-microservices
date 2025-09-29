package com.nirmalks.catalog_service.book.controller;

import com.nirmalks.catalog_service.book.api.BookRequest;
import com.nirmalks.catalog_service.book.dto.BookDto;
import com.nirmalks.catalog_service.book.service.BookService;
import common.RestPage;
import dto.PageRequestDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.time.LocalDate;

@RestController
@RequestMapping("/api/books")
@SecurityRequirement(name = "bearerAuth") // Added for consistency with AuthorController
@Tag(name = "Book Management", description = "Operations related to books in the Bookstore API") // Added Tag
public class BookController {
    @Autowired
    private BookService bookService;

    @GetMapping
    @Operation(summary = "Get paginated list of books", description = "Returns a list of books based on pagination and sorting parameters. Accessible by all users.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "List of books returned successfully")
    })
    public RestPage<BookDto> getAllBooks(PageRequestDto pageRequestDto
    ) {
        return bookService.getAllBooks(pageRequestDto);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get book by ID", description = "Returns book details for a given book ID. Accessible by all users.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Book found"),
            @ApiResponse(responseCode = "404", description = "Book not found")
    })
    public BookDto getBookById(@PathVariable Long id) {
        return bookService.getBookById(id);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    @Operation(summary = "Create a new book", description = "Creates a new book. Accessible by ADMIN role only.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Book created successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input")
    })
    public ResponseEntity<BookDto> createBook(@RequestBody BookRequest BookRequest) {
        var Book = bookService.createBook(BookRequest);
        var location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
                .buildAndExpand(Book.getId()).toUri();
        return ResponseEntity.status(HttpStatus.CREATED).header(HttpHeaders.LOCATION, String.valueOf(location)).body(Book);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{id}")
    @Operation(summary = "Update an existing book", description = "Updates details of an existing book. Accessible by ADMIN role only.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Book updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input"),
            @ApiResponse(responseCode = "404", description = "Book not found")
    })
    public BookDto updateBook(@PathVariable Long id, @RequestBody BookRequest BookRequest) {
        return bookService.updateBook(id, BookRequest);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    @Operation(summary = "Delete a book", description = "Deletes a book by ID. Accessible by ADMIN role only.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Book deleted successfully"),
            @ApiResponse(responseCode = "404", description = "Book not found")
    })
    public ResponseEntity<Void> deleteBook(@PathVariable Long id) {
        bookService.deleteBookById(id);
        return ResponseEntity.status(HttpStatus.OK).build();
    }

    @GetMapping("/genre/{name}")
    @Operation(summary = "Get books by genre", description = "Returns a paginated list of books belonging to a specific genre. Accessible by all users.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "List of books by genre returned successfully"),
            @ApiResponse(responseCode = "404", description = "Genre not found")
    })
    public Page<BookDto> getBookByGenre(@PathVariable String name,
                                        PageRequestDto pageRequestDto) {
        return bookService.getBooksByGenre(name, pageRequestDto);
    }

    @GetMapping("/author/{id}")
    @Operation(summary = "Get books by author", description = "Returns a paginated list of books by a specific author ID. Accessible by all users.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "List of books by author returned successfully"),
            @ApiResponse(responseCode = "404", description = "Author not found")
    })
    public Page<BookDto> getBookByAuthor(@PathVariable Long id,
                                         @PathVariable String name, // This 'name' path variable seems unused in the method body. Consider removing if not needed.
                                         PageRequestDto pageRequestDto) {
        return bookService.getBooksByAuthor(id, pageRequestDto);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{id}/{quantity}")
    @Operation(summary = "Update book stock", description = "Updates the stock quantity for a specific book. Accessible by ADMIN role only.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Book stock updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid quantity or book not found")
    })
    public void updateBookStock(@PathVariable Long id, @PathVariable int quantity) {
        bookService.updateBookStock(id, quantity);
    }

    @GetMapping("/search")
    @Operation(summary = "Search and filter books", description = "Searches for books based on various criteria like title, genre, publication date range, and price range. Accessible by all users.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Filtered list of books returned successfully")
    })
    public Page<BookDto> searchBooks(
            @RequestParam(required = false, defaultValue = "") String search,
            @RequestParam(required = false) String genre,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate,
            @RequestParam(required = false) Double minPrice,
            @RequestParam(required = false) Double maxPrice,
            @RequestParam(defaultValue = "title") String sortBy,
            @RequestParam(defaultValue = "asc") String sortOrder,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return bookService.getFilteredBooks(search, genre, startDate, endDate, minPrice, maxPrice, sortBy, sortOrder, page, size);
    }
}