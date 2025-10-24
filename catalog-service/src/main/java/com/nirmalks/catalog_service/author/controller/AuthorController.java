package com.nirmalks.catalog_service.author.controller;

import com.nirmalks.catalog_service.author.api.AuthorRequest;
import com.nirmalks.catalog_service.author.dto.AuthorDto;
import com.nirmalks.catalog_service.author.service.AuthorService;
import dto.PageRequestDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;

@RestController
@RequestMapping("/api/authors")
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "Author Management", description = "Operations related to authors in the Bookstore API") // Add
																										// this
																										// annotation
public class AuthorController {

	@Autowired
	private AuthorService authorService;

	@GetMapping
	@Operation(summary = "Get paginated list of authors",
			description = "Returns a list of authors based on pagination and sorting parameters")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "List of authors returned successfully") })
	public Page<AuthorDto> getAllAuthors(PageRequestDto pageRequestDto) {
		return authorService.getAllAuthors(pageRequestDto);
	}

	@GetMapping("/{id}")
	@Operation(summary = "Get author by ID", description = "Returns author details for a given author ID")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Author found"),
			@ApiResponse(responseCode = "404", description = "Author not found") })
	public AuthorDto getAuthorById(@PathVariable Long id) {
		return authorService.getAuthorById(id);
	}

	@PreAuthorize("hasRole('ADMIN')")
	@PostMapping
	@Operation(summary = "Create a new author", description = "Accessible by ADMIN role only")
	@ApiResponses(value = { @ApiResponse(responseCode = "201", description = "Author created successfully"),
			@ApiResponse(responseCode = "400", description = "Invalid input") })
	public ResponseEntity<AuthorDto> createAuthor(@RequestBody AuthorRequest authorRequest) {
		var author = authorService.createAuthor(authorRequest);
		URI location = ServletUriComponentsBuilder.fromCurrentRequest()
			.path("/{id}")
			.buildAndExpand(author.getId())
			.toUri();
		return ResponseEntity.status(HttpStatus.CREATED)
			.header(HttpHeaders.LOCATION, String.valueOf(location))
			.body(author);
	}

	@Operation(summary = "Update author", description = "Accessible by ADMIN role only")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Author updated successfully"),
			@ApiResponse(responseCode = "400", description = "Invalid input") })
	@PreAuthorize("hasRole('ADMIN')")
	@PutMapping("/{id}")
	public AuthorDto updateAuthor(@PathVariable Long id, @RequestBody AuthorRequest authorRequest) {
		return authorService.updateAuthor(id, authorRequest);
	}

	@Operation(summary = "Delete author", description = "Accessible by ADMIN role only")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Author deleted successfully"),
			@ApiResponse(responseCode = "400", description = "Invalid input") })
	@PreAuthorize("hasRole('ADMIN')")
	@DeleteMapping("/{id}")
	public ResponseEntity<Void> deleteAuthor(@PathVariable Long id) {
		authorService.deleteAuthorById(id);
		return ResponseEntity.status(HttpStatus.OK).build();
	}

}
