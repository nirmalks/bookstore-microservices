package com.nirmalks.catalog_service.genre.controller;

import com.nirmalks.catalog_service.genre.api.GenreRequest;
import com.nirmalks.catalog_service.genre.dto.GenreDto;
import com.nirmalks.catalog_service.genre.service.GenreService;
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
@RequestMapping("/api/genres")
@SecurityRequirement(name = "bearerAuth") // Assuming genre management requires
											// authentication
@Tag(name = "Genre Management", description = "Operations related to book genres") // Added
																					// Tag
public class GenreController {

	@Autowired
	private GenreService genreService;

	@GetMapping
	@Operation(summary = "Get paginated list of genres",
			description = "Returns a list of genres based on pagination and sorting parameters. Accessible by all users.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "List of genres returned successfully") })
	public Page<GenreDto> getAllGenres(PageRequestDto pageRequestDto) {
		return genreService.getAllGenres(pageRequestDto);
	}

	@GetMapping("/{id}")
	@Operation(summary = "Get genre by ID",
			description = "Returns genre details for a given genre ID. Accessible by all users.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Genre found"),
			@ApiResponse(responseCode = "404", description = "Genre not found") })
	public GenreDto getGenreById(@PathVariable Long id) {
		return genreService.getGenreById(id);
	}

	@PreAuthorize("hasRole('ADMIN')")
	@PostMapping
	@Operation(summary = "Create a new genre", description = "Creates a new genre. Accessible by ADMIN role only.")
	@ApiResponses(value = { @ApiResponse(responseCode = "201", description = "Genre created successfully"),
			@ApiResponse(responseCode = "400", description = "Invalid input") })
	public ResponseEntity<GenreDto> createGenre(@RequestBody GenreRequest GenreRequest) {
		var genre = genreService.createGenre(GenreRequest);
		URI location = ServletUriComponentsBuilder.fromCurrentRequest()
			.path("/{id}")
			.buildAndExpand(genre.getId())
			.toUri();
		return ResponseEntity.status(HttpStatus.CREATED)
			.header(HttpHeaders.LOCATION, String.valueOf(location))
			.body(genre);
	}

	@PreAuthorize("hasRole('ADMIN')")
	@PutMapping("/{id}")
	@Operation(summary = "Update an existing genre",
			description = "Updates details of an existing genre. Accessible by ADMIN role only.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Genre updated successfully"),
			@ApiResponse(responseCode = "400", description = "Invalid input"),
			@ApiResponse(responseCode = "404", description = "Genre not found") })
	public GenreDto updateGenre(@PathVariable Long id, @RequestBody GenreRequest GenreRequest) {
		return genreService.updateGenre(id, GenreRequest);
	}

	@PreAuthorize("hasRole('ADMIN')")
	@DeleteMapping("/{id}")
	@Operation(summary = "Delete a genre", description = "Deletes a genre by ID. Accessible by ADMIN role only.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Genre deleted successfully"),
			@ApiResponse(responseCode = "404", description = "Genre not found") })
	public ResponseEntity<Void> deleteGenre(@PathVariable Long id) {
		genreService.deleteGenreById(id);
		return ResponseEntity.status(HttpStatus.OK).build();
	}

}
