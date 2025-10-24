package com.nirmalks.catalog_service.genre.repository;

import com.nirmalks.catalog_service.genre.entity.Genre;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface GenreRepository extends JpaRepository<Genre, Long> {

	Optional<Genre> findByName(String name);

}
