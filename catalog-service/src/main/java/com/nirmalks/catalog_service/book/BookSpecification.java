package com.nirmalks.catalog_service.book;

import com.nirmalks.catalog_service.book.entity.Book;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDate;

public class BookSpecification {

	public static final String TITLE = "title";

	public static final String ISBN = "isbn";

	public static final String AUTHOR = "authors";

	public static final String GENRE = "genres";

	public static final String PUBLISHED_DATE = "publishedDate";

	public static final String PRICE = "price";

	public static Specification<Book> filterBy(String searchParam, String genre, LocalDate startDate, LocalDate endDate,
			Double minPrice, Double maxPrice, String sortBy, String sortOrder) {
		return Specification.where(hasSearchParam(searchParam))
			.and(hasGenre(genre))
			.and(hasPublishedDateAfter(startDate))
			.and(hasPublishedDateBefore(endDate))
			.and(hasPriceGreaterThan(minPrice))
			.and(hasPriceLessThan(maxPrice))
			.and(sortBy(sortBy, sortOrder));
	}

	private static Specification<Book> hasSearchParam(String searchParam) {
		return (root, query, cb) -> {
			if (searchParam == null || searchParam.isEmpty()) {
				return cb.conjunction(); // No filtering if the search param is empty or
											// null
			}
			// check if the searchParam matches title, isbn, or author
			Predicate titlePredicate = cb.like(cb.lower(root.get(TITLE)), "%" + searchParam.toLowerCase() + "%");
			Predicate isbnPredicate = cb.like(cb.lower(root.get(ISBN)), "%" + searchParam.toLowerCase() + "%");
			Predicate authorPredicate = cb.like(cb.lower(root.join(AUTHOR).get("name")),
					"%" + searchParam.toLowerCase() + "%");

			// Combine all predicates (OR condition for search across title, isbn, and
			// author)
			return cb.or(titlePredicate, isbnPredicate, authorPredicate);
		};
	}

	private static Specification<Book> hasGenre(String genre) {
		return (root, query, cb) -> genre == null || genre.isEmpty() ? cb.conjunction()
				: cb.equal(cb.lower(root.join(GENRE).get("name")), genre.toLowerCase());
	}

	private static Specification<Book> hasPublishedDateAfter(LocalDate publishedAfter) {
		return (root, query, cb) -> publishedAfter == null ? cb.conjunction()
				: cb.greaterThanOrEqualTo(root.get(PUBLISHED_DATE), publishedAfter);
	}

	private static Specification<Book> hasPublishedDateBefore(LocalDate publishedBefore) {
		return (root, query, cb) -> publishedBefore == null ? cb.conjunction()
				: cb.lessThanOrEqualTo(root.get(PUBLISHED_DATE), publishedBefore);
	}

	private static Specification<Book> hasPriceGreaterThan(Double priceFrom) {
		return (root, query, cb) -> priceFrom == null ? cb.conjunction()
				: cb.greaterThanOrEqualTo(root.get(PRICE), priceFrom);
	}

	private static Specification<Book> hasPriceLessThan(Double priceTo) {
		return (root, query, cb) -> priceTo == null ? cb.conjunction() : cb.lessThanOrEqualTo(root.get(PRICE), priceTo);
	}

	private static Specification<Book> sortBy(String sortBy, String sortOrder) {
		return (root, query, cb) -> {
			if (sortBy == null || sortBy.isEmpty()) {
				return cb.conjunction();
			}

			boolean isAscending = sortOrder == null || sortOrder.equals("asc");
			if (isAscending) {
				query.orderBy(cb.asc(root.get(sortBy)));
			}
			else {
				query.orderBy(cb.desc(root.get(sortBy)));
			}
			return cb.conjunction();
		};
	}

}
