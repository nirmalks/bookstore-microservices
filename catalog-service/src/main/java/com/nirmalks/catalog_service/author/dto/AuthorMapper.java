package com.nirmalks.catalog_service.author.dto;


import com.nirmalks.catalog_service.author.api.AuthorRequest;
import com.nirmalks.catalog_service.author.entity.Author;

public class AuthorMapper {
    public static AuthorDto toDto(Author author) {
        return new AuthorDto(author.getId(), author.getName(), author.getBio());
    }

    public static Author toEntity(Author author, AuthorRequest authorRequest) {
        author.setName(authorRequest.getName());
        author.setBio(authorRequest.getBio());
        return author;
    }

    public static Author toEntity(AuthorRequest authorRequest) {
        Author author = new Author();
        author.setName(authorRequest.getName());
        author.setBio(authorRequest.getBio());
        return author;
    }
}
