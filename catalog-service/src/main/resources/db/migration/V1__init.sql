CREATE TABLE Author (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    bio TEXT
);

CREATE TABLE Genre (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE Book (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    stock INT NOT NULL,
    isbn VARCHAR(20) NOT NULL UNIQUE,
    published_date DATE NOT NULL,
    image_path VARCHAR(255),
    description TEXT
);

CREATE TABLE Book_Author (
    book_id BIGINT NOT NULL,
    author_id BIGINT NOT NULL,
    PRIMARY KEY (book_id, author_id),
    FOREIGN KEY (book_id) REFERENCES Book(id) ON DELETE CASCADE,
    FOREIGN KEY (author_id) REFERENCES Author(id) ON DELETE CASCADE
);

CREATE TABLE Book_Genre (
    book_id BIGINT NOT NULL,
    genre_id BIGINT NOT NULL,
    PRIMARY KEY (book_id, genre_id),
    CONSTRAINT fk_book FOREIGN KEY (book_id) REFERENCES Book (id) ON DELETE CASCADE,
    CONSTRAINT fk_genre FOREIGN KEY (genre_id) REFERENCES Genre (id) ON DELETE CASCADE
);

INSERT INTO Author (name, bio) VALUES ('Paulo Coelho', 'Brazilian author known for The Alchemist.'); -- id = 1
INSERT INTO Author (name, bio) VALUES ('J.K. Rowling', 'British author known for Harry Potter series.'); -- id = 2

INSERT INTO Genre (name) VALUES ('Fiction'); -- id = 1
INSERT INTO Genre (name) VALUES ('Drama'); -- id = 2
INSERT INTO Genre (name) VALUES ('Fantasy'); -- id = 3

INSERT INTO Book (title, price, stock, isbn, published_date, image_path, description)
VALUES ('The Alchemist', 499.99, 10, '978-3-16-148410-0', '2024-01-01', 'the_alchemist.jpg', 'A philosophical novel by Paulo Coelho, inspiring readers to follow their dreams.'); -- id = 1

INSERT INTO Book (title, price, stock, isbn, published_date, image_path, description)
VALUES ('Harry Potter and the Sorcerer''s Stone', 899.99, 15, '978-0-7475-3269-9', '1997-06-26', 'harry_potter.jpg', 'The first book in J.K. Rowling''s Harry Potter series, introducing the magical world of Hogwarts.'); -- id = 2

INSERT INTO Book_Genre (book_id, genre_id) VALUES (1, 1);
INSERT INTO Book_Genre (book_id, genre_id) VALUES (1, 2);
INSERT INTO Book_Genre (book_id, genre_id) VALUES (2, 1);
INSERT INTO Book_Genre (book_id, genre_id) VALUES (2, 3);

INSERT INTO Book_Author (book_id, author_id) VALUES (1, 1);
INSERT INTO Book_Author (book_id, author_id) VALUES (2, 2);