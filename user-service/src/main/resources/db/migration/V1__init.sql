CREATE TYPE user_role_enum AS ENUM ('ADMIN', 'CUSTOMER');

CREATE TABLE users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role user_role_enum NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE
);

CREATE TABLE address (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL,
    address VARCHAR(500) NOT NULL,
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100) NOT NULL,
    country VARCHAR(100) NOT NULL,
    pin_code VARCHAR(20) NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_user_address FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

INSERT INTO users (username, password, role, email) VALUES ('admin', '$2a$10$sZmiMKlNc1I0fxsA5.OL7u7CJkiGrjI21wDWqrW/vunljwKalZpLK', 'ADMIN', 'admin@bookstore.com');
INSERT INTO users (username, password, role, email) VALUES ('john_doe', '$2a$10$sZmiMKlNc1I0fxsA5.OL7u7CJkiGrjI21wDWqrW/vunljwKalZpLK', 'CUSTOMER', 'john@example.com');

INSERT INTO Address (user_id, address, city, state, country, pin_code, is_default)
VALUES (1, 'Admin Street 1', 'Admin City', 'Admin State', 'Admin Country', '100001', TRUE);
INSERT INTO Address (user_id, address, city, state, country, pin_code, is_default)
VALUES (2, 'John Doe''s House', 'Customer City', 'Customer State', 'Customer Country', '200002', TRUE);