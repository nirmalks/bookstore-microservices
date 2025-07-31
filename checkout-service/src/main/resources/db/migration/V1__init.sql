CREATE TYPE order_status_enum AS ENUM('PENDING', 'SHIPPED', 'CANCELLED');

CREATE TABLE Cart (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE,
    total_price DECIMAL(10, 2) NOT NULL DEFAULT 0.0
);
CREATE TABLE Cart_Item (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cart_id BIGINT NOT NULL,
    book_id BIGINT NOT NULL,
    quantity INT NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    book_title VARCHAR(255) NOT NULL,
    CONSTRAINT fk_cart FOREIGN KEY (cart_id) REFERENCES Cart (id) ON DELETE CASCADE
);

CREATE TABLE purchase_order (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL,
    total_cost DECIMAL(10, 2) NOT NULL,
    status order_status_enum NOT NULL DEFAULT 'PENDING',
    placed_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    shipping_address VARCHAR(255),
    shipping_city VARCHAR(100),
    shipping_state VARCHAR(100),
    shipping_pin_code VARCHAR(20),
    shipping_country VARCHAR(100)
);

CREATE TABLE Order_Item (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id BIGINT NOT NULL,
    book_id BIGINT NOT NULL,
    quantity INT NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    book_title VARCHAR(255) NOT NULL,
    CONSTRAINT fk_order FOREIGN KEY (order_id) REFERENCES purchase_order (id) ON DELETE CASCADE
);


INSERT INTO Cart (user_id, total_price) VALUES (2, 0.0);

INSERT INTO purchase_order (user_id, total_cost, status, shipping_address, shipping_city, shipping_state, shipping_pin_code, shipping_country)
VALUES (2, 2499.95, 'PENDING', '123 Main St', 'Anytown', 'Anystate', '12345', 'USA');

INSERT INTO Order_Item (order_id, book_id, quantity, price, book_title)
VALUES (1, 1, 2, 999.98, 'The Great Adventure Book');
INSERT INTO Order_Item (order_id, book_id, quantity, price, book_title)
VALUES (1, 2, 1, 899.99, 'Microservices Patterns Guide');