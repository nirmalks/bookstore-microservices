Bookstore APi using Microservices

- Bookstore API using microservices architecture . Converted from the monolith version -https://github.com/nirmalks/bookstore-spring-be
- Backend Stack: Spring Boot, Spring Security (JWT), Spring Data JPA, PostgreSQL, Flyway, Spring Eureka client, Spring Eureka server, Spring Cloud gateway, Spring Boot Oauth2, Spring Webflux
- Tools & Libraries: Swagger

Key Features

* RESTful APIs for managing books, authors, users, orders, carts, and genres
* JWT-based authentication and role-based authorization (user, admin)
* Advanced book search with filtering and pagination using JPA Specifications
* Swagger documentation for API testing
* Flyway integration for consistent DB migrations
  
Admin Capabilities
* Add or update books, authors, and genres

User Capabilities
* Register, log in, and manage account profile
* Browse and search books
* Add items to cart and place orders
* View orders

## credentials
* admin cred - admin/admin123
* customer cred - john_doe/admin123

## swagger
* User service - http://localhost:8081/swagger-ui/index.html
* Catalog service - http://localhost:8082/swagger-ui/index.html
* Checkout service - http://localhost:8083/swagger-ui/index.html
