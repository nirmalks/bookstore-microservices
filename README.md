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

## Running with Docker

This project is containerized using Docker and Docker Compose. It includes the Microservices (Spring Boot), Databases (PostgreSQL), and Observability stack (Prometheus, Grafana, Zipkin).

### Prerequisites
* [Docker](https://www.docker.com/get-started) and [Docker Compose](https://docs.docker.com/compose/install/) installed on your machine.
* Java 17+ (if running Maven locally).

### 1. Build the Artifacts
Before building the Docker images, ensure the JAR files are generated for each service. Run the following command from the root directory:

```bash
./mvnw clean package -DskipTests
```
2. Directory Setup

Ensure the following monitoring configuration files exist in the root directory before starting:

prometheus.yml
alert.rules.yml
alertmanager/alertmanager.yml

3. Start the Containers

Build the images and start all infrastructure services:
```bash
docker-compose up -d --build
```
4. Startup Sequence

Databases (User, Catalog, Checkout) initialize.
Discovery Service (Eureka) starts.
Config Server waits for Discovery.
Microservices & API Gateway start once the core services are healthy.

## Accessing the Application

| Service | URL / Port | Description |
| :--- | :--- | :--- |
| API Gateway | http://localhost:8080 | Main entry point for all requests |
| Eureka Dashboard | http://localhost:8761 | Service Discovery UI |
| Zipkin | http://localhost:9411 | Distributed Tracing |
| Grafana | http://localhost:3000 | Metrics Visualization |
| Prometheus | http://localhost:9090 | Metrics Collection |
  
## credentials
* admin credentials - admin/admin123
* customer credentials - john_doe/admin123

## swagger
* User service - http://localhost:8081/swagger-ui/index.html
* Catalog service - http://localhost:8082/swagger-ui/index.html
* Checkout service - http://localhost:8083/swagger-ui/index.html
  
## Stopping the Application
To stop all containers and remove the network:


```bash
docker-compose down
```
To stop and remove database volumes (reset all data):

```bash
docker-compose down -v
```

## Screenshots

### Zipkin

Log with traceid in gateway
<img width="1875" height="397" alt="gateway-log" src="https://github.com/user-attachments/assets/dce5c59d-b4cc-4dbe-b0f6-1ca65b1a486d" />

Querying by traceid in zipkin
<img width="1918" height="831" alt="zipkin-trace" src="https://github.com/user-attachments/assets/972b082d-b8ec-4dff-9e15-f46fd07933d3" />


