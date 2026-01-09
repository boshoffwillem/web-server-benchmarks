# Actix Web Server

Rust implementation using the Actix web framework.

## Structure

- `src/models.rs` - Data models (User, Product, Category, LoginRequest, LoginResponse)
- `src/repositories.rs` - Data repositories
- `src/auth.rs` - Authentication service and JWT handling
- `src/middleware.rs` - Authentication middleware
- `src/handlers.rs` - HTTP request handlers
- `src/routes.rs` - Route handlers and endpoints
- `src/main.rs` - Application entry point

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run --release
```

Or:

```bash
./target/release/actix-benchmark
```

The server runs on `http://localhost:8080`.

## API Endpoints

### Authentication
- `POST /api/v1/auth/login` - Login with email and password

### Users (requires auth)
- `GET /api/v1/user/:id` - Get user by ID

### Products (requires auth)
- `GET /api/v1/product` - Get all products
- `GET /api/v1/product/:id` - Get product by ID

### Categories (requires auth)
- `GET /api/v1/category/:id` - Get category by ID

## Authentication

Send a JWT bearer token in the Authorization header:
```
Authorization: Bearer <token>
```
