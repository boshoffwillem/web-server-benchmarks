# Phoenix Benchmark

Elixir Phoenix implementation of the benchmark application.

## Structure

- `lib/phoenix_benchmark/models.ex` - Data models (User, Product, Category)
- `lib/phoenix_benchmark/repositories.ex` - Data repositories
- `lib/phoenix_benchmark_web/auth/auth.ex` - JWT authentication
- `lib/phoenix_benchmark_web/auth/middleware.ex` - Auth middleware
- `lib/phoenix_benchmark_web/controllers.ex` - HTTP request handlers
- `lib/phoenix_benchmark_web/router.ex` - Route definitions
- `lib/phoenix_benchmark/application.ex` - Application supervision tree

## Building

```bash
mix deps.get
mix escript.build
```

## Running

```bash
mix run --no-halt
```

Or:

```bash
./phoenix_benchmark
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
