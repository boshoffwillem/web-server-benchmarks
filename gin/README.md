# Gin Web Server

Go implementation using the Gin web framework.

## Structure

- `models/` - Data models (User, Product, Category, LoginRequest, LoginResponse)
- `repositories/` - Data repositories and auth service
- `handlers/` - HTTP route handlers
- `middleware/` - Authentication middleware
- `main.go` - Application entry point

## Building

```bash
go build -o gin-server
```

## Running

```bash
./gin-server
```

The server runs on `http://localhost:8080`.

## API Endpoints

### Authentication
- `POST /api/v1/auth/login` - Login with email and password

### Users (requires auth)
- `GET /api/v1/users/:id` - Get user by ID

### Products (requires auth)
- `GET /api/v1/product` - Get all products
- `GET /api/v1/product/:id` - Get product by ID

### Categories (requires auth)
- `GET /api/v1/categories/:id` - Get category by ID

## Authentication

Send a JWT bearer token in the Authorization header:
```
Authorization: Bearer <token>
```
