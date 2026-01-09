# Hono Bun Web Server

Bun implementation using the Hono web framework.

## Structure

- `models/` - Data model interfaces (User, Product, Category, LoginRequest, LoginResponse)
- `repositories/` - Data repositories and auth service
- `routes/` - API route handlers
- `middleware/` - Authentication middleware
- `src/index.ts` - Application entry point

## Installing

```bash
bun install
```

## Development

```bash
bun run dev
```

## Building

```bash
bun run build
```

## Running

```bash
bun run start
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
