# Build stage
FROM golang:1.21-alpine AS build

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o gin-server .

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy the binary from build stage
COPY --from=build /app/gin-server .

# Expose port
EXPOSE 8080

# Run the application
CMD ["./gin-server"]
