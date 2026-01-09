# Build stage
FROM rust:latest AS build

WORKDIR /app

COPY Cargo.toml ./

# Create a dummy src/main.rs to allow cargo fetch to work
RUN mkdir -p src && echo "fn main() {}" > src/main.rs

RUN cargo fetch

COPY src ./src
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/release/actix-benchmark /app/actix-benchmark

EXPOSE 8080

CMD ["./actix-benchmark"]
