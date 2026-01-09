# Build stage
FROM oven/bun:latest AS build

WORKDIR /app

COPY package.json bun.lockb* ./
RUN bun install

COPY . .
RUN bun build src/index.ts --outdir dist --target bun

# Production stage
FROM oven/bun:latest

WORKDIR /app

COPY package.json bun.lockb* ./
RUN bun install --production

COPY --from=build /app/dist/index.js ./dist/index.js

EXPOSE 8080

CMD ["bun", "dist/index.js"]
