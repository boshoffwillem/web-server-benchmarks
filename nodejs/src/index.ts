import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { UserRepository } from './repositories/user-repository.js';
import { ProductRepository } from './repositories/product-repository.js';
import { CategoryRepository } from './repositories/category-repository.js';
import { AuthService } from './repositories/auth-service.js';
import { createAuthMiddleware } from './middleware/auth.js';
import { createAuthRoutes } from './routes/auth.js';
import { createUserRoutes } from './routes/user.js';
import { createProductRoutes } from './routes/product.js';
import { createCategoryRoutes } from './routes/category.js';

const app = new Hono();

// Initialize repositories
const userRepository = new UserRepository();
const productRepository = new ProductRepository();
const categoryRepository = new CategoryRepository();

// Initialize services
const authService = new AuthService(userRepository);

// Initialize middleware
const authMiddleware = createAuthMiddleware();

// Register routes
createAuthRoutes(app, authService);
createUserRoutes(app, userRepository, authMiddleware);
createProductRoutes(app, productRepository, authMiddleware);
createCategoryRoutes(app, categoryRepository, authMiddleware);

const port = 8080;
serve({
  fetch: app.fetch,
  port,
});

console.log(`Server running on http://localhost:${port}`);
