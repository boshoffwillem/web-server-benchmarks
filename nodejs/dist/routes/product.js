import { Hono } from 'hono';
import { ProductRepository } from '../repositories/product-repository.js';
export function createProductRoutes(app, productRepository, authMiddleware) {
    app.get('/api/v1/product', authMiddleware, async (c) => {
        const products = productRepository.getAllProducts();
        return c.json({ products }, 200);
    });
    app.get('/api/v1/product/:id', authMiddleware, async (c) => {
        const id = c.req.param('id');
        const product = productRepository.getProductById(id);
        if (!product) {
            return c.json({ error: 'Product not found' }, 404);
        }
        return c.json({ product }, 200);
    });
}
