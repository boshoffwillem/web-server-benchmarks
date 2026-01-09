import { Hono } from 'hono';
import { CategoryRepository } from '../repositories/category-repository.js';

export function createCategoryRoutes(app: Hono, categoryRepository: CategoryRepository, authMiddleware: any) {
  app.get('/api/v1/category/:id', authMiddleware, async (c) => {
    const id = c.req.param('id');
    const category = categoryRepository.getCategoryById(id);

    if (!category) {
      return c.json({ error: 'Category not found' }, 404);
    }

    return c.json({ category }, 200);
  });
}
