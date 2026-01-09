import { Hono } from 'hono';
import { UserRepository } from '../repositories/user-repository.js';

export function createUserRoutes(app: Hono, userRepository: UserRepository, authMiddleware: any) {
  app.get('/api/v1/user/:id', authMiddleware, async (c) => {
    const id = c.req.param('id');
    const user = userRepository.getUserById(id);

    if (!user) {
      return c.json({ error: 'User not found' }, 404);
    }

    return c.json({ user }, 200);
  });
}
