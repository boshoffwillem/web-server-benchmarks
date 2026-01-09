import { Hono } from 'hono';
import { AuthService } from '../repositories/auth-service.js';

export function createAuthRoutes(app: Hono, authService: AuthService) {
  app.post('/api/v1/auth/login', async (c) => {
    const req = await c.req.json();
    const { email, password } = req;

    const user = authService.findByEmailAndPassword(email, password);
    if (!user) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = authService.generateToken(user);
    return c.json({ token }, 200);
  });
}
