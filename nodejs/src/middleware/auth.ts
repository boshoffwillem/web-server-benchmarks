import { Hono } from 'hono';
import jwt from 'jsonwebtoken';

const SECRET_KEY = '8d96c0a4544eb9dad7c6b2f1126f52d272d0d04074edbf0cb92f3a68fb';

export function createAuthMiddleware() {
  return async (c: any, next: any) => {
    const authHeader = c.req.header('Authorization');
    
    if (!authHeader) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const token = parts[1];
    
    try {
      jwt.verify(token, SECRET_KEY);
      await next();
    } catch (err) {
      return c.json({ error: 'Unauthorized' }, 401);
    }
  };
}
