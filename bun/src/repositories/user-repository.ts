import type { User } from '../models/user.js';

export class UserRepository {
  private users: User[] = [
    { id: '1', name: 'Gianfranco', email: 'gianfranco@email.com', password: 'Test123!' },
    { id: '2', name: 'Gianfranco2', email: 'gianfranco@email.com', password: 'Test123!' },
    { id: '3', name: 'Gianfranco3', email: 'gianfranco@email.com', password: 'Test123!' },
    { id: '4', name: 'Gianfranco4', email: 'gianfranco@email.com', password: 'Test123!' },
    { id: '5', name: 'Gianfranco5', email: 'gianfranco@email.com', password: 'Test123!' },
  ];

  getAllUsers(): User[] {
    return this.users;
  }

  getUserById(id: string): User | undefined {
    return this.users.find(u => u.id === id);
  }

  getUserByEmail(email: string): User | undefined {
    return this.users.find(u => u.email === email);
  }
}
