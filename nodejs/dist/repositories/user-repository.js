export class UserRepository {
    constructor() {
        this.users = [
            { id: '1', name: 'Gianfranco', email: 'gianfranco@email.com', password: 'Test123!' },
            { id: '2', name: 'Gianfranco2', email: 'gianfranco@email.com', password: 'Test123!' },
            { id: '3', name: 'Gianfranco3', email: 'gianfranco@email.com', password: 'Test123!' },
            { id: '4', name: 'Gianfranco4', email: 'gianfranco@email.com', password: 'Test123!' },
            { id: '5', name: 'Gianfranco5', email: 'gianfranco@email.com', password: 'Test123!' },
        ];
    }
    getAllUsers() {
        return this.users;
    }
    getUserById(id) {
        return this.users.find(u => u.id === id);
    }
    getUserByEmail(email) {
        return this.users.find(u => u.email === email);
    }
}
