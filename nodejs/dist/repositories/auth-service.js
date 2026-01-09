import jwt from 'jsonwebtoken';
import { UserRepository } from './user-repository.js';
const SECRET_KEY = '8d96c0a4544eb9dad7c6b2f1126f52d272d0d04074edbf0cb92f3a68fb';
export class AuthService {
    constructor(userRepository) {
        this.userRepository = userRepository;
    }
    findByEmailAndPassword(email, password) {
        const user = this.userRepository.getUserByEmail(email);
        if (user && user.password === password) {
            return user;
        }
        return undefined;
    }
    generateToken(user) {
        return jwt.sign({
            nameidentifier: user.id,
            name: user.name,
            email: user.email,
        }, SECRET_KEY, { algorithm: 'HS256', expiresIn: '24h' });
    }
}
