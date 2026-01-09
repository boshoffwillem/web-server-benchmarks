import 'dart:io';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:local_ly_api/features/users/user.dart';
import 'package:local_ly_api/features/users/user_repository.dart';

class Authenticator {
  final UserRepository _userRepository;

  Authenticator(this._userRepository);

  User? findByEmailAndPassword({
    required String email,
    required String password,
  }) {
    final user = _userRepository.getUserByEmail(email: email);

    if (user != null && user.password == password) {
      return user;
    }

    return null;
  }

  String generateToken({
    required User user,
  }) {
    final jwt = JWT(
      {
        'nameidentifier': user.id,
        'name': user.name,
        'email': user.email,
      },
    );

    return jwt.sign(SecretKey(
        '8d96c0a4544eb9dad7c6b2f1126f52d272d0d04074edbf0cb92f3a68fb'));
  }

  User? verifyToken(String token) {
    try {
      final payload = JWT.verify(
        token,
        SecretKey('8d96c0a4544eb9dad7c6b2f1126f52d272d0d04074edbf0cb92f3a68fb'),
      );

      final payloadData = payload.payload as Map<String, dynamic>;
      final id = payloadData['nameidentifier'] as String;
      return _userRepository.getUserById(id: id);
    } catch (e) {
      return null;
    }
  }
}
