import 'package:local_ly_api/features/users/user.dart';
import 'package:local_ly_api/features/users/user_repository.dart';

final User emptyUser = User.empty();

/// {@template in_memory_users_data_source}
/// An in-memory implementation of the [UsersDataSource] interface.
/// {@endtemplate}
class UserRepository {
  /// In memory [User] list
  final List<User> users = const [
    User(
      id: '1',
      name: 'Gianfranco',
      email: 'gianfranco@email.com',
      password: 'Test123!',
    ),
    User(
      id: '2',
      name: 'Gianfranco2',
      email: 'gianfranco@email.com',
      password: 'Test123!',
    ),
    User(
      id: '3',
      name: 'Gianfranco3',
      email: 'gianfranco@email.com',
      password: 'Test123!',
    ),
    User(
      id: '4',
      name: 'Gianfranco4',
      email: 'gianfranco@email.com',
      password: 'Test123!',
    ),
    User(
      id: '5',
      name: 'Gianfranco5',
      email: 'gianfranco@email.com',
      password: 'Test123!',
    ),
  ];

  List<User> getAllUsers() {
    return users;
  }

  User getUserById({required String id}) {
    return users.firstWhere(
      (user) => user.id == id,
      orElse: () => emptyUser,
    );
  }

  User getUserByEmail({required String email}) {
    return users.firstWhere(
      (user) => user.email == email,
      orElse: () => emptyUser,
    );
  }
}
