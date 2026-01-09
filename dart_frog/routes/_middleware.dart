import 'package:dart_frog/dart_frog.dart';
import 'package:local_ly_api/features/categories/category_repository.dart';
import 'package:local_ly_api/features/products/product_repository.dart';
import 'package:local_ly_api/features/users/auth/authenticator.dart';
import 'package:local_ly_api/features/users/user_repository.dart';

final UserRepository _userRepository = UserRepository();
final ProductRepository _productRepository = ProductRepository();
final CategoryRepository _categoryRepository = CategoryRepository();
final Authenticator _authenticator = Authenticator(_userRepository);

Handler middleware(Handler handler) {
  return handler
      .use(requestLogger())
      .use(provider<Authenticator>((_) => _authenticator))
      .use(provider<UserRepository>((_) => _userRepository))
      .use(provider<ProductRepository>((_) => _productRepository))
      .use(provider<CategoryRepository>((_) => _categoryRepository));
}
