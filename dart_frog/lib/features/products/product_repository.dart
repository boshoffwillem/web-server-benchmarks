import 'package:local_ly_api/features/products/product.dart';

final Product emptyProduct = Product.empty();

class ProductRepository {
  final List<Product> products = [];

  ProductRepository() {
    generateTestProducts();
  }

  List<Product> getAllProducts() {
    return products;
  }

  Product getProductById({required String id}) {
    return products.firstWhere(
      (product) => product.id == id,
      orElse: () => emptyProduct,
    );
  }

  void generateTestProducts() {
    for (var i = 1; i <= 10000; i++) {
      products.add(
        Product(
          id: '$i',
          name: 'Product $i',
          description: 'Description for product $i',
          userId: '${(i % 5) + 1}',
          price: i * 1.5,
          categoryId: '${(i % 5) + 1}',
        ),
      );
    }
  }
}
