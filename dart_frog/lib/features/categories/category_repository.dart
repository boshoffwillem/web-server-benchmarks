import 'package:local_ly_api/features/categories/category.dart';

final Category emptyCategory = Category.empty();

class CategoryRepository {
  final List<Category> categories = const [
    Category(
      id: '1',
      name: 'Dairy',
    ),
    Category(
      id: '2',
      name: 'Fruit',
    ),
    Category(
      id: '3',
      name: 'Vegetables',
    ),
    Category(
      id: '4',
      name: 'Bakery',
    ),
    Category(
      id: '5',
      name: 'Meat',
    ),
  ];

  List<Category> getAllCategories() {
    return categories;
  }

  Category getCategoryById({required String id}) {
    return categories.firstWhere(
      (category) => category.id == id,
      orElse: () => emptyCategory,
    );
  }
}
