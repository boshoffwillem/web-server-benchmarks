import 'package:equatable/equatable.dart';
import 'package:json_annotation/json_annotation.dart';

part 'product.g.dart';

@JsonSerializable()
class Product extends Equatable {
  const Product({
    required this.id,
    required this.name,
    required this.description,
    required this.userId,
    required this.price,
    required this.categoryId,
  });

  factory Product.fromJson(Map<String, dynamic> json) =>
      _$ProductFromJson(json);

  factory Product.empty() => const Product(
        id: '',
        name: '',
        description: '',
        userId: '',
        price: 0.0,
        categoryId: '',
      );

  final String id;
  final String name;
  final String description;
  final String userId;
  final double price;
  final String categoryId;

  Map<String, dynamic> toJson() => _$ProductToJson(this);

  Product copyWith({
    String? id,
    String? name,
    String? description,
    String? userId,
    double? price,
    String? categoryId,
  }) =>
      Product(
          id: id ?? this.id,
          name: name ?? this.name,
          description: description ?? this.description,
          userId: userId ?? this.userId,
          price: price ?? this.price,
          categoryId: categoryId ?? this.categoryId);

  @override
  List<Object?> get props => [id, name, description, userId, price, categoryId];
}
