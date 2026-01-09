import 'dart:io';

import 'package:dart_frog/dart_frog.dart';
import 'package:local_ly_api/features/categories/category_repository.dart';

Response onRequest(RequestContext context) {
  return switch (context.request.method) {
    HttpMethod.get => _onGet(context),
    _ => Response(statusCode: HttpStatus.methodNotAllowed),
  };
}

Response _onGet(RequestContext context) {
  final repository = context.read<CategoryRepository>();
  final categories = repository.getAllCategories();

  return Response.json(
    body: {'categories': categories},
  );
}
