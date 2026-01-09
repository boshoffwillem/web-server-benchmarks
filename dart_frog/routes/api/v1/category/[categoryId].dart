import 'dart:io';

import 'package:dart_frog/dart_frog.dart';
import 'package:local_ly_api/features/categories/category_repository.dart';

Response onRequest(
  RequestContext context,
  String categoryId,
) {
  return switch (context.request.method) {
    HttpMethod.get => _onGet(context, categoryId),
    _ => Response(statusCode: HttpStatus.methodNotAllowed),
  };
}

Response _onGet(RequestContext context, String categoryId) {
  final repository = context.read<CategoryRepository>();
  final category = repository.getCategoryById(id: categoryId);

  return Response.json(
    body: {'category': category},
  );
}
