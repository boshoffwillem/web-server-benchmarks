import 'dart:io';

import 'package:dart_frog/dart_frog.dart';
import 'package:local_ly_api/features/products/product_repository.dart';

Response onRequest(RequestContext context) {
  return switch (context.request.method) {
    HttpMethod.get => _onGet(context),
    _ => Response(statusCode: HttpStatus.methodNotAllowed),
  };
}

Response _onGet(RequestContext context) {
  final repository = context.read<ProductRepository>();
  final products = repository.getAllProducts();

  return Response.json(
    body: {'products': products},
  );
}
