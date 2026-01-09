import 'dart:io';

import 'package:dart_frog/dart_frog.dart';
import 'package:local_ly_api/features/products/product_repository.dart';

Response onRequest(
  RequestContext context,
  String productId,
) {
  return switch (context.request.method) {
    HttpMethod.get => _onGet(context, productId),
    _ => Response(statusCode: HttpStatus.methodNotAllowed),
  };
}

Response _onGet(RequestContext context, String productId) {
  final repository = context.read<ProductRepository>();
  final product = repository.getProductById(id: productId);

  return Response.json(
    body: {'product': product},
  );
}
