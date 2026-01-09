import 'dart:io';

import 'package:dart_frog/dart_frog.dart';
import 'package:local_ly_api/features/users/user_repository.dart';

Response onRequest(
  RequestContext context,
  String userId,
) {
  return switch (context.request.method) {
    HttpMethod.get => _onGet(context, userId),
    _ => Response(statusCode: HttpStatus.methodNotAllowed),
  };
}

Response _onGet(RequestContext context, String userId) {
  final repository = context.read<UserRepository>();
  final user = repository.getUserById(id: userId);

  return Response.json(
    body: {'user': user},
  );
}
