import 'dart:io';

import 'package:dart_frog/dart_frog.dart';
import 'package:local_ly_api/features/users/user_repository.dart';

Response onRequest(RequestContext context) {
  return switch (context.request.method) {
    HttpMethod.get => _onGet(context),
    _ => Response(statusCode: HttpStatus.methodNotAllowed),
  };
}

Response _onGet(RequestContext context) {
  final repository = context.read<UserRepository>();
  final users = repository.getAllUsers();

  return Response.json(
    body: {'users': users},
  );
}
