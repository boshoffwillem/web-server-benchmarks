# local_ly_api

[![style: dart frog lint][dart_frog_lint_badge]][dart_frog_lint_link]
[![License: MIT][license_badge]][license_link]
[![Powered by Dart Frog](https://img.shields.io/endpoint?url=https://tinyurl.com/dartfrog-badge)](https://dart-frog.dev)

An example application built with dart_frog

[dart_frog_lint_badge]: https://img.shields.io/badge/style-dart_frog_lint-1DF9D2.svg
[dart_frog_lint_link]: https://pub.dev/packages/dart_frog_lint
[license_badge]: https://img.shields.io/badge/license-MIT-blue.svg
[license_link]: https://opensource.org/licenses/MIT

# Commands

## Generate JSON classes

```bash
dart pub add equatable json_serializable
dart pub add --dev build_runner
dart run build_runner build -d
```

## Docker

To build the Docker image, run the following command in the root directory of the project:

```bash
docker build . -t dart-frog-app
docker run -i -t -p 8080:8080 dart-frog-app
```
