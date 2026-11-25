# Tech context

- Dart SDK `^3.5.0`
- Dependencies: `yaml`, `dart_jsonwebtoken`, `crypto`; `dev_dependencies: test`
- Run: `dart run bin/flutter_release_doctor.dart check <path>`
- Auth: `connect google` / `auth status` / `auth logout google` (OAuth PKCE + OS secure storage)
- Verify: `dart format .`, `dart analyze`, `dart test`
