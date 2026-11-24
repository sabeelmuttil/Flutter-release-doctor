# Project brief

Flutter Release Doctor is a Dart CLI that audits Flutter Android/iOS projects for release-readiness mistakes before store submission.

## Goals

- Catch easy-to-miss Android/iOS/Firebase/config issues locally
- Emit findings to the terminal and `release-doctor-report.md`
- Keep the CLI command stable: `dart run bin/flutter_release_doctor.dart check <project-path>`
