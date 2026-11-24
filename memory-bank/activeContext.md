# Active context

Just implemented **Android and iOS signing / release-build safety checks** (`lib/src/signing_check.dart`):

- Android: release buildType, signingConfig vs debug, key.properties + gitignore, minify/shrink
- iOS: Release CODE_SIGN_STYLE / DEVELOPMENT_TEAM, Debug-on-Release schemes, aps-environment
- Secrets (passwords, team IDs, keystore paths, etc.) are never printed

Previously: environment/flavor safety, app identity ↔ Firebase consistency.
