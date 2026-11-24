# Active context

Just implemented **Deep Link and Push Notification readiness checks** (`lib/src/deep_link_push_check.dart`):

- Android App Links (autoVerify + host), custom URL schemes
- iOS associated domains (applinks:), CFBundleURLTypes schemes
- Firebase Messaging → POST_NOTIFICATIONS / aps-environment readiness

Previously: platform compatibility, signing, environment/flavor, app identity.
