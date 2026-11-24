# Active context

Just implemented **Platform compatibility and store-readiness checks** (`lib/src/platform_compatibility_check.dart`):

- Android: minSdk/targetSdk/compileSdk ordering, old/missing targetSdk, cleartext traffic, POST_NOTIFICATIONS when Firebase messaging signals exist
- iOS: IPHONEOS_DEPLOYMENT_TARGET consistency, PrivacyInfo.xcprivacy presence vs privacy-sensitive usage

Previously: signing/release-build safety, environment/flavor safety, app identity ↔ Firebase.
