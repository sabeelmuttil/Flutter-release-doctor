# Flutter Release Doctor report

**Project:** `/Users/emvigo/Documents/flutter/chicking/chicking_dev/chicking`  
**Release score:** 60/100

## WARNING

- **Android permissions** (`android-sensitive-permissions`) — Sensitive permissions: android.permission.ACCESS_FINE_LOCATION.
  - Fix: Confirm every permission is essential and declared accurately in Play Data Safety.
- **Possible hard-coded secret** (`hard-coded-secret`) — A credential-like assignment was detected. The value is redacted.
  - At: `lib/firebase_options.dart:53 (api-key-like assignment)`
  - Fix: Review it; rotate real secrets and move them to secure server-side configuration.
- **Android key.properties gitignore** (`android-key-properties-gitignore`) — `android/key.properties` exists but is not ignored by `.gitignore`. Verify with `git check-ignore -v android/key.properties`.
  - Fix: Add `key.properties` (or the exact path) to `.gitignore` so signing secrets are never committed. Release Doctor does not modify the scanned project’s `.gitignore`.
- **iOS privacy manifest** (`ios-privacy-manifest`) — Only CocoaPods privacy manifests were found (e.g. `ios/Pods/FirebaseFirestoreInternal/Firestore/Source/Resources/PrivacyInfo.xcprivacy`). App-level PrivacyInfo.xcprivacy compliance could not be confirmed.
  - At: `ios/Pods/FirebaseFirestoreInternal/Firestore/Source/Resources/PrivacyInfo.xcprivacy`
  - Fix: Add an app-owned PrivacyInfo.xcprivacy under ios/Runner (or include one from the Runner target). Pods manifests alone are not sufficient.
- **Android App Links host** (`android-app-links-host`) — An HTTPS app-link intent filter has no host or uses an unresolved placeholder.
  - At: `android/app/src/main/AndroidManifest.xml:33`
  - Fix: Set a concrete android:host on the HTTPS VIEW/BROWSABLE intent filter.
- **iOS custom URL scheme** (`ios-custom-url-scheme`) — CFBundleURLTypes issue: unresolved variable scheme(s): amzn-$(…), juspay-$(…), $(…).cred, paytm-$(…), [unresolved-variable-scheme].
  - At: `ios/Runner/Info.plist:35 (unresolved-scheme)`
  - Fix: Use unique, non-empty, fully resolved URL schemes in Info.plist CFBundleURLTypes.
- **iOS associated domains** (`ios-associated-domains`) — Universal Links evidence was found, but no concrete applinks: domain is configured.
  - Fix: Add com.apple.developer.associated-domains with at least one applinks: entry in Runner entitlements.
- **CI/CD workflows** (`missing-ci-workflow`) — No `.github/workflows` directory was found, so release pipeline readiness could not be verified.
  - Fix: Add GitHub Actions workflows for Flutter validation and Android/iOS release builds.

## PASSED

- **Flutter project** (`flutter-project-found`) — pubspec.yaml found.
- **App version** (`app-version`) — `1.0.0+1` is valid.
- **Firebase configuration** (`firebase-configuration`) — Found Android and iOS config file(s).
- **Android Firebase JSON** (`android-firebase-json`) — google-services.json is valid JSON.
- **iOS privacy descriptions** (`ios-privacy-descriptions`) — Found: NSCameraUsageDescription, NSLocationWhenInUseUsageDescription, NSPhotoLibraryUsageDescription.
- **Android app identity** (`android-app-identity`) — Application ID `com.chickinguae` matches Firebase package `com.chickinguae`.
- **iOS app identity** (`ios-app-identity`) — Bundle ID `inn.uae.chicking` matches Firebase BUNDLE_ID `inn.uae.chicking`.
- **Android release signing** (`android-release-signing`) — Release signingConfig is configured and a local key.properties (or equivalent) reference is present.
- **Android release minification** (`android-release-minification`) — Release build explicitly configures minification and resource shrinking.
- **iOS release signing** (`ios-release-signing`) — Release configuration defines CODE_SIGN_STYLE and DEVELOPMENT_TEAM.
- **iOS push entitlements** (`ios-push-entitlements`) — Runner entitlements define `aps-environment` for push notifications.
- **Android SDK levels** (`android-sdk-levels`) — Resolved minSdk=29, targetSdk=36, compileSdk=36 with valid ordering.
- **iOS deployment target** (`ios-deployment-target`) — IPHONEOS_DEPLOYMENT_TARGET=15.0 is resolved and consistent across build configurations.

