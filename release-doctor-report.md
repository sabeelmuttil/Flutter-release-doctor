# Flutter Release Doctor report

**Project:** `/Users/emvigo/Documents/flutter/Flutter_Release_Doctor_MVP/.`  
**Release score:** 80/100

## WARNING

- **Firebase configuration** — No Android or iOS Firebase config found.
  - Fix: Ignore this only when Firebase is intentionally not used.
- **iOS Info.plist** — Info.plist was not found.
- **Android Firebase config** — android/ exists but android/app/google-services.json is missing.
  - Fix: Add google-services.json for this Android app/environment, or ignore if Firebase is unused.
- **Android app ID** — Could not resolve Android application ID: neither android/app/build.gradle(.kts) applicationId nor AndroidManifest package was found.

## PASSED

- **Flutter project** — pubspec.yaml found.
- **App version** — `0.1.0+1` is valid.
- **Android permissions** — No high-sensitivity permissions detected.
- **Basic security scan** — No insecure HTTP endpoint or obvious hard-coded secret detected.

