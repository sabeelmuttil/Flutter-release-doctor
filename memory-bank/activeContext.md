# Active context

Just implemented **App identity and Firebase configuration consistency**:

- Android `applicationId` (gradle/kts) or manifest `package` vs `google-services.json` package_name
- iOS bundle ID (`Info.plist` / `PRODUCT_BUNDLE_IDENTIFIER` in pbxproj) vs Firebase `BUNDLE_ID`
- Missing Firebase config per platform → warning; unresolved variables → warning; mismatches → error

Next candidates: signing/release config, min SDK / deployment target, flavors/CI readiness.
