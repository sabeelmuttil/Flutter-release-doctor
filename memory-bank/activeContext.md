# Active context

Insecure HTTP scanner false positives fixed for Xcode/XML metadata:

- Skip `ios/**/*.xcworkspace/**`, `ios/Pods/**`, `build/**`, `.dart_tool/**`, `.git/**`
- Ignore XML/plist DOCTYPE, xmlns, Apple DTD, and schema HTTP URLs
- Still warn on real HTTP in Dart, `.env`, JSON/YAML, and plist string values
- localhost / `10.0.2.2` unchanged

Prior: Firebase client-config secret exclusions; physical-goods payment flows; transaction-type summary.
