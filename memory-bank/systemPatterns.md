# System patterns

- CLI entry: `bin/flutter_release_doctor.dart`
- Core auditor: `ReleaseDoctor.check` in `lib/src/release_doctor.dart`
- Findings model: `Finding` / `FindingLevel` in `lib/src/finding.dart`
- Feature checks append to a shared `List<Finding>`; report formats are console + Markdown
- App identity consistency lives in `lib/src/app_identity_check.dart` and compares each platform only to its own Firebase config
- Environment/flavor safety lives in `lib/src/environment_flavor_check.dart`
- Signing/release-build safety lives in `lib/src/signing_check.dart`
- Platform compatibility lives in `lib/src/platform_compatibility_check.dart`
- Deep link / push readiness lives in `lib/src/deep_link_push_check.dart`
- CI/CD pipeline readiness lives in `lib/src/cicd_check.dart`
- Project config lives in `lib/src/doctor_config.dart`; every `Finding` has a stable `id`
- Config apply order: ignore (ERROR→WARNING or hide) then severity_overrides; secret IDs are non-suppressible
