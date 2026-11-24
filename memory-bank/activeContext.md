# Active context

Just implemented **CI/CD release pipeline readiness checks** (`lib/src/cicd_check.dart`):

- Inspects `.github/workflows/*.{yml,yaml}` only (no network)
- Flutter validation, Android/iOS release builds, signing secret refs, hard-coded secrets, unpinned actions, release triggers

Previously: deep link/push, platform compatibility, signing, environment/flavor, app identity.
