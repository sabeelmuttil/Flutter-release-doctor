# Progress

## Working

- Version format check
- Firebase config presence + Android JSON validity
- Android sensitive permissions
- iOS privacy description presence
- Basic HTTP / hard-coded secret scan
- App identity ↔ Firebase consistency (Android + iOS)
- Environment / flavor safety (env files, hard-coded URLs, flavors, Firebase project IDs)
- Android / iOS signing and release-build safety
- Platform compatibility / store-readiness (SDK levels, cleartext, privacy manifest)
- Deep link and push notification readiness
- CI/CD release pipeline readiness (GitHub Actions)
- Project-level `.release-doctor.yaml` config (ignore / severity / approved_hosts / transaction_type)
- Offline Google Play Billing / transaction-safety analyzer
- CI-friendly CLI (`--format`, `--output`, `--fail-on`, `--no-markdown-report`) + JSON reports
- Optional live store verification (`--online` / `--store` / `--no-store-check`) for Google Play + App Store Connect
- Google OAuth connect (`connect google` / `auth status` / `auth logout google`) with bundled Desktop client, PKCE, OS secure storage
- Versioned offline Google/Apple guideline rule registry (`guidelineVersion`) with full finding attribution
- Terminal + Markdown reports
- Fixture tests for identity, environment/flavor, transaction-safety, live-store, OAuth, and guideline registry

## Known gaps

- This repo itself is a partial Flutter project (empty manifest, no iOS folder, no Firebase configs)
