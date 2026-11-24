# Flutter Release Doctor

Local release-readiness checks for Flutter Android and iOS applications.

## First MVP

- Flutter version format validation
- Android and iOS Firebase configuration presence
- Android sensitive-permission audit
- iOS privacy-description audit
- Basic HTTP and hard-coded-secret scan
- App identity ↔ Firebase consistency
- Environment / flavor safety
- Signing / release-build safety
- Platform compatibility and store-readiness
- Deep link and push notification readiness
- CI/CD release pipeline readiness
- Project-level configuration and finding suppression
- Terminal and Markdown reports

## Run from source

```bash
dart run bin/flutter_release_doctor.dart check /path/to/flutter-project
```

The command writes `release-doctor-report.md` into the checked project.

## Configuration

Optional project config: `.release-doctor.yaml` at the Flutter project root.

If the file is absent, Release Doctor keeps its default behavior.  
Copy [`.release-doctor.example.yaml`](.release-doctor.example.yaml) to get started.

```yaml
version: 1

ignore:
  - android-sensitive-permissions

severity_overrides:
  hard-coded-api-url: error
  missing-ci-workflow: info

approved_hosts:
  - api.example.com
```

| Key | Purpose |
|-----|---------|
| `ignore` | Exact finding IDs to hide (WARNING/INFO/PASSED). Ignored ERRORs become WARNING with a suppression note. Secret-related IDs cannot be suppressed. |
| `severity_overrides` | Force a finding ID to `error`, `warning`, or `info`. |
| `approved_hosts` | Hosts allowed for hard-coded / security URL checks. |

Each finding has a stable ID shown in terminal and Markdown output, for example:

```text
[WARN ] [android-sensitive-permissions] Android permissions: ...
```

## Product direction

This project deliberately focuses on release mistakes that are easy to miss when a Flutter app has Android, iOS, Firebase, multiple environments, and CI/CD.
