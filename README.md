# Flutter Release Doctor

Local release-readiness checks for Flutter Android and iOS applications.

## First MVP

- Flutter version format validation
- Android and iOS Firebase configuration presence
- Android sensitive-permission audit
- iOS privacy-description audit
- Basic HTTP and hard-coded-secret scan
- Terminal and Markdown reports

## Run from source

```bash
dart run bin/flutter_release_doctor.dart check /path/to/flutter-project
```

The command writes `release-doctor-report.md` into the checked project.

## Product direction

This project deliberately focuses on release mistakes that are easy to miss when a Flutter app has Android, iOS, Firebase, multiple environments, and CI/CD.
