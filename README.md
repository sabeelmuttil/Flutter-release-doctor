# Flutter Release Doctor

Local release-readiness checks for Flutter Android and iOS applications.

## Features

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
- Terminal, Markdown, and JSON reports

## Run from source

```bash
dart run bin/flutter_release_doctor.dart check /path/to/flutter-project
```

Defaults (unchanged):

- readable console output
- writes `release-doctor-report.md` into the scanned project
- exit code `1` when any ERROR finding exists

## GitHub Action

Use this repository as a reusable [composite action](https://docs.github.com/en/actions/creating-actions/creating-a-composite-action). Consumers do **not** need to add this package to their Flutter app `pubspec.yaml`.

### Copy-paste example

```yaml
name: Release Doctor

on:
  pull_request:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Flutter Release Doctor
        id: release-doctor
        uses: sabeelmuttil/Flutter-release-doctor@v1
        with:
          project-path: ${{ github.workspace }}
          fail-on: error
          format: console

      - name: Print score
        if: always()
        run: echo "score=${{ steps.release-doctor.outputs.score }}"
```

Pin to a release tag (`@v1`) or commit SHA in production. Avoid floating refs like `@main`.

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `project-path` | `${{ github.workspace }}` | Flutter project root to audit |
| `fail-on` | `error` | CLI exit policy: `error`, `warning`, or `never` |
| `format` | `console` | Report format shown/written: `console`, `markdown`, or `json` |
| `report-path` | _(empty)_ | Optional file path for the selected format |
| `no-markdown-report` | `false` | When `true`, skip `release-doctor-report.md` |

### Action outputs

| Output | Description |
|--------|-------------|
| `score` | Release score (0–100) |
| `errors` | ERROR finding count |
| `warnings` | WARNING finding count |
| `report-path` | Path to the generated report used for metrics / `report-path` input |

Outputs are derived from an internal JSON run. Secret values are never exposed.

### How `fail-on` blocks PRs and releases

| `fail-on` | Step fails when |
|-----------|-----------------|
| `error` (default) | Any ERROR finding exists |
| `warning` | Any ERROR or WARNING exists (stricter PR gate) |
| `never` | Never fails after a successful scan (still publishes outputs) |

Use `fail-on: warning` on pull requests when you want incomplete release config to block merge. Use `fail-on: error` to block only hard failures. Use `fail-on: never` when you only want the report/score as an informational check.

## CLI options

```bash
dart run bin/flutter_release_doctor.dart check [project-path] [options]
```

| Option | Values | Default | Purpose |
|--------|--------|---------|---------|
| `--format` | `console`, `markdown`, `json` | `console` | stdout / `--output` format |
| `--output` | file path | _(none)_ | write the selected format to a file |
| `--fail-on` | `error`, `warning`, `never` | `error` | CI exit policy |
| `--no-markdown-report` | flag | off | skip creating `release-doctor-report.md` |
| `-h`, `--help` | flag | | show usage |

### Examples

```bash
# Default console + Markdown report
dart run bin/flutter_release_doctor.dart check .

# Markdown on stdout
dart run bin/flutter_release_doctor.dart check . --format markdown

# Machine-readable JSON on stdout (JSON only)
dart run bin/flutter_release_doctor.dart check . --format json

# Write JSON to a file (short success line on stdout)
dart run bin/flutter_release_doctor.dart check . --format json --output report.json

# Fail CI on warnings as well as errors
dart run bin/flutter_release_doctor.dart check . --fail-on warning

# Always exit 0 after a successful scan
dart run bin/flutter_release_doctor.dart check . --fail-on never

# JSON artifact without the default Markdown file
dart run bin/flutter_release_doctor.dart check . --format json --output report.json --no-markdown-report
```

`--output` refuses to overwrite protected config/source files such as `pubspec.yaml`, `.env`, or `.release-doctor.yaml` (exit `64`).

### GitHub Actions

```yaml
name: Release Doctor
on:
  pull_request:
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dart-lang/setup-dart@v1
      - name: Activate / get Release Doctor
        run: dart pub get
        working-directory: path/to/flutter_release_doctor
      - name: Run Release Doctor
        run: |
          dart run bin/flutter_release_doctor.dart check "$GITHUB_WORKSPACE" \
            --format json \
            --output release-doctor.json \
            --no-markdown-report \
            --fail-on warning
        working-directory: path/to/flutter_release_doctor
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: release-doctor-json
          path: release-doctor.json
```

JSON reports include `schemaVersion`, `projectPath`, `score`, summary counts, and a `findings` array (`id`, `level`, `title`, `detail`, `fix`, `suppressed`). Secret values are never included.

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
