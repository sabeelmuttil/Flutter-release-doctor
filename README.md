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
- Optional live Google Play / App Store Connect verification (`--online`)
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
| `--online` | flag | off | enable optional live Google Play / App Store Connect checks |
| `--store` | `google`, `apple`, `both` | `both` | live store target (only used with `--online`) |
| `--no-store-check` | flag | off | skip live store verification even when `--online` is set |
| `-h`, `--help` | flag | | show usage |

Offline is the default: **no network calls** unless `--online` is passed. Credentials are never read from source files or `.release-doctor.yaml`.

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

transaction_type: digital_goods

payment_flows:
  - external_gateway

store_compliance:
  privacy_policy_url: https://example.com/privacy
  account_required: true
  account_deletion_url: https://example.com/delete-account
  reviewer_access:
    demo_account_provided: false
  user_generated_content: false
  uses_tracking: false
```

| Key | Purpose |
|-----|---------|
| `ignore` | Exact finding IDs to hide (WARNING/INFO/PASSED). Ignored ERRORs become WARNING with a suppression note. Secret-related IDs cannot be suppressed. |
| `severity_overrides` | Force a finding ID to `error`, `warning`, or `info`. |
| `approved_hosts` | Hosts allowed for hard-coded / security URL checks. |
| `transaction_type` | `digital_goods`, `subscription`, `physical_goods`, `external_payment`, or `unknown`. |
| `payment_flows` | Optional declarations: `external_gateway`, `cash_on_delivery`, `offline_payment`, `no_in_app_payment`. |
| `store_compliance` | Optional Play/App Store guideline *risk* declarations (privacy URL, account deletion, tracking, UGC, reviewer access). |
| `store_profile` | Product policy profile used to suppress irrelevant findings (business model, auth style, location/tracking/UGC/Universal Links). |
| `store_integrations` | Optional package/bundle IDs for live API checks (`google_play.package_name`, `app_store.bundle_id`). Credentials stay in env/CI secrets. |

### Transaction / billing safety (offline)

Release Doctor statically scans Dart sources and `pubspec.yaml` for Google Play Billing / `in_app_purchase` and external gateway patterns. It does **not** call Google Play or payment APIs.

Physical-goods detection also looks for Stripe/Razorpay/Paytm/Juspay/Cashfree/PayU/WebView package names, payment/checkout/COD symbols, and payment/checkout API path strings.

| `transaction_type` | Behavior |
|--------------------|----------|
| `digital_goods` / `subscription` | ERROR if entitlement appears granted before backend verification; WARNING if acknowledgement, backend verify, or pending/cancelled/restored handling is missing |
| `physical_goods` | Never requires Google Play Billing. PASS (`external-payment-flow-detected`) on static evidence; PASS (`payment-flow-declared` / `cash-on-delivery-declared`) for honest YAML declarations; WARNING (`external-payment-flow-not-detected`) only when neither evidence nor declarations exist |
| `external_payment` | Expects Razorpay/Stripe/etc. usage |
| `unknown` | WARNING (`transaction-type-not-configured`); still flags unsafe client-side digital entitlements when billing code is present |

Every scan emits a `transaction-type` summary (PASS/INFO) so the configured value is always visible in console, Markdown, and JSON reports.

Declared `payment_flows` are **not** treated as proof of secure transaction handling.

Findings include safe file path and line number. Purchase tokens, card data, and API keys are never printed.

Example for a food-delivery / physical-goods app:

```yaml
transaction_type: physical_goods
payment_flows:
  - external_gateway
  - cash_on_delivery
```

Example for a premium subscription app:

```yaml
transaction_type: subscription
```

### Store guideline risk (offline)

Release Doctor emits **risk signals** for Google Play and Apple App Store policies. It is **not** a guaranteed-compliance checker and never claims Data Safety or App Privacy declarations are complete. Every store finding names the relevant guideline/policy area.

Each finding includes:
- `confidence`: `high` | `medium` | `low`
- `source`: `static-analysis` | `project-config` | `manual-review` | `live-api`
- optional `guideline` (e.g. Google Play User Data / Data Safety, Apple App Review 5.1.1 / 3.1 / 4.8)
- optional `evidenceSummary`

**MANUAL REVIEW** items and low-confidence findings do **not** reduce the release score or fail `--fail-on warning`.

`store_profile` avoids irrelevant checks (example: physical goods skip IAP/Play Billing requirements; phone OTP/email-only skip Sign in with Apple warnings; `uses_universal_links: false` / `uses_android_app_links: false` downgrade inferred deep-link warnings; `ci_required: false` makes missing CI informational).

Reports include this disclaimer (console, Markdown, and JSON `disclaimer` field):

> Automated checks identify risk signals; store approval and legal compliance require human review.

When live store findings are present, reports also state that **live API data is informational and not a store approval guarantee**.

Notable finding IDs: `play-data-safety-review`, `play-privacy-policy-missing`, `apple-privacy-policy-missing`, `apple-account-deletion-missing`, `apple-sign-in-with-apple-review`, `apple-att-review`, `apple-reviewer-access-missing`.

### Live store verification (optional, `--online`)

Offline static checks remain the default. With `--online`, Release Doctor can query Google Play Developer API and/or App Store Connect using credentials from the environment only:

| Store | Env vars |
|-------|----------|
| Google Play | `GOOGLE_PLAY_ACCESS_TOKEN`, or `GOOGLE_PLAY_SERVICE_ACCOUNT_FILE` / `GOOGLE_APPLICATION_CREDENTIALS` |
| App Store Connect | `APP_STORE_CONNECT_ACCESS_TOKEN`, or `APP_STORE_CONNECT_ISSUER_ID` + `APP_STORE_CONNECT_KEY_ID` + `APP_STORE_CONNECT_PRIVATE_KEY_PATH` (or `APP_STORE_CONNECT_PRIVATE_KEY`) |

Missing credentials → INFO / manual review (score unchanged). Auth failures → WARNING with redacted error text (tokens, JWTs, private keys, and service-account JSON are never printed).

Live finding IDs: `store-api-access`, `google-play-release-status`, `google-play-vitals-summary`, `app-store-connect-access`, `testflight-build-status` (`source: live-api`).

Each finding has a stable ID shown in terminal and Markdown output, for example:

```text
[WARN ] [android-sensitive-permissions] Android permissions: ...
```

## Product direction

This project deliberately focuses on release mistakes that are easy to miss when a Flutter app has Android, iOS, Firebase, multiple environments, and CI/CD.
