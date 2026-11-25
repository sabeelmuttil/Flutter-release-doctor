# Active context

Push Protection remediation complete: no real Google OAuth client ID/secret in tracked source.

- `BundledGoogleOAuthClient.clientId` / `clientSecret` are null; `config` is null
- Credentials via `--oauth-client-file`, `FLUTTER_RELEASE_DOCTOR_GOOGLE_OAUTH_CLIENT_FILE`, or `GOOGLE_OAUTH_CLIENT_ID`/`SECRET`
- Missing config → clear help pointing at `--oauth-client-file /secure/path/client_secret_xxx.json`
- Service-account JSON rejected for Desktop OAuth connect
- Secrets/tokens never printed; redaction covers client_secret / refresh_token

Prior: Offline store-guideline risk scanner (`guidelineVersion` 2026.1) + optional `--online` live store checks.
