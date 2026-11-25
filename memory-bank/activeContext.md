# Active context

Live Store Verification (optional, behind `--online`):

- Default remains offline; no network unless `--online`
- CLI: `--online`, `--store google|apple|both`, `--no-store-check`
- Config: `store_integrations.google_play.package_name` / `app_store.bundle_id`
- Credentials only from env/CI paths — never source files; secrets redacted in findings
- Finding IDs: `store-api-access`, `google-play-release-status`, `google-play-vitals-summary`, `app-store-connect-access`, `testflight-build-status` (`source: live-api`)
- Missing credentials → INFO (no score impact); auth failure → WARNING (redacted)
- Report disclaimer notes live API data is informational, not an approval guarantee

Prior: profile-aware deep-link/CI refinements; finding confidence + store_profile.
