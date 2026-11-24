# Active context

Refined false positives from the Chicking scan:

- Finding evidence (`file`/`line`/`classification`) for HTTP, secrets, API URLs, deep links
- Runner-only iOS bundle ID (ignore NSE extensions)
- HTTPS App Links only for explicit `scheme="https"`
- Universal Links warn only with concrete applinks/associated-domains evidence
- App-owned PrivacyInfo only (Pods → WARNING)
- Unresolved iOS URL schemes → WARNING
- key.properties warning mentions `git check-ignore -v`
