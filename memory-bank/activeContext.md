# Active context

Profile-aware deep-link / CI refinements:

- `uses_universal_links: false` → no associated-domains WARNING from schemes/SDK noise; MANUAL REVIEW only when concrete `applinks:` exist
- `uses_android_app_links: false` → App Links host/autoVerify → INFO
- Payment/auth SDK unresolved URL schemes → MANUAL REVIEW with SDK source; empty/duplicate app schemes stay WARNING
- `ci_required: false` → missing CI is INFO
- Real warnings kept: key.properties, PrivacyInfo, secrets, insecure HTTP, signing

Prior: finding confidence model + store_profile.
