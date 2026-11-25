# Active context

Offline store-guideline risk scanner (versioned registry `2026.1`):

- Google Play + Apple App Review rules offline — no Play/ASC API required
- Findings include platform, guidelineReference, ruleVersion, evidence, fix
- Reports expose `guidelineVersion`; MANUAL REVIEW section for unprovable rules
- Wording: potential rejection risk / manual review required — not an approval certificate
- Live store APIs remain optional behind `--online`

Prior: Google OAuth `connect google` with bundled Desktop client + OS secure storage.
