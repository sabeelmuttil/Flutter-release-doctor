# Active context

Just implemented **Environment / flavor safety checks**:

- Inspects `.env*` files, `lib/` API URLs, Android product flavors, iOS schemes, Firebase project IDs
- ERROR for production API URLs containing uat/staging/dev/localhost/10.0.2.2
- WARNINGs for missing prod env file, duplicate URLs, hard-coded lib URLs, unclear Android flavors, non-prod→prod-like URLs
- Secrets from env files are never reported

Previously: App identity ↔ Firebase consistency.

Next candidates: signing/release config, min SDK / deployment target, CI readiness.
