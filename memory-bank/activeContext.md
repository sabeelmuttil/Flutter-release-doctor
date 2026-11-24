# Active context

Just implemented **project-level configuration and finding suppression**:

- `.release-doctor.yaml` with `ignore`, `severity_overrides`, `approved_hosts`
- Stable finding `id` on every finding; shown in terminal/Markdown
- Ignored ERRORs → WARNING with suppression note; secret IDs non-suppressible
- `yaml` package dependency; `.release-doctor.example.yaml` + README docs

Previously: CI/CD, deep link/push, platform, signing, environment, identity.
