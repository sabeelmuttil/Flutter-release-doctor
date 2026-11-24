# Active context

Just implemented **structured JSON output and CI-friendly CLI options**:

- `--format console|markdown|json`, `--output`, `--fail-on error|warning|never`, `--no-markdown-report`
- JSON schema with summary + findings (`suppressed` flag)
- Protected `--output` overwrite guard; defaults unchanged

Previously: project config, CI/CD, deep link/push, platform, signing, environment, identity.
