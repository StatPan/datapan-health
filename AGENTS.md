# Repository Instructions

- GitHub issues and pull requests are the execution source of truth.
- Run `gira guide agent` before issue work and use the Gira ticket lifecycle with dry-runs before mutations.
- Keep public status output redacted: never expose credentials, full query URLs, or response rows.
- Keep the public UI as a familiar one-column vertical status list backed by pinned upstream Gatus.
- Do not deploy or modify `statpan-infra` from this repository.
- Before merge, run functional, code-quality, container, and mobile/desktop visual checks.
