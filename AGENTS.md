# Repository Instructions

- GitHub issues and pull requests are the execution source of truth.
- Run `gira guide agent` before issue work and use the Gira ticket lifecycle with dry-runs before mutations.
- Keep public status output redacted: never expose credentials, full query URLs, or response rows.
- Keep the public UI as a familiar one-column vertical status list backed by pinned upstream Gatus.
- Do not deploy or modify `statpan-infra` from this repository.
- Before merge, run functional, code-quality, container, and mobile/desktop visual checks.
- Record current-HEAD source review and the required QA evidence on the PR before `gira ticket finish`; resolve outstanding review findings first.
- `finish_review_policy: none` follows the existing zero-approval GitHub profile. It removes only the GitHub `APPROVED` gate, never source review, QA, or deployment authorization.
