# Repository Instructions

- GitHub issues and pull requests are the execution source of truth.
- Run `gira guide agent` before issue work and use the Gira ticket lifecycle with dry-runs before mutations.
- Keep public status output redacted: never expose credentials, full query URLs, or response rows.
- Keep the public UI as a familiar one-column vertical status list backed by pinned upstream Gatus.
- Do not deploy or modify `statpan-infra` from this repository.
- Before merge, run functional, code-quality, container, and mobile/desktop visual checks.
- Record current-HEAD source review and the required QA evidence on the PR before `gira ticket finish`; resolve outstanding review findings first.
- `finish_review_policy: none` follows the existing zero-approval GitHub profile. It removes only the GitHub `APPROVED` gate, never source review, QA, or deployment authorization.

## Agent runbook
- One issue, one branch, and one explicitly stated scope per change; keep unrelated work out.
- Run `make test` directly; if it is long, run it in the background and record the result in the PR body.
- Run relevant quality, container, and visual checks before review, as required by the change.
- Do not make unauthorized live calls, deployments, secret changes, or infrastructure changes; infra work uses a `statpan-infra` operational packet.
- Delegate only a bounded issue packet with paths, acceptance criteria, and prohibited actions.
- Record evidence as `[command / exit code / actual output / interpretation / unconfirmed]`.
- Never shorten hashes in evidence; preserve complete SHA values.
- H1/MVP: scoped observation and diagnosis with correct unknown/stale handling and redaction.
- H2/Beta: approved runtime and canary observation with bounded live receipt admission.
- H3/v1: budgeted observation expansion, recovery operations, and explicit unobserved coverage.
