# Repository Instructions

## Purpose and source of truth (Datapan Core)

**Core objective** (statpan_docs `projects/datapan/STRATEGY_CONTROL.md`):
공공데이터 전반을 파악하고, 필요한 데이터를 지속적으로 확보·갱신·검증하여 여러 사업에서 재사용할 수 있게 유지·공급한다.
This repo is one part of the Datapan Core product (Registry, Data, CLI, Health, Web, Infra). The product is a maintainable public-data foundation, not a single business model, procurement product, or sample cohort.

**Read order for agents** (private repo `StatPan/statpan_docs`, read `origin/main`, not a stale local checkout; reviewed at `578aebc`, 2026-10-17):
1. `projects/datapan/README.md` — source precedence.
2. `projects/datapan/REPO_CONTRACTS.md` — this repo's goal and standing feature IDs (see "Repository development goals" and its own section).
3. `projects/datapan/PM_DECISION_POLICY.md` — how requirements become Goals/issues; acceptance and escalation.
4. `projects/datapan/core/OPERATING_MODEL.md` — production vs delivery, reuse/isolation, cost, CTR/NFR/FLEX requirements.
Precedence: accepted strategy > REPO_CONTRACTS > OPERATING_MODEL > business/ research (hypotheses, not decisions) > historical docs. Implementation truth is default-branch code/tests; operational claims need dated runtime evidence; execution state lives in GitHub Goals/issues/PRs.

**Principles that bind every change**
- Production, publication, delivery, consumer receipt and customer acceptance are separate facts. Never report one as another.
- Failed/partial/unknown/not-measured are distinct states; unmeasured cost or coverage is not zero or complete. A failed refresh must not overwrite the last good version.
- Identity, provenance, observation time, and rights stay explicit. Name similarity or model inference alone is not a fact.
- Open/DIY local use stays genuinely useful; do not weaken it to push paid use. Paid value = recurring responsibility (collect, validate, refresh, source-change response, history/recovery, delivery).
- Customer-private/specific work is isolated from shared Core; reuse needs named evidence, rights, and bounded maintenance cost.
- Do not adopt a business model, price, offer, or market from an engineering ticket. Business research is not a decision; a Core release does not prove demand.
- Opening an issue/PR does not mean it is approved or prioritized. Deployment, publication, commercial activation, secrets, and ownership changes need their own explicit approval.
- Record gaps honestly: when code, docs, or runtime disagree, open/refresh an issue rather than silently changing one side.

**Health-specific purpose and boundaries**
Read `projects/datapan/REPO_CONTRACTS.md` directly with `git -C /home/statpan/workspace/statpan_docs show origin/main:projects/datapan/REPO_CONTRACTS.md`; the local `statpan_docs` checkout is stale and dirty and must remain read-only (no checkout or modification). Health's goal is operational visibility through reviewed, scoped observations and status/diagnosis contracts, not ownership of upstream calls, provider credentials, data production, or delivery acceptance. HEALTH-01 covers reviewed Registry-pinned observation scheduling and redacted receipt intake; HEALTH-02 covers observation history, incident lifecycle, silence/staleness detection, and recovery; HEALTH-03 covers bounded policy-bound diagnosis and safe next actions; HEALTH-04 covers public-safe status API/presentation that keeps owned-service status and external-dependency observations separate. The repository is complete only when those declared capabilities have their corresponding bounded contracts, evidence, and tests/runtime acceptance as stated by the source-of-truth contract and current GitHub issue/PR acceptance criteria.

Health must preserve the boundary that upstream/source state is not Datapan service state and neither is data freshness or delivery evidence; an execution stopping or going silent must itself be detectable, and unknown or stale evidence must remain explicit. Infra owns deployment, effective runtime, credential delivery, and recovery; this repository must not imply or take those responsibilities. Current work status is GitHub's source: the open MVP work is #90, #70, and #87, while the open Beta work is #83, #33, and #30 (`gh issue list --repo StatPan/datapan-health --state open`). `main ≠ deployed`: `https://status.statpan.com/datapan/` currently serves the English safe-gateway UI rather than assuming it is main's latest UI; recovery is blocked on statpan-infra #1421 (direct `curl -sI` evidence returned HTTP 200 and `content-type: text/html`, and the page title is `Datapan status | StatPan Status`).

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
