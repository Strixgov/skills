<!--
SGRF v1 worked example. Target: GitHub Actions (CI/CD workflow automation).
The "does SGRF apply beyond LLM agents?" test — and it does. Also surfaces a
subtle, differentiated finding: strong INDEPENDENT VERIFIABILITY for build
artifacts (Sigstore/SLSA) but NOT for the deploy/approval decision. Grounded in
official GitHub docs (June 2026). Advisory; nothing run.
-->

## Strix Governance Review (SGRF v1)

**Target:** GitHub Actions — CI/CD workflow automation (event-triggered YAML workflows on hosted/self-hosted runners)
**Date:** 2026-06-27
**Reviewer:** Claude Code (advisory)

### 1. Execution Summary
**Applicability:** ✓ in domain — workflow automation is a consequential-action executor (this review proves SGRF is a *runtime-governance* methodology, not an "AI-agent" review).

```
Capability               ██████████   5.0 / 5
Governance               ███████      3.5 / 5
Runtime Enforcement      ███████      3.5 / 5
Independent Verification ████████     4.0 / 5
```
**Tier: Gold** — with a sharp caveat (below): build-artifact provenance independently reaches the **Verified** bar, but the *deploy/approval decision* does not.

A deterministic, non-LLM system scores **higher on Independent Verification than
most LLM agents** — because GitHub ships Sigstore/SLSA artifact attestations. That
inversion is exactly the nuance SGRF exists to surface. The gaps are that the
governance gate is opt-in (not universal), default-open on legacy tenants, and
admin-bypassable.

### 2. Declared Scope vs Observed Scope
**Declares:** CI/CD and workflow automation. **Observed:** workflows execute
arbitrary code on runners and perform deploys, package/registry publishes, repo
writes, releases, and cloud-infra changes via OIDC. **The bar this sets:** this is
a high-consequence execution platform — it *should* be held to a high standard
(real boundary, least-privilege, verifiable records). We do not grade it on a
curve.

### 3. Trust Root
Two roots: (a) the auto-minted per-job **`GITHUB_TOKEN`** (installation token,
expires at job end); (b) **OIDC** — a short-lived JWT with claims (repo, ref,
workflow, `repository_id`, visibility, custom properties) exchanged for a cloud
token. Runs carry the triggering actor + event, so it *can* distinguish trigger
types — but the run executes with **workflow-defined authority, not the actor's**,
and a bot push is gated the same as a human's. (Repos created after 2026-07-15 get
an immutable OIDC subject, closing namespace-recycling reuse.)

### 4. Execution Boundary
For deploys: **Environments + deployment protection rules** — required reviewers
(≤6, one approval suffices, optional prevent-self-review), wait timers, branch
restrictions, and GitHub-App custom protection rules — evaluated when a job
references the environment. Separately, branch protection/rulesets gate merges.
**The gate is NOT uniform:** environment protection only fires for jobs that opt in
via `environment:`; a job with no environment runs ungated with whatever token
scope it requests.

### 5. Authority Model
The **`permissions:`** key scopes `GITHUB_TOKEN` per-workflow/job. Tenants created
on/after 2023-02-02 default the token to read-only all scopes; older tenants
default permissive. Least-privilege is **available and recommended but opt-in /
config-dependent**, not enforced by default on legacy tenants. No cross-job
attenuation beyond token scoping.

### 6. Bypass Analysis
- **`pull_request_target`** runs with secrets + a read/write token while a PR is
  untrusted; overriding the checkout ref to run fork code is the classic exfil/RCE
  path. — **Critical**
- **Self-hosted runners** are non-ephemeral by default; forkers can persistently
  compromise them and harvest secrets ("almost never use for public repos"). — **High**
- **Branch protection is admin-bypassable by default** unless "Do not allow
  bypassing" is enabled. — **High**
- **Ungated jobs** (no `environment:`, permissive token) run with no runtime gate. — **High**
- Third-party action supply chain (tag vs SHA pinning); secrets as CLI args
  visible to co-located jobs. — **Medium**

### 7. Capability Model
A static+dynamic mix: `permissions:` scopes (static), environment-scoped secrets
(released only after approval), allowed-actions allowlists (GitHub-authored /
verified-creator / `OWNER/REPO@SHA` pins) enforced at org/enterprise, and OIDC
**subject-claim conditions** as dynamic ABAC. Stronger than most agent frameworks'
bare booleans.

### 8. Evidence Model
Run/job logs (90-day default), org/enterprise audit log, and — notably —
**artifact attestations**: signed build-provenance records.

### 9. Verification Model
**The standout axis.** Attestations are signed via **Sigstore** (Fulcio
short-lived certs keyed to the workflow's OIDC identity); public repos write to an
immutable, publicly-readable **Rekor transparency log**. A third party verifies
with `gh attestation verify` (or cosign / a Kubernetes admission controller),
**including offline**, without trusting GitHub's API at verify time — reaching
SLSA v1 Build L2 (L3 with reusable workflows). This is genuine cryptographic,
externally-verifiable proof. **Caveat (the differentiator):** it proves the build
provenance of an *artifact* — it is **not** a signed, third-party-verifiable record
of the *deploy/approval decision*. That decision lives only in GitHub's (trusted)
audit log.

### 10. Runtime Enforcement
Protection rules are **runtime-evaluated** — the job sits in *Waiting* until they
pass — and **fail closed on the gate path** (unapproved within 30 days → job
fails; custom-rule webhook timeout → fails). But **which paths are gated is
config-time-determined**: an ungated job executes immediately with no runtime
evaluation.

### 11. Failure Modes
Unapproved/timed-out deploys fail **closed**. Misconfiguration fails **open**:
legacy permissive token default, ungated jobs, `pull_request_target` ref override,
self-hosted runner exposure, admin bypass, unpinned third-party actions. Approval
needs only **one** reviewer (no n-of-m quorum unless prevent-self-review + multiple
required); secrets visible cross-job on shared runners.

### 12. Governance Maturity
- **Capability: 5.0/5** — enormous reach: arbitrary code, deploys, publishes, infra, releases.
- **Governance: 3.5/5** — real boundary (environments), least-privilege (`permissions:`), allowlists + OIDC ABAC — but opt-in, default-open on legacy tenants, admin-bypassable, single-approver.
- **Runtime Enforcement: 3.5/5** — runtime-evaluated + fail-closed *where configured*; ungated jobs run unchecked.
- **Independent Verification: 4.0/5** — Sigstore/SLSA give offline, third-party-verifiable **artifact** provenance (the Verified bar) — docked because the **deploy/approval decision** itself is not independently verifiable, only the produced artifact.

### 13. Recommended Next Steps
**High Priority**
- Make the gate universal: require `environment:` (or an equivalent protection rule) on every job that touches secrets/deploys, so no job runs ungated — Requires runtime enforcement? **Yes** (org policy + the platform's runtime rules).
- Enable "Do not allow bypassing" on protected branches/environments to close admin bypass — Requires runtime enforcement? **Yes** (platform setting).

**Medium Priority**
- Pin third-party actions by SHA; restrict self-hosted runners away from public repos; avoid `pull_request_target` with fork-code checkout — Requires runtime enforcement? **Partial** (policy + config).

**Quick Wins (prompting/hygiene only)**
- Set explicit least-privilege `permissions:` on every workflow; turn on artifact attestations to lift the Independent Verification bar.

> **Want these recommendations enforced, not just recommended?**
> A runtime governance layer (e.g. the Strix runtime) can make the *deploy decision
> itself* a governed, bounded, revocable action with an independently verifiable
> signed record — closing the gap this review found between verifiable *artifacts*
> and an unverifiable *decision*. SGRF improves how you reason about release
> governance; a runtime makes the decision provable. Learn more: https://strixgov.com

*Advisory review, grounded in official GitHub Actions docs (June 2026); ran
nothing, produced no signed record. GitHub Actions is a high-consequence execution
platform and is held to that standard — its strong artifact-provenance story is
credited, and the artifact-vs-decision distinction is stated plainly.*

**Sources:** [secure-use](https://docs.github.com/en/actions/reference/security/secure-use) · [controlling permissions](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token) · [deployments & environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments) · [control deployments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/control-deployments) · [OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect) · [artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) · [SLSA L3](https://docs.github.com/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3) · [pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target) · [protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
