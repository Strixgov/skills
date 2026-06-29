<!--
Example output of /runtime-governance-review.
Target: a Strix internal surface — the governed /api/v1/evaluate decision path
(decision lifecycle + token enforcement + signed evidence + verifier), as
extended by PR #1670 (Decision Trace v1). Demonstrates the skill scoring a
high-maturity enforcement system HONESTLY: high marks where earned, real gaps
named (capability decay absent; AA-1 dormant). Advisory; nothing was run.
-->

## Strix Governance Review (SGRF v1)

**Target:** Strix Console — the governed `/api/v1/evaluate` decision path (decision lifecycle · token enforcement · signed evidence · public verifier), as extended by PR #1670 (Decision Trace v1)
**Date:** 2026-06-27
**Reviewer:** Claude Code (internal dogfood, advisory)

> Re-scored under SGRF v1's 4 orthogonal axes. Sections below use the early
> 9-heading layout; the canonical 13-section structure is in `SKILL.md`.

### 1. Trust Root
Rooted in an EXECUTED decision plus human approval, with evidence Ed25519-signed
under a key whose public half is served at a canonical JWKS
(`strixgov.com/.well-known/strix-jwks.json`). Actor id/role are bound on the
decision. **Gap:** agent-vs-human actor-class attestation (AA-1) is built but
**dormant** (the agent-key registry is empty pending a key ceremony), so
human/agent attribution is partial in production today.

### 2. Execution Boundary
A **single canonical guard** (`requireDecisionToken` / inline
`verifyAndRedeemExecutionToken`) gates every irreversible route, with a registry
of those routes (`tests/gate-j/irrev-boundaries.json`) and a CI invariant that
**no route ships unguarded** (`REQUIRED_GUARD_BASELINE = 0`). The boundary is
single, consistent, and CI-enforced — the strongest possible shape.

### 3. Bypass Opportunities
- Kernel-bypass is ratcheted: a lint catches direct tenant-scoped writes that
  skip the guard; an enforcement-coverage test fails the build on an unguarded
  irreversible route. — **Low residual**
- Dev/bypass flags (`STRIX_DEV_IMPERSONATION`, etc.) are asserted off in
  production by a boot-time invariant. — **Low**
- **Residual:** with AA-1 dormant, a "lying call site" (a process misreporting
  its actor class) is not yet cryptographically closed — that closes only when
  AA-1 is active. — **Medium**

### 4. Capability / Claim Model
Capability grants carry scope; execution tokens are **single-use, bounded
(default 5-minute TTL), and revocable**; delegated authority **attenuates** in
the swarm engine (a child grant is a strict subset of its parent). **Gap:**
capability **decay / decision confidence** is absent — grants do not lose
confidence as reality changes (repo/role/secret/policy drift). This is a known
roadmap item, not yet built.

### 5. Evidence & Verification
Every decision is Ed25519-signed over a canonical 13-field payload and is
**independently verifiable** by a third party via `@strixgov/verifier` against the
public JWKS — no trust in Strix required. PR #1670 adds the Decision Trace
additively (an ordered per-gate explanation), which improves legibility without
touching the signed payload. This is the system's strongest dimension.

### 6. Policy & Admissibility Evaluation
The PolicyEngine is deterministic and content-addressable; admissibility is
judged **at execution time** against the action, environment, and actor
(invariant #3), and **re-evaluated at point-of-use** so prior approvals do not
transfer (invariant #2). Decision Trace makes the per-gate evaluation legible
(identity → policy → risk → token → admissible).

### 7. Capability Freshness & Decision Confidence
Tokens expire and are revocable (good), but there is **no confidence decay**: a
valid grant does not weaken as context drifts, and there is no automatic
revalidation trigger. The roadmap names this (Decision Confidence, fail-closed) —
it is the clearest open gap in an otherwise strong system.

### 8. Governance Maturity (SGRF v1 — 4 orthogonal axes)
- **Capability Maturity: 4.0/5** — governs a broad capability registry across many consequential action types (deploys, mutations, role changes, payer submissions, swarm delegation).
- **Governance Maturity: 4.5/5** — single canonical guard, CI-enforced zero-unguarded baseline, authority attenuation (swarm SW-2), approval quorum with self-approval blocked; docked for AA-1 actor attribution dormant + capability decay absent.
- **Independent Verifiability: 5.0/5** — every decision Ed25519-signed over a canonical payload, independently checkable by a third party via `@strixgov/verifier` against a public JWKS — no trust in Strix required.
- **Runtime Enforcement: 5.0/5** — admissibility judged at execution time, deterministic, re-evaluated at point-of-use, fail-closed.

**Tier: Verified** — Independent Verifiability ≥ 4 (the gate for the top tier) is met: decisions are signed and third-party-checkable. The remaining gaps (capability decay, AA-1 activation) are *runtime features on the roadmap*, not hygiene — which is what a high-maturity target's open items look like.

### 9. Recommendations
**High Priority**
- Build capability decay / Decision Confidence (fail-closed: low confidence only ever tightens a verdict) — Closes the freshness gap so stale-context grants escalate or revalidate — Requires runtime enforcement? **Yes** (it is a runtime decision input; on the roadmap).
- Run the AA-1 key ceremony + flag flip — Closes the actor-attribution residual (human vs agent) — Requires runtime enforcement? **Yes** (signer + verifier are built; needs the ceremony + ops flip).

**Medium Priority**
- Ship the Decision Trace render surface (PR2) so the per-gate explanation is visible to operators/auditors, not just emitted — Requires runtime enforcement? **No** (render-only).

**Quick Wins (prompting/skills only)**
- None outstanding at the system level — the gaps here require runtime work, which is the point: a high-maturity target's remaining gaps are enforcement features, not hygiene.

> **Want these recommendations enforced, not just recommended?**
> This target *is* a runtime governance layer — most of its dimensions are
> already enforced and independently verifiable, which is why its remaining gaps
> are runtime features (decay, AA-1 activation) rather than hygiene. The same
> evaluation contract is what the advisory skills point teams toward. Learn more:
> https://strixgov.com

*This review is advisory — it read the decision path, policy engine, and evidence model and reasoned about them; it enforced nothing and produced no signed record. The signed records this system emits come from its own runtime, not from this review.*
