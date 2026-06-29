<!--
SGRF v1 worked example. Target: OpenHands (autonomous SWE agent).
The runtime-enforcement stress test: it has REAL runtime gates (confirmation
policy + security analyzer, fail-closed when on) that are OFF by default and
absent in headless/CI. Grounded in official docs + SDK source (June 2026).
Advisory; nothing run.
-->

## Strix Governance Review (SGRF v1)

**Target:** OpenHands (All Hands AI; formerly OpenDevin) — autonomous software-engineering agent
**Date:** 2026-06-27
**Reviewer:** Claude Code (advisory)

### 1. Execution Summary
**Applicability:** ✓ in domain — a maximally-capable autonomous executor (bash, arbitrary Python, browser, git, deploys).

```
Capability               ██████████   5.0 / 5
Governance               █████        2.5 / 5
Runtime Enforcement      ██████       3.0 / 5
Independent Verification ██           1.0 / 5
```
**Tier: Bronze.**

OpenHands is the strongest *runtime-enforcement* case in the set — it actually
ships a per-action gate (confirmation policy + a risk analyzer, fail-closed when
enabled), which lifts its Runtime Enforcement bar above pure-orchestration peers.
The catch: the gate is **off by default, LLM-based, and absent entirely in
headless/CI**, and sandbox isolation is the only hard boundary. Very capable,
real-but-dormant governance, near-zero verifiability.

### 2. Declared Scope vs Observed Scope
**Declares:** "the open platform for cloud coding agents." **Observed:** the
flagship `CodeActAgent` deliberately exposes *general* primitives — bash, Python
(Jupyter), a browser DSL — and "lets it express anything as code," running an
autonomous act→observe loop to completion. **The bar:** this is a maximally-
capable executor by design, so it is held to a high standard for whether
consequential actions are gated.

### 3. Trust Root
Implicit: actions are authorized by **the agent loop itself** unless a
confirmation policy intervenes. No cryptographic actor identity, and **no
distinction between human-initiated and agent-autonomous actions** at the
execution layer (both are `ActionEvent`s in one stream). The runtime executes
with whatever credentials are mounted into the sandbox — i.e. the operator's
granted authority.

### 4. Execution Boundary
A real decision point exists in the SDK (`openhands/sdk/security/`): a
**confirmation policy** (`AlwaysConfirm` / `NeverConfirm` / `ConfirmRisky(threshold)`)
plus a **security analyzer** (`LLMSecurityAnalyzer`, default `'llm'`) that annotates
each action LOW/MEDIUM/HIGH/UNKNOWN. **But the default is OFF**
(`#confirmation_mode = false`), and **headless/CLI mode is hardcoded to
always-approve** (confirmation cannot be enabled there). So the boundary is real
but opt-in, and unavailable in exactly the automated mode where it matters most.

### 5. Authority Model
Hierarchical sub-agent delegation: sub-agents are independent conversations that
**inherit the parent's model config and workspace context** — full inheritance
into the same sandbox, **no attenuation** of capability or scope across the
delegation edge.

### 6. Bypass Analysis
- **Default config runs with no confirmation.** — **High**
- **Headless/CI cannot confirm** (intentional for automation; "safety comes from
  task quality and review discipline"). — **High**
- **The gate is LLM-based** — the same model proposes the action and rates its own
  risk, so an injection that drives a tool call can also bias the risk label. — **High**
- Credentials mounted into the sandbox are exposed to whatever runs. — **Medium**

### 7. Capability Model
The **primary control is sandbox isolation** (Docker default; also K8s / local /
remote) — a real runtime control, credited, but **coarse and binary**. There is
**no per-action scoping, no token expiry, no revocation, no allowlist** in the
core model.

### 8. Evidence Model
Strong observability: an **append-only EventLog** of immutable, replayable
Action/Observation events (next-event is a pure function of history). But these
are **plain logs — not signed, not tamper-evident, not hash-chained.**
Auditability ≠ cryptographic integrity.

### 9. Verification Model
**None.** No signed receipt, no externally re-derivable verdict; a third party
must trust OpenHands' own logs.

### 10. Runtime Enforcement
Genuinely **runtime + fail-closed when enabled** — tests confirm an unclassifiable
action still requires confirmation under `ConfirmRisky`
(`test_omitted_security_risk_still_requires_confirmation`). But the **system-level
default fails toward executing** (confirmation off; headless always-approves).

### 11. Failure Modes
Injection-driven tool calls in always-approve/headless runs · the self-rating LLM
analyzer mislabeling risk · full-authority delegation amplifying a compromised
sub-agent · credential exposure inside the sandbox · coarse isolation as the only
hard boundary.

### 12. Governance Maturity
- **Capability: 5.0/5** — maximally-capable executor by design.
- **Governance: 2.5/5** — real gate primitives + conservative test semantics, undercut by off-by-default, LLM-self-rating, and non-attenuating delegation.
- **Runtime Enforcement: 3.0/5** — genuine per-action runtime gate + sandbox (above pure orchestrators), but default-off and headless-disabled.
- **Independent Verification: 1.0/5** — append-only but plain logs; nothing third-party-checkable.

### 13. Recommended Next Steps
**High Priority**
- Default the gate ON for HIGH-risk actions, and provide a *non-LLM* policy path so the proposer doesn't rate its own risk — Requires runtime enforcement? **Yes**.
- Give headless/CI a real (non-always-approve) enforcement path — Requires runtime enforcement? **Yes**.

**Medium Priority**
- Attenuate authority across sub-agent delegation (child ⊆ parent) — Requires runtime enforcement? **Yes**.

**Quick Wins (prompting/hygiene only)**
- For interactive use, turn on `confirmation_mode` + `ConfirmRisky`; mount only the minimum credentials into the sandbox.

> **Want these recommendations enforced, not just recommended?**
> A runtime governance layer (e.g. the Strix runtime) can evaluate every
> consequential action against the same criteria used in this review — at the
> moment of execution, with a non-self-rating decision — and produce an
> independently verifiable, signed record. SGRF improves how an agent *thinks*; a
> runtime moves the Runtime Enforcement and Independent Verification bars toward
> Verified. Learn more: https://strixgov.com

*Advisory review, grounded in official OpenHands docs + SDK source (June 2026);
ran nothing, produced no signed record. Sandbox isolation is a real runtime
control and is credited; governance beyond the sandbox is the operator's
responsibility.*

**Sources:** [security docs](https://docs.openhands.dev/sdk/guides/security) · [delegation](https://docs.openhands.dev/sdk/guides/agent-delegation) · [headless](https://docs.openhands.dev/openhands/usage/cli/headless) · [SDK paper (arXiv 2511.03690)](https://arxiv.org/html/2511.03690v1) · `confirmation_policy.py` / `llm_analyzer.py` (All-Hands-AI/OpenHands) · issues [#10242](https://github.com/All-Hands-AI/OpenHands/issues/10242), [#5264](https://github.com/All-Hands-AI/OpenHands/issues/5264)
