# Strix Governance Review Framework (SGRF) v1

**Status:** Draft v1.0 (canonical methodology)
**Framework version:** SGRF v1
**Date:** 2026-06-27
**Owner:** Founders / Product (operator: Claude Code)
**Claim discipline:** Lives under `docs/strategy/`, scanned by
`scripts/lint-trust-claims.mjs`. Evidence-backed language only.

**The line this exists to make true:** people remember frameworks, not commands.
The goal is that teams say *"let's run a Strix Governance Review"* the way they
say *"let's run an OWASP review."* SGRF is the methodology; the skills
(`/runtime-governance-review`, `/govern-pr`, `/release-readiness`, future
`/trust-review`) are **implementations** of it. The skills are products; the
framework is the standard.

---

## 0. What SGRF is

A repeatable methodology for reviewing whether an autonomous or agentic system
governs **execution** — the moment a consequential action is about to happen —
and whether anyone outside the system can independently confirm it did.

SGRF answers four questions about any system, every time, in the same shape:
1. What can it do? (capability)
2. How well does it govern what it does? (governance)
3. Can a third party verify that governance happened? (independent verifiability)
4. Is the governance enforced at runtime, or only recommended / logged after the
   fact? (runtime enforcement)

SGRF is **advisory by construction.** A review reasons and reports; it does not
enforce. Enforcement is a runtime's job — which is exactly the upgrade path SGRF
makes legible (Framework → Skills → Runtime → Evidence → Verifier; each layer
adds capability, none replaces the previous one).

It deliberately sits in the lineage of OWASP Top 10, the Twelve-Factor App, the
C4 model, MITRE ATT&CK, and STRIDE: a named, versioned, published rubric anyone
can run — the moat is recognition + rigor, not secrecy.

---

## 1. The four lenses (one framework, four entry points)

| Lens | Skill | Reviews |
|------|-------|---------|
| **System** | `/runtime-governance-review` | A whole project / agent / MCP server / pipeline |
| **Change** | `/govern-pr` | A single PR or diff (SGRF *delta* review) |
| **Release** | `/release-readiness` | A release/deploy candidate |
| **Architecture** | `/trust-review` (planned) | A proposed design, pre-build |

Each lens runs the **same 13 sections** and the **same 4-axis scoring** — only
the unit under review changes. That sameness is the point: a reviewer who has
seen one SGRF review can read any of them.

---

## 2. Applicability + the canonical sections (SGRF v1)

### 2.0 Applicability (declare before scoring)

SGRF reviews **runtime execution governance**. Declare a target's applicability
*up front* so out-of-domain projects are never unfairly scored:

| Applicability | Examples |
|---|---|
| **✓ In domain** | runtime execution, autonomous agents, workflow automation (CI/CD), multi-agent systems, MCP servers, execution kernels |
| **◐ Partial** | static libraries / SDKs that *enable* execution but don't perform it |
| **✗ Not applicable** | pure documentation repos, UI component libraries, prompt/guidance libraries with no execution surface |

A Partial or Not-applicable target is declared as such, and its enforcement axes
are marked **N/A by design** — not scored low (the §5 fairness rule). Every review
carries an applicability tag in its Execution Summary. (The mattpocock/skills
review scoring largely N/A is the model: SGRF should *say* "this is a guidance
library; runtime enforcement, evidence, and verification are intentionally outside
its scope," not force a governance score.)

### 2.1 The canonical sections (SGRF v1)

Every full review produces these, in order. The delta lens (`/govern-pr`) reports
only the sections a change touches; it never renumbers them.

1. **Execution Summary** — applicability tag, the **ASCII governance profile** (§3), the 4-axis numbers + tier, and a one-paragraph verdict.
2. **Declared Scope vs Observed Scope** — *what the project claims to be* vs *what execution responsibilities it actually assumes*. This **sets the bar**: a prompt library is not held to cryptographic receipts; a deploy platform is; an execution kernel is held to the highest standard. This may become SGRF's signature section — it prevents strawman comparisons by calibrating expectations before any score.
3. **Trust Root** — the ultimate source of authority; how identity is established and attributed (human vs agent; credential sharing).
4. **Execution Boundary** — where the system decides to run a consequential action; whether it is a single consistent point.
5. **Authority Model** — does authority attenuate (delegated grant ⊆ parent) or transfer wholesale; is it re-evaluated at point-of-use or inherited.
6. **Bypass Analysis** — every way a consequential action can be reached without crossing the boundary (standing/wildcard grants, skip flags, direct calls, relaxed env branches). Each rated Low/Med/High/Critical.
7. **Capability Model** — how permissions/capabilities are represented; scope, constraints, expiration, issuance evidence — or bare booleans.
8. **Evidence Model** — does each consequential decision produce a record; is it on an audited path; is it tamper-evident.
9. **Verification Model** — can a third party confirm a specific decision **without trusting the system that produced it** (signed records + public keys + an independent verifier).
10. **Runtime Enforcement** — is admissibility judged at execution time and enforced there, or only at config time / post-hoc logging.
11. **Failure Modes** — what happens on missing/conflicting/stale context, signer unavailable, policy ambiguous; does it fail open or closed.
12. **Governance Maturity** — the 4-axis profile (§3) with per-axis justification + the ASCII visual.
13. **Recommended Next Steps** — gaps prioritized, each marked *prompting/hygiene only* vs *requires runtime enforcement*.

---

## 3. Scoring — four orthogonal axes (never one blended number)

SGRF's load-bearing scoring rule: **capability and governance are independent
axes.** A highly capable system can have weak independent governance; collapsing
them into one number hides exactly the gap the review exists to surface. This is
the methodology form of a discipline Strix already enforces in code — the
composable scorecard's "never a single-aggregate-green collapse" (ADR-028) and
the swarm graph's worst-of status floor (GR-2).

**The four axes (each 1–5, scored independently — do NOT average them together):**

| Axis | Asks | Sub-signals that feed it |
|------|------|--------------------------|
| **Capability Maturity** | How much can this system *do* — autonomy, breadth of consequential actions, reach? | scope of consequential actions, autonomy level, integration breadth |
| **Governance Maturity** | How well does it govern what it does? | Trust Root Clarity · Execution Boundary Strength · Authority Model · Bypass Resistance · Capability Freshness · Human Oversight |
| **Independent Verifiability** | Can a third party confirm a decision without trusting the system? | signed records · public keys · an independent verifier · audited path coverage |
| **Runtime Enforcement** | Is governance enforced at execution time, or advisory/post-hoc? | runtime evaluation vs config-time · fail-closed defaults · non-bypassable boundary |

Report them as a **profile**, e.g.:

```
Capability Maturity        4.8 / 5
Governance Maturity        2.6 / 5
Independent Verifiability  1.4 / 5
Runtime Enforcement        1.9 / 5
```

The gap *between* axes is the finding. A 4.8/1.4 split ("very capable, barely
verifiable") is the single most important thing a review can surface, and a
blended "3.1/5" would erase it.

**The governance profile (the visual every review ends with).** Render the four
axes as horizontal bars — **not** a radar chart (a radar invites averaging the
area; bars keep the axes visibly independent). Two block characters per point
(score 1–5 → 2–10 blocks); `n/a` for an N/A-by-design axis:

```
Capability               ██████████   (a highly capable, weakly governed agent)
Governance               ██████
Runtime Enforcement      ██
Independent Verification █
```

```
Capability               ████████     (a runtime kernel: governed + verifiable)
Governance               ██████████
Runtime Enforcement      ██████████
Independent Verification ██████████
```

People remember the *shape*. A short bar on Independent Verification next to a
full Capability bar communicates "powerful but unprovable" instantly — which is
the whole thesis. The profile appears in §1 (Execution Summary) and §12.

**Why exactly four axes (no fifth).** Four is the minimum complete set:
*what it can do*, *how well it's governed*, *is it enforced*, *can it be
independently verified*. Everything else — trust-root clarity, bypass surface,
freshness, oversight, failure modes — is **explanatory** (it feeds an axis or
lives in its own section), never a fifth scored number. Resist axis sprawl; the
power of the profile is that four bars are instantly legible.

**Maturity tiers** (a coarse label *per axis* or for the governance posture
overall — never used to hide a low axis):
- **Bronze** — governance is recommended/manual; gaps are mostly hygiene.
- **Silver** — a consistent execution boundary exists; most consequential actions cross it.
- **Gold** — runtime-enforced, fail-closed, with an evidence record per decision.
- **Verified** — **gated on Independent Verifiability ≥ 4**: decisions are signed
  and independently checkable by a third party against public keys. A system
  cannot be "Verified" on enforcement alone — the top tier is exactly the
  property the runtime + evidence + verifier stack provides, and nothing claims
  it without that.

---

## 4. How the skills implement SGRF

| Skill | SGRF sections | Scoring | Notes |
|-------|---------------|---------|-------|
| `/runtime-governance-review` | all 13 | full 4-axis profile | the reference system-lens implementation |
| `/govern-pr` | the subset a diff touches (2–9), + an Execution Summary verdict | axis **deltas** (does the change move an axis up/down?) rather than absolute scores | the change-lens |
| `/release-readiness` | all 13, framed for a release candidate | full 4-axis profile + a go/no-go readiness call | the release-lens |
| `/trust-review` (planned) | all 13, applied to a *design* | projected profile (what the design would score if built) | pre-build |

Each skill states "Implements SGRF v1" in its `SKILL.md`, produces the canonical
section names verbatim, and uses the 4-axis scoring. That consistency is what
makes them recognizable as one methodology rather than disconnected commands.

---

## 5. Rules every SGRF review obeys

1. **Advisory unless a runtime is present.** The review never blocks, gates, or
   mutates. If a Strix runtime is demonstrably reachable, a review may *optionally*
   surface a real `/api/v1/evaluate` verdict + signed receipt for a specific
   action — never a fabricated one.
2. **Capability ≠ governance.** Always report the axes separately (§3).
3. **No absolute claims.** Mark anything you couldn't verify as *unverified*,
   never as a pass. The tier "Verified" has a specific, gated meaning (§3) — do
   not apply it loosely.
4. **Ground every finding** in something actually read (file:line, config entry,
   doc). A "no governance-relevant surface" result is a valid, valuable finding.
5. **Fairness to non-enforcement targets.** A guidance library or a design doc is
   not an enforcement system; score it for what it is and mark enforcement
   dimensions N/A by design rather than penalizing them.

---

## 6. Versioning

SGRF v1 freezes the **Applicability preamble + 13 section names & order** and the
**4 scoring axes**. (The Applicability declaration and the *Declared Scope vs
Observed Scope* section were added 2026-06-27 while finalizing the v1 structure
**before first external publication** — no external party had relied on the
earlier 12-section draft, so this is finalization, not a breaking change.) From
here, a change to the section set or the axes is **SGRF v2** (a new spec), so that
"reviewed under SGRF v1" remains a stable, meaningful statement over time — the
same append-only-not-edit discipline the signed-evidence schemas use (ADR-002).
Sub-signals, the ASCII-bar scale, and tier thresholds may be refined within v1
with a dated note here; the sections and axes may not. **No fifth axis** (§3).

---

## 7. Roadmap (30-day sequence; founder-gated steps flagged)

1. **Write the SGRF spec** — this document. ✅
2. **Refactor `/runtime-governance-review` + `/govern-pr` to implement SGRF v1** —
   adopt the 13 sections + 4-axis scoring. (In scope.)
3. **Build `/release-readiness` on SGRF v1.** (In scope.)
4. **Publish ~10 governance reviews** — a teaching + distribution campaign where
   each review teaches the framework and demonstrates Strix indirectly. The set is
   **deliberately diversified** to prove SGRF produces *fair, differentiated*
   results across fundamentally different architectures — not just LLM agents.
   Especially load-bearing: **GitHub Actions** (workflow automation) and an **MCP
   reference server** (execution surface independent of model choice) — including
   them proves SGRF is a *runtime-governance* methodology, not an "AI-agent-review."
   Recommended publish order (self-review **last**, so SGRF is seen applied broadly
   before it's applied to its author): **1. LangGraph · 2. OpenHands · 3. CrewAI ·
   4. GitHub Actions · 5. Claude Code · 6. Cursor · 7. Codex · 8. MCP reference
   server · 9. Most-capable-agent system prompt · 10. Strix (self-review).**
   Producing the reviews is in scope; *publishing* them externally is a founder
   decision.
5. **Create the public `strixgov/skills` (or standards) repo.** *(Founder
   decision — outside the operator's GitHub scope.)*
6. **Contribute one or two skills upstream to mattpocock/skills.** *(Founder
   decision — external repo.)*

The sequencing is deliberate: the framework earns recognition first, so that an
upstream skill reads as *"an implementation of SGRF v1,"* not *"another useful
skill."* Then the runtime is the obvious next layer for any team that wants its
SGRF score to move from Bronze/Silver to Gold/Verified.
