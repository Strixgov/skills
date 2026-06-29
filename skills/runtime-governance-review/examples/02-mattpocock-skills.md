<!--
Example output of /runtime-governance-review.
Target: github.com/mattpocock/skills (v1.0.0) — a public skills library.
Note the honesty discipline: a guidance library is NOT an enforcement system, so
several dimensions are N/A by design. The review does not ding the project for
lacking enforcement; it locates where governance must live (the host agent) and
frames a runtime as the complementary layer under ANY skills library.
-->

## Strix Governance Review (SGRF v1)

**Target:** github.com/mattpocock/skills (v1.0.0) — a public, markdown-based skills library for coding agents
**Date:** 2026-06-27
**Reviewer:** Claude Code (advisory)

> Re-scored under SGRF v1's 4 orthogonal axes. Sections below use the early
> 9-heading layout; the canonical 13-section structure is in `SKILL.md`.

### 1. Trust Root
Two roots, at two times. **At authoring time:** the repository maintainer + PR
review — what gets into the library. **At run time:** the agent that installs and
runs a skill, under its own identity and permissions. The library itself
establishes no identity for skill execution; it is instructions, and whoever runs
them inherits the authority.

### 2. Execution Boundary
There is **no execution boundary in the repository** — by design. Skills are
markdown guidance (`SKILL.md`); they execute nothing themselves. The real
boundary is whatever the host agent applies when it acts on a skill's
instructions. So "the execution boundary for mattpocock/skills" is *the host
agent's* boundary, not the library's.

### 3. Bypass Opportunities
The relevant risk is not "bypass the library's governance" (it has none, and
isn't trying to) — it is **what a skill can steer the host agent into**:
- **Model-invoked skills auto-trigger** without the user typing them. A skill's
  guidance can lead the agent toward consequential actions the user did not
  explicitly request. — **Medium** (bounded entirely by the host agent's permissions)
- **Supply-chain shape:** a compromised or careless skill could instruct
  consequential actions; the only mitigations are PR review at authoring time and
  the host agent's own permission model at run time. — **Medium**
There is no enforcement layer here to bypass — which is the honest finding, not a
deficiency to score harshly.

### 4. Capability / Claim Model
N/A by design — skills are instructions, not capabilities. There is no scope,
expiration, or issuance evidence because there is nothing being granted.

### 5. Evidence & Verification
No audit trail or verifiable record of what a skill caused; accountability lives
wherever the host agent logs. Again, expected for a guidance library.

### 6. Policy & Admissibility Evaluation
None in-repo; delegated entirely to the host agent.

### 7. Capability Freshness & Decision Confidence
N/A — static, versioned instruction files (changeset-versioned). Freshness is a
runtime concept; there is no runtime here.

### 8. Governance Maturity (SGRF v1 — 4 orthogonal axes)
*A guidance library is not an executing system, so most axes are **N/A by design**
— marked, not penalized (SGRF §5 fairness rule).*
- **Capability Maturity: N/A** — the library *does* nothing itself; capability lives in whatever host agent runs the skills.
- **Governance Maturity: N/A (by design)** — no enforcement layer in-repo; governance belongs to the host agent. (Authoring root is clear: maintainer + PR review.)
- **Independent Verifiability: 1.0/5** — no record of what a skill caused; nothing third-party-checkable.
- **Runtime Enforcement: N/A (by design)** — none in-repo; delegated to the host agent.

**Tier: N/A** — this is a guidance library, not an enforcement system, and scores honestly as one. The governance question it raises ("what can an auto-triggering skill steer the host agent into?") is answered by the *host agent's* axes, not the library's.

### 9. Recommendations
*Aimed at consumers of the library, not the maintainer — the library is doing its job.*

**High Priority**
- Treat model-invoked skills as influence on the agent: review which skills can auto-trigger, and scope the host agent's permissions so a skill cannot reach a consequential action the operator wouldn't approve — Requires runtime enforcement? **Yes** (the control lives in the host agent's runtime, not the library).

**Medium Priority**
- Pin skill versions and review diffs on update (supply-chain hygiene) — Requires runtime enforcement? **No**.

**Quick Wins (prompting/skills only)**
- Pair any installed skill set with a governance-review skill (like this one) so the operator periodically maps consequential-action surface.

> **Want these recommendations enforced, not just recommended?**
> A runtime governance layer (e.g. the Strix runtime) can evaluate every
> consequential action a host agent takes — regardless of which skill steered it —
> at the moment of execution, and produce an independently verifiable, signed
> record of each decision. Skills (from any library) improve how an agent *thinks*;
> a runtime makes what it *does* enforced and verifiable. Learn more: https://strixgov.com

*This review is advisory. mattpocock/skills is a guidance library by design; the absence of an enforcement layer is a correct architectural choice, not a defect — governance belongs in the agent that runs the skills.*
