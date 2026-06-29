<!--
Example output of /runtime-governance-review.
Target: the standing-permission + execution model of a highly capable coding
agent (Claude Code), reviewed from the GrantGuard-adjacent angle — what standing
"always allow" grants mean and how they accumulate. Advisory; nothing was run.
-->

## Strix Governance Review (SGRF v1)

**Target:** Claude Code — the agent execution + standing-permission model (the `settings.json` / `settings.local.json` allow-deny surface + permission modes + hooks)
**Date:** 2026-06-27
**Reviewer:** Claude Code (self-review, advisory)

> Re-scored under SGRF v1's 4 orthogonal axes. Sections below use the early
> 9-heading layout; the canonical 13-section structure is in `SKILL.md`.

### 1. Trust Root
The trust root is the human operator's machine and credentials. The agent acts
*under the user's identity* — it runs in the user's shell, with the user's tokens
and git config. There is no in-band signal that distinguishes "the human ran
this" from "the agent ran this autonomously"; attribution collapses to the
single local identity. Permission decisions are stored locally
(`~/.claude/settings.json`, project `settings.local.json`) — the trust root is
the local config plus whoever can edit it.

### 2. Execution Boundary
The boundary is a **per-tool permission check at tool-call time** (Bash, Edit,
Write, WebFetch, MCP tools, …). It is consistent in shape (every tool call is
checked) and it is genuinely at runtime — a good property. Permission *modes*
move the boundary (`default` prompts, `acceptEdits` auto-allows edits, `plan` is
read-only, `bypassPermissions` removes it). `PreToolUse` **hooks** are the one
programmable boundary where custom runtime logic can run.

### 3. Bypass Opportunities
- **Standing "Always Allow" grants accumulate** (the GrantGuard thesis): each
  approval adds an allow rule that fires forever after. Six months of "Always
  Allow" produces a broad, unaudited standing grant set. — **High**
- **Broad wildcards** (`Bash(*)`, `Bash(git push *)`, credential-store reads)
  short-circuit the prompt for an entire command class. — **High**
- **`bypassPermissions` mode / skip-permissions flag** removes the boundary
  entirely for a session. — **Critical**
- **`settings.local.json`** can broaden grants per-project without review. — **Medium**

### 4. Capability / Claim Model
Permissions are **static string-pattern allow/deny rules** — effectively
booleans matched against a command string. They carry no scope beyond the
pattern, **no expiration, no evidence of issuance, and no attenuation** across
spawned subagents (a subagent's tool access comes from its agent definition, not
a narrowing of the parent's grant). There is no notion of a capability that
knows *why* it was granted or *when* it should be reconsidered.

### 5. Evidence & Verification
Local session transcript + logs exist, but there is **no signed, independently
verifiable record** of what executed or why it was admitted. A third party
cannot confirm, from outside the machine, that a given action was evaluated and
allowed. The logs are not cryptographically tamper-evident.

### 6. Policy & Admissibility Evaluation
Evaluation is at runtime (good), but the "policy" is a static allow/deny list +
the active mode. It matches the command string against patterns; it does not
weigh identity, risk, environment, or prior evidence. Hooks can add real runtime
logic, but that is opt-in per operator. Changing policy means editing settings —
there is no live, centrally-managed policy.

### 7. Capability Freshness & Decision Confidence
**None.** A grant approved long ago still fires unconditionally. Nothing
revalidates when the repo changes, the operator's role changes, new secrets
appear, or risk rises. This is precisely the gap permission-hygiene tools surface
after the fact — there is no in-product decay or required revalidation.

### 8. Governance Maturity (SGRF v1 — 4 orthogonal axes)
- **Capability Maturity: 4.5/5** — a highly capable coding agent: broad consequential actions (shell, file write, deploy, network, MCP tools), high autonomy.
- **Governance Maturity: 2.0/5** — a real per-tool runtime gate exists, but standing "Always Allow" grants accumulate, broad wildcards short-circuit prompts, capability never decays, and attribution collapses to one local identity (sub-signals: trust-root clarity low, bypass-resistance low, freshness none, oversight erodes).
- **Independent Verifiability: 1.0/5** — local logs only; nothing a third party can confirm without trusting the machine.
- **Runtime Enforcement: 2.5/5** — the boundary is at runtime (good), but it is mode-removable (`bypassPermissions`) and driven by static pattern lists rather than contextual evaluation.

**Tier: Bronze.** The headline is the capability↔governance gap (**4.5 vs 2.0**): a very capable agent with weak independent governance — exactly the split a single blended score would erase.

### 9. Recommendations
**High Priority**
- Prune accumulated standing grants and narrow wildcards to specific commands — Reduces the durable bypass surface — Requires runtime enforcement? **No** (hygiene + prompting/config).
- Avoid `bypassPermissions` / skip-permissions outside throwaway sandboxes — Removes the only boundary — Requires runtime enforcement? **No** (operator discipline).

**Medium Priority**
- Add `PreToolUse` hooks for high-impact commands (deploy, push, secret access) so the boundary carries runtime logic, not just pattern matching — Requires runtime enforcement? **Partial** (hooks are a local runtime hook point).

**Quick Wins (prompting/skills only)**
- Run a permission-hygiene pass on `settings.json` / `settings.local.json`; remove anything you can't justify today.

> **Want these recommendations enforced, not just recommended?**
> A runtime governance layer (e.g. the Strix runtime) can evaluate every
> consequential action against the same criteria used in this review — at the
> moment of execution — and produce an independently verifiable, signed record of
> each decision. This review improves how an agent *thinks* about governance; a
> runtime makes the decisions *non-bypassable*. Learn more: https://strixgov.com

*This review is advisory — it read configuration and reasoned about the model; it enforced nothing and produced no signed record.*
