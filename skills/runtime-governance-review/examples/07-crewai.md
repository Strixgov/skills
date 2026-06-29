<!--
SGRF v1 worked example. Target: CrewAI (multi-agent orchestration).
Standout finding: multi-agent ATTRIBUTION + ATTENUATION collapse — no principal
survives the delegation edge; delegated agents inherit the full toolset. Grounded
in official docs + repo issues (June 2026). Advisory; nothing run.
-->

## Strix Governance Review (SGRF v1)

**Target:** CrewAI (crewAIInc/crewAI) — multi-agent orchestration framework (Crews + Flows)
**Date:** 2026-06-27
**Reviewer:** Claude Code (advisory)

### 1. Execution Summary
**Applicability:** ✓ in domain — orchestrates *and* executes (agents invoke tools + code).

```
Capability               █████████   4.5 / 5
Governance               ████        2.0 / 5
Runtime Enforcement      ████        2.0 / 5
Independent Verification ██          1.0 / 5
```
**Tier: Bronze.**

CrewAI is a capable multi-agent orchestrator whose distinctive governance gap is
**attribution**: agents carry a `role` *string*, not an actor identity, and when
one agent delegates to another, **no verifiable principal survives the delegation
edge** — and the delegate runs with its *own* full toolset (authority transfers,
it does not attenuate). This is the exact failure class a signed, attenuating
multi-agent kernel exists to close.

### 2. Declared Scope vs Observed Scope
**Declares:** a framework for orchestrating "role-playing, autonomous AI agents"
as Crews (teams executing Tasks) and Flows (event-driven workflows), with memory/
guardrails/observability "baked in." **Observed:** it both orchestrates and
executes — agents invoke hundreds of bundled tools (web, files, shell, vector DB)
and can run code. **The bar:** it's an orchestration library, so enforcement is
partly the host's job — but it *does* assume real execution, so the tool/delegation
surface is fair to scrutinize.

### 3. Trust Root
**N/A by design — and the core gap.** An agent's identity is a prompt persona
(`role`), not a cryptographic or actor identity. No trust root, no per-agent key,
no human-vs-agent actor class. A community request for an "Auth and Permissions
Delegation Layer" (#3235) confirms this is absent natively.

### 4. Execution Boundary
Partial and mostly **post-hoc**. `human_input=True` makes an agent prompt the
human *after producing its answer* (a review gate, not a pre-execution approval) —
and it's off by default. Flows add `@human_feedback` (blocks on console input).
**Task guardrails** validate *outputs* between tasks, not tool invocations. A real
pre-execution hook exists (`BeforeToolCallHook` can block a tool) but there is **no
native policy/authorization layer** on top (feature request #4877 asks for exactly
a pluggable policy contract). All gating is opt-in.

### 5. Authority Model
Delegation (`allow_delegation`, default **False**) and the hierarchical manager
agent pass a task to another agent that runs with **its own statically-assigned
toolset** — **authority transfers wholesale, it does not attenuate.** No budget,
scope-narrowing, or capability-subset at the delegation edge. (PR #2068 added
`allowed_agents` — narrowing *who* can be delegated to, i.e. the graph, not the
authority.)

### 6. Bypass Analysis
- **Unattended crews/flows** run with no human gate. — **High**
- **Default-allow tool execution** once a tool is on an agent. — **High**
- **Delegation amplifies reach** — a delegate's full toolset becomes usable, with
  no attenuation. — **High**
- **Cross-agent prompt injection** can steer one agent into delegating or invoking
  tools. — **High**
- **`code_execution_mode="unsafe"`** runs directly on the host. — **Critical** (when used)

### 7. Capability Model
Tools assigned **statically per agent**; **no scope, constraint, or expiry** on a
grant. `allow_code_execution` (default False) + `code_execution_mode`
(safe=Docker / unsafe=host) are **now deprecated**, steering users to external
sandboxes — so sandboxing is increasingly the host's responsibility.

### 8. Evidence Model
Verbose execution logs + task outputs + optional tracing. Anonymous OpenTelemetry
**telemetry** (version/OS/counts; no prompts/data unless `share_crew=True`;
disable via `CREWAI_DISABLE_TELEMETRY`). None of it is **tamper-evident or
signed** — plain, mutable records.

### 9. Verification Model
**None.** No signed evidence, no canonical decision record, no verifier; a third
party must trust CrewAI's logs.

### 10. Runtime Enforcement
Overwhelmingly **config-time** (which tools, which agents, delegation on/off) plus
opt-in runtime hooks. Defaults fail **open** for execution (allow tools, no
approval); the *safety defaults* (`allow_delegation=False`,
`allow_code_execution=False`) are conservative, but once enabled there is no
runtime re-evaluation.

### 11. Failure Modes
The headline is **multi-agent authority loss**: a delegated agent acting beyond
intended scope with an inherited full toolset; **attribution collapse** (no
principal survives the delegation edge, so a side effect can't be traced to an
originating human/agent); cross-agent injection laundering; silent partial-success
in hierarchical runs. None mitigated structurally.

### 12. Governance Maturity
- **Capability: 4.5/5** — broad multi-agent orchestration + tool/code execution.
- **Governance: 2.0/5** — conservative defaults help, but no actor identity, post-hoc-only human gate, and non-attenuating delegation.
- **Runtime Enforcement: 2.0/5** — config-time + opt-in hooks; default-allow once enabled; no runtime re-evaluation.
- **Independent Verification: 1.0/5** — plain logs + anonymous telemetry; nothing third-party-checkable.

### 13. Recommended Next Steps
**High Priority**
- Carry an attributable principal across the delegation edge (which human/agent originated this action) — Requires runtime enforcement? **Yes**.
- Attenuate authority on delegation (delegate tools ⊆ delegator) — Requires runtime enforcement? **Yes**.

**Medium Priority**
- Add a pluggable pre-execution policy layer over `BeforeToolCallHook` (#4877) — Requires runtime enforcement? **Yes**.

**Quick Wins (prompting/hygiene only)**
- Keep `allow_delegation`/`allow_code_execution` off unless needed; use an external sandbox; assign each agent the minimum toolset.

> **Want these recommendations enforced, not just recommended?**
> A runtime governance layer (e.g. the Strix runtime) can attribute every action to
> a signed principal, attenuate authority across agent-to-agent delegation, and
> produce an independently verifiable record — the exact multi-agent gaps this
> review found. SGRF improves how a crew *thinks* about governance; a runtime makes
> the delegation edge provable. Learn more: https://strixgov.com

*Advisory review, grounded in official CrewAI docs + repo issues (June 2026); ran
nothing, produced no signed record. CrewAI is orchestration, not a
governance-enforcement product — scored on that basis; its conservative defaults
are credited.*

**Sources:** [docs.crewai.com](https://docs.crewai.com/) · [Agents](https://docs.crewai.com/en/concepts/agents) · [Tasks/Guardrails](https://docs.crewai.com/en/concepts/tasks) · [Hierarchical Process](https://docs.crewai.com/en/learn/hierarchical-process) · [Human Feedback in Flows](https://docs.crewai.com/en/learn/human-feedback-in-flows) · [Telemetry](https://docs.crewai.com/en/telemetry) · issues [#4877](https://github.com/crewAIInc/crewAI/issues/4877), [#3235](https://github.com/crewAIInc/crewAI/discussions/3235), [PR #2068](https://github.com/crewAIInc/crewAI/pull/2068)
