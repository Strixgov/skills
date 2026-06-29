<!--
SGRF v1 worked example. Target: LangGraph (agent orchestration runtime).
Demonstrates the new SGRF v1 sections (Applicability, Declared-vs-Observed, ASCII
profile) and the "powerful but unprovable" shape. Grounded in official docs (June
2026). Advisory; nothing run.
-->

## Strix Governance Review (SGRF v1)

**Target:** LangGraph (langchain-ai/langgraph) — low-level agent orchestration framework + runtime
**Date:** 2026-06-27
**Reviewer:** Claude Code (advisory)

### 1. Execution Summary
**Applicability:** ✓ in domain — an agent orchestration runtime that executes tool calls.

```
Capability               █████████   4.5 / 5
Governance               █████       2.5 / 5
Runtime Enforcement      █████       2.5 / 5
Independent Verification ██          1.0 / 5
```
**Tier: Bronze.**

LangGraph is a very capable orchestration runtime that provides the *hooks* for
governance — `interrupt()`, persistence, Platform auth/RBAC, LangSmith tracing —
but leaves enforcement, attribution, capability-scoping, and verifiable evidence
to the host application. The profile is the classic "powerful but unprovable"
shape: a tall Capability bar next to a near-empty Independent Verification bar.

### 2. Declared Scope vs Observed Scope
**Declares:** "a low-level orchestration framework and runtime for building,
managing, and deploying long-running, stateful agents" — explicitly low-level,
focused on orchestration. **Observed:** it orchestrates while the host app's node
code executes — *except* the prebuilt `ToolNode`, which the framework itself runs,
auto-executing the tools in the last AI message, in parallel, with no approval
step by default. So LangGraph assumes *partial, real* execution responsibility.
**The bar this sets:** it is orchestration infrastructure, so we hold it to "does
it provide a usable boundary, attribution, and evidence hooks?" — not "does it
ship a kernel?" It should not be dinged for lacking cryptographic receipts on
*its own* layer, but the default-allow `ToolNode` is fair to scrutinize.

### 3. Trust Root
At the OSS-library/action level: none. Identity exists only at the LangGraph
Platform API layer — a `@auth.authenticate` handler returns a caller identity +
scopes, and `@auth.on` handlers do resource-level RBAC over threads/assistants/
crons. That authenticates the **caller of the API**, not the agent's individual
tool actions, and does not distinguish human-initiated vs agent-autonomous actions
once a run is underway.

### 4. Execution Boundary
An opt-in boundary exists: `interrupt()` raises `GraphInterrupt`, pauses the graph
(state persisted), surfaces a value, and resumes via `Command`; `HumanInTheLoop`
middleware (`interrupt_on`) maps tool names to approve/edit/reject/respond. **But
it is scattered, not centralized** — each developer chooses where to place
interrupts and which tools to list. A graph with no interrupt has no boundary.

### 5. Authority Model
Multi-agent via subgraphs + supervisor/handoff (`create_handoff_tool`). Authority
is **passed, not attenuated** — a handoff transfers control + shared state; there
is no built-in notion of a child's permissions being a strict subset of the
parent's. No capability attenuation across nodes/subgraphs.

### 6. Bypass Analysis
- **Default-allow tool execution** — `ToolNode` runs tool calls automatically;
  interrupts are opt-in. A tool not listed in `interrupt_on` auto-approves. — **High**
- **Parallel auto-execution** — `ToolNode` fires multiple side effects before a
  human sees any. — **High**
- **Resume-with-blanket-approve** — a single approve resumes without per-action
  scrutiny. — **Medium**
- Nothing structurally prevents a node from performing a side effect before any
  check. — **High**

### 7. Capability Model
Largely **static and developer-defined**: tools bound at graph construction;
`interrupt_on` is a static name→policy map. No native scope/constraint/expiry/
single-use semantics on what a tool may do at runtime; no revocable, time-bounded
execution grants. (Platform RBAC governs resource access, not per-action capability.)

### 8. Evidence Model
Checkpointers (SQLite/Postgres) persist graph state at every superstep — but these
are **operational persistence for resume/time-travel, not tamper-evident audit**
(mutable rows in your DB). LangSmith records the full execution tree —
**observability, not cryptographic evidence**. (LangChain's own forum has threads
asking whether an execution-evidence layer beyond traces is missing.)

### 9. Verification Model
**None.** No signed records, no public keys, no canonical payloads. A third party
cannot verify a specific decision without trusting LangSmith or the host DB.

### 10. Runtime Enforcement
Where present, interrupts/auth *are* enforced at runtime (`GraphInterrupt` genuinely
halts; auth handlers gate each request). But **coverage is config-time-determined**,
and the default posture is run-the-tool. On failure the design is **fail-safe-and-
resume**, not fail-closed-against-action: ungoverned tools simply run.

### 11. Failure Modes
Forgotten/absent interrupt → consequential tool runs unreviewed · parallel
`ToolNode` → multiple side effects before review · resume-approve gives no proof of
*who* approved · checkpoint store is mutable (editable audit trail) · handoff with
no attenuation → subagent inherits broad tool access · identity gap downstream of
the API boundary.

### 12. Governance Maturity
- **Capability: 4.5/5** — powerful orchestration: broad tool execution, multi-agent supervision, durable long-running state.
- **Governance: 2.5/5** — a real (opt-in) interrupt boundary + Platform RBAC exist, but default-allow tools, scattered coverage, and no authority attenuation.
- **Runtime Enforcement: 2.5/5** — runtime where configured, but config-determined and default-run; fail-safe-and-resume, not fail-closed.
- **Independent Verification: 1.0/5** — mutable persistence + observability only; nothing third-party-checkable.

### 13. Recommended Next Steps
**High Priority**
- Make the boundary default-deny for consequential tools (require explicit approval/allow rather than opt-in interrupts) — closes the largest bypass — Requires runtime enforcement? **Yes** (host-app or a runtime layer must enforce it).
- Attribute actions to an actor across handoffs (human vs agent) — Requires runtime enforcement? **Yes**.

**Medium Priority**
- Attenuate authority on handoff (child tools ⊆ parent) — Requires runtime enforcement? **Yes**.

**Quick Wins (prompting/hygiene only)**
- Inventory every tool reachable without an interrupt; add `interrupt_on` for each consequential one.

> **Want these recommendations enforced, not just recommended?**
> A runtime governance layer (e.g. the Strix runtime) can evaluate every
> consequential action against the same criteria used in this review — at the
> moment of execution — and produce an independently verifiable, signed record of
> each decision. SGRF improves how an agent *thinks* about governance; a runtime
> moves the Independent Verification and Runtime Enforcement bars toward Verified.
> Learn more: https://strixgov.com

*Advisory review, grounded in official LangGraph docs (June 2026); ran nothing,
produced no signed record. LangGraph is orchestration infrastructure that
intentionally delegates governance to the host app — scored on that basis.*

**Sources:** [overview](https://docs.langchain.com/oss/python/langgraph/overview) · [human-in-the-loop](https://docs.langchain.com/oss/python/langchain/human-in-the-loop) · [ToolNode](https://reference.langchain.com/python/langgraph.prebuilt/tool_node/ToolNode) · [persistence](https://docs.langchain.com/oss/python/langgraph/persistence) · [durable execution](https://docs.langchain.com/oss/python/langgraph/durable-execution) · [Platform auth](https://www.langchain.com/blog/custom-authentication-and-access-control-in-langgraph) · [subgraphs/multi-agent](https://docs.langchain.com/oss/python/langgraph/use-subgraphs)
