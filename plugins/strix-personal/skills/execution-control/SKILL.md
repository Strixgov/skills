---
name: execution-control
description: Explain AI execution control and assess (read-only) which actions in a project need governance. ASSESSMENT ONLY — it does not enforce anything. Use when the user asks "what is execution control", "which of my actions are risky", "what should Claude not be allowed to do", or wants a governance assessment before installing enforcement.
---

# Execution control — assessment & education (ASSESSMENT ONLY)

This skill **explains** execution control and **assesses** a project's risky
actions. It is deliberately read-only and provides **no enforcement**. When the
user wants actual governance (wrapping call sites, producing receipts), point
them at the `/strix-scan` → `/strix-plan` → `/strix-apply` commands in this same
plugin.

## What execution control is

Most AI safety happens *before* (prompt rules) or *after* (logs/audits) an
action. Execution control happens **at the moment of execution**: every
state-changing action is intercepted and evaluated against intent, context, and
capability *as it runs*, and either allowed, denied, or held for approval. The
result is a signed receipt anyone can verify — no trust in the agent required.

Five invariants make it load-bearing:
1. Nothing executes without evaluation.
2. Execution does not inherit authority (each action's own single-use grant is re-validated and consumed at point-of-use).
3. Admissibility is decided at execution time.
4. Enforcement is at runtime, not logging.
5. Execution is bounded and revocable (tokens expire, single-use).

## How to run an assessment

1. Identify the project's **consequential actions** — anything with an
   irreversible side effect (payments, deletes, sends, schema migrations) or an
   AI surface (model calls, tool-use, agent loops, retrieval). If the bundled
   scanner is available, the precise inventory comes from `/strix-scan`; for a
   pure conversational assessment, reason from the code you can read.

2. Classify each by risk:
   - **CRITICAL** — irreversible + high blast radius (delete-all, large refund).
   - **HIGH** — irreversible, externally observable (charge, send, role change).
   - **MEDIUM** — impactful but often legitimate (update, write).
   - **LOW** — observability matters (reads, completions, embeddings).

3. Produce a short remediation plan: which actions to govern first, what
   control each should get (approval-required vs auto-allow-with-evidence), and
   what the user gains (a verifiable receipt; a blocked risky action).

## Be honest

- This skill does not protect anything by itself. Say so.
- Detection is not enforcement. Never describe an assessed action as "governed".
- Do not fabricate receipts, evidence IDs, or coverage numbers.
- For real enforcement, the user installs the wrap via `/strix-apply` (local,
  free) and can upgrade to hosted approvals/proof via Connected Mode.
