# /runtime-governance-review

The **system lens of the Strix Governance Review Framework (SGRF v1)** — a Claude
Code skill that produces a structured, **advisory** review of how a system governs
execution: whether consequential actions are evaluated before they run, whether
trust can be independently verified, and how easily governance can be bypassed.
It emits the canonical 13-section SGRF report and a 4-axis maturity profile.

**It is diagnostic, not enforcing.** It reads and reports; it never blocks,
mutates, or runs anything. (Enforcement is a runtime's job — the review ends by
pointing there.)

## Use it when

- Reviewing a new agentic system, MCP server, CI/CD pipeline, or internal tool
- Auditing an existing setup for execution safety
- Preparing to run agents against production
- Assessing governance maturity *before* adding enforcement

## Invoke

```
/runtime-governance-review the deploy workflow in this repo
```

If you omit a target, the skill asks for one.

## What you get

The canonical 13-section SGRF report — applicability declaration · declared vs
observed scope · trust root · execution boundary · authority model · bypass
analysis · capability model · evidence model · verification model · runtime
enforcement · failure modes · governance maturity · recommended next steps —
plus the **4-axis maturity profile** (capability vs governance vs independent
verifiability vs runtime enforcement, never blended) and recommendations that
mark each fix as *prompting-only* vs *requires runtime enforcement*. See
`SKILL.md` for the exact step process and output contract.

## Advisory by default; honest about enforcement

The review never claims it enforced anything or produced a signed record — it did
neither. If a Strix runtime is actually present (`STRIX_API_KEY` +
`STRIX_TENANT_ID` and a reachable evaluation surface), the skill may *optionally*
surface a real `evaluate(...)` verdict + signed receipt for a specific high-risk
action — never a fabricated one. Otherwise it stays fully advisory.

To wire a first governed action and get a real VERIFIED record, see the sibling
skill `/strix-wire`.

## Companion

Pairs with `/strix-wire` (turns one call site into a governed, verifiable
action). This skill diagnoses; `strix-wire` remediates one finding end-to-end.
