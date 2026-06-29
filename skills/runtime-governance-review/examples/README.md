# /runtime-governance-review — worked examples

Eight reference SGRF v1 reviews against deliberately different architectures — the
real test of a methodology is whether it produces **fair, differentiated** results
across them. Each shows the output contract (13 sections + Applicability +
Declared-vs-Observed), the **4-axis profile** (Cap / Gov / Enforce / Verif — never
blended), the ASCII governance profile, and the **honesty discipline**: scored for
what it *is*, gaps marked unverified, nothing claimed as enforced.

| # | Target | SGRF profile (Cap / Gov / Enforce / Verif) · Tier | What it demonstrates |
|---|--------|---------------------------------------------------|----------------------|
| [01](./01-claude-code-agent.md) | Claude Code standing-permission model | 4.5 / 2.0 / 2.5 / 1.0 · **Bronze** | The orthogonality payoff — a **very capable** agent with **weak governance/verifiability**; the 4.5↔2.0 gap a blended score would hide. |
| [02](./02-mattpocock-skills.md) | mattpocock/skills (external library) | N/A / N/A / N/A / 1.0 · **N/A** | Fairness — a guidance library isn't an enforcement system; most axes **N/A by design**, governance located in the *host agent*. |
| [03](./03-strix-evaluate-path.md) | Strix `/evaluate` path (PR #1670) | 4.0 / 4.5 / 5.0 / 5.0 · **Verified** | The top tier — Independent Verification ≥ 4 earns **Verified**; remaining gaps are *runtime features*, not hygiene. |
| [04](./04-langgraph.md) | LangGraph (orchestration runtime) | 4.5 / 2.5 / 2.5 / 1.0 · **Bronze** | "Powerful but unprovable" — orchestration infra that delegates governance to the host; tall Capability bar, near-empty Verification. |
| [05](./05-github-actions.md) | GitHub Actions (CI/CD, **non-LLM**) | 5.0 / 3.5 / 3.5 / 4.0 · **Gold** | Proves SGRF generalizes beyond LLM agents — and surfaces real nuance: a deterministic system scores **high on Independent Verification** (Sigstore/SLSA), but only for *artifacts*, not the deploy *decision*. |
| [06](./06-openhands.md) | OpenHands (autonomous SWE agent) | 5.0 / 2.5 / 3.0 / 1.0 · **Bronze** | Real runtime gates that are **off by default** (and disabled in headless/CI); the gate is LLM-self-rating; sandbox is the only hard boundary. |
| [07](./07-crewai.md) | CrewAI (multi-agent) | 4.5 / 2.0 / 2.0 / 1.0 · **Bronze** | **Attribution collapse** — no principal survives the agent-to-agent delegation edge; authority transfers, never attenuates. |
| [08](./08-mcp-reference-server.md) | MCP reference servers (**model-independent**) | 4.0 / 2.5 / 2.5 / 1.0 · **Bronze** | SGRF on a surface with **no model at all** — proves it's *runtime*-governance, not AI-review; the protocol offloads consent/audit/identity to the host by design. |

> Examples 01–03 use the early 9-heading layout (re-scored to the 4 axes); 04–08
> are full SGRF v1 (13 sections + Applicability + Declared-vs-Observed + ASCII
> profile). The spread across an agent permission model, a guidance library, a
> runtime kernel, an orchestration framework, non-LLM CI/CD, an autonomous SWE
> agent, a multi-agent framework, and a model-independent protocol — Bronze / N/A /
> Verified / Bronze / Gold / Bronze / Bronze / Bronze — is the evidence that SGRF
> differentiates *fairly*: it credits real controls (GitHub's Sigstore/SLSA →
> Gold; OpenHands' real-but-off gate), is fair to non-enforcement targets
> (mattpocock N/A), and reserves Verified for the one system with signed,
> independently-checkable decisions. Remaining publish-order targets: Cursor,
> Codex, most-capable-agent prompt, and the Strix self-review (last).

The spread is intentional: a low-maturity target whose fixes are mostly
prompting/hygiene (01), an external target the skill must review *fairly* without
overclaiming (02), and a high-maturity target where the open gaps require runtime
work (03). Together they show the adoption ladder the skill sits on:

```
Skill      → review behavior        (advisory; any agent, no runtime)
Runtime    → non-bypassable enforcement
Evidence   → signed proof
Verifier   → independent trust
```

All three are advisory. None ran or enforced anything; none produced a signed
record. The signed records referenced in example 03 come from that system's own
runtime, not from the review.
