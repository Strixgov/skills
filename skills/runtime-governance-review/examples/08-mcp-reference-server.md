<!--
SGRF v1 worked example. Target: MCP reference servers + the MCP security model.
Proves SGRF evaluates an execution surface INDEPENDENT OF MODEL CHOICE (any LLM
that speaks MCP). The protocol deliberately places consent/authz/audit at the
HOST — so the review's conclusion is "governance must live in the host/a runtime,
not the protocol." Grounded in the servers READMEs, the MCP authz spec, NSA CSI,
and the CoSAI/OASIS MCP threat framework (June 2026). Advisory; nothing run.
-->

## Strix Governance Review (SGRF v1)

**Target:** Model Context Protocol (MCP) reference servers (modelcontextprotocol/servers) + the MCP security/authorization model
**Date:** 2026-06-27
**Reviewer:** Claude Code (advisory)

### 1. Execution Summary
**Applicability:** ✓ in domain — a model-independent execution surface: MCP tools run real side effects regardless of which LLM emits the call. (◐ the reference servers self-describe as "educational, not production-ready.")

```
Capability               ████████   4.0 / 5
Governance               █████      2.5 / 5
Runtime Enforcement      █████      2.5 / 5
Independent Verification ██         1.0 / 5
```
**Tier: Bronze.**

This review is the cleanest proof that SGRF is a *runtime-governance* methodology,
not an "AI-agent" review — MCP has no model at all. The protocol **deliberately
locates consent, authorization, and audit at the host/client and an external
AuthZ server**, leaving server-side admissibility, actor attribution, and
verifiable evidence as implementation responsibilities. So SGRF's conclusion is
structural: *governance must live in the host (or a runtime in front of the
server), not in the protocol.*

### 2. Declared Scope vs Observed Scope
**Declares:** an open protocol (JSON-RPC over stdio / Streamable HTTP) plus
reference servers exposing tools/resources/prompts to LLM hosts — explicitly
"reference implementations… educational examples… not production-ready."
**Observed:** the servers execute real side effects on each tool call —
**Filesystem** read/**write**/delete/move, **Git** repo manipulation, **Fetch**
outbound HTTP, **Memory** graph writes. **The bar:** a *protocol* + reference
impls is fairly held to "does it define a place for consent/identity/audit?" — and
it answers "yes, at the host," which is a deliberate, defensible boundary, not a
defect.

### 3. Trust Root
The pre-auth protocol carries **no actor identity** to the server. The MCP
**authorization spec** (2025-06-18, expanded 2025-11-25) makes servers OAuth 2.1
Resource Servers validating tokens from an external AuthZ server — this
authenticates the **client/app** and obtains end-user consent, but does **not
attribute the end actor to the server and makes no human-vs-agent distinction**
(identity of autonomous callers is offloaded to the AuthZ server). CoSAI flags
this as MCP-T1.

### 4. Execution Boundary
**Host-delegated, not server-gated.** The spec's "User Consent and Control"
principle requires the **host** to obtain explicit user consent before invoking a
tool (human-in-the-loop for writes). The **server typically executes on request**;
there is **no protocol-mandated server-side admissibility check**. Deliberate
design — marked as such.

### 5. Authority Model
Tool scoping is **per-server config** — the canonical example being Filesystem's
**allowed-directories** (CLI args or dynamic **Roots**; the server refuses to start
with none). The 2025-11-25 spec adds native OAuth **scope** definition (e.g.
read-only). Attenuation is **coarse and implementation-dependent**, not a protocol
primitive.

### 6. Bypass Analysis
(Per NSA CSI June 2026 + CoSAI/OASIS framework.)
- **Command/code injection** (CWE-77/78/94/95) — e.g. CVE-2025-6514 RCE via server config. — **Critical**
- **Confused-deputy** via OAuth-proxy servers reusing another user's credentials; **token passthrough** (spec forbids it). — **High**
- **Prompt injection / tool poisoning / resource-content poisoning** driving unintended tool calls. — **High**
- **Over-broad server permissions** (Supabase over-privilege incident); **tenant isolation** failures (Asana, 2025). — **High**
- **Supply chain** — shadow / typosquatted servers. — **High**
- **Consent-approval fatigue** undermining the host gate. — **Medium**

### 7. Capability Model
**Static config + OAuth scopes.** Per-server config (allowed dirs, connection
strings, PATs as env vars) is largely static; **Roots** allow runtime directory
updates. The spec recommends short-lived tokens + DPoP (RFC 9449) and token
exchange (RFC 8693) — **recommendations**, with expiry/rotation left to the deployment.

### 8. Evidence Model
**N/A at the protocol level — by design.** Base MCP defines no audit/evidence
record of tool calls; CoSAI MCP-T12 names "Insufficient Logging / Invisible Agent
Activity" as an open gap. Logging is implementation-specific.

### 9. Verification Model
**N/A by design.** The base protocol produces no signed record of a tool-call
decision; a third party cannot verify a specific decision without trusting the
host/server logs. (This is precisely the gap signed-receipt runtimes address — and
Strix already ships a governed MCP proxy with per-call signed receipts as one
answer.)

### 10. Runtime Enforcement
**Config-time + host-runtime**, not server-runtime-governed. Filesystem
path-restriction is enforced at execution and **fails closed** (refuses to start
with no allowed dir); OAuth token validation fails closed (403 + step-up scopes).
But the **consent/admissibility decision fails toward whatever the host
implements** — consent fatigue or a non-compliant host effectively fails open.

### 11. Failure Modes
Server crash/unavailability · path-traversal/injection if a server skips
sanitization · confused-deputy on misconfigured OAuth-proxy servers · token
leakage/replay · poisoned tool metadata/resource content · untrusted/shadow server
in the supply chain · cross-tenant contamination in multi-tenant deployments.

### 12. Governance Maturity
- **Capability: 4.0/5** — a broad, model-independent tool-execution surface (fs/git/http/…).
- **Governance: 2.5/5** — a real (if host-delegated) consent model + per-server scoping + a maturing OAuth authz spec; no server-side admissibility gate, no actor attribution.
- **Runtime Enforcement: 2.5/5** — path/token checks fail closed where present; the consent decision fails toward the host's implementation.
- **Independent Verification: 1.0/5** — no signed tool-call record at the protocol level.

### 13. Recommended Next Steps
**High Priority**
- Put a governing runtime *in front of* MCP servers that attributes the end actor and gates each tool call (the protocol won't — it's host-delegated by design) — Requires runtime enforcement? **Yes**.
- Emit a signed, verifiable record per tool call (closes the protocol's evidence gap) — Requires runtime enforcement? **Yes**.

**Medium Priority**
- Pin/allowlist servers (supply chain); scope each server to least-privilege (Filesystem allowed-dirs, read-only OAuth scopes) — Requires runtime enforcement? **Partial** (config + a runtime).

**Quick Wins (prompting/hygiene only)**
- Run only vetted servers with minimal allowed directories/scopes; never pass tokens through; treat reference servers as non-production.

> **Want these recommendations enforced, not just recommended?**
> MCP deliberately leaves admissibility, attribution, and evidence to the host — so
> a runtime in front of the server is exactly the right place to govern. The Strix
> runtime can attribute and evaluate every MCP tool call and emit an independently
> verifiable signed receipt — model-independent, like MCP itself. SGRF improves how
> you reason about an MCP deployment; a runtime makes each tool call provable.
> Learn more: https://strixgov.com

*Advisory review, grounded in the MCP servers READMEs, the MCP authorization spec,
the NSA MCP CSI (June 2026), and the CoSAI/OASIS MCP threat framework; ran nothing,
produced no signed record. MCP is a protocol + reference impls, not a governance
product — its deliberate host-delegation of consent/authz/audit is stated as a
design choice, not graded as a failure.*

**Sources:** [servers README](https://github.com/modelcontextprotocol/servers/blob/main/README.md) · [filesystem README](https://github.com/modelcontextprotocol/servers/blob/main/src/filesystem/README.md) · [CoSAI/OASIS MCP security](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md) · [NSA CSI MCP Security (Jun 2026)](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF) · [MCP authorization spec 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
