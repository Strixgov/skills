# @strixgov/verifier

**Prove an AI agent's decision was authorized — without trusting the
vendor that produced it.**

Runtime governance for AI agents is moving from a design-time / audit-time
concern to an **execution-time** concern. As autonomous AI systems land in
financial services, healthcare, public-sector operations, and infrastructure,
the question regulators are starting to ask isn't *"was this system designed
responsibly?"* but *"can you prove this specific decision was authorized at
the moment it was made?"*

That requires three things:

1. **Runtime authorization** — every governed action is evaluated before it executes
2. **Deterministic policy evaluation** — same inputs → same decision, every time
3. **Verifiable evidence** — any third party can confirm what was decided and that nobody altered it after the fact

What's rare about Strix is *where* the control sits and *who* it applies to:
the enforcement happens at the action boundary, and the same discipline
applies whether the actor is an agent, a human, or an automation. Most AI
governance today operates upstream of the action (prompts, evals) or
downstream (logs, post-hoc audit). Strix operates at the action itself.

This package is the public-facing layer of #3 — the open proof primitive
for that control. **Strix itself is never on the trust path** of this
verifier. No account, SDK, or API key required. The verifier re-derives
the signed bytes from the public proof API + JWKS and validates the
Ed25519 signature using only `node:crypto` and `globalThis.fetch` — the
same primitives a regulatory auditor would use.

```bash
npx @strixgov/verifier@latest 5686
```

Record `5686` is a real governance evidence record signed by the Strix
kernel on 2026-05-15. Its signing key (`strix-prod-2026-05`) is published
in the production JWKS and retained for the EU-AI-Act minimum 2-year
window — this command remains a reproducible demo for at least that long.

By default the CLI queries:
- **Proof API:** `https://www.strixgov.com/api/proof/<id>`
- **JWKS:** `https://www.strixgov.com/.well-known/strix-jwks.json`

Override with `--proof-base` / `--jwks-base` for a custom deployment.

If you'd rather drag-and-drop than CLI, the browser-side equivalent is
at [verify.strixgov.com](https://verify.strixgov.com) — a pure-static
WebCrypto verifier for Visual Artifacts v1 signed SVG cards (verdict
cards, receipts, approval seals). Same Ed25519 + JWKS primitives, same
verdict, no Strix server on the trust path. See the `visual` subcommand
below for the matching CLI form.

`@strixgov/verifier` is a **public reference implementation of AARM Core
R6** (tamper-evident receipts) — the Cloud Security Alliance's open
specification for runtime governance of autonomous AI actions. The full
AARM mapping is in the Standards alignment section below.

---

## What this package does — and what it doesn't

This package is a **verifier**, not an enforcer.

| What this package does | What this package does NOT do |
|---|---|
| Re-derives the canonical bytes of a signed evidence record and checks the Ed25519 signature against the public JWKS. | Decide whether an AI action should be allowed to execute. |
| Reports whether a record was produced by the holder of Strix's signing key. | Block, throttle, or revoke any agent's action at runtime. |
| Walks the proof chain and checks per-record link integrity. | Issue execution tokens, evaluate policy, or hold approval state. |
| Derives EU AI Act compliance flags from cryptographic outcomes (CI-5: never asserted). | Replace the runtime governance kernel that produced the record. |
| Runs entirely offline once you have the record + JWKS snapshot. | Connect to Strix, hold credentials, or require an account. |

The distinction matters: **the verifier proves the control occurred. The
runtime kernel makes the control happen.** A record that verifies tells you
that *if* a control was applied at execution time, it was applied by the
holder of the signing key whose public half is published at the JWKS URL.
It doesn't tell you that a control *had to* be applied — that's a property
of the system that produced the record, not a property of the signature.

If you're evaluating Strix as a runtime governance layer for autonomous AI,
the verifier is the open, reproducible part of the trust chain — see
[strixgov.com](https://www.strixgov.com) for the rest. If you're an auditor
or regulator checking records that were already produced, the verifier is
all you need.

---

## Quick start

```bash
# One-off verification, no install needed
npx @strixgov/verifier@latest 5686

# Or install once for repeated use
npm install -g @strixgov/verifier
strix-verify 5686
```

**Requirements:** Node.js 18.17+ or 20 LTS+ (earlier 18.x had `globalThis.fetch`
behind an experimental flag). **Zero runtime dependencies** — uses only Node's
built-in `crypto` and global `fetch`.

> **No outbound network access?** The `npx ... 5686` form fetches the
> evidence record + JWKS from `strixgov.com`. If you're behind a corporate
> firewall, in an air-gapped environment, or just want a fully offline
> proof-of-concept, see the [Offline-only quick start](#offline-only-quick-start)
> below.

Expected output:

```
@strixgov/verifier — Evidence Record #5686
────────────────────────────────────────────────────
Capability:  cron.evidenceOutboxRetry
Action:      allow
Actor:       system:cron
Created:     2026-05-15T05:27:14.691Z
Key ID:      strix-prod-2026-05   (sample — production kid as of May 2026)

Verification Results
────────────────────────────────────────────────────
  ✓ Hash valid:        true
  ✓ Signature present: true
  ✓ Signature valid:   true

  Status: VERIFIED

This record was cryptographically signed by the Strix governance kernel.
The evidence hash and signature are independently verifiable.
```

`Status: VERIFIED` is a **derived summary** of the three checks above —
true if-and-only-if all three are true. The detailed checks are always
reported so each can be audited independently.

---

## Offline-only quick start

For air-gapped environments, corporate firewalls that block
`strixgov.com`, or anyone who just wants to prove the verifier never
depends on a Strix-operated service: produce a receipt locally first,
then verify it locally — no network calls in either direction.

```bash
# 1. Install the gateway (local-first; generates its own signing key)
npm install -g @strixgov/tool-gateway

# 2. Initialize the local store (idempotent; creates ~/.strix-gateway/)
npx strix-gateway init

# 3. Export the public JWKS that the verifier will check signatures against
npx strix-gateway keys jwks > ./public-jwks.json

# 4. Produce a receipt by exercising the governed filesystem adapter once
#    (see @strixgov/tool-gateway README for the 5-minute quickstart)

# 5. Verify the chain — fully offline, no fetch() calls
npx @strixgov/verifier chain ~/.strix-gateway/receipts.jsonl --jwks ./public-jwks.json
```

The verifier uses only `node:crypto` + the JWKS file you pointed it at.
`globalThis.fetch` is never called in this path. Same Ed25519 +
canonical-JSON math, same `N/N receipts VERIFIED` output. Anyone
hand-verifying this against the source can confirm the path under
[Programmatic API](#programmatic-api) → `verifyEvidenceRecord({ record,
jwks })` — no network argument exists when both inputs are supplied.

The same offline path works for `@strixgov/mcp-proxy` receipts (when
`storagePath` is set, the proxy auto-persists the public JWK to
`<storagePath>/keys/public-jwk.json` — point `--jwks` at that file).

---

## How verification works

For evidence records, every `strix-verify <evidenceId>` run does six
things — in this order, with no hidden state in between:

1. **Fetches the evidence record from the proof API.**
   `GET https://www.strixgov.com/api/proof/<id>` returns the record's
   stored canonical fields, the signature bytes, and the kid that
   identifies which public key was used. Override the host with
   `--proof-base`.
2. **Fetches the signing public key from the JWKS endpoint.**
   `GET https://www.strixgov.com/.well-known/strix-jwks.json`, then
   selects the JWK whose kid matches the record. Override with
   `--jwks-base`.
3. **Reconstructs the canonical 13-field signed payload.** Field order,
   types, and serialization are locked. Any drift in reconstruction
   produces different bytes and fails the next step.
4. **Verifies the Ed25519 signature.** `crypto.verify(null, canonicalBytes, publicKey, signature)`. Pass → the bytes were signed by the holder of the private key whose public half is in the JWKS.
5. **Verifies the SHA-256 evidence hash.** Confirms the stored
   canonical fields match the hash that was originally chained into
   the proof chain. Pass → the record content hasn't been edited
   since signing.
6. **Reports pass/fail with the cryptographic details.** Default
   output is human-readable; `--json` returns a machine-readable
   object suitable for piping into auditing tooling.

The math is the same as any Ed25519 + JWKS verification. The contract
is: byte-for-byte canonical reconstruction must produce the bytes that
were originally signed. The CLI also runs a similar (but distinct)
5-step procedure for `approval <artifactId>` and `quorum <decisionId>`
— see `strix-verify --help` for the full breakdown.

---

## What can be verified

| Surface | Subcommand | Mode |
|---|---|---|
| Governance evidence records | `strix-verify <evidenceId>` | Online (proof API) |
| Approval artifacts (e.g. HIGH-risk approvals) | `strix-verify approval <artifactId>` | Online (proof API) |
| Approval quorum (chain continuity + quorum satisfied) | `strix-verify quorum <decisionId>` | Online (proof API) |
| Evidence + linked attestations (E1.5) | `strix-verify <evidenceId> --include-attestations` | Online (proof API) |
| Tool-gateway receipts | `strix-verify receipt <file.json> --jwks <jwks.json>` | Offline (local file) |
| Receipt chains | `strix-verify chain <file.jsonl> --jwks <jwks.json>` | Offline (local file) |
| Visual Artifacts v1 (signed SVG cards) | `strix-verify visual <file.svg> [--jwks <jwks.json>]` | Offline / online (mixed) |
| Connected-mode wire envelopes | Programmatic: `verifyConnectedWireEnvelope(...)` | Inbound HTTP (server-side) |

**Mode legend:**
- **Online** — queries `www.strixgov.com` proof API + JWKS over HTTPS. Requires network.
- **Offline** — verifies a local JSON / JSONL file against a local JWKS file. Nothing leaves your machine.
- **Inbound HTTP** — validates incoming POST request bodies on your own server, using a kernel-issued public key. Used by integrators receiving push notifications from a `@strixgov/tool-gateway` instance in connected mode.

---

## CLI usage

> **Prerequisite for the examples below:** they assume you've installed
> the package globally (`npm install -g @strixgov/verifier`). If you
> haven't installed it, prefix every command with `npx --yes @strixgov/verifier@latest`
> in place of `strix-verify`. For one-off verification, the npx form is
> the recommended path — see the [Quick start](#quick-start) above.

```bash
# Online: verify a single hosted evidence record
strix-verify 5686

# Online: include the linked attestation graph
strix-verify 5686 --include-attestations

# Online: verify an approval artifact
# Artifact IDs are Prisma cuid strings (e.g. clx8k7n2a0000abcd1234efgh).
# You obtain real IDs from the approval workflow API or audit trail.
strix-verify approval <approval-artifact-id>

# Online: verify a full quorum chain for a decision
# decisionId is also a cuid string, identifying the underlying decision
# whose approval chain you want to walk.
strix-verify quorum <decision-id>

# Offline: verify a local tool-gateway receipt
# `receipt.json` is produced by your local @strixgov/tool-gateway —
# see that package's docs for the export command. The JWKS is exported
# separately from the gateway.
npx @strixgov/tool-gateway keys jwks > ./public-jwks.json
strix-verify receipt ./receipt.json --jwks ./public-jwks.json

# Offline: walk an append-only receipt chain
# `receipts.jsonl` is newline-delimited JSON — one receipt per line,
# in chain order. Produced by the tool-gateway when chain mode is on.
strix-verify chain ~/.strix-gateway/receipts.jsonl --jwks ./public-jwks.json

# Verify a Visual Artifacts v1 SVG (browser parity with verify.strixgov.com).
# Reads the embedded canonical payload, recomputes sha256, verifies the
# embedded Ed25519 signature against a pinned JWKS (and the live JWKS if
# reachable), and surfaces drift between the two if any. Same verdict the
# browser produces.
strix-verify visual ./receipt.svg --jwks ./pinned-jwks.json

# JSON output (machine-readable, for piping into auditing tooling)
strix-verify 5686 --json
```

**Note on the `~/.strix-gateway/` path:** that's the default tool-gateway
storage root on macOS / Linux. On Windows PowerShell, `~` is not expanded
by the verifier; substitute the full path (typically
`C:\Users\<you>\.strix-gateway\receipts.jsonl`) or run from a shell that
expands `~` (Git Bash, WSL).

Override the upstream endpoints when verifying against a non-default
deployment:

```bash
strix-verify 5686 \
  --proof-base https://your-deployment.example.com \
  --jwks-base  https://your-deployment.example.com
```

---

## Verification states

For evidence records, the verifier reports three cryptographic checks
independently. Their conjunction is the `Status` field.

- **VERIFIED** — signature + hash + presence all valid against a
  recognized public JWK. The record is exactly what was signed by the
  Strix kernel.
- **COMPLIANCE_VIOLATION** — record claims to be signed but the
  signature does not validate. *Action: treat as critical. Either the
  bytes were tampered with after signing, or your verifier is below
  1.9.3 and hitting the response-flatten regression. Upgrade and
  retry; if still failing, file an issue.*
- **UNSIGNED** — record exists but carries no signature. *Action:
  cryptographic verification is not possible for this record.
  Hash-chain integrity may still be checkable via the
  `proofChainHash` field, but provenance is not.*
- **LEGACY_UNSIGNED** — record predates the migration that introduced
  Ed25519 signing. *Action: same as UNSIGNED but distinguished by a
  configured cutoff ID. Trust is by historical attestation, not by
  cryptographic verification.*

For approval artifacts and quorum, the same discipline applies, plus
chain continuity (`previousArtifactHash` walks back to genesis without
gaps) and quorum-met assertion.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | VERIFIED |
| `1` | FAILED (signature, hash, or chain broken — i.e. COMPLIANCE_VIOLATION) |
| `2` | ERROR (network failure, JWKS unreachable, key not found, malformed input, record not found) |

"Record not found" exits `2` (operational error), not `1` (verification
failure). The distinction matters: nothing was verified, so nothing
failed verification.

---

## Programmatic API

Everything the CLI does is a thin wrapper around the public exports:

```js
import {
  // Hosted evidence
  verify,
  fetchEvidence,
  fetchPublicKey,
  buildCanonicalPayload,
  verifySignature,
  verifyHash,

  // Approval artifacts
  verifyApprovalArtifact,
  verifyApprovalQuorum,
  fetchApprovalArtifact,
  fetchApprovalQuorum,
  buildApprovalCanonicalPayload,
  approvalCanonicalHash,

  // Linked attestations (E1.5)
  verifyAttestation,
  fetchAttestationsForEvidence,
  computeAttestationCompositeStatus,
  verifyWithAttestations,

  // Actor attestations (preview — not in this release)
  //   The function below is exported for forward compatibility but is
  //   not yet operational on the public verification surface. Cryptographic
  //   agent identity will ship in a subsequent release alongside the MCP
  //   gateway tooling. See the "Standards alignment" table for status.
  buildActorAttestationPayload,

  // Tool-gateway receipts + chains
  verifyReceipt,
  verifyReceiptChain,
  buildReceiptCanonicalPayload,

  // Tool-gateway chain snapshots
  verifySnapshot,
  buildSnapshotCanonicalPayload,

  // Tool-gateway connected mode
  verifyConnectedWireEnvelope,
  SUPPORTED_WIRE_VERSIONS,

  // Visual Artifacts v1 (browser parity with verify.strixgov.com)
  verifyVisual,
  extractVisualMetadata,

  // Compatibility helper covering hosted + receipt in one call
  verifyToolGatewayProof,
} from "@strixgov/verifier";
```

Hosted evidence (online):

```js
const result = await verify(5686);
if (result.verificationStatus === "VERIFIED") {
  console.log("Evidence is cryptographically valid");
}
```

Tool-gateway receipt (offline — no network):

```js
import fs from "node:fs/promises";
import { verifyReceipt } from "@strixgov/verifier";

const receipt = JSON.parse(await fs.readFile("./receipt.json", "utf8"));
const jwks    = JSON.parse(await fs.readFile("./public-jwks.json", "utf8"));

const result = await verifyReceipt(receipt, { jwks });
console.log(result.verificationStatus); // "VERIFIED" | ...
```

Connected-mode inbound HTTP envelope (kernel side):

```js
import { verifyConnectedWireEnvelope } from "@strixgov/verifier";

app.post("/strix/sync", (req, res) => {
  const result = verifyConnectedWireEnvelope({
    body:           req.rawBody,
    signatureHeader: req.headers["x-strix-signature"],
    apiKey:         process.env.STRIX_API_KEY,
  });
  if (!result.valid) return res.status(401).end();
  // ... persist req.body.payload ...
});
```

---

## Trust model

**The trust root is the public JWKS at
`https://www.strixgov.com/.well-known/strix-jwks.json`.** The verifier
never reaches anywhere else for the keys that gate validation.

**Stability guarantees:**
- The JWKS endpoint is a versioned public contract.
- Keys are retained for a **minimum of 2 years** after rotation
  (EU AI Act minimum retention). Records signed under a rotated kid
  remain verifiable for at least that window.
- Cache-Control on the JWKS response is `public, s-maxage=60`, so any
  intentional change is globally visible within ~1 minute.
- New keys are announced via the production CHANGELOG before rotation.

**What the verifier reads — and what it ignores:**
- Canonical fields are reconstructed from the stored record's `fields.*`
  block. The convenience top-level fields in the API response are for
  display and routing only and are NEVER used for canonical
  reconstruction.
- Environment, tenant ID, and signing key ID come from the signed
  record itself — never from `process.env` or other ambient context.
- Compliance flags (EU AI Act Art. 12 / 14 / 28) are *derived* from
  verification outcomes, not asserted by the verifier.

**For tool-gateway receipts**, the trust root is your local gateway's
exported JWKS (`strix-gateway keys jwks`). The verifier never reaches
out to a network in this mode — `--jwks` is a local file you control.

---

## Standards alignment

Strix is listed in the Cloud Security Alliance AARM Builders Registry
with status **Aligned**. AARM (Autonomous Action
Runtime Management) is the CSA-led specification for governing AI agents
at execution time. The full specification text lives at
[aarm.dev](https://aarm.dev/) (donated to CSA by Vanta, paper [arXiv:2602.09433](https://arxiv.org/abs/2602.09433)).

`@strixgov/verifier` is a **public reference implementation of AARM
Core R6** — tamper-evident receipts independently verifiable using
Ed25519 + JWKS, with no vendor trust path. The verifier covers Core
R1–R6 in full, with the next milestones (walk-to-genesis chain
verification + cryptographic agent identity binding) on the published
roadmap.

### AARM Core (R1–R6) — alignment map

| AARM Core Requirement | Strix implementation | Alignment |
|---|---|---|
| **R1 — Pre-execution interception** | Execution Boundary wraps every governed capability; mutations don't run until evaluation completes. | ✅ Full |
| **R2 — Context accumulation** | Canonical 13-field payload binds session, environment, tenant, actor, and capability into a single SHA-256 hash. | ✅ Full |
| **R3 — Policy evaluation with intent alignment** | Deterministic, content-addressable PolicyEngine (`sha256:…` version hash from canonical rule set). Same inputs → same decision, every time. | ✅ Full |
| **R4 — Authorization decision** | Single-use, payload-bound, scope-bound execution tokens. 5-minute default TTL. Atomic redemption. Revocable mid-flight. | ✅ Full |
| **R5 — Enforcement (allow / deny / defer)** | Hard fail-closed enforcement; handler is never invoked if any check fails. Approval/defer for HIGH/CRITICAL. | ✅ Full |
| **R6 — Tamper-evident receipts** | Ed25519-signed evidence records, locked 13-field canonical payload, SHA-256 hash chain. Reordering any field invalidates every signature. | ✅ Full |

### AARM Extended — alignment map

| AARM Extended capability | Strix implementation | Alignment |
|---|---|---|
| Approval workflows & quorum | Phase 3 approval artifacts (9-field canonical) + quorum verification with chain continuity. `strix-verify approval <id>` and `strix-verify quorum <id>` exercise this. | ✅ Full |
| Forensic reconstructibility / offline verification | Public JWKS at `/.well-known/strix-jwks.json` (2-year retention). Tool-gateway receipts + chains verify against a local JWKS file with no network access. | ✅ Full |
| Receipt chaining & auditability | `proofChainHash` cryptographically bound in every Ed25519-signed payload; per-record link integrity verifies today. Walk-to-genesis traversal is on the public-API roadmap. | ✅ Per-record · ⚠️ Walk-to-genesis on roadmap |
| Identity binding & actor attestations | Cryptographically verifiable agent identity is a planned future capability. It will ship in a subsequent release alongside the MCP gateway tooling. The current verifier package covers AARM Core R1–R6 in full; identity binding is the largest of the AARM Extended capabilities and is the next milestone on the roadmap. | 🔜 Future release |

**Status disclaimer.** "Aligned" in registry terms means the
implementation maps to AARM's written runtime-governance criteria — it
is not the same as "AARM Compliant," which requires CSA's conformance
testing protocol. Strix tracks the AARM working group and intends to
pursue formal conformance testing once that protocol publishes.

The canonical, more detailed mapping (with engineering primitives per
row) lives at [strixgov.com/partners/aarm](https://www.strixgov.com/partners/aarm).

---

## Glossary

- **Evidence record** — A row in Strix's governance kernel describing
  one governed decision (allow / deny / escalate / error) and its
  context (actor, capability, policy version, timestamps).
- **Canonical payload** — The 13-field JSON byte string that gets
  signed. Order, types, and serialization are locked — re-derivation
  must produce byte-identical output.
- **Signing key ID (`kid`)** — Identifies which Ed25519 key signed a
  record. Format: `strix-<env>-<YYYY-MM>` (e.g. `strix-prod-2026-05`).
- **JWKS** — JSON Web Key Set, RFC 7517. Standard format for publishing
  Ed25519 public keys. Strix's JWKS is at
  `/.well-known/strix-jwks.json`.
- **Approval artifact** — A signed record of an approval action
  (e.g. a reviewer signing off on a HIGH-risk decision).
- **Quorum** — Multi-approver chain verification: walks a chain of
  approval artifacts backward to genesis and asserts quorum policy
  was met.
- **Attestation** — A sibling artifact joined to an evidence record
  by `evidenceId`. Linked attestations (E1.5, available today) carry
  contextual claims about the underlying decision. Actor attestations
  (cryptographic agent identity binding) are planned for a subsequent
  release alongside the MCP gateway tooling and are not in scope for
  this release.
- **Tool-gateway receipt** — A signed record of a single tool
  invocation by an AI agent, produced by the
  `@strixgov/tool-gateway` package. Verifiable offline against the
  gateway's own JWKS.
- **Wire envelope** — The HTTP body format for connected-mode push
  from `@strixgov/tool-gateway` to a kernel. Includes replay-defense
  (timestamp + nonce + HMAC).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Error: No Record Found` (exit 2) | The ID doesn't exist in the proof API | Double-check the ID; try the `evidenceHash` instead of the numeric ID |
| `COMPLIANCE_VIOLATION` on a record that strix's own surfaces report healthy | Verifier version below 1.10.0 (response-flatten or canonical-reconstruction regression) | `npx clear-npx-cache && npx @strixgov/verifier@latest <id>` |
| `Error: Key not found in JWKS: <kid>` (exit 2) | The signing key's kid isn't in the JWKS | Check `https://www.strixgov.com/.well-known/strix-jwks.json` directly. If the kid genuinely isn't there during the 2-year retention window, the retention policy is breached — please file an issue |
| `Network error fetching … [ENOTFOUND] …` (exit 2) | DNS lookup failed for `www.strixgov.com` | Check your resolver and any corporate DNS overrides; ensure the host isn't on an internal-only domain list |
| `Network error fetching … [ECONNREFUSED] …` (exit 2) | A proxy or firewall is blocking outbound HTTPS to `www.strixgov.com` | Add `www.strixgov.com` to your outbound allowlist, or run from an unrestricted network. There is no offline mode for hosted records — see [Offline tool-gateway verification](#what-can-be-verified) if you need air-gapped operation |
| `Network error fetching … [ETIMEDOUT] …` (exit 2) | Proxy / VPN that silently drops outbound HTTPS, or unreachable host | Same as ECONNREFUSED. If you must verify from inside a restrictive network, run the CLI against a mirror you control via `--proof-base` and `--jwks-base` |
| `Network error fetching … TLS verification failed` (exit 2) | TLS-intercepting proxy without its root CA installed in Node's trust store | Install the proxy's root CA before retrying. Do NOT use `NODE_TLS_REJECT_UNAUTHORIZED=0` — that disables TLS validation globally and breaks the verifier's trust path |
| `Proof API fetch failed: HTTP 5xx` (exit 2) | Transient strix-platform issue | Retry in a few minutes |
| `Signature valid: false` while hash + presence are true | Either canonical reconstruction is wrong (verifier bug) or the record was tampered with after signing | Upgrade to latest verifier; if still failing on records strix reports as VERIFIED, file an issue |
| Clock skew warnings on tool-gateway connected-mode envelopes | Local clock drift > 5 minutes from the gateway | Sync system clock (NTP). The verifier rejects timestamps outside that window as replay defense |

---

## Versioning

This package is the cryptographic surface; we version it independently
of the Strix Console / Academy backend.

Schema changes are handled by dispatch on `schemaVersion` rather than
rewrites — older records remain verifiable by older verifier versions.
This is a load-bearing property for long-horizon audits.

Full release history:
[CHANGELOG.md](https://github.com/Strixgov/strix/blob/main/CHANGELOG.md).

**Upgrade urgency:** if you're on a version below **1.10.0**, upgrade now.
Versions 1.9.2 and 1.9.3 each patched a verification regression in the
response-flatten logic; 1.10.0 added a `signedPayload`-direct path that
bypasses canonical-reconstruction fragility (`schemaVersion` number vs
string, `regulatoryContext` key ordering, `sourceApp` discriminator).
All three regression classes affected every signed record on the hosted
proof surface; pre-1.10.0 verifiers will produce `COMPLIANCE_VIOLATION`
against records that are in fact correctly signed.

---

## Source and contributing

- **Source code:** [github.com/Strixgov/strix](https://github.com/Strixgov/strix)
- **Issue tracker:** [github.com/Strixgov/strix/issues](https://github.com/Strixgov/strix/issues)
- **Pull requests welcome.** The verifier is intentionally small (~1500
  lines, zero dependencies) so review is tractable.

When filing a bug, include:
- the `evidenceId` or `evidenceHash` you ran the verifier against
- the full CLI output (including the `Verification Results` block)
- the verifier version (`npx @strixgov/verifier --version`)
- whether strix's own status page or internal tooling reports the
  record as healthy

We treat verification regressions as critical bugs.

---

## Security / responsible disclosure

If you discover a cryptographic vulnerability — a way to produce
forged signatures, a side-channel revealing key material, a
canonical-payload ambiguity allowing two distinct inputs to produce
the same signature, or any other failure of the verifier's claimed
guarantees — please report **privately** via GitHub Security
Advisories:

[github.com/Strixgov/strix/security/advisories/new](https://github.com/Strixgov/strix/security/advisories/new)

Do not file these as public issues. We respond within 48 hours and
credit reporters in release notes unless they request otherwise.

---

## License

[MIT](https://github.com/Strixgov/strix/blob/main/LICENSE) © Velaris Group, 2026.

The cryptographic primitives are standard (Ed25519 / SHA-256 / RFC 7517
JWKS) — this package is a thin, audited wrapper around them, published
so verification cannot be gated on Strix's continued cooperation or
existence.
