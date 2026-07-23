---
name: strix-verify
description: Independently verify a Strix governance artifact — signed evidence records, approval artifacts, approval quorums, agent-swarm runs, tool-gateway receipts/chains, signed visuals, and CT inclusion/consistency proofs. Re-derives the canonical signed bytes and checks the Ed25519 signature against the public JWKS using only standard crypto — no Strix account, SDK, or API key, and Strix is never on the trust path. Use whenever someone asks to verify, audit, or confirm the authenticity of a Strix proof, evidence id, approval, quorum, receipt, or swarm run.
user-invocable: true
---

# Strix Verify

Run the open, independent `@strixgov/verifier` and report its verdict. This skill
**never decides a verdict itself** — it shells out to the verifier (Ed25519 +
JWKS) and relays exactly what the verifier returns, including its exit code.

## How to run

Prefer the plugin's bundled wrapper (uses the vendored, version-pinned verifier
— launches with no network; the network is only used to fetch the proof/JWKS
unless local `--proof`/`--jwks` files are given):

```
"${CLAUDE_PLUGIN_ROOT}/bin/strix-verify" <args>
```

If the wrapper is unavailable, fall back to the published package:

```
npx -y @strixgov/verifier@latest <args>
```

If no target is given, verify the public sample evidence record `5686`.

## Argument forms

| Goal | Command |
|---|---|
| Evidence record | `strix-verify <evidenceId>` |
| Machine-readable | `strix-verify <evidenceId> --json` |
| Approval artifact | `strix-verify approval <artifactId>` |
| Approval quorum | `strix-verify quorum <decisionId>` |
| Tool-gateway receipt (offline) | `strix-verify receipt receipt.json [--jwks jwks.json]` |
| Receipt chain | `strix-verify chain receipts.jsonl` |
| Signed visual | `strix-verify visual proof.svg` |
| CT inclusion / consistency | `strix-verify ct inclusion <hash>` |
| Agent-swarm run | `strix-verify swarm <swarmRunId>` |
| Custom deployment | append `--proof-base <url>` / `--jwks-base <url>` |

## Interpreting the result (the exit code is authoritative)

- **Exit 0 — `VERIFIED`** (incl. `VERIFIED_PINNED_ONLY` / `VERIFIED_LIVE_ONLY`):
  the record was produced by the holder of the Strix signing key published at the
  JWKS URL and the SHA-256 hash matches. Report it as cryptographically verified
  and surface the signing key id, capability, actor, and timestamp the verifier
  printed.
- **Exit 1 — `FAILED`**: a signature or hash check did not pass. This is a real
  verification failure — state which check failed (signature vs hash vs chain).
  Do not soften it.
- **Exit 2 — `ERROR`**: the verifier could not reach a verdict (network, unknown
  signing key, malformed input, record not found). This is ***cannot verify*, not
  *invalid*** — say so explicitly and report the cause. Suggest
  `--proof-base`/`--jwks-base` for a custom deployment, or offline
  `--proof`/`--jwks` files if the environment has no outbound network.

If the exit-2 cause looks like a blocked network — `Proof API fetch failed: HTTP 403`,
`JWKS fetch failed: HTTP 403`, or `Network error fetching ... [ENOTFOUND|ECONNREFUSED|ETIMEDOUT]`
— the environment (sandbox, CI, corporate proxy, or **Claude Code on the web**)
blocked the outbound fetch. The record is fine. Surface, in order: (1) allowlist
`www.strixgov.com` in the environment's network/egress settings (an environment/org
admin sets this — it's the user's policy, not Strix's); (2) use the hosted **Strix
Verify MCP connector**, which verifies through Strix infrastructure and isn't subject
to the container's egress allowlist; (3) verify offline with `--proof`/`--jwks`.

Re-run with `--json` if the caller wants the raw machine-readable result.

## Guardrails

- Never claim a record is "invalid" on an `ERROR`/exit-2 outcome — that conflates
  *cannot verify* with *forged*.
- Never assert a verdict the verifier did not return; quote the verifier's own
  status string and exit code.
- On an exit-2 network/egress block, surface the allowlist / hosted-MCP-connector
  / offline options; never suggest disabling TLS or weakening any network control
  to force a verdict.
- No Strix credentials are needed or used; verification is signature-based.
