---
description: Independently verify a Strix governance record (evidence, approval, quorum, receipt, chain, visual, CT, or swarm run) with @strixgov/verifier — Ed25519 + JWKS, no Strix account required.
argument-hint: "<evidenceId> | approval <id> | quorum <decisionId> | receipt <file> | chain <file> | visual <file.svg> | ct inclusion <hash> | swarm <id> [--json] [--proof-base <url>]"
allowed-tools: Bash(npx -y @strixgov/verifier:*), Bash(npx @strixgov/verifier:*)
---

# Strix Verifier

Run the open, independent Strix governance verifier and report the verdict.
`@strixgov/verifier` re-derives the canonical signed bytes from the public
proof API + JWKS and checks the Ed25519 signature using only standard
crypto — Strix is never on the trust path. No account, SDK, or API key.

**Arguments passed by the user:** `$ARGUMENTS`

If no arguments were given, the default is to verify the public sample
record `5686`. Otherwise pass the arguments straight through.

Verifier output:

!`npx -y @strixgov/verifier@latest ${ARGUMENTS:-5686}`

## How to interpret the output above

The CLI exit code is authoritative:

- **Exit 0 — `VERIFIED`** (incl. `VERIFIED_PINNED_ONLY` / `VERIFIED_LIVE_ONLY`):
  the record was produced by the holder of the Strix signing key whose public
  half is published at the JWKS URL, and the SHA-256 hash matches. Report it
  as cryptographically verified and surface the key ID, capability, actor, and
  timestamp the CLI printed.
- **Exit 1 — `FAILED`**: the signature is invalid or a hash mismatched. Treat
  this as a real verification failure — state which check failed (signature vs
  hash vs chain) from the output. Do not soften it.
- **Exit 2 — `ERROR`**: the verifier could not reach a verdict (network,
  unknown signing key, malformed input, record not found). This is *cannot
  verify*, not *invalid* — say so explicitly and report the cause. Suggest
  `--proof-base`/`--jwks-base` for a custom deployment, or an offline
  `--proof`/`--jwks` file if the environment has no outbound network.

### If exit 2 looks like a blocked network (egress)

A message such as `Proof API fetch failed: HTTP 403 (...)`,
`JWKS fetch failed: HTTP 403`, or `Network error fetching ...
[ENOTFOUND|ECONNREFUSED|ETIMEDOUT]` means the environment blocked the verifier's
outbound fetch to the proof API — common in a sandbox, CI container, corporate
proxy, or **Claude Code on the web**. State plainly that this is *cannot verify,
not invalid* (the record is unaffected), then surface these options to the user:

1. **Allowlist `www.strixgov.com`** in the environment's network/egress settings
   and re-run. On Claude Code (web) an environment or organization admin sets
   this — it's the user's environment policy, not something Strix controls.
2. **Use the hosted Strix Verify MCP connector**, which re-derives the same
   Ed25519 + JWKS verdict through Strix infrastructure and is *not* subject to
   the container's egress allowlist (same trust model — Strix is still never on
   the trust path).
3. **Verify offline** with local files: `--proof proof.json --jwks jwks.json`.
4. For a self-hosted Strix, pass `--proof-base <url>` / `--jwks-base <url>`.

Do **not** tell the user to disable TLS validation or otherwise weaken their
network security to make verification "work."

Subcommands the verifier supports: bare `<evidenceId>`, `approval <id>`,
`quorum <decisionId>`, `receipt <file>`, `chain <file>`, `visual <file.svg>`,
`ct inclusion|consistency`, and `swarm <swarmRunId>`. Re-run with `--json` if
the caller wants the raw machine-readable result.
