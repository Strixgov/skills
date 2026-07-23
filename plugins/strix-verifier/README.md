# Strix Verifier — Claude Code plugin

Brings the open `@strixgov/verifier` into Claude Code as a slash command, an
MCP server, and a Stop hook, so you can independently verify Strix governance
artifacts without leaving your session. No Strix account, SDK, or API key — the
verifier re-derives the signed bytes from the public proof API + JWKS and checks
the Ed25519 signature with standard crypto. **Strix is never on the trust path,
and nothing in this plugin decides a verdict** — every surface shells out to the
verifier and relays exactly what it returns (including its exit code).

## Install

```
/plugin marketplace add Strixgov/skills
/plugin install strix-verifier@strixgov
```

This plugin is published from the `strixgov` marketplace at
[`github.com/Strixgov/skills`](https://github.com/Strixgov/skills)
(`.claude-plugin/marketplace.json`), alongside the `strix-governance` plugin.

## In a restricted or sandboxed environment (read this first if you hit a 403)

Online verification fetches the proof record + JWKS over HTTPS from **one host**:

- **`www.strixgov.com`** (or your `--proof-base` / `proofBase` if you self-host).

If you run inside a sandbox, CI container, corporate proxy, or any network with
an egress allowlist — for example **Claude Code on the web** — that fetch can be
blocked. You'll see exit code `2` / `ERROR` with a message like
`Proof API fetch failed: HTTP 403 (...)` or `Network error fetching ...`.
**That is *cannot verify*, not *invalid*** — the record is fine; the environment
just won't let the verifier reach the proof API.

Three ways to get a verdict, in order of least effort:

1. **Allowlist the domain.** Add `www.strixgov.com` to your environment's allowed
   network/egress domains and re-run. On Claude Code (web) this is set by an
   environment or organization admin in the environment's network settings —
   Strix can't set it for you, because it's *your* environment's policy.
2. **Use the hosted Strix Verify MCP connector.** It re-derives the same
   Ed25519 + JWKS verdict through Strix infrastructure, so it is **not** subject
   to your container's egress allowlist. Same trust model — Strix is still never
   on the trust path; the connector only fetches the public proof + JWKS for you.
3. **Verify fully offline.** Bring the proof + JWKS in as local files and no
   network is used at all:

   ```
   /strix-verify <id> --proof proof.json --jwks jwks.json
   ```

When the MCP tools hit this, the result carries `networkBlock: true` and a
`remediation` block spelling out exactly these options, so an agent can relay
them instead of dead-ending on the 403.

## What's in the box

| Surface | File | What it does |
|---|---|---|
| Slash command | `commands/strix-verify.md` | `/strix-verify …` runs the verifier and reports the verdict inline. |
| MCP server | `mcp/server.mjs` (`.mcp.json`) | Tools `strix_verify`, `strix_verify_record`, `strix_verify_swarm` an agent can call to get a structured verdict. |
| Stop hook | `hooks/verify-on-stop.mjs` (`hooks/hooks.json`) | **Opt-in** continuous-trust check: re-verify a pinned record each turn. Off by default. |
| CLI wrapper | `bin/strix-verify` | Stable entry point; prefers the vendored verifier, falls back to `npx`. |
| Vendored verifier | `vendor/strixgov-verifier/` | The verbatim MIT-published `@strixgov/verifier@1.11.0`, so launching the verifier needs no network. |

## Use — slash command

```
/strix-verify 5686                     # verify public sample evidence record
/strix-verify 5686 --json              # raw machine-readable result
/strix-verify approval <artifactId>    # verify a signed approval artifact
/strix-verify quorum <decisionId>      # verify an approval quorum chain
/strix-verify receipt receipt.json     # verify a tool-gateway receipt (offline)
/strix-verify swarm <swarmRunId>       # verify an agent-swarm run
/strix-verify <id> --proof-base https://your-deployment.example.com
```

## Use — MCP tools

Once the plugin is enabled the `strix-verifier` MCP server is registered
automatically. Three tools are exposed:

- `strix_verify` — pass raw verifier CLI args, e.g. `{"args":["quorum","<decisionId>"]}`.
- `strix_verify_record` — `{"evidenceId":"5686","proofBase":"…"}` (proofBase optional).
- `strix_verify_swarm` — `{"swarmRunId":"<id>"}`.

Each returns `{ verdict, exitCode, interpretation, raw, source }`. A FAILED or
cannot-verify outcome is returned as **data**, not an MCP error — inspect
`exitCode`/`verdict`. When a cannot-verify (exit 2) is caused by a blocked
outbound network (egress), the result also carries `networkBlock: true` and a
`remediation` object (`{ kind, host, summary, paths[], text }`) listing how to
get a verdict — allowlist the domain, use the hosted Strix Verify MCP connector,
or verify offline. See [In a restricted or sandboxed environment](#in-a-restricted-or-sandboxed-environment).

## Use — Stop hook (opt-in)

Disabled by default (silent no-op). Enable a per-turn re-check of one pinned
record either way:

- **Per session:** set `STRIX_VERIFY_ON_STOP=5686` (or e.g. `STRIX_VERIFY_ON_STOP="swarm <runId>"`).
- **Persistently:** set `verifyOnStop.enabled: true` (and `target`) in `config.json`.

When enabled it prints one advisory line (`[strix-verify] ✓ 5686 → VERIFIED key=…`)
to stderr after each turn. It is **advisory only** — it never blocks the session,
even on a FAILED verdict. The verdict is re-derived by the verifier, not the hook.

## Configuration (`config.json`)

```json
{
  "verifierVersion": "1.11.0",
  "proofBase": "https://www.strixgov.com",
  "jwksBase": "https://www.strixgov.com",
  "sampleRecord": "5686",
  "verifyOnStop": { "enabled": false, "target": "5686" }
}
```

Nothing here is a trust input — base URLs only choose *which* deployment to
fetch proof + JWKS from; the cryptographic verdict still comes only from
Ed25519 + the published JWKS.

## Exit codes (authoritative)

`0` VERIFIED · `1` FAILED (signature/hash) · `2` ERROR (cannot verify — network,
unknown key, not found). **`ERROR` means *cannot verify*, not *invalid*.**

## Offline use

The verifier is vendored, so it launches with no network. For fully offline
verification (no proof/JWKS fetch), pass local files:

```
/strix-verify receipt receipt.json --jwks jwks.json
/strix-verify <id> --proof proof.json --jwks jwks.json
```

## Vendoring / version pinning

The bundled verifier is a verbatim copy of the MIT-published package — never a
re-implementation (the canonical/verify logic has a single upstream source of
truth). Re-pin or refresh it reproducibly:

```
node scripts/vendor-verifier.mjs            # re-vendor the version in config.json
node scripts/vendor-verifier.mjs 1.12.0     # vendor a specific version
```

After changing the version, bump `verifierVersion` in `config.json` and
`version` in `.claude-plugin/plugin.json`. `verifierVersion` tracks the *vendored
verifier* and changes only when you re-vendor; plugin-only changes (docs, hooks,
MCP UX) bump only the plugin `version`, so it may run ahead of `verifierVersion`.

## What it requires

- Node.js 18.17+ / 20 LTS+ (the verifier ships zero runtime dependencies; this
  plugin adds none).
- Network access to the proof API + JWKS at `www.strixgov.com` for online
  verification — **one domain to allowlist** in a restricted environment (see
  [In a restricted or sandboxed environment](#in-a-restricted-or-sandboxed-environment)) —
  or local `--proof` / `--jwks` files for fully offline checks, or the hosted
  Strix Verify MCP connector when you can't change the egress allowlist.

The underlying package is published at
[`@strixgov/verifier`](https://www.npmjs.com/package/@strixgov/verifier)
(MIT). Source: <https://github.com/Strixgov/strix>.
