# `/strix-wire` — wire Strix governance into a customer codebase

A Claude Code skill that takes a customer codebase from zero to a
kernel-evaluated mutation with a queryable, cryptographically **signed**
Strix decision in **about two minutes** — replacing the 15-minute manual
quickstart Path A.

This skill ships **two zero-account modes** — they prove different things,
and neither is a lesser version of the other:

| | **Sandbox Mode** | **Offline Mode** |
|---|---|---|
| Strix account needed | No | No |
| Network calls | Yes — every step, including signing, hits `www.strixgov.com` | **None** |
| Who signs | The hosted Strix kernel, with a Strix-controlled key | You — a local Ed25519 key held entirely on this machine |
| Terminal proof command | `npx @strixgov/verifier@latest <decisionId>` (INSTALL-1) | `solo strix-wire verify <path>` (LOCAL-VERIFY-1) |
| What it proves | The hosted Strix kernel evaluated and signed this decision | A local key signed a hash-chained, tamper-evident record — a `LOCAL_MACHINE_ASSERTION`, not Strix-operated custody |

**Sandbox Mode (default, hosted).** If `STRIX_API_KEY` / `STRIX_TENANT_ID`
aren't configured, the helper auto-provisions a short-lived sandbox
credential from `POST /api/public/sandbox/provision` and proceeds — a
stranger with no account still gets a real, hosted, kernel-evaluated
decision. The sandbox tenant only auto-executes this skill's closed set of
irreversible-mutation capability ids (see strix-platform's `policy.ts`
sandbox override); every other capability id goes through real risk
gating, same as a real account. The helper's final step posts a receipt
(`POST /api/v1/decisions/{decisionId}/receipt`) that Ed25519-signs the
decision itself, so the happy path ends in a genuinely verifiable
`Status: VERIFIED` record — checkable by anyone with
`npx @strixgov/verifier@latest <decisionId>`, no Strix tooling required.
The helper also still writes the older unsigned "recorded wire evidence"
row (kernel decision + payload/result hashes under a client-generated
`evidenceId`) as a secondary audit trail, unchanged. If the receipt step
itself fails, the skill degrades honestly — it never prints a verify
command with no signed record behind it.

**Offline Mode (new, zero hosted dependency).** Chosen explicitly at the
skill's proposal step. No network call anywhere — a local Ed25519 key is
generated on first run (`.strix/keys/`, 0600, never printed), and every
authorized, executed mutation is signed with it and appended to a
hash-chained local file (`.strix/evidence/receipts.jsonl`), plus exported
as a single JSON receipt per evidence id. Independently verifiable with
`solo strix-wire verify <path>` — no Strix account, no network, no Strix
tooling beyond a `solo-builder-core` install. See
[`docs/architecture/local-mode-strix-wire-v1.md`](../../../docs/architecture/local-mode-strix-wire-v1.md)
for the full design note, receipt schema, key lifecycle, threat model, and
exactly what this mode does and does NOT prove.

## What ships in this directory

```
.claude/skills/strix-wire/
├── SKILL.md                          # the playbook Claude runs; its directory name is the command
├── preflight.py                      # Step 0 fail-closed guard (refuses governed/production repos)
├── scanner.py                        # irreversible-mutation pattern scanner
├── helpers/
│   ├── governed_action.py            # Python reference helper — Sandbox Mode (hosted)
│   ├── governedAction.ts             # TypeScript reference helper — Sandbox Mode (hosted)
│   ├── governed_action_local.py      # Python reference helper — Offline Mode (zero network)
│   └── governedAction.local.ts       # TypeScript reference helper — Offline Mode (zero network)
└── README.md                         # this file
```

Everything the skill needs is bundled here — **no `pip install`** (`preflight.py`
and `scanner.py` are stdlib-only).

## Requirements (what it needs to actually run)

- **Python 3** on the machine — the scanner and the Step 0 preflight guard run
  via `python3`. Stdlib only, nothing to install.
- **Network access to `https://www.strixgov.com`** — the governance itself runs
  on the hosted kernel, not locally. The wrap's final step calls
  `POST /api/public/sandbox/provision` (zero-account sandbox credential, so no
  Strix account is required), then `/api/v1/evaluate`, `/api/v1/evidence/ingest`,
  and `/api/v1/decisions/{id}/receipt` (the Ed25519 signature). If the network is
  blocked the skill **degrades honestly** — it still scans and wraps, but it
  prints the unsigned evidence id and no verify command rather than faking one.
- **Node + npm** — only for the independent check
  (`npx @strixgov/verifier@latest <id>`) and the TypeScript helper path.
- **Not bundled here:** the fully-offline `solo demo adversarial` walkthrough is
  part of the separate `solo` CLI (`pip install solo-builder-core`), not this
  skill; and the verifier is an `npx` package. Only strix-wire itself ships in
  the plugin.

## How this skill is delivered and invoked

`strix-wire` is a **loose Claude Code project skill** — it lives at
`.claude/skills/strix-wire/` inside *this* repository. In current Claude Code a
project skill's **directory name is its command**, so an agent working with
`solo-builder-core` checked out and opened in Claude Code invokes it by typing
`/strix-wire`, and it also auto-triggers when the user asks to "wire Strix" /
"add Strix to this project" / "set up governed actions" (trigger phrasing lives
in `SKILL.md`'s frontmatter `description`).

You do **not** need a separate `.claude/commands/strix-wire.md` file — a
`.claude/skills/<name>/SKILL.md` directory and a `.claude/commands/<name>.md`
file both register the same `/<name>` command; the skill form is just the
richer one (it can ship supporting files like `scanner.py` and `helpers/`, and
Claude can auto-invoke it). See
[Claude Code → skills](https://code.claude.com/docs/en/skills.md).

### `strix-wire` in the `strix-personal` plugin

The `strix-personal` **plugin** (`plugins/strix-personal/`, installed via
`/plugin install strix-personal@strix`) is a **separate, namespaced** surface.
It ships `/strix-personal:strix-scan`, `/strix-personal:strix-plan`,
`/strix-personal:strix-apply`, `/strix-personal:strix-test`,
`/strix-personal:strix-status`, a `/strix-personal:execution-control` skill,
and — as of the productization branch — a `/strix-personal:strix-wire` fast
path. That command runs the same scan → wrap → run-once → verify flow as this
skill, behind the same Step 0 fail-closed preflight: its
`scripts/strix_preflight.py` is a **byte-identical vendored copy** of this
skill's `preflight.py`, kept in lockstep by
`scripts/sync_strix_personal_plugin.py` plus a parity test.

Bare `/strix-wire` (no namespace) is available **only** as the loose project
skill in this repo; the plugin's equivalent is always namespaced
`/strix-personal:strix-wire`.

## Troubleshooting: `/strix-wire` does not appear

1. **Confirm the file exists at the exact path** `.claude/skills/strix-wire/SKILL.md`
   relative to the directory you opened in Claude Code (a project skill is
   scoped to the repo root Claude was launched in).
2. **Restart Claude Code after a fresh checkout.** A brand-new skill *directory*
   is picked up on session start; if you cloned or pulled the skill mid-session,
   restart so it registers.
3. **Type `/` and search `strix`** to confirm the skill is listed. If you see
   `/strix-personal:...` entries but no bare `/strix-wire`, you have the plugin
   installed, not this repo open — use `/strix-personal:strix-wire` (same flow),
   or open this repo in Claude Code for the bare command.
4. **You do not need to create a commands file.** If you want a bare
   `/strix-wire` in a *different* repo, copy this whole `.claude/skills/strix-wire/`
   directory (SKILL.md + `scanner.py` + `helpers/`) into that repo's
   `.claude/skills/` and restart Claude Code.

## What the skill does

1. **Detects language** — Python vs TypeScript/JavaScript, by checking
   project markers.
2. **Scans for an irreversible mutation** — payments (Stripe), DB deletes
   (Prisma, SQLAlchemy, raw SQL), S3 deletes/writes, email/SMS sends,
   filesystem deletes, schema migrations.
3. **Proposes the wrap** — shows the candidate + the diff, asks the user
   to confirm via `AskUserQuestion`.
4. **Copies the helper** — drops `governed_action.py` or `governedAction.ts`
   into the customer's source tree, mirroring their layout.
5. **Wraps the call** — rewrites the call site to go through
   `governed_action(...)` / `governedAction(...)`.
6. **Runs it once** — executes the wrapped call against Strix using the
   customer's `STRIX_API_KEY` + `STRIX_TENANT_ID` (or an auto-provisioned
   sandbox credential — local mode), then prints the unsigned
   `evidenceId`, the proof-lookup URL, and — as the final output line —
   the runnable `npx @strixgov/verifier@latest <decisionId>` command
   (INSTALL-1: the run ends with an independent check the user executes
   themselves). Because the helper's last step signs the decision via
   the receipt route, this command genuinely returns `Status: VERIFIED`
   in the happy path — it only degrades to an honest "couldn't confirm
   the signed receipt" message if that last POST itself fails.

The scanner deliberately skips test paths. Tests creating real evidence
records would pollute the customer's audit chain.

## Running the scanner directly

The scanner is also useful standalone — for a code review pass, or to
sanity-check a codebase before wiring:

```bash
python3 .claude/skills/strix-wire/scanner.py --json | jq .
python3 .claude/skills/strix-wire/scanner.py --root ../other-repo
```

Exit codes: `0` (candidates found), `2` (none), `3` (bad invocation).

## The `governedAction()` contract

Both helpers implement the same contract:

0. **(Local mode only)** If no credentials are configured, POST
   `/api/public/sandbox/provision` (no auth) and use the returned
   `apiKey`/`tenantId` for every subsequent call in this run.
1. POST `/api/v1/evaluate` with `{ capabilityId, actor, context:
   { payloadHash, source } }`. Returns `allow` / `deny` / `escalate` plus
   a `decisionId`.
2. Run the caller's operation only on `allow`.
3. POST `/api/v1/evidence/ingest` with `{ records: [{ tenantId,
   capabilityId, actorId, actorRole, decision, reason, source,
   evidenceHash, evidenceId, timestamp, metadata }] }`. The response
   carries batch counters (`{ ingested, skipped, quarantined, ... }`),
   not per-record ids — the helper generates the `evidenceId` client-side
   (UUID v4), binds it into `evidenceHash`, and confirms
   `ingested + skipped >= 1` before reporting success. Unchanged from
   before local mode — still the unsigned secondary audit trail.
4. If step 1 returned a `decisionId`, POST
   `/api/v1/decisions/{decisionId}/receipt` with
   `{ success, result? }`. This Ed25519-signs the decision and returns
   `{ evidenceId (== decisionId), proofUrl }`. The helper constructs its
   own `npx @strixgov/verifier@latest <id>` string rather than trusting
   the route's own `verifyCommand` field, so the printed command is
   always `@latest`-pinned (INSTALL-1) regardless of the route's format.
   A failure here degrades gracefully: `result` and `evidenceId` (step 3)
   are still returned; `decisionId` / `signedEvidenceId` / `proofUrl` /
   `verifyCommand` are `null` instead of fabricated (PROOF-1).

The canonical-bytes contract from `solo_builder._canonical` is reproduced
inside each helper so `payloadHash` / `resultHash` / `evidenceHash`
reproduce byte-for-byte across the Python and TypeScript helpers.
Divergence breaks cross-SDK byte determinism (ADR-005 §4) — don't edit
the helpers post-copy.

## Capability-ID reference

The scanner emits one of these capability IDs per match. The pattern
list is GENERATED from the single-source registry at
`src/solo_builder/pattern_catalog.py` (regenerate with
`python -m solo_builder.pattern_catalog --generate-strix-wire`);
`tests/test_registry_parity.py` fails CI when any of the four detection
engines drifts from the registry.

| Category              | capability_id                     | First-proof eligible |
|-----------------------|-----------------------------------|----------------------|
| payments              | `payment.charge`, `payment.refund`| yes |
| db-delete             | `database.delete`                 | yes |
| db-update             | `database.update`                 | yes |
| db-create             | `database.create` (reserved)      | yes |
| s3-delete             | `storage.delete`                  | yes |
| s3-write              | `storage.write`                   | yes |
| email-send            | `email.send`                      | yes |
| sms-send              | `sms.send`                        | yes |
| file-delete           | `filesystem.delete`               | yes |
| schema-migration      | `database.migrate`                | yes |
| infra-apply/-destroy  | `infra.apply`, `infra.destroy`    | yes |
| iam-grant/-revoke     | `iam.grant`, `iam.revoke`         | yes |
| flag-flip             | `flag.flip`                       | yes |
| data-export           | `data.export`                     | yes |
| message-publish       | `message.publish`                 | yes |
| ai-tool-use           | `ai.tool_use`                     | yes |
| ai-agent              | `ai.agent_run`                    | yes |
| ai-provider           | `ai.completion`                   | no — observe-only |
| ai-embedding          | `ai.embedding`                    | no — observe-only |
| ai-retrieval          | `ai.retrieval`                    | no — observe-only |

These match the Strix `<artifact_type>.<action>` kernel convention
(ADR-003). The user can refine the capability later by issuing a more
specific token via `solo kernel approve`.

Observe-only AI surfaces are reported so the coverage map is honest, but
a first proof may never bind to them (PROOF-1): a model call, embedding,
or retrieval is observability, not an irreversible side effect. The two
consequential AI surfaces — `ai.agent_run` and `ai.tool_use` — rank
FIRST in scanner output: on an AI-native codebase the agent loop or LLM
tool dispatch is the wrap that matters, not the incidental Stripe call.

## Testing the helpers

```bash
pytest tests/test_strix_wire_scanner.py tests/test_strix_wire_governed_action.py
# Offline Mode — key manager, receipt schema/verifier, orchestration engine, CLI
pytest tests/test_strix_wire_local_key.py tests/test_strix_wire_local_receipt.py \
       tests/test_strix_wire_local.py tests/test_commands_strix_wire.py
```

The scanner tests assert pattern coverage + test-path skipping. The
Sandbox Mode helper tests assert canonical bytes match the `_canonical`
module byte-for-byte, the evaluate→run→evidence sequence is correct, and
denied actions never run the operation. The Offline Mode test suite
additionally covers hash/chain/signature tamper detection (one test per
signed field), key rotation + historical verification, corrupt/missing/
mismatched key files, and a policy-deny/approval-required bypass check.
`governed_action_local.py` and `governedAction.local.ts` are a genuine
cross-language conformance pair — a receipt minted by either verifies
against the other (exercised manually; see
`docs/architecture/local-mode-strix-wire-v1.md` "Verification contract").

## Out of scope

- **Multi-call wrapping.** One call at a time. Re-run the skill for more.
- **Async-context propagation.** Helpers take a callable; they do not
  thread custom context (request IDs, tracers).
- **Policy authoring.** Skill assumes the capability ID maps to a policy
  the Strix kernel already evaluates.
- **Pull request creation.** The skill stages a working-tree change; the
  user opens the PR.
