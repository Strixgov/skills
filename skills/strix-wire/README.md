# `/strix-wire` — wire Strix governance into a customer codebase

A Claude Code skill that takes a customer codebase from zero to a
kernel-evaluated mutation with a queryable, cryptographically **signed**
Strix decision in **about two minutes** — replacing the 15-minute manual
quickstart Path A.

**Strix Wire asks once for read-only analysis, then pauses only at decisions
that can change code or cause an action.** That is the consent architecture
(WIRE-CONSENT-1), and it is both easier and safer than prompting per command:
too many routine prompts train users to click "Allow" without reading, which
is exactly the wrong reflex to bring to the one approval that fires a real
irreversible action. The full design note is at
[`docs/consent-architecture.md`](../../docs/consent-architecture.md).

```text
CLICK 1   Authorize scoped repository analysis      (read-only, expires end-of-run)
   ↓      Analysis overview and recommended target
CLICK 2   Approve the exact source-code wrap        (files change: 1–2, actions execute: 0)
   ↓      Wrapper applied and validated
CLICK 3   Approve the sandbox action execution      (one run, this call site only)
```

Analysis-only users spend **1** approval; wrap-but-don't-run, **2**; the full
sandbox proof, **3**. A fourth prompt is legitimate only for genuine
environment setup (e.g. installing Node before a TypeScript run-proof).

This skill ships **two zero-account modes** — they prove different things,
and neither is a lesser version of the other:

| | **Sandbox Mode** | **Offline Mode** |
|---|---|---|
| Strix account needed | No | No |
| Network calls | Yes — every step, including signing, hits `www.strixgov.com` (only during the separately-approved execution phase — analysis contacts nothing) | **None** |
| Who signs | The hosted Strix kernel, with a Strix-controlled key | You — a local Ed25519 key held entirely on this machine |
| Terminal proof command | `npx @strixgov/verifier@latest <decisionId>` (INSTALL-1) | `solo strix-wire verify <path>` (LOCAL-VERIFY-1) |
| What it proves | The hosted Strix kernel evaluated and signed this decision | A local key signed a hash-chained, tamper-evident record — a `LOCAL_MACHINE_ASSERTION`, not Strix-operated custody |

**Sandbox Mode (default, hosted).** If `STRIX_API_KEY` / `STRIX_TENANT_ID`
aren't configured, the helper auto-provisions a short-lived sandbox
credential from `POST /api/public/sandbox/provision` and proceeds — a
stranger with no account still gets a real, hosted, kernel-evaluated
decision. The helper's final step posts a receipt that Ed25519-signs the
decision itself, so the happy path ends in a genuinely verifiable
`Status: VERIFIED` record. If the receipt step fails, the skill degrades
honestly — it never prints a verify command with no signed record behind it.

**Offline Mode (zero hosted dependency).** Chosen explicitly at the wrap
approval. No network call anywhere — a local Ed25519 key signs every
authorized, executed mutation into a hash-chained local receipt file,
independently verifiable with `solo strix-wire verify <path>`.

## What ships in this directory

```
skills/strix-wire/
├── SKILL.md                          # the playbook Claude runs
├── analyze.py                        # THE single scoped read-only analysis (one command = one authorization)
├── preflight.py                      # fail-closed guard (runs inside analyze.py; standalone for debugging)
├── scanner.py                        # irreversible-mutation scanner (runs inside analyze.py; standalone for debugging)
├── helpers/
│   ├── governed_action.py            # Python reference helper — Sandbox Mode (hosted)
│   ├── governedAction.ts             # TypeScript reference helper — Sandbox Mode (hosted)
│   ├── governed_action_local.py      # Python reference helper — Offline Mode (zero network)
│   └── governedAction.local.ts       # TypeScript reference helper — Offline Mode (zero network)
├── tests/                            # the consent-architecture contract, runnable by anyone
├── GETTING-STARTED.md                # first-time user quickstart + FAQ
└── README.md                         # this file
```

Everything the skill needs is bundled here — **no `pip install`**
(`analyze.py`, `preflight.py`, and `scanner.py` are stdlib-only).

## The analysis authorization, precisely

`analyze.py` is the whole read-only phase in one process: scope guard →
preflight → runtime detection → repository check → consequential-action scan
→ candidate analysis with automatic temporary-path exclusion →
helper-integrity comparison. One command, one permission prompt, one
disclosed card:

```bash
python3 skills/strix-wire/analyze.py --root . --json
```

By construction — and pinned by [`tests/`](./tests/) — the analyzer cannot:

- write, create, delete, move, or chmod any file;
- spawn a subprocess or execute repository code;
- open a socket or contact any service;
- read file content outside the disclosed `--root` (its own bundled files
  excepted) — and the CLI refuses a `--root` outside the current working
  directory unless `--allow-external-root` is passed for a deliberately
  re-disclosed scope;
- read content from a directory that isn't a recognized code repository;
- report "PREFLIGHT OK" from an incomplete look: a truncated scan or an
  unreadable subtree fails closed to STOP;
- install anything.

The authorization it represents is **single-run and single-root**: the
report pins `consent.scope_root`, `consent.expires = "end-of-run"`, and a
re-run or a different root requires a fresh disclosed authorization. It
never covers the wrap or the run — those are separate approvals with their
own cards (`PROPOSED CHANGE`, `RUN SANDBOX PROOF`).

Run the consent-architecture tests yourself:

```bash
python -m pytest skills/strix-wire/tests -q
```

## Running the scanner or preflight directly (debugging only)

Standalone invocations are for code review or debugging **outside** the
onboarding flow — during onboarding every phase runs inside `analyze.py`
so the user is never prompted per phase:

```bash
python3 skills/strix-wire/scanner.py --json
python3 skills/strix-wire/preflight.py --root . --json
```

Scanner exit codes: `0` (candidates found), `2` (none), `3` (bad
invocation). Preflight: `0` OK, `3` STOP (fail closed), `2` bad invocation.
Analyzer: `0` complete, `3` preflight STOP, `4` remediation required, `2`
bad invocation.

## The `governedAction()` contract

Both hosted helpers implement the same contract:

0. **(Sandbox Mode)** If no credentials are configured, POST
   `/api/public/sandbox/provision` (no auth) and use the returned
   `apiKey`/`tenantId` for every subsequent call in this run.
1. POST `/api/v1/evaluate` with `{ capabilityId, actor, context:
   { payloadHash, source } }`. Returns `allow` / `deny` / `escalate` plus a
   `decisionId`.
2. Run the caller's operation only on `allow`.
3. POST `/api/v1/evidence/ingest` — the unsigned secondary audit trail; the
   helper generates the `evidenceId` client-side (UUID v4), binds it into
   `evidenceHash`, and confirms `ingested + skipped >= 1`.
4. POST `/api/v1/decisions/{decisionId}/receipt` with `{ success, result? }`
   — Ed25519-signs the decision and returns `{ evidenceId (== decisionId),
   proofUrl }`. A failure here degrades gracefully: `result` and the
   unsigned `evidenceId` are still returned; `decisionId` /
   `signedEvidenceId` / `proofUrl` / `verifyCommand` are `null` instead of
   fabricated (PROOF-1).

The canonical-bytes contract is reproduced inside each helper so
`payloadHash` / `resultHash` / `evidenceHash` reproduce byte-for-byte across
the Python and TypeScript helpers. Divergence breaks cross-SDK byte
determinism (ADR-005 §4) — don't edit the helpers post-copy; the analysis
phase attests exactly this with its helper-integrity comparison.

## Capability-ID reference

The scanner emits one of these capability IDs per match (generated from the
single-source pattern catalog):

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

Observe-only AI surfaces are reported so the coverage map is honest, but a
first proof may never bind to them (PROOF-1). The two consequential AI
surfaces — `ai.agent_run` and `ai.tool_use` — rank FIRST in scanner output:
on an AI-native codebase the agent loop or LLM tool dispatch is the wrap
that matters, not the incidental Stripe call.

## Out of scope

- **Multi-call wrapping.** One call at a time. Re-run the skill for more —
  each run starts with a fresh analysis authorization, and once a first
  wrap exists the preflight flags the repo as already governed, so a second
  wrap takes an explicit sign-off (by design).
- **Async-context propagation.** Helpers take a callable; they do not thread
  custom context (request IDs, tracers).
- **Policy authoring.** Skill assumes the capability ID maps to a policy the
  Strix kernel already evaluates.
- **Pull request creation.** The skill stages a working-tree change; the
  user opens the PR.
