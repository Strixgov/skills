# `/strix-wire` — wire Strix governance into a customer codebase

A Claude Code skill that takes a customer codebase from zero to a
kernel-evaluated mutation with a queryable Strix evidence record in
**about two minutes** — replacing the 15-minute manual quickstart Path A.

The record is *recorded wire evidence* (kernel decision + payload/result
hashes under a client-generated `evidenceId`) — it is not Ed25519-signed
at ingest, so it reports as an unsigned record on verification surfaces.
VERIFIED is reserved for signed records.

## What ships in this directory

```
.claude/skills/strix-wire/
├── SKILL.md                          # the slash-command playbook Claude executes
├── scanner.py                        # irreversible-mutation pattern scanner
├── helpers/
│   ├── governed_action.py            # Python reference helper
│   └── governedAction.ts             # TypeScript reference helper
└── README.md                         # this file
```

The skill is invoked by typing `/strix-wire` in Claude Code. It also
auto-triggers when a user asks to "wire Strix" / "add Strix to this
project" / "set up governed actions" — the trigger phrasing is in
`SKILL.md`'s frontmatter `description`.

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
   customer's `STRIX_API_KEY` + `STRIX_TENANT_ID`, then prints the
   `evidenceId` plus the public verification URL.

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

Both helpers implement the same three-step contract:

1. POST `/api/v1/evaluate` with `{ capabilityId, actor, context:
   { payloadHash, source } }`. Returns `allow` / `deny` / `escalate`.
2. Run the caller's operation only on `allow`.
3. POST `/api/v1/evidence/ingest` with `{ records: [{ tenantId,
   capabilityId, actorId, actorRole, decision, reason, source,
   evidenceHash, evidenceId, timestamp, metadata }] }`. The response
   carries batch counters (`{ ingested, skipped, quarantined, ... }`),
   not per-record ids — the helper generates the `evidenceId` client-side
   (UUID v4), binds it into `evidenceHash`, and confirms
   `ingested + skipped >= 1` before reporting success.

The canonical-bytes contract from `solo_builder._canonical` is reproduced
inside each helper so `payloadHash` / `resultHash` / `evidenceHash`
reproduce byte-for-byte across the Python and TypeScript helpers.
Divergence breaks cross-SDK byte determinism (ADR-005 §4) — don't edit
the helpers post-copy.

## Capability-ID reference

The scanner emits one of these capability IDs per match:

| Category           | capability_id          |
|--------------------|------------------------|
| payments           | `payment.charge`       |
| db-delete          | `database.delete`      |
| db-update          | `database.update`      |
| db-create          | `database.create`      |
| s3-delete          | `storage.delete`       |
| s3-write           | `storage.write`        |
| email-send         | `email.send`           |
| sms-send           | `sms.send`             |
| file-delete        | `filesystem.delete`    |
| schema-migration   | `database.migrate`     |

These match the Strix `<artifact_type>.<action>` kernel convention
(ADR-003). The user can refine the capability later by issuing a more
specific token via `solo kernel approve`.

## Testing the helpers

```bash
pytest tests/test_strix_wire_scanner.py tests/test_strix_wire_governed_action.py
```

The scanner tests assert pattern coverage + test-path skipping. The
helper tests assert canonical bytes match the `_canonical` module
byte-for-byte, the evaluate→run→evidence sequence is correct, and denied
actions never run the operation.

## Out of scope

- **Multi-call wrapping.** One call at a time. Re-run the skill for more.
- **Async-context propagation.** Helpers take a callable; they do not
  thread custom context (request IDs, tracers).
- **Policy authoring.** Skill assumes the capability ID maps to a policy
  the Strix kernel already evaluates.
- **Pull request creation.** The skill stages a working-tree change; the
  user opens the PR.
