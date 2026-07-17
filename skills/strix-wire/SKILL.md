---
name: strix-wire
description: Wire Strix governance into the current codebase. Scans for an irreversible mutation (payment charges, deletes, sends, schema migrations), wraps the call site with governedAction(), runs it once, and prints the resulting evidenceId. Use when the user asks to "wire Strix", "wire up Strix", "add Strix to this project", "set up governed actions", "get an evidence record", or runs /strix-wire.
---

# /strix-wire — five steps to a recorded governed action

This skill takes a customer codebase from zero to a kernel-evaluated mutation
with a queryable Strix evidence record in **about two minutes** — replacing the
15-minute manual quickstart Path A.

> **Claim discipline (Sandbox Mode):** the helper's final step posts a receipt
> (`POST /api/v1/decisions/{decisionId}/receipt`) that Ed25519-signs the
> decision itself — so the happy path produces a genuinely verifiable,
> `Status: VERIFIED` record, checkable by anyone with `@strixgov/verifier`,
> no Strix account required (this is what makes it *Sandbox Mode*: zero
> account in, one real signed proof out — but every step, including the
> signing itself, is a network call to `https://www.strixgov.com`). The
> helper ALSO still writes the older unsigned "recorded wire evidence" row
> (kernel decision + payload/result hashes under a client-generated
> `evidenceId`) as a secondary audit trail — unchanged, always present. If
> the receipt step itself fails (network hiccup, transient error), the
> skill degrades honestly: it prints the unsigned evidenceId and a clear
> note that the signed proof could not be confirmed, and it never prints a
> verify command with no signed record behind it (PROOF-1 — no first proof
> counts unless it's real).

> **Two zero-account modes — not the same claim.** "Zero Strix account" has
> shipped two different ways since this skill's Offline Mode addition, and
> they prove different things:
>
> | | **Sandbox Mode** (original) | **Offline Mode** (new) |
> |---|---|---|
> | Account needed | No | No |
> | Network calls | Yes — evaluate, evidence, and the signing itself all hit `www.strixgov.com` | **None, ever** |
> | Who signs | The hosted Strix kernel, with a Strix-controlled key | **You** — a local Ed25519 key generated and held entirely on this machine |
> | Terminal proof | `npx @strixgov/verifier@latest <decisionId>` (INSTALL-1) | `solo strix-wire verify <receipt-path>` (LOCAL-VERIFY-1) |
> | What it proves | The hosted Strix kernel evaluated and signed this decision | A local key signed a hash-chained, tamper-evident record — a `LOCAL_MACHINE_ASSERTION`, not Strix-operated custody |
>
> **Default is Sandbox Mode** (unchanged, backward compatible). Offer
> **Offline Mode** at Step 3 whenever the user asks for it explicitly, says
> they have no network access, or otherwise indicates they don't want any
> hosted dependency — see "Offline Mode" below for the full contract. Never
> blend the two: a receipt is either a Sandbox Mode hosted-signed record or
> an Offline Mode `LOCAL_SIGNED_V1` record, never presented as the other.

The skill is **interactive but conservative**: it stops at the proposal step
before wrapping production code, and it never runs the mutation without an
explicit confirmation. The only outputs that mutate the codebase are:

1. One helper file copied into the customer's source tree.
2. One call site rewritten to be wrapped with `governedAction(...)`.

Everything else is read-only scanning and printing.

---

## Step 0 — Preflight guard (fail-closed; STOP means stop)

**Run this before ANYTHING else, including the credential/language checks.**
strix-wire is a quickstart for codebases with NO governance. Two kinds of repo
make wiring it a mistake, and this guard refuses by construction rather than
relying on you to notice:

```bash
python3 "${CLAUDE_PROJECT_DIR:-.}/.claude/skills/strix-wire/preflight.py" --root . --json
```

- **Exit 0 / `verdict: OK`** — no governance or production markers. Proceed to
  Preconditions.
- **Exit 3 / `verdict: STOP`** — the repo is **already Strix-governed** (a
  `governedProcedure` / Canonical Proof Flow / signed-evidence layer already
  ships here, so the quickstart helper would be a lesser, redundant, unsigned
  path) **or shows production markers** (live Stripe key, `.env.production`, a
  real deploy domain — and Step 5 runs a REAL irreversible mutation).

On **STOP you must halt.** Do not scan, wrap, copy the helper, or run anything.
Show the user the `reason` and the `markers`, and explain plainly: strix-wire is
for ungoverned scratch/sandbox repos; this looks like the wrong target. Only
continue if the user gives **explicit, specific** sign-off (e.g. "yes, I
understand this repo is already governed / is production, wire it anyway") — a
bare "yes" to a generic prompt is not enough. If they cannot confirm, tell them
to run strix-wire in a throwaway repo (`solo init --demo` or a fresh folder)
instead. The guard fails **closed**: if `preflight.py` errors or cannot run,
treat it as STOP, not OK.

## Preconditions

Before doing anything, verify these. Stop and tell the user what's missing —
do not invent fallbacks.

1. `STRIX_API_KEY` and `STRIX_TENANT_ID` — **optional**. If the user has a
   real Strix account, use it (same behavior as before: real tenant, real
   risk gating). If either is absent, say nothing and do nothing special
   here — **local mode** auto-provisions a short-lived sandbox credential
   automatically the first time the helper runs (Step 5), so a stranger with
   zero Strix account can still complete this skill end-to-end. Do NOT
   prompt the user for credentials and do NOT block on this. (The sandbox
   credential only ever unlocks this skill's own closed set of
   irreversible-mutation capability ids — every other action still goes
   through real risk gating. See the strix-platform `policy.ts` sandbox
   override.) Do NOT write any API key into any file the agent will commit;
   only into `.env.local` or shell exports that the project's `.gitignore`
   already excludes.

2. The current working directory is a code repository (has a `package.json`,
   `pyproject.toml`, `go.mod`, `Cargo.toml`, or a `.git/` directory).

3. The repository is on a clean working tree, or the user explicitly says
   "go ahead anyway". Print `git status -s` first; if there are uncommitted
   changes, ask before writing files.

---

## Step 1 — Detect language

Look for project markers and pick **one** primary language. Order of preference:

| Marker | Language | Helper to copy |
|---|---|---|
| `package.json` with TypeScript files (`*.ts`, `*.tsx`) | TypeScript | `governedAction.ts` |
| `package.json` (JS only) | JavaScript | `governedAction.ts` (works as JS via `tsc --target esnext --module esnext`) |
| `pyproject.toml` or `requirements.txt` or `setup.py` | Python | `governed_action.py` |
| Multiple — pick the one with the most source files | — | — |

Print the detected language. If none match, stop and tell the user.

---

## Step 2 — Scan for an irreversible mutation

Run the scanner bundled with this skill:

```bash
python3 "${CLAUDE_PROJECT_DIR:-.}/.claude/skills/strix-wire/scanner.py" --json
```

(If running outside this repo, the customer's `.claude/skills/strix-wire/` is
the skill root — adjust the path.)

The scanner emits a JSON array of candidates ranked by confidence. Each item:

```json
{
  "file": "src/billing/charge.py",
  "line": 47,
  "snippet": "    return stripe.Charge.create(amount=amount, currency=\"usd\", source=token)",
  "category": "payments",
  "capability_id": "payment.charge",
  "confidence": "high"
}
```

**Skip everything in test paths** (the scanner already does this, but
double-check the candidate's path — `tests/`, `__tests__/`, `*.spec.*`,
`*.test.*` are never wrapped). Wrapping a test charge would create
misleading evidence records.

**PROOF-1 — only consequential candidates count.** The scanner's categories
are all irreversible mutations by design (payments, deletes, sends,
migrations). Never wrap a no-op, a log line, or a read to make the first
proof arrive faster — a first proof only counts if the wrapped action is
consequential. A dummy proof minted to make the clock look good is a
violation of the operating doctrine, not a win. (Contract pinned by
`tests/test_strix_wire_contract.py`.)

Take the top `confidence=high` candidate. If there are zero high-confidence
hits, fall back to the top `medium`. If there are zero candidates at all,
stop and report — tell the user what scanner patterns ran and ask them to
point you at a specific function to wrap.

---

## Step 3 — Propose the wrap

Before editing, show the user:

- The candidate file, line, and snippet.
- The `capability_id` that will be sent (e.g. `payment.charge`,
  `database.delete`, `s3.delete_object`).
- The diff that will be applied (just the call-site change — not the helper
  file yet).
- A reminder that this **runs the mutation once** at the end of the skill.

Ask the user to confirm via `AskUserQuestion`. Offer four options:
"Proceed and run it (Sandbox Mode — hosted)", "Proceed offline (no account,
no network, local signing)", "Wrap only — don't run", "Pick a different
candidate".

If they pick a different candidate, return to Step 2 and present the next
one. If they pick "Wrap only", skip Step 5. If they pick "Proceed offline",
follow the **Offline Mode** path in Step 4/5 below instead of the default
Sandbox Mode path — see "Offline Mode" for the full contract. Default to
Sandbox Mode unless the user asks for offline explicitly, says they have no
network access, or otherwise signals they don't want any hosted dependency.

---

## Step 4 — Wire the helper + wrap the call

### 4a. Copy the helper

Copy the reference implementation from the skill bundle into the customer's
source tree, **mirroring their existing layout**:

- Python: `src/<pkg>/strix_wire.py` if there's a `src/<pkg>/` layout,
  otherwise `<pkg>/strix_wire.py`, otherwise `strix_wire.py` at the repo
  root.
- TypeScript: `src/lib/governedAction.ts` if `src/lib/` exists, else
  `src/governedAction.ts`, else `lib/governedAction.ts`.
- The helper source is at:
  `${CLAUDE_PROJECT_DIR}/.claude/skills/strix-wire/helpers/governed_action.py`
  or `governedAction.ts`.

Use the `Read` tool to read the artifact, then `Write` to copy it. Do NOT
modify the helper — it is the canonical client and divergence breaks
cross-SDK byte determinism with the Strix verifier.

### 4b. Wrap the call

Edit the candidate file. Two changes only:

1. **Add the import** at the top of the file, alongside existing imports.
   Use a project-relative path inferred from where you placed the helper.

2. **Wrap the call expression**.

#### Python wrap pattern

Before:
```python
result = stripe.Charge.create(amount=amount, currency="usd", source=token)
```

After:
```python
from strix_wire import governed_action  # adjust path if helper landed elsewhere

action = governed_action(
    capability_id="payment.charge",
    payload={"amount": amount, "currency": "usd"},
    operation=lambda: stripe.Charge.create(
        amount=amount, currency="usd", source=token
    ),
)
result = action.result
print(f"[strix] recorded evidenceId={action.evidence_id}")
if action.verify_command:
    print(f"[strix] proof: {action.proof_url}")
    print(action.verify_command)  # FINAL line — see Step 5
else:
    print("[strix] mutation succeeded but the signed receipt could not be confirmed — see Failure modes")
```

Notes on the wrap:
- `payload` must contain only **non-secret** request parameters. Drop API
  keys, tokens, raw card numbers — keep amounts, IDs, target identifiers.
- `operation` is a zero-arg lambda that re-runs the original call exactly
  as it was. Preserve every argument.
- `governed_action(...)` now returns a `GovernedActionResult` (fields:
  `result`, `evidence_id`, `decision_id`, `signed_evidence_id`, `proof_url`,
  `verify_command`) — not a `(result, evidence_id)` tuple. `verify_command`
  is `None` when the receipt step didn't close the loop (see Step 5).
- The `print` block is temporary scaffolding for the demo — keep it for now;
  the user removes it later.

#### TypeScript wrap pattern

Before:
```typescript
const result = await stripe.charges.create({
  amount, currency: "usd", source: token,
});
```

After:
```typescript
import { governedAction } from "./governedAction"; // adjust path

const action = await governedAction(
  {
    capabilityId: "payment.charge",
    payload: { amount, currency: "usd" },
  },
  async () => await stripe.charges.create({
    amount, currency: "usd", source: token,
  }),
);
const result = action.result;
console.log(`[strix] recorded evidenceId=${action.evidenceId}`);
if (action.verifyCommand) {
  console.log(`[strix] proof: ${action.proofUrl}`);
  console.log(action.verifyCommand); // FINAL line — see Step 5
} else {
  console.log("[strix] mutation succeeded but the signed receipt could not be confirmed — see Failure modes");
}
```

If the original line was synchronous (no `await`), keep the body sync but
keep the outer `governedAction` async — and `await` it.

#### Capability ID mapping

Use the scanner's suggested `capability_id` verbatim. Reference set
(generated from `src/solo_builder/pattern_catalog.py` — the single-source
registry all four detection engines converge on):

| Category | capability_id | First-proof eligible |
|---|---|---|
| payments | `payment.charge`, `payment.refund` | yes |
| db-delete | `database.delete` | yes |
| db-update | `database.update` | yes |
| db-create | `database.create` (reserved — no pattern yet) | yes |
| s3-delete | `storage.delete` | yes |
| s3-write | `storage.write` | yes |
| email-send | `email.send` | yes |
| sms-send | `sms.send` | yes |
| file-delete | `filesystem.delete` | yes |
| schema-migration | `database.migrate` | yes |
| infra-apply / infra-destroy | `infra.apply`, `infra.destroy` | yes |
| iam-grant / iam-revoke | `iam.grant`, `iam.revoke` | yes |
| flag-flip | `flag.flip` | yes |
| data-export | `data.export` | yes |
| message-publish | `message.publish` | yes |
| ai-tool-use | `ai.tool_use` | yes |
| ai-agent | `ai.agent_run` | yes |
| ai-provider | `ai.completion` | **no — observe-only** |
| ai-embedding | `ai.embedding` | **no — observe-only** |
| ai-retrieval | `ai.retrieval` | **no — observe-only** |

These match the Strix kernel's `<artifact_type>.<action>` capability-ID
convention (ADR-003). Do not invent new ones during the wire-up — pick
the closest match; the user can refine via `solo kernel approve` later.

**PROOF-1 tiering (load-bearing):** the scanner surfaces observe-only AI
candidates so the map is honest, but NEVER pick one as the wrap target
for the first proof — a model call, embedding, or retrieval is
observability, not an irreversible side effect. On an AI-native
codebase the scanner ranks `ai.agent_run` / `ai.tool_use` candidates
first: the agent loop or LLM tool dispatch is the consequential wrap
that makes the demo land — prefer it over an incidental CRUD or
payment call when both appear.

---

## Step 5 — Run it once and surface the evidenceId

Only run if the user picked "Proceed and run it" in Step 3.

Execute the wrapped call. The exact command depends on the project:

- Python with a `__main__` or a test fixture: run the smallest entry point
  that hits the wrapped call. Prefer a script the user identifies, or
  `python -c "from <module> import <fn>; <fn>(...)"` with **test-safe
  arguments** (Stripe test card, `usd 100`, etc.).
- TypeScript: `npm run <script>` or `node --loader ts-node/esm <file>` for
  the smallest reproducer.

If running the mutation requires real-money flow or production secrets,
**stop and tell the user** — don't try to find creative ways around it.
The skill's promise is to wrap; the user runs it in their own staging.

When the wrapped call runs, the helper does four things in order: (1) if no
`STRIX_API_KEY`/`STRIX_TENANT_ID` were configured, it silently auto-provisions
a sandbox credential from `POST /api/public/sandbox/provision` — this is what
makes the whole run possible with zero account; (2) evaluates + captures the
kernel's `decisionId`; (3) runs the mutation and writes the unsigned
evidence/ingest audit row (unchanged); (4) posts a receipt
(`POST /api/v1/decisions/{decisionId}/receipt`) that Ed25519-signs the
decision and returns a real, verifiable `evidenceId` (== `decisionId`).

The wrapped call site prints:
```
[strix] recorded evidenceId=3f2b4a1c-9e0d-4abc-8def-123456789012
```

That first `evidenceId` is the UUID the helper generates client-side for the
unsigned audit row (the ingest endpoint returns batch counters, not
per-record ids — the helper confirms `ingested + skipped >= 1`).

**The happy path — a real signed record.** When the receipt step succeeds
(the expected, common case), the helper's `verify_command` /
`verifyCommand` field is populated. Echo the proof URL, then:

**INSTALL-1 — the last line is the independent check.** The skill's FINAL
output line MUST be the runnable independent-verification command, with
nothing after it:
```
npx @strixgov/verifier@latest dec_9f2b4a1c8e0d4abc
```
(the id here is the signed `decisionId`, not the unsigned ingest
`evidenceId` printed above — they are different values in local mode). The
run is not complete until the user has a command they can execute
themselves, against a tool that owes nothing to this skill or this repo.
This is a genuinely signed record — the receipt step Ed25519-signs the
decision at `POST /api/v1/decisions/{decisionId}/receipt`, so the verifier
returns `Status: VERIFIED`, not an unsigned/recorded status (Operating
Doctrine v1, INSTALL-1; contract pinned by `tests/test_strix_wire_contract.py`).

**The degraded path — be honest, don't fabricate.** If `verify_command` /
`verifyCommand` is `None`/`null` (the receipt POST failed — see Failure
modes), do NOT print a verify command at all. Print instead:
```
[strix] mutation succeeded; unsigned evidenceId=<evidenceId> recorded.
[strix] the signed receipt could not be confirmed — see Failure modes below.
```
PROOF-1 exists precisely to prevent a dummy or unbacked proof from being
handed to the user to make the run look complete when it isn't.

---

## Step 6 — End-of-turn summary

Tell the user, in four short items:

1. What was wrapped (file path + capability_id + helper path).
2. Whether the account was real or auto-provisioned (local mode) — if
   local-mode sandbox credentials were used, say so plainly (they're
   short-lived, scoped to this skill's capability set only, and not a
   substitute for a real account for anything beyond this demo).
3. **The map** — how many OTHER ungoverned action points the scan
   surfaced while finding this one, grouped by capability family
   (e.g. "…and 14 more ungoverned action points: 6 database, 3 ai,
   2 messaging, …"). One wrap is the proof; the count is the reason to
   keep going. Point at `solo govern coverage` (from
   `solo-builder-core`) for the per-family Governance Coverage Rate and
   a CI ratchet baseline — it is an unsigned measurement, never proof.
4. The verify command — `npx @strixgov/verifier@latest <decisionId>` —
   as the LAST line of output (INSTALL-1; see Step 5), OR, if the receipt
   step degraded, the honest fallback message instead (never both, never a
   fabricated command).

Suggest one follow-up: "Run `solo kernel approve <capability_id>` to
pre-authorize automated agents to run this in production." If local-mode
sandbox credentials were used, also suggest signing up for a real Strix
account so the tenant's own risk policy (not the sandbox override) governs
future runs. Do not push a PR or commit unless the user explicitly asks —
the wrap is staged for their review.

---

## Offline Mode — zero account AND zero hosted dependency

Chosen at Step 3 ("Proceed offline"). Everything else in this skill
(preflight, language detection, scanning, the proposal) is identical —
only the wrap target, the execution, and the terminal contract differ.
See `docs/architecture/local-mode-strix-wire-v1.md` (solo-builder-core)
for the full design note, receipt schema, key lifecycle, and threat model
this section summarizes.

### Offline 4a — copy the offline helper instead

- Python: copy
  `${CLAUDE_PROJECT_DIR}/.claude/skills/strix-wire/helpers/governed_action_local.py`
  to the same target location 4a already describes (`src/<pkg>/strix_wire_local.py`,
  etc.) — never the hosted `governed_action.py`.
- TypeScript: copy `governedAction.local.ts` the same way, as
  `src/lib/governedAction.local.ts` (or the project's equivalent).
- These two files are a genuine cross-language conformance pair — either
  one's output verifies against the other's schema (same canonical bytes,
  same field set, same Ed25519 primitives) — but neither imports
  `solo_builder`; they are self-contained by design, exactly like the
  hosted helpers.
- **Note the difference from Sandbox Mode's helper:** the offline helper
  needs real filesystem access for its local key + evidence store. It is
  Node-only on the TypeScript side (no browser/edge runtime support) and
  needs the `cryptography` package on the Python side
  (`pip install cryptography` if the project doesn't already depend on it
  — most do). If `cryptography` truly cannot be installed, STOP and tell
  the user Offline Mode cannot proceed on this project — never silently
  fall back to an unsigned record (PROOF-1 applies here too).

### Offline 4b — wrap the call

Same two changes as 4b (import + wrap the call expression), but call
`governed_action_local(...)` / `governedActionLocal(...)` instead, and
pass `approval_granted=True` / `approvalGranted: true` **only** because
the user already confirmed "Proceed offline" at Step 3 for this specific
run — that confirmation IS the authorization Offline Mode's policy gate
requires for every capability this skill wraps (they are all HIGH/CRITICAL
risk by PROOF-1 construction). Never hardcode `approval_granted=True` into
code that will run unattended later — that would silently disable the
approval gate for every future run. Tell the user this plainly at Step 6.

#### Python offline wrap pattern

```python
from strix_wire_local import governed_action_local  # adjust path if helper landed elsewhere

action = governed_action_local(
    "payment.refund",
    "refund_payment",
    {"amount": amount, "currency": "usd"},
    lambda: stripe.Refund.create(amount=amount, currency="usd", payment_intent=intent_id),
    approval_granted=True,  # the user already confirmed this exact run at Step 3
)
result = action.result
print(f"[strix] Action allowed")
print(f"[strix] evidenceId={action.evidence_id}")
print(f"[strix] receipt={action.receipt_path}")
print(f"[strix] verify=solo strix-wire verify {action.receipt_path}")  # FINAL line — see below
```

#### TypeScript offline wrap pattern

```typescript
import { governedActionLocal } from "./governedAction.local"; // adjust path

const action = governedActionLocal(
  "payment.refund",
  "refund_payment",
  { amount, currency: "usd" },
  () => stripe.refunds.create({ amount, currency: "usd", payment_intent: intentId }),
  { approvalGranted: true }, // the user already confirmed this exact run at Step 3
);
const result = action.result;
console.log("[strix] Action allowed");
console.log(`[strix] evidenceId=${action.evidenceId}`);
console.log(`[strix] receipt=${action.receiptPath}`);
console.log(`[strix] verify=solo strix-wire verify ${action.receiptPath}`); // FINAL line — see below
```

### Offline Step 5 — run it once (no network anywhere)

Execute the wrapped call exactly as Step 5 describes for Sandbox Mode
(smallest reproducer, test-safe arguments, never a real production
secret). The offline helper's six-step loop — normalize, evaluate,
decide, authorize, execute, record — happens entirely on this machine: a
local Ed25519 key is generated on first run (`.strix/keys/`, 0600, never
printed) and every subsequent run reuses it; the receipt is appended to a
hash-chained local file (`.strix/evidence/receipts.jsonl`) and also
exported as a single JSON file (`.strix/evidence/<evidenceId>.json`) —
this is the path the FINAL output line points at.

Before wiring this into the customer's `.gitignore`, add `.strix/keys/`
(never commit private key material). The evidence directory
(`.strix/evidence/`) and `.strix/keys/registry.json` (public keys only)
are safe to commit if the user wants a portable, shareable audit trail —
mention this as an option, don't decide it for them.

**LOCAL-VERIFY-1 — the last line is the independent, offline check.** The
run's FINAL output line MUST be the runnable local verify command, with
nothing after it:
```
solo strix-wire verify .strix/evidence/local_ev_9f2b4a1c8e0d4abc.json
```
(if `solo` is not installed in the user's environment, say so and offer
`pip install solo-builder-core` first — the command needs no network and
no Strix credential either way, only this file and the local key
registry). This is the Offline Mode sibling of INSTALL-1 — reaching a
runnable independent check is still what "installation complete" means;
it is simply a different command because there is no hosted record to
look up. **Never** print the hosted `npx @strixgov/verifier@latest`
command after an Offline Mode run — that command looks up a decision on
`www.strixgov.com`, which never received this run at all.

**Be explicit about what this proves.** When summarizing an Offline Mode
result at Step 6, state plainly: this is a `LOCAL_MACHINE_ASSERTION` — a
local key signed a hash-chained, tamper-evident record of one authorized,
executed action. It does **not** prove Strix-operated custody,
centralized policy administration, multi-party approval, or protection
against a machine owner who controls both the runtime and the key. It IS
a real, independently reproducible, cryptographically verifiable receipt
— just not a claim about Strix infrastructure. Never describe an Offline
Mode receipt as "Strix-verified" or "hosted" — say "locally signed and
independently verifiable."

**Offline Step 6 additions** (alongside the four Step 6 items): note that
no Strix account, sandbox or real, was involved at all; and that upgrading
to Sandbox Mode or a real account later is a separate, explicit choice —
Offline Mode receipts are not automatically synced or upgraded (see
`docs/architecture/local-mode-strix-wire-v1.md` "Hosted-upgrade path").

### Offline Mode — reliance gate (require prior proof before this action)

The offline helpers support **Local Reliance Gate v1** (see
`docs/architecture/local-reliance-gate-v1.md` in solo-builder-core): the
wrapped action can REQUIRE one or more prior `LOCAL_SIGNED_V1` receipts —
independently re-verified at run time (hash, chain link, signature, key)
and checked against content bindings (capability, decision, execution
status, workspace, age) — strictly BEFORE the operation runs. A failed
requirement raises `StrixLocalRelianceDenied` and the operation never
executes; a passing gate binds the verified reliance projection into the
action's own signed receipt (`local-receipt-v2`).

Offer this **only** when the user's target action has an obvious
prerequisite already governed in this repo (a migration after a governed
backup, a deploy after a governed test run, a publish after a governed
approval). Never invent a prerequisite; ask the user which existing receipt
should gate the action, and use its `.strix/evidence/<evidenceId>.json`
path. Wrap pattern additions:

```python
from strix_wire_local import governed_action_local, RelianceRequirement

action = governed_action_local(
    "database.migrate",
    "run_production_migration",
    {"revision": revision},
    lambda: run_migration(revision),
    approval_granted=True,  # the user already confirmed this exact run
    reliance=[
        RelianceRequirement(
            "database.backup",                       # required prior capability
            ".strix/evidence/<backupEvidenceId>.json",  # its receipt
            max_age_seconds=1800,                    # e.g. backup < 30m old
        )
    ],
)
```

```typescript
const action = governedActionLocal(
  "database.migrate",
  "run_production_migration",
  { revision },
  () => runMigration(revision),
  {
    approvalGranted: true, // the user already confirmed this exact run
    reliance: [
      { capabilityId: "database.backup",
        receiptPath: ".strix/evidence/<backupEvidenceId>.json",
        maxAgeSeconds: 1800 },
    ],
  },
);
```

If the gate denies, surface the requirement's `reason` (it names the exact
failing check, e.g. `REQUIRED_PROOF_EXPIRED: receipt age 2642s exceeds
required maximum age 1800s`) and STOP — never retry by loosening the
requirement or deleting the reliance block without the user explicitly
deciding that. The standalone check is also runnable without wiring
anything: `solo reliance require --policy <file> --receipt <path>` (exit 0
only on PROCEED). Honesty note for Step 6: the reliance gate proves the
prior receipt was present, re-verified, and policy-satisfying on THIS
machine — it does not add third-party approval or protect against the
machine owner (same `LOCAL_MACHINE_ASSERTION` scope as everything else in
Offline Mode).

### Offline Mode — attestation-gated execution (require verified agent identity)

The SAME reliance gate can also require a signed **local agent
attestation** instead of (or alongside) a prior receipt — see
`docs/architecture/attestation-gated-execution-v1.md` in solo-builder-core.
A `RelianceRequirement`/`LocalRelianceRequirement` with
`receiptType: LOCAL_AGENT_ATTESTATION_V1` binds the requesting agent's
identity, class, permitted issuer, capability scope, and freshness — all
independently re-verified at gate time, never a stored verdict. Offer this
**only** when the user's target action is agent-driven and they want to
require a specific, previously-issued local identity vouch before it can
run (never invent an issuer or an agent id).

Mint the issuer key and an attestation once (outside the wrapped action,
typically during setup): `solo strix-wire attest issuer-keygen` then
`solo strix-wire attest issue --agent-id <id> --agent-class CLASS_VERIFIED
--issuer-id local-workspace-registry --scope <capability.or.prefix.*> --out
<path>`. Wrap pattern addition (Python; TypeScript mirrors with the same
field names, camelCased):

```python
reliance=[
    RelianceRequirement(
        "", "<path to the issued attestation .json>",
        requirement_id="acting-agent",
        receipt_type="LOCAL_AGENT_ATTESTATION_V1",
        agent_id_from_request=True,       # or expected_agent_id="<fixed id>"
        required_class="CLASS_VERIFIED",
        permitted_issuers=("local-workspace-registry",),
        capability_scope_must_include_subject=True,
        max_age_seconds=86400,
    )
],
requesting_agent_id="<the live requesting agent's id>",
```

A denied requirement names the exact failing check
(`ATTESTATION_SCOPE_MISMATCH`, `ATTESTATION_EXPIRED`,
`ATTESTATION_ISSUER_NOT_ALLOWED`, …) — STOP on denial, same discipline as
the receipt-based reliance gate. Standalone check:
`solo reliance require --policy <file> --requesting-agent <id>` (exit 0
only on PROCEED). One-command walkthrough of all nine scenarios:
`solo strix-wire demo --attestation-gated`. Honesty note: a valid
attestation proves a local issuer vouched for this agent's identity/class/
scope — it does NOT prove the action is safe or approved, and it carries
the same `LOCAL_MACHINE_ASSERTION` scope as everything else in Offline
Mode (no enterprise identity assurance, no organizational approval, no
hosted Strix provenance — see the architecture doc's threat model).

---

## Failure modes — handle these silently

- **No `STRIX_API_KEY`/`STRIX_TENANT_ID`**: no longer a stop condition —
  Sandbox Mode auto-provisions sandbox credentials (Step 5); Offline Mode
  never needed them in the first place. Only stop if the auto-provisioning
  call ITSELF fails (Sandbox Mode only — see the 5xx/network row below —
  same handling, just at the provisioning step instead of evaluate).
- **(Offline Mode) local policy denies the capability**: stop before
  wrapping runs — tell the user which capability was denied and why. This
  should be rare (the default policy only denies an explicit deny-list
  entry), but never silently pick a different capability instead.
- **(Offline Mode) approval not granted for a HIGH/CRITICAL capability**:
  this means Step 3's confirmation was somehow skipped — treat it as a
  bug in the skill's own flow, not a user-facing failure mode; every
  capability that reaches Offline Mode's wrap step already got the user's
  explicit "Proceed offline" confirmation.
- **(Offline Mode) `cryptography` package missing, or the local key file
  is missing/corrupt/mismatched**: stop, surface the exact error (the
  helper's `StrixLocalKeyError` message is written to be shown verbatim),
  and do NOT fall back to an unsigned record. Suggest `pip install
  cryptography` or, for a corrupted key, deleting `currentKid` from
  `.strix/keys/registry.json` to mint a fresh signing key (historical
  receipts under the old kid remain verifiable either way).
- **(Offline Mode) the mutation succeeded but the receipt failed to
  persist** (disk full, permission error): surface
  `StrixLocalReceiptPersistenceError`'s message verbatim — it states
  plainly that the mutation is NOT undone and points at the evidence
  directory. Never retry the mutation itself to "make up for" a missing
  receipt (that risks a duplicate irreversible side effect).
- **No candidates found**: stop, list patterns the scanner tried, ask for
  a manual pointer.
- **Wrap target is in a test path**: refuse, pick the next candidate.
- **Helper file already exists at the target location with different
  contents**: ask before overwriting. Show a diff.
- **Strix API returns 401/403** (real credentials only — never happens with
  auto-provisioned ones): tell the user their key/tenant pair is wrong;
  don't retry with stub data — the skill's whole value is the authentic
  evidence record.
- **Strix API returns 5xx or network error** (provisioning, evaluate,
  evidence, or receipt): surface the error and offer to retry once with
  backoff. After two retries, stop — except the **receipt** step
  specifically, which the helper already retries never (best-effort,
  single attempt) so as not to delay a mutation that already succeeded;
  if it fails, follow the degraded-path guidance in Step 5 instead of
  treating it as a stop condition.

## Out of scope for this skill

- Multi-call wrapping. The skill wraps **one** call. Use it again for the
  next one.
- Async-context propagation. The helper takes a callable; it does not
  thread custom context (request IDs, tracers). Customer wires that in
  separately.
- Policy authoring. The skill assumes the capability_id maps to a policy
  the Strix kernel already evaluates. If the customer is on a new
  capability, they'll get an `escalate` decision and the skill will
  surface that — they then run `solo kernel approve` to issue a token.

---

## Why this works

The Strix evidence stack (see `CLAUDE.md` → "Strix evidence stack") makes
the signed decision the thing that proves a governed action happened.
Every other step (scanner, wrap, copy-helper, sandbox auto-provisioning) is
mechanical setup; the moments of truth are three real network calls the
helper makes against the live, hosted kernel:

1. `POST /api/v1/evaluate` — the mutation does not run unless the kernel
   allows it. Local mode reaches this endpoint using a sandbox credential
   auto-provisioned from `POST /api/public/sandbox/provision` when no real
   account is configured; a real account reaches the exact same endpoint
   with the exact same code path.
2. `POST /api/v1/evidence/ingest` — persists the decision plus the
   payload/result hashes under a client-generated evidenceId (the
   unsigned audit-trail row, unchanged since before local mode).
3. `POST /api/v1/decisions/{decisionId}/receipt` — Ed25519-signs the
   decision itself and returns a `Status: VERIFIED`-capable record,
   checkable against the canonical JWKS at
   `https://www.strixgov.com/.well-known/strix-jwks.json` by anyone,
   using nothing but `npx @strixgov/verifier@latest <decisionId>`. This is
   the step that turns "a stranger ran a skill" into "a stranger holds an
   independently verifiable proof" — the whole point of local mode.

The 2-minute promise depends on the scanner finding a clean candidate on
the first try. When it doesn't, falling back to "show me your candidate"
is still 5 minutes — well under the manual baseline.
