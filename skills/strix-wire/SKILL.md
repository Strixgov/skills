---
name: strix-wire
description: Wire Strix governance into the current codebase. Scans for an irreversible mutation (payment charges, deletes, sends, schema migrations), wraps the call site with governedAction(), runs it once, and prints the resulting evidenceId. Use when the user asks to "wire Strix", "wire up Strix", "add Strix to this project", "set up governed actions", "get an evidence record", or runs /strix-wire.
---

# /strix-wire — five steps to a recorded governed action

This skill takes a customer codebase from zero to a kernel-evaluated mutation
with a queryable Strix evidence record in **about two minutes** — replacing the
15-minute manual quickstart Path A.

> **Claim discipline (local mode):** the helper's final step posts a receipt
> (`POST /api/v1/decisions/{decisionId}/receipt`) that Ed25519-signs the
> decision itself — so the happy path produces a genuinely verifiable,
> `Status: VERIFIED` record, checkable by anyone with `@strixgov/verifier`,
> no Strix account required (this is what makes it *local mode*: zero
> account in, one real signed proof out). The helper ALSO still writes the
> older unsigned "recorded wire evidence" row (kernel decision + payload/
> result hashes under a client-generated `evidenceId`) as a secondary audit
> trail — unchanged, always present. If the receipt step itself fails
> (network hiccup, transient error), the skill degrades honestly: it prints
> the unsigned evidenceId and a clear note that the signed proof could not
> be confirmed, and it never prints a verify command with no signed record
> behind it (PROOF-1 — no first proof counts unless it's real).

The skill is **interactive but conservative**: it stops at the proposal step
before wrapping production code, and it never runs the mutation without an
explicit confirmation. The only outputs that mutate the codebase are:

1. One helper file copied into the customer's source tree.
2. One call site rewritten to be wrapped with `governedAction(...)`.

Everything else is read-only scanning and printing.

---

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

Ask the user to confirm via `AskUserQuestion`. Offer three options:
"Proceed and run it", "Wrap only — don't run", "Pick a different candidate".

If they pick a different candidate, return to Step 2 and present the next
one. If they pick "Wrap only", skip Step 5.

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

Use the scanner's suggested `capability_id` verbatim. Reference set:

| Category | capability_id |
|---|---|
| payments | `payment.charge` |
| db-delete | `database.delete` |
| db-update | `database.update` |
| db-create | `database.create` |
| s3-delete | `storage.delete` |
| s3-write | `storage.write` |
| email-send | `email.send` |
| sms-send | `sms.send` |
| file-delete | `filesystem.delete` |
| schema-migration | `database.migrate` |

These match the Strix kernel's `<artifact_type>.<action>` capability-ID
convention (ADR-003). Do not invent new ones during the wire-up — pick
the closest match; the user can refine via `solo kernel approve` later.

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

Tell the user, in three short items:

1. What was wrapped (file path + capability_id + helper path).
2. Whether the account was real or auto-provisioned (local mode) — if
   local-mode sandbox credentials were used, say so plainly (they're
   short-lived, scoped to this skill's capability set only, and not a
   substitute for a real account for anything beyond this demo).
3. The verify command — `npx @strixgov/verifier@latest <decisionId>` —
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

## Failure modes — handle these silently

- **No `STRIX_API_KEY`/`STRIX_TENANT_ID`**: no longer a stop condition —
  local mode auto-provisions sandbox credentials (Step 5). Only stop if
  the auto-provisioning call ITSELF fails (see the 5xx/network row below —
  same handling, just at the provisioning step instead of evaluate).
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
