---
name: strix-wire
description: Wire Strix governance into the current codebase. Scans for an irreversible mutation (payment charges, deletes, sends, schema migrations), wraps the call site with governedAction(), runs it once, and prints the resulting evidenceId. Use when the user asks to "wire Strix", "wire up Strix", "add Strix to this project", "set up governed actions", "get a VERIFIED record", or runs /strix-wire.
---

# /strix-wire — five steps to a VERIFIED record

This skill takes a customer codebase from zero to a signed, externally verifiable
Strix evidence record in **about two minutes** — replacing the 15-minute manual
quickstart Path A.

The skill is **interactive but conservative**: it stops at the proposal step
before wrapping production code, and it never runs the mutation without an
explicit confirmation. The only outputs that mutate the codebase are:

1. One helper file copied into the customer's source tree.
2. One call site rewritten to be wrapped with `governedAction(...)`.

Everything else is read-only scanning and printing.

---

## Preconditions

Before doing anything, verify all of these. Stop and tell the user what's
missing — do not invent fallbacks.

1. `STRIX_API_KEY` and `STRIX_TENANT_ID` are present in the environment.
   - If either is missing, prompt the user with `AskUserQuestion` to supply
     them, then export both in the current shell before continuing. Do NOT
     write the API key into any file the agent will commit; only into
     `.env.local` or shell exports that the project's `.gitignore` already
     excludes.

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

result, evidence_id = governed_action(
    capability_id="payment.charge",
    payload={"amount": amount, "currency": "usd"},
    operation=lambda: stripe.Charge.create(
        amount=amount, currency="usd", source=token
    ),
)
print(f"[strix] VERIFIED evidenceId={evidence_id}")
```

Notes on the wrap:
- `payload` must contain only **non-secret** request parameters. Drop API
  keys, tokens, raw card numbers — keep amounts, IDs, target identifiers.
- `operation` is a zero-arg lambda that re-runs the original call exactly
  as it was. Preserve every argument.
- The `print` is temporary scaffolding for the demo — keep it for now;
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

const { result, evidenceId } = await governedAction(
  {
    capabilityId: "payment.charge",
    payload: { amount, currency: "usd" },
  },
  async () => await stripe.charges.create({
    amount, currency: "usd", source: token,
  }),
);
console.log(`[strix] VERIFIED evidenceId=${evidenceId}`);
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

When the wrapped call runs, the helper prints:
```
[strix] VERIFIED evidenceId=evt_01XJHnTcF6C7rLxPGH93GpHD
```

Echo that line back as the skill's final output, plus the verification URL
(canonical host `www.strixgov.com`; the evidenceId is whatever the helper
returned — the value below is illustrative):
```
https://www.strixgov.com/proof/<evidenceId>
```

---

## Step 6 — End-of-turn summary

Tell the user, in two sentences:

1. What was wrapped (file path + capability_id + helper path).
2. The evidenceId and the proof URL.

Suggest one follow-up: "Run `solo kernel approve <capability_id>` to
pre-authorize automated agents to run this in production." Do not push a
PR or commit unless the user explicitly asks — the wrap is staged for
their review.

---

## Failure modes — handle these silently

- **No `STRIX_API_KEY`**: prompt user, don't proceed.
- **No candidates found**: stop, list patterns the scanner tried, ask for
  a manual pointer.
- **Wrap target is in a test path**: refuse, pick the next candidate.
- **Helper file already exists at the target location with different
  contents**: ask before overwriting. Show a diff.
- **Strix API returns 401/403**: tell the user their key/tenant pair is
  wrong; don't retry with stub data — the skill's whole value is the
  authentic VERIFIED record.
- **Strix API returns 5xx or network error**: surface the error and offer
  to retry once with backoff. After two retries, stop.

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
the VERIFIED record the **only** thing that proves a governed action
happened. Every other step (scanner, wrap, copy-helper) is mechanical
setup; the moment of truth is the helper's POST to the Strix kernel and
the evidenceId in the response. That evidenceId is publicly verifiable
against the canonical JWKS at
`https://www.strixgov.com/.well-known/strix-jwks.json` — no trust in the
agent, the customer's app, or solo-builder-core required.

The 2-minute promise depends on the scanner finding a clean candidate on
the first try. When it doesn't, falling back to "show me your candidate"
is still 5 minutes — well under the manual baseline.
