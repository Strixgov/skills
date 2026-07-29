---
name: strix-wire
description: Wire Strix governance into the current codebase with one scoped read-only analysis authorization and separate explicit approvals for the source change and the sandbox execution. Scans for an irreversible mutation (payment charges, deletes, sends, schema migrations), wraps the call site with governedAction(), optionally runs it once, and prints the resulting evidenceId. Use when the user asks to "wire Strix", "wire up Strix", "add Strix to this project", "set up governed actions", "get an evidence record", or runs /strix-wire.
---

# /strix-wire — one analysis authorization, then only trust decisions

This skill takes a customer codebase from zero to a kernel-evaluated mutation
with a queryable Strix evidence record in **about two minutes** — and it asks
for exactly as many approvals as there are decisions that matter:

```text
CLICK 1
Authorize scoped repository analysis        (mechanical consent — read-only)

      ↓

Analysis overview and recommended target    (no approval needed)

      ↓

CLICK 2
Approve the exact source-code wrap          (governance decision)

      ↓

Wrapper applied and validated

      ↓

CLICK 3
Approve the sandbox action execution        (governance decision)
```

**Approval budget — hold this line:** analysis only = **1** approval; analysis
plus wrap = **2**; analysis, wrap, and sandbox proof = **3**. A fourth prompt
is permitted **only** when environment setup is genuinely required (e.g.
installing Node before a TypeScript run-proof) — never for analysis mechanics.
If you find yourself about to raise a fourth prompt for anything else, you are
violating this skill's consent architecture; stop and re-read WIRE-CONSENT-1
below.

---

## WIRE-CONSENT-1 — the consent architecture

> **The critical rule: collapse mechanical permissions, not governance
> decisions.**

Two different kinds of consent exist in this flow, and they must never be
presented as though they are equally important:

| Consent class | What it covers | How it is asked |
|---|---|---|
| **Analysis consent** (mechanical) | Every read-only step: folder inspection, preflight, runtime detection, repository check, scanning, candidate analysis, temporary-path exclusion, helper reading, helper-integrity comparison | ONE authorization, ONE command (`analyze.py`), disclosed by ONE card |
| **Action authorization** (governance) | Anything that can modify code or cause an action: applying the wrap; executing the governed call | A separate, explicit, per-decision approval — never merged, never inferred |

Invariants — every one of these is pinned by
[`tests/`](./tests/) in this skill bundle:

1. Repository access is limited to the disclosed analysis root.
2. Analysis authorization does not authorize source modification.
3. Source-modification approval does not authorize execution.
4. Execution approval is capability- and target-specific — it covers ONE run
   of ONE call site; a different target, capability, or input set requires a
   fresh approval.
5. Skipped execution is a valid terminal state, not a failure.
6. No signed evidence is claimed before an evaluated run occurs (PROOF-1).
7. Broad "allow analysis" permission can never become a reusable bypass for
   later commands: analysis consent expires at the end of the run, and the
   analyzer is incapable of writing, installing, executing, or reaching the
   network by construction.

> **Claim discipline (Sandbox Mode):** the helper's final step posts a receipt
> (`POST /api/v1/decisions/{decisionId}/receipt`) that Ed25519-signs the
> decision itself — so the happy path produces a genuinely verifiable,
> `Status: VERIFIED` record, checkable by anyone with `@strixgov/verifier`,
> no Strix account required. The helper also still writes the older unsigned
> "recorded wire evidence" row as a secondary audit trail. If the receipt step
> fails, the skill degrades honestly: it prints the unsigned evidenceId and a
> clear note that the signed proof could not be confirmed, and it never prints
> a verify command with no signed record behind it (PROOF-1).

> **Two zero-account modes — not the same claim.**
>
> | | **Sandbox Mode** (default) | **Offline Mode** |
> |---|---|---|
> | Account needed | No | No |
> | Network calls | Yes — evaluate, evidence, and the signing itself all hit `www.strixgov.com` | **None, ever** |
> | Who signs | The hosted Strix kernel, with a Strix-controlled key | **You** — a local Ed25519 key generated and held entirely on this machine |
> | Terminal proof | `npx @strixgov/verifier@latest <decisionId>` (INSTALL-1) | `solo strix-wire verify <receipt-path>` (LOCAL-VERIFY-1) |
> | What it proves | The hosted Strix kernel evaluated and signed this decision | A local key signed a hash-chained, tamper-evident record — a `LOCAL_MACHINE_ASSERTION`, not Strix-operated custody |
>
> Offer Offline Mode at the wrap approval whenever the user asks for it, says
> they have no network access, or doesn't want any hosted dependency. Never
> blend the two claims. **Note:** network calls happen only at the
> (separately approved) execution phase — analysis contacts nothing in either
> mode.

---

## Phase 1 — Approval 1 of 3: scoped repository analysis

### 1a. Present the ANALYSIS REQUEST card

Resolve the analysis root (normally the current working directory). Show this
card — root filled in, nothing omitted — as plain output, immediately before
running the analysis command. The card is the disclosure; the harness's
permission prompt for the single command below is the user's one approval
click. Do **not** additionally wrap analysis consent in an `AskUserQuestion` —
that would spend a second click on the same mechanical consent.

```text
STRIX WIRE — ANALYSIS REQUEST

Strix Wire needs permission to inspect this repository and run its
local, read-only analysis tools.

It will:

✓ Read source files in this repository
✓ Detect installed language runtimes
✓ Run the Strix preflight
✓ Run the repository scanner
✓ Analyze consequential-action candidates
✓ Compare bundled helper files for integrity

It will not:

✕ Modify source files
✕ Install packages
✕ Access files outside this repository
✕ Use credentials
✕ Contact external services
✕ Execute a consequential action

Scope:
<the resolved analysis root>

Approving the next command grants exactly this, for exactly one run.
```

### 1b. Run exactly ONE command

```bash
python3 "${CLAUDE_PROJECT_DIR:-.}/.claude/skills/strix-wire/analyze.py" --root . --json
```

(On Windows, `python` instead of `python3`. If running from the installed
plugin, the skill root is the plugin's `skills/strix-wire/` directory —
adjust the path, keep the shape: one interpreter, one script, one `--root`.)

The executed scope is bound to the disclosed scope: onboarding always uses
`--root .` (the project the user opened), and the analyzer's CLI refuses a
root outside the current working directory unless `--allow-external-root`
is passed — which onboarding never does. If the user wants a different
repository analyzed, that is a scope change: present a fresh ANALYSIS
REQUEST card showing the new root, and run the command from that directory.

The preflight portion fails closed in every direction: markers found →
STOP; scan error → STOP; scan truncated on a very large repo, or any
subtree unreadable → STOP ("we didn't finish looking" is never reported as
"clean"). A truncation STOP usually means the repo is too big for a
quickstart — suggest a smaller sandbox repo or a user-pointed function.

`analyze.py` performs, in a single read-only process, everything the old flow
spread across eight to ten separate prompts: scope guard → preflight →
runtime detection → repository check → consequential-action scan → candidate
analysis with automatic temporary-path exclusion → helper-integrity
comparison. Its exit codes: `0` complete (`verdict: OK` or `NO_CANDIDATES`),
`3` preflight STOP (fail closed), `4` remediation required, `2` bad
invocation.

**ORCHESTRATION RULE (load-bearing).** During onboarding, never run
`preflight.py`, `scanner.py`, interpreter probes (`which python3`), folder
listings (`ls`, `find`, `dir`), `git status`, helper-file reads, or integrity
diffs as separate commands — every one of those phases already runs inside
`analyze.py`'s single process. Each extra command raises an extra permission
prompt; that is a consent-architecture violation, not thoroughness. If
`analyze.py` itself errors, **fail closed**: report it and stop — do NOT
"helpfully" fall back to running the phases as individual commands, which
would both resurrect the eleven-prompt experience and bypass the disclosed
consent card. (`preflight.py` and `scanner.py` remain runnable standalone for
debugging outside this onboarding flow.)

**Missing Python / toolchain — one remediation, never a prompt loop.** If the
interpreter is missing, produce ONE message: what is missing, the one command
or link that fixes it (e.g. install Python 3.9+ from python.org or the OS
package manager), and the offer to point strix-wire at a specific function
manually instead. Then stop. Never probe alternative interpreters across
multiple prompts. A missing Node.js on a TypeScript project does NOT block
analysis — `analyze.py` reports it as a single `remediation` entry, and it
matters only if the user later approves the run-proof (that install is the
one legitimate "fourth click").

**Consent scope rules:**

- The authorization covers exactly one run of `analyze.py` over exactly the
  disclosed root. It **expires at the end of the run**.
- A new analysis run — or ANY change to the analysis root — requires a fresh
  ANALYSIS REQUEST card and a fresh approval. Never treat an earlier analysis
  approval as standing permission.
- Analysis consent never authorizes the wrap or the run. Those are Approvals
  2 and 3, and they are always asked separately.

### 1c. Preflight STOP means stop

Exit code 3 / `verdict: STOP` means the repo is **already Strix-governed** (a
`governedProcedure` / Canonical Proof Flow / signed-evidence layer already
ships here) **or shows production markers** (live Stripe key,
`.env.production`, a real deploy domain — and the optional final step runs a
REAL irreversible mutation). On STOP you must halt: no wrapping, no helper
copy, nothing. Show the user the `reason` and `markers` and explain plainly
that strix-wire is for ungoverned scratch/sandbox repos. Only continue on
**explicit, specific** sign-off (e.g. "yes, I understand this repo is
production, wire it anyway") — a bare "yes" to a generic prompt is not
enough. The guard fails **closed**: if the preflight portion errors, treat it
as STOP, not OK.

### Credentials (still zero-prompt)

`STRIX_API_KEY` / `STRIX_TENANT_ID` are **optional**. With a real account,
real tenant risk gating applies. Without one, Sandbox Mode auto-provisions a
short-lived sandbox credential the first time the helper runs — at the
(separately approved) execution phase, never during analysis. Do NOT prompt
the user for credentials, do NOT block on them, and do NOT write any key into
a committable file — only `.env.local` or shell exports already covered by
`.gitignore`.

---

## Phase 2 — Findings review (no approval needed)

Render the analysis for the user — this is an overview, not a permission
gate. From the JSON report, show:

1. **The visual block** (ASCII, adapt values; `analyze.py`'s non-JSON output
   is the reference rendering):

```text
  SCOPE       <root>
  PREFLIGHT   OK
  SCANNED     <N> files for hard-to-undo actions (payments, deletes, sends, migrations)
  FOUND       <M> candidates (<K> excluded from temporary paths automatically)
  RECOMMENDED <file>:<line>  (<capability_id>)
  HELPER      <no helper yet | path — identical to bundle | path — DIVERGES from bundle>
```

2. **One plain-language sentence** before any jargon or diff — e.g. "I found
   one action that can't be undone once it runs: a Stripe charge on line 47.
   I'll add a permission check in front of it and a signed proof behind it —
   the charge itself won't change." Never lead with `capability_id`.

3. **The map** — how many other ungoverned action points exist, grouped by
   capability family (from `scan.map`). One wrap is the proof; the count is
   the reason to keep going.

4. **Helper integrity** — if a governed-action helper already exists in the
   repo and diverges from the bundled canonical copy, say so now; the wrap
   proposal must then include restoring the canonical helper (divergence
   breaks cross-SDK byte determinism with the Strix verifier).

Candidate selection: take the recommended candidate (top
`first_proof_eligible` hit — the analyzer already ranks consequential AI
surfaces first, then irreversible mutations, and never recommends
observe-only AI surfaces; PROOF-1). If there are zero candidates, stop and
report — list what the scanner looked for and ask the user to point at a
specific function. Never wrap a no-op, a log line, or a read to make the
first proof arrive faster — a dummy proof minted to make the clock look good
is a violation of the operating doctrine, not a win.

---

## Phase 3 — Approval 2 of 3: the source-code wrap

### 3a. Present the PROPOSED CHANGE card

```text
PROPOSED CHANGE

Target:
<file>:<line>

Action:
Wrap <function/call> with a Strix governance boundary (<capability_id> —
<short parenthetical of what it means in practice>)

Files that will change:
<1 if the helper already exists and is identical; otherwise 2 —
 the call-site file, plus one helper file copied into the source tree>

Actions that will execute:
0

[Review patch]  [Apply wrapper]  [Skip]
```

Alongside the card, show:

- The candidate file, line, and snippet, and the exact diff that will be
  applied (call-site change; name the helper file that will be added). This
  is the **change preview** — the approval covers exactly what is shown
  here, nothing more.
- A **"Will / Will not" block** so the approval object is unambiguous:

  ```text
  If approved, this wrap WILL:
  - add a governance check in front of this ONE call site;
  - copy one helper file into the source tree;
  - (only after a second, separate confirmation) run the action once
    with test-safe inputs and record the result.
  It will NOT:
  - modify any other candidate the scan found;
  - touch production data, secrets, or live third-party accounts;
  - claim the repository is governed beyond this one action.
  ```

- A reminder that a denial means the original action **never runs at all** —
  it isn't run-then-flagged, it's checked-then-run.

**One confirmation is never enough to both wrap and run.** Approving here
authorizes the wrap (helper copy + call-site edit) only; execution gets its
own explicit confirmation at Phase 4. Never collapse approve → wrap → run
into a single yes.

**Harness prompts are echoes, not extra approvals.** Depending on the
user's permission mode, the harness may additionally confirm the file
edits (and later, the run command) it executes — those are mechanical
confirmations of the decision already taken on this card, showing the very
diff the user just reviewed. Never re-ask the governance question because
a harness prompt also appeared, and never skip the governance question
because a harness prompt will appear. Keep every edit inside the approved
diff so the harness confirmation matches the reviewed patch exactly.

Ask via `AskUserQuestion` with four options: "Apply the wrapper (Sandbox
Mode — hosted; I'll confirm again before anything runs)", "Apply the wrapper
offline (no account, no network, local signing; same second confirmation
before running)", "Review the patch first", "Skip — end here". If the user
wants a different candidate, return to the findings and present the next one
(no new analysis authorization needed — the report already contains the
ranked list). "Review the patch first" shows the full diff, then re-asks with
apply/skip. **"Skip" is a valid terminal state: zero files changed** — go
directly to the outcome summary and render it as a completed analysis, not a
failure.

Repository hygiene: if `git status` matters to the user's workflow, note from
the analysis report that the repo state was NOT checked for cleanliness
(analysis doesn't run git); recommend the user commit or stash before
approving if they want a clean diff — but do not run extra commands to check.

### 3b. Copy the helper (on approval)

Copy the bundled reference implementation into the customer's source tree,
mirroring their layout:

- Python: `src/<pkg>/strix_wire.py` if there's a `src/<pkg>/` layout,
  otherwise `<pkg>/strix_wire.py`, otherwise `strix_wire.py` at the root.
- TypeScript: `src/lib/governedAction.ts` if `src/lib/` exists, else
  `src/governedAction.ts`, else `lib/governedAction.ts`.
- Sandbox Mode sources: `helpers/governed_action.py` / `helpers/governedAction.ts`.
  Offline Mode sources: `helpers/governed_action_local.py` /
  `helpers/governedAction.local.ts` (copied as `strix_wire_local.py` /
  `governedAction.local.ts`).

Use `Read` then `Write`. Do NOT modify the helper — it is the canonical
client, and divergence breaks cross-SDK byte determinism with the Strix
verifier (this is exactly what the analysis's helper-integrity phase
attests). If a helper already exists at the target with different contents,
show a diff and ask before overwriting.

### 3c. Wrap the call

Edit the candidate file. Two changes only: add the import; wrap the call
expression.

#### Python wrap pattern (Sandbox Mode)

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
    print(action.verify_command)  # FINAL line — see Phase 4
else:
    print("[strix] mutation succeeded but the signed receipt could not be confirmed — see Failure modes")
```

#### TypeScript wrap pattern (Sandbox Mode)

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
  console.log(action.verifyCommand); // FINAL line — see Phase 4
} else {
  console.log("[strix] mutation succeeded but the signed receipt could not be confirmed — see Failure modes");
}
```

Notes on the wrap:

- `payload` must contain only **non-secret** request parameters. Drop API
  keys, tokens, raw card numbers — keep amounts, IDs, target identifiers.
- `operation` is a zero-arg lambda/closure that re-runs the original call
  exactly as it was. Preserve every argument.
- `governed_action(...)` returns a `GovernedActionResult` (fields: `result`,
  `evidence_id`, `decision_id`, `signed_evidence_id`, `proof_url`,
  `verify_command`), not a tuple. `verify_command` is `None` when the receipt
  step didn't close the loop.
- The `print` block is temporary scaffolding for the demo — keep it for now;
  the user removes it later.
- If the original call was synchronous, keep the body sync but keep the outer
  `governedAction` async — and `await` it.
- Never wrap anything in a test path (`tests/`, `__tests__/`, `*.spec.*`,
  `*.test.*`) — the analyzer already refuses to surface them; if one slips
  through, refuse and pick the next candidate.

#### Capability ID mapping

Use the analyzer's suggested `capability_id` verbatim. Reference set
(generated from the single-source pattern catalog all detection engines
converge on):

| Category | capability_id | First-proof eligible |
|---|---|---|
| payments | `payment.charge`, `payment.refund` | yes |
| db-delete / db-update / db-create | `database.delete`, `database.update`, `database.create` | yes |
| s3-delete / s3-write | `storage.delete`, `storage.write` | yes |
| email-send / sms-send | `email.send`, `sms.send` | yes |
| file-delete | `filesystem.delete` | yes |
| schema-migration | `database.migrate` | yes |
| infra-apply / infra-destroy | `infra.apply`, `infra.destroy` | yes |
| iam-grant / iam-revoke | `iam.grant`, `iam.revoke` | yes |
| flag-flip | `flag.flip` | yes |
| data-export | `data.export` | yes |
| message-publish | `message.publish` | yes |
| ai-tool-use / ai-agent | `ai.tool_use`, `ai.agent_run` | yes |
| ai-provider / ai-embedding / ai-retrieval | `ai.completion`, `ai.embedding`, `ai.retrieval` | **no — observe-only** |

These match the Strix kernel's `<artifact_type>.<action>` convention
(ADR-003). Do not invent new ones during the wire-up. **PROOF-1 tiering:**
never pick an observe-only AI candidate as the wrap target; on an AI-native
codebase prefer `ai.agent_run` / `ai.tool_use` over an incidental CRUD or
payment call when both appear.

### 3d. Validate without executing

After the edit: re-read the changed file and confirm exactly two changes
(import + wrapped call), and confirm the helper file landed byte-identical to
the bundle. **Applying the wrap executes nothing**: no import of the changed
module, no test run, no "quick check" execution — the wrapped action fires
only inside Phase 4, behind its own approval. Then report:
"Wrapper applied and validated. Files changed: <n>. Actions executed: 0."

---

## Phase 4 — Approval 3 of 3: sandbox execution

Only reach this phase if the user approved a run-eligible wrap in Phase 3
("Skip" and "wrap only" end the flow at the outcome summary).

### 4a. Present the RUN SANDBOX PROOF card

**Execution gets its own explicit confirmation — always.** The Phase 3
approval covered the wrap; it did NOT authorize execution. Show exactly what
the run will do — concrete, capability- and target-specific, never generic:

```text
RUN SANDBOX PROOF?

The wrapper has been applied and validated.

This run will:
✓ <capability-specific setup, e.g. "Create a temporary SQLite database
   and add one disposable record">
✓ Evaluate <capability_id> before execution
✓ Execute only the approved call site, once, with test-safe inputs
✓ Produce the applicable evidence artifact

It will not:
✕ Touch production data, credentials, or live third-party accounts
✕ Execute any other candidate
✕ Claim full repository coverage

[Run sandbox proof]  [Stop here]
```

Ask via `AskUserQuestion` ("Run sandbox proof" / "Stop here"). This approval
is **capability- and target-specific**: it authorizes ONE run of THIS call
site with THESE inputs. A different entry point, different inputs, or a
retry after a code change requires asking again.

**"Stop here" is a valid terminal state.** It leaves a wrapped-but-unrun
codebase: "Governance boundary applied; consequential action executed: No;
execution evidence created: No." No execution evidence exists and none is
claimed (PROOF-1) — render the outcome summary honestly and end.

### 4b. Run it once

Execute the wrapped call via the smallest reproducer:

- Python: the smallest entry point that hits the wrapped call — a script the
  user identifies, or `python -c "from <module> import <fn>; <fn>(...)"` with
  **test-safe arguments** (Stripe test card, `usd 100`, a temporary database,
  a disposable record).
- TypeScript: `npm run <script>` or `node --loader ts-node/esm <file>` for
  the smallest reproducer.

If running the mutation requires real-money flow or production secrets,
**stop and tell the user** — don't find creative ways around it. The skill's
promise is to wrap; the user runs it in their own staging.

When the wrapped call runs (Sandbox Mode), the helper: (1) auto-provisions a
sandbox credential from `POST /api/public/sandbox/provision` if no real
credentials are configured; (2) evaluates via `POST /api/v1/evaluate` and
captures the kernel's `decisionId` — the mutation does not run unless the
kernel allows it; (3) runs the mutation and writes the unsigned
evidence/ingest audit row; (4) posts the receipt that Ed25519-signs the
decision and returns a verifiable `evidenceId`.

**The happy path — a real signed record.** When the receipt step succeeds,
`verify_command` is populated. Echo the proof URL, then close with the
independent check.

**INSTALL-1 — the last line is the independent check.** The run's FINAL
output line MUST be the runnable verification command, with nothing after it:

```text
npx @strixgov/verifier@latest dec_9f2b4a1c8e0d4abc
```

(the id is the signed `decisionId`, not the unsigned ingest `evidenceId` —
they differ). The run is not complete until the user holds a command they can
execute themselves, against a tool that owes nothing to this skill.

**The degraded path — be honest, don't fabricate.** If `verify_command` is
`None` (the receipt POST failed), do NOT print a verify command at all:

```text
[strix] mutation succeeded; unsigned evidenceId=<evidenceId> recorded.
[strix] the signed receipt could not be confirmed — see Failure modes below.
```

---

## Outcome renderer — every journey ends here

**Format matters as much as content — this is the moment a non-technical
reader decides whether any of this made sense.** Lead with the visual, then
plain language, then next steps. Adapt to whichever terminal state was
reached; every row must be truthful for that state.

### The visual

```text
  SCANNED     <N> files for hard-to-undo actions (payments, deletes, sends, migrations)
  FOUND       <M> candidates total (<K> excluded from temporary paths)
  WRAPPED     <"1 → <file>:<line>  (<capability_id>)" | "0 — wrap skipped">
  RAN         <"allow ✓ — the action executed for real" | "not run — by user choice" | "denied — the action never ran">
  PROOF       <verify command | "none — no execution, no evidence claimed" | the honest degraded message>
  APPROVALS   <1|2|3> of 3 used — analysis ✓ · wrap <✓|skipped> · run <✓|declined|—>
```

### Plain language

One or two sentences, no jargon: what got wrapped (or that nothing was
changed, if skipped), what "wrapped" means (check-then-run, not a rewrite),
and whether the account was real or an auto-provisioned sandbox credential
(say so plainly — sandbox credentials are short-lived, scoped to this
skill's capability set, and not a substitute for a real account).

### The map

"…and <X> more ungoverned action points: <family counts> …" — one wrap is
the proof; the count is the reason to keep going. Point at
`solo govern coverage` for the per-family Governance Coverage Rate — an
unsigned measurement, never proof.

### The proof command

The verify command as the LAST line of output (INSTALL-1), or the honest
degraded/skipped message instead — never both, never fabricated.

### Next steps

1. "Run the verify command above yourself — it's independent of this skill."
   (Only when a run actually happened.)
2. "Run `/strix-wire` again to wrap the next action" (point at the map) —
   and say plainly that the next run's preflight will now flag this repo as
   **already governed**, because it is: the wrap that was just applied is
   real governance. Continuing past that guard takes the explicit
   "wire it anyway" sign-off described in Phase 1c — by design, wrapping a
   second action in a now-governed repo is a deliberate decision, not a
   silent default.
3. "Run `solo kernel approve <capability_id>` to pre-authorize automated
   agents to run this in production."
4. If sandbox credentials were used, suggest a real Strix account so the
   tenant's own risk policy governs future runs.
5. Point at [`GETTING-STARTED.md`](./GETTING-STARTED.md)'s FAQ for "did this
   change what my code does?", "what if it's denied?", "can I undo this?".

Do not push a PR or commit unless the user explicitly asks — the wrap is
staged for their review.

---

## Offline Mode — zero account AND zero hosted dependency

Chosen at Phase 3 ("Apply the wrapper offline"). Everything else — the
analysis authorization, the findings review, both approval cards — is
identical; only the helper, the execution, and the terminal contract differ.
See `docs/architecture/local-mode-strix-wire-v1.md` (solo-builder-core) for
the full design note, receipt schema, key lifecycle, and threat model.

### Offline helper + wrap

Copy `helpers/governed_action_local.py` (as `strix_wire_local.py`) or
`helpers/governedAction.local.ts` — never the hosted helper. The pair is a
cross-language conformance pair (same canonical bytes, same Ed25519
primitives), self-contained by design. The offline helper needs real
filesystem access for its local key + evidence store; it is Node-only on the
TypeScript side and needs the `cryptography` package on the Python side. If
`cryptography` cannot be installed, STOP and say Offline Mode cannot proceed
— never silently fall back to an unsigned record (PROOF-1).

Wrap with `governed_action_local(...)` / `governedActionLocal(...)`. Every
capability this skill wraps is HIGH/CRITICAL by PROOF-1 construction, so the
offline policy gate demands a human approval per run — and that approval
must live in the **run command**, never in the committed source. The wrap
therefore derives `approval_granted` from a per-invocation environment
variable:

- **Never write a literal `approval_granted=True` / `approvalGranted: true`
  into the wrapped file.** A hardcoded flag would turn the user's one-run
  Phase 4 confirmation into a permanent, code-resident authorization: the
  file gets committed, CI or a scheduled agent imports it next week, and
  the irreversible action fires with no human in the loop. The environment
  variable pattern makes the safe thing the default: source at rest grants
  nothing; an unattended run sees the variable unset and the gate denies.
- At Phase 4, after the user answers "Run sandbox proof" yes, execute the
  single reproducer with `STRIX_WIRE_RUN_APPROVED=1` set **for that one
  command only** — that is the mechanical delivery of the Phase 4 approval,
  covering exactly one run. Tell the user this plainly in the outcome
  summary.

```python
import os

from strix_wire_local import governed_action_local  # adjust path

action = governed_action_local(
    "payment.refund",
    "refund_payment",
    {"amount": amount, "currency": "usd"},
    lambda: stripe.Refund.create(amount=amount, currency="usd", payment_intent=intent_id),
    # Run-scoped human approval: set STRIX_WIRE_RUN_APPROVED=1 only on the
    # single command the user approved at Phase 4. Never hardcode True.
    approval_granted=os.environ.get("STRIX_WIRE_RUN_APPROVED") == "1",
)
result = action.result
print(f"[strix] Action allowed")
print(f"[strix] evidenceId={action.evidence_id}")
print(f"[strix] receipt={action.receipt_path}")
print(f"[strix] verify=solo strix-wire verify {action.receipt_path}")  # FINAL line
```

```typescript
import { governedActionLocal } from "./governedAction.local"; // adjust path

const action = governedActionLocal(
  "payment.refund",
  "refund_payment",
  { amount, currency: "usd" },
  () => stripe.refunds.create({ amount, currency: "usd", payment_intent: intentId }),
  // Run-scoped human approval: set STRIX_WIRE_RUN_APPROVED=1 only on the
  // single command the user approved at Phase 4. Never hardcode true.
  { approvalGranted: process.env.STRIX_WIRE_RUN_APPROVED === "1" },
);
const result = action.result;
console.log("[strix] Action allowed");
console.log(`[strix] evidenceId=${action.evidenceId}`);
console.log(`[strix] receipt=${action.receiptPath}`);
console.log(`[strix] verify=solo strix-wire verify ${action.receiptPath}`); // FINAL line
```

Phase 4's offline run command is then, e.g.:

```bash
STRIX_WIRE_RUN_APPROVED=1 python run_once.py
```

and any later invocation without the variable is **denied by default** —
that denial is the safety feature working, not a bug.

### Offline run — no network anywhere

The offline helper's six-step loop — normalize, evaluate, decide, authorize,
execute, record — happens entirely on this machine: a local Ed25519 key is
generated on first run (`.strix/keys/`, 0600, never printed); the receipt is
appended to a hash-chained local file (`.strix/evidence/receipts.jsonl`) and
exported as a single JSON file (`.strix/evidence/<evidenceId>.json`). Before
wiring into the customer's `.gitignore`, add `.strix/keys/` (never commit
private key material); `.strix/evidence/` and the public-key registry are
safe to commit if the user wants a portable audit trail — offer, don't
decide.

**LOCAL-VERIFY-1 — the last line is the independent, offline check:**

```text
solo strix-wire verify .strix/evidence/local_ev_9f2b4a1c8e0d4abc.json
```

(if `solo` is not installed, say so and offer `pip install
solo-builder-core` — the command needs no network and no Strix credential).
**Never** print the hosted `npx @strixgov/verifier@latest` command after an
Offline Mode run — that command looks up a decision on `www.strixgov.com`,
which never received this run at all.

**Be explicit about what this proves:** a `LOCAL_MACHINE_ASSERTION` — a local
key signed a hash-chained, tamper-evident record of one authorized, executed
action. It does NOT prove Strix-operated custody, centralized policy
administration, multi-party approval, or protection against a machine owner
who controls both the runtime and the key. Say "locally signed and
independently verifiable," never "Strix-verified" or "hosted."

### Reliance gate + attestation gate (opt-in extensions)

The offline helpers support **Local Reliance Gate v1**: the wrapped action
can REQUIRE prior `LOCAL_SIGNED_V1` receipts — independently re-verified at
run time (hash, chain link, signature, key) and checked against content
bindings (capability, decision, execution status, workspace, age) — strictly
BEFORE the operation runs. A failed requirement raises
`StrixLocalRelianceDenied` and the operation never executes; a passing gate
binds the verified reliance projection into the action's own signed receipt
(`local-receipt-v2`). Offer this ONLY when the target action has an obvious,
already-governed prerequisite in this repo (a migration after a governed
backup); never invent a prerequisite — ask which existing receipt should gate
the action:

```python
import os

from strix_wire_local import governed_action_local, RelianceRequirement

action = governed_action_local(
    "database.migrate",
    "run_production_migration",
    {"revision": revision},
    lambda: run_migration(revision),
    # same run-scoped approval pattern as above — never a hardcoded True
    approval_granted=os.environ.get("STRIX_WIRE_RUN_APPROVED") == "1",
    reliance=[
        RelianceRequirement(
            "database.backup",
            ".strix/evidence/<backupEvidenceId>.json",
            max_age_seconds=1800,
        )
    ],
)
```

(TypeScript mirrors with camelCased fields:
`reliance: [{ capabilityId, receiptPath, maxAgeSeconds }]`.)

The SAME gate can require a signed **local agent attestation**
(`receiptType: LOCAL_AGENT_ATTESTATION_V1`) binding the requesting agent's
identity, class, permitted issuer, capability scope, and freshness — offer
only when the action is agent-driven and the user wants a specific,
previously-issued local identity vouch. Mint once during setup:
`solo strix-wire attest issuer-keygen`, then `solo strix-wire attest issue
--agent-id <id> --agent-class CLASS_VERIFIED --issuer-id
local-workspace-registry --scope <capability.or.prefix.*> --out <path>`.

If either gate denies, surface the requirement's `reason` verbatim (it names
the exact failing check, e.g. `REQUIRED_PROOF_EXPIRED: …`,
`ATTESTATION_SCOPE_MISMATCH`) and STOP — never loosen or delete a
requirement without the user explicitly deciding that. Standalone check:
`solo reliance require --policy <file> --receipt <path>` /
`--requesting-agent <id>` (exit 0 only on PROCEED). Honesty note: both gates
prove local re-verification on THIS machine — same `LOCAL_MACHINE_ASSERTION`
scope as everything else in Offline Mode.

---

## Failure modes — handle these without extra prompts

- **`analyze.py` errors or cannot run**: fail closed. One message, stop. Do
  NOT decompose the analysis into separate per-phase commands.
- **Missing Python**: ONE remediation message (see Phase 1b), stop.
- **No candidates found** (`verdict: NO_CANDIDATES`): stop, list what the
  scanner looked for (payments/refunds, db deletes/updates, destructive SQL,
  storage deletes/writes, email/SMS sends, filesystem deletes, schema
  migrations, infra apply/destroy, IAM grants/revokes, flag flips, bulk
  exports, message publishes, AI agent runs / tool dispatch), ask for a
  manual pointer. Zero approvals were spent on anything irreversible.
- **Wrap target is in a test path**: refuse, pick the next candidate.
- **Helper file already exists at the target with different contents**: the
  analysis report's `helper_integrity` section already flagged it — show a
  diff and ask before overwriting (this is part of the Phase 3 approval, not
  a new prompt class).
- **No `STRIX_API_KEY`/`STRIX_TENANT_ID`**: not a stop condition — Sandbox
  Mode auto-provisions at the execution phase; Offline Mode never needed
  them. Only stop if the provisioning call ITSELF fails (see 5xx below).
- **Strix API returns 401/403** (real credentials only): tell the user their
  key/tenant pair is wrong; don't retry with stub data — the skill's whole
  value is the authentic evidence record.
- **Strix API returns 5xx or network error** (provisioning, evaluate,
  evidence, or receipt): surface the error and offer to retry once with
  backoff. After two retries, stop — except the **receipt** step, which the
  helper deliberately attempts only once (best-effort) so as not to delay a
  mutation that already succeeded; on receipt failure follow the degraded
  path in Phase 4, not a stop.
- **(Offline Mode) local policy denies the capability**: stop before the
  wrap runs — name the capability and why; never silently pick a different
  one.
- **(Offline Mode) approval not granted for a HIGH/CRITICAL capability**:
  if this happens on the Phase 4 run itself, the run command was issued
  without `STRIX_WIRE_RUN_APPROVED=1` — re-issue the exact approved command
  with the variable set; do not edit the source to force the flag. If it
  happens on any LATER, unattended invocation, the gate is doing precisely
  its job: the committed wrap grants nothing at rest, and each future run
  needs its own explicit human approval.
- **(Offline Mode) `cryptography` missing, or local key
  missing/corrupt/mismatched**: stop, surface the helper's
  `StrixLocalKeyError` message verbatim, never fall back to an unsigned
  record. Suggest `pip install cryptography` or deleting `currentKid` from
  `.strix/keys/registry.json` to mint a fresh key.
- **(Offline Mode) mutation succeeded but the receipt failed to persist**:
  surface `StrixLocalReceiptPersistenceError` verbatim — it states the
  mutation is NOT undone and points at the evidence directory. Never retry
  the mutation to "make up for" a missing receipt.

## Out of scope for this skill

- Multi-call wrapping. The skill wraps **one** call. Use it again for the
  next one (each new run starts with a fresh ANALYSIS REQUEST, and — once a
  first wrap exists — a preflight already-governed STOP that takes explicit
  sign-off to continue).
- Async-context propagation. The helper takes a callable; custom context
  (request IDs, tracers) is the customer's wiring.
- Policy authoring. If the capability is new to the tenant, the kernel
  returns `escalate` and the skill surfaces it — the user then runs
  `solo kernel approve` to issue a token.

## Contract tests

The consent architecture is pinned by the suite in
[`tests/`](./tests/) — runnable by anyone with
`python -m pytest skills/strix-wire/tests -q`:

- `test_consent_boundary.py` — behavioral: one authorization covers every
  analysis phase; analysis writes nothing, reads nothing outside the
  disclosed root, creates no evidence, and applies temporary-path exclusions
  automatically; helper integrity runs inside analysis scope.
- `test_consent_contract.py` — source-scanned: the ANALYSIS REQUEST card
  matches the analyzer's actual grant list; the analyzer contains no write /
  subprocess / network capability; wrap and execution each require their own
  confirmation; skipped execution and skipped wrap are valid terminal
  states; analysis consent expires end-of-run and re-scoping requires fresh
  consent.

## Why this works

The Strix evidence stack makes the signed decision the thing that proves a
governed action happened. Every mechanical step (preflight, scanning,
candidate analysis, helper integrity) is read-only setup — so it is covered
by one disclosed, expiring authorization. The moments of truth are the two
governance decisions the user takes explicitly, and — in Sandbox Mode — the
three real network calls the helper makes against the live, hosted kernel:
`POST /api/v1/evaluate` (the mutation does not run unless the kernel allows
it), `POST /api/v1/evidence/ingest` (the unsigned audit row), and
`POST /api/v1/decisions/{decisionId}/receipt` (the Ed25519-signed record
anyone can check with `npx @strixgov/verifier@latest <decisionId>`).

The 2-minute promise depends on the scanner finding a clean candidate on the
first try. When it doesn't, "show me your candidate" is still a 5-minute
path — and it costs the same three approvals, never more.
