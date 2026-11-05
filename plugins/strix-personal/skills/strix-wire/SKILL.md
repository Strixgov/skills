---
name: strix-wire
description: Wire Strix governance into the current codebase. Scan for a consequential action, propose and apply one governed wrapper, run it only with explicit confirmation, and return an independently checkable signed proof when the receipt closes. Use when the user asks to wire Strix, scan for a risky action, create a first governed action, or runs /strix-personal:strix-wire.
---

# Strix Wire — public plugin skill

This is the canonical public Strix Wire skill distributed inside the
`strix-personal` plugin. It is self-contained in the installed plugin and must
not depend on the repository that publishes the marketplace.

It takes an ungoverned codebase from one consequential action to a real
governed execution and a signed record that the user can independently check.
The phases remain distinct:

```text
DETECT → PROPOSE → WRAP → EVALUATE → AUTHORIZE → EXECUTE → RECORD → VERIFY
```

The plugin helps wire the action. The hosted Strix kernel evaluates and controls
the Sandbox and Connected paths. Offline Mode uses a local signing key and must
be presented only as a `LOCAL_MACHINE_ASSERTION`.

## Operating modes

- **Sandbox Mode (default):** no account or API key required. If
  `STRIX_API_KEY`/`STRIX_TENANT_ID` are unset, the helper auto-provisions a
  short-lived credential from `POST /api/public/sandbox/provision` and
  proceeds — a stranger with no account still gets a real, hosted,
  kernel-evaluated, Ed25519-signed record. Evaluation, execution-token
  issuance, receipt closure, signing, and public proof use the hosted Strix
  kernel.
- **Offline Mode (explicit opt-in):** no network calls. A local Ed25519 key signs
  a `LOCAL_SIGNED_V1` receipt. Do not present this as Strix-operated custody.
- **Connected Mode:** uses `STRIX_API_KEY` and `STRIX_TENANT_ID` for the user's
  tenant-scoped policy, approvals, evidence history, and proof surfaces.

Never blend these claims. Never describe a record as more verified than the
checks the verifier actually reports.

## The interaction budget — three approvals, and only three

This skill asks a human to decide exactly three times:

```
Approval 1 — analyze this repository, read-only
Approval 2 — apply THIS exact source change
Approval 3 — execute THIS exact action, once
```

**One approval never buys the next.** Approving the analysis does not
authorize a write; approving the wrap does not authorize a run; approving one
run does not authorize the next.

**A Claude Code permission prompt is not a governance approval.** The harness
prompt is permission for the *tool invocation*. The consent card below is the
product-level confirmation of the proposed operation, and it is shown even
when the harness has already prompted.

## Step 1 — One read-only analysis (Approval 1)

Preflight guard, language detection, mutation scan, candidate ranking, and
helper-integrity check are **one operation** — not five commands:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/_wire/analyze.py" --root . --json \
  --helpers-dir "${CLAUDE_PLUGIN_ROOT}/helpers" \
  --require-helpers governed_action.py,governedAction.ts
```

`--require-helpers` declares the subset this plugin ships (the two hosted-mode
helpers; the two offline-mode ones are not distributed here). Anything present
is still integrity-checked, so the declaration never excuses a tampered file.

Show this consent card **before** running it:

<!-- consent-card:analysis -->
```
Strix Wire would now analyze this repository.

It WILL:
  - read source files under this one directory, to find actions that
    cannot be undone once they run (payments, deletes, sends, migrations);
  - check whether this repo is already governed or looks like production;
  - check that its own helper files are the ones it shipped with.

It does NOT modify any file.
It does NOT execute any of your code.
It does NOT contact the network or install anything.
It does NOT leave this directory.

Scope: this repository root, this run only.
```
<!-- /consent-card:analysis -->

### Reading the result

| `status` | Exit | What you do |
|---|---|---|
| `OK` | 0 | `selected` is the proposed wrap target. Go to Step 2. |
| `STOP` | 3 | **Halt.** Governance or production markers present. |
| `ANALYSIS_INCOMPLETE` | 4 | **Do not wrap.** Coverage could not be established. |

**On `STOP`, halt.** Explain `preflight.reason` and `preflight.markers`. This
quickstart is for an ungoverned scratch, demo, or staging repository; do not
duplicate an existing Strix wrapper. If the repo is already wired, continue
with `/strix-personal:strix-status`, `/strix-personal:strix-test`, or run the
existing wrapped entry point. Any error running the analyzer is STOP, not
permission to continue.

**On `ANALYSIS_INCOMPLETE`, never present the candidate list as a finding.**
An unreadable directory, a truncated walk, a scanner failure, a
helper-integrity mismatch, or a read that escaped the root all mean the scan
may have missed consequential actions. Read `incompleteReasons` out and say
plainly that coverage could not be established — this is not a clean bill of
health. `selected` is `null` in this state, by design.

**PROOF-1:** only a consequential, irreversible action may carry the first
proof. The analyzer emits only irreversible-mutation (and consequential AI)
capability IDs and refuses test paths, so a dummy or no-op proof cannot be
minted to make a first run look complete. If there is no candidate, report
that honestly and ask the user to identify a specific consequential call. Do
not claim the project is governed.

## Preconditions

1. The working directory is a code repository (`.git`, `package.json`,
   `pyproject.toml`, `go.mod`, or `Cargo.toml`).
2. Print `git status -s`. Ask before writing if unrelated changes exist.
3. Credentials are optional. Do not prompt for them in Sandbox Mode, and never
   write secrets into a committed file.

## Step 2 — Propose and confirm

Before editing, show:

- file, line, and original snippet;
- proposed `capability_id`;
- the call-site diff (the change preview — the confirmation covers exactly
  this, nothing more);
- where the helper will be placed;
- a "Will / Will not" block: WILL add a governance check to this one call
  site, copy one helper file, and — only after a second, separate
  confirmation — run the action once with test-safe inputs; will NOT touch
  other candidates, production data, secrets, or live third-party accounts,
  and will not claim the repository is governed beyond this one action.

Offer:

1. Approve the wrap in Sandbox Mode (a second confirmation comes before
   anything runs).
2. Approve the wrap in Offline Mode (same second confirmation before
   running).
3. Wrap only; do not run.
4. Pick a different candidate.

One confirmation never both wraps and runs. Approval here authorizes the
wrap only; execution requires its own explicit confirmation at Step 4.

## Step 3 — Place the helper and wrap one call

Copy the unmodified helper from the installed plugin:

- Python: `${CLAUDE_PLUGIN_ROOT}/helpers/governed_action.py`
- TypeScript: `${CLAUDE_PLUGIN_ROOT}/helpers/governedAction.ts`

Mirror the project's layout. For a simple Python repository, use
`strix_wire.py` at the root. For TypeScript, prefer `src/lib/governedAction.ts`
when that layout exists.

Dry-run the patch first:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/strix_apply.py" --root . \
  --file <path> --line <n> --py-import "from strix_wire import governed_action"
```

After confirmation, rerun with `--apply`. Keep payloads non-secret. Preserve the
original operation exactly inside the zero-argument callback.

## Step 4 — Execute only the confirmed test-safe path

**Execution gets its own explicit confirmation.** Before running, show the
entry point, the test-safe inputs, and that the action fires once — then ask
"Run it now?". A "no" leaves a wrapped-but-unrun codebase, which is a valid,
honest terminal state (boundary applied; action executed: No; execution
evidence: No), not a failure.

Use the smallest entry point that invokes the wrapped action with disposable or
staging-safe inputs. Stop rather than improvising if execution would require
production secrets, real money, customer data, or an irreversible production
mutation.

The hosted happy path is:

```text
sandbox/provision or tenant credential
→ policy evaluation
→ bounded execution token
→ token redemption
→ operation
→ receipt closure
→ signed evidence
```

No token means no execution. Any control failure must remain explicit and
fail-closed.

## Step 5 — Surface only real proof (INSTALL-1)

**INSTALL-1 — installation is not complete until an independently verifiable
proof has been produced and verified by the installer.** When receipt closure
succeeds, print the proof URL and make the FINAL output line — with nothing
after it — the exact verifier command returned by the helper:

```text
npx @strixgov/verifier@latest <proof-id>
```

**INSTALL-1:** that verifier command is the final output line of a successful
run — not the proof id, not setup output. The run is complete only when a
stranger can copy that final output line and verify it independently.

Do not fabricate or reconstruct a verifier command when the helper did not
return one.

If the operation succeeded but signed receipt closure could not be confirmed,
state that the mutation succeeded and an unsigned audit identifier may exist,
but no signed proof is being claimed.

For Offline Mode, use the local verifier and label the result as a
`LOCAL_MACHINE_ASSERTION`.

## Step 6 — Report

Report:

1. What was wrapped and the capability ID.
2. Which operating mode was used.
3. Whether the action executed.
4. Whether signed evidence was created.
5. The independent verification command, as the final output line when available.

## Guardrails

- One consequential call per run.
- Never bypass preflight silently.
- Never duplicate an existing governance wrapper.
- Never expose credentials in commands, logs, payloads, or evidence.
- Never describe detection as enforcement.
- Never describe signature presence as full verification.
- Never claim a proof state stronger than the verifier output.
