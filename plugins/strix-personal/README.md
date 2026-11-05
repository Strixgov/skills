# Strix Personal

**Execution control for the agents you use every day.**

Install Strix → scan your project → govern the actions that matter → prove what
Claude (or any agent) was allowed to do.

Strix Personal is a Claude Code plugin. It scans your repository for
consequential actions (payments, deletes, sends, schema migrations, AI
tool-use), wraps the risky ones with `governed_action()`, tests that the wrap
actually governs, and produces **signed receipts you can verify independently**
— no trust in the agent or plugin required. The proof state is limited to the
checks the verifier actually performs.

> The plugin **renders** proof; it never **determines** it. It may detect,
> propose, patch, test, and explain — it will never silently approve an action,
> weaken a policy, fabricate a receipt, or claim coverage it didn't establish.

## Install

```text
/plugin marketplace add Strixgov/skills
/plugin install strix-personal@strixgov
/reload-plugins
```

The GitHub repository shown by Claude Code is the **marketplace publisher source**,
not the location where the skill must be run — the skill itself lives inside this
plugin at `skills/strix-wire/SKILL.md`. After installation, `strix-wire` is bundled
inside the `strix-personal` plugin and is invoked from any eligible project as:

```text
/strix-personal:strix-wire
```

Do not open the marketplace repository and do not use bare `/strix-wire` for the
public plugin flow.

The plugin is **zero-install** — it bundles its own stdlib-only scanner, helper,
and canonical `strix-wire` skill. You do not need to clone the publisher
repository or copy a skill into the target project.

### Install diagnostics

After reload, `/plugin` must show `strix-personal` as installed and enabled. A
healthy v0.2.3 reload includes the `strix-wire` skill from:

```text
<plugin cache>/strix-personal/0.2.3/skills/strix-wire/SKILL.md
```

If Claude reports `Reloaded: 0 plugins · 0 skills`, the command is unknown, or
it says the skill only exists in the publisher repository, check all three
settings scopes:

```text
~/.claude/settings.json
<repo>/.claude/settings.json
<repo>/.claude/settings.local.json
```

A project-local `settings.local.json` override wins over both broader scopes.
The effective value must be:

```json
{
  "enabledPlugins": {
    "strix-personal@strixgov": true
  }
}
```

Also inspect `/plugin` → **Errors**. Remove stale project references only when
the error names a different plugin, such as a retired
`strix-verifier@strixgov`; do not remove `strix-personal@strixgov` while diagnosing
an unrelated plugin error.

When diagnosing credentials, report only whether an environment variable is
set. Never print API-key values into a terminal transcript.

## Updating

New releases bump the plugin version and marketplace listing together:

```text
/plugin marketplace update strix
/plugin uninstall strix-personal@strixgov
/plugin install strix-personal@strixgov
/reload-plugins
```

Verify the installed version in `/plugin`. This release is **0.2.3**, author
**Strix Labs**. If Claude says the plugin is already installed globally, manage
that installed entry through `/plugin`; do not concatenate two slash commands
on one line.

## Commands and skills

| Command | What it does |
|---|---|
| `/strix-personal:strix-wire` | **Canonical fast path.** Loads the bundled plugin skill, scans, proposes one wrap, runs only after confirmation, and returns the independent verification command. |
| `/strix-personal:strix-scan` | Read-only inventory of consequential actions + coverage. |
| `/strix-personal:strix-plan` | Capability map + proposed controls + which call sites to wrap. |
| `/strix-personal:strix-apply` | Wrap one call site — rollback-safe, diff shown + confirmed before write. |
| `/strix-personal:strix-test` | Allowed / approval-required / bypass scenarios; verify the receipt. |
| `/strix-personal:strix-status` | Where every action sits on DETECTED → … → VERIFIED. |

An additional `execution-control` skill provides read-only assessment and
education. It does not enforce actions.

## Lifecycle

```text
DETECTED → WRAPPABLE → WRAPPED → TESTED → ENFORCED → VERIFIED
                                                  └→ SUPPRESSED (# strix: allow)
```

Detection is not enforcement. A scan can place an action no further than
`WRAPPED`; `TESTED`, `ENFORCED`, and `VERIFIED` each require a real runtime
signal — a fact the scanner structurally cannot observe.

Those signals are produced by the commands that actually run the checks and
recorded in a local journal (`.solo/strix-personal/signals.jsonl`), so a result
survives to the next command instead of living only in a transcript:

| State | Signal | Recorded by |
|---|---|---|
| `TESTED` | a deny/approval scenario passed | `/strix-personal:strix-test` |
| `ENFORCED` | no ungoverned sibling call exists, repo-wide | `/strix-personal:strix-apply` (bypass check) |
| `VERIFIED` | a real signed record was produced; its id is recorded | `/strix-personal:strix-test` |

Four rules keep the journal from becoming a way to *assert* governance:

- **It is not evidence.** Records carry no `record_hash` / `chain_seq` /
  `prev_hash` / `signature`. `VERIFIED` names the signed record's `evidenceId`;
  that record is what a third party verifies, not this file.
- **Every signal is bound** to the code it was recorded against, and re-checked
  on every read. A site-scoped signal follows its call rather than its line
  number; the repo-scoped bypass signal expires the moment any call site of
  that capability appears, changes, or loses its wrap — including in a file the
  original check never read.
- **A failure caps.** Because the state renders as one linear value, a failed
  check holds the entry *below* the state it gates rather than merely not
  raising it. A failing deny-scenario test cannot sit hidden under a `VERIFIED`
  earned by other signals.
- **Nothing is silent.** `/strix-personal:strix-status` reports every signal it
  dropped and why. `--no-signals` shows the static scan alone.

`strix-wire` is a zero-to-one quickstart. Once a call site is already wrapped,
preflight must stop rather than layering a second helper or second governance
boundary. Continue with `/strix-personal:strix-status`,
`/strix-personal:strix-test`, or execute the existing wrapped entry point.

## Three operating modes

- **Sandbox Mode (default, free, no account):** hosted evaluation,
  execution-token issuance, receipt signing, and public proof use
  `https://www.strixgov.com`. The hosted Strix kernel signs the record.
- **Offline Mode (explicit opt-in):** no network calls. A local Ed25519 key signs
  a `LOCAL_SIGNED_V1` receipt. This proves a `LOCAL_MACHINE_ASSERTION`, not
  Strix-operated custody.
- **Connected Mode:** set `STRIX_API_KEY` and `STRIX_TENANT_ID` for tenant-scoped
  policy, approvals, receipt history, public proof URLs, aggregation, and
  compliance surfaces.

Do not blend these claims. No proof state should exceed the verification layers
actually run.

## Manual wrap

When a call site is multi-line or ambiguous, review it manually rather than
forcing the patcher.

**Python**

```python
from strix_wire import governed_action

action = governed_action(
    capability_id="payment.charge",
    payload={"amount": amount, "currency": "usd"},
    operation=lambda: stripe.Charge.create(
        amount=amount,
        currency="usd",
        source=token,
    ),
)
result = action.result
```

**TypeScript**

```typescript
import { governedAction } from "./governedAction";

const action = await governedAction(
  { capabilityId: "payment.charge", payload: { amount, currency: "usd" } },
  async () => await stripe.charges.create({ amount, currency: "usd", source: token }),
);
const result = action.result;
```

Payloads must contain non-secret parameters only.

## Provenance

The marketplace publisher repository contains the tested source used to build
the plugin, but the installed v0.2.3 package is self-contained. Bundled scanner
and helper parity remains CI-locked against canonical sources.
Public users run the namespaced plugin skill from their own project; they do not
run the publisher repository's project skill.

Architecture and build plan: `docs/strix-personal/STRIX-PERSONAL-BUILD-PLAN.md`.

License: MIT.
