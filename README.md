# Strix Open — governance skills (SGRF v1)

The open methodology layer of [Strix](https://www.strixgov.com), an
execution-control system for AI agents. These are **Claude Code skills** that run
the **Strix Governance Review Framework (SGRF v1)**: review how any system governs
execution, score it on four orthogonal axes, and — when you're ready — wire a
first governed, recorded action.

**MIT-licensed, runs locally, no Strix account required.** The three review
lenses are advisory by construction — they read and report, they never enforce.

## What's inside

| Skill | Lens | What it does |
|---|---|---|
| `/runtime-governance-review` | system | The canonical 13-section SGRF review of a project, agent, MCP server, or CI/CD pipeline + the 4-axis profile. |
| `/govern-pr` | change | Governance-impact review of a single PR/diff — which axes does this change move, and which way. |
| `/release-readiness` | release | Is a release shipping as a governed, recorded, revocable decision? Ends in GO / GO-WITH-CONDITIONS / NO-GO. |
| `/strix-wire` | remediation | Wire one consequential call site through `governedAction()`: the kernel evaluates the action before it runs and a queryable evidence record is persisted (recorded wire evidence — not Ed25519-signed at ingest). **Requires a Strix runtime** (`STRIX_API_KEY` + `STRIX_TENANT_ID`). |

The first three are pure-advisory and need no runtime. `strix-wire` is the bridge
from the open advisory layer to the Strix runtime — open skill, commercial control
plane.

The methodology itself is vendored here as
[`strix-governance-review-framework-v1.md`](strix-governance-review-framework-v1.md) —
the frozen 13-section / 4-axis contract every lens produces, so the skills are
self-contained.

## Install

### Option A — Claude Code plugin (recommended)

Add the marketplace, then install the plugin:

```
/plugin marketplace add Strixgov/skills
/plugin install strix-governance@strixgov
/reload-plugins
```

Then invoke a lens (skills are namespaced by the plugin):

```
/strix-governance:runtime-governance-review the deploy workflow in this repo
/strix-governance:govern-pr --base origin/main --head HEAD
/strix-governance:release-readiness v1.2.0
```

### Option B — manual copy (no marketplace)

Clone this repo and copy the skills into your project's `.claude/skills/`:

```bash
git clone https://github.com/Strixgov/skills strixgov-skills
mkdir -p .claude/skills
cp -r strixgov-skills/skills/* .claude/skills/
```

Restart Claude Code (or `/reload-plugins`); the skills appear unnamespaced
(`/runtime-governance-review`, `/govern-pr`, `/release-readiness`,
`/strix-wire`).

### Prerequisites for `/strix-wire` only

The three review lenses need nothing. `strix-wire` talks to a Strix runtime:

```bash
export STRIX_API_KEY=sk_test_...     # per-tenant API key
export STRIX_TENANT_ID=your-tenant   # tenant slug
# optional: export STRIX_API_URL=https://www.strixgov.com (the default)
```

Keys go in shell exports or a git-ignored `.env.local` — never in a file the
agent will commit.

### Zero-install verification

Any Strix signed record can be checked without installing anything from this
repo:

```
npx @strixgov/verifier@latest <evidenceId>
```

## What you get

A recognizable review every time: an **applicability declaration**, **declared vs
observed scope**, the 13 SGRF sections, and the **four orthogonal axes** —
Capability · Governance · Runtime Enforcement · Independent Verification — rendered
as bars, never blended into one number. The gap between the axes is the finding: a
very capable system can be barely verifiable, and a single score would hide it.

## Advisory, and honest about it

The review skills run nothing and produce no signed record — they reason and
report. They never claim a system is "secure"; they score it for what it is and
mark anything unverified as exactly that. Where a Strix runtime is actually present
(`STRIX_API_KEY` + `STRIX_TENANT_ID` and a reachable evaluation surface), a lens
may *optionally* fold in a real verdict + signed receipt — never a fabricated one.

The upgrade path is explicit: a review improves how an agent *thinks* about
governance; a runtime makes the decision non-bypassable and produces an
independently verifiable record. Verify any Strix record yourself with the open
MIT verifier:

```
npx @strixgov/verifier@latest <evidenceId>
```

## Mirror, not the source of truth

This repository is a **public release surface**. The canonical skills live upstream
in the Strix monorepo; the SGRF methodology spec is vendored from there so the
skills resolve their cited contract offline. Changes flow upstream first, are
checked for drift against the frozen spec, then synced here at release time.

## License

MIT. See [LICENSE](LICENSE). Strix's open trust primitives (the
[`@strixgov/verifier`](https://www.npmjs.com/package/@strixgov/verifier) and the
tool-gateway) are MIT too; the hosted runtime/control plane is the commercial
layer.
