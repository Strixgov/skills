# Strix Open — Governance Skills (SGRF v1)

The open methodology layer of **Strix**, an execution-control system for AI agents.

These are **Claude Code skills** that run the **Strix Governance Review Framework (SGRF v1)** to review how a system governs execution, score it across four independent dimensions, and—when you are ready—help wire the first governed, recorded action.

> **Where this works**
>
> Strix Governance is a **Claude Code plugin**. It works in:
>
> - Claude Code CLI
> - Claude Code Desktop
> - Claude Code in VS Code
>
> It reviews the **local repository currently opened in Claude Code**.
>
> It does **not** install into or run inside the standard **Claude.ai web chat UI**.

**MIT licensed. Runs locally. No Strix account required.**

The review skills are advisory by design. They inspect, reason, and report. They do not execute or enforce anything on their own.

---

# Quick Start — 60 Seconds

## 1. Open the project you want to review

Clone or open a local repository, change into that directory, and start Claude Code:

```bash
git clone https://github.com/your-org/your-project.git
cd your-project
claude
```

You can also open an existing local project using Claude Code Desktop or Claude Code in VS Code.

## 2. Install Strix Governance

Run these commands inside Claude Code:

```text
/plugin marketplace add Strixgov/skills
/plugin install strix-governance@strixgov
/reload-plugins
```

## 3. Run your first review

```text
/strix-governance:runtime-governance-review this repository
```

That is it.

Strix Governance will review the project currently open in Claude Code.

> You do not need to clone the Strix plugin repository when installing through the marketplace.

---

# What Is Included

| Skill | Purpose | Description |
|---|---|---|
| `/runtime-governance-review` | System review | Runs the canonical 13-section SGRF review and produces a four-axis governance profile. |
| `/govern-pr` | Change review | Analyzes the governance impact of a pull request or code diff. |
| `/release-readiness` | Release review | Evaluates whether a release is governed, recorded, revocable, and independently verifiable. |
| `/strix-wire` | Guided integration | Helps route one consequential action through the Strix runtime using `governedAction()`. Requires a Strix runtime. |

The first three skills are completely local and require no Strix runtime.

`/strix-wire` is the bridge from the open advisory layer to the commercial Strix execution-control runtime.

The Governance Review Framework specification is vendored directly into this repository as:

```text
strix-governance-review-framework-v1.md
```

This keeps every review aligned with the same frozen methodology.

---

# Installation

## Option A — Claude Code Plugin

### Step 1 — Open a local project

The plugin analyzes the repository in Claude Code's current working directory.

```bash
git clone https://github.com/your-org/your-project.git
cd your-project
claude
```

You may also open a local project directly in Claude Code Desktop or Claude Code in VS Code.

### Step 2 — Install the plugin

Inside Claude Code:

```text
/plugin marketplace add Strixgov/skills
/plugin install strix-governance@strixgov
/reload-plugins
```

### Step 3 — Run a skill

```text
/strix-governance:runtime-governance-review the deployment workflow

/strix-governance:govern-pr --base origin/main --head HEAD

/strix-governance:release-readiness v1.2.0
```

The skills operate against the local project currently open in Claude Code.

---

## Option B — Manual Installation

Clone the Strix skills repository and copy the skills into your project's `.claude/skills/` directory:

```bash
git clone https://github.com/Strixgov/skills.git strixgov-skills

mkdir -p .claude/skills

cp -r strixgov-skills/skills/* .claude/skills/
```

Reload Claude Code:

```text
/reload-plugins
```

The manually installed skills appear without the plugin namespace:

```text
/runtime-governance-review
/govern-pr
/release-readiness
/strix-wire
```

---

# Example Reviews

## Review an entire repository

```text
/strix-governance:runtime-governance-review this repository
```

## Review a deployment workflow

```text
/strix-governance:runtime-governance-review the production deployment workflow
```

## Review a pull request or branch

```text
/strix-governance:govern-pr --base origin/main --head HEAD
```

## Review a release

```text
/strix-governance:release-readiness v1.2.0
```

---

# `/strix-wire` Requirements

The advisory review skills require no account, credentials, or runtime connection.

`/strix-wire` connects to a Strix runtime and requires:

```bash
export STRIX_API_KEY=sk_test_...
export STRIX_TENANT_ID=my-tenant

# Optional
export STRIX_API_URL=https://www.strixgov.com
```

Store credentials in environment variables or a git-ignored `.env.local` file.

Never commit API keys.

---

# Independent Verification

When a Strix runtime produces **signed evidence**, anyone can independently verify it using the open verifier:

```text
npx @strixgov/verifier@latest <evidenceId>
```

Verification distinguishes between the canonical proof states:

- `VERIFIED`
- `INVALID`
- `LEGACY_UNSIGNED`
- `UNVERIFIABLE`

Not every evidence record is cryptographically signed.

Legacy unsigned or recorded-only evidence remains valid within its declared legacy semantics, but it must never be represented as signed or cryptographically verified.

---

# What a Review Produces

Every review follows the same canonical methodology:

- Applicability declaration
- Declared scope
- Observed scope
- Thirteen governance review sections
- Findings and remediation priorities
- Four independent governance axes

The four axes are:

1. **Capability**
2. **Governance**
3. **Runtime Enforcement**
4. **Independent Verification**

These dimensions are intentionally kept separate rather than blended into one score.

That separation matters. A system may be highly capable while having weak runtime enforcement or little independently reproducible proof.

---

# Advisory by Design

The local review skills:

- do not execute actions;
- do not modify the reviewed system;
- do not create runtime enforcement by themselves;
- do not claim security that has not been established;
- do not fabricate verification evidence;
- do not represent unsigned evidence as signed.

They inspect, reason, and report.

When a genuine Strix runtime is present, a review may incorporate real governance decisions and independently verifiable evidence. It must never invent them.

---

# From Review to Governed Execution

The intended progression is:

```text
Review
  ↓
Identify governance gaps
  ↓
Select a consequential action
  ↓
Wire it through the execution boundary
  ↓
Evaluate before execution
  ↓
Permit, deny, or require approval
  ↓
Record evidence
  ↓
Independently verify the result
```

The open skills improve how agents and teams reason about governance.

The Strix runtime enforces governance before consequential execution.

---

# Architecture Principle

Strix is an execution-control kernel between intent and side effect.

```text
INTENT
  ↓
INTERCEPT
  ↓
EVALUATE
  ↓
DECIDE
  ↓
EXECUTE OR BLOCK
  ↓
RECORD
  ↓
VERIFY
```

Nothing executes until it is evaluated.

Nothing that affects trust may bypass governance.

No proof claim may exceed what can be independently verified.

---

# Public Release Surface

This repository is the public release surface for the open Strix governance skills.

The canonical implementation lives upstream in the Strix monorepo.

Changes are:

1. developed upstream;
2. validated against the frozen SGRF specification;
3. checked for release drift;
4. synchronized here for public use.

This repository should not be treated as a separate source of architectural truth.

---

# Troubleshooting

## The skills are not appearing

Run:

```text
/reload-plugins
```

Then confirm that the plugin is installed:

```text
/plugin
```

## Claude Code is not reviewing the correct project

Confirm that Claude Code was started from the repository you intend to review:

```bash
cd path/to/your-project
claude
```

The plugin uses Claude Code's current local project context.

## I am using Claude.ai in a browser

The plugin is not available in the standard Claude.ai web chat interface.

Use Claude Code CLI, Claude Code Desktop, or Claude Code in VS Code.

## I do not want to use the marketplace

Use the manual installation instructions and copy the skills into:

```text
.claude/skills/
```

---

# License

MIT License.

The open governance methodology, the `@strixgov/verifier`, and the tool gateway are MIT licensed.

The hosted Strix runtime and execution-control platform are commercial services.