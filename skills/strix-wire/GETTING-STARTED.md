# strix-wire — first-time quickstart

Govern one real action in about **two minutes**. strix-wire finds one
irreversible call in your code, wraps it in governance, runs it once, and hands
you a **cryptographically signed receipt anyone can verify** — with no Strix
account, and no data leaving your machine except the one evaluation request.

## Before you start — what you need

| Need | Why |
|------|-----|
| **Claude Code** (CLI or desktop) | strix-wire is a Claude Code skill, not a standalone binary. |
| **Python 3** | Runs the scanner + the safety preflight. Stdlib only — nothing to `pip install`. |
| **Node + npm** | Only for the final self-check (`npx @strixgov/verifier`). |
| **No Strix account** | If no API key is set, local mode auto-provisions a short-lived sandbox credential — you still get a real, hosted, signed decision. |

> **Use a non-production sandbox repo the first time.** strix-wire fires one
> real action. The preflight guard refuses to run in a live or already-governed
> codebase (live Stripe keys, `.env.production`, real deploy domains, or existing
> `governedProcedure` / Canonical Proof Flow). Start on a scratch project.

## Step 1 — (optional) see it work with zero install

Watch the full deny → approve → execute → re-verify flow offline, then check a
real production record. Needs the `solo` CLI (`pip install solo-builder-core`).
Skip this if you just want to wire your own repo.

```bash
solo demo adversarial                 # air-gapped end-to-end walkthrough
npx @strixgov/verifier@latest 5686    # a real Strix record → Status: VERIFIED
```

## Step 2 — install the skill in Claude Code

Adds strix-wire plus the three governance-review lenses. Already installed?
Run `/plugin update strix-governance@strixgov` to pull the latest.

```
/plugin marketplace add Strixgov/skills
/plugin install strix-governance@strixgov
```

## Step 3 — open your project and run it

Open your sandbox repo in Claude Code, then invoke the command — or just ask in
plain English ("wire Strix into this project", "set up a governed action") and
it triggers.

```
/strix-wire
```

> From the **installed plugin** the command is namespaced:
> `/strix-personal:strix-wire`. The bare `/strix-wire` appears only when the
> source repo itself is open in Claude Code.

## Step 4 — verify your own proof

strix-wire prints an `evidenceId` and a ready-to-run command. Paste it — the
receipt is Ed25519-signed and checkable by anyone, with no access to your
systems.

```bash
npx @strixgov/verifier@latest <evidenceId>   # → Status: VERIFIED
```

## What happens when you run it — it asks before it acts

**Nothing changes until you confirm the proposed wrap.**

| Stage | What it does |
|-------|--------------|
| **1. Preflight** | Stops first if the repo is production or already governed. |
| **2. Scan** | Finds one irreversible call — a charge, delete, send, or migration. |
| **3. Propose** | Shows you the exact diff and asks you to confirm. |
| **4. Run once** | Wraps the call in `governedAction()` and runs it via the hosted kernel, then signs a receipt. |
| **5. Verify** | Prints the runnable verifier command. |

## The safety guard — why a first run can't go wrong

The preflight (`preflight.py`) scans the repo **before** anything is wrapped or
run, and fails **closed**:

- **STOP (exit 3)** — production markers (`sk_live_`, `.env.production`, real
  deploy domains) or existing governance (`governedProcedure`, evidence tables,
  Canonical Proof Flow). A scan error also stops. It never fails open.
- **OK (exit 0)** — only an ungoverned, non-production repo gets wired.

## Good to know

- **One action at a time.** Re-run `/strix-wire` to govern another call site.
- **Offline degrades honestly.** If the network to `www.strixgov.com` is
  blocked, it still scans and wraps but prints an *unsigned* evidence id and no
  verify command — it never fakes a "VERIFIED".
- **Local mode is real, not a mock.** The sandbox credential produces a genuine,
  hosted, kernel-evaluated, signed decision — the same verifier confirms it.

See [`README.md`](./README.md) for the full skill reference, the
`governedAction()` contract, and the capability-ID table.
