# strix-wire — first-time quickstart

Govern one real action in about **two minutes**. strix-wire finds one
irreversible call in your code, wraps it in governance, runs it once, and hands
you a **cryptographically signed receipt anyone can verify** — with no Strix
account, and no data leaving your machine except the one evaluation request.

## Plain English first — what do these words actually mean?

You don't need any background in this to use strix-wire. Three words carry
almost all the meaning:

| Word | What it actually means |
|------|-------------------------|
| **Governing** an action | Before something consequential happens in your app — a card gets charged, a row gets deleted, an email goes out — a rule-checker looks at it first and decides **allow**, **deny**, or **ask a human**. Whatever it decides gets written down, time-stamped, with a signature no one can forge afterward. |
| **Wrapping** a call | Taking the *one line* of your existing code that does the consequential thing, and putting a thin layer around it: check permission → do the real thing (only if allowed) → write down proof. Your code still does exactly what it did before. Nothing about the business logic changes. |
| What governing an action **gives you** | A tamper-proof, independently checkable record that says "this exact action happened, at this time, and it was allowed." Anyone — an auditor, a customer, a curious engineer — can check that record themselves with a free public tool, without trusting your word, your logs, or your database. |

If you remember nothing else: **strix-wire doesn't change what your code does.
It adds a checkpoint in front of one risky line, and a receipt behind it.**

## The flow, at a glance

```
 YOUR CODEBASE
      │
      ▼
 ① SCAN      Looked through your files for anything hard to undo — a
             payment, a delete, an email/SMS send, a schema migration.
      │
      ▼
 ② FOUND     One clear candidate, e.g.:
             src/billing/charge.py:47 — a Stripe card charge
             (plus a running count of every OTHER risky spot found but
             left untouched — see "the map" in your results)
      │
      ▼
 ③ PROPOSE   Shows you the exact one-line diff. Nothing is changed yet.
             You say yes / no / pick a different one.
      │
      ▼
 ④ WRAP      Adds the permission-check + proof-writer around that ONE
             line. Everything else in your code is untouched.
      │
      ▼
 ⑤ RUN ONCE  Executes it for real. The check happens BEFORE the action —
             if it's denied, the original action never runs at all.
      │
      ▼
 ⑥ PROOF     A signed record, checkable by anyone:
             npx @strixgov/verifier@latest <id>   →   Status: VERIFIED
```

Steps ①–③ never touch your files. Only ④ writes anything, and only after
you've said yes at ③.

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

## FAQ

**Did this change what my code actually does?**
No. The one line you approved still does exactly what it did before — same
arguments, same behavior. All that's added is a permission check in front of
it and a proof-writer behind it.

**What happens if Strix says no?**
The original action **never runs**. No charge, no delete, no email — nothing.
You'd see a "denied" or "needs approval" message in place of the result.

**Do I need to sign up for anything?**
No. Sandbox Mode auto-provisions a short-lived, scoped credential the first
time it runs. Offline Mode needs nothing at all, not even a network
connection — see the mode comparison in [`README.md`](./README.md).

**Is any of my data or code sent somewhere?**
Only the one action's non-secret parameters (amounts, IDs — never API keys,
tokens, or card numbers) go to the hosted kernel, and only in Sandbox Mode.
Offline Mode sends nothing anywhere, ever.

**What's this "proof" / "evidence record" actually good for?**
It's a signed, timestamped statement — "this action happened, at this time,
and was approved" — that anyone can check themselves with a free, independent
tool (`npx @strixgov/verifier`), without trusting your word, your database, or
Strix's word either. Useful for audits, compliance evidence, customer trust,
or just knowing exactly what an automated agent did and when.

**What about the OTHER risky spots you found but didn't touch?**
strix-wire only ever wraps the **one** call you approved. Everything else it
found is reported as a count ("…and 14 more ungoverned action points") so you
know the size of the gap — nothing else is modified. Run `/strix-wire` again
to wrap the next one, or `solo govern coverage` for the full map.

**Can I undo this?**
Yes — it's a normal code change. `git diff` shows exactly the helper file
added and the one call site rewritten; `git checkout -- <file>` (or your
usual revert) removes it like any other edit.

**What's the difference between "Sandbox Mode" and "Offline Mode"?**
Sandbox Mode talks to the real, hosted Strix service (no account needed) and
gets a record Strix itself vouches for. Offline Mode never leaves your
machine — a key you hold signs the record instead, which proves it's
tamper-evident but not that a third party (Strix) witnessed it. Pick Offline
Mode if you have no network access or don't want any hosted dependency at
all. Full comparison table in [`README.md`](./README.md).

## Next steps — now that you have one proof

1. **Check the proof yourself.** Run the printed
   `npx @strixgov/verifier@latest <id>` command — it's independent of this
   skill and of Strix's own servers vouching for themselves.
2. **Wrap the next risky spot.** Re-run `/strix-wire` — it will find and
   propose the next candidate.
3. **See the whole map.** `solo govern coverage` (from `solo-builder-core`)
   reports what fraction of your risky action points are governed vs. not —
   a measurement, not a proof, but useful for prioritizing.
4. **Let automated agents run this safely.** `solo kernel approve
   <capability_id>` pre-authorizes future automated runs of this exact
   action so an agent doesn't need a human to click "yes" every time.
5. **Ready for more than a demo?** Sign up for a real Strix account so your
   own risk policy — not the sandbox default — governs future runs.

See [`README.md`](./README.md) for the full skill reference, the
`governedAction()` contract, and the capability-ID table.
