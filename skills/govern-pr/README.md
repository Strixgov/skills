# /govern-pr

The **change lens of the Strix Governance Review Framework (SGRF v1)** — a Claude
Code skill that reviews a **pull request or diff** for its governance impact, and
the change-scoped sibling of `/runtime-governance-review` (the system lens) and
`/release-readiness` (the release lens). It reports which SGRF sections a change
touches and whether it moves any of the 4 SGRF axes.

**Advisory, not gating.** It never blocks or approves a merge; it gives the human
reviewer a precise, PR-comment-ready read of whether the change moves the
governance posture, and which way.

## Use it when

- Reviewing a PR that touches auth, permissions, policy, deploy, payments,
  deletes, secrets, or any irreversible action
- You want a fast "does this weaken enforcement?" pass alongside normal review
- Gatekeeping a change into a governed codebase

## Invoke

```
/govern-pr --base origin/main --head HEAD
```

Omit the refs and it uses the current branch vs its merge-base with the default
branch, or asks.

## What you get

A one-line **governance impact verdict** (`NONE` / `ADDITIVE` / `NEEDS REVIEW` /
`WEAKENS INVARIANT`), findings tied to changed file:line, an **invariant-impact**
table (strengthened / preserved / weakened per the five execution-control
invariants), and recommendations marked *prompting-only* vs *requires runtime
enforcement*. See `SKILL.md` for the exact process and output contract.

## Honest about enforcement

The review never claims it blocked the merge or produced a signed record — it did
neither. If a Strix runtime is actually present, it may *optionally* submit a
high-impact change to the real `evaluate(...)` contract and fold in the actual
verdict + signed receipt — never a fabricated one.

## Companions

- `/runtime-governance-review` — system-scoped governance review (this skill is
  the change-scoped counterpart).
- `/strix-wire` — turn one finding into a governed, verifiable action end-to-end.
