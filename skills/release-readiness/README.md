# /release-readiness

The **release lens** of the Strix Governance Review Framework (SGRF v1) — a
Claude Code skill that reviews whether a release/deploy candidate ships as a
**governed, recorded, revocable** decision.

Siblings: `/runtime-governance-review` (system lens) and `/govern-pr` (change
lens). Same 13 SGRF sections, same 4 orthogonal axes — the unit under review is a
release, and the output adds a **GO / GO-WITH-CONDITIONS / NO-GO** readiness call.

**Advisory, not gating.** It informs the release owner; it does not block the
deploy.

## Use it when

- A release/deploy is queued and you want a governance sign-off
- You need to know what *new consequential actions* a release enables
- You want to confirm rollback/revocability before shipping
- A governance feature might be shipping dormant (flag off)

## Invoke

```
/release-readiness v1.9.7
```

## What you get

The canonical 13-section SGRF report, a 4-axis maturity profile (capability vs
governance vs independent verifiability vs runtime enforcement — never blended),
and a readiness call with **release blockers** separated from **post-release
follow-ups**. See `SKILL.md` for the full contract.

## Honest about enforcement

It never gates the deploy or produces a signed record. If a Strix runtime is
present it may *optionally* submit the deploy to the real `evaluate(...)` contract
and fold in the actual verdict + receipt — never fabricated.

## Companions

- `/govern-pr` — feeds §6 (what the release diff newly enables).
- `/runtime-governance-review` — the system-lens counterpart.
- `/strix-wire` — wire one governed, verifiable action end-to-end.
