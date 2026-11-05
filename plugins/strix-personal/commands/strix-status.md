---
description: Show where every action point sits on DETECTED → … → VERIFIED, plus coverage.
argument-hint: "[--include-ai]"
---

# /strix-status — the governance lifecycle of this repo

Render the lifecycle rollup so the user sees progress from detection to
verified governance at a glance.

## What to do

1. Run:

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/strix_status.py" --root . --include-ai $ARGUMENTS
   ```

2. Present the lifecycle histogram and coverage. Explain the states honestly:
   - **DETECTED / WRAPPABLE** — found, not yet governed.
   - **WRAPPED** — a `governed_action()` wrap is present at the call site.
   - **TESTED** — a deny/approval scenario passed, as recorded by `/strix-test`.
   - **ENFORCED** — no ungoverned sibling call exists repo-wide, as recorded by
     the `/strix-apply` bypass check.
   - **VERIFIED** — a real signed record was produced; the report names its
     `evidenceId`.
   - **SUPPRESSED** — explicitly opted out with a stated reason.

3. The scan alone cannot produce the last three. They come from recorded
   runtime signals, and every signal is re-checked against the current code
   before it counts. Read the signal line the command prints:
   - **applied** — the signal still matches the code it was recorded against.
   - **dropped / expired** — the call site changed since. The entry correctly
     falls back to `wrapped`; re-run the check rather than treating the old
     result as still true.
   - **nothing past `wrapped`** — no signals recorded yet. Point at
     `/strix-apply` (enforced) and `/strix-test` (tested, verified).

   `--no-signals` shows the static scan alone. Useful for answering "what does
   the code say, ignoring anything we recorded", not for reporting status.

4. If everything detected is governed, surface the upgrade moment: hosted
   approvals, receipt history, and public proof links come with Connected Mode
   (set `STRIX_API_KEY` + `STRIX_TENANT_ID`). Otherwise point at `/strix-apply`.

## Guardrails

- Coverage counts WRAPPED-or-better plus SUPPRESSED. Never count DETECTED as
  governed.
- Never promote a state yourself. If a signal was dropped as expired, say it
  expired — do not re-assert the earlier result from memory of a previous run.
- The signal journal is unsigned local measurement. `VERIFIED` means a signed
  record was produced and its id recorded here; the record itself is what a
  third party verifies (`npx @strixgov/verifier@latest <evidenceId>`).
