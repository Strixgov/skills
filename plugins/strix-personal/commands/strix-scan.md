---
description: Scan the current repo for consequential actions and show the governance lifecycle (read-only).
argument-hint: "[--include-ai] [path]"
---

# /strix-scan — inventory the actions that matter

Run the bundled scanner over the current repository and report what Strix found.
This step is **read-only**: it never wraps or executes anything.

## What to do

1. Run the scanner (zero-install — it uses the plugin's vendored core):

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/strix_scan.py" --root . --include-ai $ARGUMENTS
   ```

   (Drop `--include-ai` if the user only wants irreversible mutations, not AI
   call sites. Add `--json` if you need to reason over the structured result.)

2. Present the report to the user as-is. It now carries its own "How to read
   this" legend and its measurement boundary — **do not restate them in prose.**
   The reader should not need you present to interpret the inventory. Add only
   a one-line read on top:
   - the **headline** (total · coverage · blocking · governed),
   - the top **blocking** action points (HIGH/`error` severity, ungoverned),
   - which capabilities dominate (payments, deletes, sends, AI tool-use…).

3. Be honest about the lifecycle. Every action starts **DETECTED** (or
   **WRAPPABLE**). Nothing is "governed" yet. Do **not** describe a detected
   action as protected — detection is not enforcement.

4. Offer the next step: `/strix-plan` to map capabilities and propose policy,
   then `/strix-apply` to wrap one call site.

## Guardrails

- Never claim coverage the scan didn't establish.
- Test files are intentionally skipped — don't wrap test charges/sends.
- If the scan finds nothing, say so plainly and ask the user to point at a
  specific function; don't invent candidates.
