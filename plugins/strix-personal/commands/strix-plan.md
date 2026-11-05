---
description: Propose a capability map + policy for the scanned actions, and which call sites to wrap.
argument-hint: "[--include-ai]"
---

# /strix-plan — map capabilities and propose controls

Turn the scan inventory into a concrete plan: for each consequential action,
what capability it maps to, what control it should get, and what will change.

## What to do

1. Get the structured inventory:

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/strix_scan.py" --root . --include-ai --json $ARGUMENTS
   ```

2. For each **blocking** and **warning** entry, present a row:
   - `capability_id` (e.g. `payment.charge`, `database.delete`, `email.send`, `ai.tool_use`)
   - severity / risk
   - **proposed control**: `CRITICAL`/`HIGH` → approval-required; `MEDIUM` →
     auto-allow with evidence; `LOW` → record-only
   - interception point (file:line)
   - whether it is auto-wrappable (single-line assignment) or needs a manual wrap
   - the `payload` fields you'd capture (non-secret request params only — never
     API keys, tokens, or raw card numbers)

3. Recommend an order: wrap the highest-severity, cleanly-wrappable call site
   first so the user gets a real receipt fast.

4. State clearly what Strix can and cannot enforce here:
   - it can intercept the wrapped call sites in **this** codebase;
   - it cannot govern side effects that never route through `governed_action()`.

5. End by pointing to `/strix-apply --file <f> --line <n>` for the first wrap.

## Guardrails

- Do not modify any files in this step — planning is read-only.
- Use the scanner's suggested `capability_id` verbatim; don't invent new ones.
