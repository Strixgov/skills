---
description: Wrap one call site with Strix governance — rollback-safe, shown before it writes.
argument-hint: "--file <path> --line <n>"
---

# /strix-apply — wrap a call site (rollback-safe)

Apply a `governed_action()` wrap to a single call site. The change is **shown
as a diff and confirmed before anything is written**, the file is **backed up**
first, and a **bypass check** runs after.

## What to do

1. Dry-run first to produce the plan + diff (this writes nothing):

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/strix_apply.py" --root . $ARGUMENTS
   ```

   If the call site is multi-line or ambiguous, the script refuses to
   auto-wrap. In that case, wrap it by hand (see the patterns in the README's
   "Manual wrap" section) and keep the candidate at WRAPPABLE. Do not force it.

2. Show the user the diff and ask for explicit confirmation. Confirm that the
   `payload={}` placeholder will be filled with **non-secret** request params
   only.

3. On confirmation, apply it:

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/strix_apply.py" --root . $ARGUMENTS --apply
   ```

   Report the **bypass check** result. If ungoverned sibling calls to the same
   capability remain, the capability is NOT yet ENFORCED — wrap those too.

4. Tell the user how to undo: `/strix-apply --file <f> --line <n> --rollback`
   restores the file from its `.strix-bak` backup.

5. Then point them to `/strix-test` to exercise the wrap.

## Guardrails

- Never write without showing the diff and getting confirmation first.
- Never wrap a call in a test path.
- Never put secrets (API keys, tokens, card numbers) into the `payload`.
- The wrap does not run the action — the user runs it in their own staging.
