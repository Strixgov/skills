---
description: Exercise a wrapped capability — allowed, approval-required, and tamper/bypass scenarios.
argument-hint: "--file <path>"
---

# /strix-test — prove the wrap actually governs

Run three controlled checks against a wrapped call site so the user sees
governance behave before trusting it in production.

## What to do

1. **Bypass check (static, always run).** Confirm every call to the wrapped
   capability routes through the boundary — no ungoverned sibling remains:

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/strix_apply.py" --root . $ARGUMENTS
   ```

   Read the "bypass check" line. PASS means the capability reaches ENFORCED;
   OPEN means an ungoverned sibling call still exists and must be wrapped
   first. The check is repo-wide, and it records its own result — `/strix-status`
   will show `enforced` on the next run without you doing anything else.

2. **Allowed + approval-required scenarios (runtime).** If the user has
   `STRIX_API_KEY` + `STRIX_TENANT_ID` set (Connected Mode) or a local kernel,
   run the smallest entry point that hits the wrapped call with **test-safe**
   arguments (Stripe test card, tiny amounts, sandbox targets). Expect:
   - a low-risk capability → `ALLOW` → a real `evidenceId` is printed;
   - a HIGH/CRITICAL capability → `APPROVAL_REQUIRED` → the action does **not**
     run until approved.

   If neither connected mode nor a local kernel is available, say so — do not
   fabricate an evidenceId or a verdict.

   **Record what actually happened**, so it survives to `/strix-status`. Until
   this is recorded the outcome exists only in this transcript, and the next
   command will show the call site at `wrapped`:

   ```bash
   # the deny / approval scenario behaved correctly
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/strix_signal.py" record --root . \
       --kind test --file <path> --line <n> --passed

   # a real signed record came back
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/strix_signal.py" record --root . \
       --kind evidence --file <path> --line <n> --passed --evidence-id <evidenceId>
   ```

   Record a **failure** the same way, without `--passed`. That is not a
   formality: a failing signal revokes an earlier pass, so a regression shows
   up as a demotion instead of a stale green.

   Only record what you observed. If step 2 was skipped, record nothing for it
   — an unrecorded check reads as "not done", which is true, and is the honest
   outcome. Never pass `--evidence-id` for a record you did not see returned.

3. **Tamper is detectable.** Remind the user they can verify any produced
   record independently, and that a tampered payload or flipped signature byte
   is REJECTED by the verifier:

   ```bash
   npx @strixgov/verifier@latest <evidenceId>
   ```

4. Summarize as a table: `ALLOW` · `APPROVAL_REQUIRED` · `BYPASS` · `RECEIPT`.

## Guardrails

- Never run a real-money or production mutation to "complete the test." Use
  staging / test credentials, or stop and tell the user.
- Report what actually happened. If a step was skipped, say it was skipped.
