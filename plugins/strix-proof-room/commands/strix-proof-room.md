---
description: Render a Strix Proof Room manifest into a self-verifying HTML page (live <strix-verify> embeds).
argument-hint: <manifest.json> [--out room.html] | --example
---

# /strix-proof-room

Render a Strix **Proof Room** manifest to a standalone HTML page through the
bundled MIT DROP adapter. The page embeds one live `<strix-verify>` per evidence
record — each re-derives its own verdict in the browser. The adapter renders
proof; it never decides a verdict. No Strix account, SDK, or API key.

## What to do

The user invoked `/strix-proof-room $ARGUMENTS`.

1. Resolve the manifest path from `$ARGUMENTS`:
   - If it contains `--example` (or is empty), use the bundled example.
   - Otherwise treat the first non-flag token (or the value after `--manifest`)
     as a path to a room-manifest JSON file.
2. Run the bundled renderer:

   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/bin/strix-proof-room" $ARGUMENTS
   ```

   - With `--out <file>` it writes the HTML there; otherwise it prints HTML to
     stdout (pipe it to a file: `... --out room.html`).
   - To render the bundled minimal example:
     `node "${CLAUDE_PLUGIN_ROOT}/bin/strix-proof-room" --example --out room.html`

3. Report the result:
   - On success (exit 0): say where the HTML was written (or that it printed),
     and that opening it shows the room with a live verify embed per record.
   - On a validation failure (exit 1): relay the exact `strix-proof-room: ...`
     message. Common causes are real contract violations, not tool bugs:
     - a `PROVEN` claim with no `sourceEvidenceIds` (must bind ≥1 record),
     - a `ROADMAP` claim that carries evidence (roadmap is never live),
     - a claim referencing an evidence id not declared in `evidenceReferences`,
     - a `verificationUrl` that is not `https://www.strixgov.com/...`,
     - `analyticsPolicy` missing `consentRequired: true` / `rawPiiAllowed: false`.
   - On usage error (exit 2): show the usage line.

## Manifest shape (minimal)

A renderable manifest needs `status: "ACTIVE"`, a future `expiresAt`, at least
one `evidenceReferences` entry pointing at a canonical Strix verification URL,
and claims bound to those references. See `examples/proof-room-minimal.json` in
this plugin for a complete, valid example.

## Notes

- This command only **renders** a manifest locally. Publishing a governed,
  signed Proof Room (with a `manifestHash` content-address and a signed
  `decision_evidence` receipt) is a separate, authenticated step on the Strix
  Console — see the Proof Fabric docs.
- To verify any single record yourself, use the `strix-verifier` plugin or
  `npx @strixgov/verifier@latest <evidenceId>`.
