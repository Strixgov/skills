# Strix Proof Room — Claude Code plugin

Render a Strix **Proof Room** manifest into a self-verifying HTML page, right
from your Claude Code session. Each evidence record becomes a live
`<strix-verify>` embed that re-derives its own verdict in the browser — the
renderer shows proof, it never decides a verdict. No Strix account, SDK, or API
key.

## Install

```
/plugin marketplace add Strixgov/skills
/plugin install strix-proof-room@strixgov
```

## Use — slash command

```
/strix-proof-room --example                      # render the bundled minimal example
/strix-proof-room room.json --out room.html      # render your own manifest to a file
/strix-proof-room --manifest room.json           # print HTML to stdout
```

## Use — CLI

The same renderer is a plain Node script (zero dependencies):

```
node bin/strix-proof-room <manifest.json> [--out room.html] [--title "..."]
node bin/strix-proof-room --example --out room.html
```

Exit codes: `0` rendered · `1` invalid/unreadable manifest · `2` usage error.

## What's in the box

| Path | What it is |
|---|---|
| `commands/strix-proof-room.md` | The `/strix-proof-room` slash command. |
| `bin/strix-proof-room` | Node CLI: manifest JSON → standalone HTML page. |
| `lib/drop-adapter.mjs` | Verbatim MIT `@strixgov/proof-fabric-drop-adapter` — renders proof, never determines it. |
| `examples/proof-room-minimal.json` | A complete, valid minimal manifest (record 5686). |

## Manifest contract (what makes a room renderable)

A room manifest is a small JSON object. The renderer enforces the same
binding rules the Strix Console enforces before it will publish a room:

- `proofRoomVersion: "1.0"`, a slug `roomId` and `recipientScope`.
- `status: "ACTIVE"` and a future `expiresAt` (a room is bounded; an expired or
  revoked room renders a closed notice, and the records stay verifiable).
- `evidenceReferences[]` — each `{ sourceType, sourceId, verificationUrl }`,
  where `verificationUrl` is an `https://www.strixgov.com/...` URL.
- `claims[]` — each `{ claimId, status, sourceEvidenceIds[] }`:
  - `PROVEN` must bind **≥1** declared evidence id;
  - `ROADMAP` must carry **zero** evidence (it is never rendered as live);
  - every referenced evidence id must appear in `evidenceReferences`.
- `analyticsPolicy: { consentRequired: true, rawPiiAllowed: false }`.

See `examples/proof-room-minimal.json` for a working starting point.

## Scope

This plugin **renders** a manifest locally. Publishing a governed, signed Proof
Room — a `manifestHash` content-address plus a signed `decision_evidence`
receipt bound to the publish — is a separate, authenticated step on the Strix
Console (Proof Fabric). To verify any one record independently, use the
`strix-verifier` plugin or `npx @strixgov/verifier@latest <evidenceId>`.

The bundled adapter is a verbatim copy of the MIT-published
`@strixgov/proof-fabric-drop-adapter` — never a re-implementation. Source:
<https://github.com/Strixgov/strix>.
