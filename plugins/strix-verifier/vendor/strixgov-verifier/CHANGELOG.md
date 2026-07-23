# Changelog

All notable changes to `@strixgov/verifier` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.11.0] — 2026-06-07

### Added

- **`strix-verify swarm <swarmRunId>` — independent Agent Swarm v1 delegation-graph
  verification.** Fetches `GET /api/public/proof/swarm/<id>` and re-derives the
  swarm integrity verdict with the verifier's OWN SCJ v1 canonicalization,
  Ed25519 edge-signature checks, and SW-2/SW-5 attenuation algebra — zero shared
  code with `@strixgov/sdk`. Verifies each delegation edge's signature against the
  delegator's public Ed25519 JWK, recomputes attenuation root-down (capability
  subset, risk ceiling, scope subset, budget, window containment), enforces
  lineage/depth, and checks SW-4 attribution + task binding per governed action.
  Status vocabulary mirrors the proof surface: `VERIFIED | INVALID | UNVERIFIABLE
  | LEGACY_UNSIGNED` (an unknown delegator key is UNVERIFIABLE, never a false
  INVALID). Reports `agreesWithServer` (does our independent verdict match the
  server's claim?). Offline-capable via `--proof <file>`; `--json` for machine
  output. New exports: `verifySwarm`, `scjCanonicalize`.
- **Conformance lock.** `test/swarm-verifier-conformance.test.mjs` (10 cases)
  pins byte-parity against an SDK-signed golden corpus
  (`test/fixtures/swarm/proof-verified.json`): the SDK signs, the verifier's
  independent SCJ+Ed25519 path verifies. A single-byte drift in canonicalization
  fails the VERIFIED case. Contract: `docs/architecture/agent-swarm-v1.md`.

## [1.10.2] — 2026-05-20

### Fixed

- **Approval-quorum verification: plumb server-provided canonical bytes
  through the per-artifact loop in `verifyApprovalQuorum`.** v1.10.1
  fixed the single-artifact path (`verifyApprovalArtifact({ artifactId })`)
  to prefer `fetched.canonical.serialized` over local reconstruction. But
  the quorum path iterates artifacts from
  `/api/public/decisions/<id>/approvals` and called
  `verifyApprovalArtifact({ artifactPayload: a, ... })` — the
  `artifactPayload` branch had no way to honor server-provided canonical
  bytes and always fell through to `buildApprovalCanonicalPayload(artifact)`.
  Because the quorum endpoint redacts `actorUserId` from its public response, the
  reconstructed canonical bytes used `actorUserId: ""` and produced a
  different hash than the signer signed over. Every artifact in every
  quorum verification returned HASH_MISMATCH; chain continuity
  cascaded-failed because the wrong recomputed hash never matched the
  server's `proofChainHash`.

  Fix is two-sided:
  - **Server (`/api/public/decisions/<id>/approvals`):** each artifact
    in the response now carries a `canonical: { schemaVersion, payload,
    serialized }` block matching the single-artifact endpoint's shape.
  - **Client (`verifyApprovalArtifact`):** the `artifactPayload` branch
    now honors `input.canonicalSerialized` (preferred) and
    `input.canonicalPayload` (fallback). `verifyApprovalQuorum` plumbs
    `a.canonical.serialized` and `a.canonical.payload` through per
    artifact.

  Pre-1.10.2 verifiers reported every artifact in every quorum as
  HASH_MISMATCH against production; 1.10.2 verifies them correctly. If
  you are upgrading from 1.10.0/1.10.1 and have quorum verifications
  that returned HASH_MISMATCH or chainContinuous=false despite all
  individual `/api/public/approval-artifact/<id>` calls returning
  VERIFIED, re-run them against 1.10.2.

- **CLI: surface per-artifact detail on quorum failure.** When any
  artifact in a quorum fails to VERIFY, the CLI now prints a compact
  per-artifact table with the verification status and the error
  message (when present). Failed-chain output now also points at the
  diagnostic next step (re-fetch + re-run vs hash mismatch). Previously
  the CLI showed only the four summary numbers, leaving auditors with
  no way to tell why a quorum failed.

- **README repository links** now point at the public source mirror at
  `github.com/Strixgov/strix` instead of the internal-source URLs that
  shipped in the v1.10.0 and v1.10.1 npm tarballs. CLI behavior, signed-
  payload canonicalization, JWKS handling, and the verifier's
  trust-path posture are unchanged — this is a docs-hygiene patch for
  the npm-shipped README. v1.10.0 and v1.10.1 have been deprecated on
  npm with a pointer to upgrade. v1.9.x and earlier 1.x lines were
  unaffected.

### Added

- `canonicalSerialized` and `canonicalPayload` options on
  `verifyApprovalArtifact`'s `artifactPayload` branch — the offline /
  programmatic-composition counterpart of the network path's
  `directCanonical` logic. Use these when you have the original signed
  bytes already and want to skip local reconstruction.

## [1.10.1] — 2026-05-18

### Fixed

- **Approval-artifact verification: use server-provided canonical bytes
  directly instead of reconstructing from the `artifact` display projection.**
  The `/api/public/approval-artifact/:id` response splits the artifact data
  into three sections: `artifact` (display projection — missing
  `actorUserId` and `schemaVersion`), `canonical.payload` (full 9-field
  canonical object), and `canonical.serialized` (the exact JSON bytes the
  signer signed over). Prior to this release the verifier reconstructed
  canonical bytes from `artifact` only, which omitted `actorUserId` and
  produced different bytes than the signer signed over — every approval
  artifact returned `HASH_MISMATCH` against the hosted proof API despite
  the server-side recompute showing `canonicalHashMatches: true`.

  Fix: prefer `canonical.serialized` when present, fall back to
  `JSON.stringify(canonical.payload)`, fall back to local reconstruction
  from `artifact` only when the API didn't include either. Same pattern
  as v1.10.0's `signedPayload`-direct path for evidence records.

  Resolves Mode C external-verifier drift for approval artifacts.
  Pre-1.10.1 verifiers reported every `sales_approval_artifacts` row as
  `HASH_MISMATCH`; 1.10.1 verifies them correctly without server-side
  data changes.

  If you are upgrading from 1.10.0 and earlier and have approval
  artifacts that returned `HASH_MISMATCH`, re-run them against 1.10.1.
  They should report `VERIFIED`. No data was lost; the prior versions
  just couldn't reconstruct the canonical bytes correctly from the
  hosted approval-artifact response.

### Changed

- `repository.url` in `package.json` corrected from `github.com/Strixgov/strix`
  to lowercase `github.com/strixgov/strix`. GitHub URLs resolve
  case-insensitively but the canonical lowercase form is the one the
  organization publishes and the one that round-trips cleanly through
  npm package metadata and downstream tooling. (Promoted from the
  `Unreleased` section into this release.)

## [1.10.0] — 2026-05-18

### Added

- `visual` subcommand and programmatic `verifyVisual()` / `extractVisualMetadata()` exports for verifying Visual Artifacts v1. Lets callers check whether an attached visual was produced by the holder of the Strix signing key and surfaces the bound metadata. Pairs with the `verify.strixgov.com` hosted verifier shipped in `#1064`.

### Fixed

- **Verify against `signedPayload` directly when present.** When the
  proof API returns the original signed bytes via `proof.signedPayload`,
  the verifier now uses those exact bytes for Ed25519 verification
  instead of reconstructing canonical bytes from individual fields.
  Reconstruction is fragile across schema evolution — schemaVersion
  number vs string, regulatoryContext key ordering, sourceApp
  discriminator — and any divergence between signer and verifier causes
  false-negative `COMPLIANCE_VIOLATION` on records that are
  cryptographically intact.

  Academy's `/api/proof/<id>` (post-2026-05-18) returns
  `proof.signedPayload` with unwrapped canonical bytes. Older API
  versions and the Console verify endpoint are unaffected — the existing
  reconstruction path with Academy/Console discriminator is retained as
  fallback.

  Resolves Mode C external-verifier remediation for the 2026-05-17
  launch baseline. Internal verification (Academy `/api/proof`) already
  verified 100% of tested records; this brings external
  `@strixgov/verifier` into agreement.

## [1.9.4] — 2026-05-15

### Changed

- **Network-error messages now include the URL and the underlying cause.**
  Previously a proxy block, DNS failure, or TLS-intercept failure produced
  the bare `Error: fetch failed`, which gave the operator no signal about
  what to fix. The CLI now reports e.g.
  `Network error fetching https://www.strixgov.com/api/proof/5686 [ENOTFOUND]: getaddrinfo ENOTFOUND www.strixgov.com — DNS lookup failed for www.strixgov.com. Check your resolver and any corporate DNS overrides.`
  The same enrichment applies to all five outbound `fetch()` sites:
  proof API, JWKS, approval artifact, approval quorum, and Console verify.

- **HTTP-status error messages now include the URL.**
  `Proof API fetch failed: HTTP 503` becomes
  `Proof API fetch failed: HTTP 503 (https://www.strixgov.com/api/proof/5686)`
  so an operator copying the error into a bug report doesn't have to
  reconstruct what was hit.

- **CLI prints a troubleshooting pointer on network failure** when the
  human output path runs. Points at the README's Troubleshooting section
  and shows the `--proof-base` / `--jwks-base` override pattern for users
  behind corporate proxies who need to verify against a mirror they
  control.

- **`--json` payload includes `attemptedUrl` on network failure** so
  machine consumers don't have to parse the error message to discover
  which host was being contacted.

### Documentation

- README's "How verification works" section expanded from 3 steps to 6,
  matching what `strix-verify --help` already documents in detail. The
  README was a downgrade from the help text; that's now resolved.
- README's Troubleshooting table grew four rows for the common
  network-failure modes (ENOTFOUND, ECONNREFUSED, ETIMEDOUT, TLS
  verification). Explicit guidance: never set
  `NODE_TLS_REJECT_UNAUTHORIZED=0` to work around a TLS-intercepting
  proxy — that disables TLS validation globally and breaks the
  verifier's trust path.

## [1.9.3] — 2026-05-15

### Fixed

- **`fetchEvidence` no longer promotes top-level `evidenceId` over
  `fields.evidenceId`.** Same bug class as the 1.9.2 redacted-kid fix.
  The `/api/public/proof/<id>` response's top-level `evidenceId` is the
  URL path parameter the caller used to look up the record. When the
  caller looks up by `evidenceHash` (`/api/proof/<hash>`), the top-level
  value is the hash string, NOT the actual evidenceId.

  Pre-fix flow:
  1. CLI flattens response, top-level `evidenceId` (= hash string)
     overrides `fields.evidenceId` (= actual numeric ID).
  2. `buildCanonicalPayload` for Academy form calls
     `coerceEvidenceIdToNumber(record.evidenceId ?? record.id, 0)`.
  3. The hash string can't be parsed as a number → fallback to 0.
  4. Canonical bytes contain `"evidenceId":0`, signed canonical
     contains `"evidenceId":42` (or whatever the actual ID is).
  5. Signature fails for every hash-lookup verification.

  Fix: remove the `evidenceId` promotion in the flattener. `fields.evidenceId`
  is now the only value the verifier uses for canonical reconstruction.

  Caught by hand-verifying record 42 (Academy's `cron.merchDrops` from
  2026-03-20, the canonical README example) after a full re-sign + drain
  cycle confirmed timestamps + tenantId aligned correctly but signature
  still failed. The diagnostic dump showed `evidenceId:0` in the rebuilt
  canonical while Academy's stored signed_payload had `evidenceId:42`.

### Added

- `test/redaction-promotion.test.mjs` extended with a third test that
  pins the evidenceId non-promotion. The existing two tests still cover
  the kid case from 1.9.2.

## [1.9.2] — 2026-05-14

### Fixed

- **`fetchEvidence` no longer promotes the redacted top-level `signingKeyId`
  over `fields.signingKeyId`.** The `/api/public/proof/<id>` response carries
  two `signingKeyId` values: `fields.signingKeyId` (full kid, e.g.
  `strix-prod-2026-05` — the bytes that were signed) and a top-level
  `signingKeyId` (Gap-5 redacted form `strix-***-2026-05` — for display).
  Prior to this release the CLI's response-flattener promoted the redacted
  top-level value, overriding the bytes-correct `fields.signingKeyId`.
  `buildCanonicalPayload` then received the redacted kid, so the canonical
  bytes the verifier hashed and signature-checked were not the bytes the
  signer signed over. Result: every signed record from the hosted proof
  surface returned `COMPLIANCE_VIOLATION` since Gap-5 redaction shipped
  (April 2026). The cross-verify golden test did not catch this because
  it constructs `SignedFields` directly and bypasses `fetchEvidence`.

  The fix is a one-line change: remove the `signingKeyId` promotion in the
  Strix Console response shape branch. `fields.signingKeyId` is now the
  only kid the verifier sees, matching the signed bytes.

  If you are upgrading from ≤ 1.9.1 and have any records that returned
  `COMPLIANCE_VIOLATION`, re-run them against 1.9.2 — they should report
  `VERIFIED` if signed correctly. No record data was lost; the prior
  versions just couldn't reconstruct the canonical bytes correctly from
  the hosted proof response.

### Added

- `test/redaction-promotion.test.mjs` — regression test that exercises
  the full `fetchEvidence` flatten path and asserts:
  1. Canonical bytes with the full kid differ byte-for-byte from canonical
     bytes with the redacted kid (proves the verifier MUST use the full
     form).
  2. The post-1.9.2 flatten preserves `record.signingKeyId` as the full
     kid, not the redacted form.

  Catches the 1.9.2 bug class immediately on any future regression.

## [1.9.0]

### Added
- Approval-artifact subcommands: `approval <artifactId>` and `quorum <decisionId>`.
- Redacted-kid support: `resolveJwksByKid` matches `strix-***-YYYY-MM` against
  the full JWKS by YYYY-MM suffix.
- Multi-key kid collision handling: when more than one JWK shares a kid
  (legitimate during cross-environment key rotation), verification tries each
  candidate key before returning `SIGNATURE_INVALID`.
- Linked-attestation surface via `<evidenceId> --include-attestations`.

## [1.7.0]

### Added
- `verifyConnectedWireEnvelope` for verifying inbound `@strixgov/tool-gateway`
  v0.3-experimental connected-mode wire envelopes.

## [1.6.0]

### Added
- Tool-gateway receipt verification (`receipt <path>`) and chain verification
  (`chain <path>`) for `@strixgov/tool-gateway` v1 + v2 receipts.
