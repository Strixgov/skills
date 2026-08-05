# Changelog

All notable changes to `@strixgov/verifier` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.20.0] — 2026-07-22

### Added

- **`strix-verify disclosure <bundle.json> [--jwks <path>]` — independent
  selective-disclosure bundle verification** (`src/disclosure.mjs` +
  exported `verifyDisclosureBundle`). Verifies a `run_commitment_v1`
  disclosure bundle offline: re-derives the RFC 6962 Merkle root from each
  disclosed leaf + its inclusion path, checks the commitment's Ed25519
  signature, and re-verifies SE v1-shaped disclosed records through this
  package's own SE v1 path. **Zero shared code with the producer**
  (`solo-builder-core/src/run-commitment-v1.ts`): its own
  SCJ-v1-compatible canonicalization and its own Merkle walk, so agreement
  is a cross-implementation conformance result, not a shared-library
  tautology. Locked against the producer's golden vectors by
  `test/disclosure.test.mjs`.
  - **Honesty boundaries, structural.** Every result carries
    `completeness: "NOT_PROVEN"` — a commitment root proves inclusion +
    consistency of the presented slice, never that the slice is the whole
    run. Without `--jwks` the verdict is capped at `UNVERIFIABLE`, never
    `INVALID` (SD-5). Planted `verified` fields anywhere in the bundle are
    ignored — validity is always re-derived (SD-4). The CLI prints the
    completeness line and the no-JWKS cap on every run, and exits 0 only on
    `VERIFIED` (3 on `UNVERIFIABLE`, 1 on `INVALID`).
  - Part of the Verifiable Traces workstream (strix-platform
    `docs/strategy/traces-as-control-surface-v1.md` +
    `specs/selective-disclosure-traces-scope-v1.md`). The
    selective-disclosure substrate is verified end-to-end over production
    records; a public "share slices with counterparties" claim still gates
    on a first real cross-party disclosure.

## [1.19.1] — 2026-07-13

### Fixed

- **Defensive CBOR parsing in the MC-1 SCITT (COSE) verifier
  (`src/mcp-scitt.mjs`).** The minimal CBOR reader silently coerced
  out-of-bounds reads (`buf[off]` → `undefined` → `0`) on empty/truncated
  input, so a malformed COSE message fell through to `NOT_COSE_SIGN1` instead of
  the precise `MALFORMED_CBOR`. `decode` now bounds-checks up front and on every
  length read (uint8/16/32, byte/text strings), so truncated input fails as
  `MALFORMED_CBOR`. **No behavior change for valid or already-rejected inputs**
  — the verifier was already fail-closed (never a false VERIFIED); this only
  sharpens the reason code and hardens the parser against untrusted bytes.
  Locked by `test/mcp-scitt-golden-vectors.test.mjs` (empty / lone-tag /
  mid-message truncation → MALFORMED_CBOR). Found by a 360 hardiness review.

## [1.19.0] — 2026-07-12

### Added

- **`strix-verify proof export <evidenceId>` — customer-facing offline bundle
  export.** New CLI subcommand + exported `exportOfflineBundle(evidenceId,
  options)` (`src/index.mjs`). Fetches
  `GET /api/public/proof/bundle/<evidenceId>` (live since the 2026-07-10
  trust-anchor go-live) and writes the bundle to disk
  (`evidence_v1_<id>.bundle.json` by default, `-o <path>` to override,
  `--json` to print to stdout instead of writing a file). Deliberately does
  **not** verify — export and verify stay two separate commands, matching
  every other proof surface in this CLI; the follow-up step is
  `node scripts/verify-offline-bundle.mjs <file>` (strix-platform) or the
  offline bundle verifier in `solo-builder-core`. Non-200 responses (501
  pending-trust-anchor, 404 not_found, 422 record_unsigned /
  operational_key_not_attested / signing_key_not_in_jwks) are forwarded with
  their real structured reason — never a fabricated bundle. Closes the CLI
  half of `docs/architecture/offline-proof-bundle-v1.md` §"Export surface"
  (the Console "Download proof bundle" button is the remaining half). Tests:
  `test/offline-bundle-export.test.mjs` (real local HTTP server, no mocking
  library, same pattern as the CT verifier's E2E tests).

## [1.18.0] — 2026-07-09

### Added

- **MC-1 → SCITT Signed Statement (COSE_Sign1) verifier (E2 profile).** New
  zero-dep, verify-only path: `verifyMcpScittStatement(bytes, { resolveKey })`
  plus `detectMcpProofForm(bytes)`, `MCP_SCITT_PROFILE`, `MCP_PROOF_CTY`,
  `MCP_SCITT_REASONS` (`src/mcp-scitt.mjs`). Verifies a governed-tool-action
  record encoded as a COSE_Sign1 with protected-header
  `typ=application/mcp-proof-scitt+cose`, resolving the key through the caller's
  single trust-root path. Locked by `test/mcp-scitt-golden-vectors.test.mjs`
  against the byte-locked corpus `conformance/corpus/mcp_proof_scitt_v1/` — this
  verifier is now a THIRD independent implementation over that corpus (agreeing
  with the Node reference + the zero-shared-code Python impl).
- **Gated:** verifying the format is a capability, not a claim. This package
  makes **no** public "SCITT-conformant" claim — that remains gated on IANA
  media-type registration + the THREAT-MODEL §9 row
  (`docs/security/scitt-public-claim-gate.md`). Additive; no existing path
  changed. (Re-versioned from the original 1.17.0 branch after `main` took
  1.17.0 for the #1628 kid-union fix.)

## [1.17.0] — 2026-07-09

### Fixed

- **Union exact + case-insensitive kid candidates (issue #1628).** The 1.16.0
  case-insensitive resolution (issue #1306) still short-circuited on the first
  *exact* kid match. A production JWKS misconfiguration exposed the gap: the
  endpoint served a **wrong** key under the exact (uppercase `strix-PROD-2026-05`)
  kid a cohort of records carried, AND the **correct** signer key under the
  canonical lowercase kid. Because the exact match won and returned only the wrong
  key, every record in that cohort verified as `SIGNATURE_INVALID` even though its
  key was actually served. `resolveJwksByKid` now **unions** the exact matches
  with the case-variant matches (exact preferred first, case-variants appended)
  instead of returning early, so a wrong-but-exact entry can no longer shadow the
  correct case-variant. RFC 7517 declares `kid` a hint, not a unique index, so
  multiple candidates under one case-folded kid is expected; the verifier already
  tries each candidate and accepts on the first that validates, and an extra
  non-matching key is harmless. This changes key *selection* only — kid casing
  never enters the signed canonical payload, so canonical bytes and signature
  checks are untouched. The redacted-suffix branch is unchanged (YYYY-MM digits
  carry no case). Regression coverage in `test/kid-case-insensitive.test.mjs`
  (the "wrong-but-exact kid does NOT shadow the correct case-variant" case).

## [1.16.0] — 2026-06-26

### Fixed

- **Case-insensitive kid resolution (issue #1306).** A historical signer-config
  defect minted ~727 production records under an uppercase env segment in the
  kid (`strix-PROD-2026-05`) while the JWKS endpoint only ever advertises the
  canonical lowercase form (`strix-prod-2026-05`). The verifier's first-match
  resolver returned zero candidates → "Key not found in JWKS" → `UNVERIFIABLE`
  for every such record. `resolveJwksByKid` now falls back to a case-insensitive
  kid match (between the exact match and the redacted-suffix branch), bringing
  the verifier into parity with the runtime resolver
  (`apps/strix-console/src/lib/signing.ts` `getPublicKeyJwks`), which already
  matched case-insensitively. The kid casing never enters the signed canonical
  payload — it only selects which public key to try — so this changes key
  *selection* only; canonical bytes and signature checks are untouched. Exact
  matches still take precedence, and kid collisions still return all candidates.

### Added

- `resolveJwksByKid` is now exported (pure helper) so the resolution contract is
  directly testable. Regression coverage in `test/kid-case-insensitive.test.mjs`.

## [1.15.0] — 2026-06-18

### Added

- **Independent rule-9 coverage for TM-1 (`trust_mark_grant_v1` 0.7.0).**
  `verifyTrustMark` / `strix-verify trustmark` now re-derive coverage themselves
  instead of echoing the server's advisory: they fetch the licensee heartbeat
  from the grant's **signed** `surface_origin`, verify it against the grant's
  **signed** `heartbeat_key`, and check freshness + policy-match against the two
  newly **signed** comparands — `kernel_policy_hash` and `coverage_window_seconds`
  (the grant payload grows 12 → 14 fields, contract 0.7.0). The verdict trusts
  nothing but the Strix authority signature already checked at rules 1–8 plus the
  licensee heartbeat-key custody. New export `resolveTrustMarkCoverageFromGrant`;
  new `COVERAGE_STATUS` + `TRUST_MARK_WELL_KNOWN_HEARTBEAT_PATH`; new CLI flag
  `--no-coverage` (grant-only / offline). The CLI prints the coverage line as
  "independently re-derived" and **names the residual trust boundary** (a holder
  of the licensee key can emit fresh heartbeats with a dead kernel — TEE
  attestation is out of scope), never "trust nothing".
- Conformance corpus regenerated to **21 vectors** (14-field payload; +2
  construction negatives: invalid `kernel_policy_hash`, non-positive
  `coverage_window_seconds`). New suite `test/trust-mark-coverage.test.mjs`
  (independent resolver covered/not_covered/unavailable + 0.6.0↔0.7.0 schema
  tolerance), all real Ed25519, no network.

### Changed

- **Transitional 0.6.0 ↔ 0.7.0 schema tolerance.** This verifier accepts a
  14-field (0.7.0) grant AND the single pre-existing 12-field (legacy 0.6.0)
  grant, so publishing 1.15.0 does not break the live badge in the window before
  that grant is re-minted (publish-then-re-mint, the publish-then-flip
  discipline). A legacy grant verifies rules 1–8 but has no signed comparands, so
  its coverage stays **server-advisory** and the CLI says so (`coverageIndependent:
  false`) — the honest interim state until re-mint. The comparand pair is
  present-together (0.7.0) or absent-together (legacy); exactly one present, or a
  malformed comparand, is a schema failure. This tolerance is removed at schema
  freeze.

## [1.14.0] — 2026-06-17

### Changed

- **TM-1 capability promoted RESERVED → ACTIVE (ADR-029 §6).**
  `TM1_CAPABILITY_STATUS` is now `"ACTIVE"`, so `verifyTrustMarkGrant` /
  `verifyTrustMark` / `strix-verify trustmark` treat TM-1 as active by default:
  a fully-valid grant with fresh rule-9 coverage now reports **VERIFIED**
  instead of `tm1_capability_not_active`. This is published in lockstep with the
  runtime `STRIX_TRUST_MARK_V1` flip so the live badge and this independent
  verifier agree — a badge reading GREEN while the published CLI reported
  "not active" would be the exact overclaim the capability gate exists to
  prevent. **Behavior change, not an API change:** the rule-4 fail-closed logic
  is unchanged — it still fires for `capability_id !== "TM-1"` and when a caller
  explicitly passes `capabilityActive: false`; ACTIVE is simply the new shipped
  default. No signed bytes, canonical forms, signatures, or golden vectors
  change (capability status is a verifier config, not part of the signed
  payload — the corpus already verifies with `capabilityActive: true`).

### Note

- The cross-repo companion is the schema authority: `tarshann/solo-builder-core`
  must promote TM-1 RESERVED → ACTIVE in its capability registry + corpus README
  "Conformance contract" point 5, mirroring this release.

## [1.13.0] — 2026-06-16

### Added

- **TM-1 rule 10 (revocation) — `trust_mark_revocation_list_v1`.** The
  grant_id-keyed, authority-signed revocation surface (ADR-029 §8). New exports:
  `buildTrustMarkRevocationPayload`, `signTrustMarkRevocationList`,
  `parseTrustMarkRevocationList`, `verifyTrustMarkRevocationSignature`,
  `resolveGrantRevocation` (tri-state, fail-closed: a missing/malformed/wrong-key
  list → `unavailable`, never a silent `not_revoked`). Nested envelope
  `{ payload, signature, kid }`, hex Ed25519 over SCJ v1 (the grant's encoding).
- **`strix-verify trustmark --revocations <url>`** + automatic rule-10 check
  against `…/api/public/proof/trustmark/revocations`. Opt-in: a 404 at the
  default endpoint means "no source configured" (rule skipped); an explicit
  `--revocations` that can't be fetched/verified is `tm1_revocation_check_unavailable`.
  Locked by `test/trust-mark-revocation.test.mjs` (round-trip + tri-state +
  rule-10 integration).

### Note

- `TM1_CAPABILITY_STATUS` stays `"RESERVED"` — promotion to ACTIVE (+ the
  republish that makes the CLI read VERIFIED) is the separate ADR-029 §6 flip.

## [1.12.0] — 2026-06-16

### Added

- **`strix-verify trustmark <grantId>` — independent Consumer Trust Mark (TM-1)
  verification.** Fetches the published `trust_mark_grant_v1` grant from
  `GET /api/public/proof/trustmark/<grantId>` and re-derives the verdict with the
  verifier's OWN SCJ v1 canonicalization + Ed25519 check — zero shared code with
  the producer. Cross-repo TS port of the schema authority
  (`solo-builder-core` ADR-029): the 10 fixed-order rules
  (`schema → signature → jwks_resolution → capability → mark_class →
  surface_origin → heartbeat_key → validity_window → coverage → revocation`)
  and the 16 `tm1_*` reason codes, with tri-state opt-in coverage (rule 9) and
  revocation (rule 10) and the rule-6 grant/surface binding cross-checks. New
  exports: `verifyTrustMarkGrant` (pure, offline), `verifyTrustMark`
  (fetch-and-verify), `renderTrustMarkBlock`, `ed25519PublicKeyFromRawHex`,
  `TM1_REASON`, `TM1_RULE`, `TM1_CAPABILITY_STATUS`.
- **Conformance-locked to `vectors/trust_mark_grant_v1/`** (19-vector corpus):
  every positive vector's `canonical_bytes_hex` is reproduced byte-for-byte,
  every verify-time negative emits the named `failing_rule` + `reason`, and a
  **real Ed25519 vector** (`pos-07`) is checked against the pinned public key
  (`test/trust-mark-v1-golden-vectors.test.mjs`).

### Note

- **TM-1 is RESERVED.** `TM1_CAPABILITY_STATUS` ships `"RESERVED"`, so `trustmark`
  honestly reports `tm1_capability_not_active` (rule 4) for every grant until the
  ADR-029 §6 promotion — the mirror of the dormant `STRIX_TRUST_MARK_V1` runtime.

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
