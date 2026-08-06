# Verifier conformance harness

Proves the vendored `@strixgov/verifier` copy in this plugin behaves
correctly — nothing here re-implements or second-guesses its crypto; every
assertion checks that the vendored copy's own exported functions return
the outcome a conformant verifier must return.

## What's here

| File | Proves |
|---|---|
| `index.json` + `vectors/*.json` | 11 byte-locked golden vectors (3 positive, 8 negative) for the offline receipt/chain surface: valid signature, tampered payload, wrong key, key-not-found, unsigned, missing-signingKeyId, malformed signature, algorithm mismatch, schema v1/v2 (mixed version), rotated historical key, valid + broken hash-chains. |
| `generate-vectors.mjs` | Reproducible generator that minted the vectors above using real Ed25519 keys via Node's own `crypto`. **Not run at test/CI time** — mirrors `scripts/vendor-verifier.mjs`: re-run only to deliberately refresh the corpus, then re-commit the output (same discipline as `conformance/corpus/se_v1` elsewhere in this repo). |
| `run-conformance.mjs` | Loads every vector and asserts the vendored `verifyReceipt`/`verifyReceiptChain` against it. CLI: `node conformance/run-conformance.mjs`. Also exports `runConformance()` for `node --test`. |
| `conformance.test.mjs` | `node --test` wrapper around the golden-vector run. |
| `evidence-record-online.test.mjs` | The **network-based** `verify()` path (what the CLI's bare `strix-verify <id>` and the `strix_verify_record` MCP tool use) exercised against a **real loopback HTTP server** — no fetch mocking. Covers: VERIFIED, tampered→COMPLIANCE_VIOLATION, LEGACY_UNSIGNED, UNSIGNED, 404-not-found→ERROR, HTTP 500→ERROR, key-not-found→ERROR, malformed-JWKS-body→ERROR, connection-refused→ERROR. |
| `wrapper-no-crypto.test.mjs` | Structural source-scan proving `bin/strix-verify`, `mcp/server.mjs`, `hooks/verify-on-stop.mjs`, and `lib/network-hint.mjs` contain **no crypto/verdict logic of their own** — they only spawn the vendored CLI and relay its exit code + JSON, never compute or reinterpret a verdict. |

## Running it

```sh
node conformance/run-conformance.mjs                 # golden vectors, CLI form
node --test conformance/conformance.test.mjs \
            conformance/wrapper-no-crypto.test.mjs \
            conformance/evidence-record-online.test.mjs
```

Node's default `--test` directory discovery only picks up files matching
its own default glob when given a bare directory path — list the three
`*.test.mjs` files explicitly (as `scripts/lint-strixgov-skills-release.mjs`
does) rather than relying on `node --test conformance/`.

## Known scope limits (read before extending)

- **Kid-collision resolution is not exercised here.** `verifyReceipt`'s
  `opts.jwks` path resolves a key via `resolveJwkFromKid`, which is
  documented in the vendored source as a "backward-compat **first-match**
  helper" — unlike `fetchPublicKeys` (the online path), it does not try
  every JWKS entry sharing a kid. The `rcpt-pos-01-rotated-key-still-verifies`
  vector proves rotation across **distinct kids** resolves correctly; it does
  **not** prove same-kid-collision resolution (two JWKS entries sharing one
  kid) succeeds via the receipt path — that scenario is only proven for the
  online `fetchPublicKeys` path, indirectly, by the CLAUDE.md-documented
  AA-1/kid-collision fix elsewhere in this repo. This is a real gap in the
  vendored library's receipt-path key resolution, not a gap in this harness;
  it is flagged here rather than silently assumed away.
- **Algorithm-mismatch vector simulates a foreign key type reaching the
  resolver** (an RSA-shaped JWKS entry under the matching kid). It does not
  prove the vendored verifier rejects an actually-cryptographically-valid
  non-Ed25519 signature — Ed25519 is the only algorithm this package (and
  the whole Strix signing stack) ever uses, so there is no "valid RSA
  signature" case to construct against it.
- **No timeout/slow-server vector.** The vendored `fetchWithContext` does
  not set an explicit fetch timeout, so there is no timeout-specific error
  branch to golden-vector; a hung connection would surface as whatever the
  runtime's default socket behavior produces, not a documented verifier
  branch.
