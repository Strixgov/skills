// Single verification-collapse point for the strix-verifier plugin — mirrors
// apps/strix-console/src/lib/proof-explorer/verification-collapse.ts's
// discipline exactly: the vendored verifier's native status vocabulary is
// wide (VERIFIED / VERIFIED_PINNED_ONLY / VERIFIED_LIVE_ONLY / TAMPERED /
// COMPLIANCE_VIOLATION / UNSIGNED / LEGACY_UNSIGNED / ERROR / ...) and this
// is the ONLY place it collapses to the frozen 4-state public vocabulary:
//
//   VERIFIED | INVALID | LEGACY_UNSIGNED | UNVERIFIABLE
//
// Load-bearing law (do not violate): UNVERIFIABLE never becomes INVALID.
// "Cannot verify" (network/key/malformed-input) and "proven tampered" are
// different claims; collapsing the former into the latter would report a
// forgery where none was demonstrated. Conversely, a genuinely detected
// tamper (TAMPERED, COMPLIANCE_VIOLATION, signature/hash mismatch) always
// stays INVALID regardless of exit code — a wrapper must never soften a
// real rejection into "we just couldn't check."
//
// `rawStatus` + `processExitCode` are always carried alongside `state` so
// nothing here hides the vendor's own answer — this is presentation, not a
// replacement verdict.

/** @typedef {"VERIFIED"|"INVALID"|"LEGACY_UNSIGNED"|"UNVERIFIABLE"} CollapsedState */

const VERIFIED_STATUSES = new Set(["VERIFIED", "VERIFIED_PINNED_ONLY", "VERIFIED_LIVE_ONLY"]);
const INVALID_STATUSES = new Set(["TAMPERED", "COMPLIANCE_VIOLATION", "SIGNATURE_INVALID", "HASH_MISMATCH", "HASH_PREFIX_MATCH"]);
const LEGACY_UNSIGNED_STATUSES = new Set(["LEGACY_UNSIGNED"]);
// Everything else the vendored verifier can return (UNSIGNED, ERROR, UNKNOWN,
// NOT_FOUND, SIGNING_KEY_UNKNOWN, ...) means "could not reach a verdict" —
// UNVERIFIABLE, not INVALID. UNSIGNED specifically means a signature marker
// is present but unresolvable (e.g. no signingKeyId) — that is cannot-verify,
// NOT a proven tamper, so it does not join INVALID_STATUSES above.

const REASONS = {
  VERIFIED: "The vendored verifier's own crypto check passed.",
  INVALID: "The vendored verifier detected a genuine mismatch (signature, hash, or compliance) — this is a real rejection, not a network/lookup failure.",
  LEGACY_UNSIGNED: "The record predates signing and was never signed — honest floor, not an error.",
  UNVERIFIABLE: "The vendored verifier could not reach a cryptographic verdict (network, unresolvable key, malformed input, or not found). This is cannot-verify, not proof of forgery.",
};

/**
 * Collapse the vendored verifier's native output to the frozen 4-state
 * public vocabulary.
 *
 * @param {{ rawStatus?: string|null, processExitCode: number }} input
 * @returns {{ state: CollapsedState, reason: string, processExitCode: number, rawStatus: string|null }}
 */
export function collapseVerdict({ rawStatus, processExitCode }) {
  if (rawStatus == null) {
    // The vendor's own JSON status is unavailable (parse failure, crash,
    // unexpected output shape) — fall back to the CLI's own documented
    // exit-code contract (0/1/2), least-confidence path. A tamper can only
    // be asserted from the vendor's own status string, never guessed from
    // an exit code alone, so exitCode 1 here still degrades to UNVERIFIABLE
    // rather than a guessed INVALID.
    const state = processExitCode === 0 ? "VERIFIED" : "UNVERIFIABLE";
    return {
      state,
      reason:
        state === "VERIFIED"
          ? "Exit code 0 with no parseable status — treated as verified, but this is a lower-confidence path than a native VERIFIED status. Prefer --json output."
          : "No parseable verifier status was available; falling back to cannot-verify rather than guessing.",
      processExitCode,
      rawStatus: null,
    };
  }

  let state;
  if (INVALID_STATUSES.has(rawStatus)) state = "INVALID";
  else if (VERIFIED_STATUSES.has(rawStatus)) state = "VERIFIED";
  else if (LEGACY_UNSIGNED_STATUSES.has(rawStatus)) state = "LEGACY_UNSIGNED";
  else state = "UNVERIFIABLE";

  return { state, reason: REASONS[state], processExitCode, rawStatus };
}
