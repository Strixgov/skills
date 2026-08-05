/**
 * @strixgov/verifier — Consumer Trust Mark v1 (TM-1) verifier.
 *
 * Independent verification of a `trust_mark_grant_v1` grant document — the
 * publicly-resolvable signed grant that answers "is this surface governed by
 * Strix, live, right now?". No Strix tooling, SDK, or account required.
 *
 * This is the cross-repo TS port of the schema authority
 * (`solo-builder-core/src/solo_builder/trust_mark.py`, ADR-029). It is
 * conformance-locked against `vectors/trust_mark_grant_v1/` — every positive
 * vector's `canonical_bytes_hex` is reproduced byte-for-byte and every
 * negative produces the named `failing_rule` + `reason`
 * (test/trust-mark-v1-golden-vectors.test.mjs).
 *
 * The 10 verifier rules run in fixed order, short-circuiting on first failure
 * (ADR-029 §3). Renumbering is a contract break — positions 9 (coverage) and
 * 10 (revocation) are consumed by the strix-platform runtime. Rules 9/10 are
 * tri-state and opt-in (a `null` status skips the rule, the legacy/test mode);
 * `unavailable` is the substrate-error case that the public block renders as
 * `verified=null`, never `false` and never silently `true`.
 *
 * Capability gate (rule 4): TM-1 is ACTIVE in the shipped registry (the
 * ADR-029 §6 promotion). `verifyTrustMarkGrant` treats TM-1 as active by
 * default; it still fails closed at rule 4 with `tm1_capability_not_active`
 * when a caller explicitly passes `capabilityActive: false` (or when
 * `capability_id !== "TM-1"`).
 */

import crypto from "node:crypto";
// SCJ v1 canonical (CJ-1) + JWKS fetch are reused from the package core; they
// are function declarations (hoisted), so this import is safe under the
// index.mjs ⇄ trust-mark.mjs circular re-export and is only touched at runtime.
import { scjCanonicalize, fetchPublicKeys } from "./index.mjs";
import { resolveGrantRevocation, parseTrustMarkRevocationList } from "./trust-mark-revocation.mjs";

const DEFAULT_PROOF_BASE = "https://www.strixgov.com";
const DEFAULT_JWKS_BASE = "https://www.strixgov.com";

// ─── Locked vocabulary (mirrors trust_mark.py) ─────────────────────────────

/** The 16 `tm1_*` reason codes (ADR-029 §4). Stable strings; consumers MAY pattern-match. */
export const TM1_REASON = Object.freeze({
  SCHEMA_MISSING_FIELD: "tm1_schema_missing_field",
  SCHEMA_UNKNOWN_FIELD: "tm1_schema_unknown_field",
  SIGNATURE_INVALID: "tm1_signature_invalid",
  UNKNOWN_KID: "tm1_unknown_kid",
  UNKNOWN_ISS: "tm1_unknown_iss",
  CAPABILITY_NOT_ACTIVE: "tm1_capability_not_active",
  MARK_CLASS_INVALID: "tm1_mark_class_invalid",
  SURFACE_ORIGIN_INVALID: "tm1_surface_origin_invalid",
  SURFACE_MISMATCH: "tm1_surface_mismatch",
  GRANT_BINDING_MISMATCH: "tm1_grant_binding_mismatch",
  HEARTBEAT_KEY_INVALID: "tm1_heartbeat_key_invalid",
  VALIDITY_WINDOW_VIOLATED: "tm1_validity_window_violated",
  NOT_COVERED: "tm1_not_covered",
  COVERAGE_CHECK_UNAVAILABLE: "tm1_coverage_check_unavailable",
  REVOKED: "tm1_revoked",
  REVOCATION_CHECK_UNAVAILABLE: "tm1_revocation_check_unavailable",
});

/** The 10 verifier rule ids, in fixed evaluation order (ADR-029 §3). */
export const TM1_RULE = Object.freeze({
  SCHEMA: "schema",
  SIGNATURE: "signature",
  JWKS_RESOLUTION: "jwks_resolution",
  CAPABILITY: "capability",
  MARK_CLASS: "mark_class",
  SURFACE_ORIGIN: "surface_origin",
  HEARTBEAT_KEY: "heartbeat_key",
  VALIDITY_WINDOW: "validity_window",
  COVERAGE: "coverage",
  REVOCATION: "revocation",
});

const CAPABILITY_ID = "TM-1";
const MARK_CLASSES = Object.freeze(["governed_agent", "governed_commerce", "governed_content"]);
const ALLOWED_JWK_KEYS = Object.freeze(["kty", "crv", "x"]);
const SHA256_REF_RE = /^sha256:[0-9a-f]{64}$/;

const REQUIRED_PAYLOAD_FIELDS = Object.freeze([
  "grant_id",
  "capability_id",
  "tenant_id",
  "licensee",
  "mark_class",
  "surface_origin",
  "heartbeat_key",
  // kernel_policy_hash + coverage_window_seconds are the SIGNED rule-9 comparands
  // (contract 0.7.0). Signing them is what lets a verifier re-derive coverage
  // independently — the policy hash a live heartbeat is judged against, and the
  // staleness bound, come from the authority signature, not an unsigned row.
  "kernel_policy_hash",
  "coverage_window_seconds",
  "valid_from",
  "valid_until",
  "issued_at",
  "iss",
  "environment",
]);
const NON_EMPTY_STRING_FIELDS = Object.freeze([
  "grant_id",
  "tenant_id",
  "valid_from",
  "valid_until",
  "issued_at",
  "iss",
]);

/**
 * The rule-9 comparand fields (contract 0.7.0). They are present-together or
 * absent-together: a 0.7.0 grant carries both; the single pre-existing 0.6.0
 * (12-field) grant carries neither. Exactly one present is malformed.
 *
 * TRANSITIONAL LEGACY TOLERANCE: this verifier accepts a 12-field (0.6.0) grant
 * so that publishing 1.15.0 does not break the live badge in the window before
 * the grant is re-minted to 0.7.0 (publish-then-re-mint, the same lockstep
 * discipline as publish-then-flip). A 12-field grant verifies for rules 1–8 but
 * CANNOT get independently re-derived coverage — it has no signed comparands, so
 * `verifyTrustMark` reports its coverage as server-advisory and the CLI says so.
 * The frozen schema is 14-field; this tolerance is removed at schema freeze
 * (see docs/architecture/consumer-trust-mark-v1.md §"0.6.0→0.7.0 transition").
 */
const COMPARAND_FIELDS = Object.freeze(["kernel_policy_hash", "coverage_window_seconds"]);
const BASE_REQUIRED_FIELDS = Object.freeze(
  REQUIRED_PAYLOAD_FIELDS.filter((f) => !COMPARAND_FIELDS.includes(f)),
);

/**
 * Capability status the shipped verifier bundles. TM-1 is ACTIVE: the ADR-029
 * §6 promotion from RESERVED, published in lockstep with the runtime
 * STRIX_TRUST_MARK_V1 flip so the live badge and this independent verifier
 * agree (a badge that reads GREEN while the published CLI reports
 * `tm1_capability_not_active` would be the exact "claims more than it can
 * prove" gap this capability exists to close). With TM-1 ACTIVE, a fully-valid
 * grant + fresh coverage verifies; rule 4 still fails closed when a caller
 * explicitly passes `capabilityActive: false` — the fail-closed logic is
 * preserved, it is just no longer the shipped default.
 */
export const TM1_CAPABILITY_STATUS = "ACTIVE";

// ─── Structural validators (port of trust_mark.py helpers) ─────────────────

function validateSurfaceOrigin(value) {
  if (typeof value !== "string" || value === "") return "surface_origin is required";
  if (!value.startsWith("https://")) return `surface_origin must be an https origin, got ${value}`;
  const rest = value.slice("https://".length);
  if (rest === "") return `surface_origin has no host: ${value}`;
  if (rest.includes("@")) return "surface_origin must not carry credentials";
  if (/[/?#]/.test(rest)) {
    return `surface_origin must be a bare origin (no path/query/fragment), got ${value}`;
  }
  return null;
}

function validateHeartbeatJwk(jwk) {
  if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) return "heartbeat jwk object missing";
  if ("d" in jwk) return "heartbeat jwk carries a private component ('d') — public key only";
  const extra = Object.keys(jwk).filter((k) => !ALLOWED_JWK_KEYS.includes(k));
  if (extra.length > 0) return `heartbeat jwk carries unexpected members: ${extra.sort().join(",")} — public key only`;
  if (jwk.kty !== "OKP") return `heartbeat jwk kty must be 'OKP', got ${jwk.kty}`;
  if (jwk.crv !== "Ed25519") return `heartbeat jwk crv must be 'Ed25519', got ${jwk.crv}`;
  if (!jwk.x) return "heartbeat jwk x (public key material) is required";
  return null;
}

function parseIsoMs(value) {
  // Tolerant of a trailing Z (UTC), mirroring trust_mark.py._parse_iso. Returns
  // NaN on unparseable input; rule 8 maps NaN to VALIDITY_WINDOW_VIOLATED.
  if (typeof value !== "string" || value === "") return NaN;
  return Date.parse(value);
}

function fail(rule, reason, detail) {
  return { valid: false, failingRule: rule, reason, detail };
}

// ─── Ed25519 helpers ────────────────────────────────────────────────────────

/** Build an Ed25519 public KeyObject from a raw 32-byte public key (hex). */
export function ed25519PublicKeyFromRawHex(hex) {
  const raw = Buffer.from(hex, "hex");
  if (raw.length !== 32) throw new Error(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  return crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
}

/** Default TM-1 signature check: hex Ed25519 over the SCJ v1 canonical bytes. */
function defaultVerifyTm1Signature(canonicalBytes, signatureHex, publicKey) {
  let sig;
  try {
    sig = Buffer.from(signatureHex, "hex");
  } catch {
    return false;
  }
  // Buffer.from is lenient with odd/invalid hex; an Ed25519 signature is 64 bytes.
  if (sig.length !== 64) return false;
  try {
    return crypto.verify(null, canonicalBytes, publicKey, sig);
  } catch {
    return false;
  }
}

// ─── The verifier (port of trust_mark.py verify_grant) ─────────────────────

/**
 * Verify a `trust_mark_grant_v1` record. Pure, offline, never throws for a
 * verification failure — returns `{ valid, failingRule, reason, detail }`.
 *
 * @param {object} record - The grant envelope `{ payload, signature, kid, created_at }`.
 * @param {object} [opts]
 * @param {(iss: string, kid: string) => import("node:crypto").KeyObject | null} [opts.resolvePublicKey]
 *        Resolves the AUTHORITY public key for (iss, kid). Returns null when the
 *        kid is unknown (→ rule 3 `tm1_unknown_kid`). Required for a real check.
 * @param {(canonicalBytes: Buffer, signatureHex: string, key: import("node:crypto").KeyObject) => boolean} [opts.verifySignatureFn]
 *        Override the signature check (the injected `SignatureVerifier` of the
 *        Python contract). Defaults to real hex Ed25519.
 * @param {string} [opts.verifiedAt] - ISO-8601 verification time (default: now).
 * @param {string} [opts.boundGrantId] - The grant id the consumer actually resolved (rule-6 anti-substitution).
 * @param {string} [opts.boundSurfaceOrigin] - The origin the badge was embedded on (rule-6 anti-borrow).
 * @param {('covered'|'not_covered'|'unavailable'|null)} [opts.coverageStatus] - Rule-9 tri-state; null skips.
 * @param {('not_revoked'|'revoked'|'unavailable'|null)} [opts.revocationStatus] - Rule-10 tri-state; null skips.
 * @param {boolean} [opts.capabilityActive] - Treat TM-1 as ACTIVE (rule 4). Default: bundled status.
 * @returns {{ valid: boolean, failingRule: string|null, reason: string|null, detail: string|null }}
 */
export function verifyTrustMarkGrant(record, opts = {}) {
  const {
    resolvePublicKey,
    verifySignatureFn = defaultVerifyTm1Signature,
    verifiedAt,
    boundGrantId,
    boundSurfaceOrigin,
    coverageStatus = null,
    revocationStatus = null,
    capabilityActive = TM1_CAPABILITY_STATUS === "ACTIVE",
  } = opts;

  // ── Step 1: schema ──
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    return fail(TM1_RULE.SCHEMA, TM1_REASON.SCHEMA_MISSING_FIELD, "record is not an object");
  }
  const payload = record.payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return fail(TM1_RULE.SCHEMA, TM1_REASON.SCHEMA_MISSING_FIELD, "payload object missing");
  }
  const signatureHex = typeof record.signature === "string" ? record.signature : "";
  const kid = typeof record.kid === "string" ? record.kid : "";
  if (!signatureHex) return fail(TM1_RULE.SCHEMA, TM1_REASON.SCHEMA_MISSING_FIELD, "signature missing");
  if (!kid) return fail(TM1_RULE.SCHEMA, TM1_REASON.SCHEMA_MISSING_FIELD, "kid missing");

  for (const fld of BASE_REQUIRED_FIELDS) {
    if (!(fld in payload)) {
      return fail(TM1_RULE.SCHEMA, TM1_REASON.SCHEMA_MISSING_FIELD, `payload.${fld} missing`);
    }
  }
  const unknown = Object.keys(payload).filter((k) => !REQUIRED_PAYLOAD_FIELDS.includes(k));
  if (unknown.length > 0) {
    return fail(TM1_RULE.SCHEMA, TM1_REASON.SCHEMA_UNKNOWN_FIELD, `unknown payload fields: ${unknown.sort().join(",")}`);
  }
  // Rule-9 comparands: present-together (0.7.0) or absent-together (legacy 0.6.0).
  // Exactly one present is malformed; when present, both are format-validated so a
  // bad comparand is a schema failure, never silently coerced at coverage time.
  const hasPolicyHash = "kernel_policy_hash" in payload;
  const hasWindow = "coverage_window_seconds" in payload;
  if (hasPolicyHash !== hasWindow) {
    return fail(
      TM1_RULE.SCHEMA,
      TM1_REASON.SCHEMA_MISSING_FIELD,
      "kernel_policy_hash and coverage_window_seconds must be present together (0.7.0) or absent together (legacy 0.6.0)",
    );
  }
  if (hasPolicyHash) {
    if (typeof payload.kernel_policy_hash !== "string" || !SHA256_REF_RE.test(payload.kernel_policy_hash)) {
      return fail(TM1_RULE.SCHEMA, TM1_REASON.SCHEMA_MISSING_FIELD, "payload.kernel_policy_hash must be a 'sha256:<64 hex>' content reference");
    }
    const cws = payload.coverage_window_seconds;
    // typeof bool is "boolean" (not "number"); a non-integer/≤0 number is rejected too.
    if (typeof cws !== "number" || !Number.isInteger(cws) || cws <= 0) {
      return fail(TM1_RULE.SCHEMA, TM1_REASON.SCHEMA_MISSING_FIELD, "payload.coverage_window_seconds must be a positive integer");
    }
  }
  // A present-but-empty required string field is effectively missing its value
  // (the dataclass __post_init__ non-empty guard, surfaced for the Mapping path —
  // this is what catches the construction-empty-grant-id vector).
  for (const fld of NON_EMPTY_STRING_FIELDS) {
    if (typeof payload[fld] !== "string" || payload[fld] === "") {
      return fail(TM1_RULE.SCHEMA, TM1_REASON.SCHEMA_MISSING_FIELD, `payload.${fld} is required`);
    }
  }
  const licensee = payload.licensee;
  if (
    licensee === null ||
    typeof licensee !== "object" ||
    Array.isArray(licensee) ||
    !licensee.licensee_id ||
    !licensee.legal_name
  ) {
    return fail(TM1_RULE.SCHEMA, TM1_REASON.SCHEMA_MISSING_FIELD, "payload.licensee must carry licensee_id + legal_name");
  }
  const heartbeat = payload.heartbeat_key;
  if (
    heartbeat === null ||
    typeof heartbeat !== "object" ||
    Array.isArray(heartbeat) ||
    !("kid" in heartbeat) ||
    !("jwk" in heartbeat)
  ) {
    return fail(TM1_RULE.SCHEMA, TM1_REASON.SCHEMA_MISSING_FIELD, "payload.heartbeat_key must carry kid + jwk");
  }

  // ── Step 3 (before 2 — the signature needs the resolved key) ──
  const iss = payload.iss;
  const publicKey = typeof resolvePublicKey === "function" ? resolvePublicKey(iss, kid) : null;
  if (publicKey === null || publicKey === undefined) {
    return fail(TM1_RULE.JWKS_RESOLUTION, TM1_REASON.UNKNOWN_KID, `no key for (iss=${iss}, kid=${kid})`);
  }

  // ── Step 2: signature ──
  const canonicalBytes = Buffer.from(scjCanonicalize(payload), "utf8");
  if (!verifySignatureFn(canonicalBytes, signatureHex, publicKey)) {
    return fail(TM1_RULE.SIGNATURE, TM1_REASON.SIGNATURE_INVALID, "signature verification failed");
  }

  // ── Step 4: capability ──
  if (payload.capability_id !== CAPABILITY_ID) {
    return fail(TM1_RULE.CAPABILITY, TM1_REASON.CAPABILITY_NOT_ACTIVE, `capability_id must be ${CAPABILITY_ID}, got ${payload.capability_id}`);
  }
  if (!capabilityActive) {
    return fail(TM1_RULE.CAPABILITY, TM1_REASON.CAPABILITY_NOT_ACTIVE, "TM-1 capability is not ACTIVE");
  }

  // ── Step 5: mark class ──
  if (!MARK_CLASSES.includes(payload.mark_class)) {
    return fail(TM1_RULE.MARK_CLASS, TM1_REASON.MARK_CLASS_INVALID, `mark_class ${payload.mark_class} is not a known MarkClass`);
  }

  // ── Step 6: surface origin + resolution-context binding cross-checks ──
  const surfaceOrigin = payload.surface_origin;
  const originError = validateSurfaceOrigin(surfaceOrigin);
  if (originError !== null) {
    return fail(TM1_RULE.SURFACE_ORIGIN, TM1_REASON.SURFACE_ORIGIN_INVALID, originError);
  }
  if (boundGrantId !== undefined && boundGrantId !== null && payload.grant_id !== boundGrantId) {
    return fail(TM1_RULE.SURFACE_ORIGIN, TM1_REASON.GRANT_BINDING_MISMATCH, `grant_id=${payload.grant_id} != resolved grant id ${boundGrantId}`);
  }
  if (boundSurfaceOrigin !== undefined && boundSurfaceOrigin !== null && surfaceOrigin !== boundSurfaceOrigin) {
    return fail(TM1_RULE.SURFACE_ORIGIN, TM1_REASON.SURFACE_MISMATCH, `grant covers ${surfaceOrigin} but was presented on ${boundSurfaceOrigin}`);
  }

  // ── Step 7: heartbeat key ──
  const hbKid = heartbeat.kid;
  const hbJwk = heartbeat.jwk;
  if (!hbKid) return fail(TM1_RULE.HEARTBEAT_KEY, TM1_REASON.HEARTBEAT_KEY_INVALID, "heartbeat kid is required");
  const jwkError = validateHeartbeatJwk(hbJwk);
  if (jwkError !== null) return fail(TM1_RULE.HEARTBEAT_KEY, TM1_REASON.HEARTBEAT_KEY_INVALID, jwkError);

  // ── Step 8: validity window ──
  const from = parseIsoMs(payload.valid_from);
  const until = parseIsoMs(payload.valid_until);
  const at = verifiedAt !== undefined && verifiedAt !== null ? parseIsoMs(verifiedAt) : Date.now();
  if (Number.isNaN(from) || Number.isNaN(until) || Number.isNaN(at)) {
    return fail(TM1_RULE.VALIDITY_WINDOW, TM1_REASON.VALIDITY_WINDOW_VIOLATED, "validity-window timestamp is not parseable");
  }
  if (from >= until) {
    return fail(TM1_RULE.VALIDITY_WINDOW, TM1_REASON.VALIDITY_WINDOW_VIOLATED, `valid_from ${payload.valid_from} does not precede valid_until ${payload.valid_until}`);
  }
  if (at < from || at > until) {
    return fail(TM1_RULE.VALIDITY_WINDOW, TM1_REASON.VALIDITY_WINDOW_VIOLATED, `verification time is outside [${payload.valid_from}, ${payload.valid_until}]`);
  }

  // ── Step 9: coverage (opt-in) ──
  if (coverageStatus !== null && coverageStatus !== undefined) {
    if (coverageStatus === "unavailable") {
      return fail(TM1_RULE.COVERAGE, TM1_REASON.COVERAGE_CHECK_UNAVAILABLE, `coverage surface unavailable for grant_id=${payload.grant_id}`);
    }
    if (coverageStatus === "not_covered") {
      return fail(TM1_RULE.COVERAGE, TM1_REASON.NOT_COVERED, `no live heartbeat for grant_id=${payload.grant_id} on ${surfaceOrigin}`);
    }
    if (coverageStatus !== "covered") {
      return fail(TM1_RULE.COVERAGE, TM1_REASON.COVERAGE_CHECK_UNAVAILABLE, `unknown coverage status: ${coverageStatus}`);
    }
  }

  // ── Step 10: revocation (opt-in) ──
  if (revocationStatus !== null && revocationStatus !== undefined) {
    if (revocationStatus === "unavailable") {
      return fail(TM1_RULE.REVOCATION, TM1_REASON.REVOCATION_CHECK_UNAVAILABLE, `revocation list unavailable for grant_id=${payload.grant_id}`);
    }
    if (revocationStatus === "revoked") {
      return fail(TM1_RULE.REVOCATION, TM1_REASON.REVOKED, `grant_id=${payload.grant_id} is on the trust_mark_revocation_list_v1 — grant withdrawn`);
    }
    if (revocationStatus !== "not_revoked") {
      return fail(TM1_RULE.REVOCATION, TM1_REASON.REVOCATION_CHECK_UNAVAILABLE, `unknown revocation status: ${revocationStatus}`);
    }
  }

  return { valid: true, failingRule: null, reason: null, detail: null };
}

// ─── Public tri-state block (port of render_trust_mark_block, ADR-029 §5) ──

const SUBSTRATE_ERROR_REASONS = Object.freeze([
  TM1_REASON.COVERAGE_CHECK_UNAVAILABLE,
  TM1_REASON.REVOCATION_CHECK_UNAVAILABLE,
]);

/**
 * Build the public trust-mark block. `verified` is tri-state per ADR-014 §1:
 *   - true             → all checked rules passed.
 *   - false            → a definitive failure (incl. not_covered, revoked).
 *   - null + no reason  → no grant resolved.
 *   - null + reason     → cryptographically valid, but a substrate surface
 *                         (coverage/revocation) could not be consulted.
 */
export function renderTrustMarkBlock(record, verification) {
  if (record === null || record === undefined) {
    return { grantId: null, markClass: null, surfaceOrigin: null, verified: null, verificationReason: null };
  }
  const payload = (record && typeof record === "object" && record.payload) || {};
  const base = {
    grantId: payload.grant_id ?? null,
    markClass: payload.mark_class ?? null,
    surfaceOrigin: payload.surface_origin ?? null,
  };
  if (verification === null || verification === undefined || verification.valid) {
    return { ...base, verified: verification && verification.valid ? true : null, verificationReason: null };
  }
  if (SUBSTRATE_ERROR_REASONS.includes(verification.reason)) {
    return { ...base, verified: null, verificationReason: verification.reason };
  }
  return { ...base, verified: false, verificationReason: verification.reason };
}

// ─── Independent rule-9 coverage (contract 0.7.0) ──────────────────────────
// Re-derives coverage from ONLY the signed grant + the licensee heartbeat
// surface — trusting nothing but the Strix authority signature already verified
// at rules 1–8. The comparands are the SIGNED `kernel_policy_hash` (what the
// kernel policy must hash to) and `coverage_window_seconds` (the staleness
// bound); the heartbeat verifying key is the SIGNED `heartbeat_key.jwk`. Mirrors
// strix-platform's resolveTrustMarkCoverage step order + academy's heartbeat
// canonical form (base64url Ed25519 over SCJ v1 of the 9-field set).
//
// RESIDUAL TRUST BOUNDARY (state this honestly, never "trust nothing"): signing
// the comparands removes the Strix SERVER from coverage's trust base, but a
// fresh, validly-signed heartbeat still attests liveness only as strongly as the
// licensee's heartbeat-signing KEY CUSTODY. A host that holds that key can emit
// fresh heartbeats even with a dead/hollowed kernel; binding the key to the
// kernel itself (TEE remote attestation) is out of scope here. The honest claim
// is "coverage independently re-derived — trusting the grant's authority
// signature + the licensee key custody," and the CLI prints exactly that.

export const TRUST_MARK_WELL_KNOWN_HEARTBEAT_PATH = "/.well-known/strix-trust-mark-heartbeat.json";
/** Max forward clock skew (a property of clocks, not a grant → a verifier constant, not signed). */
const HEARTBEAT_FUTURE_SKEW_SECONDS = 300;
const HEARTBEAT_SCHEMA_VERSION = "trust_mark_heartbeat_v1";
const HEARTBEAT_FETCH_TIMEOUT_MS = 10_000;
// Strict RFC 3339 (mirrors solo-builder-core isStrictRfc3339 for the shapes a
// heartbeat emits: date-time with Z or numeric offset, optional fraction).
const STRICT_RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const HEARTBEAT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
/** Tri-state coverage outcome → mapped to the rule-9 status verifyTrustMarkGrant consumes. */
export const COVERAGE_STATUS = Object.freeze({ COVERED: "covered", NOT_COVERED: "not_covered", UNAVAILABLE: "unavailable" });

/** SCJ v1 canonical of the locked 9-field heartbeat (excludes `signature`). */
function canonicalizeHeartbeat(doc) {
  return scjCanonicalize({
    chainHeadHash: doc.chainHeadHash,
    chainLength: doc.chainLength,
    emittedAt: doc.emittedAt,
    grantId: doc.grantId,
    kernelPolicyHash: doc.kernelPolicyHash,
    licenseeId: doc.licenseeId,
    schemaVersion: doc.schemaVersion,
    signingKeyId: doc.signingKeyId,
    tenantId: doc.tenantId,
  });
}

/** Structural parse of an untrusted heartbeat doc (locked 9-field set + signature). Never throws. */
function parseHeartbeat(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return { ok: false, error: "heartbeat must be a JSON object" };
  const allowed = new Set(["chainHeadHash", "chainLength", "emittedAt", "grantId", "kernelPolicyHash", "licenseeId", "schemaVersion", "signingKeyId", "tenantId", "signature"]);
  for (const k of Object.keys(input)) if (!allowed.has(k)) return { ok: false, error: `unexpected field "${k}"` };
  for (const k of allowed) if (!(k in input)) return { ok: false, error: `missing field "${k}"` };
  if (input.schemaVersion !== HEARTBEAT_SCHEMA_VERSION) return { ok: false, error: `schemaVersion must be "${HEARTBEAT_SCHEMA_VERSION}"` };
  for (const f of ["grantId", "tenantId", "licenseeId", "signingKeyId"]) {
    if (typeof input[f] !== "string" || !HEARTBEAT_ID_RE.test(input[f])) return { ok: false, error: `${f} must be a 1-128 char identifier` };
  }
  for (const f of ["kernelPolicyHash", "chainHeadHash"]) {
    if (typeof input[f] !== "string" || !SHA256_REF_RE.test(input[f])) return { ok: false, error: `${f} must be a "sha256:<64 hex>" content reference` };
  }
  if (typeof input.chainLength !== "number" || !Number.isInteger(input.chainLength) || input.chainLength < 0) return { ok: false, error: "chainLength must be a non-negative integer" };
  if (typeof input.emittedAt !== "string") return { ok: false, error: "emittedAt must be a string" };
  if (typeof input.signature !== "string" || input.signature.length === 0) return { ok: false, error: "signature must be a non-empty string" };
  return { ok: true, value: input };
}

/** Verify a heartbeat's base64url Ed25519 signature against a public KeyObject. Never throws. */
function verifyHeartbeatSignature(doc, publicKey) {
  try {
    return crypto.verify(null, Buffer.from(canonicalizeHeartbeat(doc), "utf8"), publicKey, Buffer.from(doc.signature, "base64url"));
  } catch {
    return false;
  }
}

/** The heartbeat public key from the grant's SIGNED heartbeat_key.jwk (never from the surface). */
function heartbeatKeyFromGrant(payload) {
  try {
    const x = payload?.heartbeat_key?.jwk?.x;
    if (typeof x !== "string" || x === "") return null;
    return ed25519PublicKeyFromRawHex(Buffer.from(x, "base64url").toString("hex"));
  } catch {
    return null;
  }
}

/**
 * Independently re-derive rule-9 coverage for a verified 0.7.0 grant payload.
 * Returns `{ status, reason, detail }`. `status` is the tri-state
 * verifyTrustMarkGrant consumes (covered / not_covered / unavailable):
 *   - covered      — fresh, grant-bound heartbeat whose policy hash matches the
 *                    SIGNED kernel_policy_hash, signed by the SIGNED heartbeat key.
 *   - not_covered  — a DEFINITIVE failure (bad sig / wrong grant / stale beyond
 *                    the SIGNED coverage_window_seconds / future-dated / policy drift).
 *   - unavailable  — the surface could not be consulted (unreachable / malformed
 *                    / key unresolvable). Renders YELLOW, never GREEN, never a false RED.
 *
 * @param {object} payload - a verified 14-field grant payload.
 * @param {object} [opts] - { fetchImpl, now, timeoutMs }
 */
export async function resolveTrustMarkCoverageFromGrant(payload, opts = {}) {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const now = opts.now instanceof Date ? opts.now : new Date();
  const done = (status, reason, detail) => ({ status, reason, detail });

  let url;
  try {
    const base = new URL(payload.surface_origin);
    if (base.protocol !== "https:") return done(COVERAGE_STATUS.UNAVAILABLE, "SURFACE_NOT_HTTPS", `surface_origin is not https: ${payload.surface_origin}`);
    url = new URL(TRUST_MARK_WELL_KNOWN_HEARTBEAT_PATH, base.origin).toString();
  } catch {
    return done(COVERAGE_STATUS.UNAVAILABLE, "SURFACE_INVALID", `surface_origin is not an absolute URL: ${payload.surface_origin}`);
  }

  // 1. Fetch — network-level failure is unknowable, not definitive.
  let body;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? HEARTBEAT_FETCH_TIMEOUT_MS);
    let res;
    try {
      res = await fetchImpl(url, { signal: controller.signal, redirect: "error", headers: { Accept: "application/json" } });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) return done(COVERAGE_STATUS.UNAVAILABLE, "SURFACE_UNREACHABLE", `heartbeat fetch returned HTTP ${res.status}`);
    try {
      body = await res.json();
    } catch {
      return done(COVERAGE_STATUS.UNAVAILABLE, "HEARTBEAT_MALFORMED", "heartbeat document is not valid JSON");
    }
  } catch (err) {
    return done(COVERAGE_STATUS.UNAVAILABLE, "SURFACE_UNREACHABLE", `heartbeat fetch failed: ${err?.message ?? err}`);
  }

  // 2. Structural parse (locked 9-field set).
  const parsed = parseHeartbeat(body);
  if (!parsed.ok) return done(COVERAGE_STATUS.UNAVAILABLE, "HEARTBEAT_MALFORMED", parsed.error);
  const hb = parsed.value;

  // 3. Key resolution — the heartbeat key REGISTERED ON THE GRANT (signed), never one the surface serves.
  const key = heartbeatKeyFromGrant(payload);
  if (!key) return done(COVERAGE_STATUS.UNAVAILABLE, "KEY_UNKNOWN", "grant heartbeat_key.jwk did not resolve to an Ed25519 public key");

  // 4. Signature — bytes the licensee's registered key did not sign is DEFINITIVE.
  if (!verifyHeartbeatSignature(hb, key)) return done(COVERAGE_STATUS.NOT_COVERED, "SIGNATURE_INVALID", "heartbeat signature does not verify against the grant's registered key");

  // ── below runs on an AUTHENTICATED payload ──
  // 5. Grant binding — a valid heartbeat for a different grant served here is a cross-licensee replay.
  if (hb.grantId !== payload.grant_id || hb.tenantId !== payload.tenant_id) {
    return done(COVERAGE_STATUS.NOT_COVERED, "GRANT_MISMATCH", `heartbeat is bound to grant "${hb.grantId}" / tenant "${hb.tenantId}"`);
  }
  // 6. Strict timestamp — fail closed on non-RFC3339 (false-positive staleness > silent acceptance).
  if (!STRICT_RFC3339_RE.test(hb.emittedAt)) return done(COVERAGE_STATUS.NOT_COVERED, "TIMESTAMP_MALFORMED", "emittedAt is not strict RFC 3339");
  const emittedMs = Date.parse(hb.emittedAt);
  if (Number.isNaN(emittedMs)) return done(COVERAGE_STATUS.NOT_COVERED, "TIMESTAMP_MALFORMED", "emittedAt is unparseable");
  const ageSeconds = (now.getTime() - emittedMs) / 1000;
  // 7. Future-dated beyond skew — the pre-signed-heartbeat replay defense.
  if (ageSeconds < -HEARTBEAT_FUTURE_SKEW_SECONDS) return done(COVERAGE_STATUS.NOT_COVERED, "HEARTBEAT_FROM_FUTURE", `emittedAt is ${Math.round(-ageSeconds)}s in the future`);
  // 8. Staleness — the rule-9 liveness bound, from the SIGNED coverage_window_seconds.
  if (ageSeconds > payload.coverage_window_seconds) {
    return done(COVERAGE_STATUS.NOT_COVERED, "HEARTBEAT_STALE", `heartbeat is ${Math.round(ageSeconds)}s old (signed coverage window ${payload.coverage_window_seconds}s)`);
  }
  // 9. Policy binding — the live policy hash must match the SIGNED kernel_policy_hash.
  if (hb.kernelPolicyHash !== payload.kernel_policy_hash) {
    return done(COVERAGE_STATUS.NOT_COVERED, "POLICY_HASH_MISMATCH", "live kernel policy hash diverged from the grant's signed kernel_policy_hash");
  }
  return done(COVERAGE_STATUS.COVERED, "COVERAGE_OK", "fresh signed heartbeat matches the grant's signed comparands");
}

// ─── CLI fetch-and-verify ───────────────────────────────────────────────────

async function fetchJson(url) {
  let res;
  try {
    res = await fetch(url, { headers: { Accept: "application/json" } });
  } catch (err) {
    const e = new Error(`Network error fetching ${url}: ${err?.cause?.code ?? err?.message ?? err}`);
    e.url = url;
    throw e;
  }
  if (res.status === 404) {
    const e = new Error(`No Record Found: trust mark not found (${url})`);
    e.notFound = true;
    throw e;
  }
  if (res.status === 501) {
    const e = new Error("Trust-mark verifier not available on this deployment (501) — the grant verifier is not yet wired");
    e.status = 501;
    throw e;
  }
  if (!res.ok) throw new Error(`Trust mark fetch failed: HTTP ${res.status} (${url})`);
  return res.json();
}

/**
 * Fetch a grant by id from the Strix public status endpoint and reconstruct
 * the signed envelope. The status response preserves `payload` + `signature`
 * byte-for-byte (ADR-029 §5); the (possibly redacted) authority kid arrives as
 * `signingKeyId`.
 */
async function fetchGrantRecord(grantId, proofBase) {
  const url = `${proofBase}/api/public/proof/trustmark/${encodeURIComponent(grantId)}`;
  const data = await fetchJson(url);
  return {
    payload: data.payload,
    signature: typeof data.signature === "string" ? data.signature : "",
    kid: data.signingKeyId ?? data.kid ?? "",
    created_at: data.created_at ?? null,
    _server: { coverage: data.coverage ?? null, coverage_reason: data.coverage_reason ?? null, badge: data.badge ?? null, lifecycle: data.lifecycle ?? null },
  };
}

/**
 * Independent verification of a published trust-mark grant.
 *
 * Re-derives rules 1–8 offline (schema, signature, capability, mark class,
 * surface origin, heartbeat key, validity window) against the live Strix
 * authority JWKS — zero shared code with the producer. For a 0.7.0 grant (one
 * carrying the SIGNED comparands `kernel_policy_hash` + `coverage_window_seconds`)
 * rule 9 (coverage) is ALSO re-derived independently: this fetches the licensee's
 * heartbeat from the grant's signed `surface_origin`, verifies it against the
 * grant's signed `heartbeat_key`, and checks freshness + policy-match against the
 * signed comparands — trusting nothing but the authority signature. Disable with
 * `coverage: false` (grant-only / offline). A legacy 0.6.0 (12-field) grant has
 * no signed comparands, so coverage stays the server's advisory (echoed under
 * `serverReported`) and `coverageIndependent` is false — the honest interim state
 * until that grant is re-minted to 0.7.0.
 *
 * Residual trust boundary (named, not hidden): independent coverage trusts the
 * grant's authority signature + the licensee heartbeat-key CUSTODY. A holder of
 * that key can emit fresh heartbeats with a dead kernel; binding the key to the
 * kernel (TEE attestation) is out of scope. Revocation (rule 10) is independently
 * re-derived when a signed list is available.
 *
 * @param {string} grantId
 * @param {object} [options]
 * @param {string} [options.proofBase]
 * @param {string} [options.jwksBase]
 * @param {boolean} [options.capabilityActive]
 * @param {boolean} [options.coverage] - default true; false skips the heartbeat fetch (rule 9 skipped).
 * @param {typeof fetch} [options.fetchImpl] - injected fetch (heartbeat + revocation), for tests.
 * @param {Date} [options.now] - verification instant for coverage freshness, for tests.
 * @returns {Promise<object>}
 */
export async function verifyTrustMark(grantId, options = {}) {
  const proofBase = options.proofBase ?? DEFAULT_PROOF_BASE;
  const jwksBase = options.jwksBase ?? DEFAULT_JWKS_BASE;

  const result = {
    grantId,
    licenseeId: null,
    markClass: null,
    surfaceOrigin: null,
    valid: false,
    failingRule: null,
    reason: null,
    detail: null,
    capabilityActive: options.capabilityActive ?? TM1_CAPABILITY_STATUS === "ACTIVE",
    coverageStatus: null,
    coverageReason: null,
    coverageIndependent: false,
    revocationStatus: null,
    serverReported: null,
    record: null,
    error: null,
  };

  let record;
  try {
    record = await fetchGrantRecord(grantId, proofBase);
  } catch (err) {
    result.error = err.message;
    return result;
  }
  result.record = record;
  result.serverReported = record._server;
  if (record.payload && typeof record.payload === "object") {
    result.licenseeId = record.payload.licensee?.licensee_id ?? null;
    result.markClass = record.payload.mark_class ?? null;
    result.surfaceOrigin = record.payload.surface_origin ?? null;
  }

  // Resolve the authority public key from the live JWKS (handles redacted kids).
  const resolvePublicKey = (_iss, kid) => {
    try {
      // fetchPublicKeys is async; we resolve it eagerly below and close over it.
      return resolvedKeys.find(Boolean) ?? null;
    } catch {
      return null;
    }
  };
  let resolvedKeys = [];
  try {
    resolvedKeys = await fetchPublicKeys(record.kid, jwksBase);
  } catch (err) {
    // Key unknown / JWKS unreachable → rule 3 surfaces this as a non-fatal verdict.
    result.failingRule = TM1_RULE.JWKS_RESOLUTION;
    result.reason = TM1_REASON.UNKNOWN_KID;
    result.detail = err.message;
    return result;
  }

  // Rule 10 (revocation) — OPT-IN, tri-state, fail-closed. The default endpoint
  // is consulted; a 404 there means "no revocation source configured" → rule
  // skipped (the Python opt-in contract), NOT a fake "not revoked". An EXPLICIT
  // --revocations source that can't be fetched/verified is UNAVAILABLE (the
  // operator asserted a source; silence must not clear the grant).
  const revocationStatus = await resolveRevocationStatus(grantId, {
    proofBase,
    jwksBase,
    revocationsUrl: options.revocationsUrl,
    explicit: options.revocationsUrl != null,
  });
  result.revocationStatus = revocationStatus;

  // Rule 9 (coverage) — INDEPENDENTLY re-derived for a 0.7.0 grant (signed
  // comparands present), trusting only the authority signature + the licensee
  // heartbeat-key custody. A legacy 0.6.0 grant has no signed comparands → rule
  // 9 stays the server's advisory (coverageStatus null = skipped), surfaced
  // honestly under serverReported with coverageIndependent=false.
  const payload = record.payload && typeof record.payload === "object" ? record.payload : {};
  const hasComparands =
    typeof payload.kernel_policy_hash === "string" && Number.isInteger(payload.coverage_window_seconds);
  let coverageStatus = null;
  if (hasComparands && options.coverage !== false) {
    const cov = await resolveTrustMarkCoverageFromGrant(payload, {
      fetchImpl: options.fetchImpl,
      now: options.now,
      timeoutMs: options.timeoutMs,
    });
    coverageStatus = cov.status;
    result.coverageStatus = cov.status;
    result.coverageReason = cov.reason;
    result.coverageIndependent = true;
  }

  // Try each candidate key (kid collisions are legitimate; see resolveJwksByKid).
  let verdict = null;
  for (const key of resolvedKeys) {
    const v = verifyTrustMarkGrant(record, {
      resolvePublicKey: () => key,
      capabilityActive: result.capabilityActive,
      // Coverage is independently re-derived above for a 0.7.0 grant; null (skipped)
      // for a legacy grant. Revocation IS independently re-derived when a list is available.
      coverageStatus,
      revocationStatus,
    });
    verdict = v;
    if (v.valid || v.reason !== TM1_REASON.SIGNATURE_INVALID) break;
  }
  if (verdict === null) {
    verdict = verifyTrustMarkGrant(record, { resolvePublicKey, capabilityActive: result.capabilityActive, coverageStatus, revocationStatus });
  }
  result.valid = verdict.valid;
  result.failingRule = verdict.failingRule;
  result.reason = verdict.reason;
  result.detail = verdict.detail;
  return result;
}

/**
 * Fetch + verify the signed trust_mark_revocation_list_v1 and resolve a grant's
 * status. Returns `null` (rule 10 skipped) when no source is configured, or the
 * tri-state `not_revoked | revoked | unavailable`.
 */
async function resolveRevocationStatus(grantId, { proofBase, jwksBase, revocationsUrl, explicit }) {
  const url = revocationsUrl ?? `${proofBase}/api/public/proof/trustmark/revocations`;
  let res;
  try {
    res = await fetch(url, { headers: { Accept: "application/json" } });
  } catch {
    return explicit ? "unavailable" : null;
  }
  if (res.status === 404) return explicit ? "unavailable" : null;
  if (!res.ok) return "unavailable";
  let listDoc = null;
  try {
    listDoc = await res.json();
  } catch {
    return "unavailable";
  }
  // Resolve the authority key for the LIST's kid (same JWKS family as grants).
  const parsed = parseTrustMarkRevocationList(listDoc);
  let keys = [];
  if (parsed.ok) {
    try {
      keys = await fetchPublicKeys(parsed.value.kid, jwksBase);
    } catch {
      keys = [];
    }
  }
  return resolveGrantRevocation(grantId, listDoc, () => keys[0] ?? null);
}
