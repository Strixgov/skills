/**
 * AA-2 - Device Attestation v1 verifier (`device_attestation_v1`).
 *
 * The answer to **"is the device real?"** for a user-originated governed
 * action. AA-1 attests the *actor class* of the immediate caller; AA-2
 * attests that a `human`-class action actually came from a device that
 * presented a hardware-rooted assertion (a WebAuthn passkey, iOS App
 * Attest, or Android Play Integrity). Together they are what closes T3 --
 * an agent driving an authenticated human's own browser session via
 * cookie replay -- which AA-1 alone explicitly does NOT cover.
 *
 * ## Schema authority, and why this file is not it
 *
 * The normative schema, the 9 verifier rules, the 12 `aa2_*` reason codes,
 * and the DEVICE-PRE-2 matrix are owned by the Python reference
 * implementation in `Tarshann/solo-builder-core`
 * (`src/solo_builder/device_attestation.py`, ADR-016). THIS module is a
 * conformant port, and the bar stated by that repo's own promotion
 * checklist is exact:
 *
 *   "The TS verifier MUST agree byte-for-byte with
 *    solo_builder.device_attestation.verify_device_attestation."
 *
 * `test/device-attestation-conformance.test.mjs` replays all 15 published
 * vectors from `conformance/corpus/device_attestation_v1/` and asserts the
 * exact `failingRule` + `reason` pair on every negative. Drift fails CI.
 *
 * ## Rule order is the code's order, not the prose's order
 *
 * The Python docstring lists `signature` before `jwks_resolution`; the
 * Python *code* resolves the key first, because you cannot check a
 * signature without one. Ports must follow the CODE, or an unknown-kid
 * record reports `aa2_signature_invalid` where the corpus says
 * `aa2_unknown_kid`. Two further placements are deliberate and easy to get
 * wrong by "tidying":
 *
 *   - The tenant cross-check reports under the `device_pre_2` RULE with
 *     the `aa2_tenant_mismatch` REASON. Rule and reason are separate axes;
 *     do not invent a `tenant` rule to make them line up.
 *   - A REVOKED device fails the `revocation` rule with reason
 *     `aa2_signature_invalid` -- the assertion is no longer trusted --
 *     while an UNDETERMINABLE revocation answer gets its own reason,
 *     `aa2_revocation_check_unavailable`, which is the ONLY reason that
 *     renders as tri-state `verified: null`. Collapsing "could not check"
 *     into "failed" would report a device as untrustworthy because a
 *     distribution endpoint was down.
 *
 * ## Fail-closed on capability status
 *
 * Rule 4 refuses unless AA-2 is ACTIVE in the capability registry. AA-2 is
 * RESERVED until the cross-repo promotion (solo-builder-core's one-line
 * `RESERVED -> ACTIVE` flip landing the same day as strix-platform PR 2F).
 * `capabilityStatus` therefore defaults to `'reserved'` here: a caller
 * that forgets to pass it gets a refusal, never a pass. That is a dormancy
 * level, not an inconvenience.
 *
 * Zero dependencies -- `node:crypto` only, same as every other verifier in
 * this package. Independently implemented canonicalization (no import from
 * the producer side) so agreement is evidence rather than tautology.
 */

import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

// -- Locked vocabularies (ADR-016 section 1) ------------------------------

export const DEVICE_CLASS = Object.freeze({
  BROWSER: "browser",
  MOBILE_IOS: "mobile_ios",
  MOBILE_ANDROID: "mobile_android",
});

export const ATTESTATION_PROTOCOL = Object.freeze({
  WEBAUTHN: "webauthn",
  APP_ATTEST_IOS: "app_attest_ios",
  PLAY_INTEGRITY_ANDROID: "play_integrity_android",
});

/** The 9 verifier rules, in the fixed order `verifyDeviceAttestation` runs them. */
export const VERIFIER_RULE = Object.freeze({
  SCHEMA: "schema",
  SIGNATURE: "signature",
  JWKS_RESOLUTION: "jwks_resolution",
  CAPABILITY: "capability",
  DEVICE_CLASS: "device_class",
  ATTESTATION_PROTOCOL: "attestation_protocol",
  DEVICE_PRE_2: "device_pre_2",
  TIME_FRESHNESS: "time_freshness",
  REVOCATION: "revocation",
});

/** The 12 `aa2_*` reason codes. Stable strings -- consumers MAY pattern-match. */
export const DEVICE_CLASS_REASON = Object.freeze({
  SCHEMA_MISSING_FIELD: "aa2_schema_missing_field",
  SCHEMA_UNKNOWN_FIELD: "aa2_schema_unknown_field",
  SIGNATURE_INVALID: "aa2_signature_invalid",
  UNKNOWN_KID: "aa2_unknown_kid",
  UNKNOWN_ISS: "aa2_unknown_iss",
  CAPABILITY_NOT_ACTIVE: "aa2_capability_not_active",
  DEVICE_CLASS_INVALID: "aa2_device_class_invalid",
  ATTESTATION_PROTOCOL_INVALID: "aa2_attestation_protocol_invalid",
  PROTOCOL_DEVICE_MISMATCH: "aa2_protocol_device_mismatch",
  TENANT_MISMATCH: "aa2_tenant_mismatch",
  TIME_FRESHNESS_VIOLATED: "aa2_time_freshness_violated",
  REVOCATION_CHECK_UNAVAILABLE: "aa2_revocation_check_unavailable",
});

export const DEVICE_REVOCATION_STATUS = Object.freeze({
  NOT_REVOKED: "not_revoked",
  REVOKED: "revoked",
  UNAVAILABLE: "unavailable",
});

/** The 9 required payload fields (ADR-016 section 1). */
export const REQUIRED_PAYLOAD_FIELDS = Object.freeze([
  "attestation_protocol",
  "attested_at",
  "capability_id",
  "device_class",
  "device_id",
  "environment",
  "evidence_id",
  "iss",
  "tenant_id",
]);

export const AA_2 = "AA-2";

/**
 * DEVICE-PRE-2 allow-set. Mirrors
 * `solo_builder/device_class_matrix.snapshot.json`, vendored alongside the
 * corpus at `conformance/corpus/device_attestation_v1/`; the conformance
 * test loads that snapshot and asserts this set equals it, so a matrix
 * change cannot land in one implementation only.
 *
 * The 1:1 pairing is the point: the protocols are not interchangeable. A
 * mobile-browser action routes as `(browser, webauthn)` because the
 * cryptographic root is WebAuthn even on a phone. Every other combination
 * is `aa2_protocol_device_mismatch`.
 */
export const VALID_DEVICE_PROTOCOL_PAIRS = Object.freeze([
  Object.freeze([DEVICE_CLASS.BROWSER, ATTESTATION_PROTOCOL.WEBAUTHN]),
  Object.freeze([DEVICE_CLASS.MOBILE_IOS, ATTESTATION_PROTOCOL.APP_ATTEST_IOS]),
  Object.freeze([DEVICE_CLASS.MOBILE_ANDROID, ATTESTATION_PROTOCOL.PLAY_INTEGRITY_ANDROID]),
]);

const VALID_PAIR_KEYS = new Set(VALID_DEVICE_PROTOCOL_PAIRS.map(([d, p]) => `${d} ${p}`));

export function deviceClassMatchesProtocol(deviceClass, attestationProtocol) {
  return VALID_PAIR_KEYS.has(`${deviceClass} ${attestationProtocol}`);
}

// -- Own canonicalization (SCJ-v1-compatible; independently implemented) --

function canonicalize(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number in canonical payload");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(",")}}`;
  }
  throw new Error(`unsupported type in canonical payload: ${typeof value}`);
}

/** Canonical bytes the AA-2 signature covers. */
export function canonicalPayloadBytes(payload) {
  return Buffer.from(canonicalize(payload), "utf8");
}

/** Lowercase SHA-256 hex of the canonical payload bytes. */
export function payloadHash(payload) {
  return createHash("sha256").update(canonicalize(payload), "utf8").digest("hex");
}

// -- Typed construction (the construction-time negatives) ----------------

/**
 * Build a validated 9-field AA-2 payload.
 *
 * Throws -- deliberately -- rather than returning a result object. The
 * four construction-time corpus negatives assert that an unknown device
 * class, an unknown protocol, a non-`AA-2` capability id, and an empty
 * required string are all rejected here, before anything can be signed. A
 * payload that cannot be constructed cannot be attested to.
 */
export function buildDeviceAttestationPayload(input) {
  const capabilityId = input.capability_id;
  if (capabilityId !== AA_2) {
    throw new Error(
      `DeviceAttestationPayload.capability_id must equal "${AA_2}", got ${JSON.stringify(capabilityId)}`,
    );
  }
  const deviceClass = input.device_class;
  if (!Object.values(DEVICE_CLASS).includes(deviceClass)) {
    throw new Error(`device_class ${JSON.stringify(deviceClass)} is not a known DeviceClass`);
  }
  const attestationProtocol = input.attestation_protocol;
  if (!Object.values(ATTESTATION_PROTOCOL).includes(attestationProtocol)) {
    throw new Error(
      `attestation_protocol ${JSON.stringify(attestationProtocol)} is not a known AttestationProtocol`,
    );
  }
  for (const field of [
    "evidence_id",
    "device_id",
    "tenant_id",
    "attested_at",
    "iss",
    "environment",
  ]) {
    if (!input[field]) throw new Error(`${field} is required (non-empty)`);
  }
  return Object.freeze({
    attestation_protocol: attestationProtocol,
    attested_at: input.attested_at,
    capability_id: capabilityId,
    device_class: deviceClass,
    device_id: input.device_id,
    environment: input.environment,
    evidence_id: input.evidence_id,
    iss: input.iss,
    tenant_id: input.tenant_id,
  });
}

// -- Verification --------------------------------------------------------

function fail(rule, reason, detail) {
  return Object.freeze({ valid: false, failingRule: rule, reason, detail });
}

const OK = Object.freeze({ valid: true, failingRule: null, reason: null, detail: null });

function parseIso(value) {
  const cleaned =
    typeof value === "string" && value.endsWith("Z") ? value.replace(/Z$/, "+00:00") : value;
  const ms = Date.parse(cleaned);
  if (Number.isNaN(ms)) {
    throw new Error(`not a parseable ISO-8601 timestamp: ${JSON.stringify(value)}`);
  }
  return ms;
}

/**
 * Verify an AA-2 attestation record. Runs the 9 rules in fixed order and
 * short-circuits on the first failure.
 *
 * Never throws for a verification failure -- it returns a structured
 * result naming the failing rule and reason. It MAY throw `TypeError` for
 * a genuinely malformed argument (a non-object `record`).
 *
 * @param {object} record `{ payload, signature, kid, created_at }`.
 * @param {object} deps
 * @param {(payloadBytes: Buffer, signatureBytes: Buffer, publicKey: Buffer) => boolean} deps.signatureVerifier
 * @param {(args: {iss: string, kid: string}) => (Buffer|null)} deps.jwks
 * @param {string} deps.boundEvidenceTenant
 * @param {string|null} [deps.boundEvidenceOccurredAt]
 * @param {number} [deps.freshnessWindowSeconds=300]
 * @param {((args: {deviceId: string}) => string)|null} [deps.deviceRevocationResolver]
 * @param {'reserved'|'active'|'retired'} [deps.capabilityStatus='reserved'] Fails closed.
 */
export function verifyDeviceAttestation(record, deps) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    throw new TypeError(`unsupported record type: ${record === null ? "null" : typeof record}`);
  }
  const {
    signatureVerifier,
    jwks,
    boundEvidenceTenant,
    boundEvidenceOccurredAt = null,
    freshnessWindowSeconds = 300,
    deviceRevocationResolver = null,
    capabilityStatus = "reserved",
  } = deps || {};

  // Rule 1: schema.
  if (!("payload" in record)) {
    return fail(VERIFIER_RULE.SCHEMA, DEVICE_CLASS_REASON.SCHEMA_MISSING_FIELD, "payload missing");
  }
  const payload = record.payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return fail(
      VERIFIER_RULE.SCHEMA,
      DEVICE_CLASS_REASON.SCHEMA_MISSING_FIELD,
      "payload object missing",
    );
  }
  const signatureHex = String(record.signature || "");
  const kid = String(record.kid || "");
  if (!signatureHex) {
    return fail(
      VERIFIER_RULE.SCHEMA,
      DEVICE_CLASS_REASON.SCHEMA_MISSING_FIELD,
      "signature missing",
    );
  }
  if (!kid) {
    return fail(VERIFIER_RULE.SCHEMA, DEVICE_CLASS_REASON.SCHEMA_MISSING_FIELD, "kid missing");
  }
  for (const field of REQUIRED_PAYLOAD_FIELDS) {
    if (!(field in payload)) {
      return fail(
        VERIFIER_RULE.SCHEMA,
        DEVICE_CLASS_REASON.SCHEMA_MISSING_FIELD,
        `payload.${field} missing`,
      );
    }
  }
  const unknown = Object.keys(payload)
    .filter((k) => !REQUIRED_PAYLOAD_FIELDS.includes(k))
    .sort();
  if (unknown.length > 0) {
    return fail(
      VERIFIER_RULE.SCHEMA,
      DEVICE_CLASS_REASON.SCHEMA_UNKNOWN_FIELD,
      `unknown payload fields: ${JSON.stringify(unknown)}`,
    );
  }

  // Rule 3 runs before rule 2 -- you cannot check a signature without a key.
  const iss = payload.iss;
  // An ABSENT or mis-shaped key source is a named refusal, never a crash. A
  // TypeError escaping a verifier is the worst possible outcome: the caller's
  // try/catch decides the verdict instead of the verifier, and "the resolver
  // was not wired" becomes indistinguishable from "the process fell over".
  // Fail-closed means an unresolvable key produces UNKNOWN_KID -- cannot
  // verify -- which the deviceClass block renders as verified:null.
  if (
    jwks === null ||
    jwks === undefined ||
    (typeof jwks !== "function" && typeof jwks.public_key !== "function")
  ) {
    return fail(
      VERIFIER_RULE.JWKS_RESOLUTION,
      DEVICE_CLASS_REASON.UNKNOWN_KID,
      "no key source supplied to the verifier",
    );
  }
  const publicKey =
    typeof jwks === "function" ? jwks({ iss, kid }) : jwks.public_key({ iss, kid });
  if (publicKey === null || publicKey === undefined) {
    return fail(
      VERIFIER_RULE.JWKS_RESOLUTION,
      DEVICE_CLASS_REASON.UNKNOWN_KID,
      `no key for (iss=${iss}, kid=${kid})`,
    );
  }

  // Rule 2: signature.
  if (!/^[0-9a-fA-F]*$/.test(signatureHex) || signatureHex.length % 2 !== 0) {
    return fail(
      VERIFIER_RULE.SIGNATURE,
      DEVICE_CLASS_REASON.SIGNATURE_INVALID,
      "signature is not hex-encoded",
    );
  }
  const signatureBytes = Buffer.from(signatureHex, "hex");
  if (!signatureVerifier(canonicalPayloadBytes(payload), signatureBytes, publicKey)) {
    return fail(
      VERIFIER_RULE.SIGNATURE,
      DEVICE_CLASS_REASON.SIGNATURE_INVALID,
      "signature verification failed",
    );
  }

  // Rule 4: capability.
  if (payload.capability_id !== AA_2) {
    return fail(
      VERIFIER_RULE.CAPABILITY,
      DEVICE_CLASS_REASON.CAPABILITY_NOT_ACTIVE,
      `capability_id must be "${AA_2}", got ${JSON.stringify(payload.capability_id)}`,
    );
  }
  if (capabilityStatus !== "active") {
    return fail(
      VERIFIER_RULE.CAPABILITY,
      DEVICE_CLASS_REASON.CAPABILITY_NOT_ACTIVE,
      `AA-2 capability status is ${JSON.stringify(capabilityStatus)}, expected 'active'`,
    );
  }

  // Rule 5: device class enum.
  const deviceClass = payload.device_class;
  if (!Object.values(DEVICE_CLASS).includes(deviceClass)) {
    return fail(
      VERIFIER_RULE.DEVICE_CLASS,
      DEVICE_CLASS_REASON.DEVICE_CLASS_INVALID,
      `device_class ${JSON.stringify(deviceClass)} is not a known DeviceClass`,
    );
  }

  // Rule 6: attestation protocol enum.
  const attestationProtocol = payload.attestation_protocol;
  if (!Object.values(ATTESTATION_PROTOCOL).includes(attestationProtocol)) {
    return fail(
      VERIFIER_RULE.ATTESTATION_PROTOCOL,
      DEVICE_CLASS_REASON.ATTESTATION_PROTOCOL_INVALID,
      `attestation_protocol ${JSON.stringify(attestationProtocol)} is not a known AttestationProtocol`,
    );
  }

  // Rule 7: DEVICE-PRE-2 cross-check, then the tenant cross-check.
  // Both report under the device_pre_2 RULE; they carry different REASONS.
  if (!deviceClassMatchesProtocol(deviceClass, attestationProtocol)) {
    return fail(
      VERIFIER_RULE.DEVICE_PRE_2,
      DEVICE_CLASS_REASON.PROTOCOL_DEVICE_MISMATCH,
      `device_class=${deviceClass} is not compatible with attestation_protocol=${attestationProtocol}`,
    );
  }
  if (payload.tenant_id !== boundEvidenceTenant) {
    return fail(
      VERIFIER_RULE.DEVICE_PRE_2,
      DEVICE_CLASS_REASON.TENANT_MISMATCH,
      `attestation tenant_id=${JSON.stringify(payload.tenant_id)} != bound evidence tenant=${JSON.stringify(boundEvidenceTenant)}`,
    );
  }

  // Rule 8: time freshness (only when bound evidence supplies a stamp).
  if (boundEvidenceOccurredAt !== null && boundEvidenceOccurredAt !== undefined) {
    let attestedMs;
    let occurredMs;
    try {
      attestedMs = parseIso(payload.attested_at);
      occurredMs = parseIso(boundEvidenceOccurredAt);
    } catch (err) {
      return fail(
        VERIFIER_RULE.TIME_FRESHNESS,
        DEVICE_CLASS_REASON.TIME_FRESHNESS_VIOLATED,
        err instanceof Error ? err.message : String(err),
      );
    }
    const deltaSeconds = Math.abs(attestedMs - occurredMs) / 1000;
    if (deltaSeconds > freshnessWindowSeconds) {
      return fail(
        VERIFIER_RULE.TIME_FRESHNESS,
        DEVICE_CLASS_REASON.TIME_FRESHNESS_VIOLATED,
        `attested_at vs occurred_at delta ${deltaSeconds}s exceeds freshness window ${freshnessWindowSeconds}s`,
      );
    }
  }

  // Rule 9: revocation (only when a resolver is supplied).
  if (deviceRevocationResolver !== null && deviceRevocationResolver !== undefined) {
    const status = deviceRevocationResolver({ deviceId: payload.device_id });
    if (status === DEVICE_REVOCATION_STATUS.UNAVAILABLE) {
      return fail(
        VERIFIER_RULE.REVOCATION,
        DEVICE_CLASS_REASON.REVOCATION_CHECK_UNAVAILABLE,
        `device revocation list unavailable for device_id=${JSON.stringify(payload.device_id)}`,
      );
    }
    if (status === DEVICE_REVOCATION_STATUS.REVOKED) {
      return fail(
        VERIFIER_RULE.REVOCATION,
        DEVICE_CLASS_REASON.SIGNATURE_INVALID,
        `device_id=${JSON.stringify(payload.device_id)} is on the revocation list -- assertion no longer trusted`,
      );
    }
  }

  return OK;
}

/** Ed25519 verifier for the common case. Never throws on malformed key material. */
export function ed25519SignatureVerifier(payloadBytes, signatureBytes, publicKeyBytes) {
  try {
    const key = createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(publicKeyBytes),
      ]),
      format: "der",
      type: "spki",
    });
    return edVerify(null, payloadBytes, key, signatureBytes);
  } catch {
    return false;
  }
}

// -- Public `deviceClass` block (ADR-016 section 5) -----------------------

/**
 * The ONLY reason code that renders as tri-state `verified: null` rather
 * than `verified: false`.
 *
 * "The revocation surface was unreachable" is not the same statement as
 * "this device failed verification," and a public proof surface that
 * conflates them reports a healthy device as untrustworthy during an
 * unrelated outage. Same discipline as AA-1's parallel set and the
 * platform-wide UNVERIFIABLE-is-not-INVALID rule.
 */
export const SUBSTRATE_ERROR_REASONS = Object.freeze([
  DEVICE_CLASS_REASON.REVOCATION_CHECK_UNAVAILABLE,
]);

/**
 * Build the public `deviceClass` block.
 *
 * - no attestation record -> `verified: null`, no reason (legacy, or the
 *   action was not user-originated so AA-2 was never expected)
 * - valid -> `verified: true`
 * - invalid, substrate-error reason -> `verified: null` + reason
 * - invalid, any other reason -> `verified: false` + reason
 */
export function renderDeviceClassBlock(attestationRecord, verification) {
  if (attestationRecord === null || attestationRecord === undefined) {
    return Object.freeze({
      claimedClass: null,
      verified: null,
      verificationReason: null,
      attestationProtocol: null,
    });
  }
  const payload = attestationRecord.payload || {};
  const claimedClass = payload.device_class ?? null;
  const attestationProtocol = payload.attestation_protocol ?? null;

  if (verification === null || verification === undefined) {
    return Object.freeze({
      claimedClass,
      verified: null,
      verificationReason: null,
      attestationProtocol,
    });
  }
  if (verification.valid) {
    return Object.freeze({
      claimedClass,
      verified: true,
      verificationReason: null,
      attestationProtocol,
    });
  }
  const substrateError = SUBSTRATE_ERROR_REASONS.includes(verification.reason);
  return Object.freeze({
    claimedClass,
    verified: substrateError ? null : false,
    verificationReason: verification.reason ?? null,
    attestationProtocol,
  });
}
