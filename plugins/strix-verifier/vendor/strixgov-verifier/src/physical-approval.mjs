/**
 * Physical Approval Bridge v1 — independent verifier.
 *
 * Zero shared code with the producer
 * (apps/strix-console/src/lib/physical-approval/): this module re-implements
 * SCJ-v1-compatible canonicalization, content addressing, the confirmation
 * fingerprint, and Ed25519 verification using only node:crypto, and replays
 * the producer's locked golden vectors as a cross-implementation conformance
 * pin (test/physical-approval.test.mjs).
 *
 * Honest boundary, carried on every result:
 *   - The verdict attests SIGNATURE + BINDING between the presented request
 *     and response. It does NOT attest that the named person pressed a
 *     button, that organizational authority existed, that quorum was met, or
 *     that anything executed — those live in kernel records with their own
 *     verifiers (`provesApproverPresence: false`, `provesExecution: false`).
 *   - The caller supplies the authoritative request record; this verifier
 *     proves the response binds to THOSE bytes.
 *   - No device key supplied ⇒ the verdict caps at UNVERIFIABLE, never
 *     VERIFIED and never INVALID (cannot-verify ≠ proven-wrong).
 *
 * Release surfaces (1.23.0): exports-map subpath `./physical-approval`,
 * CLI subcommand `strix-verify physical-approval <requestId>` (fetches the
 * public projection at /api/public/proof/physical-approval/<id>, or reads a
 * --proof file fully offline), and MIRROR_FILES. npm publish remains an
 * operator action — cite `lint-distribution-truth --registry`, never prose.
 */

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

export const PHYSICAL_APPROVAL_REASONS = [
  "PAB_OK",
  "PAB_REQUEST_MALFORMED",
  "PAB_RESPONSE_MALFORMED",
  "PAB_ALGORITHM_UNSUPPORTED",
  "PAB_KEY_UNRESOLVED",
  "PAB_SIGNATURE_INVALID",
  "PAB_BINDING_MISMATCH",
  // PAB-24: the response's SIGNED approvalRoundId disagrees with the request's.
  // A dedicated reason (not folded into PAB_BINDING_MISMATCH) so a
  // cross-ceremony response is legible as exactly that — a round mismatch.
  "PAB_ROUND_MISMATCH",
  "PAB_EXPIRED_AT_RESPONSE",
  "PAB_FINGERPRINT_MISMATCH",
];

// ── Independent SCJ-v1-compatible canonicalization ─────────────────────────

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

function sha256HexOfCanonical(value) {
  return createHash("sha256").update(canonicalize(value), "utf8").digest("hex");
}

export { canonicalize as canonicalizePhysicalApproval, sha256HexOfCanonical as physicalApprovalContentAddress };

// ── Strict RFC 3339 (own implementation — no shared code) ──────────────────

const RFC3339_STRICT_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

function parseStrictRfc3339(s) {
  if (typeof s !== "string" || !RFC3339_STRICT_RE.test(s)) return null;
  const ms = Date.parse(s);
  return Number.isFinite(ms) ? ms : null;
}

// ── Schema shape (independent re-statement of the locked field sets) ───────

const REQUEST_FIELDS = [
  "schemaVersion",
  "requestId",
  "approvalRoundId",
  "decisionId",
  "capabilityId",
  "actionParamsHash",
  "policyVersion",
  "tenantId",
  "environment",
  "requestingActorId",
  "requestingActorClass",
  "requestedApproverId",
  "requestedDeviceId",
  "riskLevel",
  "issuedAt",
  "expiresAt",
  "nonce",
];

const RESPONSE_PAYLOAD_FIELDS = [
  "schemaVersion",
  "requestId",
  "approvalRoundId",
  "decisionId",
  "capabilityId",
  "actionParamsHash",
  "tenantId",
  "environment",
  "approverId",
  "deviceId",
  "deviceKeyId",
  "decision",
  "requestNonce",
  "respondedAt",
  "signatureAlgorithm",
];

function hasExactKeys(obj, fields) {
  const keys = Object.keys(obj);
  if (keys.length !== fields.length) return false;
  return fields.every((f) => keys.includes(f) && typeof obj[f] !== "undefined");
}

/**
 * Confirmation fingerprint — first 12 hex of the request content address,
 * uppercase, grouped XXXX-XXXX-XXXX. Re-derived independently.
 */
export function derivePhysicalApprovalFingerprint(request) {
  const hex = sha256HexOfCanonical(request).slice(0, 12).toUpperCase();
  return `${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}`;
}

/**
 * Verify one physical approval response against the presented request.
 *
 * @param {object} input  { request, response, deviceKeyJwk }
 * @param {object} [opts] { expectedFingerprint }
 * @returns {{ verdict: "VERIFIED"|"INVALID"|"UNVERIFIABLE", decision: string|null,
 *            reasons: string[], requestHash: string|null, fingerprint: string|null,
 *            provesApproverPresence: false, provesExecution: false }}
 */
export function verifyPhysicalApproval(input, opts = {}) {
  const reasons = [];
  const boundary = { provesApproverPresence: false, provesExecution: false };
  let verdict = "VERIFIED";
  const cap = (v) => {
    if (v === "INVALID") verdict = "INVALID";
    else if (v === "UNVERIFIABLE" && verdict === "VERIFIED") verdict = "UNVERIFIABLE";
  };

  const request = input?.request;
  const response = input?.response;

  if (typeof request !== "object" || request === null || Array.isArray(request) ||
      request.schemaVersion !== 2 || !hasExactKeys(request, REQUEST_FIELDS)) {
    return {
      verdict: "INVALID", decision: null,
      reasons: ["PAB_REQUEST_MALFORMED"], requestHash: null, fingerprint: null, ...boundary,
    };
  }
  const requestHash = sha256HexOfCanonical(request);
  const fingerprint = derivePhysicalApprovalFingerprint(request);

  if (typeof opts.expectedFingerprint === "string" && opts.expectedFingerprint !== fingerprint) {
    cap("INVALID");
    reasons.push("PAB_FINGERPRINT_MISMATCH");
  }

  if (typeof response !== "object" || response === null || Array.isArray(response) ||
      response.schemaVersion !== 2 || typeof response.signature !== "string") {
    return {
      verdict: "INVALID", decision: null,
      reasons: [...reasons, "PAB_RESPONSE_MALFORMED"], requestHash, fingerprint, ...boundary,
    };
  }
  const { signature, ...payload } = response;
  if (!hasExactKeys(payload, RESPONSE_PAYLOAD_FIELDS)) {
    return {
      verdict: "INVALID", decision: null,
      reasons: [...reasons, "PAB_RESPONSE_MALFORMED"], requestHash, fingerprint, ...boundary,
    };
  }

  if (payload.signatureAlgorithm !== "Ed25519") {
    cap("INVALID");
    reasons.push("PAB_ALGORITHM_UNSUPPORTED");
  }

  // PAB-24 round binding (checked first, distinct reason): the response's
  // SIGNED approvalRoundId must equal the presented request's. This is the
  // property that makes two ceremonies non-composable — a response signed under
  // round R2 can never verify against a request of round R1, because the round
  // id is inside the bytes both signatures cover.
  if (payload.approvalRoundId !== request.approvalRoundId) {
    cap("INVALID");
    reasons.push("PAB_ROUND_MISMATCH");
  }

  // Binding: every other echoed field must equal the presented request's value.
  const bindings = [
    ["requestId", payload.requestId, request.requestId],
    ["decisionId", payload.decisionId, request.decisionId],
    ["capabilityId", payload.capabilityId, request.capabilityId],
    ["actionParamsHash", payload.actionParamsHash, request.actionParamsHash],
    ["tenantId", payload.tenantId, request.tenantId],
    ["environment", payload.environment, request.environment],
    ["requestNonce", payload.requestNonce, request.nonce],
  ];
  for (const [, got, want] of bindings) {
    if (got !== want) {
      cap("INVALID");
      if (!reasons.includes("PAB_BINDING_MISMATCH")) reasons.push("PAB_BINDING_MISMATCH");
    }
  }

  // Device-claimed lateness: respondedAt at/after expiresAt is INVALID even
  // when the signature verifies (expiry outranks cryptography).
  const responded = parseStrictRfc3339(payload.respondedAt);
  const expires = parseStrictRfc3339(request.expiresAt);
  if (responded === null || expires === null) {
    cap("INVALID");
    reasons.push("PAB_RESPONSE_MALFORMED");
  } else if (responded >= expires) {
    cap("INVALID");
    reasons.push("PAB_EXPIRED_AT_RESPONSE");
  }

  // Signature — or an honest UNVERIFIABLE cap when no key was supplied.
  const jwk = input?.deviceKeyJwk;
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    cap("UNVERIFIABLE");
    reasons.push("PAB_KEY_UNRESOLVED");
  } else {
    let ok = false;
    try {
      const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
      ok = cryptoVerify(
        null,
        Buffer.from(canonicalize(payload), "utf8"),
        key,
        Buffer.from(signature, "base64url"),
      );
    } catch {
      ok = false;
    }
    if (!ok) {
      cap("INVALID");
      reasons.push("PAB_SIGNATURE_INVALID");
    }
  }

  if (verdict === "VERIFIED" && reasons.length === 0) reasons.push("PAB_OK");
  return {
    verdict,
    decision: verdict === "VERIFIED" ? payload.decision : null,
    reasons,
    requestHash,
    fingerprint,
    ...boundary,
  };
}
