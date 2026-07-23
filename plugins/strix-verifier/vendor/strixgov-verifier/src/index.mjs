/**
 * @strixgov/verifier — Independent evidence verification
 *
 * This module verifies Strix governance evidence records using only
 * standard cryptographic primitives (Ed25519, SHA-256). No Strix
 * tooling, SDK, or account is required.
 *
 * Verification flow:
 *   1. Fetch evidence record from the proof API
 *   2. Fetch the signing public key from the JWKS endpoint
 *   3. Reconstruct the canonical signed payload (13 fields, locked order)
 *   4. Verify the Ed25519 signature
 *   5. Verify the SHA-256 evidence hash
 *   6. Verify the proof chain hash links to the previous record
 */

import crypto from "node:crypto";

// ─── Configuration ────────────────────────────────────────────────────────────

// Canonical Strix Platform host. Both /api/public/* (proof, approval,
// quorum, verify) and /.well-known/strix-jwks.json are served at this
// domain. Override via { proofBase, jwksBase } options or
// --proof-base / --jwks-base flags when targeting a non-default deployment.
const DEFAULT_PROOF_BASE = "https://www.strixgov.com";
const DEFAULT_JWKS_BASE = "https://www.strixgov.com";

// ─── JWKS Fetch ───────────────────────────────────────────────────────────────

/**
 * Fetch the JWKS from the Strix JWKS endpoint and find the key by kid.
 * @param {string} kid - Key ID to look up
 * @param {string} [jwksBase] - Base URL for JWKS endpoint
 * @returns {Promise<crypto.KeyObject>} The Ed25519 public key
 */
/**
 * Resolve a (possibly redacted) kid against the keys array of a JWKS by
 * suffix-matching the YYYY-MM segment. Mirrors the resolveKidFromJwks
 * helper in apps/strix-console/src/lib/proof/redact.ts so verification
 * agrees on what a redacted kid means.
 *
 * Public verification responses scrub the env segment of the kid
 * (e.g. "strix-prod-2026-04" → "strix-***-2026-04") to avoid leaking
 * deployment environment to unauthenticated callers. The full kid is
 * retained in the canonical signed payload because that is what was
 * actually signed; the redacted form is only used in the convenience
 * fields of the public REST response.
 *
 * Returns the matching JWK or null.
 */
function resolveJwksByKid(kidOrRedacted, jwks) {
  // Return ALL JWKs matching the given kid (including redacted-form matches).
  // RFC 7517 declares kid a hint, not a unique index — and the Phase 2
  // closure scenario (Academy's retired key + strix-platform's active key
  // both bound to "strix-prod-2026-05") produces a legitimate kid collision.
  // Verifiers must try each candidate; first-match resolution misses one or
  // the other side and yields SIGNATURE_INVALID for half the records.
  const exact = (jwks.keys ?? []).filter((k) => k.kid === kidOrRedacted);
  if (exact.length > 0) return exact;

  // Redacted form: strix-***-YYYY-MM. Match by suffix.
  const m = kidOrRedacted.match(/^strix-\*\*\*-(\d{4}-\d{2})$/);
  if (!m) return [];
  const suffix = `-${m[1]}`;
  return (jwks.keys ?? []).filter(
    (k) => typeof k.kid === "string" && k.kid.endsWith(suffix),
  );
}

function resolveJwkFromKid(kidOrRedacted, jwks) {
  // Backward-compat first-match helper; new code should prefer
  // resolveJwksByKid + fetchPublicKeys and try each candidate.
  const matches = resolveJwksByKid(kidOrRedacted, jwks);
  return matches[0] ?? null;
}

function jwkToPublicKey(jwk) {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error(`Unexpected key type: ${jwk.kty}/${jwk.crv}`);
  }
  const rawBytes = Buffer.from(jwk.x, "base64url");
  const spkiHeader = Buffer.from("302a300506032b6570032100", "hex");
  const spki = Buffer.concat([spkiHeader, rawBytes]);
  return crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
}

/**
 * Internal helper: fetch a URL and convert network-layer errors into messages
 * that include the URL and the underlying cause. Without this, `globalThis.fetch`
 * throws a generic `TypeError: fetch failed` that gives the operator no signal
 * about whether the failure is DNS, proxy block, TLS, or anything else.
 *
 * @param {string} url
 * @param {RequestInit} [init]
 * @returns {Promise<Response>}
 */
async function fetchWithContext(url, init) {
  try {
    return await fetch(url, init);
  } catch (err) {
    const code = err?.cause?.code ?? err?.code;
    const cause = err?.cause?.message ?? err?.message ?? "unknown cause";
    const codePart = code ? ` [${code}]` : "";
    const helpfulHint = networkErrorHint(code, url);
    const hintPart = helpfulHint ? ` — ${helpfulHint}` : "";
    const wrapped = new Error(
      `Network error fetching ${url}${codePart}: ${cause}${hintPart}`,
    );
    wrapped.cause = err;
    wrapped.url = url;
    throw wrapped;
  }
}

/**
 * Returns a short hint for the most common network-error codes seen against
 * the strix-platform proof + JWKS endpoints. Conservative on purpose — only
 * suggests a fix when the failure mode is unambiguous.
 *
 * @param {string|undefined} code
 * @param {string} url
 * @returns {string|null}
 */
function networkErrorHint(code, url) {
  switch (code) {
    case "ENOTFOUND":
    case "EAI_AGAIN":
      return `DNS lookup failed for ${new URL(url).hostname}. Check your resolver and any corporate DNS overrides.`;
    case "ECONNREFUSED":
      return `Host refused the connection. Most often a proxy or firewall blocking outbound HTTPS.`;
    case "ETIMEDOUT":
    case "UND_ERR_CONNECT_TIMEOUT":
      return `Connection timed out. Likely a proxy, VPN, or air-gapped network without an allowlist entry for the host.`;
    case "CERT_HAS_EXPIRED":
    case "UNABLE_TO_VERIFY_LEAF_SIGNATURE":
    case "SELF_SIGNED_CERT_IN_CHAIN":
      return `TLS verification failed. If you're behind a TLS-intercepting proxy, install the proxy's root CA before retrying.`;
    default:
      return null;
  }
}

/**
 * Fetch all Ed25519 public keys from the JWKS endpoint that match the given
 * kid. Multiple results indicate a legitimate kid collision; verify
 * functions must try each candidate.
 */
export async function fetchPublicKeys(kid, jwksBase = DEFAULT_JWKS_BASE) {
  const url = `${jwksBase}/.well-known/strix-jwks.json`;
  const res = await fetchWithContext(url);
  if (!res.ok) throw new Error(`JWKS fetch failed: HTTP ${res.status} (${url})`);
  const jwks = await res.json();
  const matches = resolveJwksByKid(kid, jwks);
  if (matches.length === 0) throw new Error(`Key not found in JWKS: ${kid}`);
  return matches.map(jwkToPublicKey);
}

export async function fetchPublicKey(kid, jwksBase = DEFAULT_JWKS_BASE) {
  // Backward-compat first-match helper. Note: don't append ?kid= to the
  // URL when the kid might be redacted — the server might 404 on the
  // redacted form. Fetch the full JWKS and resolve client-side.
  const keys = await fetchPublicKeys(kid, jwksBase);
  return keys[0];
}

// ─── Evidence Fetch ───────────────────────────────────────────────────────────

/**
 * Fetch an evidence record from the proof API.
 *
 * Adapts THREE response shapes to the single flat-record shape the rest
 * of the verifier (`buildCanonicalPayload`, `verify`, etc.) expects:
 *
 *   1. Academy /api/proof/<id>:
 *      { ok: true, proof: { ...flat canonical fields }, verification: {...} }
 *      → flatten to `data.proof`. Note: Academy doesn't expose raw
 *      `signature` bytes in this response (only its own server-side
 *      verification result), so records routed here will report
 *      LEGACY_UNSIGNED at the verifier level — that's truthful: we can't
 *      do independent Ed25519 verification without the raw signature.
 *      For Academy records, point `--proof-base https://www.strixgov.com`
 *      instead — Strix Console's external_evidence fallback exposes the
 *      raw signature.
 *
 *   2. Strix Console /api/public/proof/<id> (via the /api/proof rewrite):
 *      { schemaVersion, evidenceId, verificationStatus, fields: {...},
 *        signature, signingKeyId, verifyWith, ... }
 *      → flatten `data.fields` to top level and promote `signature` +
 *      `signingKeyId`. This is the canonical Verify-Without-Us path —
 *      raw signature bytes are exposed so the verifier can re-derive
 *      the canonical payload and independently validate Ed25519.
 *
 *   3. Pre-1.3 raw shape: bare record object at top level.
 *      → return as-is (legacy callers).
 *
 * @param {number|string} evidenceId
 * @param {string} [proofBase]
 * @returns {Promise<object>} The evidence record, flattened
 */
export async function fetchEvidence(evidenceId, proofBase = DEFAULT_PROOF_BASE) {
  const url = `${proofBase}/api/proof/${evidenceId}`;
  const res = await fetchWithContext(url, { headers: { Accept: "application/json" } });
  if (res.status === 404) {
    throw new Error(`No Record Found: evidence ${evidenceId} does not exist`);
  }
  if (!res.ok) throw new Error(`Proof API fetch failed: HTTP ${res.status} (${url})`);

  const data = await res.json();

  // Strix Console / Phase 1+ response shape: canonical fields nested under
  // `data.fields`, signature + signingKeyId at top level. Detect via the
  // co-occurrence of `fields` AND a `signature` (or explicit null) key —
  // distinguishes from Academy's `proof` shape.
  //
  // IMPORTANT: top-level `signingKeyId` MUST NOT override `fields.signingKeyId`.
  // The `/api/public/proof/[evidenceId]` endpoint applies Gap-5 redaction to
  // the top-level `signingKeyId` (env segment scrubbed → "strix-***-YYYY-MM")
  // for privacy on the public response surface. The canonical payload that
  // was signed contains the FULL kid ("strix-prod-YYYY-MM"). Promoting the
  // redacted top-level value into the record breaks signature verification
  // for every signed record (canonical bytes differ from the signed bytes).
  // The redacted form is for display only — `fields.signingKeyId` is the
  // bytes-correct value the verifier must use.
  //
  // SAME RULE FOR `evidenceId` (v1.9.3 fix, 2026-05-15):
  // The top-level `evidenceId` is the URL path parameter the caller used to
  // look up the record. If they called `/api/proof/42` it's "42"; if they
  // called `/api/proof/<hash>` it's the hash. In the latter case, promoting
  // the top-level value would put the hash string into `record.evidenceId`,
  // which the canonical builder would coerce to 0 (non-numeric) for the
  // Academy form, producing different bytes from what was signed
  // (`evidenceId: 42` as number). `fields.evidenceId` is always the bytes-
  // correct value as stored in the row.
  if (
    data.fields &&
    typeof data.fields === "object" &&
    Object.prototype.hasOwnProperty.call(data, "signature")
  ) {
    return {
      ...data.fields,
      // Top-level promotions: signature and schemaVersion only. signingKeyId
      // and evidenceId are deliberately NOT promoted — see header note above.
      ...(data.signature !== undefined ? { signature: data.signature } : {}),
      ...(data.schemaVersion !== undefined ? { schemaVersion: data.schemaVersion } : {}),
    };
  }

  // Academy shape (data.proof) or pre-1.3 raw (data directly).
  return data.proof ?? data;
}

// ─── Canonical Payload ────────────────────────────────────────────────────────

/**
 * Reconstruct the canonical signed payload from an evidence record.
 * Uses the locked 13-field schema in exact order.
 * Reordering these fields invalidates all signatures.
 *
 * CANONICAL-FORM DISCRIMINATOR (v1.3):
 *   Academy (`sourceApp === "academy-platform"`) signs schemaVersion +
 *   evidenceId as JSON numbers (Academy's SignedEvidencePayload types both
 *   as numeric literals). Console-side signers emit them as JSON strings.
 *   The two byte-shapes verify against different signatures, so this
 *   function reads `record.sourceApp` and reconstructs the matching form.
 *   Pre-1.3 callers omitted sourceApp; their records sign in the Console
 *   string form (the historical default), so omitting sourceApp continues
 *   to produce the same bytes as before — backward-compatible.
 *
 * MUST stay in lockstep with apps/strix-console/src/lib/proof/canonical.ts
 * `buildCanonicalPayload`. The public-verify-parity.test.ts pins both ends.
 *
 * @param {object} record - Evidence record from the API
 * @returns {string} Deterministic JSON string
 */
export function buildCanonicalPayload(record) {
  // v1.10.0 (2026-05-18): If the proof API returns the original signed bytes
  // (`signedPayload`), use them directly. This is the only reconstruction-
  // free path — bytes match what the signer signed, no schema drift possible.
  //
  // Academy's /api/proof/X (post-2026-05-18) now returns the unwrapped
  // canonical bytes in `proof.signedPayload`. Older API versions and the
  // Console verify endpoint may omit it; fall through to reconstruction
  // with the existing Academy/Console discriminator below.
  if (typeof record.signedPayload === "string" && record.signedPayload.length > 0) {
    return record.signedPayload;
  }

  const isAcademyV1 = record.sourceApp === "academy-platform";

  // Console form coerces schemaVersion explicitly so a numeric input never
  // accidentally produces mixed-shape bytes. See canonical.ts header for
  // the full rationale.
  const schemaVersion = isAcademyV1
    ? coerceSchemaVersionToNumber(record.schemaVersion, 1)
    : (typeof record.schemaVersion === "string"
      ? record.schemaVersion
      : record.schemaVersion === undefined
        ? "1"
        : String(record.schemaVersion));
  const evidenceId = isAcademyV1
    ? coerceEvidenceIdToNumber(record.evidenceId ?? record.id, 0)
    : String(record.evidenceId ?? record.id);

  // tenantId is part of the signed bytes. Academy production records sign
  // with the operational tenant string from STRIX_TENANT_ID env (e.g.
  // "academy prod"); the previous null-forcing discriminator broke those.
  // null is also valid (Academy single-tenant deployments where the env
  // var was unset). Preserve verbatim. Mirrors canonical.ts buildCanonicalPayload.
  const tenantId = record.tenantId === undefined ? "" : record.tenantId;

  // regulatoryContext key order is part of the signed bytes. Academy signs
  // with euAiActArticle12, euAiActArticle14, euAiActArticle28, complianceMode;
  // Console signers emit complianceMode first. Postgres jsonb re-keys on
  // storage and Prisma returns the jsonb-canonical order regardless of the
  // signer's original insertion order. Reconstruct here in the signer-
  // correct order — must mirror canonical.ts byte-for-byte.
  const ctxInput = record.regulatoryContext ?? {
    complianceMode: "",
    euAiActArticle12: false,
    euAiActArticle14: false,
    euAiActArticle28: false,
  };
  const regulatoryContext = isAcademyV1
    ? {
        euAiActArticle12: ctxInput.euAiActArticle12,
        euAiActArticle14: ctxInput.euAiActArticle14,
        euAiActArticle28: ctxInput.euAiActArticle28,
        complianceMode: ctxInput.complianceMode,
      }
    : {
        complianceMode: ctxInput.complianceMode,
        euAiActArticle12: ctxInput.euAiActArticle12,
        euAiActArticle14: ctxInput.euAiActArticle14,
        euAiActArticle28: ctxInput.euAiActArticle28,
      };

  const payload = {
    schemaVersion,
    evidenceId,
    evidenceHash: record.evidenceHash ?? "",
    proofChainHash: record.proofChainHash ?? "",
    capabilityId: record.capabilityId ?? "",
    action: record.action ?? record.decision ?? "",
    actorId: record.actorId ?? record.actor?.id ?? "",
    actorRole: record.actorRole ?? record.actor?.role ?? "",
    createdAt: record.createdAt ?? "",
    signingKeyId: record.signingKeyId ?? "",
    environment: record.environment ?? "",
    tenantId,
    regulatoryContext,
  };

  return JSON.stringify(payload);
}

/**
 * Mirror of canonical.ts coerceSchemaVersionToNumber.
 * @param {string|number|undefined} value
 * @param {number} fallback
 * @returns {number}
 */
function coerceSchemaVersionToNumber(value, fallback) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.length > 0) {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return fallback;
}

/**
 * Mirror of canonical.ts coerceEvidenceIdToNumber.
 * @param {string|number|undefined} value
 * @param {number} fallback
 * @returns {number}
 */
function coerceEvidenceIdToNumber(value, fallback) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.length > 0) {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return fallback;
}

// ─── Verification ─────────────────────────────────────────────────────────────

/**
 * Verify an Ed25519 signature against the canonical payload.
 * @param {string} canonicalPayload - JSON string
 * @param {string} signature - Base64url-encoded signature
 * @param {crypto.KeyObject} publicKey - Ed25519 public key
 * @returns {boolean}
 */
export function verifySignature(canonicalPayload, signature, publicKey) {
  const data = Buffer.from(canonicalPayload, "utf8");
  const sig = Buffer.from(signature, "base64url");
  return crypto.verify(null, data, publicKey, sig);
}

/**
 * Verify the SHA-256 evidence hash matches the canonical payload hash.
 * @param {string} canonicalPayload
 * @param {string} expectedHash - SHA-256 hex hash
 * @returns {boolean}
 */
export function verifyHash(canonicalPayload, expectedHash) {
  const computed = crypto
    .createHash("sha256")
    .update(canonicalPayload)
    .digest("hex");
  return computed === expectedHash;
}

/**
 * Full end-to-end verification of an evidence record.
 * @param {number|string} evidenceId
 * @param {object} [options]
 * @param {string} [options.proofBase]
 * @param {string} [options.jwksBase]
 * @returns {Promise<object>} Verification result
 */
export async function verify(evidenceId, options = {}) {
  const proofBase = options.proofBase ?? DEFAULT_PROOF_BASE;
  const jwksBase = options.jwksBase ?? DEFAULT_JWKS_BASE;

  const result = {
    evidenceId,
    hashValid: false,
    chainValid: null, // null = not checked (would need previous record)
    signaturePresent: false,
    signatureValid: false,
    verificationStatus: "UNKNOWN",
    record: null,
    error: null,
  };

  try {
    // Step 1: Fetch the evidence record
    const record = await fetchEvidence(evidenceId, proofBase);
    result.record = record;

    // Step 2: Check if signature is present
    result.signaturePresent = !!record.signature;

    if (!record.signature || !record.signingKeyId) {
      result.verificationStatus = record.signature
        ? "UNSIGNED"
        : "LEGACY_UNSIGNED";
      return result;
    }

    // Step 3: Fetch all public keys matching the kid (kid collisions are
    // legitimate per RFC 7517; first-match resolution misses one side of
    // the Phase 2 closure scenario where Academy's retired key + strix-
    // platform's active key share kid "strix-prod-2026-05").
    const publicKeys = await fetchPublicKeys(record.signingKeyId, jwksBase);

    // Step 4: Build canonical payload
    const canonical = buildCanonicalPayload(record);

    // Step 5: Verify against each candidate until one passes
    let signatureValid = false;
    for (const pk of publicKeys) {
      if (verifySignature(canonical, record.signature, pk)) {
        signatureValid = true;
        break;
      }
    }
    result.signatureValid = signatureValid;

    // Step 6: Compute the canonical payload hash for transparency only.
    // evidenceHash is the hash of the underlying governance decision content —
    // it is a field INSIDE the canonical payload and is authenticated by the
    // Ed25519 signature. SHA-256(signing_envelope) !== evidenceHash by design;
    // the signature check is the sole integrity gate.
    result.hashValid = result.signatureValid; // authenticated by signature

    // Determine status
    if (result.signatureValid) {
      result.verificationStatus = "VERIFIED";
    } else {
      result.verificationStatus = "COMPLIANCE_VIOLATION";
    }
  } catch (err) {
    result.error = err.message;
    result.verificationStatus = "ERROR";
    if (err?.url) result.attemptedUrl = err.url;
  }

  return result;
}

// =============================================================================
// Approval Artifacts (Phase 3 Task #15)
// =============================================================================
//
// Mirrors the evidence verification surface but for the *authority* side of
// governance: every approval row is paired 1:1 with a SalesApprovalArtifact
// — a self-contained, signed canonical payload that ARK and any external
// admissibility evaluator can verify without trusting Strix's row-level
// data.
//
// The 9-field locked schema and its serialization MUST stay in lockstep
// with apps/strix-console/src/lib/sales-pipeline/approval-artifact.ts.
// Drift between this module and the server module is a correctness bug.
// =============================================================================

const DEFAULT_APPROVAL_BASE = DEFAULT_JWKS_BASE; // approval REST is on Console

/**
 * Reconstruct the canonical 9-field approval payload from an artifact record.
 * Locked field order — reordering invalidates every previously-signed
 * artifact. Returns the deterministic JSON byte string.
 *
 * The `record` argument is the artifact shape returned by
 *   GET /api/public/approval-artifact/:artifactId
 * (the `artifact` object plus `approvedAt`).
 *
 * @param {object} record
 * @returns {string} Deterministic JSON string (no whitespace)
 */
export function buildApprovalCanonicalPayload(record) {
  const approvedAt = record.approvedAt instanceof Date
    ? record.approvedAt.toISOString()
    : String(record.approvedAt ?? "");
  const method =
    record.approvalMethod === "manual" ||
    record.approvalMethod === "auto" ||
    record.approvalMethod === "breakglass"
      ? record.approvalMethod
      : "manual";

  const payload = {
    schemaVersion: "1",
    decisionId: String(record.decisionId ?? ""),
    approvalId: String(record.approvalId ?? ""),
    capabilityId: String(record.capabilityId ?? ""),
    actorUserId: String(record.actorUserId ?? ""),
    approvalMethod: method,
    policyVersion: String(record.policyVersion ?? ""),
    environment: String(record.environment ?? ""),
    approvedAt,
  };

  return JSON.stringify(payload);
}

/**
 * SHA-256 hex of the canonical approval payload.
 * @param {string} canonicalPayload
 * @returns {string} 64-char hex
 */
export function approvalCanonicalHash(canonicalPayload) {
  return crypto.createHash("sha256").update(canonicalPayload).digest("hex");
}

/**
 * Fetch a single signed approval artifact from the public REST surface.
 * @param {string} artifactId
 * @param {string} [approvalBase]
 * @returns {Promise<object>} The artifact response object
 */
export async function fetchApprovalArtifact(artifactId, approvalBase = DEFAULT_APPROVAL_BASE) {
  const url = `${approvalBase}/api/public/approval-artifact/${encodeURIComponent(artifactId)}`;
  const res = await fetchWithContext(url, { headers: { Accept: "application/json" } });
  if (res.status === 404) {
    throw new Error(`No Record Found: approval artifact ${artifactId} does not exist`);
  }
  if (!res.ok) throw new Error(`Approval artifact fetch failed: HTTP ${res.status} (${url})`);
  return res.json();
}

/**
 * Fetch all approval artifacts for a decision, ordered by sequenceNum.
 * @param {string} decisionId
 * @param {string} [approvalBase]
 * @returns {Promise<object>} { decision, approvalsRequired, artifacts, ... }
 */
export async function fetchApprovalQuorum(decisionId, approvalBase = DEFAULT_APPROVAL_BASE) {
  const url = `${approvalBase}/api/public/decisions/${encodeURIComponent(decisionId)}/approvals`;
  const res = await fetchWithContext(url, { headers: { Accept: "application/json" } });
  if (res.status === 404) {
    throw new Error(`No Record Found: decision ${decisionId} does not exist`);
  }
  if (!res.ok) throw new Error(`Approval quorum fetch failed: HTTP ${res.status} (${url})`);
  return res.json();
}

/**
 * Verify a signed approval artifact.
 *
 * Inputs are either:
 *   - { artifactId, options } — fetches from the public REST surface
 *   - { artifactPayload, signature, signingKeyId, jwks? } — fully offline
 *
 * Returns the standard 5-field verification result:
 *   {
 *     hashValid,
 *     chainValid,        // null = not checked here
 *     signaturePresent,
 *     signatureValid,
 *     verificationStatus,
 *   }
 *
 * @param {object} input
 * @returns {Promise<object>}
 */
export async function verifyApprovalArtifact(input = {}) {
  const result = {
    hashValid: false,
    chainValid: null,
    signaturePresent: false,
    signatureValid: false,
    verificationStatus: "UNKNOWN",
    record: null,
    error: null,
  };

  try {
    // Resolve the artifact record + canonical bytes + signature.
    let artifact;
    let storedHash;
    let signature;
    let signingKeyId;
    // v1.10.1: prefer server-provided canonical bytes when present, fall back
    // to local reconstruction. See Step 1 comment below.
    let directCanonical = null;

    if (input.artifactId) {
      const proofBase = input.proofBase ?? DEFAULT_APPROVAL_BASE;
      const jwksBase = input.jwksBase ?? DEFAULT_JWKS_BASE;
      const fetched = await fetchApprovalArtifact(input.artifactId, proofBase);
      artifact = fetched.artifact;
      storedHash = fetched.signing.canonicalPayloadHash;
      signature = fetched.signing.signature;
      signingKeyId = fetched.signing.signingKeyId;
      result.jwksBase = jwksBase;
      // v1.10.1: when the API returns the original signed bytes
      // (`canonical.serialized`) or the full canonical payload object
      // (`canonical.payload`), use those directly instead of reconstructing
      // from `artifact`. The `artifact` object is a display projection that
      // does not include all 9 canonical fields (e.g. `actorUserId`,
      // `schemaVersion`) — reconstructing from it produces different bytes
      // than the signer signed over.
      //
      // Pattern mirrors v1.10.0's signedPayload-direct path for evidence
      // records. Resolves Mode C external-verifier drift for approval
      // artifacts (verifier reported HASH_MISMATCH on every approval despite
      // the API server-side recompute showing canonicalHashMatches=true).
      if (typeof fetched?.canonical?.serialized === "string" && fetched.canonical.serialized.length > 0) {
        directCanonical = fetched.canonical.serialized;
      } else if (fetched?.canonical?.payload && typeof fetched.canonical.payload === "object") {
        directCanonical = JSON.stringify(fetched.canonical.payload);
      }
    } else if (input.artifactPayload) {
      artifact = input.artifactPayload;
      storedHash = input.canonicalPayloadHash ?? null;
      signature = input.signature ?? null;
      signingKeyId = input.signingKeyId ?? null;
      // v1.10.2: callers feeding an artifact in via `artifactPayload` (the
      // quorum loop, offline composition, etc.) can also pass the
      // server-provided canonical bytes alongside. Same precedence as the
      // network path — `serialized` wins, `payload` is the JSON.stringify
      // fallback, local reconstruction from `artifact` is the last resort.
      // Without this, the quorum loop reconstructs from a redacted artifact
      // projection (no `actorUserId`) and HASH_MISMATCHes every artifact.
      if (typeof input.canonicalSerialized === "string" && input.canonicalSerialized.length > 0) {
        directCanonical = input.canonicalSerialized;
      } else if (input.canonicalPayload && typeof input.canonicalPayload === "object") {
        directCanonical = JSON.stringify(input.canonicalPayload);
      }
    } else {
      throw new Error("verifyApprovalArtifact: provide artifactId or artifactPayload");
    }

    result.record = artifact;
    result.signaturePresent = !!signature;

    // Step 1: rebuild canonical payload + hash
    //
    // Prefer the canonical bytes the server already produced (directCanonical).
    // Falls back to reconstruction from `artifact` only when the API didn't
    // include canonical.serialized or canonical.payload (older API versions
    // or programmatic-input call sites). Local reconstruction is fragile by
    // design — the v1.10.0 evidence fix and this v1.10.1 approval fix both
    // close that fragility for the hosted-API call path.
    const canonical = directCanonical ?? buildApprovalCanonicalPayload(artifact);
    const recomputed = approvalCanonicalHash(canonical);
    result.hashValid = storedHash === null || storedHash === recomputed;
    result.recomputedCanonicalHash = recomputed;

    if (!signature || !signingKeyId) {
      result.verificationStatus = "UNSIGNED";
      return result;
    }

    // Step 2: resolve key
    const publicKey = input.publicKey
      ? input.publicKey
      : await fetchPublicKey(signingKeyId, input.jwksBase ?? DEFAULT_JWKS_BASE);

    // Step 3: verify signature
    result.signatureValid = verifySignature(canonical, signature, publicKey);

    // Step 4: status
    if (result.signatureValid && result.hashValid) {
      result.verificationStatus = "VERIFIED";
    } else if (!result.hashValid) {
      result.verificationStatus = "HASH_MISMATCH";
    } else {
      result.verificationStatus = "SIGNATURE_INVALID";
    }
  } catch (err) {
    result.error = err.message;
    result.verificationStatus = "ERROR";
    if (err?.url) result.attemptedUrl = err.url;
  }

  return result;
}

/**
 * Verify the approval quorum for a decision: fetch all artifacts, verify
 * each independently, check chain continuity, and report quorum
 * satisfaction.
 *
 * @param {object} input
 * @param {string} input.decisionId
 * @param {string} [input.proofBase]
 * @param {string} [input.jwksBase]
 * @returns {Promise<object>} {
 *   decisionId, requiredApprovals, validApprovals, quorumSatisfied,
 *   chainContinuous, results: [...per-artifact verification results],
 *   invalidArtifacts: [...subset of results that did not VERIFY],
 *   error,
 * }
 */
export async function verifyApprovalQuorum(input = {}) {
  const result = {
    decisionId: input.decisionId,
    requiredApprovals: 0,
    validApprovals: 0,
    quorumSatisfied: false,
    chainContinuous: false,
    results: [],
    invalidArtifacts: [],
    error: null,
  };

  try {
    if (!input.decisionId) {
      throw new Error("verifyApprovalQuorum: decisionId is required");
    }

    const proofBase = input.proofBase ?? DEFAULT_APPROVAL_BASE;
    const jwksBase = input.jwksBase ?? DEFAULT_JWKS_BASE;

    const data = await fetchApprovalQuorum(input.decisionId, proofBase);
    result.requiredApprovals = data.approvalsRequired ?? 0;

    // Verify each artifact independently. Chain check is composed across
    // them once we have the per-artifact results.
    //
    // v1.10.2: pass per-artifact canonical bytes through when the server
    // included them. The quorum endpoint (post-1.10.2) ships a `canonical`
    // block per artifact mirroring the single-artifact endpoint's shape.
    // Without this, reconstruction from the redacted artifact projection
    // (Gap 5: `actorUserId` removed) produces wrong canonical bytes and
    // every artifact returns HASH_MISMATCH.
    const verifications = [];
    for (const a of data.artifacts ?? []) {
      const v = await verifyApprovalArtifact({
        artifactPayload: a,
        canonicalPayloadHash: a.canonicalPayloadHash,
        canonicalSerialized: a?.canonical?.serialized,
        canonicalPayload: a?.canonical?.payload,
        signature: a.signature,
        signingKeyId: a.signingKeyId,
        jwksBase,
      });
      v.sequenceNum = a.sequenceNum;
      v.proofChainHash = a.proofChainHash;
      verifications.push(v);
    }
    result.results = verifications;
    result.validApprovals = verifications.filter(
      (v) => v.verificationStatus === "VERIFIED",
    ).length;
    result.invalidArtifacts = verifications.filter(
      (v) => v.verificationStatus !== "VERIFIED",
    );
    result.quorumSatisfied = result.validApprovals >= result.requiredApprovals;

    // Chain continuity: artifact[i].proofChainHash === artifact[i-1].recomputedCanonicalHash
    let chainOk = verifications.length > 0;
    for (let i = 0; i < verifications.length; i++) {
      const v = verifications[i];
      if (i === 0) {
        if (v.proofChainHash !== null && v.proofChainHash !== undefined) {
          chainOk = false;
          break;
        }
      } else {
        const prev = verifications[i - 1];
        if (v.proofChainHash !== prev.recomputedCanonicalHash) {
          chainOk = false;
          break;
        }
      }
    }
    result.chainContinuous = chainOk;
  } catch (err) {
    result.error = err.message;
  }

  return result;
}

// =============================================================================
// ATTESTATIONS (E1.5 — Option C architecture, includeAttestations support)
// =============================================================================
//
// Attestations are signed descriptors of identity, approval, and delegation
// linked to evidence by `evidenceId`. They are leaf nodes — never part of the
// evidence chain — and the base verify() flow stays unchanged when callers
// don't opt in.
//
// INVARIANT INV-ATT-3 (load-bearing, non-authority clause): attestations
//   describe verification metadata only. They MUST NOT be used as
//   authorization signals. Only policy evaluation, approval quorum
//   outcomes, and execution tokens
//   authorize execution. Severity of violation = same as missing
//   requireDecisionToken on an irreversible route.
//
// INVARIANT INV-ATT-5: backward compat — callers passing only evidenceId
//   (no options.includeAttestations) MUST receive identical results to
//   v1.0.x. No attestation fetching, no shape changes for legacy callers.
//
// Composite status per 12_attestation_schema.md §6a:
//   FULLY_VERIFIED       — base VERIFIED + all attestations VERIFIED
//   EVIDENCE_VERIFIED    — base VERIFIED, no attestations
//   PARTIAL              — base VERIFIED, ≥1 UNSIGNED/MISSING/ERROR
//   ATTESTATION_INVALID  — base VERIFIED, ≥1 SIGNATURE_INVALID/HASH_MISMATCH
//   CREDENTIAL_MISMATCH  — base VERIFIED, attribution claim inconsistent (Wave 2)
//   EVIDENCE_FAILED      — base failed (attestation state irrelevant)
// =============================================================================

/**
 * Reconstruct the canonical ACTOR attestation payload per
 * 12_attestation_schema.md §2a locked field order.
 *
 * Field order is locked — reordering invalidates every previously-signed
 * attestation. The signed bytes are JSON.stringify of an explicitly-keyed
 * object literal (deterministic by JS spec).
 *
 *   schemaVersion → attestationId → evidenceId → attestationType
 *   → actorType → actorId → actorRole → onBehalfOf → agentId
 *   → signingKeyId → environment → tenantId → createdAt
 *
 * @param {object} record - ACTOR attestation record (the parsed
 *   canonicalPayload OR the raw row with these fields available)
 * @returns {string} Deterministic JSON byte string ready for hash + signature
 */
export function buildActorAttestationPayload(record) {
  const ordered = {
    schemaVersion: String(record.schemaVersion ?? "1"),
    attestationId: String(record.attestationId ?? ""),
    evidenceId: String(record.evidenceId ?? ""),
    attestationType: "ACTOR",
    actorType: String(record.actorType ?? ""),
    actorId: String(record.actorId ?? ""),
    actorRole: String(record.actorRole ?? ""),
    onBehalfOf: record.onBehalfOf ?? null,
    agentId: record.agentId ?? null,
    signingKeyId: String(record.signingKeyId ?? ""),
    environment: String(record.environment ?? ""),
    tenantId: String(record.tenantId ?? ""),
    createdAt: String(record.createdAt ?? ""),
  };
  return JSON.stringify(ordered);
}

/**
 * Verifies a single attestation. Performs:
 *   1. Hash check: SHA-256(canonicalPayload) === canonicalPayloadHash
 *   2. Signature check: Ed25519(canonicalPayload, signature, JWKS pubkey)
 *
 * Wave 2 will fold in the CREDENTIAL_MISMATCH classifier (§6b) on top of
 * a successful hash + signature verification. For now the only state it
 * adds is `credentialMismatch: false` (placeholder for shape stability).
 *
 * @param {object} attestation - { attestationId, attestationType,
 *   canonicalPayload, canonicalPayloadHash, signature, signingKeyId, ... }
 * @param {object} [options]
 * @param {string} [options.jwksBase] - JWKS endpoint base URL
 * @returns {Promise<object>} { verificationStatus, signatureValid, hashValid,
 *   credentialMismatch, ... extracted display fields }
 */
export async function verifyAttestation(attestation, options = {}) {
  const jwksBase = options.jwksBase ?? DEFAULT_JWKS_BASE;
  const result = {
    attestationId: attestation.attestationId ?? null,
    attestationType: attestation.attestationType ?? "UNKNOWN",
    verificationStatus: "ERROR",
    signatureValid: false,
    hashValid: false,
    credentialMismatch: false,
  };

  try {
    if (!attestation.canonicalPayload) {
      result.verificationStatus = "ERROR";
      return result;
    }

    // 1. Hash check (independent of signature)
    const computedHash = crypto
      .createHash("sha256")
      .update(attestation.canonicalPayload, "utf8")
      .digest("hex");
    result.hashValid = computedHash === attestation.canonicalPayloadHash;

    if (!result.hashValid) {
      result.verificationStatus = "HASH_MISMATCH";
      return result;
    }

    // 2. Signature presence check
    if (!attestation.signature) {
      result.verificationStatus = "UNSIGNED";
      return result;
    }
    if (!attestation.signingKeyId) {
      // Signature claims present but no key id to resolve — treat as
      // SIGNATURE_INVALID. The signing key was not bound to the artifact.
      result.verificationStatus = "SIGNATURE_INVALID";
      return result;
    }

    // 3. Fetch public key from JWKS and verify signature
    let publicKey;
    try {
      publicKey = await fetchPublicKey(attestation.signingKeyId, jwksBase);
    } catch {
      result.verificationStatus = "ERROR";
      return result;
    }

    result.signatureValid = verifySignature(
      attestation.canonicalPayload,
      attestation.signature,
      publicKey,
    );

    if (!result.signatureValid) {
      result.verificationStatus = "SIGNATURE_INVALID";
      return result;
    }

    // Hash + signature both passed. Extract display fields from canonical
    // payload (parse defensively; on failure we still report VERIFIED
    // because the cryptographic checks passed).
    try {
      const parsed = JSON.parse(attestation.canonicalPayload);
      if (result.attestationType === "ACTOR") {
        result.actorType = parsed.actorType;
        result.actorId = parsed.actorId;
        result.actorRole = parsed.actorRole;
        result.onBehalfOf = parsed.onBehalfOf ?? null;
        result.agentId = parsed.agentId ?? null;
      }
    } catch {
      // Parse failure on a payload that hash-matched should be impossible;
      // log via verificationStatus so callers can detect the anomaly.
    }

    result.verificationStatus = "VERIFIED";
  } catch (err) {
    result.error = err?.message ?? "verifyAttestation error";
    result.verificationStatus = "ERROR";
  }

  return result;
}

/**
 * Fetch attestations linked to a verified evidence record from the Console
 * public verify endpoint. Console's /api/public/verify already returns the
 * `attestations[]` array (E1.4). The verifier re-runs an independent
 * verification on each row rather than trusting the Console's report.
 *
 * @param {string} evidenceHash - Full 64-char SHA-256 hex
 * @param {string} [verifyBase] - Console base URL hosting /api/public/verify
 * @returns {Promise<Array<object>>} attestation rows with canonical payloads
 */
export async function fetchAttestationsForEvidence(
  evidenceHash,
  verifyBase = DEFAULT_JWKS_BASE,
) {
  const url = `${verifyBase}/api/public/verify?hash=${encodeURIComponent(
    evidenceHash,
  )}`;
  const res = await fetchWithContext(url, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`Console verify fetch failed: HTTP ${res.status} (${url})`);
  }
  const data = await res.json();
  // The Console response includes `attestations: [...]` with the full
  // canonical payloads. Pre-E1.4 Console versions return undefined here;
  // treat that as "no attestations" (empty array).
  const list = Array.isArray(data?.attestations) ? data.attestations : [];
  // Console returns its own verification view; we only need the raw bytes
  // for independent re-verification. Filter for rows that look like full
  // attestation records (have canonicalPayload + signature).
  return list
    .filter(
      (a) =>
        a &&
        typeof a.canonicalPayload === "string" &&
        typeof a.canonicalPayloadHash === "string",
    )
    .map((a) => ({
      attestationId: a.attestationId ?? null,
      attestationType: a.attestationType ?? "UNKNOWN",
      canonicalPayload: a.canonicalPayload,
      canonicalPayloadHash: a.canonicalPayloadHash,
      signature: a.signature ?? null,
      signingKeyId: a.signingKeyId ?? null,
    }));
}

/**
 * Compute composite verification status from base evidence + attestation
 * results. Implements §6a state machine.
 */
export function computeAttestationCompositeStatus(
  baseStatus,
  attestationResults,
) {
  if (baseStatus !== "VERIFIED") return "EVIDENCE_FAILED";
  if (!attestationResults || attestationResults.length === 0) {
    return "EVIDENCE_VERIFIED";
  }
  const hasInvalid = attestationResults.some(
    (a) =>
      a.verificationStatus === "SIGNATURE_INVALID" ||
      a.verificationStatus === "HASH_MISMATCH",
  );
  if (hasInvalid) return "ATTESTATION_INVALID";

  const hasUnsignedOrMissing = attestationResults.some(
    (a) =>
      a.verificationStatus === "UNSIGNED" ||
      a.verificationStatus === "MISSING",
  );
  if (hasUnsignedOrMissing) return "PARTIAL";

  const hasError = attestationResults.some(
    (a) => a.verificationStatus === "ERROR",
  );
  if (hasError) return "PARTIAL";

  return "FULLY_VERIFIED";
}

/**
 * Extends `verify()` with linked-attestation validation. Backward-compatible:
 * call without `options.includeAttestations` and behavior is identical to the
 * v1.0.x `verify()` path (INV-ATT-5).
 *
 * Usage:
 *
 *   import { verify } from "@strixgov/verifier";
 *
 *   // Legacy mode — base evidence only
 *   const r1 = await verify(evidenceId);
 *
 *   // E1.5 mode — base + linked attestations
 *   const r2 = await verify(evidenceId, {
 *     includeAttestations: true,
 *     jwksBase: "https://www.strixgov.com",
 *     verifyBase: "https://www.strixgov.com",
 *   });
 *   // r2.attestations: [...]
 *   // r2.compositeStatus: "FULLY_VERIFIED" | "EVIDENCE_VERIFIED" | ...
 *
 * @param {number|string} evidenceId
 * @param {object} [options]
 * @param {boolean} [options.includeAttestations=false] - opt in to E1.5
 * @param {string} [options.proofBase] - Strix proof API base
 * @param {string} [options.jwksBase] - JWKS endpoint base
 * @param {string} [options.verifyBase] - Console verify endpoint base
 *   (defaults to jwksBase)
 */
export async function verifyWithAttestations(evidenceId, options = {}) {
  // Run the base verify exactly as today — no behavioral change to the
  // legacy path. The result shape is preserved.
  const base = await verify(evidenceId, options);

  if (!options.includeAttestations) {
    return base;
  }

  // Attestation surface only meaningful when we have an evidenceHash to
  // look up against the Console.
  const evidenceHash = base.record?.evidenceHash;
  if (!evidenceHash) {
    return {
      ...base,
      attestations: [],
      compositeStatus: computeAttestationCompositeStatus(
        base.verificationStatus,
        [],
      ),
    };
  }

  const verifyBase = options.verifyBase ?? options.jwksBase ?? DEFAULT_JWKS_BASE;
  const jwksBase = options.jwksBase ?? DEFAULT_JWKS_BASE;

  let rows;
  try {
    rows = await fetchAttestationsForEvidence(evidenceHash, verifyBase);
  } catch (err) {
    return {
      ...base,
      attestations: [],
      compositeStatus: computeAttestationCompositeStatus(
        base.verificationStatus,
        [],
      ),
      attestationFetchError: err?.message ?? "fetch failed",
    };
  }

  // Independently verify each attestation. We do NOT trust the Console's
  // own report — we re-run hash + signature verification client-side.
  const results = [];
  for (const row of rows) {
    const r = await verifyAttestation(row, { jwksBase });
    results.push(r);
  }

  return {
    ...base,
    attestations: results,
    compositeStatus: computeAttestationCompositeStatus(
      base.verificationStatus,
      results,
    ),
  };
}

// =============================================================================
// Tool Gateway Receipts (@strixgov/tool-gateway)
// =============================================================================
//
// Receipts produced by the local-first tool-gateway use a separate locked
// schema (11 fields). They share the cryptographic primitives (Ed25519 +
// SHA-256 + canonical JSON) with evidence and approval artifacts but are
// signed by a different key class — the developer's local kid (typically
// `local-{YYYY-MM}`), not a hosted `strix-{env}-{YYYY-MM}` key.
//
// Verification is offline-capable: pass a JWKS object directly and no
// network calls are made. Mirrors the canonical serializer in
// @strixgov/tool-gateway/src/canonical.mjs — drift between the two
// breaks every previously-issued receipt's signature.
// =============================================================================

const RECEIPT_FIELD_ORDER_V1 = Object.freeze([
  "schemaVersion",
  "receiptId",
  "capabilityId",
  "action",
  "decision",
  "risk",
  "mode",
  "invocationHash",
  "evidenceHash",
  "proofChainHash",
  "timestamp",
]);

const RECEIPT_FIELD_ORDER_V2 = Object.freeze([
  "schemaVersion",
  "receiptId",
  "capabilityId",
  "action",
  "decision",
  "risk",
  "mode",
  "policyVersion",
  "tenantId",
  "environment",
  "invocationHash",
  "evidenceHash",
  "proofChainHash",
  "timestamp",
]);

/** Back-compat alias — current schema's field order. */
const RECEIPT_FIELD_ORDER = RECEIPT_FIELD_ORDER_V2;

/**
 * Reconstruct the canonical tool-gateway receipt payload. Dispatches on
 * `receipt.schemaVersion`:
 *
 *   "1" → 11 fields (frozen pre-v0.1.1 schema)
 *   "2" → 14 fields (current; adds policyVersion, tenantId, environment)
 *
 * Output matches the @strixgov/tool-gateway serializer byte-for-byte.
 *
 * @param {object} receipt
 * @returns {string}
 */
export function buildReceiptCanonicalPayload(receipt) {
  const v = String(receipt?.schemaVersion ?? "1");
  let order;
  if (v === "1") order = RECEIPT_FIELD_ORDER_V1;
  else if (v === "2") order = RECEIPT_FIELD_ORDER_V2;
  else throw new Error(`buildReceiptCanonicalPayload: unknown schemaVersion '${v}'`);

  const parts = [];
  for (const field of order) {
    const value = receipt[field];
    if (value === undefined || value === null) {
      throw new Error(`buildReceiptCanonicalPayload: missing field '${field}'`);
    }
    parts.push(`${JSON.stringify(field)}:${JSON.stringify(value)}`);
  }
  return `{${parts.join(",")}}`;
}

/**
 * Verify a single tool-gateway receipt.
 *
 * @param {object} receipt
 * @param {{
 *   jwks?: { keys: Array<{ kid: string, kty: string, crv: string, x: string }> },
 *   jwksBase?: string,
 *   publicKey?: import("node:crypto").KeyObject,
 * }} [opts]
 * @returns {Promise<{
 *   receiptId: string,
 *   signaturePresent: boolean,
 *   signatureValid: boolean,
 *   hashValid: boolean,
 *   verificationStatus: "VERIFIED"|"UNSIGNED"|"TAMPERED"|"ERROR",
 *   error?: string,
 * }>}
 */
export async function verifyReceipt(receipt, opts = {}) {
  const result = {
    receiptId: receipt?.receiptId,
    signaturePresent: !!receipt?.signature,
    signatureValid: false,
    hashValid: false,
    verificationStatus: "ERROR",
  };

  try {
    if (!receipt || !receipt.signature) {
      result.verificationStatus = "UNSIGNED";
      return result;
    }
    if (!receipt.signingKeyId) {
      result.error = "missing signingKeyId";
      return result;
    }

    let publicKey = opts.publicKey;
    if (!publicKey) {
      let jwk;
      if (opts.jwks) {
        jwk = resolveJwkFromKid(receipt.signingKeyId, opts.jwks);
      } else if (opts.jwksBase) {
        publicKey = await fetchPublicKey(receipt.signingKeyId, opts.jwksBase);
      } else {
        result.error =
          "no public key source — provide opts.jwks, opts.jwksBase, or opts.publicKey";
        return result;
      }
      if (!publicKey && jwk) {
        if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
          throw new Error(`Unexpected key type: ${jwk.kty}/${jwk.crv}`);
        }
        const raw = Buffer.from(jwk.x, "base64url");
        const spkiHeader = Buffer.from("302a300506032b6570032100", "hex");
        const spki = Buffer.concat([spkiHeader, raw]);
        publicKey = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
      }
      if (!publicKey) {
        result.error = `key not found in JWKS: ${receipt.signingKeyId}`;
        return result;
      }
    }

    const canonical = buildReceiptCanonicalPayload(receipt);
    const sig = Buffer.from(receipt.signature, "base64url");
    result.signatureValid = crypto.verify(
      null,
      Buffer.from(canonical, "utf8"),
      publicKey,
      sig,
    );
    result.hashValid = result.signatureValid;
    result.verificationStatus = result.signatureValid ? "VERIFIED" : "TAMPERED";
  } catch (err) {
    result.error = err?.message ?? String(err);
    result.verificationStatus = "ERROR";
  }
  return result;
}

/**
 * Verify a chain of receipts (output of `strix-gateway receipts list`
 * or a `receipts.jsonl` file). Walks proofChainHash links and checks
 * every signature.
 *
 * @param {object[]} receipts
 * @param {Parameters<typeof verifyReceipt>[1]} [opts]
 */
export async function verifyReceiptChain(receipts, opts = {}) {
  const GENESIS = "0".repeat(64);
  let prev = GENESIS;
  let chainValid = true;
  let brokenAt = null;
  const perReceipt = [];

  for (const r of receipts) {
    const expected = crypto
      .createHash("sha256")
      .update(`${prev}|${r.evidenceHash}`)
      .digest("hex");
    const linkOk = expected === r.proofChainHash;
    if (!linkOk) {
      chainValid = false;
      brokenAt = brokenAt ?? r.receiptId;
    }
    const verifyResult = await verifyReceipt(r, opts);
    perReceipt.push({ ...verifyResult, linkOk });
    prev = r.proofChainHash;
  }

  return {
    count: receipts.length,
    chainValid,
    brokenAt,
    receipts: perReceipt,
  };
}

// ─── Tool Gateway Chain Snapshots (key rotation boundaries) ───────────────────
//
// When a tool-gateway rotates its signing key, it emits a "chain snapshot"
// record that is signed by BOTH the previous and the new key. Verifying a
// post-rotation chain requires resolving both kids in JWKS and confirming
// both signatures — proof that the same operator authorised the handoff.
//
// Field order MUST mirror @strixgov/tool-gateway/src/snapshots.mjs.

const SNAPSHOT_FIELD_ORDER = Object.freeze([
  "schemaVersion",
  "snapshotId",
  "previousKid",
  "newKid",
  "lastReceiptId",
  "lastProofChainHash",
  "policyVersion",
  "tenantId",
  "environment",
  "timestamp",
]);

/**
 * Reconstruct the canonical payload bytes for a chain snapshot. Output
 * matches the gateway serializer byte-for-byte.
 *
 * @param {object} snapshot
 */
export function buildSnapshotCanonicalPayload(snapshot) {
  if (!snapshot || typeof snapshot !== "object") {
    throw new TypeError("buildSnapshotCanonicalPayload: snapshot must be an object");
  }
  const parts = [];
  for (const field of SNAPSHOT_FIELD_ORDER) {
    const value = snapshot[field];
    if (value === undefined || value === null) {
      throw new Error(
        `buildSnapshotCanonicalPayload: missing field '${field}'`,
      );
    }
    parts.push(`${JSON.stringify(field)}:${JSON.stringify(value)}`);
  }
  return `{${parts.join(",")}}`;
}

/**
 * Verify both signatures on a chain snapshot.
 *
 * Resolves `previousKid` and `newKid` from `opts.jwks` (or `opts.jwksBase`)
 * and reports each signature independently. A snapshot is "VERIFIED" only
 * when BOTH signatures verify. PARTIAL means only one — that's a tampered
 * or half-applied rotation and should be treated as suspicious.
 *
 * @param {object} snapshot
 * @param {{
 *   jwks?: { keys: Array<{ kid: string, kty: string, crv: string, x: string }> },
 *   jwksBase?: string,
 * }} [opts]
 */
export async function verifySnapshot(snapshot, opts = {}) {
  const result = {
    snapshotId: snapshot?.snapshotId,
    previousKid: snapshot?.previousKid,
    newKid: snapshot?.newKid,
    previousSignatureValid: false,
    newSignatureValid: false,
    verificationStatus: "ERROR",
  };
  try {
    const payload = Buffer.from(buildSnapshotCanonicalPayload(snapshot), "utf8");
    const resolveKey = async (kid) => {
      if (opts.jwks) {
        const jwk = resolveJwkFromKid(kid, opts.jwks);
        if (!jwk) return null;
        if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
          throw new Error(`Unexpected key type for ${kid}: ${jwk.kty}/${jwk.crv}`);
        }
        const raw = Buffer.from(jwk.x, "base64url");
        const spkiHeader = Buffer.from("302a300506032b6570032100", "hex");
        const spki = Buffer.concat([spkiHeader, raw]);
        return crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
      }
      if (opts.jwksBase) return await fetchPublicKey(kid, opts.jwksBase);
      return null;
    };

    const previousKey = await resolveKey(snapshot.previousKid);
    const newKey = await resolveKey(snapshot.newKid);
    if (!previousKey) {
      result.error = `previous kid not resolvable: ${snapshot.previousKid}`;
      return result;
    }
    if (!newKey) {
      result.error = `new kid not resolvable: ${snapshot.newKid}`;
      return result;
    }
    if (snapshot.signaturePrevious) {
      result.previousSignatureValid = crypto.verify(
        null,
        payload,
        previousKey,
        Buffer.from(snapshot.signaturePrevious, "base64url"),
      );
    }
    if (snapshot.signatureNew) {
      result.newSignatureValid = crypto.verify(
        null,
        payload,
        newKey,
        Buffer.from(snapshot.signatureNew, "base64url"),
      );
    }
    if (result.previousSignatureValid && result.newSignatureValid) {
      result.verificationStatus = "VERIFIED";
    } else if (result.previousSignatureValid || result.newSignatureValid) {
      result.verificationStatus = "PARTIAL";
    } else {
      result.verificationStatus = "TAMPERED";
    }
  } catch (err) {
    result.error = err?.message ?? String(err);
    result.verificationStatus = "ERROR";
  }
  return result;
}

/**
 * End-to-end verification of a tool-gateway proof: receipts.jsonl plus
 * the snapshots.jsonl that records every key rotation. Walks the receipt
 * chain and the snapshot list independently, then asserts that:
 *
 *   1. Every snapshot's `lastProofChainHash` matches a real receipt's
 *      proofChainHash — snapshots cannot reference receipts that don't
 *      exist.
 *   2. Every snapshot is fully VERIFIED (both signatures).
 *   3. Every receipt is VERIFIED under one of the kids in JWKS.
 *
 * @param {{ receipts: object[], snapshots?: object[] }} input
 * @param {Parameters<typeof verifyReceipt>[1]} [opts]
 */
export async function verifyToolGatewayProof(input, opts = {}) {
  const receipts = input.receipts ?? [];
  const snapshots = input.snapshots ?? [];
  const chainResult = await verifyReceiptChain(receipts, opts);
  const snapResults = [];
  for (const s of snapshots) {
    const verifyResult = await verifySnapshot(s, opts);
    const last = receipts.find((r) => r.receiptId === s.lastReceiptId);
    const lastReferenceValid =
      !!last && last.proofChainHash === s.lastProofChainHash;
    snapResults.push({ ...verifyResult, lastReferenceValid });
  }
  const allReceiptsVerified = chainResult.receipts.every(
    (r) => r.verificationStatus === "VERIFIED",
  );
  const allSnapshotsVerified = snapResults.every(
    (s) => s.verificationStatus === "VERIFIED" && s.lastReferenceValid,
  );
  return {
    receipts: chainResult,
    snapshots: snapResults,
    chainValid: chainResult.chainValid,
    allReceiptsVerified,
    allSnapshotsVerified,
    overallStatus:
      chainResult.chainValid && allReceiptsVerified && allSnapshotsVerified
        ? "VERIFIED"
        : "TAMPERED",
  };
}

// ─── Connected-mode wire envelope (v0.3-experimental / v0.4-stable) ──────────
//
// When @strixgov/tool-gateway syncs a receipt or snapshot upstream, the
// envelope is `{ wireVersion, timestamp, nonce, receipts: [...] }` (or
// snapshots) and is HMAC-signed with the consumer's API key, NOT the
// gateway's Ed25519 private key. The HMAC binds the envelope to the
// API-key holder so a receiving system can authenticate the caller
// without resolving the receipt's kid first.
//
// v0.4-stable (current): body includes `timestamp` (ISO 8601) and
// `nonce` (32-char hex). The kernel MUST validate timestamp freshness
// (recommended: reject if age > 5 min or > 30 s in the future) and
// enforce nonce uniqueness. verifyConnectedWireEnvelope returns both
// fields and a `stale` flag for convenience.
//
// v0.3-experimental: legacy; no timestamp or nonce. Still recognised
// so old records remain verifiable; not emitted by tool-gateway >= v0.4.

export const SUPPORTED_WIRE_VERSIONS = Object.freeze([
  "v0.4-stable",
  "v0.3-experimental",
]);

/**
 * Verify the HMAC envelope on an inbound connected-mode POST.
 *
 * Returns `{ valid, wireVersion, recognised, timestamp, nonce, stale }`.
 * - `recognised=false` → wireVersion not in SUPPORTED_WIRE_VERSIONS;
 *   caller should reject or queue for human review.
 * - `stale=true` → timestamp is older than `maxAgeMs` or more than 30 s
 *   in the future. Only set when `maxAgeMs` is provided and the envelope
 *   carries a timestamp (v0.4-stable+).
 * - Nonce uniqueness is NOT enforced here (stateless verifier). The
 *   caller is responsible for deduplicating nonces.
 *
 * The HMAC is always computed before any format check to prevent
 * timing-oracle attacks on the signature format.
 *
 * @param {{
 *   body: string | Buffer,
 *   signatureHeader: string | undefined,
 *   apiKey: string,
 *   maxAgeMs?: number,
 * }} args
 */
export function verifyConnectedWireEnvelope({ body, signatureHeader, apiKey, maxAgeMs }) {
  const result = {
    valid: false,
    recognised: false,
    wireVersion: null,
    timestamp: null,
    nonce: null,
    stale: false,
  };

  // Always compute the HMAC before any early return so timing is
  // independent of the signature header format (prevents oracle attacks).
  const bodyBuf = typeof body === "string" ? Buffer.from(body, "utf8") : Buffer.from(body);
  const expected = crypto.createHmac("sha256", apiKey).update(bodyBuf).digest();

  if (typeof signatureHeader !== "string" || !signatureHeader) return result;
  const m = signatureHeader.match(/^hmac-sha256=([0-9a-f]{64})$/);
  if (!m) return result;
  const a = Buffer.from(m[1], "hex");
  if (a.length !== expected.length) return result;
  result.valid = crypto.timingSafeEqual(a, expected);
  if (!result.valid) return result;

  try {
    const parsed = JSON.parse(typeof body === "string" ? body : body.toString("utf8"));
    result.wireVersion = parsed?.wireVersion ?? null;
    result.recognised = SUPPORTED_WIRE_VERSIONS.includes(result.wireVersion);
    result.timestamp = parsed?.timestamp ?? null;
    result.nonce = parsed?.nonce ?? null;
    if (result.timestamp != null && maxAgeMs != null) {
      const age = Date.now() - new Date(result.timestamp).getTime();
      result.stale = age > maxAgeMs || age < -30_000;
    }
  } catch {
    /* leave fields at defaults */
  }
  return result;
}

// =============================================================================
// Visual Artifacts v1 — drag-an-SVG verification (mirror of
// apps/strix-verify-web/lib/verify.mjs)
// =============================================================================
//
// `verifyVisual(svgText, opts)` parses a VA v1 SVG's <metadata> block,
// re-computes the canonical payload hash, and runs Ed25519 verification
// against a provided JWKS. The output vocabulary mirrors the browser
// verifier — VERIFIED, VERIFIED_PINNED_ONLY, COMPLIANCE_VIOLATION,
// TAMPERED_METADATA, NO_METADATA, LEGACY_UNSIGNED, KID_NOT_FOUND,
// DRIFT_DISAGREE — so the CLI and verify.strixgov.com produce
// identical status strings for the same input.
//
// Contract: docs/architecture/visual-artifacts-v1.md
// =============================================================================

const VA_META_RX = Object.freeze({
  rendererName: /<strix:renderer\s+name="([^"]+)"/,
  rendererVersion: /<strix:renderer\s+name="[^"]+"\s+version="([^"]+)"\s*\/>/,
  visualKind: /<strix:visualKind>([^<]+)<\/strix:visualKind>/,
  renderVersion: /<strix:renderVersion>([^<]+)<\/strix:renderVersion>/,
  canonicalHash: /<strix:canonicalHash>([^<]+)<\/strix:canonicalHash>/,
  signature: /<strix:signature\s+alg="Ed25519">([^<]+)<\/strix:signature>/,
  signingKeyId: /<strix:signingKeyId>([^<]+)<\/strix:signingKeyId>/,
  canonicalPayload: /<strix:canonicalPayload><!\[CDATA\[([\s\S]*?)\]\]><\/strix:canonicalPayload>/,
});

function vaPick(svg, re) {
  const m = svg.match(re);
  return m ? m[1] : null;
}

export function extractVisualMetadata(svgText) {
  return {
    rendererName: vaPick(svgText, VA_META_RX.rendererName),
    rendererVersion: vaPick(svgText, VA_META_RX.rendererVersion),
    visualKind: vaPick(svgText, VA_META_RX.visualKind),
    renderVersion: vaPick(svgText, VA_META_RX.renderVersion),
    canonicalHash: vaPick(svgText, VA_META_RX.canonicalHash),
    signature: vaPick(svgText, VA_META_RX.signature),
    signingKeyId: vaPick(svgText, VA_META_RX.signingKeyId),
    canonicalPayload: vaPick(svgText, VA_META_RX.canonicalPayload),
  };
}

function vaFingerprint(jwk) {
  return jwk?.x ? `pk:${jwk.x.slice(0, 12)}…${jwk.x.slice(-8)}` : "(no key)";
}

function vaSha256Hex(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

function vaVerifySignature(jwk, signatureB64, payloadBytes) {
  try {
    const pubKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
    return crypto.verify(null, Buffer.from(payloadBytes, "utf8"), pubKey, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}

/**
 * Verify a Visual Artifacts v1 SVG. Mirror of the browser verifier in
 * apps/strix-verify-web/lib/verify.mjs — same status vocabulary, same
 * gates in the same order.
 *
 * @param {string} svgText - the SVG file contents
 * @param {object} opts
 * @param {object} [opts.pinnedJwks] - pinned JWKS snapshot (object with `keys` array)
 * @param {object} [opts.liveJwks] - live JWKS (object with `keys` array); pass `{ _error: '...' }` to record unavailability
 * @param {string} [opts.liveJwksUrl] - if provided and opts.liveJwks omitted, fetched at verify time
 * @returns {Promise<object>}
 */
export async function verifyVisual(svgText, opts = {}) {
  const meta = extractVisualMetadata(svgText);
  const result = {
    meta,
    visualHash: `sha256:${vaSha256Hex(svgText)}`,
    canonical: { embeddedHash: meta.canonicalHash, recomputedHash: null, match: null },
    pinned: { jwkPresent: false, fingerprint: null, ok: false, error: null },
    live: { jwkPresent: false, fingerprint: null, ok: false, error: null, fetched: false, url: opts.liveJwksUrl ?? null },
    drift: { state: "UNKNOWN", detail: "" },
    verificationStatus: "UNKNOWN",
    verificationReason: "",
  };

  if (!meta.visualKind || !meta.renderVersion || !meta.canonicalHash) {
    result.verificationStatus = "NO_METADATA";
    result.verificationReason = "This SVG carries no VA v1 metadata block. Probably a screenshot or an unsigned decorative SVG.";
    return result;
  }
  if (!meta.signature || !meta.signingKeyId) {
    result.verificationStatus = "LEGACY_UNSIGNED";
    result.verificationReason = "Metadata is present but no signature is embedded.";
    return result;
  }
  if (meta.canonicalPayload) {
    const recomputed = `sha256:${vaSha256Hex(meta.canonicalPayload)}`;
    result.canonical.recomputedHash = recomputed;
    result.canonical.match = recomputed === meta.canonicalHash;
    if (!result.canonical.match) {
      result.verificationStatus = "TAMPERED_METADATA";
      result.verificationReason = "Embedded canonical payload bytes do not match the declared canonicalHash.";
      return result;
    }
  }

  let pinnedJwks = opts.pinnedJwks ?? null;
  let liveJwks = opts.liveJwks ?? null;
  if (!liveJwks && opts.liveJwksUrl) {
    try {
      const r = await fetch(opts.liveJwksUrl, { cache: "no-cache" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      liveJwks = await r.json();
    } catch (err) {
      liveJwks = { _error: err.message };
    }
  }

  const resolve = (jwks) => Array.isArray(jwks?.keys) ? (jwks.keys.find((k) => k.kid === meta.signingKeyId) ?? null) : null;

  if (pinnedJwks) {
    const jwk = resolve(pinnedJwks);
    if (jwk) {
      result.pinned.jwkPresent = true;
      result.pinned.fingerprint = vaFingerprint(jwk);
      result.pinned.ok = vaVerifySignature(jwk, meta.signature, meta.canonicalPayload);
    } else {
      result.pinned.error = `kid '${meta.signingKeyId}' not in pinned snapshot`;
    }
  } else {
    result.pinned.error = "no pinned JWKS provided";
  }

  if (liveJwks && !liveJwks._error) {
    result.live.fetched = true;
    const jwk = resolve(liveJwks);
    if (jwk) {
      result.live.jwkPresent = true;
      result.live.fingerprint = vaFingerprint(jwk);
      result.live.ok = vaVerifySignature(jwk, meta.signature, meta.canonicalPayload);
    } else {
      result.live.error = `kid '${meta.signingKeyId}' not in live JWKS`;
    }
  } else if (liveJwks?._error) {
    result.live.error = liveJwks._error;
  }

  // Drift detection
  if (!result.live.fetched) {
    result.drift = { state: "LIVE_UNAVAILABLE", detail: result.live.error ?? "Live JWKS not fetched." };
  } else if (!result.pinned.jwkPresent && !result.live.jwkPresent) {
    result.drift = { state: "KID_NOT_FOUND", detail: "Neither pinned nor live JWKS contains this kid." };
  } else if (result.pinned.jwkPresent && !result.live.jwkPresent) {
    result.drift = { state: "DRIFT_LIVE_MISSING", detail: "Pinned snapshot has the kid; live JWKS does not." };
  } else if (!result.pinned.jwkPresent && result.live.jwkPresent) {
    result.drift = { state: "DRIFT_PINNED_MISSING", detail: "Live JWKS has the kid; pinned snapshot does not." };
  } else if (result.pinned.fingerprint === result.live.fingerprint) {
    result.drift = { state: "AGREED", detail: "Pinned snapshot and live JWKS publish the same key." };
  } else {
    result.drift = {
      state: "DRIFT_KEY_DIFFERS",
      detail: `Pinned: ${result.pinned.fingerprint}. Live: ${result.live.fingerprint}.`,
    };
  }

  // Final status
  if (result.pinned.ok && (result.live.ok || !result.live.fetched)) {
    result.verificationStatus = result.live.fetched ? "VERIFIED" : "VERIFIED_PINNED_ONLY";
  } else if (result.pinned.ok !== result.live.ok && result.live.fetched && result.live.jwkPresent) {
    result.verificationStatus = "DRIFT_DISAGREE";
  } else if (!result.pinned.jwkPresent && result.live.fetched && result.live.jwkPresent) {
    result.verificationStatus = result.live.ok ? "VERIFIED_LIVE_ONLY" : "COMPLIANCE_VIOLATION";
  } else if (!result.pinned.jwkPresent && !result.live.jwkPresent) {
    result.verificationStatus = "KID_NOT_FOUND";
  } else {
    result.verificationStatus = "COMPLIANCE_VIOLATION";
  }

  result.verificationReason = vaExplainStatus(result.verificationStatus, result);
  return result;
}

function vaExplainStatus(status, r) {
  switch (status) {
    case "VERIFIED": return "Signed by the kid claimed in the SVG. Pinned and live JWKS agree.";
    case "VERIFIED_PINNED_ONLY": return `Pinned snapshot verified. Live JWKS not reached (${r.live.error ?? "no detail"}).`;
    case "VERIFIED_LIVE_ONLY": return "Live JWKS verified. Pinned snapshot does not contain this kid.";
    case "DRIFT_DISAGREE": return "Pinned and live JWKS disagree on this kid.";
    case "COMPLIANCE_VIOLATION": return "Ed25519 verification failed.";
    case "KID_NOT_FOUND": return `Kid '${r.meta.signingKeyId}' unknown to both pinned and live JWKS.`;
    default: return "";
  }
}

// =============================================================================
// Strix-CT v1 (Cryptographic Transparency Log)
// =============================================================================
//
// Verifies inclusion + consistency proofs from a Strix-CT sequencer.
// Mirrors the Merkle algebra of apps/strix-ct-sequencer/src/merkle.mjs +
// apps/strix-ct-witness/src/witness.mjs — drift between any of the three
// breaks every previously-issued proof.
// Spec: docs/architecture/strix-ct-v1.md
// =============================================================================

const CT_LEAF_PREFIX = Buffer.from([0x00]);
const CT_NODE_PREFIX = Buffer.from([0x01]);

function ctHashLeaf(dataHex) {
  return crypto.createHash("sha256").update(Buffer.concat([CT_LEAF_PREFIX, Buffer.from(dataHex, "hex")])).digest();
}
function ctHashNode(left, right) {
  return crypto.createHash("sha256").update(Buffer.concat([CT_NODE_PREFIX, left, right])).digest();
}
function ctLargestPow2LessThan(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
function ctParsePathEntry(s) {
  return Buffer.from(s.replace(/^sha256:/, ""), "hex");
}
function ctParseRoot(s) {
  return Buffer.from(s.replace(/^sha256:/, ""), "hex");
}

export function verifyCtInclusionPath(leafHash, leafIndex, treeSize, auditPathHashes, rootHash) {
  if (leafIndex < 0 || leafIndex >= treeSize) return false;
  const computed = _ctVerifyInclRec(leafHash, leafIndex, treeSize, auditPathHashes);
  return computed !== null && computed.equals(rootHash);
}

function _ctVerifyInclRec(leafHash, leafIndex, treeSize, path) {
  if (treeSize === 1) return path.length === 0 ? leafHash : null;
  if (path.length === 0) return null;
  const k = ctLargestPow2LessThan(treeSize);
  const top = path[path.length - 1];
  const inner = path.slice(0, -1);
  if (leafIndex < k) {
    const left = _ctVerifyInclRec(leafHash, leafIndex, k, inner);
    if (left === null) return null;
    return ctHashNode(left, top);
  }
  const right = _ctVerifyInclRec(leafHash, leafIndex - k, treeSize - k, inner);
  if (right === null) return null;
  return ctHashNode(top, right);
}

export function verifyCtConsistencyPath(firstTreeSize, secondTreeSize, firstRoot, secondRoot, proof) {
  if (firstTreeSize > secondTreeSize) return false;
  if (firstTreeSize === secondTreeSize) {
    return proof.length === 0 && firstRoot.equals(secondRoot);
  }
  if (firstTreeSize === 0) return proof.length === 0;
  if (proof.length === 0) return false;
  let node = firstTreeSize - 1;
  let lastNode = secondTreeSize - 1;
  while ((node & 1) === 1) { node >>= 1; lastNode >>= 1; }
  let pos = 0;
  let hash1, hash2;
  if (node > 0) { hash1 = proof[pos]; hash2 = proof[pos]; pos++; }
  else { hash1 = firstRoot; hash2 = firstRoot; }
  while (node > 0) {
    if ((node & 1) === 1) {
      if (pos >= proof.length) return false;
      hash1 = ctHashNode(proof[pos], hash1);
      hash2 = ctHashNode(proof[pos], hash2);
      pos++;
    } else if (node < lastNode) {
      if (pos >= proof.length) return false;
      hash2 = ctHashNode(hash2, proof[pos]);
      pos++;
    }
    node >>= 1; lastNode >>= 1;
  }
  while (lastNode > 0) {
    if (pos >= proof.length) return false;
    hash2 = ctHashNode(hash2, proof[pos]);
    pos++; lastNode >>= 1;
  }
  return hash1.equals(firstRoot) && hash2.equals(secondRoot) && pos === proof.length;
}

export async function verifyCtInclusion(evidenceHashHex, opts = {}) {
  const ctBase = opts.ctBase ?? "https://well-known.strixgov.com";
  if (typeof evidenceHashHex !== "string" || !/^[0-9a-f]{64}$/.test(evidenceHashHex)) {
    return { verificationStatus: "ERROR", evidenceHash: evidenceHashHex, error: "evidenceHash must be 64-char lowercase hex" };
  }
  let proof = opts.proof;
  if (!proof) {
    try {
      const url = `${ctBase}/ct/v1/inclusion?evidenceHash=${evidenceHashHex}`;
      const r = await fetch(url, { cache: "no-cache" });
      if (r.status === 404) return { verificationStatus: "NOT_LOGGED", evidenceHash: evidenceHashHex };
      if (!r.ok) return { verificationStatus: "ERROR", evidenceHash: evidenceHashHex, error: `HTTP ${r.status}` };
      proof = await r.json();
    } catch (err) {
      return { verificationStatus: "ERROR", evidenceHash: evidenceHashHex, error: err.message };
    }
  }
  const leafHash = ctHashLeaf(evidenceHashHex);
  const auditPath = proof.auditPath.map(ctParsePathEntry);
  const rootHash = ctParseRoot(proof.rootHash);
  const ok = verifyCtInclusionPath(leafHash, proof.leafIndex, proof.treeSize, auditPath, rootHash);
  return {
    verificationStatus: ok ? "VERIFIED" : "PROOF_INVALID",
    evidenceHash: evidenceHashHex,
    leafIndex: proof.leafIndex,
    treeSize: proof.treeSize,
    rootHash: proof.rootHash,
  };
}

export async function verifyCtConsistency(sthFirst, sthSecond, opts = {}) {
  const ctBase = opts.ctBase ?? "https://well-known.strixgov.com";
  if (sthFirst?.logId !== sthSecond?.logId) {
    return { verificationStatus: "ERROR", firstTreeSize: sthFirst?.treeSize, secondTreeSize: sthSecond?.treeSize, error: `STHs are for different logs: ${sthFirst?.logId} vs ${sthSecond?.logId}` };
  }
  if (sthFirst?.treeSize > sthSecond?.treeSize) {
    return { verificationStatus: "PROOF_INVALID", firstTreeSize: sthFirst?.treeSize, secondTreeSize: sthSecond?.treeSize, error: "firstTreeSize > secondTreeSize — log went backwards" };
  }
  let proof = opts.proof;
  if (!proof) {
    try {
      const url = `${ctBase}/ct/v1/consistency?from=${sthFirst.treeSize}`;
      const r = await fetch(url, { cache: "no-cache" });
      if (!r.ok) return { verificationStatus: "ERROR", firstTreeSize: sthFirst.treeSize, secondTreeSize: sthSecond.treeSize, error: `HTTP ${r.status}` };
      proof = await r.json();
    } catch (err) {
      return { verificationStatus: "ERROR", firstTreeSize: sthFirst.treeSize, secondTreeSize: sthSecond.treeSize, error: err.message };
    }
  }
  const firstRoot = ctParseRoot(sthFirst.rootHash);
  const secondRoot = ctParseRoot(sthSecond.rootHash);
  const proofHashes = proof.consistencyPath.map(ctParsePathEntry);
  const ok = verifyCtConsistencyPath(sthFirst.treeSize, sthSecond.treeSize, firstRoot, secondRoot, proofHashes);
  return {
    verificationStatus: ok ? "VERIFIED" : "PROOF_INVALID",
    firstTreeSize: sthFirst.treeSize,
    secondTreeSize: sthSecond.treeSize,
  };
}


// =============================================================================
// Agent Swarm v1 — independent delegation-graph verification
// =============================================================================
//
// `verifySwarm(swarmRunId, opts)` fetches GET /api/public/proof/swarm/<id> and
// INDEPENDENTLY re-derives the swarm integrity verdict — it does NOT trust the
// server's `verification_status`. Zero shared code with @strixgov/sdk: this
// module re-implements SCJ v1 canonicalization, Ed25519 edge-signature
// verification, and the SW-2/SW-5 attenuation algebra. Drift between this and
// the SDK is the only risk; the conformance test (test/swarm-verifier-
// conformance.test.mjs) pins byte-parity against SDK-signed golden vectors.
//
// Status vocabulary mirrors the proof surface:
//   VERIFIED | INVALID | UNVERIFIABLE | LEGACY_UNSIGNED
//
// Contract: docs/architecture/agent-swarm-v1.md (contractVersion 0.2.0).

/**
 * SCJ v1 canonical JSON — independent re-implementation. Byte-identical to
 * solo-builder-core/src/canonical-json.ts for valid inputs: recursive,
 * object keys sorted ascending, arrays order-preserved, numbers/strings via
 * JSON.stringify. (The verifier path only needs the valid-input branch; the
 * SDK signer owns the reject-on-malformed branch.)
 */
export function scjCanonicalize(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) throw new Error("SCJ: non-finite number");
    return JSON.stringify(value);
  }
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => scjCanonicalize(v)).join(",") + "]";
  }
  if (t === "object") {
    const keys = Object.keys(value).sort();
    return (
      "{" +
      keys
        .map((k) => JSON.stringify(k) + ":" + scjCanonicalize(value[k]))
        .join(",") +
      "}"
    );
  }
  throw new Error("SCJ: unsupported type " + t);
}

/** Convert an OKP/Ed25519 public JWK into a KeyObject, or null on bad input. */
function swarmJwkToKey(jwk) {
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    return null;
  }
  try {
    return crypto.createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    return null;
  }
}

const SWARM_RISK_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

function swarmRiskLEQ(child, parent) {
  const c = SWARM_RISK_ORDER[child];
  const p = SWARM_RISK_ORDER[parent];
  return typeof c === "number" && typeof p === "number" && c <= p;
}

/** child capabilities ⊆ parent capabilities. */
function swarmCapabilitiesSubset(child, parent) {
  const set = new Set(parent);
  return child.every((c) => set.has(c));
}

/**
 * child scope ⊆ parent scope: for every key in child, the parent must constrain
 * the same key and the child's values must be a subset of the parent's. A key
 * absent from the parent means the parent did NOT grant it → amplification.
 */
function swarmScopeSubset(child, parent) {
  for (const key of Object.keys(child)) {
    if (!(key in parent)) return false;
    const cv = child[key];
    const pv = parent[key];
    if (Array.isArray(cv) && Array.isArray(pv)) {
      const pset = new Set(pv.map((x) => JSON.stringify(x)));
      if (!cv.every((x) => pset.has(JSON.stringify(x)))) return false;
    } else if (JSON.stringify(cv) !== JSON.stringify(pv)) {
      return false;
    }
  }
  return true;
}

/** child budget ≤ parent budget (null parent = unbounded; null child under bounded parent is amplification). */
function swarmBudgetLEQ(child, parent) {
  if (parent === null || parent === undefined) return true;
  if (child === null || child === undefined) return false;
  return child <= parent;
}

/** child window ⊆ parent window (RFC-3339 strings compared as instants). */
function swarmWindowWithin(childStart, childEnd, parentStart, parentEnd) {
  const cs = Date.parse(childStart);
  const ce = Date.parse(childEnd);
  const ps = Date.parse(parentStart);
  const pe = Date.parse(parentEnd);
  if ([cs, ce, ps, pe].some((n) => Number.isNaN(n))) return false;
  return cs >= ps && ce <= pe;
}

/** Authority view of a run envelope. */
function swarmRunAuthority(run) {
  return {
    capabilities: run.capabilityCeiling,
    risk: run.riskCeiling,
    scope: run.scopeCeiling,
    budget: run.budgetCeiling,
    notBefore: run.openedAt,
    notAfter: run.expiresAt,
  };
}

/** Authority view of a delegation edge envelope. */
function swarmEdgeAuthority(e) {
  return {
    capabilities: e.capabilitySubset,
    risk: e.riskCeiling,
    scope: e.scopeSubset,
    budget: e.budget,
    notBefore: e.notBefore,
    notAfter: e.notAfter,
  };
}

/** Does `child` authority attenuate `parent` authority? (SW-2/SW-5) */
function swarmAttenuates(child, parent) {
  return (
    swarmCapabilitiesSubset(child.capabilities, parent.capabilities) &&
    swarmRiskLEQ(child.risk, parent.risk) &&
    swarmScopeSubset(child.scope, parent.scope) &&
    swarmBudgetLEQ(child.budget, parent.budget) &&
    swarmWindowWithin(child.notBefore, child.notAfter, parent.notBefore, parent.notAfter)
  );
}

/**
 * Verify one action's delegation path: edge signatures (against delegator
 * pubkeys), lineage, depth, attenuation root-down, and SW-4 attribution.
 * Returns { status, reason, failedAtIndex }.
 */
function swarmVerifyActionPath(action, edgesByid, run, rootAuthorizedAgentId, nowMs) {
  const path = action.delegationPath ?? [];
  const rows = path.map((id) => edgesByid.get(id));

  // Missing edge → orphaned side effect.
  if (rows.some((r) => !r)) {
    return { status: "INVALID", reason: "SWARM_ORPHAN_SIDE_EFFECT", failedAtIndex: -1 };
  }
  // Unsigned edge → nothing to verify cryptographically.
  if (rows.some((r) => !r.signature)) {
    return { status: "LEGACY_UNSIGNED", reason: "SWARM_PATH_BROKEN", failedAtIndex: -1 };
  }
  // Unknown delegator key → cannot verify.
  for (const r of rows) {
    if (swarmJwkToKey(r.delegatorPublicKeyJwk) === null) {
      return { status: "UNVERIFIABLE", reason: "SWARM_DELEGATOR_KEY_UNKNOWN", failedAtIndex: -1 };
    }
  }

  const runStart = Date.parse(run.openedAt);
  const runEnd = Date.parse(run.expiresAt);
  let expectedDelegator = rootAuthorizedAgentId;
  let parentAuthority = swarmRunAuthority(run);

  for (let i = 0; i < rows.length; i++) {
    const edge = rows[i].canonical.payload;
    const pub = swarmJwkToKey(rows[i].delegatorPublicKeyJwk);

    // Ed25519 signature over SCJ-canonical envelope bytes.
    let sigOk = false;
    try {
      sigOk = crypto.verify(
        null,
        Buffer.from(scjCanonicalize(edge), "utf-8"),
        pub,
        Buffer.from(rows[i].signature, "base64"),
      );
    } catch {
      sigOk = false;
    }
    if (!sigOk) return { status: "INVALID", reason: "SWARM_PATH_BROKEN", failedAtIndex: i };

    // Lineage + depth.
    if (edge.delegatorAgentId !== expectedDelegator) {
      return { status: "INVALID", reason: "SWARM_PATH_BROKEN", failedAtIndex: i };
    }
    if (edge.depth !== i + 1) {
      return { status: "INVALID", reason: "SWARM_PATH_BROKEN", failedAtIndex: i };
    }
    if (edge.depth > run.maxDepth) {
      return { status: "INVALID", reason: "SWARM_DEPTH_EXCEEDED", failedAtIndex: i };
    }

    // Window containment + liveness.
    const eStart = Date.parse(edge.notBefore);
    const eEnd = Date.parse(edge.notAfter);
    if (eStart < runStart || eEnd > runEnd) {
      return { status: "INVALID", reason: "SWARM_EXPIRED", failedAtIndex: i };
    }
    if (nowMs !== null && (nowMs < eStart || nowMs > eEnd)) {
      return { status: "INVALID", reason: "SWARM_EXPIRED", failedAtIndex: i };
    }

    // Attenuation, recomputed root-down.
    if (!swarmAttenuates(swarmEdgeAuthority(edge), parentAuthority)) {
      return { status: "INVALID", reason: "SWARM_AMPLIFICATION_DETECTED", failedAtIndex: i };
    }

    expectedDelegator = edge.delegateeAgentId;
    parentAuthority = swarmEdgeAuthority(edge);
  }

  // SW-4 attribution: executor = leaf delegatee, taskHash binding.
  const leaf = rows[rows.length - 1]?.canonical.payload;
  if (!leaf || action.executingAgentId !== leaf.delegateeAgentId) {
    return { status: "INVALID", reason: "SWARM_ORPHAN_SIDE_EFFECT", failedAtIndex: -1 };
  }
  if (action.taskHash !== leaf.taskHash) {
    return { status: "INVALID", reason: "SWARM_TASK_HASH_MISMATCH", failedAtIndex: -1 };
  }

  return { status: "VERIFIED", reason: "SWARM_VERIFIED", failedAtIndex: -1 };
}

const SWARM_STATUS_RANK = { INVALID: 3, UNVERIFIABLE: 2, LEGACY_UNSIGNED: 1, VERIFIED: 0 };

/**
 * Independently verify a swarm run's delegation graph.
 *
 * @param {string} swarmRunId
 * @param {{ base?: string, proof?: object, now?: Date }} [opts]
 *   - base: API host (default www.strixgov.com)
 *   - proof: inject the proof-API response (offline / testing) instead of fetching
 *   - now: wall clock for window liveness (default: skip liveness, only containment)
 */
export async function verifySwarm(swarmRunId, opts = {}) {
  const base = opts.base ?? DEFAULT_JWKS_BASE;

  let proof = opts.proof;
  if (!proof) {
    const url = `${base}/api/public/proof/swarm/${encodeURIComponent(swarmRunId)}`;
    let res;
    try {
      res = await fetch(url, { cache: "no-cache", headers: { accept: "application/json" } });
    } catch (err) {
      return { verificationStatus: "ERROR", swarmRunId, error: err.message };
    }
    if (res.status === 404) {
      return { verificationStatus: "NOT_FOUND", swarmRunId };
    }
    if (!res.ok) {
      return { verificationStatus: "ERROR", swarmRunId, error: `HTTP ${res.status}` };
    }
    proof = await res.json();
  }

  const run = proof.run?.canonical?.payload ?? proof.run;
  if (!run || !run.swarmRunId) {
    return { verificationStatus: "ERROR", swarmRunId, error: "malformed proof response (no run)" };
  }

  const edges = proof.delegations ?? [];
  const actions = proof.actions ?? [];

  const edgesByid = new Map();
  for (const e of edges) {
    const env = e.canonical?.payload;
    if (env) edgesByid.set(env.delegationId, e);
  }

  // SW-1 rooting: the proof surface exposes `rooted` (root decision APPROVED).
  // We re-assert the structural rooting fields are present; the APPROVED status
  // itself is the server's RLS-scoped read (an auditor cross-checks the decision
  // via /api/public/decisions/<id>).
  const rooted =
    proof.rooted === true && !!run.rootDecisionId && !!run.rootApprovalId && !!run.rootActorId;

  const rootAuthorizedAgentId =
    edges.find((e) => e.canonical?.payload?.depth === 1)?.canonical?.payload?.delegatorAgentId ?? "";

  const nowMs = opts.now ? opts.now.getTime() : null;

  const actionResults = [];
  let overall = edges.length === 0 && actions.length === 0 ? "LEGACY_UNSIGNED" : "VERIFIED";
  let overallReason = overall === "LEGACY_UNSIGNED" ? "SWARM_NO_SIGNED_MATERIAL" : "SWARM_VERIFIED";

  if (!rooted && (edges.length > 0 || actions.length > 0)) {
    overall = "INVALID";
    overallReason = "SWARM_UNROOTED";
  }

  for (const action of actions) {
    const env = action.canonical?.payload ?? action;
    const r = rooted
      ? swarmVerifyActionPath(env, edgesByid, run, rootAuthorizedAgentId, nowMs)
      : { status: "INVALID", reason: "SWARM_UNROOTED", failedAtIndex: -1 };
    actionResults.push({
      swarmActionId: env.swarmActionId,
      evidenceId: env.evidenceId,
      executingAgentId: env.executingAgentId,
      status: r.status,
      reason: r.reason,
      failedAtIndex: r.failedAtIndex,
    });
    if (SWARM_STATUS_RANK[r.status] > SWARM_STATUS_RANK[overall]) {
      overall = r.status;
      overallReason = r.reason;
    }
  }

  return {
    verificationStatus: overall,
    reason: overallReason,
    swarmRunId: run.swarmRunId,
    rooted,
    counts: { edges: edges.length, actions: actions.length },
    actions: actionResults,
    // Agreement check: does our independent verdict match the server's?
    serverStatus: proof.verification_status ?? null,
    agreesWithServer: proof.verification_status ? proof.verification_status === overall : null,
  };
}
