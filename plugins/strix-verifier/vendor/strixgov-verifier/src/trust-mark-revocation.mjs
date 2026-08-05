/**
 * @strixgov/verifier — trust_mark_revocation_list_v1 (TM-1 rule-10 distribution).
 *
 * Rule 10 of the grant verifier asks "is this grant_id withdrawn?" against a
 * signed, publicly-distributable revocation list (ADR-029 §8). This is the
 * sibling of the grant: SAME authority trust root, nested envelope
 * `{ payload, signature, kid }`, hex Ed25519 over the SCJ v1 canonical payload
 * (the grant's encoding — NOT the heartbeat's base64url). Keyed by `grant_id`;
 * deliberately NOT the frozen operational-kid revocation list (that one is
 * keyed by kid — do not overload it).
 *
 * Tri-state + fail-closed (the AA-1 / Gate-D discipline, matching
 * verifyTrustMarkGrant's rule 10):
 *   - REVOKED      — list verifies AND grant_id ∈ revoked[]      → tm1_revoked
 *   - NOT_REVOKED  — list verifies AND grant_id ∉ revoked[]      → rule 10 PASS
 *   - UNAVAILABLE  — list missing / malformed / signature invalid → tm1_revocation_check_unavailable
 * UNAVAILABLE is never treated as NOT_REVOKED ("no silent allow"): a tampered or
 * unverifiable list cannot clear a grant.
 *
 * The authority key NEVER touches the platform runtime — the list is signed
 * offline (scripts/sign-trust-mark-revocation-list.mjs) and served verbatim.
 */

import crypto from "node:crypto";
import { scjCanonicalize } from "./index.mjs";

export const TRUST_MARK_REVOCATION_SCHEMA_VERSION = "trust_mark_revocation_list_v1";

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/**
 * Build the canonical revocation-list PAYLOAD. Entries are sorted by grant_id
 * (deterministic bytes, like the OB-3 list sorts by kid). Append-only semantics
 * are the operator's; this just normalizes whatever set it is handed.
 *
 * @param {{ revoked: Array<{grant_id:string, revoked_at:string, decision_evidence_id:string}>, issuedAt:string, iss:string }} input
 */
export function buildTrustMarkRevocationPayload(input) {
  if (!input || typeof input !== "object") throw new Error("revocation input must be an object");
  if (typeof input.issuedAt !== "string" || !input.issuedAt) throw new Error("issuedAt is required");
  if (typeof input.iss !== "string" || !input.iss) throw new Error("iss is required");
  const entries = Array.isArray(input.revoked) ? input.revoked : [];
  const revoked = entries
    .map((e) => {
      if (!e || typeof e !== "object" || !ID_RE.test(String(e.grant_id))) {
        throw new Error(`each revoked entry needs a valid grant_id (got ${JSON.stringify(e?.grant_id)})`);
      }
      if (typeof e.revoked_at !== "string" || !e.revoked_at) throw new Error(`revoked_at required for ${e.grant_id}`);
      if (typeof e.decision_evidence_id !== "string" || !e.decision_evidence_id) {
        throw new Error(`decision_evidence_id required for ${e.grant_id}`);
      }
      return { grant_id: e.grant_id, revoked_at: e.revoked_at, decision_evidence_id: e.decision_evidence_id };
    })
    .sort((a, b) => (a.grant_id < b.grant_id ? -1 : a.grant_id > b.grant_id ? 1 : 0));
  return {
    schema_version: TRUST_MARK_REVOCATION_SCHEMA_VERSION,
    revoked,
    issued_at: input.issuedAt,
    iss: input.iss,
  };
}

/** SCJ v1 canonical bytes of the payload — the exact signed bytes. */
export function canonicalizeTrustMarkRevocation(payload) {
  return scjCanonicalize({
    schema_version: payload.schema_version,
    revoked: (payload.revoked ?? []).map((e) => ({
      grant_id: e.grant_id,
      revoked_at: e.revoked_at,
      decision_evidence_id: e.decision_evidence_id,
    })),
    issued_at: payload.issued_at,
    iss: payload.iss,
  });
}

/** Sign a built payload with the authority Ed25519 private key (hex signature). */
export function signTrustMarkRevocationList(payload, privateKey, kid) {
  if (typeof kid !== "string" || !kid) throw new Error("kid is required");
  const canonical = Buffer.from(canonicalizeTrustMarkRevocation(payload), "utf8");
  const signature = crypto.sign(null, canonical, privateKey).toString("hex");
  return { payload, signature, kid };
}

/** Structural parse of an untrusted revocation document. Never throws. */
export function parseTrustMarkRevocationList(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, error: "revocation list must be a JSON object" };
  }
  const doc = input;
  const payload = doc.payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return { ok: false, error: "payload object missing" };
  }
  if (payload.schema_version !== TRUST_MARK_REVOCATION_SCHEMA_VERSION) {
    return { ok: false, error: `schema_version must be "${TRUST_MARK_REVOCATION_SCHEMA_VERSION}"` };
  }
  if (!Array.isArray(payload.revoked)) return { ok: false, error: "payload.revoked must be an array" };
  for (const e of payload.revoked) {
    if (!e || typeof e !== "object" || typeof e.grant_id !== "string") {
      return { ok: false, error: "each revoked entry needs a string grant_id" };
    }
  }
  if (typeof payload.issued_at !== "string" || typeof payload.iss !== "string") {
    return { ok: false, error: "payload.issued_at + payload.iss are required strings" };
  }
  if (typeof doc.signature !== "string" || !/^[0-9a-fA-F]{128}$/.test(doc.signature)) {
    return { ok: false, error: "signature must be a 64-byte hex Ed25519 signature" };
  }
  if (typeof doc.kid !== "string" || !doc.kid) return { ok: false, error: "kid must be a non-empty string" };
  return { ok: true, value: doc };
}

/** Verify the hex Ed25519 signature of a parsed list against a public key. Never throws. */
export function verifyTrustMarkRevocationSignature(doc, publicKey) {
  try {
    const canonical = Buffer.from(canonicalizeTrustMarkRevocation(doc.payload), "utf8");
    return crypto.verify(null, canonical, publicKey, Buffer.from(doc.signature, "hex"));
  } catch {
    return false;
  }
}

/**
 * Resolve a grant's revocation status against a (possibly absent) signed list.
 * Tri-state, fail-closed.
 *
 * @param {string} grantId
 * @param {unknown} listDoc - the fetched/loaded revocation document, or null.
 * @param {(kid: string) => import("node:crypto").KeyObject | null} resolveAuthorityKey
 * @returns {"not_revoked"|"revoked"|"unavailable"}
 */
export function resolveGrantRevocation(grantId, listDoc, resolveAuthorityKey) {
  if (listDoc === null || listDoc === undefined) return "unavailable";
  const parsed = parseTrustMarkRevocationList(listDoc);
  if (!parsed.ok) return "unavailable";
  const key = typeof resolveAuthorityKey === "function" ? resolveAuthorityKey(parsed.value.kid) : null;
  if (!key) return "unavailable";
  if (!verifyTrustMarkRevocationSignature(parsed.value, key)) return "unavailable";
  const hit = parsed.value.payload.revoked.some((e) => e.grant_id === grantId);
  return hit ? "revoked" : "not_revoked";
}
