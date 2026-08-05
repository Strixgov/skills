/**
 * Selective-disclosure bundle verification (run_commitment_v1) — the
 * INDEPENDENT re-derivation path.
 *
 * Zero shared code with the producer (`solo-builder-core/src/run-commitment-v1.ts`):
 * this module re-implements the SCJ-v1-compatible canonicalization (sorted
 * keys, no whitespace, no ASCII-escaping) and the RFC 6962 §2.1 Merkle walk
 * from scratch using only node:crypto. Drift between the two implementations
 * is caught by replaying the producer's golden vectors in
 * test/disclosure.test.mjs (the conformance-program discipline).
 *
 * Honesty rules (mirroring the producer contract, re-derived not imported):
 *  - SD-1  every result carries `completeness: "NOT_PROVEN"` — a root proves
 *          inclusion + consistency of what is presented, structurally never
 *          that the slice is the whole run.
 *  - SD-4  the root is re-derived from each disclosed leaf + its audit path;
 *          planted `verified` fields anywhere in the bundle are ignored.
 *  - SD-5  an unresolvable commitment key → UNVERIFIABLE, never INVALID;
 *          a path that fails to re-derive the signed root → INVALID.
 *
 * Record-level re-verification: disclosed records that carry the SE v1 shape
 * (signature + signingKeyId + a canonical field set) are re-verified with
 * THIS package's own SE v1 path (buildCanonicalPayload + verifySignature).
 * A record this module cannot recognize caps at UNVERIFIABLE — it is never
 * assumed valid.
 */

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { buildCanonicalPayload, resolveJwksByKid, verifySignature } from "./index.mjs";

const HEX64 = /^[0-9a-f]{64}$/;

export const DISCLOSURE_REASONS = Object.freeze({
  OK: "DISCLOSURE_OK",
  SCHEMA_INVALID: "DISCLOSURE_SCHEMA_INVALID",
  KEY_UNRESOLVED: "DISCLOSURE_KEY_UNRESOLVED",
  SIGNATURE_INVALID: "DISCLOSURE_SIGNATURE_INVALID",
  PROOF_MALFORMED: "DISCLOSURE_PROOF_MALFORMED",
  ROOT_MISMATCH: "DISCLOSURE_ROOT_MISMATCH",
  LEAF_RECORD_MISMATCH: "DISCLOSURE_LEAF_RECORD_MISMATCH",
  RECORD_UNRECOGNIZED: "DISCLOSURE_RECORD_UNRECOGNIZED",
  RECORD_INVALID: "DISCLOSURE_RECORD_INVALID",
  RECORD_KEY_UNRESOLVED: "DISCLOSURE_RECORD_KEY_UNRESOLVED",
});

// ── Own canonicalization (SCJ-v1-compatible; independently implemented) ──

function canonicalize(value) {
  if (value === null || typeof value === "number" || typeof value === "boolean") {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("non-finite number in canonical payload");
    }
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

// ── Own RFC 6962 §2.1 walk (leaf 0x00 / node 0x01) ──────────────────────

function sha256(...parts) {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

function leafNode(leafHex) {
  return sha256(Buffer.from([0x00]), Buffer.from(leafHex, "hex"));
}

/** RFC 6962 §2.1.1 inclusion-proof verification walk. Returns hex root or null. */
export function rootFromInclusionPath(leafHash, leafIndex, treeSize, path) {
  if (!HEX64.test(leafHash ?? "")) return null;
  if (!Number.isInteger(leafIndex) || leafIndex < 0) return null;
  if (!Number.isInteger(treeSize) || treeSize < 1 || leafIndex >= treeSize) return null;
  if (!Array.isArray(path) || path.some((p) => !HEX64.test(p ?? ""))) return null;

  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leafNode(leafHash);
  for (const sibling of path) {
    if (sn === 0) return null;
    const sib = Buffer.from(sibling, "hex");
    if (fn % 2 === 1 || fn === sn) {
      r = sha256(Buffer.from([0x01]), sib, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = sha256(Buffer.from([0x01]), r, sib);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) return null;
  return r.toString("hex");
}

// ── Key + record helpers ────────────────────────────────────────────────

function keyFromJwk(jwk) {
  try {
    return createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    return null;
  }
}

function looksLikeSeV1(record) {
  return (
    record &&
    typeof record === "object" &&
    typeof record.signature === "string" &&
    typeof record.signingKeyId === "string" &&
    (record.evidenceHash !== undefined || record.evidence_hash !== undefined)
  );
}

/**
 * Re-verify a disclosed SE v1 record with this package's own canonical +
 * signature path. Returns { verdict, reason }.
 */
function verifySeV1Record(record, jwks) {
  const candidates = resolveJwksByKid(record.signingKeyId, jwks);
  if (!candidates || candidates.length === 0) {
    return { verdict: "UNVERIFIABLE", reason: DISCLOSURE_REASONS.RECORD_KEY_UNRESOLVED };
  }
  let canonical;
  try {
    canonical = buildCanonicalPayload(record);
  } catch {
    return { verdict: "INVALID", reason: DISCLOSURE_REASONS.RECORD_INVALID };
  }
  for (const jwk of candidates) {
    const key = keyFromJwk(jwk);
    if (key && verifySignature(canonical, record.signature, key)) {
      return { verdict: "VERIFIED", reason: DISCLOSURE_REASONS.OK };
    }
  }
  return { verdict: "INVALID", reason: DISCLOSURE_REASONS.RECORD_INVALID };
}

// ── Bundle verification ─────────────────────────────────────────────────

/**
 * Verify a disclosure bundle offline.
 *
 * @param {object} bundle  A run_commitment_v1 disclosure bundle.
 * @param {object} opts
 * @param {object} [opts.jwks]  JWKS ({ keys: [...] }) used for BOTH the
 *   commitment signature and SE v1 record re-verification. Absent → the
 *   commitment verdict caps at UNVERIFIABLE (SD-5), never INVALID.
 * @param {(record: unknown) => "VERIFIED"|"INVALID"|"UNVERIFIABLE"} [opts.recordVerifier]
 *   Optional override for record re-verification (defaults to the SE v1 path).
 */
export function verifyDisclosureBundle(bundle, opts = {}) {
  const reasons = [];
  const perRecord = [];
  let worst = "VERIFIED";
  const cap = (v) => {
    if (v === "INVALID") worst = "INVALID";
    else if (v === "UNVERIFIABLE" && worst === "VERIFIED") worst = "UNVERIFIABLE";
  };

  const c = bundle?.commitment;
  const p = c?.payload;
  if (
    bundle?.bundleVersion !== 1 ||
    !p ||
    p.schemaVersion !== 1 ||
    p.leafHashAlgorithm !== "sha256-rfc6962" ||
    !HEX64.test(p.rootHash ?? "") ||
    !Number.isInteger(p.leafCount) ||
    p.leafCount < 1 ||
    !Array.isArray(bundle.disclosed)
  ) {
    return {
      verdict: "INVALID",
      reasons: [DISCLOSURE_REASONS.SCHEMA_INVALID],
      completeness: "NOT_PROVEN",
      perRecord: [],
    };
  }

  // Commitment signature — own canonicalization, own verify (SD-4/SD-5).
  const jwks = opts.jwks ?? null;
  const candidates = jwks ? resolveJwksByKid(c.signingKeyId, jwks) : [];
  if (!candidates || candidates.length === 0) {
    cap("UNVERIFIABLE");
    reasons.push(DISCLOSURE_REASONS.KEY_UNRESOLVED);
  } else {
    let ok = false;
    let canonical;
    try {
      canonical = canonicalize(p);
    } catch {
      canonical = null;
    }
    if (canonical !== null) {
      for (const jwk of candidates) {
        const key = keyFromJwk(jwk);
        if (
          key &&
          cryptoVerify(null, Buffer.from(canonical, "utf-8"), key, Buffer.from(c.signature, "base64"))
        ) {
          ok = true;
          break;
        }
      }
    }
    if (!ok) {
      cap("INVALID");
      reasons.push(DISCLOSURE_REASONS.SIGNATURE_INVALID);
    }
  }

  const verifyRecord =
    opts.recordVerifier ??
    ((record) => {
      if (!looksLikeSeV1(record)) {
        return jwks ? "UNVERIFIABLE" : "UNVERIFIABLE";
      }
      if (!jwks) return "UNVERIFIABLE";
      return verifySeV1Record(record, jwks).verdict;
    });

  for (const entry of bundle.disclosed) {
    let verdict = "VERIFIED";
    let reason = DISCLOSURE_REASONS.OK;
    const rec = entry?.record;
    const address =
      rec && typeof rec === "object" ? rec[entry.contentAddressField] : undefined;
    if (address !== entry.leafHash) {
      verdict = "INVALID";
      reason = DISCLOSURE_REASONS.LEAF_RECORD_MISMATCH;
    } else {
      const derived = rootFromInclusionPath(
        entry.leafHash,
        entry.leafIndex,
        p.leafCount,
        entry.inclusionPath,
      );
      if (derived === null) {
        verdict = "INVALID";
        reason = DISCLOSURE_REASONS.PROOF_MALFORMED;
      } else if (derived !== p.rootHash) {
        verdict = "INVALID";
        reason = DISCLOSURE_REASONS.ROOT_MISMATCH;
      } else {
        const rv = verifyRecord(rec);
        if (rv === "INVALID") {
          verdict = "INVALID";
          reason = DISCLOSURE_REASONS.RECORD_INVALID;
        } else if (rv === "UNVERIFIABLE") {
          verdict = "UNVERIFIABLE";
          reason = looksLikeSeV1(rec)
            ? DISCLOSURE_REASONS.RECORD_KEY_UNRESOLVED
            : DISCLOSURE_REASONS.RECORD_UNRECOGNIZED;
        }
      }
    }
    perRecord.push({ leafIndex: entry?.leafIndex, verdict, reason });
    cap(verdict);
  }

  if (worst === "VERIFIED") reasons.push(DISCLOSURE_REASONS.OK);
  return { verdict: worst, reasons, completeness: "NOT_PROVEN", perRecord };
}
