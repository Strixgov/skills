/**
 * MC-1 → SCITT Signed Statement (COSE_Sign1) verification — E2 profile.
 *
 * Verifies a governed-tool-action record encoded as a SCITT Signed Statement
 * (a COSE_Sign1, CBOR tag 18, protected-header typ `application/mcp-proof-scitt+cose`)
 * carrying the MC-1 payload as SCJ v1 canonical JSON bytes. Zero-dependency:
 * a minimal CBOR reader + `node:crypto` Ed25519, matching the rest of this
 * package. Verify-only — this package never signs.
 *
 * Cross-validated: the bytes this verifies are byte-locked in
 * `conformance/corpus/mcp_proof_scitt_v1/` and independently agreed by a Python
 * implementation (cbor2 + PyNaCl). See `test/mcp-scitt-golden-vectors.test.mjs`.
 *
 * GATED SURFACE: this is the code path (step 4b of the E2 public-claim gate).
 * A public "SCITT-aligned / SCITT-conformant" claim is still gated on IANA
 * media-type registration + the THREAT-MODEL §9 row (see
 * docs/security/scitt-public-claim-gate.md). The presence of this verifier is a
 * capability, not a claim.
 */
import { createPublicKey, verify as edVerify } from "node:crypto";

export const MCP_SCITT_PROFILE = "application/mcp-proof-scitt+cose";
export const MCP_PROOF_CTY = "application/mcp-proof+json";

// COSE / CWT header labels (RFC 9052 / RFC 8392 / draft-ietf-cose-typ-header).
const H_ALG = 1, H_CTY = 3, H_KID = 4, H_CWT = 15, H_TYP = 16;
const CWT_ISS = 1, CWT_SUB = 2;
const ALG_EDDSA = -8;

/** Verdict reason codes (stable public vocabulary). */
export const MCP_SCITT_REASONS = Object.freeze({
  VERIFIED: "VERIFIED",
  MALFORMED_CBOR: "MALFORMED_CBOR",
  NOT_COSE_SIGN1: "NOT_COSE_SIGN1",
  BAD_STRUCTURE: "BAD_STRUCTURE",
  BAD_PROTECTED_HEADER: "BAD_PROTECTED_HEADER",
  WRONG_PROFILE: "WRONG_PROFILE",
  UNSUPPORTED_ALG: "UNSUPPORTED_ALG",
  KEY_UNKNOWN: "KEY_UNKNOWN",
  SIGNATURE_INVALID: "SIGNATURE_INVALID",
});

// ── Minimal CBOR encode (only what Sig_structure needs) + decode ─────────────
function head(major, n) {
  const mt = major << 5;
  if (n < 24) return Buffer.from([mt | n]);
  if (n < 0x100) return Buffer.from([mt | 24, n]);
  if (n < 0x10000) { const b = Buffer.alloc(3); b[0] = mt | 25; b.writeUInt16BE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = mt | 26; b.writeUInt32BE(n, 1); return b;
}
const cBstr = (b) => Buffer.concat([head(2, b.length), b]);
const cTstr = (s) => { const b = Buffer.from(s, "utf8"); return Buffer.concat([head(3, b.length), b]); };
const cArr = (items) => Buffer.concat([head(4, items.length), ...items]);

function decode(buf, off = 0) {
  // Defensive: reject truncated/out-of-bounds input up front so a malformed
  // message fails as MALFORMED_CBOR rather than silently coercing undefined->0.
  if (off < 0 || off >= buf.length) throw new Error("truncated: read past end");
  const ib = buf[off];
  const major = ib >> 5;
  const ai = ib & 0x1f;
  let val, p = off + 1;
  if (ai < 24) val = ai;
  else if (ai === 24) { if (p + 1 > buf.length) throw new Error("truncated uint8"); val = buf[p]; p += 1; }
  else if (ai === 25) { if (p + 2 > buf.length) throw new Error("truncated uint16"); val = buf.readUInt16BE(p); p += 2; }
  else if (ai === 26) { if (p + 4 > buf.length) throw new Error("truncated uint32"); val = buf.readUInt32BE(p); p += 4; }
  else throw new Error("unsupported additional info");
  switch (major) {
    case 0: return { value: val, next: p };
    case 1: return { value: -1 - val, next: p };
    case 2: if (p + val > buf.length) throw new Error("truncated byte string"); return { value: buf.subarray(p, p + val), next: p + val };
    case 3: if (p + val > buf.length) throw new Error("truncated text string"); return { value: buf.subarray(p, p + val).toString("utf8"), next: p + val };
    case 4: { const a = []; let q = p; for (let i = 0; i < val; i++) { const r = decode(buf, q); a.push(r.value); q = r.next; } return { value: a, next: q }; }
    case 5: { const m = new Map(); let q = p; for (let i = 0; i < val; i++) { const k = decode(buf, q); const v = decode(buf, k.next); m.set(typeof k.value === "object" ? k.value.toString("hex") : k.value, v.value); q = v.next; } return { value: m, next: q }; }
    case 6: { const r = decode(buf, p); return { value: { tag: val, content: r.value }, next: r.next }; }
    default: throw new Error("unsupported major type");
  }
}

/**
 * Which MC-1 form is this? A CBOR COSE_Sign1 (tag 18, 0xD2) with the SCITT
 * profile typ → "mcp_proof_scitt_cose"; a JSON object → "mcp_proof_v1_json";
 * else "unknown". (v1 JSON verification lives in @strixgov/sdk; this package
 * verifies the COSE form.)
 */
export function detectMcpProofForm(bytes) {
  if (!bytes || bytes.length === 0) return "unknown";
  if (bytes[0] === 0xd2) return "mcp_proof_scitt_cose";
  let i = 0; while (i < bytes.length && (bytes[i] === 0x20 || bytes[i] === 0x0a || bytes[i] === 0x09 || bytes[i] === 0x0d)) i++;
  if (bytes[i] === 0x7b) return "mcp_proof_v1_json";
  return "unknown";
}

function toPublicKey(k) {
  if (!k) return undefined;
  if (typeof k === "object" && k.type === "public") return k; // already a KeyObject
  try { return createPublicKey({ key: k, format: "jwk" }); } catch { return undefined; }
}

/**
 * Verify a SCITT Signed Statement (COSE_Sign1) for the MC-1 profile.
 *
 * @param {Buffer|Uint8Array} bytes  the COSE_Sign1 message.
 * @param {{ resolveKey: (kid: string) => (import('crypto').KeyObject | object | undefined) }} opts
 *        resolveKey resolves a kid to a public key (KeyObject or JWK) — the ONE
 *        trust-root path the caller controls (e.g. resolveJwkFromKid over the JWKS).
 * @returns {{ ok: boolean, reason: string, kid?: string, iss?: string, sub?: string, payload?: string }}
 */
export function verifyMcpScittStatement(bytes, opts = {}) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const R = MCP_SCITT_REASONS;
  let decoded;
  try { decoded = decode(buf).value; } catch { return { ok: false, reason: R.MALFORMED_CBOR }; }
  if (!decoded || decoded.tag !== 18 || !Array.isArray(decoded.content) || decoded.content.length !== 4)
    return { ok: false, reason: R.NOT_COSE_SIGN1 };
  const [protectedBytes, , payloadBytes, sigBytes] = decoded.content;
  if (!Buffer.isBuffer(protectedBytes) || !Buffer.isBuffer(payloadBytes) || !Buffer.isBuffer(sigBytes))
    return { ok: false, reason: R.BAD_STRUCTURE };

  let ph;
  try { ph = decode(protectedBytes).value; } catch { return { ok: false, reason: R.BAD_PROTECTED_HEADER }; }
  const typ = ph.get(H_TYP);
  if (typ !== MCP_SCITT_PROFILE) return { ok: false, reason: R.WRONG_PROFILE };
  if (ph.get(H_ALG) !== ALG_EDDSA) return { ok: false, reason: R.UNSUPPORTED_ALG };
  const kidBuf = ph.get(H_KID);
  const kid = Buffer.isBuffer(kidBuf) ? kidBuf.toString("utf8") : undefined;
  const cwt = ph.get(H_CWT);
  const iss = cwt && cwt.get ? cwt.get(CWT_ISS) : undefined;
  const sub = cwt && cwt.get ? cwt.get(CWT_SUB) : undefined;

  const resolveKey = typeof opts.resolveKey === "function" ? opts.resolveKey : () => opts.publicKey;
  const pub = toPublicKey(resolveKey(kid));
  if (!pub) return { ok: false, reason: R.KEY_UNKNOWN, kid, iss, sub };

  // Sig_structure = [ "Signature1", protected (bstr), external_aad (empty bstr), payload (bstr) ]
  const sigStructure = cArr([cTstr("Signature1"), cBstr(protectedBytes), cBstr(Buffer.alloc(0)), cBstr(payloadBytes)]);
  if (!edVerify(null, sigStructure, pub, sigBytes)) return { ok: false, reason: R.SIGNATURE_INVALID, kid, iss, sub };
  return { ok: true, reason: R.VERIFIED, kid, iss, sub, payload: payloadBytes.toString("utf8") };
}
