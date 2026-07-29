#!/usr/bin/env node
// Generates the Gate-J golden-vector corpus for the vendored @strixgov/verifier
// copy in this plugin. Mirrors the repo's se_v1 corpus convention
// (conformance/corpus/se_v1/index.json + positive/negative vectors), scoped to
// the receipt/chain surface that is testable fully offline (no network).
//
// This is a GENERATOR, run once to produce the committed vectors under
// vectors/*.json + index.json — it is not re-run at test/CI time (mirrors
// scripts/vendor-verifier.mjs: reproducible, but the checked-in output is
// what CI actually gates on). Re-run only when deliberately refreshing the
// corpus, and re-commit the output.
//
// Every signature below is minted with a REAL Ed25519 key via Node's own
// `crypto` module and verified through the vendored verifier's own exported
// functions (buildReceiptCanonicalPayload, verifyReceipt) — nothing here
// re-implements or second-guesses the vendored crypto/verdict logic.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildReceiptCanonicalPayload } from "../vendor/strixgov-verifier/src/index.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, "vectors");
fs.mkdirSync(OUT, { recursive: true });

function genKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const raw = spki.subarray(spki.length - 32); // strip the fixed 12-byte SPKI header
  return { publicKey, privateKey, x: raw.toString("base64url") };
}

function jwk(kid, x) {
  return { kty: "OKP", crv: "Ed25519", kid, x };
}

function sign(privateKey, canonical) {
  return crypto.sign(null, Buffer.from(canonical, "utf8"), privateKey).toString("base64url");
}

function sha256hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

const GENESIS = "0".repeat(64);
function chainHash(prev, evidenceHash) {
  return sha256hex(`${prev}|${evidenceHash}`);
}

// Two independent keypairs simulate a key rotation: OLD (retired) + CURRENT.
const oldKey = genKeyPair();
const curKey = genKeyPair();
const foreignKey = genKeyPair(); // never appears in any JWKS — "wrong key" vector

const OLD_KID = "strix-plugin-conformance-2026-01";
const CUR_KID = "strix-plugin-conformance-2026-07";

// A JWKS carrying BOTH the retired and current key — the "rotated historical
// key still resolves" scenario (GAP: verifyReceipt's opts.jwks path uses
// first-match-by-kid resolution, so this only proves distinct-kid rotation,
// not same-kid-collision resolution — see conformance/README.md).
const rotationJwks = { keys: [jwk(OLD_KID, oldKey.x), jwk(CUR_KID, curKey.x)] };

const vectors = [];

function baseReceiptV1(overrides = {}) {
  return {
    schemaVersion: "1",
    receiptId: "rcpt-conformance-0001",
    capabilityId: "governance.evaluate",
    action: "allow",
    decision: "ALLOW",
    risk: "MEDIUM",
    mode: "enforced",
    invocationHash: "inv" + "0".repeat(61),
    evidenceHash: "evh" + "1".repeat(61),
    proofChainHash: chainHash(GENESIS, "evh" + "1".repeat(61)),
    timestamp: "2026-07-01T00:00:00.000Z",
    ...overrides,
  };
}

function mintReceipt(receipt, signingKey, kid) {
  const canonical = buildReceiptCanonicalPayload(receipt);
  return {
    ...receipt,
    signingKeyId: kid,
    signature: sign(signingKey, canonical),
  };
}

// --- V1: valid, signed with the OLDER (retired) key; JWKS carries both ------
{
  const r = baseReceiptV1();
  const signed = mintReceipt(r, oldKey.privateKey, OLD_KID);
  vectors.push({
    id: "rcpt-pos-01-rotated-key-still-verifies",
    category: "positive",
    description:
      "Signed with a retired kid whose key is still present in the JWKS alongside " +
      "the current key (key rotation). Must resolve and verify by exact kid match " +
      "regardless of the retired key's position in the JWKS.",
    kind: "receipt",
    jwks: rotationJwks,
    receipt: signed,
    expected: { verificationStatus: "VERIFIED", signatureValid: true, hashValid: true },
  });
}

// --- V2: schema v2 (mixed-version), current key ------------------------------
{
  const r = {
    schemaVersion: "2",
    receiptId: "rcpt-conformance-0002",
    capabilityId: "governance.evaluate",
    action: "allow",
    decision: "ALLOW",
    risk: "LOW",
    mode: "enforced",
    policyVersion: "sha256:conformance",
    tenantId: "conformance-tenant",
    environment: "test",
    invocationHash: "inv" + "2".repeat(61),
    evidenceHash: "evh" + "2".repeat(61),
    proofChainHash: chainHash(GENESIS, "evh" + "2".repeat(61)),
    timestamp: "2026-07-02T00:00:00.000Z",
  };
  const signed = mintReceipt(r, curKey.privateKey, CUR_KID);
  vectors.push({
    id: "rcpt-pos-02-schema-v2-mixed-version",
    category: "positive",
    description:
      "schemaVersion=2 receipt (adds policyVersion/tenantId/environment) signed with " +
      "the current key. Proves the vendored canonical builder's version dispatch and " +
      "verification agree for the newer schema, alongside the v1 vectors above.",
    kind: "receipt",
    jwks: rotationJwks,
    receipt: signed,
    expected: { verificationStatus: "VERIFIED", signatureValid: true, hashValid: true },
  });
}

// --- negative: tampered payload (field mutated post-signature) --------------
{
  const r = baseReceiptV1({ receiptId: "rcpt-conformance-0003" });
  const signed = mintReceipt(r, curKey.privateKey, CUR_KID);
  const tampered = { ...signed, action: "denied" }; // mutate AFTER signing
  vectors.push({
    id: "rcpt-neg-01-tampered-payload",
    category: "negative",
    description:
      "Signature was minted over action=allow; the shipped receipt claims " +
      "action=denied. Canonical bytes no longer match the signature. MUST reject.",
    kind: "receipt",
    jwks: rotationJwks,
    receipt: tampered,
    expected: { verificationStatus: "TAMPERED", signatureValid: false, hashValid: false },
  });
}

// --- negative: wrong key (same kid, but JWKS entry is a foreign key) --------
{
  const r = baseReceiptV1({ receiptId: "rcpt-conformance-0004" });
  const signed = mintReceipt(r, curKey.privateKey, CUR_KID);
  const wrongKeyJwks = { keys: [jwk(OLD_KID, oldKey.x), jwk(CUR_KID, foreignKey.x)] };
  vectors.push({
    id: "rcpt-neg-02-wrong-key",
    category: "negative",
    description:
      "A well-formed signature, but the JWKS entry under the matching kid is a " +
      "foreign public key (not the one that signed). MUST reject — the key did " +
      "not sign these bytes.",
    kind: "receipt",
    jwks: wrongKeyJwks,
    receipt: signed,
    expected: { verificationStatus: "TAMPERED", signatureValid: false, hashValid: false },
  });
}

// --- negative: key not found (kid absent from JWKS) -------------------------
{
  const r = baseReceiptV1({ receiptId: "rcpt-conformance-0005" });
  const signed = mintReceipt(r, curKey.privateKey, "strix-plugin-conformance-2099-01");
  vectors.push({
    id: "rcpt-neg-03-key-not-found",
    category: "negative",
    description:
      "signingKeyId does not match any kid in the provided JWKS. MUST fail closed " +
      "with an explicit key-not-found error, never a false VERIFIED.",
    kind: "receipt",
    jwks: rotationJwks,
    receipt: signed,
    expected: { verificationStatus: "ERROR", signatureValid: false, errorIncludes: "not found" },
  });
}

// --- negative: unsigned (no signature field at all) -------------------------
{
  const r = baseReceiptV1({ receiptId: "rcpt-conformance-0006" });
  vectors.push({
    id: "rcpt-neg-04-unsigned",
    category: "negative",
    description: "Receipt carries no signature field at all. MUST report UNSIGNED, never VERIFIED.",
    kind: "receipt",
    jwks: rotationJwks,
    receipt: r,
    expected: { verificationStatus: "UNSIGNED", signaturePresent: false },
  });
}

// --- negative: signature present but signingKeyId missing ------------------
{
  const r = baseReceiptV1({ receiptId: "rcpt-conformance-0007" });
  const canonical = buildReceiptCanonicalPayload(r);
  const receipt = { ...r, signature: sign(curKey.privateKey, canonical) }; // no signingKeyId
  vectors.push({
    id: "rcpt-neg-05-missing-signing-key-id",
    category: "negative",
    description:
      "Receipt has a signature but no signingKeyId — there is no way to resolve a " +
      "verifying key. MUST fail closed with an explicit error, never assume a key.",
    kind: "receipt",
    jwks: rotationJwks,
    receipt,
    expected: { verificationStatus: "ERROR", errorIncludes: "signingKeyId" },
  });
}

// --- negative: malformed signature bytes ------------------------------------
{
  const r = baseReceiptV1({ receiptId: "rcpt-conformance-0008" });
  const signed = mintReceipt(r, curKey.privateKey, CUR_KID);
  const malformed = { ...signed, signature: "not-a-valid-base64url-signature!!" };
  vectors.push({
    id: "rcpt-neg-06-malformed-signature",
    category: "negative",
    description:
      "The signature field is not valid base64url / not a valid Ed25519 signature " +
      "length. Buffer.from(str, 'base64url') is lenient (drops invalid chars rather " +
      "than throwing), so this decodes to a wrong-length buffer and crypto.verify " +
      "deterministically returns false. MUST reject, never crash uncaught or VERIFY.",
    kind: "receipt",
    jwks: rotationJwks,
    receipt: malformed,
    expected: { verificationStatus: "TAMPERED", signatureValid: false, hashValid: false },
  });
}

// --- negative: algorithm mismatch (JWKS entry is not OKP/Ed25519) ----------
{
  const r = baseReceiptV1({ receiptId: "rcpt-conformance-0009" });
  const signed = mintReceipt(r, curKey.privateKey, CUR_KID);
  const wrongAlgJwks = {
    keys: [{ kty: "RSA", kid: CUR_KID, n: "not-a-real-modulus", e: "AQAB" }],
  };
  vectors.push({
    id: "rcpt-neg-07-algorithm-mismatch",
    category: "negative",
    description:
      "The JWKS entry under the matching kid is not an OKP/Ed25519 key (simulates a " +
      "foreign/unsupported key type reaching the resolver). MUST fail closed with an " +
      "explicit error, never silently coerce to a different algorithm.",
    kind: "receipt",
    jwks: wrongAlgJwks,
    receipt: signed,
    expected: { verificationStatus: "ERROR", errorIncludes: "Unexpected key type" },
  });
}

// --- chain: valid 2-receipt chain (v1 -> v2), correctly linked --------------
{
  const r1 = baseReceiptV1({ receiptId: "rcpt-chain-01-a", evidenceHash: "evh" + "a".repeat(61) });
  r1.proofChainHash = chainHash(GENESIS, r1.evidenceHash);
  const signed1 = mintReceipt(r1, oldKey.privateKey, OLD_KID);

  const r2 = {
    schemaVersion: "2",
    receiptId: "rcpt-chain-01-b",
    capabilityId: "governance.evaluate",
    action: "allow",
    decision: "ALLOW",
    risk: "LOW",
    mode: "enforced",
    policyVersion: "sha256:conformance",
    tenantId: "conformance-tenant",
    environment: "test",
    invocationHash: "inv" + "b".repeat(61),
    evidenceHash: "evh" + "b".repeat(61),
    proofChainHash: chainHash(signed1.proofChainHash, "evh" + "b".repeat(61)),
    timestamp: "2026-07-03T00:00:01.000Z",
  };
  const signed2 = mintReceipt(r2, curKey.privateKey, CUR_KID);

  vectors.push({
    id: "chain-pos-01-valid-two-receipt-chain",
    category: "positive",
    description:
      "A 2-receipt chain, schema v1 then v2, correctly linked via " +
      "proofChainHash = sha256(prev|evidenceHash), signed with rotated keys (old then " +
      "current). MUST report chainValid=true and both receipts VERIFIED.",
    kind: "chain",
    jwks: rotationJwks,
    receipts: [signed1, signed2],
    expected: { chainValid: true, brokenAt: null, allVerified: true },
  });
}

// --- chain: broken link (proofChainHash tampered on the 2nd receipt) --------
{
  const r1 = baseReceiptV1({ receiptId: "rcpt-chain-02-a", evidenceHash: "evh" + "c".repeat(61) });
  r1.proofChainHash = chainHash(GENESIS, r1.evidenceHash);
  const signed1 = mintReceipt(r1, curKey.privateKey, CUR_KID);

  const r2 = baseReceiptV1({ receiptId: "rcpt-chain-02-b", evidenceHash: "evh" + "d".repeat(61) });
  // Correctly-signed, but proofChainHash does NOT reference signed1 (broken link) —
  // the signature itself is still valid over these (wrong) canonical bytes.
  r2.proofChainHash = chainHash(GENESIS, r2.evidenceHash); // should reference signed1.proofChainHash, doesn't
  const signed2 = mintReceipt(r2, curKey.privateKey, CUR_KID);

  vectors.push({
    id: "chain-neg-01-broken-link",
    category: "negative",
    description:
      "The 2nd receipt's proofChainHash does not reference the 1st receipt's " +
      "proofChainHash (a spliced/reordered/omitted receipt). Both signatures are " +
      "individually VALID — this proves link-integrity detection is independent of " +
      "signature verification. MUST report chainValid=false with brokenAt the 2nd " +
      "receipt's id, while both receipts individually VERIFY.",
    kind: "chain",
    jwks: rotationJwks,
    receipts: [signed1, signed2],
    expected: { chainValid: false, brokenAt: "rcpt-chain-02-b", allVerified: true },
  });
}

// --- write vectors + index ----------------------------------------------------
const index = {
  schema_version: "strix_verifier_plugin_conformance_v1",
  description:
    "Gate-J golden-vector corpus for the vendored @strixgov/verifier copy bundled " +
    "in the strix-verifier Claude Code plugin. Every vector is checked against the " +
    "REAL vendored verifyReceipt/verifyReceiptChain — this proves the vendored copy " +
    "behaves correctly, it does not re-implement or second-guess its crypto.",
  vector_count: { positive: 0, negative: 0, total: 0 },
  vectors: [],
};

for (const v of vectors) {
  const file = `${v.id}.json`;
  fs.writeFileSync(path.join(OUT, file), JSON.stringify(v, null, 2) + "\n");
  index.vectors.push({
    id: v.id,
    category: v.category,
    kind: v.kind,
    description: v.description,
    relative_path: `vectors/${file}`,
  });
  index.vector_count[v.category]++;
  index.vector_count.total++;
}

fs.writeFileSync(path.join(__dirname, "index.json"), JSON.stringify(index, null, 2) + "\n");

console.log(`Wrote ${vectors.length} vectors to ${OUT} + index.json`);
