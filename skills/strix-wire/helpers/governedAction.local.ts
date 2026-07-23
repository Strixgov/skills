/**
 * Local Mode /strix-wire helper — offline, zero-account, zero-hosted-dependency.
 *
 * Copied by the `/strix-wire` skill's **Offline Mode** path into a
 * customer's own source tree — the sibling of `governedAction.ts` (Sandbox
 * Mode). Zero npm dependencies: uses Node's built-in `node:crypto`,
 * `node:fs`, and `node:path` modules only. Unlike the hosted
 * `governedAction.ts` (which is fetch-only and runs in any modern
 * browser/edge runtime), this file needs local filesystem access for the
 * key store and evidence chain, so it is **Node-only** (Node 16+, where
 * `crypto.sign`/`crypto.verify`/JWK OKP export landed).
 *
 * Local Mode's loop, spelled out completely differently from Sandbox
 * Mode's:
 *
 *   1. normalize   — capabilityId + action name + non-secret params.
 *   2. evaluate    — a small, deterministic, OFFLINE policy table decides
 *                     ALLOW / DENY / REQUIRE_APPROVAL. No network call, no
 *                     hosted kernel — a real but minimal, single-machine
 *                     policy, not the Strix kernel's multi-tenant
 *                     PolicyEngine.
 *   3. decide      — DENY throws before anything else happens.
 *                     REQUIRE_APPROVAL throws unless `approvalGranted` is
 *                     true (the caller's attestation that a human already
 *                     confirmed this exact run).
 *   4. authorize   — implicit in step 3: getting past it IS the
 *                     authorization.
 *   5. execute     — run the operation at most once.
 *   6. record      — build the canonical LOCAL_SIGNED_V1 payload, sign it
 *                     with a local Ed25519 key (generated on first run,
 *                     persisted under `.strix/keys/`, never printed or
 *                     logged), and append it to a hash-chained local file
 *                     under `.strix/evidence/`.
 *
 * Zero network calls anywhere in this file. Zero Strix account. The
 * receipt this mints is independently verifiable with `solo strix-wire
 * verify <path>` (from any solo-builder-core checkout/install) — this is a
 * genuine cross-language conformance pair with `governed_action_local.py`:
 * both produce byte-identical canonical payloads and either can verify the
 * other's output.
 *
 * **What this proves, precisely — read before wiring this into anything
 * consequential.** A LOCAL_SIGNED_V1 receipt is a `LOCAL_MACHINE_ASSERTION`:
 * it proves the holder of a specific local key produced a hash-chained,
 * tamper-evident record of one authorized, executed action. It does NOT
 * prove Strix-operated custody, centralized policy administration, or
 * protection against a machine owner who controls both this file and the
 * key it generates. See `docs/architecture/local-mode-strix-wire-v1.md` in
 * the solo-builder-core repo for the full non-claims list and threat model.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

export const SCHEMA_VERSION = "local-receipt-v1";
// Additive-versioned sibling: the v1 field set PLUS `relianceRef` — minted
// if and only if the action declared a Local Reliance requirement (Local
// Reliance Gate v1; see docs/architecture/local-reliance-gate-v1.md in the
// solo-builder-core repo). Actions without one keep minting v1 byte-identically.
export const SCHEMA_VERSION_V2 = "local-receipt-v2";
// Additive-versioned sibling of SCHEMA_VERSION_V2: the v2 field set PLUS
// `chainRef` — minted if and only if the action ran through a ChainSession
// (Chained Governed Autonomy v1; see
// docs/architecture/chained-governed-autonomy-v1.md in solo-builder-core).
// Version selection is priority-ordered by presence, not field count: any
// populated chainRef -> v3 (even with no relianceRef at all — a
// non-attestation-gated chain's root step has a chainRef but nothing to
// require yet); else any populated relianceRef -> v2; else v1.
export const SCHEMA_VERSION_V3 = "local-receipt-v3";
// Additive-versioned SIBLING of SCHEMA_VERSION_V3 (Chained Governed
// Autonomy v2; see docs/architecture/chained-governed-autonomy-v2.md in
// solo-builder-core): the v3 field set with `chainRef` REPLACED by
// `dagRef` — minted if and only if the action ran through a DagSession.
// v4 is NOT built on top of v3: a record is v3 XOR v4, never both.
// Version selection is priority-ordered by presence: any populated
// dagRef -> v4; else any populated chainRef -> v3; else any populated
// relianceRef -> v2; else v1.
export const SCHEMA_VERSION_V4 = "local-receipt-v4";
export const RECORD_MODE = "LOCAL_SIGNED_V1";
export const DEFAULT_STATE_DIR = ".strix";
export const RELIANCE_POLICY_SCHEMA_VERSION = "local-reliance-policy-v1";

// Attestation-Gated Execution v1 — a second, independent artifact family the
// SAME reliance gate can require (see docs/architecture/
// attestation-gated-execution-v1.md in solo-builder-core). This helper only
// VERIFIES presented attestations as part of reliance evaluation; issuing
// one is the local issuer's job (e.g. `solo strix-wire attest issue`), not
// this consumer-side orchestration helper.
export const ATTESTATION_SCHEMA_VERSION = "local-agent-attestation-v1";
export const ATTESTATION_RECORD_MODE = "LOCAL_AGENT_ATTESTATION_V1";

// ──────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────

export class StrixLocalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StrixLocalError";
  }
}
export class StrixLocalDenied extends StrixLocalError {
  constructor(message: string) { super(message); this.name = "StrixLocalDenied"; }
}
export class StrixLocalApprovalRequired extends StrixLocalError {
  constructor(message: string) { super(message); this.name = "StrixLocalApprovalRequired"; }
}
export class StrixLocalKeyError extends StrixLocalError {
  constructor(message: string) { super(message); this.name = "StrixLocalKeyError"; }
}
export class StrixLocalReceiptPersistenceError extends StrixLocalError {
  constructor(message: string) { super(message); this.name = "StrixLocalReceiptPersistenceError"; }
}
export class StrixLocalRelianceDenied extends StrixLocalError {
  /** Full layered reliance result — surface WHICH requirement failed and
   * why; never convert this into execution success. */
  reliance: RelianceResult;
  constructor(message: string, reliance: RelianceResult) {
    super(message);
    this.name = "StrixLocalRelianceDenied";
    this.reliance = reliance;
  }
}
/** Chained Governed Autonomy v1 — a caller supplied a chainStep claiming a
 * non-root predecessor but no independently-verified, satisfied
 * "chain-predecessor" reliance requirement backs that claim. The operation
 * was NOT run and no receipt was minted. Reachable only by calling
 * governedActionLocal directly with a hand-built LocalChainStep, bypassing
 * ChainSession (which always constructs a matching requirement for a
 * non-root step). */
export class StrixLocalChainPredecessorUnverified extends StrixLocalError {
  constructor(message: string) {
    super(message);
    this.name = "StrixLocalChainPredecessorUnverified";
  }
}
/** Chained Governed Autonomy v2 — a caller supplied a dagStep declaring
 * one or more parents, but at least one declared parent index has no
 * independently-verified, satisfied "dag-parent-{i}" reliance requirement
 * backing it (or the declared parent set contains a duplicate evidence
 * id). The operation was NOT run and no receipt was minted. Reachable
 * only by calling governedActionLocal directly with a hand-built
 * LocalDagStep, bypassing DagSession (which always constructs a matching
 * requirement per declared parent, and rejects duplicates at construction
 * time). */
export class StrixLocalDagParentUnverified extends StrixLocalError {
  constructor(message: string) {
    super(message);
    this.name = "StrixLocalDagParentUnverified";
  }
}

// ──────────────────────────────────────────────────────────────────────
// Canonical bytes — byte-identical to governed_action_local.py's _canonicalize
// ──────────────────────────────────────────────────────────────────────

function canonicalize(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new StrixLocalError("NaN/Infinity not allowed in canonical bytes");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
  }
  throw new StrixLocalError(`unsupported value in canonical bytes: ${typeof value}`);
}

function sha256Hex(s: string): string {
  return crypto.createHash("sha256").update(Buffer.from(s, "utf-8")).digest("hex");
}

function hashCanonical(value: unknown): string {
  return sha256Hex(canonicalize(value));
}

function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function newEvidenceId(): string {
  return "local_ev_" + crypto.randomBytes(16).toString("hex");
}

// ──────────────────────────────────────────────────────────────────────
// Raw Ed25519 key material <-> Node KeyObject (via JWK OKP, no ASN.1/DER)
// ──────────────────────────────────────────────────────────────────────

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

// RFC 8410 fixed ASN.1 prefix for an Ed25519 PKCS8 private key: a 32-byte
// raw seed is the ENTIRE private key material, so this 16-byte prefix is a
// constant, never key-dependent. Using PKCS8/DER (instead of JWK) to build
// the KeyObject means Node only ever needs the raw seed — it derives the
// public component itself, so this path never depends on (and can never be
// fooled by) a caller-supplied public key.
const ED25519_PKCS8_DER_PREFIX_HEX = "302e020100300506032b657004220420";

function privateKeyObjectFromRawSeed(privHex: string): crypto.KeyObject {
  const der = Buffer.from(ED25519_PKCS8_DER_PREFIX_HEX + privHex, "hex");
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Derive the raw public key hex straight from a private KeyObject —
 * Node computes the public component internally; nothing here trusts a
 * caller-supplied public key. */
function publicKeyHexFromPrivateKeyObject(priv: crypto.KeyObject): string {
  const pubJwk = crypto.createPublicKey(priv).export({ format: "jwk" }) as { x?: string };
  if (!pubJwk.x) throw new StrixLocalKeyError("failed to derive the Ed25519 public key from private key material");
  return Buffer.from(pubJwk.x, "base64url").toString("hex");
}

function publicKeyFromRaw(pubHex: string): crypto.KeyObject {
  return crypto.createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: b64url(Buffer.from(pubHex, "hex")) },
    format: "jwk",
  });
}

function generateRawKeyPair(): { privHex: string; pubHex: string } {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const privJwk = privateKey.export({ format: "jwk" }) as { d?: string };
  if (!privJwk.d) {
    throw new StrixLocalKeyError("failed to export raw Ed25519 private key material from the platform crypto provider");
  }
  const privHex = Buffer.from(privJwk.d, "base64url").toString("hex");
  const pubHex = publicKeyHexFromPrivateKeyObject(privateKeyObjectFromRawSeed(privHex));
  return { privHex, pubHex };
}

function signRaw(privHex: string, data: Buffer): string {
  return crypto.sign(null, data, privateKeyObjectFromRawSeed(privHex)).toString("hex");
}

export function verifyRaw(pubHex: string, data: Buffer, sigHex: string): boolean {
  try {
    return crypto.verify(null, data, publicKeyFromRaw(pubHex), Buffer.from(sigHex, "hex"));
  } catch {
    return false;
  }
}

// ──────────────────────────────────────────────────────────────────────
// Local key manager
// ──────────────────────────────────────────────────────────────────────

export interface LocalSigningKey {
  kid: string;
  privateKeyHex: string;
  publicKeyHex: string;
  publicKeyFingerprint: string;
  createdAt: string;
}

function fingerprint(pubHex: string): string {
  return crypto.createHash("sha256").update(Buffer.from(pubHex, "hex")).digest("hex");
}

function kidFor(pubHex: string): string {
  return `local-${fingerprint(pubHex).slice(0, 16)}`;
}

interface KeyRegistry {
  currentKid: string | null;
  keys: Record<string, { publicKeyHex: string; publicKeyFingerprint: string; createdAt: string; status: string; algorithm: string }>;
}

function registryPath(stateDir: string): string {
  return path.join(stateDir, "keys", "registry.json");
}

export function resolvePublicKey(stateDir: string, kid: string): Buffer | null {
  const regPath = registryPath(stateDir);
  if (!fs.existsSync(regPath)) return null;
  let data: KeyRegistry;
  try {
    data = JSON.parse(fs.readFileSync(regPath, "utf-8"));
  } catch {
    return null;
  }
  const meta = data.keys?.[kid];
  if (!meta?.publicKeyHex) return null;
  try {
    return Buffer.from(meta.publicKeyHex, "hex");
  } catch {
    return null;
  }
}

export function generateOrLoadKey(stateDir: string): LocalSigningKey {
  const keysDir = path.join(stateDir, "keys");
  const regPath = registryPath(stateDir);

  if (fs.existsSync(regPath)) {
    let data: KeyRegistry;
    try {
      data = JSON.parse(fs.readFileSync(regPath, "utf-8"));
    } catch (exc) {
      throw new StrixLocalKeyError(`corrupt key registry at ${regPath}: ${exc}`);
    }
    const kid = data.currentKid;
    if (kid) {
      const meta = data.keys?.[kid];
      if (!meta) throw new StrixLocalKeyError(`registry names current kid ${kid} but has no metadata for it`);
      const keyPath = path.join(keysDir, `${kid}.key`);
      if (!fs.existsSync(keyPath)) {
        throw new StrixLocalKeyError(
          `private key file missing for kid ${kid} at ${keyPath} — it was deleted or moved. ` +
            "Historical receipts under this kid still verify from the registry's public key; " +
            "remove 'currentKid' from registry.json to mint a fresh signing key.",
        );
      }
      const raw = fs.readFileSync(keyPath, "utf-8").trim();
      // Re-derive the public key straight from the private key bytes — a
      // real mismatch check (not just "did it parse"). Any malformed hex or
      // wrong-length key throws here, which we surface as StrixLocalKeyError.
      let derivedPubHex: string;
      try {
        derivedPubHex = publicKeyHexFromPrivateKeyObject(privateKeyObjectFromRawSeed(raw));
      } catch (exc) {
        throw new StrixLocalKeyError(`private key file for kid ${kid} is corrupt or invalid: ${exc}`);
      }
      if (derivedPubHex !== meta.publicKeyHex) {
        throw new StrixLocalKeyError(
          `private key file for kid ${kid} does not match its registry public key — possible tamper. Refusing to sign.`,
        );
      }
      return {
        kid,
        privateKeyHex: raw,
        publicKeyHex: meta.publicKeyHex,
        publicKeyFingerprint: fingerprint(meta.publicKeyHex),
        createdAt: meta.createdAt || "",
      };
    }
  }

  // First run: generate.
  const { privHex, pubHex } = generateRawKeyPair();
  const kid = kidFor(pubHex);
  const createdAt = isoNow();

  fs.mkdirSync(keysDir, { recursive: true });
  const keyPath = path.join(keysDir, `${kid}.key`);
  fs.writeFileSync(keyPath, privHex, { encoding: "utf-8", mode: 0o600 });
  try {
    fs.chmodSync(keyPath, 0o600);
  } catch {
    // Best-effort — some filesystems (notably certain Windows setups) don't
    // support POSIX chmod bits. Treat the file as sensitive regardless.
  }

  let data: KeyRegistry = {
    currentKid: kid,
    keys: { [kid]: { publicKeyHex: pubHex, publicKeyFingerprint: fingerprint(pubHex), createdAt, status: "active", algorithm: "ed25519" } },
  };
  if (fs.existsSync(regPath)) {
    try {
      const existing: KeyRegistry = JSON.parse(fs.readFileSync(regPath, "utf-8"));
      existing.keys = { ...existing.keys, ...data.keys };
      existing.currentKid = kid;
      data = existing;
    } catch {
      // corrupt existing registry — overwrite with a fresh one rather than crash
    }
  }
  const tmpPath = `${regPath}.tmp`;
  // Plain JSON.stringify — a replacer array filters property names at
  // EVERY depth, which would have silently dropped every nested field
  // (publicKeyHex, createdAt, ...) since only the top-level keys were
  // listed. Key ordering here is cosmetic only; it plays no part in the
  // canonical signing contract (see `canonicalize()` above).
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2) + "\n", "utf-8");
  fs.renameSync(tmpPath, regPath);

  const gitignorePath = path.join(keysDir, ".gitignore");
  if (!fs.existsSync(gitignorePath)) fs.writeFileSync(gitignorePath, "*.key\n", "utf-8");

  return { kid, privateKeyHex: privHex, publicKeyHex: pubHex, publicKeyFingerprint: fingerprint(pubHex), createdAt };
}

// ──────────────────────────────────────────────────────────────────────
// Local policy — deterministic, offline (mirrors governed_action_local.py)
// ──────────────────────────────────────────────────────────────────────

export const DEFAULT_POLICY_RULES: Record<string, [string, number | null]> = {
  "payment.charge": ["HIGH", null],
  "payment.refund": ["HIGH", 500.0],
  "database.delete": ["HIGH", null],
  "database.update": ["HIGH", null],
  "database.create": ["MEDIUM", null],
  "storage.delete": ["HIGH", null],
  "storage.write": ["MEDIUM", null],
  "email.send": ["MEDIUM", null],
  "sms.send": ["MEDIUM", null],
  "filesystem.delete": ["HIGH", null],
  "database.migrate": ["CRITICAL", null],
  "infra.apply": ["CRITICAL", null],
  "infra.destroy": ["CRITICAL", null],
  "iam.grant": ["CRITICAL", null],
  "iam.revoke": ["CRITICAL", null],
  "flag.flip": ["MEDIUM", null],
  "data.export": ["HIGH", null],
  "message.publish": ["MEDIUM", null],
  "ai.tool_use": ["HIGH", null],
  "ai.agent_run": ["HIGH", null],
};

const AUTO_ALLOW_RISK = new Set(["LOW"]);

export function policyRef(rules: Record<string, [string, number | null]> = DEFAULT_POLICY_RULES, version = "local-policy-v1"): { version: string; hash: string } {
  const ruleView: Record<string, { risk: string; approvalThreshold: number | null }> = {};
  for (const cap of Object.keys(rules).sort()) {
    const [risk, threshold] = rules[cap];
    ruleView[cap] = { risk, approvalThreshold: threshold };
  }
  return { version, hash: hashCanonical({ rules: ruleView }) };
}

export function evaluatePolicy(
  capabilityId: string,
  params: Record<string, unknown>,
  rules: Record<string, [string, number | null]> = DEFAULT_POLICY_RULES,
): [string, string] {
  const rule = rules[capabilityId];
  if (!rule) return ["REQUIRE_APPROVAL", `capability ${capabilityId} has no local policy rule — approval required`];
  const [risk, threshold] = rule;
  if (AUTO_ALLOW_RISK.has(risk)) return ["ALLOW", `${risk} risk — auto-allowed under local policy`];
  if (threshold !== null) {
    const amount = params.amount;
    if (typeof amount === "number" && amount >= threshold) {
      return ["REQUIRE_APPROVAL", `amount ${amount} >= approval threshold ${threshold} for ${capabilityId}`];
    }
  }
  return ["REQUIRE_APPROVAL", `${risk} risk action — local confirmation required before execution`];
}

// ──────────────────────────────────────────────────────────────────────
// Local Reliance Gate v1 — verified prior proof as an execution
// precondition (mirrors solo_builder.strix_wire_local_reliance and
// governed_action_local.py; byte-identical policyHash, statuses, reason
// codes, and detail strings — cross-language conformance depends on it)
// ──────────────────────────────────────────────────────────────────────

const ALLOWED_DECISIONS = ["ALLOW", "REQUIRE_APPROVAL_GRANTED"] as const;
const ALLOWED_EXECUTION_STATUSES = ["SUCCEEDED", "FAILED"] as const;
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const RELIANCE_DETAILS: Record<string, string> = {
  RECORD_MODE_DISALLOWED: "the receipt recordMode is not an allowed receipt type for this requirement",
  UNSUPPORTED_SCHEMA_VERSION: "the receipt schemaVersion is not supported by this verifier",
  EVIDENCE_HASH_INVALID: "evidenceHash does not match the recomputed canonical hash",
  CHAIN_INVALID: "proofChainHash does not match the recomputed value",
  SIGNATURE_MISSING: "no signature present on the receipt",
  SIGNATURE_INVALID: "signature does not verify against the resolved public key",
  KEY_UNRESOLVED: "signingKeyId does not resolve in the presented key registry",
  CAPABILITY_MISMATCH: "receipt capabilityId does not match the required capability",
  DECISION_MISMATCH: "receipt decision is not an accepted decision for this requirement",
  EXECUTION_STATUS_MISMATCH: "receipt executionStatus does not match the required execution status",
  WORKSPACE_MISMATCH: "receipt workspaceFingerprint does not match the protected action's workspace",
  SIGNING_KEY_MISMATCH: "receipt signingKeyId is not a key in this workspace's local registry",
  PARAMS_HASH_MISMATCH: "receipt paramsHash does not match the required subject binding",
  TIMESTAMP_UNPARSEABLE: "receipt createdAt is not a strict RFC3339 Z-suffixed timestamp",
  RECEIPT_FUTURE_DATED: "receipt createdAt is in the future",
};

// Attestation-Gated Execution v1 reason codes + details — identical strings
// to solo_builder.strix_wire_local_reliance's _ATTESTATION_DETAILS and
// governed_action_local.py's _ATTESTATION_DETAILS. Public contract;
// additive only, never rename/reuse.
const ATTESTATION_DETAILS: Record<string, string> = {
  ATTESTATION_MALFORMED: "the presented attestation is not a well-formed JSON object with a payload",
  ATTESTATION_SCHEMA_UNSUPPORTED: "the attestation recordMode/schemaVersion is not supported by this verifier",
  ATTESTATION_HASH_MISMATCH: "attestationHash does not match the recomputed canonical hash",
  ATTESTATION_SIGNATURE_INVALID: "attestation signature is missing or does not verify against the resolved issuer public key",
  ATTESTATION_KEY_UNKNOWN: "signingKeyId does not resolve in the presented issuer key registry",
  ATTESTATION_ISSUER_NOT_ALLOWED: "attestation issuerId is not on this requirement's permitted-issuer allow-list",
  ATTESTATION_AGENT_MISMATCH: "attestation agentId does not match the required requesting agent identity",
  ATTESTATION_CLASS_MISMATCH: "attestation agentClass does not match the required class",
  ATTESTATION_WORKSPACE_MISMATCH: "attestation workspaceFingerprint does not match the protected action's workspace",
  ATTESTATION_SCOPE_MISMATCH: "attestation capabilityScopes does not include the protected capability",
  ATTESTATION_NOT_YET_VALID: "attestation issuedAt is in the future",
  ATTESTATION_EXPIRED: "attestation has expired",
  ATTESTATION_REVOKED: "attestation has been revoked",
  ATTESTATION_UNVERIFIABLE: "attestation could not be verified for a reason this gate could not classify further",
};

/** Exact match, or a "<prefix>.*" wildcard matching any capability strictly
 * under that prefix. Mirrors solo_builder.strix_wire_local_attestation.scope_matches. */
function scopeMatches(pattern: string, capabilityId: string): boolean {
  if (pattern === capabilityId) return true;
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -2);
    return capabilityId.startsWith(prefix + ".");
  }
  return false;
}

/** Offline lookup for the LOCAL attestation issuer's key registry, rooted
 * at `<stateDir>/attestation/issuer/keys/registry.json` — deliberately
 * separate from the workspace's own governed-action signing key registry
 * (the issuer is a distinct local authority). */
function resolveAttestationIssuerKey(stateDir: string, kid: string): Buffer | null {
  return resolvePublicKey(path.join(stateDir, "attestation", "issuer"), kid);
}

/** Mirrors LocalAttestationRevocationList. A missing revocation list file
 * means nothing is revoked; a corrupt one is a loud fault. */
function isAttestationRevoked(stateDir: string, attestationId: string): boolean {
  const revPath = path.join(stateDir, "attestation", "revoked.json");
  if (!fs.existsSync(revPath)) return false;
  let data: unknown;
  try {
    data = JSON.parse(fs.readFileSync(revPath, "utf-8"));
  } catch (exc) {
    throw new StrixLocalError(`corrupt attestation revocation list at ${revPath}: ${(exc as Error).message}`);
  }
  const revoked = data && typeof data === "object" ? (data as Record<string, unknown>).revoked : undefined;
  if (!revoked || typeof revoked !== "object" || Array.isArray(revoked)) {
    throw new StrixLocalError(`malformed attestation revocation list at ${revPath}: missing 'revoked'`);
  }
  return attestationId in (revoked as Record<string, unknown>);
}

/** Mirror of solo_builder.strix_wire_local_attestation.verify_attestation_crypto.
 * Recomputes everything, trusts nothing stored. Never throws for bad input. */
function verifyLocalAttestationCrypto(
  record: unknown,
  stateDir: string,
): {
  hashValid: boolean;
  signaturePresent: boolean;
  signatureValid: boolean | null;
  keyResolved: boolean;
  recordMode: string | null;
  status: string;
  cryptoCode: string | null;
} {
  const out = {
    hashValid: false,
    signaturePresent: false,
    signatureValid: null as boolean | null,
    keyResolved: false,
    recordMode: null as string | null,
    status: "UNVERIFIABLE",
    cryptoCode: null as string | null,
  };
  const rec = record as Record<string, unknown> | null;
  const payload = rec && typeof rec === "object" ? (rec.payload as Record<string, unknown> | undefined) : undefined;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    out.cryptoCode = "ATTESTATION_MALFORMED";
    return out;
  }
  const recordMode = payload.recordMode;
  out.recordMode = typeof recordMode === "string" ? recordMode : null;
  if (recordMode !== ATTESTATION_RECORD_MODE || payload.schemaVersion !== ATTESTATION_SCHEMA_VERSION) {
    out.cryptoCode = "ATTESTATION_SCHEMA_UNSUPPORTED";
    return out;
  }

  const core: Record<string, unknown> = {};
  for (const k of Object.keys(payload)) {
    if (k !== "attestationHash") core[k] = payload[k];
  }
  out.hashValid = hashCanonical(core) === payload.attestationHash;

  const signatureHex = rec!.signature;
  out.signaturePresent = typeof signatureHex === "string" && signatureHex.length > 0;

  const kid = payload.signingKeyId;
  const pub = typeof kid === "string" ? resolveAttestationIssuerKey(stateDir, kid) : null;
  out.keyResolved = pub !== null;
  if (out.signaturePresent && pub !== null) {
    out.signatureValid = verifyRaw(pub.toString("hex"), Buffer.from(canonicalize(payload), "utf-8"), signatureHex as string);
  }

  if (!out.hashValid) {
    out.status = "INVALID";
    out.cryptoCode = "ATTESTATION_HASH_MISMATCH";
  } else if (!out.signaturePresent) {
    out.status = "INVALID";
    out.cryptoCode = "ATTESTATION_SIGNATURE_INVALID";
  } else if (!out.keyResolved) {
    out.status = "UNVERIFIABLE";
    out.cryptoCode = "ATTESTATION_KEY_UNKNOWN";
  } else if (!out.signatureValid) {
    out.status = "INVALID";
    out.cryptoCode = "ATTESTATION_SIGNATURE_INVALID";
  } else {
    out.status = "VERIFIED";
    out.cryptoCode = null;
  }
  return out;
}

export interface RelianceRequirement {
  capabilityId?: string;
  /** Locator only — resolved against workspaceRoot; never hashed into policyHash. */
  receiptPath: string;
  requirementId?: string;
  /** RECORD_MODE (default) or ATTESTATION_RECORD_MODE — dispatches which
   * artifact family this requirement is evaluated against. */
  receiptType?: string;
  decisions?: string[];
  executionStatus?: string;
  maxAgeSeconds?: number | null;
  sameWorkspace?: boolean;
  sameSigningKey?: boolean;
  allowUnresolvedKey?: boolean;
  paramsHash?: string | null;
  // --- Attestation-only fields (receiptType === ATTESTATION_RECORD_MODE) ---
  agentIdFromRequest?: boolean;
  expectedAgentId?: string | null;
  requiredClass?: string | null;
  permittedIssuers?: string[];
  capabilityScopeMustIncludeSubject?: boolean;
}

interface NormalizedRequirement {
  capabilityId: string;
  receiptPath: string;
  requirementId: string;
  receiptType: string;
  decisions: string[];
  executionStatus: string;
  maxAgeSeconds: number | null;
  sameWorkspace: boolean;
  sameSigningKey: boolean;
  allowUnresolvedKey: boolean;
  paramsHash: string | null;
  agentIdFromRequest: boolean;
  expectedAgentId: string | null;
  requiredClass: string | null;
  permittedIssuers: string[];
  capabilityScopeMustIncludeSubject: boolean;
}

export interface RelianceRequirementResult {
  requirementId: string;
  evidenceId: string | null;
  evidenceHash: string | null;
  recordMode: string | null;
  hashValid: boolean;
  chainValid: boolean;
  signaturePresent: boolean;
  signatureValid: boolean | null;
  keyResolved: boolean;
  capabilityMatched: boolean;
  workspaceMatched: boolean;
  decisionMatched: boolean;
  executionStatusMatched: boolean;
  signingKeyMatched: boolean;
  paramsHashMatched: boolean;
  freshnessValid: boolean;
  status: string;
  satisfied: boolean;
  reason: string;
  // --- Attestation-only outcome fields (present only when artifactType is
  // set — always omitted for LOCAL_SIGNED_V1 results, so existing output
  // shapes are byte-identical to before Attestation-Gated Execution v1) ---
  artifactType?: string;
  attestationAgentId?: string | null;
  attestationAgentClass?: string | null;
  attestationIssuerId?: string | null;
  scopeMatched?: boolean | null;
}

export interface RelianceResult {
  reliancePolicyId: string;
  reliancePolicyVersion: number;
  policyHash: string;
  verificationStatus: string;
  relianceVerdict: string;
  requirements: RelianceRequirementResult[];
  reason: string;
  checkedAt: string;
}

function normalizeRequirements(requirements: RelianceRequirement[]): NormalizedRequirement[] {
  if (!requirements.length) {
    throw new StrixLocalError("reliance requires at least one requirement — an empty list is not a gate");
  }
  const seen = new Set<string>();
  return requirements.map((req, i) => {
    const receiptType = req.receiptType ?? RECORD_MODE;
    if (receiptType !== RECORD_MODE && receiptType !== ATTESTATION_RECORD_MODE) {
      throw new StrixLocalError(
        `unsupported receiptType ${receiptType} — Local Reliance Gate v1 accepts only ${RECORD_MODE} or ${ATTESTATION_RECORD_MODE}`,
      );
    }
    const isAttestation = receiptType === ATTESTATION_RECORD_MODE;
    if (!isAttestation && (!req.capabilityId || !req.capabilityId.trim())) {
      throw new StrixLocalError("reliance requirement capabilityId must be a non-empty string");
    }
    const decisions = req.decisions ?? [...ALLOWED_DECISIONS];
    if (!decisions.length || decisions.some((d) => !(ALLOWED_DECISIONS as readonly string[]).includes(d))) {
      throw new StrixLocalError(`reliance decisions must be a non-empty subset of ${ALLOWED_DECISIONS.join(", ")}`);
    }
    const executionStatus = req.executionStatus ?? "SUCCEEDED";
    if (!(ALLOWED_EXECUTION_STATUSES as readonly string[]).includes(executionStatus)) {
      throw new StrixLocalError(`reliance executionStatus must be one of ${ALLOWED_EXECUTION_STATUSES.join(", ")}`);
    }
    const maxAge = req.maxAgeSeconds ?? null;
    if (maxAge !== null && (!Number.isInteger(maxAge) || maxAge <= 0)) {
      throw new StrixLocalError("reliance maxAgeSeconds must be a positive integer when set");
    }
    const paramsHash = req.paramsHash ?? null;
    if (paramsHash !== null && !/^[0-9a-f]{64}$/.test(paramsHash)) {
      throw new StrixLocalError("reliance paramsHash must be a 64-char lowercase sha256 hex string");
    }
    const sameSigningKey = req.sameSigningKey ?? false;
    const agentIdFromRequest = req.agentIdFromRequest ?? false;
    const expectedAgentId = req.expectedAgentId ?? null;
    const requiredClass = req.requiredClass ?? null;
    const permittedIssuers = req.permittedIssuers ?? [];
    const capabilityScopeMustIncludeSubject = req.capabilityScopeMustIncludeSubject ?? false;
    const attestationFieldsSet =
      agentIdFromRequest || expectedAgentId !== null || requiredClass !== null || permittedIssuers.length > 0 || capabilityScopeMustIncludeSubject;
    if (!isAttestation) {
      if (attestationFieldsSet) {
        throw new StrixLocalError(
          "agentIdFromRequest/expectedAgentId/requiredClass/permittedIssuers/capabilityScopeMustIncludeSubject " +
            `are attestation-only fields — set receiptType to ${ATTESTATION_RECORD_MODE} to use them`,
        );
      }
    } else {
      if (sameSigningKey) throw new StrixLocalError("sameSigningKey has no meaning on an attestation requirement");
      if (paramsHash !== null) throw new StrixLocalError("paramsHash has no meaning on an attestation requirement");
      if (agentIdFromRequest && expectedAgentId !== null) {
        throw new StrixLocalError("agentIdFromRequest and expectedAgentId are mutually exclusive");
      }
      if (!permittedIssuers.length) {
        throw new StrixLocalError("an attestation requirement must declare at least one permittedIssuers entry");
      }
    }
    const requirementId = req.requirementId || `req-${i + 1}`;
    if (seen.has(requirementId)) throw new StrixLocalError(`duplicate reliance requirementId ${requirementId}`);
    seen.add(requirementId);
    return {
      capabilityId: req.capabilityId ?? "",
      receiptPath: req.receiptPath,
      requirementId,
      receiptType,
      decisions,
      executionStatus,
      maxAgeSeconds: maxAge,
      sameWorkspace: req.sameWorkspace ?? true,
      sameSigningKey,
      allowUnresolvedKey: req.allowUnresolvedKey ?? false,
      paramsHash,
      agentIdFromRequest,
      expectedAgentId,
      requiredClass,
      permittedIssuers,
      capabilityScopeMustIncludeSubject,
    };
  });
}

function requirementCanonicalDict(r: NormalizedRequirement): Record<string, unknown> {
  if (r.receiptType === ATTESTATION_RECORD_MODE) {
    return {
      requirementId: r.requirementId,
      artifactType: r.receiptType,
      agentIdFromRequest: r.agentIdFromRequest,
      expectedAgentId: r.expectedAgentId,
      requiredClass: r.requiredClass,
      permittedIssuers: [...r.permittedIssuers].sort(),
      capabilityScopeMustIncludeSubject: r.capabilityScopeMustIncludeSubject,
      sameWorkspace: r.sameWorkspace,
      maxAgeSeconds: r.maxAgeSeconds,
      allowUnresolvedKey: r.allowUnresolvedKey,
    };
  }
  return {
    requirementId: r.requirementId,
    capabilityId: r.capabilityId,
    receiptType: r.receiptType,
    decisions: [...r.decisions].sort(),
    executionStatus: r.executionStatus,
    maxAgeSeconds: r.maxAgeSeconds,
    sameWorkspace: r.sameWorkspace,
    sameSigningKey: r.sameSigningKey,
    allowUnresolvedKey: r.allowUnresolvedKey,
    paramsHash: r.paramsHash,
  };
}

function reliancePolicyHash(capabilityId: string, requirements: NormalizedRequirement[]): string {
  return hashCanonical({
    schemaVersion: RELIANCE_POLICY_SCHEMA_VERSION,
    relianceId: `inline:${capabilityId}`,
    version: 1,
    subject: { capabilityId },
    onFailure: "DENY",
    threshold: null,
    requires: requirements.map(requirementCanonicalDict),
  });
}

function registryKids(stateDir: string): string[] | null {
  const regPath = registryPath(stateDir);
  if (!fs.existsSync(regPath)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(regPath, "utf-8"));
    return data && typeof data.keys === "object" && data.keys !== null ? Object.keys(data.keys) : null;
  } catch {
    return null;
  }
}

/** Minimal mirror of solo-builder-core's `verify_record`: recompute
 * everything, trust nothing stored. Never throws for bad input. */
/** Chained Governed Autonomy v1 structural shape check: chainRef must be
 * an object with chainId/stepIndex, and stepIndex 0 <-> no predecessor
 * claim (both directions), mirroring the reference engine's verify_record. */
function chainRefShapeValid(chainRef: unknown): boolean {
  if (typeof chainRef !== "object" || chainRef === null || Array.isArray(chainRef)) return false;
  const ref = chainRef as Record<string, unknown>;
  if (typeof ref.chainId !== "string" || typeof ref.stepIndex !== "number" || !Number.isInteger(ref.stepIndex)) {
    return false;
  }
  const prevId = ref.previousStepEvidenceId;
  const prevHash = ref.previousStepEvidenceHash;
  if (ref.stepIndex === 0) return prevId === null && prevHash === null;
  return prevId !== null && prevId !== undefined && prevHash !== null && prevHash !== undefined;
}

/** Chained Governed Autonomy v2 structural shape check: dagRef must be an
 * object with dagId/stepIndex and a parentEvidenceRefs array of
 * {evidenceId, evidenceHash} objects with no duplicate evidenceId —
 * mirroring the reference engine's verify_record. Unlike chainRef,
 * stepIndex === 0 does NOT imply an empty parentEvidenceRefs (a DAG can
 * have multiple independent source nodes at different stepIndex
 * values). */
function dagRefShapeValid(dagRef: unknown): boolean {
  if (typeof dagRef !== "object" || dagRef === null || Array.isArray(dagRef)) return false;
  const ref = dagRef as Record<string, unknown>;
  if (typeof ref.dagId !== "string" || typeof ref.stepIndex !== "number" || !Number.isInteger(ref.stepIndex)) {
    return false;
  }
  const parentRefs = ref.parentEvidenceRefs;
  if (!Array.isArray(parentRefs)) return false;
  const ids: unknown[] = [];
  for (const r of parentRefs) {
    if (typeof r !== "object" || r === null || Array.isArray(r)) return false;
    const rr = r as Record<string, unknown>;
    if (typeof rr.evidenceId !== "string" || typeof rr.evidenceHash !== "string") return false;
    ids.push(rr.evidenceId);
  }
  return new Set(ids).size === ids.length;
}

function verifyLocalRecordForReliance(
  record: unknown,
  stateDir: string,
): {
  hashValid: boolean;
  chainValid: boolean;
  signaturePresent: boolean;
  signatureValid: boolean | null;
  keyResolved: boolean;
  status: string;
  cryptoCode: string | null;
} {
  const out = {
    hashValid: false,
    chainValid: false,
    signaturePresent: false,
    signatureValid: null as boolean | null,
    keyResolved: false,
    status: "UNVERIFIABLE",
    cryptoCode: "UNSUPPORTED_SCHEMA_VERSION" as string | null,
  };
  const rec = record as Record<string, unknown> | null;
  const payload = rec && typeof rec === "object" ? (rec.payload as Record<string, unknown> | undefined) : undefined;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    out.cryptoCode = "RECEIPT_MALFORMED";
    return out;
  }
  if (payload.recordMode !== RECORD_MODE) {
    out.cryptoCode = "RECORD_MODE_DISALLOWED";
    return out;
  }
  const schemaVersion = payload.schemaVersion;
  if (
    schemaVersion !== SCHEMA_VERSION &&
    schemaVersion !== SCHEMA_VERSION_V2 &&
    schemaVersion !== SCHEMA_VERSION_V3 &&
    schemaVersion !== SCHEMA_VERSION_V4
  ) {
    out.cryptoCode = "UNSUPPORTED_SCHEMA_VERSION";
    return out;
  }

  const core: Record<string, unknown> = {};
  for (const k of Object.keys(payload)) {
    if (k !== "evidenceHash" && k !== "proofChainHash") core[k] = payload[k];
  }
  out.hashValid = hashCanonical(core) === payload.evidenceHash;
  out.chainValid =
    hashCanonical({ evidenceHash: payload.evidenceHash, prevHash: payload.prevHash ?? null, chainSeq: payload.chainSeq }) ===
    payload.proofChainHash;
  const signatureHex = rec!.signature;
  out.signaturePresent = typeof signatureHex === "string" && signatureHex.length > 0;

  const kid = payload.signingKeyId;
  const pub = typeof kid === "string" ? resolvePublicKey(stateDir, kid) : null;
  out.keyResolved = pub !== null;
  if (out.signaturePresent && pub !== null) {
    out.signatureValid = verifyRaw(pub.toString("hex"), Buffer.from(canonicalize(payload), "utf-8"), signatureHex as string);
  }

  // Version/field cross-checks (a v1 smuggling relianceRef, a v2 without
  // one, a non-v3 smuggling chainRef, a v3 without a structured one, a
  // non-v4 smuggling dagRef, or a v4 without a structured one, is
  // structurally INVALID for its declared version).
  const relianceRef = payload.relianceRef;
  const structuralInvalid =
    (schemaVersion === SCHEMA_VERSION && "relianceRef" in payload) ||
    (schemaVersion === SCHEMA_VERSION_V2 && (typeof relianceRef !== "object" || relianceRef === null || Array.isArray(relianceRef))) ||
    ((schemaVersion === SCHEMA_VERSION || schemaVersion === SCHEMA_VERSION_V2) && "chainRef" in payload) ||
    (schemaVersion === SCHEMA_VERSION_V3 && !chainRefShapeValid(payload.chainRef)) ||
    ((schemaVersion === SCHEMA_VERSION || schemaVersion === SCHEMA_VERSION_V2 || schemaVersion === SCHEMA_VERSION_V3) &&
      "dagRef" in payload) ||
    (schemaVersion === SCHEMA_VERSION_V4 && "chainRef" in payload) ||
    (schemaVersion === SCHEMA_VERSION_V4 && !("chainRef" in payload) && !dagRefShapeValid(payload.dagRef));

  if (!out.hashValid) {
    out.status = "INVALID";
    out.cryptoCode = "EVIDENCE_HASH_INVALID";
  } else if (!out.chainValid) {
    out.status = "INVALID";
    out.cryptoCode = "CHAIN_INVALID";
  } else if (structuralInvalid) {
    out.status = "INVALID";
    out.cryptoCode = "UNSUPPORTED_SCHEMA_VERSION";
  } else if (!out.signaturePresent) {
    out.status = "INVALID";
    out.cryptoCode = "SIGNATURE_MISSING";
  } else if (!out.keyResolved) {
    out.status = "UNVERIFIABLE";
    out.cryptoCode = "KEY_UNRESOLVED";
  } else if (!out.signatureValid) {
    out.status = "INVALID";
    out.cryptoCode = "SIGNATURE_INVALID";
  } else {
    out.status = "VERIFIED";
    out.cryptoCode = null;
  }
  return out;
}

function unmetRequirement(req: NormalizedRequirement, status: string, reason: string): RelianceRequirementResult {
  const out: RelianceRequirementResult = {
    requirementId: req.requirementId,
    evidenceId: null,
    evidenceHash: null,
    recordMode: null,
    hashValid: false,
    chainValid: false,
    signaturePresent: false,
    signatureValid: null,
    keyResolved: false,
    capabilityMatched: false,
    workspaceMatched: false,
    decisionMatched: false,
    executionStatusMatched: false,
    signingKeyMatched: false,
    paramsHashMatched: false,
    freshnessValid: false,
    status,
    satisfied: false,
    reason,
  };
  if (req.receiptType === ATTESTATION_RECORD_MODE) {
    out.artifactType = ATTESTATION_RECORD_MODE;
    out.attestationAgentId = null;
    out.attestationAgentClass = null;
    out.attestationIssuerId = null;
    out.scopeMatched = null;
  }
  return out;
}

/** Dispatch on the requirement's artifact family. Both branches produce the
 * SAME result shape and feed the SAME worst-of/dedup logic in
 * evaluateRelianceLocal — one reliance gate, two artifact vocabularies,
 * never a second parallel authorization system. */
function evaluateRequirement(
  req: NormalizedRequirement,
  opts: {
    workspaceRoot: string;
    stateDir: string;
    wsFingerprint: string;
    kids: string[] | null;
    nowMs: number;
    requestingAgentId: string | null;
    subjectCapabilityId: string | null;
  },
): RelianceRequirementResult {
  if (req.receiptType === ATTESTATION_RECORD_MODE) {
    return evaluateAttestationRequirement(req, opts);
  }
  return evaluateReceiptRequirement(req, opts);
}

function evaluateReceiptRequirement(
  req: NormalizedRequirement,
  opts: { workspaceRoot: string; stateDir: string; wsFingerprint: string; kids: string[] | null; nowMs: number },
): RelianceRequirementResult {
  const receiptPath = path.isAbsolute(req.receiptPath) ? req.receiptPath : path.join(opts.workspaceRoot, req.receiptPath);
  if (!fs.existsSync(receiptPath)) {
    return unmetRequirement(req, "MISSING", "REQUIRED_PROOF_MISSING: no receipt was presented for this requirement");
  }
  let record: unknown = null;
  try {
    record = JSON.parse(fs.readFileSync(receiptPath, "utf-8"));
  } catch {
    record = null;
  }
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    return unmetRequirement(req, "MALFORMED", "RECEIPT_MALFORMED: the presented receipt is not a JSON object");
  }
  const payload = (record as Record<string, unknown>).payload as Record<string, unknown> | undefined;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return unmetRequirement(req, "MALFORMED", "RECEIPT_MALFORMED: the presented receipt is not a JSON object with a payload");
  }

  const vr = verifyLocalRecordForReliance(record, opts.stateDir);
  const cryptoCode = vr.cryptoCode;

  const capabilityMatched = payload.capabilityId === req.capabilityId;
  const decisionMatched = typeof payload.decision === "string" && req.decisions.includes(payload.decision);
  const executionStatusMatched = payload.executionStatus === req.executionStatus;
  const workspaceMatched = !req.sameWorkspace || payload.workspaceFingerprint === opts.wsFingerprint;
  const signingKeyMatched =
    !req.sameSigningKey || (opts.kids !== null && typeof payload.signingKeyId === "string" && opts.kids.includes(payload.signingKeyId));
  const action = payload.action as Record<string, unknown> | undefined;
  const paramsHashMatched =
    req.paramsHash === null || (!!action && typeof action === "object" && action.paramsHash === req.paramsHash);

  const createdRaw = payload.createdAt;
  let ageSeconds: number | null = null;
  let freshnessCode: string | null = null;
  const createdMs = typeof createdRaw === "string" && TIMESTAMP_RE.test(createdRaw) ? Date.parse(createdRaw) : NaN;
  // Round-trip check: Date.parse is LENIENT on calendar-invalid dates in
  // this format (e.g. "2026-02-30" rolls to March 2; "T24:00:00" rolls to
  // the next day) — the Python reference's strptime rejects both. Requiring
  // the parsed instant to serialize back to the exact input string makes
  // this side equally strict (fail-closed on anything non-canonical).
  const roundTrip = Number.isNaN(createdMs)
    ? null
    : new Date(createdMs).toISOString().replace(/\.\d{3}Z$/, "Z");
  if (roundTrip === null || roundTrip !== createdRaw) {
    freshnessCode = "TIMESTAMP_UNPARSEABLE";
  } else {
    // Math.trunc (NOT floor): truncate toward zero, matching Python int().
    ageSeconds = Math.trunc((opts.nowMs - createdMs) / 1000);
    if (ageSeconds < 0) {
      freshnessCode = "RECEIPT_FUTURE_DATED";
    } else if (req.maxAgeSeconds !== null && ageSeconds > req.maxAgeSeconds) {
      freshnessCode = "REQUIRED_PROOF_EXPIRED";
    }
  }
  const freshnessValid = freshnessCode === null;

  // First failing check in the SAME fixed order as the reference impl.
  let code: string | null = cryptoCode !== null && cryptoCode !== "KEY_UNRESOLVED" ? cryptoCode : null;
  let detail: string | null = null;
  if (code === null) {
    if (cryptoCode === "KEY_UNRESOLVED" && !req.allowUnresolvedKey) code = "KEY_UNRESOLVED";
    else if (!capabilityMatched) code = "CAPABILITY_MISMATCH";
    else if (!decisionMatched) code = "DECISION_MISMATCH";
    else if (!executionStatusMatched) code = "EXECUTION_STATUS_MISMATCH";
    else if (!workspaceMatched) code = "WORKSPACE_MISMATCH";
    else if (!signingKeyMatched) code = "SIGNING_KEY_MISMATCH";
    else if (!paramsHashMatched) code = "PARAMS_HASH_MISMATCH";
    else if (!freshnessValid) {
      code = freshnessCode;
      if (code === "REQUIRED_PROOF_EXPIRED") {
        detail = `receipt age ${ageSeconds}s exceeds required maximum age ${req.maxAgeSeconds}s`;
      }
    }
  }

  const satisfied = code === null;
  let reason: string;
  if (satisfied) {
    reason =
      cryptoCode === "KEY_UNRESOLVED"
        ? "SATISFIED: conditions passed with an UNRESOLVED signing key — allowUnresolvedKey " +
          "is set on this requirement; the receipt content is hash-consistent but NOT authenticated"
        : "SATISFIED: all required proof conditions passed for this requirement";
  } else if (detail) {
    reason = `${code}: ${detail}`;
  } else if (code === "RECEIPT_MALFORMED") {
    reason = "RECEIPT_MALFORMED: the presented receipt is not a JSON object with a payload";
  } else {
    reason = `${code}: ${RELIANCE_DETAILS[code!]}`;
  }

  return {
    requirementId: req.requirementId,
    evidenceId: typeof payload.evidenceId === "string" ? payload.evidenceId : null,
    evidenceHash: typeof payload.evidenceHash === "string" ? payload.evidenceHash : null,
    recordMode: typeof payload.recordMode === "string" ? payload.recordMode : null,
    hashValid: vr.hashValid,
    chainValid: vr.chainValid,
    signaturePresent: vr.signaturePresent,
    signatureValid: vr.signatureValid,
    keyResolved: vr.keyResolved,
    capabilityMatched,
    workspaceMatched,
    decisionMatched,
    executionStatusMatched,
    signingKeyMatched,
    paramsHashMatched,
    freshnessValid,
    status: vr.status,
    satisfied,
    reason,
  };
}

/** Evaluate one ATTESTATION_RECORD_MODE requirement — the 16 checks of
 * Attestation-Gated Execution v1, in the SAME fixed order as the Python
 * reference implementations (cross-language conformance depends on this
 * order matching exactly). Identity evidence is an INPUT here, never the
 * authority: a VERIFIED attestation still must pass every content binding
 * below before this requirement is satisfied, and satisfying it is only
 * ONE input into the overall reliance verdict. */
function evaluateAttestationRequirement(
  req: NormalizedRequirement,
  opts: {
    workspaceRoot: string;
    stateDir: string;
    wsFingerprint: string;
    nowMs: number;
    requestingAgentId: string | null;
    subjectCapabilityId: string | null;
  },
): RelianceRequirementResult {
  const attestationPath = path.isAbsolute(req.receiptPath) ? req.receiptPath : path.join(opts.workspaceRoot, req.receiptPath);
  if (!fs.existsSync(attestationPath)) {
    return unmetRequirement(req, "MISSING", "ATTESTATION_MISSING: no attestation was presented for this requirement");
  }
  let record: unknown = null;
  try {
    record = JSON.parse(fs.readFileSync(attestationPath, "utf-8"));
  } catch {
    record = null;
  }
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    return unmetRequirement(req, "MALFORMED", "ATTESTATION_MALFORMED: the presented attestation is not a JSON object");
  }
  const payload = (record as Record<string, unknown>).payload as Record<string, unknown> | undefined;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return unmetRequirement(
      req, "MALFORMED", "ATTESTATION_MALFORMED: the presented attestation is not a JSON object with a payload",
    );
  }

  const vr = verifyLocalAttestationCrypto(record, opts.stateDir);
  const cryptoCode = vr.cryptoCode;

  const attestationId = typeof payload.attestationId === "string" ? payload.attestationId : null;
  const attestationHash = typeof payload.attestationHash === "string" ? payload.attestationHash : null;
  const recordMode = typeof payload.recordMode === "string" ? payload.recordMode : null;
  const agentId = typeof payload.agentId === "string" ? payload.agentId : null;
  const agentClass = typeof payload.agentClass === "string" ? payload.agentClass : null;
  const issuerId = typeof payload.issuerId === "string" ? payload.issuerId : null;

  const issuerMatched = issuerId !== null && req.permittedIssuers.includes(issuerId);
  let agentMatched: boolean;
  if (req.agentIdFromRequest) {
    agentMatched = opts.requestingAgentId !== null && agentId === opts.requestingAgentId;
  } else if (req.expectedAgentId !== null) {
    agentMatched = agentId === req.expectedAgentId;
  } else {
    agentMatched = true;
  }
  const classMatched = req.requiredClass === null || agentClass === req.requiredClass;
  const workspaceMatched = !req.sameWorkspace || payload.workspaceFingerprint === opts.wsFingerprint;
  const scopes = payload.capabilityScopes;
  let scopeMatched: boolean;
  if (req.capabilityScopeMustIncludeSubject) {
    scopeMatched = Boolean(
      opts.subjectCapabilityId !== null &&
        Array.isArray(scopes) &&
        scopes.some((s) => typeof s === "string" && scopeMatches(s, opts.subjectCapabilityId as string)),
    );
  } else {
    scopeMatched = true;
  }

  const issuedRaw = payload.issuedAt;
  const expiresRaw = payload.expiresAt;
  const issuedMs = typeof issuedRaw === "string" && TIMESTAMP_RE.test(issuedRaw) ? Date.parse(issuedRaw) : NaN;
  const expiresMs = typeof expiresRaw === "string" && TIMESTAMP_RE.test(expiresRaw) ? Date.parse(expiresRaw) : NaN;
  const issuedRoundTrip = Number.isNaN(issuedMs) ? null : new Date(issuedMs).toISOString().replace(/\.\d{3}Z$/, "Z");
  const expiresRoundTrip = Number.isNaN(expiresMs) ? null : new Date(expiresMs).toISOString().replace(/\.\d{3}Z$/, "Z");
  const issuedValid = issuedRoundTrip !== null && issuedRoundTrip === issuedRaw;
  const expiresValid = expiresRoundTrip !== null && expiresRoundTrip === expiresRaw;

  const notYetValid = issuedValid && issuedMs > opts.nowMs;
  const expired = expiresValid && opts.nowMs > expiresMs;
  const ageSeconds = issuedValid ? Math.trunc((opts.nowMs - issuedMs) / 1000) : null;
  const maxAgeExceeded = req.maxAgeSeconds !== null && ageSeconds !== null && ageSeconds > req.maxAgeSeconds;
  const freshnessValid = issuedValid && expiresValid && !notYetValid && !expired && !maxAgeExceeded;
  const revoked = attestationId !== null && isAttestationRevoked(opts.stateDir, attestationId);

  let code: string | null = null;
  let detail: string | null = null;
  if (cryptoCode === "ATTESTATION_KEY_UNKNOWN" && !req.allowUnresolvedKey) {
    code = "ATTESTATION_KEY_UNKNOWN";
  } else if (cryptoCode !== null && cryptoCode !== "ATTESTATION_KEY_UNKNOWN") {
    code = cryptoCode;
  } else if (!issuerMatched) {
    code = "ATTESTATION_ISSUER_NOT_ALLOWED";
  } else if (!agentMatched) {
    code = "ATTESTATION_AGENT_MISMATCH";
  } else if (!classMatched) {
    code = "ATTESTATION_CLASS_MISMATCH";
  } else if (!workspaceMatched) {
    code = "ATTESTATION_WORKSPACE_MISMATCH";
  } else if (!scopeMatched) {
    code = "ATTESTATION_SCOPE_MISMATCH";
  } else if (!issuedValid || !expiresValid) {
    code = "ATTESTATION_MALFORMED";
    detail = "issuedAt/expiresAt could not be parsed as strict RFC3339 Z-suffixed timestamps";
  } else if (notYetValid) {
    code = "ATTESTATION_NOT_YET_VALID";
  } else if (expired) {
    code = "ATTESTATION_EXPIRED";
    detail = "attestation expiresAt has passed";
  } else if (maxAgeExceeded) {
    code = "ATTESTATION_EXPIRED";
    detail = `attestation age ${ageSeconds}s exceeds required maximum age ${req.maxAgeSeconds}s`;
  } else if (revoked) {
    code = "ATTESTATION_REVOKED";
  }

  const satisfied = code === null;
  let reason: string;
  if (satisfied) {
    reason =
      cryptoCode === "ATTESTATION_KEY_UNKNOWN"
        ? "SATISFIED: conditions passed with an UNRESOLVED signing key — allowUnresolvedKey " +
          "is set on this requirement; the attestation content is hash-consistent but NOT authenticated"
        : "SATISFIED: all required attestation conditions passed for this requirement";
  } else if (detail) {
    reason = `${code}: ${detail}`;
  } else {
    const failingCode = code ?? "ATTESTATION_UNVERIFIABLE";
    reason = `${failingCode}: ${ATTESTATION_DETAILS[failingCode] ?? "attestation verification could not complete"}`;
  }

  return {
    requirementId: req.requirementId,
    evidenceId: attestationId,
    evidenceHash: attestationHash,
    recordMode,
    hashValid: vr.hashValid,
    chainValid: true, // attestations are independently signed, not chained — vacuously true
    signaturePresent: vr.signaturePresent,
    signatureValid: vr.signatureValid,
    keyResolved: vr.keyResolved,
    capabilityMatched: true, // not an attestation concept — "passed or not required"
    workspaceMatched,
    decisionMatched: true, // not an attestation concept
    executionStatusMatched: true, // not an attestation concept
    signingKeyMatched: true, // sameSigningKey has no meaning for attestations
    paramsHashMatched: true, // paramsHash has no meaning for attestations
    freshnessValid,
    status: vr.status,
    satisfied,
    reason,
    artifactType: ATTESTATION_RECORD_MODE,
    attestationAgentId: agentId,
    attestationAgentClass: agentClass,
    attestationIssuerId: issuerId,
    scopeMatched,
  };
}

/** Filesystem-reads-only, zero-network reliance evaluation. NEVER trusts a
 * stored verdict — every receipt/attestation is re-verified from its own
 * bytes.
 *
 * `requestingAgentId` (Attestation-Gated Execution v1): the live requesting
 * agent's identity, bound against an ATTESTATION_RECORD_MODE requirement's
 * agentIdFromRequest. */
export function evaluateRelianceLocal(
  capabilityId: string,
  requirements: RelianceRequirement[],
  opts: { workspaceRoot: string; stateDir: string; now?: string; requestingAgentId?: string | null },
): RelianceResult {
  const nowMs = opts.now !== undefined ? Date.parse(opts.now) : Date.now();
  if (Number.isNaN(nowMs)) throw new StrixLocalError(`invalid reliance 'now' timestamp: ${opts.now}`);
  const checkedAt = new Date(nowMs).toISOString().replace(/\.\d{3}Z$/, "Z");
  const wsFingerprint = workspaceFingerprint(opts.workspaceRoot);
  const kids = registryKids(opts.stateDir);
  const normalized = normalizeRequirements(requirements);
  const requestingAgentId = opts.requestingAgentId ?? null;

  const results: RelianceRequirementResult[] = normalized.map((req) => {
    try {
      return evaluateRequirement(req, {
        workspaceRoot: opts.workspaceRoot,
        stateDir: opts.stateDir,
        wsFingerprint,
        kids,
        nowMs,
        requestingAgentId,
        subjectCapabilityId: capabilityId,
      });
    } catch (exc) {
      // A crashing verifier must deny — never escape the gate as success.
      return unmetRequirement(req, "ERROR", `VERIFIER_ERROR: ${(exc as Error).name}: ${(exc as Error).message}`);
    }
  });

  // Distinct-evidence discipline: one receipt satisfies at most one requirement.
  const seenEvidence = new Set<string>();
  for (const r of results) {
    if (r.satisfied && r.evidenceId !== null) {
      if (seenEvidence.has(r.evidenceId)) {
        r.satisfied = false;
        r.reason = "DUPLICATE_EVIDENCE: the same evidenceId was presented for more than one requirement";
      } else {
        seenEvidence.add(r.evidenceId);
      }
    }
  }

  const statuses = new Set(results.map((r) => r.status));
  let verificationStatus: string;
  if (statuses.has("INVALID")) verificationStatus = "INVALID";
  else if ([...statuses].some((s) => s !== "VERIFIED")) verificationStatus = "UNVERIFIABLE";
  else verificationStatus = "VERIFIED";

  const proceed = results.every((r) => r.satisfied);
  let reason: string;
  if (proceed) {
    reason = "ALL_REQUIREMENTS_SATISFIED: all required proof conditions passed";
  } else {
    const first = results.find((r) => !r.satisfied)!;
    reason = `requirement '${first.requirementId}' failed — ${first.reason}`;
  }

  return {
    reliancePolicyId: `inline:${capabilityId}`,
    reliancePolicyVersion: 1,
    policyHash: reliancePolicyHash(capabilityId, normalized),
    verificationStatus,
    relianceVerdict: proceed ? "PROCEED" : "DENY",
    requirements: results,
    reason,
    checkedAt,
  };
}

/** Attestation-Gated Execution v1: the downstream receipt must bind agent
 * id / class / issuer / capability-scope result / workspace-binding result
 * / freshness result alongside attestationId/attestationHash
 * (evidenceId/evidenceHash) and verification status (status). */
function attestationRequirementRef(r: RelianceRequirementResult): Record<string, unknown> {
  return {
    requirementId: r.requirementId,
    evidenceId: r.evidenceId,
    evidenceHash: r.evidenceHash,
    recordMode: r.recordMode,
    status: r.status,
    satisfied: r.satisfied,
    reason: r.reason,
    artifactType: r.artifactType,
    attestationAgentId: r.attestationAgentId,
    attestationAgentClass: r.attestationAgentClass,
    attestationIssuerId: r.attestationIssuerId,
    scopeMatched: r.scopeMatched,
    workspaceMatched: r.workspaceMatched,
    freshnessValid: r.freshnessValid,
  };
}

/** Compact projection bound into the downstream local-receipt-v2 signed
 * payload. Semantic bindings only — no receipt paths, no formatting. */
function relianceReceiptRef(result: RelianceResult): Record<string, unknown> {
  return {
    reliancePolicyId: result.reliancePolicyId,
    reliancePolicyVersion: result.reliancePolicyVersion,
    policyHash: result.policyHash,
    relianceVerdict: result.relianceVerdict,
    verificationStatus: result.verificationStatus,
    checkedAt: result.checkedAt,
    requirements: result.requirements.map((r) =>
      r.artifactType === ATTESTATION_RECORD_MODE
        ? attestationRequirementRef(r)
        : {
            requirementId: r.requirementId,
            evidenceId: r.evidenceId,
            evidenceHash: r.evidenceHash,
            recordMode: r.recordMode,
            status: r.status,
            satisfied: r.satisfied,
            reason: r.reason,
          },
    ),
  };
}

// ──────────────────────────────────────────────────────────────────────
// Canonical payload + signing + chain
// ──────────────────────────────────────────────────────────────────────

function workspaceFingerprint(root: string): string {
  return hashCanonical({ path: path.resolve(root) });
}

function buildPayload(opts: {
  evidenceId: string;
  capabilityId: string;
  actionName: string;
  params: Record<string, unknown>;
  ref: { version: string; hash: string };
  decision: string;
  executionStatus: string;
  workspaceRoot: string;
  key: LocalSigningKey;
  chainSeq: number;
  prevHash: string | null;
  relianceRef?: Record<string, unknown> | null;
  chainRef?: Record<string, unknown> | null;
  dagRef?: Record<string, unknown> | null;
}): Record<string, unknown> {
  const relianceRef = opts.relianceRef ?? null;
  const chainRef = opts.chainRef ?? null;
  const dagRef = opts.dagRef ?? null;
  if (chainRef !== null && dagRef !== null) {
    throw new StrixLocalError(
      "chainRef and dagRef are mutually exclusive — a receipt is local-receipt-v3 XOR " +
        "local-receipt-v4, never both",
    );
  }
  const action = {
    name: opts.actionName,
    paramsHash: hashCanonical(opts.params),
    paramsSchemaHash: hashCanonical(Object.keys(opts.params).sort()),
  };
  const schemaVersion =
    dagRef !== null
      ? SCHEMA_VERSION_V4
      : chainRef !== null
        ? SCHEMA_VERSION_V3
        : relianceRef === null
          ? SCHEMA_VERSION
          : SCHEMA_VERSION_V2;
  const core: Record<string, unknown> = {
    schemaVersion,
    recordMode: RECORD_MODE,
    evidenceId: opts.evidenceId,
    createdAt: isoNow(),
    capabilityId: opts.capabilityId,
    action,
    policyRef: opts.ref,
    decision: opts.decision,
    executionStatus: opts.executionStatus,
    workspaceFingerprint: workspaceFingerprint(opts.workspaceRoot),
    signingKeyId: opts.key.kid,
    publicKeyFingerprint: opts.key.publicKeyFingerprint,
    runtimeVersion: "strix-wire-local-helper-ts/1.0.0",
    chainSeq: opts.chainSeq,
    prevHash: opts.prevHash,
  };
  if (relianceRef !== null) {
    // Round-trip through the canonical serializer: plain JSON-safe deep
    // copy; rejects unserializable content eagerly.
    core.relianceRef = JSON.parse(canonicalize(relianceRef));
  }
  if (chainRef !== null) {
    core.chainRef = JSON.parse(canonicalize(chainRef));
  }
  if (dagRef !== null) {
    core.dagRef = JSON.parse(canonicalize(dagRef));
  }
  const evidenceHash = hashCanonical(core);
  const proofChainHash = hashCanonical({ evidenceHash, prevHash: opts.prevHash, chainSeq: opts.chainSeq });
  return { ...core, evidenceHash, proofChainHash };
}

function signPayload(payload: Record<string, unknown>, key: LocalSigningKey): Record<string, unknown> {
  const signature = signRaw(key.privateKeyHex, Buffer.from(canonicalize(payload), "utf-8"));
  return { payload, signature };
}

function chainPaths(stateDir: string): { dir: string; chainPath: string } {
  const dir = path.join(stateDir, "evidence");
  return { dir, chainPath: path.join(dir, "receipts.jsonl") };
}

function lastHashAndSeq(chainPath: string): [string | null, number] {
  // `lines.length` (every non-blank physical line, whether it parses or
  // not) is the chain-sequence count on purpose: a corrupted/truncated
  // line still occupies a slot on disk, so a newly minted receipt must
  // never be assigned a chainSeq that collides with a record that already
  // physically exists (mirrors the sibling Python helper's
  // `_last_hash_and_seq` and solo_builder's `LocalReceiptChain.next_seq`).
  if (!fs.existsSync(chainPath)) return [null, 0];
  const lines = fs.readFileSync(chainPath, "utf-8").split("\n").filter((l) => l.trim().length > 0);
  let lastHash: string | null = null;
  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      const hash = entry?.payload?.evidenceHash;
      // Only advance lastHash on a line that both parses AND carries a
      // real evidenceHash — a valid-JSON-but-wrong-shape line (or a
      // legitimately corrupt one) must never reset lastHash to null and
      // silently lose the last genuine chain position to point at.
      if (typeof hash === "string" && hash.length > 0) {
        lastHash = hash;
      }
    } catch {
      // tolerate a corrupt line — it still occupies a chain-sequence slot
      // (see `lines.length` in the return below), it just can't supply a
      // hash to chain the next receipt to.
    }
  }
  return [lastHash, lines.length];
}

function appendAndExport(stateDir: string, record: Record<string, unknown>): string {
  const { dir, chainPath } = chainPaths(stateDir);
  fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(chainPath, JSON.stringify(record) + "\n", "utf-8");
  const payload = record.payload as Record<string, unknown>;
  const evidenceId = payload.evidenceId as string;
  const singlePath = path.join(dir, `${evidenceId}.json`);
  fs.writeFileSync(singlePath, JSON.stringify(record, null, 2) + "\n", "utf-8");
  return singlePath;
}

// ──────────────────────────────────────────────────────────────────────
// The public surface
// ──────────────────────────────────────────────────────────────────────

export interface LocalGovernedActionResult<T> {
  result: T;
  evidenceId: string;
  receiptPath: string;
  record: Record<string, unknown>;
}

/** Chained Governed Autonomy v2 — the minimal DAG-position metadata
 * governedActionLocal needs to derive the receipt's dagRef projection.
 * Constructed ONLY by DagSession from its own internal, non-caller-
 * suppliable bookkeeping — mirrors LocalChainStep, generalized from a
 * single optional predecessor to a list of zero or more parents.
 * parentEvidenceIds is empty for a source node — valid at any stepIndex,
 * not only at 0. Each entry's role here is purely to tell this function
 * HOW MANY parents were declared; the string values themselves are never
 * trusted for the signed output (see the dagStep derivation below). */
export interface LocalDagStep {
  dagId: string;
  stepIndex: number;
  parentEvidenceIds: string[];
  attestationRequired: boolean;
}

export function governedActionLocal<T>(
  capabilityId: string,
  actionName: string,
  payload: Record<string, unknown>,
  operation: () => T,
  opts: {
    approvalGranted?: boolean;
    workspaceRoot?: string;
    stateDir?: string;
    /** Local Reliance Gate v1: prior proofs that must independently
     * re-verify BEFORE the operation runs. Any unmet requirement throws
     * StrixLocalRelianceDenied; the verified projection is bound into the
     * downstream signed receipt (local-receipt-v2 relianceRef).
     * Attestation-Gated Execution v1: a requirement whose receiptType is
     * ATTESTATION_RECORD_MODE is independently re-verified against the
     * LOCAL issuer key registry + revocation list rooted under this same
     * stateDir — identity evidence is an INPUT to this authorization
     * decision, never the authorization itself; the ordinary policy above
     * still evaluates independently and must ALSO permit the capability. */
    reliance?: RelianceRequirement[];
    /** The live requesting agent's identity, bound against an attestation
     * requirement's agentIdFromRequest. */
    requestingAgentId?: string | null;
    /** Chained Governed Autonomy v1 — supplied ONLY by ChainSession. This
     * function does not construct any chain-predecessor or
     * chain-attestation reliance requirement itself (the session does,
     * via `reliance` like any other requirement) — `chainStep` is used
     * purely to derive the receipt's `chainRef` projection AFTER
     * evaluateRelianceLocal has already run and the action is authorized
     * to proceed. */
    chainStep?: LocalChainStep | null;
    /** Chained Governed Autonomy v2 — supplied ONLY by DagSession. Same
     * discipline as chainStep, generalized to zero or more parents. */
    dagStep?: LocalDagStep | null;
  } = {},
): LocalGovernedActionResult<T> {
  const workspaceRoot = opts.workspaceRoot ?? process.cwd();
  const stateDir = opts.stateDir ?? path.join(workspaceRoot, DEFAULT_STATE_DIR);
  const approvalGranted = opts.approvalGranted ?? false;

  const [rawDecision, reason] = evaluatePolicy(capabilityId, payload);

  // Local Reliance Gate v1 — evaluated AFTER policy, BEFORE decide/
  // authorize/execute. Independent re-verification; stored verdicts are
  // never trusted.
  let relianceResult: RelianceResult | null = null;
  if (opts.reliance !== undefined) {
    relianceResult = evaluateRelianceLocal(capabilityId, opts.reliance, {
      workspaceRoot,
      stateDir,
      requestingAgentId: opts.requestingAgentId ?? null,
    });
  }

  if (rawDecision === "DENY") {
    throw new StrixLocalDenied(`${capabilityId}: ${reason}`);
  }
  if (relianceResult !== null && relianceResult.relianceVerdict !== "PROCEED") {
    throw new StrixLocalRelianceDenied(
      `${capabilityId}: reliance denied — ${relianceResult.reason}. The protected operation was not called.`,
      relianceResult,
    );
  }
  if (rawDecision === "REQUIRE_APPROVAL" && !approvalGranted) {
    throw new StrixLocalApprovalRequired(`${capabilityId}: ${reason} (approval not granted)`);
  }
  // --- everything above runs BEFORE operation(); nothing below may
  // --- execute unless policy cleared, every declared reliance requirement
  // --- verified, and any required approval was granted.

  const decision = rawDecision === "ALLOW" ? "ALLOW" : "REQUIRE_APPROVAL_GRANTED";
  const relianceRef = relianceResult !== null ? relianceReceiptRef(relianceResult) : null;

  // Chained Governed Autonomy v1: chainRef is DERIVED from the reliance
  // evaluation that just cleared above — never accepted as raw input.
  const chainStep = opts.chainStep ?? null;
  let chainRef: Record<string, unknown> | null = null;
  if (chainStep !== null) {
    let agentId: string | null = null;
    if (chainStep.attestationRequired && relianceResult !== null) {
      const attResult = relianceResult.requirements.find((r) => r.requirementId === "chain-attestation");
      agentId = attResult?.attestationAgentId ?? null;
    }

    // Same "derive, never trust raw input" treatment as agentId above: a
    // caller bypassing ChainSession (which always constructs a matching,
    // satisfied "chain-predecessor" requirement for a non-root step)
    // cannot make this function sign an unverified predecessor claim — it
    // fails closed instead.
    let previousStepEvidenceId = chainStep.previousEvidenceId;
    let previousStepEvidenceHash = chainStep.previousEvidenceHash;
    if (previousStepEvidenceId !== null || previousStepEvidenceHash !== null) {
      const predResult =
        relianceResult !== null
          ? relianceResult.requirements.find((r) => r.requirementId === "chain-predecessor")
          : undefined;
      if (!predResult || !predResult.satisfied) {
        throw new StrixLocalChainPredecessorUnverified(
          "chainStep declares a non-root predecessor (previousStepEvidenceId/Hash is not null) but " +
            "no independently-verified, satisfied 'chain-predecessor' reliance requirement was found " +
            "in this call's reliance evaluation. A chainRef predecessor claim must always be backed by " +
            "a re-verified requirement, never accepted as raw chainStep input.",
        );
      }
      previousStepEvidenceId = predResult.evidenceId ?? null;
      previousStepEvidenceHash = predResult.evidenceHash ?? null;
    }

    chainRef = {
      chainId: chainStep.chainId,
      stepIndex: chainStep.stepIndex,
      previousStepEvidenceId,
      previousStepEvidenceHash,
      agentAttestationRequired: chainStep.attestationRequired,
      agentId,
    };
  }

  // Chained Governed Autonomy v2: dagRef is DERIVED from the reliance
  // evaluation that just cleared above — never accepted as raw input.
  // Same "derive, never trust raw input" treatment as chainRef, extended
  // to a list of zero or more parents: every declared parent index must
  // be backed by its own independently-verified, satisfied
  // "dag-parent-{i}" requirement in THIS call's evaluation, and the
  // SIGNED dagRef embeds that requirement's own verified
  // evidenceId/evidenceHash — never the caller's raw dagStep claim.
  const dagStep = opts.dagStep ?? null;
  let dagRef: Record<string, unknown> | null = null;
  if (dagStep !== null) {
    if (new Set(dagStep.parentEvidenceIds).size !== dagStep.parentEvidenceIds.length) {
      throw new StrixLocalDagParentUnverified(
        "dagStep declares a duplicate parent evidence id — a DAG step cannot depend on the same " +
          "parent twice.",
      );
    }

    let dagAgentId: string | null = null;
    if (dagStep.attestationRequired && relianceResult !== null) {
      const dagAttResult = relianceResult.requirements.find((r) => r.requirementId === "dag-attestation");
      dagAgentId = dagAttResult?.attestationAgentId ?? null;
    }

    const parentRefs: Array<{ evidenceId: string | null; evidenceHash: string | null }> = [];
    for (let parentIndex = 0; parentIndex < dagStep.parentEvidenceIds.length; parentIndex += 1) {
      const requirementId = `dag-parent-${parentIndex}`;
      const parentResult =
        relianceResult !== null ? relianceResult.requirements.find((r) => r.requirementId === requirementId) : undefined;
      if (!parentResult || !parentResult.satisfied) {
        throw new StrixLocalDagParentUnverified(
          `dagStep declares parent index ${parentIndex} but no independently-verified, satisfied ` +
            `'${requirementId}' reliance requirement was found in this call's reliance evaluation. ` +
            "A dagRef parent claim must always be backed by a re-verified requirement, never " +
            "accepted as raw dagStep input.",
        );
      }
      parentRefs.push({ evidenceId: parentResult.evidenceId ?? null, evidenceHash: parentResult.evidenceHash ?? null });
    }

    // Canonical order, NOT declaration order: parentEvidenceRefs is
    // semantically an unordered SET (every verifyLocalDag check already
    // resolves it by evidenceId/stepIndex value, never list position — see
    // CGA2-13). Sorting by (evidenceId, evidenceHash) before signing means
    // two logically-identical parent sets declared in different orders
    // ([A, B] vs [B, A]) always produce the same canonical bytes and
    // signature. This is a construction-time-only guarantee — verifyLocalDag
    // deliberately stays order-agnostic when reading.
    parentRefs.sort((a, b) => {
      const idCompare = (a.evidenceId ?? "").localeCompare(b.evidenceId ?? "");
      if (idCompare !== 0) return idCompare;
      return (a.evidenceHash ?? "").localeCompare(b.evidenceHash ?? "");
    });

    dagRef = {
      dagId: dagStep.dagId,
      stepIndex: dagStep.stepIndex,
      parentEvidenceRefs: parentRefs,
      agentAttestationRequired: dagStep.attestationRequired,
      agentId: dagAgentId,
    };
  }

  const key = generateOrLoadKey(stateDir);
  const ref = policyRef();
  const { dir: evidenceDir, chainPath } = chainPaths(stateDir);
  const [prevHash, chainSeq] = lastHashAndSeq(chainPath);

  let result: T;
  try {
    result = operation();
  } catch (exc) {
    try {
      const failedPayload = buildPayload({
        evidenceId: newEvidenceId(),
        capabilityId,
        actionName,
        params: payload,
        ref,
        decision,
        executionStatus: "FAILED",
        workspaceRoot,
        key,
        chainSeq,
        prevHash,
        relianceRef,
        chainRef,
        dagRef,
      });
      appendAndExport(stateDir, signPayload(failedPayload, key));
    } catch (receiptExc) {
      // eslint-disable-next-line no-console
      console.warn(`failed to record a FAILED receipt after the operation itself failed: ${receiptExc}`);
    }
    throw exc;
  }

  let record: Record<string, unknown>;
  let receiptPath: string;
  try {
    const successPayload = buildPayload({
      evidenceId: newEvidenceId(),
      capabilityId,
      actionName,
      params: payload,
      ref,
      decision,
      executionStatus: "SUCCEEDED",
      workspaceRoot,
      key,
      chainSeq,
      prevHash,
      relianceRef,
      chainRef,
      dagRef,
    });
    record = signPayload(successPayload, key);
    receiptPath = appendAndExport(stateDir, record);
  } catch (exc) {
    throw new StrixLocalReceiptPersistenceError(
      `${capabilityId} executed successfully, but the signed receipt could not be persisted: ${exc}. ` +
        `The mutation is NOT undone. Inspect ${evidenceDir} before retrying.`,
    );
  }

  const evidenceId = (record.payload as Record<string, unknown>).evidenceId as string;
  return { result, evidenceId, receiptPath, record };
}

// ──────────────────────────────────────────────────────────────────────
// Chained Governed Autonomy v1 — ChainSession + verifyLocalChain
// ──────────────────────────────────────────────────────────────────────

export class LocalChainError extends StrixLocalError {}

/** Chained Governed Autonomy v1 — the minimal chain-position metadata
 * governedActionLocal needs to derive the receipt's chainRef projection.
 * Constructed ONLY by ChainSession from its own internal, non-caller-
 * suppliable bookkeeping. previousEvidenceId/Hash are null at
 * stepIndex === 0 (chain root). */
export interface LocalChainStep {
  chainId: string;
  stepIndex: number;
  previousEvidenceId: string | null;
  previousEvidenceHash: string | null;
  attestationRequired: boolean;
}

/** The identity policy every step of a chain must satisfy, applied
 * uniformly by ChainSession. permittedIssuers has no default: an
 * attestation policy with no issuer trust boundary at all is not a
 * fail-closed identity check. */
export class ChainAttestationPolicy {
  readonly permittedIssuers: string[];
  readonly requiredClass: string | null;
  readonly capabilityScopeMustIncludeSubject: boolean;
  readonly agentIdFromRequest: boolean;
  readonly expectedAgentId: string | null;
  readonly maxAgeSeconds: number | null;
  readonly allowUnresolvedKey: boolean;

  constructor(
    permittedIssuers: string[],
    opts: {
      requiredClass?: string | null;
      capabilityScopeMustIncludeSubject?: boolean;
      agentIdFromRequest?: boolean;
      expectedAgentId?: string | null;
      maxAgeSeconds?: number | null;
      allowUnresolvedKey?: boolean;
    } = {},
  ) {
    if (!permittedIssuers || permittedIssuers.length === 0) {
      throw new LocalChainError(
        "ChainAttestationPolicy.permittedIssuers must be non-empty — trusting any issuer by default " +
          "is not a fail-closed identity boundary",
      );
    }
    const agentIdFromRequest = opts.agentIdFromRequest ?? true;
    const expectedAgentId = opts.expectedAgentId ?? null;
    if (agentIdFromRequest && expectedAgentId !== null) {
      throw new LocalChainError("agentIdFromRequest and expectedAgentId are mutually exclusive");
    }
    this.permittedIssuers = permittedIssuers;
    this.requiredClass = opts.requiredClass ?? null;
    this.capabilityScopeMustIncludeSubject = opts.capabilityScopeMustIncludeSubject ?? true;
    this.agentIdFromRequest = agentIdFromRequest;
    this.expectedAgentId = expectedAgentId;
    this.maxAgeSeconds = opts.maxAgeSeconds ?? null;
    this.allowUnresolvedKey = opts.allowUnresolvedKey ?? false;
  }
}

/** The sanctioned API for a Chained Governed Autonomy v1 sequence — the
 * standalone-helper mirror of solo_builder.strix_wire_local_chain.ChainSession.
 *
 * There is no lower-level way to mint a valid local-receipt-v3 chain step:
 * receiptPath, previousStepEvidenceId/Hash, and stepIndex are all derived
 * from this session's own internal state, updated ONLY after a step's
 * receipt is actually minted. A denial or a failed operation leaves the
 * "last known good" pointer untouched, so a retried step reuses the same
 * predecessor and the same stepIndex. */
export class ChainSession {
  readonly chainId: string;
  private readonly workspaceRoot: string;
  private readonly stateDir: string;
  private readonly attestationPolicy: ChainAttestationPolicy | null;
  private readonly sameSigningKey: boolean;
  private readonly stepMaxAgeSeconds: number | null;

  private stepIndex = 0;
  private lastCapabilityId: string | null = null;
  private lastReceiptPath: string | null = null;
  private lastEvidenceId: string | null = null;
  private lastEvidenceHash: string | null = null;

  constructor(opts: {
    workspaceRoot: string;
    stateDir: string;
    attestationPolicy?: ChainAttestationPolicy | null;
    chainId?: string | null;
    sameSigningKey?: boolean;
    stepMaxAgeSeconds?: number | null;
  }) {
    this.chainId = opts.chainId ?? `local_chain_${crypto.randomBytes(16).toString("hex")}`;
    this.workspaceRoot = opts.workspaceRoot;
    this.stateDir = opts.stateDir;
    this.attestationPolicy = opts.attestationPolicy ?? null;
    this.sameSigningKey = opts.sameSigningKey ?? true;
    this.stepMaxAgeSeconds = opts.stepMaxAgeSeconds ?? null;
  }

  get nextStepIndex(): number {
    return this.stepIndex;
  }

  step<T>(
    capabilityId: string,
    actionName: string,
    params: Record<string, unknown>,
    operation: () => T,
    opts: {
      approvalGranted?: boolean;
      requestingAgentId?: string | null;
      attestationPath?: string | null;
      extraReliance?: RelianceRequirement[];
    } = {},
  ): LocalGovernedActionResult<T> {
    if (this.attestationPolicy !== null && !opts.attestationPath) {
      throw new LocalChainError(
        "this chain declares an attestationPolicy — every step must supply attestationPath (the " +
          "applicable agent attestation for THIS step); it cannot be silently skipped",
      );
    }
    if (this.attestationPolicy !== null && this.attestationPolicy.agentIdFromRequest && !opts.requestingAgentId) {
      throw new LocalChainError(
        "this chain's attestationPolicy binds agentIdFromRequest — every step must supply requestingAgentId",
      );
    }

    const relianceReqs: RelianceRequirement[] = [];
    if (this.stepIndex > 0) {
      if (this.lastCapabilityId === null || this.lastReceiptPath === null) {
        throw new LocalChainError("internal chain state inconsistency: no predecessor tracked past step 0");
      }
      relianceReqs.push({
        capabilityId: this.lastCapabilityId,
        receiptPath: this.lastReceiptPath,
        requirementId: "chain-predecessor",
        receiptType: RECORD_MODE,
        executionStatus: "SUCCEEDED",
        sameWorkspace: true,
        sameSigningKey: this.sameSigningKey,
        maxAgeSeconds: this.stepMaxAgeSeconds,
      });
    }
    if (this.attestationPolicy !== null) {
      relianceReqs.push({
        receiptPath: opts.attestationPath as string,
        requirementId: "chain-attestation",
        receiptType: ATTESTATION_RECORD_MODE,
        agentIdFromRequest: this.attestationPolicy.agentIdFromRequest,
        expectedAgentId: this.attestationPolicy.expectedAgentId,
        requiredClass: this.attestationPolicy.requiredClass,
        permittedIssuers: this.attestationPolicy.permittedIssuers,
        capabilityScopeMustIncludeSubject: this.attestationPolicy.capabilityScopeMustIncludeSubject,
        maxAgeSeconds: this.attestationPolicy.maxAgeSeconds,
        allowUnresolvedKey: this.attestationPolicy.allowUnresolvedKey,
      });
    }
    if (opts.extraReliance) relianceReqs.push(...opts.extraReliance);

    const chainStep: LocalChainStep = {
      chainId: this.chainId,
      stepIndex: this.stepIndex,
      previousEvidenceId: this.lastEvidenceId,
      previousEvidenceHash: this.lastEvidenceHash,
      attestationRequired: this.attestationPolicy !== null,
    };

    const result = governedActionLocal(capabilityId, actionName, params, operation, {
      approvalGranted: opts.approvalGranted ?? false,
      workspaceRoot: this.workspaceRoot,
      stateDir: this.stateDir,
      // undefined (not []) when there is nothing to require yet — step 0
      // of a chain with no attestationPolicy has no predecessor and no
      // identity check; evaluateRelianceLocal refuses an empty-requirement
      // array by construction.
      reliance: relianceReqs.length > 0 ? relianceReqs : undefined,
      requestingAgentId: opts.requestingAgentId ?? null,
      chainStep,
    });

    // Advance ONLY on success — a denial or a failed operation throws out
    // of governedActionLocal before this line.
    this.stepIndex += 1;
    this.lastCapabilityId = capabilityId;
    this.lastReceiptPath = result.receiptPath;
    this.lastEvidenceId = result.evidenceId;
    this.lastEvidenceHash = (result.record.payload as Record<string, unknown>).evidenceHash as string;
    return result;
  }
}

const STATUS_RANK: Record<string, number> = { VERIFIED: 0, UNVERIFIABLE: 1, INVALID: 2 };

/** Format a number array the way Python's f"{list}" does ("[0, 1, 2]",
 * comma-SPACE) — NOT JSON.stringify ("[0,1,2]", no space). Reason strings
 * embedding this must be byte-identical to the Python reference/helper. */
function pyListRepr(values: unknown[]): string {
  return `[${values.join(", ")}]`;
}

export interface LocalChainVerificationReport {
  ok: boolean;
  chainId: string | null;
  steps: number;
  stepsValid: number;
  sequenceLinked: boolean;
  verificationStatus: string;
  reason: string;
  results: Array<Record<string, unknown>>;
}

/** Independently re-verify an ORDERED sequence of local-receipt-v3 records
 * claiming membership in the same chain. Mirrors
 * solo_builder.strix_wire_local_chain.verify_local_chain — callers are
 * responsible for CURATING the sequence (every receipt under a
 * workspace's evidence directory whose chainRef.chainId matches the chain
 * of interest and whose executionStatus is SUCCEEDED, sorted by
 * chainRef.stepIndex).
 *
 * Checks: (1) every record independently verified via the EXISTING,
 * unchanged verifyLocalRecordForReliance — no new crypto path; (2) every
 * record declares schemaVersion local-receipt-v3 with a structured
 * chainRef; (3) chainId identical across every record; (4) stepIndex
 * dense and strictly monotonic starting at 0; (5) for every record at
 * stepIndex > 0, chainRef.previousStepEvidenceId/Hash equal the ACTUAL
 * evidenceId/evidenceHash of the record at stepIndex - 1, byte-for-byte.
 * Worst-of roll-up: the overall verificationStatus is the worst
 * individual record status. */
export function verifyLocalChain(
  records: Array<Record<string, unknown>>,
  stateDir: string,
): LocalChainVerificationReport {
  if (records.length === 0) {
    return {
      ok: false,
      chainId: null,
      steps: 0,
      stepsValid: 0,
      sequenceLinked: false,
      verificationStatus: "UNVERIFIABLE",
      reason: "EMPTY_CHAIN: no records presented",
      results: [],
    };
  }

  const results: Array<Record<string, unknown>> = [];
  const chainIds = new Set<unknown>();
  const seenStepIndices: unknown[] = [];
  let sequenceLinked = true;
  let worstStatus = "VERIFIED";
  let stepsValid = 0;
  const reasons: string[] = [];

  let prevEvidenceId: unknown = null;
  let prevEvidenceHash: unknown = null;

  records.forEach((record, idx) => {
    const cryptoResult = verifyLocalRecordForReliance(record, stateDir);
    const payload = (record.payload && typeof record.payload === "object" ? record.payload : {}) as Record<
      string,
      unknown
    >;
    const chainRef =
      payload.chainRef && typeof payload.chainRef === "object" && !Array.isArray(payload.chainRef)
        ? (payload.chainRef as Record<string, unknown>)
        : null;

    let stepOk = cryptoResult.status === "VERIFIED";
    const stepReasonParts: string[] = [];

    if (payload.schemaVersion !== SCHEMA_VERSION_V3 || chainRef === null) {
      stepOk = false;
      sequenceLinked = false;
      stepReasonParts.push(`record at index ${idx} is not a local-receipt-v3 chain step (missing/wrong chainRef)`);
    } else {
      chainIds.add(chainRef.chainId);
      seenStepIndices.push(chainRef.stepIndex);
      const claimedPrevId = chainRef.previousStepEvidenceId ?? null;
      const claimedPrevHash = chainRef.previousStepEvidenceHash ?? null;
      if (idx === 0) {
        if (claimedPrevId !== null || claimedPrevHash !== null) {
          stepOk = false;
          sequenceLinked = false;
          stepReasonParts.push("first record in the set claims a predecessor");
        }
      } else if (claimedPrevId !== prevEvidenceId || claimedPrevHash !== prevEvidenceHash) {
        stepOk = false;
        sequenceLinked = false;
        stepReasonParts.push(
          `record at index ${idx} claims a predecessor that does not match the actual prior record in this set`,
        );
      }
      prevEvidenceId = payload.evidenceId ?? null;
      prevEvidenceHash = payload.evidenceHash ?? null;
    }

    const entry: Record<string, unknown> = {
      index: idx,
      evidenceId: payload.evidenceId ?? null,
      verification: cryptoResult,
      chainRef,
      stepOk,
    };
    if (stepReasonParts.length > 0) entry.reason = stepReasonParts.join("; ");
    results.push(entry);

    if (stepOk) stepsValid += 1;
    const rank = STATUS_RANK[cryptoResult.status] ?? 2;
    if (rank > STATUS_RANK[worstStatus]) worstStatus = cryptoResult.status;
    if (!stepOk && stepReasonParts.length === 0) {
      reasons.push(`index ${idx}: ${cryptoResult.cryptoCode}`);
    } else if (stepReasonParts.length > 0) {
      reasons.push(`index ${idx}: ${stepReasonParts.join("; ")}`);
    }
  });

  if (chainIds.size > 1) {
    sequenceLinked = false;
    reasons.push(`records claim ${chainIds.size} distinct chainIds — not one chain`);
  }
  const expectedIndices = records.map((_, i) => i);
  if (JSON.stringify(seenStepIndices) !== JSON.stringify(expectedIndices)) {
    sequenceLinked = false;
    // pyListRepr, not JSON.stringify: the reason string must be
    // byte-identical to the Python reference/helper's f"{list}"
    // formatting ("[0, 1]", comma-SPACE) — reason text is part of the
    // contract (see the golden-vector corpus's scoping note).
    reasons.push(
      `stepIndex sequence ${pyListRepr(seenStepIndices)} is not dense/strictly-monotonic from 0 ` +
        `(expected ${pyListRepr(expectedIndices)})`,
    );
  }

  const ok = sequenceLinked && stepsValid === records.length && worstStatus === "VERIFIED";
  const reason = ok
    ? "ALL_STEPS_VERIFIED_AND_LINKED: every record verified and the sequence is intact"
    : reasons.length > 0
      ? reasons.join(" | ")
      : "one or more steps failed verification";

  return {
    ok,
    chainId: chainIds.size === 1 ? (Array.from(chainIds)[0] as string) : null,
    steps: records.length,
    stepsValid,
    sequenceLinked,
    verificationStatus: worstStatus,
    reason,
    results,
  };
}

// ──────────────────────────────────────────────────────────────────────
// Chained Governed Autonomy v2 — DagSession + verifyLocalDag
// ──────────────────────────────────────────────────────────────────────

export class DagSessionError extends StrixLocalError {}

/** The sanctioned API for a Chained Governed Autonomy v2 DAG — the
 * standalone-helper mirror of solo_builder.strix_wire_local_dag.DagSession.
 *
 * There is no lower-level way to mint a valid local-receipt-v4 DAG node:
 * every declared parent must be an evidence id this session has itself
 * already produced, duplicates are rejected, and stepIndex is this
 * session's own creation-order counter — none of these are
 * caller-suppliable. A denial or a failed operation leaves the tracked
 * node dict and step counter untouched, so a retried step reuses the
 * same stepIndex and the same declared parent set. */
export class DagSession {
  readonly dagId: string;
  private readonly workspaceRoot: string;
  private readonly stateDir: string;
  private readonly attestationPolicy: ChainAttestationPolicy | null;
  private readonly sameSigningKey: boolean;
  private readonly stepMaxAgeSeconds: number | null;

  private stepIndex = 0;
  // evidenceId -> [receiptPath, capabilityId]
  private nodes = new Map<string, [string, string]>();

  constructor(opts: {
    workspaceRoot: string;
    stateDir: string;
    attestationPolicy?: ChainAttestationPolicy | null;
    dagId?: string | null;
    sameSigningKey?: boolean;
    stepMaxAgeSeconds?: number | null;
  }) {
    this.dagId = opts.dagId ?? `local_dag_${crypto.randomBytes(16).toString("hex")}`;
    this.workspaceRoot = opts.workspaceRoot;
    this.stateDir = opts.stateDir;
    this.attestationPolicy = opts.attestationPolicy ?? null;
    this.sameSigningKey = opts.sameSigningKey ?? true;
    this.stepMaxAgeSeconds = opts.stepMaxAgeSeconds ?? null;
  }

  get nextStepIndex(): number {
    return this.stepIndex;
  }

  step<T>(
    capabilityId: string,
    actionName: string,
    params: Record<string, unknown>,
    operation: () => T,
    opts: {
      parentEvidenceIds?: string[];
      approvalGranted?: boolean;
      requestingAgentId?: string | null;
      attestationPath?: string | null;
      extraReliance?: RelianceRequirement[];
    } = {},
  ): LocalGovernedActionResult<T> {
    const parentIds = opts.parentEvidenceIds ?? [];

    if (new Set(parentIds).size !== parentIds.length) {
      throw new DagSessionError(
        "parentEvidenceIds contains a duplicate — a DAG step cannot depend on the same parent twice",
      );
    }
    const unknown = parentIds.filter((pid) => !this.nodes.has(pid));
    if (unknown.length > 0) {
      throw new DagSessionError(
        `parentEvidenceIds references evidence id(s) ${JSON.stringify(unknown)} that this DagSession ` +
          "has not itself produced — a step's declared parents must all originate from a prior, " +
          "successful .step() call on this SAME session",
      );
    }

    if (this.attestationPolicy !== null && !opts.attestationPath) {
      throw new DagSessionError(
        "this DAG declares an attestationPolicy — every step must supply attestationPath (the " +
          "applicable agent attestation for THIS step); it cannot be silently skipped",
      );
    }
    if (this.attestationPolicy !== null && this.attestationPolicy.agentIdFromRequest && !opts.requestingAgentId) {
      throw new DagSessionError(
        "this DAG's attestationPolicy binds agentIdFromRequest — every step must supply requestingAgentId",
      );
    }

    const relianceReqs: RelianceRequirement[] = [];
    parentIds.forEach((parentId, i) => {
      const [receiptPath, parentCapabilityId] = this.nodes.get(parentId) as [string, string];
      relianceReqs.push({
        capabilityId: parentCapabilityId,
        receiptPath,
        requirementId: `dag-parent-${i}`,
        receiptType: RECORD_MODE,
        executionStatus: "SUCCEEDED",
        sameWorkspace: true,
        sameSigningKey: this.sameSigningKey,
        maxAgeSeconds: this.stepMaxAgeSeconds,
      });
    });
    if (this.attestationPolicy !== null) {
      relianceReqs.push({
        receiptPath: opts.attestationPath as string,
        requirementId: "dag-attestation",
        receiptType: ATTESTATION_RECORD_MODE,
        agentIdFromRequest: this.attestationPolicy.agentIdFromRequest,
        expectedAgentId: this.attestationPolicy.expectedAgentId,
        requiredClass: this.attestationPolicy.requiredClass,
        permittedIssuers: this.attestationPolicy.permittedIssuers,
        capabilityScopeMustIncludeSubject: this.attestationPolicy.capabilityScopeMustIncludeSubject,
        maxAgeSeconds: this.attestationPolicy.maxAgeSeconds,
        allowUnresolvedKey: this.attestationPolicy.allowUnresolvedKey,
      });
    }
    if (opts.extraReliance) relianceReqs.push(...opts.extraReliance);

    const dagStep: LocalDagStep = {
      dagId: this.dagId,
      stepIndex: this.stepIndex,
      parentEvidenceIds: parentIds,
      attestationRequired: this.attestationPolicy !== null,
    };

    const result = governedActionLocal(capabilityId, actionName, params, operation, {
      approvalGranted: opts.approvalGranted ?? false,
      workspaceRoot: this.workspaceRoot,
      stateDir: this.stateDir,
      // undefined (not []) when there is nothing to require yet — a
      // source node with no attestationPolicy has no parents and no
      // identity check; evaluateRelianceLocal refuses an
      // empty-requirement array by construction.
      reliance: relianceReqs.length > 0 ? relianceReqs : undefined,
      requestingAgentId: opts.requestingAgentId ?? null,
      dagStep,
    });

    // Advance ONLY on success — a denial or a failed operation throws out
    // of governedActionLocal before this line.
    this.nodes.set(result.evidenceId, [result.receiptPath, capabilityId]);
    this.stepIndex += 1;
    return result;
  }
}

export interface LocalDagVerificationReport {
  ok: boolean;
  dagId: string | null;
  nodes: number;
  nodesValid: number;
  graphLinked: boolean;
  verificationStatus: string;
  reason: string;
  results: Array<Record<string, unknown>>;
}

/** Independently re-verify a curated set of local-receipt-v4 records
 * claiming membership in the same DAG. Mirrors
 * solo_builder.strix_wire_local_dag.verify_local_dag — callers are
 * responsible for CURATING the set (every receipt under a workspace's
 * evidence directory whose dagRef.dagId matches the DAG of interest and
 * whose executionStatus is SUCCEEDED).
 *
 * Presentation order carries no meaning here (a DAG has no single "next"
 * record) — every check resolves cross-record references by
 * evidenceId/stepIndex VALUE, never by list position (a deliberate
 * difference from verifyLocalChain's linear chain, where order IS part
 * of the claim).
 *
 * Checks: (1) every record independently verified via the EXISTING,
 * unchanged verifyLocalRecordForReliance — no new crypto path; (2) every
 * record declares schemaVersion local-receipt-v4 with a well-formed
 * dagRef; (3) an index evidenceId -> (stepIndex, evidenceHash, dagId) is
 * built from records passing check 2 — a second record claiming an
 * evidenceId already seen is a DUPLICATE NODE IDENTITY, flagged rather
 * than silently overwritten; (3.5) any record whose OWN evidenceId is
 * duplicated in the curated set is invalid (ambiguous node identity),
 * and any record declaring a parent whose evidenceId is duplicated
 * fails closed (an ambiguous parent can never be resolved to a specific
 * evidenceHash/stepIndex — it is never treated as "whichever one was
 * seen last"; this is what makes order-independence, check 6, safe);
 * (4) dagId identical across every record; (5) stepIndex values are a
 * set of distinct non-negative integers, dense from 0; (6) every
 * parentEvidenceRefs entry must have an evidenceId present in the index
 * and NOT duplicated, match its actual evidenceHash exactly, and have a
 * stepIndex strictly less than the referencing record's own (the
 * cycle-exclusion rule). Worst-of roll-up: the overall
 * verificationStatus is the worst individual record status.
 *
 * What this does NOT prove: that the curated set is the DAG's complete
 * history — same honesty boundary as verifyLocalChain. */
export function verifyLocalDag(records: Array<Record<string, unknown>>, stateDir: string): LocalDagVerificationReport {
  if (records.length === 0) {
    return {
      ok: false,
      dagId: null,
      nodes: 0,
      nodesValid: 0,
      graphLinked: false,
      verificationStatus: "UNVERIFIABLE",
      reason: "EMPTY_DAG: no records presented",
      results: [],
    };
  }

  const cryptoResults: Array<Record<string, unknown>> = [];
  const payloads: Array<Record<string, unknown>> = [];
  const schemaOkFlags: boolean[] = [];
  const index = new Map<string, [number, unknown, unknown]>();
  // A record's evidenceId is supposed to be globally unique (uuid-generated
  // at mint time) — two records sharing one in the curated set is either a
  // curation bug or an adversarial splice, and letting the LAST one silently
  // win the index would make parent-resolution dependent on incidental list
  // order/duplication, exactly the property this whole verifier exists to
  // NOT have (see CGA2-14). Track collisions so BOTH records, and anyone
  // referencing the ambiguous id as a parent, fail closed rather than
  // resolving to an arbitrary winner.
  const duplicateEvidenceIds = new Set<string>();

  for (const record of records) {
    const cryptoResult = verifyLocalRecordForReliance(record, stateDir);
    const payload = (record.payload && typeof record.payload === "object" ? record.payload : {}) as Record<
      string,
      unknown
    >;
    const dagRef = payload.dagRef;
    const schemaOk = payload.schemaVersion === SCHEMA_VERSION_V4 && dagRefShapeValid(dagRef);

    cryptoResults.push(cryptoResult);
    payloads.push(payload);
    schemaOkFlags.push(schemaOk);

    if (schemaOk) {
      const ref = dagRef as Record<string, unknown>;
      const evidenceId = payload.evidenceId;
      if (typeof evidenceId === "string") {
        if (index.has(evidenceId)) {
          duplicateEvidenceIds.add(evidenceId);
        }
        index.set(evidenceId, [ref.stepIndex as number, payload.evidenceHash, ref.dagId]);
      }
    }
  }

  const results: Array<Record<string, unknown>> = [];
  const dagIds = new Set<unknown>();
  const stepIndices: unknown[] = [];
  let worstStatus = "VERIFIED";
  let nodesValid = 0;
  let graphLinked = true;
  const reasons: string[] = [];

  for (let idx = 0; idx < records.length; idx += 1) {
    const cryptoResult = cryptoResults[idx];
    const payload = payloads[idx];
    const schemaOk = schemaOkFlags[idx];
    const dagRef = schemaOk ? (payload.dagRef as Record<string, unknown>) : null;

    let nodeOk = cryptoResult.status === "VERIFIED";
    const reasonParts: string[] = [];

    if (!schemaOk) {
      nodeOk = false;
      graphLinked = false;
      reasonParts.push(`record at index ${idx} is not a local-receipt-v4 DAG node (missing/malformed dagRef)`);
    } else {
      dagIds.add(dagRef!.dagId);
      stepIndices.push(dagRef!.stepIndex);
      const ownEvidenceId = payload.evidenceId;
      if (typeof ownEvidenceId === "string" && duplicateEvidenceIds.has(ownEvidenceId)) {
        nodeOk = false;
        graphLinked = false;
        reasonParts.push(
          `record at index ${idx} has evidenceId '${ownEvidenceId}' which appears on more than one ` +
            "record in the curated set — ambiguous node identity",
        );
      }
      const parentRefs = dagRef!.parentEvidenceRefs as Array<Record<string, unknown>>;
      parentRefs.forEach((parentRef, parentPosition) => {
        const parentId = parentRef.evidenceId as string;
        if (duplicateEvidenceIds.has(parentId)) {
          nodeOk = false;
          graphLinked = false;
          reasonParts.push(
            `record at index ${idx} declares parent '${parentId}' (position ${parentPosition}) whose ` +
              "evidenceId is ambiguous — it appears on more than one record in the curated set, so it " +
              "cannot be resolved",
          );
          return;
        }
        const parentEntry = index.get(parentId);
        if (!parentEntry) {
          nodeOk = false;
          graphLinked = false;
          reasonParts.push(
            `record at index ${idx} declares parent '${parentId}' (position ${parentPosition}) that ` +
              "is not present in the curated set",
          );
          return;
        }
        const [parentStepIndex, parentEvidenceHash] = parentEntry;
        if (parentRef.evidenceHash !== parentEvidenceHash) {
          nodeOk = false;
          graphLinked = false;
          reasonParts.push(
            `record at index ${idx} declares parent '${parentId}' with an evidenceHash that does ` +
              "not match that parent's actual evidenceHash in the curated set",
          );
        }
        if (typeof parentStepIndex !== "number" || parentStepIndex >= (dagRef!.stepIndex as number)) {
          nodeOk = false;
          graphLinked = false;
          reasonParts.push(
            `record at index ${idx} declares parent '${parentId}' whose stepIndex does not precede ` +
              "this record's own stepIndex — a cycle or a fabricated stepIndex",
          );
        }
      });
    }

    const entry: Record<string, unknown> = {
      index: idx,
      evidenceId: payload.evidenceId ?? null,
      dagRef,
      verification: cryptoResult,
      nodeOk,
    };
    if (reasonParts.length > 0) entry.reason = reasonParts.join("; ");
    results.push(entry);

    if (nodeOk) nodesValid += 1;
    const rank = STATUS_RANK[cryptoResult.status as string] ?? 2;
    if (rank > STATUS_RANK[worstStatus]) worstStatus = cryptoResult.status as string;
    if (!nodeOk) {
      reasons.push(
        reasonParts.length > 0 ? `index ${idx}: ${reasonParts.join("; ")}` : `index ${idx}: ${cryptoResult.cryptoCode}`,
      );
    }
  }

  if (dagIds.size > 1) {
    graphLinked = false;
    reasons.push(`records claim ${dagIds.size} distinct dagIds — not one DAG`);
  }
  const expectedIndices = records.map((_, i) => i);
  const sortedStepIndices = [...stepIndices].sort((a, b) => (a as number) - (b as number));
  if (JSON.stringify(sortedStepIndices) !== JSON.stringify(expectedIndices)) {
    graphLinked = false;
    // pyListRepr, not JSON.stringify: the reason string must be
    // byte-identical to the Python reference/helper's f"{list}"
    // formatting ("[0, 1]", comma-SPACE) — reason text is part of the
    // contract.
    reasons.push(
      `stepIndex set ${pyListRepr(sortedStepIndices)} is not dense/distinct from 0 (expected ` +
        `${pyListRepr(expectedIndices)})`,
    );
  }

  const ok = graphLinked && nodesValid === records.length && worstStatus === "VERIFIED";
  const reason = ok
    ? "ALL_NODES_VERIFIED_AND_LINKED: every record verified and the DAG is intact"
    : reasons.length > 0
      ? reasons.join(" | ")
      : "one or more nodes failed verification";

  return {
    ok,
    dagId: dagIds.size === 1 ? (Array.from(dagIds)[0] as string) : null,
    nodes: records.length,
    nodesValid,
    graphLinked,
    verificationStatus: worstStatus,
    reason,
    results,
  };
}
