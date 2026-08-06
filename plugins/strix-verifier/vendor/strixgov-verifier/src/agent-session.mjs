/**
 * Governed agent navigation session verification (agent_navigation_evidence_v1
 * + run_commitment_v1 with runKind "agent_session") — the INDEPENDENT
 * re-derivation path.
 *
 * Zero shared code with the producer
 * (`solo-builder-core/src/agent-navigation-evidence-v1.ts`): this module
 * re-implements the SCJ-v1-compatible canonicalization, the per-event
 * content addressing, the chain walk, and the RFC 6962 §2.1 Merkle root
 * from scratch using only node:crypto. Drift between the two
 * implementations is caught by replaying the producer's locked golden
 * vectors in test/agent-session.test.mjs (the conformance-program
 * discipline). Only JWKS key SELECTION is shared with index.mjs — key
 * distribution is not part of the byte contract.
 *
 * WHAT A VERIFIED VERDICT MEANS — AND WHAT IT DOES NOT
 * ---------------------------------------------------
 * VERIFIED says: these navigation events, in this order, are the ones
 * sealed under this signed session root, and none of them has been edited,
 * removed, reordered, or inserted since.
 *
 * It does NOT say the agent recorded everything it did (completeness is
 * "NOT_PROVEN" on every result — an unrecorded action leaves no trace to
 * detect), and it does NOT say the review's findings, severities, or
 * recommendations are correct (`provesReviewCorrectness` is structurally
 * false). Findings are re-checked for BINDING only, and findings never
 * change the session verdict.
 *
 * Honesty rules (mirroring the producer contract, re-derived not imported):
 *  - NAV-1  a chain with no signed commitment is never VERIFIED.
 *  - NAV-3  completeness is always "NOT_PROVEN".
 *  - NAV-4  provesReviewCorrectness is always false.
 *  - NAV-6  worst-of roll-up; never averaged, never one green badge.
 *  - NAV-7  an unresolvable commitment key → UNVERIFIABLE, never INVALID;
 *           a broken chain or a root mismatch → INVALID regardless of
 *           whether a key was supplied.
 */

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { resolveJwksByKid } from "./index.mjs";

const HEX64 = /^[0-9a-f]{64}$/;

const AGENT_SESSION_RUN_KIND = "agent_session";
const AGENT_NAVIGATION_SCHEMA_VERSION = 1;

const NAVIGATION_ACTIONS = Object.freeze([
  "SESSION_START",
  "LOGIN",
  "OPEN_SCREEN",
  "TAP",
  "INPUT",
  "SUBMIT",
  "SCROLL",
  "NAVIGATE_BACK",
  "CAPTURE_SCREENSHOT",
  "LOGOUT",
  "SESSION_END",
]);

export const AGENT_SESSION_REASONS = Object.freeze({
  OK: "NAV_OK",
  NO_EVENTS: "NAV_NO_EVENTS",
  SCHEMA_INVALID: "NAV_SCHEMA_INVALID",
  EVENT_HASH_MISMATCH: "NAV_EVENT_HASH_MISMATCH",
  SESSION_ID_MISMATCH: "NAV_SESSION_ID_MISMATCH",
  SESSION_SCOPE_MISMATCH: "NAV_SESSION_SCOPE_MISMATCH",
  STEP_INDEX_BROKEN: "NAV_STEP_INDEX_BROKEN",
  CHAIN_LINK_BROKEN: "NAV_CHAIN_LINK_BROKEN",
  TIMESTAMP_NOT_MONOTONIC: "NAV_TIMESTAMP_NOT_MONOTONIC",
  COMMITMENT_ABSENT: "NAV_COMMITMENT_ABSENT",
  COMMITMENT_RUN_KIND_MISMATCH: "NAV_COMMITMENT_RUN_KIND_MISMATCH",
  COMMITMENT_SESSION_MISMATCH: "NAV_COMMITMENT_SESSION_MISMATCH",
  COMMITMENT_SCOPE_MISMATCH: "NAV_COMMITMENT_SCOPE_MISMATCH",
  LEAF_COUNT_MISMATCH: "NAV_LEAF_COUNT_MISMATCH",
  ROOT_MISMATCH: "NAV_ROOT_MISMATCH",
  COMMITMENT_KEY_UNRESOLVED: "NAV_COMMITMENT_KEY_UNRESOLVED",
  COMMITMENT_SIGNATURE_INVALID: "NAV_COMMITMENT_SIGNATURE_INVALID",
});

export const FINDING_BINDING_REASONS = Object.freeze({
  OK: "FND_OK",
  NO_FINDINGS: "FND_NONE_PRESENTED",
  SCHEMA_INVALID: "FND_SCHEMA_INVALID",
  UNBOUND_EVENT: "FND_UNBOUND_EVENT",
  SCREEN_MISMATCH: "FND_SCREEN_MISMATCH",
  SCREENSHOT_MISMATCH: "FND_SCREENSHOT_MISMATCH",
  ROOT_MISMATCH: "FND_ROOT_MISMATCH",
  SESSION_MISMATCH: "FND_SESSION_MISMATCH",
  DUPLICATE_ID: "FND_DUPLICATE_ID",
});

// ── Own canonicalization (SCJ-v1-compatible; independently implemented) ──

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

function sha256Hex(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// ── Own RFC 6962 §2.1 Merkle root (leaf 0x00 / node 0x01) ──────────────

function hashBytes(...parts) {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

function leafNode(leafHex) {
  return hashBytes(Buffer.from([0x00]), Buffer.from(leafHex, "hex"));
}

function largestPowerOfTwoBelow(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function merkleRoot(nodes) {
  if (nodes.length === 1) return nodes[0];
  const k = largestPowerOfTwoBelow(nodes.length);
  return hashBytes(
    Buffer.from([0x01]),
    merkleRoot(nodes.slice(0, k)),
    merkleRoot(nodes.slice(k)),
  );
}

/** Independently compute the RFC 6962 root over ordered 64-hex leaves. */
export function computeSessionRoot(leaves) {
  if (!Array.isArray(leaves) || leaves.length === 0) return null;
  if (leaves.some((l) => typeof l !== "string" || !HEX64.test(l))) return null;
  return merkleRoot(leaves.map(leafNode)).toString("hex");
}

// ── Strict RFC 3339 (independently implemented) ────────────────────────

const RFC3339 =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function isStrictRfc3339(value) {
  if (typeof value !== "string" || !RFC3339.test(value)) return false;
  return Number.isFinite(Date.parse(value));
}

// ── Verdict algebra (NAV-6) ───────────────────────────────────────────

const RANK = { VERIFIED: 0, UNVERIFIABLE: 1, INVALID: 2 };

function worstOf(a, b) {
  return RANK[a] >= RANK[b] ? a : b;
}

function dedupe(values) {
  return [...new Set(values)];
}

// ── Chain structure ───────────────────────────────────────────────────

function checkChain(events) {
  const reasons = [];
  let broken = false;

  if (!Array.isArray(events) || events.length === 0) {
    return { broken: true, reasons: [AGENT_SESSION_REASONS.NO_EVENTS], chainHead: null };
  }

  const first = events[0];
  if (!first || typeof first !== "object" || !first.payload || typeof first.payload !== "object") {
    return { broken: true, reasons: [AGENT_SESSION_REASONS.SCHEMA_INVALID], chainHead: null };
  }
  const scope = {
    sessionId: first.payload.sessionId,
    tenantId: first.payload.tenantId,
    environment: first.payload.environment,
    capabilityId: first.payload.capabilityId,
  };

  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (!e || typeof e !== "object" || !e.payload || typeof e.eventHash !== "string") {
      reasons.push(AGENT_SESSION_REASONS.SCHEMA_INVALID);
      broken = true;
      continue;
    }
    const p = e.payload;

    if (p.schemaVersion !== AGENT_NAVIGATION_SCHEMA_VERSION) {
      reasons.push(AGENT_SESSION_REASONS.SCHEMA_INVALID);
      broken = true;
    }
    if (!NAVIGATION_ACTIONS.includes(p.action)) {
      reasons.push(AGENT_SESSION_REASONS.SCHEMA_INVALID);
      broken = true;
    }
    if (p.screenshotHash !== null && !HEX64.test(String(p.screenshotHash))) {
      reasons.push(AGENT_SESSION_REASONS.SCHEMA_INVALID);
      broken = true;
    }
    if (!isStrictRfc3339(p.occurredAt)) {
      reasons.push(AGENT_SESSION_REASONS.SCHEMA_INVALID);
      broken = true;
    }

    // Re-derive the content address from the payload's canonical bytes.
    let derived = null;
    try {
      derived = sha256Hex(canonicalize(p));
    } catch {
      derived = null;
    }
    if (derived === null || derived !== e.eventHash) {
      reasons.push(AGENT_SESSION_REASONS.EVENT_HASH_MISMATCH);
      broken = true;
    }

    if (p.sessionId !== scope.sessionId) {
      reasons.push(AGENT_SESSION_REASONS.SESSION_ID_MISMATCH);
      broken = true;
    }
    // agentId may legitimately vary across a session (multi-agent handoff).
    if (
      p.tenantId !== scope.tenantId ||
      p.environment !== scope.environment ||
      p.capabilityId !== scope.capabilityId
    ) {
      reasons.push(AGENT_SESSION_REASONS.SESSION_SCOPE_MISMATCH);
      broken = true;
    }

    if (p.stepIndex !== i) {
      reasons.push(AGENT_SESSION_REASONS.STEP_INDEX_BROKEN);
      broken = true;
    }

    const expectedPrev = i === 0 ? null : events[i - 1].eventHash;
    if (p.previousEventHash !== expectedPrev) {
      reasons.push(AGENT_SESSION_REASONS.CHAIN_LINK_BROKEN);
      broken = true;
    }

    if (
      i > 0 &&
      isStrictRfc3339(p.occurredAt) &&
      isStrictRfc3339(events[i - 1]?.payload?.occurredAt) &&
      p.occurredAt < events[i - 1].payload.occurredAt
    ) {
      reasons.push(AGENT_SESSION_REASONS.TIMESTAMP_NOT_MONOTONIC);
      broken = true;
    }
  }

  return {
    broken,
    reasons: dedupe(reasons),
    chainHead: events[events.length - 1]?.eventHash ?? null,
  };
}

// ── Finding binding (never affects the session verdict — NAV/FND-6) ────

function checkFindings(findings, events, rootHash, sessionId) {
  if (findings === undefined || findings === null) {
    return { verdict: "VERIFIED", reasons: [FINDING_BINDING_REASONS.NO_FINDINGS], perFinding: [] };
  }
  if (!Array.isArray(findings)) {
    return { verdict: "INVALID", reasons: [FINDING_BINDING_REASONS.SCHEMA_INVALID], perFinding: [] };
  }
  if (findings.length === 0) {
    return { verdict: "VERIFIED", reasons: [FINDING_BINDING_REASONS.NO_FINDINGS], perFinding: [] };
  }

  const byHash = new Map();
  for (const e of events ?? []) {
    if (e && typeof e.eventHash === "string") byHash.set(e.eventHash, e);
  }

  const seen = new Set();
  const perFinding = [];
  let verdict = "VERIFIED";
  const reasons = [];

  for (const f of findings) {
    const id = f && typeof f.findingId === "string" ? f.findingId : "(unnamed)";
    let reason = FINDING_BINDING_REASONS.OK;

    if (!f || typeof f !== "object" || typeof f.observedEventHash !== "string") {
      reason = FINDING_BINDING_REASONS.SCHEMA_INVALID;
    } else if (seen.has(id)) {
      reason = FINDING_BINDING_REASONS.DUPLICATE_ID;
    } else if (f.sessionRootHash !== rootHash) {
      reason = FINDING_BINDING_REASONS.ROOT_MISMATCH;
    } else if (f.sessionId !== sessionId) {
      reason = FINDING_BINDING_REASONS.SESSION_MISMATCH;
    } else if (!byHash.has(f.observedEventHash)) {
      reason = FINDING_BINDING_REASONS.UNBOUND_EVENT;
    } else {
      const observed = byHash.get(f.observedEventHash).payload;
      if (f.screen !== observed.screen) reason = FINDING_BINDING_REASONS.SCREEN_MISMATCH;
      else if ((f.screenshotHash ?? null) !== (observed.screenshotHash ?? null)) {
        reason = FINDING_BINDING_REASONS.SCREENSHOT_MISMATCH;
      }
    }

    seen.add(id);
    const fv = reason === FINDING_BINDING_REASONS.OK ? "VERIFIED" : "INVALID";
    verdict = worstOf(verdict, fv);
    if (reason !== FINDING_BINDING_REASONS.OK) reasons.push(reason);
    perFinding.push({ findingId: id, verdict: fv, reason });
  }

  return {
    verdict,
    reasons: dedupe(reasons.length ? reasons : [FINDING_BINDING_REASONS.OK]),
    perFinding,
  };
}

// ── Commitment signature ──────────────────────────────────────────────

function jwkToKey(jwk) {
  try {
    return createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    return null;
  }
}

function verifyCommitmentSignature(commitment, jwks) {
  const candidates = jwks ? resolveJwksByKid(commitment.signingKeyId, jwks) : [];
  if (!candidates || candidates.length === 0) return "KEY_UNKNOWN";
  let canonical;
  try {
    canonical = canonicalize(commitment.payload);
  } catch {
    return false;
  }
  for (const jwk of candidates) {
    const key = jwkToKey(jwk);
    if (!key) continue;
    try {
      if (
        cryptoVerify(
          null,
          Buffer.from(canonical, "utf8"),
          key,
          Buffer.from(commitment.signature, "base64"),
        )
      ) {
        return true;
      }
    } catch {
      /* try the next candidate */
    }
  }
  return false;
}

// ── Public entry point ────────────────────────────────────────────────

/**
 * Verify an agent-session bundle.
 *
 * @param {object} bundle  { bundleVersion, commitment, events, findings? }
 * @param {object} [opts]  { jwks } — omit to cap the verdict at UNVERIFIABLE.
 */
export function verifyAgentSessionBundle(bundle, opts = {}) {
  const jwks = opts.jwks ?? null;

  const base = {
    completeness: "NOT_PROVEN",
    provesReviewCorrectness: false,
  };

  if (!bundle || typeof bundle !== "object" || bundle.bundleVersion !== 1) {
    return {
      verdict: "INVALID",
      reasons: [AGENT_SESSION_REASONS.SCHEMA_INVALID],
      ...base,
      integrityAnchoredBy: "NONE",
      eventCount: 0,
      chainHead: null,
      findingsBinding: { verdict: "INVALID", reasons: [FINDING_BINDING_REASONS.SCHEMA_INVALID], perFinding: [] },
    };
  }

  const events = bundle.events;
  const commitment = bundle.commitment;
  const chain = checkChain(events);
  const reasons = [...chain.reasons];
  let verdict = chain.broken ? "INVALID" : "VERIFIED";

  const payload =
    commitment && typeof commitment === "object" && commitment.payload &&
    typeof commitment.payload === "object"
      ? commitment.payload
      : null;

  if (!payload || typeof commitment.signature !== "string") {
    return {
      verdict: "INVALID",
      reasons: dedupe([...reasons, AGENT_SESSION_REASONS.SCHEMA_INVALID]),
      ...base,
      integrityAnchoredBy: "NONE",
      eventCount: Array.isArray(events) ? events.length : 0,
      chainHead: chain.chainHead,
      findingsBinding: checkFindings(bundle.findings, events, null, null),
    };
  }

  if (payload.runKind !== AGENT_SESSION_RUN_KIND) {
    reasons.push(AGENT_SESSION_REASONS.COMMITMENT_RUN_KIND_MISMATCH);
    verdict = "INVALID";
  }

  const firstPayload = Array.isArray(events) ? events[0]?.payload : undefined;
  if (firstPayload) {
    if (payload.runId !== firstPayload.sessionId) {
      reasons.push(AGENT_SESSION_REASONS.COMMITMENT_SESSION_MISMATCH);
      verdict = "INVALID";
    }
    if (
      payload.tenantId !== firstPayload.tenantId ||
      payload.environment !== firstPayload.environment
    ) {
      reasons.push(AGENT_SESSION_REASONS.COMMITMENT_SCOPE_MISMATCH);
      verdict = "INVALID";
    }
  }

  // Binds the session LENGTH: trailing truncation is caught here even
  // though the shortened chain is internally consistent.
  if (payload.leafCount !== (Array.isArray(events) ? events.length : 0)) {
    reasons.push(AGENT_SESSION_REASONS.LEAF_COUNT_MISMATCH);
    verdict = "INVALID";
  }

  // Re-derive the root from the presented events; never trust the stored one.
  if (Array.isArray(events) && events.length > 0) {
    const derivedRoot = computeSessionRoot(events.map((e) => e?.eventHash));
    if (derivedRoot === null) {
      reasons.push(AGENT_SESSION_REASONS.SCHEMA_INVALID);
      verdict = "INVALID";
    } else if (derivedRoot !== payload.rootHash) {
      reasons.push(AGENT_SESSION_REASONS.ROOT_MISMATCH);
      verdict = "INVALID";
    }
  }

  // Signature LAST — a structural failure above already stands alone (NAV-7).
  const sigOutcome = verifyCommitmentSignature(commitment, jwks);
  if (sigOutcome === "KEY_UNKNOWN") {
    reasons.push(AGENT_SESSION_REASONS.COMMITMENT_KEY_UNRESOLVED);
    verdict = worstOf(verdict, "UNVERIFIABLE");
  } else if (sigOutcome === false) {
    reasons.push(AGENT_SESSION_REASONS.COMMITMENT_SIGNATURE_INVALID);
    verdict = "INVALID";
  }

  const findingsBinding = checkFindings(
    bundle.findings,
    events,
    payload.rootHash,
    firstPayload?.sessionId ?? null,
  );

  return {
    verdict,
    reasons: dedupe(reasons.length ? reasons : [AGENT_SESSION_REASONS.OK]),
    ...base,
    integrityAnchoredBy: verdict === "VERIFIED" ? "SIGNED_SESSION_COMMITMENT" : "NONE",
    eventCount: Array.isArray(events) ? events.length : 0,
    chainHead: chain.chainHead,
    findingsBinding,
  };
}
