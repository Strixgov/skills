/**
 * Customer-side helper that turns one mutation into a recorded Strix action.
 *
 * Reference implementation copied into customer codebases by the
 * `/strix-wire` Claude Code skill. The contract is small and intentionally
 * boring:
 *
 *   1. Caller hands us a `capabilityId`, the request `payload` (no secrets),
 *      and an async function that performs the mutation.
 *   2. We ask the Strix kernel whether the action is allowed
 *      (`POST /api/v1/evaluate`).
 *   3. If allowed, we run the operation.
 *   4. We POST an evidence record to `POST /api/v1/evidence/ingest`
 *      (body: `{ records: [...] }`) and return `{ result, evidenceId }`.
 *
 * Evidence identity: the ingest endpoint's response carries batch counters
 * (`{ ingested, skipped, quarantined, ... }`), NOT per-record ids — so this
 * helper GENERATES the `evidenceId` client-side (UUID v4), sends it inside
 * the record, and returns that same id after confirming the batch was
 * accepted. The record's dedup identity server-side is
 * `(tenantId, evidenceHash)`; we bind the generated `evidenceId` into the
 * hashed material so every execution produces a distinct evidence row
 * (a retry of the SAME record is idempotent — reported as `skipped`).
 *
 * Canonical bytes match the contract in `solo_builder/_canonical.py`
 * (sorted keys, no whitespace, UTF-8) so hashes reproduce across the
 * TypeScript and Python helpers byte-for-byte.
 *
 * Zero npm dependencies — uses global `fetch` and `crypto.subtle`. Works
 * in Node 18+ and any modern browser/edge runtime.
 *
 * Environment:
 *   STRIX_API_KEY    — required
 *   STRIX_TENANT_ID  — required
 *   STRIX_API_URL    — optional, defaults to https://www.strixgov.com
 *   STRIX_ACTOR      — optional, identifies who ran the action
 */

const DEFAULT_URL = "https://www.strixgov.com";
const EVALUATE_PATH = "/api/v1/evaluate";
const EVIDENCE_PATH = "/api/v1/evidence/ingest";

// ──────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────

export class StrixError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StrixError";
  }
}
export class StrixDenied extends StrixError {
  constructor(message: string) { super(message); this.name = "StrixDenied"; }
}
export class StrixApprovalRequired extends StrixError {
  constructor(message: string) { super(message); this.name = "StrixApprovalRequired"; }
}
export class StrixUnreachable extends StrixError {
  constructor(message: string) { super(message); this.name = "StrixUnreachable"; }
}

// ──────────────────────────────────────────────────────────────────────
// Canonical bytes — matches solo_builder._canonical.canonicalize
// ──────────────────────────────────────────────────────────────────────

/**
 * Deterministic JSON serialization. Byte-identical to the Python
 * `_canonicalize` in this skill's `governed_action.py`.
 *
 * Rules (ADR-005 §4):
 *   - Object keys sorted lexicographically.
 *   - No whitespace.
 *   - UTF-8.
 *   - No NaN, no Infinity.
 */
function canonicalize(value: unknown): string {
  return canonicalizeInner(value);
}

function canonicalizeInner(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new StrixError("NaN/Infinity not allowed in canonical bytes");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalizeInner).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts = keys.map(
      (k) => JSON.stringify(k) + ":" + canonicalizeInner(obj[k]),
    );
    return "{" + parts.join(",") + "}";
  }
  // bigint, undefined, symbol, function — fall through.
  throw new StrixError(`unsupported value in canonical bytes: ${typeof value}`);
}

async function sha256Hex(s: string): Promise<string> {
  const bytes = new TextEncoder().encode(s);
  // Node 18+ exposes crypto.subtle via globalThis.crypto.
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** UUID v4 via WebCrypto; RNG fallback covers runtimes without randomUUID. */
function newEvidenceId(): string {
  const c = globalThis.crypto as Crypto & { randomUUID?: () => string };
  if (typeof c?.randomUUID === "function") return c.randomUUID();
  const bytes = new Uint8Array(16);
  c.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// ──────────────────────────────────────────────────────────────────────
// Transport
// ──────────────────────────────────────────────────────────────────────

/**
 * Remove the API key from any text that could reach logs, exceptions, or
 * CI comments. Mirrors the `_scrub` discipline in `governed_action.py` —
 * a credential must never leak through an error path.
 */
function makeScrubber(apiKey: string): (text: string) => string {
  return (text: string) => {
    if (!apiKey) return text;
    let out = text.split(`Bearer ${apiKey}`).join("Bearer <redacted>");
    out = out.split(apiKey).join("<redacted>");
    return out;
  };
}

async function postJSON(
  url: string,
  body: unknown,
  headers: Record<string, string>,
  timeoutMs: number,
  scrub: (text: string) => string,
): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: canonicalize(body),
      signal: controller.signal,
    });
  } catch (err) {
    throw new StrixUnreachable(`network error: ${scrub((err as Error).message)}`);
  } finally {
    clearTimeout(timer);
  }
  const text = await resp.text();
  if (resp.status >= 400 && resp.status < 500) {
    throw new StrixDenied(`strix ${resp.status}: ${scrub(text.slice(0, 200))}`);
  }
  if (resp.status >= 500) {
    throw new StrixError(`strix ${resp.status}: ${scrub(text.slice(0, 200))}`);
  }
  if (!text) return {};
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new StrixUnreachable(`strix returned non-JSON: ${scrub(text.slice(0, 200))}`);
  }
}

// ──────────────────────────────────────────────────────────────────────
// Evidence envelope — matches the /api/v1/evidence/ingest IngestRecord
// ──────────────────────────────────────────────────────────────────────

interface EvidenceParams {
  base: string;
  headers: Record<string, string>;
  timeout: number;
  scrub: (text: string) => string;
  capabilityId: string;
  actor: string;
  tenantId: string;
  payloadHash: string;
  resultHash: string | null;
  outcome: "ok" | "error";
  durationMs: number;
  /** Included only on the success path — the error path records hashes
   *  only, so params of a failed operation are never persisted. */
  payload?: Record<string, unknown>;
}

async function postEvidence(p: EvidenceParams): Promise<string> {
  const evidenceId = newEvidenceId();
  // Server-side dedup identity is (tenantId, evidenceHash). Binding the
  // fresh evidenceId into the hashed material makes every execution a
  // distinct evidence row while keeping a retry of the SAME record
  // idempotent (the server reports it as `skipped`).
  const evidenceHash = await sha256Hex(
    canonicalize({
      capabilityId: p.capabilityId,
      evidenceId,
      outcome: p.outcome,
      payloadHash: p.payloadHash,
      resultHash: p.resultHash,
    }),
  );
  const record: Record<string, unknown> = {
    tenantId: p.tenantId,
    capabilityId: p.capabilityId,
    actorId: p.actor,
    actorRole: "operator",
    decision: "allow",
    reason:
      p.outcome === "ok"
        ? "governed action executed"
        : "governed action failed after allow",
    source: "strix-wire",
    evidenceHash,
    evidenceId,
    timestamp: new Date().toISOString(),
    metadata: {
      payloadHash: p.payloadHash,
      resultHash: p.resultHash,
      outcome: p.outcome,
      durationMs: p.durationMs,
      ...(p.payload !== undefined ? { payload: p.payload } : {}),
    },
  };
  const resp = await postJSON(
    `${p.base}${EVIDENCE_PATH}`,
    { records: [record] },
    p.headers,
    p.timeout,
    p.scrub,
  );
  const ingested = Number(resp.ingested ?? 0);
  const skipped = Number(resp.skipped ?? 0);
  const quarantined = Number(resp.quarantined ?? 0);
  if (ingested + skipped < 1) {
    throw new StrixError(
      `evidence endpoint accepted 0 records (ingested=${ingested}, ` +
        `skipped=${skipped}, quarantined=${quarantined})`,
    );
  }
  return evidenceId;
}

// ──────────────────────────────────────────────────────────────────────
// Public surface
// ──────────────────────────────────────────────────────────────────────

export interface GovernedActionInput {
  /** e.g. `"payment.charge"`, `"database.delete"` — kernel capability ID. */
  capabilityId: string;
  /** Non-secret request parameters. Hashed and recorded. */
  payload: Record<string, unknown>;
  /** Who's running this. Defaults to `process.env.STRIX_ACTOR` or `"solo-cli"`. */
  actor?: string;
  /** Override `process.env.STRIX_API_KEY`. */
  apiKey?: string;
  /** Override `process.env.STRIX_TENANT_ID`. */
  tenantId?: string;
  /** Override `process.env.STRIX_API_URL`. Defaults to canonical host. */
  strixUrl?: string;
  /** Per-request timeout in ms. Default 5000. */
  timeoutMs?: number;
}

export interface GovernedActionResult<T> {
  result: T;
  evidenceId: string;
}

/**
 * Govern an irreversible mutation.
 *
 * @throws StrixDenied            — kernel refused. Operation NOT run.
 * @throws StrixApprovalRequired  — out-of-band approval needed.
 * @throws StrixUnreachable       — network failed. Operation NOT run.
 * @throws anything the operation itself throws (after a failure evidence
 *                                  record is best-effort emitted).
 */
export async function governedAction<T>(
  input: GovernedActionInput,
  operation: () => Promise<T> | T,
): Promise<GovernedActionResult<T>> {
  const env =
    (typeof process !== "undefined" && process.env) ||
    ({} as NodeJS.ProcessEnv);
  // Trim surrounding whitespace/newlines — a secret saved with a trailing
  // newline would otherwise produce an invalid (and credential-leaking)
  // Authorization header. Mirrors governed_action.py.
  const apiKey = (input.apiKey ?? env.STRIX_API_KEY ?? "").trim();
  const tenantId = (input.tenantId ?? env.STRIX_TENANT_ID ?? "").trim();
  if (!apiKey || !tenantId) {
    throw new StrixError(
      "STRIX_API_KEY and STRIX_TENANT_ID must be set " +
        "(pass them explicitly or export them in the environment).",
    );
  }
  const scrub = makeScrubber(apiKey);
  const actor = input.actor ?? env.STRIX_ACTOR ?? "solo-cli";
  const base = (
    input.strixUrl ??
    env.STRIX_API_URL ??
    DEFAULT_URL
  ).replace(/\/+$/, "");
  const headers = {
    Authorization: `Bearer ${apiKey}`,
    "X-Tenant-Id": tenantId,
  };
  const timeout = input.timeoutMs ?? 5000;

  // 1. Pre-flight evaluate. The payload hash rides in `context` — the
  //    kernel's public input boundary — so it lands on the decision's
  //    audit row (same channel the FailGuard verdict uses).
  const payloadHash = await sha256Hex(canonicalize(input.payload));
  const decision = await postJSON(
    `${base}${EVALUATE_PATH}`,
    {
      capabilityId: input.capabilityId,
      actor: { id: actor, role: "operator" },
      context: { payloadHash, source: "strix-wire" },
    },
    headers,
    timeout,
    scrub,
  );
  const action = String(
    (decision.action ?? decision.decision ?? "").toString(),
  ).toLowerCase();
  if (action === "deny") {
    const reason = String(decision.reason ?? "policy denied");
    throw new StrixDenied(`${input.capabilityId}: ${scrub(reason)}`);
  }
  if (action === "escalate" || action === "require_approval") {
    throw new StrixApprovalRequired(
      `${input.capabilityId} requires approval — run ` +
        `\`solo kernel approve ${input.capabilityId}\` and retry.`,
    );
  }
  if (action !== "allow") {
    throw new StrixError(`unexpected kernel decision: ${scrub(action)}`);
  }

  // 2. Run.
  const t0 = Date.now();
  let result: T;
  try {
    result = await operation();
  } catch (err) {
    try {
      await postEvidence({
        base,
        headers,
        timeout,
        scrub,
        capabilityId: input.capabilityId,
        actor,
        tenantId,
        payloadHash,
        resultHash: null,
        outcome: "error",
        durationMs: Date.now() - t0,
      });
    } catch {
      /* swallow — original error must propagate */
    }
    throw err;
  }

  // 3. Record evidence.
  const resultHash = await sha256Hex(canonicalize(toJSONable(result)));
  const evidenceId = await postEvidence({
    base,
    headers,
    timeout,
    scrub,
    capabilityId: input.capabilityId,
    actor,
    tenantId,
    payloadHash,
    resultHash,
    outcome: "ok",
    durationMs: Date.now() - t0,
    payload: input.payload,
  });
  return { result, evidenceId };
}

function toJSONable(value: unknown): unknown {
  if (value === null || value === undefined) return value ?? null;
  if (["boolean", "number", "string"].includes(typeof value)) return value;
  if (Array.isArray(value)) return value.map(toJSONable);
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = toJSONable(v);
    }
    return out;
  }
  return String(value);
}
