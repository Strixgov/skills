/**
 * Customer-side helper that turns one mutation into a VERIFIED Strix record.
 *
 * Reference implementation copied into customer codebases by the
 * `/strix-wire` Claude Code skill. The contract is small and intentionally
 * boring:
 *
 *   1. Caller hands us a `capabilityId`, the request `payload` (no secrets),
 *      and an async function that performs the mutation.
 *   2. We ask the Strix kernel whether the action is allowed.
 *   3. If allowed, we run the operation.
 *   4. We POST the result envelope to the Strix evidence endpoint and
 *      return `{ result, evidenceId }`.
 *
 * The byte-shape of the evidence envelope matches the canonicalization
 * contract in `solo_builder/_canonical.py` (sorted keys, no whitespace,
 * UTF-8) so the `evidenceId` we get back hashes the same bytes the offline
 * `@strixgov/verifier` will hash. Cross-SDK byte determinism is preserved.
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

// ──────────────────────────────────────────────────────────────────────
// Transport
// ──────────────────────────────────────────────────────────────────────

async function postJSON(
  url: string,
  body: unknown,
  headers: Record<string, string>,
  timeoutMs: number,
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
    throw new StrixUnreachable(`network error: ${(err as Error).message}`);
  } finally {
    clearTimeout(timer);
  }
  const text = await resp.text();
  if (resp.status >= 400 && resp.status < 500) {
    throw new StrixDenied(`strix ${resp.status}: ${text.slice(0, 200)}`);
  }
  if (resp.status >= 500) {
    throw new StrixError(`strix ${resp.status}: ${text.slice(0, 200)}`);
  }
  if (!text) return {};
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch (err) {
    throw new StrixUnreachable(`strix returned non-JSON: ${text.slice(0, 200)}`);
  }
}

// ──────────────────────────────────────────────────────────────────────
// Public surface
// ──────────────────────────────────────────────────────────────────────

export interface GovernedActionInput {
  /** e.g. `"payment.charge"`, `"database.delete"` — kernel capability ID. */
  capabilityId: string;
  /** Non-secret request parameters. Hashed and signed. */
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
  const apiKey = input.apiKey ?? env.STRIX_API_KEY;
  const tenantId = input.tenantId ?? env.STRIX_TENANT_ID;
  if (!apiKey || !tenantId) {
    throw new StrixError(
      "STRIX_API_KEY and STRIX_TENANT_ID must be set " +
        "(pass them explicitly or export them in the environment).",
    );
  }
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

  // 1. Pre-flight evaluate.
  const payloadHash = await sha256Hex(canonicalize(input.payload));
  const decision = await postJSON(
    `${base}${EVALUATE_PATH}`,
    {
      capabilityId: input.capabilityId,
      actor: { id: actor, role: "operator" },
      payloadHash,
    },
    headers,
    timeout,
  );
  const action = String(
    (decision.action ?? decision.decision ?? "").toString(),
  ).toLowerCase();
  if (action === "deny") {
    const reason = String(decision.reason ?? "policy denied");
    throw new StrixDenied(`${input.capabilityId}: ${reason}`);
  }
  if (action === "escalate" || action === "require_approval") {
    throw new StrixApprovalRequired(
      `${input.capabilityId} requires approval — run ` +
        `\`solo kernel approve ${input.capabilityId}\` and retry.`,
    );
  }
  if (action !== "allow") {
    throw new StrixError(`unexpected kernel decision: ${action}`);
  }

  // 2. Run.
  const t0 = Date.now();
  let result: T;
  try {
    result = await operation();
  } catch (err) {
    try {
      await postJSON(
        `${base}${EVIDENCE_PATH}`,
        {
          records: [{
            capabilityId: input.capabilityId,
            actor,
            tenantId,
            payloadHash,
            outcome: "error",
            durationMs: Date.now() - t0,
          }],
        },
        headers,
        timeout,
      );
    } catch {
      /* swallow — original error must propagate */
    }
    throw err;
  }

  // 3. Record evidence.
  const resultHash = await sha256Hex(canonicalize(toJSONable(result)));
  const record = await postJSON(
    `${base}${EVIDENCE_PATH}`,
    {
      records: [{
        capabilityId: input.capabilityId,
        actor,
        tenantId,
        payload: input.payload,
        payloadHash,
        resultHash,
        outcome: "ok",
        durationMs: Date.now() - t0,
      }],
    },
    headers,
    timeout,
  );
  const responseRecords = Array.isArray(record.records) ? record.records : [];
  const firstRecord = responseRecords[0] as Record<string, unknown> | undefined;
  const evidenceId = String(firstRecord?.evidenceId ?? firstRecord?.id ?? record.evidenceId ?? record.id ?? "");
  if (!evidenceId) {
    throw new StrixError(
      `evidence endpoint returned no id: ${JSON.stringify(record)}`,
    );
  }
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
