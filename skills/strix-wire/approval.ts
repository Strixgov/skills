/**
 * Strix Wire run approval — TypeScript consume side.
 *
 * The cross-language sibling of `approval.py`. Both implementations read the
 * same on-disk record format, so a grant minted by the Python CLI is redeemed
 * by either runtime. Neither imports the other; they are a conformance pair,
 * matching the discipline already used for `governedAction.local.ts` and
 * `governed_action_local.py`.
 *
 * Minting stays Python-only on purpose: it is an operator action the skill
 * performs once, at Step 5, and a second mint implementation would be a
 * second place for the binding rules to drift.
 *
 * The invariants are `approval.py`'s, unchanged:
 *
 *   RA-1  source at rest grants no execution authority
 *   RA-2  single use, via an atomic rename claim
 *   RA-3  bound to repo root + capability + candidate + patch hash + mode
 *   RA-4  expiring
 *   RA-5  fail closed — never throws, never silently true
 *   RA-6  the secret is removed from the environment before anything else
 *   RA-7  a failed validation still burns the token
 *
 * This file is copied into the customer tree as `strixWireApproval.ts`. It is
 * dependency-free (Node stdlib only) and safe to commit: by RA-1 it grants
 * nothing on its own.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

/** Deliberately NOT the historical boolean `STRIX_WIRE_RUN_APPROVED`. */
export const ENV_VAR = "STRIX_WIRE_RUN_APPROVAL";
export const TOKEN_PREFIX = "swa1";

const APPROVAL_SUBDIR = path.join(".strix", "wire", "approvals");
const SCHEMA_VERSION = "strix.wire.run-approval.v1";
const VALID_MODES = new Set(["SANDBOX", "OFFLINE", "PERSONAL"]);

export interface ConsumeOptions {
  capabilityId: string;
  candidate: string;
  patchHash: string;
  /** Repository root. Defaults to `process.cwd()`. */
  root?: string;
  mode?: string;
  /** Explicit token, for tests. Otherwise read from the environment. */
  token?: string;
  /** Epoch seconds, for tests. */
  now?: number;
}

/**
 * Byte-identical to Python's
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
 *
 * `JSON.stringify` already emits no whitespace and leaves non-ASCII raw; the
 * only missing piece is key ordering, which is why keys are emitted through
 * an explicit sort rather than relying on insertion order.
 */
function canonical(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${JSON.stringify(obj[k])}`);
  return `{${parts.join(",")}}`;
}

function sha256(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

function rootIdentity(root: string): string {
  return sha256(fs.realpathSync(root));
}

export function bindingHash(args: {
  root: string;
  capabilityId: string;
  candidate: string;
  patchHash: string;
  mode: string;
}): string {
  return sha256(
    canonical({
      bindingVersion: 1,
      capabilityId: args.capabilityId,
      candidate: args.candidate,
      mode: args.mode,
      patchHash: args.patchHash,
      repoRootHash: rootIdentity(args.root),
    }),
  );
}

/**
 * Redeem the run approval for exactly this action. Never throws (RA-5).
 *
 * Returns `true` only for a valid, unexpired, unconsumed grant bound to
 * precisely this `(root, capabilityId, candidate, patchHash, mode)`.
 */
export function consumeRunApproval(options: ConsumeOptions): boolean {
  // RA-6: strip the secret first, so a child process spawned by the wrapped
  // operation cannot inherit it and a later throw cannot leave it behind.
  const envToken = process.env[ENV_VAR];
  delete process.env[ENV_VAR];
  const presented = options.token ?? envToken;

  try {
    if (!presented || !presented.startsWith(`${TOKEN_PREFIX}.`)) return false;

    const root = options.root ?? process.cwd();
    const tokenId = sha256(presented);
    const dir = path.join(root, APPROVAL_SUBDIR);
    const recordPath = path.join(dir, `${tokenId}.json`);
    const claimedPath = path.join(dir, `${tokenId}.consumed`);

    // RA-2 / RA-7: claim atomically FIRST. The winner of the rename owns the
    // token; a concurrent duplicate, and any retry after a failed check,
    // finds nothing.
    try {
      fs.renameSync(recordPath, claimedPath);
    } catch {
      return false;
    }

    let record: Record<string, unknown>;
    try {
      record = JSON.parse(fs.readFileSync(claimedPath, "utf8"));
    } catch {
      return false;
    }

    if (!record || typeof record !== "object") return false;
    if (record.schemaVersion !== SCHEMA_VERSION) return false;
    if (record.tokenId !== tokenId) return false;

    // RA-4: expiry.
    const now = options.now ?? Date.now() / 1000;
    const expiresAt = Number(record.expiresAt);
    if (!Number.isFinite(expiresAt) || now >= expiresAt) return false;

    // RA-3: re-derive the binding from what the CALLER claims to be doing.
    // The record's descriptive fields are never trusted as the answer.
    const mode = options.mode ?? (record.mode as string);
    if (typeof mode !== "string" || !VALID_MODES.has(mode)) return false;

    const derived = bindingHash({
      root,
      capabilityId: options.capabilityId,
      candidate: options.candidate,
      patchHash: options.patchHash,
      mode,
    });
    const stored = record.bindingHash;
    if (typeof stored !== "string" || stored.length !== derived.length) {
      return false;
    }
    return crypto.timingSafeEqual(Buffer.from(derived), Buffer.from(stored));
  } catch {
    // RA-5: no failure mode reaches the caller as anything but "denied".
    return false;
  }
}

export default consumeRunApproval;
