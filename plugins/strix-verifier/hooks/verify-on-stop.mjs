#!/usr/bin/env node
// Stop hook for the strix-verifier plugin.
//
// Purpose: an OPT-IN "continuous trust" signal. When enabled, each time Claude
// finishes a turn this re-verifies a pinned Strix record and prints a one-line
// verdict, so a session working inside a Strix context gets a live reminder
// that the proof still holds.
//
// Discipline:
//   * Default OFF. Silent no-op unless explicitly enabled (config.json
//     verifyOnStop.enabled === true, or env STRIX_VERIFY_ON_STOP=<recordId>).
//   * ADVISORY ONLY. It never blocks the session (always exits 0 / continue:true).
//     A verifier plugin must not hijack the assistant because some unrelated
//     record failed — it reports, the human decides.
//   * The verdict is re-derived by the vendored @strixgov/verifier (Ed25519 +
//     JWKS). This hook never decides VERIFIED/FAILED itself.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { networkHintFor } from "../lib/network-hint.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = join(__dirname, "..");

function emitContinue() {
  // Stop hooks read JSON on stdout when exit code is 0.
  process.stdout.write(
    JSON.stringify({ continue: true, hookSpecificOutput: { hookEventName: "Stop" } }) + "\n"
  );
  process.exit(0);
}

// Drain stdin (the Stop event payload) but we don't need its contents.
try {
  readFileSync(0, "utf8");
} catch {
  /* no stdin is fine */
}

// Resolve config + env gating.
let config = {};
try {
  config = JSON.parse(readFileSync(join(PLUGIN_ROOT, "config.json"), "utf8"));
} catch {
  /* missing/invalid config → treat as disabled */
}

const envTarget = process.env.STRIX_VERIFY_ON_STOP; // e.g. "5686" or "swarm <id>"
const vos = config.verifyOnStop || {};
const enabled = Boolean(envTarget) || vos.enabled === true;
const target = (envTarget || vos.target || config.sampleRecord || "5686").toString().trim();

if (!enabled || !target) emitContinue();

// Build args: allow the target to carry a subcommand (e.g. "swarm <id>").
const targetArgs = target.split(/\s+/).filter(Boolean);

const vendored = join(PLUGIN_ROOT, "vendor", "strixgov-verifier", "bin", "verify.mjs");
let cmd, args;
try {
  readFileSync(vendored); // existence probe
  cmd = process.execPath; // node
  args = [vendored, ...targetArgs, "--json"];
} catch {
  cmd = "npx";
  args = ["-y", `@strixgov/verifier@${config.verifierVersion || "1.11.0"}`, ...targetArgs, "--json"];
}

const res = spawnSync(cmd, args, { encoding: "utf8", timeout: 20000 });
const code = res.status;

let verdict = "ERROR";
let detail = "";
let errorText = res.stderr || "";
try {
  const parsed = JSON.parse(res.stdout || "{}");
  verdict =
    parsed.verificationStatus ||
    parsed.status ||
    parsed.verdict ||
    (code === 0 ? "VERIFIED" : code === 1 ? "FAILED" : "ERROR");
  const kid = parsed.signingKeyId || parsed.record?.signingKeyId;
  detail = kid ? ` key=${kid}` : "";
  if (typeof parsed.error === "string") errorText += " " + parsed.error;
} catch {
  verdict = code === 0 ? "VERIFIED" : code === 1 ? "FAILED" : "ERROR";
}

// Advisory line to stderr so it surfaces to the user without polluting the
// hook's stdout JSON contract.
const mark = verdict.startsWith("VERIFIED") ? "✓" : verdict === "FAILED" ? "✗" : "?";
process.stderr.write(`[strix-verify] ${mark} ${target} → ${verdict}${detail}\n`);

// If the ERROR was an outbound-network/egress block, add one advisory line: the
// record is fine, the environment just blocked the fetch. Still advisory only —
// never blocks the session, and a hint failure is swallowed.
try {
  const hint = networkHintFor({ exitCode: code, text: errorText, proofBase: config.proofBase });
  if (hint && hint.kind === "EGRESS_BLOCK") {
    process.stderr.write(
      `[strix-verify]   ↳ can't reach ${hint.host} (egress-blocked, not invalid) — allowlist it, ` +
        `use the hosted Strix Verify MCP connector, or verify offline with --proof/--jwks.\n`,
    );
  }
} catch {
  /* advisory only */
}

emitContinue();
