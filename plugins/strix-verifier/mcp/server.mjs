#!/usr/bin/env node
// strix-verifier MCP server — exposes the bundled @strixgov/verifier as MCP
// tools so an agent can request an independent verdict on a Strix governance
// artifact and get back structured JSON (verdict + exit code + raw result).
//
// Zero dependencies on purpose (mirrors the verifier itself): a minimal
// JSON-RPC 2.0 implementation over the MCP stdio transport (newline-delimited
// JSON messages; logs go to stderr, never stdout).
//
// Trust note: this server NEVER decides a verdict. It shells out to the
// vendored Ed25519 + JWKS verifier and relays exactly what the CLI returns,
// including its exit code (0 VERIFIED · 1 FAILED · 2 cannot-verify).

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { networkHintFor, DEFAULT_PROOF_BASE } from "../lib/network-hint.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = join(__dirname, "..");
const VENDORED = join(PLUGIN_ROOT, "vendor", "strixgov-verifier", "bin", "verify.mjs");

let CONFIG = {};
try {
  CONFIG = JSON.parse(readFileSync(join(PLUGIN_ROOT, "config.json"), "utf8"));
} catch {
  /* defaults below */
}
const PINNED = CONFIG.verifierVersion || "1.11.0";

const PROTOCOL_VERSION = "2025-06-18";
const SERVER_INFO = { name: "strix-verifier", version: "1.11.1" };

const TOOLS = [
  {
    name: "strix_verify",
    description:
      "Independently verify any Strix governance artifact by passing raw @strixgov/verifier CLI arguments. " +
      "Examples of args: [\"5686\"] (evidence record), [\"approval\",\"<id>\"], [\"quorum\",\"<decisionId>\"], " +
      "[\"receipt\",\"./receipt.json\"], [\"swarm\",\"<runId>\"], [\"ct\",\"inclusion\",\"<hash>\"]. " +
      "Returns the verdict, the CLI exit code (0 VERIFIED, 1 FAILED, 2 cannot-verify), and the raw JSON result. " +
      "Verdicts are re-derived from Ed25519 + the public JWKS — Strix is never on the trust path.",
    inputSchema: {
      type: "object",
      properties: {
        args: {
          type: "array",
          items: { type: "string" },
          description: "Verifier CLI arguments, in order. Do not include --json; it is added automatically."
        }
      },
      required: ["args"]
    }
  },
  {
    name: "strix_verify_record",
    description:
      "Convenience: verify a single Strix evidence record by its evidenceId. Optionally override the proof/JWKS " +
      "base URL for a custom deployment. Returns verdict + exit code + raw result.",
    inputSchema: {
      type: "object",
      properties: {
        evidenceId: { type: "string", description: "The evidence record id, e.g. \"5686\"." },
        proofBase: { type: "string", description: "Optional proof API base URL (default https://www.strixgov.com)." },
        jwksBase: { type: "string", description: "Optional JWKS base URL (defaults to proofBase)." }
      },
      required: ["evidenceId"]
    }
  },
  {
    name: "strix_verify_swarm",
    description:
      "Convenience: verify an agent-swarm run by its swarmRunId (re-derives the delegation-chain verdict). " +
      "Optionally override the base URL. Returns verdict + exit code + raw result.",
    inputSchema: {
      type: "object",
      properties: {
        swarmRunId: { type: "string", description: "The swarm run id." },
        base: { type: "string", description: "Optional base URL for the swarm proof API." }
      },
      required: ["swarmRunId"]
    }
  }
];

// Pull a --proof-base / --jwks-base override out of raw CLI args so a network
// hint names the right host for a custom deployment.
function proofBaseFromArgs(args) {
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    if (a === "--proof-base" || a === "--jwks-base") return args[i + 1];
    if (a.startsWith("--proof-base=")) return a.slice("--proof-base=".length);
    if (a.startsWith("--jwks-base=")) return a.slice("--jwks-base=".length);
  }
  return undefined;
}

function runVerifier(cliArgs) {
  const args = [...cliArgs];
  if (!args.includes("--json")) args.push("--json");

  let cmd, spawnArgs;
  if (existsSync(VENDORED)) {
    cmd = process.execPath; // node
    spawnArgs = [VENDORED, ...args];
  } else {
    cmd = "npx";
    spawnArgs = ["-y", `@strixgov/verifier@${PINNED}`, ...args];
  }

  const res = spawnSync(cmd, spawnArgs, { encoding: "utf8", timeout: 60000, maxBuffer: 8 * 1024 * 1024 });
  const exitCode = res.status === null ? 2 : res.status;

  let raw = null;
  try {
    raw = JSON.parse(res.stdout || "");
  } catch {
    /* non-JSON output (e.g. unexpected error) */
  }

  const verdict =
    (raw && (raw.verificationStatus || raw.status || raw.verdict)) ||
    (exitCode === 0 ? "VERIFIED" : exitCode === 1 ? "FAILED" : "ERROR");

  let interpretation =
    exitCode === 0
      ? "Cryptographically verified — produced by the holder of the Strix signing key (Ed25519) and the hash matches."
      : exitCode === 1
      ? "FAILED — a signature or hash check did not pass. This is a real verification failure, not a network issue."
      : "Cannot verify (ERROR) — network, unknown signing key, malformed input, or record not found. NOT the same as invalid.";

  // When exit 2 is actually an outbound-network/egress block (sandbox, CI,
  // corporate proxy, Claude Code on the web), turn the dead-end ERROR into an
  // actionable remediation. Render-only: verdict + exitCode are unchanged
  // (cannot-verify stays cannot-verify). Best-effort — a hint bug must never
  // turn an otherwise-fine result into a failure.
  let networkBlock;
  let remediation;
  try {
    const errorText = [
      typeof raw?.error === "string" ? raw.error : "",
      typeof raw === "string" ? raw : "",
      res.stderr || "",
    ].join(" ");
    const hint = networkHintFor({
      exitCode,
      text: errorText,
      proofBase: proofBaseFromArgs(cliArgs) || CONFIG.proofBase || DEFAULT_PROOF_BASE,
    });
    if (hint) {
      networkBlock = true;
      remediation = hint;
      interpretation = `${hint.summary} See \`remediation\` for how to get a verdict.`;
    }
  } catch {
    /* hint is best-effort; never block the result */
  }

  return {
    verdict,
    exitCode,
    interpretation,
    ...(networkBlock ? { networkBlock, remediation } : {}),
    raw: raw ?? (res.stdout || "").trim(),
    stderr: (res.stderr || "").trim() || undefined,
    source: existsSync(VENDORED) ? `vendored @strixgov/verifier@${PINNED}` : `npx @strixgov/verifier@${PINNED}`
  };
}

function toolCall(name, input) {
  let cliArgs;
  if (name === "strix_verify") {
    if (!Array.isArray(input?.args)) throw new Error("`args` must be an array of strings");
    cliArgs = input.args.map(String);
  } else if (name === "strix_verify_record") {
    if (!input?.evidenceId) throw new Error("`evidenceId` is required");
    cliArgs = [String(input.evidenceId)];
    if (input.proofBase) cliArgs.push("--proof-base", String(input.proofBase));
    if (input.jwksBase) cliArgs.push("--jwks-base", String(input.jwksBase));
  } else if (name === "strix_verify_swarm") {
    if (!input?.swarmRunId) throw new Error("`swarmRunId` is required");
    cliArgs = ["swarm", String(input.swarmRunId)];
    if (input.base) cliArgs.push("--base", String(input.base));
  } else {
    throw new Error(`Unknown tool: ${name}`);
  }

  const result = runVerifier(cliArgs);
  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    // A FAILED/ERROR verdict is reported as data, not a tool error — the caller
    // inspects exitCode/verdict. isError is reserved for malformed requests.
    isError: false
  };
}

// ---- JSON-RPC 2.0 over stdio (newline-delimited) ----

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function handle(msg) {
  const { id, method, params } = msg;
  const isNotification = id === undefined || id === null;

  try {
    switch (method) {
      case "initialize":
        return send({
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: PROTOCOL_VERSION,
            capabilities: { tools: {} },
            serverInfo: SERVER_INFO
          }
        });
      case "tools/list":
        return send({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
      case "tools/call": {
        const result = toolCall(params?.name, params?.arguments || {});
        return send({ jsonrpc: "2.0", id, result });
      }
      case "ping":
        return send({ jsonrpc: "2.0", id, result: {} });
      default:
        if (isNotification) return; // ignore unknown notifications (e.g. notifications/initialized)
        return send({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } });
    }
  } catch (err) {
    if (isNotification) return;
    send({ jsonrpc: "2.0", id, error: { code: -32603, message: String(err?.message || err) } });
  }
}

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let nl;
  while ((nl = buffer.indexOf("\n")) !== -1) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      process.stderr.write(`[strix-verifier-mcp] dropped non-JSON line\n`);
      continue;
    }
    handle(msg);
  }
});
process.stdin.on("end", () => process.exit(0));
process.stderr.write(`[strix-verifier-mcp] ready (verifier: ${existsSync(VENDORED) ? "vendored " + PINNED : "npx"})\n`);
