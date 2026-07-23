#!/usr/bin/env node

/**
 * @strixgov/verifier CLI
 *
 * Independent verification of Strix governance evidence records.
 * Uses only standard Ed25519 + SHA-256 — no Strix SDK required.
 *
 * Usage:
 *   npx @strixgov/verifier <evidenceId>
 *   npx @strixgov/verifier 42
 *   npx @strixgov/verifier 42 --proof-base https://your-deployment.example.com --jwks-base https://your-deployment.example.com
 *
 * Exit codes:
 *   0 = VERIFIED
 *   1 = FAILED (signature invalid or hash mismatch)
 *   2 = ERROR (network, key not found, etc.)
 */

import fs from "node:fs/promises";
import {
  verify,
  verifyApprovalArtifact,
  verifyApprovalQuorum,
  verifyWithAttestations,
  verifyReceipt,
  verifyReceiptChain,
  verifyVisual,
  verifyCtInclusion,
  verifyCtConsistency,
  verifySwarm,
} from "../src/index.mjs";

/**
 * Read a text file with explicit BOM detection.
 *
 * PowerShell's `>` redirect on Windows writes files as UTF-16 LE with a
 * BOM (FF FE). Node's `fs.readFile(p, "utf8")` returns the raw bytes
 * re-interpreted as UTF-8, so a JWKS that came out of `npx strix-gateway
 * keys jwks > file.json` parses as `￾{...` and JSON.parse blows up with
 * `Unexpected token '�'`. That error tells a CLI user nothing; the fix
 * names the encoding and the one-line PowerShell repair.
 *
 * - UTF-8 BOM (EF BB BF): silently stripped (matches browser JSON behavior).
 * - UTF-16 LE BOM (FF FE) / UTF-16 BE BOM (FE FF): throw with the fix.
 * - UTF-32 BOMs: same family of fix, called out separately.
 *
 * @param {string} filePath
 * @returns {Promise<string>}
 */
async function readTextFileNoBom(filePath) {
  const buf = await fs.readFile(filePath);
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    throw new Error(
      `${filePath}: file is UTF-16 LE BOM-encoded (PowerShell '>' default on Windows). ` +
        `Re-export the file as UTF-8 without BOM:\n` +
        `  PowerShell 7+:  <cmd> | Out-File -Encoding utf8NoBOM ${filePath}\n` +
        `  PowerShell 5.1: <cmd> | Out-File -Encoding ascii ${filePath}\n` +
        `Or write it from cmd.exe instead of PowerShell.`,
    );
  }
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    throw new Error(
      `${filePath}: file is UTF-16 BE BOM-encoded. Re-export as UTF-8 without BOM ` +
        `(see https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-file).`,
    );
  }
  if (
    buf.length >= 4 &&
    ((buf[0] === 0xff && buf[1] === 0xfe && buf[2] === 0x00 && buf[3] === 0x00) ||
      (buf[0] === 0x00 && buf[1] === 0x00 && buf[2] === 0xfe && buf[3] === 0xff))
  ) {
    throw new Error(
      `${filePath}: file is UTF-32 BOM-encoded. Re-export as UTF-8 without BOM.`,
    );
  }
  let text = buf.toString("utf8");
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return text;
}

async function readJsonFile(filePath) {
  return JSON.parse(await readTextFileNoBom(filePath));
}

// ─── Argument Parsing ─────────────────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
  console.log(`
@strixgov/verifier — Independent governance evidence + approval verification

Usage:
  strix-verify <evidenceId> [options]
  strix-verify approval <artifactId> [options]
  strix-verify quorum <decisionId> [options]
  strix-verify receipt <path-to-receipt.json> [--jwks <path>]
  strix-verify chain <path-to-receipts.jsonl> [--jwks <path>]
  strix-verify visual <path-to-svg> [--jwks <path>] [--live-jwks-url <url>]
  strix-verify ct inclusion <evidenceHash> [--ct-base <url>] [--proof <file>]
  strix-verify ct consistency <sth1.json> <sth2.json> [--ct-base <url>] [--proof <file>]
  strix-verify swarm <swarmRunId> [--base <url>] [--proof <file>] [--json]

Options:
  --proof-base <url>      Base URL for proof API (default: https://www.strixgov.com)
  --jwks-base <url>       Base URL for JWKS endpoint (default: https://www.strixgov.com)
  --verify-base <url>     Base URL for Console verify endpoint (defaults to --jwks-base)
  --include-attestations  Fetch + verify linked attestations (E1.5; v1.3.0+)
  --json                  Output raw JSON instead of formatted text
  --help, -h              Show this help

Examples:
  strix-verify 1
  strix-verify 42 --json
  strix-verify 42 --include-attestations
  strix-verify approval <artifactId>
  strix-verify quorum <decisionId>

What evidence verification does:
  1. Fetches the evidence record from the proof API
  2. Fetches the signing public key from the JWKS endpoint
  3. Reconstructs the canonical 13-field signed payload
  4. Verifies the Ed25519 signature
  5. Verifies the SHA-256 evidence hash
  6. Reports pass/fail with cryptographic details

What approval verification does (Phase 3):
  1. Fetches a signed approval artifact (or all artifacts for a decision)
  2. Reconstructs the canonical 9-field approval payload
  3. Verifies the Ed25519 signature against the public JWKS
  4. Verifies the SHA-256 canonical hash
  5. For quorum mode: checks chain continuity + quorum satisfaction

No Strix account, SDK, or API key required.
`);
  process.exit(0);
}

// Visual Artifacts v1 — verify an SVG produced by the @strixgov/render renderer.
// Mirror of apps/strix-verify-web (same gates, same outcome vocabulary).
if (args[0] === "visual") {
  const filePath = args[1];
  if (!filePath) {
    console.error("Missing path. Usage: strix-verify visual <path-to-svg> [--jwks <path>] [--live-jwks-url <url>] [--json]");
    process.exit(2);
  }
  let pinnedJwksPath = null;
  let liveJwksUrl = null;
  let jsonOut = false;
  for (let i = 2; i < args.length; i++) {
    if (args[i] === "--jwks" && args[i + 1]) pinnedJwksPath = args[++i];
    else if (args[i] === "--live-jwks-url" && args[i + 1]) liveJwksUrl = args[++i];
    else if (args[i] === "--json") jsonOut = true;
  }
  try {
    const svg = await fs.readFile(filePath, "utf8");
    const opts = {};
    if (pinnedJwksPath) {
      const parsed = await readJsonFile(pinnedJwksPath);
      opts.pinnedJwks = "keys" in parsed ? parsed : { keys: [parsed] };
    }
    if (liveJwksUrl) opts.liveJwksUrl = liveJwksUrl;
    const result = await verifyVisual(svg, opts);
    if (jsonOut) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log();
      console.log(`@strixgov/verifier — Visual Artifacts v1`);
      console.log("─".repeat(56));
      console.log(`  File:              ${filePath}`);
      console.log(`  Visual kind:       ${result.meta.visualKind ?? "—"}`);
      console.log(`  Render version:    ${result.meta.renderVersion ?? "—"}`);
      console.log(`  Signing kid:       ${result.meta.signingKeyId ?? "—"}`);
      console.log(`  Canonical hash:    ${result.canonical.embeddedHash ?? "—"}`);
      console.log(`  Self-consistent:   ${result.canonical.match === true ? "yes" : result.canonical.match === false ? "NO" : "—"}`);
      console.log(`  Pinned:            ${result.pinned.jwkPresent ? (result.pinned.ok ? "VERIFIED" : "FAILED") : "(no kid match)"}${result.pinned.error ? "  · " + result.pinned.error : ""}`);
      console.log(`  Live:              ${result.live.fetched ? (result.live.jwkPresent ? (result.live.ok ? "VERIFIED" : "FAILED") : "(no kid match)") : "(not fetched)"}${result.live.error ? "  · " + result.live.error : ""}`);
      console.log(`  Drift:             ${result.drift.state}`);
      console.log(`  Status:            ${result.verificationStatus}`);
      console.log(`  Reason:            ${result.verificationReason}`);
      console.log();
    }
    const exitCode = ["VERIFIED", "VERIFIED_PINNED_ONLY", "VERIFIED_LIVE_ONLY"].includes(result.verificationStatus) ? 0 : 1;
    process.exit(exitCode);
  } catch (err) {
    console.error(`strix-verify visual: ${err.message}`);
    process.exit(2);
  }
}

// Strix-CT v1 — inclusion + consistency proof verification.
// Standalone (sequencer endpoint, not the proof API). Per
// docs/architecture/strix-ct-v1.md.
if (args[0] === "ct") {
  const sub = args[1];
  let ctBase = null;
  let proofPath = null;
  let jsonOut = false;
  // Collect non-flag positional args
  const positional = [];
  for (let i = 2; i < args.length; i++) {
    if (args[i] === "--ct-base" && args[i + 1]) ctBase = args[++i];
    else if (args[i] === "--proof" && args[i + 1]) proofPath = args[++i];
    else if (args[i] === "--json") jsonOut = true;
    else positional.push(args[i]);
  }

  try {
    if (sub === "inclusion") {
      const evidenceHash = positional[0];
      if (!evidenceHash) {
        console.error("Missing evidenceHash. Usage: strix-verify ct inclusion <evidenceHash> [--ct-base <url>] [--proof <file>] [--json]");
        process.exit(2);
      }
      const opts = {};
      if (ctBase) opts.ctBase = ctBase;
      if (proofPath) {
        opts.proof = JSON.parse(await fs.readFile(proofPath, "utf8"));
      }
      const r = await verifyCtInclusion(evidenceHash, opts);
      if (jsonOut) {
        console.log(JSON.stringify(r, null, 2));
      } else {
        console.log();
        console.log(`@strixgov/verifier — Strix-CT v1 inclusion`);
        console.log("─".repeat(56));
        console.log(`  Evidence hash:     ${r.evidenceHash}`);
        console.log(`  Leaf index:        ${r.leafIndex ?? "—"}`);
        console.log(`  Tree size:         ${r.treeSize ?? "—"}`);
        console.log(`  Root hash:         ${r.rootHash ?? "—"}`);
        console.log(`  Status:            ${r.verificationStatus}`);
        if (r.error) console.log(`  Error:             ${r.error}`);
        console.log();
      }
      if (r.error) process.exit(2);
      process.exit(r.verificationStatus === "VERIFIED" ? 0 : 1);
    }

    if (sub === "consistency") {
      const path1 = positional[0];
      const path2 = positional[1];
      if (!path1 || !path2) {
        console.error("Missing STH paths. Usage: strix-verify ct consistency <sth1.json> <sth2.json> [--ct-base <url>] [--proof <file>] [--json]");
        process.exit(2);
      }
      const [sth1Raw, sth2Raw] = await Promise.all([fs.readFile(path1, "utf8"), fs.readFile(path2, "utf8")]);
      const sth1 = JSON.parse(sth1Raw);
      const sth2 = JSON.parse(sth2Raw);
      const opts = {};
      if (ctBase) opts.ctBase = ctBase;
      if (proofPath) opts.proof = JSON.parse(await fs.readFile(proofPath, "utf8"));
      const r = await verifyCtConsistency(sth1, sth2, opts);
      if (jsonOut) {
        console.log(JSON.stringify(r, null, 2));
      } else {
        console.log();
        console.log(`@strixgov/verifier — Strix-CT v1 consistency`);
        console.log("─".repeat(56));
        console.log(`  First tree size:   ${r.firstTreeSize}`);
        console.log(`  Second tree size:  ${r.secondTreeSize}`);
        console.log(`  Status:            ${r.verificationStatus}`);
        if (r.error) console.log(`  Error:             ${r.error}`);
        console.log();
      }
      if (r.error) process.exit(2);
      process.exit(r.verificationStatus === "VERIFIED" ? 0 : 1);
    }

    console.error(`Unknown ct subcommand: ${sub}. Expected 'inclusion' or 'consistency'.`);
    process.exit(2);
  } catch (err) {
    console.error(`strix-verify ct: ${err.message}`);
    process.exit(2);
  }
}

// Agent Swarm v1 — independent delegation-graph verification.
// Fetches GET /api/public/proof/swarm/<id> and re-derives the verdict with the
// verifier's own SCJ + Ed25519 + attenuation algebra. Per
// docs/architecture/agent-swarm-v1.md.
if (args[0] === "swarm") {
  let base = null;
  let proofPath = null;
  let jsonOut = false;
  const positional = [];
  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--base" && args[i + 1]) base = args[++i];
    else if (args[i] === "--proof" && args[i + 1]) proofPath = args[++i];
    else if (args[i] === "--json") jsonOut = true;
    else positional.push(args[i]);
  }

  try {
    const swarmRunId = positional[0];
    if (!swarmRunId) {
      console.error(
        "Missing swarmRunId. Usage: strix-verify swarm <swarmRunId> [--base <url>] [--proof <file>] [--json]",
      );
      process.exit(2);
    }
    const opts = {};
    if (base) opts.base = base;
    if (proofPath) opts.proof = JSON.parse(await fs.readFile(proofPath, "utf8"));

    const r = await verifySwarm(swarmRunId, opts);

    if (jsonOut) {
      console.log(JSON.stringify(r, null, 2));
    } else {
      console.log();
      console.log(`@strixgov/verifier — Agent Swarm v1`);
      console.log("─".repeat(56));
      console.log(`  Swarm run:         ${r.swarmRunId ?? swarmRunId}`);
      console.log(`  Rooted (SW-1):     ${r.rooted ?? "—"}`);
      if (r.counts) {
        console.log(`  Delegations:       ${r.counts.edges}`);
        console.log(`  Governed actions:  ${r.counts.actions}`);
      }
      console.log(`  Status:            ${r.verificationStatus}`);
      if (r.reason) console.log(`  Reason:            ${r.reason}`);
      if (r.agreesWithServer !== null && r.agreesWithServer !== undefined) {
        console.log(`  Agrees w/ server:  ${r.agreesWithServer}`);
      }
      if (Array.isArray(r.actions) && r.actions.length > 0) {
        console.log("  Actions:");
        for (const a of r.actions) {
          console.log(`    - ${a.executingAgentId} → ${a.status} (${a.reason})`);
        }
      }
      if (r.error) console.log(`  Error:             ${r.error}`);
      console.log();
    }
    if (r.error || r.verificationStatus === "ERROR") process.exit(2);
    process.exit(r.verificationStatus === "VERIFIED" ? 0 : 1);
  } catch (err) {
    console.error(`strix-verify swarm: ${err.message}`);
    process.exit(2);
  }
}

// Tool-gateway receipt subcommands (offline-capable)
if (args[0] === "receipt" || args[0] === "chain") {
  const subcommand = args[0];
  const filePath = args[1];
  if (!filePath) {
    console.error(
      `Missing path. Usage: strix-verify ${subcommand} <path> [--jwks <path>]`,
    );
    process.exit(2);
  }
  let jwksPath = null;
  let jsonOut = false;
  for (let i = 2; i < args.length; i++) {
    if (args[i] === "--jwks" && args[i + 1]) jwksPath = args[++i];
    else if (args[i] === "--json") jsonOut = true;
  }

  try {
    const opts = {};
    if (jwksPath) {
      const parsed = await readJsonFile(jwksPath);
      opts.jwks = "keys" in parsed ? parsed : { keys: [parsed] };
    }

    const raw = await readTextFileNoBom(filePath);

    if (subcommand === "receipt") {
      const receipt = JSON.parse(raw);
      const result = await verifyReceipt(receipt, opts);
      if (jsonOut) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log();
        console.log(`@strixgov/verifier — Tool Gateway Receipt`);
        console.log("─".repeat(56));
        console.log(`  Receipt ID:        ${receipt.receiptId}`);
        console.log(`  Capability:        ${receipt.capabilityId}`);
        console.log(`  Action:            ${receipt.action}`);
        console.log(`  Decision:          ${receipt.decision}`);
        console.log(`  Risk:              ${receipt.risk}`);
        console.log(`  Mode:              ${receipt.mode}`);
        console.log(`  Signing key id:    ${receipt.signingKeyId}`);
        console.log(`  Hash valid:        ${result.hashValid}`);
        console.log(`  Signature present: ${result.signaturePresent}`);
        console.log(`  Signature valid:   ${result.signatureValid}`);
        console.log(`  Status:            ${result.verificationStatus}`);
        if (result.error) console.log(`  Error:             ${result.error}`);
        console.log();
      }
      if (result.error) process.exit(2);
      process.exit(result.verificationStatus === "VERIFIED" ? 0 : 1);
    }

    // chain — JSONL or JSON array
    const receipts = raw.trim().startsWith("[")
      ? JSON.parse(raw)
      : raw
          .split("\n")
          .filter(Boolean)
          .map((l) => JSON.parse(l));
    const result = await verifyReceiptChain(receipts, opts);
    if (jsonOut) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log();
      console.log(`@strixgov/verifier — Tool Gateway Receipt Chain`);
      console.log("─".repeat(56));
      console.log(`  Receipts:          ${result.count}`);
      console.log(`  Chain valid:       ${result.chainValid}`);
      if (result.brokenAt) {
        console.log(`  Broken at:         ${result.brokenAt}`);
      }
      let signedOk = 0;
      for (const r of result.receipts) {
        if (r.verificationStatus === "VERIFIED") signedOk++;
      }
      console.log(`  Signatures valid:  ${signedOk}/${result.count}`);

      // Per-receipt detail when anything failed. Mirrors the quorum
      // path's behavior — a count-only summary leaves an auditor with
      // no way to tell which receipt broke and why.
      const anyFailed =
        !result.chainValid || signedOk !== result.count;
      if (anyFailed) {
        console.log();
        console.log(`  Receipts (${result.receipts.length}):`);
        for (const r of result.receipts) {
          const sigTag = r.verificationStatus === "VERIFIED" ? "✓" : "✗";
          const linkTag = r.linkOk === false ? "  link✗" : "";
          console.log(
            `    ${sigTag} ${(r.receiptId ?? "—").padEnd(28)} ${r.verificationStatus.padEnd(18)}${linkTag}`,
          );
          if (r.error) console.log(`        error: ${r.error}`);
        }
      }
      console.log();
    }
    if (!result.chainValid) process.exit(1);
    const allSigned = result.receipts.every(
      (r) => r.verificationStatus === "VERIFIED",
    );
    process.exit(allSigned ? 0 : 1);
  } catch (err) {
    console.error(`Fatal error: ${err.message}`);
    process.exit(2);
  }
}

// Approval artifact subcommand
if (args[0] === "approval" || args[0] === "quorum") {
  const subcommand = args[0];
  const id = args[1];
  if (!id) {
    console.error(`Missing ID. Usage: strix-verify ${subcommand} <id>`);
    process.exit(2);
  }

  const subOpts = {};
  let subJson = false;
  for (let i = 2; i < args.length; i++) {
    if (args[i] === "--proof-base" && args[i + 1]) {
      subOpts.proofBase = args[++i];
    } else if (args[i] === "--jwks-base" && args[i + 1]) {
      subOpts.jwksBase = args[++i];
    } else if (args[i] === "--json") {
      subJson = true;
    }
  }

  try {
    const result = subcommand === "approval"
      ? await verifyApprovalArtifact({ artifactId: id, ...subOpts })
      : await verifyApprovalQuorum({ decisionId: id, ...subOpts });

    if (subJson) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log();
      console.log(`@strixgov/verifier — ${subcommand === "approval" ? "Approval Artifact" : "Approval Quorum"} ${id}`);
      console.log("─".repeat(64));
      if (result.error) {
        console.log(`Error: ${result.error}`);
      } else if (subcommand === "approval") {
        console.log(`  Hash valid:        ${result.hashValid}`);
        console.log(`  Signature present: ${result.signaturePresent}`);
        console.log(`  Signature valid:   ${result.signatureValid}`);
        console.log(`  Status:            ${result.verificationStatus}`);
      } else {
        console.log(`  Required:          ${result.requiredApprovals}`);
        console.log(`  Valid approvals:   ${result.validApprovals}`);
        console.log(`  Quorum satisfied:  ${result.quorumSatisfied}`);
        console.log(`  Chain continuous:  ${result.chainContinuous}`);

        // Per-artifact detail. Print compactly when everything verifies;
        // print full failure reasons when any artifact didn't VERIFY.
        const all = result.results ?? [];
        if (all.length > 0) {
          console.log();
          console.log(`  Artifacts (${all.length}):`);
          for (const v of all) {
            const tag = v.verificationStatus === "VERIFIED" ? "✓" : "✗";
            const seq = v.sequenceNum ?? "?";
            const id = v.record?.id ?? v.record?.approvalId ?? "—";
            console.log(`    ${tag} #${seq}  ${v.verificationStatus.padEnd(18)} ${id}`);
            if (v.verificationStatus !== "VERIFIED" && v.error) {
              console.log(`        error: ${v.error}`);
            }
          }
        }

        // If chain broke, point at the first link that broke. The chain
        // walk in verifyApprovalQuorum stops at the first mismatch.
        if (!result.chainContinuous && all.length > 0) {
          console.log();
          console.log(`  Chain note: first artifact whose proofChainHash`);
          console.log(`  did not match the previous artifact's recomputed`);
          console.log(`  canonical hash. If individual artifacts above`);
          console.log(`  show VERIFIED, the chain mismatch is the server`);
          console.log(`  response shape — re-fetch and re-run.`);
        }
      }
      console.log();
    }

    const ok = subcommand === "approval"
      ? result.verificationStatus === "VERIFIED"
      : result.quorumSatisfied && result.chainContinuous;
    if (result.error) process.exit(2);
    process.exit(ok ? 0 : 1);
  } catch (err) {
    console.error(`Fatal error: ${err.message}`);
    process.exit(2);
  }
}

const evidenceId = args[0];
const options = {};
let jsonOutput = false;

for (let i = 1; i < args.length; i++) {
  if (args[i] === "--proof-base" && args[i + 1]) {
    options.proofBase = args[++i];
  } else if (args[i] === "--jwks-base" && args[i + 1]) {
    options.jwksBase = args[++i];
  } else if (args[i] === "--verify-base" && args[i + 1]) {
    options.verifyBase = args[++i];
  } else if (args[i] === "--include-attestations") {
    options.includeAttestations = true;
  } else if (args[i] === "--json") {
    jsonOutput = true;
  }
}

// ─── Verification ─────────────────────────────────────────────────────────────

const RESET = "\x1b[0m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";

function statusColor(status) {
  if (status === "VERIFIED") return GREEN;
  if (status === "LEGACY_UNSIGNED" || status === "UNSIGNED") return YELLOW;
  return RED;
}

function checkMark(ok) {
  return ok ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
}

try {
  // E1.5: when --include-attestations is set, route through the
  // attestation-aware verifier. Result shape is a superset of base verify.
  const result = options.includeAttestations
    ? await verifyWithAttestations(evidenceId, options)
    : await verify(evidenceId, options);

  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log();
    console.log(
      `${BOLD}@strixgov/verifier${RESET} — Evidence Record #${evidenceId}`
    );
    console.log(`${"─".repeat(52)}`);

    if (result.error) {
      console.log(`${RED}Error: ${result.error}${RESET}`);
      if (/Network error fetching/.test(result.error)) {
        console.log("");
        console.log(`${DIM}If you're behind a corporate proxy, VPN, or air-gapped network,${RESET}`);
        console.log(`${DIM}see the Troubleshooting section:${RESET}`);
        console.log(`  https://www.npmjs.com/package/@strixgov/verifier#troubleshooting`);
        console.log("");
        console.log(`${DIM}To use a custom deployment instead of www.strixgov.com:${RESET}`);
        console.log(`  strix-verify <id> --proof-base https://your.host --jwks-base https://your.host`);
      }
      process.exit(2);
    }

    const record = result.record;
    if (record) {
      console.log(
        `${DIM}Capability:${RESET}  ${record.capabilityId ?? "unknown"}`
      );
      console.log(
        `${DIM}Action:${RESET}      ${record.action ?? record.decision ?? "unknown"}`
      );
      console.log(
        `${DIM}Actor:${RESET}       ${record.actorId ?? record.actor?.id ?? "unknown"}`
      );
      console.log(
        `${DIM}Created:${RESET}     ${record.createdAt ?? "unknown"}`
      );
      console.log(
        `${DIM}Key ID:${RESET}      ${record.signingKeyId ?? "none"}`
      );
      console.log();
    }

    console.log(`${BOLD}Verification Results${RESET}`);
    console.log(`${"─".repeat(52)}`);
    console.log(
      `  ${checkMark(result.hashValid)} Hash valid:        ${result.hashValid}`
    );
    console.log(
      `  ${checkMark(result.signaturePresent)} Signature present: ${result.signaturePresent}`
    );
    console.log(
      `  ${checkMark(result.signatureValid)} Signature valid:   ${result.signatureValid}`
    );
    console.log();

    const color = statusColor(result.verificationStatus);
    console.log(
      `  ${BOLD}Status: ${color}${result.verificationStatus}${RESET}`
    );
    console.log();

    if (result.verificationStatus === "VERIFIED") {
      console.log(
        `${GREEN}This record was cryptographically signed by the Strix governance kernel.${RESET}`
      );
      console.log(
        `${GREEN}The evidence hash and signature are independently verifiable.${RESET}`
      );
    } else if (result.verificationStatus === "LEGACY_UNSIGNED") {
      console.log(
        `${YELLOW}This is a pre-Signed Evidence v1 record (no signature).${RESET}`
      );
      console.log(
        `${YELLOW}Hash integrity can still be verified but provenance cannot.${RESET}`
      );
    } else {
      console.log(
        `${RED}Verification failed. The record may have been tampered with.${RESET}`
      );
    }
    console.log();

    // ── E1.5: render attestations if --include-attestations was passed ───
    if (options.includeAttestations) {
      console.log(`${BOLD}Linked Attestations${RESET}`);
      console.log(`${"─".repeat(52)}`);
      const atts = result.attestations ?? [];
      if (atts.length === 0) {
        console.log(`${DIM}  (no attestations found)${RESET}`);
      } else {
        for (const a of atts) {
          const color = statusColor(a.verificationStatus);
          console.log(
            `  ${checkMark(a.verificationStatus === "VERIFIED")} ` +
              `[${a.attestationType}] ${color}${a.verificationStatus}${RESET}`,
          );
          if (a.attestationType === "ACTOR" && a.actorType) {
            console.log(
              `       ${DIM}actor:${RESET} ${a.actorType}` +
                (a.actorId ? ` (${a.actorId})` : "") +
                (a.agentId ? ` agent=${a.agentId}` : "") +
                (a.onBehalfOf ? ` onBehalfOf=${a.onBehalfOf}` : ""),
            );
          }
        }
      }
      console.log();
      const ccolor = statusColor(
        result.compositeStatus === "FULLY_VERIFIED" ||
          result.compositeStatus === "EVIDENCE_VERIFIED"
          ? "VERIFIED"
          : "FAIL",
      );
      console.log(
        `  ${BOLD}Composite: ${ccolor}${result.compositeStatus}${RESET}`,
      );
      console.log();
    }
  }

  // Exit code based on verification status
  if (result.verificationStatus === "VERIFIED") {
    process.exit(0);
  } else if (result.error) {
    process.exit(2);
  } else {
    process.exit(1);
  }
} catch (err) {
  if (jsonOutput) {
    const payload = { error: err.message, verificationStatus: "ERROR" };
    if (err.url) payload.attemptedUrl = err.url;
    console.log(JSON.stringify(payload));
  } else {
    console.error(`${RED}Fatal error: ${err.message}${RESET}`);
    if (/Network error fetching/.test(err.message)) {
      console.error("");
      console.error(`${DIM}If you're behind a corporate proxy, VPN, or air-gapped network,${RESET}`);
      console.error(`${DIM}see the Troubleshooting section:${RESET}`);
      console.error(`  https://www.npmjs.com/package/@strixgov/verifier#troubleshooting`);
      console.error("");
      console.error(`${DIM}To use a custom deployment instead of www.strixgov.com:${RESET}`);
      console.error(`  strix-verify <id> --proof-base https://your.host --jwks-base https://your.host`);
    }
  }
  process.exit(2);
}
