// Gate-J structural check: "confirmation that the wrapper cannot reinterpret
// the verifier's verdict." Every non-vendored surface (bin wrapper, MCP
// server, Stop hook) must relay the vendored verifier's own verdict — never
// compute, second-guess, or upgrade one. This is a source-scan, not a crypto
// test: it proves by absence that no verdict logic exists outside
// vendor/strixgov-verifier/.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

// Any of these appearing OUTSIDE vendor/ would mean a wrapper is computing a
// crypto verdict itself instead of relaying the vendored verifier's answer.
// Deliberately scoped to actual crypto/canonicalization CALLS, not the word
// "Ed25519" in prose — the wrapper's own docs correctly describe what the
// vendored verifier does, and that's not the thing this check guards against.
const FORBIDDEN_PATTERNS = [
  /crypto\.verify\s*\(/,
  /crypto\.createVerify\s*\(/,
  /crypto\.sign\s*\(/,
  /createPublicKey\s*\(/,
  /verifySignature\s*\(/,
  /buildCanonicalPayload\s*\(/,
  /buildReceiptCanonicalPayload\s*\(/,
];

const SURFACES = ["bin/strix-verify", "mcp/server.mjs", "hooks/verify-on-stop.mjs", "lib/network-hint.mjs"];

test("wrapper surfaces contain no crypto/verdict logic of their own", () => {
  for (const rel of SURFACES) {
    const file = path.join(ROOT, rel);
    assert.ok(fs.existsSync(file), `${rel} should exist`);
    const src = fs.readFileSync(file, "utf8");
    for (const re of FORBIDDEN_PATTERNS) {
      assert.doesNotMatch(
        src,
        re,
        `${rel} matches forbidden pattern ${re} — a wrapper must relay the vendored ` +
          `verifier's verdict, never compute or reinterpret one itself`,
      );
    }
  }
});

test("wrapper surfaces only invoke the verifier as a subprocess (spawn/exec), never import its crypto internals", () => {
  const bin = fs.readFileSync(path.join(ROOT, "bin/strix-verify"), "utf8");
  assert.match(bin, /vendor\/strixgov-verifier\/bin\/verify\.mjs/, "bin wrapper must launch the vendored CLI");
  assert.doesNotMatch(bin, /vendor\/strixgov-verifier\/src\/index\.mjs/, "bin wrapper must not import verifier internals directly");

  const mcp = fs.readFileSync(path.join(ROOT, "mcp/server.mjs"), "utf8");
  assert.match(mcp, /spawnSync\s*\(/, "MCP server must invoke the verifier as a subprocess");
  assert.doesNotMatch(mcp, /from\s+["'].*vendor\/strixgov-verifier\/src/, "MCP server must not import verifier internals directly");

  const hook = fs.readFileSync(path.join(ROOT, "hooks/verify-on-stop.mjs"), "utf8");
  assert.match(hook, /spawnSync\s*\(/, "Stop hook must invoke the verifier as a subprocess");
  assert.doesNotMatch(hook, /from\s+["'].*vendor\/strixgov-verifier\/src/, "Stop hook must not import verifier internals directly");
});

test("MCP server never overrides a FAILED/ERROR exit code's implied verdict with a planted status field", () => {
  const mcp = fs.readFileSync(path.join(ROOT, "mcp/server.mjs"), "utf8");
  // The verdict must be derived preferring the vendored CLI's OWN JSON output
  // (verificationStatus/status/verdict) with an exitCode-derived fallback —
  // never a hardcoded "VERIFIED" default regardless of exit code.
  assert.match(
    mcp,
    /exitCode === 0 \? "VERIFIED" : exitCode === 1 \? "FAILED" : "ERROR"/,
    "the exitCode-derived fallback verdict must map 0/1/else to VERIFIED/FAILED/ERROR, matching the CLI's own contract",
  );
});

// Gate-G: single verification-collapse point (mirrors
// apps/strix-console/src/lib/proof-explorer/verification-collapse.ts's
// discipline). The frozen 4-state public vocabulary (VERIFIED / INVALID /
// LEGACY_UNSIGNED / UNVERIFIABLE) must be computed in exactly ONE place —
// lib/verdict-collapse.mjs — and every structured-output surface must
// import it rather than inventing its own mapping.
const COLLAPSE_MODULE = "lib/verdict-collapse.mjs";
const STRUCTURED_OUTPUT_SURFACES = ["mcp/server.mjs", "hooks/verify-on-stop.mjs"];

test("every structured-output surface imports the collapse point, none reinvent it", () => {
  for (const rel of STRUCTURED_OUTPUT_SURFACES) {
    const src = fs.readFileSync(path.join(ROOT, rel), "utf8");
    assert.match(
      src,
      /from\s+["'].*lib\/verdict-collapse\.mjs["']/,
      `${rel} must import collapseVerdict from ${COLLAPSE_MODULE} rather than computing the frozen-state mapping itself`,
    );
  }
});

test("no file other than the collapse module hardcodes the frozen-state mapping literals", () => {
  // A source-scan proxy for "only lib/verdict-collapse.mjs decides the
  // frozen public state": UNVERIFIABLE is a derived value everywhere else
  // (a variable read from collapseVerdict's result) — it should never
  // appear as a literal string constant outside the collapse module itself
  // (or this test, or the golden-vector fixtures, which are data not code).
  const scanDirs = ["bin", "mcp", "hooks", "lib"];
  const offenders = [];
  for (const dir of scanDirs) {
    const full = path.join(ROOT, dir);
    if (!fs.existsSync(full)) continue;
    const files = fs.readdirSync(full, { withFileTypes: true }).filter((e) => e.isFile());
    for (const f of files) {
      const rel = path.join(dir, f.name).split(path.sep).join("/");
      if (rel.endsWith(COLLAPSE_MODULE)) continue;
      const src = fs.readFileSync(path.join(ROOT, rel), "utf8");
      if (/"UNVERIFIABLE"/.test(src)) offenders.push(rel);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `only ${COLLAPSE_MODULE} may hardcode the literal "UNVERIFIABLE" — found it in: ${offenders.join(", ")}`,
  );
});
