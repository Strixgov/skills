#!/usr/bin/env node
// Gate-J conformance runner. Loads every vector in vectors/*.json (via
// index.json) and asserts the vendored @strixgov/verifier's REAL exported
// functions (verifyReceipt / verifyReceiptChain) reach exactly the recorded
// `expected` outcome. No crypto is re-implemented here — every assertion is
// "does the vendored copy's own function return what a conformant verifier
// must return", the same discipline as conformance/corpus/se_v1 elsewhere
// in this repo.
//
// Usage:
//   node conformance/run-conformance.mjs
//
// Exits non-zero on the first mismatch (with a full mismatch report printed
// first) so it gates CI (wired into scripts/lint-strixgov-skills-release.mjs).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyReceipt,
  verifyReceiptChain,
} from "../vendor/strixgov-verifier/src/index.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadJson(rel) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, rel), "utf8"));
}

export async function runConformance() {
const index = loadJson("index.json");
const failures = [];
let checked = 0;

function check(label, cond, detail) {
  checked++;
  if (!cond) failures.push(`${label}: ${detail}`);
}

for (const entry of index.vectors) {
  const v = loadJson(entry.relative_path);

  if (v.kind === "receipt") {
    const result = await verifyReceipt(v.receipt, { jwks: v.jwks });
    const exp = v.expected;

    if (exp.verificationStatus) {
      check(
        v.id,
        result.verificationStatus === exp.verificationStatus,
        `expected verificationStatus=${exp.verificationStatus}, got ${result.verificationStatus}`,
      );
    }
    if (exp.verificationStatusOneOf) {
      check(
        v.id,
        exp.verificationStatusOneOf.includes(result.verificationStatus),
        `expected verificationStatus in [${exp.verificationStatusOneOf}], got ${result.verificationStatus}`,
      );
    }
    if (typeof exp.signatureValid === "boolean") {
      check(
        v.id,
        result.signatureValid === exp.signatureValid,
        `expected signatureValid=${exp.signatureValid}, got ${result.signatureValid}`,
      );
    }
    if (typeof exp.hashValid === "boolean") {
      check(v.id, result.hashValid === exp.hashValid, `expected hashValid=${exp.hashValid}, got ${result.hashValid}`);
    }
    if (typeof exp.signaturePresent === "boolean") {
      check(
        v.id,
        result.signaturePresent === exp.signaturePresent,
        `expected signaturePresent=${exp.signaturePresent}, got ${result.signaturePresent}`,
      );
    }
    if (exp.errorIncludes) {
      check(
        v.id,
        typeof result.error === "string" && result.error.includes(exp.errorIncludes),
        `expected error to include "${exp.errorIncludes}", got ${JSON.stringify(result.error)}`,
      );
    }
  } else if (v.kind === "chain") {
    const result = await verifyReceiptChain(v.receipts, { jwks: v.jwks });
    const exp = v.expected;

    check(v.id, result.chainValid === exp.chainValid, `expected chainValid=${exp.chainValid}, got ${result.chainValid}`);
    check(v.id, result.brokenAt === exp.brokenAt, `expected brokenAt=${JSON.stringify(exp.brokenAt)}, got ${JSON.stringify(result.brokenAt)}`);
    if (exp.allVerified) {
      const allOk = result.receipts.every((r) => r.verificationStatus === "VERIFIED");
      check(v.id, allOk, `expected every receipt VERIFIED, got statuses [${result.receipts.map((r) => r.verificationStatus)}]`);
    }
  } else {
    failures.push(`${v.id}: unknown vector kind "${v.kind}"`);
  }
}

  return {
    pass: failures.length === 0,
    failures,
    checked,
    vectorCount: index.vector_count,
  };
}

// CLI entrypoint — only runs process.exit when invoked directly (not when
// imported by a node:test wrapper).
if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runConformance();
  if (!r.pass) {
    console.error(`[strix-verifier-conformance] FAIL — ${r.failures.length} mismatch(es) of ${r.checked} checks:`);
    for (const f of r.failures) console.error(`  - ${f}`);
    process.exit(1);
  }
  console.log(
    `[strix-verifier-conformance] PASS — ${r.vectorCount.total} vectors ` +
      `(${r.vectorCount.positive} positive, ${r.vectorCount.negative} negative), ` +
      `${r.checked} assertions, all agree with the vendored verifier.`,
  );
}
