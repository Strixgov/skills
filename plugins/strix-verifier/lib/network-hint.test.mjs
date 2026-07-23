// Locks the network-block heuristic against REAL @strixgov/verifier output.
// Run: node --test plugins/strix-verifier/lib/
//
// The messages below are captured verbatim from the vendored verifier — the
// HTTP-403 case is exactly what `node vendor/.../verify.mjs 5686 --json` emits
// inside an egress-restricted environment (the customer's reported failure).

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  classifyVerifierFailure,
  buildRemediation,
  extractFirstUrl,
  networkHintFor,
} from "./network-hint.mjs";

// ── classification: the actionable egress cases ───────────────────────────────

test("egress 403 from a proxy is an EGRESS_BLOCK", () => {
  assert.equal(
    classifyVerifierFailure({
      exitCode: 2,
      text: "Proof API fetch failed: HTTP 403 (https://www.strixgov.com/api/proof/5686)",
    }),
    "EGRESS_BLOCK",
  );
});

test("JWKS 403 is an EGRESS_BLOCK", () => {
  assert.equal(
    classifyVerifierFailure({
      exitCode: 2,
      text: "JWKS fetch failed: HTTP 403 (https://www.strixgov.com/.well-known/strix-jwks.json)",
    }),
    "EGRESS_BLOCK",
  );
});

test("DNS / connect / timeout throws are EGRESS_BLOCK", () => {
  for (const text of [
    "Network error fetching https://www.strixgov.com/api/proof/5686 [ENOTFOUND]: getaddrinfo ENOTFOUND www.strixgov.com",
    "Network error fetching https://www.strixgov.com/api/proof/5686 [ECONNREFUSED]: connect ECONNREFUSED",
    "Network error fetching https://www.strixgov.com/api/proof/5686 [ETIMEDOUT]: Connection timed out.",
    "Network error fetching https://www.strixgov.com/.well-known/strix-jwks.json [UND_ERR_CONNECT_TIMEOUT]: ...",
  ]) {
    assert.equal(classifyVerifierFailure({ exitCode: 2, text }), "EGRESS_BLOCK", text);
  }
});

// ── classification: things that must NOT be reframed ──────────────────────────

test("5xx is SERVICE_UNAVAILABLE, not an egress block", () => {
  assert.equal(
    classifyVerifierFailure({
      exitCode: 2,
      text: "Proof API fetch failed: HTTP 503 (https://www.strixgov.com/api/proof/5686)",
    }),
    "SERVICE_UNAVAILABLE",
  );
});

test("record-not-found (404) is NOT a network block", () => {
  assert.equal(
    classifyVerifierFailure({
      exitCode: 2,
      text: "Proof API fetch failed: HTTP 404 (https://www.strixgov.com/api/proof/does-not-exist)",
    }),
    null,
  );
});

test("unknown signing key is NOT a network block", () => {
  assert.equal(
    classifyVerifierFailure({ exitCode: 2, text: "Key not found in JWKS: strix-prod-2026-05" }),
    null,
  );
});

test("a real FAILED (exit 1) is never reframed as a network blip", () => {
  assert.equal(
    classifyVerifierFailure({ exitCode: 1, text: "Network error fetching https://x [ENOTFOUND]" }),
    null,
  );
});

test("VERIFIED (exit 0) is never a network block", () => {
  assert.equal(classifyVerifierFailure({ exitCode: 0, text: "" }), null);
});

// ── url extraction + remediation shape ────────────────────────────────────────

test("extractFirstUrl pulls the attempted URL out of the 403 message", () => {
  assert.equal(
    extractFirstUrl("Proof API fetch failed: HTTP 403 (https://www.strixgov.com/api/proof/5686)"),
    "https://www.strixgov.com/api/proof/5686",
  );
});

test("EGRESS remediation names the host and offers allowlist + connector + offline", () => {
  const r = buildRemediation({
    kind: "EGRESS_BLOCK",
    attemptedUrl: "https://www.strixgov.com/api/proof/5686",
  });
  assert.equal(r.host, "www.strixgov.com");
  assert.ok(r.paths.length >= 3, "at least allowlist + connector + offline");
  // honest framing
  assert.match(r.summary, /cannot verify/i);
  assert.doesNotMatch(r.summary, /\binvalid record\b/i);
  // the three load-bearing options are present
  assert.match(r.text, /allowlist/i);
  assert.match(r.text, /MCP connector/i);
  assert.match(r.text, /--proof\b/);
  // never recommends weakening security
  assert.doesNotMatch(r.text, /NODE_TLS_REJECT_UNAUTHORIZED|disable TLS/i);
});

test("a custom --proof-base host is reflected in the remediation", () => {
  const r = buildRemediation({
    kind: "EGRESS_BLOCK",
    proofBase: "https://strix.internal.example",
    attemptedUrl: null,
  });
  assert.equal(r.host, "strix.internal.example");
});

test("networkHintFor wires classify + build together (and returns null off-network)", () => {
  const hit = networkHintFor({
    exitCode: 2,
    text: "Proof API fetch failed: HTTP 403 (https://www.strixgov.com/api/proof/5686)",
  });
  assert.equal(hit.kind, "EGRESS_BLOCK");
  assert.equal(networkHintFor({ exitCode: 1, text: "bad signature" }), null);
});
