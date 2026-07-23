// network-hint — turn the verifier's exit-2 "cannot verify" into something a
// customer can ACT on when the real cause is a blocked outbound network.
//
// Why this exists: every online surface of this plugin (slash command, MCP
// server, Stop hook) shells out to @strixgov/verifier, which fetches the proof
// record + JWKS over HTTPS from www.strixgov.com. In a sandbox, CI container,
// corporate proxy, or an egress-allowlisted environment (e.g. Claude Code on
// the web), that fetch is blocked and the verifier exits 2 / ERROR with a
// message like `Proof API fetch failed: HTTP 403 (...)`. A customer who doesn't
// know what to do hits a dead end. This module names the cause and lists the
// ways out.
//
// Discipline — this module is RENDER-ONLY:
//   * It never decides a verdict and never changes the exit code. An ERROR
//     stays ERROR; "cannot verify" is never reframed as "invalid" (and a real
//     FAILED / exit 1 is never reframed as a network blip — see the exitCode
//     guard below).
//   * It never tells anyone to weaken their own network security (e.g. disable
//     TLS validation) to force a verdict — allowlist, use the hosted connector,
//     or verify offline.
//   * Zero dependencies, pure functions — mirrors the verifier + this plugin.
//
// The substrings below are grounded in the vendored verifier's real output
// (src/index.mjs `fetchWithContext` + the `<X> fetch failed: HTTP <n>` throws);
// lib/network-hint.test.mjs pins them against captured messages.

export const DEFAULT_PROOF_BASE = "https://www.strixgov.com";

// Outbound fetch was blocked / never reached the host, OR a proxy answered with
// a gateway-style refusal (403 forbidden by an egress proxy, 407 proxy-auth).
// These are the actionable "your environment blocked it" cases.
const EGRESS_SIGNATURES = [
  "network error fetching", // fetch() threw — DNS / connect / TLS (wraps the code)
  "fetch failed: http 403", // egress proxy answered 403 (the sandbox case)
  "fetch failed: http 407", // proxy authentication required
  "enotfound",
  "eai_again",
  "econnrefused",
  "etimedout",
  "und_err_connect_timeout",
];

// The host was reached but returned a server error. Transient, not an egress
// problem — different remediation (retry), so classified separately.
const SERVICE_SIGNATURES = [
  "fetch failed: http 500",
  "fetch failed: http 502",
  "fetch failed: http 503",
  "fetch failed: http 504",
];

/**
 * Classify a verifier failure from its exit code + emitted text.
 *
 * @param {{ exitCode?: number, text?: string }} input
 * @returns {"EGRESS_BLOCK" | "SERVICE_UNAVAILABLE" | null}
 *   null means "not a network-shaped failure" — leave the verifier's own
 *   message untouched (e.g. unknown signing key, record-not-found 404, a real
 *   signature/hash FAILED, or a clean VERIFIED).
 */
export function classifyVerifierFailure({ exitCode, text } = {}) {
  // Only exit 2 ("cannot verify") is ever network-shaped. Exit 0 (VERIFIED) and
  // exit 1 (a real signature/hash FAILED) must never be reframed.
  if (exitCode !== 2) return null;
  const hay = String(text || "").toLowerCase();
  if (!hay) return null;
  // 5xx checked before the broader egress set so a 503 isn't mislabeled.
  if (SERVICE_SIGNATURES.some((s) => hay.includes(s))) return "SERVICE_UNAVAILABLE";
  if (EGRESS_SIGNATURES.some((s) => hay.includes(s))) return "EGRESS_BLOCK";
  return null;
}

/** Pull the first http(s) URL out of an error string, or null. */
export function extractFirstUrl(text) {
  const m = String(text || "").match(/https?:\/\/[^\s)"'<>]+/);
  return m ? m[0] : null;
}

function hostOf(url, fallbackBase) {
  for (const candidate of [url, fallbackBase, DEFAULT_PROOF_BASE]) {
    if (!candidate) continue;
    try {
      return new URL(candidate).host;
    } catch {
      /* try next */
    }
  }
  return "www.strixgov.com";
}

/**
 * Build a structured, render-only remediation for a classified network failure.
 *
 * @param {{ kind: "EGRESS_BLOCK" | "SERVICE_UNAVAILABLE", proofBase?: string, attemptedUrl?: string }} input
 * @returns {{ kind: string, host: string, summary: string, paths: {title: string, detail: string}[], text: string }}
 */
export function buildRemediation({ kind, proofBase, attemptedUrl } = {}) {
  const host = hostOf(attemptedUrl, proofBase);

  if (kind === "SERVICE_UNAVAILABLE") {
    const summary =
      `Reached ${host} but it returned a server error (5xx). This is "cannot verify", ` +
      `not "invalid" — the record is unaffected.`;
    const paths = [
      { title: "Retry shortly", detail: "A 5xx is usually transient. Re-run in a few minutes." },
      {
        title: "Verify offline",
        detail: "If you have the proof + JWKS as local files, pass --proof proof.json --jwks jwks.json (no network).",
      },
    ];
    return { kind, host, summary, paths, text: renderText(summary, paths) };
  }

  // EGRESS_BLOCK (default)
  const summary =
    `Could not reach ${host} to fetch the proof/JWKS. This is "cannot verify", not "invalid" — ` +
    `the record is fine; this environment is blocking the verifier's outbound network to ${host}.`;
  const paths = [
    {
      title: `Allowlist ${host}`,
      detail:
        `Add ${host} to your environment's allowed network/egress domains and re-run. ` +
        `On Claude Code (web) an environment or organization admin sets this in the environment's ` +
        `network settings — Strix can't set it for you, it's your environment's policy.`,
    },
    {
      title: "Use the hosted Strix Verify MCP connector",
      detail:
        "It re-derives the same Ed25519 + JWKS verdict through Strix infrastructure, so it is NOT " +
        "subject to this container's egress allowlist. Same trust model — Strix is still never on the " +
        "trust path; the connector only fetches the public proof + JWKS on your behalf.",
    },
    {
      title: "Verify offline",
      detail:
        "If you can bring the proof + JWKS in as local files, no network is used: " +
        "strix-verify <id> --proof proof.json --jwks jwks.json.",
    },
    {
      title: "Point at a self-hosted Strix",
      detail: "If you verify against your own deployment, pass --proof-base <url> --jwks-base <url>.",
    },
  ];
  return { kind, host, summary, paths, text: renderText(summary, paths) };
}

function renderText(summary, paths) {
  const lines = [summary, "", "Ways to get a verdict:"];
  paths.forEach((p, i) => {
    lines.push(`  ${i + 1}. ${p.title} — ${p.detail}`);
  });
  return lines.join("\n");
}

/**
 * Convenience: classify + (when network-shaped) build remediation in one call.
 * Returns null when the failure is not network-shaped.
 *
 * @param {{ exitCode?: number, text?: string, proofBase?: string }} input
 */
export function networkHintFor({ exitCode, text, proofBase } = {}) {
  const kind = classifyVerifierFailure({ exitCode, text });
  if (!kind) return null;
  return buildRemediation({ kind, proofBase, attemptedUrl: extractFirstUrl(text) });
}
