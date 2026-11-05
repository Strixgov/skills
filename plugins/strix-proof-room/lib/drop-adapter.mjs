// @strixgov/proof-fabric-drop-adapter
//
// The first renderer adapter for the Strix Proof Fabric
// (docs/architecture/proof-fabric-v1.md). It projects a canonical room manifest
// into DROP-compatible content. Its entire contract is captured by the law:
//
//   Every leaf may only render what the root can currently prove.
//
// Hard rules this module embodies (and tests pin):
//   - It RENDERS proof; it never DETERMINES proof. Every live claim is emitted
//     as a <strix-verify> embed whose verdict is computed in the visitor's
//     browser against the canonical proof route — never a static "VERIFIED".
//   - verificationUrls are preserved verbatim and must resolve to a canonical
//     Strix host (fail-closed re-check; PF-8 / Gate J).
//   - It never stores or passes through private signing material.
//   - ROADMAP claims render visibly separated, never as live.
//   - It applies expiry / revocation, and on a closed room it still tells the
//     reader the evidence remains independently verifiable (room availability
//     != evidence validity).
//   - Forwarding-survival: every rendered room carries the npx verifier command
//     and the canonical proof URL, so proof survives the adapter being deleted.
//
// This adapter is renderer-specific in name only — the manifest and render
// model are provider-independent; a Vercel/Salesforce/static-HTML adapter would
// reuse the same render model and swap toHtml.

const CANONICAL_VERIFICATION_HOSTS = new Set([
  "www.strixgov.com",
  "strixgov.com",
]);

const EMBED_SCRIPT_URL = "https://verify.strixgov.com/embed.js";

// Keys that would mean a manifest is carrying secrets it must never carry.
const FORBIDDEN_KEY_RE =
  /(privatekey|signingkey|secretkey|secret|seed|mnemonic|passphrase|password|apikey|api_key)/i;

/** npx command anyone can run to verify a record with zero adapter dependency. */
export function verifierCommand(sourceId) {
  return `npx @strixgov/verifier@latest ${sourceId}`;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function assertNoSecrets(manifest) {
  // Walk every key in the manifest; reject anything that looks like key
  // material. The adapter must never store or relay private signing material.
  const stack = [manifest];
  while (stack.length) {
    const node = stack.pop();
    if (node === null || typeof node !== "object") continue;
    for (const [k, val] of Object.entries(node)) {
      if (FORBIDDEN_KEY_RE.test(k)) {
        throw new Error(
          `proof-fabric-drop-adapter: manifest carries a forbidden secret-like field "${k}" — ` +
            `a leaf must never store private signing material`,
        );
      }
      if (val && typeof val === "object") stack.push(val);
    }
  }
}

function parseCanonicalUrl(verificationUrl, sourceId) {
  let url;
  try {
    url = new URL(verificationUrl);
  } catch {
    throw new Error(
      `proof-fabric-drop-adapter: evidence "${sourceId}" verificationUrl is not an absolute URL`,
    );
  }
  if (url.protocol !== "https:") {
    throw new Error(
      `proof-fabric-drop-adapter: evidence "${sourceId}" verificationUrl must be https`,
    );
  }
  if (!CANONICAL_VERIFICATION_HOSTS.has(url.hostname)) {
    throw new Error(
      `proof-fabric-drop-adapter: evidence "${sourceId}" verificationUrl host "${url.hostname}" ` +
        `is not canonical — the adapter may not front a non-Strix trust source`,
    );
  }
  return url;
}

/**
 * Fail-closed structural re-check of the security-critical manifest invariants
 * the adapter depends on. This intentionally duplicates the load-bearing subset
 * of scripts/lint-proof-fabric-claims.mjs so the adapter is safe even if a
 * manifest reaches it without passing the build-time lint.
 */
export function validateForRender(manifest) {
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("proof-fabric-drop-adapter: manifest must be an object");
  }
  if (manifest.proofRoomVersion !== "1.0") {
    throw new Error("proof-fabric-drop-adapter: unsupported proofRoomVersion");
  }
  assertNoSecrets(manifest);

  const refs = Array.isArray(manifest.evidenceReferences)
    ? manifest.evidenceReferences
    : [];
  const declared = new Map();
  for (const ref of refs) {
    parseCanonicalUrl(ref?.verificationUrl, ref?.sourceId);
    declared.set(ref.sourceId, ref);
  }

  const claims = Array.isArray(manifest.claims) ? manifest.claims : [];
  for (const claim of claims) {
    const evIds = Array.isArray(claim?.sourceEvidenceIds) ? claim.sourceEvidenceIds : [];
    if (claim?.status === "PROVEN" && evIds.length === 0) {
      throw new Error(
        `proof-fabric-drop-adapter: PROVEN claim "${claim.claimId}" is unbound`,
      );
    }
    if (claim?.status === "ROADMAP" && evIds.length > 0) {
      throw new Error(
        `proof-fabric-drop-adapter: ROADMAP claim "${claim.claimId}" carries evidence — cannot render as live`,
      );
    }
    for (const evId of evIds) {
      if (!declared.has(evId)) {
        throw new Error(
          `proof-fabric-drop-adapter: claim "${claim.claimId}" references undeclared evidence "${evId}"`,
        );
      }
    }
  }
  return declared;
}

/**
 * Resolve whether the room is open right now, independent of evidence validity.
 * Returns { open, state, reason }. `state` is one of ACTIVE | EXPIRED | REVOKED.
 */
export function resolveRoomAccess(manifest, now = new Date()) {
  const at = now instanceof Date ? now : new Date(now);
  if (manifest.status === "REVOKED" || manifest.revokedAt) {
    return { open: false, state: "REVOKED", reason: "Room access was revoked." };
  }
  if (manifest.expiresAt) {
    const expires = new Date(manifest.expiresAt);
    if (Number.isFinite(expires.getTime()) && at.getTime() >= expires.getTime()) {
      return { open: false, state: "EXPIRED", reason: "Room access has expired." };
    }
  }
  if (manifest.status === "EXPIRED") {
    return { open: false, state: "EXPIRED", reason: "Room access has expired." };
  }
  if (manifest.status === "ACTIVE") {
    return { open: true, state: "ACTIVE", reason: null };
  }
  // Unknown/missing status fails closed.
  return { open: false, state: manifest.status ?? "UNKNOWN", reason: "Room is not active." };
}

/**
 * Build a renderer-independent render model from a manifest. The model is the
 * portable artifact; toHtml() (or any other renderer) consumes it.
 *
 * opts: { now?, subtitle?, ctaText?, boundaries?: string[] }
 */
export function renderRoom(manifest, opts = {}) {
  const declared = validateForRender(manifest);
  const access = resolveRoomAccess(manifest, opts.now);

  const claims = Array.isArray(manifest.claims) ? manifest.claims : [];
  const proven = claims.filter((c) => c.status === "PROVEN");
  const roadmap = claims.filter((c) => c.status === "ROADMAP");
  const legacy = claims.filter((c) => c.status === "LEGACY_UNSIGNED");

  // Distinct evidence refs used by live (PROVEN/LEGACY) claims, in declared order.
  const liveEvidenceIds = new Set();
  for (const c of [...proven, ...legacy]) {
    for (const id of c.sourceEvidenceIds || []) liveEvidenceIds.add(id);
  }
  const liveEvidence = [...liveEvidenceIds].map((id) => {
    const ref = declared.get(id);
    const url = new URL(ref.verificationUrl);
    return {
      sourceId: id,
      sourceType: ref.sourceType,
      verificationUrl: ref.verificationUrl,
      proofBase: url.origin, // canonical host preserved for the embed
      command: verifierCommand(id),
    };
  });

  return {
    proofRoomVersion: manifest.proofRoomVersion,
    roomId: manifest.roomId,
    title: manifest.title,
    subtitle:
      opts.subtitle ??
      "AI agents should not be able to act without control — and every governed action should leave a receipt you can check yourself.",
    access,
    liveEvidence,
    claims: { proven, roadmap, legacy },
    boundaries: opts.boundaries ?? [],
    ctaText: opts.ctaText ?? "Let Strix govern one action in your pipeline.",
  };
}

function renderEmbed(ev) {
  // The embed computes the verdict in-browser. The adapter never asserts it.
  return (
    `<strix-verify evidence-id="${escapeHtml(ev.sourceId)}" ` +
    `proof-base="${escapeHtml(ev.proofBase)}"></strix-verify>\n` +
    `<noscript><a href="${escapeHtml(ev.verificationUrl)}">Verify record ` +
    `${escapeHtml(ev.sourceId)}</a> — or run <code>${escapeHtml(ev.command)}</code></noscript>`
  );
}

/** Render the model to a DROP-compatible HTML fragment. */
export function toHtml(model) {
  const parts = [];
  parts.push(`<section class="strix-proof-room" data-room-id="${escapeHtml(model.roomId)}">`);
  parts.push(`<script src="${EMBED_SCRIPT_URL}" async></script>`);
  parts.push(`<header><h1>${escapeHtml(model.title)}</h1><p>${escapeHtml(model.subtitle)}</p></header>`);

  if (!model.access.open) {
    // Closed room: deny access, but the proof remains independently verifiable.
    parts.push(
      `<div class="strix-room-closed" data-state="${escapeHtml(model.access.state)}">` +
        `<strong>${model.access.state === "REVOKED" ? "ROOM REVOKED" : "ROOM EXPIRED"}</strong>` +
        `<p>${escapeHtml(model.access.reason)} The proof records remain independently verifiable.</p>`,
    );
    for (const ev of model.liveEvidence) {
      parts.push(
        `<p><a href="${escapeHtml(ev.verificationUrl)}">Verify record ${escapeHtml(ev.sourceId)}</a> ` +
          `— or run <code>${escapeHtml(ev.command)}</code></p>`,
      );
    }
    parts.push(`</div></section>`);
    return parts.join("\n");
  }

  // Live proof: one self-verifying embed per live evidence record.
  if (model.liveEvidence.length > 0) {
    parts.push(`<div class="strix-live-proof">`);
    for (const ev of model.liveEvidence) parts.push(renderEmbed(ev));
    parts.push(`</div>`);
  }

  // Proven claims.
  if (model.claims.proven.length > 0) {
    parts.push(`<ul class="strix-claims strix-claims-proven">`);
    for (const c of model.claims.proven) {
      parts.push(`<li>${escapeHtml(c.text ?? c.claimId)}</li>`);
    }
    parts.push(`</ul>`);
  }

  // Roadmap claims — visibly separated, explicitly not live.
  if (model.claims.roadmap.length > 0) {
    parts.push(`<div class="strix-roadmap"><p>On the roadmap (not yet provable):</p><ul>`);
    for (const c of model.claims.roadmap) {
      parts.push(`<li data-status="ROADMAP">${escapeHtml(c.text ?? c.claimId)} <em>(roadmap)</em></li>`);
    }
    parts.push(`</ul></div>`);
  }

  // Boundaries.
  if (model.boundaries.length > 0) {
    parts.push(`<div class="strix-boundaries"><p>What this does not claim:</p><ul>`);
    for (const b of model.boundaries) parts.push(`<li>${escapeHtml(b)}</li>`);
    parts.push(`</ul></div>`);
  }

  // Single CTA.
  parts.push(`<div class="strix-cta"><strong>${escapeHtml(model.ctaText)}</strong></div>`);
  parts.push(`</section>`);
  return parts.join("\n");
}

/** Convenience: manifest -> DROP HTML in one call. */
export function renderRoomHtml(manifest, opts = {}) {
  return toHtml(renderRoom(manifest, opts));
}

export default { renderRoom, renderRoomHtml, toHtml, resolveRoomAccess, validateForRender, verifierCommand };
