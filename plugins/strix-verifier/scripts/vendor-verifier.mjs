#!/usr/bin/env node
// Reproducibly (re-)vendor the published @strixgov/verifier into vendor/.
//
//   node scripts/vendor-verifier.mjs            # vendor the pinned version from config.json
//   node scripts/vendor-verifier.mjs 1.22.0     # vendor an explicit version
//
// What it does: `npm pack @strixgov/verifier@<version> --json`, extracts the
// tarball into vendor/strixgov-verifier/, and writes vendor/PROVENANCE.json
// (registry integrity + shasum + a self-verified digest over the extracted
// tree) so the vendored copy is auditable against the registry. It does NOT
// modify any source — vendoring is a verbatim copy of the MIT-published
// package (re-implementing the canonical/verify logic is forbidden; the
// published package is the single source of truth).
//
// It does NOT touch the version pins outside vendor/ — those are listed at the
// end of a successful run and checked by the release lint.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  readFileSync,
  writeFileSync,
  rmSync,
  renameSync,
  mkdtempSync,
  readdirSync,
  chmodSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";
import { tmpdir } from "node:os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = join(__dirname, "..");

let version = process.argv[2];
if (!version) {
  try {
    version = JSON.parse(readFileSync(join(PLUGIN_ROOT, "config.json"), "utf8")).verifierVersion;
  } catch {
    /* fall through */
  }
}
if (!version) {
  console.error("No version given and none found in config.json. Usage: node scripts/vendor-verifier.mjs <version>");
  process.exit(1);
}

const spec = `@strixgov/verifier@${version}`;
const work = mkdtempSync(join(tmpdir(), "strix-vendor-"));
console.error(`Packing ${spec} …`);

// --json, NOT the stderr notices. npm ELIDES the middle of the integrity in
// its human-readable notice output ("sha512-O+MzZ1o5bd1Iv[...]VhEMO8NAU/Lig=="),
// so scraping stderr yields a value that looks like a pin and pins nothing.
// The JSON form carries the full integrity and the shasum.
const pack = spawnSync("npm", ["pack", spec, "--pack-destination", work, "--json"], {
  encoding: "utf8",
});
if (pack.status !== 0) {
  console.error(pack.stderr || "npm pack failed");
  process.exit(pack.status || 1);
}
let integrity, shasum;
try {
  const meta = JSON.parse(pack.stdout)[0];
  integrity = meta?.integrity;
  shasum = meta?.shasum;
} catch {
  console.error("Could not parse `npm pack --json` output — refusing to write provenance.");
  process.exit(1);
}
if (!integrity || !shasum) {
  console.error(`npm pack --json returned no integrity/shasum for ${spec} — refusing to write provenance.`);
  process.exit(1);
}
const tgz = readdirSync(work).find((f) => f.endsWith(".tgz"));
if (!tgz) {
  console.error("Could not locate packed tarball.");
  process.exit(1);
}

const dest = join(PLUGIN_ROOT, "vendor", "strixgov-verifier");
if (existsSync(dest)) rmSync(dest, { recursive: true, force: true });

const extract = spawnSync("tar", ["-xzf", join(work, tgz), "-C", work], { encoding: "utf8" });
if (extract.status !== 0) {
  console.error(extract.stderr || "tar extract failed");
  process.exit(extract.status || 1);
}
renameSync(join(work, "package"), dest);
// npm tarballs ship bin scripts as 0644 (the exec bit is normally restored at
// install time by npm's bin linking, which vendoring bypasses) — restore it so
// the CLI runs directly and git tracks 100755, per the integration test.
chmodSync(join(dest, "bin", "verify.mjs"), 0o755);
rmSync(work, { recursive: true, force: true });

// ─── Write vendor/PROVENANCE.json ────────────────────────────────────────
//
// This used to be hand-maintained: the script vendored, printed an integrity
// string, and told you to remember the rest. Two things made that unsafe —
// the printed integrity was npm's ELIDED form (see above), and the digest had
// to be transcribed by hand into a file whose entire job is to be a
// fingerprint nobody typed. Copying a hash by hand into a trust artifact is
// the failure mode this repo lints for elsewhere.
//
// `vendoredTreeSha256` is a stable digest over the extracted tree: files
// sorted by path, each contributing "<relpath>\0<content>\0". The release
// lints recompute it INDEPENDENTLY from the same tree and fail on mismatch —
// duplicated deliberately, because the plugin ships standalone into two
// public mirrors and cannot import from scripts/. The property they enforce
// is consistency between file and tree, so an independent reimplementation is
// the right relationship, not a shared helper.

function treeDigest(root) {
  const walk = (d) =>
    readdirSync(d, { withFileTypes: true }).flatMap((e) => {
      const p = join(d, e.name);
      return e.isDirectory() ? walk(p) : [p];
    });
  const h = createHash("sha256");
  for (const f of walk(root).sort()) {
    h.update(relative(root, f).replace(/\\/g, "/"));
    h.update("\0");
    h.update(readFileSync(f));
    h.update("\0");
  }
  return h.digest("hex");
}

const provPath = join(PLUGIN_ROOT, "vendor", "PROVENANCE.json");
const provenance = {
  package: "@strixgov/verifier",
  version,
  source: "npm",
  registry: "https://registry.npmjs.org/",
  tarballIntegrity: integrity,
  tarballShasum: shasum,
  vendoredTreeSha256: treeDigest(dest),
  note:
    "Verbatim MIT-published package, vendored via scripts/vendor-verifier.mjs (never re-implemented). " +
    "tarballIntegrity/tarballShasum pin the npm registry artifact; vendoredTreeSha256 is a stable digest " +
    "over the extracted tree (sorted relative-path + content) that CI recomputes to detect any manual edit.",
};
writeFileSync(provPath, JSON.stringify(provenance, null, 2) + "\n");

// Self-verify: re-read the file and recompute from disk, so a write that did
// not land — or a tree that changed between digest and write — fails here
// rather than at the next release gate.
const written = JSON.parse(readFileSync(provPath, "utf8"));
const recomputed = treeDigest(dest);
if (written.vendoredTreeSha256 !== recomputed) {
  console.error(
    `PROVENANCE.json self-verify FAILED: wrote ${written.vendoredTreeSha256}, tree recomputes to ${recomputed}.`,
  );
  process.exit(1);
}

console.error(`Vendored ${spec} → vendor/strixgov-verifier`);
console.error(`registry integrity: ${integrity}`);
console.error(`registry shasum:    ${shasum}`);
console.error(`vendored tree:      ${provenance.vendoredTreeSha256} (self-verified)`);
console.error(`Wrote vendor/PROVENANCE.json @ ${version}`);
console.error("");
console.error("STILL MANUAL — the version pins outside vendor/ are not touched by this script:");
console.error("  config.json verifierVersion · .claude-plugin/plugin.json version");
console.error("  bin/strix-verify · bin/strix-verify.cmd · mcp/server.mjs · hooks/verify-on-stop.mjs");
console.error("  and every .claude-plugin/marketplace.json copy.");
console.error("Run the release lint after bumping them; it checks each pin against config.json.");
