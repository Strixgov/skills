#!/usr/bin/env node
// Reproducibly (re-)vendor the published @strixgov/verifier into vendor/.
//
//   node scripts/vendor-verifier.mjs            # vendor the pinned version from config.json
//   node scripts/vendor-verifier.mjs 1.20.0     # vendor an explicit version
//
// What it does: `npm pack @strixgov/verifier@<version>`, extracts the tarball
// into vendor/strixgov-verifier/, and prints the npm-reported integrity sha512
// so the vendored copy is auditable against the registry. It does NOT modify
// any source — vendoring is a verbatim copy of the MIT-published package
// (re-implementing the canonical/verify logic is forbidden; the published
// package is the single source of truth).

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, renameSync, mkdtempSync, readdirSync, chmodSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
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

const pack = spawnSync("npm", ["pack", spec, "--pack-destination", work], { encoding: "utf8" });
if (pack.status !== 0) {
  console.error(pack.stderr || "npm pack failed");
  process.exit(pack.status || 1);
}
// npm prints the integrity/shasum on stderr (notices) and the tarball name on stdout.
const integrity = (pack.stderr.match(/integrity:\s*(\S+)/) || [])[1];
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

console.error(`Vendored ${spec} → vendor/strixgov-verifier`);
if (integrity) console.error(`registry integrity: ${integrity}`);
console.error("Remember to bump verifierVersion in config.json + plugin.json if the version changed.");
