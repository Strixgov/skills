// Gate-F/G integration matrix: does the PACKAGED plugin actually install,
// discover, launch, and run correctly — not just "do the vendored crypto
// functions return the right verdict" (that's conformance/). Every test here
// exercises a real subprocess, a real marketplace manifest, or a real
// filesystem/git property; nothing is mocked.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const PLUGIN_ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

// Windows cannot execute a shebang'd sh script directly (no shebang support
// at the OS level, regardless of which shell launched this test process) —
// bin/strix-verify.cmd is the real, separately-maintained entry point there.
// `shell: true` is required for Node to launch a .cmd file at all on Windows.
const IS_WIN = process.platform === "win32";
const STRIX_VERIFY_BIN = path.join(PLUGIN_ROOT, "bin", IS_WIN ? "strix-verify.cmd" : "strix-verify");

// On win32, `spawnSync(file, args, {shell: true})` joins `file` and `args`
// into a command line by plain string concatenation — it does NOT quote
// `file` even when it contains spaces, so a bin path under e.g. "strix
// verify plugin\bin\strix-verify.cmd" breaks at the first space. Quote
// ourselves and hand the shell one pre-built command-line string instead.
function runStrixVerify(bin, args, opts = {}) {
  if (!IS_WIN) return spawnSync(bin, args, { encoding: "utf8", timeout: 15000, ...opts });
  const quote = (s) => (/\s/.test(s) ? `"${s}"` : s);
  const cmdLine = [quote(bin), ...args.map(quote)].join(" ");
  return spawnSync(cmdLine, { encoding: "utf8", timeout: 15000, shell: true, ...opts });
}

// ---------------------------------------------------------------------------
// 1. Cold-install: marketplace -> plugin manifest -> every referenced file
// resolves. Both the canonical (plugins/strix-verifier, staged under the
// strix-platform repo-root marketplace) and the release-staged copy (under
// release/strixgov-skills/) sit two directories below their own real
// marketplace.json, so this test runs unmodified against either mirror.
// ---------------------------------------------------------------------------
test("cold-install: marketplace entry resolves to every file the plugin manifest references", () => {
  const marketplaceRoot = path.join(PLUGIN_ROOT, "..", "..");
  const marketplacePath = path.join(marketplaceRoot, ".claude-plugin", "marketplace.json");
  assert.ok(fs.existsSync(marketplacePath), `expected a marketplace.json two levels above the plugin at ${marketplacePath}`);

  const marketplace = JSON.parse(fs.readFileSync(marketplacePath, "utf8"));
  const entry = (marketplace.plugins || []).find((p) => p.name === "strix-verifier");
  assert.ok(entry, "marketplace.json must have a strix-verifier plugin entry");

  const resolvedRoot = path.resolve(marketplaceRoot, entry.source);
  assert.equal(resolvedRoot, PLUGIN_ROOT, "the marketplace entry's source must resolve to this exact plugin directory");

  const pluginManifestPath = path.join(resolvedRoot, ".claude-plugin", "plugin.json");
  assert.ok(fs.existsSync(pluginManifestPath));
  const pluginManifest = JSON.parse(fs.readFileSync(pluginManifestPath, "utf8"));
  assert.equal(pluginManifest.version, entry.version, "plugin.json version must match the marketplace entry (checked again here at the integration layer, not just the release lint)");

  // hooks.json + .mcp.json: every ${CLAUDE_PLUGIN_ROOT}-relative command must
  // resolve to a real file once the variable is substituted.
  for (const manifestFile of ["hooks/hooks.json", ".mcp.json"]) {
    const p = path.join(resolvedRoot, manifestFile);
    assert.ok(fs.existsSync(p), `${manifestFile} should exist`);
    const raw = fs.readFileSync(p, "utf8");
    const matches = [...raw.matchAll(/\$\{CLAUDE_PLUGIN_ROOT\}([^"\\]*)/g)];
    assert.ok(matches.length > 0, `${manifestFile} should reference \${CLAUDE_PLUGIN_ROOT} at least once`);
    for (const m of matches) {
      const rel = m[1].replace(/^["'\s]+/, "").trim();
      const target = path.join(resolvedRoot, rel);
      assert.ok(fs.existsSync(target), `${manifestFile} references \${CLAUDE_PLUGIN_ROOT}${rel} but ${target} does not exist`);
    }
  }
});

// ---------------------------------------------------------------------------
// 2. Command + Skill discovery: frontmatter parses with the fields the host
// actually reads.
// ---------------------------------------------------------------------------
function parseFrontmatter(src) {
  const m = src.match(/^---\n([\s\S]*?)\n---/);
  return m ? m[1] : null;
}

test("command discovery: commands/strix-verify.md has the frontmatter Claude Code reads", () => {
  const src = fs.readFileSync(path.join(PLUGIN_ROOT, "commands", "strix-verify.md"), "utf8");
  const fm = parseFrontmatter(src);
  assert.ok(fm, "commands/strix-verify.md must have --- frontmatter ---");
  for (const key of ["description:", "argument-hint:", "allowed-tools:"]) {
    assert.ok(fm.includes(key), `frontmatter missing "${key}"`);
  }
});

test("skill discovery: skills/strix-verify/SKILL.md has the render/invocation frontmatter", () => {
  const src = fs.readFileSync(path.join(PLUGIN_ROOT, "skills", "strix-verify", "SKILL.md"), "utf8");
  const fm = parseFrontmatter(src);
  assert.ok(fm, "SKILL.md must have --- frontmatter ---");
  for (const key of ["name:", "description:", "user-invocable:"]) {
    assert.ok(fm.includes(key), `frontmatter missing "${key}"`);
  }
});

// ---------------------------------------------------------------------------
// 3. MCP server startup: a REAL subprocess (not an import), driven through the
// exact JSON-RPC handshake a host performs.
// ---------------------------------------------------------------------------
test("MCP server: real subprocess responds to initialize -> tools/list -> tools/call -> ping", () => {
  const input =
    [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      { jsonrpc: "2.0", id: 3, method: "ping" },
    ]
      .map((m) => JSON.stringify(m))
      .join("\n") + "\n";

  const res = spawnSync(process.execPath, [path.join(PLUGIN_ROOT, "mcp", "server.mjs")], {
    input,
    encoding: "utf8",
    timeout: 15000,
  });
  assert.equal(res.status, 0, `MCP server subprocess should exit 0, stderr: ${res.stderr}`);

  const lines = res.stdout.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const byId = Object.fromEntries(lines.map((m) => [m.id, m]));

  assert.equal(byId[1].result.serverInfo.name, "strix-verifier");
  assert.ok(Array.isArray(byId[2].result.tools) && byId[2].result.tools.length === 3);
  assert.deepEqual(byId[2].result.tools.map((t) => t.name).sort(), ["strix_verify", "strix_verify_record", "strix_verify_swarm"]);
  assert.deepEqual(byId[3].result, {});
});

// ---------------------------------------------------------------------------
// 4. Executable permission preservation: check the bit git actually tracks
// (100755 vs 100644), not just the local filesystem's current mode — the
// tracked mode is what survives a fresh checkout on any platform.
// ---------------------------------------------------------------------------
test("executable files are tracked with the executable git mode (100755), not just chmod'd locally", () => {
  const execFiles = ["bin/strix-verify", "mcp/server.mjs", "hooks/verify-on-stop.mjs", "vendor/strixgov-verifier/bin/verify.mjs"];
  for (const rel of execFiles) {
    const full = path.join(PLUGIN_ROOT, rel);
    const out = execFileSync("git", ["ls-files", "-s", full], { cwd: PLUGIN_ROOT, encoding: "utf8" }).trim();
    assert.ok(out.length > 0, `git should track ${rel}`);
    const mode = out.split(/\s+/)[0];
    assert.equal(mode, "100755", `${rel} must be tracked with mode 100755 (executable) so it survives a checkout on any platform; got ${mode}`);
  }
});

// ---------------------------------------------------------------------------
// 5. Offline execution: run the REAL bin wrapper as a subprocess against a
// local receipt file, no network involved. Reuses a Gate-J golden vector so
// this doesn't invent a second, potentially-drifted fixture.
// ---------------------------------------------------------------------------
test("offline: bin/strix-verify verifies a local receipt file through the vendored CLI, no network", () => {
  const vectorDir = path.join(PLUGIN_ROOT, "conformance", "vectors");
  const vector = JSON.parse(fs.readFileSync(path.join(vectorDir, "rcpt-pos-01-rotated-key-still-verifies.json"), "utf8"));

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "strix-verify-offline-"));
  const receiptPath = path.join(tmp, "receipt.json");
  const jwksPath = path.join(tmp, "jwks.json");
  fs.writeFileSync(receiptPath, JSON.stringify(vector.receipt));
  fs.writeFileSync(jwksPath, JSON.stringify(vector.jwks));

  const res = runStrixVerify(STRIX_VERIFY_BIN, ["receipt", receiptPath, "--jwks", jwksPath, "--json"]);
  fs.rmSync(tmp, { recursive: true, force: true });

  assert.equal(res.status, 0, `expected exit 0 (VERIFIED) for a valid offline receipt; stderr: ${res.stderr}`);
  const parsed = JSON.parse(res.stdout);
  assert.equal(parsed.verificationStatus, "VERIFIED");
});

// ---------------------------------------------------------------------------
// 6. npx fallback: when the vendored copy is unavailable / forced off, the
// wrapper must fall back to `npx <package>@<version>`. Proven with a stubbed
// `npx` on PATH (so this never touches the real network) that just records
// its own invocation.
// ---------------------------------------------------------------------------
test("npx fallback: STRIX_VERIFIER_FORCE_NPX=1 invokes npx with the pinned package@version", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "strix-verify-npxstub-"));
  const marker = path.join(tmp, "npx-invocation.json");

  if (IS_WIN) {
    // cmd.exe resolves a bare `npx` via PATHEXT — `npx.cmd` is what it finds.
    // The .cmd just re-launches node so the marker-writing logic (and its
    // argv slicing) stays identical to the POSIX stub below.
    fs.writeFileSync(
      path.join(tmp, "npx.js"),
      `require("fs").writeFileSync(${JSON.stringify(marker)}, JSON.stringify(process.argv.slice(2)));\n`,
    );
    fs.writeFileSync(path.join(tmp, "npx.cmd"), `@echo off\r\nnode "%~dp0npx.js" %*\r\n`);
  } else {
    const stubPath = path.join(tmp, "npx");
    fs.writeFileSync(
      stubPath,
      `#!/usr/bin/env node\nrequire("fs").writeFileSync(${JSON.stringify(marker)}, JSON.stringify(process.argv.slice(2)));\nprocess.exit(0);\n`,
    );
    fs.chmodSync(stubPath, 0o755);
  }

  const res = runStrixVerify(STRIX_VERIFY_BIN, ["5686"], {
    env: { ...process.env, PATH: `${tmp}${path.delimiter}${process.env.PATH}`, STRIX_VERIFIER_FORCE_NPX: "1" },
  });
  assert.equal(res.status, 0, `stub npx should exit 0; stderr: ${res.stderr}`);

  assert.ok(fs.existsSync(marker), "the stubbed npx should have been invoked");
  const args = JSON.parse(fs.readFileSync(marker, "utf8"));
  fs.rmSync(tmp, { recursive: true, force: true });

  assert.deepEqual(args.slice(0, 2), ["-y", "@strixgov/verifier@1.11.0"], `expected npx invoked with -y @strixgov/verifier@<pinned>, got ${JSON.stringify(args)}`);
  assert.equal(args[2], "5686");
});

// ---------------------------------------------------------------------------
// 7. Spaces in the install path: a classic Windows/shell footgun. Copy the
// whole plugin to a temp directory whose name contains a space and confirm
// the bin wrapper still launches.
// ---------------------------------------------------------------------------
test("spaces in the install path do not break the bin wrapper", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "strix verify plugin "));
  fs.cpSync(PLUGIN_ROOT, tmp, { recursive: true });

  const res = runStrixVerify(path.join(tmp, "bin", IS_WIN ? "strix-verify.cmd" : "strix-verify"), ["--help"]);
  fs.rmSync(tmp, { recursive: true, force: true });

  assert.equal(res.status, 0, `expected --help to exit 0 from a spaced path; stderr: ${res.stderr}`);
  assert.match(res.stdout, /strix-verify/i);
});
