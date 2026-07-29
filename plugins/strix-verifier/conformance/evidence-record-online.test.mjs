// Gate-J / Gate-G online-path conformance. The receipt/chain vectors in
// run-conformance.mjs exercise the vendored verifier's offline functions;
// this file exercises the NETWORK-based `verify()` path — the one the CLI's
// bare `strix-verify <evidenceId>` and the strix_verify_record MCP tool
// actually use — against a REAL loopback HTTP server (no fetch mocking, no
// re-implemented crypto). Every scenario below is a genuine HTTP round trip.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import crypto from "node:crypto";
import { verify } from "../vendor/strixgov-verifier/src/index.mjs";

function genKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const x = spki.subarray(spki.length - 32).toString("base64url");
  return { privateKey, x };
}

function sign(privateKey, canonical) {
  return crypto.sign(null, Buffer.from(canonical, "utf8"), privateKey).toString("base64url");
}

const KID = "test-online-2026-07";
const { privateKey, x } = genKeyPair();
const CANONICAL = "test-canonical-payload-for-online-path-conformance";
const SIGNATURE = sign(privateKey, CANONICAL);
const GOOD_JWKS = { keys: [{ kty: "OKP", crv: "Ed25519", kid: KID, x }] };

// A small routable test server: each route is a function of (req) -> response
// spec, so each test case starts its own server with only the routes it needs.
function startServer(routes) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const route = routes[req.url];
      if (!route) {
        res.writeHead(404, { "content-type": "application/json" }).end(JSON.stringify({ error: "not found" }));
        return;
      }
      if (route.raw) {
        res.writeHead(route.status ?? 200, { "content-type": "application/json" });
        res.end(route.raw);
        return;
      }
      res.writeHead(route.status ?? 200, { "content-type": "application/json" });
      res.end(JSON.stringify(route.body));
    });
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function baseUrl(server) {
  const { port } = server.address();
  return `http://127.0.0.1:${port}`;
}

test("online: valid signature over the real proof + JWKS endpoints -> VERIFIED", async () => {
  const server = await startServer({
    "/api/proof/1": { body: { evidenceId: "1", schemaVersion: "1", signedPayload: CANONICAL, signature: SIGNATURE, signingKeyId: KID } },
    "/.well-known/strix-jwks.json": { body: GOOD_JWKS },
  });
  try {
    const url = baseUrl(server);
    const r = await verify("1", { proofBase: url, jwksBase: url });
    assert.equal(r.verificationStatus, "VERIFIED");
    assert.equal(r.signatureValid, true);
  } finally {
    server.close();
  }
});

test("online: tampered signedPayload (bytes changed after signing) -> COMPLIANCE_VIOLATION, not VERIFIED", async () => {
  const server = await startServer({
    "/api/proof/1": { body: { evidenceId: "1", schemaVersion: "1", signedPayload: CANONICAL + "-tampered", signature: SIGNATURE, signingKeyId: KID } },
    "/.well-known/strix-jwks.json": { body: GOOD_JWKS },
  });
  try {
    const url = baseUrl(server);
    const r = await verify("1", { proofBase: url, jwksBase: url });
    assert.equal(r.verificationStatus, "COMPLIANCE_VIOLATION");
    assert.equal(r.signatureValid, false);
  } finally {
    server.close();
  }
});

test("online: no signature field at all -> LEGACY_UNSIGNED (never VERIFIED, never a crash)", async () => {
  const server = await startServer({
    "/api/proof/1": { body: { evidenceId: "1", schemaVersion: "1", signedPayload: CANONICAL } },
    "/.well-known/strix-jwks.json": { body: GOOD_JWKS },
  });
  try {
    const url = baseUrl(server);
    const r = await verify("1", { proofBase: url, jwksBase: url });
    assert.equal(r.verificationStatus, "LEGACY_UNSIGNED");
  } finally {
    server.close();
  }
});

test("online: signature present but signingKeyId missing -> UNSIGNED", async () => {
  const server = await startServer({
    "/api/proof/1": { body: { evidenceId: "1", schemaVersion: "1", signedPayload: CANONICAL, signature: SIGNATURE } },
    "/.well-known/strix-jwks.json": { body: GOOD_JWKS },
  });
  try {
    const url = baseUrl(server);
    const r = await verify("1", { proofBase: url, jwksBase: url });
    assert.equal(r.verificationStatus, "UNSIGNED");
  } finally {
    server.close();
  }
});

test("online: record not found (404) -> ERROR (cannot-verify), never a false negative or crash", async () => {
  const server = await startServer({
    "/api/proof/1": { status: 404, body: { error: "not found" } },
    "/.well-known/strix-jwks.json": { body: GOOD_JWKS },
  });
  try {
    const url = baseUrl(server);
    const r = await verify("1", { proofBase: url, jwksBase: url });
    assert.equal(r.verificationStatus, "ERROR");
    assert.match(r.error, /No Record Found/);
  } finally {
    server.close();
  }
});

test("online: proof API 500 -> ERROR with the HTTP status in the message", async () => {
  const server = await startServer({
    "/api/proof/1": { status: 500, body: { error: "internal" } },
    "/.well-known/strix-jwks.json": { body: GOOD_JWKS },
  });
  try {
    const url = baseUrl(server);
    const r = await verify("1", { proofBase: url, jwksBase: url });
    assert.equal(r.verificationStatus, "ERROR");
    assert.match(r.error, /HTTP 500/);
  } finally {
    server.close();
  }
});

test("online: signingKeyId not present in JWKS -> ERROR (key not found), never a false VERIFIED", async () => {
  const server = await startServer({
    "/api/proof/1": { body: { evidenceId: "1", schemaVersion: "1", signedPayload: CANONICAL, signature: SIGNATURE, signingKeyId: "unknown-kid-2099" } },
    "/.well-known/strix-jwks.json": { body: GOOD_JWKS },
  });
  try {
    const url = baseUrl(server);
    const r = await verify("1", { proofBase: url, jwksBase: url });
    assert.equal(r.verificationStatus, "ERROR");
    assert.match(r.error, /Key not found in JWKS/);
  } finally {
    server.close();
  }
});

test("online: malformed JWKS response body (not valid JSON) -> ERROR, no uncaught crash", async () => {
  const server = await startServer({
    "/api/proof/1": { body: { evidenceId: "1", schemaVersion: "1", signedPayload: CANONICAL, signature: SIGNATURE, signingKeyId: KID } },
    "/.well-known/strix-jwks.json": { raw: "{ this is not valid json " },
  });
  try {
    const url = baseUrl(server);
    const r = await verify("1", { proofBase: url, jwksBase: url });
    assert.equal(r.verificationStatus, "ERROR");
  } finally {
    server.close();
  }
});

test("online: connection refused (server closed before use) -> ERROR with a network error, not a crash", async () => {
  const server = await startServer({});
  const url = baseUrl(server);
  server.close();
  await new Promise((resolve) => server.once("close", resolve));

  const r = await verify("1", { proofBase: url, jwksBase: url });
  assert.equal(r.verificationStatus, "ERROR");
  assert.match(r.error, /Network error|ECONNREFUSED/);
});
