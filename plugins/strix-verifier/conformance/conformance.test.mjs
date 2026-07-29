import test from "node:test";
import assert from "node:assert/strict";
import { runConformance } from "./run-conformance.mjs";

test("Gate-J golden-vector corpus: vendored verifier agrees with every vector", async () => {
  const r = await runConformance();
  assert.ok(
    r.pass,
    `${r.failures.length} conformance mismatch(es):\n` + r.failures.map((f) => `  - ${f}`).join("\n"),
  );
  assert.ok(r.checked >= 20, `expected a substantive number of assertions, got ${r.checked}`);
});
