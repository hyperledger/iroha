import assert from "node:assert/strict";
import test from "node:test";
import { buildCompilerRequest } from "../src/kotodamaCompiler/client.js";

test("compiler source sets preserve complete named files for native and service dispatch", () => {
  const source = 'seiyaku App { include "parts/view.ko"; }';
  const request = buildCompilerRequest(source, {
    sourceName: "contracts/./app.ko",
    sources: [{ sourceName: "contracts/parts/view.ko", source: "view fn value() authorize(anyone) -> int { 7 }" }],
  });
  assert.deepEqual(request, {
    source, artifacts: [], sourceName: "contracts/app.ko", zk: false,
    sources: [{ sourceName: "contracts/parts/view.ko", source: "view fn value() authorize(anyone) -> int { 7 }" }],
  });
});

test("compiler source sets reject ambiguous paths and missing root identities", () => {
  assert.throws(() => buildCompilerRequest("seiyaku App {}", { sources: [] }), /sourceName is required/u);
  for (const sourceName of ["../escape.ko", "/absolute.ko", "C:\\absolute.ko"]) {
    assert.throws(() => buildCompilerRequest("seiyaku App {}", {
      sourceName: "app.ko", sources: [{ sourceName, source: "" }],
    }), /source paths|source path escapes/u);
  }
  assert.throws(() => buildCompilerRequest("seiyaku App {}", {
    sourceName: "app.ko", sources: [{ sourceName: "other/../app.ko", source: "" }],
  }), /duplicate Kotodama source path/u);
});

test("compiler source set limits apply across all caller supplied files", () => {
  assert.throws(() => buildCompilerRequest("seiyaku App {}", {
    sourceName: "app.ko", sources: Array.from({ length: 512 }, (_, index) => ({ sourceName: `${index}.ko`, source: "" })),
  }), /at most 512 files/u);
  assert.throws(() => buildCompilerRequest("seiyaku App {}", {
    sourceName: "app.ko", sources: Array.from({ length: 16 }, (_, index) => ({ sourceName: `${index}.ko`, source: " ".repeat(1024 * 1024) })),
  }), /16777216-byte limit/u);
});

test("compiler source entries must be inert data objects", () => {
  const source = { sourceName: "helper.ko", get source() { throw new Error("getter must not run"); } };
  assert.throws(() => buildCompilerRequest("seiyaku App {}", { sourceName: "app.ko", sources: [source] }), /enumerable data property/u);
});


test("compiler source sets preserve locked packages and bound their complete inventories", () => {
  const pkg = { identity: "math@1", modules: [{ sourceName: "src/math.ko", source: "module Math {}" }], sources: [{ sourceName: "src/body.ko", source: "" }], exports: ["Math::value"], imports: [] };
  const request = buildCompilerRequest("seiyaku App {}", { sourceName: "app.ko", imports: [{ alias: "Math", package: "math@1" }], packages: [pkg] });
  assert.deepEqual(request.packages, [{ ...pkg, artifacts: [] }]);
  assert.deepEqual(request.imports, [{ alias: "Math", package: "math@1" }]);
  assert.throws(() => buildCompilerRequest("seiyaku App {}", { sourceName: "app.ko", packages: [pkg, pkg] }), /duplicate package identity/u);
  assert.throws(() => buildCompilerRequest("seiyaku App {}", { sourceName: "app.ko", packages: [{ ...pkg, sources: [{ sourceName: "src/./math.ko", source: "" }] }] }), /duplicate Kotodama source path/u);
  assert.throws(() => buildCompilerRequest("seiyaku App {}", { sourceName: "app.ko", packages: [{ ...pkg, exports: ["Math::value", "Math::value"] }] }), /duplicate package export/u);
  assert.throws(() => buildCompilerRequest("seiyaku App {}", { sourceName: "app.ko", packages: [{ ...pkg, sources: Array.from({ length: 511 }, (_, index) => ({ sourceName: `${index}.ko`, source: "" })) }] }), /at most 512 files/u);
});

test("compiler source arrays reject accessor elements without invoking them", () => {
  const sources = [];
  Object.defineProperty(sources, "0", { enumerable: true, get() { throw new Error("getter must not run"); } });
  assert.throws(() => buildCompilerRequest("seiyaku App {}", { sourceName: "app.ko", sources }), /inert data entries/u);
});
