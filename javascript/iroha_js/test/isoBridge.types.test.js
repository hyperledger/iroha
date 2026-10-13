import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("ISO payment types require retained business identity and exact native terms", () => {
  const tsc = fileURLToPath(
    new URL("../node_modules/typescript/bin/tsc", import.meta.url),
  );
  const fixture = fileURLToPath(
    new URL("./fixtures/typescript/isoNativePayment.types.ts", import.meta.url),
  );
  const result = spawnSync(
    process.execPath,
    [
      tsc,
      "--noEmit",
      "--strict",
      "--skipLibCheck",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      "--target",
      "ES2022",
      "--types",
      "node",
      fixture,
    ],
    { encoding: "utf8" },
  );
  assert.equal(
    result.status,
    0,
    `tsc failed:\n${result.stdout}\n${result.stderr}`,
  );
});
