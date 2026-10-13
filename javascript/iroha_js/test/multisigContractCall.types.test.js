import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("contract multisig proposal declarations require the reviewed canonical draft and content hash", () => {
  const result = spawnSync(process.execPath, [
    fileURLToPath(new URL("../node_modules/typescript/bin/tsc", import.meta.url)),
    "--noEmit", "--strict", "--skipLibCheck", "--module", "NodeNext",
    "--moduleResolution", "NodeNext", "--target", "ES2022", "--types", "node",
    fileURLToPath(new URL("./fixtures/typescript/multisigContractCall.types.ts", import.meta.url)),
  ], { encoding: "utf8" });
  assert.equal(result.status, 0, `tsc failed:\n${result.stdout}\n${result.stderr}`);
});
