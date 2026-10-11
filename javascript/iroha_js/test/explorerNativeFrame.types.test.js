import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const packageRoot = fileURLToPath(new URL("..", import.meta.url));

test("Explorer declarations expose the sole native frame and reject retired trees", () => {
  const result = spawnSync(process.execPath, [
    "./node_modules/typescript/bin/tsc", "--noEmit", "--strict", "--skipLibCheck",
    "--module", "NodeNext", "--moduleResolution", "NodeNext", "--target", "ES2022",
    "--types", "node", "./test/fixtures/typescript/explorerNativeFrame.types.ts",
  ], { cwd: packageRoot, encoding: "utf8" });
  assert.equal(result.status, 0, [result.stdout, result.stderr].filter(Boolean).join("\n"));
});

test("Explorer OpenAPI and MCP name the same native instruction fields", () => {
  const readJson = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
  const openapi = readJson("../../../crates/iroha_torii/assets/openapi/torii.json");
  const exported = readJson("../../../artifacts/openapi/torii.json");
  const schemas = openapi.components.schemas;
  const box = schemas.ExplorerInstructionDetail.properties.box;
  assert.deepEqual(Object.keys(box.properties).sort(), ["framed_sha256", "instruction", "wire_id"]);
  assert.deepEqual(box.required, ["wire_id", "framed_sha256", "instruction"]);
  assert.equal(box.additionalProperties, false);
  assert.equal(box.properties.framed_sha256.pattern, "^[0-9a-f]{64}$");
  assert.deepEqual(schemas.ExplorerTransactionRejection.required, ["reason", "message"]);
  assert.deepEqual(exported.components.schemas.ExplorerInstructionDetail, schemas.ExplorerInstructionDetail);
  assert.deepEqual(exported.components.schemas.ExplorerTransactionDetail, schemas.ExplorerTransactionDetail);
  assert.equal(schemas.ExplorerInstructionPayload, undefined);
  const mcp = readFileSync(new URL("../../../crates/iroha_torii/src/mcp/manual_tool_descriptors_v1.json", import.meta.url), "utf8");
  assert.equal(mcp.includes("box.encoded"), false);
  assert.equal(mcp.includes("box.json"), false);
  assert.equal(mcp.includes("box.wire_id, box.framed_sha256, box.instruction"), true);
});
