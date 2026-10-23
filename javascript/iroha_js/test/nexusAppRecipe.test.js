// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const PACKAGE_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

test("Nexus App transfer recipe executes the canonical native codec end to end", () => {
  const result = spawnSync(
    process.execPath,
    [path.join(PACKAGE_ROOT, "recipes/nexus_app_transfer.mjs")],
    {
      cwd: PACKAGE_ROOT,
      encoding: "utf8",
      // Native local-unit verification has a 180-second dependency-hash bound.
      // Allow that mandatory check plus 30 seconds for the transfer recipe.
      timeout: 210_000,
      env: { ...process.env, NO_COLOR: "1" },
    },
  );
  assert.equal(
    result.status,
    0,
    `recipe failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.match(
    result.stdout,
    /payload hash: 2cacc93dde41f87f33da6c74281c887bdf2e54d6e11ef7e3cf6eb970a7df7db9/u,
  );
  assert.match(
    result.stdout,
    /signed transaction hash: ef1e1042fb07356fa96d6d51898837f5d2030b8e6286acb1c31076501360aad5/u,
  );
  assert.match(result.stdout, /final status: Applied/u);
});
