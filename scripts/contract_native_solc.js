"use strict";

// Native SCCP compiler adapter for Node test harnesses (`specs/sccp.md` §5.5).
// Requires Python 3 and an absolute `compilerPath` published by
// `python3 scripts/contract_artifact_corridor.py materialize --target evm`.
// The corridor re-authenticates the executable (SHA-256, native format and
// version banner) and admits only content-only sources compiled with exactly
// the locked cancun legacy-pipeline settings. `evm` (Ethereum and BSC) is the
// only target.
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const REPO = path.resolve(__dirname, "..");
const TARGETS = new Set(["evm"]);

/**
 * Compiles one standard-json input with the pinned native compiler of `target`
 * and returns the parsed standard-json output.
 */
function compileNativeSolidity(input, { target = "evm", compilerPath, pythonBin = "python3" } = {}) {
  assert.equal(typeof input, "string", "standard-json compiler input must be a string");
  assert(TARGETS.has(target), "compiler target must be evm");
  assert(typeof compilerPath === "string" && path.isAbsolute(compilerPath),
    "an absolute authenticated native compiler path is required");
  const result = spawnSync(pythonBin, [
    path.join(__dirname, "contract_artifact_corridor.py"), "compile-input",
    "--target", target, "--compiler", compilerPath,
  ], { input, encoding: "utf8", maxBuffer: 128 * 1024 * 1024, cwd: REPO });
  assert.equal(result.status, 0, result.stderr || result.error?.message || "native compiler failed");
  return JSON.parse(result.stdout);
}

module.exports = { compileNativeSolidity };
