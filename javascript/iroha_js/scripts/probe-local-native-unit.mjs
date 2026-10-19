#!/usr/bin/env node
// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  REQUIRED_NATIVE_EXPORTS,
  probeNativeBindingExports,
} from "./copy-native.mjs";
import { machOSigningIndependentSHA256 } from "../src/nativeArtifactHash.js";

assert.equal(process.argv.length, 5, "local native probe arguments are exact");
const [artifact, emitted, rawPolicy] = process.argv.slice(2);
assert.equal(resolve(artifact), artifact);
assert.equal(resolve(emitted), emitted);
const policy = JSON.parse(rawPolicy);
assert.deepEqual(Object.keys(policy).sort(), ["abi_version", "forbidden", "required", "required_results"]);
assert.equal(policy.abi_version, 31);
assert(REQUIRED_NATIVE_EXPORTS.every((name) => policy.required.includes(name)));

// This is the existing real publication consumer, including network-context,
// ABI, private-file revision and native privacy catalog/Exact12 checks.
probeNativeBindingExports(artifact, policy.required, policy.abi_version);
const nativeModule = { exports: {} };
process.dlopen(nativeModule, artifact);
const binding = nativeModule.exports;
const exports = Object.getOwnPropertyNames(binding).sort();
assert(exports.length > 0);
for (const name of exports) {
  const descriptor = Object.getOwnPropertyDescriptor(binding, name);
  assert(Object.hasOwn(descriptor, "value"), "native exports have no accessors");
  assert(descriptor.value === null || typeof descriptor.value !== "object", "native data exports are primitive");
}
assert(policy.required.every((name) => typeof binding[name] === "function"));
for (const [name, expected] of Object.entries(policy.required_results)) {
  assert.equal(binding[name](), expected);
}
const retiredPrefix = "connect_norito_" + ["cash", "offline"].reverse().join("_") + "_";
const forbidden = exports.filter((name) => policy.forbidden.includes(name) || name.startsWith(retiredPrefix));
assert.deepEqual(forbidden, []);
process.stdout.write(JSON.stringify({
  abi_version: binding.connectNoritoBridgeAbiVersion(),
  exports,
  forbidden,
  required_exports: policy.required,
  required_results: policy.required_results,
  signing_independent_emitted: machOSigningIndependentSHA256(readFileSync(emitted)),
  signing_independent_artifact: machOSigningIndependentSHA256(readFileSync(artifact)),
}) + "\n");
