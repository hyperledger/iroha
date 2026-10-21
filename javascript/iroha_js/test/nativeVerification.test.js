import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  machOSigningIndependentSHA256,
  peSigningIndependentSHA256,
} from "../src/nativeArtifactHash.js";

const NATIVE_IMPLEMENTATIONS = [
  ["source", await import("../src/native.js")],
  ["package dist", await import("../dist/native.js")],
];
const SOURCE_PROVENANCE = Object.freeze({
  build_execution_policy: "trusted-local-cargo-v1",
  build_provenance_version: 4,
  source_git_revision: "a".repeat(40),
  source_tree_clean: true,
  source_tree_sha256: "b".repeat(64),
});
const MACOS_BUILD_IDENTITY = Object.freeze({
  sdk_root: "/opt/iroha/test/MacOSX26.5.sdk",
  sdk_version: "26.5",
  sdk_settings_sha256: "c".repeat(64),
  deployment_target: "11.0",
  clang_path: "/opt/iroha/test/bin/clang",
  clang_version: "Apple clang version 21.0.0 (fixture)",
  linker_path: "/opt/iroha/test/bin/ld",
  linker_version: "@(#)PROGRAM:ld PROJECT:ld-27037.1",
});

function sha256(data) {
  return createHash("sha256").update(data).digest("hex");
}

function checksumEntry(digest, extra = {}) {
  return {
    sha256: digest,
    ...SOURCE_PROVENANCE,
    ...((process.platform === "darwin" &&
      extra.pe_signing_independent_sha256 === undefined) ||
      extra.mach_o_signing_independent_sha256 !== undefined
      ? { macos_build: MACOS_BUILD_IDENTITY } : {}),
    ...extra,
  };
}

function syntheticSignedMachO({ signatureByte, signatureSize, codeByte = 0x42 }) {
  const headerBytes = 32;
  const segmentCommandBytes = 72;
  const signatureCommandBytes = 16;
  const commandBytes = segmentCommandBytes + signatureCommandBytes;
  const codeBytes = 16;
  const signatureOffset = headerBytes + commandBytes + codeBytes;
  const bytes = Buffer.alloc(signatureOffset + signatureSize, 0);
  bytes.writeUInt32LE(0xfeedfacf, 0);
  bytes.writeUInt32LE(0x0100000c, 4);
  bytes.writeUInt32LE(8, 12);
  bytes.writeUInt32LE(2, 16);
  bytes.writeUInt32LE(commandBytes, 20);

  const segment = headerBytes;
  bytes.writeUInt32LE(0x19, segment);
  bytes.writeUInt32LE(segmentCommandBytes, segment + 4);
  bytes.write("__LINKEDIT", segment + 8, "ascii");
  bytes.writeBigUInt64LE(BigInt(signatureSize + codeBytes), segment + 32);
  bytes.writeBigUInt64LE(BigInt(headerBytes + commandBytes), segment + 40);
  bytes.writeBigUInt64LE(BigInt(signatureSize + codeBytes), segment + 48);

  const signatureCommand = segment + segmentCommandBytes;
  bytes.writeUInt32LE(0x1d, signatureCommand);
  bytes.writeUInt32LE(signatureCommandBytes, signatureCommand + 4);
  bytes.writeUInt32LE(signatureOffset, signatureCommand + 8);
  bytes.writeUInt32LE(signatureSize, signatureCommand + 12);
  bytes.fill(codeByte, headerBytes + commandBytes, signatureOffset);
  bytes.fill(signatureByte, signatureOffset);
  return bytes;
}

function syntheticUnsignedPe({ codeByte = 0x42 } = {}) {
  const peOffset = 64;
  const coffBytes = 20;
  const optionalBytes = 240;
  const optionalOffset = peOffset + 4 + coffBytes;
  const bytes = Buffer.alloc(optionalOffset + optionalBytes + 17, codeByte);
  bytes.fill(0, 0, optionalOffset + optionalBytes);
  bytes.write("MZ", 0, "ascii");
  bytes.writeUInt32LE(peOffset, 0x3c);
  bytes.write("PE\0\0", peOffset, "binary");
  bytes.writeUInt16LE(optionalBytes, peOffset + 4 + 16);
  bytes.writeUInt16LE(0x20b, optionalOffset);
  bytes.writeUInt32LE(16, optionalOffset + 108);
  return bytes;
}

function authenticodeSignPe(unsigned, { certificateByte = 0x77, certificateBytes = 64 } = {}) {
  const padding = (8 - (unsigned.length % 8)) % 8;
  const certificateOffset = unsigned.length + padding;
  const signed = Buffer.alloc(certificateOffset + certificateBytes);
  unsigned.copy(signed);
  signed.writeUInt32LE(0x1234_5678, 64 + 4 + 20 + 64);
  const certificateDirectory = 64 + 4 + 20 + 112 + 4 * 8;
  signed.writeUInt32LE(certificateOffset, certificateDirectory);
  signed.writeUInt32LE(certificateBytes, certificateDirectory + 4);
  signed.fill(certificateByte, certificateOffset);
  signed.writeUInt32LE(certificateBytes, certificateOffset);
  signed.writeUInt16LE(0x0200, certificateOffset + 4);
  signed.writeUInt16LE(0x0002, certificateOffset + 6);
  return signed;
}

async function withTempDir(run) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "iroha-js-native-"));
  try {
    return await run(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

for (const [implementationName, implementation] of NATIVE_IMPLEMENTATIONS) {
  const {
    __resetNativeStateForTests,
    __snapshotNativeBindingForTests,
    getNativeBinding,
    verifyNativeBinding,
  } = implementation;
  const variantTest = (name, run) => test(`${implementationName}: ${name}`, run);

variantTest("verifyNativeBinding succeeds when checksum matches manifest entry", async () => {
  __resetNativeStateForTests();
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
    const contents = Buffer.from("native-stub");
    await fs.writeFile(bindingPath, contents);
    const digest = sha256(contents);
    const platformKey = `${process.platform}-${process.arch}`;
    await fs.writeFile(
      manifestPath,
      `${JSON.stringify({ entries: { [platformKey]: checksumEntry(digest) } }, null, 2)}\n`,
    );

    const result = verifyNativeBinding(bindingPath, { manifestPath });
    assert.equal(result.ok, true);
    assert.equal(result.status, "verified");
    assert.equal(result.sha256, digest);
    assert.equal(result.expectedSha256, digest);
  });
});

variantTest("Darwin V4 rejects missing or stale SDK identity", async () => {
  __resetNativeStateForTests();
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const contents = Buffer.from("darwin-native-stub");
    await fs.writeFile(bindingPath, contents);
    const base = checksumEntry(sha256(contents), {
      macos_build: MACOS_BUILD_IDENTITY,
    });
    const valid = verifyNativeBinding(bindingPath, {
      expectedChecksums: { "darwin-arm64": base },
      platformKey: "darwin-arm64",
    });
    assert.equal(valid.ok, true);
    assert.deepEqual(valid.macosBuild, MACOS_BUILD_IDENTITY);
    const missing = { ...base };
    delete missing.macos_build;
    for (const invalid of [
      missing,
      { ...base, build_provenance_version: 3 },
      { ...base, macos_build: {
        ...MACOS_BUILD_IDENTITY,
        sdk_settings_sha256: "0",
      } },
    ]) {
      const rejected = verifyNativeBinding(bindingPath, {
        expectedChecksums: { "darwin-arm64": invalid },
        platformKey: "darwin-arm64",
      });
      assert.equal(rejected.ok, false);
      assert.equal(rejected.status, "manifest_error");
    }
  });
});

variantTest("getNativeBinding rejects a checksum-valid dirty-source artifact", async () => {
  __resetNativeStateForTests();
  const previousNativeDir = process.env.IROHA_JS_NATIVE_DIR;
  const originalBufferToJson = Buffer.prototype.toJSON;
  let serializedVerifiedBytes = false;
  try {
    Buffer.prototype.toJSON = function toJSON() {
      serializedVerifiedBytes = true;
      return originalBufferToJson.call(this);
    };
    await withTempDir(async (dir) => {
      const bindingPath = path.join(dir, "iroha_js_host.node");
      const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
      const contents = Buffer.from("dirty-source-native-stub");
      await fs.writeFile(bindingPath, contents);
      await fs.writeFile(
        manifestPath,
        `${JSON.stringify({
          entries: {
            [`${process.platform}-${process.arch}`]: checksumEntry(sha256(contents), {
              source_tree_clean: false,
            }),
          },
        })}\n`,
      );
      process.env.IROHA_JS_NATIVE_DIR = dir;
      assert.throws(
        () => getNativeBinding(),
        (error) => {
          assert.match(error.message, /source verification (?:failed|timed out)/u);
          assert.equal(error.code, "ERR_IROHA_NATIVE_BINDING");
          assert.equal(error.nativeStatus, "source_provenance_error");
          return true;
        },
      );
    });
    assert.equal(
      serializedVerifiedBytes,
      false,
      "dirty-source verification must not serialize retained native bytes",
    );
  } finally {
    Buffer.prototype.toJSON = originalBufferToJson;
    if (previousNativeDir === undefined) {
      delete process.env.IROHA_JS_NATIVE_DIR;
    } else {
      process.env.IROHA_JS_NATIVE_DIR = previousNativeDir;
    }
    __resetNativeStateForTests();
  }
});

for (const scenario of [
  { name: "Electron", electron: true },
  {
    name: "Electron timeout", electron: true,
    failure: { code: "ETIMEDOUT", status: null, signal: "SIGTERM" },
    diagnostic: { kind: "timeout", code: "ETIMEDOUT", status: null, signal: "SIGTERM" },
  },
  { name: "Node", electron: false },
  {
    name: "Node verifier nonzero exit", electron: false,
    failure: { status: 2, signal: null },
    diagnostic: { kind: "verifier_failure", code: null, status: 2, signal: null },
  },
  {
    name: "Node spawn error", electron: false,
    failure: { code: "ENOENT", status: null, signal: null },
    diagnostic: { kind: "verifier_failure", code: "ENOENT", status: null, signal: null },
  },
  {
    name: "Node unsafe diagnostic fields", electron: false,
    failure: { code: "PRIVATE\nargv", status: "PRIVATE", signal: "PRIVATE\noutput" },
    diagnostic: { kind: "verifier_failure", code: null, status: null, signal: null },
  },
]) {
  variantTest(`dirty-source verification uses a bounded subprocess (${scenario.name})`, async (t) => {
    __resetNativeStateForTests();
    const previousNativeDir = process.env.IROHA_JS_NATIVE_DIR;
    const previousNodeOptions = process.env.NODE_OPTIONS;
    const previousRunAsNode = process.env.ELECTRON_RUN_AS_NODE;
    const previousElectron = Object.getOwnPropertyDescriptor(process.versions, "electron");
    const verifier = t.mock.method(childProcess, "execFileSync", () => {
      if (scenario.failure) {
        throw Object.assign(new Error("PRIVATE verifier message and argv"), {
          ...scenario.failure,
          stdout: Buffer.from("PRIVATE stdout"),
          stderr: Buffer.from("PRIVATE stderr"),
          spawnargs: ["PRIVATE argv"],
        });
      }
      return Buffer.alloc(0);
    });
    const nativeLoad = t.mock.method(process, "dlopen", () => {
      throw new Error("mock native load reached");
    });
    syncBuiltinESMExports();
    try {
      if (scenario.electron) {
        Object.defineProperty(process.versions, "electron", {
          configurable: true,
          value: "40.0.0",
        });
      } else {
        delete process.versions.electron;
      }
      process.env.NODE_OPTIONS = "--require=untrusted-parent-hook";
      process.env.ELECTRON_RUN_AS_NODE = "0";
      await withTempDir(async (dir) => {
        const contents = Buffer.from("checksum-valid-but-not-loadable-native-stub");
        await fs.writeFile(path.join(dir, "iroha_js_host.node"), contents);
        await fs.writeFile(
          path.join(dir, "iroha_js_host.checksums.json"),
          JSON.stringify({
            entries: {
              [`${process.platform}-${process.arch}`]: checksumEntry(sha256(contents), {
                cargo_profile: "debug",
                source_tree_clean: false,
              }),
            },
          }),
        );
        process.env.IROHA_JS_NATIVE_DIR = dir;
        assert.throws(
          () => getNativeBinding(),
          (error) => {
            assert.equal(error.code, "ERR_IROHA_NATIVE_BINDING");
            assert.equal(
              error.nativeStatus,
              scenario.failure ? "source_provenance_error" : "load_error",
              "only successful provenance verification may reach native loading",
            );
            if (scenario.failure) {
              assert.deepEqual(error.sourceVerification, {
                ...scenario.diagnostic, timeoutMs: 60_000,
              });
              assert.ok(Object.isFrozen(error.sourceVerification));
              assert.match(error.message, scenario.diagnostic.kind === "timeout"
                ? /source verification timed out after 60000 ms/u
                : /source verification failed/u);
              assert.doesNotMatch(error.message, /does not match/u);
              assert.doesNotMatch(error.message + JSON.stringify(error), /PRIVATE/u);
              for (const key of ["cause", "stdout", "stderr", "spawnargs"]) {
                assert.equal(Object.hasOwn(error, key), false);
              }
            } else {
              assert.match(error.message, /mock native load reached/u);
              assert.equal(Object.hasOwn(error, "sourceVerification"), false);
            }
            return true;
          },
        );

        assert.equal(verifier.mock.callCount(), 1);
        assert.equal(nativeLoad.mock.callCount(), scenario.failure ? 0 : 1);
        const [executable, args, options] = verifier.mock.calls[0].arguments;
        const sdkRoot = fileURLToPath(new URL("../", import.meta.url));
        assert.equal(executable, process.execPath);
        assert.deepEqual(args, [
          path.join(sdkRoot, "scripts", "read-native-build-source-state.mjs"),
          "--verify",
          path.resolve(sdkRoot, "..", ".."),
          JSON.stringify({
            cargoProfile: "debug",
            sourceGitRevision: SOURCE_PROVENANCE.source_git_revision,
            sourceTreeClean: false,
            sourceTreeSha256: SOURCE_PROVENANCE.source_tree_sha256,
          }),
        ]);
        assert.equal(options.timeout, 60_000);
        assert.equal(options.maxBuffer, 16 * 1024);
        assert.equal(options.env.IROHA_JS_NATIVE_DIR, dir);
        assert.equal(options.env.NODE_OPTIONS, "");
        assert.equal(options.env.ELECTRON_RUN_AS_NODE, scenario.electron ? "1" : "0");
        assert.equal(process.env.NODE_OPTIONS, "--require=untrusted-parent-hook");
        assert.equal(process.env.ELECTRON_RUN_AS_NODE, "0");
      });
    } finally {
      verifier.mock.restore();
      nativeLoad.mock.restore();
      syncBuiltinESMExports();
      for (const [key, value] of [
        ["IROHA_JS_NATIVE_DIR", previousNativeDir],
        ["NODE_OPTIONS", previousNodeOptions],
        ["ELECTRON_RUN_AS_NODE", previousRunAsNode],
      ]) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      if (previousElectron) {
        Object.defineProperty(process.versions, "electron", previousElectron);
      } else {
        delete process.versions.electron;
      }
      __resetNativeStateForTests();
    }
  });
}

variantTest("checksum-only entries are rejected without V4 source provenance", async () => {
  __resetNativeStateForTests();
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
    const contents = Buffer.from("native-stub");
    const platformKey = `${process.platform}-${process.arch}`;
    await fs.writeFile(bindingPath, contents);
    await fs.writeFile(
      manifestPath,
      `${JSON.stringify({
        entries: {
          [platformKey]: { sha256: sha256(contents) },
        },
      })}\n`,
    );

    const result = verifyNativeBinding(bindingPath, { manifestPath });
    assert.equal(result.ok, false);
    assert.equal(result.status, "manifest_error");
  });
});

variantTest("Darwin verification accepts only signing-container changes", async () => {
  __resetNativeStateForTests();
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
    const original = syntheticSignedMachO({ signatureByte: 0x11, signatureSize: 64 });
    const resigned = syntheticSignedMachO({ signatureByte: 0x77, signatureSize: 96 });
    const stableDigest = machOSigningIndependentSHA256(original);
    assert.equal(stableDigest, machOSigningIndependentSHA256(resigned));
    await fs.writeFile(bindingPath, resigned);
    await fs.writeFile(
      manifestPath,
      `${JSON.stringify({
        entries: {
          "darwin-arm64": checksumEntry(sha256(original), {
            mach_o_signing_independent_sha256: stableDigest,
          }),
        },
      })}\n`,
    );

    const verified = verifyNativeBinding(bindingPath, {
      manifestPath,
      platformKey: "darwin-arm64",
    });
    assert.equal(verified.ok, true);
    assert.equal(verified.status, "verified_resigned_macho");
    assert.equal(verified.machOSigningIndependentSha256, stableDigest);

    resigned[32 + 72 + 16] ^= 1;
    await fs.writeFile(bindingPath, resigned);
    const tampered = verifyNativeBinding(bindingPath, {
      manifestPath,
      platformKey: "darwin-arm64",
    });
    assert.equal(tampered.ok, false);
    assert.equal(tampered.status, "hash_mismatch");
  });
});

variantTest("Darwin signing-independent fallback rejects malformed Mach-O bounds", async () => {
  __resetNativeStateForTests();
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
    const original = syntheticSignedMachO({ signatureByte: 0x11, signatureSize: 64 });
    const malformed = Buffer.from(original);
    malformed.writeUInt32LE(0xffff_ffff, 20);
    await fs.writeFile(bindingPath, malformed);
    await fs.writeFile(
      manifestPath,
      `${JSON.stringify({
        entries: {
          "darwin-arm64": checksumEntry(sha256(original), {
            mach_o_signing_independent_sha256:
              machOSigningIndependentSHA256(original),
          }),
        },
      })}\n`,
    );
    const result = verifyNativeBinding(bindingPath, {
      manifestPath,
      platformKey: "darwin-arm64",
    });
    assert.equal(result.ok, false);
    assert.equal(result.status, "hash_error");
  });
});

variantTest("Windows verification accepts only a final bounded Authenticode region", async () => {
  __resetNativeStateForTests();
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
    const original = syntheticUnsignedPe();
    const signed = authenticodeSignPe(original);
    const stableDigest = peSigningIndependentSHA256(original);
    assert.equal(
      stableDigest,
      peSigningIndependentSHA256(signed, original.length, { requireSigned: true }),
    );
    await fs.writeFile(bindingPath, signed);
    await fs.writeFile(
      manifestPath,
      `${JSON.stringify({
        entries: {
          "win32-x64": checksumEntry(sha256(original), {
            pe_signing_independent_sha256: stableDigest,
            pe_unsigned_size: original.length,
          }),
        },
      })}\n`,
    );
    const verified = verifyNativeBinding(bindingPath, {
      manifestPath,
      platformKey: "win32-x64",
    });
    assert.equal(verified.ok, true);
    assert.equal(verified.status, "verified_resigned_pe");
    assert.equal(verified.peSigningIndependentSha256, stableDigest);
    assert.equal(verified.expectedPeUnsignedSize, original.length);
    assert.equal(verified.sourceGitRevision, "a".repeat(40));
    assert.equal(verified.sourceTreeClean, true);
    assert.equal(verified.sourceTreeSha256, "b".repeat(64));

    signed[original.length - 1] ^= 1;
    await fs.writeFile(bindingPath, signed);
    const tampered = verifyNativeBinding(bindingPath, {
      manifestPath,
      platformKey: "win32-x64",
    });
    assert.equal(tampered.ok, false);
    assert.equal(tampered.status, "hash_mismatch");
  });
});

variantTest("Windows signing fallback rejects missing or malformed certificate bounds", async () => {
  __resetNativeStateForTests();
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
    const original = syntheticUnsignedPe();
    const malformed = authenticodeSignPe(original);
    malformed[original.length] = 1;
    await fs.writeFile(bindingPath, malformed);
    await fs.writeFile(
      manifestPath,
      `${JSON.stringify({
        entries: {
          "win32-x64": checksumEntry(sha256(original), {
            pe_signing_independent_sha256: peSigningIndependentSHA256(original),
            pe_unsigned_size: original.length,
          }),
        },
      })}\n`,
    );
    const malformedResult = verifyNativeBinding(bindingPath, {
      manifestPath,
      platformKey: "win32-x64",
    });
    assert.equal(malformedResult.ok, false);
    assert.equal(malformedResult.status, "hash_error");

    await fs.writeFile(bindingPath, original);
    original[original.length - 1] ^= 1;
    await fs.writeFile(bindingPath, original);
    const unsignedResult = verifyNativeBinding(bindingPath, {
      manifestPath,
      platformKey: "win32-x64",
    });
    assert.equal(unsignedResult.ok, false);
    assert.equal(unsignedResult.status, "hash_error");
  });
});

variantTest("getNativeBinding rejects checksum mismatches", async () => {
  __resetNativeStateForTests();
  const previousOverride = process.env.IROHA_JS_NATIVE_DIR;

  try {
    await withTempDir(async (dir) => {
      const bindingPath = path.join(dir, "iroha_js_host.node");
      const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
      await fs.writeFile(bindingPath, "tampered");
      const platformKey = `${process.platform}-${process.arch}`;
      await fs.writeFile(
        manifestPath,
        `${JSON.stringify(
          {
            entries: {
              [platformKey]: checksumEntry(sha256(Buffer.from("expected"))),
            },
          },
          null,
          2,
        )}\n`,
      );
      process.env.IROHA_JS_NATIVE_DIR = dir;
      assert.throws(
        () => getNativeBinding(),
        (error) => {
          assert.match(error.message, /checksum mismatch/u);
          assert.equal(error.code, "ERR_IROHA_NATIVE_BINDING");
          assert.equal(error.nativeStatus, "hash_mismatch");
          return true;
        },
      );
    });
  } finally {
    if (previousOverride === undefined) {
      delete process.env.IROHA_JS_NATIVE_DIR;
    } else {
      process.env.IROHA_JS_NATIVE_DIR = previousOverride;
    }
    __resetNativeStateForTests();
  }
});

variantTest("verifyNativeBinding fails closed when its manifest is missing", async () => {
  __resetNativeStateForTests();
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
    await fs.writeFile(bindingPath, "missing-manifest");

    const strict = verifyNativeBinding(bindingPath, { manifestPath });
    assert.equal(strict.ok, false);
    assert.equal(strict.status, "missing_manifest");
  });
});

variantTest("verification rehashes files and reloads manifests on every call", async () => {
  __resetNativeStateForTests();
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
    const platformKey = `${process.platform}-${process.arch}`;
    const original = Buffer.from("original-native");
    const replacement = Buffer.from("replacement-native");
    await fs.writeFile(bindingPath, original);
    await fs.writeFile(
      manifestPath,
      `${JSON.stringify(
        { entries: { [platformKey]: checksumEntry(sha256(original)) } },
        null,
        2,
      )}\n`,
    );

    assert.equal(verifyNativeBinding(bindingPath, { manifestPath }).ok, true);
    await fs.writeFile(bindingPath, replacement);
    const replacedBinding = verifyNativeBinding(bindingPath, { manifestPath });
    assert.equal(replacedBinding.ok, false);
    assert.equal(replacedBinding.status, "hash_mismatch");

    await fs.writeFile(bindingPath, original);
    assert.equal(verifyNativeBinding(bindingPath, { manifestPath }).ok, true);
    await fs.writeFile(
      manifestPath,
      `${JSON.stringify(
        { entries: { [platformKey]: checksumEntry(sha256(replacement)) } },
        null,
        2,
      )}\n`,
    );
    const replacedManifest = verifyNativeBinding(bindingPath, { manifestPath });
    assert.equal(replacedManifest.ok, false);
    assert.equal(replacedManifest.status, "hash_mismatch");
  });
});

variantTest("verified snapshots retain the authenticated bytes across path substitution", async () => {
  __resetNativeStateForTests();
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
    const platformKey = `${process.platform}-${process.arch}`;
    const authenticated = Buffer.from("authenticated-native-bytes");
    const substituted = Buffer.from("substituted-after-verification");
    await fs.writeFile(bindingPath, authenticated);
    await fs.writeFile(
      manifestPath,
      `${JSON.stringify(
        { entries: { [platformKey]: checksumEntry(sha256(authenticated)) } },
        null,
        2,
      )}\n`,
    );

    const snapshot = __snapshotNativeBindingForTests(
      bindingPath,
      { manifestPath },
      () => writeFileSync(bindingPath, substituted),
    );
    try {
      assert.equal(snapshot.ok, true);
      assert.deepEqual(readFileSync(snapshot.path), authenticated);
      assert.deepEqual(readFileSync(bindingPath), substituted);
      assert.equal(sha256(readFileSync(snapshot.path)), snapshot.sha256);
      assert.match(path.basename(snapshot.path), new RegExp(`^${snapshot.sha256}\\.node$`, "u"));
      if (process.platform !== "win32") {
        assert.equal(statSync(snapshot.directory).mode & 0o777, 0o700);
        assert.equal(statSync(snapshot.path).mode & 0o777, 0o500);
      }
    } finally {
      await fs.rm(snapshot.directory, { recursive: true, force: true });
    }
  });
});

variantTest("normal exit cleans owned snapshots without touching authenticated originals", async () => {
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
    const contents = Buffer.from("verified-snapshot-lifecycle-fixture");
    await fs.writeFile(bindingPath, contents);
    await fs.writeFile(manifestPath, JSON.stringify({ entries: {
      [`${process.platform}-${process.arch}`]: checksumEntry(sha256(contents)),
    } }));
    const moduleUrl = new URL(
      implementationName === "source" ? "../src/native.js" : "../dist/native.js",
      import.meta.url,
    ).href;
    // Both natural event-loop completion and explicit nonzero exit must run
    // synchronous cleanup; neither test loads an unauthenticated native module.
    for (const exitCode of [0, 7]) {
      const temporaryDirectory = path.join(dir, `snapshots-${exitCode}`);
      await fs.mkdir(temporaryDirectory);
      const child = childProcess.spawnSync(process.execPath, [
        "--input-type=module", "--eval", `
          import assert from "node:assert/strict";
          import { existsSync, readFileSync, readdirSync } from "node:fs";
          import { tmpdir } from "node:os";
          import { __snapshotNativeBindingForTests, getNativeBinding }
            from ${JSON.stringify(moduleUrl)};
          const initialListeners = process.listenerCount("exit");
          assert.throws(() => getNativeBinding(), error => error.nativeStatus === "load_error");
          assert.equal(process.listenerCount("exit"), initialListeners);
          assert.deepEqual(readdirSync(tmpdir()), []);
          const snapshots = Array.from({ length: 12 }, () =>
            __snapshotNativeBindingForTests(${JSON.stringify(bindingPath)}, {
              manifestPath: ${JSON.stringify(manifestPath)},
            }));
          assert.equal(process.listenerCount("exit"), initialListeners + 1);
          for (const snapshot of snapshots) {
            assert.equal(snapshot.ok, true);
            assert.equal(existsSync(snapshot.path), true);
            assert.equal(readFileSync(snapshot.path, "utf8"), ${JSON.stringify(contents.toString())});
          }
          // A verified file that cannot be loaded must clean its own snapshot
          // immediately, without removing the other live snapshots.
          const beforeFailure = readdirSync(tmpdir()).filter(name => name.startsWith("iroha-js-host-"));
          assert.throws(() => getNativeBinding(), error => error.nativeStatus === "load_error");
          assert.deepEqual(readdirSync(tmpdir()).filter(name => name.startsWith("iroha-js-host-")), beforeFailure);
          assert.equal(process.listenerCount("exit"), initialListeners + 1);
          console.log(JSON.stringify(snapshots));
          ${exitCode === 0 ? "" : `process.exit(${exitCode});`}
        `,
      ], { encoding: "utf8", env: {
        ...process.env,
        IROHA_JS_NATIVE_DIR: dir,
        TMPDIR: temporaryDirectory,
        TMP: temporaryDirectory,
        TEMP: temporaryDirectory,
      } });
      assert.equal(child.error, undefined);
      assert.equal(child.status, exitCode, child.stderr);
      assert.equal(child.stderr, "");
      const snapshots = JSON.parse(child.stdout.trim());
      assert.equal(snapshots.length, 12);
      for (const snapshot of snapshots) {
        await assert.rejects(fs.stat(snapshot.directory), { code: "ENOENT" });
      }
      assert.deepEqual(await fs.readFile(bindingPath), contents);
      assert.equal(verifyNativeBinding(bindingPath, { manifestPath }).ok, true);
    }
  });
});

variantTest("verification rejects malformed checksum manifests and entries", async () => {
  __resetNativeStateForTests();
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const manifestPath = path.join(dir, "iroha_js_host.checksums.json");
    const platformKey = `${process.platform}-${process.arch}`;
    const validHash = sha256(Buffer.from("native-stub"));
    await fs.writeFile(bindingPath, "native-stub");

    for (const manifest of [
      { [platformKey]: { sha256: "0".repeat(64) } },
      { entries: [] },
      { entries: { [platformKey]: { sha256: "A".repeat(64) } } },
      { entries: { [platformKey]: { sha256: "0".repeat(64), extra: true } } },
      {
        entries: {
          [platformKey]: {
            sha256: validHash,
            build_execution_policy: "trusted-local-cargo-v1",
            source_git_revision: "a".repeat(40),
            source_tree_clean: true,
            source_tree_sha256: "b".repeat(64),
          },
        },
      },
      {
        entries: {
          [platformKey]: {
            sha256: validHash,
            build_execution_policy: "hermetic-build-v1",
            build_provenance_version: 3,
            source_git_revision: "a".repeat(40),
            source_tree_clean: true,
            source_tree_sha256: "b".repeat(64),
          },
        },
      },
      {
        entries: {
          [platformKey]: {
            sha256: validHash,
            build_execution_policy: "trusted-local-cargo-v1",
            build_provenance_version: 2,
            source_git_revision: "a".repeat(40),
            source_tree_clean: true,
            source_tree_sha256: "b".repeat(64),
          },
        },
      },
      {
        entries: {
          [platformKey]: {
            sha256: validHash,
            source_git_revision: "a".repeat(40),
          },
        },
      },
      {
        entries: {
          [platformKey]: {
            sha256: validHash,
            source_git_revision: "a".repeat(40),
            source_tree_clean: true,
          },
        },
      },
      {
        entries: {
          [platformKey]: {
            sha256: validHash,
            source_tree_sha256: "b".repeat(64),
          },
        },
      },
      {
        entries: {
          [platformKey]: {
            sha256: validHash,
            source_git_revision: "a".repeat(40),
            source_tree_clean: true,
            source_tree_sha256: "B".repeat(64),
          },
        },
      },
      {
        entries: {
          [platformKey]: {
            sha256: validHash,
            source_git_revision: "A".repeat(40),
            source_tree_clean: true,
            source_tree_sha256: "b".repeat(64),
          },
        },
      },
      {
        entries: {
          [platformKey]: {
            sha256: validHash,
            pe_signing_independent_sha256: "0".repeat(64),
          },
        },
      },
      {
        entries: {
          [platformKey]: { sha256: validHash },
          "other-x64": { sha256: "not-a-checksum" },
        },
      },
      {
        entries: {
          [platformKey]: { sha256: validHash },
          [platformKey.toUpperCase()]: { sha256: validHash },
        },
      },
      { entries: { "MixedCase-x64": { sha256: validHash } } },
      { entries: { invalid: { sha256: validHash } } },
    ]) {
      await fs.writeFile(manifestPath, `${JSON.stringify(manifest)}\n`);
      const result = verifyNativeBinding(bindingPath, { manifestPath });
      assert.equal(result.ok, false);
      assert.equal(result.status, "manifest_error");
    }
  });
});

variantTest("explicit expected checksums are validated independently per call", async () => {
  __resetNativeStateForTests();
  await withTempDir(async (dir) => {
    const bindingPath = path.join(dir, "iroha_js_host.node");
    const contents = Buffer.from("native-stub");
    const platformKey = `${process.platform}-${process.arch}`;
    await fs.writeFile(bindingPath, contents);

    const verified = verifyNativeBinding(bindingPath, {
      platformKey,
      expectedChecksums: {
        [platformKey]: checksumEntry(sha256(contents)),
      },
    });
    assert.equal(verified.ok, true);

    const rejected = verifyNativeBinding(bindingPath, {
      platformKey,
      expectedChecksums: {
        [platformKey]: checksumEntry("0".repeat(64)),
      },
    });
    assert.equal(rejected.ok, false);
    assert.equal(rejected.status, "hash_mismatch");

    const malformed = verifyNativeBinding(bindingPath, {
      platformKey,
      expectedChecksums: [],
    });
    assert.equal(malformed.ok, false);
    assert.equal(malformed.status, "manifest_error");
  });
});

variantTest("getNativeBinding throws when binding is missing", async () => {
  __resetNativeStateForTests();
  const previousOverride = process.env.IROHA_JS_NATIVE_DIR;

  try {
    await withTempDir(async (dir) => {
      process.env.IROHA_JS_NATIVE_DIR = dir;
      assert.throws(
        () => getNativeBinding(),
        (error) => {
          assert.match(error.message, /binding missing/u);
          assert.equal(error.code, "ERR_IROHA_NATIVE_BINDING");
          assert.equal(error.nativeStatus, "missing_file");
          return true;
        },
      );
    });
  } finally {
    if (previousOverride === undefined) {
      delete process.env.IROHA_JS_NATIVE_DIR;
    } else {
      process.env.IROHA_JS_NATIVE_DIR = previousOverride;
    }
    __resetNativeStateForTests();
  }
});
}
