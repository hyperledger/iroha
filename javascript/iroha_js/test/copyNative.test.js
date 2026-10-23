import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  probeNativeBindingExports,
  publishNativeBinding,
  recoverNativeBindingPublication,
  REQUIRED_NATIVE_BRIDGE_ABI_VERSION,
  REQUIRED_NATIVE_EXPORTS,
  REQUIRED_NATIVE_EXPORT_RESULTS,
} from "../scripts/copy-native.mjs";
import { getNativeBinding, verifyNativeBinding } from "../src/native.js";

const PLATFORM = "linux";
const ARCH = "x64";
const PLATFORM_KEY = `${PLATFORM}-${ARCH}`;
const NATIVE_FILENAME = "iroha_js_host.node";
const MANIFEST_FILENAME = "iroha_js_host.checksums.json";
const COPY_NATIVE_SCRIPT = path.resolve("scripts/copy-native.mjs");
const SOURCE_REVISION = "a".repeat(40);
const SOURCE_TREE_DIGEST = "b".repeat(64);
const TRANSACTION_INITIALIZER_PREFIX = ".iroha-js-host-init-txn-v1-";
const CLEANUP_MARKER_PATTERN =
  /^\.iroha-js-host-cleanup-v1-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.owner\.json$/u;

function nativeProbeFixtureSource({
  omit = [],
  abiVersion = REQUIRED_NATIVE_BRIDGE_ABI_VERSION,
  catalogBody = "return Buffer.from([0x4e, 0x52, 0x54, 0x30]);",
  validatorBody =
    "return Buffer.isBuffer(archive) && archive.equals(Buffer.from([0x4e, 0x52, 0x54, 0x30])) ? 0 : 8;",
} = {}) {
  const omitted = new Set(omit);
  const methods = REQUIRED_NATIVE_EXPORTS.filter((name) => !omitted.has(name)).map(
    (name) => {
      if (name === "connectNoritoBridgeAbiVersion") {
        return `${name}() { return ${JSON.stringify(abiVersion)}; }`;
      }
      if (name === "privacyCompiledProfileCatalogV1") {
        return `${name}() { ${catalogBody} }`;
      }
      if (name === "privacyValidateCompiledProfileCatalogV1") {
        return `${name}(archive) { ${validatorBody} }`;
      }
      if (name === "privacyValidateExact12CapabilityManifestV1") {
        return `${name}() { return 8; }`;
      }
      if (/^norito(?:Encode|Decode)Instruction(?:BoxArchive)?$/u.test(name)) {
        const result = name.startsWith("noritoEncode")
          ? "Buffer.from(input)" : "Buffer.from(input).toString()";
        return `${name}(input, prefix) { if (!Number.isInteger(prefix) || prefix < 0 || prefix > 65535) throw new TypeError("network prefix"); return ${result}; }`;
      }
      const result = REQUIRED_NATIVE_EXPORT_RESULTS[name];
      return `${name}() {${
        result === undefined ? "" : ` return ${JSON.stringify(result)};`
      } }`;
    },
  );
  return `module.exports = { ${methods.join(", ")} };\n`;
}

function fixtureBuildProvenance(
  source,
  cargoProfile = "debug",
  sourceOverrides = {},
) {
  return {
    version: 4,
    build_execution_policy: "trusted-local-cargo-v1",
    cargo_profile: cargoProfile,
    native_sha256: createHash("sha256").update(readFileSync(source)).digest("hex"),
    source_git_revision: SOURCE_REVISION,
    source_tree_clean: true,
    source_tree_sha256: SOURCE_TREE_DIGEST,
    ...sourceOverrides,
  };
}

const delay = (milliseconds) => new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));

async function waitForFile(file, child, timeoutMs = 10_000) {
  const started = Date.now();
  while (!existsSync(file)) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`copy-native crash worker exited before reaching its phase: ${child.stderrText}`);
    }
    if (Date.now() - started > timeoutMs) {
      throw new Error(`timed out waiting for copy-native crash worker marker: ${file}`);
    }
    await delay(10);
  }
}

function spawnCrashPublisher(layout, phase) {
  const markerId = createHash("sha256").update(phase).digest("hex");
  const marker = path.join(layout.root, `phase-${markerId}`);
const source = String.raw`
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { publishNativeBinding } from ${JSON.stringify(pathToFileURL(COPY_NATIVE_SCRIPT).href)};
const blocker = new Int32Array(new SharedArrayBuffer(4));
await publishNativeBinding({
  source: process.env.SOURCE,
  destDir: process.env.DEST_DIR,
  platform: ${JSON.stringify(PLATFORM)},
  arch: ${JSON.stringify(ARCH)},
  signNative() {},
  probeBinding() {},
  cargoProfile: "debug",
  readBuildProvenance(source) {
    return {
      version: 4,
      build_execution_policy: "trusted-local-cargo-v1",
      cargo_profile: "debug",
      native_sha256: createHash("sha256").update(readFileSync(source)).digest("hex"),
      source_git_revision: ${JSON.stringify(SOURCE_REVISION)},
      source_tree_clean: true,
      source_tree_sha256: ${JSON.stringify(SOURCE_TREE_DIGEST)},
    };
  },
  readSourceState() {
    return {
      sourceGitRevision: ${JSON.stringify(SOURCE_REVISION)},
      sourceTreeClean: true,
    };
  },
  log() {},
  phaseHook(phase) {
    if (phase !== process.env.TARGET_PHASE) return;
    writeFileSync(process.env.MARKER, phase, { flag: "wx" });
    Atomics.wait(blocker, 0, 0);
  },
});
`;
  const child = spawn(process.execPath, ["--input-type=module", "--eval", source], {
    env: {
      ...process.env,
      DEST_DIR: layout.destDir,
      MARKER: marker,
      SOURCE: layout.source,
      TARGET_PHASE: phase,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  child.stderrText = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    child.stderrText += chunk;
  });
  return { child, marker };
}

function waitForExit(child) {
  return new Promise((resolveExit, rejectExit) => {
    child.once("error", rejectExit);
    child.once("exit", (code, signal) => resolveExit({ code, signal }));
  });
}

async function killPublisherAtPhase(layout, phase) {
  const { child, marker } = spawnCrashPublisher(layout, phase);
  await waitForFile(marker, child);
  const exited = waitForExit(child);
  assert.equal(child.kill("SIGKILL"), true);
  const exit = await exited;
  assert.equal(exit.code, null);
  assert.equal(exit.signal, "SIGKILL");
  const lockPath = path.join(layout.destDir, ".build-dist.lock");
  assert.equal(existsSync(lockPath), true, "hard-killed publisher must leave its lock");
  const stale = new Date(Date.now() - 10 * 60_000);
  utimesSync(lockPath, stale, stale);
}

function createLayout(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), "iroha-js-copy-native-"));
  const source = path.join(root, "libiroha_js_host.so");
  const destDir = path.join(root, "native");
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return {
    root,
    source,
    destDir,
    bindingPath: path.join(destDir, NATIVE_FILENAME),
    manifestPath: path.join(destDir, MANIFEST_FILENAME),
  };
}

function publicationOptions(layout, overrides = {}) {
  return {
    source: layout.source,
    destDir: layout.destDir,
    platform: PLATFORM,
    arch: ARCH,
    signNative() {},
    probeBinding() {},
    log() {},
    cargoProfile: "debug",
    readBuildProvenance(source) {
      return fixtureBuildProvenance(source);
    },
    readSourceState() {
      return {
        sourceGitRevision: SOURCE_REVISION,
        sourceTreeClean: true,
      };
    },
    ...overrides,
  };
}

function publicationArtifacts(destDir) {
  if (!existsSync(destDir)) return [];
  return readdirSync(destDir)
    .filter(
      (name) => name.startsWith(".iroha-js-host-") || name === ".build-dist.lock",
    )
    .sort();
}

function interruptedCleanupPaths(layout) {
  const names = readdirSync(layout.destDir);
  const markerName = names.find((name) =>
    CLEANUP_MARKER_PATTERN.test(name),
  );
  assert.ok(markerName, "interrupted cleanup ownership marker must exist");
  const marker = path.join(layout.destDir, markerName);
  const transactionId = JSON.parse(
    readFileSync(marker, "utf8"),
  ).transactionId;
  const directoryName = `.iroha-js-host-txn-${transactionId}`;
  const directory = path.join(layout.destDir, directoryName);
  assert.ok(
    existsSync(directory),
    "interrupted owned transaction directory must exist",
  );
  return {
    directory,
    directoryName,
    marker,
    markerName,
  };
}

function cleanupMarkerEntryCount(layout) {
  const markerName = readdirSync(layout.destDir).find((name) =>
    CLEANUP_MARKER_PATTERN.test(name),
  );
  assert.ok(markerName);
  const marker = JSON.parse(
    readFileSync(path.join(layout.destDir, markerName), "utf8"),
  );
  assert.ok(Array.isArray(marker.entries));
  return marker.entries.length;
}

function assertPublishedPairWithoutCleanup(layout, expectedBytes) {
  assert.deepEqual(readFileSync(layout.bindingPath), expectedBytes);
  assert.equal(
    verifyNativeBinding(layout.bindingPath, {
      manifestPath: layout.manifestPath,
      platformKey: PLATFORM_KEY,
    }).ok,
    true,
  );
}

function snapshotPair(layout) {
  return {
    binding: readFileSync(layout.bindingPath),
    manifest: readFileSync(layout.manifestPath),
  };
}

function assertVerifiedPair(layout, expectedBytes) {
  assert.deepEqual(readFileSync(layout.bindingPath), expectedBytes);
  const verification = verifyNativeBinding(layout.bindingPath, {
    manifestPath: layout.manifestPath,
    platformKey: PLATFORM_KEY,
  });
  assert.equal(verification.ok, true);
  assert.deepEqual(publicationArtifacts(layout.destDir), []);
  return verification;
}

test("native publication replaces an existing pair repeatably without rename-overwrite", async (t) => {
  const layout = createLayout(t);
  const first = Buffer.from("first verified native binding");
  const second = Buffer.from("second verified native binding");
  const probes = [];
  const options = publicationOptions(layout, {
    probeBinding(bindingPath, requiredExports) {
      probes.push({ bindingPath, requiredExports: [...requiredExports] });
      assert.deepEqual(requiredExports, REQUIRED_NATIVE_EXPORTS);
    },
  });

  writeFileSync(layout.source, first);
  const firstResult = await publishNativeBinding(options);
  assert.equal(firstResult.platformKey, PLATFORM_KEY);
  assertVerifiedPair(layout, first);
  assert.deepEqual(
    JSON.parse(readFileSync(layout.manifestPath, "utf8")).entries[PLATFORM_KEY],
    {
      sha256: firstResult.sha256,
      build_provenance_version: 4,
      build_execution_policy: "trusted-local-cargo-v1",
      cargo_profile: "debug",
      source_git_revision: SOURCE_REVISION,
      source_tree_clean: true,
      source_tree_sha256: SOURCE_TREE_DIGEST,
    },
  );

  // A second publication exercises the Windows-compatible backup-first path:
  // neither rename targets an existing public filename.
  writeFileSync(layout.source, second);
  const secondResult = await publishNativeBinding(options);
  assert.notEqual(secondResult.sha256, firstResult.sha256);
  assertVerifiedPair(layout, second);
  assert.equal(probes.length, 2);
  assert.ok(probes.every(({ bindingPath }) => bindingPath.includes(".iroha-js-host-")));
});

test("same-source publication is idempotent after a fresh probe and returns the exact digest", async (t) => {
  const layout = createLayout(t);
  const bytes = Buffer.from("same verified native binding");
  const probes = [];
  const logs = [];
  const options = publicationOptions(layout, {
    probeBinding(bindingPath) {
      probes.push(bindingPath);
    },
    log(message) {
      logs.push(message);
    },
  });
  writeFileSync(layout.source, bytes);
  const first = await publishNativeBinding(options);
  const second = await publishNativeBinding(options);

  assert.equal(second.sha256, first.sha256);
  assert.match(second.sha256, /^[0-9a-f]{64}$/u);
  assert.equal(probes.length, 2, "an unchanged candidate must still pass its fresh addon probe");
  assert.ok(probes.every((bindingPath) => bindingPath.includes(".iroha-js-host-txn-")));
  assert.match(logs.at(-1), /already matches the verified build output/u);
  assertVerifiedPair(layout, bytes);
});

test("an identical binary with a different valid manifest encoding is idempotent", async (t) => {
  const layout = createLayout(t);
  const bytes = Buffer.from("same native with alternate manifest encoding");
  const logs = [];
  const options = publicationOptions(layout, {
    log(message) {
      logs.push(message);
    },
  });
  writeFileSync(layout.source, bytes);
  const first = await publishNativeBinding(options);

  const alternateManifest = `${JSON.stringify(
    JSON.parse(readFileSync(layout.manifestPath, "utf8")),
  )}\n`;
  writeFileSync(layout.manifestPath, alternateManifest);
  assert.equal(
    verifyNativeBinding(layout.bindingPath, {
      manifestPath: layout.manifestPath,
      platformKey: PLATFORM_KEY,
    }).ok,
    true,
  );

  // This failpoint would make the old implementation enter an unrecoverable
  // transaction because the old and next binaries have the same digest.
  const second = await publishNativeBinding({ ...options, failpoint: "after-native" });
  assert.equal(second.sha256, first.sha256);
  assert.equal(readFileSync(layout.manifestPath, "utf8"), alternateManifest);
  assert.match(logs.at(-1), /already matches the verified build output/u);
  assertVerifiedPair(layout, bytes);
});

test("an identical binary with different sealed-source provenance replaces the manifest", async (t) => {
  const layout = createLayout(t);
  const bytes = Buffer.from("same binary from two sealed source states");
  writeFileSync(layout.source, bytes);
  await publishNativeBinding(publicationOptions(layout));

  const nextRevision = "c".repeat(40);
  const nextDigest = "c".repeat(64);
  const second = await publishNativeBinding(
    publicationOptions(layout, {
      readBuildProvenance(source) {
        return fixtureBuildProvenance(source, "debug", {
          source_git_revision: nextRevision,
          source_tree_sha256: nextDigest,
        });
      },
      readSourceState() {
        return {
          sourceGitRevision: nextRevision,
          sourceTreeClean: true,
        };
      },
    }),
  );

  assert.equal(second.sha256, createHash("sha256").update(bytes).digest("hex"));
  const verification = assertVerifiedPair(layout, bytes);
  assert.equal(verification.sourceGitRevision, nextRevision);
  assert.equal(verification.sourceTreeClean, true);
  assert.equal(verification.sourceTreeSha256, nextDigest);
});

test("identical-binary provenance replacement failpoints restore the exact previous pair", async (t) => {
  for (const failpoint of ["after-backup", "after-native", "after-manifest"]) {
    await t.test(failpoint, async (subtest) => {
      const layout = createLayout(subtest);
      const bytes = Buffer.from(`same binary provenance replacement ${failpoint}`);
      writeFileSync(layout.source, bytes);
      await publishNativeBinding(publicationOptions(layout));
      const before = snapshotPair(layout);
      const replacementRevision = "d".repeat(40);

      await assert.rejects(
        publishNativeBinding(
          publicationOptions(layout, {
            failpoint,
            readBuildProvenance(source) {
              return fixtureBuildProvenance(source, "debug", {
                source_git_revision: replacementRevision,
                source_tree_sha256: "d".repeat(64),
              });
            },
            readSourceState() {
              return {
                sourceGitRevision: replacementRevision,
                sourceTreeClean: true,
              };
            },
          }),
        ),
        new RegExp(`injected test failure at ${failpoint}`, "u"),
      );
      assert.deepEqual(snapshotPair(layout), before);
      assertVerifiedPair(layout, bytes);
    });
  }
});

test("every publication failpoint restores the exact previous pair and cleans staging", async (t) => {
  for (const failpoint of ["after-backup", "after-native", "after-manifest"]) {
    await t.test(failpoint, async (subtest) => {
      const layout = createLayout(subtest);
      writeFileSync(layout.source, Buffer.from(`old-${failpoint}`));
      await publishNativeBinding(publicationOptions(layout));
      const before = snapshotPair(layout);

      writeFileSync(layout.source, Buffer.from(`new-${failpoint}`));
      await assert.rejects(
        publishNativeBinding(publicationOptions(layout, { failpoint })),
        new RegExp(`injected test failure at ${failpoint}`, "u"),
      );
      assert.deepEqual(snapshotPair(layout), before);
      assertVerifiedPair(layout, before.binding);
    });
  }
});

test("failed first publication leaves no partial binary or checksum manifest", async (t) => {
  for (const failpoint of ["after-backup", "after-native", "after-manifest"]) {
    await t.test(failpoint, async (subtest) => {
      const layout = createLayout(subtest);
      writeFileSync(layout.source, Buffer.from(`new-${failpoint}`));
      await assert.rejects(
        publishNativeBinding(publicationOptions(layout, { failpoint })),
        new RegExp(`injected test failure at ${failpoint}`, "u"),
      );
      assert.equal(existsSync(layout.bindingPath), false);
      assert.equal(existsSync(layout.manifestPath), false);
      assert.deepEqual(publicationArtifacts(layout.destDir), []);
    });
  }
});

test("publisher rejects a stale build-provenance binary before destination mutation", async (t) => {
  const layout = createLayout(t);
  writeFileSync(layout.source, "current-native-output");
  await assert.rejects(
    publishNativeBinding(
      publicationOptions(layout, {
        readBuildProvenance() {
          return {
            ...fixtureBuildProvenance(layout.source),
            native_sha256: "0".repeat(64),
          };
        },
      }),
    ),
    /does not match the compiled binary/u,
  );
  assert.equal(existsSync(layout.destDir), false);
});

test("publisher rejects malformed V2 source seals before destination mutation", async (t) => {
  const layout = createLayout(t);
  writeFileSync(layout.source, "current-native-output");
  const missingDigest = fixtureBuildProvenance(layout.source);
  delete missingDigest.source_tree_sha256;
  for (const malformed of [
    missingDigest,
    {
      ...fixtureBuildProvenance(layout.source),
      source_tree_sha256: "B".repeat(64),
    },
    { ...fixtureBuildProvenance(layout.source), unexpected: true },
    { ...fixtureBuildProvenance(layout.source), version: 1 },
  ]) {
    await assert.rejects(
      publishNativeBinding(
        publicationOptions(layout, {
          readBuildProvenance() {
            return malformed;
          },
        }),
      ),
      /unexpected or missing fields|does not match the compiled binary/u,
    );
    assert.equal(existsSync(layout.destDir), false);
  }
});

test("probe, signing, and post-publish verification failures preserve the old pair", async (t) => {
  for (const [label, override] of [
    ["sign", { signNative() { throw new Error("injected signing failure"); } }],
    ["probe", { probeBinding() { throw new Error("injected probe failure"); } }],
    [
      "post-verify",
      {
        verifyBinding(bindingPath, options) {
          if (
            !bindingPath.includes(".iroha-js-host-txn-") &&
            readFileSync(bindingPath, "utf8") === "new-post-verify"
          ) {
            return { ok: false, status: "injected_post_verify" };
          }
          return verifyNativeBinding(bindingPath, options);
        },
      },
    ],
  ]) {
    await t.test(label, async (subtest) => {
      const layout = createLayout(subtest);
      writeFileSync(layout.source, Buffer.from(`old-${label}`));
      await publishNativeBinding(publicationOptions(layout));
      const before = snapshotPair(layout);
      writeFileSync(layout.source, Buffer.from(`new-${label}`));

      await assert.rejects(
        publishNativeBinding(publicationOptions(layout, override)),
        /injected|verification/u,
      );
      assert.deepEqual(snapshotPair(layout), before);
      assertVerifiedPair(layout, before.binding);
    });
  }
});

test("publisher rejects an ambiguous partial destination before mutation", async (t) => {
  const partial = createLayout(t);
  mkdirSync(partial.destDir, { recursive: true });
  writeFileSync(partial.source, Buffer.from("replacement"));
  writeFileSync(partial.bindingPath, Buffer.from("orphan"));
  await assert.rejects(
    publishNativeBinding(publicationOptions(partial)),
    /partial binary\/checksum pair/u,
  );
  assert.deepEqual(readFileSync(partial.bindingPath), Buffer.from("orphan"));
  assert.equal(existsSync(partial.manifestPath), false);
  assert.deepEqual(publicationArtifacts(partial.destDir), []);
});

test("SIGKILL recovery resolves every durable replacement phase to an exact old or new pair", async (t) => {
  const phases = [
    ["transaction-owner-written", "previous"],
    ["transaction-owner-synced", "previous"],
    ["transaction-initializer-renamed", "previous"],
    ["transaction-created", "previous"],
    ["staged-native-synced", "previous"],
    ["staged-manifest-synced", "previous"],
    ["journal-prepared", "previous"],
    ["previous-manifest-renamed", "previous"],
    ["previous-manifest-moved", "previous"],
    ["previous-native-renamed", "previous"],
    ["previous-native-moved", "previous"],
    ["next-native-renamed", "previous"],
    ["next-native-moved", "previous"],
    ["next-manifest-renamed", "next"],
    ["next-manifest-moved", "next"],
    ["published-pair-verified", "next"],
    ["published-verified", "next"],
    ["journal-committed", "next"],
    ["cleanup-marker-temp-synced", "next"],
    ["cleanup-marker-linked", "existing"],
    ["cleanup-marker-synced", "existing"],
    ["cleanup-owned", "existing"],
    ["cleanup-entry-removed:1", "existing"],
    ["cleanup-directory-removed", "existing"],
  ];
  for (const [phase, expected] of phases) {
    await t.test(phase, async (subtest) => {
      const layout = createLayout(subtest);
      const previous = Buffer.from(`previous-${phase}`);
      const next = Buffer.from(`next-${phase}`);
      writeFileSync(layout.source, previous);
      await publishNativeBinding(publicationOptions(layout));
      writeFileSync(layout.source, next);

      await killPublisherAtPhase(layout, phase);
      const recovery = await recoverNativeBindingPublication({
        destDir: layout.destDir,
        platform: PLATFORM,
        arch: ARCH,
      });
      if (expected === "previous") {
        assert.ok(["existing", "previous"].includes(recovery.outcome));
      } else {
        assert.equal(recovery.outcome, expected);
      }
      assertVerifiedPair(
        layout,
        expected === "next" || expected === "existing" ? next : previous,
      );

      const final = Buffer.from(`repeatable-${phase}`);
      writeFileSync(layout.source, final);
      await publishNativeBinding(publicationOptions(layout));
      assertVerifiedPair(layout, final);
    });
  }
});

test("SIGKILL recovery covers every first-publication phase without inventing a prior pair", async (t) => {
  const phases = [
    ["transaction-owner-written", "absent"],
    ["transaction-owner-synced", "absent"],
    ["transaction-initializer-renamed", "absent"],
    ["transaction-created", "absent"],
    ["staged-native-synced", "absent"],
    ["staged-manifest-synced", "absent"],
    ["journal-prepared", "absent"],
    ["next-native-renamed", "absent"],
    ["next-native-moved", "absent"],
    ["next-manifest-renamed", "next"],
    ["next-manifest-moved", "next"],
    ["published-pair-verified", "next"],
    ["published-verified", "next"],
    ["journal-committed", "next"],
    ["cleanup-marker-temp-synced", "next"],
    ["cleanup-marker-linked", "existing"],
    ["cleanup-marker-synced", "existing"],
    ["cleanup-owned", "existing"],
    ["cleanup-entry-removed:1", "existing"],
    ["cleanup-directory-removed", "existing"],
  ];
  for (const [phase, expected] of phases) {
    await t.test(phase, async (subtest) => {
      const layout = createLayout(subtest);
      const next = Buffer.from(`first-${phase}`);
      writeFileSync(layout.source, next);
      await killPublisherAtPhase(layout, phase);

      const recovery = await recoverNativeBindingPublication({
        destDir: layout.destDir,
        platform: PLATFORM,
        arch: ARCH,
      });
      if (expected === "next" || expected === "existing") {
        assert.equal(recovery.outcome, expected);
        assertVerifiedPair(layout, next);
      } else {
        assert.ok(["absent", "none"].includes(recovery.outcome));
        assert.equal(existsSync(layout.bindingPath), false);
        assert.equal(existsSync(layout.manifestPath), false);
        assert.deepEqual(publicationArtifacts(layout.destDir), []);
      }

      const final = Buffer.from(`repeatable-first-${phase}`);
      writeFileSync(layout.source, final);
      await publishNativeBinding(publicationOptions(layout));
      assertVerifiedPair(layout, final);
    });
  }
});

test("SIGKILL after initializer mkdir leaves unowned data untouched without blocking publication", async (t) => {
  const layout = createLayout(t);
  const next = Buffer.from("initializer-created-before-owner");
  writeFileSync(layout.source, next);
  await killPublisherAtPhase(layout, "transaction-initializer-created");

  const initializers = readdirSync(layout.destDir).filter((name) =>
    name.startsWith(TRANSACTION_INITIALIZER_PREFIX),
  );
  assert.equal(initializers.length, 1);
  const initializer = path.join(layout.destDir, initializers[0]);
  assert.deepEqual(readdirSync(initializer), []);

  const recovery = await recoverNativeBindingPublication({
    destDir: layout.destDir,
    platform: PLATFORM,
    arch: ARCH,
  });
  assert.ok(["absent", "none"].includes(recovery.outcome));
  assert.equal(existsSync(initializer), true);

  await publishNativeBinding(publicationOptions(layout));
  assertPublishedPairWithoutCleanup(layout, next);
  assert.equal(existsSync(initializer), true);
  assert.deepEqual(readdirSync(initializer), []);
});

test("a partial initializer owner marker remains forensic and cannot block publication", async (t) => {
  const layout = createLayout(t);
  const initializer = path.join(
    layout.destDir,
    `${TRANSACTION_INITIALIZER_PREFIX}11111111-1111-4111-8111-111111111111-22222222-2222-4222-8222-222222222222`,
  );
  const owner = path.join(
    initializer,
    ".iroha-js-host-transaction-owner-v1.json",
  );
  mkdirSync(initializer, { recursive: true });
  writeFileSync(owner, '{"version":');

  const recovery = await recoverNativeBindingPublication({
    destDir: layout.destDir,
    platform: PLATFORM,
    arch: ARCH,
  });
  assert.ok(["absent", "none"].includes(recovery.outcome));
  assert.equal(readFileSync(owner, "utf8"), '{"version":');

  const next = Buffer.from("publication-after-partial-initializer-owner");
  writeFileSync(layout.source, next);
  await publishNativeBinding(publicationOptions(layout));
  assertPublishedPairWithoutCleanup(layout, next);
  assert.equal(readFileSync(owner, "utf8"), '{"version":');
});

test("an owner-sync failure leaves a fully written initializer recoverable", async (t) => {
  const layout = createLayout(t);
  writeFileSync(layout.source, Buffer.from("owner-sync-failure"));

  await assert.rejects(
    publishNativeBinding(
      publicationOptions(layout, {
        phaseHook(phase) {
          if (phase === "transaction-owner-written") {
            throw new Error("injected owner sync failure");
          }
        },
      }),
    ),
    /injected owner sync failure/u,
  );
  const initializer = readdirSync(layout.destDir).find((name) =>
    name.startsWith(TRANSACTION_INITIALIZER_PREFIX),
  );
  assert.ok(initializer);

  const recovery = await recoverNativeBindingPublication({
    destDir: layout.destDir,
    platform: PLATFORM,
    arch: ARCH,
  });
  assert.ok(["absent", "none"].includes(recovery.outcome));
  assert.equal(
    existsSync(path.join(layout.destDir, initializer)),
    false,
  );
  assert.deepEqual(publicationArtifacts(layout.destDir), []);
});

test("a truncated owner write during initialization is preserved without blocking publication", async (t) => {
  const layout = createLayout(t);
  writeFileSync(layout.source, Buffer.from("truncated-initializer-owner"));

  await assert.rejects(
    publishNativeBinding(
      publicationOptions(layout, {
        phaseHook(phase) {
          if (phase !== "transaction-owner-written") return;
          const initializer = readdirSync(layout.destDir).find((name) =>
            name.startsWith(TRANSACTION_INITIALIZER_PREFIX),
          );
          assert.ok(initializer);
          writeFileSync(
            path.join(
              layout.destDir,
              initializer,
              ".iroha-js-host-transaction-owner-v1.json",
            ),
            '{"version":',
          );
        },
      }),
    ),
    /ownership marker is not valid JSON/u,
  );
  const initializer = readdirSync(layout.destDir).find((name) =>
    name.startsWith(TRANSACTION_INITIALIZER_PREFIX),
  );
  assert.ok(initializer);
  const owner = path.join(
    layout.destDir,
    initializer,
    ".iroha-js-host-transaction-owner-v1.json",
  );
  assert.equal(readFileSync(owner, "utf8"), '{"version":');

  const next = Buffer.from("publication-after-truncated-owner-write");
  writeFileSync(layout.source, next);
  await publishNativeBinding(publicationOptions(layout));
  assertPublishedPairWithoutCleanup(layout, next);
  assert.equal(readFileSync(owner, "utf8"), '{"version":');
});

test("SIGKILL recovery accepts every canonical cleanup-deletion suffix", async (t) => {
  await t.test("first publication", async (group) => {
    const probe = createLayout(group);
    const probeBytes = Buffer.from("cleanup-suffix-first-probe");
    writeFileSync(probe.source, probeBytes);
    await killPublisherAtPhase(probe, "cleanup-marker-synced");
    const entryCount = cleanupMarkerEntryCount(probe);
    await recoverNativeBindingPublication({
      destDir: probe.destDir,
      platform: PLATFORM,
      arch: ARCH,
    });
    assertVerifiedPair(probe, probeBytes);

    for (let removed = 1; removed <= entryCount; removed += 1) {
      await group.test(`after ${removed} removals`, async (subtest) => {
        const layout = createLayout(subtest);
        const next = Buffer.from(`cleanup-suffix-first-${removed}`);
        writeFileSync(layout.source, next);
        await killPublisherAtPhase(
          layout,
          `cleanup-entry-removed:${removed}`,
        );
        const recovery = await recoverNativeBindingPublication({
          destDir: layout.destDir,
          platform: PLATFORM,
          arch: ARCH,
        });
        assert.equal(recovery.outcome, "existing");
        assertVerifiedPair(layout, next);
      });
    }
  });

  await t.test("replacement publication", async (group) => {
    const probe = createLayout(group);
    const probeNext = Buffer.from("cleanup-suffix-replacement-probe-next");
    writeFileSync(
      probe.source,
      Buffer.from("cleanup-suffix-replacement-probe-previous"),
    );
    await publishNativeBinding(publicationOptions(probe));
    writeFileSync(probe.source, probeNext);
    await killPublisherAtPhase(probe, "cleanup-marker-synced");
    const entryCount = cleanupMarkerEntryCount(probe);
    await recoverNativeBindingPublication({
      destDir: probe.destDir,
      platform: PLATFORM,
      arch: ARCH,
    });
    assertVerifiedPair(probe, probeNext);

    for (let removed = 1; removed <= entryCount; removed += 1) {
      await group.test(`after ${removed} removals`, async (subtest) => {
        const layout = createLayout(subtest);
        const next = Buffer.from(`cleanup-suffix-replacement-${removed}`);
        writeFileSync(
          layout.source,
          Buffer.from(`cleanup-suffix-previous-${removed}`),
        );
        await publishNativeBinding(publicationOptions(layout));
        writeFileSync(layout.source, next);
        await killPublisherAtPhase(
          layout,
          `cleanup-entry-removed:${removed}`,
        );
        const recovery = await recoverNativeBindingPublication({
          destDir: layout.destDir,
          platform: PLATFORM,
          arch: ARCH,
        });
        assert.equal(recovery.outcome, "existing");
        assertVerifiedPair(layout, next);
      });
    }
  });
});

test("recovery refuses arbitrary cleanup-prefixed user data without deleting it", async (t) => {
  const layout = createLayout(t);
  const userDirectory = path.join(
    layout.destDir,
    ".iroha-js-host-cleanup-user-data",
  );
  const keep = path.join(userDirectory, "keep.txt");
  mkdirSync(userDirectory, { recursive: true });
  writeFileSync(keep, "must survive");

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /unowned cleanup-prefixed artifact/u,
  );
  assert.equal(readFileSync(keep, "utf8"), "must survive");
});

test("recovery refuses an exact cleanup directory name without its ownership marker", async (t) => {
  const layout = createLayout(t);
  const spoofed = path.join(
    layout.destDir,
    ".iroha-js-host-cleanup-v1-11111111-1111-4111-8111-111111111111-22222222-2222-4222-8222-222222222222",
  );
  const keep = path.join(spoofed, "keep.txt");
  mkdirSync(spoofed, { recursive: true });
  writeFileSync(keep, "unowned exact-name data");

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /unmarked cleanup directory/u,
  );
  assert.equal(readFileSync(keep, "utf8"), "unowned exact-name data");
});

test("recovery refuses an exact unjournaled transaction without its pre-existing owner marker", async (t) => {
  const layout = createLayout(t);
  const transaction = path.join(
    layout.destDir,
    ".iroha-js-host-txn-77777777-7777-4777-8777-777777777777",
  );
  const keep = path.join(transaction, `${NATIVE_FILENAME}.next`);
  mkdirSync(transaction, { recursive: true });
  writeFileSync(keep, "allowlisted name containing unowned user data");

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /without its durable ownership marker/u,
  );
  assert.equal(
    readFileSync(keep, "utf8"),
    "allowlisted name containing unowned user data",
  );
  assert.equal(existsSync(transaction), true);
});

test("cleanup never overwrites an intervening exact cleanup directory", async (t) => {
  const layout = createLayout(t);
  const next = Buffer.from("no-clobber-cleanup-target");
  let inserted;
  let insertedIdentity;
  writeFileSync(layout.source, next);

  await assert.rejects(
    publishNativeBinding(
      publicationOptions(layout, {
        phaseHook(phase) {
          if (phase !== "cleanup-marker-synced") return;
          const markerName = readdirSync(layout.destDir).find((name) =>
            CLEANUP_MARKER_PATTERN.test(name),
          );
          assert.ok(markerName);
          inserted = path.join(
            layout.destDir,
            markerName.slice(0, -".owner.json".length),
          );
          mkdirSync(inserted);
          const metadata = lstatSync(inserted, { bigint: true });
          insertedIdentity = {
            dev: metadata.dev,
            ino: metadata.ino,
          };
        },
      }),
    ),
    (error) => {
      const messages = [
        error.message,
        ...(error instanceof AggregateError
          ? error.errors.map((nested) => nested.message)
          : []),
      ].join("\n");
      return /intervening cleanup directory|cleanup artifacts must be recovered/u.test(
        messages,
      );
    },
  );
  assert.ok(inserted);
  const after = lstatSync(inserted, { bigint: true });
  assert.deepEqual(
    { dev: after.dev, ino: after.ino },
    insertedIdentity,
  );
  assert.equal(existsSync(layout.bindingPath), false);
  assert.equal(existsSync(layout.manifestPath), false);
});

test("recovery refuses a spoofed exact marker and preserves it", async (t) => {
  const layout = createLayout(t);
  mkdirSync(layout.destDir, { recursive: true });
  const marker = path.join(
    layout.destDir,
    ".iroha-js-host-cleanup-v1-33333333-3333-4333-8333-333333333333-44444444-4444-4444-8444-444444444444.owner.json",
  );
  writeFileSync(marker, '{"attacker":"not an ownership marker"}\n');

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /unexpected or missing fields/u,
  );
  assert.equal(
    readFileSync(marker, "utf8"),
    '{"attacker":"not an ownership marker"}\n',
  );
});

test("recovery discards a partial cleanup-marker temporary only for an owned transaction", async (t) => {
  const layout = createLayout(t);
  writeFileSync(layout.source, Buffer.from("partial-cleanup-marker-temporary"));
  await killPublisherAtPhase(layout, "staged-native-synced");
  const transactionName = readdirSync(layout.destDir).find((name) =>
    name.startsWith(".iroha-js-host-txn-"),
  );
  assert.ok(transactionName);
  const transactionId = transactionName.slice(
    ".iroha-js-host-txn-".length,
  );
  const temporary = path.join(
    layout.destDir,
    `.iroha-js-host-cleanup-v1-${transactionId}-88888888-8888-4888-8888-888888888888.owner-99999999-9999-4999-8999-999999999999.tmp`,
  );
  writeFileSync(temporary, '{"version":');

  const recovery = await recoverNativeBindingPublication({
    destDir: layout.destDir,
    platform: PLATFORM,
    arch: ARCH,
  });
  assert.ok(["absent", "none"].includes(recovery.outcome));
  assert.equal(existsSync(temporary), false);
  assert.equal(
    existsSync(path.join(layout.destDir, transactionName)),
    false,
  );
  assert.deepEqual(publicationArtifacts(layout.destDir), []);
});

test("recovery fails closed on a truncated published cleanup marker", async (t) => {
  const layout = createLayout(t);
  const next = Buffer.from("truncated-cleanup-marker");
  writeFileSync(layout.source, next);
  await killPublisherAtPhase(layout, "cleanup-marker-synced");
  const cleanup = interruptedCleanupPaths(layout);
  writeFileSync(cleanup.marker, '{"version":');

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /ownership marker is not valid JSON/u,
  );
  assert.equal(existsSync(cleanup.directory), true);
  assert.equal(readFileSync(cleanup.marker, "utf8"), '{"version":');
  assertPublishedPairWithoutCleanup(layout, next);
});

test("recovery rejects a cleanup marker symlink without touching its target", async (t) => {
  const layout = createLayout(t);
  const next = Buffer.from("cleanup-marker-symlink");
  const external = path.join(layout.root, "external-marker-target.json");
  writeFileSync(layout.source, next);
  await killPublisherAtPhase(layout, "cleanup-marker-synced");
  const cleanup = interruptedCleanupPaths(layout);
  const bytes = "external marker target must survive";
  writeFileSync(external, bytes);
  unlinkSync(cleanup.marker);
  symlinkSync(external, cleanup.marker);

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /regular non-symbolic-link file/u,
  );
  assert.equal(readFileSync(external, "utf8"), bytes);
  assert.equal(lstatSync(cleanup.marker).isSymbolicLink(), true);
  assert.equal(existsSync(cleanup.directory), true);
  assertPublishedPairWithoutCleanup(layout, next);
});

test("recovery rejects a multiply linked cleanup marker", async (t) => {
  const layout = createLayout(t);
  const next = Buffer.from("cleanup-marker-hardlink");
  const extraLink = path.join(layout.root, "extra-cleanup-marker-link.json");
  writeFileSync(layout.source, next);
  await killPublisherAtPhase(layout, "cleanup-marker-synced");
  const cleanup = interruptedCleanupPaths(layout);
  linkSync(cleanup.marker, extraLink);

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /singly linked regular file/u,
  );
  assert.deepEqual(readFileSync(extraLink), readFileSync(cleanup.marker));
  assert.equal(existsSync(cleanup.directory), true);
  assertPublishedPairWithoutCleanup(layout, next);
});

test("recovery rejects a cleanup marker whose transaction identity was replaced", async (t) => {
  const layout = createLayout(t);
  const next = Buffer.from("cleanup-marker-identity-next");
  writeFileSync(layout.source, next);
  await killPublisherAtPhase(layout, "cleanup-owned");
  const cleanup = interruptedCleanupPaths(layout);
  const marker = JSON.parse(readFileSync(cleanup.marker, "utf8"));
  marker.transactionId = "55555555-5555-4555-8555-555555555555";
  writeFileSync(cleanup.marker, `${JSON.stringify(marker, null, 2)}\n`);

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /transaction id does not match its artifact name/u,
  );
  assert.equal(existsSync(cleanup.directory), true);
  assert.equal(existsSync(cleanup.marker), true);
  assertPublishedPairWithoutCleanup(layout, next);
});

test("recovery rejects a marker/journal transaction mismatch even with a rewritten inventory", async (t) => {
  const layout = createLayout(t);
  const next = Buffer.from("cleanup-journal-mismatch-next");
  writeFileSync(layout.source, next);
  await killPublisherAtPhase(layout, "cleanup-owned");
  const cleanup = interruptedCleanupPaths(layout);
  const journal = path.join(cleanup.directory, "journal-000000.json");
  const entry = JSON.parse(readFileSync(journal, "utf8"));
  entry.transactionId = "66666666-6666-4666-8666-666666666666";
  writeFileSync(journal, `${JSON.stringify(entry, null, 2)}\n`);
  const marker = JSON.parse(readFileSync(cleanup.marker, "utf8"));
  const journalMetadata = lstatSync(journal, { bigint: true });
  const journalIndex = marker.entries.findIndex(
    ({ name }) => name === "journal-000000.json",
  );
  assert.notEqual(journalIndex, -1);
  marker.entries[journalIndex] = {
    name: "journal-000000.json",
    birthtimeNs: String(journalMetadata.birthtimeNs),
    dev: String(journalMetadata.dev),
    ino: String(journalMetadata.ino),
    mtimeNs: String(journalMetadata.mtimeNs),
    sha256: createHash("sha256").update(readFileSync(journal)).digest("hex"),
    size: String(journalMetadata.size),
  };
  writeFileSync(cleanup.marker, `${JSON.stringify(marker, null, 2)}\n`);

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /journal transaction id does not match its directory/u,
  );
  assert.equal(existsSync(cleanup.directory), true);
  assert.equal(existsSync(cleanup.marker), true);
  assertPublishedPairWithoutCleanup(layout, next);
});

test("recovery rejects a replacement directory at an owned cleanup pathname", async (t) => {
  const layout = createLayout(t);
  const next = Buffer.from("cleanup-directory-replacement-next");
  writeFileSync(layout.source, next);
  await killPublisherAtPhase(layout, "cleanup-owned");
  const cleanup = interruptedCleanupPaths(layout);
  const preservedOwnedDirectory = path.join(
    layout.destDir,
    ".forensic-original-cleanup",
  );
  renameSync(cleanup.directory, preservedOwnedDirectory);
  mkdirSync(cleanup.directory);
  const keep = path.join(cleanup.directory, "keep.txt");
  writeFileSync(keep, "replacement must survive");

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /no longer matches its ownership marker/u,
  );
  assert.equal(readFileSync(keep, "utf8"), "replacement must survive");
  assert.equal(existsSync(preservedOwnedDirectory), true);
  assert.equal(existsSync(cleanup.marker), true);
  assertPublishedPairWithoutCleanup(layout, next);
});

test("recovery rejects an impossible non-suffix cleanup inventory", async (t) => {
  const layout = createLayout(t);
  const next = Buffer.from("cleanup-impossible-inventory-next");
  writeFileSync(
    layout.source,
    Buffer.from("cleanup-impossible-inventory-previous"),
  );
  await publishNativeBinding(publicationOptions(layout));
  writeFileSync(layout.source, next);
  await killPublisherAtPhase(layout, "cleanup-owned");
  const cleanup = interruptedCleanupPaths(layout);
  const removedOutOfOrder = path.join(
    cleanup.directory,
    `${NATIVE_FILENAME}.previous`,
  );
  const mustPrecedeIt = path.join(
    cleanup.directory,
    `${MANIFEST_FILENAME}.previous`,
  );
  assert.equal(existsSync(removedOutOfOrder), true);
  assert.equal(existsSync(mustPrecedeIt), true);
  unlinkSync(removedOutOfOrder);

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /not a canonical deletion suffix/u,
  );
  assert.equal(existsSync(mustPrecedeIt), true);
  assert.equal(existsSync(cleanup.marker), true);
  assertPublishedPairWithoutCleanup(layout, next);
});

test("recovery refuses tampered backup bytes and preserves the forensic transaction", async (t) => {
  const layout = createLayout(t);
  const previous = Buffer.from("tamper-test-previous");
  writeFileSync(layout.source, previous);
  await publishNativeBinding(publicationOptions(layout));
  writeFileSync(layout.source, Buffer.from("tamper-test-next"));
  await killPublisherAtPhase(layout, "previous-native-moved");

  const transaction = readdirSync(layout.destDir).find((name) =>
    name.startsWith(".iroha-js-host-txn-"),
  );
  assert.ok(transaction);
  const backup = path.join(layout.destDir, transaction, `${NATIVE_FILENAME}.previous`);
  chmodSync(backup, 0o600);
  writeFileSync(backup, Buffer.from("attacker-replaced-backup"));

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /tampered|does not match the journal/u,
  );
  assert.equal(existsSync(layout.bindingPath), false);
  assert.equal(existsSync(layout.manifestPath), false);
  assert.ok(publicationArtifacts(layout.destDir).includes(transaction));
});

test("recovery rejects a journal with injected fields before mutating the prior pair", async (t) => {
  const layout = createLayout(t);
  const previous = Buffer.from("journal-tamper-previous");
  writeFileSync(layout.source, previous);
  await publishNativeBinding(publicationOptions(layout));
  writeFileSync(layout.source, Buffer.from("journal-tamper-next"));
  await killPublisherAtPhase(layout, "journal-prepared");

  const transaction = readdirSync(layout.destDir).find((name) =>
    name.startsWith(".iroha-js-host-txn-"),
  );
  assert.ok(transaction);
  const journal = path.join(layout.destDir, transaction, "journal-000000.json");
  const malicious = JSON.parse(readFileSync(journal, "utf8"));
  malicious.attacker = "injected";
  writeFileSync(journal, `${JSON.stringify(malicious)}\n`);

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /unexpected or missing fields/u,
  );
  assert.deepEqual(readFileSync(layout.bindingPath), previous);
  assert.equal(
    verifyNativeBinding(layout.bindingPath, {
      manifestPath: layout.manifestPath,
      platformKey: PLATFORM_KEY,
    }).ok,
    true,
  );
  assert.ok(publicationArtifacts(layout.destDir).includes(transaction));
});

test("recovery rejects a journal symlink before reading its target", async (t) => {
  const layout = createLayout(t);
  const previous = Buffer.from("journal-symlink-previous");
  const external = path.join(layout.root, "external-journal-target.json");
  writeFileSync(layout.source, previous);
  await publishNativeBinding(publicationOptions(layout));
  writeFileSync(layout.source, Buffer.from("journal-symlink-next"));
  await killPublisherAtPhase(layout, "journal-prepared");
  const transaction = readdirSync(layout.destDir).find((name) =>
    name.startsWith(".iroha-js-host-txn-"),
  );
  assert.ok(transaction);
  const journal = path.join(
    layout.destDir,
    transaction,
    "journal-000000.json",
  );
  const externalBytes = '{"external":"must not be consumed or changed"}\n';
  writeFileSync(external, externalBytes);
  unlinkSync(journal);
  symlinkSync(external, journal);

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /regular non-symbolic-link file/u,
  );
  assert.equal(readFileSync(external, "utf8"), externalBytes);
  assert.deepEqual(readFileSync(layout.bindingPath), previous);
  assert.equal(lstatSync(journal).isSymbolicLink(), true);
});

test("recovery rejects a journal that skips durable phases", async (t) => {
  const layout = createLayout(t);
  const previous = Buffer.from("journal-phase-previous");
  writeFileSync(layout.source, previous);
  await publishNativeBinding(publicationOptions(layout));
  writeFileSync(layout.source, Buffer.from("journal-phase-next"));
  await killPublisherAtPhase(layout, "journal-prepared");

  const transaction = readdirSync(layout.destDir).find((name) =>
    name.startsWith(".iroha-js-host-txn-"),
  );
  assert.ok(transaction);
  const journal = path.join(layout.destDir, transaction, "journal-000000.json");
  const malicious = JSON.parse(readFileSync(journal, "utf8"));
  malicious.phase = "committed";
  writeFileSync(journal, `${JSON.stringify(malicious)}\n`);

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /journal phases are non-canonical/u,
  );
  assert.deepEqual(readFileSync(layout.bindingPath), previous);
  assert.ok(publicationArtifacts(layout.destDir).includes(transaction));
});

test("recovery bounds a maliciously oversized journal before parsing", async (t) => {
  const layout = createLayout(t);
  const previous = Buffer.from("oversized-journal-previous");
  writeFileSync(layout.source, previous);
  await publishNativeBinding(publicationOptions(layout));
  writeFileSync(layout.source, Buffer.from("oversized-journal-next"));
  await killPublisherAtPhase(layout, "journal-prepared");

  const transaction = readdirSync(layout.destDir).find((name) =>
    name.startsWith(".iroha-js-host-txn-"),
  );
  assert.ok(transaction);
  const journal = path.join(layout.destDir, transaction, "journal-000000.json");
  writeFileSync(journal, "[".repeat(16 * 1024 + 1));

  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /journal entry exceeds 16384 bytes/u,
  );
  assert.deepEqual(readFileSync(layout.bindingPath), previous);
  assert.ok(publicationArtifacts(layout.destDir).includes(transaction));
});

test("recovery rejects duplicated exact old components instead of guessing ownership", async (t) => {
  const layout = createLayout(t);
  writeFileSync(layout.source, Buffer.from("duplicate-old-previous"));
  await publishNativeBinding(publicationOptions(layout));
  writeFileSync(layout.source, Buffer.from("duplicate-old-next"));
  await killPublisherAtPhase(layout, "journal-prepared");

  const transaction = readdirSync(layout.destDir).find((name) =>
    name.startsWith(".iroha-js-host-txn-"),
  );
  assert.ok(transaction);
  copyFileSync(
    layout.bindingPath,
    path.join(layout.destDir, transaction, `${NATIVE_FILENAME}.previous`),
  );
  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /duplicate previous-pair components/u,
  );
  assert.deepEqual(readFileSync(layout.bindingPath), Buffer.from("duplicate-old-previous"));
});

test("recovery rejects a committed-looking pair when its exact prior backup is missing", async (t) => {
  const layout = createLayout(t);
  const next = Buffer.from("missing-prior-next");
  writeFileSync(layout.source, Buffer.from("missing-prior-previous"));
  await publishNativeBinding(publicationOptions(layout));
  writeFileSync(layout.source, next);
  await killPublisherAtPhase(layout, "next-manifest-renamed");

  const transaction = readdirSync(layout.destDir).find((name) =>
    name.startsWith(".iroha-js-host-txn-"),
  );
  assert.ok(transaction);
  rmSync(path.join(layout.destDir, transaction, `${NATIVE_FILENAME}.previous`));
  await assert.rejects(
    recoverNativeBindingPublication({
      destDir: layout.destDir,
      platform: PLATFORM,
      arch: ARCH,
    }),
    /missing or duplicate previous-pair components/u,
  );
  assert.deepEqual(readFileSync(layout.bindingPath), next);
  assert.equal(
    verifyNativeBinding(layout.bindingPath, {
      manifestPath: layout.manifestPath,
      platformKey: PLATFORM_KEY,
    }).ok,
    true,
  );
});

test("a partial next journal write is ignored while the last fsynced entry drives recovery", async (t) => {
  const layout = createLayout(t);
  const previous = Buffer.from("partial-journal-previous");
  writeFileSync(layout.source, previous);
  await publishNativeBinding(publicationOptions(layout));
  writeFileSync(layout.source, Buffer.from("partial-journal-next"));
  await killPublisherAtPhase(layout, "journal-prepared");

  const transaction = readdirSync(layout.destDir).find((name) =>
    name.startsWith(".iroha-js-host-txn-"),
  );
  assert.ok(transaction);
  writeFileSync(
    path.join(
      layout.destDir,
      transaction,
      ".journal-000001-00000000-0000-4000-8000-000000000000.tmp",
    ),
    '{"version":',
  );
  const recovery = await recoverNativeBindingPublication({
    destDir: layout.destDir,
    platform: PLATFORM,
    arch: ARCH,
  });
  assert.equal(recovery.outcome, "previous");
  assertVerifiedPair(layout, previous);
});

test("publisher refuses a checksum-invalid existing pair before creating a transaction", async (t) => {
  const layout = createLayout(t);
  writeFileSync(layout.source, Buffer.from("valid-existing"));
  await publishNativeBinding(publicationOptions(layout));
  chmodSync(layout.bindingPath, 0o600);
  writeFileSync(layout.bindingPath, Buffer.from("tampered-existing"));
  writeFileSync(layout.source, Buffer.from("replacement"));

  await assert.rejects(
    publishNativeBinding(publicationOptions(layout)),
    /Existing native binding(?: after recovery)? failed checksum verification/u,
  );
  assert.deepEqual(readFileSync(layout.bindingPath), Buffer.from("tampered-existing"));
  assert.deepEqual(publicationArtifacts(layout.destDir), []);
});

test("required-export probe accepts a complete module and rejects missing symbols", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "iroha-js-native-probe-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const complete = path.join(root, "complete.cjs");
  const incomplete = path.join(root, "incomplete.cjs");
  const wrongAbi = path.join(root, "wrong-abi.cjs");
  const completeSource = nativeProbeFixtureSource();
  writeFileSync(complete, completeSource);
  writeFileSync(incomplete, "module.exports = { noritoEncodeInstruction() {} };\n");
  writeFileSync(wrongAbi, nativeProbeFixtureSource({
    validatorBody: "return 0;",
  }).replace(
    "securePrivateFileAbiVersion() { return 1; }",
    "securePrivateFileAbiVersion() { return 2; }",
  ));

  assert.equal(
    probeNativeBindingExports(complete),
    REQUIRED_NATIVE_BRIDGE_ABI_VERSION,
  );
  assert.throws(
    () => probeNativeBindingExports(incomplete),
    /missing required native exports.*noritoDecodeInstruction.*compileKotodama/u,
  );
  assert.throws(
    () => probeNativeBindingExports(wrongAbi),
    /invalid required native export results.*securePrivateFileAbiVersion expected 1 but found 2/u,
  );
  assert.throws(
    () => probeNativeBindingExports(complete, ["not-valid!"]),
    /non-empty identifier array/u,
  );
  assert.throws(
    () =>
      probeNativeBindingExports(
        complete,
        REQUIRED_NATIVE_EXPORTS,
        REQUIRED_NATIVE_BRIDGE_ABI_VERSION - 2,
      ),
    new RegExp(
      `ABI mismatch.*expected ${REQUIRED_NATIVE_BRIDGE_ABI_VERSION - 2}.*found ${REQUIRED_NATIVE_BRIDGE_ABI_VERSION}`,
      "u",
    ),
  );
});

test("required-export probe rejects missing strict boundary symbols", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "iroha-js-native-symbol-gate-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));

  for (const missing of [
    "accountAddressParseEncoded",
    "accountAddressRender",
    "noritoEncodeInstructionBoxArchive",
    "noritoDecodeInstructionBoxArchive",
    "buildKaigiAuthorizationProofV1",
    "buildKaigiUsageProofV1",
    "privacyCompiledProfileCatalogV1",
    "privacyExact12CapabilityManifestJsonV1",
    "privacyRequireExact12CapabilityTupleV1",
    "privacyValidateCompiledProfileCatalogV1",
    "privacyValidateExact12CapabilityManifestV1",
    "blockProofsVerifyAuthenticatedV1",
    "inspectSorafsOrderbookSubmissionForDiscriminantV1",
    "verifySorafsOrderbookSubmissionReceiptV1",
  ]) {
    const fixture = path.join(root, `${missing}.cjs`);
    writeFileSync(fixture, nativeProbeFixtureSource({ omit: [missing] }));
    assert.throws(
      () => probeNativeBindingExports(fixture),
      new RegExp(`missing required native exports: ${missing}`, "u"),
      missing,
    );
  }
});

test("required-export probe rejects codecs that ignore the selected network context", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "iroha-js-native-context-probe-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = path.join(root, "implicit-context.cjs");
  writeFileSync(fixture, nativeProbeFixtureSource().replaceAll(
    'if (!Number.isInteger(prefix) || prefix < 0 || prefix > 65535) throw new TypeError("network prefix"); ',
    "",
  ));
  assert.throws(() => probeNativeBindingExports(fixture), /invalid native instruction network context contract.*accepted a missing or invalid network prefix/u);
});

test("required-export probe fail-closes on adversarial compiled-profile catalogs", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "iroha-js-native-catalog-gate-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const hostileFixtures = [
    {
      name: "text",
      catalogBody: 'return "NRT0";',
      expected: /must return 1\.\.262144 non-shared Buffer bytes/u,
    },
    {
      name: "typed-array-alias",
      catalogBody: "return Uint8Array.from([0x4e]);",
      expected: /must return 1\.\.262144 non-shared Buffer bytes/u,
    },
    {
      name: "shared-memory",
      catalogBody: "return Buffer.from(new SharedArrayBuffer(1));",
      expected: /must return 1\.\.262144 non-shared Buffer bytes/u,
    },
    {
      name: "empty",
      catalogBody: "return Buffer.alloc(0);",
      expected: /must return 1\.\.262144 non-shared Buffer bytes/u,
    },
    {
      name: "oversized",
      catalogBody: "return Buffer.alloc(256 * 1024 + 1);",
      expected: /must return 1\.\.262144 non-shared Buffer bytes/u,
    },
    {
      name: "validator-rejection",
      validatorBody: "return 8;",
      expected: /must accept the published catalog with status 0, found 8/u,
    },
    {
      name: "boolean-validator-result",
      validatorBody: "return false;",
      expected: /must accept the published catalog with status 0, found false/u,
    },
    {
      name: "catalog-exception",
      catalogBody: 'throw new Error("hostile detail");',
      expected: /invalid native privacy compiled-profile catalog contract: hostile detail/u,
    },
    {
      name: "validator-exception",
      validatorBody: 'throw new Error("hostile detail");',
      expected: /invalid native privacy compiled-profile catalog contract: hostile detail/u,
    },
  ];

  for (const { name, expected, ...options } of hostileFixtures) {
    const fixture = path.join(root, `${name}.cjs`);
    writeFileSync(fixture, nativeProbeFixtureSource(options));
    assert.throws(() => probeNativeBindingExports(fixture), expected, name);
  }
});

test("native publication rejects dirty or stale source provenance", async (t) => {
  const layout = createLayout(t);
  writeFileSync(layout.source, Buffer.from("native source provenance fixture"));

  await assert.rejects(
    publishNativeBinding(
      publicationOptions(layout, {
        readBuildProvenance(source) {
          return {
            ...fixtureBuildProvenance(source),
            source_tree_clean: false,
          };
        },
      }),
    ),
    /requires build provenance and current source to be clean/u,
  );
  await assert.rejects(
    publishNativeBinding(
      publicationOptions(layout, {
        readSourceState() {
          return {
            sourceGitRevision: "b".repeat(40),
            sourceTreeClean: true,
          };
        },
      }),
    ),
    /does not match the current source revision/u,
  );
  assert.equal(existsSync(layout.bindingPath), false);
  assert.equal(existsSync(layout.manifestPath), false);
});

test(
  "required-export probe loads a real addon through the recovery-compatible private suffix",
  (t) => {
    // Authenticate the selected original artifact through the canonical loader.
    const binding = getNativeBinding();
    assert.equal(typeof binding.noritoEncodeInstruction, "function");
    const nativePath = process.env.IROHA_JS_NATIVE_DIR
      ? path.resolve(process.env.IROHA_JS_NATIVE_DIR, NATIVE_FILENAME)
      : fileURLToPath(new URL(`../native/${NATIVE_FILENAME}`, import.meta.url));
    assert.equal(
      existsSync(nativePath),
      true,
      `the selected authenticated native addon must exist at ${nativePath}`,
    );
    const root = mkdtempSync(path.join(os.tmpdir(), "iroha-js-native-dlopen-probe-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const staged = path.join(root, `${NATIVE_FILENAME}.next`);
    copyFileSync(nativePath, staged);
    // Authentication above binds the current artifact. This probe separately
    // exercises dlopen through the publication-recovery private suffix.
    assert.doesNotThrow(() =>
      probeNativeBindingExports(staged, ["noritoEncodeInstruction"]),
    );
  },
);
