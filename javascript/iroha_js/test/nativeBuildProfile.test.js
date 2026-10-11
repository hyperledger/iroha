import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs, {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import {
  cargoBuildArgsForNativeProfile,
  NATIVE_BUILD_PROFILE_ENV,
  resolveNativeBuildProfile,
} from "../scripts/native-build-profile.mjs";
import {
  nativeBuildOutputPath as completedBuildOutputPath,
  nativeBuildNamespace,
  runNativeBuild as actualRunNativeBuild,
  verifyCargoDependencyArtifacts,
} from "../scripts/build-native.mjs";
import { publishNativeBinding } from "../scripts/copy-native.mjs";
import {
  nativeBuildProvenancePath,
  readNativeBuildProvenance,
  writeNativeBuildProvenance,
} from "../scripts/native-build-provenance.mjs";
import { nativeSourceProvenanceMatches } from "../src/native.js";

const FIXTURE_ATTEMPT_ID = "00000000-0000-4000-8000-000000000001";
function nativeBuildOutputPath(options) {
  return path.join(nativeBuildNamespace(options), FIXTURE_ATTEMPT_ID, options.cargoProfile,
    options.platform === "darwin" ? "libiroha_js_host.dylib" : "libiroha_js_host.so");
}
function runNativeBuild(options) {
  return actualRunNativeBuild({ newAttemptId: () => FIXTURE_ATTEMPT_ID, ...options });
}

const SOURCE_DIGEST = "b".repeat(64);
const SOURCE_REVISION = "a".repeat(40);

function sourceState(overrides = {}) {
  return {
    sourceGitRevision: SOURCE_REVISION,
    sourceTreeClean: false,
    sourceTreeSha256: SOURCE_DIGEST,
    ...overrides,
  };
}

function cargoArtifactProfile(cargoProfile) {
  const optimized = cargoProfile === "release" || cargoProfile === "deploy";
  return {
    opt_level: optimized ? "3" : "0",
    debuginfo: 0,
    debug_assertions: !optimized,
    overflow_checks: !optimized,
    test: false,
  };
}

function createFixture(t, { profile = "debug", toolchainDirectory = "rust-1.93.1" } = {}) {
  const repoRoot = realpathSync(
    mkdtempSync(path.join(os.tmpdir(), "iroha-js-live-root-")),
  );
  const targetRoot = realpathSync(
    mkdtempSync(path.join(os.tmpdir(), "iroha-js-live-target-")),
  );
  const toolchainsRoot = realpathSync(
    mkdtempSync(path.join(os.tmpdir(), "iroha-js-toolchains-")),
  );
  t.after(() => {
    rmSync(repoRoot, { recursive: true, force: true });
    rmSync(targetRoot, { recursive: true, force: true });
    rmSync(toolchainsRoot, { recursive: true, force: true });
  });

  const packageRoot = path.join(repoRoot, "crates", "iroha_js_host");
  const sourcePath = path.join(packageRoot, "src", "lib.rs");
  mkdirSync(path.dirname(sourcePath), { recursive: true });
  writeFileSync(
    path.join(repoRoot, "Cargo.toml"),
    [
      "[workspace]",
      "members = [\"crates/iroha_js_host\"]",
      "",
      "[workspace.package]",
      "version = \"0.0.0\"",
      "",
    ].join("\n"),
  );
  writeFileSync(path.join(repoRoot, "Cargo.lock"), "version = 4\n");
  writeFileSync(
    path.join(repoRoot, "rust-toolchain.toml"),
    "[toolchain]\nchannel = \"1.93.1\"\n",
  );
  writeFileSync(
    path.join(packageRoot, "Cargo.toml"),
    [
      "[package]",
      "name = \"iroha_js_host\"",
      "version.workspace = true",
      "",
      "[lib]",
      "crate-type = [\"cdylib\"]",
      "",
    ].join("\n"),
  );
  writeFileSync(sourcePath, "pub fn fixture() {}\n");

  const binDirectory = path.join(
    toolchainsRoot,
    toolchainDirectory,
    "bin",
  );
  mkdirSync(binDirectory, { recursive: true });
  const cargoPath = path.join(binDirectory, "cargo");
  const rustcPath = path.join(binDirectory, "rustc");
  const rustdocPath = path.join(binDirectory, "rustdoc");
  for (const executable of [cargoPath, rustcPath, rustdocPath]) {
    writeFileSync(executable, "#!/bin/sh\nexit 99\n");
    chmodSync(executable, 0o700);
  }

  const runTool = (executable, args, options) => {
    assert.equal(options.cwd, repoRoot);
    assert.equal(options.timeout, 15_000);
    assert.equal(options.maxBuffer, 64 * 1024);
    assert.deepEqual(options.stdio, ["ignore", "pipe", "pipe"]);
    const responses = new Map([
      [cargoPath + " --version", "cargo 1.93.1 (fixture 2026-01-01)\n"],
      [rustcPath + " -vV", "rustc 1.93.1 (fixture 2026-01-01)\nrelease: 1.93.1\n"],
      [rustdocPath + " --version", "rustdoc 1.93.1 (fixture 2026-01-01)\n"],
      [rustcPath + " --print sysroot", path.dirname(binDirectory) + "\n"],
    ]);
    const key = executable + " " + args.join(" ");
    assert.ok(responses.has(key), "unexpected toolchain probe: " + key);
    return { status: 0, signal: null, stdout: responses.get(key) };
  };

  const env = {
    CARGO_BUILD_JOBS: "1",
    CARGO_INCREMENTAL: "0",
    CARGO_NET_OFFLINE: "true",
    CARGO_TARGET_DIR: targetRoot,
    IROHA_JS_CARGO_LOCKFILE_PATH: path.join(repoRoot, "Cargo.lock"),
    IROHA_JS_CARGO_PATH: cargoPath,
    RUSTC: rustcPath,
    RUSTDOC: rustdocPath,
    ...(profile === "debug"
      ? {}
      : { [NATIVE_BUILD_PROFILE_ENV]: profile }),
  };
  const nativePath = nativeBuildOutputPath({
    repoRoot,
    sourceState: sourceState(),
    cargoProfile: profile,
    env,
    platform: "linux",
  });
  return {
    cargoPath,
    env,
    runTool,
    nativePath,
    packageRoot,
    profile,
    repoRoot,
    sourcePath,
    targetRoot,
  };
}

function intendedCargoArtifact(fixture, overrides = {}) {
  const artifact = {
    reason: "compiler-artifact",
    package_id:
      "path+" +
      pathToFileURL(fixture.packageRoot).href +
      "#0.0.0",
    manifest_path: path.join(fixture.packageRoot, "Cargo.toml"),
    target: {
      crate_types: ["cdylib"],
      kind: ["cdylib"],
      name: "iroha_js_host",
      src_path: fixture.sourcePath,
    },
    executable: null,
    features: [],
    filenames: [fixture.nativePath],
    fresh: false,
    profile: cargoArtifactProfile(fixture.profile),
  };
  return {
    ...artifact,
    ...overrides,
    target:
      overrides.target === undefined
        ? artifact.target
        : { ...artifact.target, ...overrides.target },
  };
}

function cargoJson(...messages) {
  return (
    messages.map((message) => JSON.stringify(message)).join("\n") + "\n"
  );
}

function successfulCargoJson(fixture, overrides = {}) {
  return cargoJson(
    intendedCargoArtifact(fixture, overrides),
    { reason: "build-finished", success: true },
  );
}

function writeNativeOutput(fixture, bytes = "native-output") {
  mkdirSync(path.dirname(fixture.nativePath), { recursive: true });
  writeFileSync(fixture.nativePath, bytes);
}

function sha256File(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

test("native profiles map to one explicit Cargo profile contract", () => {
  assert.equal(resolveNativeBuildProfile({}), "debug");
  assert.deepEqual(cargoBuildArgsForNativeProfile("debug"), []);
  assert.deepEqual(cargoBuildArgsForNativeProfile("release"), ["--release"]);
  assert.deepEqual(
    cargoBuildArgsForNativeProfile("deploy"),
    ["--profile", "deploy"],
  );
  for (const invalid of ["", "dev", "production", "DEBUG"]) {
    assert.throws(
      () =>
        resolveNativeBuildProfile({
          [NATIVE_BUILD_PROFILE_ENV]: invalid,
        }),
      /must be exactly/u,
    );
  }
});

test("native output requires the caller-provided absolute Cargo target", () => {
  assert.throws(
    () =>
      nativeBuildOutputPath({
        cargoProfile: "debug",
        env: {},
        platform: "linux",
      }),
    /requires CARGO_TARGET_DIR/u,
  );
  assert.throws(
    () =>
      nativeBuildOutputPath({
        cargoProfile: "debug",
        env: { CARGO_TARGET_DIR: "relative-target" },
        platform: "linux",
      }),
    /absolute canonical path/u,
  );
});

test("native build admits standalone and rustup layouts by actual pinned versions and sysroot", (t) => {
  for (const toolchainDirectory of ["rust-1.93.1", "1.93.1-x86_64-unknown-linux-gnu"]) {
    const fixture = createFixture(t, { toolchainDirectory });
    const probes = [];
    const status = runNativeBuild({
      repoRoot: fixture.repoRoot,
      env: fixture.env,
      platform: "linux",
      runTool(executable, args, options) {
        probes.push([path.basename(executable), args]);
        return fixture.runTool(executable, args, options);
      },
      readSourceState: () => sourceState(),
      runCargo: () => ({ status: 7, stdout: "" }),
    });
    assert.equal(status, 7);
    assert.deepEqual(probes, [
      ["rustc", ["-vV"]],
      ["cargo", ["--version"]],
      ["rustdoc", ["--version"]],
      ["rustc", ["--print", "sysroot"]],
    ]);
  }
});

test("native build rejects unpinned, mixed, or unverifiable toolchains before Cargo", async (t) => {
  const cases = [
    { executable: "rustc", args: "-vV", stdout: "rustc 1.93.1 (fixture)\nrelease: 1.94.0\n", message: /rustc must report exactly release/u },
    { executable: "rustc", args: "-vV", stdout: "rustc 1.93.1 (fixture)\nrelease: 1.93.1\nrelease: 1.93.1\n", message: /rustc must report exactly release/u },
    { executable: "cargo", args: "--version", stdout: "cargo 1.94.0 (fixture)\n", message: /cargo must report exactly version/u },
    { executable: "rustdoc", args: "--version", stdout: "rustdoc 1.93.1-nightly (fixture)\n", message: /rustdoc must report exactly version/u },
    { executable: "cargo", args: "--version", stdout: "rustdoc 1.93.1 (fixture)\n", message: /cargo must report exactly version/u },
    { executable: "rustc", args: "--print sysroot", stdout: "relative/sysroot\n", message: /sysroot must be an absolute canonical path/u },
    { executable: "rustc", args: "--print sysroot", foreignSysroot: true, message: /bin directory of rustc's reported sysroot/u },
    { executable: "rustc", args: "-vV", result: { status: 9, stdout: "" }, message: /could not verify rustc -vV/u },
    { executable: "cargo", args: "--version", result: { error: Object.assign(new Error("timeout"), { code: "ETIMEDOUT" }), status: null, stdout: "" }, message: /could not verify cargo --version/u },
  ];
  for (const [index, entry] of cases.entries()) {
    await t.test(String(index) + ": " + entry.message, () => {
      const fixture = createFixture(t);
      assert.throws(() => runNativeBuild({
        repoRoot: fixture.repoRoot,
        env: fixture.env,
        platform: "linux",
        runTool(executable, args, options) {
          if (path.basename(executable) === entry.executable && args.join(" ") === entry.args) {
            return entry.result ?? { status: 0, signal: null, stdout: entry.foreignSysroot ? fixture.repoRoot : entry.stdout };
          }
          return fixture.runTool(executable, args, options);
        },
        readSourceState: () => sourceState(),
        runCargo() { throw new Error("Cargo must not run"); },
      }), entry.message);
    });
  }
  const fixture = createFixture(t);
  const otherBin = path.join(fixture.repoRoot, "other-bin");
  mkdirSync(otherBin);
  const otherRustdoc = path.join(otherBin, "rustdoc");
  writeFileSync(otherRustdoc, "fixture");
  chmodSync(otherRustdoc, 0o700);
  assert.throws(() => runNativeBuild({
    repoRoot: fixture.repoRoot,
    env: { ...fixture.env, RUSTDOC: otherRustdoc },
    runTool() { throw new Error("mixed toolchain must fail before probes"); },
    runCargo() { throw new Error("Cargo must not run"); },
  }), /must come from one pinned toolchain/u);
});

test("native build uses stock Cargo with exact live root manifest, root lock, and source target", (t) => {
  const fixture = createFixture(t);
  const state = sourceState();
  let invalidated;
  let written;
  let sourceReads = 0;
  const status = runNativeBuild({
    runTool: fixture.runTool,
    repoRoot: fixture.repoRoot,
    env: fixture.env,
    platform: "linux",
    readSourceState(root, options) {
      assert.equal(root, fixture.repoRoot);
      assert.equal(options.env, fixture.env);
      sourceReads += 1;
      return state;
    },
    invalidateProvenance(nativePath) {
      invalidated = nativePath;
    },
    runCargo(cargoPath, args, options) {
      assert.equal(cargoPath, fixture.cargoPath);
      assert.equal(options.cwd, fixture.repoRoot);
      assert.equal(
        options.cargoEnv.CARGO_TARGET_DIR,
        path.dirname(path.dirname(fixture.nativePath)),
      );
      assert.equal(options.cargoEnv.CARGO, fixture.cargoPath);
      assert.equal(options.cargoEnv.RUSTC, fixture.env.RUSTC);
      assert.equal(options.cargoEnv.RUSTDOC, fixture.env.RUSTDOC);
      assert.equal(options.cargoEnv.RUSTC_BOOTSTRAP, undefined);
      assert.equal(options.cargoEnv.IROHA_JS_CARGO_LOCKFILE_PATH, path.join(fixture.repoRoot, "Cargo.lock"));
      assert.equal(
        options.cargoEnv.IROHA_GIT_COMMIT_HASH,
        SOURCE_REVISION,
      );
      assert.deepEqual(args, [
        "build",
        "--locked",
        "--offline",
        "--jobs",
        "1",
        "--manifest-path",
        path.join(fixture.repoRoot, "Cargo.toml"),
        "--package",
        "iroha_js_host",
        "--lib",
        "--target-dir",
        path.dirname(path.dirname(fixture.nativePath)),
        "--message-format=json-render-diagnostics",
      ]);
      writeNativeOutput(fixture, "authenticated-live-root-output");
      return {
        status: 0,
        stdout: successfulCargoJson(fixture),
      };
    },
    writeProvenance(nativePath, provenance) {
      written = { nativePath, provenance };
      writeNativeBuildProvenance(nativePath, provenance);
    },
  });
  assert.equal(status, 0);
  assert.equal(invalidated, fixture.nativePath);
  assert.equal(written.nativePath, fixture.nativePath);
  assert.equal(written.provenance.source_tree_clean, false);
  assert.equal(written.provenance.source_tree_sha256, SOURCE_DIGEST);
  assert.equal(
    written.provenance.native_sha256,
    sha256File(fixture.nativePath),
  );
  assert.equal(sourceReads, 3);
  assert.equal(
    readFileSync(fixture.nativePath, "utf8"),
    "authenticated-live-root-output",
  );
  assert.equal(
    existsSync(path.join(fixture.targetRoot, "cargo-target")),
    false,
  );
});

test("macOS native build seals SDK, deployment target, and Apple tools into Cargo fingerprints", {
  skip: process.platform !== "darwin",
}, (t) => {
  const fixture = createFixture(t);
  fixture.nativePath = nativeBuildOutputPath({
    repoRoot: fixture.repoRoot,
    sourceState: sourceState(),
    cargoProfile: "debug",
    env: fixture.env,
    platform: "darwin",
  });
  const clang = path.join(fixture.repoRoot, "apple-clang");
  const linker = path.join(fixture.repoRoot, "apple-ld");
  for (const executable of [clang, linker]) {
    writeFileSync(executable, "#!/bin/sh\nexit 99\n");
    chmodSync(executable, 0o700);
  }
  const runTool = (executable, args, options) => {
    if (executable === "/usr/bin/xcrun") {
      assert.equal(options.cwd, fixture.repoRoot);
      const name = args.join(" ");
      if (name === "--find clang") return { status: 0, stdout: clang };
      if (name === "--find ld") return { status: 0, stdout: linker };
      assert.fail(`unexpected xcrun probe: ${name}`);
    }
    if (executable === clang) {
      assert.deepEqual(args, ["--version"]);
      return { status: 0, stdout: "Apple clang version 21.0.0 (fixture)\n" };
    }
    if (executable === linker) {
      assert.deepEqual(args, ["-v"]);
      return {
        status: 0,
        stdout: "",
        stderr: "@(#)PROGRAM:ld PROJECT:ld-27037.1\n",
      };
    }
    return fixture.runTool(executable, args, options);
  };
  const run = (version) => {
    const sdkRoot = path.join(fixture.repoRoot, `MacOSX${version}.sdk`);
    mkdirSync(sdkRoot);
    writeFileSync(path.join(sdkRoot, "SDKSettings.json"),
      `${JSON.stringify({ Version: version })}\n`);
    const env = {
      ...fixture.env,
      SDKROOT: sdkRoot,
      MACOSX_DEPLOYMENT_TARGET: "11.0",
    };
    fixture.nativePath = nativeBuildOutputPath({ repoRoot: fixture.repoRoot, cargoProfile: "debug", env, platform: "darwin", sourceState: sourceState() });
    let rustflags;
    const result = runNativeBuild({
      repoRoot: fixture.repoRoot,
      env,
      platform: "darwin",
      runTool,
      readSourceState: () => sourceState(),
      runCargo(_cargo, args, { cargoEnv }) {
        assert.equal(args[0], "rustc");
        assert.deepEqual(args.slice(-3), ["--", "-C", "strip=none"]);
        assert.equal(cargoEnv.SDKROOT, sdkRoot);
        rustflags = cargoEnv.RUSTFLAGS;
        assert.ok(!rustflags.includes("strip="), "do not change dependency stripping");
        writeNativeOutput(fixture, `macos-sdk-${version}`);
        return { status: 0, stdout: successfulCargoJson(fixture) };
      },
    });
    assert.equal(result, 0);
    const provenance = readNativeBuildProvenance(fixture.nativePath);
    assert.equal(provenance.version, 4);
    assert.equal(provenance.macos_build.sdk_root, sdkRoot);
    assert.equal(provenance.macos_build.sdk_version, version);
    assert.equal(provenance.macos_build.deployment_target, "11.0");
    assert.match(provenance.macos_build.sdk_settings_sha256, /^[0-9a-f]{64}$/u);
    return rustflags;
  };
  const firstFlags = run("26.5");
  const secondFlags = run("27.0");
  assert.match(firstFlags, /-Cmetadata=iroha_js_macos_[0-9a-f]{64}/u);
  assert.notEqual(secondFlags, firstFlags);
  const lastSdkRoot = path.join(fixture.repoRoot, "MacOSX27.0.sdk");
  assert.throws(() => runNativeBuild({
    repoRoot: fixture.repoRoot,
    env: {
      ...fixture.env,
      SDKROOT: lastSdkRoot,
      MACOSX_DEPLOYMENT_TARGET: "11.0",
    },
    platform: "darwin",
    runTool,
    readSourceState: () => sourceState(),
    runCargo() {
      writeNativeOutput(fixture, "sdk-changed-during-cargo");
      writeFileSync(path.join(lastSdkRoot, "SDKSettings.json"),
        `${JSON.stringify({ Version: "27.1" })}\n`);
      return { status: 0, stdout: successfulCargoJson(fixture) };
    },
  }), /SDK or Apple toolchain changed while Cargo was running/u);
  assert.equal(existsSync(nativeBuildProvenancePath(fixture.nativePath)), false);
  assert.throws(() => runNativeBuild({
    repoRoot: fixture.repoRoot,
    env: { ...fixture.env, SDKROOT: lastSdkRoot },
    platform: "darwin",
    runTool,
    runCargo() { assert.fail("missing deployment target must fail before Cargo"); },
  }), /explicit MACOSX_DEPLOYMENT_TARGET/u);
});

test("a fresh Cargo artifact is authenticated without forcing a rebuild", (t) => {
  const fixture = createFixture(t);
  assert.equal(buildFixture(fixture, {
    runCargo() {
      writeNativeOutput(fixture, "already-current-output");
      return { status: 0, stdout: successfulCargoJson(fixture) };
    },
  }), 0);
  const originalInode = lstatSync(fixture.nativePath, {
    bigint: true,
  }).ino;
  let written = 0;
  assert.equal(
    runNativeBuild({
    runTool: fixture.runTool,
      repoRoot: fixture.repoRoot,
      env: fixture.env,
      platform: "linux",
      readSourceState: () => sourceState(),
      invalidateProvenance() {},
      runCargo() {
        return {
          status: 0,
          stdout: successfulCargoJson(fixture, { fresh: true }),
        };
      },
      writeProvenance(nativePath, provenance) {
        written += 1;
        writeNativeBuildProvenance(nativePath, provenance);
      },
    }),
    0,
  );
  assert.equal(written, 1);
  assert.equal(
    readFileSync(fixture.nativePath, "utf8"),
    "already-current-output",
  );
  assert.notEqual(
    lstatSync(fixture.nativePath, { bigint: true }).ino,
    originalInode,
  );
});

test("a non-fresh Cargo artifact must update an existing output", (t) => {
  const fixture = createFixture(t);
  writeNativeOutput(fixture, "stale-output");
  let writes = 0;
  assert.throws(
    () =>
      runNativeBuild({
    runTool: fixture.runTool,
        repoRoot: fixture.repoRoot,
        env: fixture.env,
        platform: "linux",
        readSourceState: () => sourceState(),
        invalidateProvenance() {},
        runCargo() {
          return {
            status: 0,
            stdout: successfulCargoJson(fixture),
          };
        },
        writeProvenance() {
          writes += 1;
        },
      }),
    /non-fresh Cargo artifact did not update/u,
  );
  assert.equal(writes, 0);
});

test("Cargo hardlink uplift is replaced by one authenticated output link", (t) => {
  const fixture = createFixture(t);
  const dependencyOutput = path.join(
    fixture.targetRoot,
    "debug",
    "deps",
    "libiroha_js_host-fixture.so",
  );
  assert.equal(
    runNativeBuild({
    runTool: fixture.runTool,
      repoRoot: fixture.repoRoot,
      env: fixture.env,
      platform: "linux",
      readSourceState: () => sourceState(),
      invalidateProvenance() {},
      runCargo() {
        mkdirSync(path.dirname(dependencyOutput), { recursive: true });
        writeFileSync(dependencyOutput, "hardlinked-output");
        linkSync(dependencyOutput, fixture.nativePath);
        assert.equal(
          lstatSync(fixture.nativePath, { bigint: true }).nlink,
          2n,
        );
        return {
          status: 0,
          stdout: successfulCargoJson(fixture),
        };
      },
      writeProvenance: writeNativeBuildProvenance,
    }),
    0,
  );
  assert.equal(
    lstatSync(fixture.nativePath, { bigint: true }).nlink,
    1n,
  );
  assert.equal(
    lstatSync(dependencyOutput, { bigint: true }).nlink,
    1n,
  );
  assert.equal(readFileSync(fixture.nativePath, "utf8"), "hardlinked-output");
});

test("Cargo JSON must identify the exact live-root cdylib", (t) => {
  const fixture = createFixture(t);
  let writes = 0;
  assert.throws(
    () =>
      runNativeBuild({
    runTool: fixture.runTool,
        repoRoot: fixture.repoRoot,
        env: fixture.env,
        platform: "linux",
        readSourceState: () => sourceState(),
        invalidateProvenance() {},
        runCargo() {
          writeNativeOutput(fixture);
          return {
            status: 0,
            stdout: successfulCargoJson(fixture, {
              package_id:
                "registry+https://example.invalid/index#iroha_js_host@0.0.0",
            }),
          };
        },
        writeProvenance() {
          writes += 1;
        },
      }),
    /invalid iroha_js_host cdylib/u,
  );
  assert.equal(writes, 0);
});

test("source drift after Cargo prevents provenance publication", (t) => {
  const fixture = createFixture(t);
  const before = sourceState();
  const after = sourceState({ sourceTreeSha256: "c".repeat(64) });
  let reads = 0;
  let writes = 0;
  assert.throws(
    () =>
      runNativeBuild({
    runTool: fixture.runTool,
        repoRoot: fixture.repoRoot,
        env: fixture.env,
        platform: "linux",
        readSourceState() {
          reads += 1;
          return reads === 1 ? before : after;
        },
        invalidateProvenance() {},
        runCargo() {
          writeNativeOutput(fixture);
          return {
            status: 0,
            stdout: successfulCargoJson(fixture),
          };
        },
        writeProvenance() {
          writes += 1;
        },
      }),
    /source tree changed while Cargo was running/u,
  );
  assert.equal(writes, 0);
});

for (const profile of ["release", "deploy"]) {
  test(profile + " native build rejects a dirty source before Cargo", (t) => {
    const fixture = createFixture(t, { profile });
    let cargoRuns = 0;
    assert.throws(
      () =>
        runNativeBuild({
    runTool: fixture.runTool,
          repoRoot: fixture.repoRoot,
          env: fixture.env,
          platform: "linux",
          readSourceState: () => sourceState(),
          runCargo() {
            cargoRuns += 1;
            return { status: 7, stdout: "" };
          },
        }),
      /require an exactly clean source tree/u,
    );
    assert.equal(cargoRuns, 0);
  });
}

test("the live build rejects incomplete or redirected build envelopes", async (t) => {
  const fixture = createFixture(t);
  const cases = [
    {
      label: /requires CARGO_INCREMENTAL=0/u,
      mutate(env) {
        delete env.CARGO_INCREMENTAL;
      },
    },
    {
      label: /IROHA_JS_CARGO_PATH must be an absolute canonical path/u,
      mutate(env) {
        env.IROHA_JS_CARGO_PATH = "cargo";
      },
    },
    {
      label: /requires CARGO_TARGET_DIR to be an absolute canonical path/u,
      mutate(env) {
        env.CARGO_TARGET_DIR = "target";
      },
    },
    {
      label: /Cargo.lock must be the authenticated repository root Cargo.lock/u,
      mutate(env) {
        const nested = path.join(fixture.repoRoot, "private-lock");
        mkdirSync(nested);
        env.IROHA_JS_CARGO_LOCKFILE_PATH = path.join(nested, "Cargo.lock");
        writeFileSync(env.IROHA_JS_CARGO_LOCKFILE_PATH, "version = 4\n");
      },
    },
    {
      label: /forbids Cargo profile environment override/u,
      mutate(env) {
        env.CARGO_PROFILE_DEV_DEBUG = "0";
      },
    },
  ];
  for (const entry of cases) {
    await t.test(String(entry.label), () => {
      const env = { ...fixture.env };
      entry.mutate(env);
      assert.throws(
        () =>
          runNativeBuild({
    runTool: fixture.runTool,
            repoRoot: fixture.repoRoot,
            env,
            platform: "linux",
            readSourceState: () => sourceState(),
            runCargo() {
              throw new Error("Cargo must not run");
            },
          }),
        entry.label,
      );
    });
  }
});

test("the live build rejects a byte-identical foreign Cargo.lock before Cargo", (t) => {
  const fixture = createFixture(t);
  const lockDirectory = realpathSync(
    mkdtempSync(path.join(os.tmpdir(), "iroha-js-release-lock-")),
  );
  t.after(() => rmSync(lockDirectory, { recursive: true, force: true }));
  const externalLock = path.join(lockDirectory, "Cargo.lock");
  fs.copyFileSync(path.join(fixture.repoRoot, "Cargo.lock"), externalLock);
  assert.deepEqual(readFileSync(externalLock), readFileSync(path.join(fixture.repoRoot, "Cargo.lock")));
  assert.throws(() => runNativeBuild({
    runTool: fixture.runTool,
    repoRoot: fixture.repoRoot,
    env: { ...fixture.env, IROHA_JS_CARGO_LOCKFILE_PATH: externalLock },
    platform: "linux",
    readSourceState: () => sourceState(),
    runCargo() { assert.fail("foreign lock must fail before Cargo"); },
  }), /Cargo.lock must be the authenticated repository root Cargo.lock/u);
});

for (const bootstrap of ["1", "0", "-1", "iroha_js_host"]) {
  test("native build rejects RUSTC_BOOTSTRAP=" + bootstrap + " before any compiler probe", (t) => {
    const fixture = createFixture(t);
    assert.throws(() => runNativeBuild({
      repoRoot: fixture.repoRoot,
      env: { ...fixture.env, RUSTC_BOOTSTRAP: bootstrap },
      platform: "linux",
      runTool() { assert.fail("bootstrap must fail before compiler probes"); },
      runCargo() { assert.fail("bootstrap must fail before Cargo"); },
    }), /forbids RUSTC_BOOTSTRAP/u);
  });
}

test("failed Cargo leaves the output unauthenticated", (t) => {
  const fixture = createFixture(t);
  let invalidations = 0;
  let writes = 0;
  const status = runNativeBuild({
    runTool: fixture.runTool,
    repoRoot: fixture.repoRoot,
    env: fixture.env,
    platform: "linux",
    readSourceState: () => sourceState(),
    invalidateProvenance() {
      invalidations += 1;
    },
    runCargo() {
      return { status: 7, stdout: "" };
    },
    writeProvenance() {
      writes += 1;
    },
  });
  assert.equal(status, 7);
  assert.equal(invalidations, 1);
  assert.equal(writes, 0);
});

function buildProvenance(source, cargoProfile, state) {
  return {
    version: 4,
    build_execution_policy: "trusted-local-cargo-v1",
    cargo_profile: cargoProfile,
    native_sha256: sha256File(source),
    source_git_revision: state.sourceGitRevision,
    source_tree_clean: state.sourceTreeClean,
    source_tree_sha256: state.sourceTreeSha256,
  };
}

function publicationVerifier(file) {
  return {
    ok: true,
    sha256: sha256File(file),
  };
}

test("debug publication accepts only the exact current dirty tree", async (t) => {
  const root = mkdtempSync(
    path.join(os.tmpdir(), "iroha-js-dirty-publication-"),
  );
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, "libiroha_js_host.so");
  const destDir = path.join(root, "native");
  const state = sourceState();
  writeFileSync(source, "dirty-tree-native");

  const result = await publishNativeBinding({
    source,
    destDir,
    platform: "linux",
    arch: "x64",
    cargoProfile: "debug",
    signNative() {},
    verifyBinding: publicationVerifier,
    probeBinding() {},
    readBuildProvenance: () => buildProvenance(source, "debug", state),
    readSourceState: () => state,
    log() {},
  });
  const manifest = JSON.parse(readFileSync(result.manifestPath, "utf8"));
  assert.equal(
    manifest.entries["linux-x64"].source_tree_clean,
    false,
  );
  assert.equal(
    manifest.entries["linux-x64"].source_tree_sha256,
    SOURCE_DIGEST,
  );
});

test("dirty publication rejects a different current tree hash", async (t) => {
  const root = mkdtempSync(
    path.join(os.tmpdir(), "iroha-js-dirty-mismatch-"),
  );
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, "libiroha_js_host.so");
  const destDir = path.join(root, "native");
  const built = sourceState();
  const current = sourceState({ sourceTreeSha256: "c".repeat(64) });
  writeFileSync(source, "dirty-tree-native");

  await assert.rejects(
    publishNativeBinding({
      source,
      destDir,
      platform: "linux",
      arch: "x64",
      cargoProfile: "debug",
      signNative() {},
      verifyBinding: publicationVerifier,
      probeBinding() {},
      readBuildProvenance: () =>
        buildProvenance(source, "debug", built),
      readSourceState: () => current,
      log() {},
    }),
    /does not match the exact dirty source tree/u,
  );
  assert.equal(existsSync(destDir), false);
});

test("release publication remains clean-only", async (t) => {
  const root = mkdtempSync(
    path.join(os.tmpdir(), "iroha-js-dirty-release-"),
  );
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, "libiroha_js_host.so");
  const state = sourceState();
  writeFileSync(source, "dirty-tree-native");

  await assert.rejects(
    publishNativeBinding({
      source,
      destDir: path.join(root, "native"),
      platform: "linux",
      arch: "x64",
      cargoProfile: "release",
      signNative() {},
      verifyBinding: publicationVerifier,
      probeBinding() {},
      readBuildProvenance: () =>
        buildProvenance(source, "release", state),
      readSourceState: () => state,
      log() {},
    }),
    /release publication requires build provenance and current source to be clean/u,
  );
});

test("native loading policy binds dirty debug artifacts to the exact tree", () => {
  const current = sourceState();
  const verification = {
    cargoProfile: "debug",
    sourceGitRevision: SOURCE_REVISION,
    sourceTreeClean: false,
    sourceTreeSha256: SOURCE_DIGEST,
  };
  assert.equal(
    nativeSourceProvenanceMatches(verification, current),
    true,
  );
  assert.equal(
    nativeSourceProvenanceMatches(
      verification,
      sourceState({ sourceTreeSha256: "c".repeat(64) }),
    ),
    false,
  );
  assert.equal(
    nativeSourceProvenanceMatches(
      { ...verification, cargoProfile: "release" },
      current,
    ),
    false,
  );
  assert.equal(
    nativeSourceProvenanceMatches(
      { ...verification, sourceTreeClean: true },
      undefined,
    ),
    true,
  );
});


// These tests inject only synchronous filesystem boundary observations and fake
// Cargo responses. They neither run the stub executables nor load native code.
const OUTPUT_FIELDS = ["ctimeNs", "dev", "ino", "mode", "mtimeNs", "nlink", "size"];

function withFilesystemOverrides(factory, action) {
  const originals = { ...fs };
  const overrides = factory(originals);
  Object.assign(fs, overrides);
  syncBuiltinESMExports();
  try {
    return action();
  } finally {
    for (const name of Object.keys(overrides)) fs[name] = originals[name];
    syncBuiltinESMExports();
  }
}

function changedStat(metadata, field) {
  return Object.assign(Object.create(Object.getPrototypeOf(metadata)), metadata, {
    [field]: metadata[field] + 1n,
  });
}

function buildFixture(fixture, overrides = {}) {
  return runNativeBuild({
    repoRoot: fixture.repoRoot,
    env: fixture.env,
    platform: "linux",
    runTool: fixture.runTool,
    readSourceState: () => sourceState(),
    runCargo() {
      writeNativeOutput(fixture);
      return { status: 0, stdout: successfulCargoJson(fixture) };
    },
    ...overrides,
  });
}

function assertArtifactRefusal(action, phase, comparison, changedFields) {
  let refusal;
  assert.throws(action, (error) => {
    refusal = error;
    assert.equal(error.code, "ERR_IROHA_NATIVE_ARTIFACT_CHANGED");
    assert.equal(error.artifactIdentity.phase, phase);
    const failed = error.artifactIdentity.failed_comparisons.find(
      (entry) => entry.comparison === comparison,
    );
    assert.ok(failed, JSON.stringify(error.artifactIdentity));
    if (changedFields !== undefined) assert.deepEqual(failed.changed_fields, changedFields);
    assert.ok(error.message.includes(JSON.stringify(error.artifactIdentity)));
    return true;
  });
  return refusal.artifactIdentity;
}

test("exact canonical ROOT/target is admitted as the generated cache", (t) => {
  const fixture = createFixture(t);
  fixture.targetRoot = path.join(fixture.repoRoot, "target");
  fixture.env.CARGO_TARGET_DIR = fixture.targetRoot;
  fixture.nativePath = nativeBuildOutputPath({ repoRoot: fixture.repoRoot, sourceState: sourceState(), cargoProfile: fixture.profile, env: fixture.env, platform: "linux" });
  assert.equal(buildFixture(fixture, {
    runCargo(_cargo, args, { cargoEnv }) {
      assert.equal(args[args.indexOf("--target-dir") + 1], path.dirname(path.dirname(fixture.nativePath)));
      assert.equal(cargoEnv.CARGO_TARGET_DIR, path.dirname(path.dirname(fixture.nativePath)));
      writeNativeOutput(fixture);
      return { status: 0, stdout: successfulCargoJson(fixture) };
    },
  }), 0);
});

test("canonical qualification child builds the original manifest and lock", (t) => {
  const fixture = createFixture(t);
  fixture.targetRoot = path.join(fixture.repoRoot, "target", "qualification", "native-consumer");
  fixture.env.CARGO_TARGET_DIR = fixture.targetRoot;
  fixture.nativePath = nativeBuildOutputPath({ repoRoot: fixture.repoRoot, sourceState: sourceState(), cargoProfile: fixture.profile, env: fixture.env, platform: "linux" });
  assert.equal(buildFixture(fixture, {
    runCargo(_cargo, args, { cargoEnv }) {
      assert.equal(args[args.indexOf("--manifest-path") + 1], path.join(fixture.repoRoot, "Cargo.toml"));
      assert.equal(cargoEnv.IROHA_JS_CARGO_LOCKFILE_PATH, path.join(fixture.repoRoot, "Cargo.lock"));
      assert.equal(cargoEnv.CARGO_TARGET_DIR, path.dirname(path.dirname(fixture.nativePath)));
      assert.ok(cargoEnv.CARGO_TARGET_DIR.startsWith(fixture.targetRoot + path.sep));
      writeNativeOutput(fixture);
      return { status: 0, stdout: successfulCargoJson(fixture) };
    },
  }), 0);
});

for (const relative of ["target/qualification", "target/qualification-other/lane", "crates/native-target"]) {
  test("qualification path exception rejects " + relative, (t) => {
    const fixture = createFixture(t);
    fixture.env.CARGO_TARGET_DIR = path.join(fixture.repoRoot, relative);
    assert.throws(() => buildFixture(fixture, {
      runCargo() { assert.fail("unadmitted source descendants must fail before Cargo"); },
    }), /must not contain or be contained by the build source/u);
  });
}

test("privacy native build uses the original root lock and a disjoint target with stock Cargo", (t) => {
  const fixture = createFixture(t);
  const corridor = realpathSync(
    mkdtempSync(path.join(os.tmpdir(), "iroha-js-privacy-build-")),
  );
  t.after(() => rmSync(corridor, { recursive: true, force: true }));
  fixture.targetRoot = path.join(corridor, "js-native", "target");
  fixture.env.CARGO_TARGET_DIR = fixture.targetRoot;
  fixture.env.IROHA_JS_CARGO_LOCKFILE_PATH = path.join(fixture.repoRoot, "Cargo.lock");
  fixture.nativePath = nativeBuildOutputPath({
    repoRoot: fixture.repoRoot,
    sourceState: sourceState(),
    cargoProfile: fixture.profile,
    env: fixture.env,
    platform: "linux",
  });
  assert.equal(buildFixture(fixture, {
    runCargo(_cargo, args, { cargoEnv }) {
      assert.equal(args.includes("-Z"), false);
      assert.equal(args.includes("--lockfile-path"), false);
      assert.equal(args.includes("--locked"), true);
      assert.deepEqual(
        args.slice(args.indexOf("--manifest-path"), args.indexOf("--manifest-path") + 2),
        ["--manifest-path", path.join(fixture.repoRoot, "Cargo.toml")],
      );
      assert.equal(cargoEnv.IROHA_JS_CARGO_LOCKFILE_PATH, path.join(fixture.repoRoot, "Cargo.lock"));
      assert.equal(cargoEnv.CARGO_TARGET_DIR, path.dirname(path.dirname(fixture.nativePath)));
      writeNativeOutput(fixture);
      return { status: 0, stdout: successfulCargoJson(fixture) };
    },
  }), 0);
});

test("privacy native build rejects an ignored source-tree lock before Cargo", (t) => {
  const fixture = createFixture(t);
  const lock = path.join(
    fixture.repoRoot, "target", "privacy-sdk-cargo", "lock", "Cargo.lock",
  );
  mkdirSync(path.dirname(lock), { recursive: true });
  fs.copyFileSync(path.join(fixture.repoRoot, "Cargo.lock"), lock);
  assert.throws(() => buildFixture(fixture, {
    env: { ...fixture.env, IROHA_JS_CARGO_LOCKFILE_PATH: lock },
    runCargo() { assert.fail("source-tree lock must fail before Cargo"); },
  }), /Cargo.lock must be the authenticated repository root Cargo.lock/u);
});

for (const location of ["root", "ancestor", "source-subdirectory", "target-descendant"]) {
  test("Cargo target rejects " + location + " before creating it or running Cargo", (t) => {
    const fixture = createFixture(t);
    const target = {
      root: fixture.repoRoot,
      ancestor: path.dirname(fixture.repoRoot),
      "source-subdirectory": path.join(fixture.repoRoot, "generated-elsewhere"),
      "target-descendant": path.join(fixture.repoRoot, "target", "nested"),
    }[location];
    const existed = existsSync(target);
    assert.throws(() => buildFixture(fixture, {
      env: { ...fixture.env, CARGO_TARGET_DIR: target },
      runCargo() { assert.fail("rejected targets must not run Cargo"); },
    }), /must not contain or be contained by the build source/u);
    assert.equal(existsSync(target), existed);
  });
}

for (const location of ["canonical-target", "external-target", "external-ancestor"]) {
  test("Cargo target rejects symlink " + location, (t) => {
    const fixture = createFixture(t);
    let target;
    if (location === "canonical-target") {
      target = path.join(fixture.repoRoot, "target");
      fs.symlinkSync(fixture.targetRoot, target);
    } else {
      const alias = path.join(path.dirname(fixture.cargoPath), "target-alias");
      fs.symlinkSync(fixture.targetRoot, alias);
      target = location === "external-ancestor" ? path.join(alias, "nested") : alias;
    }
    assert.throws(() => buildFixture(fixture, {
      env: { ...fixture.env, CARGO_TARGET_DIR: target },
      runCargo() { assert.fail("symlink targets must not run Cargo"); },
    }), /non-symbolic-link directory|path must be canonical/u);
  });
}

for (const [boundary, phase, comparison] of [
  ["initial", "before-digest", "expected-to-before"],
  ["opened", "opened", "before-to-opened"],
  ["during", "after-digest", "before-to-opened-after"],
  ["path", "after-digest", "before-to-path-after"],
]) {
  for (const field of OUTPUT_FIELDS) {
    test("Cargo digest rejects " + field + " drift at " + boundary + " boundary", (t) => {
      const fixture = createFixture(t);
      let active = false;
      let nativeInode;
      let pathReads = 0;
      let descriptorReads = 0;
      let writes = 0;
      withFilesystemOverrides((original) => ({
        lstatSync(file, options) {
          const metadata = original.lstatSync(file, options);
          if (active && file === fixture.nativePath) {
            pathReads += 1;
            if ((boundary === "initial" && pathReads === 2) ||
                (boundary === "path" && pathReads === 3)) return changedStat(metadata, field);
          }
          return metadata;
        },
        fstatSync(descriptor, options) {
          const metadata = original.fstatSync(descriptor, options);
          if (active && metadata.ino === nativeInode) {
            descriptorReads += 1;
            if ((boundary === "opened" && descriptorReads === 1) ||
                (boundary === "during" && descriptorReads === 2)) return changedStat(metadata, field);
          }
          return metadata;
        },
      }), () => {
        const diagnostic = assertArtifactRefusal(() => buildFixture(fixture, {
          runCargo() {
            writeNativeOutput(fixture);
            nativeInode = lstatSync(fixture.nativePath, { bigint: true }).ino;
            active = true;
            return { status: 0, stdout: successfulCargoJson(fixture) };
          },
          writeProvenance() { writes += 1; },
        }), phase, comparison, [field]);
        assert.deepEqual(Object.keys(diagnostic.before), OUTPUT_FIELDS);
        if (boundary === "during" || boundary === "path") {
          assert.equal(diagnostic.bytes_read, diagnostic.expected_bytes);
          assert.ok(diagnostic.opened_before);
          assert.ok(diagnostic.opened_after);
          assert.ok(diagnostic.at_path);
        }
      });
      assert.equal(writes, 0);
    });
  }
}

test("Cargo digest names a short-read byte-count mismatch even with unchanged stat fields", (t) => {
  const fixture = createFixture(t);
  let nativeInode;
  withFilesystemOverrides((original) => ({
    readSync(descriptor, ...args) {
      if (original.fstatSync(descriptor, { bigint: true }).ino === nativeInode) return 0;
      return original.readSync(descriptor, ...args);
    },
  }), () => {
    const diagnostic = assertArtifactRefusal(() => buildFixture(fixture, {
      runCargo() {
        writeNativeOutput(fixture);
        nativeInode = lstatSync(fixture.nativePath, { bigint: true }).ino;
        return { status: 0, stdout: successfulCargoJson(fixture) };
      },
    }), "after-digest", "byte-count");
    assert.equal(diagnostic.bytes_read, "0");
    assert.equal(diagnostic.expected_bytes, String(Buffer.byteLength("native-output")));
    assert.deepEqual(diagnostic.failed_comparisons.map((entry) => entry.comparison), ["byte-count"]);
  });
});

for (const directory of ["target", "profile"]) {
  test("directory identity is retained across Cargo for " + directory, (t) => {
    const fixture = createFixture(t);
    const target = directory === "target" ? fixture.targetRoot : path.dirname(fixture.nativePath);
    const retired = target + "-retired";
    t.after(() => rmSync(retired, { recursive: true, force: true }));
    assert.throws(() => buildFixture(fixture, {
      runCargo() {
        fs.renameSync(target, retired);
        mkdirSync(target);
        writeNativeOutput(fixture);
        return { status: 0, stdout: successfulCargoJson(fixture) };
      },
      writeProvenance() { assert.fail("replacement must not publish provenance"); },
    }), /Cargo (target|profile) directory changed identity/u);
  });
}

test("profile replacement during copy is refused without cleaning through the replacement", (t) => {
  const fixture = createFixture(t);
  const profile = path.dirname(fixture.nativePath);
  const retired = profile + "-retired";
  t.after(() => rmSync(retired, { recursive: true, force: true }));
  let foreignTemporary;
  withFilesystemOverrides((original) => ({
    copyFileSync(from, to, flags) {
      original.copyFileSync(from, to, flags);
      original.renameSync(profile, retired);
      original.mkdirSync(profile);
      foreignTemporary = to;
      original.writeFileSync(to, "foreign-directory-marker");
    },
  }), () => assert.throws(() => buildFixture(fixture), /profile directory changed identity/u));
  assert.equal(readFileSync(foreignTemporary, "utf8"), "foreign-directory-marker");
});

test("profile replacement during provenance publication is refused without invalidating foreign data", (t) => {
  const fixture = createFixture(t);
  const profile = path.dirname(fixture.nativePath);
  const retired = profile + "-retired";
  t.after(() => rmSync(retired, { recursive: true, force: true }));
  let invalidations = 0;
  assert.throws(() => buildFixture(fixture, {
    invalidateProvenance() { invalidations += 1; },
    writeProvenance() {
      fs.renameSync(profile, retired);
      mkdirSync(profile);
      writeFileSync(path.join(profile, "foreign-marker"), "preserve");
    },
  }), /profile directory changed identity/u);
  assert.equal(invalidations, 1);
  assert.equal(readFileSync(path.join(profile, "foreign-marker"), "utf8"), "preserve");
});

for (const changedCopy of ["source", "staged"]) {
  test("copy mismatch diagnostics include expected and actual digests for " + changedCopy, (t) => {
    const fixture = createFixture(t);
    let nativeInode;
    let copied = false;
    withFilesystemOverrides((original) => ({
      copyFileSync(from, to, flags) {
        original.copyFileSync(from, to, flags);
        copied = true;
        if (changedCopy === "staged") original.writeFileSync(to, "different-copy");
      },
      readSync(descriptor, buffer, offset, length, position) {
        const read = original.readSync(descriptor, buffer, offset, length, position);
        // Simulate a same-metadata source read changing after the first digest.
        if (changedCopy === "source" && read > 0 && copied &&
            original.fstatSync(descriptor, { bigint: true }).ino === nativeInode) buffer[offset] ^= 1;
        return read;
      },
    }), () => {
      const diagnostic = assertArtifactRefusal(() => buildFixture(fixture, {
        runCargo() {
          writeNativeOutput(fixture);
          nativeInode = lstatSync(fixture.nativePath, { bigint: true }).ino;
          return { status: 0, stdout: successfulCargoJson(fixture) };
        },
      }), "copied", changedCopy === "staged" ? "source-to-staged-copy" : "source-before-to-after-copy");
      const mismatch = diagnostic.failed_comparisons[0];
      assert.match(mismatch.expected_sha256, /^[a-f0-9]{64}$/u);
      assert.match(mismatch.actual_sha256, /^[a-f0-9]{64}$/u);
      assert.notEqual(mismatch.expected_sha256, mismatch.actual_sha256);
      assert.ok(diagnostic.failed_comparisons.every((entry) => !entry.changed_fields));
    });
  });
}

for (const side of ["source", "staged"]) {
  test("pre-rename diagnostics separately join the " + side + " identity", (t) => {
    const fixture = createFixture(t);
    let active = false;
    let sourceReads = 0;
    let stagedReads = 0;
    withFilesystemOverrides((original) => ({
      lstatSync(file, options) {
        const metadata = original.lstatSync(file, options);
        if (active && file === fixture.nativePath) {
          sourceReads += 1;
          if (side === "source" && sourceReads === 6) return changedStat(metadata, "ctimeNs");
        }
        if (typeof file === "string" && path.basename(file).startsWith(".libiroha_js_host.so.authenticated-")) {
          stagedReads += 1;
          if (side === "staged" && stagedReads === 3) return changedStat(metadata, "ctimeNs");
        }
        return metadata;
      },
    }), () => {
      const diagnostic = assertArtifactRefusal(() => buildFixture(fixture, {
        runCargo() {
          writeNativeOutput(fixture);
          active = true;
          return { status: 0, stdout: successfulCargoJson(fixture) };
        },
      }), "before-rename", side + "-seal-to-before-rename", ["ctimeNs"]);
      assert.equal(diagnostic.failed_comparisons.length, 1);
    });
  });
}

test("publication rejects a same-byte replacement instead of the staged inode", (t) => {
  const fixture = createFixture(t);
  let writes = 0;
  withFilesystemOverrides((original) => ({
    renameSync(from, to) {
      original.renameSync(from, to);
      if (to === fixture.nativePath && path.basename(from).includes(".authenticated-")) {
        const replacement = to + ".foreign";
        original.copyFileSync(to, replacement, fs.constants.COPYFILE_EXCL);
        original.renameSync(replacement, to);
      }
    },
  }), () => {
    const diagnostic = assertArtifactRefusal(() => buildFixture(fixture, {
      writeProvenance() { writes += 1; },
    }), "after-rename", "staged-to-published");
    const failed = diagnostic.failed_comparisons.find((entry) => entry.comparison === "staged-to-published");
    assert.ok(failed.changed_fields.includes("ino"));
    assert.ok(!failed.changed_fields.includes("ctimeNs"));
    assert.ok(!diagnostic.failed_comparisons.some((entry) => entry.comparison === "source-to-published"));
  });
  assert.equal(writes, 0);
});

test("publication digest mismatch names the expected and actual SHA-256", (t) => {
  const fixture = createFixture(t);
  withFilesystemOverrides((original) => ({
    renameSync(from, to) {
      original.renameSync(from, to);
      if (to === fixture.nativePath && path.basename(from).includes(".authenticated-")) {
        original.writeFileSync(to, "changed-publication");
      }
    },
  }), () => {
    const diagnostic = assertArtifactRefusal(() => buildFixture(fixture), "after-rename", "source-to-published");
    const failed = diagnostic.failed_comparisons.find((entry) => entry.comparison === "source-to-published");
    assert.equal(failed.expected_sha256, createHash("sha256").update("native-output").digest("hex"));
    assert.equal(failed.actual_sha256, createHash("sha256").update("changed-publication").digest("hex"));
  });
});

test("the owned rename allows its ctime transition while both stable reads remain strict", (t) => {
  const fixture = createFixture(t);
  let publishedInode;
  withFilesystemOverrides((original) => ({
    renameSync(from, to) {
      original.renameSync(from, to);
      if (to === fixture.nativePath && path.basename(from).includes(".authenticated-")) {
        publishedInode = original.lstatSync(to, { bigint: true }).ino;
      }
    },
    lstatSync(file, options) {
      const metadata = original.lstatSync(file, options);
      return metadata.ino === publishedInode ? changedStat(metadata, "ctimeNs") : metadata;
    },
    fstatSync(descriptor, options) {
      const metadata = original.fstatSync(descriptor, options);
      return metadata.ino === publishedInode ? changedStat(metadata, "ctimeNs") : metadata;
    },
  }), () => assert.equal(buildFixture(fixture), 0));
});

test("ctime drift during the final published read remains a refusal", (t) => {
  const fixture = createFixture(t);
  let publishedInode;
  let reads = 0;
  withFilesystemOverrides((original) => ({
    renameSync(from, to) {
      original.renameSync(from, to);
      if (to === fixture.nativePath && path.basename(from).includes(".authenticated-")) {
        publishedInode = original.lstatSync(to, { bigint: true }).ino;
      }
    },
    fstatSync(descriptor, options) {
      const metadata = original.fstatSync(descriptor, options);
      if (metadata.ino === publishedInode && ++reads === 2) return changedStat(metadata, "ctimeNs");
      return metadata;
    },
  }), () => assert.throws(() => buildFixture(fixture), /authenticated output changed while it was read/u));
});

function assertNoBuildReceipt(fixture) {
  const receipt = nativeBuildProvenancePath(fixture.nativePath);
  assert.equal(existsSync(receipt), false);
  assert.equal(existsSync(receipt + ".previous"), false);
}

function atFinalSourceRead(action) {
  let reads = 0;
  return () => {
    if (++reads === 3) action();
    return sourceState();
  };
}

test("final publication admits the unchanged default writer receipt", (t) => {
  const fixture = createFixture(t);
  assert.equal(buildFixture(fixture), 0);
  assert.deepEqual(readNativeBuildProvenance(fixture.nativePath), buildProvenance(
    fixture.nativePath, "debug", sourceState(),
  ));
});

for (const boundary of ["receipt-rename", "final-source-read"]) {
  for (const mutation of ["same-byte-inode", "changed-bytes"]) {
    test(`final publication refuses ${mutation} at ${boundary} and invalidates receipts`, (t) => {
      const fixture = createFixture(t);
      let replaced = false;
      withFilesystemOverrides((original) => {
        const replace = () => {
          const previous = original.lstatSync(fixture.nativePath, { bigint: true });
          const bytes = mutation === "same-byte-inode"
            ? original.readFileSync(fixture.nativePath) : Buffer.from("changed-native-output");
          const replacement = fixture.nativePath + ".replacement";
          original.writeFileSync(replacement, bytes);
          original.renameSync(replacement, fixture.nativePath);
          assert.notEqual(original.lstatSync(fixture.nativePath, { bigint: true }).ino, previous.ino);
          replaced = true;
        };
        fixture.finalRead = atFinalSourceRead(() => {
          if (boundary === "final-source-read") replace();
        });
        return {
          renameSync(from, to) {
            original.renameSync(from, to);
            if (boundary === "receipt-rename" && to === nativeBuildProvenancePath(fixture.nativePath)) replace();
          },
        };
      }, () => assert.throws(() => buildFixture(fixture, {
        readSourceState: fixture.finalRead,
      }), /artifact changed before digest verification/u));
      assert.equal(replaced, true);
      assertNoBuildReceipt(fixture);
      assert.equal(existsSync(fixture.nativePath), true);
    });
  }
}

for (const field of OUTPUT_FIELDS) {
  test(`final publication keeps saved ${field} strict after the source read`, (t) => {
    const fixture = createFixture(t);
    let finalRead = false;
    withFilesystemOverrides((original) => ({
      lstatSync(file, options) {
        const metadata = original.lstatSync(file, options);
        return finalRead && file === fixture.nativePath ? changedStat(metadata, field) : metadata;
      },
    }), () => assertArtifactRefusal(() => buildFixture(fixture, {
      readSourceState: atFinalSourceRead(() => { finalRead = true; }),
    }), "before-digest", "expected-to-before", [field]));
    assertNoBuildReceipt(fixture);
  });
}

test("final publication compares the full digest even when metadata observations are unchanged", (t) => {
  const fixture = createFixture(t);
  let finalRead = false;
  let descriptor;
  withFilesystemOverrides((original) => ({
    openSync(file, ...args) {
      const result = original.openSync(file, ...args);
      if (finalRead && file === fixture.nativePath) descriptor = result;
      return result;
    },
    readSync(fd, buffer, ...args) {
      const count = original.readSync(fd, buffer, ...args);
      if (finalRead && fd === descriptor && count > 0) buffer[0] ^= 1;
      return count;
    },
  }), () => assertArtifactRefusal(() => buildFixture(fixture, {
    readSourceState: atFinalSourceRead(() => { finalRead = true; }),
  }), "final-publication", "sealed-to-final"));
  assertNoBuildReceipt(fixture);
});

for (const mutation of ["valid-different-profile", "same-byte-inode", "deleted", "malformed", "extra-field"]) {
  test(`final publication refuses ${mutation} receipt after the source read`, (t) => {
    const fixture = createFixture(t);
    assert.throws(() => buildFixture(fixture, {
      readSourceState: atFinalSourceRead(() => {
        const receipt = nativeBuildProvenancePath(fixture.nativePath);
        const bytes = readFileSync(receipt);
        // Recovery sidecars cannot continue authenticating a refused build.
        writeFileSync(receipt + ".previous", bytes);
        if (mutation === "deleted") {
          rmSync(receipt);
        } else if (mutation === "same-byte-inode") {
          writeFileSync(receipt + ".replacement", bytes);
          fs.renameSync(receipt + ".replacement", receipt);
        } else if (mutation === "malformed") {
          writeFileSync(receipt, "{broken");
        } else {
          const data = JSON.parse(bytes);
          if (mutation === "valid-different-profile") data.cargo_profile = "release";
          else data.extra = true;
          writeFileSync(receipt, JSON.stringify(data, null, 2) + "\n");
        }
      }),
    }), /generated provenance|ENOENT/u);
    assertNoBuildReceipt(fixture);
    assert.equal(readFileSync(fixture.nativePath, "utf8"), "native-output");
  });
}

for (const mutation of ["same-byte-inode", "changed-content"]) {
  test(`final publication refuses ${mutation} receipt substitution during native digest`, (t) => {
    const fixture = createFixture(t);
    let finalRead = false;
    let mutated = false;
    let descriptor;
    withFilesystemOverrides((original) => ({
      openSync(file, ...args) {
        const result = original.openSync(file, ...args);
        if (finalRead && file === fixture.nativePath) descriptor = result;
        return result;
      },
      readSync(fd, ...args) {
        const count = original.readSync(fd, ...args);
        if (finalRead && fd === descriptor && !mutated) {
          const receipt = nativeBuildProvenancePath(fixture.nativePath);
          const bytes = original.readFileSync(receipt);
          if (mutation === "same-byte-inode") {
            original.writeFileSync(receipt + ".replacement", bytes);
            original.renameSync(receipt + ".replacement", receipt);
          } else original.writeFileSync(receipt, "{}");
          mutated = true;
        }
        return count;
      },
    }), () => assert.throws(() => buildFixture(fixture, {
      readSourceState: atFinalSourceRead(() => { finalRead = true; }),
    }), /generated provenance changed after publication/u));
    assert.equal(mutated, true);
    assertNoBuildReceipt(fixture);
  });
}

test("final publication checks native identity after the last receipt read", (t) => {
  const fixture = createFixture(t);
  let finalRead = false;
  let receiptOpens = 0;
  let changed = false;
  withFilesystemOverrides((original) => ({
    openSync(file, ...args) {
      const descriptor = original.openSync(file, ...args);
      if (finalRead && file === nativeBuildProvenancePath(fixture.nativePath) && ++receiptOpens === 2) {
        const replacement = fixture.nativePath + ".replacement";
        original.writeFileSync(replacement, original.readFileSync(fixture.nativePath));
        original.renameSync(replacement, fixture.nativePath);
        changed = true;
      }
      return descriptor;
    },
  }), () => assertArtifactRefusal(() => buildFixture(fixture, {
    readSourceState: atFinalSourceRead(() => { finalRead = true; }),
  }), "final-publication", "sealed-to-final-path"));
  assert.equal(changed, true);
  assertNoBuildReceipt(fixture);
});

test("final publication refuses source drift and removes the actual writer receipt", (t) => {
  const fixture = createFixture(t);
  let reads = 0;
  assert.throws(() => buildFixture(fixture, {
    readSourceState() {
      return ++reads === 3 ? sourceState({ sourceTreeSha256: "c".repeat(64) }) : sourceState();
    },
  }), /source changed while provenance was published/u);
  assertNoBuildReceipt(fixture);
});

test("final publication does not invalidate receipts through a replaced profile directory", (t) => {
  const fixture = createFixture(t);
  const profile = path.dirname(fixture.nativePath);
  const retired = profile + "-retired";
  t.after(() => rmSync(retired, { recursive: true, force: true }));
  assert.throws(() => buildFixture(fixture, {
    readSourceState: atFinalSourceRead(() => {
      fs.renameSync(profile, retired);
      mkdirSync(profile);
      writeFileSync(nativeBuildProvenancePath(fixture.nativePath), "foreign-receipt");
    }),
  }), /profile directory changed identity/u);
  assert.equal(readFileSync(nativeBuildProvenancePath(fixture.nativePath), "utf8"), "foreign-receipt");
});

function namespacedOutput(fixture, overrides = {}) {
  return nativeBuildOutputPath({
    repoRoot: fixture.repoRoot, cargoProfile: "debug", env: fixture.env,
    platform: "linux", sourceState: sourceState(), ...overrides,
  });
}

test("source cache namespaces separate checkouts sharing a target and toolchain", (t) => {
  const first = createFixture(t);
  const second = createFixture(t);
  const sameInputs = { env: first.env, sourceState: sourceState() };
  assert.notEqual(namespacedOutput(first, sameInputs), namespacedOutput(second, sameInputs));
  assert.equal(namespacedOutput(first), namespacedOutput(first));
  assert.notEqual(namespacedOutput(first), namespacedOutput(first, { cargoProfile: "release" }));
  assert.notEqual(namespacedOutput(first), namespacedOutput(first, { env: { ...first.env, RUSTFLAGS: "-Ctarget-cpu=native" } }));
});

test("source content changes select a new cache even after restoring mtimes", (t) => {
  const fixture = createFixture(t);
  const before = lstatSync(fixture.sourcePath);
  const firstState = sourceState({ sourceTreeSha256: sha256File(fixture.sourcePath) });
  const first = namespacedOutput(fixture, { sourceState: firstState });
  writeFileSync(fixture.sourcePath, "pub fn changed() {}\n");
  fs.utimesSync(fixture.sourcePath, before.atime, before.mtime);
  const secondState = sourceState({ sourceTreeSha256: sha256File(fixture.sourcePath) });
  assert.notEqual(namespacedOutput(fixture, { sourceState: secondState }), first);
});

test("toolchain bytes select a new cache even at the same canonical path", (t) => {
  const fixture = createFixture(t);
  const first = namespacedOutput(fixture);
  const before = lstatSync(fixture.env.RUSTC);
  writeFileSync(fixture.env.RUSTC, "#!/bin/sh\nexit 98\n");
  fs.utimesSync(fixture.env.RUSTC, before.atime, before.mtime);
  assert.notEqual(namespacedOutput(fixture), first);
});

function dependencyArtifact(fixture, overrides = {}) {
  const packageRoot = path.join(fixture.repoRoot, "crates", "dependency");
  const sourcePath = path.join(packageRoot, "src", "lib.rs");
  mkdirSync(path.dirname(sourcePath), { recursive: true });
  writeFileSync(sourcePath, "pub fn dependency() {}\n");
  writeFileSync(path.join(packageRoot, "Cargo.toml"), '[package]\nname = "dependency"\nversion = "1.0.0"\n');
  const filename = path.join(path.dirname(fixture.nativePath), "deps", "libdependency-fixture.rlib");
  mkdirSync(path.dirname(filename), { recursive: true });
  writeFileSync(filename, "dependency bytes");
  return intendedCargoArtifact(fixture, {
    package_id: "path+" + pathToFileURL(packageRoot).href + "#1.0.0",
    manifest_path: path.join(packageRoot, "Cargo.toml"),
    target: { name: "dependency", kind: ["rlib"], crate_types: ["rlib"], src_path: sourcePath },
    filenames: [filename], ...overrides,
  });
}

for (const mutation of ["foreign-manifest", "foreign-source", "foreign-output", "external-label"]) {
  test(`dependency closure rejects ${mutation} even when the final addon is valid`, (t) => {
    const fixture = createFixture(t);
    const foreign = createFixture(t);
    let written = false;
    assert.throws(() => buildFixture(fixture, {
      runCargo() {
        writeNativeOutput(fixture);
        const dependency = dependencyArtifact(fixture);
        if (mutation === "foreign-manifest") {
          dependency.manifest_path = path.join(foreign.packageRoot, "Cargo.toml");
          dependency.package_id = "path+" + pathToFileURL(foreign.packageRoot).href + "#0.0.0";
        } else if (mutation === "foreign-source") {
          dependency.target.src_path = foreign.sourcePath;
        } else if (mutation === "foreign-output") {
          const file = path.join(fixture.targetRoot, "unrelated.rlib");
          writeFileSync(file, "outside namespace");
          dependency.filenames = [file];
        } else {
          dependency.package_id = "registry+https://example.invalid/index#dependency@1.0.0";
        }
        return { status: 0, stdout: cargoJson(dependency, intendedCargoArtifact(fixture),
          { reason: "build-finished", success: true }) };
      },
      writeProvenance() { written = true; },
    }), /authenticated checkout|outside the authenticated source target|mislabeled a local dependency/u);
    assert.equal(written, false);
  });
}

test("build retains exact compiler messages and hashes every local dependency output", (t) => {
  const fixture = createFixture(t);
  let compilerMessages;
  assert.equal(buildFixture(fixture, {
    runCargo() {
      writeNativeOutput(fixture);
      compilerMessages = cargoJson(dependencyArtifact(fixture), intendedCargoArtifact(fixture),
        { reason: "build-finished", success: true });
      return { status: 0, stdout: compilerMessages };
    },
  }), 0);
  const profile = path.dirname(fixture.nativePath);
  const logs = fs.readdirSync(profile).filter((name) => name.endsWith(".jsonl"));
  assert.equal(logs.length, 1);
  const log = path.join(profile, logs[0]);
  assert.equal(readFileSync(log, "utf8"), compilerMessages);
  const receipt = JSON.parse(readFileSync(log + ".inputs.json", "utf8"));
  assert.equal(receipt.compiler_log_sha256, sha256File(log));
  assert.equal(receipt.native_sha256, sha256File(fixture.nativePath));
  assert.equal(completedBuildOutputPath({ repoRoot: fixture.repoRoot, cargoProfile: "debug",
    env: fixture.env, platform: "linux", sourceState: sourceState() }), fixture.nativePath);
  assert.equal(receipt.local_artifacts.length, 2);
  assert.equal(receipt.local_files.length, 2);
  for (const file of receipt.local_files) assert.equal(file.sha256, sha256File(file.path));
  assert.equal(verifyCargoDependencyArtifacts(compilerMessages, {
    repoRoot: fixture.repoRoot, targetRoot: path.dirname(profile),
  }).length, 2);
});

test("toolchain mutation during Cargo cannot publish dependency qualification", (t) => {
  const fixture = createFixture(t);
  assert.throws(() => buildFixture(fixture, {
    runCargo() {
      writeNativeOutput(fixture);
      writeFileSync(fixture.env.RUSTC, "#!/bin/sh\nexit 98\n");
      return { status: 0, stdout: successfulCargoJson(fixture) };
    },
    writeProvenance() { assert.fail("changed toolchain cannot publish"); },
  }), /toolchain or input namespace changed/u);
  assert.equal(fs.readdirSync(path.dirname(fixture.nativePath))
    .some((name) => name.endsWith(".inputs.json")), false);
});

const RETRY_ATTEMPT_ID = "00000000-0000-4000-8000-000000000002";
function setRetryOutput(fixture) {
  fixture.nativePath = path.join(nativeBuildNamespace({ repoRoot: fixture.repoRoot,
    cargoProfile: "debug", env: fixture.env, platform: "linux", sourceState: sourceState() }),
  RETRY_ATTEMPT_ID, "debug", "libiroha_js_host.so");
}

for (const failure of ["interrupted", "source-drift", "cargo-failure"]) {
  test(`same-input retry after ${failure} preserves the failed attempt and builds in a fresh target`, (t) => {
    const fixture = createFixture(t);
    const failedPath = fixture.nativePath;
    let reads = 0;
    const run = () => buildFixture(fixture, {
      readSourceState() {
        reads += 1;
        return failure === "source-drift" && reads > 1
          ? sourceState({ sourceTreeSha256: "c".repeat(64) }) : sourceState();
      },
      runCargo() {
        writeNativeOutput(fixture, "failed attempt bytes");
        if (failure === "interrupted") throw new Error("injected interrupted compiler");
        return { status: failure === "cargo-failure" ? 7 : 0,
          stdout: successfulCargoJson(fixture) };
      },
    });
    if (failure === "cargo-failure") assert.equal(run(), 7);
    else assert.throws(run, /interrupted compiler|source tree changed/u);
    const failedHash = sha256File(failedPath);
    assert.equal(existsSync(path.join(path.dirname(path.dirname(failedPath)), ".in-progress.json")), true);
    assert.throws(() => completedBuildOutputPath({ repoRoot: fixture.repoRoot,
      cargoProfile: "debug", env: fixture.env, platform: "linux", sourceState: sourceState() }));
    setRetryOutput(fixture);
    assert.equal(buildFixture(fixture, { newAttemptId: () => RETRY_ATTEMPT_ID }), 0);
    assert.notEqual(path.dirname(fixture.nativePath), path.dirname(failedPath));
    assert.equal(sha256File(failedPath), failedHash);
    assert.equal(completedBuildOutputPath({ repoRoot: fixture.repoRoot, cargoProfile: "debug",
      env: fixture.env, platform: "linux", sourceState: sourceState() }), fixture.nativePath);
  });
}

test("corrupted completed local dependency forces a fresh target without deleting evidence", (t) => {
  const fixture = createFixture(t);
  let localOutput;
  assert.equal(buildFixture(fixture, {
    runCargo() {
      writeNativeOutput(fixture);
      const dependency = dependencyArtifact(fixture);
      localOutput = dependency.filenames[0];
      return { status: 0, stdout: cargoJson(dependency, intendedCargoArtifact(fixture),
        { reason: "build-finished", success: true }) };
    },
  }), 0);
  writeFileSync(localOutput, "corrupted warm artifact");
  assert.throws(() => completedBuildOutputPath({ repoRoot: fixture.repoRoot, cargoProfile: "debug",
    env: fixture.env, platform: "linux", sourceState: sourceState() }), /dependency output changed/u);
  setRetryOutput(fixture);
  assert.equal(buildFixture(fixture, { newAttemptId: () => RETRY_ATTEMPT_ID }), 0);
  assert.equal(readFileSync(localOutput, "utf8"), "corrupted warm artifact");
});

test("fresh local artifacts without successful dependency evidence are rejected", (t) => {
  const fixture = createFixture(t);
  assert.throws(() => buildFixture(fixture, {
    runCargo() {
      writeNativeOutput(fixture);
      return { status: 0, stdout: successfulCargoJson(fixture, { fresh: true }) };
    },
  }), /without a matching completed dependency receipt/u);
});

test("warm dependency corruption during Cargo cannot qualify a fresh artifact", (t) => {
  const fixture = createFixture(t);
  let dependency;
  assert.equal(buildFixture(fixture, {
    runCargo() {
      writeNativeOutput(fixture);
      dependency = dependencyArtifact(fixture);
      return { status: 0, stdout: cargoJson(dependency, intendedCargoArtifact(fixture),
        { reason: "build-finished", success: true }) };
    },
  }), 0);
  assert.throws(() => buildFixture(fixture, {
    runCargo() {
      writeFileSync(dependency.filenames[0], "changed after namespace authentication");
      return { status: 0, stdout: cargoJson({ ...dependency, fresh: true },
        intendedCargoArtifact(fixture, { fresh: true }), { reason: "build-finished", success: true }) };
    },
  }), /without a matching completed dependency receipt/u);
});
