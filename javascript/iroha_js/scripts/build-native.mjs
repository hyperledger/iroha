#!/usr/bin/env node
/** Build the native iroha_js_host library from the authenticated live root. */
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  accessSync,
  closeSync,
  constants,
  copyFileSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  cargoBuildArgsForNativeProfile,
  resolveNativeBuildProfile,
} from "./native-build-profile.mjs";
import {
  createNativeBuildProvenance,
  invalidateNativeBuildProvenance,
  nativeBuildProvenancePath,
  NATIVE_BUILD_CARGO_LOCK_ENV,
  readNativeBuildSourceState,
  readStableRegularFile,
  readStableRegularFileDigest,
  writeNativeBuildProvenance,
} from "./native-build-provenance.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultRepoRoot = join(scriptDir, "..", "..", "..");
const INTENDED_PACKAGE = "iroha_js_host";
const PINNED_RUST_TOOLCHAIN = "1.93.1";
const CARGO_PATH_ENV = "IROHA_JS_CARGO_PATH";
const MAX_CARGO_JSON_BYTES = 64 * 1024 * 1024;
const MAX_CARGO_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_TOOLCHAIN_PROBE_BYTES = 64 * 1024;
const TOOLCHAIN_PROBE_TIMEOUT_MS = 15_000;
const MACOS_SDK_SETTINGS_BYTES = 1024 * 1024;
const MACOS_VERSION_PATTERN = /^\d+(?:\.\d+){1,2}$/u;
const REQUIRED_BUILD_ENVIRONMENT = Object.freeze({
  CARGO_BUILD_JOBS: "1",
  CARGO_INCREMENTAL: "0",
  CARGO_NET_OFFLINE: "true",
});
const UNSUPPORTED_DIRECTORY_SYNC_CODES = new Set([
  "EACCES",
  "EBADF",
  "EINVAL",
  "EISDIR",
  "ENOTSUP",
  "EPERM",
]);

function syncDirectory(directory) {
  let descriptor;
  try {
    descriptor = openSync(directory, constants.O_RDONLY);
    fsyncSync(descriptor);
  } catch (error) {
    if (!UNSUPPORTED_DIRECTORY_SYNC_CODES.has(error?.code)) throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function isPathInside(parent, child) {
  const pathFromParent = relative(parent, child);
  return (
    pathFromParent === "" ||
    (pathFromParent !== ".." && !pathFromParent.startsWith(".." + sep))
  );
}

function assertDisjointPathAncestry(left, right, label) {
  if (isPathInside(left, right) || isPathInside(right, left)) {
    throw new Error(
      label + " must not contain or be contained by the build source.",
    );
  }
}

function canonicalDirectory(path, label, { create = false } = {}) {
  const resolvedPath = resolve(path);
  if (create) mkdirSync(resolvedPath, { mode: 0o700, recursive: true });
  const metadata = lstatSync(resolvedPath, { bigint: true });
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(label + " must be a real non-symbolic-link directory.");
  }
  const canonicalPath = realpathSync(resolvedPath);
  if (canonicalPath !== resolvedPath) {
    throw new Error(label + " path must be canonical.");
  }
  return Object.freeze({
    canonicalPath,
    identity: Object.freeze({ dev: metadata.dev, ino: metadata.ino }),
  });
}

function assertDirectoryIdentity(directory, label) {
  const metadata = lstatSync(directory.canonicalPath, { bigint: true });
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.dev !== directory.identity.dev ||
    metadata.ino !== directory.identity.ino ||
    realpathSync(directory.canonicalPath) !== directory.canonicalPath
  ) {
    throw new Error(label + " changed identity.");
  }
}

function canonicalRegularFile(path, label, { executable = false } = {}) {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    !isAbsolute(path) ||
    resolve(path) !== path
  ) {
    throw new Error(label + " must be an absolute canonical path.");
  }
  const metadata = lstatSync(path, { bigint: true });
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    realpathSync(path) !== path
  ) {
    throw new Error(label + " must be a canonical regular non-symbolic-link file.");
  }
  if (executable) accessSync(path, constants.X_OK);
  return path;
}

function readUtf8RegularFile(path, label, maximumBytes) {
  return new TextDecoder("utf-8", { fatal: true }).decode(
    readStableRegularFile(path, {
      label,
      maximumBytes,
      requireNonempty: true,
    }).bytes,
  );
}

function readPinnedToolchain(repoRoot) {
  const path = canonicalRegularFile(
    join(repoRoot, "rust-toolchain.toml"),
    "Native build Rust toolchain file",
  );
  const document = readUtf8RegularFile(
    path,
    "Native build Rust toolchain file",
    64 * 1024,
  );
  const channels = [
    ...document.matchAll(
      /^[ \t]*channel[ \t]*=[ \t]*"([^"\r\n]+)"[ \t]*(?:#.*)?$/gmu,
    ),
  ];
  if (channels.length !== 1 || channels[0][1] !== PINNED_RUST_TOOLCHAIN) {
    throw new Error(
      "Native build requires rust-toolchain.toml to pin Rust " +
        PINNED_RUST_TOOLCHAIN +
        ".",
    );
  }
  return channels[0][1];
}

function requiredExecutable(env, key, executableName) {
  const path = canonicalRegularFile(
    env[key],
    "Native build " + key,
    { executable: true },
  );
  const actualName = basename(path).toLowerCase();
  if (
    actualName !== executableName &&
    actualName !== executableName + ".exe"
  ) {
    throw new Error(
      "Native build " + key + " must name the " + executableName + " executable.",
    );
  }
  return path;
}

function probePinnedExecutable(
  executable, args, repoRoot, env, runTool, stream = "stdout",
) {
  const result = runTool(executable, args, {
    cwd: repoRoot,
    env,
    encoding: "utf8",
    maxBuffer: MAX_TOOLCHAIN_PROBE_BYTES,
    timeout: TOOLCHAIN_PROBE_TIMEOUT_MS,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (
    result?.error !== undefined ||
    result?.status !== 0 ||
    (result.signal !== undefined && result.signal !== null) ||
    typeof result[stream] !== "string" ||
    Buffer.byteLength(result[stream], "utf8") > MAX_TOOLCHAIN_PROBE_BYTES
  ) {
    throw new Error(
      "Native build could not verify " + basename(executable) + " " + args.join(" ") + ".",
    );
  }
  return result[stream].trim();
}

function validatePinnedExecutables(repoRoot, env, runTool) {
  const channel = readPinnedToolchain(repoRoot);
  const cargoPath = requiredExecutable(env, CARGO_PATH_ENV, "cargo");
  const rustcPath = requiredExecutable(env, "RUSTC", "rustc");
  const rustdocPath = requiredExecutable(env, "RUSTDOC", "rustdoc");
  const binDirectory = dirname(cargoPath);
  if (
    dirname(rustcPath) !== binDirectory ||
    dirname(rustdocPath) !== binDirectory
  ) {
    throw new Error(
      "Native build Cargo, rustc, and rustdoc must come from one pinned toolchain.",
    );
  }
  const rustcVersion = probePinnedExecutable(rustcPath, ["-vV"], repoRoot, env, runTool);
  const releases = [...rustcVersion.matchAll(/^release: ([^\r\n]+)\r?$/gmu)];
  if (!rustcVersion.startsWith("rustc " + channel + " ") ||
      releases.length !== 1 || releases[0][1] !== channel) {
    throw new Error(
      "Native build rustc must report exactly release " + channel + ".",
    );
  }
  for (const [executable, name] of [[cargoPath, "cargo"], [rustdocPath, "rustdoc"]]) {
    const version = probePinnedExecutable(executable, ["--version"], repoRoot, env, runTool);
    const parsed = /^(cargo|rustdoc) (\S+)(?: \([^\r\n]*\))?$/u.exec(version);
    if (parsed?.[1] !== name || parsed[2] !== channel) {
      throw new Error("Native build " + name + " must report exactly version " + channel + ".");
    }
  }
  const sysrootPath = probePinnedExecutable(rustcPath, ["--print", "sysroot"], repoRoot, env, runTool);
  if (!isAbsolute(sysrootPath) || resolve(sysrootPath) !== sysrootPath) {
    throw new Error("Native build rustc sysroot must be an absolute canonical path.");
  }
  const sysroot = canonicalDirectory(sysrootPath, "Native build rustc sysroot");
  if (join(sysroot.canonicalPath, "bin") !== binDirectory) {
    throw new Error("Native build executables must share the bin directory of rustc's reported sysroot.");
  }
  return Object.freeze({ cargoPath, rustcPath, rustdocPath });
}

function macosBuildIdentity(repoRoot, env, runTool) {
  if (typeof env.MACOSX_DEPLOYMENT_TARGET !== "string" ||
      !MACOS_VERSION_PATTERN.test(env.MACOSX_DEPLOYMENT_TARGET)) {
    throw new Error("Native macOS build requires an explicit MACOSX_DEPLOYMENT_TARGET version.");
  }
  const xcrun = canonicalRegularFile("/usr/bin/xcrun", "Native build xcrun", {
    executable: true,
  });
  const requestedSdk = env.SDKROOT ?? probePinnedExecutable(
    xcrun, ["--sdk", "macosx", "--show-sdk-path"], repoRoot, env, runTool,
  );
  const sdkRoot = canonicalDirectory(
    realpathSync(requestedSdk), "Native build macOS SDKROOT",
  ).canonicalPath;
  const settings = readStableRegularFile(join(sdkRoot, "SDKSettings.json"), {
    label: "Native build macOS SDK settings",
    maximumBytes: MACOS_SDK_SETTINGS_BYTES,
    requireNonempty: true,
  }).bytes;
  let sdkVersion;
  try {
    sdkVersion = JSON.parse(settings.toString("utf8")).Version;
  } catch {
    throw new Error("Native build macOS SDK settings are invalid.");
  }
  if (typeof sdkVersion !== "string" || !MACOS_VERSION_PATTERN.test(sdkVersion)) {
    throw new Error("Native build macOS SDK version is invalid.");
  }
  const clangPath = canonicalRegularFile(
    realpathSync(probePinnedExecutable(
      xcrun, ["--find", "clang"], repoRoot, env, runTool,
    )), "Native build Apple clang", { executable: true },
  );
  const linkerPath = canonicalRegularFile(
    realpathSync(probePinnedExecutable(
      xcrun, ["--find", "ld"], repoRoot, env, runTool,
    )), "Native build Apple linker", { executable: true },
  );
  const clangVersion = probePinnedExecutable(
    clangPath, ["--version"], repoRoot, env, runTool,
  ).split("\n", 1)[0];
  const linkerVersion = probePinnedExecutable(
    linkerPath, ["-v"], repoRoot, env, runTool, "stderr",
  ).split("\n", 1)[0];
  if (!clangVersion.startsWith("Apple clang version ") ||
      !linkerVersion.startsWith("@(#)PROGRAM:ld PROJECT:ld-")) {
    throw new Error("Native build Apple compiler or linker version is invalid.");
  }
  return Object.freeze({
    sdk_root: sdkRoot,
    sdk_version: sdkVersion,
    sdk_settings_sha256: createHash("sha256").update(settings).digest("hex"),
    deployment_target: env.MACOSX_DEPLOYMENT_TARGET,
    clang_path: clangPath,
    clang_version: clangVersion,
    linker_path: linkerPath,
    linker_version: linkerVersion,
  });
}

function macosCargoEnvironment(env, identity) {
  const fingerprint = createHash("sha256")
    .update(JSON.stringify(identity)).digest("hex");
  const metadataFlag = `-Cmetadata=iroha_js_macos_${fingerprint}`;
  const cargoEnv = { ...env, SDKROOT: identity.sdk_root };
  if (env.CARGO_ENCODED_RUSTFLAGS !== undefined) {
    cargoEnv.CARGO_ENCODED_RUSTFLAGS = env.CARGO_ENCODED_RUSTFLAGS
      ? `${env.CARGO_ENCODED_RUSTFLAGS}\x1f${metadataFlag}` : metadataFlag;
  } else {
    cargoEnv.RUSTFLAGS = env.RUSTFLAGS
      ? `${env.RUSTFLAGS} ${metadataFlag}` : metadataFlag;
  }
  return cargoEnv;
}

function validateRequiredEnvironment(env) {
  if (env.RUSTC_BOOTSTRAP !== undefined) {
    throw new Error("Native build forbids RUSTC_BOOTSTRAP; use the stock pinned toolchain.");
  }
  for (const [key, expected] of Object.entries(REQUIRED_BUILD_ENVIRONMENT)) {
    if (env[key] !== expected) {
      throw new Error(
        "Native build requires " + key + "=" + expected + ".",
      );
    }
  }
}

function canonicalRepoRoot(repoRoot) {
  const resolved = resolve(repoRoot);
  return canonicalDirectory(
    resolved,
    "Native build repository root",
  ).canonicalPath;
}

function canonicalBuildInputs(repoRoot, env) {
  const cargoManifest = canonicalRegularFile(
    join(repoRoot, "Cargo.toml"),
    "Native build root Cargo.toml",
  );
  const configuredLock = env[NATIVE_BUILD_CARGO_LOCK_ENV];
  if (typeof configuredLock !== "string" || configuredLock.length === 0) {
    throw new Error(
      "Native build requires " +
        NATIVE_BUILD_CARGO_LOCK_ENV +
        " to name an absolute canonical Cargo.lock.",
    );
  }
  const cargoLock = canonicalRegularFile(
    configuredLock,
    "Native build Cargo.lock",
  );
  if (basename(cargoLock) !== "Cargo.lock") {
    throw new Error("Native build Cargo lock path must end in Cargo.lock.");
  }
  const rootLock = join(repoRoot, "Cargo.lock");
  if (cargoLock !== rootLock) {
    throw new Error(
      "Native build Cargo.lock must be the authenticated repository root Cargo.lock.",
    );
  }
  return Object.freeze({ cargoLock, cargoManifest });
}

function canonicalTargetRoot(repoRoot, env) {
  const configured = env.CARGO_TARGET_DIR;
  if (
    typeof configured !== "string" ||
    configured.length === 0 ||
    !isAbsolute(configured) ||
    resolve(configured) !== configured
  ) {
    throw new Error(
      "Native build requires CARGO_TARGET_DIR to be an absolute canonical path.",
    );
  }
  // Generated qualification lanes keep original-checkout builds and outputs
  // together. Canonical paths and directory identities are still checked below.
  const qualificationParent = join(repoRoot, "target", "qualification");
  const qualificationChild = configured.startsWith(qualificationParent + sep);
  if (configured !== join(repoRoot, "target") && !qualificationChild) {
    assertDisjointPathAncestry(
      repoRoot,
      configured,
      "Native build Cargo target",
    );
  }
  const target = canonicalDirectory(
    configured,
    "Native build Cargo target directory",
    { create: true },
  );
  return target;
}

function assertCargoProfileEnvironment(env) {
  const profileOverride = Object.keys(env).find((key) =>
    key.toUpperCase().startsWith("CARGO_PROFILE_"),
  );
  if (profileOverride !== undefined) {
    throw new Error(
      "Native build forbids Cargo profile environment override " +
        profileOverride +
        ".",
    );
  }
}

function nativeFilename(platform) {
  if (platform === "win32") return "iroha_js_host.dll";
  return "libiroha_js_host." + (platform === "darwin" ? "dylib" : "so");
}

export function nativeBuildNamespace({
  repoRoot = defaultRepoRoot,
  cargoProfile,
  env = process.env,
  platform = process.platform,
  sourceState,
}) {
  if (
    cargoProfile !== "debug" &&
    cargoProfile !== "release" &&
    cargoProfile !== "deploy"
  ) {
    throw new TypeError(
      "Native build Cargo profile must be debug, release, or deploy.",
    );
  }
  const targetRoot = env.CARGO_TARGET_DIR;
  if (
    typeof targetRoot !== "string" ||
    targetRoot.length === 0 ||
    !isAbsolute(targetRoot) ||
    resolve(targetRoot) !== targetRoot
  ) {
    throw new Error(
      "Native build requires CARGO_TARGET_DIR to be an absolute canonical path.",
    );
  }
  const root = canonicalRepoRoot(repoRoot);
  const source = sourceState ?? readNativeBuildSourceState(root, { env });
  if (!/^[0-9a-f]{64}$/u.test(source.sourceTreeSha256)) {
    throw new Error("Native build requires an authenticated complete source fingerprint.");
  }
  const toolchain = [
    [CARGO_PATH_ENV, "cargo"], ["RUSTC", "rustc"], ["RUSTDOC", "rustdoc"],
  ].map(([key, name]) => {
    const path = requiredExecutable(env, key, name);
    const { sha256 } = readStableRegularFileDigest(path, {
      label: "Native build " + name,
      maximumBytes: 512 * 1024 * 1024,
      requireNonempty: true,
    });
    return { path, sha256 };
  });
  // Keep the complete authenticated inventory. A narrowed Rust-only input
  // closure would need its own audit of build scripts and generated inputs.
  const buildEnvironment = Object.fromEntries(Object.keys(env).sort()
    .filter((key) => /^(?:CARGO_(?:BUILD_|TARGET_|ENCODED_RUSTFLAGS$)|RUSTFLAGS$|RUSTC_(?:WRAPPER|WORKSPACE_WRAPPER)$|SDKROOT$|MACOSX_DEPLOYMENT_TARGET$)/u.test(key))
    .map((key) => [key, env[key]]));
  const fingerprint = createHash("sha256").update(JSON.stringify({
    version: 1,
    root,
    source,
    toolchain,
    toolchainChannel: readPinnedToolchain(root),
    cargoProfile,
    platform,
    arch: process.arch,
    buildEnvironment,
  })).digest("hex");
  return join(targetRoot, "iroha-js-source", fingerprint);
}


function completedNamespace(namespace, { cargoProfile, platform, repoRoot, sourceState }) {
  const completedPath = join(namespace, "completed.json");
  const completed = JSON.parse(readUtf8RegularFile(completedPath,
    "Completed native namespace", 16 * 1024));
  if (completed.version !== 1 ||
      !/^[0-9a-f-]{36}$/u.test(completed.attempt_id) ||
      !/^iroha-js-cargo-[0-9a-f-]{36}\.jsonl\.inputs\.json$/u.test(completed.receipt) ||
      !/^[0-9a-f]{64}$/u.test(completed.receipt_sha256)) {
    throw new Error("Completed native namespace has an invalid identity.");
  }
  const target = join(namespace, completed.attempt_id);
  canonicalDirectory(target, "Completed native target");
  try {
    lstatSync(join(target, ".in-progress.json"));
    throw new Error("Native namespace contains an unfinished build attempt.");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const profile = join(target, cargoProfile);
  const receiptPath = join(profile, completed.receipt);
  const receiptFile = readStableRegularFile(receiptPath, {
    label: "Completed native dependency receipt", maximumBytes: MAX_CARGO_JSON_BYTES,
  });
  if (receiptFile.sha256 !== completed.receipt_sha256) {
    throw new Error("Completed native dependency receipt changed.");
  }
  const receipt = JSON.parse(receiptFile.bytes.toString("utf8"));
  const nativePath = join(profile, nativeFilename(platform));
  if (receipt.version !== 1 || receipt.target_root !== target ||
      receipt.native_path !== nativePath ||
      receipt.repo_root !== repoRoot || !sameSourceState(receipt.source, sourceState) ||
      !Array.isArray(receipt.local_files) || receipt.local_files.length === 0) {
    throw new Error("Completed native dependency receipt has a foreign target.");
  }
  const logPath = receiptPath.slice(0, -".inputs.json".length);
  const compilerLog = readStableRegularFile(logPath, {
    label: "Completed Cargo compiler stream", maximumBytes: MAX_CARGO_JSON_BYTES,
  });
  if (compilerLog.sha256 !== receipt.compiler_log_sha256) {
    throw new Error("Completed Cargo compiler stream changed.");
  }
  const local = verifyCargoDependencyArtifacts(compilerLog.bytes, {
    repoRoot: receipt.repo_root, targetRoot: target,
  });
  const expectedFiles = [...new Set(local.flatMap(({ filenames }) => filenames))].sort();
  if (!exactStringArray(receipt.local_files.map(({ path }) => path), expectedFiles)) {
    throw new Error("Completed native dependency receipt omitted local artifacts.");
  }
  for (const file of receipt.local_files) {
    if (!/^[0-9a-f]{64}$/u.test(file.sha256) ||
        digestCargoArtifactSource(file.path).sha256 !== file.sha256) {
      throw new Error("Completed native dependency output changed: " + file.path);
    }
  }
  if (receipt.local_files.find(({ path }) => path === nativePath)?.sha256 !== receipt.native_sha256) {
    throw new Error("Completed native dependency receipt omitted the addon.");
  }
  return { target, nativePath, receipt, completed };
}

/** Resolve only an authenticated completed attempt for publication. */
export function nativeBuildOutputPath(options) {
  const repoRoot = canonicalRepoRoot(options.repoRoot ?? defaultRepoRoot);
  const sourceState = options.sourceState ?? readNativeBuildSourceState(repoRoot, { env: options.env ?? process.env });
  const namespace = nativeBuildNamespace({ ...options, repoRoot, sourceState });
  return completedNamespace(namespace, {
    cargoProfile: options.cargoProfile, platform: options.platform ?? process.platform,
    repoRoot, sourceState,
  }).nativePath;
}

function selectBuildAttempt(namespace, { cargoProfile, platform, repoRoot, sourceState, newAttemptId }) {
  let previous;
  try {
    previous = completedNamespace(namespace, { cargoProfile, platform, repoRoot, sourceState });
  } catch (error) {
    // Retain incomplete/corrupt attempts. Only a successfully authenticated
    // receipt allows local Cargo cache reuse; a retry starts a fresh directory.
    if (error.code !== "ENOENT") process.stderr.write("Native cache retry: " + error.message + "\n");
  }
  let target = previous?.target;
  for (;;) {
    if (target === undefined) {
      const id = newAttemptId();
      if (!/^[0-9a-f-]{36}$/u.test(id)) throw new Error("Native build attempt ID is invalid.");
      target = join(namespace, id);
      canonicalDirectory(target, "Native build attempt directory", { create: true });
    }
    const ownerPath = join(target, ".in-progress.json");
    const owner = Buffer.from(JSON.stringify({ pid: process.pid, nonce: randomUUID() }) + "\n");
    try {
      writeFileSync(ownerPath, owner, { flag: "wx", mode: 0o600 });
      return { target, previous: previous?.target === target ? previous.receipt : undefined,
        ownerPath, owner };
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      target = undefined;
      previous = undefined;
    }
  }
}

function parseCargoMessages(stdout) {
  const encoded = Buffer.isBuffer(stdout)
    ? stdout.toString("utf8")
    : typeof stdout === "string"
      ? stdout
      : null;
  if (encoded === null) {
    throw new Error("Successful Cargo execution did not return JSON messages.");
  }
  const messages = [];
  for (const line of encoded.split(/\r?\n/u)) {
    if (line.length === 0) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      throw new Error("Cargo emitted a malformed JSON build message.");
    }
    if (
      message === null ||
      typeof message !== "object" ||
      Array.isArray(message) ||
      typeof message.reason !== "string"
    ) {
      throw new Error("Cargo emitted a malformed JSON build message.");
    }
    messages.push(message);
  }
  return messages;
}

function readWorkspacePackageVersion(repoRoot) {
  const manifestPath = join(repoRoot, "Cargo.toml");
  const manifest = readUtf8RegularFile(
    manifestPath,
    "Native build workspace Cargo manifest",
    MAX_CARGO_MANIFEST_BYTES,
  );
  const sectionHeader = /^\[workspace\.package\][ \t]*(?:#.*)?$/mu.exec(
    manifest,
  );
  if (sectionHeader === null) {
    throw new Error(
      "Native build workspace Cargo manifest has no workspace.package section.",
    );
  }
  const sectionTail = manifest.slice(
    sectionHeader.index + sectionHeader[0].length,
  );
  const nextSection = /^\[[^\]\r\n]+\][ \t]*(?:#.*)?$/mu.exec(sectionTail);
  const section =
    nextSection === null
      ? sectionTail
      : sectionTail.slice(0, nextSection.index);
  const versions = [
    ...section.matchAll(
      /^version[ \t]*=[ \t]*"([^"\r\n]+)"[ \t]*(?:#.*)?$/gmu,
    ),
  ];
  if (
    versions.length !== 1 ||
    !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u.test(
      versions[0][1],
    )
  ) {
    throw new Error(
      "Native build workspace Cargo manifest has no exact semantic version.",
    );
  }
  return versions[0][1];
}

function packageIdNamesIntendedPackage(
  packageId,
  expectedPackageRoot,
  expectedVersion,
) {
  return (
    typeof packageId === "string" &&
    packageId ===
      "path+" +
        pathToFileURL(realpathSync(expectedPackageRoot)).href +
        "#" +
        expectedVersion
  );
}

function exactStringArray(value, expected) {
  return (
    Array.isArray(value) &&
    value.length === expected.length &&
    value.every((item, index) => item === expected[index])
  );
}

function cargoArtifactProfileMatches(value, cargoProfile) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const optimized = cargoProfile === "release" || cargoProfile === "deploy";
  return (
    value.opt_level === (optimized ? "3" : "0") &&
    value.debuginfo === 0 &&
    value.debug_assertions === !optimized &&
    value.overflow_checks === !optimized &&
    value.test === false
  );
}

function artifactMightBeIntended(
  message,
  expectedNativePath,
  expectedSourcePath,
) {
  const filenames = Array.isArray(message.filenames) ? message.filenames : [];
  return (
    message.target?.name === INTENDED_PACKAGE ||
    message.target?.src_path === expectedSourcePath ||
    filenames.some(
      (filename) =>
        typeof filename === "string" &&
        isAbsolute(filename) &&
        resolve(filename) === expectedNativePath,
    )
  );
}

function verifyCargoArtifactMessages(
  stdout,
  { cargoProfile, nativePath, repoRoot },
) {
  const expectedNativePath = resolve(nativePath);
  const expectedPackageRoot = resolve(
    repoRoot,
    "crates",
    INTENDED_PACKAGE,
  );
  const expectedManifestPath = join(expectedPackageRoot, "Cargo.toml");
  const expectedVersion = readWorkspacePackageVersion(repoRoot);
  const expectedSourcePath = resolve(
    expectedPackageRoot,
    "src",
    "lib.rs",
  );
  const messages = parseCargoMessages(stdout);
  const buildFinished = messages.filter(
    ({ reason }) => reason === "build-finished",
  );
  if (
    buildFinished.length !== 1 ||
    buildFinished[0].success !== true ||
    messages.at(-1) !== buildFinished[0]
  ) {
    throw new Error(
      "Cargo did not emit exactly one successful terminal build-finished message.",
    );
  }
  const candidates = messages.filter(
    (message) =>
      message.reason === "compiler-artifact" &&
      artifactMightBeIntended(
        message,
        expectedNativePath,
        expectedSourcePath,
      ),
  );
  if (candidates.length !== 1) {
    throw new Error(
      "Cargo did not emit exactly one iroha_js_host compiler artifact.",
    );
  }
  const artifact = candidates[0];
  const filenames = Array.isArray(artifact.filenames)
    ? artifact.filenames
    : [];
  const matchingFilenames = filenames.filter(
    (filename) =>
      typeof filename === "string" &&
      isAbsolute(filename) &&
      resolve(filename) === expectedNativePath,
  );
  if (
    !packageIdNamesIntendedPackage(
      artifact.package_id,
      expectedPackageRoot,
      expectedVersion,
    ) ||
    artifact.manifest_path !== expectedManifestPath ||
    realpathSync(artifact.manifest_path) !== expectedManifestPath ||
    artifact.target?.name !== INTENDED_PACKAGE ||
    !exactStringArray(artifact.target?.kind, ["cdylib"]) ||
    !exactStringArray(artifact.target?.crate_types, ["cdylib"]) ||
    artifact.target?.src_path !== expectedSourcePath ||
    realpathSync(artifact.target.src_path) !== expectedSourcePath ||
    !exactStringArray(artifact.features, []) ||
    artifact.executable !== null ||
    !cargoArtifactProfileMatches(artifact.profile, cargoProfile) ||
    typeof artifact.fresh !== "boolean" ||
    matchingFilenames.length !== 1 ||
    realpathSync(matchingFilenames[0]) !== expectedNativePath
  ) {
    throw new Error(
      "Cargo emitted an invalid iroha_js_host cdylib compiler artifact.",
    );
  }
  return artifact;
}

/** Validate the complete local dependency closure reported by Cargo. */
export function verifyCargoDependencyArtifacts(stdout, { repoRoot, targetRoot, nativePath }) {
  const root = canonicalRepoRoot(repoRoot);
  const target = realpathSync(targetRoot);
  const local = [];
  for (const artifact of parseCargoMessages(stdout)) {
    if (artifact.reason !== "compiler-artifact") continue;
    if (typeof artifact.package_id !== "string" ||
        !/^(?:path|registry|git)\+/u.test(artifact.package_id)) {
      throw new Error("Cargo dependency has an unsupported package identity.");
    }
    const manifest = canonicalRegularFile(artifact.manifest_path, "Cargo dependency manifest");
    const source = canonicalRegularFile(artifact.target?.src_path, "Cargo dependency source");
    if (!Array.isArray(artifact.filenames) || artifact.filenames.length === 0 ||
        typeof artifact.fresh !== "boolean") {
      throw new Error("Cargo dependency has no exact artifact files or freshness state.");
    }
    for (const filename of artifact.filenames) {
      // The final addon has the stricter inode/digest seal immediately below.
      if (filename !== nativePath) canonicalRegularFile(filename, "Cargo dependency artifact");
      if (!isPathInside(target, filename)) {
        throw new Error("Cargo dependency artifact is outside the authenticated source target.");
      }
    }
    if (!artifact.package_id.startsWith("path+")) {
      if (isPathInside(root, manifest) || isPathInside(root, source)) {
        throw new Error("Cargo mislabeled a local dependency as an external package.");
      }
      continue;
    }
    const packageRoot = dirname(manifest);
    if (!isPathInside(root, manifest) || !isPathInside(root, source) ||
        basename(manifest) !== "Cargo.toml" ||
        !artifact.package_id.startsWith("path+" + pathToFileURL(packageRoot).href + "#")) {
      throw new Error("Cargo local dependency does not belong to the authenticated checkout.");
    }
    local.push(artifact);
  }
  if (local.length === 0) throw new Error("Cargo reported no authenticated local dependencies.");
  return local;
}

function forwardCargoRenderedDiagnostics(stdout) {
  const encoded = Buffer.isBuffer(stdout)
    ? stdout.toString("utf8")
    : typeof stdout === "string"
      ? stdout
      : "";
  for (const line of encoded.split(/\r?\n/u)) {
    if (line.length === 0) continue;
    try {
      const rendered = JSON.parse(line)?.message?.rendered;
      if (typeof rendered === "string") process.stderr.write(rendered);
    } catch {
      // Strict validation reports malformed output after Cargo exits.
    }
  }
}

function sameOutputIdentity(left, right) {
  return (
    left !== null &&
    left !== undefined &&
    right !== null &&
    right !== undefined &&
    left.ctimeNs === right.ctimeNs &&
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.mtimeNs === right.mtimeNs &&
    left.nlink === right.nlink &&
    left.size === right.size
  );
}

const OUTPUT_IDENTITY_FIELDS = Object.freeze([
  "ctimeNs", "dev", "ino", "mode", "mtimeNs", "nlink", "size",
]);

function changedOutputFields(left, right, { afterRename = false } = {}) {
  return OUTPUT_IDENTITY_FIELDS.filter(
    (field) => !(afterRename && field === "ctimeNs") && left?.[field] !== right?.[field],
  );
}

function sameRenamedOutputIdentity(left, right) {
  // Our explicit rename may change ctime. Each stable read on either side
  // still checks ctime; every other identity field must survive publication.
  return changedOutputFields(left, right, { afterRename: true }).length === 0;
}

function artifactIdentityDiagnostic(identity) {
  if (identity === undefined || identity === null) return null;
  return Object.fromEntries(
    OUTPUT_IDENTITY_FIELDS.map(
      (field) => [field, identity[field]?.toString() ?? null],
    ),
  );
}

function artifactChangeError(message, phase, sourcePath, {
  expected,
  before,
  openedBefore,
  openedAfter,
  atPath,
  bytesRead,
  checkByteCount = false,
  identities = [],
  digests = [],
} = {}) {
  const failedComparisons = identities.flatMap(
    ([comparison, left, right, options]) => {
      const changedFields = changedOutputFields(left, right, options);
      return changedFields.length === 0 ? [] : [{
        comparison,
        changed_fields: changedFields,
        expected: artifactIdentityDiagnostic(left),
        actual: artifactIdentityDiagnostic(right),
      }];
    },
  );
  for (const [comparison, expectedDigest, actualDigest] of digests) {
    if (expectedDigest !== actualDigest) {
      failedComparisons.push({ comparison, expected_sha256: expectedDigest, actual_sha256: actualDigest });
    }
  }
  if (checkByteCount && bytesRead !== before.size) {
    failedComparisons.push({
      comparison: "byte-count",
      expected_bytes: before.size.toString(),
      actual_bytes: bytesRead.toString(),
    });
  }
  const diagnostic = Object.freeze({
    phase,
    path: sourcePath,
    failed_comparisons: failedComparisons,
    expected: artifactIdentityDiagnostic(expected),
    before: artifactIdentityDiagnostic(before),
    opened_before: artifactIdentityDiagnostic(openedBefore),
    opened_after: artifactIdentityDiagnostic(openedAfter),
    at_path: artifactIdentityDiagnostic(atPath),
    bytes_read: bytesRead?.toString() ?? null,
    expected_bytes: before?.size?.toString() ?? expected?.size?.toString() ?? null,
  });
  const error = new Error(message + " " + JSON.stringify(diagnostic));
  error.code = "ERR_IROHA_NATIVE_ARTIFACT_CHANGED";
  error.artifactIdentity = diagnostic;
  return error;
}

function cargoArtifactSourceIdentity(path) {
  const metadata = lstatSync(path, { bigint: true });
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.nlink < 1n ||
    metadata.size === 0n ||
    realpathSync(path) !== resolve(path)
  ) {
    throw new Error(
      "Cargo native build artifact must be a nonempty canonical regular file.",
    );
  }
  return Object.freeze({
    ctimeNs: metadata.ctimeNs,
    dev: metadata.dev,
    ino: metadata.ino,
    mode: metadata.mode,
    mtimeNs: metadata.mtimeNs,
    nlink: metadata.nlink,
    size: metadata.size,
  });
}

function cargoArtifactIdentityOrNull(path) {
  try {
    return cargoArtifactSourceIdentity(path);
  } catch (error) {
    if (error?.code === "ENOENT" || error?.code === "ENOTDIR") return null;
    throw error;
  }
}

function digestCargoArtifactSource(sourcePath, expectedIdentity) {
  const before = cargoArtifactSourceIdentity(sourcePath);
  if (
    expectedIdentity !== undefined &&
    !sameOutputIdentity(before, expectedIdentity)
  ) {
    throw artifactChangeError(
      "Cargo native build artifact changed before digest verification.",
      "before-digest", sourcePath, {
        expected: expectedIdentity, before,
        identities: [["expected-to-before", expectedIdentity, before]],
      },
    );
  }
  const descriptor = openSync(
    sourcePath,
    constants.O_RDONLY |
      (constants.O_NOFOLLOW ?? 0) |
      (constants.O_CLOEXEC ?? 0),
  );
  const digest = createHash("sha256");
  let total = 0n;
  let openedBefore;
  let openedAfter;
  try {
    openedBefore = fstatSync(descriptor, { bigint: true });
    if (
      !openedBefore.isFile() ||
      openedBefore.isSymbolicLink() ||
      openedBefore.nlink < 1n ||
      !sameOutputIdentity(before, openedBefore)
    ) {
      throw artifactChangeError(
        "Cargo native build artifact changed while it was opened.",
        "opened", sourcePath,
        {
          expected: expectedIdentity, before, openedBefore, bytesRead: total,
          identities: [["before-to-opened", before, openedBefore]],
        },
      );
    }
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let bytesRead;
    do {
      bytesRead = readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead > 0) {
        digest.update(buffer.subarray(0, bytesRead));
        total += BigInt(bytesRead);
      }
    } while (bytesRead > 0);
    openedAfter = fstatSync(descriptor, { bigint: true });
  } finally {
    closeSync(descriptor);
  }
  const after = cargoArtifactSourceIdentity(sourcePath);
  if (
    openedAfter === undefined ||
    total !== before.size ||
    !sameOutputIdentity(before, openedAfter) ||
    !sameOutputIdentity(before, after)
  ) {
    throw artifactChangeError(
      "Cargo native build artifact changed during digest verification.",
      "after-digest", sourcePath,
      {
        expected: expectedIdentity, before, openedBefore, openedAfter,
        atPath: after, bytesRead: total, checkByteCount: true,
        identities: [
          ["before-to-opened-after", before, openedAfter],
          ["before-to-path-after", before, after],
        ],
      },
    );
  }
  return Object.freeze({
    identity: before,
    sha256: digest.digest("hex"),
  });
}

function sealCargoArtifactInPlace(nativePath, expectedIdentity, assertDirectories) {
  assertDirectories();
  const sourceBefore = digestCargoArtifactSource(nativePath, expectedIdentity);
  const temporaryPath = join(
    dirname(nativePath),
    "." +
      basename(nativePath) +
      ".authenticated-" +
      process.pid +
      "-" +
      randomUUID(),
  );
  let renamed = false;
  try {
    assertDirectories();
    copyFileSync(nativePath, temporaryPath, constants.COPYFILE_EXCL);
    assertDirectories();
    const sourceAfter = digestCargoArtifactSource(
      nativePath,
      sourceBefore.identity,
    );
    const temporarySeal = readStableRegularFileDigest(temporaryPath, {
      label: "Native build authenticated output",
      requireNonempty: true,
    });
    if (
      sourceAfter.sha256 !== sourceBefore.sha256 ||
      temporarySeal.sha256 !== sourceBefore.sha256
    ) {
      throw artifactChangeError(
        "Cargo native build artifact changed while it was authenticated.",
        "copied", nativePath,
        {
          expected: sourceBefore.identity, before: sourceAfter.identity,
          atPath: temporarySeal.identity,
          digests: [
            ["source-before-to-after-copy", sourceBefore.sha256, sourceAfter.sha256],
            ["source-to-staged-copy", sourceBefore.sha256, temporarySeal.sha256],
          ],
        },
      );
    }
    assertDirectories();
    const stagedBeforeRename = cargoArtifactSourceIdentity(temporaryPath);
    const sourceBeforeRename = cargoArtifactSourceIdentity(nativePath);
    if (
      !sameOutputIdentity(temporarySeal.identity, stagedBeforeRename) ||
      !sameOutputIdentity(sourceBefore.identity, sourceBeforeRename)
    ) {
      throw artifactChangeError(
        "Native build artifact identity changed before publication.",
        "before-rename", nativePath,
        {
          expected: sourceBefore.identity, before: sourceBeforeRename,
          openedBefore: temporarySeal.identity, atPath: stagedBeforeRename,
          identities: [
            ["source-seal-to-before-rename", sourceBefore.identity, sourceBeforeRename],
            ["staged-seal-to-before-rename", temporarySeal.identity, stagedBeforeRename],
          ],
        },
      );
    }
    renameSync(temporaryPath, nativePath);
    renamed = true;
    assertDirectories();
    syncDirectory(dirname(nativePath));
    const finalSeal = readStableRegularFileDigest(nativePath, {
      label: "Native build authenticated output",
      requireNonempty: true,
    });
    if (
      finalSeal.sha256 !== sourceBefore.sha256 ||
      !sameRenamedOutputIdentity(temporarySeal.identity, finalSeal.identity)
    ) {
      throw artifactChangeError(
        "Native build authenticated output changed during publication.",
        "after-rename", nativePath,
        {
          expected: temporarySeal.identity, atPath: finalSeal.identity,
          identities: [["staged-to-published", temporarySeal.identity, finalSeal.identity, { afterRename: true }]],
          digests: [["source-to-published", sourceBefore.sha256, finalSeal.sha256]],
        },
      );
    }
    assertDirectories();
    return finalSeal;
  } finally {
    if (!renamed) {
      // Do not follow a replaced profile directory during failure cleanup.
      assertDirectories();
      rmSync(temporaryPath, { force: true });
    }
  }
}

function sameSourceState(left, right) {
  return (
    left?.sourceGitRevision === right?.sourceGitRevision &&
    left?.sourceTreeClean === right?.sourceTreeClean &&
    left?.sourceTreeSha256 === right?.sourceTreeSha256
  );
}

function readGeneratedProvenance(nativePath, expectedBytes, expectedIdentity) {
  const receipt = readStableRegularFile(nativeBuildProvenancePath(nativePath), {
    label: "Native build generated provenance",
    maximumBytes: expectedBytes.length,
    requireNonempty: true,
  });
  if (
    !receipt.bytes.equals(expectedBytes) ||
    (expectedIdentity !== undefined &&
      !sameOutputIdentity(expectedIdentity, receipt.identity))
  ) {
    throw new Error("Native build generated provenance changed after publication.");
  }
  return receipt;
}

function verifyFinalPublication(nativePath, sealedOutput, expectedBytes, receiptIdentity, assertDirectories) {
  assertDirectories();
  readGeneratedProvenance(nativePath, expectedBytes, receiptIdentity);
  assertDirectories();
  // The saved seal is already the published inode. No rename exception applies.
  const finalOutput = digestCargoArtifactSource(nativePath, sealedOutput.identity);
  if (finalOutput.sha256 !== sealedOutput.sha256) {
    throw artifactChangeError(
      "Native build authenticated output digest changed after provenance publication.",
      "final-publication", nativePath, {
        expected: sealedOutput.identity, atPath: finalOutput.identity,
        digests: [["sealed-to-final", sealedOutput.sha256, finalOutput.sha256]],
      },
    );
  }
  assertDirectories();
  readGeneratedProvenance(nativePath, expectedBytes, receiptIdentity);
  const finalIdentity = cargoArtifactSourceIdentity(nativePath);
  if (!sameOutputIdentity(sealedOutput.identity, finalIdentity)) {
    throw artifactChangeError(
      "Native build authenticated output identity changed during the final provenance check.",
      "final-publication", nativePath, {
        expected: sealedOutput.identity, atPath: finalIdentity,
        identities: [["sealed-to-final-path", sealedOutput.identity, finalIdentity]],
      },
    );
  }
  assertDirectories();
}

function releaseProfileRequiresCleanSource(cargoProfile, sourceState) {
  if (cargoProfile !== "debug" && sourceState.sourceTreeClean !== true) {
    throw new Error(
      "Native release and deploy builds require an exactly clean source tree.",
    );
  }
}

export function runNativeBuild({
  repoRoot = defaultRepoRoot,
  env = process.env,
  platform = process.platform,
  runTool = spawnSync,
  runCargo = (
    cargoPath,
    args,
    { cwd, cargoEnv },
  ) =>
    spawnSync(cargoPath, args, {
      cwd,
      encoding: "utf8",
      env: cargoEnv,
      maxBuffer: MAX_CARGO_JSON_BYTES,
      stdio: ["inherit", "pipe", "inherit"],
    }),
  readSourceState = readNativeBuildSourceState,
  createProvenance = createNativeBuildProvenance,
  invalidateProvenance = invalidateNativeBuildProvenance,
  writeProvenance = writeNativeBuildProvenance,
  newAttemptId = randomUUID,
} = {}) {
  assertCargoProfileEnvironment(env);
  validateRequiredEnvironment(env);
  const cargoProfile = resolveNativeBuildProfile(env);
  const root = canonicalRepoRoot(repoRoot);
  const inputs = canonicalBuildInputs(root, env);
  const executables = validatePinnedExecutables(root, env, runTool);
  const macosBuild = platform === "darwin"
    ? macosBuildIdentity(root, env, runTool) : undefined;
  const target = canonicalTargetRoot(root, env);
  const sourceBefore = readSourceState(root, { env });
  const namespacePath = nativeBuildNamespace({
    repoRoot: root, cargoProfile, env, platform, sourceState: sourceBefore,
  });
  const namespace = canonicalDirectory(namespacePath, "Native build namespace", { create: true });
  const attempt = selectBuildAttempt(namespacePath, {
    cargoProfile, platform, repoRoot: root, sourceState: sourceBefore, newAttemptId,
  });
  const sourceTarget = canonicalDirectory(attempt.target, "Native build source target directory");
  const nativePath = join(attempt.target, cargoProfile, nativeFilename(platform));
  const profileDirectory = canonicalDirectory(
    dirname(nativePath),
    "Native build Cargo profile directory",
    { create: true },
  );
  if (profileDirectory.canonicalPath !== dirname(nativePath)) {
    throw new Error("Native build Cargo profile directory is not canonical.");
  }
  const assertDirectories = () => {
    assertDirectoryIdentity(target, "Native build Cargo target directory");
    assertDirectoryIdentity(namespace, "Native build namespace");
    assertDirectoryIdentity(sourceTarget, "Native build source target directory");
    assertDirectoryIdentity(profileDirectory, "Native build Cargo profile directory");
  };

  const suppliedRevision = env.IROHA_GIT_COMMIT_HASH;
  if (
    suppliedRevision !== undefined &&
    suppliedRevision !== sourceBefore.sourceGitRevision
  ) {
    throw new Error(
      "IROHA_GIT_COMMIT_HASH does not match the authenticated build source.",
    );
  }
  releaseProfileRequiresCleanSource(cargoProfile, sourceBefore);

  assertDirectories();
  const outputBefore = cargoArtifactIdentityOrNull(nativePath);
  invalidateProvenance(nativePath);
  // Stock Cargo resolves this authenticated root manifest to its exact root lock.
  // --locked rejects dependency drift; no alternate lock or unstable flag is admitted.
  const buildArgs = [
    platform === "darwin" ? "rustc" : "build",
    "--locked",
    "--offline",
    "--jobs",
    "1",
    "--manifest-path",
    inputs.cargoManifest,
    "--package",
    INTENDED_PACKAGE,
    "--lib",
    "--target-dir",
    sourceTarget.canonicalPath,
    "--message-format=json-render-diagnostics",
    ...cargoBuildArgsForNativeProfile(cargoProfile),
    // rustc's debug-info stripping can leave a misaligned Mach-O LINKEDIT
    // string pool that dyld refuses to load. Override only the final addon;
    // dependency profiles and the authenticated toolchain remain unchanged.
    ...(platform === "darwin" ? ["--", "-C", "strip=none"] : []),
  ];
  const cargoEnv = {
    ...(macosBuild === undefined ? env : macosCargoEnvironment(env, macosBuild)),
    CARGO: executables.cargoPath,
    CARGO_TARGET_DIR: sourceTarget.canonicalPath,
    [NATIVE_BUILD_CARGO_LOCK_ENV]: inputs.cargoLock,
    IROHA_GIT_COMMIT_HASH: sourceBefore.sourceGitRevision,
    RUSTC: executables.rustcPath,
    RUSTDOC: executables.rustdocPath,
  };
  assertDirectories();
  const build = runCargo(executables.cargoPath, buildArgs, {
    cargoEnv,
    cwd: root,
  });
  assertDirectories();
  // Preserve the actual compiler stream, including failed builds. A later
  // mutable target directory is not evidence of the dependencies used here.
  const compilerLogPath = join(profileDirectory.canonicalPath,
    "iroha-js-cargo-" + randomUUID() + ".jsonl");
  const compilerBytes = Buffer.from(build?.stdout ?? "", "utf8");
  writeFileSync(compilerLogPath, compilerBytes, { flag: "wx", mode: 0o600 });
  forwardCargoRenderedDiagnostics(build?.stdout);
  if (build?.error !== undefined) {
    throw new Error(
      "Cargo could not be executed: " +
        (build.error?.message ?? String(build.error)),
    );
  }
  if (build?.status !== 0) return build?.status ?? 1;
  if (macosBuild !== undefined &&
      JSON.stringify(macosBuildIdentity(root, env, runTool)) !== JSON.stringify(macosBuild)) {
    throw new Error("Native build macOS SDK or Apple toolchain changed while Cargo was running.");
  }

  const artifact = verifyCargoArtifactMessages(build.stdout, {
    cargoProfile,
    nativePath,
    repoRoot: root,
  });
  const localArtifacts = verifyCargoDependencyArtifacts(build.stdout, {
    repoRoot: root,
    targetRoot: sourceTarget.canonicalPath,
    nativePath,
  });
  for (const dependency of localArtifacts.filter(({ fresh }) => fresh)) {
    for (const filename of dependency.filenames) {
      const previous = attempt.previous?.local_files.find(({ path }) => path === filename);
      if (previous === undefined || digestCargoArtifactSource(filename).sha256 !== previous.sha256) {
        throw new Error("Cargo reused a local artifact without a matching completed dependency receipt.");
      }
    }
  }
  const outputAfterCargo = cargoArtifactSourceIdentity(nativePath);
  if (
    artifact.fresh === false &&
    outputBefore !== null &&
    sameOutputIdentity(outputBefore, outputAfterCargo)
  ) {
    throw new Error(
      "A non-fresh Cargo artifact did not update the native output.",
    );
  }

  const sealedOutput = sealCargoArtifactInPlace(
    nativePath, outputAfterCargo, assertDirectories,
  );
  assertDirectories();
  const sourceAfter = readSourceState(root, { env });
  const provenance = createProvenance({
    cargoProfile,
    macosBuild,
    nativePath,
    sourceBefore,
    sourceAfter,
  });
  if (nativeBuildNamespace({ repoRoot: root, cargoProfile, env, platform,
    sourceState: sourceAfter }) !== namespacePath) {
    throw new Error("Native build toolchain or input namespace changed while Cargo was running.");
  }
  if (provenance.native_sha256 !== sealedOutput.sha256) {
    throw new Error(
      "Native build provenance does not match the authenticated output.",
    );
  }
  const expectedReceiptBytes = Buffer.from(`${JSON.stringify(provenance, null, 2)}\n`, "utf8");
  const localFiles = [...new Set(localArtifacts.flatMap(({ filenames }) => filenames))]
    .sort().map((path) => ({ path, sha256: path === nativePath
      ? sealedOutput.sha256 : digestCargoArtifactSource(path).sha256 }));
  const dependencyReceipt = {
    version: 1,
    repo_root: root,
    target_root: sourceTarget.canonicalPath,
    source: sourceAfter,
    native_path: nativePath,
    native_sha256: sealedOutput.sha256,
    compiler_log_sha256: createHash("sha256").update(compilerBytes).digest("hex"),
    local_artifacts: localArtifacts,
    local_files: localFiles,
  };
  try {
    assertDirectories();
    writeProvenance(nativePath, provenance);
    assertDirectories();
    const publishedReceipt = readGeneratedProvenance(nativePath, expectedReceiptBytes);
    assertDirectories();
    const sourceAfterPublication = readSourceState(root, { env });
    assertDirectories();
    if (!sameSourceState(sourceAfter, sourceAfterPublication)) {
      throw new Error(
        "Native build source changed while provenance was published.",
      );
    }
    if (nativeBuildNamespace({ repoRoot: root, cargoProfile, env, platform,
      sourceState: sourceAfterPublication }) !== namespacePath) {
      throw new Error("Native build toolchain or input namespace changed during publication.");
    }
    if (macosBuild !== undefined &&
        JSON.stringify(macosBuildIdentity(root, env, runTool)) !== JSON.stringify(macosBuild)) {
      throw new Error("Native build macOS SDK or Apple toolchain changed during publication.");
    }
    verifyFinalPublication(
      nativePath, sealedOutput, expectedReceiptBytes, publishedReceipt.identity, assertDirectories,
    );
    const compilerLog = readStableRegularFileDigest(compilerLogPath, {
      label: "Retained Cargo compiler stream", maximumBytes: MAX_CARGO_JSON_BYTES,
    });
    if (compilerLog.sha256 !== dependencyReceipt.compiler_log_sha256) {
      throw new Error("Retained Cargo compiler stream changed before publication.");
    }
    writeFileSync(compilerLogPath + ".inputs.json", JSON.stringify(dependencyReceipt, null, 2) + "\n",
      { flag: "wx", mode: 0o600 });
    const dependencyReceiptHash = readStableRegularFileDigest(compilerLogPath + ".inputs.json", {
      label: "Completed dependency receipt", maximumBytes: MAX_CARGO_JSON_BYTES,
    }).sha256;
    const owner = readStableRegularFile(attempt.ownerPath, {
      label: "Native build attempt owner", maximumBytes: 1024,
    });
    if (!owner.bytes.equals(attempt.owner)) throw new Error("Native build attempt owner changed.");
    assertDirectories();
    rmSync(attempt.ownerPath);
    const completed = Buffer.from(JSON.stringify({ version: 1, attempt_id: basename(attempt.target),
      receipt: basename(compilerLogPath) + ".inputs.json", receipt_sha256: dependencyReceiptHash }) + "\n");
    const pending = join(namespacePath, ".completed-" + randomUUID());
    writeFileSync(pending, completed, { flag: "wx", mode: 0o600 });
    assertDirectories();
    renameSync(pending, join(namespacePath, "completed.json"));
    syncDirectory(namespacePath);
  } catch (error) {
    assertDirectories();
    invalidateProvenance(nativePath);
    throw error;
  }
  return 0;
}

if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  process.exitCode = runNativeBuild();
}
