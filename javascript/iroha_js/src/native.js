import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fsyncSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";

import {
  machOSigningIndependentSHA256,
  peSigningIndependentSHA256,
} from "./nativeArtifactHash.js";

const NATIVE_FILENAME = "iroha_js_host.node";
const CHECKSUM_FILENAME = "iroha_js_host.checksums.json";
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const PLATFORM_KEY_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)+$/u;
const PE_DOS_HEADER_BYTES = 64;
const NATIVE_BUILD_SOURCE_STATE_READER = "read-native-build-source-state.mjs";
const LOCAL_UNIT_MANIFEST = "iroha_js_host.local-unit.json";
const LOCAL_UNIT_SCHEMA = "iroha.js-native-local-unit.v1";

let cachedBinding;
let cachedBindingPath;
let cachedSnapshotDir;
const ownedSnapshotDirectories = new Set();

function nativeBindingError(reason, status = "unknown") {
  const error = new Error(`Native binding required; ${reason}`);
  Object.defineProperties(error, {
    code: {
      value: "ERR_IROHA_NATIVE_BINDING",
      enumerable: true,
    },
    nativeStatus: {
      value: status,
      enumerable: true,
    },
  });
  return error;
}

function nativeSetupHint(paths) {
  return existsSync(join(paths.jsRoot, "scripts", "build-native.mjs"))
    ? "run `npm run build:native`"
    : "set `IROHA_JS_NATIVE_DIR` to a directory containing a separately built binding and checksum manifest";
}

function formatForceNativeVerificationError(verification, paths) {
  switch (verification.status) {
    case "missing_file":
      return nativeBindingError(
        `binding missing at ${paths.bindingPath}; ${nativeSetupHint(paths)}.`,
        verification.status,
      );
    case "manifest_error":
      return nativeBindingError(
        `checksum manifest at ${paths.checksumPath} is invalid or unreadable: ${
          verification.error?.message ?? verification.error
        }.`,
        verification.status,
      );
    case "missing_manifest":
    case "missing_expected_entry":
      return nativeBindingError(
        `checksum manifest missing entries for ${verification.platform}; ${nativeSetupHint(paths)}.`,
        verification.status,
      );
    case "hash_mismatch":
      return nativeBindingError(
        `checksum mismatch for ${paths.bindingPath}; expected ${verification.expectedSha256}, found ${verification.sha256}.`,
        verification.status,
      );
    case "hash_error":
    default:
      return nativeBindingError(
        `verification failed (${verification.status}).`,
        verification.status,
      );
  }
}

export function nativeSourceProvenanceMatches(
  verification,
  currentSource,
) {
  if (
    typeof verification?.sourceGitRevision !== "string" ||
    typeof verification?.sourceTreeSha256 !== "string"
  ) {
    return false;
  }
  if (verification.sourceTreeClean === true) return true;
  return (
    verification.sourceTreeClean === false &&
    verification.cargoProfile === "debug" &&
    currentSource?.sourceTreeClean === false &&
    currentSource.sourceGitRevision === verification.sourceGitRevision &&
    currentSource.sourceTreeSha256 === verification.sourceTreeSha256
  );
}

function assertLoadableSourceProvenance(verification, paths) {
  if (verification.sourceTreeClean === true) return;
  try {
    const repoRoot = resolve(paths.jsRoot, "..", "..");
    execFileSync(
      process.execPath,
      [
        join(paths.jsRoot, "scripts", NATIVE_BUILD_SOURCE_STATE_READER),
        "--verify",
        repoRoot,
        JSON.stringify({
          cargoProfile: verification.cargoProfile,
          sourceGitRevision: verification.sourceGitRevision,
          sourceTreeClean: verification.sourceTreeClean,
          sourceTreeSha256: verification.sourceTreeSha256,
        }),
      ],
      {
        env: {
          ...process.env,
          NODE_OPTIONS: "",
          // Electron's execPath is an application (or renderer helper). Run
          // this verifier as Node, never as another GUI or renderer process.
          ...(process.versions.electron ? { ELECTRON_RUN_AS_NODE: "1" } : {}),
        },
        maxBuffer: 16 * 1024,
        timeout: 15_000,
      },
    );
    return;
  } catch {
    throw nativeBindingError(
      `dirty source tree from ${paths.bindingPath} does not match current SDK source.`,
      "source_provenance_error",
    );
  }
}

function verifyLocalUnitBinding(paths) {
  try {
    const output = paths.nativeDir;
    const root = resolve(paths.jsRoot, "..", "..");
    if (!paths.hasOverride || realpathSync(output) !== output ||
        !output.startsWith(join(root, "target", "qualification") + "/") ||
        !existsSync(join(root, "Cargo.toml"))) {
      throw new Error("local-unit binding requires the current source checkout and canonical target/qualification child");
    }
    const readOriginal = (path, limit) => {
      const stat = lstatSync(path);
      if (realpathSync(path) !== path || !stat.isFile() || stat.size < 1 || stat.size > limit) {
        throw new Error("local-unit record is not a bounded original regular file");
      }
      return readFileSync(path);
    };
    const manifest = JSON.parse(readOriginal(join(output, LOCAL_UNIT_MANIFEST), 16 * 1024).toString("utf8"));
    if (Object.keys(manifest).sort().join(",") !==
        "artifact_scope,artifact_sha256,build_provenance_version,cargo_profile,platform,producer_record_sha256,schema,source_root" ||
        manifest.schema !== LOCAL_UNIT_SCHEMA || manifest.artifact_scope !== "local-unit" ||
        manifest.build_provenance_version !== 4 || manifest.cargo_profile !== "debug" ||
        manifest.platform !== `${process.platform}-${process.arch}` || manifest.source_root !== root ||
        !SHA256_PATTERN.test(manifest.producer_record_sha256) || !SHA256_PATTERN.test(manifest.artifact_sha256)) {
      throw new Error("local-unit manifest scope/profile/platform/source is not exact");
    }
    const producerPath = join(output, "producer-record.json");
    const producerBytes = readOriginal(producerPath, 64 * 1024 * 1024);
    if (createHash("sha256").update(producerBytes).digest("hex") !== manifest.producer_record_sha256) {
      throw new Error("local-unit producer record differs from its pin");
    }
    const producer = JSON.parse(producerBytes.toString("utf8"));
    const candidates = ["/opt/homebrew/opt/python@3.12/bin/python3.12", "/usr/local/opt/python@3.12/bin/python3.12"];
    const python = candidates.filter((path) => existsSync(path))
      .map((path) => realpathSync(path)).find((path) => path === producer.config?.python);
    const verifier = join(root, "scripts", "native_js_local_unit.py");
    if (!python || producer.tools?.[python] !== createHash("sha256").update(readFileSync(python)).digest("hex") ||
        producer.tools?.[verifier] !== createHash("sha256").update(readFileSync(verifier)).digest("hex")) {
      throw new Error("local-unit Python/repository verifier differs from current fixed owners");
    }
    const result = JSON.parse(execFileSync(python, ["-I", "-S", "-B", verifier, "verify",
      "--root", root, "--output", output, "--producer-sha256", manifest.producer_record_sha256], {
      cwd: root,
      env: { PATH: "/usr/bin:/bin", HOME: process.env.HOME, LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
      encoding: "utf8", maxBuffer: 16 * 1024, timeout: 60_000,
    }));
    if (result.schema !== LOCAL_UNIT_SCHEMA || result.artifact_scope !== "local-unit" ||
        result.build_provenance_version !== 4 || result.verified !== true ||
        result.artifact_path !== paths.bindingPath || result.artifact_sha256 !== manifest.artifact_sha256) {
      throw new Error("local-unit verifier returned a different binding or scope");
    }
    const hash = hashFile(paths.bindingPath, true);
    if (!hash.ok || hash.sha256 !== result.artifact_sha256) {
      throw new Error("local-unit verified native bytes changed before snapshot");
    }
    return { ok: true, sha256: hash.sha256, verifiedBytes: hash.bytes };
  } catch (error) {
    throw nativeBindingError(`local-unit custody verification failed: ${error?.message ?? error}.`, "local_unit_provenance_error");
  }
}

/**
 * Load the required native `iroha_js_host` binding.
 */
export function getNativeBinding() {
  const paths = resolveNativePaths();
  if (cachedBindingPath !== paths.bindingPath) {
    cachedBinding = undefined;
    cleanupSnapshotDirectory(cachedSnapshotDir);
    cachedSnapshotDir = undefined;
  }
  if (cachedBinding !== undefined) {
    return cachedBinding;
  }

  const localUnit = existsSync(join(paths.nativeDir, LOCAL_UNIT_MANIFEST));
  const verification = localUnit ? verifyLocalUnitBinding(paths) : verifyNativeBindingInternal(
    paths.bindingPath, { manifestPath: paths.checksumPath }, true,
  );
  if (!verification.ok) {
    throw formatForceNativeVerificationError(verification, paths);
  }
  if (!localUnit) assertLoadableSourceProvenance(verification, paths);

  let snapshot;
  try {
    snapshot = materializeVerifiedSnapshot(verification);
    const require = createRequire(import.meta.url);
    cachedBinding = require(snapshot.path);
  } catch (error) {
    cleanupSnapshotDirectory(snapshot?.directory);
    throw nativeBindingError(
      `failed to load verified binding from ${paths.bindingPath}: ${error?.message ?? error}.`,
      "load_error",
    );
  }
  cachedBindingPath = paths.bindingPath;
  cachedSnapshotDir = snapshot.directory;
  return cachedBinding;
}

/** Verify a native binding against the checksum manifest. */
export function verifyNativeBinding(
  bindingPath,
  options = {},
) {
  return verifyNativeBindingInternal(bindingPath, options, false);
}

function verifyNativeBindingInternal(
  bindingPath,
  { manifestPath, expectedChecksums, platformKey } = {},
  retainBytes,
) {
  if (!existsSync(bindingPath)) {
    return {
      ok: false,
      status: "missing_file",
      path: bindingPath,
      manifestPath,
    };
  }

  const hash = hashFile(bindingPath, retainBytes);
  if (!hash.ok) {
    return {
      ok: false,
      status: "hash_error",
      path: bindingPath,
      manifestPath,
      error: hash.error,
    };
  }

  const platform = platformKey ?? `${process.platform}-${process.arch}`;
  const checksumEntries =
    expectedChecksums === undefined
      ? loadChecksumEntries(manifestPath ?? resolveNativePaths().checksumPath)
      : normalizeExpectedChecksums(expectedChecksums);

  if (checksumEntries.error) {
    return {
      ok: false,
      status: "manifest_error",
      path: bindingPath,
      manifestPath,
      platform,
      sha256: hash.sha256,
      error: checksumEntries.error,
    };
  }

  if (!checksumEntries.entries) {
    return {
      ok: false,
      status: "missing_manifest",
      path: bindingPath,
      manifestPath,
      platform,
      sha256: hash.sha256,
    };
  }

  if (
    typeof platform !== "string" ||
    !PLATFORM_KEY_PATTERN.test(platform) ||
    platform !== platform.toLowerCase()
  ) {
    return {
      ok: false,
      status: "manifest_error",
      path: bindingPath,
      manifestPath,
      platform,
      sha256: hash.sha256,
      error: new TypeError(
        "native platform key must be a canonical lowercase platform-architecture pair",
      ),
    };
  }
  const entries = checksumEntries.entries;
  if (!Object.hasOwn(entries, platform)) {
    return {
      ok: false,
      status: "missing_expected_entry",
      path: bindingPath,
      manifestPath,
      platform,
      sha256: hash.sha256,
    };
  }
  const expectedEntry = entries[platform];
  const expectedSha256 = expectedEntry?.sha256;
  const expectedMachOSigningIndependentSha256 =
    expectedEntry?.mach_o_signing_independent_sha256;
  const expectedCargoProfile = expectedEntry?.cargo_profile;
  const expectedPeSigningIndependentSha256 =
    expectedEntry?.pe_signing_independent_sha256;
  const expectedPeUnsignedSize = expectedEntry?.pe_unsigned_size;
  const expectedSourceGitRevision = expectedEntry?.source_git_revision;
  const expectedSourceTreeClean = expectedEntry?.source_tree_clean;
  const expectedSourceTreeSha256 = expectedEntry?.source_tree_sha256;
  const expectedBuildExecutionPolicy = expectedEntry?.build_execution_policy;
  const expectedBuildProvenanceVersion = expectedEntry?.build_provenance_version;
  const expectedMacosBuild = expectedEntry?.macos_build;
  if (!validChecksumEntry(expectedEntry, platform)) {
    return {
      ok: false,
      status: "manifest_error",
      path: bindingPath,
      manifestPath,
      platform,
      sha256: hash.sha256,
      error: new TypeError(
        `checksum entry for ${platform} has an invalid platform checksum profile`,
      ),
    };
  }

  let verificationStatus = "verified";
  let machOSigningIndependentSha256;
  let peSigningIndependentSha256;
  if (expectedSha256 !== hash.sha256 && platform.startsWith("darwin-")) {
    try {
      machOSigningIndependentSha256 = machOSigningIndependentSHA256(hash.fileBytes);
    } catch (error) {
      return {
        ok: false,
        status: "hash_error",
        path: bindingPath,
        manifestPath,
        platform,
        sha256: hash.sha256,
        expectedSha256,
        error,
      };
    }
    if (machOSigningIndependentSha256 === expectedMachOSigningIndependentSha256) {
      verificationStatus = "verified_resigned_macho";
    }
  }

  if (
    expectedSha256 !== hash.sha256 &&
    platform.startsWith("win32-") &&
    typeof expectedPeSigningIndependentSha256 === "string"
  ) {
    try {
      peSigningIndependentSha256 = peSigningIndependentSHA256(
        hash.fileBytes,
        expectedPeUnsignedSize,
        { requireSigned: true },
      );
    } catch (error) {
      return {
        ok: false,
        status: "hash_error",
        path: bindingPath,
        manifestPath,
        platform,
        sha256: hash.sha256,
        expectedSha256,
        error,
      };
    }
    if (peSigningIndependentSha256 === expectedPeSigningIndependentSha256) {
      verificationStatus = "verified_resigned_pe";
    }
  }

  if (
    expectedSha256 !== hash.sha256 &&
    verificationStatus !== "verified_resigned_macho" &&
    verificationStatus !== "verified_resigned_pe"
  ) {
    return {
      ok: false,
      status: "hash_mismatch",
      path: bindingPath,
      manifestPath,
      platform,
      sha256: hash.sha256,
      expectedSha256,
    };
  }

  const result = {
    ok: true,
    status: verificationStatus,
    path: bindingPath,
    manifestPath,
    platform,
    sha256: hash.sha256,
    expectedSha256,
    ...(expectedCargoProfile === undefined
      ? {}
      : { cargoProfile: expectedCargoProfile }),
    ...(expectedMachOSigningIndependentSha256 === undefined
      ? {}
      : { expectedMachOSigningIndependentSha256 }),
    ...(machOSigningIndependentSha256 === undefined
      ? {}
      : {
          machOSigningIndependentSha256,
          expectedMachOSigningIndependentSha256,
        }),
    ...(expectedPeSigningIndependentSha256 === undefined
      ? {}
      : {
          expectedPeSigningIndependentSha256,
          expectedPeUnsignedSize,
        }),
    ...(peSigningIndependentSha256 === undefined
      ? {}
      : {
          peSigningIndependentSha256,
          expectedPeSigningIndependentSha256,
          expectedPeUnsignedSize,
        }),
    ...(expectedSourceGitRevision === undefined
      ? {}
      : {
          buildExecutionPolicy: expectedBuildExecutionPolicy,
          buildProvenanceVersion: expectedBuildProvenanceVersion,
          sourceGitRevision: expectedSourceGitRevision,
          sourceTreeClean: expectedSourceTreeClean,
          sourceTreeSha256: expectedSourceTreeSha256,
          ...(expectedMacosBuild === undefined ? {} : { macosBuild: expectedMacosBuild }),
        }),
  };
  if (retainBytes) {
    result.verifiedBytes = hash.bytes;
  }
  return result;
}

/**
 * Materialize a verified snapshot while a test replaces the original path.
 * @internal
 */
export function __snapshotNativeBindingForTests(
  bindingPath,
  options = {},
  afterVerification,
) {
  const verification = verifyNativeBindingInternal(bindingPath, options, true);
  if (!verification.ok) {
    return verification;
  }
  if (afterVerification !== undefined) {
    if (typeof afterVerification !== "function") {
      throw new TypeError("afterVerification must be a function");
    }
    afterVerification();
  }
  const snapshot = materializeVerifiedSnapshot(verification);
  return {
    ok: true,
    status: "snapshotted",
    sha256: verification.sha256,
    path: snapshot.path,
    directory: snapshot.directory,
  };
}

/**
 * Reset cached native state (test helper).
 * @internal
 */
export function __resetNativeStateForTests() {
  cachedBinding = undefined;
  cachedBindingPath = undefined;
  cleanupSnapshotDirectory(cachedSnapshotDir);
  cachedSnapshotDir = undefined;
}

function materializeVerifiedSnapshot(verification) {
  if (!Buffer.isBuffer(verification.verifiedBytes)) {
    throw new TypeError("verified native bytes are unavailable");
  }
  const directory = mkdtempSync(join(tmpdir(), "iroha-js-host-"));
  if (ownedSnapshotDirectories.size === 0) {
    process.once("exit", cleanupOwnedSnapshots);
  }
  ownedSnapshotDirectories.add(directory);
  let descriptor;
  try {
    if (process.platform !== "win32") {
      chmodSync(directory, 0o700);
    }
    const path = join(directory, `${verification.sha256}.node`);
    const noFollow = constants.O_NOFOLLOW ?? 0;
    descriptor = openSync(
      path,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollow,
      0o500,
    );
    writeFileSync(descriptor, verification.verifiedBytes);
    fsyncSync(descriptor);
    if (process.platform !== "win32") {
      fchmodSync(descriptor, 0o500);
    }
    closeSync(descriptor);
    descriptor = undefined;

    const metadata = lstatSync(path);
    if (
      !metadata.isFile() ||
      metadata.size !== verification.verifiedBytes.byteLength
    ) {
      throw new Error("verified native snapshot is not the expected regular file");
    }
    const finalHash = hashFile(path, false);
    if (!finalHash.ok || finalHash.sha256 !== verification.sha256) {
      throw new Error("verified native snapshot changed before module loading");
    }
    return { path, directory };
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // The primary snapshot error remains authoritative.
      }
    }
    cleanupSnapshotDirectory(directory);
    throw error;
  }
}

function cleanupOwnedSnapshots() {
  for (const directory of ownedSnapshotDirectories) {
    cleanupSnapshotDirectory(directory);
  }
}

function cleanupSnapshotDirectory(directory) {
  if (!directory) {
    return;
  }
  try {
    rmSync(directory, { recursive: true, force: true });
    ownedSnapshotDirectories.delete(directory);
    if (ownedSnapshotDirectories.size === 0) {
      process.removeListener("exit", cleanupOwnedSnapshots);
    }
  } catch {
    // Keep failed removals for a final synchronous retry at normal process exit.
    // Windows can still lock a mapped addon then; cleanup remains best effort.
  }
}

function resolveNativePaths() {
  const baseDir = dirname(fileURLToPath(import.meta.url));
  const jsRoot = resolve(baseDir, "..");
  const nativeDirOverride = process.env.IROHA_JS_NATIVE_DIR;
  const nativeDir = nativeDirOverride ? resolve(nativeDirOverride) : join(jsRoot, "native");
  return {
    bindingPath: join(nativeDir, NATIVE_FILENAME),
    checksumPath: join(nativeDir, CHECKSUM_FILENAME),
    jsRoot,
    nativeDir,
    hasOverride: Boolean(nativeDirOverride),
  };
}

function loadChecksumEntries(manifestPath) {
  if (!manifestPath || !existsSync(manifestPath)) {
    return { entries: null, error: null };
  }

  try {
    const raw = readFileSync(manifestPath, "utf8");
    const parsed = JSON.parse(raw);
    if (
      !isPlainObject(parsed) ||
      Object.keys(parsed).length !== 1 ||
      !isPlainObject(parsed.entries)
    ) {
      throw new TypeError(
        "checksum manifest must be an object containing only an entries object",
      );
    }
    return validateChecksumEntries(parsed.entries);
  } catch (error) {
    return { entries: null, error };
  }
}

function normalizeExpectedChecksums(expectedChecksums) {
  return validateChecksumEntries(expectedChecksums);
}

function validateChecksumEntries(entries) {
  if (!isPlainObject(entries) || Object.keys(entries).length === 0) {
    return {
      entries: null,
      error: new TypeError(
        "checksum entries must be a non-empty platform-entry object",
      ),
    };
  }
  const normalizedKeys = new Set();
  for (const [platform, entry] of Object.entries(entries)) {
    const normalized = platform.toLowerCase();
    if (normalizedKeys.has(normalized)) {
      return {
        entries: null,
        error: new TypeError(
          `checksum entries contain a case-colliding platform key: ${platform}`,
        ),
      };
    }
    normalizedKeys.add(normalized);
    if (platform !== normalized || !PLATFORM_KEY_PATTERN.test(platform)) {
      return {
        entries: null,
        error: new TypeError(
          `checksum platform key must be canonical lowercase: ${platform}`,
        ),
      };
    }
    if (!validChecksumEntry(entry, platform)) {
      return {
        entries: null,
        error: new TypeError(
          `checksum entry for ${platform} has an invalid platform checksum profile`,
        ),
      };
    }
  }
  return { entries, error: null };
}

function validChecksumEntry(entry, platform) {
  if (
    !isPlainObject(entry) ||
    typeof entry.sha256 !== "string" ||
    !SHA256_PATTERN.test(entry.sha256)
  ) {
    return false;
  }
  const allowed = new Set([
    "build_execution_policy",
    "build_provenance_version",
    "cargo_profile",
    "sha256",
    "source_git_revision",
    "source_tree_clean",
    "source_tree_sha256",
  ]);
  const macos = platform.startsWith("darwin-");
  if (macos) allowed.add("macos_build");
  const hasMachO = Object.hasOwn(entry, "mach_o_signing_independent_sha256");
  const hasPeHash = Object.hasOwn(entry, "pe_signing_independent_sha256");
  const hasPeSize = Object.hasOwn(entry, "pe_unsigned_size");
  if (hasMachO) allowed.add("mach_o_signing_independent_sha256");
  if (hasPeHash) allowed.add("pe_signing_independent_sha256");
  if (hasPeSize) allowed.add("pe_unsigned_size");
  if (Object.keys(entry).some((key) => !allowed.has(key))) return false;
  if (
    entry.cargo_profile !== undefined &&
    entry.cargo_profile !== "debug" &&
    entry.cargo_profile !== "release" &&
    entry.cargo_profile !== "deploy"
  ) {
    return false;
  }
  const hasSourceRevision = Object.hasOwn(entry, "source_git_revision");
  const hasSourceClean = Object.hasOwn(entry, "source_tree_clean");
  const hasSourceTreeSha256 = Object.hasOwn(entry, "source_tree_sha256");
  const hasBuildExecutionPolicy = Object.hasOwn(
    entry,
    "build_execution_policy",
  );
  const hasBuildProvenanceVersion = Object.hasOwn(
    entry,
    "build_provenance_version",
  );
  if (
    !hasBuildExecutionPolicy ||
    !hasBuildProvenanceVersion ||
    !hasSourceRevision ||
    !hasSourceClean ||
    !hasSourceTreeSha256 ||
    entry.build_execution_policy !== "trusted-local-cargo-v1" ||
    entry.build_provenance_version !== 4 ||
    (macos && !validMacosBuildIdentity(entry.macos_build)) ||
    typeof entry.source_git_revision !== "string" ||
    !/^[0-9a-f]{40}$/u.test(entry.source_git_revision) ||
    typeof entry.source_tree_clean !== "boolean" ||
    typeof entry.source_tree_sha256 !== "string" ||
    !SHA256_PATTERN.test(entry.source_tree_sha256)
  ) {
    return false;
  }
  if (
    hasMachO &&
    (!platform.startsWith("darwin-") ||
      hasPeHash ||
      hasPeSize ||
      typeof entry.mach_o_signing_independent_sha256 !== "string" ||
      !SHA256_PATTERN.test(entry.mach_o_signing_independent_sha256))
  ) {
    return false;
  }
  if (
    hasPeHash !== hasPeSize ||
    (hasPeHash &&
      (!platform.startsWith("win32-") ||
        hasMachO ||
        typeof entry.pe_signing_independent_sha256 !== "string" ||
        !SHA256_PATTERN.test(entry.pe_signing_independent_sha256) ||
        !Number.isSafeInteger(entry.pe_unsigned_size) ||
        entry.pe_unsigned_size < PE_DOS_HEADER_BYTES))
  ) {
    return false;
  }
  return true;
}

function validMacosBuildIdentity(identity) {
  if (!isPlainObject(identity)) return false;
  const keys = [
    "sdk_root", "sdk_version", "sdk_settings_sha256",
    "deployment_target", "clang_path", "clang_version",
    "linker_path", "linker_version",
  ];
  if (Object.keys(identity).length !== keys.length ||
      keys.some((key) => !Object.hasOwn(identity, key))) return false;
  const version = /^\d+(?:\.\d+){1,2}$/u;
  return [identity.sdk_root, identity.clang_path, identity.linker_path].every(
    (value) => typeof value === "string" && posix.isAbsolute(value) &&
      posix.normalize(value) === value,
  ) &&
    version.test(identity.sdk_version) &&
    SHA256_PATTERN.test(identity.sdk_settings_sha256) &&
    version.test(identity.deployment_target) &&
    typeof identity.clang_version === "string" &&
    identity.clang_version.startsWith("Apple clang version ") &&
    typeof identity.linker_version === "string" &&
    identity.linker_version.startsWith("@(#)PROGRAM:ld PROJECT:ld-");
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hashFile(filePath, retainBytes = false) {
  try {
    const file = readFileSync(filePath);
    const sha256 = createHash("sha256").update(file).digest("hex");
    return {
      ok: true,
      sha256,
      fileBytes: file,
      bytes: retainBytes ? file : undefined,
    };
  } catch (error) {
    return { ok: false, error };
  }
}
