#!/usr/bin/env node
/**
 * Publish the compiled `iroha_js_host` dynamic library as a verified `.node`
 * artifact. Publication is transactional and repeatable on platforms where a
 * rename cannot replace an existing file (notably Windows).
 */
import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyNativeBinding } from "../src/native.js";
import {
  machOSigningIndependentSHA256,
  peSigningIndependentSHA256,
} from "../src/nativeArtifactHash.js";
import {
  acquireDistLock,
  assertDistLockOwnership,
  releaseDistLock,
  syncDirectory,
} from "./build-dist.mjs";
import { resolveNativeBuildProfile } from "./native-build-profile.mjs";
import { nativeBuildOutputPath } from "./build-native.mjs";
import {
  readNativeBuildSourceState,
  readNativeBuildProvenance,
  validateNativeBuildProvenance,
} from "./native-build-provenance.mjs";

const __filename = fileURLToPath(import.meta.url);
const scriptDir = dirname(__filename);
const repoRoot = join(scriptDir, "..", "..", "..");
const NATIVE_FILENAME = "iroha_js_host.node";
const CHECKSUM_FILENAME = "iroha_js_host.checksums.json";
const TRANSACTION_PREFIX = ".iroha-js-host-txn-";
const TRANSACTION_INITIALIZER_PREFIX = ".iroha-js-host-init-txn-v1-";
const TRANSACTION_OWNER_FILENAME = ".iroha-js-host-transaction-owner-v1.json";
const TRANSACTION_OWNER_VERSION = 1;
const CLEANUP_PREFIX = ".iroha-js-host-cleanup-";
const CLEANUP_VERSION = 1;
const CLEANUP_MARKER_SUFFIX = ".owner.json";
const JOURNAL_VERSION = 2;
const MAX_JOURNAL_BYTES = 16 * 1024;
const MAX_TRANSACTION_OWNER_BYTES = 16 * 1024;
const MAX_CLEANUP_MARKER_BYTES = 128 * 1024;
const MAX_CLEANUP_ENTRIES = 32;
const MAX_CHECKSUM_MANIFEST_BYTES = 1024 * 1024;
// A cold debug build derives and validates the complete privacy profile catalog,
// including the ZK-X509 fixed-algebraic schedules, in this subprocess. Keep the
// probe bounded while allowing that fail-closed check to finish unoptimized.
const NATIVE_BINDING_PROBE_TIMEOUT_MS = 120_000;
const UUID_V4_SOURCE =
  "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const UUID_V4_PATTERN = new RegExp(`^${UUID_V4_SOURCE}$`, "u");
const TRANSACTION_DIRECTORY_PATTERN = new RegExp(
  `^${TRANSACTION_PREFIX}(${UUID_V4_SOURCE})$`,
  "u",
);
const TRANSACTION_INITIALIZER_PATTERN = new RegExp(
  `^${TRANSACTION_INITIALIZER_PREFIX}(${UUID_V4_SOURCE})-(${UUID_V4_SOURCE})$`,
  "u",
);
const CLEANUP_DIRECTORY_PATTERN = new RegExp(
  `^${CLEANUP_PREFIX}v1-(${UUID_V4_SOURCE})-(${UUID_V4_SOURCE})$`,
  "u",
);
const CLEANUP_MARKER_PATTERN = new RegExp(
  `^(${CLEANUP_PREFIX}v1-(${UUID_V4_SOURCE})-(${UUID_V4_SOURCE}))\\.owner\\.json$`,
  "u",
);
const CLEANUP_MARKER_TEMP_PATTERN = new RegExp(
  `^(${CLEANUP_PREFIX}v1-(${UUID_V4_SOURCE})-(${UUID_V4_SOURCE}))\\.owner-(${UUID_V4_SOURCE})\\.tmp$`,
  "u",
);
const JOURNAL_PATTERN = /^journal-(\d{6})\.json$/u;
const JOURNAL_TEMP_PATTERN = new RegExp(
  `^\\.journal-(\\d{6})-${UUID_V4_SOURCE}\\.tmp$`,
  "u",
);
const NEXT_NATIVE_FILENAME = `${NATIVE_FILENAME}.next`;
const NEXT_MANIFEST_FILENAME = `${CHECKSUM_FILENAME}.next`;
const PREVIOUS_NATIVE_FILENAME = `${NATIVE_FILENAME}.previous`;
const PREVIOUS_MANIFEST_FILENAME = `${CHECKSUM_FILENAME}.previous`;
const DISCARDED_NATIVE_FILENAME = `${NATIVE_FILENAME}.discarded-next`;
const DISCARDED_MANIFEST_FILENAME = `${CHECKSUM_FILENAME}.discarded-next`;
const TEST_FAILPOINTS = new Set(["after-backup", "after-native", "after-manifest"]);
const JOURNAL_PHASES = Object.freeze([
  "prepared",
  "previous-manifest-moved",
  "previous-native-moved",
  "next-native-moved",
  "next-manifest-moved",
  "published-verified",
  "committed",
]);
const JOURNAL_PHASE_SET = new Set(JOURNAL_PHASES);
const TRANSACTION_ARTIFACT_NAMES = new Set([
  TRANSACTION_OWNER_FILENAME,
  NEXT_NATIVE_FILENAME,
  NEXT_MANIFEST_FILENAME,
  PREVIOUS_NATIVE_FILENAME,
  PREVIOUS_MANIFEST_FILENAME,
  DISCARDED_NATIVE_FILENAME,
  DISCARDED_MANIFEST_FILENAME,
]);

export const REQUIRED_NATIVE_EXPORTS = Object.freeze([
  "accountAddressParseEncoded",
  "accountAddressRender",
  "blockProofsVerifyAuthenticatedV1",
  "connectNoritoBridgeAbiVersion",
  "noritoEncodeInstruction",
  "noritoEncodeInstructionBoxArchive",
  "noritoDecodeInstructionBoxArchive",
  "noritoDecodeInstruction",
  "inspectSorafsOrderbookSubmissionForDiscriminantV1",
  "verifySorafsOrderbookSubmissionReceiptV1",
  "compileKotodama",
  "buildKaigiAuthorizationProofV1",
  "buildKaigiUsageProofV1",
  "privacyCompiledProfileCatalogV1",
  "privacyExact12CapabilityManifestJsonV1",
  "privacyRequireExact12CapabilityTupleV1",
  "privacyValidateCompiledProfileCatalogV1",
  "privacyValidateExact12CapabilityManifestV1",
  "sorafsValidateAppealFinanceCancelAssetLockJson",
  "securePrivateFileAbiVersion",
  "securePrivateDirectoryEnsure",
  "securePrivateFileRead",
  "securePrivateFileWriteAtomic",
]);
export const REQUIRED_NATIVE_BRIDGE_ABI_VERSION = 31;
export const REQUIRED_NATIVE_EXPORT_RESULTS = Object.freeze({
  connectNoritoBridgeAbiVersion: REQUIRED_NATIVE_BRIDGE_ABI_VERSION,
  securePrivateFileAbiVersion: 1,
});

function assertRegularFile(path, label) {
  if (!existsSync(path)) {
    throw new Error(`${label} is missing at ${path}`);
  }
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular non-symbolic-link file: ${path}`);
  }
  return metadata;
}

function assertChecksumManifest(path, label) {
  const metadata = assertRegularFile(path, label);
  if (metadata.size > MAX_CHECKSUM_MANIFEST_BYTES) {
    throw new Error(`${label} exceeds the native checksum manifest size limit`);
  }
  return metadata;
}

function assertDirectory(path, label) {
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular non-symbolic-link directory: ${path}`);
  }
}

function syncFile(path) {
  const descriptor = openSync(path, constants.O_RDONLY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function directoryIdentity(metadata) {
  return Object.freeze({
    birthtimeNs: String(metadata.birthtimeNs),
    dev: String(metadata.dev),
    ino: String(metadata.ino),
  });
}

function fileIdentity(metadata, sha256) {
  return Object.freeze({
    birthtimeNs: String(metadata.birthtimeNs),
    dev: String(metadata.dev),
    ino: String(metadata.ino),
    mtimeNs: String(metadata.mtimeNs),
    sha256,
    size: String(metadata.size),
  });
}

function sameDirectoryIdentity(left, right) {
  return (
    left?.birthtimeNs === right?.birthtimeNs &&
    left?.dev === right?.dev &&
    left?.ino === right?.ino
  );
}

function sameFileIdentity(left, right) {
  return (
    sameDirectoryIdentity(left, right) &&
    left?.mtimeNs === right?.mtimeNs &&
    left?.sha256 === right?.sha256 &&
    left?.size === right?.size
  );
}

function sameFileMetadata(left, right) {
  return (
    left.birthtimeNs === right.birthtimeNs &&
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mtimeNs === right.mtimeNs &&
    left.size === right.size
  );
}

function snapshotDirectoryIdentity(path, label) {
  const metadata = lstatSync(path, { bigint: true });
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular non-symbolic-link directory: ${path}`);
  }
  return directoryIdentity(metadata);
}

function openStableRegularFile(path, label) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new Error(`${label} must be a regular non-symbolic-link file: ${path}`);
  }
  const descriptor = openSync(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  const opened = fstatSync(descriptor, { bigint: true });
  if (!opened.isFile() || !sameFileMetadata(before, opened)) {
    closeSync(descriptor);
    throw new Error(`${label} changed while it was being opened: ${path}`);
  }
  return { before, descriptor };
}

function snapshotRegularFileIdentity(path, label) {
  const { before, descriptor } = openStableRegularFile(path, label);
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(64 * 1024);
  try {
    let bytesRead;
    do {
      bytesRead = readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead > 0) hash.update(buffer.subarray(0, bytesRead));
    } while (bytesRead > 0);
    const after = fstatSync(descriptor, { bigint: true });
    const atPath = lstatSync(path, { bigint: true });
    if (
      !sameFileMetadata(before, after) ||
      !sameFileMetadata(after, atPath) ||
      !atPath.isFile() ||
      atPath.isSymbolicLink()
    ) {
      throw new Error(`${label} changed while it was being read: ${path}`);
    }
    return fileIdentity(after, hash.digest("hex"));
  } finally {
    closeSync(descriptor);
  }
}

function readStableRegularFile(
  path,
  label,
  maxBytes,
  { requireSingleLink = false } = {},
) {
  const { before, descriptor } = openStableRegularFile(path, label);
  try {
    if (requireSingleLink && before.nlink !== 1n) {
      throw new Error(`${label} must be a singly linked regular file: ${path}`);
    }
    if (before.size > BigInt(maxBytes)) {
      throw new Error(`${label} exceeds ${maxBytes} bytes`);
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    const atPath = lstatSync(path, { bigint: true });
    if (
      !sameFileMetadata(before, after) ||
      !sameFileMetadata(after, atPath) ||
      (requireSingleLink && (after.nlink !== 1n || atPath.nlink !== 1n)) ||
      !atPath.isFile() ||
      atPath.isSymbolicLink()
    ) {
      throw new Error(`${label} changed while it was being read: ${path}`);
    }
    return {
      bytes,
      identity: fileIdentity(
        after,
        createHash("sha256").update(bytes).digest("hex"),
      ),
    };
  } finally {
    closeSync(descriptor);
  }
}

function defaultSignNative(path, { platform, cwd }) {
  if (platform !== "darwin") return;
  const sign = spawnSync("codesign", ["--force", "--sign", "-", path], {
    cwd,
    stdio: "inherit",
    env: process.env,
  });
  if (sign.status !== 0) {
    throw new Error(
      `Failed to ad-hoc sign ${path}; macOS requires a valid signature for Node.js native addons.`,
    );
  }
}

/** Load a staged addon in a short-lived process and require its public methods. */
export function probeNativeBindingExports(
  bindingPath,
  requiredExports = REQUIRED_NATIVE_EXPORTS,
  requiredAbiVersion = REQUIRED_NATIVE_BRIDGE_ABI_VERSION,
) {
  if (
    !Array.isArray(requiredExports) ||
    requiredExports.length === 0 ||
    requiredExports.some(
      (name) => typeof name !== "string" || !/^[A-Za-z][A-Za-z0-9]*$/u.test(name),
    )
  ) {
    throw new TypeError("required native exports must be a non-empty identifier array");
  }
  if (!Number.isSafeInteger(requiredAbiVersion) || requiredAbiVersion < 0) {
    throw new TypeError("required native bridge ABI version must be a safe unsigned integer");
  }
  const requiredResults = Object.fromEntries(
    requiredExports.flatMap((name) => {
      if (name === "connectNoritoBridgeAbiVersion") {
        return [[name, requiredAbiVersion]];
      }
      return Object.hasOwn(REQUIRED_NATIVE_EXPORT_RESULTS, name)
        ? [[name, REQUIRED_NATIVE_EXPORT_RESULTS[name]]]
        : [];
    }),
  );
  const probeSource = String.raw`
const bindingPath = process.argv[1];
let binding;
if (/\.(?:cjs|js)$/iu.test(bindingPath)) {
  // Test-only fixture support; production stages a native library.
  binding = require(bindingPath);
} else {
  // Publication deliberately retains the legacy .node.next transaction name
  // for crash-recovery compatibility. require() dispatches by the last
  // extension and would parse that Mach-O/ELF/PE file as JavaScript, whereas
  // process.dlopen loads the addon independent of its private filename.
  const nativeModule = { exports: {} };
  process.dlopen(nativeModule, bindingPath);
  binding = nativeModule.exports;
}
const required = JSON.parse(process.argv[2]);
const requiredResults = JSON.parse(process.argv[3]);
const missing = required.filter((name) => typeof binding[name] !== "function");
if (missing.length > 0) {
  process.stderr.write("missing required native exports: " + missing.join(", "));
  process.exitCode = 1;
}
if (
  Object.hasOwn(requiredResults, "connectNoritoBridgeAbiVersion") &&
  typeof binding.connectNoritoBridgeAbiVersion === "function"
) {
  const expectedAbi = requiredResults.connectNoritoBridgeAbiVersion;
  const actualAbi = binding.connectNoritoBridgeAbiVersion();
  if (!Number.isSafeInteger(actualAbi) || actualAbi !== expectedAbi) {
    process.stderr.write(
      "native bridge ABI mismatch: expected " + expectedAbi + ", found " + String(actualAbi),
    );
    process.exitCode = 1;
  }
}
const wrongResult = Object.entries(requiredResults).flatMap(([name, expected]) => {
  if (name === "connectNoritoBridgeAbiVersion") return [];
  if (typeof binding[name] !== "function") return [];
  try {
    const observed = binding[name]();
    return Object.is(observed, expected) ? [] : [[name, expected, observed]];
  } catch (error) {
    return [[name, expected, "threw " + String(error?.message ?? error)]];
  }
});
if (wrongResult.length > 0) {
  process.stderr.write(
    "invalid required native export results: " +
      wrongResult
        .map(
          ([name, expected, observed]) =>
            name + " expected " + expected + " but found " + String(observed),
        )
        .join(", "),
  );
  process.exitCode = 1;
}
const instructionCodecs = [
  "noritoEncodeInstruction", "noritoDecodeInstruction",
  "noritoEncodeInstructionBoxArchive", "noritoDecodeInstructionBoxArchive",
];
if (instructionCodecs.every((name) => required.includes(name) && typeof binding[name] === "function")) {
  try {
    const json = '{"Custom":{"payload":{"probe":"explicit-network-context"}}}';
    for (const [encode, decode] of [[instructionCodecs[0], instructionCodecs[1]], [instructionCodecs[2], instructionCodecs[3]]]) {
      const bytes = binding[encode](json, 369);
      if (!Buffer.isBuffer(bytes) || bytes.byteLength === 0 || bytes.byteLength > 65536) {
        throw new Error(encode + " must return bounded non-empty Buffer bytes");
      }
      if (binding[decode](bytes, 369) !== json) {
        throw new Error(decode + " must roundtrip canonical instruction JSON");
      }
      for (const prefix of [undefined, -1, 0.5, 65536, NaN, Infinity]) {
        for (const [name, input] of [[encode, json], [decode, bytes]]) {
          let rejected = false;
          try { binding[name](input, prefix); } catch { rejected = true; }
          if (!rejected) throw new Error(name + " accepted a missing or invalid network prefix");
        }
      }
    }
  } catch (error) {
    process.stderr.write("invalid native instruction network context contract: " + String(error?.message ?? error));
    process.exitCode = 1;
  }
}
if (
  required.includes("privacyCompiledProfileCatalogV1") &&
  required.includes("privacyValidateCompiledProfileCatalogV1") &&
  typeof binding.privacyCompiledProfileCatalogV1 === "function" &&
  typeof binding.privacyValidateCompiledProfileCatalogV1 === "function"
) {
  try {
    const catalog = binding.privacyCompiledProfileCatalogV1();
    if (
      !Buffer.isBuffer(catalog) ||
      !(catalog.buffer instanceof ArrayBuffer) ||
      catalog.byteLength === 0 ||
      catalog.byteLength > 256 * 1024
    ) {
      throw new Error(
        "privacyCompiledProfileCatalogV1 must return 1..262144 non-shared Buffer bytes",
      );
    }
    const validationStatus = binding.privacyValidateCompiledProfileCatalogV1(catalog);
    if (!Number.isSafeInteger(validationStatus) || validationStatus !== 0) {
      throw new Error(
        "privacyValidateCompiledProfileCatalogV1 must accept the published catalog with status 0, found " +
          String(validationStatus),
      );
    }
  } catch (error) {
    process.stderr.write(
      "invalid native privacy compiled-profile catalog contract: " +
        String(error?.message ?? error),
    );
    process.exitCode = 1;
  }
}
if (
  required.includes("privacyValidateExact12CapabilityManifestV1") &&
  typeof binding.privacyValidateExact12CapabilityManifestV1 === "function"
) {
  try {
    for (const hostile of [Buffer.alloc(0), Buffer.from("digest-shell")]) {
      const status = binding.privacyValidateExact12CapabilityManifestV1(hostile);
      if (!Number.isSafeInteger(status) || status === 0) {
        throw new Error(
          "privacyValidateExact12CapabilityManifestV1 must reject empty and digest-shell bytes, found " +
            String(status),
        );
      }
    }
  } catch (error) {
    process.stderr.write(
      "invalid native Exact12 capability-manifest validator contract: " +
        String(error?.message ?? error),
    );
    process.exitCode = 1;
  }
}
`;
  const probe = spawnSync(
    process.execPath,
    [
      "--eval",
      probeSource,
      bindingPath,
      JSON.stringify(requiredExports),
      JSON.stringify(requiredResults),
    ],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: process.env,
      timeout: NATIVE_BINDING_PROBE_TIMEOUT_MS,
      windowsHide: true,
      maxBuffer: 64 * 1024,
    },
  );
  if (probe.error) {
    throw new Error(`Failed to probe staged native binding ${bindingPath}`, {
      cause: probe.error,
    });
  }
  if (probe.status !== 0) {
    const detail = String(probe.stderr ?? "").trim().slice(0, 4096);
    throw new Error(
      `Staged native binding failed required-export verification${
        detail.length === 0 ? "" : `: ${detail}`
      }`,
    );
  }
  return requiredAbiVersion;
}

function triggerFailpoint(failpoint, point) {
  if (failpoint === point) {
    throw new Error(`copy-native injected test failure at ${point}`);
  }
}

function verificationError(label, verification) {
  return new Error(
    `${label} failed checksum verification (${verification?.status ?? "unknown"})`,
  );
}

function sha256File(path) {
  const hash = createHash("sha256");
  const descriptor = openSync(path, constants.O_RDONLY);
  const buffer = Buffer.allocUnsafe(64 * 1024);
  try {
    let bytesRead;
    do {
      bytesRead = readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead > 0) hash.update(buffer.subarray(0, bytesRead));
    } while (bytesRead > 0);
  } finally {
    closeSync(descriptor);
  }
  return hash.digest("hex");
}

function assertSha256(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
}

function pairIdentity(nativePath, manifestPath) {
  return Object.freeze({
    nativeSha256: sha256File(nativePath),
    manifestSha256: sha256File(manifestPath),
  });
}

function samePairIdentity(left, right) {
  return (
    left?.nativeSha256 === right?.nativeSha256 &&
    left?.manifestSha256 === right?.manifestSha256
  );
}

function verifyExactPair({
  nativePath,
  manifestPath,
  expected,
  verifyBinding,
  platformKey,
  label,
}) {
  assertRegularFile(nativePath, `${label} native binding`);
  assertChecksumManifest(manifestPath, `${label} checksum manifest`);
  const actual = pairIdentity(nativePath, manifestPath);
  if (!samePairIdentity(actual, expected)) {
    throw new Error(`${label} does not match its journaled binary/checksum identity`);
  }
  const verification = verifyBinding(nativePath, { manifestPath, platformKey });
  if (!verification?.ok) throw verificationError(label, verification);
  if (verification.sha256 !== undefined && verification.sha256 !== expected.nativeSha256) {
    throw new Error(`${label} verifier returned a checksum inconsistent with the journal`);
  }
  return verification;
}

function assertExactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
}

function validateJournalIdentity(identity, label) {
  assertExactKeys(identity, ["manifestSha256", "nativeSha256"], label);
  assertSha256(identity.nativeSha256, `${label}.nativeSha256`);
  assertSha256(identity.manifestSha256, `${label}.manifestSha256`);
  return Object.freeze({ ...identity });
}

function validateTransactionOwner(value, transactionId) {
  assertExactKeys(
    value,
    ["directory", "ownerId", "transactionId", "version"],
    "native publication transaction owner",
  );
  if (value.version !== TRANSACTION_OWNER_VERSION) {
    throw new Error(
      `unsupported native publication transaction owner version: ${value.version}`,
    );
  }
  if (value.transactionId !== transactionId) {
    throw new Error(
      "native publication transaction owner id does not match its directory",
    );
  }
  if (!UUID_V4_PATTERN.test(value.ownerId)) {
    throw new Error("native publication transaction owner has an invalid owner id");
  }
  return Object.freeze({
    directory: validateCleanupDirectoryIdentity(value.directory),
    ownerId: value.ownerId,
    transactionId: value.transactionId,
    version: value.version,
  });
}

function transactionIdFromDirectory(directory) {
  const match = TRANSACTION_DIRECTORY_PATTERN.exec(basename(directory));
  if (match === null) {
    throw new Error(
      `native publication transaction directory has an invalid id: ${directory}`,
    );
  }
  return match[1];
}

function readTransactionOwnerAt(directory, transactionId) {
  const markerPath = join(directory, TRANSACTION_OWNER_FILENAME);
  if (!existsSync(markerPath)) {
    throw new Error(
      `native publication refuses a transaction without its durable ownership marker: ${directory}`,
    );
  }
  const snapshot = readStableRegularFile(
    markerPath,
    "Native publication transaction ownership marker",
    MAX_TRANSACTION_OWNER_BYTES,
    { requireSingleLink: true },
  );
  let parsed;
  try {
    parsed = JSON.parse(snapshot.bytes.toString("utf8"));
  } catch (error) {
    throw new Error(
      `native publication transaction ownership marker is not valid JSON: ${markerPath}`,
      { cause: error },
    );
  }
  const owner = validateTransactionOwner(parsed, transactionId);
  const actualDirectory = snapshotDirectoryIdentity(
    directory,
    "Native publication owned transaction directory",
  );
  if (!sameDirectoryIdentity(actualDirectory, owner.directory)) {
    throw new Error(
      "native publication transaction directory no longer matches its owner marker",
    );
  }
  return { identity: snapshot.identity, owner };
}

function readTransactionOwner(directory, expectedTransactionId) {
  const transactionId = transactionIdFromDirectory(directory);
  if (
    expectedTransactionId !== undefined &&
    transactionId !== expectedTransactionId
  ) {
    throw new Error(
      "native publication transaction path does not match the expected transaction id",
    );
  }
  return readTransactionOwnerAt(directory, transactionId);
}

function writeTransactionOwner(
  directory,
  transactionId,
  lock,
  phaseHook,
) {
  const owner = {
    version: TRANSACTION_OWNER_VERSION,
    transactionId,
    ownerId: randomUUID(),
    directory: snapshotDirectoryIdentity(
      directory,
      "New native publication transaction directory",
    ),
  };
  const markerPath = join(directory, TRANSACTION_OWNER_FILENAME);
  assertDistLockOwnership(lock);
  writeFileSync(markerPath, `${JSON.stringify(owner, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  phaseHook?.("transaction-owner-written");
  syncFile(markerPath);
  syncDirectory(directory);
  phaseHook?.("transaction-owner-synced");
  return readTransactionOwnerAt(directory, transactionId);
}

function journalEntry(transaction, sequence, phase) {
  return {
    version: JOURNAL_VERSION,
    transactionId: transaction.transactionId,
    ownerId: transaction.ownerId,
    sequence,
    phase,
    platformKey: transaction.platformKey,
    previous: transaction.previous,
    next: transaction.next,
  };
}

function validateJournalEntry(value, transactionId, expectedSequence) {
  assertExactKeys(
    value,
    [
      "next",
      "ownerId",
      "phase",
      "platformKey",
      "previous",
      "sequence",
      "transactionId",
      "version",
    ],
    `native publication journal ${expectedSequence}`,
  );
  if (value.version !== JOURNAL_VERSION) {
    throw new Error(`unsupported native publication journal version: ${value.version}`);
  }
  if (value.transactionId !== transactionId) {
    throw new Error("native publication journal transaction id does not match its directory");
  }
  if (!UUID_V4_PATTERN.test(value.ownerId)) {
    throw new Error("native publication journal has an invalid owner id");
  }
  if (value.sequence !== expectedSequence) {
    throw new Error("native publication journal sequence is non-canonical");
  }
  if (!JOURNAL_PHASE_SET.has(value.phase)) {
    throw new Error(`native publication journal has unknown phase: ${value.phase}`);
  }
  if (typeof value.platformKey !== "string" || !/^[a-z0-9_-]+-[a-z0-9_-]+$/u.test(value.platformKey)) {
    throw new Error("native publication journal has an invalid platform key");
  }
  if (value.previous !== null) validateJournalIdentity(value.previous, "journal.previous");
  validateJournalIdentity(value.next, "journal.next");
  return value;
}

function appendJournalPhase(transaction, phase, lock) {
  if (!JOURNAL_PHASE_SET.has(phase)) {
    throw new Error(`unknown native publication journal phase: ${phase}`);
  }
  const sequence = transaction.sequence + 1;
  const sequenceText = String(sequence).padStart(6, "0");
  const finalPath = join(transaction.directory, `journal-${sequenceText}.json`);
  const temporaryPath = join(
    transaction.directory,
    `.journal-${sequenceText}-${randomUUID()}.tmp`,
  );
  writeFileSync(
    temporaryPath,
    `${JSON.stringify(journalEntry(transaction, sequence, phase), null, 2)}\n`,
    { flag: "wx", mode: 0o600 },
  );
  syncFile(temporaryPath);
  assertDistLockOwnership(lock);
  renameSync(temporaryPath, finalPath);
  syncDirectory(transaction.directory);
  transaction.sequence = sequence;
  transaction.phase = phase;
}

function readTransaction(directory, expectedTransactionId) {
  assertDirectory(directory, "Native publication transaction");
  const transactionId = transactionIdFromDirectory(directory);
  if (
    expectedTransactionId !== undefined &&
    transactionId !== expectedTransactionId
  ) {
    throw new Error(
      "native publication transaction directory does not match the expected id",
    );
  }
  const ownerSnapshot = readTransactionOwner(directory, transactionId);
  const journalNames = readdirSync(directory)
    .filter((name) => JOURNAL_PATTERN.test(name))
    .sort();
  if (journalNames.length === 0) return null;
  let baseline;
  let expectedPhases;
  let last;
  for (let index = 0; index < journalNames.length; index += 1) {
    const expectedName = `journal-${String(index).padStart(6, "0")}.json`;
    if (journalNames[index] !== expectedName) {
      throw new Error("native publication journal contains a gap or duplicate sequence");
    }
    const journalPath = join(directory, expectedName);
    const journalSnapshot = readStableRegularFile(
      journalPath,
      "Native publication journal entry",
      MAX_JOURNAL_BYTES,
      { requireSingleLink: true },
    );
    let parsed;
    try {
      parsed = JSON.parse(journalSnapshot.bytes.toString("utf8"));
    } catch (error) {
      throw new Error(`native publication journal is not valid JSON: ${journalPath}`, {
        cause: error,
      });
    }
    const entry = validateJournalEntry(parsed, transactionId, index);
    if (entry.ownerId !== ownerSnapshot.owner.ownerId) {
      throw new Error(
        "native publication journal owner id does not match the transaction owner",
      );
    }
    expectedPhases ??= entry.previous === null
      ? JOURNAL_PHASES.filter(
          (phase) =>
            phase !== "previous-manifest-moved" && phase !== "previous-native-moved",
        )
      : JOURNAL_PHASES;
    if (entry.phase !== expectedPhases[index]) {
      throw new Error("native publication journal phases are non-canonical");
    }
    const invariant = JSON.stringify({
      next: entry.next,
      ownerId: entry.ownerId,
      platformKey: entry.platformKey,
      previous: entry.previous,
      transactionId: entry.transactionId,
      version: entry.version,
    });
    if (baseline === undefined) baseline = invariant;
    else if (baseline !== invariant) {
      throw new Error("native publication journal invariants changed between phases");
    }
    last = entry;
  }
  return {
    directory,
    next: Object.freeze({ ...last.next }),
    ownerId: last.ownerId,
    phase: last.phase,
    platformKey: last.platformKey,
    previous: last.previous === null ? null : Object.freeze({ ...last.previous }),
    sequence: last.sequence,
    transactionId,
  };
}

function classifyFile(path, previousDigest, nextDigest, label) {
  if (!existsSync(path)) return "absent";
  assertRegularFile(path, label);
  const digest = sha256File(path);
  if (previousDigest !== undefined && digest === previousDigest) return "previous";
  if (digest === nextDigest) return "next";
  throw new Error(`${label} is tampered or does not match the journal`);
}

function requireFileKind(actual, expected, label) {
  if (actual !== "absent" && actual !== expected) {
    throw new Error(`${label} has the wrong journaled generation`);
  }
}

function syncRename(source, destination, lock) {
  assertDistLockOwnership(lock);
  renameSync(source, destination);
  syncDirectory(dirname(source));
  if (dirname(destination) !== dirname(source)) syncDirectory(dirname(destination));
}

function assertDecimalString(value, label) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} must be a canonical unsigned decimal string`);
  }
}

function validateCleanupDirectoryIdentity(value) {
  assertExactKeys(
    value,
    ["birthtimeNs", "dev", "ino"],
    "native publication cleanup directory identity",
  );
  assertDecimalString(value.birthtimeNs, "cleanup.directory.birthtimeNs");
  assertDecimalString(value.dev, "cleanup.directory.dev");
  assertDecimalString(value.ino, "cleanup.directory.ino");
  return Object.freeze({ ...value });
}

function isKnownTransactionEntry(name) {
  return (
    TRANSACTION_ARTIFACT_NAMES.has(name) ||
    JOURNAL_PATTERN.test(name) ||
    JOURNAL_TEMP_PATTERN.test(name)
  );
}

function validateCleanupEntry(value, index) {
  assertExactKeys(
    value,
    ["birthtimeNs", "dev", "ino", "mtimeNs", "name", "sha256", "size"],
    `native publication cleanup entry ${index}`,
  );
  if (typeof value.name !== "string" || !isKnownTransactionEntry(value.name)) {
    throw new Error(`native publication cleanup marker has an unknown entry: ${value.name}`);
  }
  assertDecimalString(value.birthtimeNs, `cleanup.entries[${index}].birthtimeNs`);
  assertDecimalString(value.dev, `cleanup.entries[${index}].dev`);
  assertDecimalString(value.ino, `cleanup.entries[${index}].ino`);
  assertDecimalString(value.mtimeNs, `cleanup.entries[${index}].mtimeNs`);
  assertDecimalString(value.size, `cleanup.entries[${index}].size`);
  assertSha256(value.sha256, `cleanup.entries[${index}].sha256`);
  return Object.freeze({ ...value });
}

function validateCleanupMarker(value, expected) {
  assertExactKeys(
    value,
    [
      "cleanupId",
      "directory",
      "entries",
      "ownerId",
      "transactionId",
      "version",
    ],
    "native publication cleanup marker",
  );
  if (value.version !== CLEANUP_VERSION) {
    throw new Error(`unsupported native publication cleanup marker version: ${value.version}`);
  }
  if (
    !UUID_V4_PATTERN.test(value.transactionId) ||
    value.transactionId !== expected.transactionId
  ) {
    throw new Error(
      "native publication cleanup marker transaction id does not match its artifact name",
    );
  }
  if (!UUID_V4_PATTERN.test(value.cleanupId) || value.cleanupId !== expected.cleanupId) {
    throw new Error(
      "native publication cleanup marker cleanup id does not match its artifact name",
    );
  }
  if (!UUID_V4_PATTERN.test(value.ownerId)) {
    throw new Error("native publication cleanup marker has an invalid owner id");
  }
  if (
    !Array.isArray(value.entries) ||
    value.entries.length > MAX_CLEANUP_ENTRIES
  ) {
    throw new Error(
      `native publication cleanup marker must contain at most ${MAX_CLEANUP_ENTRIES} entries`,
    );
  }
  const entries = value.entries.map(validateCleanupEntry);
  const entryNames = entries.map(({ name }) => name);
  const sortedNames = [...entryNames].sort();
  if (
    entryNames.some((name, index) => name !== sortedNames[index]) ||
    new Set(entryNames).size !== entryNames.length
  ) {
    throw new Error(
      "native publication cleanup marker entries must be unique and canonically ordered",
    );
  }
  return Object.freeze({
    cleanupId: value.cleanupId,
    directory: validateCleanupDirectoryIdentity(value.directory),
    entries: Object.freeze(entries),
    ownerId: value.ownerId,
    transactionId: value.transactionId,
    version: value.version,
  });
}

function cleanupMarkerTempArtifacts(destinationDirectory) {
  const artifacts = [];
  for (const name of readdirSync(destinationDirectory)) {
    const match = CLEANUP_MARKER_TEMP_PATTERN.exec(name);
    if (match === null) continue;
    artifacts.push({
      baseName: match[1],
      cleanupId: match[3],
      markerPath: join(
        destinationDirectory,
        `${match[1]}${CLEANUP_MARKER_SUFFIX}`,
      ),
      path: join(destinationDirectory, name),
      transactionId: match[2],
    });
  }
  return artifacts.sort((left, right) => left.path.localeCompare(right.path));
}

function recoverCleanupMarkerTemps(destinationDirectory, lock) {
  for (const artifact of cleanupMarkerTempArtifacts(destinationDirectory)) {
    const transactionDirectory = join(
      destinationDirectory,
      `${TRANSACTION_PREFIX}${artifact.transactionId}`,
    );
    const transactionExists = existsSync(transactionDirectory);
    const markerExists = existsSync(artifact.markerPath);
    if (!transactionExists && !markerExists) {
      throw new Error(
        `native publication refuses an orphan cleanup marker temporary: ${artifact.path}`,
      );
    }
    if (transactionExists) {
      readTransactionOwner(transactionDirectory, artifact.transactionId);
    }
    const temporaryMetadata = lstatSync(artifact.path);
    if (!temporaryMetadata.isFile() || temporaryMetadata.isSymbolicLink()) {
      throw new Error(
        `native publication cleanup marker temporary must be a regular non-symbolic-link file: ${artifact.path}`,
      );
    }
    if (markerExists) {
      const record = {
        baseName: artifact.baseName,
        cleanupId: artifact.cleanupId,
        directory: undefined,
        markerPath: artifact.markerPath,
        transactionId: artifact.transactionId,
      };
      const markerSnapshot = readCleanupMarker(record, {
        requireSingleLink: false,
      });
      const temporarySnapshot = snapshotRegularFileIdentity(
        artifact.path,
        "Native publication cleanup marker temporary",
      );
      if (!sameFileIdentity(temporarySnapshot, markerSnapshot.identity)) {
        throw new Error(
          "native publication cleanup marker temporary does not match its published marker",
        );
      }
    }
    assertDistLockOwnership(lock);
    unlinkSync(artifact.path);
    syncDirectory(destinationDirectory);
  }
}

function cleanupArtifactRecords(destinationDirectory) {
  const records = new Map();
  for (const name of readdirSync(destinationDirectory)) {
    if (!name.startsWith(CLEANUP_PREFIX)) continue;
    const directoryMatch = CLEANUP_DIRECTORY_PATTERN.exec(name);
    const markerMatch = CLEANUP_MARKER_PATTERN.exec(name);
    if (directoryMatch === null && markerMatch === null) {
      throw new Error(
        `native publication found an unowned cleanup-prefixed artifact: ${name}`,
      );
    }
    const baseName = directoryMatch === null ? markerMatch[1] : name;
    const transactionId =
      directoryMatch === null ? markerMatch[2] : directoryMatch[1];
    const cleanupId =
      directoryMatch === null ? markerMatch[3] : directoryMatch[2];
    const record = records.get(baseName) ?? {
      baseName,
      cleanupId,
      directory: undefined,
      markerPath: undefined,
      transactionId,
    };
    if (
      record.transactionId !== transactionId ||
      record.cleanupId !== cleanupId
    ) {
      throw new Error(`native publication cleanup artifact identity is ambiguous: ${name}`);
    }
    if (directoryMatch === null) {
      record.markerPath = join(destinationDirectory, name);
    } else {
      record.directory = join(destinationDirectory, name);
    }
    records.set(baseName, record);
  }
  return [...records.values()].sort((left, right) =>
    left.baseName.localeCompare(right.baseName),
  );
}

function readCleanupMarker(record, { requireSingleLink = true } = {}) {
  if (record.markerPath === undefined) {
    throw new Error(
      `native publication cleanup directory is missing its ownership marker: ${record.baseName}`,
    );
  }
  const snapshot = readStableRegularFile(
    record.markerPath,
    "Native publication cleanup ownership marker",
    MAX_CLEANUP_MARKER_BYTES,
    { requireSingleLink },
  );
  let parsed;
  try {
    parsed = JSON.parse(snapshot.bytes.toString("utf8"));
  } catch (error) {
    throw new Error(
      `native publication cleanup ownership marker is not valid JSON: ${record.markerPath}`,
      { cause: error },
    );
  }
  return {
    identity: snapshot.identity,
    marker: validateCleanupMarker(parsed, record),
  };
}

function cleanupInventory(directory, transactionId) {
  const ownerSnapshot = readTransactionOwner(directory, transactionId);
  readTransaction(directory, transactionId);
  const names = readdirSync(directory).sort();
  if (names.length > MAX_CLEANUP_ENTRIES) {
    throw new Error(
      `native publication transaction exceeds the ${MAX_CLEANUP_ENTRIES}-entry cleanup limit`,
    );
  }
  const entries = names.map((name) => {
    if (!isKnownTransactionEntry(name)) {
      throw new Error(
        `native publication transaction contains an unexpected artifact: ${name}`,
      );
    }
    return Object.freeze({
      name,
      ...snapshotRegularFileIdentity(
        join(directory, name),
        "Native publication cleanup inventory entry",
      ),
    });
  });
  return { entries, ownerId: ownerSnapshot.owner.ownerId };
}

function markerEntryMap(marker) {
  return new Map(marker.entries.map((entry) => [entry.name, entry]));
}

function assertOwnedCleanupDirectory(
  directory,
  marker,
  { requireComplete = false, verifyAllEntries = true } = {},
) {
  const actualDirectory = snapshotDirectoryIdentity(
    directory,
    "Native publication cleanup directory",
  );
  if (!sameDirectoryIdentity(actualDirectory, marker.directory)) {
    throw new Error(
      "native publication cleanup directory no longer matches its ownership marker",
    );
  }
  const expectedEntries = markerEntryMap(marker);
  const names = readdirSync(directory).sort();
  const deletionOrder = cleanupDeletionOrder(
    marker.entries.map(({ name }) => name),
  );
  const expectedRemaining = deletionOrder
    .slice(deletionOrder.length - names.length)
    .sort();
  if (
    (requireComplete && names.length !== marker.entries.length) ||
    names.length > marker.entries.length ||
    names.some((name, index) => name !== expectedRemaining[index])
  ) {
    throw new Error(
      requireComplete
        ? "native publication cleanup directory does not match its complete marked inventory"
        : "native publication cleanup directory is not a canonical deletion suffix",
    );
  }
  if (names.includes(TRANSACTION_OWNER_FILENAME)) {
    const transactionOwner = readTransactionOwner(
      directory,
      marker.transactionId,
    );
    if (transactionOwner.owner.ownerId !== marker.ownerId) {
      throw new Error(
        "native publication cleanup marker owner id does not match the transaction owner",
      );
    }
  }
  for (const name of names) {
    const expected = expectedEntries.get(name);
    if (expected === undefined || !isKnownTransactionEntry(name)) {
      throw new Error(
        `native publication cleanup directory contains an unowned direct child: ${name}`,
      );
    }
    if (verifyAllEntries) {
      const actual = snapshotRegularFileIdentity(
        join(directory, name),
        "Native publication cleanup direct child",
      );
      if (!sameFileIdentity(actual, expected)) {
        throw new Error(
          `native publication cleanup direct child changed after ownership was recorded: ${name}`,
        );
      }
    }
  }
  const remainingJournals = names.filter((name) => JOURNAL_PATTERN.test(name));
  if (remainingJournals.length > 0) {
    readTransaction(directory, marker.transactionId);
  }
  return names;
}

function sameCleanupMarkerSnapshot(left, right) {
  return (
    sameFileIdentity(left.identity, right.identity) &&
    JSON.stringify(left.marker) === JSON.stringify(right.marker)
  );
}

function assertCleanupMarkerUnchanged(record, expected) {
  const actual = readCleanupMarker(record);
  if (!sameCleanupMarkerSnapshot(actual, expected)) {
    throw new Error(
      "native publication cleanup ownership marker changed during cleanup",
    );
  }
  return actual;
}

function cleanupDeletionOrder(names) {
  return [...names].sort((left, right) => {
    if (left === TRANSACTION_OWNER_FILENAME) return 1;
    if (right === TRANSACTION_OWNER_FILENAME) return -1;
    const leftJournal = JOURNAL_PATTERN.exec(left);
    const rightJournal = JOURNAL_PATTERN.exec(right);
    if (leftJournal !== null && rightJournal !== null) {
      return Number(rightJournal[1]) - Number(leftJournal[1]);
    }
    if (leftJournal !== null) return 1;
    if (rightJournal !== null) return -1;
    return left.localeCompare(right);
  });
}

function removeOwnedCleanupDirectory(
  record,
  markerSnapshot,
  destinationDirectory,
  lock,
  phaseHook,
) {
  const initialNames = assertOwnedCleanupDirectory(
    record.directory,
    markerSnapshot.marker,
  );
  const expectedEntries = markerEntryMap(markerSnapshot.marker);
  let removedCount =
    markerSnapshot.marker.entries.length - initialNames.length;
  for (const name of cleanupDeletionOrder(initialNames)) {
    assertDistLockOwnership(lock);
    assertCleanupMarkerUnchanged(record, markerSnapshot);
    const remaining = assertOwnedCleanupDirectory(
      record.directory,
      markerSnapshot.marker,
      { verifyAllEntries: false },
    );
    if (!remaining.includes(name)) continue;
    const actual = snapshotRegularFileIdentity(
      join(record.directory, name),
      "Native publication cleanup direct child before unlink",
    );
    if (!sameFileIdentity(actual, expectedEntries.get(name))) {
      throw new Error(
        `native publication cleanup direct child was replaced before unlink: ${name}`,
      );
    }
    assertDistLockOwnership(lock);
    if (
      !sameDirectoryIdentity(
        snapshotDirectoryIdentity(
          record.directory,
          "Native publication cleanup directory before unlink",
        ),
        markerSnapshot.marker.directory,
      )
    ) {
      throw new Error(
        "native publication cleanup directory was replaced before unlink",
      );
    }
    // V3 explicitly trusts same-UID peer processes. Inside that boundary we
    // revalidate the lock, directory inode, direct-child inode, and digest
    // immediately before the path-based unlink. Node has no portable
    // directory-handle-relative unlink across POSIX and Windows.
    unlinkSync(join(record.directory, name));
    syncDirectory(record.directory);
    removedCount += 1;
    phaseHook?.(`cleanup-entry-removed:${removedCount}`);
  }
  assertCleanupMarkerUnchanged(record, markerSnapshot);
  assertOwnedCleanupDirectory(record.directory, markerSnapshot.marker, {
    verifyAllEntries: false,
  });
  if (readdirSync(record.directory).length !== 0) {
    throw new Error("native publication cleanup directory could not be emptied safely");
  }
  assertDistLockOwnership(lock);
  if (
    !sameDirectoryIdentity(
      snapshotDirectoryIdentity(
        record.directory,
        "Native publication cleanup directory before removal",
      ),
      markerSnapshot.marker.directory,
    )
  ) {
    throw new Error("native publication cleanup directory was replaced before removal");
  }
  rmdirSync(record.directory);
  syncDirectory(destinationDirectory);
  phaseHook?.("cleanup-directory-removed");
  assertCleanupMarkerUnchanged(record, markerSnapshot);
  assertDistLockOwnership(lock);
  unlinkSync(record.markerPath);
  syncDirectory(destinationDirectory);
}

function writeCleanupMarker(
  transactionDirectory,
  destinationDirectory,
  transactionId,
  lock,
  phaseHook,
) {
  recoverCleanupMarkerTemps(destinationDirectory, lock);
  const existingRecords = cleanupArtifactRecords(destinationDirectory);
  if (!UUID_V4_PATTERN.test(transactionId)) {
    throw new Error("native publication cleanup requires a canonical transaction id");
  }
  if (existingRecords.length !== 0) {
    if (
      existingRecords.length !== 1 ||
      existingRecords[0].transactionId !== transactionId ||
      existingRecords[0].markerPath === undefined ||
      existingRecords[0].directory !== undefined
    ) {
      throw new Error(
        "native publication cleanup artifacts must be recovered before creating another",
      );
    }
    const record = existingRecords[0];
    const markerSnapshot = readCleanupMarker(record);
    assertOwnedCleanupDirectory(transactionDirectory, markerSnapshot.marker, {
      requireComplete: true,
    });
    return { markerSnapshot, record };
  }
  const directory = snapshotDirectoryIdentity(
    transactionDirectory,
    "Native publication transaction before cleanup",
  );
  const inventory = cleanupInventory(transactionDirectory, transactionId);
  const cleanupId = randomUUID();
  const baseName = `${CLEANUP_PREFIX}v1-${transactionId}-${cleanupId}`;
  const record = {
    baseName,
    cleanupId,
    directory: join(destinationDirectory, baseName),
    markerPath: join(
      destinationDirectory,
      `${baseName}${CLEANUP_MARKER_SUFFIX}`,
    ),
    transactionId,
  };
  const marker = {
    version: CLEANUP_VERSION,
    transactionId,
    cleanupId,
    directory,
    entries: inventory.entries,
    ownerId: inventory.ownerId,
  };
  const temporaryPath = join(
    destinationDirectory,
    `${baseName}.owner-${randomUUID()}.tmp`,
  );
  assertDistLockOwnership(lock);
  writeFileSync(temporaryPath, `${JSON.stringify(marker, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  syncFile(temporaryPath);
  phaseHook?.("cleanup-marker-temp-synced");
  assertDistLockOwnership(lock);
  linkSync(temporaryPath, record.markerPath);
  syncDirectory(destinationDirectory);
  phaseHook?.("cleanup-marker-linked");
  unlinkSync(temporaryPath);
  syncDirectory(destinationDirectory);
  const markerSnapshot = readCleanupMarker(record);
  assertOwnedCleanupDirectory(transactionDirectory, markerSnapshot.marker, {
    requireComplete: true,
  });
  return { markerSnapshot, record };
}

function cleanupTransactionDirectory(
  transactionDirectory,
  destinationDirectory,
  lock,
  phaseHook,
) {
  if (!existsSync(transactionDirectory)) return;
  const transactionMatch = TRANSACTION_DIRECTORY_PATTERN.exec(
    basename(transactionDirectory),
  );
  if (transactionMatch === null) {
    throw new Error(
      `native publication refuses to clean a non-transaction directory: ${transactionDirectory}`,
    );
  }
  const { markerSnapshot, record } = writeCleanupMarker(
    transactionDirectory,
    destinationDirectory,
    transactionMatch[1],
    lock,
    phaseHook,
  );
  phaseHook?.("cleanup-marker-synced");
  assertCleanupMarkerUnchanged(record, markerSnapshot);
  assertOwnedCleanupDirectory(transactionDirectory, markerSnapshot.marker, {
    requireComplete: true,
  });
  const forbiddenCleanupDirectory = join(
    destinationDirectory,
    record.baseName,
  );
  if (existsSync(forbiddenCleanupDirectory)) {
    throw new Error(
      "native publication refuses to overwrite an intervening cleanup directory",
    );
  }
  assertDistLockOwnership(lock);
  phaseHook?.("cleanup-owned");
  removeOwnedCleanupDirectory(
    { ...record, directory: transactionDirectory },
    markerSnapshot,
    destinationDirectory,
    lock,
    phaseHook,
  );
}

function assertTransactionEntries(transaction) {
  for (const name of readdirSync(transaction.directory)) {
    if (
      JOURNAL_PATTERN.test(name) ||
      JOURNAL_TEMP_PATTERN.test(name) ||
      TRANSACTION_ARTIFACT_NAMES.has(name)
    ) {
      const path = join(transaction.directory, name);
      if (
        name === NEXT_MANIFEST_FILENAME ||
        name === PREVIOUS_MANIFEST_FILENAME ||
        name === DISCARDED_MANIFEST_FILENAME
      ) {
        assertChecksumManifest(path, "Native publication transaction checksum manifest");
      } else {
        assertRegularFile(path, "Native publication transaction artifact");
      }
      continue;
    }
    throw new Error(`native publication transaction contains an unexpected artifact: ${name}`);
  }
}

function verifyTransactionArtifacts(transaction) {
  assertTransactionEntries(transaction);
  const paths = {
    discardedManifest: join(transaction.directory, DISCARDED_MANIFEST_FILENAME),
    discardedNative: join(transaction.directory, DISCARDED_NATIVE_FILENAME),
    nextManifest: join(transaction.directory, NEXT_MANIFEST_FILENAME),
    nextNative: join(transaction.directory, NEXT_NATIVE_FILENAME),
    previousManifest: join(transaction.directory, PREVIOUS_MANIFEST_FILENAME),
    previousNative: join(transaction.directory, PREVIOUS_NATIVE_FILENAME),
  };
  requireFileKind(
    classifyFile(
      paths.nextNative,
      undefined,
      transaction.next.nativeSha256,
      "Staged next native binding",
    ),
    "next",
    "Staged next native binding",
  );
  requireFileKind(
    classifyFile(
      paths.nextManifest,
      undefined,
      transaction.next.manifestSha256,
      "Staged next checksum manifest",
    ),
    "next",
    "Staged next checksum manifest",
  );
  requireFileKind(
    classifyFile(
      paths.discardedNative,
      undefined,
      transaction.next.nativeSha256,
      "Discarded next native binding",
    ),
    "next",
    "Discarded next native binding",
  );
  requireFileKind(
    classifyFile(
      paths.discardedManifest,
      undefined,
      transaction.next.manifestSha256,
      "Discarded next checksum manifest",
    ),
    "next",
    "Discarded next checksum manifest",
  );
  if (transaction.previous === null) {
    if (existsSync(paths.previousNative) || existsSync(paths.previousManifest)) {
      throw new Error("first native publication unexpectedly contains previous-pair backups");
    }
  } else {
    requireFileKind(
      classifyFile(
        paths.previousNative,
        transaction.previous.nativeSha256,
        transaction.next.nativeSha256,
        "Previous native binding backup",
      ),
      "previous",
      "Previous native binding backup",
    );
    requireFileKind(
      classifyFile(
        paths.previousManifest,
        transaction.previous.manifestSha256,
        transaction.next.manifestSha256,
        "Previous checksum manifest backup",
      ),
      "previous",
      "Previous checksum manifest backup",
    );
  }
  return paths;
}

function recoverTransaction({
  transaction,
  destinationDirectory,
  verifyBinding,
  lock,
  prefer = "auto",
}) {
  const dest = join(destinationDirectory, NATIVE_FILENAME);
  const checksumManifestPath = join(destinationDirectory, CHECKSUM_FILENAME);
  const paths = verifyTransactionArtifacts(transaction);
  let nativeKind = classifyFile(
    dest,
    transaction.previous?.nativeSha256,
    transaction.next.nativeSha256,
    "Published native binding",
  );
  const sameNativeGeneration =
    transaction.previous !== null &&
    transaction.previous.nativeSha256 === transaction.next.nativeSha256;
  if (sameNativeGeneration && nativeKind !== "absent") {
    const previousBackupExists = existsSync(paths.previousNative);
    const nextStagedExists = existsSync(paths.nextNative);
    if (previousBackupExists && !nextStagedExists) {
      nativeKind = "next";
    } else if (!previousBackupExists && nextStagedExists) {
      nativeKind = "previous";
    } else {
      throw new Error(
        "native publication recovery cannot determine the location of an identical native generation",
      );
    }
  }
  const manifestKind = classifyFile(
    checksumManifestPath,
    transaction.previous?.manifestSha256,
    transaction.next.manifestSha256,
    "Published checksum manifest",
  );
  const nextNativeCopies =
    Number(nativeKind === "next") +
    Number(existsSync(paths.nextNative)) +
    Number(existsSync(paths.discardedNative));
  const nextManifestCopies =
    Number(manifestKind === "next") +
    Number(existsSync(paths.nextManifest)) +
    Number(existsSync(paths.discardedManifest));
  if (nextNativeCopies !== 1 || nextManifestCopies !== 1) {
    throw new Error("native publication transaction has missing or duplicate next-pair components");
  }
  if (transaction.previous !== null) {
    const previousNativeCopies =
      Number(nativeKind === "previous") + Number(existsSync(paths.previousNative));
    const previousManifestCopies =
      Number(manifestKind === "previous") + Number(existsSync(paths.previousManifest));
    if (previousNativeCopies !== 1 || previousManifestCopies !== 1) {
      throw new Error(
        "native publication transaction has missing or duplicate previous-pair components",
      );
    }
  }
  const completeNext = nativeKind === "next" && manifestKind === "next";
  const completePrevious = nativeKind === "previous" && manifestKind === "previous";
  const commitNext = prefer === "next" || (prefer === "auto" && completeNext);

  if (commitNext) {
    if (!completeNext) {
      throw new Error("native publication cannot commit an incomplete next pair");
    }
    if (transaction.previous !== null) {
      if (!existsSync(paths.previousNative) || !existsSync(paths.previousManifest)) {
        throw new Error("native publication cannot verify the exact previous pair before commit");
      }
    }
    const verification = verifyExactPair({
      nativePath: dest,
      manifestPath: checksumManifestPath,
      expected: transaction.next,
      verifyBinding,
      platformKey: transaction.platformKey,
      label: "Recovered next native binding",
    });
    cleanupTransactionDirectory(transaction.directory, destinationDirectory, lock);
    return { outcome: "next", verification };
  }

  if (completePrevious) {
    const verification = verifyExactPair({
      nativePath: dest,
      manifestPath: checksumManifestPath,
      expected: transaction.previous,
      verifyBinding,
      platformKey: transaction.platformKey,
      label: "Recovered previous native binding",
    });
    cleanupTransactionDirectory(transaction.directory, destinationDirectory, lock);
    return { outcome: "previous", verification };
  }

  // Remove only journal-authenticated next components from the public names.
  // Renames target absent transaction paths and are repeatable on Windows.
  if (manifestKind === "next") {
    if (existsSync(paths.discardedManifest)) {
      throw new Error("native publication recovery found duplicate next manifests");
    }
    syncRename(checksumManifestPath, paths.discardedManifest, lock);
  }
  if (nativeKind === "next") {
    if (existsSync(paths.discardedNative)) {
      throw new Error("native publication recovery found duplicate next binaries");
    }
    syncRename(dest, paths.discardedNative, lock);
  }

  if (transaction.previous === null) {
    if (existsSync(dest) || existsSync(checksumManifestPath)) {
      throw new Error("first native publication recovery could not restore the exact absent state");
    }
    cleanupTransactionDirectory(transaction.directory, destinationDirectory, lock);
    return { outcome: "absent" };
  }

  const currentNativeKind = classifyFile(
    dest,
    transaction.previous.nativeSha256,
    transaction.next.nativeSha256,
    "Native binding during rollback",
  );
  const currentManifestKind = classifyFile(
    checksumManifestPath,
    transaction.previous.manifestSha256,
    transaction.next.manifestSha256,
    "Checksum manifest during rollback",
  );
  if (currentNativeKind === "absent") {
    if (!existsSync(paths.previousNative)) {
      throw new Error("native publication recovery is missing the exact previous binary");
    }
    syncRename(paths.previousNative, dest, lock);
  } else if (currentNativeKind !== "previous") {
    throw new Error("native publication recovery could not isolate the next binary");
  }
  if (currentManifestKind === "absent") {
    if (!existsSync(paths.previousManifest)) {
      throw new Error("native publication recovery is missing the exact previous manifest");
    }
    syncRename(paths.previousManifest, checksumManifestPath, lock);
  } else if (currentManifestKind !== "previous") {
    throw new Error("native publication recovery could not isolate the next manifest");
  }
  const verification = verifyExactPair({
    nativePath: dest,
    manifestPath: checksumManifestPath,
    expected: transaction.previous,
    verifyBinding,
    platformKey: transaction.platformKey,
    label: "Rolled-back previous native binding",
  });
  cleanupTransactionDirectory(transaction.directory, destinationDirectory, lock);
  return { outcome: "previous", verification };
}

function transactionDirectories(destinationDirectory) {
  return readdirSync(destinationDirectory)
    .filter((name) => name.startsWith(TRANSACTION_PREFIX))
    .map((name) => join(destinationDirectory, name));
}

function initializedTransactionArtifacts(destinationDirectory) {
  const artifacts = [];
  for (const name of readdirSync(destinationDirectory)) {
    const match = TRANSACTION_INITIALIZER_PATTERN.exec(name);
    if (match === null) continue;
    artifacts.push({
      directory: join(destinationDirectory, name),
      initializerId: match[2],
      transactionId: match[1],
    });
  }
  return artifacts.sort((left, right) =>
    left.directory.localeCompare(right.directory),
  );
}

function inspectInitializedTransaction(artifact) {
  try {
    assertDirectory(
      artifact.directory,
      "Native publication transaction initializer",
    );
    const names = readdirSync(artifact.directory);
    if (
      names.length !== 1 ||
      names[0] !== TRANSACTION_OWNER_FILENAME
    ) {
      return undefined;
    }
    return readTransactionOwnerAt(
      artifact.directory,
      artifact.transactionId,
    );
  } catch {
    // The initializer namespace is never treated as an owned transaction
    // until its complete one-file inventory and ownership record validate.
    // Missing, partial, or adversarial initializers remain untouched as
    // forensic data and cannot block a later independently named transaction.
    return undefined;
  }
}

function recoverInitializedTransactions(destinationDirectory, lock) {
  for (const artifact of initializedTransactionArtifacts(destinationDirectory)) {
    const initialOwner = inspectInitializedTransaction(artifact);
    if (initialOwner === undefined) continue;
    const transactionDirectory = join(
      destinationDirectory,
      `${TRANSACTION_PREFIX}${artifact.transactionId}`,
    );
    if (existsSync(transactionDirectory)) {
      throw new Error(
        `native publication found both initialized and final transaction directories for ${artifact.transactionId}`,
      );
    }
    assertDistLockOwnership(lock);
    const currentOwner = inspectInitializedTransaction(artifact);
    if (
      currentOwner === undefined ||
      !sameFileIdentity(currentOwner.identity, initialOwner.identity) ||
      currentOwner.owner.ownerId !== initialOwner.owner.ownerId ||
      !sameDirectoryIdentity(
        currentOwner.owner.directory,
        initialOwner.owner.directory,
      )
    ) {
      throw new Error(
        "native publication transaction initializer changed before publication",
      );
    }
    renameSync(artifact.directory, transactionDirectory);
    syncDirectory(destinationDirectory);
    readTransactionOwner(transactionDirectory, artifact.transactionId);
  }
}

function recoverCleanupArtifacts(destinationDirectory, lock) {
  recoverCleanupMarkerTemps(destinationDirectory, lock);
  const records = cleanupArtifactRecords(destinationDirectory);
  const prepared = [];
  const transactionIds = new Set();
  for (const record of records) {
    if (record.markerPath === undefined) {
      throw new Error(
        `native publication refuses an unmarked cleanup directory: ${record.baseName}`,
      );
    }
    if (record.directory !== undefined) {
      throw new Error(
        `native publication refuses an unexpected cleanup directory: ${record.baseName}`,
      );
    }
    if (transactionIds.has(record.transactionId)) {
      throw new Error(
        `native publication found multiple cleanup markers for transaction ${record.transactionId}`,
      );
    }
    transactionIds.add(record.transactionId);
    const markerSnapshot = readCleanupMarker(record);
    const transactionDirectory = join(
      destinationDirectory,
      `${TRANSACTION_PREFIX}${record.transactionId}`,
    );
    const transactionExists = existsSync(transactionDirectory);
    if (transactionExists) {
      assertOwnedCleanupDirectory(
        transactionDirectory,
        markerSnapshot.marker,
      );
    }
    prepared.push({
      markerSnapshot,
      record,
      transactionDirectory: transactionExists ? transactionDirectory : undefined,
    });
  }

  for (const item of prepared) {
    const { markerSnapshot, record, transactionDirectory } = item;
    if (transactionDirectory !== undefined) {
      assertCleanupMarkerUnchanged(record, markerSnapshot);
      assertOwnedCleanupDirectory(transactionDirectory, markerSnapshot.marker);
      removeOwnedCleanupDirectory(
        { ...record, directory: transactionDirectory },
        markerSnapshot,
        destinationDirectory,
        lock,
      );
      continue;
    }
    // A marker can outlive its directory if the process was interrupted
    // between rmdir() and unlinking the marker. Removing this exact, validated
    // marker never traverses or mutates an unrelated directory.
    assertCleanupMarkerUnchanged(record, markerSnapshot);
    assertDistLockOwnership(lock);
    unlinkSync(record.markerPath);
    syncDirectory(destinationDirectory);
  }
}

function recoverInterruptedPublications({
  destinationDirectory,
  platformKey,
  verifyBinding,
  lock,
}) {
  recoverCleanupArtifacts(destinationDirectory, lock);
  recoverInitializedTransactions(destinationDirectory, lock);

  const journaled = [];
  for (const directory of transactionDirectories(destinationDirectory)) {
    assertDirectory(directory, "Native publication transaction artifact");
    const transaction = readTransaction(directory);
    if (transaction === null) {
      const allowed = new Set([
        TRANSACTION_OWNER_FILENAME,
        NEXT_NATIVE_FILENAME,
        NEXT_MANIFEST_FILENAME,
      ]);
      for (const name of readdirSync(directory)) {
        if (!allowed.has(name) && !JOURNAL_TEMP_PATTERN.test(name)) {
          throw new Error(
            `native publication found an ambiguous unjournaled artifact: ${name}`,
          );
        }
        assertRegularFile(
          join(directory, name),
          "Unjournaled native publication staging artifact",
        );
      }
      cleanupTransactionDirectory(directory, destinationDirectory, lock);
      continue;
    }
    if (transaction.platformKey !== platformKey) {
      throw new Error(
        `native publication journal platform ${transaction.platformKey} does not match ${platformKey}`,
      );
    }
    journaled.push(transaction);
  }
  if (journaled.length > 1) {
    throw new Error("native publication found multiple journaled transactions; refusing ambiguity");
  }
  if (journaled.length === 1) {
    return recoverTransaction({
      transaction: journaled[0],
      destinationDirectory,
      verifyBinding,
      lock,
      prefer: "auto",
    });
  }
  const dest = join(destinationDirectory, NATIVE_FILENAME);
  const manifest = join(destinationDirectory, CHECKSUM_FILENAME);
  const nativeExists = existsSync(dest);
  const manifestExists = existsSync(manifest);
  if (nativeExists !== manifestExists) {
    throw new Error(
      "native destination contains a partial binary/checksum pair without a recovery journal",
    );
  }
  if (!nativeExists) return { outcome: "none" };
  assertRegularFile(dest, "Existing native binding after recovery");
  assertChecksumManifest(manifest, "Existing native checksum manifest after recovery");
  const verification = verifyBinding(dest, { manifestPath: manifest, platformKey });
  if (!verification?.ok) {
    throw verificationError("Existing native binding after recovery", verification);
  }
  return { outcome: "existing", verification };
}

function createTransaction(
  destinationDirectory,
  platformKey,
  previous,
  next,
  lock,
  phaseHook,
) {
  const transactionId = randomUUID();
  const initializerDirectory = join(
    destinationDirectory,
    `${TRANSACTION_INITIALIZER_PREFIX}${transactionId}-${randomUUID()}`,
  );
  const directory = join(
    destinationDirectory,
    `${TRANSACTION_PREFIX}${transactionId}`,
  );
  assertDistLockOwnership(lock);
  mkdirSync(initializerDirectory, { mode: 0o700 });
  phaseHook?.("transaction-initializer-created");
  const ownerSnapshot = writeTransactionOwner(
    initializerDirectory,
    transactionId,
    lock,
    phaseHook,
  );
  assertDistLockOwnership(lock);
  if (existsSync(directory)) {
    throw new Error(
      `native publication transaction target already exists: ${directory}`,
    );
  }
  renameSync(initializerDirectory, directory);
  phaseHook?.("transaction-initializer-renamed");
  syncDirectory(destinationDirectory);
  phaseHook?.("transaction-created");
  const finalOwnerSnapshot = readTransactionOwner(directory, transactionId);
  if (
    !sameFileIdentity(finalOwnerSnapshot.identity, ownerSnapshot.identity) ||
    finalOwnerSnapshot.owner.ownerId !== ownerSnapshot.owner.ownerId
  ) {
    throw new Error(
      "native publication transaction ownership changed during initialization",
    );
  }
  return {
    directory,
    next,
    ownerId: finalOwnerSnapshot.owner.ownerId,
    phase: undefined,
    platformKey,
    previous,
    sequence: -1,
    transactionId,
  };
}

function publishStagedPair({
  transaction,
  destinationDirectory,
  verifyBinding,
  platformKey,
  failpoint,
  phaseHook,
  lock,
}) {
  const stagedNative = join(transaction.directory, NEXT_NATIVE_FILENAME);
  const stagedManifest = join(transaction.directory, NEXT_MANIFEST_FILENAME);
  const backupNative = join(transaction.directory, PREVIOUS_NATIVE_FILENAME);
  const backupManifest = join(transaction.directory, PREVIOUS_MANIFEST_FILENAME);
  const dest = join(destinationDirectory, NATIVE_FILENAME);
  const checksumManifestPath = join(destinationDirectory, CHECKSUM_FILENAME);

  appendJournalPhase(transaction, "prepared", lock);
  phaseHook?.("journal-prepared");
  if (transaction.previous !== null) {
    syncRename(checksumManifestPath, backupManifest, lock);
    phaseHook?.("previous-manifest-renamed");
    appendJournalPhase(transaction, "previous-manifest-moved", lock);
    phaseHook?.("previous-manifest-moved");
    syncRename(dest, backupNative, lock);
    phaseHook?.("previous-native-renamed");
    appendJournalPhase(transaction, "previous-native-moved", lock);
    phaseHook?.("previous-native-moved");
  }
  triggerFailpoint(failpoint, "after-backup");

  syncRename(stagedNative, dest, lock);
  phaseHook?.("next-native-renamed");
  appendJournalPhase(transaction, "next-native-moved", lock);
  phaseHook?.("next-native-moved");
  triggerFailpoint(failpoint, "after-native");

  // Publish the authenticating manifest last. Until this rename completes,
  // the loader rejects the new binary as missing its checksum contract.
  syncRename(stagedManifest, checksumManifestPath, lock);
  phaseHook?.("next-manifest-renamed");
  appendJournalPhase(transaction, "next-manifest-moved", lock);
  phaseHook?.("next-manifest-moved");
  triggerFailpoint(failpoint, "after-manifest");

  const published = verifyExactPair({
    nativePath: dest,
    manifestPath: checksumManifestPath,
    expected: transaction.next,
    verifyBinding,
    platformKey,
    label: "Published native binding",
  });
  phaseHook?.("published-pair-verified");
  appendJournalPhase(transaction, "published-verified", lock);
  phaseHook?.("published-verified");
  appendJournalPhase(transaction, "committed", lock);
  phaseHook?.("journal-committed");
  return published;
}

function assertBuildSourceMatchesCurrent(
  buildProvenance,
  sourceState,
  { phase = "publication" } = {},
) {
  if (
    sourceState.sourceGitRevision !== buildProvenance.source_git_revision
  ) {
    throw new Error(
      `Native build provenance does not match the current source revision during ${phase}.`,
    );
  }
  if (sourceState.sourceTreeClean !== buildProvenance.source_tree_clean) {
    throw new Error(
      "Native publication requires build provenance and current source to be clean for release profiles or identically dirty for a debug build.",
    );
  }
  const currentDigest = sourceState.sourceTreeSha256;
  if (
    sourceState.sourceTreeClean === false &&
    (typeof currentDigest !== "string" ||
      currentDigest !== buildProvenance.source_tree_sha256)
  ) {
    throw new Error(
      `Native build provenance does not match the exact dirty source tree during ${phase}.`,
    );
  }
  if (
    currentDigest !== undefined &&
    currentDigest !== buildProvenance.source_tree_sha256
  ) {
    throw new Error(
      `Native build provenance does not match the exact source tree during ${phase}.`,
    );
  }
}

/**
 * Stage, authenticate, probe, and transactionally publish one native binding.
 * The source and destination must be on the same machine; staging occurs in
 * the destination directory so all publication renames stay on one volume.
 */
export async function publishNativeBinding({
  source,
  destDir,
  platform = process.platform,
  arch = process.arch,
  signNative = defaultSignNative,
  verifyBinding = verifyNativeBinding,
  probeBinding = probeNativeBindingExports,
  requiredExports = REQUIRED_NATIVE_EXPORTS,
  failpoint,
  phaseHook,
  log = console.log,
  cargoProfile = resolveNativeBuildProfile(),
  readBuildProvenance = readNativeBuildProvenance,
  readSourceState = readNativeBuildSourceState,
} = {}) {
  if (typeof source !== "string" || source.length === 0) {
    throw new TypeError("native source must be a non-empty path");
  }
  if (typeof destDir !== "string" || destDir.length === 0) {
    throw new TypeError("native destination must be a non-empty directory path");
  }
  if (
    cargoProfile !== "debug" &&
    cargoProfile !== "release" &&
    cargoProfile !== "deploy"
  ) {
    throw new TypeError(
      'cargoProfile must be exactly "debug", "release", or "deploy"',
    );
  }
  if (failpoint !== undefined && !TEST_FAILPOINTS.has(failpoint)) {
    throw new TypeError(`unknown copy-native failpoint: ${failpoint}`);
  }
  if (
    typeof signNative !== "function" ||
    typeof verifyBinding !== "function" ||
    typeof probeBinding !== "function" ||
    typeof readBuildProvenance !== "function" ||
    typeof readSourceState !== "function" ||
    (phaseHook !== undefined && typeof phaseHook !== "function") ||
    typeof log !== "function"
  ) {
    throw new TypeError("native publication hooks must be functions");
  }

  const sourcePath = resolve(source);
  const destinationDirectory = resolve(destDir);
  const dest = join(destinationDirectory, NATIVE_FILENAME);
  const checksumManifestPath = join(destinationDirectory, CHECKSUM_FILENAME);
  if (sourcePath === dest) {
    throw new TypeError("native source and published destination must differ");
  }
  assertRegularFile(sourcePath, "Compiled native module");
  const buildProvenance = validateNativeBuildProvenance(
    readBuildProvenance(sourcePath),
    sourcePath,
    { platform },
  );
  if (buildProvenance.cargo_profile !== cargoProfile) {
    throw new Error("Native build provenance Cargo profile does not match publication.");
  }
  const publicationSource = readSourceState(repoRoot);
  assertBuildSourceMatchesCurrent(buildProvenance, publicationSource);
  if (
    cargoProfile !== "debug" &&
    (publicationSource.sourceTreeClean !== true ||
      buildProvenance.source_tree_clean !== true)
  ) {
    throw new Error(
      "Native release publication requires build provenance and current source to be clean.",
    );
  }
  mkdirSync(destinationDirectory, { recursive: true });
  assertDirectory(destinationDirectory, "Native destination");

  const platformKey = `${platform}-${arch}`.toLowerCase();
  let lock;
  let transaction;
  let primaryError;
  try {
    lock = await acquireDistLock({ root: destinationDirectory });
    recoverInterruptedPublications({
      destinationDirectory,
      platformKey,
      verifyBinding,
      lock,
    });
    phaseHook?.("recovery-complete");
    const nativeExists = existsSync(dest);
    const manifestExists = existsSync(checksumManifestPath);
    if (nativeExists !== manifestExists) {
      throw new Error(
        "native destination contains a partial binary/checksum pair; refusing to replace ambiguous state",
      );
    }
    if (nativeExists) {
      assertRegularFile(dest, "Existing native binding");
      assertChecksumManifest(checksumManifestPath, "Existing native checksum manifest");
    }

    let previous = null;
    let previousVerification;
    let previousSupportsDarwinResigning = platform !== "darwin";
    if (nativeExists) {
      const verification = verifyBinding(dest, {
        manifestPath: checksumManifestPath,
        platformKey,
      });
      if (!verification?.ok) {
        throw verificationError("Existing native binding", verification);
      }
      previousVerification = verification;
      previous = pairIdentity(dest, checksumManifestPath);
      previousSupportsDarwinResigning =
        platform !== "darwin" ||
        typeof verification.expectedMachOSigningIndependentSha256 === "string";
      if (verification.sha256 !== undefined && verification.sha256 !== previous.nativeSha256) {
        throw new Error("Existing native verifier returned an inconsistent checksum");
      }
    }

    // Create the transaction before staging, but do not write a journal until
    // the complete next pair has been synced, authenticated, and probed. A
    // crash before that point therefore leaves a provably non-destructive
    // directory that startup recovery can discard.
    transaction = createTransaction(
      destinationDirectory,
      platformKey,
      previous,
      Object.freeze({ nativeSha256: "0".repeat(64), manifestSha256: "0".repeat(64) }),
      lock,
      phaseHook,
    );
    if (platform !== "win32") chmodSync(transaction.directory, 0o700);
    const stagedNative = join(transaction.directory, NEXT_NATIVE_FILENAME);
    const stagedManifest = join(transaction.directory, NEXT_MANIFEST_FILENAME);

    copyFileSync(sourcePath, stagedNative, constants.COPYFILE_EXCL);
    if (sha256File(stagedNative) !== buildProvenance.native_sha256) {
      throw new Error("Staged native module does not match its build provenance.");
    }
    signNative(stagedNative, { platform, cwd: repoRoot });
    if (platform !== "win32") chmodSync(stagedNative, 0o500);
    syncFile(stagedNative);
    syncDirectory(transaction.directory);
    phaseHook?.("staged-native-synced");

    const sha256 = sha256File(stagedNative);
    const stagedBytes = readFileSync(stagedNative);
    const machOSigningIndependentSha256 =
      platform === "darwin" ? machOSigningIndependentSHA256(stagedBytes) : null;
    if (platform === "darwin" && machOSigningIndependentSha256 === null) {
      throw new Error("Darwin native binding is not a supported signed Mach-O image");
    }
    const peSigningIndependentSha256 =
      platform === "win32"
        ? peSigningIndependentSHA256(stagedBytes, stagedBytes.length)
        : null;
    if (platform === "win32" && peSigningIndependentSha256 === null) {
      throw new Error("Windows native binding is not a supported PE/COFF image");
    }
    const checksumEntry = {
      sha256,
      build_provenance_version: buildProvenance.version,
      build_execution_policy: buildProvenance.build_execution_policy,
      cargo_profile: cargoProfile,
      source_git_revision: buildProvenance.source_git_revision,
      source_tree_clean: buildProvenance.source_tree_clean,
      source_tree_sha256: buildProvenance.source_tree_sha256,
      ...(platform === "darwin"
        ? { macos_build: buildProvenance.macos_build } : {}),
      ...(machOSigningIndependentSha256 === null
        ? {}
        : { mach_o_signing_independent_sha256: machOSigningIndependentSha256 }),
      ...(peSigningIndependentSha256 === null
        ? {}
        : {
            pe_signing_independent_sha256: peSigningIndependentSha256,
            pe_unsigned_size: stagedBytes.length,
          }),
    };
    writeFileSync(
      stagedManifest,
      `${JSON.stringify(
        {
          entries: {
            [platformKey]: checksumEntry,
          },
        },
        null,
        2,
      )}\n`,
      { flag: "wx", mode: 0o600 },
    );
    syncFile(stagedManifest);
    syncDirectory(transaction.directory);
    phaseHook?.("staged-manifest-synced");

    const staged = verifyBinding(stagedNative, {
      manifestPath: stagedManifest,
      platformKey,
    });
    if (!staged?.ok) throw verificationError("Staged native binding", staged);
    probeBinding(stagedNative, requiredExports);
    const postProbeSource = readSourceState(repoRoot);
    assertBuildSourceMatchesCurrent(buildProvenance, postProbeSource, {
      phase: "staged addon probing",
    });

    transaction.next = pairIdentity(stagedNative, stagedManifest);
    if (staged.sha256 !== undefined && staged.sha256 !== transaction.next.nativeSha256) {
      throw new Error("Staged native verifier returned an inconsistent checksum");
    }
    // An identical executable is idempotent only when its build provenance is
    // also identical. A byte-identical build from a different sealed source
    // still needs a transactional manifest update.
    const previousProvenanceMatches =
      previousVerification?.buildProvenanceVersion ===
        buildProvenance.version &&
      previousVerification?.buildExecutionPolicy ===
        buildProvenance.build_execution_policy &&
      previousVerification?.cargoProfile === buildProvenance.cargo_profile &&
      previousVerification?.sourceGitRevision ===
        buildProvenance.source_git_revision &&
      previousVerification?.sourceTreeClean ===
        buildProvenance.source_tree_clean &&
      previousVerification?.sourceTreeSha256 ===
        buildProvenance.source_tree_sha256 &&
      (platform !== "darwin" ||
        JSON.stringify(previousVerification?.macosBuild) ===
          JSON.stringify(buildProvenance.macos_build));
    if (
      transaction.previous !== null &&
      transaction.previous.nativeSha256 === transaction.next.nativeSha256 &&
      previousSupportsDarwinResigning &&
      previousProvenanceMatches
    ) {
      const matchingSha256 = transaction.next.nativeSha256;
      cleanupTransactionDirectory(
        transaction.directory,
        destinationDirectory,
        lock,
        phaseHook,
      );
      transaction = undefined;
      log(`Native module at ${dest} already matches the verified build output`);
      return {
        bindingPath: dest,
        manifestPath: checksumManifestPath,
        platformKey,
        sha256: matchingSha256,
      };
    }

    if (transaction.previous !== null) {
      verifyExactPair({
        nativePath: dest,
        manifestPath: checksumManifestPath,
        expected: transaction.previous,
        verifyBinding,
        platformKey,
        label: "Pre-publication existing native binding",
      });
    }

    const published = publishStagedPair({
      transaction,
      destinationDirectory,
      verifyBinding,
      platformKey,
      failpoint,
      phaseHook,
      lock,
    });
    cleanupTransactionDirectory(
      transaction.directory,
      destinationDirectory,
      lock,
      phaseHook,
    );
    transaction = undefined;
    log(`Published verified native module to ${dest}`);
    log(`Wrote checksum manifest to ${checksumManifestPath}`);
    return {
      bindingPath: dest,
      manifestPath: checksumManifestPath,
      platformKey,
      sha256: published.sha256,
    };
  } catch (error) {
    primaryError = error;
    if (lock && transaction && existsSync(transaction.directory)) {
      try {
        const journaled = readTransaction(transaction.directory);
        if (journaled !== null) {
          recoverTransaction({
            transaction: journaled,
            destinationDirectory,
            verifyBinding,
            lock,
            prefer: "previous",
          });
        } else {
          cleanupTransactionDirectory(transaction.directory, destinationDirectory, lock);
        }
        transaction = undefined;
      } catch (recoveryError) {
        const aggregate = new AggregateError(
          [error, recoveryError],
          "native publication failed and durable recovery could not restore the exact prior pair",
        );
        primaryError = aggregate;
        throw aggregate;
      }
    }
    throw error;
  } finally {
    const cleanupErrors = [];
    if (transaction && existsSync(transaction.directory)) {
      try {
        if (lock) assertDistLockOwnership(lock);
        const journaled = readTransaction(transaction.directory);
        if (journaled === null) {
          cleanupTransactionDirectory(transaction.directory, destinationDirectory, lock);
        }
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (lock) {
      try {
        releaseDistLock(lock);
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (cleanupErrors.length > 0) {
      if (primaryError) {
        throw new AggregateError(
          [primaryError, ...cleanupErrors],
          `native publication failed (${primaryError.message}) and cleanup was incomplete`,
        );
      }
      if (cleanupErrors.length === 1) throw cleanupErrors[0];
      throw new AggregateError(cleanupErrors, "native publication cleanup was incomplete");
    }
  }
}

/** Recover a killed native publication without beginning a new one. */
export async function recoverNativeBindingPublication({
  destDir,
  platform = process.platform,
  arch = process.arch,
  verifyBinding = verifyNativeBinding,
} = {}) {
  if (typeof destDir !== "string" || destDir.length === 0) {
    throw new TypeError("native destination must be a non-empty directory path");
  }
  if (typeof verifyBinding !== "function") {
    throw new TypeError("native recovery verifyBinding must be a function");
  }
  const destinationDirectory = resolve(destDir);
  assertDirectory(destinationDirectory, "Native destination");
  const platformKey = `${platform}-${arch}`.toLowerCase();
  const lock = await acquireDistLock({ root: destinationDirectory });
  let primaryError;
  try {
    return recoverInterruptedPublications({
      destinationDirectory,
      platformKey,
      verifyBinding,
      lock,
    });
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try {
      releaseDistLock(lock);
    } catch (releaseError) {
      if (primaryError) {
        throw new AggregateError(
          [primaryError, releaseError],
          "native recovery failed and its publication lock could not be released",
        );
      }
      throw releaseError;
    }
  }
}

function defaultNativePaths() {
  const cargoProfile = resolveNativeBuildProfile();
  const configuredDestDir = process.env.IROHA_JS_NATIVE_DIR;
  const destDir = configuredDestDir
    ? isAbsolute(configuredDestDir)
      ? configuredDestDir
      : join(repoRoot, configuredDestDir)
    : join(repoRoot, "javascript", "iroha_js", "native");
  return {
    source: nativeBuildOutputPath({ repoRoot, cargoProfile }),
    destDir,
    cargoProfile,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === __filename) {
  publishNativeBinding(defaultNativePaths()).catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
