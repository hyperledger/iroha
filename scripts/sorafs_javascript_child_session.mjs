// Private fixed child session; never accepts test/subject/native callbacks.
// Parent archive/candidate/runtime and whole-tree custody remain mandatory.
import { after, test } from "node:test";
import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { OriginalChildInput } from "./sorafs_javascript_child_input.mjs";
import { ChildLoadObservations } from "./sorafs_javascript_child_loads.mjs";
import { NativeCacheObservation } from "./sorafs_javascript_native_cache.mjs";
import { NativeSnapshotFiles } from "./sorafs_javascript_child_files.mjs";
import { SorafsJavascriptTestEvents } from "./sorafs_javascript_test_events.mjs";

const FULL = ["dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtimeNs", "ctimeNs"];
const SUITES = Object.freeze([
  ["cancelAssetLockV1", "registerCancelAssetLockV1Tests"],
  ["sorafsAppealFinanceValidation", "registerSorafsAppealFinanceValidationTests"],
  ["sorafsFixtureBundleValidation", "registerSorafsFixtureBundleValidationTests"],
  ["sorafsOrderbookSubmission", "registerSorafsOrderbookSubmissionTests"],
  ["sorafsOrchestrator.parity", "registerSorafsOrchestratorParityTests"],
  ["sorafsPdpValidation", "registerSorafsPdpValidationTests"],
]);
// The first nine entries are the existing ABI31 checker's exact Node inventory.
// A source contract control must keep this projection bound to that sole owner.
const ABI_SYMBOLS = Object.freeze([
  "connectNoritoBridgeAbiVersion", "inspectSorafsOrderbookSubmissionForDiscriminantV1",
  "privateSettlementVerifyAuditApprovalResponseV1", "privateSettlementVerifyAuditorCapsuleResponseWithRequestV1",
  "privateSettlementVerifyCommitteeProofResponseV1", "sorafsValidateAppealFinanceCancelAssetLockJson",
  "validationFeeCurrentPolicyProofRequestV1", "validationFeeVerifyCurrentPolicyProofV1",
  "verifySorafsOrderbookSubmissionReceiptV1",
]);
const RETIRED_ABI_SYMBOLS = Object.freeze([
  "privateSettlementVerifyAuditorCapsuleResponseV1",
  "validationFeeHijiriQuoteRequestV1", "validationFeeVerifyHijiriQuoteResponseV1",
]);
const SORAFS_SYMBOLS = Object.freeze(["sorafsValidateFixtureBundleJson", "sorafsMultiFetchLocal",
  "sorafsValidatePdpPayloadJson", "sorafsValidatePdpCommitmentChallengeJson",
  "sorafsValidatePdpChallengeProofJson", "sorafsValidatePdpBundleJson"]);
const cacheIdentify = NativeCacheObservation.prototype.identify;
const cacheRecheck = NativeCacheObservation.prototype.recheck;
const filesIdentify = NativeSnapshotFiles.prototype.identify;
const filesRecheck = NativeSnapshotFiles.prototype.recheck;
const filesClose = NativeSnapshotFiles.prototype.close;
const eventAccept = SorafsJavascriptTestEvents.prototype.accept;
const eventFinish = SorafsJavascriptTestEvents.prototype.finish;
const loadIdentify = ChildLoadObservations.prototype.identifyNative;
const loadRecheck = ChildLoadObservations.prototype.recheck;
const loadClose = ChildLoadObservations.prototype.close;
let prepared;
function demand(value, message) { if (!value) throw new Error(`JavaScript child session: ${message}`); }
function directoryURL(path) { return pathToFileURL(path + "/"); }
function seal(info) { return Object.freeze(Object.fromEntries(FULL.map((key) => [key, info[key].toString()]))); }

// These complete named-file observations supplement, not replace, the parent's
// retained exact tree owners. Pathname checks are not an openat/sandbox claim.
function readOriginal(root, row, retain = false) {
  const name = join(root, row.path);
  demand(realpathSync(name) === name, "original path contains a link or alias");
  const before = lstatSync(name, { bigint: true });
  demand(before.isFile() && before.nlink === 1n && before.uid === BigInt(process.getuid())
    && before.size === BigInt(row.size)
    && (row.mode === undefined ? (before.mode & 0o22n) === 0n : (before.mode & 0o7777n) === BigInt(row.mode)),
    "original file type, owner, mode or size differs");
  let fd, failure, result;
  try {
    fd = openSync(name, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | (constants.O_CLOEXEC ?? 0));
    const initial = fstatSync(fd, { bigint: true });
    demand(FULL.every((key) => initial[key] === before[key]), "original changed before open");
    const hash = createHash("sha256"), chunk = Buffer.alloc(64 * 1024), kept = retain ? Buffer.alloc(row.size) : null;
    let offset = 0;
    while (offset < row.size) {
      const count = readSync(fd, chunk, 0, Math.min(chunk.length, row.size - offset), offset);
      demand(count > 0, "original ended before its declared size");
      hash.update(chunk.subarray(0, count)); kept?.set(chunk.subarray(0, count), offset); offset += count;
    }
    demand(readSync(fd, chunk, 0, 1, row.size) === 0 && hash.digest("hex") === row.sha256, "original bytes differ");
    const opened = fstatSync(fd, { bigint: true }), named = lstatSync(name, { bigint: true });
    demand(FULL.every((key) => opened[key] === before[key] && named[key] === before[key])
      && realpathSync(name) === name, "original changed while captured");
    result = Object.freeze({ path: name, sha256: row.sha256, size: row.size, seal: seal(before), ...(retain ? { bytes: kept } : {}) });
  } catch (error) { failure = error; }
  if (fd !== undefined) {
    const original = fd; fd = undefined;
    try { closeSync(original); } catch (cleanup) {
      if (failure) throw new AggregateError([failure, cleanup], "original read and descriptor cleanup failed");
      throw cleanup;
    }
  }
  if (failure) throw failure;
  return result;
}
function capture(input) {
  const rows = [];
  for (const [root, members] of [[input.coreRoot, input.source], [input.installedRoot, input.installed], [input.toolsRoot, input.tools]])
    for (const row of members) rows.push(readOriginal(root, row));
  rows.push(readOriginal(dirname(input.native.originalPath), { path: "iroha_js_host.checksums.json",
    sha256: input.native.checksumSha256, size: input.native.checksumSize }));
  return Object.freeze(rows);
}
function symbols(binding) {
  const names = Reflect.ownKeys(binding);
  // Match the sole ABI owner's rejection-only prefix; this is not an export or decoder.
  const retiredPrefix = "connect_norito_" + ["cash", "offline"].reverse().join("_") + "_";
  demand(names.length <= 1024 && names.every((name) => typeof name === "string"), "native symbol inventory differs");
  demand(names.every((name) => !RETIRED_ABI_SYMBOLS.includes(name)
    && !name.startsWith(retiredPrefix)), "retired native export present");
  for (const name of [...ABI_SYMBOLS, ...SORAFS_SYMBOLS])
    demand(typeof Object.getOwnPropertyDescriptor(binding, name)?.value === "function", `missing native capability ${name}`);
  const version = binding.connectNoritoBridgeAbiVersion();
  demand(version === 31 && Number.isSafeInteger(version), "same-binding ABI is not 31");
  return Object.freeze({ bridgeAbiVersion: version, requiredSymbols: ABI_SYMBOLS, sorafsSymbols: SORAFS_SYMBOLS });
}

class PreparedChild {
  #inputOwner; #input; #capture; #cache; #files; #loads; #events;
  #phase = "preparing"; #binding; #getter; #verification; #subjects = []; #hookObservation; #failed = false; #checking = false;
  constructor(expectedSha256) {
    try {
      demand(/^24\./u.test(process.versions.node) && ["darwin", "linux"].includes(process.platform), "requires selected POSIX Node24");
      this.#inputOwner = new OriginalChildInput(expectedSha256); this.#input = this.#inputOwner.value;
      demand(fileURLToPath(import.meta.url) === join(this.#input.toolsRoot, "sorafs_javascript_child_session.mjs"), "tool execution location differs");
      demand((process.env.NODE_OPTIONS ?? "") === "" && (process.env.NODE_PATH ?? "") === ""
        && process.env.IROHA_JS_NATIVE_DIR === dirname(this.#input.native.originalPath)
        && process.env.TMPDIR === this.#input.temporaryRoot, "fixed process environment differs");
      this.#capture = capture(this.#input);
      this.#cache = new NativeCacheObservation();
      this.#files = new NativeSnapshotFiles({ originalPath: this.#input.native.originalPath,
        temporaryRoot: this.#input.temporaryRoot, expectedSha256: this.#input.native.sha256, expectedSize: this.#input.native.size });
      const name = "javascript/iroha_js/test/fixtures/sorafs_native_suite_contract_v1.json";
      const contract = readOriginal(this.#input.coreRoot, this.#input.source.find((row) => row.path === name), true).bytes;
      this.#events = new SorafsJavascriptTestEvents(contract, { suiteRoot: join(this.#input.coreRoot, "javascript/iroha_js/test/sorafsNativeSuites") });
      this.#loads = new ChildLoadObservations(this.#inputOwner);
      this.#phase = "prepared";
    } catch (error) {
      this.#failed = true;
      try { this.close(); } catch (cleanup) { throw new AggregateError([error, cleanup], "child preparation and cleanup failed"); }
      throw error;
    }
  }
  get entryPath() { return join(this.#input.toolsRoot, "sorafs_javascript_child_entry.mjs"); }
  async #subject(specifier, expected) {
    const url = import.meta.resolve(specifier);
    demand(url === pathToFileURL(join(this.#input.installedRoot, "@iroha/iroha-js", expected)).href, "actual installed subject resolution differs");
    const module = await import(url);
    this.#subjects.push({ specifier, url, module, exports: Object.entries(module) });
    return module;
  }
  async register() {
    demand(!this.#failed && this.#phase === "prepared", "entry does not own the original prepared session");
    this.#phase = "registering";
    try {
      const native = await this.#subject(pathToFileURL(join(this.#input.installedRoot, "@iroha/iroha-js/dist/native.js")).href, "dist/native.js");
      this.#getter = native.getNativeBinding;
      this.#verification = native.verifyNativeBinding(this.#input.native.originalPath);
      const v = this.#verification;
      demand(v.ok === true && v.sha256 === this.#input.native.sha256 && v.sourceTreeClean === true
        && v.sourceGitRevision === this.#input.native.sourceCommit
        && v.sourceTreeSha256 === this.#input.native.nativeSourceTreeSha256, "original native checksum/source relation differs");
      this.#binding = this.#getter();
      cacheIdentify.call(this.#cache, this.#getter); filesIdentify.call(this.#files, this.#cache);
      loadIdentify.call(this.#loads, this.#cache);
      symbols(this.#binding);
      const norito = await this.#subject("@iroha/iroha-js/norito", "dist/public/norito.js");
      const sorafs = await this.#subject("@iroha/iroha-js/sorafs", "dist/public/sorafs.js");
      const torii = await this.#subject("@iroha/iroha-js/torii", "dist/toriiClient.js");
      const api = await this.#subject("@iroha/iroha-js", "dist/index.js");
      const hooks = await this.#subject(pathToFileURL(join(this.#input.installedRoot, "@iroha/iroha-js/dist/toriiTestHooks.js")).href, "dist/toriiTestHooks.js");
      const pick = (module, names) => Object.freeze(Object.fromEntries(names.map((name) => {
        demand(Object.hasOwn(module, name), `installed subject is missing ${name}`); return [name, module[name]];
      })));
      const fixture = (name) => directoryURL(join(this.#input.coreRoot, "fixtures", name));
      const contexts = [
        { test, subject: pick(norito, ["decodeCancelAssetLockV1", "encodeCancelAssetLockV1"]), fixtureRoot: fixture("sorafs_manifest/appeal_finance") },
        { test, subject: pick(sorafs, ["validateAppealFinanceCancelAssetLock"]), fixtureRoot: fixture("sorafs_manifest/appeal_finance") },
        { test, subject: pick(sorafs, ["SORAFS_FIXTURE_BUNDLE_MAX_PAYLOADS_V1", "SORAFS_FIXTURE_BUNDLE_PAYLOAD_KINDS", "validateFixtureBundle"]),
          fixtureRoot: fixture("sorafs_manifest"), nativeBinding: this.#binding, nativeBindingError: null },
        { test, subject: Object.freeze({ ...pick(torii, ["LocalSigningContext", "SorafsOrderbookSubmissionAmbiguousError", "ToriiClient"]),
          ...pick(api, ["NetworkId"]), ...pick(hooks, ["TORII_TEST_NATIVE_BINDING"]) }) },
        { test, subject: Object.freeze({ getNativeBinding: this.#getter }), fixtureRoot: fixture("sorafs_orchestrator/multi_peer_parity_v1"),
          repositoryRoot: directoryURL(this.#input.coreRoot), temporaryRoot: this.#input.temporaryRoot,
          nativeBinding: this.#binding, nativeBindingError: null },
        { test, subject: pick(sorafs, ["SORAFS_PDP_PAYLOAD_KINDS", "validatePdpBundle", "validatePdpChallengeProof", "validatePdpCommitmentChallenge", "validatePdpPayload"]),
          fixtureRoot: fixture("sorafs_manifest") },
      ];
      for (const [index, [name, registration]] of SUITES.entries()) {
        const module = await import(pathToFileURL(join(this.#input.coreRoot, "javascript/iroha_js/test/sorafsNativeSuites", name + ".js")).href);
        demand(typeof module[registration] === "function", "original suite registration missing");
        module[registration](Object.freeze(contexts[index]));
      }
      after(() => {
        demand(!this.#failed && this.#phase === "registered", "final hook does not own the original session");
        try { this.#hookObservation = this.#recheck(); this.#phase = "hook-complete"; }
        catch (error) { this.#failed = true; throw error; }
      });
      this.#phase = "registered";
    } catch (error) { this.#failed = true; throw error; }
  }
  #recheck() {
    if (this.#checking) this.#failed = true;
    demand(!this.#failed && this.#phase !== "closed", "child recheck is refused or reentrant");
    this.#checking = true;
    try {
    this.#inputOwner.recheck();
    demand(JSON.stringify(capture(this.#input)) === JSON.stringify(this.#capture), "input file observations changed");
    for (const row of this.#subjects)
      demand(row.exports.every(([key, value]) => Object.is(row.module[key], value)), "installed namespace export changed");
    demand(this.#getter() === this.#binding, "original getter no longer returns the same binding");
    const cache = cacheRecheck.call(this.#cache), files = filesRecheck.call(this.#files);
    const abi = symbols(this.#binding), loads = loadRecheck.call(this.#loads);
    demand(!this.#failed && this.#phase !== "closed", "child ended during final observation");
    return Object.freeze({ cache, files, abi, loads });
    } catch (error) { this.#failed = true; throw error; }
    finally { this.#checking = false; }
  }
  accept(event) {
    demand(!this.#failed && this.#phase !== "closed", "prepared child is invalidated");
    try { eventAccept.call(this.#events, event); } catch (error) { this.#failed = true; throw error; }
  }
  finishAfterEof() {
    demand(!this.#failed && this.#phase === "hook-complete" && this.#hookObservation,
      "original final hook did not complete before stream EOF");
    try {
      const final = this.#recheck(), events = eventFinish.call(this.#events); this.#phase = "consumed";
      return Object.freeze({ schema: "sorafs.javascript.child_observation.v1", inputSha256: this.#input.inputSha256,
        runtime: Object.freeze({ version: process.version, platform: process.platform, arch: process.arch }),
        inputs: this.#capture, subjects: Object.freeze(this.#subjects.map(({ specifier, url }) => Object.freeze({ specifier, url }))),
        native: final, events, finalHook: "completed", stream: "eof" });
    } catch (error) { this.#failed = true; throw error; }
  }
  close() {
    this.#phase = "closed"; this.#failed = true;
    const loads = this.#loads, files = this.#files, input = this.#inputOwner;
    this.#loads = this.#files = this.#inputOwner = undefined;
    const errors = [];
    for (const action of [() => loads && loadClose.call(loads), () => files && filesClose.call(files), () => input?.close()])
      try { action(); } catch (error) { errors.push(error); }
    if (errors.length) throw new AggregateError(errors, "child owner cleanup failed");
  }
}

/** Called only by the fixed bootstrap before the entry's original import. */
export function prepareChild(expectedInputSha256) {
  demand(prepared === undefined, "child preparation is one-shot");
  prepared = null; // Reserve this sole attempt before any descriptor or hook acquisition.
  const owner = new PreparedChild(expectedInputSha256); prepared = owner; return owner;
}
/** Called only by the fixed entry; retains the actual original prepared owner. */
export async function registerPreparedChild() {
  demand(prepared instanceof PreparedChild, "entry has no original prepared owner");
  await prepared.register();
}
