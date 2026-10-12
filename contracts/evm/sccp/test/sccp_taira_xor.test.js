"use strict";

// Behaviour and revert-path suite for `contracts/evm/sccp/SccpTairaXor.sol`
// (`specs/sccp.md` §5.1, §5.2 and the §11.5 contract rules) on the locked EDR
// runtime. Every test runs under the Prague and the Osaka rules and for both
// destination profiles (Ethereum, chain id 1; BSC, chain id 56).
//
// `sccp_v1_fixtures.test.js` replays the shared fixtures. This suite covers
// what no fixture row reaches: every constructor bound at both edges, the
// chain-identity check of every state-changing entry point, every admitted and
// excluded committee size, the order of the `VerifyCertificate` steps, the
// block-reference and payload rules, the supply cap and the bitmap word
// boundaries, deadline edges, voids, the canonical calldata of
// `transferToTaira` and `voidFrozen`, controls on both tracks and the binding
// of a control leaf, the pause, latches, rotations, checkpoint use after a
// rotation, the saturating arithmetic of §5.1.2, the ERC-20 surface, and the
// publication of `SccpCertificate` exactly on the full path. Transfer and
// control leaves are minted for each profile's own lane and for the CREATE2
// address of the destination under test, so the BSC profile runs every leaf
// rule too.
//
// Every certificate is signed by the independent model (`sccp_v1_model.js`),
// which first reproduces the certificates of `fixtures/sccp/finality_v1.json`
// byte for byte. Calls are encoded and logs are built with the model's
// interface, never with the ABI the compiler emitted. Destinations are created
// through the deterministic deployer of §5.2.1.
//
// The last test of every run is the coverage listing: each refusal a test
// asserts is recorded under its error name, and the listing must contain every
// error the compiled contract declares. It also names the one outcome outside
// the §5.2.2 error table (`OUTSIDE_THE_ERROR_TABLE`) and fails if a test
// reached any other, such as a Solidity panic.
//
// Run: `node --test contracts/evm/sccp/test/sccp_taira_xor.test.js` with the
// locked EVM runtime installed (`npm ci --ignore-scripts` in
// `scripts/contract_tooling/evm-runtime`, or `SCCP_EVM_RUNTIME_DIR` /
// `NODE_PATH` naming an installed copy). Test-only convenience:
// `SCCP_ERROR_COVERAGE_REPORT=<file>` also writes the coverage listing as JSON.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const { after, describe, it } = require("node:test");
const m = require("./sccp_v1_model.js");
const h = require("./sccp_edr_harness.js");
const r = require("./sccp_replay.js");

const { ethers, ZERO32, ZERO_ADDRESS, U64_MAX } = m;
const { ethereum: ETHEREUM, bsc: BSC } = m.PROFILES;
const abi = ethers.AbiCoder.defaultAbiCoder();

const HARDFORKS = Object.freeze(["prague", "osaka"]);
const PROFILES = Object.freeze([ETHEREUM, BSC]);
// A chain id that is no profile's: a destination copied there refuses every entry point.
const UNRELATED_CHAIN = Object.freeze({ name: "unrelated", chainId: 11_155_111n });

const NETWORK_ID = `0x${"5a".repeat(32)}`;
const OTHER_NETWORK_ID = `0x${"a5".repeat(32)}`;
const INSTANCE = `0x${"c3".repeat(32)}`;
const REVISION = 3;
const UNIT = 1_000_000_000n; // one XOR in Taira units (9 decimals)
const CAP = 1_000_000n * UNIT;
const T0 = 1_800_000_000n; // deployment time of every destination, in seconds
const HOUR = 3_600n;
const DAY = 86_400n;
const VALIDITY_MS = 14n * DAY * 1000n;
const GENERATION = 7n;
const START = 1_000n;
const U128_MAX = (1n << 128n) - 1n;
const U256_MAX = (1n << 256n) - 1n;
// The last block time whose milliseconds fit `u64` (§5.1.2 "Arithmetic").
const LAST_UNSATURATED_SECOND = U64_MAX / 1000n;
const TAIRA_RECIPIENT = ethers.concat(["0x0102", ethers.keccak256("0x02")]); // 34 bytes
const FIELD_P_BYTES = m.be(m.FIELD_P, 48);
// The address the dirty-memory runs move every build to, so that all of them see the same leaves.
const SHARED_ADDRESS = ethers.getAddress(`0x${"33".repeat(20)}`);
const FIXED_RECIPIENT = ethers.getAddress(`0x${"c1".repeat(20)}`);

/** Entry points of the revision 4 attestation transport (§5.2.2 "Removed"). */
const RETIRED_SELECTORS = Object.freeze([
  "0x8056d161", // finalizeFromTaira (attestation form)
  "0x96925736", // finalizeFromTairaHistorical
  "0x909ea456", // rotateRosters
  "0x0ce970d6", // applyControl (attestation form)
  "0x935a913b", // applyControlHistorical
  "0xc3de98ad", // voidExpired (attestation form)
  "0xbe335b84", // voidExpiredHistorical
  "0x85a00f5c", // rosterState
]);
const RETIRED_VIEWS = Object.freeze([
  "rosterState()",
  "domainSeparator()",
  "initialRosterDigest()",
  "initialRosterGeneration()",
  "maxRosterValidityMs()",
]);

const EMPTY_REVERT = "(empty revert data)";
/**
 * Outcomes that are no row of the §5.2.2 error table, with the only way each
 * arises. The coverage listing requires exactly these besides the declared
 * errors.
 */
const OUTSIDE_THE_ERROR_TABLE = Object.freeze({
  [EMPTY_REVERT]:
    "Solidity's ABI decoder (a typed calldata word above its width, calldata that is too short, an unknown or " +
    "retired selector, value sent to a non-payable function) and a hash-to-G2 precompile that ran out of gas",
});

const ms = (seconds) => BigInt(seconds) * 1000n;
const id = (text) => ethers.id(text);

// ---------------------------------------------------------------------------
// Coverage listing
// ---------------------------------------------------------------------------

/** `hardfork/profile` → error name → the titles of the tests that asserted it. */
const coverage = new Map();

function recordRefusal(ctx, name) {
  const key = `${ctx.hardfork}/${ctx.profile.name}`;
  const errors = coverage.get(key) ?? new Map();
  const tests = errors.get(name) ?? new Set();
  tests.add(ctx.title);
  errors.set(name, tests);
  coverage.set(key, errors);
}

/**
 * Requires `outcome` to be a revert with exactly the error `name` and the
 * arguments `args` (`name === null`: empty revert data), and records it in the
 * coverage listing. An error that takes arguments must be given them.
 */
function refused(ctx, outcome, name, args = [], where = "") {
  const label = `${ctx.title}${where ? `: ${where}` : ""}`;
  const expected = name ?? EMPTY_REVERT;
  assert(outcome.revert !== undefined, `${label}: expected ${expected}, but the call succeeded`);
  const error = h.decodeRevert(outcome.revert);
  assert.equal(error.name, name, `${label}: expected ${expected}, got ${h.describeRevert(outcome.revert)}`);
  assert.deepEqual(error.args, args, `${label}: arguments of ${expected}`);
  recordRefusal(ctx, expected);
}

/** Requires `outcome` to be a mined, successful transaction and returns its receipt. */
function ok(ctx, outcome, where = "") {
  const label = `${ctx.title}${where ? `: ${where}` : ""}`;
  assert(outcome.receipt, `${label}: reverted with ${outcome.revert && h.describeRevert(outcome.revert)}`);
  return outcome.receipt;
}

// ---------------------------------------------------------------------------
// Destinations and the model's Taira
// ---------------------------------------------------------------------------

const committees = new Map();

/** A committee of `n` §11.3 test keys; `family` selects a disjoint key set. */
function committeeOf(n, family = 0) {
  const key = `${n}/${family}`;
  if (!committees.has(key)) {
    const indices = Array.from({ length: n }, (_, index) => (40 + 31 * family + index) % 256);
    committees.set(key, m.committee(`n${n}/f${family}`, indices));
  }
  return committees.get(key);
}

/**
 * A key set of a size §3.8 does not admit, in canonical order with its root,
 * in the shape of `m.committee`: `q = n − f` as the rule would give it.
 */
function irregularCommittee(n) {
  const members = Array.from({ length: n }, (_, index) => 200 + index).map((index) => ({
    key: m.testPublicKey(index % 256),
    secret: m.testSecret(index % 256),
  }));
  members.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const keys = members.map((member) => member.key);
  return Object.freeze({
    name: `irregular n${n}`,
    n,
    q: n - Math.floor((n - 1) / 3),
    keys,
    secrets: members.map((member) => member.secret),
    root: m.committeeRoot(keys),
    bytes: ethers.concat(keys),
  });
}

function tairaFor({ profile, destinationWord, revision = REVISION, generation = GENERATION, start = START, signedBy }) {
  const taira = new m.TairaModel({ networkId: NETWORK_ID, instance: INSTANCE, profile, destinationWord, revision });
  taira.start(generation, signedBy, start, VALIDITY_MS);
  return taira;
}

/**
 * A fresh chain of `run.profile` under `run.hardfork` with one destination,
 * deployed at `at` seconds (default `T0`) through the deterministic deployer
 * and pinned to `signedBy` (default: the committee of `n` test keys), and the
 * model's Taira for it. `target` selects the build (`sccp_replay.js`);
 * `relocateTo` moves the destination before any leaf names it.
 */
async function open(run, options = {}) {
  const { hardfork, profile } = run;
  const signedBy = options.signedBy ?? committeeOf(options.n ?? 4);
  const at = options.at ?? T0;
  const target = options.target ?? r.PRODUCTION;
  const deployment = {
    tairaNetworkId: NETWORK_ID,
    consensusInstance: INSTANCE,
    networkTag: profile.tag,
    routeRevision: options.revision ?? REVISION,
    maxWrappedSupply: options.cap ?? CAP,
    initialGeneration: options.generation ?? GENERATION,
    initialCommitteeRoot: signedBy.root,
    initialStartHeight: options.start ?? START,
    initialUntilMs: options.untilMs ?? ms(at) + VALIDITY_MS,
  };
  const chain = await h.Chain.open(profile, {
    hardfork,
    allowBlocksWithSameTimestamp: options.sameTimestamp ?? false,
  });
  try {
    let { destination } = await h.deploy(chain, deployment, { at, creation: target.creation });
    if (options.relocateTo !== undefined) destination = await h.relocate(destination, options.relocateTo);
    const taira = tairaFor({
      profile,
      destinationWord: m.addressWord(destination.address),
      revision: deployment.routeRevision,
      generation: deployment.initialGeneration,
      start: deployment.initialStartHeight,
      signedBy,
    });
    return {
      ...run,
      title: run.title ?? "",
      chain,
      dest: destination,
      taira,
      deployment,
      signedBy,
      target,
      recipient: ethers.getAddress(chain.accounts[9]),
    };
  } catch (error) {
    await chain.close();
    throw error;
  }
}

/** A second Taira with the keys and the route of `ctx.taira`: the blocks a departed quorum forges. */
function forgerOf(ctx) {
  const { taira } = ctx;
  const { generation, committee, startHeight } = taira.current;
  return tairaFor({
    profile: taira.profile,
    destinationWord: taira.destinationWord,
    revision: taira.revision,
    generation,
    start: startHeight,
    signedBy: committee,
  });
}

/** A block of the current generation of `taira` whose header takes `fields` as they stand. */
function headerBlock(taira, fields) {
  const { generation, committee } = taira.current;
  const header = {
    networkId: taira.networkId,
    flags: m.FLAG_ACTIVE,
    messageCount: 0n,
    sccpRoot: ZERO32,
    historySize: 0n,
    historyRoot: ZERO32,
    generation,
    committeeRoot: committee.root,
    validityMs: 0n,
    nextCommitteeRoot: ZERO32,
    ...fields,
  };
  const x = m.encodeHeader(header);
  return { height: BigInt(header.height), header, x, committee, leaves: [], historyIndex: null };
}

/**
 * A transfer leaf for the destination of `ctx`. `overrides` replace payload
 * fields as `m.encodePayload` takes them; `binding` replaces what the leaf
 * binds besides the payload (`networkId`, `profile`, `destinationWord`).
 */
function transferOf(ctx, transfer, binding = {}) {
  const { nonce, amount = UNIT, deadlineMs = ms(T0 + DAY), recipient = ctx.recipient, overrides = {} } = transfer;
  const fields = m.outboundFields(ctx.profile, {
    nonce,
    revision: ctx.taira.revision,
    deadlineMs,
    amount,
    sender: m.DEFAULT_TAIRA_SENDER,
    recipient,
  });
  const payload = m.encodePayload({ ...fields, ...overrides });
  const laneProfile = binding.profile ?? ctx.profile;
  const messageId = m.outboundMessageId(binding.networkId ?? NETWORK_ID, laneProfile, payload);
  return {
    kind: "transfer",
    leaf: m.transferLeaf(messageId, binding.destinationWord ?? ctx.taira.destinationWord),
    payload,
    nonce: BigInt(nonce),
    amount: BigInt(amount),
    recipient,
    // The id the destination computes, over its own lane.
    messageId: m.outboundMessageId(NETWORK_ID, ctx.profile, payload),
  };
}

/** The six control fields of a leaf, with ids derived from the nonce. */
function controlFields(controlNonce, track = 1, parliamentPaused = false, fastPauseUntilMs = 0n) {
  return {
    controlNonce: BigInt(controlNonce),
    track,
    parliamentPaused,
    fastPauseUntilMs: BigInt(fastPauseUntilMs),
    certificateId: id(`certificate ${controlNonce}/${track}`),
    effectHash: id(`effect ${controlNonce}/${track}`),
  };
}

/**
 * A control leaf for the destination of `ctx`, built as it stands. `binding`
 * replaces what the leaf binds besides the fields (`networkId`, `profile`,
 * `laneBytes`, `destinationWord`, `revision`).
 */
function controlOf(ctx, fields, binding = {}) {
  const leaf = m.controlLeaf({
    networkId: binding.networkId ?? NETWORK_ID,
    profile: binding.profile ?? ctx.profile,
    laneBytes: binding.laneBytes,
    destinationWord: binding.destinationWord ?? ctx.taira.destinationWord,
    revision: binding.revision ?? ctx.taira.revision,
    nonce: fields.controlNonce,
    track: fields.track,
    parliamentPaused: fields.parliamentPaused,
    fastPauseUntilMs: fields.fastPauseUntilMs,
    certificateId: fields.certificateId,
    effectHash: fields.effectHash,
  });
  return ctx.taira.recordedControl(leaf, fields);
}

/** The proof of leaf `item` of `block`, a block of `taira`, under the header of `certified`. */
function proofOf(taira, item, block, certified = block) {
  const index = block.leaves.indexOf(item);
  assert(index >= 0, "the leaf is in the block");
  return item.kind === "transfer"
    ? taira.messageProof(block.height, index, certified)
    : taira.controlProof(block.height, index, certified);
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

function call(ctx, name, args, options) {
  return ctx.dest.attempt(ctx.target.encode(name, args), options);
}

const submit = (ctx, certificates, options) =>
  call(ctx, "submitCheckpoints", [certificates.map(r.certificateArg)], options);
const finalizeInline = (ctx, certificate, proof, options) =>
  call(ctx, "finalizeFromTaira", [r.certificateArg(certificate), r.messageProofArg(proof)], options);
const finalizeStored = (ctx, x, proof, options) =>
  call(ctx, "finalizeFromCheckpoint", [[x], r.messageProofArg(proof)], options);
const controlInline = (ctx, certificate, proof, options) =>
  call(ctx, "applyControl", [r.certificateArg(certificate), r.controlProofArg(proof)], options);
const controlStored = (ctx, x, proof, options) =>
  call(ctx, "applyControlFromCheckpoint", [[x], r.controlProofArg(proof)], options);
const voidInline = (ctx, nonce, certificate, proof, options) =>
  call(ctx, "voidExpired", [nonce, r.certificateArg(certificate), r.messageProofArg(proof)], options);
const voidStored = (ctx, nonce, x, proof, options) =>
  call(ctx, "voidExpiredFromCheckpoint", [nonce, [x], r.messageProofArg(proof)], options);
const voidFrozen = (ctx, first, count, options) => call(ctx, "voidFrozen", [first, count], options);
const burn = (ctx, from, amount, nonce, options = {}, tairaRecipient = TAIRA_RECIPIENT) =>
  call(ctx, "transferToTaira", [tairaRecipient, amount, nonce], { ...options, from });

/** Runs `body` on a snapshot of the chain of `ctx` and returns the chain to it afterwards. */
async function onSnapshot(ctx, body) {
  const snapshot = await ctx.chain.snapshot();
  try {
    return await body();
  } finally {
    await ctx.chain.restore(snapshot);
  }
}

// ---------------------------------------------------------------------------
// Logs and state
// ---------------------------------------------------------------------------

const log = (name, ...values) => m.eventLog(name, values);

/** `SccpCertificate` of a certificate whose header parses. */
function published(certificate) {
  const header = m.parseHeader(certificate.header);
  const { qc, signature } = certificate;
  return log("SccpCertificate", header.height, header.generation, qc, certificate.header, signature);
}

const stored = (block) => log("SccpCheckpointed", block.height, m.checkpointId(block.x));
const rotated = (block, untilMs) =>
  log("SccpCommitteeRotated", block.header.generation + 1n, block.header.nextCommitteeRoot, untilMs, block.height + 1n);
const latched = (reason, block, a) =>
  log("SccpLatched", reason, block.header.generation, block.height, a, m.checkpointId(block.x));
const minted = (item) => [
  log("Transfer", ZERO_ADDRESS, item.recipient, item.amount),
  log("SccpFinalized", item.messageId, item.nonce, item.recipient, item.amount),
];
const voided = (item) => log("SccpVoided", item.messageId, item.nonce);
const applied = (fields, storedUntilMs = fields.fastPauseUntilMs) =>
  log(
    "SccpControlApplied",
    fields.controlNonce,
    fields.track,
    fields.parliamentPaused,
    storedUntilMs,
    fields.certificateId,
  );

/** Requires the logs of `receipt` to be exactly `expected`, in order, as raw topics and data. */
function assertLogs(ctx, receipt, expected, where) {
  assert.deepEqual(ctx.dest.logs(receipt), expected, `${ctx.title}: ${where}`);
}

async function committeeState(destination) {
  const [root, untilMs, start, high, generation] = await destination.view("committeeState");
  return { root, untilMs, start, high, generation };
}

async function pauseState(destination) {
  const [parliamentPaused, fastPauseUntilMs, controlNonce, effective] = await destination.view("pauseState");
  return { parliamentPaused, fastPauseUntilMs, controlNonce, effective };
}

function storageAt(destination, slot) {
  return destination.chain
    .rpc("eth_getStorageAt", [destination.address, ethers.toQuantity(slot), "latest"])
    .then(BigInt);
}

function setStorageAt(destination, slot, value) {
  return destination.chain.rpc("hardhat_setStorageAt", [destination.address, ethers.toQuantity(slot), m.word(value)]);
}

/** The storage slot of `mapping[key]` for a mapping declared at `slot`. */
function mappingSlot(type, key, slot) {
  return BigInt(ethers.keccak256(abi.encode([type, "uint256"], [key, slot])));
}

/** §5.2.3 slot B and slot C from their fields: the first-named field is the low-order one. */
const packSlotB = ({ untilMs, start, high, generation }) =>
  untilMs | (start << 64n) | (high << 128n) | (generation << 192n);
const packSlotC = ({ controlNonce, opCount, fastPauseUntilMs, parliamentPaused, equivocated }) =>
  controlNonce | (opCount << 64n) | (fastPauseUntilMs << 128n) | (BigInt(parliamentPaused) << 192n) |
  (BigInt(equivocated) << 200n);

/** Copies the code and the non-mapping storage of `destination` to the same address of another chain. */
async function transplant(destination, chain) {
  const source = destination.chain;
  const { address } = destination;
  await chain.rpc("hardhat_setCode", [address, await source.rpc("eth_getCode", [address, "latest"])]);
  for (let slot = 0; slot < 9; slot += 1) {
    const key = ethers.toQuantity(slot);
    await chain.rpc(
      "hardhat_setStorageAt",
      [address, key, await source.rpc("eth_getStorageAt", [address, key, "latest"])],
    );
  }
  return new h.Destination(chain, address, destination.iface);
}

/** `data` with the bytes at `offset` replaced by `replacement`. */
function patch(data, offset, replacement) {
  const bytes = ethers.getBytes(data);
  bytes.set(ethers.getBytes(replacement), offset);
  return ethers.hexlify(bytes);
}

/**
 * The calldata position of the tuple reached from the argument head by
 * following `path`: each entry is the index of an offset word, relative to the
 * tuple that holds it.
 */
function tupleStart(calldata, path) {
  let start = 4;
  for (const index of path) {
    start += Number(BigInt(ethers.dataSlice(calldata, start + 32 * index, start + 32 * (index + 1))));
  }
  return start;
}

/** Head word `index` of the tuple at `path`. */
function wordAt(calldata, path, index) {
  const position = tupleStart(calldata, path) + 32 * index;
  return BigInt(ethers.dataSlice(calldata, position, position + 32));
}

/** `calldata` with head word `index` of the tuple at `path` replaced by `value`. */
function withWord(calldata, path, index, value) {
  return patch(calldata, tupleStart(calldata, path) + 32 * index, m.word(value));
}

/**
 * The canonical `transferToTaira` calldata, or a variant of it: `offset`,
 * `length`, `padding` and `tail` replace its parts, and `inserted` are words
 * put before the length word.
 */
function transferCalldata(recipient, amount, nonce, variant = {}) {
  const length = ethers.dataLength(recipient);
  const padding = variant.padding ?? `0x${"00".repeat((32 - (length % 32)) % 32)}`;
  return ethers.concat([
    m.iface.getFunction("transferToTaira").selector,
    m.word(variant.offset ?? 0x60),
    m.word(amount),
    m.word(nonce),
    ...(variant.inserted ?? []),
    m.word(variant.length ?? length),
    recipient,
    padding,
    variant.tail ?? "0x",
  ]);
}

// ---------------------------------------------------------------------------
// Test wrappers
// ---------------------------------------------------------------------------

/** A test on one fresh destination; `options` are those of `open`. */
function scenario(run, title, options, body) {
  it(title, async (t) => {
    const ctx = await open({ ...run, title }, options);
    try {
      await body(ctx, t);
    } finally {
      await ctx.chain.close();
    }
  });
}

/** `open` options: consecutive blocks may share one timestamp, so that calls can share a second. */
const SAME_SECOND = Object.freeze({ sameTimestamp: true });
/** `open` options: a pin whose first handoff can only be at height and generation 2^64 − 2. */
const NEAR_THE_TOP = Object.freeze({ generation: U64_MAX - 1n, start: U64_MAX - 2n });

/** A test that opens its own chains; `body` gets the run with the test's title. */
function plain(run, title, body) {
  it(title, (t) => body({ ...run, title }, t));
}

// ---------------------------------------------------------------------------
// The compiled interface
// ---------------------------------------------------------------------------

const DECLARED_ERRORS = h
  .loadArtifacts()
  .abi.filter((entry) => entry.type === "error")
  .map((entry) => entry.name)
  .sort();

describe("SccpTairaXor: the compiled interface (§5.2.2)", () => {
  it("declares exactly the functions, events and errors of the specification", () => {
    const compiled = h.loadArtifacts().iface;
    const signatures = (contractInterface, type) =>
      contractInterface.fragments
        .filter((fragment) => fragment.type === type)
        .map((fragment) => fragment.format("sighash"))
        .sort();
    for (const type of ["function", "event", "error"]) {
      assert.deepEqual(signatures(compiled, type), signatures(m.iface, type), `${type} signatures`);
    }
    assert.deepEqual(compiled.deploy.inputs.map((input) => input.type), [...m.CONSTRUCTOR_TYPES]);
    assert.equal(compiled.deploy.payable, false, "the constructor takes no value");
    assert.equal(compiled.fallback, null, "no fallback function");
    assert.equal(compiled.receive, false, "no receive function");
    const functions = compiled.fragments.filter((fragment) => fragment.type === "function");
    assert(functions.every((fragment) => !fragment.payable), "no function is payable");
    assert.deepEqual(
      DECLARED_ERRORS,
      [...m.SCCP_ERRORS, ...m.ERC20_ERRORS].map((error) => ethers.ErrorFragment.from(error).name).sort(),
    );
    assert.equal(DECLARED_ERRORS.length, 31, "26 SCCP errors and 5 ERC-6093 errors");
  });

  it("carries no name of the retired transport, of TON initialization or of an owner", () => {
    const text = JSON.stringify(h.loadArtifacts().abi);
    const retired = /Roster|Historical|Attestation|domainSeparator|DirectCaller|NotInitialized|AlreadyInitialized/;
    assert.equal(retired.test(text), false);
    assert.equal(/owner|admin|guardian|upgrade|pause\(|unpause/i.test(text.replace(/"owner"/g, "")), false);
    const current = new Set(
      m.iface.fragments.filter((fragment) => fragment.type === "function").map((fragment) => fragment.selector),
    );
    for (const selector of [...RETIRED_SELECTORS, ...RETIRED_VIEWS.map(m.selector)]) {
      assert(!current.has(selector), `${selector} is not a current selector`);
    }
    assert.equal(m.selector("rosterState()"), RETIRED_SELECTORS.at(-1));
  });
});

// ---------------------------------------------------------------------------
// Certificates that do not depend on the destination profile, minted once
// ---------------------------------------------------------------------------

const ADMITTED_SIZES = Object.freeze([4, 7, 10, 13, 16, 19, 22, 25, 28, 31]);
const EXCLUDED_SIZES = Object.freeze([1, 2, 3, 5, 6, 8, 32, 34]);
const sizeKits = new Map();

/**
 * For a committee of `n` keys: two blocks without leaves, with certificates
 * of the highest `q` signers, of a scattered quorum, of `q + 1` signers and
 * of `q − 1` signers.
 */
function sizeKit(n, signedBy = committeeOf(n)) {
  if (!sizeKits.has(n)) {
    const taira = tairaFor({ profile: ETHEREUM, destinationWord: ZERO32, signedBy });
    const { q } = signedBy;
    // The `signers` word has 32 bits, so a key set above 32 is signed by members 0..31 only.
    const members = Math.min(n, 32);
    const all = Array.from({ length: members }, (_, index) => index);
    const scattered = Array.from({ length: q }, (_, k) => (q === 1 ? 0 : Math.floor((k * (members - 1)) / (q - 1))));
    assert.equal(new Set(scattered).size, q, "the scattered quorum has q distinct signers");
    const blocks = [0n, 1n].map((offset) => taira.block(1010n + offset, ms(T0 + 10n), []));
    sizeKits.set(n, {
      signedBy,
      blocks,
      highest: taira.certify(blocks[0], { signerIndices: all.slice(members - q) }),
      scattered: taira.certify(blocks[1], { signerIndices: scattered }),
      superset: members > q ? taira.certify(blocks[1], { signerIndices: all.slice(0, q + 1) }) : null,
      subset: q > 1 ? taira.certify(blocks[1], { signerIndices: all.slice(0, q - 1) }) : null,
    });
  }
  return sizeKits.get(n);
}

/** `certificate` with the `signers` word of its `QC_FIXED` replaced. */
function withSigners(certificate, signers) {
  return { ...certificate, qc: patch(certificate.qc, 112, m.be(signers, 4)) };
}

// ---------------------------------------------------------------------------
// Dirty-memory scripts
// ---------------------------------------------------------------------------

const dirtyScripts = new Map();

/**
 * One sequence of calls for a destination of `profile` at `SHARED_ADDRESS`
 * pinned to a committee of `n` keys, with the outcome each call must have. It
 * enters every entry point that verifies a certificate, on the full and on the
 * cheap path, with certificates that verify and with certificates that fail
 * at the pairing check and inside `G1ADD`, a batch of 16 certificates, a
 * rotation and a latch. The same calldata runs on every build.
 */
function dirtyScript(profile, n) {
  const key = `${profile.name}/${n}`;
  if (dirtyScripts.has(key)) return dirtyScripts.get(key);
  const signedBy = committeeOf(n);
  const next = committeeOf(n, 1);
  const taira = tairaFor({ profile, destinationWord: m.addressWord(SHARED_ADDRESS), signedBy });
  const ctx = { profile, taira, recipient: FIXED_RECIPIENT };
  const past = ms(T0 + 50n);
  const steps = [];
  const step = (name, args, expected, at) => steps.push({ name, args, expected, at });
  const certificateArg = r.certificateArg;
  const message = (item, block) => r.messageProofArg(proofOf(taira, item, block));
  const control = (item, block) => r.controlProofArg(proofOf(taira, item, block));

  const first = [
    transferOf(ctx, { nonce: 1 }),
    controlOf(ctx, controlFields(1, 1, false, 0n)),
    transferOf(ctx, { nonce: 2, deadlineMs: past }),
  ];
  const a = taira.block(1010n, ms(T0 + 10n), first);
  const certificateA = certificateArg(taira.certify(a));
  step("submitCheckpoints", [[certificateA]], "ok", T0 + 100n);
  step("finalizeFromTaira", [certificateA, message(first[0], a)], "ok");
  step("applyControl", [certificateA, control(first[1], a)], "ok");
  step("voidExpired", [2n, certificateA, message(first[2], a)], "ok");

  const minting = transferOf(ctx, { nonce: 3 });
  const b = taira.block(1011n, ms(T0 + 11n), [minting]);
  step("finalizeFromTaira", [certificateArg(taira.certify(b)), message(minting, b)], "ok");
  const lapsed = controlOf(ctx, controlFields(2, 2, false, past));
  const c = taira.block(1012n, ms(T0 + 12n), [lapsed]);
  step("applyControl", [certificateArg(taira.certify(c)), control(lapsed, c)], "ok");
  const expired = transferOf(ctx, { nonce: 4, deadlineMs: past });
  const d = taira.block(1013n, ms(T0 + 13n), [expired]);
  step("voidExpired", [4n, certificateArg(taira.certify(d)), message(expired, d)], "ok");

  const e = taira.block(1014n, ms(T0 + 14n), []);
  const genuine = taira.certify(e);
  step("submitCheckpoints", [[certificateArg(taira.certify(e, { kind: 0x02 }))]], "BadSignature");
  step("submitCheckpoints", [[certificateArg(offCurve(genuine))]], "BadCommittee");
  step("submitCheckpoints", [[certificateArg({ ...genuine, signature: taira.certify(d).signature })]], "BadSignature");

  const all = Array.from({ length: n }, (_, index) => index);
  const quorums = [all.slice(0, signedBy.q), all.slice(-signedBy.q)];
  const batch = Array.from({ length: m.MAX_CERTIFICATES_PER_CALL }, (_, index) =>
    taira.block(1100n + BigInt(index), ms(T0 + 20n + BigInt(index)), []));
  const certificates = batch.map((block, index) =>
    certificateArg(taira.certify(block, { signerIndices: quorums[index % 2] })));
  step("submitCheckpoints", [certificates], "ok");

  const handoff = taira.block(1200n, ms(T0 + 60n), [], { rotate: "key", nextCommittee: next });
  step("submitCheckpoints", [[certificateArg(taira.certify(handoff))]], "ok");
  const later = transferOf(ctx, { nonce: 5 });
  const f = taira.block(1201n, ms(T0 + 61n), [later]);
  step("finalizeFromTaira", [certificateArg(taira.certify(f)), message(later, f)], "ok");
  // The successor generation signs another header at height 1201: an inline use refuses, a checkpoint latches.
  const conflict = headerBlock(taira, { height: 1201n, timestampMs: ms(T0 + 62n) });
  const conflicting = certificateArg(taira.certify(conflict));
  step("finalizeFromTaira", [conflicting, message(later, f)], "LatchRequired");
  step("submitCheckpoints", [[conflicting]], "ok");
  step("submitCheckpoints", [[certificateA]], "Equivocated");

  const script = Object.freeze({
    signedBy,
    steps,
    heights: [1009n, 1010n, 1011n, 1012n, 1013n, 1014n, 1099n, 1100n, 1115n, 1116n, 1200n, 1201n, 1202n],
    nonces: [0n, 1n, 2n, 3n, 4n, 5n, 6n],
  });
  dirtyScripts.set(key, script);
  return script;
}

/** `certificate` with the `y` of its first signer moved off the curve, on the same side of `HALF_P`. */
function offCurve(certificate) {
  const y = BigInt(ethers.dataSlice(certificate.signerYs, 0, 48));
  const moved = (y + 1n > m.HALF_P) === (y > m.HALF_P) && y + 1n < m.FIELD_P ? y + 1n : y - 1n;
  assert.equal(moved > m.HALF_P, y > m.HALF_P, "the moved y keeps the sign flag of the key");
  return { ...certificate, signerYs: patch(certificate.signerYs, 0, m.be(moved, 48)) };
}

// ---------------------------------------------------------------------------
// The suite, per hardfork and profile
// ---------------------------------------------------------------------------

for (const hardfork of HARDFORKS) {
  for (const profile of PROFILES) {
    const other = profile === ETHEREUM ? BSC : ETHEREUM;
    const run = Object.freeze({ hardfork, profile });

    describe(`SccpTairaXor on ${profile.name} (chain id ${profile.chainId}), ${hardfork}`, () => {
      // -- construction -------------------------------------------------------

      plain(run, "constructor: every bound at both edges, WrongChain for tag and chain id (§5.2.1)", async (ctx) => {
        const signedBy = committeeOf(4);
        const nowMs = ms(T0);
        const bound = m.MAX_VALIDITY_MS + m.MAX_INIT_SLACK_MS;
        const base = {
          tairaNetworkId: NETWORK_ID,
          consensusInstance: INSTANCE,
          networkTag: profile.tag,
          routeRevision: REVISION,
          maxWrappedSupply: CAP,
          initialGeneration: GENERATION,
          initialCommitteeRoot: signedBy.root,
          initialStartHeight: START,
          initialUntilMs: nowMs + VALIDITY_MS,
        };
        const chains = [];
        const openChain = async (chainProfile) => {
          const chain = await h.Chain.open(chainProfile, { hardfork, allowBlocksWithSameTimestamp: true });
          chains.push(chain);
          await chain.installDeployer();
          return chain;
        };
        try {
          const chain = await openChain(profile);
          // The constructor's own error, then the same init code through the deployer, which
          // answers a failed creation with empty data and leaves no code.
          const refuse = async (onChain, init, error, where) => {
            refused(ctx, await onChain.attempt({ data: init, at: T0 }), error, [], where);
            const viaDeployer = { to: m.SCCP_EVM_DEPLOYER, data: ethers.concat([m.SCCP_EVM_SALT, init]), at: T0 };
            refused(ctx, await onChain.attempt(viaDeployer), null, [], `${where}, through the deployer`);
            assert.equal(await onChain.rpc("eth_getCode", [m.create2Address(init), "latest"]), "0x", where);
          };
          const refusals = [
            ["the Taira tag", { networkTag: m.TAIRA_TAG }, "WrongChain"],
            ["the tag of the other profile", { networkTag: other.tag }, "WrongChain"],
            ["the retired tag 0x43", { networkTag: 0x43 }, "WrongChain"],
            ["tag 0", { networkTag: 0 }, "WrongChain"],
            ["tag 0xff", { networkTag: 0xff }, "WrongChain"],
            ["an unknown tag together with a zero revision", { networkTag: 0x44, routeRevision: 0 }, "WrongChain"],
            ["a zero Taira network id", { tairaNetworkId: ZERO32 }, "BadConfig"],
            ["a zero consensus instance", { consensusInstance: ZERO32 }, "BadConfig"],
            ["route revision 0", { routeRevision: 0 }, "BadConfig"],
            ["a supply cap of 0", { maxWrappedSupply: 0n }, "BadConfig"],
            ["a supply cap of 2^128", { maxWrappedSupply: U128_MAX + 1n }, "BadConfig"],
            ["a supply cap of 2^256 − 1", { maxWrappedSupply: U256_MAX }, "BadConfig"],
            ["generation 0", { initialGeneration: 0n }, "BadConfig"],
            ["a zero committee root", { initialCommitteeRoot: ZERO32 }, "BadConfig"],
            ["start height 0", { initialStartHeight: 0n }, "BadConfig"],
            ["untilMs 0", { initialUntilMs: 0n }, "BadConfig"],
            ["untilMs one millisecond before now", { initialUntilMs: nowMs - 1n }, "BadConfig"],
            ["untilMs equal to now", { initialUntilMs: nowMs }, "BadConfig"],
            ["untilMs one millisecond above the bound", { initialUntilMs: nowMs + bound + 1n }, "BadConfig"],
            ["untilMs 2^64 − 1", { initialUntilMs: U64_MAX }, "BadConfig"],
          ];
          for (const [where, overrides, error] of refusals) {
            await refuse(chain, h.initCode({ ...base, ...overrides }), error, where);
          }
          // The chain id is the profile's identity word: the own tag is refused everywhere else.
          for (const foreign of [other, UNRELATED_CHAIN]) {
            const where = `the own tag on chain id ${foreign.chainId}`;
            await refuse(await openChain(foreign), h.initCode(base), "WrongChain", where);
          }
          // Typed constructor words above their width, a missing word and value: the ABI decoder.
          const { creation } = h.loadArtifacts();
          const args = m.constructorArgs(base);
          const dirty = [
            ["a network tag word above uint8", 2, BigInt(profile.tag) | (1n << 8n)],
            ["a route revision word above uint32", 3, BigInt(REVISION) | (1n << 32n)],
            ["a generation word above uint64", 5, GENERATION | (1n << 64n)],
            ["a start height word above uint64", 7, START | (1n << 64n)],
            ["an untilMs word above uint64", 8, base.initialUntilMs | (1n << 64n)],
          ];
          for (const [where, index, value] of dirty) {
            const types = m.CONSTRUCTOR_TYPES.map((type, position) => (position === index ? "uint256" : type));
            const values = args.map((argument, position) => (position === index ? value : argument));
            await refuse(chain, ethers.concat([creation, abi.encode(types, values)]), null, where);
          }
          const encoded = m.encodeConstructorArgs(base);
          await refuse(chain, ethers.concat([creation, ethers.dataSlice(encoded, 0, 8 * 32)]), null, "eight words");
          const withValue = await chain.attempt({ data: h.initCode(base), value: 1n, at: T0 });
          refused(ctx, withValue, null, [], "value sent to the constructor");

          // Accepted edges: each deploys and holds exactly the pinned state.
          const accepted = [
            ["untilMs one millisecond after now", { initialUntilMs: nowMs + 1n }],
            ["untilMs at the bound", { initialUntilMs: nowMs + bound }],
            ["a supply cap of 1", { maxWrappedSupply: 1n }],
            ["a supply cap of 2^128 − 1", { maxWrappedSupply: U128_MAX }],
            [
              "generation 1, start height 1, revision 1",
              { initialGeneration: 1n, initialStartHeight: 1n, routeRevision: 1 },
            ],
            [
              "the largest generation, start height and revision",
              { initialGeneration: U64_MAX, initialStartHeight: U64_MAX, routeRevision: 0xffffffff },
            ],
          ];
          for (const [where, overrides] of accepted) {
            const deployment = { ...base, ...overrides };
            const { destination, receipt } = await h.deploy(chain, deployment, { at: T0 });
            assert.equal(receipt.logs.length, 0, `${where}: the constructor emits nothing`);
            assert.deepEqual(await committeeState(destination), {
              root: deployment.initialCommitteeRoot,
              untilMs: deployment.initialUntilMs,
              start: deployment.initialStartHeight,
              high: deployment.initialStartHeight - 1n,
              generation: deployment.initialGeneration,
            }, where);
            assert.deepEqual([...(await destination.view("initialCommittee"))], [
              deployment.initialGeneration,
              deployment.initialCommitteeRoot,
              deployment.initialStartHeight,
              deployment.initialUntilMs,
            ], where);
            assert.deepEqual(
              await pauseState(destination),
              { parliamentPaused: false, fastPauseUntilMs: 0n, controlNonce: 0n, effective: false },
              where,
            );
            assert.equal(await destination.view("routeRevision"), BigInt(deployment.routeRevision), where);
            assert.equal(await destination.view("maxWrappedSupply"), deployment.maxWrappedSupply, where);
            assert.equal(await destination.view("opCount"), 0n, where);
            assert.equal(await destination.view("equivocated"), false, where);
            assert.equal(await destination.view("totalSupply"), 0n, where);
            assert.equal(
              await chain.rpc("eth_getCode", [destination.address, "latest"]),
              h.expectedRuntime(h.immutableWords(deployment)),
              `${where}: the runtime is the locked template with the nine immutables`,
            );
          }
          // A deadline one millisecond after the deployment time: Live in that second only.
          const briefly = new h.Destination(
            chain,
            m.create2Address(h.initCode({ ...base, initialUntilMs: nowMs + 1n })),
          );
          const frozen = m.iface.encodeFunctionData("voidFrozen", [0n, 1n]);
          refused(ctx, await briefly.attempt(frozen, { at: T0 }), "NotFrozen", [], "now_ms < untilMs");
          ok(ctx, await briefly.attempt(frozen, { at: T0 + 1n }), "now_ms > untilMs");
        } finally {
          for (const chain of chains) await chain.close();
        }
      });

      scenario(run, "views, immutables and the storage layout of §5.2.3", {}, async (ctx) => {
        const { chain, dest, taira, deployment, signedBy } = ctx;
        const holder = ctx.recipient;
        const spender = ethers.getAddress(chain.accounts[3]);
        const { immutableReferences } = h.loadArtifacts();
        assert.deepEqual(
          [...new Set(immutableReferences.map((reference) => reference.name))].sort(),
          Object.keys(h.immutableWords(deployment)).sort(),
          "the runtime reads exactly the nine immutables",
        );
        assert.equal(
          await chain.rpc("eth_getCode", [dest.address, "latest"]),
          h.expectedRuntime(h.immutableWords(deployment)),
        );
        assert.equal(await dest.view("name"), "Taira XOR");
        assert.equal(await dest.view("symbol"), "tXOR");
        assert.equal(await dest.view("decimals"), 9n);
        assert.equal(await dest.view("totalSupply"), 0n);
        assert.equal(await dest.view("tairaNetworkId"), NETWORK_ID);
        assert.equal(await dest.view("consensusInstance"), INSTANCE);
        assert.equal(await dest.view("routeRevision"), BigInt(REVISION));
        assert.equal(await dest.view("maxWrappedSupply"), CAP);
        assert.equal(await dest.view("maxValidityMs"), m.MAX_VALIDITY_MS);
        assert.deepEqual(
          [...(await dest.view("initialCommittee"))],
          [GENERATION, signedBy.root, START, ms(T0) + VALIDITY_MS],
        );
        assert.equal(await dest.view("checkpointHeader", [START]), ZERO32);
        assert.equal(await dest.view("isConsumed", [0n]), false);
        assert.equal(await dest.view("transferNonces", [holder]), 0n);
        assert.equal(await dest.view("mintingPaused"), false);

        const cur = { untilMs: ms(T0) + VALIDITY_MS, start: START, high: START - 1n, generation: GENERATION };
        const fresh = {
          controlNonce: 0n,
          opCount: 0n,
          fastPauseUntilMs: 0n,
          parliamentPaused: false,
          equivocated: false,
        };
        assert.equal(await storageAt(dest, 0), BigInt(signedBy.root), "slot A");
        assert.equal(await storageAt(dest, 1), packSlotB(cur), "slot B");
        assert.equal(await storageAt(dest, 2), packSlotC(fresh), "slot C");
        for (let slot = 3; slot <= 8; slot += 1) assert.equal(await storageAt(dest, slot), 0n, `slot ${slot}`);

        // A mint, a control, a burn and an approval, then every slot they wrote.
        const item = transferOf(ctx, { nonce: 300, amount: 5n * UNIT });
        const fields = controlFields(9, 2, true, ms(T0 + 2n * HOUR));
        const pause = controlOf(ctx, fields);
        const block = taira.block(1010n, ms(T0 + 10n), [item, pause]);
        ok(ctx, await finalizeInline(ctx, taira.certify(block), proofOf(taira, item, block)));
        ok(ctx, await controlStored(ctx, block.x, proofOf(taira, pause, block)));
        ok(ctx, await burn(ctx, 9, 2n * UNIT, 0n));
        ok(ctx, await call(ctx, "approve", [spender, 77n], { from: 9 }));
        const { fastPauseUntilMs } = fields;
        const state = { ...fresh, controlNonce: 9n, opCount: 3n, fastPauseUntilMs, parliamentPaused: true };
        assert.equal(await storageAt(dest, 0), BigInt(signedBy.root), "slot A");
        assert.equal(await storageAt(dest, 1), packSlotB({ ...cur, high: 1010n }), "slot B after a checkpoint");
        assert.equal(await storageAt(dest, 2), packSlotC(state), "slot C after three operations");
        assert.equal(await storageAt(dest, mappingSlot("uint64", 1010n, 3)), BigInt(m.checkpointId(block.x)));
        assert.equal(
          await storageAt(dest, mappingSlot("uint256", 300n >> 8n, 4)),
          1n << (300n & 255n),
          "bitmap word 1",
        );
        assert.equal(await storageAt(dest, mappingSlot("address", holder, 5)), 1n, "transferNonces");
        assert.equal(await storageAt(dest, 6), 3n * UNIT, "totalSupply");
        assert.equal(await storageAt(dest, mappingSlot("address", holder, 7)), 3n * UNIT, "balanceOf");
        const allowanceSlot = BigInt(
          ethers.keccak256(abi.encode(["address", "uint256"], [spender, mappingSlot("address", holder, 8)])),
        );
        assert.equal(await storageAt(dest, allowanceSlot), 77n, "allowance");
        assert.equal(await dest.view("allowance", [holder, spender]), 77n);
        assert.equal(await dest.view("opCount"), 3n, "an approval is no SCCP operation");
        assert.equal(await dest.view("controlNonce"), 9n);

        // A latch sets the last byte of slot C and zeroes `untilMs`, the low word of slot B.
        const conflict = forgerOf(ctx).block(1010n, ms(T0 + 11n), []);
        ok(ctx, await submit(ctx, [taira.certify(conflict)]));
        assert.equal(await storageAt(dest, 1), packSlotB({ ...cur, high: 1010n, untilMs: 0n }), "slot B after a latch");
        assert.equal(await storageAt(dest, 2), packSlotC({ ...state, equivocated: true }), "slot C after a latch");
        assert.equal(await dest.view("equivocated"), true);
      });

      scenario(run, "retired and unknown selectors, short calldata and value: empty revert data", {}, async (ctx) => {
        const { chain, dest } = ctx;
        const selectors = [...RETIRED_SELECTORS, ...RETIRED_VIEWS.map(m.selector), "0xdeadbeef", "0x00000000"];
        for (const selector of selectors) {
          for (const data of [selector, ethers.concat([selector, m.word(0), m.word(0)])]) {
            refused(ctx, await dest.attempt(data), null, [], `selector ${selector}`);
            await assert.rejects(chain.call(dest.address, data), `eth_call of ${selector}`);
          }
        }
        refused(ctx, await dest.attempt("0x"), null, [], "empty calldata");
        refused(ctx, await dest.attempt("0x5b094c"), null, [], "three bytes of calldata");
        refused(ctx, await dest.attempt("0x", { value: 1n }), null, [], "a plain value transfer");
        const calls = [
          m.iface.encodeFunctionData("voidFrozen", [0n, 1n]),
          m.iface.encodeFunctionData("approve", [ctx.recipient, 1n]),
          m.iface.encodeFunctionData("submitCheckpoints", [[]]),
          m.iface.encodeFunctionData("transferToTaira", [TAIRA_RECIPIENT, 1n, 0n]),
        ];
        for (const data of calls) refused(ctx, await dest.attempt(data, { value: 1n }), null, [], "value with a call");
        assert.equal(BigInt(await chain.rpc("eth_getBalance", [dest.address, "latest"])), 0n);
        assert.equal(await dest.view("opCount"), 0n);
      });

      plain(run, "WrongChain on every state-changing entry point of a copy on another chain id", async (run0) => {
        const home = await open(run0, { sameTimestamp: true });
        const chains = [];
        try {
          const { taira, dest, deployment } = home;
          const copies = [];
          for (const foreign of [other, UNRELATED_CHAIN]) {
            const chain = await h.Chain.open(foreign, { hardfork, allowBlocksWithSameTimestamp: true });
            chains.push(chain);
            copies.push(await transplant(dest, chain));
          }
          const probes = { heights: [1010n, 1011n], nonces: [1n, 2n, 3n, 4n, 100n] };
          const initial = await dest.state(probes);
          const mints = [1, 2].map((nonce) => transferOf(home, { nonce }));
          const expired = [3, 4].map((nonce) => transferOf(home, { nonce, deadlineMs: ms(T0 + 50n) }));
          const controls = [1, 2].map((nonce) => controlOf(home, controlFields(nonce)));
          const block = taira.block(1010n, ms(T0 + 10n), [...mints, ...expired, ...controls]);
          const next = taira.block(1011n, ms(T0 + 11n), []);
          const certificate = r.certificateArg(taira.certify(block));
          const message = (item) => r.messageProofArg(proofOf(taira, item, block));
          const control = (item) => r.controlProofArg(proofOf(taira, item, block));
          const at = T0 + 100n;
          const frozenAt = deployment.initialUntilMs / 1000n + 1n;
          const steps = [
            ["finalizeFromTaira", [certificate, message(mints[0])], at],
            ["applyControl", [certificate, control(controls[0])], at],
            ["voidExpired", [3n, certificate, message(expired[0])], at],
            ["submitCheckpoints", [[r.certificateArg(taira.certify(next))]], at],
            ["finalizeFromCheckpoint", [[block.x], message(mints[1])], at],
            ["applyControlFromCheckpoint", [[block.x], control(controls[1])], at],
            ["voidExpiredFromCheckpoint", [4n, [block.x], message(expired[1])], at],
            ["transferToTaira", [TAIRA_RECIPIENT, UNIT, 0n], at],
            ["voidFrozen", [100n, 5n], frozenAt],
          ];
          const stateChanging = m.iface.fragments
            .filter((fragment) => fragment.type === "function" && fragment.stateMutability === "nonpayable")
            .map((fragment) => fragment.name)
            .filter((name) => !["transfer", "transferFrom", "approve"].includes(name));
          assert.deepEqual(steps.map(([name]) => name).sort(), stateChanging.sort(), "the nine SCCP entry points");
          for (const [name, args, time] of steps) {
            const data = m.iface.encodeFunctionData(name, args);
            // The call is valid: the destination on its own chain performs it.
            ok(home, await dest.attempt(data, { at: time, from: 9 }), `${name} on the own chain`);
            for (const copy of copies) {
              const where = `${name} on chain id ${copy.chain.profile.chainId}`;
              refused(home, await copy.attempt(data, { at: time, from: 9 }), "WrongChain", [], where);
            }
          }
          assert.equal(await dest.view("opCount"), 8n, "eight counted operations and one checkpoint batch");
          for (const copy of copies) {
            const where = `chain id ${copy.chain.profile.chainId}`;
            // The chain identity comes before every other check of the contract.
            const encode = (name, args) => m.iface.encodeFunctionData(name, args);
            const seventeen = Array.from({ length: 17 }, () => certificate);
            for (const [what, data] of [
              ["an empty batch", encode("submitCheckpoints", [[]])],
              ["17 certificates", encode("submitCheckpoints", [seventeen])],
              ["voidFrozen with a trailing byte", ethers.concat([encode("voidFrozen", [0n, 1n]), "0x00"])],
              ["voidFrozen of an empty range", encode("voidFrozen", [0n, 0n])],
              [
                "transferToTaira with a trailing word",
                transferCalldata(TAIRA_RECIPIENT, UNIT, 0n, { tail: m.word(0) }),
              ],
              ["transferToTaira of amount 0", encode("transferToTaira", [TAIRA_RECIPIENT, 0n, 0n])],
              ["an unknown checkpoint", encode("finalizeFromCheckpoint", [[next.x], message(mints[0])])],
            ]) {
              refused(home, await copy.attempt(data), "WrongChain", [], `${where}: ${what}`);
            }
            // Only the ABI decoder runs earlier (§3.4): a `parliamentPaused` word above 1.
            const dirtyFlag = r.withRawParliamentPaused(encode("applyControl", [certificate, control(controls[0])]), 2);
            refused(home, await copy.attempt(dirtyFlag), null, [], `${where}: a parliamentPaused word of 2`);
            assert.deepEqual(
              { ...(await copy.state(probes)), live: initial.live },
              initial,
              `${where}: nothing changed`,
            );
            assert.equal(await copy.view("tairaNetworkId"), NETWORK_ID, `${where}: views answer`);
          }
        } finally {
          await home.chain.close();
          for (const chain of chains) await chain.close();
        }
      });

      // -- certificate verification ---------------------------------------------

      plain(run, "every committee size in {4, 7, …, 31} verifies with exactly q = n − f signers", async (ctx) => {
        for (const n of ADMITTED_SIZES) {
          const kit = sizeKit(n);
          const { q } = kit.signedBy;
          assert.equal(q, n - (n - 1) / 3, `q of n = ${n}`);
          const live = await open(ctx, { signedBy: kit.signedBy, sameTimestamp: true });
          try {
            const where = `n = ${n}`;
            const at = { at: T0 + 100n };
            // Real signatures of q + 1 and of q − 1 members: `signerYs` is not 48·q bytes.
            refused(live, await submit(live, [kit.superset], at), "BadCertificate", [], `${where}: q + 1 signers`);
            refused(live, await submit(live, [kit.subset], at), "BadCertificate", [], `${where}: q − 1 signers`);
            // The signer word alone: one bit fewer, one more, and one moved past the committee.
            const signers = kit.highest.meta.signers;
            const lowest = signers & -signers;
            const moved = (signers & ~(1n << BigInt(n - 1))) | (1n << BigInt(n));
            for (const [what, word] of [
              ["popcount q − 1", signers & ~lowest],
              ["popcount q + 1", signers | 1n],
              [`bit ${n} set`, moved],
            ]) {
              const mutated = withSigners(kit.highest, word);
              refused(live, await submit(live, [mutated], at), "BadCertificate", [], `${where}: ${what}`);
            }
            const receipt = ok(live, await submit(live, [kit.highest, kit.scattered], at), where);
            assertLogs(live, receipt, [
              published(kit.highest),
              stored(kit.blocks[0]),
              published(kit.scattered),
              stored(kit.blocks[1]),
            ], where);
            assert.equal((await committeeState(live.dest)).high, kit.blocks[1].height, where);
          } finally {
            await live.chain.close();
          }
        }
      });

      plain(run, "no other committee size is admitted, whatever root is pinned and whoever signed", async (ctx) => {
        for (const n of EXCLUDED_SIZES) {
          // A destination pinned to the root of n keys, and certificates their q = n − f signed.
          const kit = sizeKit(n, irregularCommittee(n));
          const live = await open(ctx, { signedBy: kit.signedBy, sameTimestamp: true });
          try {
            assert.equal((await committeeState(live.dest)).root, kit.signedBy.root);
            for (const certificate of [kit.highest, kit.scattered]) {
              assert.equal(ethers.dataLength(certificate.signerYs), 48 * kit.signedBy.q);
              refused(live, await submit(live, [certificate]), "BadCommittee", [], `n = ${n}`);
            }
            assert.equal(await live.dest.view("checkpointHeader", [1010n]), ZERO32);
          } finally {
            await live.chain.close();
          }
        }
        // The committee length alone, on a destination pinned to four keys.
        const live = await open(ctx, {});
        try {
          const { highest } = sizeKit(4);
          const key = ethers.dataSlice(highest.committee, 0, 48);
          const lengths = [0, 47, 48, 191, 193, 240, 1536, 1632];
          for (const length of lengths) {
            const repeated = ethers.concat(Array.from({ length: Math.ceil(length / 48) + 1 }, () => key));
            const committee = ethers.dataSlice(repeated, 0, length);
            const where = `${length} committee bytes`;
            refused(live, await submit(live, [{ ...highest, committee }]), "BadCommittee", [], where);
          }
        } finally {
          await live.chain.close();
        }
        // A root pinned over four keys and one stray byte: the four keys sign, the length is refused.
        const keys = committeeOf(4, 2);
        const bytes = ethers.concat([keys.bytes, "0x00"]);
        const root = ethers.keccak256(ethers.concat([m.ascii("SCCP/COMMITTEE/V1"), "0x04", bytes]));
        const padded = await open(ctx, { signedBy: { ...keys, name: "four keys and a byte", bytes, root } });
        try {
          const certificate = padded.taira.certify(padded.taira.block(1010n, ms(T0 + 10n), []));
          assert.equal(ethers.dataLength(certificate.committee), 193);
          assert.equal((await committeeState(padded.dest)).root, root);
          refused(padded, await submit(padded, [certificate]), "BadCommittee", [], "193 bytes under a root over them");
        } finally {
          await padded.chain.close();
        }
      });

      scenario(run, "VerifyCertificate reports its first failing step, on both paths (§5.1.3)", {}, async (ctx) => {
        const { taira } = ctx;
        const block = taira.block(1010n, ms(T0 + 10n), []);
        const good = taira.certify(block);
        const otherBlock = taira.block(1011n, ms(T0 + 11n), []);
        const firstY = BigInt(ethers.dataSlice(good.signerYs, 0, 48));
        const flags = Number(ethers.dataSlice(good.header, 64, 65));
        const keys = [0, 1, 2, 3].map((index) => ethers.dataSlice(good.committee, 48 * index, 48 * (index + 1)));
        const lowestSigner = good.meta.signers & -good.meta.signers;
        const mutations = {
          shortQc: (c) => ({ ...c, qc: ethers.dataSlice(c.qc, 0, 115) }),
          longQc: (c) => ({ ...c, qc: ethers.concat([c.qc, "0x00"]) }),
          shortHeader: (c) => ({ ...c, header: ethers.dataSlice(c.header, 0, 220) }),
          longHeader: (c) => ({ ...c, header: ethers.concat([c.header, "0x00"]) }),
          shortSignature: (c) => ({ ...c, signature: ethers.dataSlice(c.signature, 0, 191) }),
          longSignature: (c) => ({ ...c, signature: ethers.concat([c.signature, "0x00"]) }),
          fiveKeys: (c) => ({ ...c, committee: ethers.concat([c.committee, keys[0]]) }),
          shortYs: (c) => ({ ...c, signerYs: ethers.dataSlice(c.signerYs, 0, 96) }),
          longYs: (c) => ({ ...c, signerYs: ethers.concat([c.signerYs, ethers.dataSlice(c.signerYs, 0, 48)]) }),
          badMagic: (c) => ({ ...c, header: patch(c.header, 0, "0x00") }),
          reservedFlag: (c) => ({ ...c, header: patch(c.header, 64, m.be(flags | 0x04, 1)) }),
          inactive: (c) => ({ ...c, header: patch(c.header, 64, "0x00") }),
          otherNetwork: (c) => ({ ...c, header: patch(c.header, 16, OTHER_NETWORK_ID) }),
          nextGeneration: (c) => ({ ...c, header: patch(c.header, 141, m.be(GENERATION + 1n, 8)) }),
          otherRoot: (c) => ({ ...c, header: patch(c.header, 149, id("another committee root")) }),
          swappedKeys: (c) => ({ ...c, committee: ethers.concat([keys[1], keys[0], keys[2], keys[3]]) }),
          fewerSigners: (c) => withSigners(c, good.meta.signers & ~lowestSigner),
          zeroSignature: (c) => ({ ...c, signature: `0x${"00".repeat(192)}` }),
          yAboveField: (c) => ({ ...c, signerYs: patch(c.signerYs, 0, FIELD_P_BYTES) }),
          limbAboveField: (c) => ({ ...c, signature: patch(c.signature, 48, FIELD_P_BYTES) }),
          negatedY: (c) => ({ ...c, signerYs: patch(c.signerYs, 0, m.be(m.FIELD_P - firstY, 48)) }),
          offCurveY: (c) => offCurve(c),
          otherSignature: (c) => ({ ...c, signature: taira.certify(otherBlock).signature }),
        };
        const mutate = (names) => names.reduce((certificate, name) => mutations[name](certificate), good);
        const rows = [
          // Step 1, in its order: QC_FIXED, X, the signature, the committee, signerYs.
          [["shortQc"], "BadCertificate"],
          [["longQc"], "BadCertificate"],
          [["shortHeader"], "BadHeader"],
          [["longHeader"], "BadHeader"],
          [["shortSignature"], "BadCertificate"],
          [["longSignature"], "BadCertificate"],
          [["fiveKeys"], "BadCommittee"],
          [["shortYs"], "BadCertificate"],
          [["longYs"], "BadCertificate"],
          [["shortQc", "shortHeader"], "BadCertificate"],
          [["shortHeader", "shortSignature"], "BadHeader"],
          [["shortSignature", "fiveKeys"], "BadCertificate"],
          [["fiveKeys", "shortYs"], "BadCommittee"],
          // Step 1 before step 2, step 2 before step 3.
          [["shortYs", "badMagic"], "BadCertificate"],
          [["badMagic"], "BadHeader"],
          [["reservedFlag"], "BadHeader"],
          [["inactive"], "BadHeader"],
          [["otherNetwork"], "BadHeader"],
          [["badMagic", "nextGeneration"], "BadHeader"],
          [["otherNetwork", "nextGeneration"], "BadHeader"],
          [["otherNetwork", "otherRoot"], "BadHeader"],
          // Step 3 before step 4: classification comes before the committee bytes.
          [["nextGeneration"], "CommitteeNotAccepted"],
          [["otherRoot"], "CommitteeNotAccepted"],
          [["nextGeneration", "swappedKeys"], "CommitteeNotAccepted"],
          [["otherRoot", "zeroSignature"], "CommitteeNotAccepted"],
          // Step 4 before step 5, step 5 before step 6.
          [["swappedKeys"], "BadCommittee"],
          [["swappedKeys", "fewerSigners"], "BadCommittee"],
          [["fewerSigners"], "BadCertificate"],
          [["fewerSigners", "zeroSignature"], "BadCertificate"],
          // Step 6, in its order: σ = O, every y, every σ limb, every signer key.
          [["zeroSignature"], "BadSignature"],
          [["zeroSignature", "yAboveField"], "BadSignature"],
          [["yAboveField"], "BadCommittee"],
          [["yAboveField", "limbAboveField"], "BadCommittee"],
          [["limbAboveField"], "BadSignature"],
          [["limbAboveField", "negatedY"], "BadSignature"],
          [["negatedY"], "BadCommittee"],
          // Step 6 before the curve, step 10 before step 11.
          [["negatedY", "otherSignature"], "BadCommittee"],
          [["offCurveY"], "BadCommittee"],
          [["offCurveY", "otherSignature"], "BadCommittee"],
          [["otherSignature"], "BadSignature"],
        ];
        for (const [names, error] of rows) {
          refused(ctx, await submit(ctx, [mutate(names)]), error, [], `full path: ${names.join(" + ")}`);
        }
        assert.equal(await ctx.dest.view("checkpointHeader", [1010n]), ZERO32, "no refused certificate stored X");
        assertLogs(ctx, ok(ctx, await submit(ctx, [good])), [published(good), stored(block)], "the certificate itself");

        // The cheap path (step 8): X is stored, so steps 9–12 are skipped, but steps 1–6 still run.
        const cheap = [
          [["shortQc"], "BadCertificate"],
          [["shortHeader"], "BadHeader"],
          [["fiveKeys"], "BadCommittee"],
          [["shortYs"], "BadCertificate"],
          [["swappedKeys"], "BadCommittee"],
          [["fewerSigners"], "BadCertificate"],
          [["zeroSignature"], "BadSignature"],
          [["yAboveField"], "BadCommittee"],
          [["limbAboveField"], "BadSignature"],
          [["negatedY"], "BadCommittee"],
          [["zeroSignature", "negatedY"], "BadSignature"],
          // The signature and the curve are not consulted again: nothing changes, nothing is published.
          [["otherSignature"], "NothingToDo"],
          [["offCurveY"], "NothingToDo"],
          [["offCurveY", "otherSignature"], "NothingToDo"],
          [[], "NothingToDo"],
        ];
        for (const [names, error] of cheap) {
          refused(ctx, await submit(ctx, [mutate(names)]), error, [], `stored X: ${names.join(" + ") || "unchanged"}`);
        }
        // A batch that stores nothing new, but raises nothing either, changes no state.
        refused(ctx, await submit(ctx, [good, mutate(["otherSignature"]), good]), "NothingToDo", [], "three stored X");
      });

      scenario(run, "SccpCertificate is emitted exactly on the full path (§5.1.3 steps 8, 12)", {}, async (ctx) => {
        const { taira, chain, dest } = ctx;
        const past = ms(T0 + 50n);
        const mints = [1, 2, 3, 4].map((nonce) => transferOf(ctx, { nonce }));
        const expired = transferOf(ctx, { nonce: 5, deadlineMs: past });
        const controls = [1, 2].map((nonce) => controlOf(ctx, controlFields(nonce)));
        const a = taira.block(1010n, ms(T0 + 10n), [...mints, expired, ...controls]);
        const b = taira.block(1011n, ms(T0 + 11n), []);
        const third = controlOf(ctx, controlFields(3));
        const c = taira.block(1012n, ms(T0 + 12n), [third]);
        const voidable = transferOf(ctx, { nonce: 6, deadlineMs: past });
        const d = taira.block(1013n, ms(T0 + 13n), [voidable]);
        const late = transferOf(ctx, { nonce: 7, deadlineMs: past });
        const e = taira.block(1014n, ms(T0 + 14n), [late]);
        const f = taira.block(1015n, ms(T0 + 15n), []);
        const certificate = taira.certify(a);
        const proof = (item, block = a) => proofOf(taira, item, block);

        // Full path: published, stored, then the action.
        let receipt = ok(ctx, await finalizeInline(ctx, certificate, proof(mints[0]), { at: T0 + 100n }));
        assertLogs(ctx, receipt, [published(certificate), stored(a), ...minted(mints[0])], "first use of X");
        // Cheap path: the same certificate, the same X under another result body and other
        // signers, and the same X under a signature that does not verify.
        receipt = ok(ctx, await finalizeInline(ctx, certificate, proof(mints[1])));
        assertLogs(ctx, receipt, minted(mints[1]), "the same certificate again");
        const otherBody = taira.certify(a, { bodyTag: "0x01", signerIndices: [1, 2, 3] });
        assert.notEqual(otherBody.qc, certificate.qc);
        assert.notEqual(otherBody.signature, certificate.signature);
        receipt = ok(ctx, await finalizeInline(ctx, otherBody, proof(mints[2])));
        assertLogs(ctx, receipt, minted(mints[2]), "a stored X under another QC");
        const unverifiable = { ...certificate, signature: taira.certify(b).signature };
        receipt = ok(ctx, await finalizeInline(ctx, unverifiable, proof(mints[3])));
        assertLogs(ctx, receipt, minted(mints[3]), "a stored X under a signature of another message");
        receipt = ok(ctx, await controlInline(ctx, certificate, proof(controls[0])));
        assertLogs(ctx, receipt, [applied(controls[0].control)], "applyControl on a stored X");
        receipt = ok(ctx, await voidInline(ctx, 5n, certificate, proof(expired)));
        assertLogs(ctx, receipt, [voided(expired)], "voidExpired on a stored X");
        receipt = ok(ctx, await controlStored(ctx, a.x, proof(controls[1])));
        assertLogs(ctx, receipt, [applied(controls[1].control)], "a checkpoint entry point");
        refused(ctx, await submit(ctx, [certificate]), "NothingToDo", [], "a stored X as a checkpoint");

        // One batch with a new certificate twice and a stored one: published and stored once.
        const second = taira.certify(b);
        receipt = ok(ctx, await submit(ctx, [second, second, certificate]));
        assertLogs(ctx, receipt, [published(second), stored(b)], "a repeated certificate in one batch");
        // The first use of X by each other inline entry point.
        const forControl = taira.certify(c);
        receipt = ok(ctx, await controlInline(ctx, forControl, proof(third, c)));
        assertLogs(ctx, receipt, [published(forControl), stored(c), applied(third.control)], "applyControl, full path");
        const forVoid = taira.certify(d);
        receipt = ok(ctx, await voidInline(ctx, 6n, forVoid, proof(voidable, d)));
        assertLogs(ctx, receipt, [published(forVoid), stored(d), voided(voidable)], "voidExpired, full path");

        // A call that reverts after the verification discards the event and the checkpoint.
        const reverting = taira.certify(e);
        refused(ctx, await finalizeInline(ctx, reverting, proof(late, e)), "DeadlinePassed");
        assert.equal(await dest.view("checkpointHeader", [1014n]), ZERO32);
        receipt = ok(ctx, await voidInline(ctx, 7n, reverting, proof(late, e)));
        assertLogs(ctx, receipt, [published(reverting), stored(e), voided(late)], "the full path again after a revert");

        // Through an internal call: the forged certificate is published all the same.
        const forwarder = await h.deployForwarder(chain, dest.address);
        const relayed = taira.certify(f);
        const data = m.iface.encodeFunctionData("submitCheckpoints", [[r.certificateArg(relayed)]]);
        receipt = ok(ctx, await chain.attempt({ to: forwarder, data }));
        assertLogs(ctx, receipt, [published(relayed), stored(f)], "a relayed certificate");
        refused(ctx, await chain.attempt({ to: forwarder, data }), "NothingToDo", [], "a relayed stored X");

        // A latch publishes the conflicting certificate before `SccpLatched`; an inline use
        // of it reverts and publishes nothing.
        const conflict = forgerOf(ctx).block(1010n, ms(T0 + 16n), []);
        const conflicting = taira.certify(conflict);
        await onSnapshot(ctx, async () => {
          const latch = ok(ctx, await submit(ctx, [conflicting]));
          assertLogs(ctx, latch, [published(conflicting), latched(1, conflict, m.checkpointId(a.x))], "a latch");
        });
        // A forged rotation through an internal call: published, stored and installed.
        const handoff = taira.block(1020n, ms(T0 + 20n), [], { rotate: "key", nextCommittee: committeeOf(4, 1) });
        const rotation = taira.certify(handoff);
        const rotate = m.iface.encodeFunctionData("submitCheckpoints", [[r.certificateArg(rotation)]]);
        receipt = ok(ctx, await chain.attempt({ to: forwarder, data: rotate }));
        const untilMs = ms(T0 + 20n) + VALIDITY_MS;
        assertLogs(
          ctx,
          receipt,
          [published(rotation), stored(handoff), rotated(handoff, untilMs)],
          "a relayed rotation",
        );
        assert.equal(await dest.view("opCount"), 10n, "four mints, three controls and three voids");
      });

      // -- proofs and payloads ------------------------------------------------

      scenario(run, "block references: the certified block and older blocks (§5.1.5)", {}, async (ctx) => {
        const { taira } = ctx;
        const before = taira.block(1005n, ms(T0 + 5n), []);
        const a = [10, 11, 12].map((nonce) => transferOf(ctx, { nonce }));
        const h1 = taira.block(1010n, ms(T0 + 10n), a);
        const b = [transferOf(ctx, { nonce: 20 })];
        const h2 = taira.block(1020n, ms(T0 + 20n), b);
        const empty = taira.block(1030n, ms(T0 + 30n), []);
        const c = [30, 31, 32].map((nonce) => transferOf(ctx, { nonce }));
        const h3 = taira.block(1040n, ms(T0 + 40n), c);
        assert.deepEqual([before, empty, h3].map((block) => block.header.historySize), [0n, 2n, 3n]);
        ok(ctx, await submit(ctx, [before, empty, h3].map((block) => taira.certify(block)), { at: T0 + 100n }));
        const finalize = (x, proof, reference) =>
          finalizeStored(
            ctx,
            x,
            reference === undefined ? proof : { ...proof, block: { ...proof.block, ...reference } },
          );
        const badProof = async (x, proof, reference, where) =>
          refused(ctx, await finalize(x, proof, reference), "BadProof", [], where);

        // The certified block itself: its root, its count, index 0 and no path.
        const own = proofOf(taira, c[0], h3);
        const position = { historyIndex: 2n, historyPath: m.merklePath(taira.history.slice(0, 3), 2) };
        assert.equal(m.merkleRootFromPath(taira.history[2], 2n, 3n, position.historyPath), h3.header.historyRoot);
        await badProof(h3.x, own, { sccpRoot: id("another root") }, "same height: another root");
        // A tree of the reference's own making, with the leaf in it: only the root rule refuses it.
        const fabricated = [c[0].leaf, id("fabricated leaf 1"), id("fabricated leaf 2")];
        const underFabricated = { ...own, path: m.merklePath(fabricated, 0) };
        assert.equal(m.merkleRootFromPath(c[0].leaf, 0n, 3n, underFabricated.path), m.merkleRoot(fabricated));
        await badProof(h3.x, underFabricated, { sccpRoot: m.merkleRoot(fabricated) }, "same height: a fabricated tree");
        await badProof(h3.x, own, { messageCount: 2n }, "same height: a smaller count");
        // Leaf 0 of three leaves has the path it would have among four: only the count rule refuses it.
        assert.equal(m.merkleRootFromPath(c[0].leaf, 0n, 4n, own.path), h3.header.sccpRoot);
        await badProof(h3.x, own, { messageCount: 4n }, "same height: a larger count");
        await badProof(h3.x, own, { historyIndex: 2n }, "same height: a history index");
        await badProof(h3.x, own, { historyPath: position.historyPath }, "same height: a history path");
        await badProof(h3.x, own, position, "same height: the block's true history position");
        // A certified block without messages has a zero root, which no reference may repeat.
        const none = { height: 1030n, sccpRoot: ZERO32, messageCount: 0n, historyIndex: 0n, historyPath: [] };
        await badProof(empty.x, own, none, "same height: a block without messages");
        await badProof(empty.x, own, { height: 1030n }, "same height: the root of another block");
        // An older block: a leaf of the history accumulator after X.
        const older = proofOf(taira, a[1], h1, h3);
        assert.equal(older.block.historyPath.length, 2);
        await badProof(h3.x, older, { height: 1041n }, "older: a height above X");
        await badProof(h3.x, older, { height: 1040n }, "older: the height of X with another block's root");
        await badProof(h3.x, older, { height: 1011n }, "older: another height");
        await badProof(h3.x, older, { messageCount: 0n }, "older: count 0");
        await badProof(h3.x, older, { messageCount: 513n }, "older: count 513");
        await badProof(h3.x, older, { messageCount: 2n }, "older: another count");
        await badProof(h3.x, older, { sccpRoot: ZERO32 }, "older: a zero root");
        await badProof(h3.x, older, { sccpRoot: h2.header.sccpRoot }, "older: the root of another block");
        await badProof(h3.x, older, { historyIndex: 1n }, "older: another history index");
        await badProof(h3.x, older, { historyIndex: 3n }, "older: an index at the history size");
        await badProof(h3.x, older, { historyPath: older.block.historyPath.slice(1) }, "older: a shorter path");
        await badProof(h3.x, older, { historyPath: [...older.block.historyPath, ZERO32] }, "older: a longer path");
        await badProof(h3.x, older, { historyPath: [...older.block.historyPath].reverse() }, "older: a reordered path");
        const thirtyThree = Array.from({ length: 33 }, (_, index) => id(`sibling ${index}`));
        await badProof(h3.x, older, { historyPath: thirtyThree }, "older: 33 siblings");
        // A header whose history is empty proves no older block.
        const nothing = {
          height: 1004n,
          sccpRoot: h1.header.sccpRoot,
          messageCount: 3n,
          historyIndex: 0n,
          historyPath: [],
        };
        await badProof(before.x, older, nothing, "older: under an empty history");
        // The leaf path inside the block: a[2] is promoted at the first level.
        const promoted = proofOf(taira, a[2], h1, h3);
        assert.equal(promoted.path.length, 1);
        await badProof(h3.x, { ...promoted, leafIndex: 1 }, undefined, "leaf: another index");
        await badProof(h3.x, { ...promoted, leafIndex: 3 }, undefined, "leaf: an index at the count");
        await badProof(h3.x, { ...promoted, path: [] }, undefined, "leaf: a shorter path");
        await badProof(h3.x, { ...promoted, path: [...promoted.path, ZERO32] }, undefined, "leaf: a longer path");
        await badProof(h3.x, { ...promoted, payload: a[1].payload }, undefined, "leaf: another payload");
        // The root of a one-leaf block is its leaf, at index 0 only.
        const lone = proofOf(taira, b[0], h2, h3);
        assert.deepEqual([lone.leafIndex, lone.path], [0, []]);
        await badProof(h3.x, { ...lone, leafIndex: 1 }, undefined, "leaf: index 1 of a one-leaf block");
        await badProof(
          h3.x,
          { ...lone, leafIndex: 0xffffffff },
          undefined,
          "leaf: the largest index of a one-leaf block",
        );
        // Each accepted form: the certified block, an older block under it, and an older block
        // under a certified block that carries no message itself.
        assertLogs(ctx, ok(ctx, await finalize(h3.x, own)), minted(c[0]), "the certified block");
        assertLogs(ctx, ok(ctx, await finalize(h3.x, older)), minted(a[1]), "an older block");
        assertLogs(ctx, ok(ctx, await finalize(h3.x, promoted)), minted(a[2]), "a promoted leaf");
        assertLogs(
          ctx,
          ok(ctx, await finalize(h3.x, proofOf(taira, b[0], h2, h3))),
          minted(b[0]),
          "another older block",
        );
        assertLogs(
          ctx,
          ok(ctx, await finalize(empty.x, proofOf(taira, a[0], h1, empty))),
          minted(a[0]),
          "under an empty block",
        );
        refused(ctx, await finalize(empty.x, proofOf(taira, a[0], h1, empty)), "AlreadyConsumed", [10n]);
      });

      scenario(run, "proof bounds: 512 leaves, 9 siblings; a history of 2^32, 32 siblings", {}, async (ctx) => {
        const { taira } = ctx;
        // A block of 512 leaves: its first and its last leaf have nine siblings each.
        const edges = [50, 51].map((nonce) => transferOf(ctx, { nonce }));
        const filler = Array.from({ length: 510 }, (_, index) => ({ kind: "filler", leaf: id(`filler ${index}`) }));
        const full = taira.block(1500n, ms(T0 + 50n), [edges[0], ...filler, edges[1]]);
        assert.equal(full.header.messageCount, 512n);
        const certificate = taira.certify(full);
        const first = proofOf(taira, edges[0], full);
        const last = proofOf(taira, edges[1], full);
        assert.deepEqual([first.path.length, last.path.length, last.leafIndex], [9, 9, 511]);
        const tenth = { ...first, path: [...first.path, ZERO32] };
        refused(ctx, await finalizeInline(ctx, certificate, tenth, { at: T0 + 100n }), "BadProof", [], "10 siblings");
        refused(
          ctx,
          await finalizeInline(ctx, certificate, { ...last, leafIndex: 512 }),
          "BadProof",
          [],
          "leaf index 512",
        );
        assertLogs(ctx, ok(ctx, await finalizeInline(ctx, certificate, first)), [
          published(certificate),
          stored(full),
          ...minted(edges[0]),
        ], "leaf 0 of 512");
        assertLogs(ctx, ok(ctx, await finalizeStored(ctx, full.x, last)), minted(edges[1]), "leaf 511 of 512");

        // A history of the largest size X5 admits. Leaf 0 and leaf 2^32 − 1 have 32 siblings.
        const size = m.MAX_HISTORY_SIZE;
        const deep = transferOf(ctx, { nonce: 60 });
        const siblings = Array.from({ length: 32 }, (_, index) => id(`history sibling ${index}`));
        const leaf = m.historyLeaf(1600n, deep.leaf, 1n);
        const reference = (historyIndex, historyPath = siblings) => ({
          payload: deep.payload,
          leafIndex: 0,
          path: [],
          block: { height: 1600n, sccpRoot: deep.leaf, messageCount: 1n, historyIndex, historyPath },
        });
        const headers = [0n, size - 1n].map((index, position) =>
          headerBlock(taira, {
            height: 2000n + BigInt(position),
            timestampMs: ms(T0 + 60n),
            historySize: size,
            historyRoot: m.merkleRootFromPath(leaf, index, size, siblings),
          }));
        ok(ctx, await submit(ctx, headers.map((block) => taira.certify(block))));
        refused(
          ctx,
          await finalizeStored(ctx, headers[0].x, reference(0n, [...siblings, ZERO32])),
          "BadProof",
          [],
          "33 siblings",
        );
        refused(
          ctx,
          await finalizeStored(ctx, headers[0].x, reference(0n, siblings.slice(1))),
          "BadProof",
          [],
          "31 siblings",
        );
        refused(ctx, await finalizeStored(ctx, headers[0].x, reference(size)), "BadProof", [], "history index 2^32");
        refused(ctx, await finalizeStored(ctx, headers[0].x, reference(size - 1n)), "BadProof", [], "the other end");
        assertLogs(
          ctx,
          ok(ctx, await finalizeStored(ctx, headers[0].x, reference(0n))),
          minted(deep),
          "history leaf 0",
        );
        // The last leaf verifies too: the call gets as far as the consumed set.
        refused(ctx, await finalizeStored(ctx, headers[1].x, reference(size - 1n)), "AlreadyConsumed", [60n]);
        // One leaf more than X5 admits is no header at all.
        const beyond = headerBlock(
          taira,
          { height: 2002n, timestampMs: ms(T0 + 60n), historySize: size + 1n, historyRoot: id("root") },
        );
        refused(ctx, await submit(ctx, [taira.certify(beyond)]), "BadHeader", [], "a history of 2^32 + 1");

        // Histories that Taira never builds, signed all the same: a leaf for a height above X, and a
        // block of 513 leaves. The reference rules refuse both, although every path verifies.
        const single = (height, sccpRoot, messageCount, header) => {
          const historyRoot = m.historyLeaf(height, sccpRoot, messageCount);
          const block = headerBlock(taira, { height: header, timestampMs: ms(T0 + 70n), historySize: 1n, historyRoot });
          return { block, reference: { height, sccpRoot, messageCount, historyIndex: 0n, historyPath: [] } };
        };
        const [early, late] = [61, 62].map((nonce) => transferOf(ctx, { nonce }));
        const below = single(2009n, early.leaf, 1n, 2010n);
        const above = single(2021n, late.leaf, 1n, 2020n);
        const wide = Array.from({ length: 512 }, (_, index) => id(`wide ${index}`));
        const widest = transferOf(ctx, { nonce: 63 });
        const leaves = [...wide, widest.leaf];
        const overfull = single(2029n, m.merkleRoot(leaves), 513n, 2030n);
        const lastPath = m.merklePath(leaves, 512);
        assert.equal(lastPath.length, 1, "the promoted last leaf of 513 has one sibling");
        assert.equal(m.merkleRootFromPath(widest.leaf, 512n, 513n, lastPath), m.merkleRoot(leaves));
        ok(ctx, await submit(ctx, [below, above, overfull].map(({ block }) => taira.certify(block))));
        const through = ({ block, reference }, item, leafIndex = 0, path = []) =>
          finalizeStored(ctx, block.x, { payload: item.payload, leafIndex, path, block: reference });
        // The root of a one-leaf history is its leaf, at index 0 only.
        for (const historyIndex of [1n, U64_MAX]) {
          const elsewhere = { block: below.block, reference: { ...below.reference, historyIndex } };
          refused(ctx, await through(elsewhere, early), "BadProof", [], `index ${historyIndex} of a one-leaf history`);
        }
        assertLogs(ctx, ok(ctx, await through(below, early)), minted(early), "a history leaf one height below X");
        refused(ctx, await through(above, late), "BadProof", [], "a history leaf one height above X");
        refused(ctx, await through(overfull, widest, 512, lastPath), "BadProof", [], "a block of 513 leaves");
      });

      scenario(run, "payload rules of §3.2 for this destination, on a mint and on a void", {}, async (ctx) => {
        const { taira, dest } = ctx;
        const zeroRecipient = { recipient: m.accountBytes(profile, ZERO_ADDRESS) };
        const sender = m.DEFAULT_TAIRA_SENDER;
        const cases = [
          ["kind 1", { kind: 1 }, "BadPayload"],
          ["kind 3", { kind: 3 }, "BadPayload"],
          ["version 0", { version: 0 }, "BadPayload"],
          ["version 2", { version: 2 }, "BadPayload"],
          ["the own domain as source", { sourceDomain: profile.domain }, "BadPayload"],
          ["source domain 4", { sourceDomain: 4 }, "BadPayload"],
          ["the other profile's domain as destination", { destDomain: other.domain }, "BadPayload"],
          ["destination domain 0", { destDomain: 0 }, "BadPayload"],
          ["destination domain 4", { destDomain: 4 }, "BadPayload"],
          ["another route revision", { routeRevision: REVISION + 1 }, "BadPayload"],
          ["route revision 0", { routeRevision: 0 }, "BadPayload"],
          ["deadline 0", { deadlineMs: 0 }, "BadPayload"],
          ["asset home domain 1", { assetHomeDomain: 1 }, "BadPayload"],
          ["asset id codec 2", { assetIdCodec: 2 }, "BadPayload"],
          ["asset id XOR", { assetId: m.ascii("XOR") }, "BadPayload"],
          ["asset id xorx", { assetId: m.ascii("xorx") }, "BadPayload"],
          ["asset id xo", { assetId: m.ascii("xo") }, "BadPayload"],
          ["an asset id length of 4", { assetIdLen: 4 }, "BadPayload"],
          ["amount 0", { amount: 0 }, "BadPayload"],
          ["sender codec 2", { senderCodec: 2 }, "BadPayload"],
          ["sender codec 7", { senderCodec: 7 }, "BadPayload"],
          ["an empty sender", { sender: "0x" }, "BadPayload"],
          ["a sender of 1025 bytes", { sender: `0x${"ab".repeat(1025)}` }, "BadPayload"],
          ["a sender length one above its bytes", { senderLen: ethers.dataLength(sender) + 1 }, "BadPayload"],
          ["a sender length one below its bytes", { senderLen: ethers.dataLength(sender) - 1 }, "BadPayload"],
          ["recipient codec 3", { recipientCodec: 3 }, "BadPayload"],
          ["the retired recipient codec 5", { recipientCodec: 5 }, "BadPayload"],
          ["recipient codec 7", { recipientCodec: 7 }, "BadPayload"],
          ["a recipient of 21 bytes", { recipient: ethers.concat(["0x41", ctx.recipient]) }, "BadPayload"],
          ["a recipient of 19 bytes", { recipient: ethers.dataSlice(ctx.recipient, 1) }, "BadPayload"],
          ["a recipient length of 21", { recipientLen: 21 }, "BadPayload"],
          ["route id codec 2", { routeIdCodec: 2 }, "BadPayload"],
          ["the route of the other profile", { routeId: m.ascii(other.routeId) }, "BadPayload"],
          ["a route id in upper case", { routeId: m.ascii(profile.routeId.toUpperCase()) }, "BadPayload"],
          ["a route id of 12 bytes", { routeId: m.ascii(profile.routeId.slice(0, 12)) }, "BadPayload"],
          ["a route id length of 14", { routeIdLen: 14 }, "BadPayload"],
          ["one trailing byte", { trailing: "0x00" }, "BadPayload"],
          ["4096 trailing bytes", { trailing: `0x${"00".repeat(4096)}` }, "BadPayload"],
          ["the zero recipient", zeroRecipient, "BadRecipient"],
          ["the destination itself as recipient", { recipient: m.accountBytes(profile, dest.address) }, "BadRecipient"],
          // The payload is parsed in full before its recipient is judged.
          ["the zero recipient and another route", { ...zeroRecipient, routeId: m.ascii(other.routeId) }, "BadPayload"],
          ["the zero recipient and a trailing byte", { ...zeroRecipient, trailing: "0x00" }, "BadPayload"],
          // The recipient is judged before the deadline.
          ["the zero recipient after the deadline", { ...zeroRecipient, deadlineMs: ms(T0) }, "BadRecipient"],
        ];
        const items = cases.map(([, overrides], index) => transferOf(ctx, { nonce: 100 + index, overrides }));
        const whole = transferOf(ctx, { nonce: 200 });
        const truncate = (bytes) => {
          const payload = ethers.dataSlice(whole.payload, 0, bytes);
          const leaf = m.transferLeaf(m.outboundMessageId(NETWORK_ID, profile, payload), taira.destinationWord);
          return { kind: "transfer", leaf, payload, nonce: 200n };
        };
        const truncated = [ethers.dataLength(whole.payload) - 1, 58, 0].map(truncate);
        const accepted = [
          transferOf(ctx, { nonce: 300, overrides: { sender: "0x01" } }),
          transferOf(ctx, { nonce: 301, overrides: { sender: `0x${"cd".repeat(1024)}` } }),
          transferOf(ctx, { nonce: 302, amount: 1n }),
        ];
        const aboveCap = transferOf(ctx, { nonce: 303, amount: U128_MAX });
        const block = taira.block(1010n, ms(T0 + 10n), [...items, ...truncated, ...accepted, aboveCap, whole]);
        ok(ctx, await submit(ctx, [taira.certify(block)], { at: T0 + 100n }));
        const proof = (item) => proofOf(taira, item, block);
        for (const [index, [where, , error]] of cases.entries()) {
          refused(ctx, await finalizeStored(ctx, block.x, proof(items[index])), error, [], `mint: ${where}`);
          refused(
            ctx,
            await voidStored(ctx, items[index].nonce, block.x, proof(items[index])),
            error,
            [],
            `void: ${where}`,
          );
        }
        for (const item of truncated) {
          const where = `${ethers.dataLength(item.payload)} payload bytes`;
          refused(ctx, await finalizeStored(ctx, block.x, proof(item)), "BadPayload", [], where);
          refused(ctx, await voidStored(ctx, 200n, block.x, proof(item)), "BadPayload", [], where);
        }
        // Check order (§5.1.2): the block reference, the payload, the deadline, then the leaf path.
        const bad = proof(items[0]);
        const recount = { ...bad, block: { ...bad.block, messageCount: bad.block.messageCount + 1n } };
        refused(
          ctx,
          await finalizeStored(ctx, block.x, recount),
          "BadProof",
          [],
          "a bad reference before a bad payload",
        );
        refused(
          ctx,
          await finalizeStored(ctx, block.x, { ...bad, path: [] }),
          "BadPayload",
          [],
          "a bad payload before a bad path",
        );
        const valid = proof(whole);
        refused(
          ctx,
          await voidStored(ctx, 200n, block.x, { ...valid, path: [] }),
          "DeadlineNotReached",
          [],
          "the deadline before the path",
        );
        refused(
          ctx,
          await finalizeStored(ctx, block.x, { ...valid, path: [] }),
          "BadProof",
          [],
          "a valid payload on a bad path",
        );
        // The extremes §3.1 admits, and the largest amount, which is refused only by the cap.
        for (const item of accepted) {
          assertLogs(
            ctx,
            ok(ctx, await finalizeStored(ctx, block.x, proof(item))),
            minted(item),
            `nonce ${item.nonce}`,
          );
        }
        const largest = await finalizeStored(ctx, block.x, proof(aboveCap));
        refused(ctx, largest, "SupplyCapExceeded", [], "amount 2^128 − 1");
        assert.equal(await dest.view("opCount"), 3n);
        assert.equal(await dest.view("totalSupply"), 2n * UNIT + 1n);
      });

      scenario(run, "deadline edges of inline mints and voids, sub-second included", SAME_SECOND, async (ctx) => {
        const { taira } = ctx;
        const T = T0 + 1000n;
        const atDeadline = transferOf(ctx, { nonce: 1, deadlineMs: ms(T + 1n) });
        const justPassed = transferOf(ctx, { nonce: 2, deadlineMs: ms(T + 2n) - 1n });
        const withinSecond = transferOf(ctx, { nonce: 3, deadlineMs: ms(T + 3n) + 999n });
        const voidable = transferOf(ctx, { nonce: 4, deadlineMs: ms(T) });
        const boundary = [5, 6].map((nonce) => transferOf(ctx, { nonce, deadlineMs: ms(T + 10n) + 1n }));
        const block = taira.block(1010n, ms(T0 + 10n), [atDeadline, justPassed, withinSecond, voidable, ...boundary]);
        const certificate = taira.certify(block);
        const proof = (item) => proofOf(taira, item, block);
        const mint = (item, at) => finalizeInline(ctx, certificate, proof(item), { at });
        const cancel = (item, at) => voidInline(ctx, item.nonce, certificate, proof(item), { at });
        refused(ctx, await cancel(voidable, T), "DeadlineNotReached", [], "a void at the deadline");
        ok(ctx, await mint(atDeadline, T + 1n), "a mint at the deadline");
        refused(ctx, await mint(justPassed, T + 2n), "DeadlinePassed", [], "a mint one millisecond late");
        ok(ctx, await mint(withinSecond, T + 3n), "a mint in the second of the deadline");
        refused(ctx, await cancel(withinSecond, T + 4n), "AlreadyConsumed", [3n], "a void of a minted nonce");
        assertLogs(ctx, ok(ctx, await cancel(justPassed, T + 5n)), [voided(justPassed)], "a void after the deadline");
        assertLogs(ctx, ok(ctx, await cancel(voidable, T + 6n)), [voided(voidable)], "a void one second late");
        // A deadline one millisecond into a second: that second mints, the next one voids.
        refused(ctx, await cancel(boundary[0], T + 10n), "DeadlineNotReached", [], "a void one millisecond early");
        ok(ctx, await mint(boundary[0], T + 10n), "a mint one millisecond early");
        refused(ctx, await mint(boundary[1], T + 11n), "DeadlinePassed", [], "a mint 999 milliseconds late");
        assertLogs(
          ctx,
          ok(ctx, await cancel(boundary[1], T + 11n)),
          [voided(boundary[1])],
          "a void 999 milliseconds late",
        );
        assert.equal(await ctx.dest.view("opCount"), 6n);
        assert.equal(await ctx.dest.view("totalSupply"), 3n * UNIT, "a void mints nothing");
      });

      // -- the consumed set, the cap and voids ---------------------------------

      scenario(run, "the supply cap and the bitmap word boundaries (§5.1.4, §5.2.3)", { cap: 3000n }, async (ctx) => {
        const { taira, dest } = ctx;
        const amounts = [[255n, 1000n], [256n, 1000n], [0n, 999n]];
        const filling = amounts.map(([nonce, amount]) => transferOf(ctx, { nonce, amount }));
        const exact = transferOf(ctx, { nonce: 511n, amount: 1n });
        const over = transferOf(ctx, { nonce: 512n, amount: 1n });
        const two = transferOf(ctx, { nonce: 513n, amount: 2n });
        const top = transferOf(ctx, { nonce: U64_MAX, amount: 2n });
        const huge = transferOf(ctx, { nonce: 700n, amount: U128_MAX });
        const block = taira.block(1010n, ms(T0 + 10n), [...filling, exact, over, two, top, huge]);
        ok(ctx, await submit(ctx, [taira.certify(block)], { at: T0 + 100n }));
        const mint = (item) => finalizeStored(ctx, block.x, proofOf(taira, item, block));
        const supply = () => dest.view("totalSupply");
        for (const item of filling) assertLogs(ctx, ok(ctx, await mint(item)), minted(item), `nonce ${item.nonce}`);
        assert.equal(await supply(), 2999n);
        // The cap is compared as amount ≤ cap − supply: one unit fits, two do not.
        refused(ctx, await mint(two), "SupplyCapExceeded", [], "one unit above the cap");
        assert.equal(await dest.view("isConsumed", [513n]), false, "a refused mint consumes nothing");
        ok(ctx, await mint(exact), "exactly the cap");
        assert.equal(await supply(), 3000n);
        refused(ctx, await mint(over), "SupplyCapExceeded", [], "a full cap");
        refused(ctx, await mint(huge), "SupplyCapExceeded", [], "2^128 − 1 on a full cap");
        // A consumed nonce is reported before the cap.
        refused(ctx, await mint(filling[0]), "AlreadyConsumed", [255n], "a consumed nonce on a full cap");
        // The cap counts the current supply: a burn returns headroom.
        ok(ctx, await burn(ctx, 9, 1n, 0n));
        ok(ctx, await mint(over), "after a burn of one unit");
        refused(ctx, await mint(top), "SupplyCapExceeded", [], "two units after a burn of one");
        ok(ctx, await burn(ctx, 9, 2n, 1n));
        ok(ctx, await mint(top), "the largest nonce");
        assert.equal(await supply(), 3000n);
        assert.equal(await dest.view("balanceOf", [ctx.recipient]), 3000n);
        for (const [nonce, consumed] of [
          [0n, true],
          [1n, false],
          [254n, false],
          [255n, true],
          [256n, true],
          [257n, false],
          [510n, false],
          [511n, true],
          [512n, true],
          [513n, false],
          [767n, false],
          [768n, false],
          [U64_MAX - 1n, false],
          [U64_MAX, true],
        ]) {
          assert.equal(await dest.view("isConsumed", [nonce]), consumed, `nonce ${nonce}`);
        }
        // word = nonce >> 8, bit = nonce & 255.
        const word = (index) => storageAt(dest, mappingSlot("uint256", index, 4));
        assert.equal(await word(0n), (1n << 255n) | 1n, "word 0 holds nonces 0 and 255");
        assert.equal(await word(1n), (1n << 255n) | 1n, "word 1 holds nonces 256 and 511");
        assert.equal(await word(2n), 1n, "word 2 holds nonce 512");
        assert.equal(await word(U64_MAX >> 8n), 1n << 255n, "the last word holds nonce 2^64 − 1");
        assert.equal(await dest.view("opCount"), 8n, "six mints and two burns");
      });

      scenario(run, "voidExpired*: nonce argument, consumed set and Live", { cap: 2n * UNIT }, async (ctx) => {
        const { taira, dest, deployment } = ctx;
        const past = ms(T0 + 50n);
        const lapsed = [42n, 43n, 46n, 47n].map((nonce) => transferOf(ctx, { nonce, deadlineMs: past }));
        const aboveCap = transferOf(ctx, { nonce: 44n, deadlineMs: past, amount: 5n * UNIT });
        const top = transferOf(ctx, { nonce: U64_MAX, deadlineMs: past });
        const pending = transferOf(ctx, { nonce: 45n });
        const block = taira.block(1010n, ms(T0 + 10n), [...lapsed, aboveCap, top, pending]);
        const certificate = taira.certify(block);
        const proof = (item) => proofOf(taira, item, block);
        const inline = (nonce, item, options) => voidInline(ctx, nonce, certificate, proof(item), options);
        const fromCheckpoint = (nonce, item, options) => voidStored(ctx, nonce, block.x, proof(item), options);

        // The nonce argument must be the payload's; a refused void stores nothing.
        refused(ctx, await inline(41n, lapsed[0], { at: T0 + 100n }), "BadNonce", [42n], "inline, another nonce");
        assert.equal(await dest.view("checkpointHeader", [1010n]), ZERO32);
        let receipt = ok(ctx, await inline(42n, lapsed[0]));
        assertLogs(ctx, receipt, [published(certificate), stored(block), voided(lapsed[0])], "an inline void");
        assert.equal(await dest.view("isConsumed", [42n]), true);
        assert.equal(await dest.view("totalSupply"), 0n, "a void mints nothing");
        assert.equal(await dest.view("opCount"), 1n);
        refused(ctx, await inline(42n, lapsed[0]), "AlreadyConsumed", [42n], "inline, voided twice");
        refused(ctx, await fromCheckpoint(42n, lapsed[0]), "AlreadyConsumed", [42n], "voided twice");
        // The argument is checked before the consumed set.
        refused(ctx, await fromCheckpoint(41n, lapsed[0]), "BadNonce", [42n], "a consumed payload, another nonce");
        refused(ctx, await fromCheckpoint(43n, lapsed[0]), "BadNonce", [42n], "the nonce of another payload");
        refused(
          ctx,
          await finalizeStored(ctx, block.x, proof(lapsed[0])),
          "DeadlinePassed",
          [],
          "a mint after the void",
        );
        assertLogs(ctx, ok(ctx, await fromCheckpoint(43n, lapsed[1])), [voided(lapsed[1])], "a void from a checkpoint");
        // A void skips the supply cap, and the largest nonce is a nonce like any other.
        assertLogs(ctx, ok(ctx, await fromCheckpoint(44n, aboveCap)), [voided(aboveCap)], "an amount above the cap");
        assertLogs(ctx, ok(ctx, await fromCheckpoint(U64_MAX, top)), [voided(top)], "nonce 2^64 − 1");
        // Before the deadline there is nothing to void, whether the nonce is minted or not.
        refused(ctx, await fromCheckpoint(45n, pending), "DeadlineNotReached");
        ok(ctx, await finalizeStored(ctx, block.x, proof(pending)));
        refused(
          ctx,
          await fromCheckpoint(45n, pending),
          "DeadlineNotReached",
          [],
          "a minted nonce before its deadline",
        );
        // The dynamic arguments need no canonical-calldata rule: trailing bytes change nothing.
        const args = [46n, [block.x], r.messageProofArg(proof(lapsed[2]))];
        const data = m.iface.encodeFunctionData("voidExpiredFromCheckpoint", args);
        assertLogs(
          ctx,
          ok(ctx, await dest.attempt(ethers.concat([data, m.word(0), "0x01"]))),
          [voided(lapsed[2])],
          "trailing bytes",
        );
        assert.equal(await dest.view("opCount"), 6n, "five voids and one mint");

        // Live: an expired destination and a latched one void nothing by proof.
        await onSnapshot(ctx, async () => {
          const expiredAt = deployment.initialUntilMs / 1000n + 1n;
          refused(ctx, await fromCheckpoint(47n, lapsed[3], { at: expiredAt }), "CommitteeNotAccepted", [], "expired");
          refused(ctx, await inline(47n, lapsed[3]), "CommitteeNotAccepted", [], "inline, expired");
        });
        await onSnapshot(ctx, async () => {
          ok(ctx, await submit(ctx, [taira.certify(forgerOf(ctx).block(1010n, ms(T0 + 11n), []))]), "a latch");
          refused(ctx, await fromCheckpoint(47n, lapsed[3]), "Equivocated", [], "latched");
          refused(ctx, await inline(47n, lapsed[3]), "Equivocated", [], "inline, latched");
          assertLogs(
            ctx,
            ok(ctx, await voidFrozen(ctx, 47n, 1n)),
            [log("SccpVoided", ZERO32, 47n)],
            "voidFrozen after a latch",
          );
        });
        assertLogs(ctx, ok(ctx, await inline(47n, lapsed[3])), [voided(lapsed[3])], "the snapshots are restored");
      });

      scenario(run, "voidFrozen: ranges, the consumed set and the 2^64 end (§5.1.8)", SAME_SECOND, async (ctx) => {
        const { taira, dest, deployment } = ctx;
        const items = [5n, 300n, 700n, 800n].map((nonce) => transferOf(ctx, { nonce, amount: 1n }));
        const block = taira.block(1010n, ms(T0 + 10n), items);
        ok(ctx, await submit(ctx, [taira.certify(block)], { at: T0 + 100n }));
        for (const item of items) ok(ctx, await finalizeStored(ctx, block.x, proofOf(taira, item, block)));
        const none = (first, count) => Array.from(
          { length: Number(count) },
          (_, offset) => log("SccpVoided", ZERO32, first + BigInt(offset)),
        );
        const word = (index) => storageAt(dest, mappingSlot("uint256", index, 4));

        // Live: the range is judged first, then Frozen, then the consumed set.
        refused(ctx, await voidFrozen(ctx, 0n, 0n), "BadAmount", [], "live: count 0");
        refused(ctx, await voidFrozen(ctx, 0n, 257n), "BadAmount", [], "live: count 257");
        refused(ctx, await voidFrozen(ctx, U64_MAX, 2n), "BadAmount", [], "live: a range past 2^64");
        refused(ctx, await voidFrozen(ctx, 1000n, 1n), "NotFrozen", [], "live");
        refused(ctx, await voidFrozen(ctx, 5n, 1n), "NotFrozen", [], "live: a consumed nonce");
        // A latch freezes at once.
        await onSnapshot(ctx, async () => {
          ok(ctx, await submit(ctx, [taira.certify(forgerOf(ctx).block(1010n, ms(T0 + 11n), []))]), "a latch");
          refused(ctx, await voidFrozen(ctx, 5n, 1n), "AlreadyConsumed", [5n], "latched: a consumed nonce");
          assertLogs(ctx, ok(ctx, await voidFrozen(ctx, 1000n, 3n)), none(1000n, 3n), "latched");
          assert.equal(await dest.view("opCount"), 5n, "a range is one operation");
        });
        // Expiry: Live holds through the second of `untilMs` and ends with the next one.
        const lastLive = deployment.initialUntilMs / 1000n;
        refused(ctx, await voidFrozen(ctx, 1000n, 1n, { at: lastLive }), "NotFrozen", [], "now_ms = untilMs");
        const at = { at: lastLive + 1n };
        refused(ctx, await voidFrozen(ctx, 0n, 0n, at), "BadAmount", [], "frozen: count 0");
        refused(ctx, await voidFrozen(ctx, 0n, 257n, at), "BadAmount", [], "frozen: count 257");
        // A consumed nonce in a one-word range, and in either word of a two-word range: the
        // lowest one is reported and the whole range stays unconsumed.
        refused(ctx, await voidFrozen(ctx, 0n, 256n, at), "AlreadyConsumed", [5n], "one word");
        refused(ctx, await voidFrozen(ctx, 250n, 100n, at), "AlreadyConsumed", [300n], "the second of two words");
        refused(ctx, await voidFrozen(ctx, 600n, 256n, at), "AlreadyConsumed", [700n], "the first of two words");
        refused(ctx, await voidFrozen(ctx, 701n, 256n, at), "AlreadyConsumed", [800n], "the second word again");
        for (const nonce of [0n, 250n, 255n, 256n, 600n, 701n]) {
          assert.equal(await dest.view("isConsumed", [nonce]), false, `nonce ${nonce} after a refused range`);
        }
        assertLogs(ctx, ok(ctx, await voidFrozen(ctx, 1000n, 1n, at)), none(1000n, 1n), "one nonce");
        assertLogs(ctx, ok(ctx, await voidFrozen(ctx, 1024n, 256n, at)), none(1024n, 256n), "256 nonces of one word");
        assert.equal(await word(4n), U256_MAX, "word 4 is full");
        assertLogs(ctx, ok(ctx, await voidFrozen(ctx, 1400n, 256n, at)), none(1400n, 256n), "256 nonces of two words");
        assert.equal(await word(5n), (U256_MAX << 120n) & U256_MAX, "word 5 holds nonces 1400..1535");
        assert.equal(await word(6n), (1n << 120n) - 1n, "word 6 holds nonces 1536..1655");
        refused(ctx, await voidFrozen(ctx, 1400n, 1n, at), "AlreadyConsumed", [1400n], "voided twice");
        refused(ctx, await voidFrozen(ctx, 1399n, 2n, at), "AlreadyConsumed", [1400n], "a range into a voided one");
        refused(ctx, await voidFrozen(ctx, 1600n, 100n, at), "AlreadyConsumed", [1600n], "a range out of a voided one");
        assertLogs(ctx, ok(ctx, await voidFrozen(ctx, 1399n, 1n, at)), none(1399n, 1n), "the nonce before the range");
        assertLogs(ctx, ok(ctx, await voidFrozen(ctx, 1656n, 1n, at)), none(1656n, 1n), "the nonce after the range");
        // firstNonce + count = 2^64 is the last valid range; one more is none.
        refused(ctx, await voidFrozen(ctx, U64_MAX - 254n, 256n, at), "BadAmount", [], "first + count = 2^64 + 1");
        refused(ctx, await voidFrozen(ctx, U64_MAX, 2n, at), "BadAmount", [], "two nonces from 2^64 − 1");
        assertLogs(
          ctx,
          ok(ctx, await voidFrozen(ctx, U64_MAX - 255n, 256n, at)),
          none(U64_MAX - 255n, 256n),
          "first + count = 2^64",
        );
        assert.equal(await dest.view("isConsumed", [U64_MAX]), true);
        assert.equal(await dest.view("isConsumed", [U64_MAX - 256n]), false);
        assert.equal(await word(U64_MAX >> 8n), U256_MAX, "the last word is full");
        refused(ctx, await voidFrozen(ctx, U64_MAX, 1n, at), "AlreadyConsumed", [U64_MAX], "nonce 2^64 − 1 again");
        // Only the 68-byte encoding: longer calldata is refused by the contract before the
        // range, shorter calldata and a word above uint64 by the ABI decoder.
        const encode = (first, count) => m.iface.encodeFunctionData("voidFrozen", [first, count]);
        const canonical = encode(2000n, 1n);
        assert.equal(ethers.dataLength(canonical), 0x44);
        for (const [where, data, error] of [
          ["a trailing byte", ethers.concat([canonical, "0x00"]), "NonCanonicalCalldata"],
          ["a trailing word", ethers.concat([canonical, m.word(0)]), "NonCanonicalCalldata"],
          ["a trailing byte on an empty range", ethers.concat([encode(2000n, 0n), "0x00"]), "NonCanonicalCalldata"],
          ["a missing byte", ethers.dataSlice(canonical, 0, 0x43), null],
          ["one word", ethers.dataSlice(canonical, 0, 0x24), null],
          ["a first nonce of 2^64", patch(canonical, 4, m.word(1n << 64n)), null],
          ["a count of 2^64 + 1", patch(canonical, 36, m.word((1n << 64n) + 1n)), null],
        ]) {
          refused(ctx, await dest.attempt(data, at), error, [], where);
        }
        ok(ctx, await dest.attempt(canonical, at), "the canonical encoding");
        assert.equal(await dest.view("opCount"), 4n + 7n, "four mints and seven voided ranges");
        // A frozen destination mints nothing and applies nothing, and burns stay open.
        refused(ctx, await finalizeStored(ctx, block.x, proofOf(taira, items[0], block), at), "CommitteeNotAccepted");
        refused(
          ctx,
          await submit(ctx, [taira.certify(taira.block(1011n, ms(T0 + 12n), []))], at),
          "CommitteeNotAccepted",
        );
        ok(ctx, await burn(ctx, 9, 1n, 0n, at), "a burn on an expired destination");
        assert.equal(await dest.view("totalSupply"), 3n);
      });

      // -- destination → Taira --------------------------------------------------

      scenario(run, "transferToTaira: burn, sender nonce, payload, canonical calldata (§5.1.7)", {}, async (ctx) => {
        const { taira, chain, dest } = ctx;
        const sender = ethers.getAddress(chain.accounts[5]);
        const second = ethers.getAddress(chain.accounts[6]);
        const funding = [
          transferOf(ctx, { nonce: 1, amount: 10n * UNIT, recipient: sender }),
          transferOf(ctx, { nonce: 2, amount: 4n * UNIT, recipient: second }),
        ];
        const block = taira.block(1010n, ms(T0 + 10n), funding);
        ok(ctx, await submit(ctx, [taira.certify(block)], { at: T0 + 100n }));
        for (const item of funding) ok(ctx, await finalizeStored(ctx, block.x, proofOf(taira, item, block)));
        // What a burn of `from` leaves: the payload of §3.2 with the caller as sender, its id over
        // the lane (own, Taira), the ERC-20 burn and the source event.
        const burnOf = (from, amount, nonce, tairaRecipient = TAIRA_RECIPIENT) => {
          const payload = m.inboundPayload(
            profile,
            { nonce, revision: REVISION, amount, sender: from, tairaRecipient },
          );
          const messageId = m.inboundMessageId(NETWORK_ID, profile, payload);
          return {
            payload,
            messageId,
            logs: [
              log("Transfer", from, ZERO_ADDRESS, amount),
              log("SccpTransferToTaira", messageId, from, nonce, payload),
            ],
          };
        };
        const first = burnOf(sender, 3n * UNIT, 0n);
        assert.equal(await dest.simulate("transferToTaira", [TAIRA_RECIPIENT, 3n * UNIT, 0n], 5), first.messageId);
        let receipt = ok(ctx, await burn(ctx, 5, 3n * UNIT, 0n));
        assertLogs(ctx, receipt, first.logs, "the first burn");
        assert.equal(await chain.returnData(receipt), first.messageId, "the return value");
        const sourceEvent = dest.logs(receipt)[1];
        assert.equal(sourceEvent.topics[2], m.addressWord(sender).toLowerCase(), "topics[2] = word(sender)");
        assert.equal(
          sourceEvent.data,
          abi.encode(["uint64", "bytes"], [0n, first.payload]),
          "data = abi.encode(nonce, payload)",
        );
        assert.equal(await dest.view("transferNonces", [sender]), 1n);
        assert.equal(await dest.view("balanceOf", [sender]), 7n * UNIT);
        assert.equal(await dest.view("totalSupply"), 11n * UNIT);
        assert.equal(await dest.view("opCount"), 3n);

        // The amount, then the nonce, then the balance.
        refused(ctx, await burn(ctx, 5, 0n, 1n), "BadAmount", [], "amount 0");
        refused(ctx, await burn(ctx, 5, U128_MAX + 1n, 1n), "BadAmount", [], "amount 2^128");
        refused(ctx, await burn(ctx, 5, U256_MAX, 1n), "BadAmount", [], "amount 2^256 − 1");
        refused(ctx, await burn(ctx, 5, 0n, 9n), "BadAmount", [], "amount 0 with another nonce");
        refused(ctx, await burn(ctx, 5, UNIT, 0n), "BadNonce", [1n], "a replayed nonce");
        refused(ctx, await burn(ctx, 5, UNIT, 2n), "BadNonce", [1n], "a skipped nonce");
        refused(ctx, await burn(ctx, 5, 100n * UNIT, 9n), "BadNonce", [1n], "another nonce above the balance");
        const balance = 7n * UNIT;
        refused(ctx, await burn(ctx, 5, balance + 1n, 1n), "ERC20InsufficientBalance", [sender, balance, balance + 1n]);
        refused(
          ctx,
          await burn(ctx, 5, U128_MAX, 1n),
          "ERC20InsufficientBalance",
          [sender, balance, U128_MAX],
          "2^128 − 1",
        );
        assert.equal(await dest.view("transferNonces", [sender]), 1n, "a refused burn keeps the nonce");
        // Every sender has its own nonce sequence.
        assertLogs(ctx, ok(ctx, await burn(ctx, 6, UNIT, 0n)), burnOf(second, UNIT, 0n).logs, "another sender");
        refused(ctx, await burn(ctx, 6, UNIT, 0n), "BadNonce", [1n], "another sender, replayed");

        // Recipient lengths 1..=1024, the bytes themselves are not judged.
        const recipients = ["0x7f", `0x${"00".repeat(32)}`, `0x${"ee".repeat(33)}`, `0x${"ee".repeat(1024)}`];
        for (const [index, tairaRecipient] of recipients.entries()) {
          const nonce = 1n + BigInt(index);
          const expected = burnOf(sender, 1n, nonce, tairaRecipient);
          const where = `a recipient of ${ethers.dataLength(tairaRecipient)} bytes`;
          assertLogs(ctx, ok(ctx, await burn(ctx, 5, 1n, nonce, {}, tairaRecipient)), expected.logs, where);
        }
        const send = (data) => dest.attempt(data, { from: 5 });
        const canonical = transferCalldata(TAIRA_RECIPIENT, 1n, 5n);
        assert.equal(canonical, m.iface.encodeFunctionData("transferToTaira", [TAIRA_RECIPIENT, 1n, 5n]));
        const unpadded = { padding: "0x" };
        for (const [where, data, error] of [
          ["an empty recipient", transferCalldata("0x", 1n, 5n), "NonCanonicalCalldata"],
          ["a recipient of 1025 bytes", transferCalldata(`0x${"ee".repeat(1025)}`, 1n, 5n), "NonCanonicalCalldata"],
          [
            "the recipient one word further",
            transferCalldata(TAIRA_RECIPIENT, 1n, 5n, { offset: 0x80, inserted: [m.word(0)] }),
            "NonCanonicalCalldata",
          ],
          // The same, with a word at the canonical place of the length that fits the calldata size.
          [
            "the recipient one word further, behind a fitting length",
            transferCalldata(TAIRA_RECIPIENT, 1n, 5n, { offset: 0x80, inserted: [m.word(96)] }),
            "NonCanonicalCalldata",
          ],
          [
            "a nonzero last padding byte",
            transferCalldata(TAIRA_RECIPIENT, 1n, 5n, { padding: `0x${"00".repeat(29)}01` }),
            "NonCanonicalCalldata",
          ],
          [
            "a nonzero first padding byte",
            transferCalldata(TAIRA_RECIPIENT, 1n, 5n, { padding: `0x01${"00".repeat(29)}` }),
            "NonCanonicalCalldata",
          ],
          [
            "a length one below the bytes",
            transferCalldata(TAIRA_RECIPIENT, 1n, 5n, { length: 33 }),
            "NonCanonicalCalldata",
          ],
          ["no padding", transferCalldata(TAIRA_RECIPIENT, 1n, 5n, unpadded), "NonCanonicalCalldata"],
          ["a trailing byte", transferCalldata(TAIRA_RECIPIENT, 1n, 5n, { tail: "0x00" }), "NonCanonicalCalldata"],
          ["a trailing word", transferCalldata(TAIRA_RECIPIENT, 1n, 5n, { tail: m.word(0) }), "NonCanonicalCalldata"],
          // The calldata rule comes before the amount and the nonce.
          [
            "a trailing byte with amount 0",
            transferCalldata(TAIRA_RECIPIENT, 0n, 5n, { tail: "0x00" }),
            "NonCanonicalCalldata",
          ],
          [
            "a trailing byte with another nonce",
            transferCalldata(TAIRA_RECIPIENT, 1n, 9n, { tail: "0x00" }),
            "NonCanonicalCalldata",
          ],
          // What Solidity's own decoder refuses, with empty data.
          ["a nonce word of 2^64 + 5", transferCalldata(TAIRA_RECIPIENT, 1n, (1n << 64n) + 5n), null],
          ["an offset past the calldata", transferCalldata(TAIRA_RECIPIENT, 1n, 5n, { offset: 0x1000 }), null],
          ["a length past the calldata", transferCalldata(TAIRA_RECIPIENT, 1n, 5n, { length: 0x1000 }), null],
          ["half of the recipient bytes", ethers.dataSlice(canonical, 0, 4 + 0x80 + 17), null],
          ["two argument words", ethers.dataSlice(canonical, 0, 4 + 0x40), null],
        ]) {
          refused(ctx, await send(data), error, [], where);
        }
        assert.equal(await dest.view("transferNonces", [sender]), 5n);
        assertLogs(ctx, ok(ctx, await send(canonical)), burnOf(sender, 1n, 5n).logs, "the canonical encoding");

        // The sender is the caller, a contract included; it has its own nonce sequence.
        const forwarder = await h.deployForwarder(chain, dest.address);
        const relayedBurn = m.iface.encodeFunctionData("transferToTaira", [TAIRA_RECIPIENT, UNIT, 0n]);
        const relayed = { to: forwarder, from: 5, data: relayedBurn };
        refused(
          ctx,
          await chain.attempt(relayed),
          "ERC20InsufficientBalance",
          [forwarder, 0n, UNIT],
          "a caller without tokens",
        );
        ok(ctx, await call(ctx, "transfer", [forwarder, UNIT], { from: 5 }));
        assertLogs(
          ctx,
          ok(ctx, await chain.attempt(relayed)),
          burnOf(forwarder, UNIT, 0n).logs,
          "a burn by a contract",
        );
        assert.equal(await dest.view("transferNonces", [forwarder]), 1n);
        assert.equal(await dest.view("transferNonces", [sender]), 6n);
        assert.equal(await dest.view("opCount"), 2n + 8n, "two mints and eight burns");
        assert.equal(await dest.view("totalSupply"), 14n * UNIT - 3n * UNIT - UNIT - 5n - UNIT);
      });

      // -- controls and the pause ----------------------------------------------------

      scenario(run, "applyControl: tracks, nonces, clamp and local expiry (§5.1.6)", SAME_SECOND, async (ctx) => {
        const { taira, dest } = ctx;
        const T = T0 + 100n;
        const until = ms(T0 + 2n * HOUR);
        const exactAt = T0 + 3n * HOUR;
        const overAt = exactAt + 10n;
        const farAt = overAt + 10n;
        const lapsedAt = farAt + 10n;
        const max = m.MAX_FAST_PAUSE_MS;
        const leaves = {
          paused: controlOf(ctx, controlFields(1, 1, true, 0n)),
          fast: controlOf(ctx, controlFields(2, 2, true, until)),
          resumed: controlOf(ctx, controlFields(5, 1, false, until)),
          skipped: controlOf(ctx, controlFields(4, 1, false, 0n)),
          equal: controlOf(ctx, controlFields(5, 2, false, until)),
          zero: controlOf(ctx, controlFields(0, 1, false, 0n)),
          atBound: controlOf(ctx, controlFields(10, 2, false, ms(exactAt) + max)),
          aboveBound: controlOf(ctx, controlFields(11, 2, false, ms(overAt) + max + 1n)),
          far: controlOf(ctx, controlFields(12, 2, false, ms(T0 + 100n * DAY))),
          lapsed: controlOf(ctx, controlFields(13, 2, false, 1n)),
          last: controlOf(ctx, controlFields(U64_MAX, 1, false, 0n)),
          after: controlOf(ctx, controlFields(14, 1, true, 0n)),
          // Leaves that violate a §3.4 constraint; a genuine committee never certifies one.
          trackZero: controlOf(ctx, controlFields(20, 0)),
          trackThree: controlOf(ctx, controlFields(21, 3)),
          fastWithoutExpiry: controlOf(ctx, controlFields(22, 2, false, 0n)),
          noCertificate: controlOf(ctx, { ...controlFields(23), certificateId: ZERO32 }),
          noEffect: controlOf(ctx, { ...controlFields(24), effectHash: ZERO32 }),
          staleAndMalformed: controlOf(ctx, controlFields(1, 3)),
        };
        const mints = [1, 2].map((nonce) => transferOf(ctx, { nonce }));
        const block = taira.block(1010n, ms(T0 + 10n), [...Object.values(leaves), ...mints]);
        const certificate = taira.certify(block);
        const proof = (item) => proofOf(taira, item, block);
        const apply = (item, at) => controlStored(ctx, block.x, proof(item), { at });
        const mint = (item, at) => finalizeStored(ctx, block.x, proof(item), { at });
        const expectState = async (item, storedUntilMs, effective, where) => {
          const { controlNonce, parliamentPaused } = item.control;
          const expected = { parliamentPaused, fastPauseUntilMs: storedUntilMs, controlNonce, effective };
          assert.deepEqual(await pauseState(dest), expected, `${ctx.title}: ${where}`);
          assert.equal(await dest.view("controlNonce"), controlNonce, where);
          assert.equal(await dest.view("mintingPaused"), effective, where);
        };

        // Track 1 sets the Parliament flag; the first use of the certificate is published.
        let receipt = ok(ctx, await controlInline(ctx, certificate, proof(leaves.paused), { at: T }));
        assertLogs(ctx, receipt, [published(certificate), stored(block), applied(leaves.paused.control)], "track 1");
        await expectState(leaves.paused, 0n, true, "track 1");
        assert.equal(await dest.view("opCount"), 1n);
        refused(ctx, await mint(mints[0], T), "MintingIsPaused", [], "the Parliament pause");
        // The constraints of §3.4 come before the nonce: a malformed leaf is BadControl even when stale.
        const malformed = [
          "trackZero",
          "trackThree",
          "fastWithoutExpiry",
          "noCertificate",
          "noEffect",
          "staleAndMalformed",
        ];
        for (const name of malformed) {
          refused(ctx, await apply(leaves[name], T), "BadControl", [], name);
          refused(
            ctx,
            await controlInline(ctx, certificate, proof(leaves[name]), { at: T }),
            "BadControl",
            [],
            `inline: ${name}`,
          );
        }
        // Track 2 carries the complete state: the Parliament flag stays, the fast pause is added.
        assertLogs(ctx, ok(ctx, await apply(leaves.fast, T)), [applied(leaves.fast.control)], "track 2");
        await expectState(leaves.fast, until, true, "track 2");
        // A skipped nonce: 5 after 2. The Parliament resumes, the fast pause still holds.
        receipt = ok(ctx, await controlInline(ctx, certificate, proof(leaves.resumed), { at: T }));
        assertLogs(ctx, receipt, [applied(leaves.resumed.control)], "nonce 5 after nonce 2");
        await expectState(leaves.resumed, until, true, "nonce 5");
        for (const name of ["skipped", "equal", "paused", "fast", "zero"]) {
          refused(ctx, await apply(leaves[name], T), "StaleControl", [], `nonce ${leaves[name].control.controlNonce}`);
        }
        refused(
          ctx,
          await controlInline(ctx, certificate, proof(leaves.equal), { at: T }),
          "StaleControl",
          [],
          "inline, equal",
        );
        assert.equal(await dest.view("opCount"), 3n, "a refused control is no operation");
        // The fast pause ends by the destination's own clock: effective while now_ms < fastPauseUntilMs.
        refused(ctx, await mint(mints[0], until / 1000n - 1n), "MintingIsPaused", [], "one second before the expiry");
        assert.equal(await dest.view("mintingPaused"), true);
        assertLogs(ctx, ok(ctx, await mint(mints[0], until / 1000n)), minted(mints[0]), "at the expiry");
        assert.equal(await dest.view("mintingPaused"), false);
        // The clamp min(leaf, now_ms + MAX_FAST_PAUSE_MS): the bound itself is kept, one more is cut.
        assertLogs(
          ctx,
          ok(ctx, await apply(leaves.atBound, exactAt)),
          [applied(leaves.atBound.control)],
          "at the bound",
        );
        await expectState(leaves.atBound, ms(exactAt) + max, true, "at the bound");
        receipt = ok(ctx, await apply(leaves.aboveBound, overAt));
        assertLogs(ctx, receipt, [applied(leaves.aboveBound.control, ms(overAt) + max)], "one above the bound");
        await expectState(leaves.aboveBound, ms(overAt) + max, true, "one above the bound");
        receipt = ok(ctx, await apply(leaves.far, farAt));
        assertLogs(ctx, receipt, [applied(leaves.far.control, ms(farAt) + max)], "far above the bound");
        await expectState(leaves.far, ms(farAt) + max, true, "far above the bound");
        refused(ctx, await mint(mints[1], farAt), "MintingIsPaused", [], "the clamped fast pause");
        // A track-2 leaf applied after its expiry only consumes its nonce and ends the pause.
        assertLogs(
          ctx,
          ok(ctx, await apply(leaves.lapsed, lapsedAt)),
          [applied(leaves.lapsed.control)],
          "after its expiry",
        );
        await expectState(leaves.lapsed, 1n, false, "after its expiry");
        assertLogs(ctx, ok(ctx, await mint(mints[1], lapsedAt)), minted(mints[1]), "after a lapsed fast pause");
        // The largest nonce applies, and nothing applies after it.
        const largest = ok(ctx, await apply(leaves.last, lapsedAt));
        assertLogs(ctx, largest, [applied(leaves.last.control)], "nonce 2^64 − 1");
        await expectState(leaves.last, 0n, false, "nonce 2^64 − 1");
        refused(ctx, await apply(leaves.after, lapsedAt), "StaleControl", [], "after the largest nonce");
        refused(ctx, await apply(leaves.last, lapsedAt), "StaleControl", [], "the largest nonce again");
        assert.equal(await dest.view("opCount"), 10n, "eight controls and two mints");
      });

      scenario(run, "a leaf binds its kind, lane, destination, revision and every field (§3.4)", {}, async (ctx) => {
        const { taira, dest } = ctx;
        const fields = controlFields(20, 2, false, ms(T0 + HOUR));
        const elsewhere = m.addressWord(`0x${"22".repeat(20)}`);
        const reversed = m.inboundLaneBytes(NETWORK_ID, profile);
        const foreignControls = [
          ["the lane of the other profile", controlOf(ctx, fields, { profile: other })],
          ["another Taira network", controlOf(ctx, fields, { networkId: OTHER_NETWORK_ID })],
          ["the reverse lane", controlOf(ctx, fields, { laneBytes: reversed })],
          ["another destination", controlOf(ctx, fields, { destinationWord: elsewhere })],
          ["the zero destination", controlOf(ctx, fields, { destinationWord: ZERO32 })],
          ["another revision", controlOf(ctx, fields, { revision: REVISION + 1 })],
          ["revision 0", controlOf(ctx, fields, { revision: 0 })],
        ];
        const own = controlOf(ctx, fields);
        const payment = transferOf(ctx, { nonce: 1 });
        const foreignTransfers = [
          ["the lane of the other profile", transferOf(ctx, { nonce: 2 }, { profile: other })],
          ["another Taira network", transferOf(ctx, { nonce: 3 }, { networkId: OTHER_NETWORK_ID })],
          ["another destination", transferOf(ctx, { nonce: 4 }, { destinationWord: elsewhere })],
        ];
        const leaves = [
          ...foreignControls.map(([, item]) => item),
          own,
          payment,
          ...foreignTransfers.map(([, item]) => item),
        ];
        const block = taira.block(1010n, ms(T0 + 10n), leaves);
        ok(ctx, await submit(ctx, [taira.certify(block)], { at: T0 + 100n }));
        const proof = (item) => proofOf(taira, item, block);
        const at = (item) => {
          const leafIndex = block.leaves.indexOf(item);
          return { leafIndex, path: m.merklePath(block.leaves.map((leaf) => leaf.leaf), leafIndex) };
        };
        // The destination computes the leaf from its own lane, address and revision.
        for (const [where, item] of foreignControls) {
          refused(ctx, await controlStored(ctx, block.x, proof(item)), "BadProof", [], `a control of ${where}`);
        }
        for (const [where, item] of foreignTransfers) {
          refused(ctx, await finalizeStored(ctx, block.x, proof(item)), "BadProof", [], `a transfer of ${where}`);
        }
        // No leaf kind passes as the other: a transfer leaf offered as a control, and the reverse.
        const ownProof = proof(own);
        const paymentProof = proof(payment);
        refused(
          ctx,
          await controlStored(ctx, block.x, { ...ownProof, ...at(payment) }),
          "BadProof",
          [],
          "a transfer leaf as a control",
        );
        refused(
          ctx,
          await finalizeStored(ctx, block.x, { ...paymentProof, ...at(own) }),
          "BadProof",
          [],
          "a control leaf as a transfer",
        );
        // Every field is in the leaf: one changed field is another leaf.
        const changed = [
          ["the nonce", { controlNonce: fields.controlNonce + 1n }],
          ["the track", { track: 1 }],
          ["the Parliament flag", { parliamentPaused: true }],
          ["the expiry", { fastPauseUntilMs: fields.fastPauseUntilMs + 1n }],
          ["the certificate id", { certificateId: id("another certificate") }],
          ["the effect hash", { effectHash: id("another effect") }],
        ];
        for (const [where, override] of changed) {
          refused(
            ctx,
            await controlStored(ctx, block.x, { ...ownProof, ...override }),
            "BadProof",
            [],
            `${where} changed`,
          );
        }
        assert.equal(await dest.view("opCount"), 0n);
        assertLogs(ctx, ok(ctx, await controlStored(ctx, block.x, ownProof)), [applied(fields)], "the own control");
        assert.equal(await dest.view("mintingPaused"), true);
        refused(ctx, await finalizeStored(ctx, block.x, paymentProof), "MintingIsPaused");
        assertLogs(
          ctx,
          ok(ctx, await finalizeStored(ctx, block.x, paymentProof, { at: T0 + HOUR })),
          minted(payment),
          "the own transfer",
        );
      });

      scenario(run, "the effective pause blocks minting only and survives a rotation (§5.1.6)", {}, async (ctx) => {
        const { taira, dest, chain } = ctx;
        const past = ms(T0 + 50n);
        const funded = transferOf(ctx, { nonce: 1, amount: 5n * UNIT });
        const blocked = transferOf(ctx, { nonce: 2 });
        const lapsed = [3n, 4n].map((nonce) => transferOf(ctx, { nonce, deadlineMs: past }));
        const pause = controlOf(ctx, controlFields(1, 1, true, 0n));
        const fast = controlOf(ctx, controlFields(2, 2, true, ms(T0 + HOUR)));
        const resume = controlOf(ctx, controlFields(3, 1, false, 0n));
        const a = taira.block(1010n, ms(T0 + 10n), [funded, blocked, ...lapsed, pause, fast, resume]);
        const certificate = taira.certify(a);
        const later = transferOf(ctx, { nonce: 5 });
        const b = taira.block(1011n, ms(T0 + 11n), [later]);
        const proof = (item, block = a, certified = block) => proofOf(taira, item, block, certified);
        ok(ctx, await finalizeInline(ctx, certificate, proof(funded), { at: T0 + 100n }));
        ok(ctx, await controlInline(ctx, certificate, proof(pause)));
        assert.equal(await dest.view("mintingPaused"), true);

        // Minting is refused, before the block reference, the payload and the deadline.
        refused(ctx, await finalizeStored(ctx, a.x, proof(blocked)), "MintingIsPaused", [], "from a checkpoint");
        refused(ctx, await finalizeInline(ctx, certificate, proof(blocked)), "MintingIsPaused", [], "inline");
        refused(
          ctx,
          await finalizeInline(ctx, taira.certify(b), proof(later, b)),
          "MintingIsPaused",
          [],
          "inline, a new X",
        );
        assert.equal(await dest.view("checkpointHeader", [1011n]), ZERO32, "the refused call stored nothing");
        const recount = { ...proof(blocked), block: { ...proof(blocked).block, messageCount: 1n } };
        refused(ctx, await finalizeStored(ctx, a.x, recount), "MintingIsPaused", [], "with a bad block reference");
        refused(ctx, await finalizeStored(ctx, a.x, proof(lapsed[0])), "MintingIsPaused", [], "after the deadline");
        // Checkpoints, voids, burns, token transfers and controls stay open.
        ok(ctx, await submit(ctx, [taira.certify(b)]), "a checkpoint while paused");
        assertLogs(
          ctx,
          ok(ctx, await voidInline(ctx, 3n, certificate, proof(lapsed[0]))),
          [voided(lapsed[0])],
          "an inline void",
        );
        assertLogs(ctx, ok(ctx, await voidStored(ctx, 4n, a.x, proof(lapsed[1]))), [voided(lapsed[1])], "a void");
        ok(ctx, await burn(ctx, 9, UNIT, 0n), "a burn while paused");
        ok(
          ctx,
          await call(ctx, "transfer", [ethers.getAddress(chain.accounts[4]), UNIT], { from: 9 }),
          "a transfer while paused",
        );
        assertLogs(
          ctx,
          ok(ctx, await controlStored(ctx, a.x, proof(fast))),
          [applied(fast.control)],
          "a control while paused",
        );
        // A rotation while paused; the pause state is not the committee's and stays.
        const handoff = taira.block(1020n, ms(T0 + 20n), [], { rotate: "key", nextCommittee: committeeOf(4, 1) });
        const rotation = taira.certify(handoff);
        const untilMs = ms(T0 + 20n) + VALIDITY_MS;
        assertLogs(
          ctx,
          ok(ctx, await submit(ctx, [rotation])),
          [published(rotation), stored(handoff), rotated(handoff, untilMs)],
          "a rotation",
        );
        const state = await pauseState(dest);
        assert.deepEqual(
          state,
          { parliamentPaused: true, fastPauseUntilMs: ms(T0 + HOUR), controlNonce: 2n, effective: true },
        );
        refused(
          ctx,
          await finalizeStored(ctx, handoff.x, proof(blocked, a, handoff)),
          "MintingIsPaused",
          [],
          "after the rotation",
        );
        // Live comes before the pause.
        await onSnapshot(ctx, async () => {
          const expired = { at: untilMs / 1000n + 1n };
          refused(
            ctx,
            await finalizeStored(ctx, handoff.x, proof(blocked, a, handoff), expired),
            "CommitteeNotAccepted",
          );
        });
        // The newest control resumes: it carries the complete state, so the fast pause ends too.
        const resumed = ok(ctx, await controlStored(ctx, handoff.x, proof(resume, a, handoff)));
        assertLogs(ctx, resumed, [applied(resume.control)], "the resuming control, through the history");
        assert.equal(await dest.view("mintingPaused"), false);
        assertLogs(
          ctx,
          ok(ctx, await finalizeStored(ctx, handoff.x, proof(blocked, a, handoff))),
          minted(blocked),
          "a mint after the pause",
        );
        assert.equal(await dest.view("opCount"), 8n, "two mints, three controls, two voids and one burn");
      });

      // -- latches, batches and rotations ---------------------------------------

      scenario(run, "V1–V3: LatchRequired inline, a lasting latch in a checkpoint batch", {}, async (ctx) => {
        const { taira, dest, signedBy } = ctx;
        const past = ms(T0 + 50n);
        const funded = transferOf(ctx, { nonce: 1, amount: 3n * UNIT });
        const pending = transferOf(ctx, { nonce: 2 });
        const lapsed = transferOf(ctx, { nonce: 3, deadlineMs: past });
        const controlItem = controlOf(ctx, controlFields(1));
        const lower = taira.block(1005n, ms(T0 + 5n), []);
        const a = taira.block(1010n, ms(T0 + 10n), [funded, pending, lapsed, controlItem]);
        const certificateA = taira.certify(a);
        const proof = (item) => proofOf(taira, item, a);
        ok(ctx, await submit(ctx, [taira.certify(lower), certificateA], { at: T0 + 100n }));
        ok(ctx, await finalizeStored(ctx, a.x, proof(funded)));
        const probes = { heights: [990n, 999n, 1005n, 1007n, 1010n, 1011n, 1020n], nonces: [1n, 2n, 3n, 10n, 11n] };
        const before = await dest.state(probes);
        const idOf = (block) => m.checkpointId(block.x);

        // Conflicts the current generation signed, each with a leaf for every inline entry point.
        const conflict = (height, timestampMs, base, options) => {
          const forger = forgerOf(ctx);
          const leaves = [
            transferOf(ctx, { nonce: base }),
            transferOf(ctx, { nonce: base + 1, deadlineMs: past }),
            controlOf(ctx, controlFields(base)),
          ];
          const block = forger.block(height, timestampMs, leaves, options);
          return { forger, block, leaves, certificate: forger.certify(block) };
        };
        const heartbeat = { rotate: "heartbeat" };
        const rows = [
          ["V1: another X at a stored height", conflict(1010n, ms(T0 + 11n), 10), 1, idOf(a)],
          ["V2: a height below the start", conflict(999n, ms(T0 + 12n), 20), 2, signedBy.root],
          ["V3: a rotation below high", conflict(1007n, ms(T0 + 13n), 30, heartbeat), 3, signedBy.root],
          [
            "V1 before V3: a rotation at a stored height below high",
            conflict(1005n, ms(T0 + 14n), 40, heartbeat),
            1,
            idOf(lower),
          ],
          ["V2 before V3: a rotation below the start", conflict(990n, ms(T0 + 15n), 50, heartbeat), 2, signedBy.root],
        ];
        for (const [where, { forger, block, leaves, certificate }, reason, first] of rows) {
          const [mint, old, controlLeaf] = leaves.map((item) => proofOf(forger, item, block));
          refused(
            ctx,
            await finalizeInline(ctx, certificate, mint),
            "LatchRequired",
            [],
            `finalizeFromTaira, ${where}`,
          );
          refused(
            ctx,
            await controlInline(ctx, certificate, controlLeaf),
            "LatchRequired",
            [],
            `applyControl, ${where}`,
          );
          refused(
            ctx,
            await voidInline(ctx, leaves[1].nonce, certificate, old),
            "LatchRequired",
            [],
            `voidExpired, ${where}`,
          );
          const unchanged = await dest.state(probes);
          assert.deepEqual(unchanged, before, `${where}: an inline entry point never latches`);
          await onSnapshot(ctx, async () => {
            const receipt = ok(ctx, await submit(ctx, [certificate]), where);
            assertLogs(ctx, receipt, [published(certificate), latched(reason, block, first)], where);
            const expected = structuredClone(before);
            expected.equivocated = true;
            expected.live = false;
            expected.committee.until_ms = 0;
            assert.deepEqual(await dest.state(probes), expected, `${where}: the latch changes nothing else`);
          });
        }
        // V1 before V2: after a handoff, the successor signs another X at a height its
        // predecessor stored, which lies below the successor's start.
        await onSnapshot(ctx, async () => {
          const forger = forgerOf(ctx);
          const handoff = forger.block(1020n, ms(T0 + 20n), [], heartbeat);
          ok(ctx, await submit(ctx, [forger.certify(handoff)]));
          const belowStart = forger.block(1010n, ms(T0 + 21n), []);
          const signed = forger.certify(belowStart);
          await onSnapshot(ctx, async () => {
            assertLogs(
              ctx,
              ok(ctx, await submit(ctx, [signed])),
              [published(signed), latched(1, belowStart, idOf(a))],
              "V1 before V2",
            );
          });
          const unstored = forger.block(1015n, ms(T0 + 22n), []);
          const other = forger.certify(unstored);
          assertLogs(
            ctx,
            ok(ctx, await submit(ctx, [other])),
            [published(other), latched(2, unstored, signedBy.root)],
            "V2 after a handoff",
          );
        });

        // The latch itself, for good.
        const { forger, block: conflicting, leaves, certificate } = rows[0][1];
        ok(ctx, await submit(ctx, [certificate]));
        assert.deepEqual(
          await committeeState(dest),
          { root: signedBy.root, untilMs: 0n, start: START, high: 1010n, generation: GENERATION },
        );
        assert.equal(await dest.view("equivocated"), true);
        assert.equal(await dest.view("checkpointHeader", [1010n]), idOf(a), "the conflicting X is not stored");
        assert.equal(await dest.view("opCount"), 1n, "a latch is no operation");
        const fresh = taira.block(1011n, ms(T0 + 30n), [transferOf(ctx, { nonce: 60 })]);
        const freshProof = proofOf(taira, fresh.leaves[0], fresh);
        const seventeen = Array.from({ length: 17 }, () => certificateA);
        const conflictProof = proofOf(forger, leaves[0], conflicting);
        for (const [where, attempt, error] of [
          ["a new certificate", () => submit(ctx, [taira.certify(fresh)]), "Equivocated"],
          ["the conflicting certificate again", () => submit(ctx, [certificate]), "Equivocated"],
          ["a stored certificate", () => submit(ctx, [certificateA]), "Equivocated"],
          // The two batch-size checks come before Live.
          ["an empty batch", () => submit(ctx, []), "NothingToDo"],
          ["17 certificates", () => submit(ctx, seventeen), "TooManyCertificates"],
          ["finalizeFromCheckpoint", () => finalizeStored(ctx, a.x, proof(pending)), "Equivocated"],
          ["finalizeFromTaira on a stored X", () => finalizeInline(ctx, certificateA, proof(pending)), "Equivocated"],
          ["finalizeFromTaira on a new X", () => finalizeInline(ctx, taira.certify(fresh), freshProof), "Equivocated"],
          ["applyControlFromCheckpoint", () => controlStored(ctx, a.x, proof(controlItem)), "Equivocated"],
          ["applyControl", () => controlInline(ctx, certificateA, proof(controlItem)), "Equivocated"],
          ["voidExpiredFromCheckpoint", () => voidStored(ctx, 3n, a.x, proof(lapsed)), "Equivocated"],
          ["voidExpired", () => voidInline(ctx, 3n, certificateA, proof(lapsed)), "Equivocated"],
          // V1–V3 are judged before Live, and so is the stored id of a checkpoint.
          ["finalizeFromTaira on the conflict", () => finalizeInline(ctx, certificate, conflictProof), "LatchRequired"],
          ["an unknown checkpoint", () => finalizeStored(ctx, fresh.x, freshProof), "UnknownCheckpoint"],
          // Time does not clear the latch.
          ["a new certificate a day later", () => submit(ctx, [taira.certify(fresh)], { at: T0 + DAY }), "Equivocated"],
        ]) {
          refused(ctx, await attempt(), error, [], `latched: ${where}`);
        }
        // A latched destination is frozen: ranges void, and tokens still move and burn.
        assertLogs(
          ctx,
          ok(ctx, await voidFrozen(ctx, 2n, 2n)),
          [log("SccpVoided", ZERO32, 2n), log("SccpVoided", ZERO32, 3n)],
          "voidFrozen",
        );
        ok(ctx, await burn(ctx, 9, UNIT, 0n), "a burn after the latch");
        ok(ctx, await call(ctx, "transfer", [ethers.getAddress(ctx.chain.accounts[4]), UNIT], { from: 9 }));
        assert.equal(await dest.view("mintingPaused"), false, "the latch is not the pause");
        assert.equal(await dest.view("opCount"), 3n);
      });

      scenario(run, "submitCheckpoints batches: atomic, but a latch and a lost Live stop", {}, async (ctx) => {
        const { taira, dest } = ctx;
        const blocks = [0n, 1n, 2n, 3n].map((offset) => taira.block(1010n + offset, ms(T0 + 10n + offset), []));
        const [c0, c1, c2, c3] = blocks.map((block) => taira.certify(block));
        const malformed = { ...c3, qc: "0x" };
        const unsigned = taira.certify(blocks[3], { kind: 0x02 });
        const otherGeneration = { ...c1, header: patch(c1.header, 141, m.be(GENERATION + 1n, 8)) };
        const generation = async () => (await committeeState(dest)).generation;
        const storedAt = (height) => dest.view("checkpointHeader", [height]);

        // One failing certificate undoes the batch.
        refused(
          ctx,
          await submit(ctx, [c0, c1, unsigned], { at: T0 + 100n }),
          "BadSignature",
          [],
          "a bad signature last",
        );
        refused(ctx, await submit(ctx, [c0, malformed]), "BadCertificate", [], "a malformed certificate last");
        refused(ctx, await submit(ctx, [c0, otherGeneration]), "CommitteeNotAccepted", [], "another generation last");
        assert.equal(await storedAt(1010n), ZERO32);
        assert.equal((await committeeState(dest)).high, START - 1n);
        ok(ctx, await submit(ctx, [c0]));
        // Stored certificates in a batch are skipped; only what is new changes state.
        assertLogs(
          ctx,
          ok(ctx, await submit(ctx, [c0, c1, c0])),
          [published(c1), stored(blocks[1])],
          "one new certificate of three",
        );
        refused(ctx, await submit(ctx, [c0, c1]), "NothingToDo", [], "two stored certificates");

        // A latch inside a batch: what came before it persists, what comes after is not examined.
        const conflict = forgerOf(ctx).block(1010n, ms(T0 + 20n), []);
        const conflicting = taira.certify(conflict);
        const first = m.checkpointId(blocks[0].x);
        await onSnapshot(ctx, async () => {
          const receipt = ok(ctx, await submit(ctx, [c2, conflicting, c3, malformed]));
          assertLogs(
            ctx,
            receipt,
            [published(c2), stored(blocks[2]), published(conflicting), latched(1, conflict, first)],
            "a latch second",
          );
          assert.equal(await storedAt(1012n), m.checkpointId(blocks[2].x), "the checkpoint before the latch persists");
          assert.equal(await storedAt(1013n), ZERO32, "the certificate after the latch is not processed");
          assert.deepEqual(
            await committeeState(dest),
            { root: ctx.signedBy.root, untilMs: 0n, start: START, high: 1012n, generation: GENERATION },
          );
        });
        await onSnapshot(ctx, async () => {
          const receipt = ok(ctx, await submit(ctx, [conflicting, malformed, unsigned]));
          assertLogs(ctx, receipt, [published(conflicting), latched(1, conflict, first)], "a latch first");
        });

        // A rotation inside a batch: the next certificate must be the successor's.
        const handoff = taira.block(1020n, ms(T0 + 30n), [], { rotate: "key", nextCommittee: committeeOf(4, 1) });
        const successorBlock = taira.block(1021n, ms(T0 + 31n), []);
        const rotation = taira.certify(handoff);
        const successor = taira.certify(successorBlock);
        refused(
          ctx,
          await submit(ctx, [c2, rotation, c3]),
          "CommitteeNotAccepted",
          [],
          "the retired generation after its handoff",
        );
        refused(
          ctx,
          await submit(ctx, [successor, rotation]),
          "CommitteeNotAccepted",
          [],
          "the successor before its handoff",
        );
        assert.equal(await generation(), GENERATION);
        assert.equal(await storedAt(1012n), ZERO32);
        const untilMs = ms(T0 + 30n) + VALIDITY_MS;
        assertLogs(ctx, ok(ctx, await submit(ctx, [c2, rotation, successor])), [
          published(c2),
          stored(blocks[2]),
          published(rotation),
          stored(handoff),
          rotated(handoff, untilMs),
          published(successor),
          stored(successorBlock),
        ], "a checkpoint, a rotation and the successor's first certificate");
        assert.equal(await generation(), GENERATION + 1n);
        refused(ctx, await submit(ctx, [rotation]), "CommitteeNotAccepted", [], "the handoff again");

        // A rotation whose successor is expired on arrival: installed, and the batch stops there.
        await onSnapshot(ctx, async () => {
          const forger = forgerOf(ctx);
          const brief = forger.block(1030n, ms(T0 + 40n), [], { rotate: "heartbeat", validityMs: 1000n });
          const unreached = forger.block(1031n, ms(T0 + 41n), []);
          const last = forger.certify(brief);
          const receipt = ok(ctx, await submit(ctx, [last, forger.certify(unreached), malformed]));
          assertLogs(
            ctx,
            receipt,
            [published(last), stored(brief), rotated(brief, ms(T0 + 41n))],
            "a successor that is expired",
          );
          assert.deepEqual(await committeeState(dest), {
            root: committeeOf(4, 1).root,
            untilMs: ms(T0 + 41n),
            start: 1031n,
            high: 1030n,
            generation: GENERATION + 2n,
          });
          assert.equal(await storedAt(1031n), ZERO32);
          refused(
            ctx,
            await submit(ctx, [forger.certify(unreached)]),
            "CommitteeNotAccepted",
            [],
            "an expired destination",
          );
          ok(ctx, await voidFrozen(ctx, 0n, 1n), "voidFrozen after the lost Live");
          assert.equal(await dest.view("opCount"), 1n, "checkpoints and rotations are not counted");
        });
        // A successor whose deadline is the very millisecond of the call is Live: the batch goes on.
        const now = T0 + 500n;
        const exact = taira.block(1030n, ms(now - 1n), [], { rotate: "heartbeat", validityMs: 1000n });
        const reached = taira.block(1031n, ms(now), []);
        const [handoffAtDeadline, afterIt] = [exact, reached].map((block) => taira.certify(block));
        assertLogs(ctx, ok(ctx, await submit(ctx, [handoffAtDeadline, afterIt], { at: now })), [
          published(handoffAtDeadline),
          stored(exact),
          rotated(exact, ms(now)),
          published(afterIt),
          stored(reached),
        ], "a successor whose deadline is now");
        assert.equal(await generation(), GENERATION + 2n);
        refused(
          ctx,
          await submit(ctx, [taira.certify(taira.block(1032n, ms(now), []))]),
          "CommitteeNotAccepted",
          [],
          "a second later",
        );
        assert.equal(await dest.view("opCount"), 0n, "checkpoints and rotations are not counted");
      });

      scenario(run, "sixteen rotations in one call, one generation each, in order", SAME_SECOND, async (ctx) => {
        const { taira, dest, signedBy } = ctx;
        const kPrime = committeeOf(4, 1);
        const now = T0 + 1000n;
        const rotations = [];
        for (let index = 0; index < 17; index += 1) {
          const position = BigInt(index);
          const signer = taira.current.committee;
          // Two key changes, then a heartbeat; each grants another validity.
          const validityMs = VALIDITY_MS - position * 3_600_000n;
          const rotate = index % 3 === 2
            ? { rotate: "heartbeat", validityMs }
            : { rotate: "key", nextCommittee: signer === signedBy ? kPrime : signedBy, validityMs };
          // Every fourth handoff is dated after the call: its successor counts from the destination's clock.
          const timestampMs = index % 4 === 3 ? ms(now + 500n + position) : ms(T0 + 20n + position);
          const block = taira.block(1010n + 10n * position, timestampMs, [], rotate);
          const effective = timestampMs < ms(now) ? timestampMs : ms(now);
          rotations.push({ block, certificate: taira.certify(block), untilMs: effective + validityMs });
        }
        const certificates = rotations.map((rotation) => rotation.certificate);
        const at = { at: now };
        refused(ctx, await submit(ctx, certificates, at), "TooManyCertificates", [], "17 rotations");
        refused(
          ctx,
          await submit(ctx, [certificates[1], certificates[0]], at),
          "CommitteeNotAccepted",
          [],
          "out of order",
        );
        refused(
          ctx,
          await submit(ctx, [certificates[0], certificates[2]], at),
          "CommitteeNotAccepted",
          [],
          "a skipped generation",
        );
        assert.equal((await committeeState(dest)).generation, GENERATION);
        const receipt = ok(ctx, await submit(ctx, certificates.slice(0, 16), at));
        const expected = rotations.slice(0, 16).flatMap(({ block, certificate, untilMs }) => [
          published(certificate),
          stored(block),
          rotated(block, untilMs),
        ]);
        assertLogs(ctx, receipt, expected, "16 rotations");
        const sixteenth = rotations[15];
        assert.deepEqual(await committeeState(dest), {
          root: sixteenth.block.header.nextCommitteeRoot,
          untilMs: sixteenth.untilMs,
          start: sixteenth.block.height + 1n,
          high: sixteenth.block.height,
          generation: GENERATION + 16n,
        });
        assert.equal(sixteenth.untilMs, ms(now) + VALIDITY_MS - 15n * 3_600_000n, "the last handoff is future-dated");
        for (const { block } of rotations.slice(0, 16)) {
          assert.equal(await dest.view("checkpointHeader", [block.height]), m.checkpointId(block.x));
        }
        assert.equal(await dest.view("opCount"), 0n);
        refused(
          ctx,
          await submit(ctx, [certificates[15]], at),
          "CommitteeNotAccepted",
          [],
          "the installing handoff again",
        );
        ok(ctx, await submit(ctx, [certificates[16]], at), "the seventeenth, alone");
        assert.equal((await committeeState(dest)).generation, GENERATION + 17n);
      });

      scenario(run, "checkpoint use after rotations: U1, U2, a return to earlier keys (§5.1.3)", {}, async (ctx) => {
        const { taira, dest, signedBy } = ctx;
        const kPrime = committeeOf(4, 1);
        const item = (nonce) => transferOf(ctx, { nonce });
        const notAccepted = async (outcome, where) => refused(ctx, await outcome, "CommitteeNotAccepted", [], where);
        // Generation 7 (K): a block with messages, and a genuine block that nobody submits in time.
        const [tA, tA2, tA3] = [item(1), item(7), item(13)];
        const cA = controlOf(ctx, controlFields(1));
        const a = taira.block(1010n, ms(T0 + 10n), [tA, cA, tA2, tA3]);
        const certificateA = taira.certify(a);
        const unsubmitted = taira.certify(taira.block(1015n, ms(T0 + 15n), [item(8)]));
        const tR1 = item(2);
        const r1 = taira.block(1020n, ms(T0 + 20n), [tR1], { rotate: "key", nextCommittee: kPrime });
        // Generation 8 (K′), then a heartbeat to generation 9 with the same keys.
        const [tB, tB2] = [item(3), item(9)];
        const b = taira.block(1030n, ms(T0 + 30n), [tB, tB2]);
        const certificateB = taira.certify(b);
        const tR2 = item(4);
        const r2 = taira.block(1040n, ms(T0 + 40n), [tR2], { rotate: "heartbeat" });
        const tC = item(5);
        const c = taira.block(1050n, ms(T0 + 50n), [tC]);
        // Generation 9 also signs a handoff to K at height 1055 that Taira never made.
        const forger = forgerOf(ctx);
        const [tF, tF2] = [item(10), item(12)];
        const forged = forger.block(1055n, ms(T0 + 55n), [tF, tF2], { rotate: "key", nextCommittee: signedBy });
        // The genuine handoff back to K, and generation 10.
        const r3 = taira.block(1060n, ms(T0 + 60n), [item(6)], { rotate: "key", nextCommittee: signedBy });
        const tD = item(11);
        const d = taira.block(1070n, ms(T0 + 70n), [tD]);
        const proof = (leaf, block, certified = block) => proofOf(taira, leaf, block, certified);
        const state = async () => {
          const { root, generation, start } = await committeeState(dest);
          return { root, generation, start };
        };

        ok(ctx, await submit(ctx, [certificateA], { at: T0 + 100n }));
        ok(ctx, await submit(ctx, [taira.certify(r1)]));
        assert.deepEqual(await state(), { root: kPrime.root, generation: 8n, start: 1021n });
        // A checkpoint of the retired generation is not usable, stored or presented again.
        await notAccepted(finalizeStored(ctx, a.x, proof(tA, a)), "generation 7 under generation 8");
        await notAccepted(controlStored(ctx, a.x, proof(cA, a)), "a control of generation 7");
        await notAccepted(finalizeInline(ctx, certificateA, proof(tA, a)), "the certificate of generation 7, inline");
        await notAccepted(submit(ctx, [unsubmitted]), "a genuine certificate of generation 7");
        // U2: the handoff that installed the current generation proves its own block and, through
        // the history, the messages and controls of the retired generation.
        assertLogs(
          ctx,
          ok(ctx, await finalizeStored(ctx, r1.x, proof(tR1, r1))),
          minted(tR1),
          "U2, the handoff's block",
        );
        assertLogs(ctx, ok(ctx, await finalizeStored(ctx, r1.x, proof(tA, a, r1))), minted(tA), "U2, an older block");
        assertLogs(
          ctx,
          ok(ctx, await controlStored(ctx, r1.x, proof(cA, a, r1))),
          [applied(cA.control)],
          "U2, an older control",
        );
        // U1: a checkpoint of the current generation.
        ok(ctx, await submit(ctx, [certificateB]));
        assertLogs(ctx, ok(ctx, await finalizeStored(ctx, b.x, proof(tB, b))), minted(tB), "U1");

        // A heartbeat keeps the root and moves the generation: both must match.
        ok(ctx, await submit(ctx, [taira.certify(r2)]));
        assert.deepEqual(await state(), { root: kPrime.root, generation: 9n, start: 1041n });
        await notAccepted(finalizeStored(ctx, b.x, proof(tB2, b)), "the same root, an older generation");
        await notAccepted(
          finalizeInline(ctx, certificateB, proof(tB2, b)),
          "the same keys, an older generation, inline",
        );
        await notAccepted(finalizeStored(ctx, r1.x, proof(tA2, a, r1)), "the handoff before the last one");
        assertLogs(ctx, ok(ctx, await finalizeStored(ctx, r2.x, proof(tR2, r2))), minted(tR2), "U2 after a heartbeat");
        assertLogs(
          ctx,
          ok(ctx, await finalizeStored(ctx, r2.x, proof(tB2, b, r2))),
          minted(tB2),
          "U2, generation 8 under the heartbeat",
        );

        // The forged handoff used inline: it is stored and it proves, but installs nothing.
        const forgedCertificate = forger.certify(forged);
        const receipt = ok(ctx, await finalizeInline(ctx, forgedCertificate, proofOf(forger, tF, forged)));
        assertLogs(ctx, receipt, [published(forgedCertificate), stored(forged), ...minted(tF)], "a handoff, inline");
        assert.deepEqual(await state(), { root: kPrime.root, generation: 9n, start: 1041n });
        ok(ctx, await submit(ctx, [taira.certify(c)]), "a checkpoint below high");
        // The return to K as generation 10.
        ok(ctx, await submit(ctx, [taira.certify(r3)]));
        assert.deepEqual(await state(), { root: signedBy.root, generation: 10n, start: 1061n });
        // K is current again, but generation 7 is not: its checkpoints and certificates stay refused,
        // and none of them latches.
        await notAccepted(
          finalizeStored(ctx, a.x, proof(tA2, a)),
          "generation 7 under generation 10 with the same keys",
        );
        await notAccepted(
          finalizeInline(ctx, certificateA, proof(tA2, a)),
          "the certificate of generation 7 after the return",
        );
        await notAccepted(submit(ctx, [unsubmitted]), "a genuine certificate of generation 7 after the return");
        await notAccepted(submit(ctx, [taira.certify(r1)]), "the first handoff again");
        await notAccepted(
          finalizeStored(ctx, r2.x, proof(tA2, a, r2)),
          "the heartbeat handoff after the next rotation",
        );
        // U2 needs the handoff that installed cur: the forged one names the same root and the
        // preceding generation, but another start height.
        await notAccepted(
          finalizeStored(ctx, forged.x, proofOf(forger, tF2, forged)),
          "a stored handoff that did not install cur",
        );
        assert.equal(await dest.view("equivocated"), false);
        assertLogs(
          ctx,
          ok(ctx, await finalizeStored(ctx, r3.x, proof(tA2, a, r3))),
          minted(tA2),
          "generation 7 under the last handoff",
        );
        ok(ctx, await submit(ctx, [taira.certify(d)]));
        assertLogs(
          ctx,
          ok(ctx, await finalizeStored(ctx, d.x, proof(tC, c, d))),
          minted(tC),
          "generation 9 under generation 10",
        );
        assertLogs(
          ctx,
          ok(ctx, await finalizeStored(ctx, d.x, proof(tA3, a, d))),
          minted(tA3),
          "generation 7 under generation 10",
        );
        assertLogs(ctx, ok(ctx, await finalizeStored(ctx, d.x, proof(tD, d))), minted(tD), "generation 10");
        assert.equal(await dest.view("opCount"), 11n, "ten mints and one control");
      });

      // -- arithmetic -----------------------------------------------------------------

      plain(run, "arithmetic: clock, rotation deadline and fast-pause bound saturate at 2^64 − 1", async (run0) => {
        // Deployed twenty-three days before the last second whose milliseconds fit u64.
        const S = LAST_UNSATURATED_SECOND - 2_000_000n;
        const ctx = await open(run0, { at: S });
        try {
          const { taira, chain, dest } = ctx;
          const max = m.MAX_VALIDITY_MS;
          assert(ms(S) + max > U64_MAX, "now_ms + MAX_VALIDITY_MS is above u64");
          // A rotation whose t_eff + validity is above 2^64 − 1: the deadline saturates.
          const first = taira.block(1010n, ms(S), [], { rotate: "heartbeat", validityMs: max });
          let certificate = taira.certify(first);
          let receipt = ok(ctx, await submit(ctx, [certificate], { at: S + 10n }));
          assertLogs(
            ctx,
            receipt,
            [published(certificate), stored(first), rotated(first, U64_MAX)],
            "a saturated deadline",
          );
          assert.equal((await committeeState(dest)).untilMs, U64_MAX);
          // Generation 8: a control and transfers whose times are the largest u64 values.
          const pause = controlOf(ctx, controlFields(1, 2, false, U64_MAX));
          const atMax = [1n, 2n].map((nonce) => transferOf(ctx, { nonce, deadlineMs: U64_MAX }));
          const belowMax = [3n, 4n].map((nonce) => transferOf(ctx, { nonce, deadlineMs: U64_MAX - 1n }));
          const b = taira.block(1011n, ms(S + 11n), [pause, ...atMax, ...belowMax]);
          ok(ctx, await submit(ctx, [taira.certify(b)], { at: S + 20n }));
          // now_ms + MAX_FAST_PAUSE_MS is above u64: the bound is 2^64 − 1 and the leaf value stays.
          assertLogs(
            ctx,
            ok(ctx, await controlStored(ctx, b.x, proofOf(taira, pause, b), { at: S + 30n })),
            [applied(pause.control)],
            "an expiry of 2^64 − 1",
          );
          assert.deepEqual(
            await pauseState(dest),
            { parliamentPaused: false, fastPauseUntilMs: U64_MAX, controlNonce: 1n, effective: true },
          );
          refused(ctx, await finalizeStored(ctx, b.x, proofOf(taira, atMax[0], b)), "MintingIsPaused");
          // A handoff dated 2^64 − 1: t_eff is the destination's clock, and the sum is never formed with X.timestamp.
          await onSnapshot(ctx, async () => {
            const short = forgerOf(ctx).block(1020n, U64_MAX, [], { rotate: "heartbeat", validityMs: 1000n });
            const signed = taira.certify(short);
            const installed = ok(ctx, await submit(ctx, [signed], { at: S + 40n }));
            assertLogs(
              ctx,
              installed,
              [published(signed), stored(short), rotated(short, ms(S + 41n))],
              "t_eff = now_ms",
            );
          });
          // The last second that fits: now_ms = block.timestamp × 1000 still, and saturated one second later.
          for (const [timestamp, untilMs] of [
            [LAST_UNSATURATED_SECOND, ms(LAST_UNSATURATED_SECOND) + 1n],
            [LAST_UNSATURATED_SECOND + 1n, U64_MAX],
          ]) {
            await onSnapshot(ctx, async () => {
              const short = forgerOf(ctx).block(1020n, U64_MAX, [], { rotate: "heartbeat", validityMs: 1n });
              const signed = taira.certify(short);
              const installed = ok(ctx, await submit(ctx, [signed], { at: timestamp }));
              const where = `now_ms at block.timestamp ${timestamp}`;
              assertLogs(ctx, installed, [published(signed), stored(short), rotated(short, untilMs)], where);
            });
          }
          const second = taira.block(1020n, U64_MAX, [], { rotate: "heartbeat", validityMs: max });
          certificate = taira.certify(second);
          receipt = ok(ctx, await submit(ctx, [certificate], { at: S + 40n }));
          assertLogs(
            ctx,
            receipt,
            [published(certificate), stored(second), rotated(second, U64_MAX)],
            "a future-dated handoff",
          );
          const underHandoff = (item) => proofOf(taira, item, b, second);

          // The clock saturates: block.timestamp × 1000 no longer fits u64.
          for (const timestamp of [LAST_UNSATURATED_SECOND + 1n, 1n << 62n]) {
            await chain.mine(timestamp);
            const where = `block.timestamp ${timestamp}`;
            assert.deepEqual(
              await pauseState(dest),
              { parliamentPaused: false, fastPauseUntilMs: U64_MAX, controlNonce: 1n, effective: false },
              where,
            );
            assert.equal(await dest.view("mintingPaused"), false, `${where}: now_ms = fastPauseUntilMs is not paused`);
            refused(ctx, await voidFrozen(ctx, 100n, 1n), "NotFrozen", [], `${where}: now_ms = untilMs is Live`);
            const [mintable, voidable] = timestamp === 1n << 62n ? [atMax[1], belowMax[1]] : [atMax[0], belowMax[0]];
            refused(
              ctx,
              await voidStored(ctx, mintable.nonce, second.x, underHandoff(mintable)),
              "DeadlineNotReached",
              [],
              where,
            );
            refused(ctx, await finalizeStored(ctx, second.x, underHandoff(voidable)), "DeadlinePassed", [], where);
            assertLogs(
              ctx,
              ok(ctx, await finalizeStored(ctx, second.x, underHandoff(mintable))),
              minted(mintable),
              `${where}: a mint`,
            );
            assertLogs(
              ctx,
              ok(ctx, await voidStored(ctx, voidable.nonce, second.x, underHandoff(voidable))),
              [voided(voidable)],
              `${where}: a void`,
            );
          }
          // On the saturated clock: a control whose bound would be 2^64 − 1 + MAX, a rotation whose
          // sum is exactly 2^64, and a deployment, which no untilMs can satisfy.
          const lapsed = controlOf(ctx, controlFields(2, 2, false, 123n));
          const c = taira.block(1030n, U64_MAX, [lapsed]);
          certificate = taira.certify(c);
          receipt = ok(ctx, await controlInline(ctx, certificate, proofOf(taira, lapsed, c)));
          assertLogs(
            ctx,
            receipt,
            [published(certificate), stored(c), applied(lapsed.control)],
            "a control on the saturated clock",
          );
          const third = taira.block(1040n, U64_MAX, [], { rotate: "heartbeat", validityMs: 1n });
          certificate = taira.certify(third);
          receipt = ok(ctx, await submit(ctx, [certificate]));
          assertLogs(
            ctx,
            receipt,
            [published(certificate), stored(third), rotated(third, U64_MAX)],
            "2^64 − 1 + 1 saturates",
          );
          const redeployed = { ...ctx.deployment, initialGeneration: 99n, initialUntilMs: U64_MAX };
          refused(
            ctx,
            await h.createDirectly(chain, redeployed),
            "BadConfig",
            [],
            "a deployment on the saturated clock",
          );
          // A successor whose deadline is in the past ends Live, also from the saturated clock.
          const fourth = taira.block(1050n, 5n, [], { rotate: "heartbeat", validityMs: 1n });
          certificate = taira.certify(fourth);
          receipt = ok(ctx, await submit(ctx, [certificate]));
          assertLogs(
            ctx,
            receipt,
            [published(certificate), stored(fourth), rotated(fourth, 6n)],
            "t_eff = X.timestamp",
          );
          assertLogs(ctx, ok(ctx, await voidFrozen(ctx, 100n, 1n)), [log("SccpVoided", ZERO32, 100n)], "frozen");
          assert.equal(await dest.view("opCount"), 7n);
        } finally {
          await ctx.chain.close();
        }
      });

      scenario(run, "arithmetic: a handoff at height and generation 2^64 − 2 (X6, U2)", NEAR_THE_TOP, async (ctx) => {
        const { taira, dest, signedBy } = ctx;
        const [underHandoff, underTop] = [1n, 2n].map((nonce) => transferOf(ctx, { nonce }));
        const handoff = taira.block(U64_MAX - 1n, ms(T0 + 10n), [underHandoff], { rotate: "heartbeat" });
        let certificate = taira.certify(handoff);
        const untilMs = ms(T0 + 10n) + VALIDITY_MS;
        let receipt = ok(ctx, await submit(ctx, [certificate], { at: T0 + 100n }));
        assertLogs(
          ctx,
          receipt,
          [published(certificate), stored(handoff), rotated(handoff, untilMs)],
          "the last handoff X6 admits",
        );
        assert.deepEqual(
          await committeeState(dest),
          { root: signedBy.root, untilMs, start: U64_MAX, high: U64_MAX - 1n, generation: U64_MAX },
        );
        // U2 at the top: generation + 1 and height + 1 are compared without wrapping.
        receipt = ok(ctx, await finalizeStored(ctx, handoff.x, proofOf(taira, underHandoff, handoff)));
        assertLogs(ctx, receipt, minted(underHandoff), "U2 at the top");
        // Generation 2^64 − 1 certifies height 2^64 − 1, and can never hand off.
        const top = taira.block(U64_MAX, ms(T0 + 20n), [underTop]);
        certificate = taira.certify(top);
        receipt = ok(ctx, await finalizeInline(ctx, certificate, proofOf(taira, underTop, top)));
        assertLogs(ctx, receipt, [published(certificate), stored(top), ...minted(underTop)], "height 2^64 − 1");
        assert.equal((await committeeState(dest)).high, U64_MAX);
        assert.equal(await dest.view("checkpointHeader", [U64_MAX]), m.checkpointId(top.x));
        const rotation = {
          flags: m.FLAG_ACTIVE | m.FLAG_ROTATION,
          validityMs: 1000n,
          nextCommitteeRoot: signedBy.root,
          timestampMs: ms(T0 + 30n),
        };
        // X6 is judged when X is parsed, before the generation is compared with the current one.
        for (const [where, fields] of [
          ["height and generation 2^64 − 1", { height: U64_MAX }],
          ["generation 2^64 − 1", { height: U64_MAX - 1n }],
          ["height 2^64 − 1", { height: U64_MAX, generation: 5n }],
        ]) {
          const refusedHandoff = headerBlock(taira, { ...rotation, ...fields });
          refused(ctx, await submit(ctx, [taira.certify(refusedHandoff)]), "BadHeader", [], `a handoff at ${where}`);
        }
      });

      // -- the token ----------------------------------------------------------------

      scenario(run, "ERC-20 surface with ERC-6093 errors", {}, async (ctx) => {
        const { taira, chain, dest } = ctx;
        const [holder, receiver, spender] = [5, 6, 7].map((index) => ethers.getAddress(chain.accounts[index]));
        const funded = transferOf(ctx, { nonce: 1, amount: 10n * UNIT, recipient: holder });
        const block = taira.block(1010n, ms(T0 + 10n), [funded]);
        ok(ctx, await finalizeInline(ctx, taira.certify(block), proofOf(taira, funded, block), { at: T0 + 100n }));
        const balance = (account) => dest.view("balanceOf", [account]);
        const send = (name, args, from) => call(ctx, name, args, { from });

        assert.equal(await dest.simulate("transfer", [receiver, 3n * UNIT], 5), true);
        assertLogs(
          ctx,
          ok(ctx, await send("transfer", [receiver, 3n * UNIT], 5)),
          [log("Transfer", holder, receiver, 3n * UNIT)],
          "transfer",
        );
        assert.deepEqual([await balance(holder), await balance(receiver)], [7n * UNIT, 3n * UNIT]);
        assertLogs(
          ctx,
          ok(ctx, await send("transfer", [receiver, 0n], 5)),
          [log("Transfer", holder, receiver, 0n)],
          "a transfer of 0",
        );
        assertLogs(
          ctx,
          ok(ctx, await send("transfer", [holder, UNIT], 5)),
          [log("Transfer", holder, holder, UNIT)],
          "a transfer to oneself",
        );
        assert.equal(await balance(holder), 7n * UNIT);
        refused(ctx, await send("transfer", [ZERO_ADDRESS, 1n], 5), "ERC20InvalidReceiver", [ZERO_ADDRESS]);
        refused(
          ctx,
          await send("transfer", [dest.address, 1n], 5),
          "ERC20InvalidReceiver",
          [dest.address],
          "the token itself",
        );
        refused(
          ctx,
          await send("transfer", [receiver, 7n * UNIT + 1n], 5),
          "ERC20InsufficientBalance",
          [holder, 7n * UNIT, 7n * UNIT + 1n],
        );
        refused(
          ctx,
          await send("transfer", [receiver, 1n], 7),
          "ERC20InsufficientBalance",
          [spender, 0n, 1n],
          "an empty account",
        );

        refused(ctx, await send("approve", [ZERO_ADDRESS, 1n], 5), "ERC20InvalidSpender", [ZERO_ADDRESS]);
        assert.equal(await dest.simulate("approve", [spender, 2n * UNIT], 5), true);
        assertLogs(
          ctx,
          ok(ctx, await send("approve", [spender, 2n * UNIT], 5)),
          [log("Approval", holder, spender, 2n * UNIT)],
          "approve",
        );
        assert.equal(await dest.view("allowance", [holder, spender]), 2n * UNIT);
        assert.equal(await dest.simulate("transferFrom", [holder, receiver, UNIT], 7), true);
        assertLogs(
          ctx,
          ok(ctx, await send("transferFrom", [holder, receiver, UNIT], 7)),
          [log("Transfer", holder, receiver, UNIT)],
          "transferFrom",
        );
        assert.equal(await dest.view("allowance", [holder, spender]), UNIT, "the allowance is spent");
        refused(
          ctx,
          await send("transferFrom", [holder, receiver, UNIT + 1n], 7),
          "ERC20InsufficientAllowance",
          [spender, UNIT, UNIT + 1n],
        );
        // The allowance is judged before the balance and the receiver.
        refused(
          ctx,
          await send("transferFrom", [holder, ZERO_ADDRESS, 100n * UNIT], 7),
          "ERC20InsufficientAllowance",
          [spender, UNIT, 100n * UNIT],
          "above both",
        );
        refused(
          ctx,
          await send("transferFrom", [holder, ZERO_ADDRESS, 1n], 7),
          "ERC20InvalidReceiver",
          [ZERO_ADDRESS],
          "transferFrom",
        );
        refused(
          ctx,
          await send("transferFrom", [holder, dest.address, 1n], 7),
          "ERC20InvalidReceiver",
          [dest.address],
          "transferFrom to the token",
        );
        refused(
          ctx,
          await send("transferFrom", [receiver, holder, 1n], 7),
          "ERC20InsufficientAllowance",
          [spender, 0n, 1n],
          "no allowance",
        );
        // Nobody can approve for the zero address, so only a transfer of 0 reaches the sender check.
        refused(ctx, await send("transferFrom", [ZERO_ADDRESS, receiver, 0n], 7), "ERC20InvalidSender", [ZERO_ADDRESS]);
        // An unlimited allowance is not decremented; a finite one above the balance fails on the balance.
        ok(ctx, await send("approve", [spender, U256_MAX], 5));
        ok(ctx, await send("transferFrom", [holder, receiver, UNIT], 7));
        assert.equal(await dest.view("allowance", [holder, spender]), U256_MAX);
        const held = await balance(holder);
        refused(
          ctx,
          await send("transferFrom", [holder, receiver, held + 1n], 7),
          "ERC20InsufficientBalance",
          [holder, held, held + 1n],
        );
        ok(ctx, await send("approve", [spender, 0n], 5), "an allowance of 0");
        refused(
          ctx,
          await send("transferFrom", [holder, receiver, 1n], 7),
          "ERC20InsufficientAllowance",
          [spender, 0n, 1n],
          "revoked",
        );
        // An address word above 160 bits is refused by the ABI decoder.
        const dirty = patch(
          m.iface.encodeFunctionData("transfer", [receiver, 1n]),
          4,
          m.word((1n << 160n) | BigInt(receiver)),
        );
        refused(ctx, await dest.attempt(dirty, { from: 5 }), null, [], "an address word above 160 bits");
        assert.equal(await dest.view("totalSupply"), 10n * UNIT, "transfers keep the supply");
        assert.equal((await balance(holder)) + (await balance(receiver)), 10n * UNIT);
        assert.equal(await dest.view("opCount"), 1n, "token transfers and approvals are no SCCP operations");
      });

      // -- the ABI decoder, memory and gas ---------------------------------------------

      scenario(run, "typed calldata words above their width: the ABI decoder (§3.4, §5.2.2)", {}, async (ctx) => {
        const { taira, dest } = ctx;
        const item = transferOf(ctx, { nonce: 1, deadlineMs: ms(T0 + 50n) });
        const fields = controlFields(1, 2, true, ms(T0 + HOUR));
        const controlItem = controlOf(ctx, fields);
        const mintable = transferOf(ctx, { nonce: 2 });
        const block = taira.block(1010n, ms(T0 + 10n), [item, controlItem, mintable]);
        const certificate = r.certificateArg(taira.certify(block));
        ok(ctx, await submit(ctx, [taira.certify(block)], { at: T0 + 100n }));
        const control = r.controlProofArg(proofOf(taira, controlItem, block));
        const encode = (name, args) => m.iface.encodeFunctionData(name, args);
        const finalize = encode(
          "finalizeFromCheckpoint",
          [[block.x], r.messageProofArg(proofOf(taira, mintable, block))],
        );
        const cancel = encode(
          "voidExpiredFromCheckpoint",
          [1n, [block.x], r.messageProofArg(proofOf(taira, item, block))],
        );
        const apply = encode("applyControlFromCheckpoint", [[block.x], control]);
        const inline = encode("applyControl", [certificate, control]);
        // [calldata, path of the tuple, head word, the value the word holds, a value above its width]
        const rows = [
          ["MessageProofV1.leafIndex", finalize, [1], 1, 2n, (1n << 32n) | 2n],
          ["BlockRefV1.height", finalize, [1, 3], 0, 1010n, (1n << 64n) | 1010n],
          ["BlockRefV1.messageCount", finalize, [1, 3], 2, 3n, (1n << 32n) | 3n],
          ["BlockRefV1.historyIndex", finalize, [1, 3], 3, 0n, 1n << 64n],
          ["the nonce of voidExpiredFromCheckpoint", cancel, [], 0, 1n, (1n << 64n) | 1n],
          ["ControlProofV1.controlNonce", apply, [1], 0, 1n, (1n << 64n) | 1n],
          ["ControlProofV1.track", apply, [1], 1, 2n, (1n << 8n) | 2n],
          ["ControlProofV1.parliamentPaused", apply, [1], 2, 1n, 2n],
          ["ControlProofV1.parliamentPaused, all bits", apply, [1], 2, 1n, U256_MAX],
          [
            "ControlProofV1.fastPauseUntilMs",
            apply,
            [1],
            3,
            fields.fastPauseUntilMs,
            (1n << 64n) | fields.fastPauseUntilMs,
          ],
          ["ControlProofV1.leafIndex", apply, [1], 6, 1n, (1n << 32n) | 1n],
          ["BlockRefV1.height of a control", apply, [1, 8], 0, 1010n, (1n << 64n) | 1010n],
          ["ControlProofV1.parliamentPaused, inline", inline, [1], 2, 1n, 2n],
          ["ControlProofV1.track, inline", inline, [1], 1, 2n, (1n << 8n) | 2n],
        ];
        for (const [where, calldata, path, index, held, value] of rows) {
          assert.equal(wordAt(calldata, path, index), held, `${where}: the word is the field`);
          refused(ctx, await dest.attempt(withWord(calldata, path, index, value)), null, [], where);
        }
        // The flag of a control is read before anything else: no other fault answers first.
        const empty = ["0x", "0x", "0x", "0x", "0x"];
        const faulty = withWord(encode("applyControl", [empty, control]), [1], 2, 2n);
        refused(ctx, await dest.attempt(faulty), null, [], "a dirty flag with a malformed certificate");
        refused(
          ctx,
          await dest.attempt(encode("applyControl", [empty, control])),
          "BadCertificate",
          [],
          "a clean flag with it",
        );
        // Offsets and lengths that leave the calldata.
        refused(
          ctx,
          await dest.attempt(patch(finalize, 4 + 32, m.word(0x10000))),
          null,
          [],
          "a proof offset past the calldata",
        );
        const payloadAt = tupleStart(finalize, [1, 0]);
        refused(
          ctx,
          await dest.attempt(patch(finalize, payloadAt, m.word(0x10000))),
          null,
          [],
          "a payload length past the calldata",
        );
        refused(
          ctx,
          await dest.attempt(ethers.dataSlice(finalize, 0, ethers.dataLength(finalize) - 33)),
          null,
          [],
          "truncated calldata",
        );
        assert.equal(await dest.view("opCount"), 0n);
        // The unchanged calldata is valid: every refusal above was the changed word.
        assertLogs(ctx, ok(ctx, await dest.attempt(cancel)), [voided(item)], "the unchanged void");
        assertLogs(ctx, ok(ctx, await dest.attempt(apply)), [applied(fields)], "the unchanged control");
        refused(ctx, await dest.attempt(finalize), "MintingIsPaused", [], "the unchanged mint, now paused");
      });

      plain(run, "dirty memory: n = 4, 7, 31 and a batch of 16, same outcomes as fresh memory", async (ctx) => {
        for (const n of [4, 7, 31]) {
          const script = dirtyScript(profile, n);
          const transcript = async (target) => {
            const live = await open(ctx, { signedBy: script.signedBy, relocateTo: SHARED_ADDRESS, target });
            try {
              const entries = [];
              for (const [index, step] of script.steps.entries()) {
                const where = `n = ${n}, ${target.name}, step ${index} (${step.name})`;
                const outcome = await live.dest.attempt(target.encode(step.name, step.args), { at: step.at });
                const entry = {};
                if (step.expected === "ok") {
                  const receipt = ok(live, outcome, where);
                  entry.logs = live.dest.logs(receipt);
                  entry.returnData = await live.chain.returnData(receipt);
                } else {
                  refused(live, outcome, step.expected, [], where);
                  entry.revert = outcome.revert;
                }
                entry.state = await live.dest.state({ heights: script.heights, nonces: script.nonces });
                entry.balance = (await live.dest.view("balanceOf", [FIXED_RECIPIENT])).toString();
                entries.push(entry);
              }
              return entries;
            } finally {
              await live.chain.close();
            }
          };
          const fresh = await transcript(r.PRODUCTION);
          const certificateTopic = m.iface.getEvent("SccpCertificate").topicHash;
          const logs = fresh.flatMap((entry) => entry.logs ?? []);
          const publications = logs.filter((entry) => entry.topics[0] === certificateTopic);
          assert.equal(publications.length, 23, `n = ${n}: full-path verifications of the script`);
          assert.equal(fresh.at(-1).state.equivocated, true, `n = ${n}: the script ends latched`);
          assert.equal(fresh.at(-1).state.committee.generation, Number(GENERATION) + 1, `n = ${n}: after one rotation`);
          for (const [words, fill] of r.DIRTY_FILLS) {
            const target = r.dirtyTarget(words, fill);
            assert.deepEqual(await transcript(target), fresh, `n = ${n}: ${target.name}`);
          }
          // The harness build itself, entered through the production entry points.
          assert.deepEqual(await transcript(r.inheritedTarget()), fresh, `n = ${n}: the harness build on fresh memory`);
        }
      });

      scenario(run, "a certificate with too little gas fails whole and changes nothing", {}, async (ctx, t) => {
        const { taira, chain, dest } = ctx;
        const block = taira.block(1010n, ms(T0 + 10n), []);
        const certificate = taira.certify(block);
        const data = m.iface.encodeFunctionData("submitCheckpoints", [[r.certificateArg(certificate)]]);
        const probes = { heights: [1010n] };
        const before = await dest.state(probes);
        // One transaction with a gas limit: its receipt, its revert data, or "out of gas".
        const send = async (gas) => {
          const timestamp = await chain.setNextTimestamp();
          try {
            const transaction = { from: chain.accounts[0], to: dest.address, data, gas: ethers.toQuantity(gas) };
            const hash = await chain.rpc("eth_sendTransaction", [transaction]);
            return { receipt: await chain.rpc("eth_getTransactionReceipt", [hash]) };
          } catch (error) {
            if ((await chain.latest()).timestamp !== timestamp) await chain.rpc("evm_mine");
            const revert = h.revertData(error);
            if (revert !== null) return { revert };
            assert(Object.hasOwn(error.data?.reason ?? {}, "OutOfGas"), `gas ${gas}: ${error.message}`);
            return { outOfGas: true };
          }
        };
        const kinds = new Map();
        let enough = null;
        for (let gas = 60_000n; gas <= 300_000n && enough === null; gas += 2_500n) {
          const outcome = await send(gas);
          if (outcome.receipt) {
            assert.equal(outcome.receipt.status, "0x1");
            assertLogs(ctx, outcome.receipt, [published(certificate), stored(block)], `gas ${gas}`);
            enough = gas;
            break;
          }
          const kind = outcome.outOfGas ? "out of gas" : h.decodeRevert(outcome.revert).name ?? EMPTY_REVERT;
          kinds.set(kind, [...(kinds.get(kind) ?? []), gas]);
          assert.deepEqual({ ...(await dest.state(probes)), live: before.live }, before, `gas ${gas}: nothing changed`);
        }
        assert(enough !== null, "the certificate verifies below 300 000 gas");
        // A precompile that runs out of gas burns what was forwarded to it. What is left decides the
        // outcome: none (out of gas), a revert with empty data from hash-to-G2, or the error of the
        // step whose precompile was starved. None of them is a verdict on the certificate.
        const allowed = ["out of gas", EMPTY_REVERT, "BadCommittee", "BadSignature"];
        assert.deepEqual([...kinds.keys()].filter((kind) => !allowed.includes(kind)), []);
        assert(kinds.has("out of gas") && kinds.has(EMPTY_REVERT), "the sweep reaches a starved hash-to-G2");
        recordRefusal(ctx, EMPTY_REVERT);
        for (const [kind, limits] of kinds) t.diagnostic(`${kind}: gas limits ${limits.at(0)}..${limits.at(-1)}`);
        t.diagnostic(`first sufficient gas limit of the sweep: ${enough}`);
      });

      scenario(run, "counter limits that no call sequence reaches, by storage injection", {}, async (ctx) => {
        const { taira, chain, dest } = ctx;
        const [sender, second] = [5, 6].map((index) => ethers.getAddress(chain.accounts[index]));
        const funding = [sender, second].map((recipient, nonce) =>
          transferOf(ctx, { nonce, amount: 5n * UNIT, recipient }));
        const block = taira.block(1010n, ms(T0 + 10n), funding);
        ok(ctx, await submit(ctx, [taira.certify(block)], { at: T0 + 100n }));
        for (const item of funding) ok(ctx, await finalizeStored(ctx, block.x, proofOf(taira, item, block)));
        // Both states take 2^64 operations. The test pins what the bytecode does there.
        const nonceSlot = mappingSlot("address", sender, 5);
        const sourceNonce = (receipt) => abi.decode(["uint64", "bytes"], dest.logs(receipt)[1].data)[0];
        // §5.1.7: source nonces are 0 ..= 2^64 − 2. The last one is used like any other.
        await setStorageAt(dest, nonceSlot, U64_MAX - 1n);
        refused(ctx, await burn(ctx, 5, UNIT, U64_MAX), "BadNonce", [U64_MAX - 1n], "one nonce early");
        const last = ok(ctx, await burn(ctx, 5, UNIT, U64_MAX - 1n), "the burn with nonce 2^64 − 2");
        assert.equal(sourceNonce(last), U64_MAX - 1n);
        assert.equal(await dest.view("transferNonces", [sender]), U64_MAX);
        // A stored next nonce of 2^64 − 1 is exhausted: every burn of the sender answers
        // BadNonce(2^64 − 1), whatever nonce it expects, and changes nothing. The nonce is never
        // used and the counter never wraps.
        const exhausted = {
          slot: await storageAt(dest, nonceSlot),
          slotC: await storageAt(dest, 2),
          balance: await dest.view("balanceOf", [sender]),
          supply: await dest.view("totalSupply"),
        };
        assert.deepEqual(
          [exhausted.slot, exhausted.balance, (exhausted.slotC >> 64n) & U64_MAX],
          [U64_MAX, 4n * UNIT, 3n],
          "the stored nonce, the balance after one burn, and two mints and one burn counted",
        );
        for (const expected of [U64_MAX, 0n, 1n, U64_MAX - 1n]) {
          refused(ctx, await burn(ctx, 5, UNIT, expected), "BadNonce", [U64_MAX], `exhausted, expecting ${expected}`);
        }
        // The checks that precede the nonce keep their own errors.
        refused(ctx, await burn(ctx, 5, 0n, U64_MAX), "BadAmount", [], "exhausted, amount 0");
        assert.deepEqual(
          {
            slot: await storageAt(dest, nonceSlot),
            slotC: await storageAt(dest, 2),
            balance: await dest.view("balanceOf", [sender]),
            supply: await dest.view("totalSupply"),
          },
          exhausted,
          "a refused burn of an exhausted sender changes nothing",
        );
        // The exhaustion is the sender's own: another sender burns with its own nonces.
        assert.equal(sourceNonce(ok(ctx, await burn(ctx, 6, UNIT, 0n), "another sender")), 0n);
        assert.equal(await dest.view("transferNonces", [second]), 1n);

        // §5.1.1: opCount saturates at 2^64 − 1. A counted operation at 2^64 − 2 reaches the
        // bound, and every later one succeeds and leaves it there.
        const slotC = await storageAt(dest, 2);
        assert.equal((slotC >> 64n) & U64_MAX, 4n, "two mints and two burns");
        const withOpCount = (count) => (slotC & ~(U64_MAX << 64n)) | (count << 64n);
        await setStorageAt(dest, 2, withOpCount(U64_MAX - 1n));
        assert.equal(await dest.view("opCount"), U64_MAX - 1n);
        assert.equal(sourceNonce(ok(ctx, await burn(ctx, 6, UNIT, 1n), "the burn that reaches the bound")), 1n);
        assert.equal(await dest.view("opCount"), U64_MAX);
        // A burn, a mint, a control and a void at the bound: each takes effect, none moves the count.
        const fields = controlFields(1n);
        const more = [
          controlOf(ctx, fields),
          transferOf(ctx, { nonce: 2, recipient: second }),
          transferOf(ctx, { nonce: 3, deadlineMs: ms(T0 + 150n) }),
        ];
        const later = taira.block(1020n, ms(T0 + 20n), more);
        ok(ctx, await submit(ctx, [taira.certify(later)], { at: T0 + 200n }));
        assert.equal(sourceNonce(ok(ctx, await burn(ctx, 6, UNIT, 2n), "a burn at the bound")), 2n);
        const [control, mint, expired] = more.map((item) => proofOf(taira, item, later));
        let receipt = ok(ctx, await finalizeStored(ctx, later.x, mint));
        assertLogs(ctx, receipt, minted(more[1]), "a mint at the bound");
        receipt = ok(ctx, await controlStored(ctx, later.x, control));
        assertLogs(ctx, receipt, [applied(fields)], "a control at the bound");
        receipt = ok(ctx, await voidStored(ctx, 3n, later.x, expired));
        assertLogs(ctx, receipt, [voided(more[2])], "a void at the bound");
        assert.equal(await dest.view("opCount"), U64_MAX);
        assert.equal(await dest.view("transferNonces", [second]), 3n);
        assert.equal(await dest.view("balanceOf", [second]), 5n * UNIT - 3n * UNIT + UNIT);
        assert.equal(await dest.view("controlNonce"), 1n);
        assert.deepEqual([await dest.view("isConsumed", [2n]), await dest.view("isConsumed", [3n])], [true, true]);
        assert.equal(
          await storageAt(dest, 2),
          withOpCount(U64_MAX) | 1n,
          "slot C holds the saturated count, the applied control nonce and nothing else new",
        );
      });

      // -- coverage -------------------------------------------------------------------

      it("coverage: every error the contract declares was reached by a test of this run", (t) => {
        const reached = coverage.get(`${hardfork}/${profile.name}`) ?? new Map();
        const missing = DECLARED_ERRORS.filter((name) => !reached.has(name));
        assert.deepEqual(missing, [], "declared errors that no test reached");
        const outside = [...reached.keys()].filter((name) => !DECLARED_ERRORS.includes(name)).sort();
        assert.deepEqual(outside, Object.keys(OUTSIDE_THE_ERROR_TABLE).sort(), "outcomes outside the error table");
        const short = (title) => title.split(/[:,(]/)[0].trim();
        for (const name of [...DECLARED_ERRORS, ...outside]) {
          const tests = [...new Set([...reached.get(name)].map(short))].sort();
          t.diagnostic(`${name} ← ${tests.join(" | ")}`);
        }
        for (const [name, reason] of Object.entries(OUTSIDE_THE_ERROR_TABLE)) t.diagnostic(`${name}: ${reason}`);
      });
    });
  }
}

after(() => {
  const target = process.env.SCCP_ERROR_COVERAGE_REPORT;
  if (!target) return;
  const listing = {};
  for (const [key, errors] of [...coverage.entries()].sort()) {
    listing[key] = Object.fromEntries([...errors.entries()].sort().map(([name, tests]) => [name, [...tests].sort()]));
  }
  const report = { outside_the_error_table: OUTSIDE_THE_ERROR_TABLE, listing };
  fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`);
});
