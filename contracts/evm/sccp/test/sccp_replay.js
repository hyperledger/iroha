"use strict";

// Replay driver for the shared SCCP fixtures on EDR (`specs/sccp.md` §11.1,
// §11.3, §11.4): it turns the rows of `finality_v1.json`,
// `finality_rust_v1.json`, `committee_transitions_v1.json` and
// `control_v1.json` into calls of a deployed `SccpTairaXor`, and compares what
// the contract did with what the row records: the outcome (success, or the
// exact custom error with its arguments), the logs in order as raw topics and
// data, the return value, and the complete destination state after every step,
// read through views only. Expected logs and calldata are built with the
// interface of the independent model, and the proofs of every row are checked
// against the model's own leaves and block references first.
//
// A scenario step is `(state, call, now_ms) → (state_after, outcome, events)`.
// The destination clock has one-second resolution, so every `now_ms` is a
// whole second and never decreases within a scenario; steps that share a time
// are mined in consecutive blocks with one timestamp.
//
// `Ledger` records which rows ran, so that a suite can prove it executed every
// row of every fixture it loaded.

const assert = require("node:assert/strict");
const model = require("./sccp_v1_model.js");
const harness = require("./sccp_edr_harness.js");

const { ethers, iface } = model;
const { Chain } = harness;

const HARNESS_SOURCES = Object.freeze([
  "contracts/evm/sccp/SccpTairaXor.sol",
  "contracts/evm/sccp/lib/BLS12_381.sol",
  "contracts/evm/sccp/test/harness/SccpDirtyMemoryHarness.sol",
]);
const DIRTY_HARNESS_SOURCE = HARNESS_SOURCES[2];
// EIP-170: the test-only harness must stay deployable under the mainnet code-size limit.
const MAX_RUNTIME_BYTES = 24_576;
const TRANSFER_TOPIC = iface.getEvent("Transfer").topicHash;
const VIEW_KEYS = Object.freeze([
  "committeeState",
  "controlNonce",
  "equivocated",
  "initialCommittee",
  "live",
  "mintingPaused",
  "opCount",
  "pauseState",
]);

// ---------------------------------------------------------------------------
// ABI arguments of fixture JSON
// ---------------------------------------------------------------------------

/** `TairaCertificateV1` of the `evm` object of a fixture certificate. */
function certificateArg(evm) {
  return [evm.qc, evm.header, evm.signature, evm.committee, evm.signerYs];
}

function blockRefArg(block) {
  return [block.height, block.sccpRoot, block.messageCount, block.historyIndex, block.historyPath];
}

/** `MessageProofV1` of a fixture or model proof. */
function messageProofArg(proof) {
  return [proof.payload, proof.leafIndex, proof.path, blockRefArg(proof.block)];
}

/**
 * `ControlProofV1` of a fixture or model proof. `parliamentPaused` must be a
 * boolean: the typed interface cannot carry another value (§3.4), and
 * `withRawParliamentPaused` builds the calldata that tries.
 */
function controlProofArg(proof) {
  assert.equal(typeof proof.parliamentPaused, "boolean", "parliamentPaused is a bool on the EVM interface");
  return [
    proof.controlNonce,
    proof.track,
    proof.parliamentPaused,
    proof.fastPauseUntilMs,
    proof.certificateId,
    proof.effectHash,
    proof.leafIndex,
    proof.path,
    blockRefArg(proof.block),
  ];
}

/**
 * Calldata of `applyControl` or `applyControlFromCheckpoint` whose
 * `parliamentPaused` word holds `value` instead of 0 or 1. The control proof
 * is the second argument, and `parliamentPaused` the third head word of its
 * tuple.
 */
function withRawParliamentPaused(calldata, value) {
  const bytes = ethers.getBytes(calldata);
  const controlOffset = Number(BigInt(ethers.hexlify(bytes.slice(4 + 32, 4 + 64))));
  const position = 4 + controlOffset + 2 * 32;
  assert(BigInt(ethers.hexlify(bytes.slice(position, position + 32))) <= 1n, "the patched word is the bool");
  bytes.set(ethers.getBytes(model.word(value)), position);
  return ethers.hexlify(bytes);
}

function pooled(pool, id) {
  assert(Object.hasOwn(pool, id), `certificate ${id} is in the pool`);
  return pool[id];
}

/** The entry point and the arguments of one fixture step. */
function stepCall(step, pool) {
  const certificate = () => certificateArg(pooled(pool, step.certificate).evm);
  const checkpoint = () => [step.checkpoint.header];
  switch (step.call) {
    case "submitCheckpoints":
      return ["submitCheckpoints", [step.certificates.map((id) => certificateArg(pooled(pool, id).evm))]];
    case "finalizeFromTaira":
      return ["finalizeFromTaira", [certificate(), messageProofArg(step.proof)]];
    case "finalizeFromCheckpoint":
      return ["finalizeFromCheckpoint", [checkpoint(), messageProofArg(step.proof)]];
    case "applyControl":
      return ["applyControl", [certificate(), controlProofArg(step.proof)]];
    case "applyControlFromCheckpoint":
      return ["applyControlFromCheckpoint", [checkpoint(), controlProofArg(step.proof)]];
    case "voidExpired":
      return ["voidExpired", [step.nonce, certificate(), messageProofArg(step.proof)]];
    case "voidExpiredFromCheckpoint":
      return ["voidExpiredFromCheckpoint", [step.nonce, checkpoint(), messageProofArg(step.proof)]];
    case "voidFrozen":
      return ["voidFrozen", [BigInt(step.firstNonce), BigInt(step.count)]];
    default:
      throw new Error(`unknown fixture call ${step.call}`);
  }
}

// ---------------------------------------------------------------------------
// Targets: the production entry points, or the dirty-memory harness
// ---------------------------------------------------------------------------

/** The locked build, called through the entry point a step names. */
const PRODUCTION = Object.freeze({
  name: "production",
  creation: undefined,
  encode: (name, args) => iface.encodeFunctionData(name, args),
});

const DIRTY_ENTRY_POINTS = Object.freeze({
  submitCheckpoints: "dirtySubmitCheckpoints",
  finalizeFromTaira: "dirtyFinalizeFromTaira",
  applyControl: "dirtyApplyControl",
  voidExpired: "dirtyVoidExpired",
});

const dirtyBuilds = new Map();

/**
 * Compiles `SccpDirtyMemoryHarness` with the pinned compiler and the locked
 * settings, once per set of `overrides` (a source path → the content that
 * replaces the checkout's, for a build with a planted defect).
 */
function dirtyHarnessBuild(overrides = {}) {
  const key = JSON.stringify(Object.entries(overrides).sort());
  if (!dirtyBuilds.has(key)) {
    const compiled = harness.compileTestSources([...HARNESS_SOURCES], overrides);
    const artifact = compiled[DIRTY_HARNESS_SOURCE].SccpDirtyMemoryHarness;
    const runtimeBytes = artifact.evm.deployedBytecode.object.length / 2;
    assert(runtimeBytes <= MAX_RUNTIME_BYTES, `the dirty-memory harness is ${runtimeBytes} bytes, above EIP-170`);
    dirtyBuilds.set(key, Object.freeze({
      creation: `0x${artifact.evm.bytecode.object}`,
      iface: new ethers.Interface(artifact.abi),
      runtimeBytes,
    }));
  }
  return dirtyBuilds.get(key);
}

/**
 * `SccpDirtyMemoryHarness`: the four entry points that verify a certificate
 * run after `words` words of `fill` were written from the free memory pointer
 * on; every other call goes to the inherited entry point. `build` selects a
 * harness build other than the checkout's.
 */
function dirtyTarget(words, fill, build = dirtyHarnessBuild()) {
  return Object.freeze({
    name: `dirty memory (${words} words of ${fill.slice(0, 6)}…${fill.slice(-2)})`,
    creation: build.creation,
    encode: (name, args) =>
      Object.hasOwn(DIRTY_ENTRY_POINTS, name)
        ? build.iface.encodeFunctionData(DIRTY_ENTRY_POINTS[name], [...args, words, fill])
        : iface.encodeFunctionData(name, args),
  });
}

/** The production entry points of a harness build: the inherited contract on fresh memory. */
function inheritedTarget(build = dirtyHarnessBuild()) {
  return Object.freeze({
    name: "harness build, production entry points",
    creation: build.creation,
    encode: PRODUCTION.encode,
  });
}

/**
 * Memory fills of the dirty-memory runs, `[words, fill]`. Each covers all the
 * memory one call uses (a batch of 16 certificates stays below 3 000 words),
 * so that no buffer of the verification starts from zero bytes; the fills
 * differ in the bytes a stale read would see.
 */
const DIRTY_FILLS = Object.freeze([
  Object.freeze([4096, `0x${"ff".repeat(32)}`]),
  Object.freeze([4096, `0x${"a5".repeat(32)}`]),
  Object.freeze([8192, `0x${"01".repeat(32)}`]),
  Object.freeze([4096, `0x${"00".repeat(31)}01`]),
]);

// ---------------------------------------------------------------------------
// Expected logs
// ---------------------------------------------------------------------------

/**
 * The raw logs `{topics, data}` the fixture events of one step stand for.
 * `sccp` are the SCCP events in order; `transfers` the ERC-20 `Transfer` logs
 * they imply, one mint per `SccpFinalized`.
 */
function expectedLogs(events, pool) {
  const sccp = [];
  const transfers = [];
  for (const event of events) {
    switch (event.event) {
      case "SccpCertificate": {
        const { evm } = pooled(pool, event.certificate);
        sccp.push(
          model.eventLog("SccpCertificate", [event.height, event.generation, evm.qc, evm.header, evm.signature]),
        );
        break;
      }
      case "SccpCheckpointed":
        sccp.push(model.eventLog("SccpCheckpointed", [event.height, event.header]));
        break;
      case "SccpCommitteeRotated":
        sccp.push(
          model.eventLog("SccpCommitteeRotated", [event.generation, event.root, event.untilMs, event.startHeight]),
        );
        break;
      case "SccpLatched":
        sccp.push(model.eventLog("SccpLatched", [event.reason, event.generation, event.height, event.a, event.b]));
        break;
      case "SccpControlApplied":
        sccp.push(
          model.eventLog("SccpControlApplied", [
            event.controlNonce,
            event.track,
            event.parliamentPaused,
            event.fastPauseUntilMs,
            event.certificateId,
          ]),
        );
        break;
      case "SccpFinalized":
        transfers.push(model.eventLog("Transfer", [model.ZERO_ADDRESS, event.recipient, BigInt(event.tokenAmount)]));
        sccp.push(
          model.eventLog("SccpFinalized", [event.messageId, event.nonce, event.recipient, BigInt(event.tokenAmount)]),
        );
        break;
      case "SccpVoided":
        sccp.push(model.eventLog("SccpVoided", [event.messageId, event.nonce]));
        break;
      default:
        throw new Error(`unknown fixture event ${event.event}`);
    }
  }
  return { sccp, transfers };
}

/** Requires the logs of `receipt` to be exactly the expected SCCP logs in order and the implied transfers. */
function assertLogs(destination, receipt, expected, where) {
  const logs = destination.logs(receipt);
  const isTransfer = (log) => log.topics[0] === TRANSFER_TOPIC;
  assert.deepEqual(logs.filter((log) => !isTransfer(log)), expected.sccp, `${where}: SCCP logs`);
  assert.deepEqual(logs.filter(isTransfer), expected.transfers, `${where}: ERC-20 Transfer logs`);
}

// ---------------------------------------------------------------------------
// Model cross-checks of fixture proofs
// ---------------------------------------------------------------------------

/** The header a step proves under: its inline certificate's, or its checkpoint's. */
function stepHeader(step, pool) {
  if (step.checkpoint) return step.checkpoint.header;
  if (step.certificate) return pooled(pool, step.certificate).evm.header;
  return null;
}

/**
 * Whether the model accepts the block reference and the leaf path of a step's
 * proof: `"ok"`, or `"BadProof"`. The leaf is computed from the deployment's
 * own lane, destination word and route revision, as the contract computes it.
 * Returns null for a step whose header the model cannot parse.
 */
function modelProofVerdict(step, pool, fixtureDeployment) {
  const profile = model.profileOf(fixtureDeployment.network);
  let header;
  try {
    header = model.parseHeader(stepHeader(step, pool));
  } catch (error) {
    if (error instanceof model.ModelError) return null;
    throw error;
  }
  const { proof } = step;
  const leaf =
    proof.payload !== undefined
      ? model.transferLeaf(
          model.outboundMessageId(fixtureDeployment.taira_network_id, profile, proof.payload),
          fixtureDeployment.destination_word,
        )
      : model.controlLeaf({
          networkId: fixtureDeployment.taira_network_id,
          profile,
          destinationWord: fixtureDeployment.destination_word,
          revision: fixtureDeployment.route_revision,
          nonce: proof.controlNonce,
          track: proof.track,
          parliamentPaused: proof.parliamentPaused,
          fastPauseUntilMs: proof.fastPauseUntilMs,
          certificateId: proof.certificateId,
          effectHash: proof.effectHash,
        });
  try {
    const { sccpRoot, messageCount } = model.checkBlockRef(header, proof.block);
    model.checkLeaf(leaf, proof.leafIndex, messageCount, proof.path, sccpRoot);
  } catch (error) {
    if (error instanceof model.ModelError && error.check === "BadProof") return "BadProof";
    throw error;
  }
  return "ok";
}

// ---------------------------------------------------------------------------
// Coverage ledger
// ---------------------------------------------------------------------------

/** Records the fixture rows a suite executed, by group and row id. */
class Ledger {
  constructor() {
    this.groups = new Map();
  }

  /** Marks row `id` of `group` as executed; a row runs once per group. */
  ran(group, id) {
    const rows = this.groups.get(group) ?? new Set();
    assert(!rows.has(id), `row ${group}/${id} ran twice`);
    rows.add(id);
    this.groups.set(group, rows);
  }

  /** The executed row ids of `group`, sorted. */
  rows(group) {
    return [...(this.groups.get(group) ?? [])].sort();
  }

  /** Number of executed rows per group. */
  counts() {
    return Object.fromEntries([...this.groups.entries()].map(([group, rows]) => [group, rows.size]).sort());
  }
}

// ---------------------------------------------------------------------------
// Destinations for replays
// ---------------------------------------------------------------------------

/**
 * Opens a chain of `profile` under `hardfork` whose blocks may share a
 * timestamp, deploys `deployment` at `at` seconds through the deterministic
 * deployer and, with `relocateTo`, moves the destination to that address.
 */
async function openDestination({ hardfork, profile, deployment, at, target = PRODUCTION, relocateTo }) {
  const chain = await Chain.open(profile, { hardfork, allowBlocksWithSameTimestamp: true });
  let { destination } = await harness.deploy(chain, deployment, { at, creation: target.creation });
  if (relocateTo !== undefined) destination = await harness.relocate(destination, relocateTo);
  return { chain, destination };
}

/** The 20-byte address a fixture destination word names. */
function addressOfWord(destinationWord) {
  const padding = ethers.dataSlice(destinationWord, 0, 12);
  assert.equal(padding, `0x${"00".repeat(12)}`, "an EVM destination word is an address");
  return ethers.getAddress(ethers.dataSlice(destinationWord, 12));
}

/**
 * The latest second at which the constructor accepts `untilMs`, but no later
 * than one second before `firstStepMs`: the deployment time of a replay.
 */
function deploymentTime(untilMs, firstStepMs) {
  const beforeFirstStep = BigInt(firstStepMs) / 1000n - 1n;
  const lastAccepted = (BigInt(untilMs) - 1n) / 1000n;
  const at = beforeFirstStep < lastAccepted ? beforeFirstStep : lastAccepted;
  assert(
    BigInt(untilMs) - at * 1000n <= model.MAX_VALIDITY_MS + model.MAX_INIT_SLACK_MS,
    "the pinned untilMs is within the constructor bound at the deployment time",
  );
  return at;
}

// ---------------------------------------------------------------------------
// Certificate rows (`finality_v1.json`, `finality_rust_v1.json`)
// ---------------------------------------------------------------------------

/** Requires `outcome` to be a revert with exactly the error `expected`, which takes no argument. */
function assertRefusal(outcome, expected, where) {
  assert(outcome.revert !== undefined, `${where}: expected ${expected}, but the call succeeded`);
  const described = `${where}: ${harness.describeRevert(outcome.revert)}`;
  assert.deepEqual(harness.decodeRevert(outcome.revert), { name: expected, args: [] }, described);
}

/** The deployment a certificate row verifies under: its pin in the fixture's verification context. */
function certificateRowDeployment(context, pin, profile) {
  return harness.deploymentOf(
    {
      taira_network_id: context.taira_network_id,
      consensus_instance: context.consensus_instance,
      route_revision: 1,
      max_wrapped_supply: "10000000000",
      pin,
    },
    profile,
  );
}

/**
 * The state of a destination deployed with the fixture `pin`, seen at `nowMs`,
 * in the `state_after` shape (§5.1.1): `high = start − 1`, no checkpoint, no
 * latch, no pause.
 */
function initialState(pin, nowMs) {
  return {
    checkpoints: [],
    committee: {
      generation: pin.generation,
      high: pin.start_height - 1,
      root: pin.committee_root,
      start: pin.start_height,
      until_ms: pin.until_ms,
    },
    consumed: [],
    equivocated: false,
    live: BigInt(nowMs) <= BigInt(pin.until_ms),
    op_count: 0,
    pause: { control_nonce: 0, effective: false, fast_pause_until_ms: 0, parliament_paused: false },
    total_supply: "0",
  };
}

/**
 * Replays one certificate row: a fresh destination deployed with the row's
 * pin one second before `now_ms`, then `submitCheckpoints([certificate])` at
 * `now_ms`. A row that expects `ok` must emit `SccpCertificate` with the exact
 * certificate bytes, `SccpCheckpointed` and, at a rotation, the
 * `SccpCommitteeRotated` that §5.1.2 gives, and leave exactly that state. Any
 * other row must revert with exactly the named error and change nothing.
 * Returns the receipt of a successful submission.
 */
async function replayCertificateRow({ hardfork, profile, context, row, target = PRODUCTION, gasLabel }) {
  const where = `${hardfork} ${profile.name} ${target.name}: certificate ${row.label}`;
  const expected = row.expected.evm;
  assert(typeof expected === "string", `${where}: the row has an EVM outcome`);
  assert.equal(BigInt(row.now_ms) % 1000n, 0n, `${where}: now_ms is a whole second`);
  const now = BigInt(row.now_ms) / 1000n;
  const { chain, destination } = await openDestination({
    hardfork,
    profile,
    deployment: certificateRowDeployment(context, row.pin, profile),
    at: now - 1n,
    target,
  });
  try {
    const wireHeight = ethers.dataLength(row.evm.header) >= 56 ? BigInt(ethers.dataSlice(row.evm.header, 48, 56)) : 0n;
    const neighbours = [wireHeight - 1n, wireHeight, wireHeight + 1n];
    const probes = { heights: neighbours.filter((height) => height >= 0n && height <= model.U64_MAX), nonces: [0n] };
    const before = await destination.state(probes);
    assert.deepEqual(before, initialState(row.pin, (now - 1n) * 1000n), `${where}: initial state`);
    const data = target.encode("submitCheckpoints", [[certificateArg(row.evm)]]);
    const outcome = await destination.attempt(data, { at: now });
    const after = await destination.state(probes);
    if (expected !== "ok") {
      assertRefusal(outcome, expected, where);
      assert.deepEqual(after, initialState(row.pin, row.now_ms), `${where}: a refused certificate changes nothing`);
      return null;
    }
    assert(outcome.receipt, `${where}: reverted with ${outcome.revert && harness.describeRevert(outcome.revert)}`);
    const header = model.parseHeader(row.evm.header);
    assert.deepEqual(
      header,
      {
        ...model.headerFromFixture(row.header_fields),
        active: true,
        rotation: (row.header_fields.flags & model.FLAG_ROTATION) !== 0,
      },
      `${where}: the header fields the row records`,
    );
    const id = model.checkpointId(row.evm.header);
    assert.equal(id, row.checkpoint_id, `${where}: checkpoint id`);
    const events = [
      { event: "SccpCertificate", certificate: "row", height: header.height, generation: header.generation },
      { event: "SccpCheckpointed", height: header.height, header: id },
    ];
    const state = initialState(row.pin, row.now_ms);
    state.checkpoints = [{ height: harness.jsonInteger(header.height), id }];
    state.committee.high = harness.jsonInteger(header.height);
    if (header.rotation) {
      // §5.1.2: the successor trusts until min(t_eff(X) + validity, 2^64 − 1), t_eff = min(X.timestamp, now).
      const nowMs = BigInt(row.now_ms);
      const sum = (header.timestampMs < nowMs ? header.timestampMs : nowMs) + header.validityMs;
      const untilMs = sum > model.U64_MAX ? model.U64_MAX : sum;
      events.push({
        event: "SccpCommitteeRotated",
        generation: header.generation + 1n,
        root: header.nextCommitteeRoot,
        untilMs,
        startHeight: header.height + 1n,
      });
      state.committee = {
        generation: harness.jsonInteger(header.generation + 1n),
        high: harness.jsonInteger(header.height),
        root: header.nextCommitteeRoot,
        start: harness.jsonInteger(header.height + 1n),
        until_ms: harness.jsonInteger(untilMs),
      };
      state.live = nowMs <= untilMs;
    }
    assertLogs(destination, outcome.receipt, expectedLogs(events, { row }), where);
    assert.deepEqual(after, state, `${where}: state after the checkpoint`);
    if (gasLabel !== undefined) harness.recordGas(chain, gasLabel, outcome.receipt, data);
    return outcome.receipt;
  } finally {
    await chain.close();
  }
}

/**
 * Replays one `headers` row of `finality_v1.json`: the certificate `base`
 * with its header replaced by the row's `x`, on a destination pinned to the
 * generation and committee root that `x` names (where it names any). A header
 * the parser refuses answers `BadHeader` at step 2. One the parser admits
 * (`destination: "accept"`) passes steps 2 and 3 and is refused at step 4
 * with `BadCommittee`, because the keys of `base` are not its committee.
 */
async function replayHeaderRow({ hardfork, profile, context, base, row }) {
  const where = `${hardfork} ${profile.name}: header ${row.label}`;
  const length = ethers.dataLength(row.x);
  const generation = length >= 149 ? BigInt(ethers.dataSlice(row.x, 141, 149)) : 0n;
  const root = length >= 181 ? ethers.dataSlice(row.x, 149, 181) : model.ZERO32;
  const pin = {
    ...base.pin,
    generation: generation === 0n ? base.pin.generation : harness.jsonInteger(generation),
    committee_root: root === model.ZERO32 ? base.pin.committee_root : root,
  };
  const now = BigInt(base.now_ms) / 1000n;
  const { chain, destination } = await openDestination({
    hardfork,
    profile,
    deployment: certificateRowDeployment(context, pin, profile),
    at: now - 1n,
  });
  try {
    const expected = row.destination === "accept" ? "BadCommittee" : row.destination;
    const certificate = certificateArg({ ...base.evm, header: row.x });
    const data = iface.encodeFunctionData("submitCheckpoints", [[certificate]]);
    assertRefusal(await destination.attempt(data, { at: now }), expected, where);
    assert.deepEqual(await destination.state(), initialState(pin, base.now_ms), `${where}: nothing changed`);
  } finally {
    await chain.close();
  }
}

// ---------------------------------------------------------------------------
// Scenarios (`committee_transitions_v1.json`, `control_v1.json`)
// ---------------------------------------------------------------------------

/** Whether a scenario has no step that depends on the destination's network or address. */
function isProfileIndependent(scenario) {
  return scenario.steps.every((step) => ["submitCheckpoints", "views", "voidFrozen"].includes(step.call));
}

/** Heights and nonces to probe after every step of a scenario: all it names, and their neighbours. */
function scenarioProbes(scenario, pool) {
  const heights = new Set();
  const nonces = new Set();
  const addHeight = (height) => {
    for (const value of [BigInt(height) - 1n, BigInt(height), BigInt(height) + 1n]) {
      if (value >= 0n && value <= model.U64_MAX) heights.add(value);
    }
  };
  const addNonce = (nonce) => {
    for (const value of [BigInt(nonce) - 1n, BigInt(nonce), BigInt(nonce) + 1n]) {
      if (value >= 0n && value <= model.U64_MAX) nonces.add(value);
    }
  };
  const addHeader = (header) => {
    if (ethers.dataLength(header) >= 56) addHeight(BigInt(ethers.dataSlice(header, 48, 56)));
  };
  addHeight(scenario.deployment.pin.start_height);
  for (const step of scenario.steps) {
    for (const id of [...(step.certificates ?? []), ...(step.certificate ? [step.certificate] : [])]) {
      addHeader(pooled(pool, id).evm.header);
    }
    if (step.checkpoint) addHeader(step.checkpoint.header);
    if (step.proof) {
      addHeight(step.proof.block.height);
      if (step.proof.payload !== undefined && ethers.dataLength(step.proof.payload) >= 18) {
        addNonce(BigInt(ethers.dataSlice(step.proof.payload, 10, 18)));
      }
    }
    if (step.nonce !== undefined) addNonce(step.nonce);
    if (step.call === "voidFrozen") {
      // The start of the range and at most 257 of its nonces: one more than the largest valid range.
      const first = BigInt(step.firstNonce);
      const count = BigInt(step.count) > 257n ? 257n : BigInt(step.count);
      addNonce(first);
      for (let offset = 1n; offset < count; offset += 1n) addNonce(first + offset);
    }
    for (const checkpoint of step.state_after.checkpoints) addHeight(checkpoint.height);
    for (const nonce of step.state_after.consumed) addNonce(nonce);
  }
  return { heights: [...heights], nonces: [...nonces] };
}

/** The views a `views` step records, in its shape; `live` follows from them and the latest block time. */
async function readViews(destination) {
  const committee = await destination.view("committeeState");
  const initial = await destination.view("initialCommittee");
  const pause = await destination.view("pauseState");
  const equivocated = await destination.view("equivocated");
  const nowMs = (await destination.chain.latest()).timestamp * 1000n;
  const integer = harness.jsonInteger;
  return {
    committeeState: {
      generation: integer(committee[4]),
      high: integer(committee[3]),
      root: committee[0],
      start: integer(committee[2]),
      untilMs: integer(committee[1]),
    },
    controlNonce: integer(await destination.view("controlNonce")),
    equivocated,
    initialCommittee: {
      generation: integer(initial[0]),
      root: initial[1],
      start: integer(initial[2]),
      untilMs: integer(initial[3]),
    },
    live: !equivocated && nowMs <= committee[1],
    mintingPaused: await destination.view("mintingPaused"),
    opCount: integer(await destination.view("opCount")),
    pauseState: {
      controlNonce: integer(pause[2]),
      effective: pause[3],
      fastPauseUntilMs: integer(pause[1]),
      parliamentPaused: pause[0],
    },
  };
}

/**
 * Replays one step of a scenario and compares outcome, error arguments, logs,
 * return value, token balances and the state afterwards. `context` carries the
 * scenario's `{destination, pool, target, probes, balances, fixtureDeployment,
 * where}`.
 */
async function replayStep(context, step, index) {
  const { destination, pool, target, probes, balances } = context;
  const { chain } = destination;
  const where = `${context.where} step ${index} (${step.call})`;
  const now = BigInt(step.now_ms) / 1000n;
  const { expected } = step;
  if (step.call === "views") {
    await chain.mine(now);
    assert.deepEqual(Object.keys(expected).sort(), [...VIEW_KEYS], `${where}: the views the fixture records`);
    assert.deepEqual(await readViews(destination), expected, `${where}: views`);
  } else {
    if (step.proof) {
      const verdict = modelProofVerdict(step, pool, context.fixtureDeployment);
      if (expected.outcome === "ok" || expected.outcome === "BadProof") {
        assert.equal(verdict, expected.outcome, `${where}: the model's verdict on the proof`);
      }
    }
    const [name, args] = stepCall(step, pool);
    const outcome = await destination.attempt(target.encode(name, args), { at: now });
    if (expected.outcome === "ok") {
      assert(outcome.receipt, `${where}: reverted with ${outcome.revert && harness.describeRevert(outcome.revert)}`);
      assertLogs(destination, outcome.receipt, expectedLogs(expected.events, pool), where);
      if (expected.return !== undefined) {
        // A finalization returns the message id, which the model derives from the payload alone.
        assert.equal(await chain.returnData(outcome.receipt), expected.return, `${where}: return value`);
        const { taira_network_id: networkId, network } = context.fixtureDeployment;
        const id = model.outboundMessageId(networkId, model.profileOf(network), step.proof.payload);
        assert.equal(id, expected.return, `${where}: the model's message id`);
      }
      if (expected.stopped !== undefined) {
        assert(["latch", "frozen"].includes(expected.stopped), `${where}: a known stop reason`);
        assert.equal(step.state_after.live, false, `${where}: a stopped batch leaves the destination frozen`);
      }
      for (const event of expected.events) {
        if (event.event !== "SccpFinalized") continue;
        const recipient = ethers.getAddress(event.recipient);
        balances.set(recipient, (balances.get(recipient) ?? 0n) + BigInt(event.tokenAmount));
      }
    } else {
      assert(outcome.revert !== undefined, `${where}: expected ${expected.outcome}, but the call succeeded`);
      const error = harness.decodeRevert(outcome.revert);
      assert.equal(error.name, expected.outcome, `${where}: ${harness.describeRevert(outcome.revert)}`);
      const inputs = iface.getError(expected.outcome).inputs;
      assert.deepEqual(
        Object.keys(expected.error_args ?? {}).sort(),
        inputs.map((input) => input.name).sort(),
        `${where}: the fixture names every argument of ${expected.outcome}`,
      );
      assert.deepEqual(
        error.args,
        inputs.map((input) => BigInt(expected.error_args[input.name])),
        `${where}: arguments of ${expected.outcome}`,
      );
      assert.deepEqual(expected.events, [], `${where}: a failed call records no event`);
    }
  }
  assert.deepEqual(await destination.state(probes), step.state_after, `${where}: state after the step`);
  for (const [recipient, balance] of balances) {
    assert.equal(await destination.view("balanceOf", [recipient]), balance, `${where}: balance of ${recipient}`);
  }
}

/**
 * Replays one scenario on a fresh destination and returns the number of steps
 * it ran. On the fixture's own profile the destination is moved to the address
 * its `destination_word` names, so that the recorded leaves are its own; on
 * another profile only a scenario without leaves can run
 * (`isProfileIndependent`). `onStep(index)` is called after every step.
 */
async function replayScenario({ hardfork, profile, scenario, pool, target = PRODUCTION, source, onStep }) {
  assert.equal(scenario.flavor, "evm", `${scenario.name} is an EVM scenario`);
  const fixtureDeployment = scenario.deployment;
  const ownProfile = model.profileOf(fixtureDeployment.network);
  if (profile !== ownProfile) {
    const refusal = `${scenario.name} binds ${ownProfile.name} and cannot run on ${profile.name}`;
    assert(isProfileIndependent(scenario), refusal);
  }
  const where = `${hardfork} ${profile.name} ${target.name}: ${source} ${scenario.name}`;
  const { chain, destination } = await openDestination({
    hardfork,
    profile,
    deployment: harness.deploymentOf(fixtureDeployment, profile),
    at: deploymentTime(fixtureDeployment.pin.until_ms, scenario.steps[0].now_ms),
    target,
    relocateTo: profile === ownProfile ? addressOfWord(fixtureDeployment.destination_word) : undefined,
  });
  try {
    const probes = scenarioProbes(scenario, pool);
    const initial = await destination.state(probes);
    delete initial.live;
    delete initial.pause.effective;
    assert.deepEqual(initial, scenario.initial_state, `${where}: initial state`);
    const context = { destination, pool, target, probes, balances: new Map(), fixtureDeployment, where };
    let previous = 0n;
    for (const [index, step] of scenario.steps.entries()) {
      const nowMs = BigInt(step.now_ms);
      assert.equal(nowMs % 1000n, 0n, `${where} step ${index}: now_ms is a whole second`);
      assert(nowMs >= previous, `${where} step ${index}: now_ms never decreases`);
      previous = nowMs;
      await replayStep(context, step, index);
      if (onStep) onStep(index);
    }
    return scenario.steps.length;
  } finally {
    await chain.close();
  }
}

module.exports = {
  DIRTY_ENTRY_POINTS,
  DIRTY_FILLS,
  HARNESS_SOURCES,
  Ledger,
  PRODUCTION,
  addressOfWord,
  assertLogs,
  blockRefArg,
  certificateArg,
  certificateRowDeployment,
  controlProofArg,
  deploymentTime,
  dirtyHarnessBuild,
  dirtyTarget,
  expectedLogs,
  inheritedTarget,
  initialState,
  isProfileIndependent,
  messageProofArg,
  modelProofVerdict,
  openDestination,
  replayCertificateRow,
  replayHeaderRow,
  replayScenario,
  replayStep,
  scenarioProbes,
  stepCall,
  withRawParliamentPaused,
};
