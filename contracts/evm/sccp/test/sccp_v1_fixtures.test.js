"use strict";

// Replay of the shared SCCP v1 fixtures against `SccpTairaXor.sol` on the
// locked EDR runtime (`specs/sccp.md` §11.1, §11.3, §11.4 item 3), under both
// the Prague and the Osaka rules:
//
// - `finality_v1.json`: every certificate with an EVM form (positive, negative
//   and flavour-specific), every header row, and the row of
//   `finality_rust_v1.json`;
// - `committee_transitions_v1.json`: every step of every EVM scenario, with the
//   outcome or the exact error and its arguments, the logs as raw topics and
//   data, the return value and the full state after every step, read through
//   views only; the deployment bound (`init_bounds`); the selector, topic and
//   error-name tables;
// - `control_v1.json`: every step of every destination-effect scenario, the
//   rejected controls certified by the model, and every recorded control leaf
//   of an EVM target applied on its own chain;
// - `evm_calldata_v1.json`: every selector, topic, golden call, view, return
//   and log, the P4 CREATE2 sample, and every `calldata_conformance` entry.
//
// The canonical run is the locked build on the fixtures' own profile
// (`ethereum-mainnet`, chain id 1). Rows that bind no network also run under
// the BSC profile (chain id 56), and every certificate and scenario runs once
// more through `test/harness/SccpDirtyMemoryHarness.sol`, which verifies on
// memory that is not zero. Destinations are created through the deterministic
// deployer of §5.2.1. The last test of each hardfork compares the rows that
// ran with an independent enumeration of the fixtures and with pinned counts,
// so a row that did not run, and a regenerated fixture with fewer rows, fail.
//
// Before any test uses a certificate the JavaScript model signed, the model
// reproduces every positive certificate of `finality_v1.json` byte for byte
// (`sccp_v1_model.js`, `requireReproduction`). The model then mints what the
// recorded rows cannot carry: the certified trees around the recorded control
// leaves, the mint the conformance entries burn, a history with a heartbeat, a
// key change and a history proof on both profiles (with the two check orders
// of §5.1.2 and §5.1.5 that the recorded rows `inline_calls_after_expiry` and
// `same_height_block_ref_with_history` pin on `ethereum-mainnet` only), and a
// batch of 16 certificates of an n = 31 committee, on fresh and on dirty memory.
//
// Two groups of tests check the suite itself: a replay must refuse a row that
// records another state, outcome, argument, log, return value or time, and the
// dirty-memory entry points must expose a build that reads unwritten memory,
// which the production entry points alone do not.
//
// Run: `node --test contracts/evm/sccp/test/sccp_v1_fixtures.test.js` with the
// locked EVM runtime installed (`npm ci --ignore-scripts` in
// `scripts/contract_tooling/evm-runtime`, or `SCCP_EVM_RUNTIME_DIR` /
// `NODE_PATH` naming an installed copy).

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { describe, it } = require("node:test");
const m = require("./sccp_v1_model.js");
const h = require("./sccp_edr_harness.js");
const r = require("./sccp_replay.js");

const { ethers, REPO } = m;
const { ethereum: ETHEREUM, bsc: BSC } = m.PROFILES;

const HARDFORKS = Object.freeze(["prague", "osaka"]);
const FIXTURES = path.join(REPO, "fixtures", "sccp");

function load(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, name), "utf8"));
}

const FINALITY = load("finality_v1.json");
const FINALITY_RUST = load("finality_rust_v1.json");
const TRANSITIONS = load("committee_transitions_v1.json");
const CONTROL = load("control_v1.json");
const CALLDATA = load("evm_calldata_v1.json");

const CONTEXT = FINALITY.verification_context;
const EVM_SCENARIOS = TRANSITIONS.scenarios.filter((scenario) => scenario.flavor === "evm");
const CONTROL_SCENARIOS = CONTROL.destination_effects;
const PORTABLE_SCENARIOS = EVM_SCENARIOS.filter(r.isProfileIndependent);
const CONFORMANCE_FUNCTIONS = Object.freeze(["transferToTaira", "voidFrozen"]);
const CONFORMANCE = CALLDATA.calldata_conformance;

/**
 * Pinned row counts. A regenerated fixture with other counts fails here until
 * the numbers are reviewed and updated, so coverage cannot shrink silently.
 */
const ROW_COUNTS = Object.freeze({
  "finality.test_keys": 35,
  "finality.committees": 4,
  "finality.certificates": 13,
  "finality.flavor_specific_certificates": 1,
  "finality.negative_certificates": 53,
  "finality.negative_certificates with an EVM form": 51,
  "finality.negative_certificates with a TON form": 40,
  "finality.flavor_specific_certificates with a TON form": 1,
  "finality.headers.valid": 8,
  "finality.headers.invalid": 33,
  "finality_rust.negative_certificates": 1,
  "transitions.scenarios": 40,
  "transitions.scenarios of the EVM flavor": 32,
  "transitions.steps": 138,
  "transitions.scenarios without leaves": 22,
  "transitions.steps of scenarios without leaves": 58,
  "transitions.certificates": 77,
  "transitions.committees": 17,
  "transitions.init_bounds": 5,
  "transitions.selectors": 24,
  "transitions.event_topics": 8,
  "control.scenarios": 10,
  "control.steps": 42,
  "control.certificates": 11,
  "control.spec_examples": 4,
  "control.controls": 36,
  "control.controls of an EVM target": 24,
  "control.rejected": 9,
  "control.rejected with a destination outcome": 8,
  "calldata.selectors": 24,
  "calldata.events": 8,
  "calldata.calls": 13,
  "calldata.views": 15,
  "calldata.logs": 4,
  "calldata_conformance.transferToTaira": 13,
  "calldata_conformance.voidFrozen": 12,
});

/** Negative certificates that only the TON flavour can express (`expected.evm` is null). */
const TON_ONLY_NEGATIVES = Object.freeze(["sigma_ton_uncompressed_flag", "ton_signature_length_95"]);

// The base time of the scenario fixtures, in seconds, and the validity of their pin.
const T0 = 1_800_000_000n;
const VALIDITY_MS = 1_209_600_000n;
const UNIT = 1_000_000_000n;
// Test keys of the committee that signs the certificates this suite mints itself.
const MODEL_COMMITTEE_KEYS = Object.freeze([120, 121, 122, 123]);
// The two statements of `lib/BLS12_381.sol` that write Z_pad, the zero block that
// `expand_message_xmd` hashes first; a build without them is the planted defect of the
// dirty-memory control test.
const LIBRARY_SOURCE = "contracts/evm/sccp/lib/BLS12_381.sol";
const Z_PAD_WRITES = /^ *mstore\(s, 0\) \/\/ Z_pad[^\n]*\n *mstore\(add\(s, 0x20\), 0\)\n/gm;

const withEvmForm = (rows) => rows.filter((row) => row.expected.evm !== null);
const labels = (rows) => rows.map((row) => row.label);

/** The ids `scenario#index` of every step of `scenarios`. */
function stepIds(scenarios) {
  return scenarios.flatMap((scenario) => scenario.steps.map((_, index) => `${scenario.name}#${index}`));
}

/** A stable id of a `controls` row of `control_v1.json`: its position and its distinguishing fields. */
function controlRowId(row) {
  const fields = `r${row.route_revision}/t${row.track}/p${row.parliament_paused}/u${row.fast_pause_until_ms}`;
  return `${CONTROL.controls.indexOf(row)}:${row.target}/${fields}`;
}

/** The four groups of certificate rows, each of the shape of a `finality_v1.json` certificate. */
const CERTIFICATE_GROUPS = Object.freeze([
  ["finality.certificates", FINALITY.certificates],
  ["finality.flavor_specific_certificates", FINALITY.flavor_specific_certificates],
  ["finality.negative_certificates", FINALITY.negative_certificates],
  ["finality_rust.negative_certificates", FINALITY_RUST.negative_certificates],
]);

/**
 * The rows every hardfork must execute, by ledger group, enumerated from the
 * fixtures alone (independently of the loops that define the tests).
 */
function expectedRows() {
  const conformance = CONFORMANCE.map((entry) => `${entry.function}/${entry.label}`);
  const controlsOf = (profile) => CONTROL.controls.filter((row) => row.target === profile.network).map(controlRowId);
  const rows = {
    "ethereum/finality.headers.valid": labels(FINALITY.headers.valid),
    "ethereum/finality.headers.invalid": labels(FINALITY.headers.invalid),
    "ethereum/transitions.steps": stepIds(EVM_SCENARIOS),
    "bsc/transitions.steps": stepIds(PORTABLE_SCENARIOS),
    "dirty/transitions.steps": stepIds(EVM_SCENARIOS),
    "ethereum/control.steps": stepIds(CONTROL_SCENARIOS),
    "dirty/control.steps": stepIds(CONTROL_SCENARIOS),
    "ethereum/control.rejected": labels(CONTROL.rejected.filter((row) => row.destination !== null)),
    "ethereum/control.spec_examples": CONTROL.spec_examples.map((row) => `nonce ${row.control_nonce}`),
    "ethereum/control.controls": controlsOf(ETHEREUM),
    "bsc/control.controls": controlsOf(BSC),
    "ethereum/transitions.init_bounds": labels(TRANSITIONS.init_bounds),
    "bsc/transitions.init_bounds": labels(TRANSITIONS.init_bounds),
    "ethereum/calldata.deployment": ["P4"],
    "ethereum/calldata.calls": labels(CALLDATA.calls),
    "ethereum/calldata.views": labels(CALLDATA.views),
    "ethereum/calldata.logs": labels(CALLDATA.logs),
    "ethereum/calldata_conformance": conformance,
    "bsc/calldata_conformance": conformance,
  };
  for (const run of ["ethereum", "bsc", "dirty"]) {
    for (const [group, groupRows] of CERTIFICATE_GROUPS) rows[`${run}/${group}`] = labels(withEvmForm(groupRows));
  }
  return rows;
}

/** Control fields of a `control_v1.json` row in the ABI names of `ControlProofV1`. */
function controlFields(row) {
  return {
    controlNonce: BigInt(row.control_nonce),
    track: row.track,
    parliamentPaused: row.parliament_paused,
    fastPauseUntilMs: BigInt(row.fast_pause_until_ms),
    certificateId: row.certificate_id,
    effectHash: row.effect_hash,
  };
}

/** The control leaf of a `control_v1.json` row as the model builds it for `profile`. */
function modelControlLeaf(row, profile) {
  return m.controlLeaf({
    networkId: CONTROL.taira_network_id,
    profile,
    destinationWord: CONTROL.destination_words[row.target],
    revision: row.route_revision,
    nonce: row.control_nonce,
    track: row.track,
    parliamentPaused: row.parliament_paused,
    fastPauseUntilMs: row.fast_pause_until_ms,
    certificateId: row.certificate_id,
    effectHash: row.effect_hash,
  });
}

/** The `SccpControlApplied` event and the pause state a control row leaves when applied at `at` seconds. */
function appliedControl(row, at) {
  const paused = row.parliament_paused === 1;
  // now_ms + MAX_FAST_PAUSE_MS is above every recorded expiry, so the clamp leaves it.
  assert(BigInt(row.fast_pause_until_ms) <= at * 1000n + m.MAX_FAST_PAUSE_MS, "the recorded expiry is below the clamp");
  return {
    event: {
      event: "SccpControlApplied",
      controlNonce: row.control_nonce,
      track: row.track,
      parliamentPaused: paused,
      fastPauseUntilMs: row.fast_pause_until_ms,
      certificateId: row.certificate_id,
    },
    pause: {
      control_nonce: row.control_nonce,
      effective: paused || at * 1000n < BigInt(row.fast_pause_until_ms),
      fast_pause_until_ms: row.fast_pause_until_ms,
      parliament_paused: paused,
    },
  };
}

/**
 * A fresh destination of `profile`, deployed at `T0`, whose pinned committee
 * `signedBy` the model holds, with the model's Taira for it. With `relocateTo`
 * the destination is moved to that address and Taira's leaves name it;
 * `target` selects the build (`sccp_replay.js`).
 */
async function modelDestination({ hardfork, profile, revision = 1, relocateTo, signedBy, target }) {
  const pinned = signedBy ?? m.committee("M", [...MODEL_COMMITTEE_KEYS]);
  const deployment = {
    tairaNetworkId: CONTROL.taira_network_id,
    consensusInstance: CONTROL.consensus_instance,
    networkTag: profile.tag,
    routeRevision: revision,
    maxWrappedSupply: 1_000n * UNIT,
    initialGeneration: 5n,
    initialCommitteeRoot: pinned.root,
    initialStartHeight: 1000n,
    initialUntilMs: T0 * 1000n + VALIDITY_MS,
  };
  const { chain, destination } = await r.openDestination({ hardfork, profile, deployment, at: T0, relocateTo, target });
  const taira = new m.TairaModel({
    networkId: deployment.tairaNetworkId,
    instance: deployment.consensusInstance,
    profile,
    destinationWord: m.addressWord(destination.address),
    revision,
  });
  taira.start(deployment.initialGeneration, pinned, deployment.initialStartHeight, VALIDITY_MS);
  return { chain, destination, taira, deployment };
}

/** The two logs a full verification of `block` under pooled certificate `id` leaves: published, then stored. */
function publishedAndStored(id, block) {
  return [
    { event: "SccpCertificate", certificate: id, height: block.height, generation: block.header.generation },
    { event: "SccpCheckpointed", height: block.height, header: m.checkpointId(block.x) },
  ];
}

let mintedLargeBatch = null;

/**
 * Sixteen certificates of consecutive blocks under one committee of 31 test
 * keys, with three different quorums of 21 signers; minted once per process.
 */
function largeBatch() {
  if (mintedLargeBatch === null) {
    const signedBy = m.committee("N31", Array.from({ length: 31 }, (_, index) => 130 + index));
    const taira = new m.TairaModel({
      networkId: CONTROL.taira_network_id,
      instance: CONTROL.consensus_instance,
      profile: ETHEREUM,
      destinationWord: m.ZERO32,
    });
    taira.start(5n, signedBy, 1000n, VALIDITY_MS);
    const all = Array.from({ length: signedBy.n }, (_, index) => index);
    const quorums = [all.slice(0, signedBy.q), all.slice(-signedBy.q), all.filter((index) => index % 3 !== 1)];
    const blocks = Array.from({ length: m.MAX_CERTIFICATES_PER_CALL }, (_, index) =>
      taira.block(2000n + BigInt(index), (T0 + BigInt(index)) * 1000n, []));
    const certificates = blocks.map((block, index) =>
      taira.certify(block, { signerIndices: quorums[index % quorums.length] }));
    for (const quorum of quorums) assert.equal(quorum.length, signedBy.q, "a quorum of n = 31 has 21 signers");
    mintedLargeBatch = Object.freeze({ signedBy, blocks, certificates });
  }
  return mintedLargeBatch;
}

/** Runs `body` on a snapshot of `chain` and returns the chain to it afterwards. */
async function onSnapshot(chain, body) {
  const snapshot = await chain.snapshot();
  try {
    return await body();
  } finally {
    await chain.restore(snapshot);
  }
}

/** Requires `outcome` to be a revert with the error `expected` (null: empty revert data). */
function assertRevert(outcome, expected, where) {
  assert(outcome.revert !== undefined, `${where}: expected ${expected ?? "an empty revert"}, but the call succeeded`);
  assert.equal(h.decodeRevert(outcome.revert).name, expected, `${where}: ${h.describeRevert(outcome.revert)}`);
}

/** The deployer calldata `salt ‖ init code` of an init code. */
function deployerCalldata(init) {
  return ethers.concat([m.SCCP_EVM_SALT, init]);
}

/** Rebuild the Rust golden scenario with the independent model's trees and ABI. */
function rustGoldenScenario() {
  const scenario = CALLDATA.scenario;
  const deployment = h.deploymentOf({ ...CALLDATA.deployment, pin: scenario.pin });
  const certificate = (row) => [row.qc, row.header, row.signature_evm, ethers.concat(row.committee), row.signer_ys];
  const c100 = certificate(scenario.certificate_100);
  const c150 = certificate(scenario.certificate_150_rotation);
  const c200 = certificate(scenario.certificate_200);
  const transferLeaves = scenario.payloads.map((row) => m.transferLeaf(row.message_id, scenario.destination.destination_word));
  const control = scenario.control;
  const controlLeaf = m.controlLeaf({
    networkId: scenario.taira_network_id, profile: ETHEREUM,
    destinationWord: scenario.destination.destination_word, revision: scenario.destination.route_revision,
    nonce: control.control_nonce, track: control.track, parliamentPaused: control.parliament_paused,
    fastPauseUntilMs: control.fast_pause_until_ms, certificateId: control.certificate_id, effectHash: control.effect_hash,
  });
  const leaves = [transferLeaves[1], transferLeaves[2], controlLeaf];
  const direct = [100n, m.merkleRoot(leaves), 3n, 0n, []];
  const historical = [100n, m.merkleRoot(leaves), 3n, 1n, m.merklePath(scenario.history_leaves, 1)];
  const proof1 = [scenario.payloads[1].payload, 0n, m.merklePath(leaves, 0), direct];
  const proof2 = [scenario.payloads[2].payload, 1n, m.merklePath(leaves, 1), historical];
  const controlProof = (block) => [control.control_nonce, control.track, control.parliament_paused,
    control.fast_pause_until_ms, control.certificate_id, control.effect_hash, 2n, m.merklePath(leaves, 2), block];
  const account = (seed) => ethers.concat(["0x020120", ethers.keccak256(ethers.concat([m.ascii("SCCP/FIXTURE/TAIRA/V1"), m.be(seed, 1)]))]);
  const recipient = ethers.getAddress(ethers.dataSlice(ethers.keccak256(ethers.concat([m.ascii("SCCP/FIXTURE/EXTERNAL/V1"), "0x02"])), 12));
  const args = {
    finalize_direct: [c100, proof1], finalize_historical: [c200, proof2],
    finalize_checkpoint_direct: [[c100[1]], proof1], finalize_checkpoint_historical: [[c200[1]], proof2],
    checkpoint_rotation: [[c150]], checkpoint_rotation_and_latest: [[c150, c200]],
    apply_control_direct: [c100, controlProof(direct)], apply_control_historical: [c200, controlProof(historical)],
    apply_control_checkpoint: [[c200[1]], controlProof(historical)],
    void_expired: [1n, c100, proof1], void_expired_checkpoint: [2n, [c200[1]], proof2],
    void_frozen: [4n, 3n], transfer_to_taira: [account(9), 1_500_000_000n, 0n],
  };
  return { scenario, deployment, c100, c150, c200, leaves, transferLeaves, args, account, recipient };
}

// ---------------------------------------------------------------------------
// The model against the fixtures (no chain)
// ---------------------------------------------------------------------------

describe("SCCP v1 fixtures: the JavaScript model reproduces the reference", () => {
  it("pins the row counts of every fixture this suite replays", () => {
    const count = (rows, keep) => rows.filter(keep).length;
    const measured = {
      "finality.test_keys": FINALITY.test_keys.length,
      "finality.committees": Object.keys(FINALITY.committees).length,
      "finality.certificates": FINALITY.certificates.length,
      "finality.flavor_specific_certificates": FINALITY.flavor_specific_certificates.length,
      "finality.negative_certificates": FINALITY.negative_certificates.length,
      "finality.negative_certificates with an EVM form": withEvmForm(FINALITY.negative_certificates).length,
      "finality.negative_certificates with a TON form": count(FINALITY.negative_certificates, (row) => row.expected.ton !== null),
      "finality.flavor_specific_certificates with a TON form": count(FINALITY.flavor_specific_certificates, (row) => row.expected.ton !== null),
      "finality.headers.valid": FINALITY.headers.valid.length,
      "finality.headers.invalid": FINALITY.headers.invalid.length,
      "finality_rust.negative_certificates": FINALITY_RUST.negative_certificates.length,
      "transitions.scenarios": TRANSITIONS.scenarios.length,
      "transitions.scenarios of the EVM flavor": EVM_SCENARIOS.length,
      "transitions.steps": stepIds(EVM_SCENARIOS).length,
      "transitions.scenarios without leaves": PORTABLE_SCENARIOS.length,
      "transitions.steps of scenarios without leaves": stepIds(PORTABLE_SCENARIOS).length,
      "transitions.certificates": Object.keys(TRANSITIONS.certificates).length,
      "transitions.committees": Object.keys(TRANSITIONS.committees).length,
      "transitions.init_bounds": TRANSITIONS.init_bounds.length,
      "transitions.selectors": Object.keys(TRANSITIONS.selectors).length,
      "transitions.event_topics": Object.keys(TRANSITIONS.event_topics).length,
      "control.scenarios": CONTROL_SCENARIOS.length,
      "control.steps": stepIds(CONTROL_SCENARIOS).length,
      "control.certificates": Object.keys(CONTROL.certificates).length,
      "control.spec_examples": CONTROL.spec_examples.length,
      "control.controls": CONTROL.controls.length,
      "control.controls of an EVM target": count(CONTROL.controls, (row) => row.target !== "ton-mainnet"),
      "control.rejected": CONTROL.rejected.length,
      "control.rejected with a destination outcome": count(CONTROL.rejected, (row) => row.destination !== null),
      "calldata.selectors": CALLDATA.selectors.length,
      "calldata.events": CALLDATA.events.length,
      "calldata.calls": CALLDATA.calls.length,
      "calldata.views": CALLDATA.views.length,
      "calldata.logs": CALLDATA.logs.length,
      "calldata_conformance.transferToTaira": count(CONFORMANCE, (entry) => entry.function === "transferToTaira"),
      "calldata_conformance.voidFrozen": count(CONFORMANCE, (entry) => entry.function === "voidFrozen"),
    };
    assert.deepEqual(measured, { ...ROW_COUNTS });
    assert.deepEqual([...new Set(CONFORMANCE.map((row) => row.function))].sort(), [...CONFORMANCE_FUNCTIONS].sort());
    for (const rows of [CALLDATA.calls, CALLDATA.views, CALLDATA.logs]) {
      assert.equal(new Set(labels(rows)).size, rows.length, "Rust calldata labels are unique");
    }
    // The rows no EVM harness replays are exactly the known ones.
    const tonOnly = FINALITY.negative_certificates.filter((row) => row.expected.evm === null);
    assert.deepEqual(labels(tonOnly), [...TON_ONLY_NEGATIVES]);
    assert.deepEqual(labels(CONTROL.rejected.filter((row) => row.destination === null)), ["taira_target"]);
    assert(CONTROL_SCENARIOS.every((scenario) => scenario.flavor === "evm"), "every control scenario is an EVM one");
    for (const scenario of [...EVM_SCENARIOS, ...CONTROL_SCENARIOS]) {
      assert.equal(scenario.deployment.network, ETHEREUM.network, `${scenario.name} runs on ethereum-mainnet`);
    }
    // Row ids are unique within a fixture list, so the ledger can key on them.
    for (const rows of [
      FINALITY.certificates,
      FINALITY.negative_certificates,
      FINALITY.flavor_specific_certificates,
      FINALITY.headers.valid,
      FINALITY.headers.invalid,
      CONTROL.rejected,
      TRANSITIONS.init_bounds,
    ]) {
      assert.equal(new Set(labels(rows)).size, rows.length, "labels are unique");
    }
    for (const scenarios of [TRANSITIONS.scenarios, CONTROL_SCENARIOS]) {
      const names = new Set(scenarios.map((scenario) => scenario.name));
      assert.equal(names.size, scenarios.length, "scenario names are unique");
    }
  });

  it("rebuilds the test keys, the committees and every positive certificate of finality_v1.json byte for byte", () => {
    const wireDerived = CERTIFICATE_GROUPS.filter(([group]) => group.startsWith("finality."))
      .flatMap(([, rows]) => rows)
      .filter((row) => row.forgery_evidence_id !== undefined).length;
    const counts = {
      testKeys: ROW_COUNTS["finality.test_keys"],
      committees: ROW_COUNTS["finality.committees"],
      certificates: ROW_COUNTS["finality.certificates"],
      wireDerived,
    };
    assert.deepEqual({ ...m.reproduceFinalityFixture(FINALITY) }, counts);
    assert.deepEqual({ ...m.requireReproduction() }, counts, "the gate ran on the committed file");
    // The Rust-only row is genuine up to its signature: its message is the one its wire fields give.
    for (const row of FINALITY_RUST.negative_certificates) {
      const derived = m.wireDigests(CONTEXT.consensus_instance, row.evm.qc, row.evm.header);
      assert.deepEqual([derived.r, derived.preimage, derived.m], [row.r, row.commit_preimage, row.m], row.label);
      assert.equal(m.checkpointId(row.evm.header), row.checkpoint_id, row.label);
      assert.deepEqual(FINALITY_RUST.committees[row.committee], FINALITY.committees[row.committee]);
    }
    assert.deepEqual(FINALITY_RUST.verification_context, CONTEXT);
  });

  it("refuses a fixture certificate that differs in one byte", () => {
    const mutated = structuredClone(FINALITY);
    const signature = ethers.getBytes(mutated.certificates[0].evm.signature);
    signature[191] ^= 0x01;
    mutated.certificates[0].evm.signature = ethers.hexlify(signature);
    assert.throws(() => m.reproduceFinalityFixture(mutated), /n4_lowest_q: EVM wire form/);
    const otherKey = structuredClone(FINALITY);
    otherKey.test_keys[3].sk = m.be(BigInt(otherKey.test_keys[3].sk) + 1n, 32);
    assert.throws(() => m.reproduceFinalityFixture(otherKey), /test key 3: secret/);
  });

  it("signs, aggregates and decompresses as the certificate rows record, also for keys outside G1", () => {
    // The aggregate of the signers' own signatures is the recorded aggregate signature.
    const row = FINALITY.certificates.find((entry) => entry.label === "n7_scattered_q");
    const signedBy = m.committee(row.committee, FINALITY.committees[row.committee].test_key_indices);
    const signatures = row.signer_indices.map((index) => m.sign(signedBy.secrets[index], row.m));
    assert.equal(m.g2Evm192(m.aggregateSignatures(signatures)), row.evm.signature);
    const [secret] = signedBy.secrets;
    assert.equal(m.g2Evm192(m.sign(secret, row.m)), m.g2Evm192(m.hashToG2(row.m).multiply(secret)));
    assert.equal(m.publicKey(secret), signedBy.keys[0]);
    assert.equal(m.keyGen(FINALITY.test_keys[0].ikm), BigInt(FINALITY.test_keys[0].sk));
    assert.throws(() => m.keyGen("0x00"), /at least 32 bytes/);
    const minted = m.buildCertificate({
      committee: signedBy,
      signerIndices: row.signer_indices,
      header: row.evm.header,
      instance: CONTEXT.consensus_instance,
      epoch: row.qc_fixed_fields.epoch,
      epochContext: row.qc_fixed_fields.epoch_context,
      view: row.qc_fixed_fields.view,
      blockHash: row.qc_fixed_fields.block_hash,
      resultBody: row.qc_fixed_fields.result_body,
    });
    const { qc, header, signature, committee, signerYs } = minted;
    assert.deepEqual({ qc, header, signature, committee, signerYs }, row.evm, "the public builder mints the row");
    // Rows pinned under the root of their exact key bytes: dirty flags, x ≥ p, (0, 0), keys outside G1.
    const pinned = CERTIFICATE_GROUPS.flatMap(([, rows]) => rows).filter((entry) => entry.pin.keys !== undefined);
    assert.equal(pinned.length, 8, "rows that pin their own key bytes");
    for (const entry of pinned) {
      assert.equal(m.committeeRoot(entry.pin.keys), entry.pin.committee_root, `${entry.label}: pinned root`);
      assert.equal(ethers.concat(entry.pin.keys), entry.evm.committee, `${entry.label}: committee bytes`);
    }
    for (const label of ["key_flag_infinity_0xc0", "key_flag_uncompressed", "signer_x_ge_p"]) {
      const entry = pinned.find((candidate) => candidate.label === label);
      const listed = entry.pin.keys;
      const genuine = m.committee(entry.committee, FINALITY.committees[entry.committee].test_key_indices);
      // These rows replace one genuine signer key, then sort the listed keys
      // and remap the signer seats and y witnesses. Discover that replacement
      // from the row: neither its malformed seat nor its original seat is fixed.
      const replaced = genuine.keys.filter((key) => !listed.includes(key));
      const malformed = listed.flatMap((key, index) => genuine.keys.includes(key) ? [] : [{ key, index }]);
      assert.equal(replaced.length, 1, `${label}: one genuine key was replaced`);
      assert.equal(malformed.length, 1, `${label}: one malformed key was listed`);
      const [{ key: badKey, index: badIndex }] = malformed;
      assert(entry.signer_indices.includes(badIndex), `${label}: the malformed key is a signer`);
      assert.deepEqual(listed, [...listed].sort(), `${label}: canonical listed-key order`);
      assert.equal(m.decompressG1(badKey), null, `${label}: key ${badIndex} is no compressed point below p`);
      const original = ethers.getBytes(replaced[0]);
      if (label === "key_flag_infinity_0xc0") original[0] |= 0x40;
      else if (label === "key_flag_uncompressed") original[0] &= 0x7f;
      else {
        original[0] = (original[0] & 0xe0) | 0x1f;
        original.fill(0xff, 1);
      }
      assert.equal(ethers.hexlify(original), badKey, `${label}: the recorded key mutation`);
      const sourceKeys = listed.map((key) => key === badKey ? replaced[0] : key);
      const sourceSeats = entry.signer_indices.map((index) => genuine.keys.indexOf(sourceKeys[index]));
      const fields = entry.qc_fixed_fields;
      const rebuilt = m.buildCertificate({
        committee: genuine,
        signerIndices: sourceSeats,
        header: m.encodeHeader(m.headerFromFixture(entry.header_fields)),
        instance: CONTEXT.consensus_instance,
        epoch: fields.epoch,
        epochContext: fields.epoch_context,
        view: fields.view,
        blockHash: fields.block_hash,
        resultBody: fields.result_body,
        kind: entry.commit_kind,
        dst: entry.dst,
      });
      const signers = m.signersWord(entry.signer_indices);
      assert.equal(signers, BigInt(fields.signers), `${label}: remapped signer word`);
      assert.equal(m.signerBitmap(entry.signer_indices, genuine.n), entry.bitmap, `${label}: remapped bitmap`);
      const remappedQc = m.encodeQcFixed({ ...m.parseQcFixed(rebuilt.qc), signers });
      assert.deepEqual({
        qc: remappedQc,
        header: rebuilt.header,
        signature: rebuilt.signature,
        committee: ethers.concat(listed),
        // The malformed key deliberately retains its genuine member's y.
        signerYs: m.signerYs(sourceKeys, entry.signer_indices),
      }, entry.evm, `${label}: every EVM wire value, including remapped genuine witnesses`);
      assert.deepEqual({
        qc_fixed_cell: ethers.dataSlice(remappedQc, 0, FINALITY.constants.qc_fixed_len - 4),
        signature: m.g2Compressed(rebuilt.meta.sigma),
        signers: Number(signers),
        x_head: ethers.dataSlice(rebuilt.header, 0, FINALITY.constants.x_head_len),
        x_tail: ethers.dataSlice(rebuilt.header, FINALITY.constants.x_head_len),
      }, entry.ton, `${label}: every TON wire value`);
      assert.equal(rebuilt.meta.r, entry.r, `${label}: R`);
      assert.equal(rebuilt.meta.preimage, entry.commit_preimage, `${label}: Commit preimage`);
      assert.equal(rebuilt.meta.m, entry.m, `${label}: signed message`);
      assert.equal(m.checkpointId(rebuilt.header), entry.checkpoint_id, `${label}: checkpoint id`);
      for (const key of listed.filter((key) => key !== badKey)) {
        const recorded = FINALITY.test_keys.find((candidate) => candidate.pk === key);
        const point = m.decompressG1(key);
        assert.equal(m.be(point.y, 48), recorded.pk_y, `${label}: genuine key y`);
        assert.equal(m.g1Eip2537(point), recorded.pk_eip2537, `${label}: genuine key EIP-2537 form`);
      }
      const reason = new RegExp(`committee key ${badIndex} is not a compressed curve point`);
      assert.throws(() => m.signerYs(listed, entry.signer_indices), reason);
      assert.throws(() => m.aggregateKey(listed, entry.signer_indices), reason);
    }
    // Two keys shifted by T and −T are outside G1; their y and the unchanged aggregate key are derivable.
    const [shifted] = FINALITY.flavor_specific_certificates;
    const genuine = FINALITY.committees[shifted.committee].keys;
    assert.equal(m.signerYs(shifted.pin.keys, shifted.signer_indices), shifted.evm.signerYs);
    assert.notDeepEqual(shifted.pin.keys, genuine);
    assert.deepEqual(
      m.aggregateKey(shifted.pin.keys, shifted.signer_indices),
      m.aggregateKey(genuine, shifted.signer_indices),
      "the shifts cancel in the aggregate",
    );
    const outside = shifted.pin.keys.filter((key) => !genuine.includes(key));
    assert.equal(outside.length, 2);
    for (const key of outside) {
      // The curve implementation finds the point on the curve and refuses it for its subgroup only.
      const point = m.bls.G1.ProjectivePoint.fromAffine(m.decompressG1(key));
      assert.throws(() => point.assertValidity(), /not in prime-order subgroup/);
      assert.equal(point.isTorsionFree(), false, "a shifted key is outside G1");
    }
    assert.throws(() => m.profileOf("ton-mainnet"), /no EVM profile/);
    assert.equal(m.profileOf("bsc-mainnet"), BSC);
  });

  it("rebuilds the committees of the scenario fixtures and the pins of their deployments", () => {
    for (const [source, fixture] of [["transitions", TRANSITIONS], ["control", CONTROL]]) {
      for (const [name, recorded] of Object.entries(fixture.committees)) {
        const built = m.committee(name, recorded.test_key_indices);
        const what = `${source} committee ${name}`;
        assert.deepEqual(built.keys, recorded.keys, `${what}: canonical key order`);
        assert.deepEqual(built.testKeyIndices, recorded.test_key_indices, `${what}: key indices`);
        assert.equal(built.root, recorded.root, `${what}: root`);
        assert.deepEqual([built.n, built.q], [recorded.n, recorded.q], `${what}: n and q`);
      }
    }
    for (const scenario of [...EVM_SCENARIOS, ...CONTROL_SCENARIOS]) {
      const { pin } = scenario.deployment;
      assert.equal(m.committeeRoot(pin.keys), pin.committee_root, `${scenario.name}: the pinned root`);
      // §5.1.1: the initial state is the pin, with no checkpoint, no latch and no pause.
      const initial = r.initialState(pin, 0n);
      delete initial.live;
      delete initial.pause.effective;
      assert.deepEqual(scenario.initial_state, initial, `${scenario.name}: initial state`);
    }
  });

  it("reproduces the §11.2 worked examples: X, R, checkpoint ids, QC_FIXED, P, m and committee roots", () => {
    const examples = FINALITY.worked_examples;
    for (const [name, example] of Object.entries(examples.cases)) {
      const x = m.encodeHeader(m.headerFromFixture(example.fields));
      assert.equal(x, example.x, `${name}: X`);
      assert.equal(m.resultR(x, example.d_body), example.r, `${name}: R`);
      if (example.checkpoint_id !== undefined) assert.equal(m.checkpointId(x), example.checkpoint_id, `${name}: id`);
      assert.equal(m.parseHeader(x).active, name !== "inactive", `${name}: ACTIVE`);
    }
    const qc = examples.qc_fixed;
    assert.equal(m.signersWord(qc.signer_indices), BigInt(qc.fields.signers));
    assert.deepEqual(m.signerIndices(qc.fields.signers), qc.signer_indices);
    assert.equal(m.signerBitmap(qc.signer_indices, 31), qc.bitmap);
    const fields = {
      epoch: BigInt(qc.fields.epoch),
      epochContext: qc.fields.epoch_context,
      view: BigInt(qc.fields.view),
      blockHash: qc.fields.block_hash,
      resultBody: qc.fields.result_body,
      signers: BigInt(qc.fields.signers),
    };
    assert.equal(m.encodeQcFixed(fields), qc.encoded);
    assert.deepEqual(m.parseQcFixed(qc.encoded), fields);
    // Copying the bitmap bytes raw gives another word (the negative of §3.7).
    assert.notEqual(BigInt(qc.raw_bitmap_signers_negative), BigInt(qc.fields.signers));
    const commit = examples.commit;
    const preimage = m.commitPreimage({
      instance: commit.instance,
      epoch: commit.epoch,
      epochContext: commit.epoch_context,
      height: commit.height,
      view: commit.view,
      blockHash: commit.block_hash,
      r: commit.r,
    });
    assert.equal(preimage, commit.preimage);
    assert.equal(m.commitMessage(preimage), commit.m);
    assert.equal(commit.r, examples.cases.rotation.r);
    assert.equal(m.committeeRoot(examples.synthetic_committee_root.keys), examples.synthetic_committee_root.root);
    for (const row of FINALITY.signer_encodings) {
      assert.equal(m.signersWord(row.indices), BigInt(row.signers), row.label);
      assert.equal(m.be(row.signers, 4), row.signers_be32, row.label);
      assert.equal(m.signerBitmap(row.indices, row.n), row.bitmap, row.label);
      assert.deepEqual(m.signerIndices(row.signers), row.indices, row.label);
      // Every row is a full quorum, except the three-signer example of §3.7.
      if (row.label !== "n31_example") assert.equal(row.indices.length, m.quorum(row.n), row.label);
    }
    assert.throws(() => m.quorum(5), /invalid committee size/);
    assert.throws(() => m.committeeRoot([]), /1\.\.=255 keys/);
  });

  it("parses every header row and names the first violated check, in the order Length, X1 to X7", () => {
    for (const row of FINALITY.headers.valid) {
      const fields = m.headerFromFixture(row.fields);
      assert.deepEqual(m.parseHeader(row.x), { ...fields, active: row.active, rotation: row.rotation }, row.label);
      assert.equal(m.encodeHeader(fields), row.x, row.label);
      assert.equal(m.checkpointId(row.x), row.checkpoint_id, row.label);
      assert.equal(ethers.concat([row.x_head, row.x_tail]), row.x, row.label);
      assert.equal(row.destination, row.active ? "accept" : "BadHeader", row.label);
    }
    const checks = new Set();
    for (const row of FINALITY.headers.invalid) {
      assert.throws(
        () => m.parseHeader(row.x),
        (error) => error instanceof m.ModelError && error.check === row.error,
        `${row.label}: first violated check ${row.error}`,
      );
      assert.equal(row.destination, "BadHeader", row.label);
      checks.add(row.error);
    }
    assert.deepEqual([...checks].sort(), ["Length", "X1", "X2", "X3", "X4", "X5", "X6", "X7"]);
  });

  it("rebuilds every control leaf with its 199-byte preimage, and the constraint verdict of every rejected one", () => {
    for (const row of [...CONTROL.spec_examples, ...CONTROL.controls]) {
      const what = `${row.target} r${row.route_revision} n${row.control_nonce} t${row.track}`;
      const profile = row.target === "ton-mainnet" ? null : m.profileOf(row.target);
      assert.equal(row.destination_word, CONTROL.destination_words[row.target], what);
      const fields = {
        laneBytes: row.lane_bytes,
        destinationWord: row.destination_word,
        revision: row.route_revision,
        nonce: row.control_nonce,
        track: row.track,
        parliamentPaused: row.parliament_paused,
        fastPauseUntilMs: row.fast_pause_until_ms,
        certificateId: row.certificate_id,
        effectHash: row.effect_hash,
      };
      assert.equal(m.controlLeafPreimage(fields), row.preimage, `${what}: preimage`);
      assert.equal(ethers.dataLength(row.preimage), m.CONTROL_PREIMAGE_LEN, what);
      assert.equal(ethers.concat([row.ton_b1, row.ton_b2]), row.preimage, `${what}: TON builders`);
      assert.equal(m.controlLeaf(fields), row.leaf, `${what}: leaf`);
      if (profile !== null) {
        assert.equal(m.outboundLaneBytes(CONTROL.taira_network_id, profile), row.lane_bytes, `${what}: lane`);
        assert.equal(modelControlLeaf(row, profile), row.leaf, `${what}: leaf from the profile`);
      }
      assert.equal(m.controlConstraintsHold(controlFields(row)), true, `${what}: constraints`);
    }
    for (const row of CONTROL.rejected) {
      if (row.unchecked_leaf === undefined) {
        assert.equal(row.destination, null, row.label);
        continue;
      }
      assert.equal(modelControlLeaf(row, m.profileOf(row.target)), row.unchecked_leaf, `${row.label}: unchecked leaf`);
      const holds = m.controlConstraintsHold(controlFields(row));
      assert.equal(holds, row.error !== "BadControl", `${row.label}: constraints`);
    }
    assert.equal(m.topic(CONTROL.event_signature), CONTROL.topic_control_applied);
    assert.equal(m.iface.getEvent("SccpControlApplied").topicHash, CONTROL.topic_control_applied);
    assert.equal(BigInt(CONTROL.max_fast_pause_ms), m.MAX_FAST_PAUSE_MS);
  });

  it("rebuilds every Rust revision-5 calldata, view, log and P4 deployment row", () => {
    assert.equal(CALLDATA.schema, "iroha.sccp.evm-calldata.v1");
    assert.match(CALLDATA.spec, /revision 5/);
    const compiled = h.loadArtifacts();
    const golden = rustGoldenScenario();
    const { scenario, deployment, leaves, transferLeaves, args, account, recipient } = golden;
    const pin = CALLDATA.deployment;
    assert.equal(pin.network, scenario.destination.target);
    assert.equal(pin.taira_network_id, scenario.taira_network_id);
    assert.equal(pin.consensus_instance, scenario.consensus_instance);
    assert.equal(pin.route_revision, scenario.destination.route_revision);
    assert.equal(ethers.getAddress(pin.deployer), m.SCCP_EVM_DEPLOYER);
    assert.equal(pin.salt, m.SCCP_EVM_SALT);
    assert.equal(ethers.keccak256(compiled.creation), pin.creation_code_hash);
    assert.equal(m.encodeConstructorArgs(deployment), pin.constructor_args);
    const init = h.initCode(deployment);
    assert.equal(ethers.keccak256(init), pin.init_code_hash);
    assert.equal(m.create2Address(init), ethers.getAddress(pin.address));
    assert.deepEqual(CALLDATA.selectors.map((row) => row.function).sort(), Object.keys(TRANSITIONS.selectors).sort());
    for (const row of CALLDATA.selectors) {
      assert.deepEqual({ signature: row.signature, selector: row.selector }, TRANSITIONS.selectors[row.function]);
      for (const iface of [m.iface, compiled.iface]) {
        assert.equal(iface.getFunction(row.function).format("sighash"), row.signature);
        assert.equal(iface.getFunction(row.function).selector, row.selector);
      }
    }
    assert.deepEqual(CALLDATA.events.map((row) => row.signature).sort(), Object.values(TRANSITIONS.event_topics).map((row) => row.signature).sort());
    for (const row of CALLDATA.events) {
      assert.equal(m.iface.getEvent(row.signature).topicHash, row.topic0);
      assert.equal(compiled.iface.getEvent(row.signature).topicHash, row.topic0);
    }
    for (const [field, keys] of [["certificate_100", scenario.committee_g7], ["certificate_150_rotation", scenario.committee_g7], ["certificate_200", scenario.committee_g8]]) {
      const certificate = scenario[field];
      const header = m.parseHeader(certificate.header);
      assert.equal(header.height, BigInt(certificate.height));
      assert.equal(header.networkId, scenario.taira_network_id);
      assert.deepEqual(certificate.committee, keys);
      assert.equal(header.committeeRoot, m.committeeRoot(keys));
      assert.equal(certificate.signer_ys, m.signerYs(keys, [0, 1, 2]));
      assert.equal(certificate.signature_evm, m.g2Evm192(m.bls.G2.ProjectivePoint.fromHex(ethers.getBytes(certificate.aggregate_signature))));
    }
    assert.equal(scenario.pin.committee_root, m.committeeRoot(scenario.committee_g7));
    for (const row of scenario.payloads) {
      assert.equal(row.payload, m.encodePayload(m.outboundFields(ETHEREUM, {
        nonce: row.nonce, revision: scenario.destination.route_revision, deadlineMs: scenario.deadline_ms,
        amount: 1_000_000_000n + BigInt(row.nonce), sender: account(1), recipient,
      })));
      assert.equal(row.message_id, m.outboundMessageId(scenario.taira_network_id, ETHEREUM, row.payload));
    }
    assert.equal(scenario.block_100_root, m.merkleRoot(leaves));
    assert.deepEqual(scenario.history_leaves, [m.historyLeaf(50n, transferLeaves[0], 1n),
      m.historyLeaf(100n, m.merkleRoot(leaves), 3n), m.historyLeaf(200n, transferLeaves[3], 1n)]);
    assert.equal(m.parseHeader(scenario.certificate_100.header).historyRoot, m.historyRoot(scenario.history_leaves.slice(0, 2)));
    assert.equal(m.parseHeader(scenario.certificate_200.header).historyRoot, m.historyRoot(scenario.history_leaves));
    assert.deepEqual(labels(CALLDATA.calls).sort(), Object.keys(args).sort());
    for (const row of CALLDATA.calls) {
      assert.equal(m.iface.encodeFunctionData(row.function, args[row.label]), row.calldata, row.label);
      assert.equal(compiled.iface.encodeFunctionData(row.function, args[row.label]), row.calldata, row.label);
    }
    const viewArgs = { checkpointHeader: [150n], isConsumed: [300n], transferNonces: [`0x${"55".repeat(20)}`] };
    assert.deepEqual([...new Set([...CALLDATA.calls, ...CALLDATA.views].map((row) => row.function))].sort(), CALLDATA.selectors.map((row) => row.function).sort());
    for (const row of CALLDATA.views) {
      assert.equal(m.iface.encodeFunctionData(row.function, viewArgs[row.function] || []), row.calldata, row.label);
      assert.equal(compiled.iface.encodeFunctionData(row.function, viewArgs[row.function] || []), row.calldata, row.label);
    }
    for (const row of CALLDATA.logs) {
      const parsed = m.iface.parseLog(row);
      assert.deepEqual(m.eventLog(parsed.name, parsed.args), { topics: row.topics, data: row.data }, row.label);
    }
  });

  it("declares the selectors, topics and errors of the fixture tables, and so does the compiled contract", () => {
    const compiled = h.loadArtifacts().iface;
    for (const [name, { signature, selector }] of Object.entries(TRANSITIONS.selectors)) {
      assert.equal(m.selector(signature), selector, signature);
      assert.equal(m.iface.getFunction(name).format("sighash"), signature, name);
      assert.equal(m.iface.getFunction(name).selector, selector, name);
    }
    for (const [name, { signature, topic0 }] of Object.entries(TRANSITIONS.event_topics)) {
      assert.equal(m.topic(signature), topic0, signature);
      assert.equal(m.iface.getEvent(name).format("sighash"), signature, name);
    }
    assert.equal(m.SCCP_FUNCTIONS.length, ROW_COUNTS["transitions.selectors"]);
    assert.equal(m.SCCP_EVENTS.length, ROW_COUNTS["transitions.event_topics"]);
    // §5.2.2: the shared error names. Two are TON codes that no EVM destination declares.
    const tonOnlyInitErrors = ["AlreadyInitialized", "NotInitialized"];
    const modelErrors = m.SCCP_ERRORS.map((fragment) => /^error (\w+)\(/.exec(fragment)[1]).sort();
    const sharedErrors = Object.keys(TRANSITIONS.error_codes.shared);
    assert.deepEqual(sharedErrors.filter((name) => !tonOnlyInitErrors.includes(name)).sort(), modelErrors);
    // Every outcome a fixture names is success or a declared error.
    const outcomes = new Set();
    for (const scenario of [...EVM_SCENARIOS, ...CONTROL_SCENARIOS]) {
      for (const step of scenario.steps) if (step.call !== "views") outcomes.add(step.expected.outcome);
    }
    for (const [, rows] of CERTIFICATE_GROUPS) {
      for (const row of withEvmForm(rows)) outcomes.add(row.expected.evm);
    }
    for (const outcome of outcomes) assert(outcome === "ok" || modelErrors.includes(outcome), `outcome ${outcome}`);
    // The compiled contract has exactly the interface the model wrote from §5.2.2.
    const of = (contractInterface, type) => contractInterface.fragments.filter((fragment) => fragment.type === type);
    const signatures = (fragments) => fragments.map((fragment) => fragment.format("sighash")).sort();
    for (const type of ["function", "event", "error"]) {
      assert.deepEqual(signatures(of(compiled, type)), signatures(of(m.iface, type)), `${type}s of the contract`);
    }
    // Struct field names, output types and names, and whether a function writes state. `view` and
    // `pure` are one class here: both are read with a static call.
    const fieldNames = (type) => {
      if (type.baseType === "array") return fieldNames(type.arrayChildren);
      return type.baseType === "tuple" ? type.components.map((field) => [field.name, fieldNames(field)]) : null;
    };
    const shape = (entry) => ({
      structs: entry.inputs.map(fieldNames),
      outputs: entry.outputs.map((output) => output.format("sighash")),
      readOnly: entry.constant,
      payable: entry.payable,
    });
    const renamedOutputs = [];
    for (const fragment of of(m.iface, "function")) {
      const emitted = compiled.getFunction(fragment.format("sighash"));
      assert.deepEqual(shape(emitted), shape(fragment), `${fragment.name}: structs, outputs and mutability`);
      fragment.outputs.forEach((output, index) => {
        const name = emitted.outputs[index].name;
        if (name !== output.name) renamedOutputs.push([fragment.name, name, output.name]);
      });
    }
    // §5.2.2 names the third output of `pauseState()` `controlNonce`. Solidity cannot declare that
    // name next to the `controlNonce()` getter without a shadowing warning, and the build admits no
    // warning, so the compiled ABI calls it `controlNonce_`. Selector and encoding are unaffected.
    assert.deepEqual(renamedOutputs, [["pauseState", "controlNonce_", "controlNonce"]]);
    for (const type of ["event", "error"]) {
      for (const fragment of of(m.iface, type)) {
        const signature = fragment.format("sighash");
        const emitted = type === "event" ? compiled.getEvent(signature) : compiled.getError(signature);
        assert.equal(emitted.format("full"), fragment.format("full"), `${fragment.name}: argument names and indexing`);
      }
    }
    const constructors = of(compiled, "constructor");
    assert.equal(constructors.length, 1);
    assert.deepEqual(constructors[0].inputs.map((input) => input.type), [...m.CONSTRUCTOR_TYPES]);
    const constants = TRANSITIONS.constants;
    assert.equal(constants.max_certificates_per_call, m.MAX_CERTIFICATES_PER_CALL);
    assert.equal(constants.max_void_frozen_range_evm, m.MAX_VOID_FROZEN_RANGE);
    assert.equal(BigInt(constants.max_validity_ms), m.MAX_VALIDITY_MS);
    assert.equal(BigInt(constants.max_init_slack_ms), m.MAX_INIT_SLACK_MS);
  });

  it("pins the deterministic deployer and the CREATE2 address formula", () => {
    assert.equal(m.SCCP_EVM_DEPLOYER, ethers.getAddress("0x4e59b44847b379578588920ca78fbf26c0b4956c"));
    assert.equal(ethers.dataLength(m.SCCP_EVM_DEPLOYER_RUNTIME), 69);
    assert.equal(
      ethers.keccak256(m.SCCP_EVM_DEPLOYER_RUNTIME),
      "0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989",
    );
    const deployment = h.deploymentOf(EVM_SCENARIOS[0].deployment);
    const init = h.initCode(deployment);
    assert.equal(init, ethers.concat([h.loadArtifacts().creation, m.encodeConstructorArgs(deployment)]));
    const independent = ethers.getCreate2Address(m.SCCP_EVM_DEPLOYER, m.ZERO32, ethers.keccak256(init));
    assert.equal(m.create2Address(init), independent);
    const other = h.deploymentOf(EVM_SCENARIOS[0].deployment, BSC);
    assert.equal(other.networkTag, BSC.tag);
    assert.notEqual(m.create2Address(h.initCode(other)), independent, "the address is a function of the arguments");
    assert.equal(ethers.dataLength(m.encodeConstructorArgs(deployment)), 9 * 32);
    assert.equal(m.constructorArgs(deployment).length, m.CONSTRUCTOR_TYPES.length);
  });

  it("checks block references and leaf paths as §5.1.5 states", () => {
    const signedBy = m.committee("M", [...MODEL_COMMITTEE_KEYS]);
    const taira = new m.TairaModel({
      networkId: CONTEXT.taira_network_id,
      instance: CONTEXT.consensus_instance,
      profile: ETHEREUM,
      destinationWord: CONTEXT.destination_word,
    });
    taira.start(5n, signedBy, 1000n, VALIDITY_MS);
    const recipient = `0x${"44".repeat(20)}`;
    const transfer = (nonce) => taira.transfer({ nonce, amount: UNIT, deadlineMs: T0 * 1000n, recipient });
    const older = taira.block(1010n, T0 * 1000n, [transfer(0), transfer(1), transfer(2)]);
    taira.block(1011n, T0 * 1000n + 1000n, []);
    const newer = taira.block(1020n, T0 * 1000n + 2000n, [transfer(3)]);
    const newest = m.parseHeader(newer.x);
    assert.equal(newest.historySize, 2n);
    for (const [height, index, certified] of [[1010n, 2, older], [1010n, 1, newer], [1020n, 0, newer]]) {
      const proof = taira.messageProof(height, index, certified);
      const { leaf } = taira.blocks.get(height).leaves[index];
      const { sccpRoot, messageCount } = m.checkBlockRef(m.parseHeader(certified.x), proof.block);
      m.checkLeaf(leaf, proof.leafIndex, messageCount, proof.path, sccpRoot);
      assert.equal(m.merkleRootFromPath(leaf, index, messageCount, proof.path), sccpRoot);
    }
    const historical = taira.blockRef(1010n, newer);
    assert.equal(historical.historyPath.length, 1);
    const badProof = (ref) => assert.throws(() => m.checkBlockRef(newest, ref), (error) => error.check === "BadProof");
    badProof({ ...historical, historyPath: [] });
    badProof({ ...historical, historyIndex: 1n });
    badProof({ ...historical, messageCount: 4n });
    badProof({ ...historical, messageCount: 0n });
    badProof({ ...historical, messageCount: 513n });
    badProof({ ...historical, sccpRoot: m.ZERO32 });
    badProof({ ...historical, height: 1021n });
    badProof({ ...historical, historyPath: Array(33).fill(m.ZERO32) });
    const same = taira.blockRef(1020n, newer);
    assert.deepEqual(m.checkBlockRef(newest, same), { sccpRoot: newer.header.sccpRoot, messageCount: 1n });
    badProof({ ...same, historyIndex: 1n });
    badProof({ ...same, historyPath: [m.ZERO32] });
    badProof({ ...same, messageCount: 2n });
    badProof({ ...same, sccpRoot: older.header.sccpRoot });
    const leaves = older.leaves.map((item) => item.leaf);
    const root = older.header.sccpRoot;
    assert.throws(() => m.checkLeaf(leaves[0], 0, 3n, Array(10).fill(m.ZERO32), root), /BadProof/);
    assert.throws(() => m.checkLeaf(leaves[0], 1, 3n, m.merklePath(leaves, 0), root), /BadProof/);
    assert.throws(() => m.merkleRootFromPath(leaves[0], 3, 3n, []), /BadProof/);
    assert.equal(m.historyRoot([]), m.ZERO32);
    // A model control leaf is the leaf of its fields, whatever they are.
    const fields = controlFields(CONTROL.spec_examples[0]);
    assert.equal(taira.control(fields).leaf, CONTROL.spec_examples[0].leaf);
    assert.deepEqual(taira.recordedControl(m.ZERO32, fields), { kind: "control", leaf: m.ZERO32, control: fields });
  });

  it("builds calldata, expected logs and probes of fixture steps", () => {
    const scenario = EVM_SCENARIOS.find((entry) => entry.name === "finalize_proofs_cap_and_voids");
    const pool = TRANSITIONS.certificates;
    const names = new Set();
    for (const step of scenario.steps) {
      if (step.call === "views") continue;
      const [name, args] = r.stepCall(step, pool);
      names.add(name);
      const data = r.PRODUCTION.encode(name, args);
      assert.equal(ethers.dataSlice(data, 0, 4), TRANSITIONS.selectors[name].selector, name);
      const decoded = m.iface.decodeFunctionData(name, data);
      assert.equal(m.iface.encodeFunctionData(name, decoded), data, `${name}: canonical`);
      if (step.proof && ["ok", "BadProof"].includes(step.expected.outcome)) {
        assert.equal(r.modelProofVerdict(step, pool, scenario.deployment), step.expected.outcome, name);
      }
    }
    for (const name of ["finalizeFromTaira", "finalizeFromCheckpoint", "voidExpiredFromCheckpoint", "voidFrozen"]) {
      assert(names.has(name), `the scenario calls ${name}`);
    }
    assert.throws(() => r.stepCall({ call: "unknownCall" }, pool), /unknown fixture call/);
    assert.throws(() => r.stepCall({ call: "submitCheckpoints", certificates: ["c999"] }, pool), /c999 is in the pool/);
    const finalized = scenario.steps.find((step) => step.expected.return !== undefined);
    const logs = r.expectedLogs(finalized.expected.events, pool);
    assert.equal(logs.transfers.length, 1);
    assert.equal(logs.sccp.at(-1).topics[0], TRANSITIONS.event_topics.SccpFinalized.topic0);
    assert.equal(logs.sccp.at(-1).topics[1], finalized.expected.return);
    assert.throws(() => r.expectedLogs([{ event: "UnknownEvent" }], pool), /unknown fixture event/);
    const probes = r.scenarioProbes(scenario, pool);
    for (const step of scenario.steps) {
      for (const checkpoint of step.state_after.checkpoints) assert(probes.heights.includes(BigInt(checkpoint.height)));
      for (const nonce of step.state_after.consumed) assert(probes.nonces.includes(BigInt(nonce)));
    }
    assert.equal(r.isProfileIndependent(scenario), false);
    assert.equal(r.isProfileIndependent(EVM_SCENARIOS[0]), true);
    assert.equal(r.addressOfWord(CONTEXT.destination_word), ethers.getAddress(`0x${"22".repeat(20)}`));
    assert.throws(() => r.addressOfWord(`0x${"35".repeat(32)}`), /an EVM destination word/);
    // The deployment time: one second before the first step, or the last second the pin admits.
    assert.equal(r.deploymentTime(1_801_209_600_000n, 1_800_000_060_000n), 1_800_000_059n);
    assert.equal(r.deploymentTime(1_801_209_600_000n, 1_801_209_600_000n), 1_801_209_599n);
    assert.equal(r.deploymentTime(1_801_209_600_001n, 1_801_209_700_000n), 1_801_209_600n);
    assert.throws(() => r.deploymentTime(1_810_000_000_000n, 1_800_000_060_000n), /constructor bound/);
  });

  it("patches the parliamentPaused word of a control call, and only that word", () => {
    const step = CONTROL_SCENARIOS[0].steps.find((entry) => entry.call === "applyControl");
    const [name, args] = r.stepCall(step, CONTROL.certificates);
    const data = m.iface.encodeFunctionData(name, args);
    const patched = ethers.getBytes(r.withRawParliamentPaused(data, 2));
    const differing = [];
    ethers.getBytes(data).forEach((byte, index) => {
      if (byte !== patched[index]) differing.push(index);
    });
    assert.equal(patched.length, ethers.dataLength(data));
    assert.equal(differing.length, 1, "one byte differs");
    assert.equal(patched[differing[0]], 2, "the bool word holds 2");
    assert.equal((differing[0] - 4) % 32, 31, "the last byte of an ABI word");
    assert.equal(r.withRawParliamentPaused(data, step.proof.parliamentPaused ? 1 : 0), data);
    // The word is the flag: writing the other boolean flips exactly `parliamentPaused`.
    const other = r.withRawParliamentPaused(data, step.proof.parliamentPaused ? 0 : 1);
    const flipped = m.iface.decodeFunctionData(name, other);
    assert.equal(flipped[1].parliamentPaused, !step.proof.parliamentPaused);
    assert.equal(flipped[1].controlNonce, BigInt(step.proof.controlNonce));
    assert.throws(() => r.controlProofArg({ ...step.proof, parliamentPaused: 2 }), /bool on the EVM interface/);
  });

  it("counts calldata gas, renders fixture integers and keeps a ledger of executed rows", () => {
    assert.deepEqual(h.calldataCost("0x00ff0001"), {
      bytes: 4,
      zeroBytes: 2,
      nonzeroBytes: 2,
      intrinsic: 21_040,
      floor: 21_100,
    });
    assert.equal(h.jsonInteger(9_007_199_254_740_991n), 9_007_199_254_740_991);
    assert.equal(h.jsonInteger(9_007_199_254_740_992n), "9007199254740992");
    assert.deepEqual(h.decodeRevert("0x"), { name: null, args: [] });
    assert.deepEqual(h.decodeRevert(m.iface.encodeErrorResult("BadNonce", [7])), { name: "BadNonce", args: [7n] });
    assert.throws(() => h.decodeRevert("0xdeadbeef"), /no declared error/);
    assert.equal(h.describeRevert("0x"), "empty revert data");
    assert.equal(h.describeRevert(m.iface.encodeErrorResult("AlreadyConsumed", [3])), "AlreadyConsumed(3)");
    assert.equal(h.describeRevert("0xdeadbeef"), "undeclared revert data 0xdeadbeef");
    const ledger = new r.Ledger();
    ledger.ran("group", "b");
    ledger.ran("group", "a");
    assert.deepEqual(ledger.rows("group"), ["a", "b"]);
    assert.deepEqual(ledger.rows("other"), []);
    assert.deepEqual(ledger.counts(), { group: 2 });
    assert.throws(() => ledger.ran("group", "a"), /ran twice/);
    const words = h.immutableWords(h.deploymentOf(EVM_SCENARIOS[0].deployment));
    const referenced = new Set(h.loadArtifacts().immutableReferences.map((entry) => entry.name));
    assert.deepEqual(Object.keys(words).sort(), [...referenced].sort(), "the nine §5.2.3 immutables");
    for (const value of Object.values(words)) assert.equal(ethers.dataLength(value), 32);
  });

  it("compiles the dirty-memory harness with the locked settings, within the code-size limit", () => {
    const build = r.dirtyHarnessBuild();
    assert.equal(r.dirtyHarnessBuild(), build, "one build per set of sources");
    assert(build.runtimeBytes > ethers.dataLength(h.loadArtifacts().runtimeTemplate), "the harness adds entry points");
    assert(build.runtimeBytes <= 24_576);
    for (const [entryPoint, dirty] of Object.entries(r.DIRTY_ENTRY_POINTS)) {
      const inputs = (fragment) => fragment.inputs.map((input) => input.format("sighash"));
      assert.deepEqual(
        inputs(build.iface.getFunction(dirty)),
        [...inputs(m.iface.getFunction(entryPoint)), "uint256", "bytes32"],
        `${dirty} takes the arguments of ${entryPoint}, then the fill`,
      );
    }
    const target = r.dirtyTarget(...r.DIRTY_FILLS[0]);
    const selectorOf = (data) => ethers.dataSlice(data, 0, 4);
    assert.equal(selectorOf(target.encode("voidFrozen", [0, 1])), TRANSITIONS.selectors.voidFrozen.selector);
    assert.equal(
      selectorOf(target.encode("submitCheckpoints", [[]])),
      build.iface.getFunction("dirtySubmitCheckpoints").selector,
    );
    const inherited = r.inheritedTarget();
    assert.equal(inherited.creation, build.creation);
    const submit = TRANSITIONS.selectors.submitCheckpoints.selector;
    assert.equal(selectorOf(inherited.encode("submitCheckpoints", [[]])), submit);
    // Every fill covers the memory of the largest batch, so that no buffer starts from zero bytes.
    for (const [words, fill] of r.DIRTY_FILLS) {
      assert(words >= 4096, "a fill covers at least 4 096 words");
      assert.notEqual(fill, m.ZERO32);
    }
  });
});

// ---------------------------------------------------------------------------
// The replay driver itself
// ---------------------------------------------------------------------------

const eventOf = (step, name) => step.expected.events.find((event) => event.event === name);
const lastStep = (scenario) => scenario.steps.at(-1);

/**
 * Changes to a recorded scenario that a replay must refuse: what is wrong, the
 * scenario, the change, and the failure it must give.
 */
const WRONG_SCENARIO_RECORDS = Object.freeze([
  {
    what: "the initial state",
    scenario: "initial_pin",
    change: (s) => { s.initial_state.committee.high += 1; },
    failure: /initial state/,
  },
  {
    what: "a view",
    scenario: "initial_pin",
    change: (s) => { s.steps[0].expected.opCount += 1; },
    failure: /step 0 \(views\): views/,
  },
  {
    what: "the pinned committee in a view",
    scenario: "initial_pin",
    change: (s) => { s.steps[0].expected.initialCommittee.start += 1; },
    failure: /step 0 \(views\): views/,
  },
  {
    what: "high after a checkpoint",
    scenario: "checkpoint_raises_high",
    change: (s) => { s.steps[0].state_after.committee.high += 1; },
    failure: /state after/,
  },
  {
    what: "a stored checkpoint",
    scenario: "checkpoint_raises_high",
    change: (s) => { lastStep(s).state_after.checkpoints.pop(); },
    failure: /state after/,
  },
  {
    what: "a checkpoint id",
    scenario: "checkpoint_raises_high",
    change: (s) => { s.steps[0].state_after.checkpoints[0].id = m.word(1); },
    failure: /state after/,
  },
  {
    what: "untilMs after a rotation",
    scenario: "rotation_key_change",
    change: (s) => { s.steps[0].state_after.committee.until_ms += 1; },
    failure: /state after/,
  },
  {
    what: "the latch",
    scenario: "latch_inside_batch",
    change: (s) => { s.steps[0].state_after.equivocated = false; },
    failure: /state after/,
  },
  {
    what: "Live",
    scenario: "expiry_then_refusal_then_void_frozen",
    change: (s) => { lastStep(s).state_after.live = true; },
    failure: /state after/,
  },
  {
    what: "a consumed nonce",
    scenario: "finalize_proofs_cap_and_voids",
    change: (s) => { lastStep(s).state_after.consumed.pop(); },
    failure: /state after/,
  },
  {
    what: "the supply",
    scenario: "finalize_proofs_cap_and_voids",
    change: (s) => { lastStep(s).state_after.total_supply = "1"; },
    failure: /state after/,
  },
  {
    what: "opCount",
    scenario: "finalize_proofs_cap_and_voids",
    change: (s) => { lastStep(s).state_after.op_count += 1; },
    failure: /state after/,
  },
  {
    what: "the effective pause",
    scenario: "pause_then_resume",
    change: (s) => { s.steps[0].state_after.pause.effective = !s.steps[0].state_after.pause.effective; },
    failure: /state after/,
  },
  {
    what: "the stored fast-pause expiry",
    scenario: "max_fast_pause_clamp",
    change: (s) => { s.steps[0].state_after.pause.fast_pause_until_ms += 1; },
    failure: /state after/,
  },
  {
    what: "the control nonce",
    scenario: "stale_equal_and_gap_nonces",
    change: (s) => { s.steps[0].state_after.pause.control_nonce += 1; },
    failure: /state after/,
  },
  {
    what: "success of a refused call",
    scenario: "old_generations_refused",
    change: (s) => { s.steps[1].expected.outcome = "ok"; },
    failure: /reverted with CommitteeNotAccepted\(\)/,
  },
  {
    what: "another error",
    scenario: "old_generations_refused",
    change: (s) => { s.steps[1].expected.outcome = "BadCommittee"; },
    failure: /CommitteeNotAccepted\(\)/,
  },
  {
    what: "an error of a successful call",
    scenario: "checkpoint_raises_high",
    change: (s) => { s.steps[0].expected = { outcome: "NothingToDo", events: [] }; },
    failure: /expected NothingToDo, but the call succeeded/,
  },
  {
    what: "an error argument",
    scenario: "expiry_then_refusal_then_void_frozen",
    change: (s) => { s.steps.find((step) => step.expected.error_args).expected.error_args.nonce += 1; },
    failure: /arguments of AlreadyConsumed/,
  },
  {
    what: "a missing error argument",
    scenario: "expiry_then_refusal_then_void_frozen",
    change: (s) => { delete s.steps.find((step) => step.expected.error_args).expected.error_args; },
    failure: /names every argument/,
  },
  {
    what: "a missing event",
    scenario: "checkpoint_raises_high",
    change: (s) => { s.steps[0].expected.events.pop(); },
    failure: /SCCP logs/,
  },
  {
    what: "the event order",
    scenario: "checkpoint_raises_high",
    change: (s) => { s.steps[0].expected.events.reverse(); },
    failure: /SCCP logs/,
  },
  {
    what: "an event field",
    scenario: "rotation_key_change",
    change: (s) => { eventOf(s.steps[0], "SccpCommitteeRotated").startHeight += 1; },
    failure: /SCCP logs/,
  },
  {
    what: "the published certificate",
    scenario: "sixteen_batched_rotations",
    change: (s) => {
      const published = s.steps[0].expected.events.filter((event) => event.event === "SccpCertificate");
      [published[0].certificate, published[1].certificate] = [published[1].certificate, published[0].certificate];
    },
    failure: /SCCP logs/,
  },
  {
    what: "the latch reason",
    scenario: "latch_inside_batch",
    change: (s) => { eventOf(s.steps[0], "SccpLatched").reason ^= 3; },
    failure: /SCCP logs/,
  },
  {
    what: "a minted amount",
    scenario: "finalize_proofs_cap_and_voids",
    change: (s) => { eventOf(s.steps[0], "SccpFinalized").tokenAmount = "1"; },
    failure: /SCCP logs/,
  },
  {
    what: "a voided nonce",
    scenario: "expiry_then_refusal_then_void_frozen",
    change: (s) => {
      const voided = s.steps.find((step) => step.call === "voidFrozen" && step.expected.outcome === "ok");
      eventOf(voided, "SccpVoided").nonce += 1;
    },
    failure: /SCCP logs/,
  },
  {
    what: "a control flag",
    scenario: "pause_then_resume",
    change: (s) => {
      const applied = eventOf(s.steps[0], "SccpControlApplied");
      applied.parliamentPaused = !applied.parliamentPaused;
    },
    failure: /SCCP logs/,
  },
  {
    what: "the return value",
    scenario: "finalize_proofs_cap_and_voids",
    change: (s) => { s.steps[0].expected.return = m.ZERO32; },
    failure: /return value/,
  },
  {
    what: "a time that decreases",
    scenario: "checkpoint_raises_high",
    change: (s) => { lastStep(s).now_ms = s.steps[0].now_ms - 1000; },
    failure: /now_ms never decreases/,
  },
  {
    what: "a sub-second time",
    scenario: "checkpoint_raises_high",
    change: (s) => { s.steps[0].now_ms += 1; },
    failure: /now_ms is a whole second/,
  },
]);

describe(`SCCP v1 fixtures: a replay refuses a row that records something else (${HARDFORKS[0]})`, () => {
  const hardfork = HARDFORKS[0];
  const recorded = (name) => {
    const transition = EVM_SCENARIOS.find((scenario) => scenario.name === name);
    const scenario = transition ?? CONTROL_SCENARIOS.find((entry) => entry.name === name);
    assert(scenario, `scenario ${name} exists`);
    return { scenario: structuredClone(scenario), pool: transition ? TRANSITIONS.certificates : CONTROL.certificates };
  };

  it("a scenario with another state, outcome, argument, log, return value or time", async () => {
    for (const { what, scenario: name, change, failure } of WRONG_SCENARIO_RECORDS) {
      const { scenario, pool } = recorded(name);
      const original = JSON.stringify(scenario);
      change(scenario);
      assert.notEqual(JSON.stringify(scenario), original, `${what}: the record changed`);
      await assert.rejects(
        r.replayScenario({ hardfork, profile: ETHEREUM, scenario, pool, source: "changed" }),
        (error) => error instanceof assert.AssertionError && failure.test(error.message),
        `a replay must refuse ${what} of ${name}`,
      );
    }
  });

  it("a certificate or header row with another outcome or checkpoint id", async () => {
    const replay = (row) => r.replayCertificateRow({ hardfork, profile: ETHEREUM, context: CONTEXT, row });
    const positive = FINALITY.certificates.find((row) => row.label === "key_change_rotation");
    const negative = FINALITY.negative_certificates.find((row) => row.label === "sigma_zero");
    const wrongOutcome = { ...positive, expected: { evm: "BadSignature" } };
    await assert.rejects(replay(wrongOutcome), /expected BadSignature, but the call succeeded/);
    await assert.rejects(replay({ ...positive, checkpoint_id: m.ZERO32 }), /checkpoint id/);
    await assert.rejects(replay({ ...negative, expected: { evm: "BadCommittee" } }), /BadSignature\(\)/);
    await assert.rejects(replay({ ...negative, expected: { evm: "ok" } }), /reverted with BadSignature\(\)/);
    await assert.rejects(replay({ ...negative, expected: { evm: null } }), /the row has an EVM outcome/);
    const base = FINALITY.certificates.find((row) => row.label === "n4_lowest_q");
    const header = (row) => r.replayHeaderRow({ hardfork, profile: ETHEREUM, context: CONTEXT, base, row });
    const valid = FINALITY.headers.valid.find((row) => row.label === "rotation");
    const invalid = FINALITY.headers.invalid.find((row) => row.label === "rotation_validity_zero");
    await assert.rejects(header({ ...valid, destination: "BadHeader" }), /BadCommittee\(\)/);
    await assert.rejects(header({ ...invalid, destination: "accept" }), /BadHeader\(\)/);
    // A scenario with leaves is bound to its own network.
    const scenario = EVM_SCENARIOS.find((entry) => !r.isProfileIndependent(entry));
    await assert.rejects(
      r.replayScenario({ hardfork, profile: BSC, scenario, pool: TRANSITIONS.certificates, source: "bound" }),
      /binds ethereum and cannot run on bsc/,
    );
  });
});

// ---------------------------------------------------------------------------
// The contract on EDR
// ---------------------------------------------------------------------------

for (const hardfork of HARDFORKS) {
  describe(`SCCP v1 fixtures on EDR (${hardfork})`, () => {
    const ledger = new r.Ledger();

    // -- deployment ---------------------------------------------------------

    for (const profile of [ETHEREUM, BSC]) {
      it(`creates the destination through SCCP_EVM_DEPLOYER at its CREATE2 address on ${profile.name}`, async () => {
        const chain = await h.Chain.open(profile, { hardfork, allowBlocksWithSameTimestamp: true });
        try {
          const fixture = EVM_SCENARIOS[0].deployment;
          const { pin } = fixture;
          const deployment = h.deploymentOf(fixture, profile);
          const { destination, receipt, address, init } = await h.deploy(chain, deployment, { at: T0 });
          const code = () => chain.rpc("eth_getCode", [address, "latest"]);
          assert.equal(address, m.create2Address(init));
          assert.equal(ethers.getAddress(await chain.returnData(receipt)), address, "the proxy returns the address");
          assert.equal(receipt.logs.length, 0);
          assert.equal(
            await code(),
            h.expectedRuntime(h.immutableWords(deployment)),
            "the runtime is the locked template with the nine immutables",
          );
          assert.deepEqual(await destination.state(), r.initialState(pin, T0 * 1000n));
          assert.equal(await destination.view("tairaNetworkId"), fixture.taira_network_id);
          assert.equal(await destination.view("consensusInstance"), fixture.consensus_instance);
          assert.equal(await destination.view("routeRevision"), BigInt(fixture.route_revision));
          assert.equal(await destination.view("maxWrappedSupply"), BigInt(fixture.max_wrapped_supply));
          assert.equal(await destination.view("maxValidityMs"), m.MAX_VALIDITY_MS);
          assert.deepEqual(
            [...(await destination.view("initialCommittee"))],
            [BigInt(pin.generation), pin.committee_root, BigInt(pin.start_height), BigInt(pin.until_ms)],
          );
          // The same arguments cannot create a second contract: CREATE2 fails and the proxy reverts.
          const again = await chain.attempt({ to: m.SCCP_EVM_DEPLOYER, data: deployerCalldata(init) });
          assertRevert(again, null, "a second deployment");
          // Arguments of the other profile are refused by the constructor on this chain.
          const foreign = h.deploymentOf(fixture, profile === ETHEREUM ? BSC : ETHEREUM);
          const foreignInit = h.initCode(foreign);
          assertRevert(await h.createDirectly(chain, foreign), "WrongChain", "a foreign network tag");
          const viaProxy = await chain.attempt({ to: m.SCCP_EVM_DEPLOYER, data: deployerCalldata(foreignInit) });
          assertRevert(viaProxy, null, "a foreign network tag through the proxy");
          assert.equal(await chain.rpc("eth_getCode", [m.create2Address(foreignInit), "latest"]), "0x");
          // The copy at the fixtures' destination word keeps code and state.
          const copy = await h.relocate(destination, r.addressOfWord(fixture.destination_word));
          assert.equal(copy.address, ethers.getAddress(`0x${"22".repeat(20)}`));
          assert.deepEqual(await copy.state(), await destination.state());
          assert.equal(await chain.rpc("eth_getCode", [copy.address, "latest"]), await code());
        } finally {
          await chain.close();
        }
      });

      it(`applies the deployment bound on the pinned untilMs on ${profile.name} (init_bounds)`, async () => {
        const fixture = EVM_SCENARIOS[0].deployment;
        for (const row of TRANSITIONS.init_bounds) {
          const where = `${profile.name} init_bounds ${row.label}`;
          const pin = { ...fixture.pin, until_ms: row.until_ms };
          const deployment = h.deploymentOf({ ...fixture, pin }, profile);
          const [nowMs, untilMs] = [BigInt(row.now_ms), BigInt(row.until_ms)];
          assert.equal(nowMs % 1000n, 0n, where);
          const inBound = untilMs > nowMs && untilMs - nowMs <= m.MAX_VALIDITY_MS + m.MAX_INIT_SLACK_MS;
          assert.equal(row.expected, inBound ? "ok" : "BadConfig", `${where}: the bound of §5.1.2`);
          const at = nowMs / 1000n;
          const chain = await h.Chain.open(profile, { hardfork, allowBlocksWithSameTimestamp: true });
          try {
            if (row.expected === "ok") {
              const { destination } = await h.deploy(chain, deployment, { at });
              assert.deepEqual(await destination.state(), r.initialState(pin, row.now_ms), where);
              assert.equal((await destination.view("initialCommittee"))[3], untilMs, where);
            } else {
              // The constructor's own error, then the same init code through the proxy.
              assertRevert(await h.createDirectly(chain, deployment, { at }), row.expected, where);
              const init = h.initCode(deployment);
              await chain.installDeployer();
              const viaProxy = await chain.attempt({ to: m.SCCP_EVM_DEPLOYER, data: deployerCalldata(init), at });
              assertRevert(viaProxy, null, `${where} through the proxy`);
              assert.equal(await chain.rpc("eth_getCode", [m.create2Address(init), "latest"]), "0x", where);
            }
          } finally {
            await chain.close();
          }
          ledger.ran(`${profile.name}/transitions.init_bounds`, row.label);
        }
      });
    }

    // -- finality_v1.json and finality_rust_v1.json -----------------------------

    for (const [group, rows] of CERTIFICATE_GROUPS) {
      for (const row of withEvmForm(rows)) {
        it(`${group} ${row.label}: ${row.expected.evm}`, async () => {
          const gasLabel = `submitCheckpoints 1 certificate (${group} ${row.label})`;
          await r.replayCertificateRow({
            hardfork,
            profile: ETHEREUM,
            context: CONTEXT,
            row,
            gasLabel: row.expected.evm === "ok" ? gasLabel : undefined,
          });
          ledger.ran(`ethereum/${group}`, row.label);
        });
      }

      it(`${group}: the same outcomes under the BSC profile`, async () => {
        for (const row of withEvmForm(rows)) {
          await r.replayCertificateRow({ hardfork, profile: BSC, context: CONTEXT, row });
          ledger.ran(`bsc/${group}`, row.label);
        }
      });

      it(`${group}: the same outcomes when verification starts on dirty memory`, async () => {
        for (const [index, row] of withEvmForm(rows).entries()) {
          const target = r.dirtyTarget(...r.DIRTY_FILLS[index % r.DIRTY_FILLS.length]);
          await r.replayCertificateRow({ hardfork, profile: ETHEREUM, context: CONTEXT, row, target });
          ledger.ran(`dirty/${group}`, row.label);
        }
      });
    }

    it("finality.certificates: a build that reads unwritten memory passes on fresh memory only", async () => {
      // The planted defect: hash-to-G2 without its two Z_pad writes (§3.8 step 8) reads that block
      // from whatever the memory held. Through the production entry points the block is still zero
      // and every certificate verifies; only the dirty-memory entry points show the defect, under
      // every fill and for n = 4, 7 and 31.
      const library = fs.readFileSync(path.join(REPO, LIBRARY_SOURCE), "utf8");
      assert.equal((library.match(Z_PAD_WRITES) ?? []).length, 1, "the library writes Z_pad once, in the pinned form");
      const defective = r.dirtyHarnessBuild({ [LIBRARY_SOURCE]: library.replace(Z_PAD_WRITES, "") });
      const sizes = new Set();
      for (const row of FINALITY.certificates) {
        const replay = (target) =>
          r.replayCertificateRow({ hardfork, profile: ETHEREUM, context: CONTEXT, row, target });
        await replay(r.inheritedTarget(defective));
        for (const [words, fill] of r.DIRTY_FILLS) {
          await assert.rejects(
            replay(r.dirtyTarget(words, fill, defective)),
            /reverted with BadSignature\(\)/,
            `${row.label}: ${words} words of ${fill} reach the unwritten block`,
          );
        }
        sizes.add(FINALITY.committees[row.committee].n);
      }
      assert.deepEqual([...sizes].sort((a, b) => a - b), [4, 7, 31]);
    });

    it("finality.certificates n4_lowest_q: published the same when a contract relays the call", async () => {
      const row = FINALITY.certificates.find((entry) => entry.label === "n4_lowest_q");
      const now = BigInt(row.now_ms) / 1000n;
      const { chain, destination } = await r.openDestination({
        hardfork,
        profile: ETHEREUM,
        deployment: r.certificateRowDeployment(CONTEXT, row.pin, ETHEREUM),
        at: now - 2n,
      });
      try {
        const forwarder = await h.deployForwarder(chain, destination.address);
        const data = m.iface.encodeFunctionData("submitCheckpoints", [[r.certificateArg(row.evm)]]);
        const receipt = await chain.send({ to: forwarder, data, at: now });
        const header = m.parseHeader(row.evm.header);
        const events = [
          { event: "SccpCertificate", certificate: "row", height: header.height, generation: header.generation },
          { event: "SccpCheckpointed", height: header.height, header: row.checkpoint_id },
        ];
        r.assertLogs(destination, receipt, r.expectedLogs(events, { row }), "a relayed certificate");
        assert.equal(await destination.view("checkpointHeader", [header.height]), row.checkpoint_id);
        // A relayed failure carries the destination's error through the forwarder.
        await h.expectRevert(chain.send({ to: forwarder, data }), "NothingToDo");
      } finally {
        await chain.close();
      }
    });

    for (const group of ["valid", "invalid"]) {
      it(`finality.headers.${group}: a certificate that carries the header answers as the row records`, async () => {
        const base = FINALITY.certificates.find((entry) => entry.label === "n4_lowest_q");
        for (const row of FINALITY.headers[group]) {
          await r.replayHeaderRow({ hardfork, profile: ETHEREUM, context: CONTEXT, base, row });
          ledger.ran(`ethereum/finality.headers.${group}`, row.label);
        }
      });
    }

    // -- committee_transitions_v1.json and control_v1.json scenarios -----------

    const scenarioGroups = [
      ["transitions", EVM_SCENARIOS, TRANSITIONS.certificates],
      ["control", CONTROL_SCENARIOS, CONTROL.certificates],
    ];

    for (const [source, scenarios, pool] of scenarioGroups) {
      for (const scenario of scenarios) {
        it(`${source} scenario ${scenario.name} (${scenario.steps.length} steps)`, async () => {
          await r.replayScenario({
            hardfork,
            profile: ETHEREUM,
            scenario,
            pool,
            source,
            onStep: (index) => ledger.ran(`ethereum/${source}.steps`, `${scenario.name}#${index}`),
          });
        });
      }

      it(`${source} scenarios: the same steps when verification starts on dirty memory`, async () => {
        for (const [index, scenario] of scenarios.entries()) {
          await r.replayScenario({
            hardfork,
            profile: ETHEREUM,
            scenario,
            pool,
            source,
            target: r.dirtyTarget(...r.DIRTY_FILLS[index % r.DIRTY_FILLS.length]),
            onStep: (step) => ledger.ran(`dirty/${source}.steps`, `${scenario.name}#${step}`),
          });
        }
      });
    }

    it("transitions scenarios without leaves: the same steps under the BSC profile", async () => {
      for (const scenario of PORTABLE_SCENARIOS) {
        await r.replayScenario({
          hardfork,
          profile: BSC,
          scenario,
          pool: TRANSITIONS.certificates,
          source: "transitions",
          onStep: (index) => ledger.ran("bsc/transitions.steps", `${scenario.name}#${index}`),
        });
      }
    });

    // -- certificates the model mints -------------------------------------------

    for (const profile of [ETHEREUM, BSC]) {
      it(`a history the model mints verifies on ${profile.name}: rotations and a history proof`, async () => {
        const { chain, destination, taira } = await modelDestination({ hardfork, profile });
        try {
          const first = taira.current.committee;
          const second = m.committee("M2", MODEL_COMMITTEE_KEYS.map((index) => index + 4));
          const recipient = ethers.getAddress(chain.accounts[7]);
          const ms = (seconds) => seconds * 1000n;
          const amount = 3n * UNIT;
          const deadlineMs = ms(T0 + 3600n);
          const transfers = [0, 1].map((nonce) => taira.transfer({ nonce, amount, deadlineMs, recipient }));
          const carrying = taira.block(1010n, ms(T0 + 10n), [transfers[0]]);
          const heartbeat = taira.block(1020n, ms(T0 + 20n), [], { rotate: "heartbeat" });
          const halved = VALIDITY_MS / 2n;
          const handoff = { rotate: "key", nextCommittee: second, validityMs: halved };
          const keyChange = taira.block(1030n, ms(T0 + 30n), [], handoff);
          taira.block(1035n, ms(T0 + 35n), [transfers[1]]);
          const later = taira.block(1040n, ms(T0 + 40n), []);
          const producers = [carrying, heartbeat, keyChange, later].map((block) => block.committee);
          assert.deepEqual(producers, [first, first, first, second]);
          const submit = (certificates) =>
            m.iface.encodeFunctionData("submitCheckpoints", [certificates.map(r.certificateArg)]);
          const pool = {};
          const certified = (id, block, options) => {
            pool[id] = { evm: taira.certify(block, options) };
            return pool[id].evm;
          };
          const published = publishedAndStored;
          // A PrepareQC and a signature under another hash domain are refused at the pairing check.
          const otherDomain = FINALITY.negative_certificates.find((row) => row.label === "wrong_dst").dst;
          for (const options of [{ kind: 0x02 }, { dst: otherDomain }]) {
            const refused = await destination.attempt(submit([taira.certify(carrying, options)]), { at: T0 + 50n });
            assertRevert(refused, "BadSignature", `${profile.name}: signed with ${JSON.stringify(options)}`);
          }
          // A scattered quorum of the pinned committee.
          const scattered = certified("carrying", carrying, { signerIndices: [0, 1, 3] });
          let receipt = await destination.raw(submit([scattered]), { at: T0 + 100n });
          const checkpointed = r.expectedLogs(published("carrying", carrying), pool);
          r.assertLogs(destination, receipt, checkpointed, "a scattered quorum");
          assert.equal(chain.nowMs(), ms(T0 + 100n));
          // The stored X under another result body and other signers: the cheap path, nothing to do.
          const sameHeader = taira.certify(carrying, { bodyTag: "0x01", signerIndices: [1, 2, 3] });
          assert.notEqual(sameHeader.qc, pool.carrying.evm.qc);
          assertRevert(await destination.attempt(submit([sameHeader])), "NothingToDo", `${profile.name}: a stored X`);
          // A heartbeat and a key change in one batch: §5.1.2 gives each successor its deadline.
          const batch = [certified("heartbeat", heartbeat), certified("keyChange", keyChange)];
          receipt = await destination.raw(submit(batch), { at: T0 + 200n });
          const rotated = (generation, root, untilMs, startHeight) => ({
            event: "SccpCommitteeRotated",
            generation,
            root,
            untilMs,
            startHeight,
          });
          const events = [
            ...published("heartbeat", heartbeat),
            rotated(6, first.root, ms(T0 + 20n) + VALIDITY_MS, 1021),
            ...published("keyChange", keyChange),
            rotated(7, second.root, ms(T0 + 30n) + halved, 1031),
          ];
          r.assertLogs(destination, receipt, r.expectedLogs(events, pool), "two rotations");
          assert.deepEqual((await destination.state()).committee, {
            generation: 7,
            high: 1030,
            root: second.root,
            start: 1031,
            until_ms: h.jsonInteger(ms(T0 + 30n) + halved),
          });
          // The new committee certifies; the retired one is refused for the same header.
          const retired = m.buildCertificate({
            committee: first,
            header: later.x,
            instance: taira.instance,
            ...taira.qcFields(later.height, later.x),
          });
          assertRevert(await destination.attempt(submit([retired])), "BadCommittee", `${profile.name}: retired keys`);
          await destination.raw(submit([certified("later", later)]), { at: T0 + 300n });
          // The transfer of generation 5 is proven under the checkpoint of generation 7, through the history.
          const proof = taira.messageProof(1010n, 0, later);
          assert.equal(proof.block.historyPath.length, 1);
          const args = [[later.x], r.messageProofArg(proof)];
          assert.equal(await destination.simulate("finalizeFromCheckpoint", args), transfers[0].messageId);
          receipt = await destination.tx("finalizeFromCheckpoint", args);
          const [finalized] = destination.events(receipt, "SccpFinalized");
          assert.deepEqual([...finalized.parsed.args], [transfers[0].messageId, 0n, recipient, amount]);
          assert.equal(await destination.view("balanceOf", [recipient]), amount);
          const state = await destination.state({ heights: [1010n, 1020n, 1030n, 1035n, 1040n], nonces: [0n, 1n] });
          assert.deepEqual(state.checkpoints.map((checkpoint) => checkpoint.height), [1010, 1020, 1030, 1040]);
          assert.deepEqual([state.consumed, state.op_count, state.total_supply], [[0], 1, amount.toString()]);
          // §5.1.5: the certified block itself is referenced with index 0 and no history path.
          const last = taira.block(1050n, ms(T0 + 50n), [taira.transfer({ nonce: 2, amount, deadlineMs, recipient })]);
          const own = taira.messageProof(1050n, 0, last);
          const genuine = taira.certify(last);
          const inline = (certificate, messageProof) => {
            const args = [r.certificateArg(certificate), r.messageProofArg(messageProof)];
            return m.iface.encodeFunctionData("finalizeFromTaira", args);
          };
          for (const reference of [{ historyIndex: 1n }, { historyPath: [m.ZERO32] }]) {
            const withHistory = { ...own, block: { ...own.block, ...reference } };
            const refused = await destination.attempt(inline(genuine, withHistory));
            assertRevert(refused, "BadProof", `${profile.name}: same height, with ${Object.keys(reference)}`);
          }
          // §5.1.2: an inline entry point obtains X before it checks Live. After the deadline of
          // generation 7, a certificate that does not verify is refused for its signature and a
          // genuine one because the destination has expired; neither stores its checkpoint.
          const expired = (ms(T0 + 30n) + halved) / 1000n + 1n;
          const unsigned = await destination.attempt(inline(taira.certify(last, { kind: 0x02 }), own), { at: expired });
          assertRevert(unsigned, "BadSignature", `${profile.name}: an unverifiable inline certificate, after expiry`);
          const late = await destination.attempt(inline(genuine, own), { at: expired });
          assertRevert(late, "CommitteeNotAccepted", `${profile.name}: a genuine inline certificate, after expiry`);
          assert.equal(await destination.view("checkpointHeader", [1050n]), m.ZERO32);
          assert.equal((await destination.state()).live, false);
        } finally {
          await chain.close();
        }
      });
    }

    it("a batch of 16 certificates of an n = 31 committee verifies on fresh and on dirty memory", async () => {
      const batch = largeBatch();
      const [words, fill] = r.DIRTY_FILLS[2];
      for (const target of [r.PRODUCTION, r.dirtyTarget(words, fill)]) {
        const where = `${target.name}: 16 certificates of n = 31`;
        const { chain, destination } = await modelDestination({
          hardfork,
          profile: ETHEREUM,
          signedBy: batch.signedBy,
          target,
        });
        try {
          const certificates = batch.certificates.map(r.certificateArg);
          const tooMany = target.encode("submitCheckpoints", [[...certificates, certificates[0]]]);
          assertRevert(await destination.attempt(tooMany), "TooManyCertificates", `${where}, and one more`);
          const data = target.encode("submitCheckpoints", [certificates]);
          const outcome = await destination.attempt(data, { at: T0 + 100n });
          assert(outcome.receipt, `${where}: reverted with ${outcome.revert && h.describeRevert(outcome.revert)}`);
          const pool = Object.fromEntries(batch.certificates.map((evm, index) => [`c${index}`, { evm }]));
          const events = batch.blocks.flatMap((block, index) => publishedAndStored(`c${index}`, block));
          r.assertLogs(destination, outcome.receipt, r.expectedLogs(events, pool), where);
          const heights = batch.blocks.map((block) => block.height);
          const state = await destination.state({ heights: [heights[0] - 1n, ...heights, heights.at(-1) + 1n] });
          assert.deepEqual(state.checkpoints.map((checkpoint) => BigInt(checkpoint.height)), heights, where);
          assert.equal(BigInt(state.committee.high), heights.at(-1), where);
          assert.equal(state.op_count, 0, `${where}: checkpoints are not counted`);
          if (target === r.PRODUCTION) {
            h.recordGas(chain, "submitCheckpoints 16 certificates, n = 31 (model)", outcome.receipt, data);
          }
        } finally {
          await chain.close();
        }
      }
    });

    // -- control_v1.json leaves, certified by the model -------------------------

    it("control.rejected: a certified leaf that Taira would refuse to record answers as the row records", async () => {
      const rows = CONTROL.rejected.filter((row) => row.destination !== null);
      const relocateTo = r.addressOfWord(CONTROL.destination_words[ETHEREUM.network]);
      const { chain, destination, taira } = await modelDestination({ hardfork, profile: ETHEREUM, relocateTo });
      try {
        const leaves = rows.map((row) => taira.recordedControl(row.unchecked_leaf, controlFields(row)));
        const block = taira.block(1010n, T0 * 1000n + 60_000n, leaves);
        const certificate = taira.certify(block);
        const before = await destination.state({ heights: [1010n] });
        const call = (name, source, row, index) => {
          const proof = taira.controlProof(1010n, index, block);
          const typed = row.parliament_paused === 0 || row.parliament_paused === 1;
          const parliamentPaused = typed ? row.parliament_paused === 1 : true;
          const data = m.iface.encodeFunctionData(name, [source, r.controlProofArg({ ...proof, parliamentPaused })]);
          return typed ? data : r.withRawParliamentPaused(data, row.parliament_paused);
        };
        // §3.4: a `parliamentPaused` word other than 0 or 1 never reaches the contract's checks. The
        // ABI decoder refuses it with empty revert data, where the references answer `BadControl`.
        const outcomeOf = (row) => (row.parliament_paused > 1 ? null : row.destination);
        const untyped = rows.filter((row) => outcomeOf(row) !== row.destination);
        assert.deepEqual(untyped.map((row) => [row.label, row.destination]), [["parliament_paused_2", "BadControl"]]);
        for (const [index, row] of rows.entries()) {
          const outcome = await destination.attempt(call("applyControl", r.certificateArg(certificate), row, index));
          assertRevert(outcome, outcomeOf(row), `control.rejected ${row.label} inline`);
        }
        assert.deepEqual(await destination.state({ heights: [1010n] }), before, "refused controls change nothing");
        await destination.tx("submitCheckpoints", [[r.certificateArg(certificate)]]);
        for (const [index, row] of rows.entries()) {
          const outcome = await destination.attempt(call("applyControlFromCheckpoint", [block.x], row, index));
          assertRevert(outcome, outcomeOf(row), `control.rejected ${row.label} from the checkpoint`);
          ledger.ran("ethereum/control.rejected", row.label);
        }
        const after = await destination.state({ heights: [1010n] });
        assert.deepEqual(after.pause, before.pause);
        assert.equal(after.op_count, 0);
        assert.deepEqual(after.checkpoints, [{ height: 1010, id: m.checkpointId(block.x) }]);
      } finally {
        await chain.close();
      }
    });

    it("control.spec_examples: the four §3.4 leaves apply in order and leave their pause state", async () => {
      const relocateTo = r.addressOfWord(CONTROL.destination_words[ETHEREUM.network]);
      const { chain, destination, taira } = await modelDestination({ hardfork, profile: ETHEREUM, relocateTo });
      try {
        const rows = CONTROL.spec_examples;
        const leaves = rows.map((row) => taira.recordedControl(row.leaf, controlFields(row)));
        const block = taira.block(1010n, T0 * 1000n + 60_000n, leaves);
        const certificate = taira.certify(block);
        const pool = { certificate: { evm: certificate } };
        // The first inline use verifies and stores the certificate; later uses take the cheap path.
        const firstUse = [
          { event: "SccpCertificate", certificate: "certificate", height: 1010, generation: 5 },
          { event: "SccpCheckpointed", height: 1010, header: m.checkpointId(block.x) },
        ];
        for (const [index, row] of rows.entries()) {
          const where = `control.spec_examples nonce ${row.control_nonce}`;
          const at = T0 + 600n + BigInt(index);
          const proof = { ...taira.controlProof(1010n, index, block), parliamentPaused: row.parliament_paused === 1 };
          const args = [r.certificateArg(certificate), r.controlProofArg(proof)];
          const receipt = await destination.tx("applyControl", args, { at });
          const applied = appliedControl(row, at);
          const events = index === 0 ? [...firstUse, applied.event] : [applied.event];
          r.assertLogs(destination, receipt, r.expectedLogs(events, pool), where);
          const state = await destination.state({ heights: [1010n] });
          assert.deepEqual(state.pause, applied.pause, where);
          assert.equal(state.op_count, index + 1, where);
          ledger.ran("ethereum/control.spec_examples", `nonce ${row.control_nonce}`);
        }
      } finally {
        await chain.close();
      }
    });

    for (const profile of [ETHEREUM, BSC]) {
      it(`control.controls: every recorded leaf of ${profile.network} is the one its contract computes`, async () => {
        const ofProfile = CONTROL.controls.filter((row) => row.target === profile.network);
        for (const revision of [...new Set(ofProfile.map((row) => row.route_revision))]) {
          const rows = ofProfile.filter((row) => row.route_revision === revision);
          const relocateTo = r.addressOfWord(CONTROL.destination_words[profile.network]);
          const { chain, destination, taira } = await modelDestination({ hardfork, profile, revision, relocateTo });
          try {
            const leaves = rows.map((row) => taira.recordedControl(row.leaf, controlFields(row)));
            const block = taira.block(1010n, T0 * 1000n + 60_000n, leaves);
            const certificate = taira.certify(block);
            const pool = { certificate: { evm: certificate } };
            const id = m.checkpointId(block.x);
            const at = T0 + 600n;
            for (const [index, row] of rows.entries()) {
              const where = `control.controls ${controlRowId(row)}`;
              await onSnapshot(chain, async () => {
                const paused = row.parliament_paused === 1;
                const proof = { ...taira.controlProof(1010n, index, block), parliamentPaused: paused };
                const args = [r.certificateArg(certificate), r.controlProofArg(proof)];
                const receipt = await destination.tx("applyControl", args, { at });
                const applied = appliedControl(row, at);
                const events = [
                  { event: "SccpCertificate", certificate: "certificate", height: 1010, generation: 5 },
                  { event: "SccpCheckpointed", height: 1010, header: id },
                  applied.event,
                ];
                r.assertLogs(destination, receipt, r.expectedLogs(events, pool), where);
                const state = await destination.state({ heights: [1010n] });
                assert.deepEqual(state.pause, applied.pause, where);
                assert.equal(state.op_count, 1, where);
                assert.deepEqual(state.checkpoints, [{ height: 1010, id }], where);
              });
              assert.equal(await destination.view("controlNonce"), 0n, `${where}: the snapshot is restored`);
              ledger.ran(`${profile.name}/control.controls`, controlRowId(row));
            }
          } finally {
            await chain.close();
          }
        }
      });
    }

    // -- every Rust golden call, view return, log and P4 deployment ------------

    it("executes every Rust golden entry against the locked revision-5 contract", async () => {
      const golden = rustGoldenScenario();
      const { scenario, deployment, c100, c150, c200, recipient } = golden;
      const chain = await h.Chain.open(ETHEREUM, { hardfork, allowBlocksWithSameTimestamp: true });
      try {
        const deployed = await h.deploy(chain, deployment, { at: T0 });
        assert.equal(deployed.address, ethers.getAddress(CALLDATA.deployment.address));
        assert.equal(ethers.keccak256(deployed.init), CALLDATA.deployment.init_code_hash);
        assert.equal(await chain.rpc("eth_getCode", [deployed.address, "latest"]), h.expectedRuntime(h.immutableWords(deployment)));
        ledger.ran("ethereum/calldata.deployment", "P4");
        const destination = await h.relocate(deployed.destination, r.addressOfWord(scenario.destination.destination_word));
        const calls = new Map(CALLDATA.calls.map((row) => [row.label, row]));
        const sender = ethers.getAddress(`0x${"55".repeat(20)}`);
        const at = T0 + 300n;
        const raw = (label, options = {}) => destination.raw(calls.get(label).calldata, { at, ...options });
        const submit = (certificates) => destination.tx("submitCheckpoints", [certificates], { at });
        const observedLogs = new Map();
        for (const row of CALLDATA.calls) {
          await onSnapshot(chain, async () => {
            const late = ["finalize_historical", "finalize_checkpoint_historical", "apply_control_historical",
              "apply_control_checkpoint", "void_expired_checkpoint"].includes(row.label);
            const stored = row.function.endsWith("FromCheckpoint");
            if (late) await submit(stored ? [c150, c200] : [c150]);
            else if (stored) await submit([c100]);
            if (row.function === "transferToTaira") {
              await raw("finalize_direct");
              await submit([c150]);
              await raw("finalize_historical");
              for (const address of [recipient, sender]) {
                await chain.rpc("hardhat_setBalance", [address, ethers.toQuantity(10n ** 20n)]);
                await chain.rpc("hardhat_impersonateAccount", [address]);
              }
              await destination.tx("transfer", [sender, 2_000_000_003n], { from: recipient, at });
            }
            const callTime = row.function.startsWith("voidExpired") ? BigInt(scenario.deadline_ms) / 1000n + 1n
              : row.function === "voidFrozen" ? BigInt(scenario.pin.until_ms) / 1000n + 1n : at;
            const receipt = await destination.raw(row.calldata, { from: row.function === "transferToTaira" ? sender : 0, at: callTime });
            const logs = destination.logs(receipt);
            const checkpoints = row.function === "submitCheckpoints";
            assert.equal(await destination.view("opCount"), checkpoints ? 0n : row.function === "transferToTaira" ? 3n : 1n, row.label);
            const result = await chain.returnData(receipt);
            if (row.function.startsWith("finalize")) {
              const nonce = late ? 2 : 1;
              assert.equal(result, scenario.payloads[nonce].message_id, row.label);
              assert.equal(await destination.view("isConsumed", [nonce]), true, row.label);
              assert.equal(await destination.view("balanceOf", [recipient]), 1_000_000_000n + BigInt(nonce), row.label);
              assert.equal(await destination.view("totalSupply"), 1_000_000_000n + BigInt(nonce), row.label);
            } else if (row.function.startsWith("applyControl")) {
              assert.equal(result, "0x", row.label);
              assert.equal(await chain.call(destination.address, m.iface.encodeFunctionData("pauseState")), scenario.pause_state_return, row.label);
            } else if (row.function.startsWith("void")) {
              assert.equal(result, "0x", row.label);
              for (const nonce of row.function === "voidFrozen" ? [4, 5, 6] : [late ? 2 : 1]) {
                assert.equal(await destination.view("isConsumed", [nonce]), true, row.label);
              }
              assert.equal(await destination.view("totalSupply"), 0n, row.label);
            } else if (row.function === "transferToTaira") {
              const log = CALLDATA.logs.find((entry) => entry.label === "transfer_to_taira");
              assert.equal(result, log.topics[1], row.label);
              assert.equal(await destination.view("transferNonces", [sender]), 1n, row.label);
              assert.equal(await destination.view("balanceOf", [sender]), 500_000_003n, row.label);
              assert.equal(await destination.view("totalSupply"), 500_000_003n, row.label);
            } else {
              assert(checkpoints, `unhandled golden call ${row.label}`);
              assert.equal(result, "0x", row.label);
              assert.equal(await destination.view("checkpointHeader", [150]), m.checkpointId(c150[1]), row.label);
              const committee = await destination.view("committeeState");
              assert.equal(committee[4], 8n, row.label);
              assert.equal(committee[3], row.label === "checkpoint_rotation" ? 150n : 200n, row.label);
            }
            const selected = { finalize_direct: "certificate_100", void_expired: "voided_expired",
              void_frozen: "voided_frozen", transfer_to_taira: "transfer_to_taira" }[row.label];
            if (selected) {
              const expected = CALLDATA.logs.find((entry) => entry.label === selected);
              const matching = logs.filter((entry) => entry.topics.every((topic, index) => topic === expected.topics[index]));
              assert.equal(matching.length, 1, selected);
              assert.deepEqual(matching[0], { topics: expected.topics, data: expected.data }, selected);
              observedLogs.set(selected, matching[0]);
            }
            ledger.ran("ethereum/calldata.calls", row.label);
          });
        }
        for (const row of CALLDATA.logs) {
          assert.deepEqual(observedLogs.get(row.label), { topics: row.topics, data: row.data }, row.label);
          ledger.ran("ethereum/calldata.logs", row.label);
        }
        for (const row of CALLDATA.views) {
          await onSnapshot(chain, async () => {
            let expected;
            if (row.function === "committeeState" || row.function === "checkpointHeader") {
              await raw("checkpoint_rotation");
              expected = row.function === "committeeState" ? scenario.committee_state_after_rotation
                : m.iface.encodeFunctionResult(row.function, [m.checkpointId(c150[1])]);
            } else if (row.function === "pauseState") {
              await raw("apply_control_direct");
              expected = scenario.pause_state_return;
            } else if (row.function === "initialCommittee") {
              expected = scenario.initial_committee_return;
            } else {
              const values = { consensusInstance: scenario.consensus_instance, equivocated: false,
                maxValidityMs: m.MAX_VALIDITY_MS, isConsumed: false, transferNonces: 0n,
                tairaNetworkId: scenario.taira_network_id, routeRevision: deployment.routeRevision,
                maxWrappedSupply: deployment.maxWrappedSupply, mintingPaused: false, controlNonce: 0n, opCount: 0n };
              assert(Object.hasOwn(values, row.function), `unhandled golden view ${row.function}`);
              expected = m.iface.encodeFunctionResult(row.function, [values[row.function]]);
            }
            assert.equal(await chain.call(destination.address, row.calldata), expected, row.label);
            ledger.ran("ethereum/calldata.views", row.label);
          });
        }
      } finally {
        await chain.close();
      }
    });

    // -- evm_calldata_v1.json calldata_conformance ------------------------------

    for (const profile of [ETHEREUM, BSC]) {
      it(`calldata_conformance: accepts exactly the entries the Rust decoder accepts on ${profile.name}`, async () => {
        const { chain, destination, taira, deployment } = await modelDestination({ hardfork, profile });
        try {
          const sender = ethers.getAddress(chain.accounts[5]);
          const minted = 10n * UNIT;
          // A nonce outside every range of the table, so that the mint consumes none of them.
          const mintNonce = 1000n;
          const deadlineMs = T0 * 1000n + 3_600_000n;
          const transfer = taira.transfer({ nonce: mintNonce, amount: minted, deadlineMs, recipient: sender });
          const block = taira.block(1010n, T0 * 1000n + 60_000n, [transfer]);
          const mint = [r.certificateArg(taira.certify(block)), r.messageProofArg(taira.messageProof(1010n, 0, block))];
          await destination.tx("finalizeFromTaira", mint, { at: T0 + 100n });
          assert.equal(await destination.view("balanceOf", [sender]), minted);
          const frozenAt = deployment.initialUntilMs / 1000n + 1n;
          const seen = new Set();
          for (const entry of CONFORMANCE) {
            const id = `${entry.function}/${entry.label}`;
            const where = `${profile.name} calldata_conformance ${id}`;
            assert(!seen.has(id), `${where}: duplicate entry`);
            seen.add(id);
            assert.equal(ethers.dataSlice(entry.calldata, 0, 4), TRANSITIONS.selectors[entry.function].selector, where);
            assert.equal(entry.decoder === "accept", entry.contract === "accept", `${where}: both verdicts agree`);
            await onSnapshot(chain, async () => {
              const at = entry.function === "voidFrozen" ? frozenAt : T0 + 200n;
              const outcome = await destination.attempt(entry.calldata, { from: 5, at });
              if (entry.contract !== "accept") {
                assertRevert(outcome, entry.contract === "empty" ? null : entry.contract, where);
                return;
              }
              assert(outcome.receipt, `${where}: reverted with ${outcome.revert && h.describeRevert(outcome.revert)}`);
              const args = m.iface.decodeFunctionData(entry.function, entry.calldata);
              assert.equal(m.iface.encodeFunctionData(entry.function, args), entry.calldata, `${where}: canonical`);
              if (entry.function === "transferToTaira") {
                const [tairaRecipient, amount, nonce] = args;
                const payload = m.inboundPayload(profile, { nonce, revision: 1, amount, sender, tairaRecipient });
                const messageId = m.inboundMessageId(deployment.tairaNetworkId, profile, payload);
                const expected = {
                  sccp: [m.eventLog("SccpTransferToTaira", [messageId, sender, nonce, payload])],
                  transfers: [m.eventLog("Transfer", [sender, m.ZERO_ADDRESS, amount])],
                };
                r.assertLogs(destination, outcome.receipt, expected, where);
                assert.equal(await chain.returnData(outcome.receipt), messageId, `${where}: return value`);
                assert.equal(await destination.view("transferNonces", [sender]), nonce + 1n, where);
                assert.equal(await destination.view("balanceOf", [sender]), minted - amount, where);
                assert.equal(await destination.view("totalSupply"), minted - amount, where);
              } else {
                const [first, count] = args;
                const last = first + count - 1n;
                const voided = Array.from({ length: Number(count) }, (_, offset) =>
                  m.eventLog("SccpVoided", [m.ZERO32, first + BigInt(offset)]));
                assert.deepEqual(destination.logs(outcome.receipt), voided, where);
                const inRange = (nonce) => nonce >= 0n && nonce <= m.U64_MAX;
                const nonces = [first - 1n, first, last, last + 1n, mintNonce].filter(inRange);
                const state = await destination.state({ nonces });
                const consumed = [...new Set([first, last, mintNonce])].sort((a, b) => (a < b ? -1 : 1));
                assert.deepEqual(state.consumed.map(BigInt), consumed, where);
                assert.equal(state.live, false, where);
              }
              assert.equal(await destination.view("opCount"), 2n, `${where}: one operation after the mint`);
            });
            assert.equal(await destination.view("opCount"), 1n, `${where}: the snapshot is restored`);
            assert.equal(await destination.view("transferNonces", [sender]), 0n, `${where}: the snapshot is restored`);
            ledger.ran(`${profile.name}/calldata_conformance`, id);
          }
        } finally {
          await chain.close();
        }
      });
    }

    // -- coverage ---------------------------------------------------------------

    it("ran every row of every fixture, on every run that replays it", (t) => {
      const expected = expectedRows();
      for (const [group, ids] of Object.entries(expected)) {
        assert.deepEqual(ledger.rows(group), [...ids].sort(), `rows of ${group} that ran`);
      }
      const counts = ledger.counts();
      assert.deepEqual(Object.keys(counts).sort(), Object.keys(expected).sort(), "no row ran outside these groups");
      const count = (...prefixes) =>
        Object.entries(counts)
          .filter(([group]) => prefixes.some((prefix) => group.startsWith(prefix)))
          .reduce((sum, [, rows]) => sum + rows, 0);
      const certificates =
        ROW_COUNTS["finality.certificates"] +
        ROW_COUNTS["finality.flavor_specific_certificates"] +
        ROW_COUNTS["finality.negative_certificates with an EVM form"] +
        ROW_COUNTS["finality_rust.negative_certificates"];
      const headers = ROW_COUNTS["finality.headers.valid"] + ROW_COUNTS["finality.headers.invalid"];
      const conformance =
        ROW_COUNTS["calldata_conformance.transferToTaira"] + ROW_COUNTS["calldata_conformance.voidFrozen"];
      assert.deepEqual(
        {
          "certificates and headers on ethereum": count("ethereum/finality"),
          "certificates on bsc": count("bsc/finality"),
          "certificates on dirty memory": count("dirty/finality"),
          "transition steps on ethereum": count("ethereum/transitions.steps"),
          "transition steps on bsc": count("bsc/transitions.steps"),
          "transition steps on dirty memory": count("dirty/transitions.steps"),
          "control steps on ethereum": count("ethereum/control.steps"),
          "control steps on dirty memory": count("dirty/control.steps"),
          "rejected controls": count("ethereum/control.rejected"),
          "control leaves on their chains": count("ethereum/control.controls", "bsc/control.controls"),
          "spec control leaves": count("ethereum/control.spec_examples"),
          "init bounds": count("ethereum/transitions.init_bounds", "bsc/transitions.init_bounds"),
          "Rust golden entries": count("ethereum/calldata."),
          "calldata conformance entries": count("ethereum/calldata_conformance", "bsc/calldata_conformance"),
        },
        {
          "certificates and headers on ethereum": certificates + headers,
          "certificates on bsc": certificates,
          "certificates on dirty memory": certificates,
          "transition steps on ethereum": ROW_COUNTS["transitions.steps"],
          "transition steps on bsc": ROW_COUNTS["transitions.steps of scenarios without leaves"],
          "transition steps on dirty memory": ROW_COUNTS["transitions.steps"],
          "control steps on ethereum": ROW_COUNTS["control.steps"],
          "control steps on dirty memory": ROW_COUNTS["control.steps"],
          "rejected controls": ROW_COUNTS["control.rejected with a destination outcome"],
          "control leaves on their chains": ROW_COUNTS["control.controls of an EVM target"],
          "spec control leaves": ROW_COUNTS["control.spec_examples"],
          "init bounds": 2 * ROW_COUNTS["transitions.init_bounds"],
          "Rust golden entries": 1 + ROW_COUNTS["calldata.calls"] + ROW_COUNTS["calldata.views"] + ROW_COUNTS["calldata.logs"],
          "calldata conformance entries": 2 * conformance,
        },
      );
      const total = Object.values(counts).reduce((sum, rows) => sum + rows, 0);
      t.diagnostic(`${hardfork}: ${total} fixture rows replayed: ${JSON.stringify(counts)}`);
    });

    it("records the gas of every positive certificate", (t) => {
      const measured = h.gasMeasurements()[hardfork] ?? {};
      for (const [group, rows] of CERTIFICATE_GROUPS) {
        for (const row of withEvmForm(rows).filter((entry) => entry.expected.evm === "ok")) {
          const measurement = measured[`submitCheckpoints 1 certificate (${group} ${row.label})`]?.ethereum;
          assert(measurement, `gas of ${row.label} was recorded`);
          const { gasUsed, calldataBytes, intrinsic, floor, execution } = measurement;
          assert(execution > 0 && gasUsed === execution + intrinsic, row.label);
          assert(gasUsed >= floor, `${row.label}: above the EIP-7623 floor`);
          const detail = `calldata ${calldataBytes} bytes, execution ${execution}`;
          t.diagnostic(`${hardfork} gas ${row.label}: ${gasUsed} (${detail})`);
        }
      }
      assert(h.gasReport().includes(`| ${hardfork} |`), "the report has rows of this hardfork");
      h.writeGasReport();
    });
  });
}
