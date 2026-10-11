"use strict";

// Gas of `contracts/evm/sccp/SccpTairaXor.sol` for every row of the cost table
// of `specs/sccp.md` §5.4, measured on the locked EDR runtime under the Prague
// and the Osaka rules and for both destination profiles (Ethereum, chain id 1;
// BSC, chain id 56):
//
// - `submitCheckpoints` with one certificate, with a heartbeat and a key-change
//   rotation, with 16 certificates and with 16 rotations, for committees of
//   n = 4, 7 and 31 (and from them the cost of each extra certificate);
// - `finalizeFromTaira`, `applyControl` and `voidExpired` with an inline
//   certificate, for the same three committee sizes;
// - `finalizeFromCheckpoint`, `voidExpiredFromCheckpoint` and
//   `applyControlFromCheckpoint`, each with its smallest proof and with the
//   largest one the rules admit (a block of 512 leaves, proven through a
//   history of 2^32 leaves);
// - `voidFrozen` of 1 and of 256 nonces, `transferToTaira`, and the deployment
//   through `SCCP_EVM_DEPLOYER`;
// - the `LOG3` of `SccpCertificate`, read from the execution trace.
//
// Every row states the storage it writes, because that decides most of its
// cost. The measurements are compared with the committed baseline
// `gas_baseline_v1.json` (hardfork → row → profile). A row fails when it is
// above 1.1 × its baseline, the rule of §5.4, and also when it is below 0.9 ×
// its baseline, so that a stale baseline cannot hide a later regression. A row
// that is missing from the baseline, or from the run, fails too. Every
// certificate is signed by the independent model (`sccp_v1_model.js`), from
// fixed test keys, so the calldata and with it the gas is the same on every
// run.
//
// Run: `node --test contracts/evm/sccp/test/sccp_gas.test.js` with the locked
// EVM runtime installed. Test-only conveniences: `SCCP_GAS_BASELINE=write`
// rewrites the baseline from this run instead of comparing (review the diff),
// and `SCCP_GAS_REPORT=<file>` also writes the measurements as JSON.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { describe, it } = require("node:test");
const m = require("./sccp_v1_model.js");
const h = require("./sccp_edr_harness.js");
const r = require("./sccp_replay.js");

const { ethers, ZERO32 } = m;
const { ethereum: ETHEREUM, bsc: BSC } = m.PROFILES;

const HARDFORKS = Object.freeze(["prague", "osaka"]);
const PROFILES = Object.freeze([ETHEREUM, BSC]);
const SIZES = Object.freeze([4, 7, 31]);
const BASELINE_PATH = path.join(__dirname, "gas_baseline_v1.json");
const BASELINE_SCHEMA = "sccp-evm-gas-baseline/v1";
// A measurement m passes iff 9·b ≤ 10·m ≤ 11·b for its baseline b.
const TOLERANCE = Object.freeze({ numeratorAbove: 11n, numeratorBelow: 9n, denominator: 10n });
// EIP-7883 (Osaka) prices each of the four MODEXP field reductions of hash-to-G2 at 500 gas instead of 200.
const MODEXP_REPRICING = 4 * 300;
// EIP-7825 (Osaka): no transaction may use more than 2^24 gas.
const TRANSACTION_GAS_CAP = 1 << 24;

const NETWORK_ID = `0x${"5a".repeat(32)}`;
const INSTANCE = `0x${"c3".repeat(32)}`;
const UNIT = 1_000_000_000n;
const T0 = 1_800_000_000n;
const VALIDITY_MS = 14n * 86_400n * 1000n;
const GENERATION = 5n;
const START = 1_000n;
const RECIPIENT = ethers.getAddress(`0x${"c1".repeat(20)}`);
// Account 5 of every EDR test chain (`edr-provider.js`): the sender of the measured burns.
const BURNER_INDEX = 5;
const BURNER = ethers.getAddress("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc");
const TAIRA_RECIPIENT = ethers.concat(["0x0102", ethers.keccak256("0x02")]); // 34 bytes
const CERTIFICATE_TOPIC = m.iface.getEvent("SccpCertificate").topicHash;

const ms = (seconds) => BigInt(seconds) * 1000n;
const id = (text) => ethers.id(text);

// ---------------------------------------------------------------------------
// The model's Taira and the calls of every row, built once per profile and size
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

function deploymentOf(profile, signedBy) {
  return {
    tairaNetworkId: NETWORK_ID,
    consensusInstance: INSTANCE,
    networkTag: profile.tag,
    routeRevision: 1,
    maxWrappedSupply: 1_000_000n * UNIT,
    initialGeneration: GENERATION,
    initialCommitteeRoot: signedBy.root,
    initialStartHeight: START,
    initialUntilMs: ms(T0) + VALIDITY_MS,
  };
}

/** The CREATE2 address of the destination of `profile` pinned to `signedBy`. */
function addressOf(profile, signedBy) {
  return m.create2Address(h.initCode(deploymentOf(profile, signedBy)));
}

function tairaFor(profile, signedBy) {
  const destinationWord = m.addressWord(addressOf(profile, signedBy));
  const taira = new m.TairaModel({ networkId: NETWORK_ID, instance: INSTANCE, profile, destinationWord });
  taira.start(GENERATION, signedBy, START, VALIDITY_MS);
  return taira;
}

function transferOf(taira, nonce, { recipient = RECIPIENT, deadlineMs = ms(T0 + 86_400n), amount = UNIT } = {}) {
  return taira.transfer({ nonce, amount, deadlineMs, recipient });
}

function controlOf(taira, controlNonce) {
  return taira.control({
    controlNonce: BigInt(controlNonce),
    track: 1,
    parliamentPaused: false,
    fastPauseUntilMs: 0n,
    certificateId: id(`certificate ${controlNonce}`),
    effectHash: id(`effect ${controlNonce}`),
  });
}

const encode = (name, args) => m.iface.encodeFunctionData(name, args);
const certificateArg = (taira, block) => r.certificateArg(taira.certify(block));
const messageArg = (taira, block, index, certified = block) =>
  r.messageProofArg(taira.messageProof(block.height, index, certified));
const controlArg = (taira, block, index, certified = block) =>
  r.controlProofArg(taira.controlProof(block.height, index, certified));

const checkpointCalls = new Map();

/**
 * The `submitCheckpoints` calls of a committee of `n` keys, in the order they
 * run on one destination. The headers carry no leaf, so the same calls serve
 * both profiles.
 */
function checkpointCallsOf(n) {
  if (!checkpointCalls.has(n)) {
    const signedBy = committeeOf(n);
    const other = committeeOf(n, 1);
    const taira = tairaFor(ETHEREUM, signedBy);
    const submit = (blocks) => encode("submitCheckpoints", [blocks.map((block) => certificateArg(taira, block))]);
    const at = (offset) => ms(T0 + 10n + BigInt(offset));
    const one = submit([taira.block(1010n, at(0), [])]);
    const sixteen = submit(Array.from({ length: 16 }, (_, index) => taira.block(1100n + BigInt(index), at(index), [])));
    const heartbeat = submit([taira.block(1200n, at(20), [], { rotate: "heartbeat" })]);
    const keyChange = submit([taira.block(1210n, at(21), [], { rotate: "key", nextCommittee: other })]);
    // Sixteen key changes between the two key sets, one generation each.
    const rotations = submit(Array.from({ length: 16 }, (_, index) => {
      const nextCommittee = taira.current.committee === other ? signedBy : other;
      return taira.block(1300n + 10n * BigInt(index), at(30 + index), [], { rotate: "key", nextCommittee });
    }));
    checkpointCalls.set(n, Object.freeze([
      [`submitCheckpoints, 1 certificate, n = ${n} (new checkpoint, high raised)`, one],
      [`submitCheckpoints, 16 certificates, n = ${n} (16 new checkpoints)`, sixteen],
      [`submitCheckpoints, 1 certificate with rotation, n = ${n} (heartbeat: slot B)`, heartbeat],
      [`submitCheckpoints, 1 certificate with rotation, n = ${n} (key change: root and slot B)`, keyChange],
      [`submitCheckpoints, 16 rotations, n = ${n} (key changes)`, rotations],
    ]));
  }
  return checkpointCalls.get(n);
}

const inlineCalls = new Map();

/** The inline entry-point calls of `profile` and a committee of `n` keys, in the order they run. */
function inlineCallsOf(profile, n) {
  const key = `${profile.name}/${n}`;
  if (!inlineCalls.has(key)) {
    const taira = tairaFor(profile, committeeOf(n));
    const at = (offset) => ms(T0 + 10n + BigInt(offset));
    const first = taira.block(1010n, at(0), [transferOf(taira, 0)]);
    const second = taira.block(1011n, at(1), [transferOf(taira, 1), transferOf(taira, 2)]);
    const third = taira.block(1012n, at(2), [controlOf(taira, 1)]);
    const fourth = taira.block(1013n, at(3), [transferOf(taira, 3, { deadlineMs: ms(T0 + 50n) })]);
    const stored = certificateArg(taira, second);
    inlineCalls.set(key, Object.freeze([
      [
        `finalizeFromTaira inline, n = ${n} (new X; first operation: new balance, bitmap word and slot C)`,
        encode("finalizeFromTaira", [certificateArg(taira, first), messageArg(taira, first, 0)]),
      ],
      [
        `finalizeFromTaira inline, n = ${n} (new X; existing balance, used bitmap word)`,
        encode("finalizeFromTaira", [stored, messageArg(taira, second, 0)]),
      ],
      [
        `finalizeFromTaira inline, n = ${n} (stored X, cheap path; existing balance, used bitmap word)`,
        encode("finalizeFromTaira", [stored, messageArg(taira, second, 1)]),
      ],
      [
        `applyControl inline, n = ${n} (new X)`,
        encode("applyControl", [certificateArg(taira, third), controlArg(taira, third, 0)]),
      ],
      [
        `voidExpired inline, n = ${n} (new X; used bitmap word)`,
        encode("voidExpired", [3n, certificateArg(taira, fourth), messageArg(taira, fourth, 0)]),
      ],
    ]));
  }
  return inlineCalls.get(key);
}

const checkpointUseCalls = new Map();

/**
 * The checkpoint entry-point, burn and `voidFrozen` calls of `profile`, on a
 * destination pinned to four keys: `setup` stores the checkpoints, `rows` are
 * measured in order, `funding` mints what `BURNER` then burns, and `frozen`
 * are measured after the deadline.
 */
function checkpointUseCallsOf(profile) {
  if (!checkpointUseCalls.has(profile.name)) {
    const taira = tairaFor(profile, committeeOf(4));
    const at = (offset) => ms(T0 + 10n + BigInt(offset));
    const past = { deadlineMs: ms(T0 + 50n) };
    // Smallest proofs: a block of one leaf, referenced at the certified height.
    const mints = [0, 1].map((nonce) => taira.block(1010n + BigInt(nonce), at(nonce), [transferOf(taira, nonce)]));
    const funding = taira.block(1012n, at(2), [transferOf(taira, 2, { recipient: BURNER, amount: 10n * UNIT })]);
    const lapsed = taira.block(1013n, at(3), [transferOf(taira, 3, past)]);
    const controlled = taira.block(1014n, at(4), [controlOf(taira, 1)]);
    // Largest proofs: leaves 0..2 of a block of 512 leaves (9 siblings), which is leaf 0 of a
    // history of 2^32 leaves (32 siblings) under a header that commits to that history.
    const large = [
      transferOf(taira, 512, { recipient: ethers.getAddress(`0x${"c2".repeat(20)}`) }),
      transferOf(taira, 1024, past),
      controlOf(taira, 2),
    ];
    const filler = Array.from({ length: 509 }, (_, index) => ({ kind: "filler", leaf: id(`filler ${index}`) }));
    const leaves = [...large, ...filler].map((item) => item.leaf);
    const sccpRoot = m.merkleRoot(leaves);
    const historyPath = Array.from({ length: 32 }, (_, index) => id(`history sibling ${index}`));
    const size = m.MAX_HISTORY_SIZE;
    const header = {
      networkId: NETWORK_ID,
      height: 2000n,
      timestampMs: at(5),
      flags: m.FLAG_ACTIVE,
      messageCount: 0n,
      sccpRoot: ZERO32,
      historySize: size,
      historyRoot: m.merkleRootFromPath(m.historyLeaf(1500n, sccpRoot, 512n), 0n, size, historyPath),
      generation: GENERATION,
      committeeRoot: committeeOf(4).root,
      validityMs: 0n,
      nextCommitteeRoot: ZERO32,
    };
    const deep = { height: 2000n, header, x: m.encodeHeader(header), committee: committeeOf(4) };
    const reference = { height: 1500n, sccpRoot, messageCount: 512n, historyIndex: 0n, historyPath };
    const position = (leafIndex) => ({ leafIndex, path: m.merklePath(leaves, leafIndex), block: reference });
    assert.equal(position(0).path.length, 9, "a leaf of 512 has nine siblings");
    const largeMessage = (index) => r.messageProofArg({ payload: large[index].payload, ...position(index) });
    const largeControl = r.controlProofArg({ ...large[2].control, ...position(2) });
    const stored = [...mints, funding, lapsed, controlled, deep];
    checkpointUseCalls.set(profile.name, Object.freeze({
      setup: encode("submitCheckpoints", [stored.map((block) => certificateArg(taira, block))]),
      funding: encode("finalizeFromCheckpoint", [[funding.x], messageArg(taira, funding, 0)]),
      rows: [
        [
          "finalizeFromCheckpoint (1-leaf block; first operation: new balance, bitmap word and slot C)",
          encode("finalizeFromCheckpoint", [[mints[0].x], messageArg(taira, mints[0], 0)]),
        ],
        [
          "finalizeFromCheckpoint (1-leaf block; existing balance, used bitmap word)",
          encode("finalizeFromCheckpoint", [[mints[1].x], messageArg(taira, mints[1], 0)]),
        ],
        [
          "finalizeFromCheckpoint (512-leaf block through a 32-sibling history path; new balance and bitmap word)",
          encode("finalizeFromCheckpoint", [[deep.x], largeMessage(0)]),
        ],
        [
          "voidExpiredFromCheckpoint (1-leaf block; used bitmap word)",
          encode("voidExpiredFromCheckpoint", [3n, [lapsed.x], messageArg(taira, lapsed, 0)]),
        ],
        [
          "voidExpiredFromCheckpoint (512-leaf block through a 32-sibling history path; new bitmap word)",
          encode("voidExpiredFromCheckpoint", [1024n, [deep.x], largeMessage(1)]),
        ],
        [
          "applyControlFromCheckpoint (1-leaf block)",
          encode("applyControlFromCheckpoint", [[controlled.x], controlArg(taira, controlled, 0)]),
        ],
        [
          "applyControlFromCheckpoint (512-leaf block through a 32-sibling history path)",
          encode("applyControlFromCheckpoint", [[deep.x], largeControl]),
        ],
      ],
      burns: [
        ["transferToTaira (34-byte recipient; first burn of the sender)", [TAIRA_RECIPIENT, UNIT, 0n]],
        ["transferToTaira (34-byte recipient; later burn)", [TAIRA_RECIPIENT, UNIT, 1n]],
        ["transferToTaira (1024-byte recipient; later burn)", [`0x${"ee".repeat(1024)}`, UNIT, 2n]],
      ].map(([label, args]) => [label, encode("transferToTaira", args)]),
      frozen: [
        ["voidFrozen, 1 nonce (new bitmap word)", [5000n, 1n]],
        ["voidFrozen, 256 nonces (one new bitmap word)", [5120n, 256n]],
        ["voidFrozen, 256 nonces (two new bitmap words)", [6000n, 256n]],
      ].map(([label, args]) => [label, encode("voidFrozen", args)]),
    }));
  }
  return checkpointUseCalls.get(profile.name);
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/** Row → the number of `SccpCertificate` logs of its transaction (full-path verifications). */
const fullPaths = new Map();
/** Derived values: hardfork → row → profile → gas. */
const derived = {};

function recordDerived(chain, label, value) {
  derived[chain.hardfork] = derived[chain.hardfork] ?? {};
  derived[chain.hardfork][label] = derived[chain.hardfork][label] ?? {};
  derived[chain.hardfork][label][chain.profile.name] = value;
}

/** Sends `data` to `to`, requires success, and records the gas of the transaction under `label`. */
async function measure(chain, label, to, data, options = {}) {
  const receipt = await chain.send({ ...options, to, data });
  const gasUsed = h.recordGas(chain, label, receipt, data);
  assert(gasUsed <= TRANSACTION_GAS_CAP, `${label}: ${gasUsed} gas is above the EIP-7825 cap`);
  const verified = receipt.logs.filter((entry) => entry.topics[0] === CERTIFICATE_TOPIC).length;
  assert.equal(fullPaths.get(label) ?? verified, verified, `${label}: full-path verifications`);
  fullPaths.set(label, verified);
  return receipt;
}

async function withDestination(hardfork, profile, n, body) {
  const signedBy = committeeOf(n);
  const chain = await h.Chain.open(profile, { hardfork });
  try {
    const deployment = deploymentOf(profile, signedBy);
    const { destination, receipt, init } = await h.deploy(chain, deployment, { at: T0 });
    assert.equal(destination.address, addressOf(profile, signedBy), "the leaves name the CREATE2 address");
    await body({ chain, destination, receipt, init, deployment });
  } finally {
    await chain.close();
  }
}

/** The gas of every `LOG3` of the transaction `receipt`, from its execution trace. */
async function log3Costs(chain, receipt) {
  const options = { disableStorage: true, disableMemory: true, disableStack: true };
  const trace = await chain.rpc("debug_traceTransaction", [receipt.transactionHash, options]);
  return trace.structLogs.filter((step) => step.op === "LOG3").map((step) => Number(step.gasCost));
}

for (const hardfork of HARDFORKS) {
  describe(`SccpTairaXor gas (${hardfork})`, () => {
    for (const profile of PROFILES) {
      for (const n of SIZES) {
        it(`submitCheckpoints rows, n = ${n}, on ${profile.name}`, async () => {
          await withDestination(hardfork, profile, n, async ({ chain, destination }) => {
            const [[oneLabel], [sixteenLabel]] = checkpointCallsOf(n);
            const receipts = {};
            for (const [index, [label, data]] of checkpointCallsOf(n).entries()) {
              const at = T0 + 100n + BigInt(index);
              receipts[label] = await measure(chain, label, destination.address, data, { at });
            }
            const gas = (label) => Number(BigInt(receipts[label].gasUsed));
            const extra = Math.floor((gas(sixteenLabel) - gas(oneLabel)) / 15);
            recordDerived(chain, `submitCheckpoints, each extra certificate, n = ${n}`, extra);
            // One LOG3 with the three byte strings of the certificate; n does not enter it.
            const [log3, ...others] = await log3Costs(chain, receipts[oneLabel]);
            assert.deepEqual(others, [], "one LOG3 in a checkpoint of one certificate");
            recordDerived(chain, `SccpCertificate LOG3, n = ${n}`, log3);
            const generation = (await destination.view("committeeState"))[4];
            assert.equal(generation, GENERATION + 18n, "a heartbeat, a key change and 16 more rotations");
            assert.equal(await destination.view("opCount"), 0n);
          });
        });

        it(`inline rows, n = ${n}, on ${profile.name}`, async () => {
          await withDestination(hardfork, profile, n, async ({ chain, destination }) => {
            for (const [index, [label, data]] of inlineCallsOf(profile, n).entries()) {
              await measure(chain, label, destination.address, data, { at: T0 + 100n + BigInt(index) });
            }
            assert.equal(await destination.view("opCount"), 5n, "three mints, a control and a void");
            assert.equal(await destination.view("balanceOf", [RECIPIENT]), 3n * UNIT);
          });
        });
      }

      it(`checkpoint, burn and voidFrozen rows, and the deployment, on ${profile.name}`, async () => {
        await withDestination(hardfork, profile, 4, async ({ chain, destination, receipt, init, deployment }) => {
          const deployerCalldata = ethers.concat([m.SCCP_EVM_SALT, init]);
          const deploymentGas = h.recordGas(chain, "deployment through SCCP_EVM_DEPLOYER", receipt, deployerCalldata);
          assert(deploymentGas <= TRANSACTION_GAS_CAP, "the deployment fits the EIP-7825 cap");
          fullPaths.set("deployment through SCCP_EVM_DEPLOYER", 0);
          assert.equal(ethers.getAddress(chain.accounts[BURNER_INDEX]), BURNER, "the funded account sends the burns");
          const calls = checkpointUseCallsOf(profile);
          await chain.send({ to: destination.address, data: calls.setup, at: T0 + 100n });
          for (const [label, data] of calls.rows) await measure(chain, label, destination.address, data);
          await chain.send({ to: destination.address, data: calls.funding });
          for (const [label, data] of calls.burns) {
            await measure(chain, label, destination.address, data, { from: BURNER_INDEX });
          }
          assert.equal(await destination.view("opCount"), 7n + 1n + 3n);
          const frozenAt = deployment.initialUntilMs / 1000n + 1n;
          for (const [index, [label, data]] of calls.frozen.entries()) {
            await measure(chain, label, destination.address, data, { at: frozenAt + BigInt(index) });
          }
          assert.equal(await destination.view("isConsumed", [6255n]), true);
        });
      });
    }
  });
}

// ---------------------------------------------------------------------------
// The baseline
// ---------------------------------------------------------------------------

/** Every row of §5.4 that a run must measure, for every hardfork and profile. */
function requiredRows() {
  const rows = ["deployment through SCCP_EVM_DEPLOYER"];
  for (const n of SIZES) {
    rows.push(...checkpointCallsOf(n).map(([label]) => label));
    rows.push(...inlineCallsOf(ETHEREUM, n).map(([label]) => label));
  }
  const calls = checkpointUseCallsOf(ETHEREUM);
  rows.push(...[...calls.rows, ...calls.burns, ...calls.frozen].map(([label]) => label));
  return rows.sort((a, b) => a.localeCompare(b));
}

function sortedDerived() {
  const sorted = {};
  for (const hardfork of HARDFORKS) {
    sorted[hardfork] = {};
    for (const label of Object.keys(derived[hardfork] ?? {}).sort((a, b) => a.localeCompare(b))) {
      sorted[hardfork][label] = derived[hardfork][label];
    }
  }
  return sorted;
}

/**
 * The baseline file as text: JSON with two-space indentation, in which every
 * object of numbers (one measurement, or the two profiles of a derived row)
 * stays on one line, so that a changed row is one changed line of the diff.
 */
function baselineText(baseline) {
  const numbersOnly = /\{\n(?:\s+"[^"\n]+": \d+,?\n)+\s+\}/g;
  const oneLine = (object) => object.replace(/\s*\n\s*/g, " ");
  return `${JSON.stringify(baseline, null, 2).replace(numbersOnly, oneLine)}\n`;
}

function withinTolerance(measured, baseline) {
  const { numeratorAbove, numeratorBelow, denominator } = TOLERANCE;
  const [value, reference] = [BigInt(measured), BigInt(baseline)];
  return denominator * value <= numeratorAbove * reference && denominator * value >= numeratorBelow * reference;
}

describe("SccpTairaXor gas: the committed baseline", () => {
  it("measured every row of §5.4 under both hardforks and for both profiles", () => {
    const measured = h.gasMeasurements();
    const required = requiredRows();
    assert.equal(new Set(required).size, required.length, "row names are unique");
    for (const hardfork of HARDFORKS) {
      assert.deepEqual(Object.keys(measured[hardfork] ?? {}), required, `rows measured under ${hardfork}`);
      for (const label of required) {
        const profiles = measured[hardfork][label];
        assert.deepEqual(Object.keys(profiles).sort(), ["bsc", "ethereum"], `${hardfork} ${label}`);
        for (const { gasUsed, intrinsic, floor, execution } of Object.values(profiles)) {
          assert(execution > 0 && gasUsed === intrinsic + execution, `${hardfork} ${label}: execution gas`);
          assert(gasUsed >= floor, `${hardfork} ${label}: at or above the EIP-7623 floor`);
        }
      }
      assert.equal(Object.keys(derived[hardfork] ?? {}).length, 2 * SIZES.length, `derived rows under ${hardfork}`);
    }
  });

  it("differs between Prague and Osaka by the MODEXP repricing of each full-path certificate only", () => {
    const { prague, osaka } = h.gasMeasurements();
    for (const label of requiredRows()) {
      for (const profile of PROFILES) {
        const difference = osaka[label][profile.name].gasUsed - prague[label][profile.name].gasUsed;
        assert.equal(difference, MODEXP_REPRICING * fullPaths.get(label), `${label} on ${profile.name}`);
      }
    }
    // The 16-certificate rows verify 16 certificates, the cheap path none.
    const counts = [...fullPaths.entries()];
    assert.deepEqual([...new Set(counts.map(([, count]) => count))].sort((a, b) => a - b), [0, 1, 16]);
    assert(counts.filter(([label]) => label.includes("cheap path")).every(([, count]) => count === 0));
  });

  it("is within the tolerance of gas_baseline_v1.json, row by row", (t) => {
    const measured = h.gasMeasurements();
    const run = { rows: measured, derived: sortedDerived() };
    if (process.env.SCCP_GAS_BASELINE === "write") {
      const baseline = {
        schema: BASELINE_SCHEMA,
        spec: "specs/sccp.md §5.4",
        generator: "contracts/evm/sccp/test/sccp_gas.test.js (SCCP_GAS_BASELINE=write)",
        note:
          "Gas used per hardfork, row and profile on the locked EDR runtime. `rows` are whole transactions " +
          "(gasUsed = intrinsic + execution; floor is the EIP-7623 minimum of the calldata). `derived` are " +
          "(gas of 16 certificates − gas of 1) / 15 and the LOG3 of SccpCertificate from the execution trace. " +
          "The bsc profile is the same build under chain id 56 on EDR; it is no measurement of a BSC node.",
        tolerance: {
          rule: "a measured value m passes iff below·b ≤ denominator·m ≤ above·b for its baseline b",
          above: Number(TOLERANCE.numeratorAbove),
          below: Number(TOLERANCE.numeratorBelow),
          denominator: Number(TOLERANCE.denominator),
        },
        ...run,
      };
      fs.writeFileSync(BASELINE_PATH, baselineText(baseline));
      t.diagnostic(`wrote ${BASELINE_PATH}`);
      return;
    }
    const committed = fs.readFileSync(BASELINE_PATH, "utf8");
    const baseline = JSON.parse(committed);
    assert.equal(baseline.schema, BASELINE_SCHEMA);
    assert.equal(committed, baselineText(baseline), "the baseline file is in the form this suite writes");
    assert.deepEqual(
      [baseline.tolerance.above, baseline.tolerance.below, baseline.tolerance.denominator],
      [TOLERANCE.numeratorAbove, TOLERANCE.numeratorBelow, TOLERANCE.denominator].map(Number),
      "the baseline states the tolerance this suite applies",
    );
    const drift = [];
    const changed = [];
    for (const [kind, gasOf] of [["rows", (entry) => entry.gasUsed], ["derived", (entry) => entry]]) {
      for (const hardfork of HARDFORKS) {
        const expected = baseline[kind][hardfork];
        const actual = run[kind][hardfork];
        const sameRows = `${kind} of ${hardfork}: the baseline has these rows`;
        assert.deepEqual(Object.keys(actual), Object.keys(expected), sameRows);
        for (const [label, profiles] of Object.entries(actual)) {
          assert.deepEqual(Object.keys(profiles), Object.keys(expected[label]), `${hardfork} ${label}: profiles`);
          for (const [profile, entry] of Object.entries(profiles)) {
            const [value, reference] = [gasOf(entry), gasOf(expected[label][profile])];
            const where = `${hardfork} ${profile} ${label}: ${value} against a baseline of ${reference}`;
            if (!withinTolerance(value, reference)) drift.push(where);
            else if (value !== reference) changed.push(where);
          }
        }
      }
    }
    for (const where of changed) t.diagnostic(`within tolerance, but not the baseline value: ${where}`);
    assert.deepEqual(drift, [], "rows outside 0.9..1.1 × their baseline");
  });

  it("applies the tolerance at its edges", () => {
    assert.equal(withinTolerance(110, 100), true);
    assert.equal(withinTolerance(111, 100), false);
    assert.equal(withinTolerance(90, 100), true);
    assert.equal(withinTolerance(89, 100), false);
    assert.equal(withinTolerance(254_000, 254_000), true);
    assert.equal(withinTolerance(279_401, 254_000), false);
    assert.equal(withinTolerance(228_599, 254_000), false);
  });

  it("reports the measurements", (t) => {
    const measured = h.gasMeasurements();
    for (const hardfork of HARDFORKS) {
      for (const [label, profiles] of Object.entries(measured[hardfork])) {
        const { ethereum, bsc } = profiles;
        const detail = `calldata ${ethereum.calldataBytes} bytes, execution ${ethereum.execution}`;
        t.diagnostic(`${hardfork} | ${label} | ETH ${ethereum.gasUsed} | BSC ${bsc.gasUsed} | ${detail}`);
      }
      for (const [label, profiles] of Object.entries(sortedDerived()[hardfork])) {
        t.diagnostic(`${hardfork} | ${label} | ETH ${profiles.ethereum} | BSC ${profiles.bsc} | derived`);
      }
    }
    h.writeGasReport();
  });
});
