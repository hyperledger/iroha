"use strict";

// Direct contract replay of payload/tree/history/native-event shared fixtures.
// Rational amount normalization belongs to the source SDK, and TON payloads
// belong to the TON contract. All malformed payload rows still exercise the
// EVM decoder, with foreign directions explicitly refused by its domain check.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const m = require("./sccp_v1_model.js");
const h = require("./sccp_edr_harness.js");
const r = require("./sccp_replay.js");
const { ethers, REPO } = m;
const profiles = [m.PROFILES.ethereum, m.PROFILES.bsc];
const load = (name) => JSON.parse(fs.readFileSync(path.join(REPO, "fixtures/sccp", name), "utf8"));
const payload = load("payload_v1.json");
const tree = load("commitment_tree_v1.json");
const history = load("history_v1.json");
const native = load("native_transfer_event_v1.json");
const fastPause = load("fast_pause_v1.json");
const forgery = load("forgery_evidence_v1.json");
const SOURCE = "contracts/evm/sccp/SccpTairaXor.sol";
const HARNESS = "contracts/evm/sccp/test/harness/SccpFixtureHarness.sol";
const T0 = 1_800_000_000n;
const evmDirections = () => payload.directions.filter((row) =>
  profiles.some((profile) => [row.source, row.target].includes(profile.network)));
const pathIds = (rows, countKey) => rows.flatMap((row) => row.paths.map((_, index) => `${row[countKey]}/${index}`));

/** Independent fixture enumeration consumed by the suite's executed-row ledger. */
function expectedRows() {
  return {
    "shared/payload.directions": evmDirections().map((row) => row.label),
    "shared/payload.rejected": payload.rejected_payloads.map((row) => row.label),
    "shared/tree.examples": Object.keys(tree.examples),
    "shared/tree.roots": tree.trees.map((row) => String(row.count)),
    "shared/tree.paths": pathIds(tree.trees, "count"),
    "shared/tree.negatives": tree.negatives.map((row) => row.label),
    "shared/history.roots": ["0", ...history.sizes.map((row) => String(row.size))],
    "shared/history.paths": pathIds(history.sizes, "size"),
    "shared/native.transfers": native.transfers.filter((row) => row.log).map((row) => row.source_profile),
    "shared/native.voids": profiles.flatMap((profile) => native.voids.map((row) => `${profile.name}/${row.name}`)),
    "shared/fast_pause.controls": fastPause.controls.filter((row) => row.network === "ethereum-mainnet").map((row) => row.id),
    "shared/forgery.ids": [...forgery.rows, ...forgery.deduplication].map((row) => row.label),
  };
}

/** Pin both row totals and every position: regenerated fixtures cannot shed coverage. */
function pinRows() {
  assert.equal(fastPause.controls.length, 8);
  assert.equal(fastPause.controls.filter((row) => row.network === "ethereum-mainnet").length, 4);
  assert.equal(forgery.rows.length, 19);
  assert.equal(forgery.deduplication.length, 3);
  assert.deepEqual({
    directions: payload.directions.length, evmDirections: evmDirections().length,
    refusals: payload.rejected_payloads.length, treeLeaves: tree.leaves.length,
    treeRoots: tree.trees.length, treePaths: pathIds(tree.trees, "count").length,
    negatives: tree.negatives.length, examples: Object.keys(tree.examples).length,
    historyLeaves: history.leaves.length, historyRoots: history.sizes.length,
    historyPaths: pathIds(history.sizes, "size").length,
    transfers: native.transfers.length, evmTransfers: native.transfers.filter((row) => row.log).length,
    voids: native.voids.length, voidLogs: native.voids.reduce((sum, row) => sum + row.logs.length, 0),
  }, {
    directions: 6, evmDirections: 4, refusals: 33, treeLeaves: 512, treeRoots: 18,
    treePaths: 665, negatives: 6, examples: 3, historyLeaves: 40, historyRoots: 40,
    historyPaths: 820, transfers: 3, evmTransfers: 2, voids: 2, voidLogs: 4,
  });
  for (const row of tree.trees) assert.equal(row.paths.length, row.count, `all ${row.count} tree positions`);
  for (const row of history.sizes) assert.equal(row.paths.length, row.size, `all ${row.size} history positions`);
  assert.equal(Math.max(...tree.trees.map((row) => row.count)), tree.leaves.length);
  assert.equal(Math.max(...history.sizes.map((row) => row.size)), history.leaves.length);
  for (const [group, rows] of Object.entries(expectedRows())) {
    assert.equal(new Set(rows).size, rows.length, `unique row ids: ${group}`);
  }
}

let build;
/** Compile unchanged helper bodies with only their private visibility exposed to tests. */
function harnessBuild() {
  if (build) return build;
  let source = fs.readFileSync(path.join(REPO, SOURCE), "utf8");
  for (const name of ["_parseOutboundPayload", "_outboundMessageId", "_inboundPayload", "_inboundMessageId",
    "_merkleRoot", "_checkLeaf", "_checkBlockRef", "_transferLeaf", "_controlLeaf", "_node", "_commitMessage"]) {
    const pattern = new RegExp(`(function ${name}\\([^]*?\\))([^{]*?)\\bprivate\\b`);
    assert.equal([...source.matchAll(new RegExp(pattern.source, "g"))].length, 1, `one private ${name}`);
    source = source.replace(pattern, "$1$2internal");
  }
  // The encoding-only golden below must use exactly the production event statement.
  const emission = "emit SccpVoided(messageId, nonce);";
  assert.equal(source.split(emission).length, 2, "one production expired-void emission");
  assert(fs.readFileSync(path.join(REPO, HARNESS), "utf8").includes(emission));
  const compiled = h.compileTestSources([SOURCE, "contracts/evm/sccp/lib/BLS12_381.sol", HARNESS], { [SOURCE]: source });
  const artifact = compiled[HARNESS].SccpFixtureHarness;
  build = { name: "shared fixture harness", creation: `0x${artifact.evm.bytecode.object}`, iface: new ethers.Interface(artifact.abi) };
  return build;
}

async function openHarness(modelDestination, options) {
  const target = harnessBuild();
  const opened = await modelDestination({ ...options, target });
  opened.destination = new h.Destination(opened.chain, opened.destination.address, target.iface);
  return opened;
}

/** Both EVM outbound decoders, both inbound builders, and every malformed row. */
async function replayPayloads(hardfork, ledger, modelDestination) {
  for (const row of evmDirections()) {
    const profile = profiles.find((entry) => [row.source, row.target].includes(entry.network));
    const { chain, destination } = await openHarness(modelDestination, { hardfork, profile, revision: row.route_revision });
    try {
      assert.equal(m.payloadHash(row.payload), row.payload_hash, row.label);
      if (row.source === "sora-taira") {
        const decoded = await destination.view("fixtureOutbound", [row.payload]);
        assert.deepEqual([...decoded], [BigInt(row.nonce), BigInt(row.deadline_ms), BigInt(row.amount),
          ethers.getAddress(row.recipient), row.message_id], row.label);
      } else {
        const decoded = await destination.simulate("fixtureInbound", [row.nonce, row.amount, row.recipient], row.sender);
        assert.deepEqual([...decoded], [row.payload, row.message_id], row.label);
      }
      ledger.ran("shared/payload.directions", row.label);
    } finally { await chain.close(); }
  }
  const { chain, destination } = await openHarness(modelDestination, { hardfork, profile: profiles[0] });
  try {
    const sourceErrors = new Set(["Truncated", "TrailingBytes", "TooLong", "WrongKind", "WrongVersion", "BadDomains",
      "ZeroRevision", "BadAsset", "WrongSenderCodec", "DeadlineMismatch", "ZeroAmount", "BadRecipient",
      "WrongRecipientCodec", "BadSender", "RouteMismatch", "BadRouteId", "TonAmountBound"]);
    for (const row of payload.rejected_payloads) {
      assert(sourceErrors.has(row.error), `${row.label}: classify new source error ${row.error}`);
      // EVM intentionally has a compact error surface. Zero own-chain address
      // reaches BadRecipient; malformed layouts, foreign directions and all
      // other decoding errors are BadPayload (including a 21-byte recipient).
      const expected = row.label === "zero_evm_recipient" ? "BadRecipient" : "BadPayload";
      await h.expectRevert(destination.view("fixtureOutbound", [row.payload]), expected, []);
      ledger.ran("shared/payload.rejected", row.label);
    }
  } finally { await chain.close(); }
}

/** All counts and positions, including promoted odd nodes and leaf-type confusion. */
async function replayTrees(hardfork, ledger, modelDestination) {
  const { chain, destination } = await openHarness(modelDestination, { hardfork, profile: profiles[0],
    relocateTo: r.addressOfWord(tree.destination.destination_word), revision: tree.destination.route_revision });
  try {
    const { transfer, control, node } = tree.examples;
    const fields = { controlNonce: control.control_nonce, track: control.track,
      parliamentPaused: Boolean(control.parliament_paused), fastPauseUntilMs: control.fast_pause_until_ms,
      certificateId: control.certificate_id, effectHash: control.effect_hash, leafIndex: 0, path: [],
      block: { height: 0, sccpRoot: m.ZERO32, messageCount: 0, historyIndex: 0, historyPath: [] } };
    assert.deepEqual([...(await destination.view("fixtureLeaves", [transfer.message_id, fields, node.left, node.right]))],
      [transfer.leaf, control.leaf, node.node]);
    for (const name of Object.keys(tree.examples)) ledger.ran("shared/tree.examples", name);
    for (const row of tree.trees) {
      for (const [index, siblings] of row.paths.entries()) {
        const args = [tree.leaves[index], index, row.count, siblings];
        assert.equal(await destination.view("fixtureRoot", args), row.root, `tree ${row.count}/${index}`);
        await destination.view("fixtureCheckLeaf", [...args, row.root]);
        ledger.ran("shared/tree.paths", `${row.count}/${index}`);
      }
      ledger.ran("shared/tree.roots", String(row.count));
    }
    for (const row of tree.negatives) {
      const args = [row.leaf, row.index, row.count, row.path];
      if (row.result.error) {
        assert(["PathTooShort", "PathTooLong", "IndexOutOfRange"].includes(row.result.error));
        await h.expectRevert(destination.view("fixtureRoot", args), "BadProof", []);
      } else {
        assert.equal(await destination.view("fixtureRoot", args), row.result.computed_root, row.label);
        assert.notEqual(row.result.computed_root, row.expected_root, row.label);
      }
      await h.expectRevert(destination.view("fixtureCheckLeaf", [...args, row.expected_root]), "BadProof", []);
      ledger.ran("shared/tree.negatives", row.label);
    }
  } finally { await chain.close(); }
}

/** Every recorded historical block under every accumulator size and root. */
async function replayHistory(hardfork, ledger, modelDestination) {
  const { chain, destination } = await openHarness(modelDestination, { hardfork, profile: profiles[0] });
  try {
    for (const row of history.sizes) {
      for (const [index, siblings] of row.paths.entries()) {
        const leaf = history.leaves[index];
        const reference = { height: leaf.height, sccpRoot: leaf.sccp_root, messageCount: leaf.message_count,
          historyIndex: index, historyPath: siblings };
        assert.equal(await destination.view("fixtureRoot", [leaf.leaf, index, row.size, siblings]), row.root);
        assert.deepEqual([...(await destination.view("fixtureHistory", [row.size, row.root, reference]))],
          [leaf.sccp_root, BigInt(leaf.message_count)], `history ${row.size}/${index}`);
        ledger.ran("shared/history.paths", `${row.size}/${index}`);
      }
      ledger.ran("shared/history.roots", String(row.size));
    }
    const leaf = history.leaves[0];
    await h.expectRevert(destination.view("fixtureHistory", [0, history.empty_root,
      { height: leaf.height, sccpRoot: leaf.sccp_root, messageCount: leaf.message_count, historyIndex: 0, historyPath: [] }]),
    "BadProof", []);
    ledger.ran("shared/history.roots", "0");
  } finally { await chain.close(); }
}

const receiptLogs = (receipt, topic) => receipt.logs.filter((log) => log.topics[0] === topic)
  .map((log) => ({ address: log.address.toLowerCase(), topics: [...log.topics], data: log.data }));

/** Actual ETH/BSC burns and voids, compared byte-for-byte with the native-event goldens. */
async function replayNativeEvents(hardfork, ledger, modelDestination) {
  for (const profile of profiles) {
    for (const row of native.transfers.filter((entry) => entry.source_profile === profile.network)) {
      const { chain, destination, taira, deployment } = await modelDestination({ hardfork, profile,
        revision: row.route_revision, relocateTo: row.log.address });
      try {
        const sender = row.sender.bytes;
        await chain.rpc("hardhat_setBalance", [sender, ethers.toQuantity(10n ** 20n)]);
        await chain.rpc("hardhat_impersonateAccount", [sender]);
        const leaf = taira.transfer({ nonce: 0, amount: BigInt(row.amount) * (BigInt(row.nonce) + 1n),
          deadlineMs: (T0 + 100n) * 1000n, recipient: sender });
        const block = taira.block(1001n, T0 * 1000n, [leaf]);
        await destination.tx("finalizeFromTaira", [r.certificateArg(taira.certify(block)), taira.messageProof(block.height, 0, block)], { at: T0 });
        let receipt;
        for (let nonce = 0n; nonce <= BigInt(row.nonce); ++nonce) {
          receipt = await destination.tx("transferToTaira", [row.recipient.bytes, row.amount, nonce], { from: sender, at: T0 });
        }
        assert.deepEqual(receiptLogs(receipt, native.event_topics.SccpTransferToTaira), [row.log], row.source_profile);
        assert.equal(await chain.returnData(receipt), row.message_id);
        assert.equal(await destination.view("balanceOf", [sender]), 0n);
        assert.equal(m.payloadHash(row.payload), row.payload_hash);
        ledger.ran("shared/native.transfers", row.source_profile);

        for (const voidRow of native.voids) {
          assert(["expired", "frozen"].includes(voidRow.normalized.void_kind), `new void kind ${voidRow.name}`);
          if (voidRow.normalized.void_kind === "expired") {
            const expired = taira.transfer({ nonce: voidRow.normalized.first_nonce, amount: row.amount,
              deadlineMs: (T0 + 100n) * 1000n, recipient: sender });
            const expiredBlock = taira.block(1002n, T0 * 1000n, [expired]);
            const actual = await destination.tx("voidExpired", [voidRow.normalized.first_nonce,
              r.certificateArg(taira.certify(expiredBlock)), taira.messageProof(expiredBlock.height, 0, expiredBlock)], { at: T0 + 101n });
            // The encoding fixture deliberately uses an arbitrary id with no
            // payload preimage. Production must emit the actual certified id;
            // all other topics/data/address are exactly the recorded layout.
            assert.deepEqual(receiptLogs(actual, native.event_topics.SccpVoided), voidRow.logs.map((log) =>
              ({ ...log, topics: [log.topics[0], expired.messageId, ...log.topics.slice(2)] })));
            const harness = await openHarness(modelDestination, { hardfork, profile,
              revision: row.route_revision, relocateTo: voidRow.normalized.emitter });
            try {
              const encoded = await harness.destination.tx("fixtureVoidEvent", [voidRow.normalized.message_id_or_zero,
                voidRow.normalized.first_nonce], { at: T0 });
              assert.deepEqual(receiptLogs(encoded, native.event_topics.SccpVoided), voidRow.logs);
            } finally { await harness.chain.close(); }
          } else {
            const frozen = await destination.tx("voidFrozen", [voidRow.normalized.first_nonce, voidRow.normalized.count],
              { at: deployment.initialUntilMs / 1000n + 1n });
            assert.deepEqual(receiptLogs(frozen, native.event_topics.SccpVoided), voidRow.logs);
          }
          ledger.ran("shared/native.voids", `${profile.name}/${voidRow.name}`);
        }
      } finally { await chain.close(); }
    }
  }
}

/** Full public applyControl replay with real q-share certificates of the recorded leaves. */
async function replayFastPause(hardfork, ledger, modelDestination) {
  for (const row of fastPause.controls.filter((entry) => entry.network === "ethereum-mainnet")) {
    const at = BigInt(row.now_ms) / 1000n;
    assert.equal(at * 1000n, BigInt(row.now_ms));
    const { chain, destination, taira } = await openHarness(modelDestination, {
      hardfork, profile: profiles[0], revision: row.fields.route_revision, at,
      relocateTo: r.addressOfWord(row.destination_word),
    });
    try {
      const f = row.fields;
      const fields = { controlNonce: f.control_nonce, track: f.track,
        parliamentPaused: Boolean(f.parliament_paused), fastPauseUntilMs: f.fast_pause_until_ms,
        certificateId: f.certificate_id, effectHash: f.effect_hash };
      assert.equal(m.controlLeaf({ networkId: row.network_id, profile: profiles[0],
        destinationWord: row.destination_word, revision: f.route_revision, nonce: f.control_nonce, ...fields }), row.leaf);
      assert.equal(ethers.keccak256(row.preimage), row.leaf);
      const block = taira.block(1001n, BigInt(row.now_ms), [taira.recordedControl(row.leaf, fields)]);
      const proof = taira.controlProof(block.height, 0, block);
      const leaves = await destination.view("fixtureLeaves", [m.ZERO32, proof, m.ZERO32, m.ZERO32]);
      assert.equal(leaves[1], row.leaf, row.id);
      const args = [r.certificateArg(taira.certify(block)), proof];
      if (row.previous_control_nonce !== 0) {
        assert.equal(row.previous_control_nonce, f.control_nonce);
        await destination.tx("applyControl", args, { at });
        await h.expectRevert(destination.simulate("applyControl", args), row.expected.outcome, []);
      } else {
        assert.equal(row.expected.outcome, "Applied");
        await destination.tx("applyControl", args, { at });
      }
      const pause = await destination.view("pauseState", []);
      assert.deepEqual([...pause], [Boolean(f.parliament_paused), BigInt(row.expected.applied_until_ms),
        BigInt(f.control_nonce), row.expected.minting_paused], row.id);
      ledger.ran("shared/fast_pause.controls", row.id);
    } finally { await chain.close(); }
  }
}

/** Evidence ids are Taira hashes; bind them to the destination's actual signed message. */
async function replayForgeryIds(hardfork, ledger, modelDestination) {
  const { createRequire } = require("node:module");
  const runtime = process.env.SCCP_EVM_RUNTIME_DIR || path.join(REPO, "scripts/contract_tooling/evm-runtime");
  const { blake2b } = createRequire(path.join(runtime, "package.json"))("@noble/hashes/blake2b");
  const id = (generation, message, signers) => {
    const bytes = blake2b(ethers.getBytes(ethers.concat([ethers.toUtf8Bytes("sccp/forgery-evidence/v1"),
      ethers.toBeHex(generation, 8), message, ethers.toBeHex(signers, 4)])), { dkLen: 32 });
    bytes[31] |= 1;
    return ethers.hexlify(bytes);
  };
  const { chain, destination } = await openHarness(modelDestination, { hardfork, profile: profiles[0] });
  try {
    const derivedMessages = new Map();
    const coreOutcomes = new Set(["E1", "E2", "E3", "E4", "NotEvidence", "EvidenceExpired", "WitnessRequired", "BadWitness"]);
    for (const row of forgery.rows) {
      assert(coreOutcomes.has(row.expected.outcome), `${row.label}: explicit Taira evidence outcome`);
      const message = await destination.view("fixtureCommitMessage", [row.input.qc, row.input.header]);
      assert.equal(message, row.expected.message, row.label);
      assert.equal(m.wireDigests(forgery.constants.consensus_instance, row.input.qc, row.input.header).r,
        row.expected.result, row.label);
      const signers = BigInt(ethers.dataSlice(row.input.qc, 112, 116));
      const generation = BigInt(ethers.dataSlice(row.input.header, 141, 149));
      assert.equal(id(generation, message, signers), row.expected.evidence_id, row.label);
      derivedMessages.set(row.label, message);
      ledger.ran("shared/forgery.ids", row.label);
    }
    for (const row of forgery.deduplication) {
      assert(["Recorded", "EvidenceDuplicate"].includes(row.expected.outcome));
      assert.equal(id(row.input.generation, derivedMessages.get("e2_future"), row.input.signers), row.expected.evidence_id, row.label);
      ledger.ran("shared/forgery.ids", row.label);
    }
  } finally { await chain.close(); }
}

module.exports = { expectedRows, pinRows, replayPayloads, replayTrees, replayHistory, replayNativeEvents,
  replayFastPause, replayForgeryIds };
