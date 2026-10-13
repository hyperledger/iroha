import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { signEd25519 } from "../src/crypto.js";
import { NetworkId } from "../src/networkId.js";
import {
  parseStrictLosslessIntegerJson,
  stringifyStrictLosslessIntegerJson,
} from "../src/strictLosslessJson.js";
import { parseSumeragiLanesJson, parseSumeragiLanesPayload } from "../src/sumeragiTyped.js";
import { OperatorSigningContext, ToriiClient } from "../src/toriiClient.js";

// This shared corpus is emitted and roundtripped by the canonical Rust generator
// (`kotlin-fixture-gen native-sumeragi-lanes-v1`). JS exposes the JSON lane contract;
// it does not interpret the TSV's Norito column.
const laneRows = Object.fromEntries(
  readFileSync(new URL("../../../fixtures/sumeragi/native_lanes_v1.tsv", import.meta.url), "utf8")
    .trimEnd()
    .split("\n")
    .filter((line) => !line.startsWith("#"))
    .map((line) => {
      const [name, json, noritoHex, ...extra] = line.split("\t");
      assert.equal(extra.length, 0);
      assert.ok(noritoHex.startsWith("4e525430"), "producer must retain its canonical Norito archive");
      return [name, json];
    }),
);
assert.deepEqual(Object.keys(laneRows).sort(), ["empty", "mixed_lanes", "running_lane"]);
const U64_MAX = (1n << 64n) - 1n;

const mutate = (change) => {
  const lanes = parseStrictLosslessIntegerJson(laneRows.mixed_lanes, "fixture");
  change(lanes[0]);
  return stringifyStrictLosslessIntegerJson(lanes, "mutated fixture");
};
const mutateRecord = (change) => mutate((lane) => change(lane.record));

for (const [name, json] of Object.entries(laneRows)) {
  test(`current Rust lane corpus: ${name}`, () => {
    const lanes = parseSumeragiLanesJson(json);
    // JSON object member order is not semantic. Keep integer tokens lossless on
    // both sides so the Rust corpus's u64 values cannot round through Number.
    assert.deepEqual(
      parseStrictLosslessIntegerJson(
        stringifyStrictLosslessIntegerJson(lanes, "native lanes corpus"), "roundtripped lanes",
      ),
      parseStrictLosslessIntegerJson(json, "Rust lanes corpus"),
    );
    assert.ok(Object.isFrozen(lanes));
    for (const lane of lanes) {
      assert.ok(Object.isFrozen(lane.record));
      assert.ok(Object.isFrozen(lane.record.committee));
      assert.ok(Object.isFrozen(lane.record.params.key_allowed_algorithms));
      assert.ok(Object.isFrozen(lane.record.da_layout));
      assert.ok(Object.isFrozen(lane.record.da_layout.encoding));
    }
  });
}

test("lane corpus keeps every lane state and exact unsigned range", () => {
  assert.deepEqual([...parseSumeragiLanesJson(laneRows.empty)], []);
  const [running, pending, closing] = parseSumeragiLanesJson(laneRows.mixed_lanes);
  assert.equal(running.record.lane, 1);
  assert.equal(running.record.incarnation, "11".repeat(32));
  assert.equal(running.record.committee.length, 4);
  assert.ok(running.record.committee.every(({ peer, pop }) => peer.startsWith("ea0130") && Buffer.from(pop, "base64").length === 96));
  assert.equal(running.record.closing, null);
  assert.deepEqual([...running.record.params.key_allowed_algorithms], ["bls_normal"]);
  assert.equal(running.record.params.due_work_max_lag_ms, 60_000);
  assert.deepEqual(running.record.da_layout, {
    encoding: { encoding: "reed_solomon16", details: null }, chunk_size_bytes: 262144,
    data_shards: 4, parity_shards: 2, max_payload_size_bytes: 16777216, max_chunk_count: 1024,
  });
  assert.equal(running.instance.protocol_version, 1);
  assert.equal(running.instance.leader, running.record.committee[0].peer);
  assert.equal(running.instance.footprint.probe, U64_MAX);
  assert.equal(pending.instance, null);
  assert.equal(pending.record.dataspace, U64_MAX);
  assert.equal(pending.record.rescued, U64_MAX);
  assert.equal(pending.record.merged.block_hash, "00".repeat(32));
  assert.equal(closing.record.lane, 2 ** 32 - 1);
  assert.equal(closing.record.closing, U64_MAX);
  assert.equal(closing.record.merged.height, U64_MAX);
  assert.deepEqual({ ...closing.instance.halted }, { reason: "publication_recovery_required", details: U64_MAX });
});

test("every lane field is required and unknown or retired fields fail closed", () => {
  assert.equal(parseSumeragiLanesJson(mutate(() => {})).length, 3);
  const [lane] = parseStrictLosslessIntegerJson(laneRows.mixed_lanes, "fixture");
  for (const field of Object.keys(lane)) {
    assert.throws(() => parseSumeragiLanesJson(mutate((value) => { delete value[field]; })), field);
  }
  assert.throws(() => parseSumeragiLanesJson(mutate((value) => { value.retired = null; })));
  for (const field of Object.keys(lane.record)) {
    assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { delete record[field]; })), field);
  }
  for (const retired of ["lane_finality_manifest", "merge_carrier", "queue_plan", "relay_envelope"]) {
    assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { record[retired] = null; })), retired);
  }
  for (const owner of ["params", "da_layout", "merged"]) {
    for (const field of Object.keys(lane.record[owner])) {
      assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { delete record[owner][field]; })), `${owner}.${field}`);
    }
    assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { record[owner].legacy = 0; })));
  }
  for (const field of ["encoding", "details"]) {
    assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { delete record.da_layout.encoding[field]; })), field);
  }
  assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { record.da_layout.encoding.legacy = null; })));
  for (const field of ["peer", "pop"]) {
    assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { delete record.committee[0][field]; })), field);
  }
  assert.throws(() => parseSumeragiLanesPayload({}));
  assert.throws(() => parseSumeragiLanesPayload([{ record: lane.record, instance: { protocol_version: 1 } }]));
});

test("lane data availability admits compact final stripes and rejects malformed RS16 geometry", () => {
  const changedLayout = (change) => mutateRecord((record) => {
    // Keep the block bound valid so these cases exercise the changed DA geometry.
    record.params.max_block_bytes = 4194304;
    change(record.da_layout);
  });
  const compact = parseSumeragiLanesJson(changedLayout((layout) => {
    layout.max_payload_size_bytes = 4194305; layout.max_chunk_count = 30;
  }));
  assert.equal(compact[0].record.da_layout.max_payload_size_bytes, 4194305);
  for (const [field, bad] of [
    ["chunk_size_bytes", 0], ["chunk_size_bytes", 1], ["chunk_size_bytes", 3], ["chunk_size_bytes", 262146],
    ["data_shards", 0], ["data_shards", 17], ["data_shards", 65536], ["parity_shards", 0], ["parity_shards", 17],
    ["max_payload_size_bytes", 0], ["max_payload_size_bytes", 16777217], ["max_chunk_count", 0],
    ["max_chunk_count", 1025], ["max_chunk_count", 95],
  ]) assert.throws(() => parseSumeragiLanesJson(changedLayout((layout) => { layout[field] = bad; })), `${field}=${bad}`);
  assert.throws(() => parseSumeragiLanesJson(changedLayout((layout) => { layout.data_shards = 1; layout.parity_shards = 2; })));
  assert.throws(() => parseSumeragiLanesJson(changedLayout((layout) => { layout.encoding.encoding = "plain"; })));
  assert.throws(() => parseSumeragiLanesJson(changedLayout((layout) => { layout.encoding.details = {}; })));
  assert.throws(() => parseSumeragiLanesJson(changedLayout((layout) => { layout.max_payload_size_bytes = 4194305; layout.max_chunk_count = 29; })));
  assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { record.params.max_block_bytes = 16777217; })));
});

test("malformed lane scalars, keys, proofs and bodies never alias canonical values", () => {
  for (const bad of [-1, "1", 1.5, null, true, 2 ** 32]) {
    const lanes = parseStrictLosslessIntegerJson(laneRows.mixed_lanes, "fixture");
    lanes[0].record.lane = bad;
    assert.throws(() => parseSumeragiLanesPayload(lanes), `lane ${bad}`);
  }
  for (const bad of ["11".repeat(31), "aa".repeat(32), "11".repeat(33), 17]) {
    assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { record.incarnation = bad; })), String(bad));
  }
  for (const field of ["block_cadence_ms", "due_work_max_lag_ms", "payload_retry_interval_ms", "exec_budget_ms", "apply_budget_ms", "max_block_bytes", "epoch_length_blocks", "demotion_window"]) {
    assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { record.params[field] = 0; })), `zero ${field}`);
  }
  assert.equal(parseSumeragiLanesJson(mutateRecord((record) => { record.params.due_work_max_lag_ms = U64_MAX; }))[0].record.params.due_work_max_lag_ms, U64_MAX);
  for (const bad of [-1, U64_MAX + 1n, "60000", true, null]) {
    assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { record.params.due_work_max_lag_ms = bad; })));
  }
  assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { record.params.max_block_bytes = 2 ** 32; })));
  for (const algorithms of [["bls"], ["BLS_NORMAL"], "bls_normal", [1]]) {
    assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { record.params.key_allowed_algorithms = algorithms; })));
  }
  const [lane] = parseStrictLosslessIntegerJson(laneRows.mixed_lanes, "fixture");
  const { peer, pop } = lane.record.committee[0];
  for (const bad of [peer.toLowerCase(), `bls_normal:${peer}`, `ed0120${"AB".repeat(32)}`, ` ${peer}`]) {
    assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { record.committee[0].peer = bad; })), bad);
  }
  for (const bad of [pop.slice(0, -4), `${pop}AAAA`, `-${pop.slice(1)}`, `${pop}=`, ""]) {
    assert.throws(() => parseSumeragiLanesJson(mutateRecord((record) => { record.committee[0].pop = bad; })), bad);
  }
  const running = laneRows.running_lane;
  for (const wire of [
    running.replace('"rescued":0', '"rescued":-0'),
    running.replace('"rescued":0', '"rescued":0,"rescued":0'),
    running.replace('"rescued":0', '"rescued":0.0'),
    "",
    " ".repeat(16 * 1024 * 1024 + 1),
  ]) {
    assert.throws(() => parseSumeragiLanesJson(wire));
  }
});

test("getSumeragiLanes signs one bounded JSON GET and validates the served list", async () => {
  const privateKey = Buffer.alloc(32, 0x0b);
  const context = new OperatorSigningContext(NetworkId.fromBytes(Buffer.alloc(32, 0xa5)), {
    publicKey: "ed012066BE7E332C7A453332BD9D0A7F7DB055F5C5EF1A06ADA66D98B39FB6810C473A",
    sign: (message) => signEd25519(message, privateKey),
  });
  let served = laneRows.mixed_lanes;
  const calls = [];
  const client = new ToriiClient("https://torii.example", {
    operatorSigningContext: context,
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return new Response(served, { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  const lanes = await client.getSumeragiLanes();
  assert.equal(lanes.length, 3);
  assert.equal(lanes[2].record.closing, U64_MAX);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://torii.example/v1/sumeragi/lanes");
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.body, undefined);
  served = JSON.stringify({ protocol_version: 1 });
  await assert.rejects(() => client.getSumeragiLanes());
});
