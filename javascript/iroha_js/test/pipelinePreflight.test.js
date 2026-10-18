// `GET /v1/pipeline/preflight` parsing against the Rust-produced Torii body.
//
// `fixtures/torii/pipeline_preflight.json` is generated from Torii's
// `PipelinePreflightResponse` by
// `cargo test -p iroha_torii --lib pipeline_preflight_fixture`; it is never
// hand-edited, so these tests pin the SDK to the fields the node serves.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { NetworkId } from "../src/networkId.js";
import { ToriiClient, isStatusQueueStalled } from "../src/toriiClient.js";
import { makeTestOperatorSigningContext } from "./toriiClientTestHelpers.js";

const BASE_URL = "https://torii.example";
const FIXTURE_TEXT = readFileSync(
  new URL("../../../fixtures/torii/pipeline_preflight.json", import.meta.url),
  "utf8",
);
const OPERATOR_SIGNING_CONTEXT = makeTestOperatorSigningContext(
  NetworkId.fromBytes(Buffer.alloc(32, 0xa5)),
);
const STALL_BLOCK_CADENCES = 20;

function servedPayload() {
  return JSON.parse(FIXTURE_TEXT);
}

async function fetchPreflight(payload, onRequest = () => {}) {
  const client = new ToriiClient(BASE_URL, {
    operatorSigningContext: OPERATOR_SIGNING_CONTEXT,
    fetchImpl: async (url, init) => {
      onRequest(url, init);
      return new Response(JSON.stringify(payload), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  return client.getPipelinePreflight();
}

function status(queueSize, nonEmptyElapsedMs, lastBlockElapsedMs = 0) {
  return {
    queue_size: queueSize,
    time_since_last_block_ms: lastBlockElapsedMs,
    time_since_last_non_empty_block_ms: nonEmptyElapsedMs,
  };
}

test("fixture carries exactly the served preflight sections", () => {
  const payload = servedPayload();
  assert.deepEqual(Object.keys(payload), [
    "schema_version",
    "chain_height",
    "sumeragi",
    "admission",
    "block",
    "pipeline",
    "queue",
    "fees",
  ]);
  assert.deepEqual(Object.keys(payload.sumeragi), ["block_cadence_ms"]);
});

test("getPipelinePreflight parses every served field of the Rust sample", async () => {
  const payload = servedPayload();
  let request;
  const preflight = await fetchPreflight(payload, (url, init) => {
    request = { url, init };
  });

  assert.equal(request.url, `${BASE_URL}/v1/pipeline/preflight`);
  assert.equal(request.init.method, "GET");
  assert.equal(preflight.schema_version, 1);
  assert.equal(preflight.chain_height, 42);
  assert.deepEqual(preflight.sumeragi, { block_cadence_ms: 1_000 });
  assert.deepEqual(preflight.admission, {
    max_signatures: 16,
    max_instructions: 4_096,
    max_tx_bytes: 1_048_576,
    max_decompressed_bytes: 4_194_304,
    max_metadata_depth: 8,
  });
  assert.deepEqual(preflight.block, { max_transactions: 512 });
  assert.deepEqual(preflight.pipeline, {
    signature_batch_max_ed25519: 64,
    signature_batch_max_secp256k1: 32,
    signature_batch_max_pqc: 12,
    signature_batch_max_bls: 24,
    overlay_max_instructions: 2_048,
    ivm_max_cycles_upper_bound: 2_000_000,
    ivm_admission_cycle_limit: 1_000_000,
    ivm_max_decoded_instructions: 131_072,
  });
  assert.deepEqual(preflight.queue, { size: 3, queued: 2, inflight: 1 });
  assert.deepEqual(preflight.fees, {
    ...payload.fees,
    base_fee: "0.1",
    per_byte_fee: "0.0002",
    per_instruction_fee: "0.001",
    per_gas_unit_fee: "0.00005",
  });
  assert.equal(preflight.fees.successful_claim_fee_exempt_authorities.length, 1);
  assert.notEqual(
    preflight.fees.fee_sink_account_id,
    preflight.fees.sponsor_vault_custody_account_id,
  );
  assert.deepEqual(preflight.raw, payload);
});

test("stall threshold is twenty served block cadences", async () => {
  const preflight = await fetchPreflight(servedPayload());
  const threshold = STALL_BLOCK_CADENCES * 1_000;

  assert.equal(preflight.stallThresholdMs, threshold);
  assert.equal(preflight.isStatusStalled(status(1, threshold)), false);
  assert.equal(preflight.isStatusStalled(status(1, threshold + 1)), true);
  assert.equal(preflight.isStatusStalled(status(0, threshold + 1)), false);
  // Before the first non-empty block the elapsed time since any block is used.
  assert.equal(preflight.isStatusStalled(status(1, 0, threshold + 1)), true);
  assert.equal(preflight.isStatusStalled(status(1, 0, threshold)), false);
  assert.equal(
    preflight.isStatusStalled(status(2, threshold + 1)),
    isStatusQueueStalled(status(2, threshold + 1), preflight.stallThresholdMs),
  );
});

test("stall threshold scales with the served cadence and saturates", async () => {
  const slow = servedPayload();
  slow.sumeragi.block_cadence_ms = 5_000;
  assert.equal((await fetchPreflight(slow)).stallThresholdMs, 100_000);

  const huge = servedPayload();
  huge.sumeragi.block_cadence_ms = Number.MAX_SAFE_INTEGER;
  const saturated = await fetchPreflight(huge);
  assert.equal(saturated.stallThresholdMs, Number.MAX_SAFE_INTEGER);
  assert.equal(
    saturated.isStatusStalled(status(1, Number.MAX_SAFE_INTEGER)),
    false,
  );
});

test("getPipelinePreflight rejects the retired sumeragi timing fields", async () => {
  for (const field of ["block_time_ms", "commit_time_ms", "stall_threshold_ms"]) {
    const payload = servedPayload();
    payload.sumeragi[field] = 6_000;
    await assert.rejects(
      () => fetchPreflight(payload),
      new RegExp(`sumeragi contains unknown field ${field}`, "u"),
    );
  }
  const retired = servedPayload();
  retired.sumeragi = { block_time_ms: 1_000, commit_time_ms: 2_000, stall_threshold_ms: 6_000 };
  await assert.rejects(() => fetchPreflight(retired), /sumeragi contains unknown field/u);
});

test("getPipelinePreflight requires a positive integer block cadence", async () => {
  for (const [value, message] of [
    [undefined, /block_cadence_ms is required/u],
    [0, /block_cadence_ms must be positive/u],
    ["1000", /block_cadence_ms must be an integer/u],
    [-1, /block_cadence_ms must be >= 0/u],
  ]) {
    const payload = servedPayload();
    if (value === undefined) {
      delete payload.sumeragi.block_cadence_ms;
    } else {
      payload.sumeragi.block_cadence_ms = value;
    }
    await assert.rejects(() => fetchPreflight(payload), message);
  }
});

test("getPipelinePreflight rejects fields Torii does not serve", async () => {
  for (const section of [null, "admission", "block", "pipeline", "queue", "fees"]) {
    const payload = servedPayload();
    const target = section === null ? payload : payload[section];
    target.unserved_field = 1;
    await assert.rejects(
      () => fetchPreflight(payload),
      /contains unknown field unserved_field/u,
    );
  }
});

test("getPipelinePreflight rejects the retired aggregate signature batch field", async () => {
  const payload = servedPayload();
  payload.pipeline.signature_batch_max = 0;
  await assert.rejects(
    () => fetchPreflight(payload),
    /pipeline contains unknown field signature_batch_max/u,
  );
});

test("getPipelinePreflight requires both positive current IVM cycle limits", async () => {
  for (const [field, value] of [
    ["ivm_max_cycles_upper_bound", undefined],
    ["ivm_admission_cycle_limit", 0],
  ]) {
    const payload = servedPayload();
    if (value === undefined) {
      delete payload.pipeline[field];
    } else {
      payload.pipeline[field] = value;
    }
    await assert.rejects(() => fetchPreflight(payload), /is required|must be positive/u);
  }
});

test("getPipelinePreflight rejects alias-shaped fee account ids", async () => {
  for (const [field, value] of [
    ["fee_sink_account_id", "fees@system"],
    ["sponsor_vault_custody_account_id", "vault@system"],
    ["successful_claim_fee_exempt_authorities", ["authority@system"]],
  ]) {
    const payload = servedPayload();
    payload.fees[field] = value;
    await assert.rejects(
      () => fetchPreflight(payload),
      /must not include '@domain'|canonical I105 account id/u,
    );
  }
});

test("getPipelinePreflight requires the served fee strings", async () => {
  for (const [field, value, message] of [
    ["fee_asset_id", undefined, /fees\.fee_asset_id must be a non-empty string/u],
    ["base_fee", 0, /fees\.base_fee must be a non-empty string/u],
    [
      "successful_claim_fee_exempt_authorities",
      undefined,
      /successful_claim_fee_exempt_authorities must be an array of strings/u,
    ],
  ]) {
    const payload = servedPayload();
    if (value === undefined) {
      delete payload.fees[field];
    } else {
      payload.fees[field] = value;
    }
    await assert.rejects(() => fetchPreflight(payload), message);
  }
  const relay = servedPayload();
  relay.fees.settlement_mode = "lane_relay_burn";
  await assert.rejects(() => fetchPreflight(relay), /contains unknown field settlement_mode/u);
});
