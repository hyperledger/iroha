import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { ToriiClient, LocalSigningContext } from "../src/toriiClient.js";
import { NetworkId } from "../src/networkId.js";
import {
  decodeValidatorStakingPreparationFrameV1 as decode,
  encodeValidatorStakingPreparationFrameV1 as encode,
  validateValidatorStakingPreparationV1 as validate,
} from "../src/norito.js";

const rows = new Map(readFileSync(new URL("../../../fixtures/validator_staking/preparation_v1.tsv", import.meta.url), "utf8")
  .split("\n").filter((row) => row && !row.startsWith("#")).map((row) => {
    const [name, hex] = row.split("\t"); return [name, Buffer.from(hex, "hex")];
  }));
const names = ["registration", "bond", "unbond", "claim"];
function fixture(kind = "registration") {
  const requestBytes = rows.get(`prepare_${kind}_request`), responseBytes = rows.get(`prepare_${kind}_response`);
  assert.ok(requestBytes && responseBytes, `missing Rust preparation frames for ${kind}`);
  const request = decode("PreparationRequest", requestBytes), response = decode("Preparation", responseBytes);
  return { request, response, requestBytes, responseBytes, network: response.network_id, xor: response.xor_asset_definition_id };
}
function response(bytes, status = 200, headers = {}) {
  return new Response(bytes, { status, headers: { "Content-Type": "application/x-norito", ...headers } });
}
function client(f, fetchImpl, extra = {}) {
  return new ToriiClient("https://staking.invalid", { localSigningContext: new LocalSigningContext(f.network, 753),
    fetchImpl, maxRetries: 3, retryMethods: ["POST"], ...extra });
}

test("preparation reproduces every Rust request/response frame and pinned Global XOR binding", () => {
  for (const name of names) {
    const f = fixture(name);
    assert.deepEqual(encode("PreparationRequest", f.request), f.requestBytes);
    assert.deepEqual(encode("Preparation", f.response), f.responseBytes);
    assert.equal(validate(f.response, f.request, f.network, f.xor), f.response);
    assert.equal(f.response.observed_height, 200n);
    assert.equal(f.response.assumed_execution_height, 201n);
    assert.equal(f.response.balances.length, 2);
    for (const row of f.response.balances) {
      assert.equal(row.stake_reserved, "1000"); assert.equal(row.rewards_reserved, "22");
      assert.deepEqual(row.asset.scope, { kind: "global", value: null });
    }
  }
});

test("preparation exact frames reject truncation, schema, layout, CRC, padding and oversize", () => {
  const f = fixture();
  for (let end = 0; end < f.responseBytes.length; end += 1) assert.throws(() => decode("Preparation", f.responseBytes.subarray(0, end)));
  for (const index of [4, 5, 6, 22, 23, 31, 39]) {
    const bytes = Buffer.from(f.responseBytes); bytes[index] ^= 1;
    assert.throws(() => decode("Preparation", bytes));
  }
  assert.throws(() => decode("Preparation", Buffer.concat([f.responseBytes, Buffer.of(0)])));
  assert.throws(() => decode("Preparation", Buffer.concat([f.responseBytes.subarray(0, 40), Buffer.of(0), f.responseBytes.subarray(40)])));
  assert.throws(() => decode("Preparation", f.requestBytes));
  assert.throws(() => decode("Preparation", Buffer.alloc(256 * 1024 + 1)), /bound/);
  assert.throws(() => encode("PreparationRequest", { ...f.request, valid_for_blocks: 0 }), /positive/);
});

test("preparation response cannot change intent, network, XOR, scope, expiry or exact balance set", () => {
  const f = fixture();
  const reject = (value, message) => assert.throws(() => validate(value, f.request, f.network, f.xor), message);
  reject({ ...f.response, request: { ...f.request, lane_id: 1 } }, /request/);
  const other = Buffer.from(f.network.toBytes()); other[0] ^= 1;
  reject({ ...f.response, network_id: NetworkId.fromBytes(other) }, /network/);
  reject({ ...f.response, xor_asset_definition_id: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM" }, /xor_asset_definition_id/);
  reject({ ...f.response, observed_height: 0n }, /height/);
  reject({ ...f.response, assumed_execution_height: 202n }, /height/);
  reject({ ...f.response, balances: [...f.response.balances].reverse() }, /balances/);
  reject({ ...f.response, balances: [f.response.balances[0]] }, /balances/);
  const p = f.response.plan.value;
  reject({ ...f.response, plan: { kind: "monetary", value: { ...p, amount: "999" } } }, /intent/);
  reject({ ...f.response, plan: { kind: "monetary", value: { ...p, valid_until_height: 211n } } }, /expiry/);
  reject({ ...f.response, plan: { kind: "monetary", value: { ...p, precondition: { kind: "registration", value: { activation_height: 0n } } } } }, /intent/);
  const scoped = { ...p.source_asset, scope: { kind: "dataspace", value: 7n } };
  const badScope = { ...f.response, plan: { kind: "monetary", value: { ...p, source_asset: scoped, destination_asset: { ...p.destination_asset, scope: scoped.scope } } },
    balances: f.response.balances.map((row) => ({ ...row, asset: { ...row.asset, scope: scoped.scope } })) };
  reject(badScope, /global_xor/);
  assert.throws(() => validate(f.response, f.request, f.network, "invalid-xor"));
});

test("reward preparation binds the automatic entitlement and current recipient", () => {
  const f = fixture("claim"), plan = f.response.plan.value;
  const reject = (value) => assert.throws(() => validate({ ...f.response, plan: { kind: "claim", value } }, f.request, f.network, f.xor));
  reject({ ...plan, fee_claim: null });
  reject({ ...plan, fee_claim: { ...plan.fee_claim, amount: "0" } });
  reject({ ...plan, fee_claim: { ...plan.fee_claim, lifecycle_seal: Buffer.alloc(32) } });
  reject({ ...plan, fee_claim: { ...plan.fee_claim, destination_asset: plan.fee_claim.source_asset } });
  for (const retired of ["max_records", "upto_epoch", "accrued_sources"]) {
    const request = { ...f.request, operation: { ...f.request.operation, value: { ...f.request.operation.value, [retired]: null } } };
    assert.throws(() => encode("PreparationRequest", request), /exact native fields/);
  }
});

test("staking preparation sends one exact unsigned POST and retains request against callback mutation", async () => {
  const f = fixture(); let calls = 0;
  const c = client(f, async (url, init) => {
    calls += 1; assert.equal(url, "https://staking.invalid/v1/nexus/staking/prepare");
    assert.equal(init.method, "POST"); assert.equal(init.redirect, "error");
    assert.deepEqual(Buffer.from(init.body), f.requestBytes);
    assert.equal(new Headers(init.headers).get("Content-Type"), "application/x-norito");
    assert.equal(new Headers(init.headers).get("x-iroha-signature"), null);
    f.request.operation.value.amount = "999";
    return response(f.responseBytes);
  });
  const result = await c.preparePublicLanePlan(f.request, f.xor);
  assert.equal(result.plan.value.amount, "1000"); assert.equal(calls, 1);
});

test("staking transport rejects wrong media, missing binding, cancellation and unbounded error bodies", async () => {
  const f = fixture();
  for (const reply of [() => response(f.responseBytes, 200, { "Content-Type": "application/json" }),
    () => response(f.responseBytes, 200, { "Content-Length": String(256 * 1024 + 1) }),
    () => response(Buffer.alloc(256 * 1024 + 1), 503), () => response(Buffer.of(1), 503)]) {
    let calls = 0; const c = client(f, async () => { calls += 1; return reply(); });
    await assert.rejects(c.preparePublicLanePlan(f.request, f.xor)); assert.equal(calls, 1);
  }
  let calls = 0; const c = client(f, async () => { calls += 1; return response(f.responseBytes); });
  const signal = AbortSignal.abort(new Error("cancelled"));
  await assert.rejects(c.preparePublicLanePlan(f.request, f.xor, { signal }), /cancelled/); assert.equal(calls, 0);
  const noPin = new ToriiClient("https://staking.invalid", { fetchImpl: async () => { calls += 1; } });
  await assert.rejects(noPin.preparePublicLanePlan(f.request, f.xor)); assert.equal(calls, 0);
});

// These transports deliberately ignore fetch cancellation, as user-supplied
// fetch callbacks may do. The production owner must stop waiting and dispose
// the eventual response without relying on a cooperative callback.
test("staking preparation original deadline cancels a slow body after late headers", { timeout: 2000 }, async () => {
  const f = fixture();
  // Warm the ordinary optional module before the measured mocked dispatch.
  await client(f, async () => response(f.responseBytes)).preparePublicLanePlan(f.request, f.xor);
  for (const status of [200, 503]) {
    let cancelled = false, completed = false, calls = 0, bodyTimer;
    const c = client(f, async () => {
      calls += 1;
      await new Promise((resolve) => setTimeout(resolve, 60));
      return response(new ReadableStream({
        start(controller) {
          controller.enqueue(f.responseBytes.subarray(0, 1));
          // Completion is after the original 100 ms deadline but before a
          // mistakenly reset 100 ms body deadline starting at the headers.
          bodyTimer = setTimeout(() => {
            completed = true;
            controller.enqueue(f.responseBytes.subarray(1));
            controller.close();
          }, 70);
        },
        cancel() { cancelled = true; clearTimeout(bodyTimer); },
      }), status);
    }, { timeoutMs: 100 });
    try {
      await assert.rejects(c.preparePublicLanePlan(f.request, f.xor), /timed out/);
      assert.equal(cancelled, true); assert.equal(completed, false); assert.equal(calls, 1);
    } finally { clearTimeout(bodyTimer); }
  }
});

test("staking preparation original deadline disposes headers arriving after timeout", { timeout: 2000 }, async () => {
  const f = fixture(); let deliver, cancelled = false, calls = 0;
  const c = client(f, () => { calls += 1; return new Promise((resolve) => { deliver = resolve; }); }, { timeoutMs: 30 });
  await assert.rejects(c.preparePublicLanePlan(f.request, f.xor), /timed out/);
  assert.equal(calls, 1);
  const disposed = new Promise((resolve) => {
    deliver(response(new ReadableStream({ cancel() { cancelled = true; resolve(); } })));
  });
  await disposed;
  assert.equal(cancelled, true);
});

test("staking preparation disposes a late response after synchronous dispatch cancellation", { timeout: 2000 }, async () => {
  const f = fixture(), controller = new AbortController(); let deliver, cancelled = false;
  const c = client(f, () => {
    controller.abort(new Error("cancelled during dispatch"));
    return new Promise((resolve) => { deliver = resolve; });
  });
  await assert.rejects(c.preparePublicLanePlan(f.request, f.xor, { signal: controller.signal }), /cancelled during dispatch/);
  await new Promise((resolve) => {
    deliver(response(new ReadableStream({ cancel() { cancelled = true; resolve(); } })));
  });
  assert.equal(cancelled, true);
});
