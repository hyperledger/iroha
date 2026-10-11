import assert from "node:assert/strict";
import test from "node:test";
import { AccountAddress } from "../src/address.js";
import { _createNoritoInstructionApi } from "../src/norito.js";
import { createNativeRuntime } from "../src/nativeRuntime.js";

const instruction = { Log: { level: "INFO", msg: "canonical owner fixture" } };
const json = JSON.stringify(instruction);

test("multisig instruction vector embeds exact Rust archives without rebuilding inner frames", () => {
  const second = { Log: { level: "WARN", msg: "second owner fixture" } };
  const archiveByJson = new Map([
    [json, Buffer.of(0xde, 0xad, 0xbe, 0xef)],
    [JSON.stringify(second), Buffer.of(0x91, 0x23, 0x45)],
  ]);
  const archiveCalls = [];
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction: (value) => Buffer.from(value),
    noritoDecodeInstruction: (bytes) => Buffer.from(bytes).toString(),
    noritoEncodeInstructionBoxArchive(value) {
      archiveCalls.push(value);
      return archiveByJson.get(value);
    },
  }));
  const actual = api._encodeMultisigInstructions([instruction, second], 753);
  assert.deepEqual(actual, Buffer.from([
    2, 0, 0, 0, 0, 0, 0, 0, // vector count
    4, 0xde, 0xad, 0xbe, 0xef, // one length, exact first archive
    3, 0x91, 0x23, 0x45, // one length, exact second archive
  ]));
  assert.deepEqual(archiveCalls, [json, JSON.stringify(second)]);
  const rejection = new Error("owner rejected embedded instruction");
  const rejected = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction: () => Buffer.of(1),
    noritoDecodeInstruction: () => json,
    noritoEncodeInstructionBoxArchive() { throw rejection; },
  }));
  assert.throws(() => rejected._encodeMultisigInstructions([instruction], 753), (error) => error === rejection);
});

test("all four instruction APIs use the canonical owner even for formerly pure JS variants", () => {
  const calls = [];
  const frame = Buffer.from([1, 2, 3]);
  const archive = Buffer.from([4, 5, 6]);
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction(value) { calls.push(["encodeFrame", value]); return frame; },
    noritoDecodeInstruction(value) { calls.push(["decodeFrame", Buffer.from(value)]); return json; },
    noritoEncodeInstructionBoxArchive(value) { calls.push(["encodeArchive", value]); return archive; },
    noritoDecodeInstructionBoxArchive(value) { calls.push(["decodeArchive", Buffer.from(value)]); return json; },
  }));
  assert.deepEqual(api.noritoEncodeInstruction(instruction, 753), frame);
  assert.deepEqual(api.noritoDecodeInstruction(frame, 753), instruction);
  assert.deepEqual(api.noritoEncodeInstructionBoxArchive(instruction, 753), archive);
  assert.deepEqual(api.noritoDecodeInstructionBoxArchive(archive, 753), instruction);
  assert.deepEqual(new Set(calls.map(([name]) => name)), new Set(["encodeFrame", "decodeFrame", "encodeArchive", "decodeArchive"]));
  assert.equal(calls.find(([name]) => name === "encodeArchive")[1], json);
});

test("owner rejection never falls back to a local encoder or archive decoder", () => {
  const rejection = new Error("canonical owner rejected fixture");
  const fail = () => { throw rejection; };
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction: fail, noritoDecodeInstruction: fail,
    noritoEncodeInstructionBoxArchive: fail, noritoDecodeInstructionBoxArchive: fail,
  }));
  for (const operation of [
    () => api.noritoEncodeInstruction(instruction, 753),
    () => api.noritoDecodeInstruction(Buffer.of(1), 753),
    () => api.noritoEncodeInstructionBoxArchive(instruction, 753),
    () => api.noritoDecodeInstructionBoxArchive(Buffer.of(1), 753),
  ]) assert.throws(operation, (error) => error === rejection);
});

test("preencoded instruction frames are checked by Rust instead of passed through", () => {
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoDecodeInstruction: () => json,
    noritoEncodeInstruction: () => Buffer.of(1, 2),
  }));
  assert.throws(() => api.noritoEncodeInstruction(Buffer.of(1, 2, 3), 753), /not canonical/);
  assert.throws(() => api.noritoEncodeInstruction(Buffer.of(1, 2, 3).toString("base64"), 753), /not canonical/);
  assert.deepEqual(api.noritoEncodeInstruction(Buffer.of(1, 2), 753), Buffer.of(1, 2));
});

test("frame decode retains raw JSON mode and owner receives only the requested byte view", () => {
  const backing = Uint8Array.of(99, 1, 2, 99);
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoDecodeInstruction(bytes) {
      assert.deepEqual(Buffer.from(bytes), Buffer.of(1, 2));
      return json;
    },
  }));
  assert.equal(api.noritoDecodeInstruction(backing.subarray(1, 3), 753, { parseJson: false }), json);
});

test("instruction JSON text reaches Rust without rounding unsafe u64 tokens", () => {
  const exact = ' {"Custom":{"payload":{"large":18446744073709551615}}} ';
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction(value) { assert.equal(value, exact); return Buffer.of(1); },
    noritoDecodeInstruction() { return exact; },
  }));
  assert.deepEqual(api.noritoEncodeInstruction(exact, 753), Buffer.of(1));
  assert.equal(api.noritoDecodeInstruction(Buffer.of(1), 753, { parseJson: false }), exact);
});

test("duplicate keys in JSON text remain visible to the canonical owner's rejection", () => {
  const exact = '{"Custom":{"payload":{"same":1,"same":2}}}';
  const rejection = new Error("owner rejected duplicate key");
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction(value) { assert.equal(value, exact); throw rejection; },
  }));
  assert.throws(() => api.noritoEncodeInstruction(exact, 753), (error) => error === rejection);
});

test("object inputs reject unsafe integers, non-finite numbers and unsupported bigint before native serialization", () => {
  let calls = 0;
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction() { calls += 1; return Buffer.of(1); },
  }));
  for (const value of [Number.MAX_SAFE_INTEGER + 1, -(Number.MAX_SAFE_INTEGER + 1), NaN, Infinity, -Infinity, 1n]) {
    assert.throws(() => api.noritoEncodeInstruction({ Custom: { payload: { nested: [value] } } }, 753), /exact JSON text/);
  }
  assert.equal(calls, 0);
  api.noritoEncodeInstruction({ Custom: { payload: { finiteFraction: 1.25, safe: Number.MAX_SAFE_INTEGER } } }, 753);
  assert.equal(calls, 1);
});

test("parsed owner output rejects rounded integers while preserving fractional JSON and exact raw mode", () => {
  for (const token of ["9007199254740993", "-9007199254740993", "18446744073709551615", "1e999"]) {
    const exact = `{"Custom":{"payload":{"value":${token}}}}`;
    const api = _createNoritoInstructionApi(createNativeRuntime({
      noritoDecodeInstruction: () => exact,
      noritoDecodeInstructionBoxArchive: () => exact,
    }));
    assert.throws(() => api.noritoDecodeInstruction(Buffer.of(1), 753), /exact JSON text/);
    assert.throws(() => api.noritoDecodeInstructionBoxArchive(Buffer.of(1), 753), /exact JSON text/);
    assert.equal(api.noritoDecodeInstruction(Buffer.of(1), 753, { parseJson: false }), exact);
  }
  const exact = '{"Custom":{"payload":{"value":1.25,"safe":9007199254740991}}}';
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoDecodeInstruction: () => exact,
    noritoDecodeInstructionBoxArchive: () => exact,
  }));
  assert.deepEqual(api.noritoDecodeInstruction(Buffer.of(1), 753), JSON.parse(exact));
  assert.deepEqual(api.noritoDecodeInstructionBoxArchive(Buffer.of(1), 753), JSON.parse(exact));
});

function exactInstructionOwner(exactJson) {
  const frame = Buffer.of(0xa1, 0x01);
  const archive = Buffer.of(0xb2, 0x02);
  const encoded = [];
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction(value, networkPrefix) {
      assert.equal(networkPrefix, 753);
      assert.equal(value, exactJson);
      encoded.push("frame");
      return frame;
    },
    noritoDecodeInstruction(value, networkPrefix) {
      assert.equal(networkPrefix, 753);
      assert.deepEqual(Buffer.from(value), frame);
      return exactJson;
    },
    noritoEncodeInstructionBoxArchive(value, networkPrefix) {
      assert.equal(networkPrefix, 753);
      assert.equal(value, exactJson);
      encoded.push("archive");
      return archive;
    },
    noritoDecodeInstructionBoxArchive(value, networkPrefix) {
      assert.equal(networkPrefix, 753);
      assert.deepEqual(Buffer.from(value), archive);
      return exactJson;
    },
  }));
  return { api, frame, archive, encoded };
}

test("public ballot durations stay exact through frame and archive owners alongside retail dispatch", (context) => {
  const account = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
  // Address validation has its own native owner. Isolate that dependency so
  // this test exercises instruction JSON dispatch without loading an addon.
  context.mock.method(AccountAddress, "parseEncoded", (value) => {
    assert.equal(value, account);
    return { address: { toI105: () => account }, chainDiscriminant: 753 };
  });
  for (const variant of ["CastPlainBallot", "UpdatePlainConviction"]) {
    for (const duration of [0, Number.MAX_SAFE_INTEGER, 9007199254740993n, 18446744073709551615n, "18446744073709551615"]) {
      const payload = {
        referendum_id: "exact-duration",
        owner: account,
        amount: "1.25",
        duration_blocks: duration,
        ...(variant === "CastPlainBallot" ? { direction: 1 } : {}),
      };
      const exact = `{"${variant}":{"referendum_id":"exact-duration","owner":"${account}","amount":"1.25","duration_blocks":${duration}${variant === "CastPlainBallot" ? ',"direction":1' : ""}}}`;
      const { api, frame, archive, encoded } = exactInstructionOwner(exact);
      const source = { [variant]: payload };
      const expected = {
        [variant]: {
          ...payload,
          duration_blocks: typeof duration === "string" ? BigInt(duration) : duration,
        },
      };
      assert.deepEqual(api.noritoEncodeInstruction(source, 753), frame);
      assert.deepEqual(api.noritoEncodeInstructionBoxArchive(source, 753), archive);
      assert.deepEqual(structuredClone(api.noritoDecodeInstruction(frame, 753)), expected);
      assert.deepEqual(structuredClone(api.noritoDecodeInstructionBoxArchive(archive, 753)), expected);
      assert.equal(api.noritoDecodeInstruction(frame, 753, { parseJson: false }), exact);
      assert.deepEqual(encoded, ["frame", "frame", "archive"]);
      assert.equal(source[variant].duration_blocks, duration, "encoding must not mutate the input");
    }
  }
});

test("all retail instruction variants retain exact JSON across frame and archive owners", () => {
  const fixtures = [
    {
      value: { ActivateRetailDailyLimitV1: { policy: { physical_dataspace: 8648377547929788715n, revision: 1 } } },
      exact: '{"ActivateRetailDailyLimitV1":{"policy":{"physical_dataspace":8648377547929788715,"revision":1}}}',
    },
    {
      value: { BindRetailIdentityV1: { attestation: { body: { physical_dataspace: 18446744073709551615n, policy_revision: 1 } } } },
      exact: '{"BindRetailIdentityV1":{"attestation":{"body":{"physical_dataspace":18446744073709551615,"policy_revision":1}}}}',
    },
    {
      value: { RetailMonetaryMovementV1: { purpose: "mint_to_reserve", amount: "9007199254740993.25", operation_digest: Array(32).fill(3) } },
      exact: `{"RetailMonetaryMovementV1":{"purpose":"mint_to_reserve","amount":"9007199254740993.25","operation_digest":[${Array(32).fill(3).join(",")}]}}`,
    },
  ];
  for (const { value, exact } of fixtures) {
    const { api, frame, archive, encoded } = exactInstructionOwner(exact);
    assert.deepEqual(api.noritoEncodeInstruction(value, 753), frame);
    assert.deepEqual(api.noritoEncodeInstructionBoxArchive(value, 753), archive);
    assert.deepEqual(structuredClone(api.noritoDecodeInstruction(frame, 753)), value);
    assert.deepEqual(structuredClone(api.noritoDecodeInstructionBoxArchive(archive, 753)), value);
    assert.equal(api.noritoDecodeInstruction(frame, 753, { parseJson: false }), exact);
    assert.deepEqual(encoded, ["frame", "frame", "archive"]);
  }
});

test("retail exact-integer dispatch rejects lossy object numbers before either encoder", () => {
  const fail = () => assert.fail("invalid integer must not reach the native owner");
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction: fail,
    noritoEncodeInstructionBoxArchive: fail,
  }));
  for (const physical_dataspace of [Number.MAX_SAFE_INTEGER + 1, 1.5, NaN, Infinity, -0]) {
    const source = { ActivateRetailDailyLimitV1: { policy: { physical_dataspace } } };
    assert.throws(() => api.noritoEncodeInstruction(source, 753), /canonical safe integers/u);
    assert.throws(() => api.noritoEncodeInstructionBoxArchive(source, 753), /canonical safe integers/u);
  }
});

test("retail and public-ballot decoders keep strict duplicate-key rejection", () => {
  for (const exact of [
    '{"ActivateRetailDailyLimitV1":{"policy":{"physical_dataspace":9007199254740993,"physical_dataspace":1}}}',
    '{"CastPlainBallot":{"duration_blocks":18446744073709551615,"duration_blocks":1}}',
    '{"UpdatePlainConviction":{"duration_blocks":18446744073709551615,"duration_blocks":1}}',
  ]) {
    const { api, frame, archive } = exactInstructionOwner(exact);
    assert.throws(() => api.noritoDecodeInstruction(frame, 753), /duplicate object key/u);
    assert.throws(() => api.noritoDecodeInstructionBoxArchive(archive, 753), /duplicate object key/u);
  }
});

test("u128 election tallies reach both encoders exactly and never decode as rounded numbers", () => {
  const tallyProof = {
    backend: "pipa-r/pasta",
    proof: { backend: "pipa-r/pasta", bytes: [1] },
    vk_ref: { backend: "pipa-r/pasta", name: "vk_tally" },
  };
  const maximum = (1n << 128n) - 1n;
  const source = { zk: { FinalizeElection: { election_id: "exact-tally", tally: [maximum, 0], tally_proof: tallyProof } } };
  const exact = `{"zk":{"FinalizeElection":{"election_id":"exact-tally","tally":[${maximum},0],"tally_proof":${JSON.stringify(tallyProof)}}}}`;
  const { api, frame, archive, encoded } = exactInstructionOwner(exact);
  assert.deepEqual(api.noritoEncodeInstruction(source, 753), frame);
  assert.deepEqual(api.noritoEncodeInstructionBoxArchive(source, 753), archive);
  assert.equal(api.noritoDecodeInstruction(frame, 753, { parseJson: false }), exact);
  assert.throws(() => api.noritoDecodeInstruction(frame, 753), /exact JSON text/u);
  assert.throws(() => api.noritoDecodeInstructionBoxArchive(archive, 753), /exact JSON text/u);
  assert.deepEqual(encoded, ["frame", "frame", "archive"]);
  assert.deepEqual(source.zk.FinalizeElection.tally, [maximum, 0]);
});
