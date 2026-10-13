// Native evidence transport and strict audit projection tests.
import test from "node:test";
import assert from "node:assert/strict";
import { ToriiClient as SourceToriiClient } from "../src/toriiClient.js";
import { NetworkId } from "../src/networkId.js";
import { canonicalHashLiteral } from "../src/instructionBuilderPrimitives.js";
import { makeTestOperatorSigningContext } from "./toriiClientTestHelpers.js";
const BASE_URL = "https://localhost:8080";
const operatorSigningContext = makeTestOperatorSigningContext(NetworkId.fromBytes(Buffer.alloc(32, 0xa5)));
class ToriiClient extends SourceToriiClient {
  constructor(baseUrl, options = {}) {
    super(baseUrl, { operatorSigningContext, ...options });
  }
}

function createResponse({ status, jsonData, arrayData, textBody, headers }) {
  const implicitEmptyBody =
    (status === 204 || status === 404) &&
    jsonData === undefined &&
    arrayData === undefined &&
    textBody === undefined;
  const effectiveJsonData = jsonData === undefined
    ? (implicitEmptyBody ? null : {})
    : jsonData;
  const effectiveHeaders = headers ?? (
    arrayData === undefined && textBody === undefined
      ? { "content-type": "application/json" }
      : {}
  );
  const responseText = implicitEmptyBody
    ? ""
    : typeof textBody === "string"
      ? textBody
      : JSON.stringify(effectiveJsonData);
  const bodyBytes =
    arrayData instanceof ArrayBuffer
      ? new Uint8Array(arrayData)
      : ArrayBuffer.isView(arrayData)
        ? new Uint8Array(
            arrayData.buffer,
            arrayData.byteOffset,
            arrayData.byteLength,
          )
        : new TextEncoder().encode(responseText);
  return {
    status,
    json: async () => effectiveJsonData,
    arrayBuffer: async () => {
      if (arrayData instanceof ArrayBuffer) {
        return arrayData;
      }
      if (ArrayBuffer.isView(arrayData)) {
        return arrayData.buffer.slice(arrayData.byteOffset, arrayData.byteOffset + arrayData.byteLength);
      }
      return bodyBytes.buffer.slice(
        bodyBytes.byteOffset,
        bodyBytes.byteOffset + bodyBytes.byteLength,
      );
    },
    text: async () => responseText,
    body: new ReadableStream({
      start(controller) {
        if (bodyBytes.byteLength > 0) controller.enqueue(bodyBytes);
        controller.close();
      },
    }),
    headers: {
      get(name) {
        const normalized = name.toLowerCase();
        for (const [key, value] of Object.entries(effectiveHeaders)) {
          if (key.toLowerCase() === normalized) {
            return value;
          }
        }
        return null;
      },
    },
  };
}

function canonicalSumeragiEvidenceRecord(overrides = {}) {
  return {
    kind: "NativeSumeragiEvidence",
    value: {
      scope: { kind: "root", value: null },
      class: "phase_vote",
      height: 31,
      epoch: 2,
      context_id: "11".repeat(32),
      instance: "22".repeat(32),
      authority_generation: "33".repeat(32),
      offenders: [{ signer: 3, peer_id: "ea013082F39DD89C3AA5C497C7C1843C21C117CF77E7A569E80B827B401A275179DD57F67CA52601BF4C127F848D71740A5D08" }],
      safety_violation: false,
      native_frame_hash: "44".repeat(32),
      recorded_height: 40,
      recorded_view: 2,
      recorded_ms: 1_700_000_000_000,
      consensus_admitted_height: 41,
      penalty_status: { status: "pending", details: null },
      ...overrides,
    },
  };
}

test("listSumeragiEvidence encodes the bounded canonical query", async () => {
  let observedSignal;
  const fetchImpl = async (url, init) => {
    assert.equal(
      url,
      `${BASE_URL}/v1/sumeragi/evidence?limit=25&offset=5&kind=NativeSumeragiEvidence`,
    );
    assert.equal(init.headers.Accept, "application/json");
    observedSignal = init.signal;
    assert.ok(observedSignal instanceof AbortSignal);
    return createResponse({
      status: 200,
      jsonData: {
        total: 6,
        items: [canonicalSumeragiEvidenceRecord()],
      },
      headers: { "content-type": "application/json" },
    });
  };
  const controller = new AbortController();
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.listSumeragiEvidence({
    limit: 25,
    offset: 5,
    kind: "NativeSumeragiEvidence",
    signal: controller.signal,
  });
  assert.equal(payload.total, 6);
  assert.equal(payload.items.length, 1);
  assert.deepEqual(payload.items[0], canonicalSumeragiEvidenceRecord());
  controller.abort();
  assert.equal(observedSignal?.aborted, false, "completed requests detach caller abort listeners");
});

test("listSumeragiEvidence rejects invalid kind", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  await assert.rejects(
    () => client.listSumeragiEvidence({ kind: "DoublePrepare" }),
    /kind must be NativeSumeragiEvidence/,
  );
});

test("listSumeragiEvidence rejects out-of-range pagination before dispatch", async () => {
  let calls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      calls += 1;
      return createResponse({ status: 200 });
    },
  });
  await assert.rejects(() => client.listSumeragiEvidence({ limit: 1001 }), /limit must be <= 1000/);
  await assert.rejects(() => client.listSumeragiEvidence({ offset: 10001 }), /offset must be <= 10000/);
  assert.equal(calls, 0);
});

test("listSumeragiEvidence accepts the exact native evidence kind filter", async () => {
  const fetchImpl = async (url) => {
    assert.equal(
      url,
      `${BASE_URL}/v1/sumeragi/evidence?kind=NativeSumeragiEvidence`,
    );
    return createResponse({
      status: 200,
      jsonData: { total: 0, items: [] },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  assert.deepEqual(
    await client.listSumeragiEvidence({ kind: "NativeSumeragiEvidence" }),
    { total: 0, items: [] },
  );
});

test("listSumeragiEvidence rejects unsupported options", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200, jsonData: { total: 0, items: [] } }),
  });
  await assert.rejects(
    () =>
      client.listSumeragiEvidence({
        kind: "NativeSumeragiEvidence",
        limit: 1,
        note: "extra",
      }),
    /listSumeragiEvidence options contains unsupported fields: note/,
  );
});

test("listSumeragiEvidence normalizes the closed evidence payload", async () => {
  const canonical = canonicalSumeragiEvidenceRecord({
    penalty_status: { status: "applied", details: { height: 84 } },
  });
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        total: 1,
        items: [canonical],
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.listSumeragiEvidence();
  assert.deepEqual(payload, { total: 1, items: [canonical] });
});

test("listSumeragiEvidence rejects malformed payloads", async () => {
  const item = canonicalSumeragiEvidenceRecord();
  delete item.value.recorded_height;
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        total: 1,
        items: [item],
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(() => client.listSumeragiEvidence(), /recorded_height/);
});

test("listSumeragiEvidence requires the exact page envelope", async () => {
  await Promise.all(
    [
      [{ items: [] }, /missing total/],
      [{ total: 0 }, /missing items/],
      [{ total: 0, items: [], cursor: null }, /unexpected cursor/],
      [{ total: "0", items: [] }, /total must be an unsigned JSON integer/],
    ].map(async ([payload, expected]) => {
      const client = new ToriiClient(BASE_URL, {
        fetchImpl: async () =>
          createResponse({
            status: 200,
            jsonData: payload,
            headers: { "content-type": "application/json" },
          }),
      });
      await assert.rejects(() => client.listSumeragiEvidence(), expected);
    }),
  );
});

test("listSumeragiEvidence rejects impossible or oversized pages", async () => {
  for (const [options, payload, expected] of [
    [
      {},
      { total: 51, items: Array.from({ length: 51 }, () => canonicalSumeragiEvidenceRecord()) },
      /at most 50 records/,
    ],
    [
      { offset: 1 },
      { total: 1, items: [canonicalSumeragiEvidenceRecord()] },
      /must cover offset plus returned items/,
    ],
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: payload,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(() => client.listSumeragiEvidence(options), expected);
  }
});

test("listSumeragiEvidence accepts an empty page beyond the total", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: { total: 1, items: [] },
        headers: { "content-type": "application/json" },
      }),
  });

  assert.deepEqual(await client.listSumeragiEvidence({ offset: 10 }), {
    total: 1,
    items: [],
  });
});

test("Sumeragi evidence reads preserve the full unsigned 64-bit range", async () => {
  const maximum = "18446744073709551615";
  const marker = "__U64_MAX__";
  const item = canonicalSumeragiEvidenceRecord({
    height: marker,
    epoch: marker,
    recorded_height: marker,
    recorded_view: marker,
    recorded_ms: marker,
    consensus_admitted_height: marker,
    penalty_status: { status: "applied", details: { height: marker } },
  });
  const listBody = JSON.stringify({ total: marker, items: [item] }).replaceAll(
    `"${marker}"`,
    maximum,
  );
  const countBody = `{"count":${maximum}}`;
  const responses = [listBody, countBody];
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        textBody: responses.shift(),
        headers: { "content-type": "application/json" },
      }),
  });

  const page = await client.listSumeragiEvidence();
  assert.equal(page.total, 18446744073709551615n);
  for (const field of [
    "height",
    "epoch",
    "recorded_height",
    "recorded_view",
    "recorded_ms",
    "consensus_admitted_height",
  ]) {
    assert.equal(page.items[0].value[field], 18446744073709551615n);
  }
  assert.equal(page.items[0].value.penalty_status.details.height, 18446744073709551615n);
  assert.equal((await client.getSumeragiEvidenceCount()).count, 18446744073709551615n);
});

test("listSumeragiEvidence enforces its JSON media type and byte ceiling", async () => {
  const canonicalBody = '{"total":0,"items":[]}';
  for (const [textBody, headers, expected] of [
    [canonicalBody, { "content-type": "text/plain" }, /application\/json media type/],
    [
      canonicalBody,
      {
        "content-type": "application/json",
        "content-length": String(1024 * 1024 + 1),
      },
      /exceeds the 1048576-byte response limit/,
    ],
    [
      canonicalBody.padEnd(1024 * 1024 + 1, " "),
      { "content-type": "application/json" },
      /exceeds the 1048576-byte response limit/,
    ],
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          textBody,
          headers,
        }),
    });
    await assert.rejects(() => client.listSumeragiEvidence(), expected);
  }
});

test("listSumeragiEvidence rejects malformed exact evidence shapes", async () => {
  const equivocation = canonicalSumeragiEvidenceRecord({ class: "proposal" });
  const missingContext = structuredClone(equivocation);
  delete missingContext.value.context_id;
  const cases = [
    [{ ...equivocation, value: { ...equivocation.value, class: "Prepare" } }, /\.class must be one of/],
    [{ ...equivocation, value: { ...equivocation.value, offenders: [{ ...equivocation.value.offenders[0], signer: "3" }] } }, /\.signer must be an unsigned JSON integer/],
    [{ ...equivocation, value: { ...equivocation.value, offenders: [{ ...equivocation.value.offenders[0], signer: 1024 }] } }, /\.signer must be at most 1023/],
    [{ ...equivocation, value: { ...equivocation.value, context_id: "AA".repeat(32) } }, /exact lowercase 32-byte hex/],
    [{ ...equivocation, value: { ...equivocation.value, artifact_hash_2: "22".repeat(32) } }, /unexpected artifact_hash_2/],
    [{ ...equivocation, kind: "SumeragiEquivocation" }, /kind must be NativeSumeragiEvidence/],
    [{ ...equivocation, value: { ...equivocation.value, offenders: [] } }, /offenders must contain/],
    [{ ...equivocation, value: { ...equivocation.value, offenders: [equivocation.value.offenders[0], equivocation.value.offenders[0]] } }, /signer must increase/],
    [{ ...equivocation, value: { ...equivocation.value, offenders: [equivocation.value.offenders[0], { ...equivocation.value.offenders[0], signer: 4 }] } }, /peer_id must be unique/],
    [{ ...equivocation, value: { ...equivocation.value, offenders: [{ ...equivocation.value.offenders[0], peer_id: "invalid" }] } }, /peer_id must be a canonical/],
    [{ ...equivocation, value: { ...equivocation.value, safety_violation: 0 } }, /safety_violation/],
    [missingContext, /missing context_id/],
    [{ ...equivocation, kind: "DoublePrepare" }, /kind must be NativeSumeragiEvidence/],
    [{ ...equivocation, value: { ...equivocation.value, consensus_admitted_height: null } }, /consensus_admitted_height/],
    [{ ...equivocation, value: { ...equivocation.value, penalty_status: { status: "pending", details: {} } } }, /details must be null/],
    [{ ...equivocation, value: { ...equivocation.value, penalty_status: { status: "applied", details: null } } }, /must be an object/],
    [{ ...equivocation, value: { ...equivocation.value, penalty_status: { status: "applied", details: { height: 8, note: "x" } } } }, /unexpected note/],
    [{ ...equivocation, value: { ...equivocation.value, penalty_status: { status: "cancelled", details: { height: 8 } } } }, /must be pending or applied/],
    [{ ...equivocation, value: { ...equivocation.value, penalty_status: { status: "retired", details: null } } }, /must be pending or applied/],
    [{ ...equivocation, value: { ...equivocation.value, penalty_applied: false } }, /unexpected penalty_applied/],
  ];
  await Promise.all(
    cases.map(async ([item, expected]) => {
      const client = new ToriiClient(BASE_URL, {
        fetchImpl: async () =>
          createResponse({
            status: 200,
            jsonData: { total: 1, items: [item] },
            headers: { "content-type": "application/json" },
          }),
      });
      await assert.rejects(() => client.listSumeragiEvidence(), expected);
    }),
  );
});

test("getSumeragiEvidenceCount returns count payload", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: { count: 7 },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getSumeragiEvidenceCount();
  assert.deepEqual(result, { count: 7 });
});

test("getSumeragiEvidenceCount requires the exact count envelope", async () => {
  for (const [payload, expected] of [
    [{}, /missing count/],
    [{ count: 1, total: 1 }, /unexpected total/],
    [{ count: "1" }, /count must be an unsigned JSON integer/],
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: payload,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(() => client.getSumeragiEvidenceCount(), expected);
  }
});

test("getSumeragiEvidenceCount enforces the 1 KiB response ceiling", async () => {
  const canonicalBody = '{"count":0}';
  for (const [textBody, headers] of [
    [
      canonicalBody,
      {
        "content-type": "application/json",
        "content-length": String(1024 + 1),
      },
    ],
    [canonicalBody.padEnd(1024 + 1, " "), { "content-type": "application/json" }],
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({ status: 200, textBody, headers }),
    });
    await assert.rejects(
      () => client.getSumeragiEvidenceCount(),
      /exceeds the 1024-byte response limit/,
    );
  }
});

test("native evidence requires every attribution field and accepts each native class", async () => {
  const canonical = canonicalSumeragiEvidenceRecord();
  for (const [inside, fields] of [[false, Object.keys(canonical)], [true, Object.keys(canonical.value)]]) {
    for (const field of fields) {
      const item = structuredClone(canonical);
      delete (inside ? item.value : item)[field];
      const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({
        status: 200, jsonData: { total: 1, items: [item] }, headers: { "content-type": "application/json" },
      }) });
      await assert.rejects(() => client.listSumeragiEvidence(), new RegExp(`missing ${field}`));
    }
  }
  for (const nativeClass of ["proposal", "phase_vote", "timeout_vote", "invalid_proposal", "conflicting_certificates"]) {
    const item = canonicalSumeragiEvidenceRecord({ class: nativeClass });
    const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({
      status: 200, jsonData: { total: 1, items: [item] }, headers: { "content-type": "application/json" },
    }) });
    assert.equal((await client.listSumeragiEvidence()).items[0].value.class, nativeClass);
  }
});

test("listSumeragiEvidence preserves unattributed certificate safety violations", async () => {
  const evidence = canonicalSumeragiEvidenceRecord({
    class: "conflicting_certificates", safety_violation: true, offenders: [],
  });
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200, jsonData: { total: 1, items: [evidence] } }),
  });
  const result = await client.listSumeragiEvidence();
  assert.equal(result.items[0].value.class, "conflicting_certificates");
  assert.equal(result.items[0].value.safety_violation, true);
  assert.deepEqual(result.items[0].value.offenders, []);
  assert.equal(result.items[0].value.native_frame_hash, evidence.value.native_frame_hash);
});


test("empty offenders require an exact conflicting-certificate safety violation", async () => {
  for (const overrides of [
    { class: "conflicting_certificates", safety_violation: false },
    { class: "conflicting_certificates", safety_violation: 1 },
    { class: "phase_vote", safety_violation: true },
  ]) {
    const record = canonicalSumeragiEvidenceRecord({ ...overrides, offenders: [] });
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({ status: 200, jsonData: { total: 1, items: [record] } }),
    });
    await assert.rejects(() => client.listSumeragiEvidence(), /offenders must contain/);
  }
});


// Synthetic model DATA exercises the decoder; these bytes carry no verified signatures.
function sccpForgeryEvidenceRecord() {
  return {
    kind: "SccpForgeryEvidence",
    value: {
      record: {
        evidence: {
          qc: "A1".repeat(116), header: "b2".repeat(221), aggregate_signature: "C3".repeat(96),
          anchor: { core_hash: "00".repeat(32), result: "00".repeat(32), path: Array(12).fill("07".repeat(32)) },
        },
        rule: { rule: "E4", detail: null }, generation: 7, start_height: 23,
        offenders: [{ signer: 0, lane_id: 1, validator: "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP", activation_height: 19 }],
      },
      attribution: {
        scope: { kind: "sccp_generation", value: { generation: 7 } },
        instance: "01".repeat(32), height: 23, epoch: 99,
        context_id: "02".repeat(32), authority_generation: "03".repeat(32),
        offenders: [{ signer: 0, peer_id: canonicalSumeragiEvidenceRecord().value.offenders[0].peer_id, lane_stake: null }],
        safety_violation: false,
      },
      recorded_height: 42, recorded_view: 5, recorded_ms: 1234, consensus_admitted_height: 42,
      penalty_status: { status: "pending", details: null },
    },
  };
}

function laneEvidenceScope() {
  return { kind: "lane", value: {
    lane: 3, incarnation: "00".repeat(32), created_at: 8, admission_parent_height: 7,
    admission_parent_hash: canonicalHashLiteral(Buffer.alloc(32, 0xA1)),
    admission_parent_core_hash: "Aa".repeat(32), admission_parent_result: "00".repeat(32),
  } };
}

async function readEvidence(item, options = {}) {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({
    status: 200, jsonData: { total: 1, items: [item] },
  }) });
  return (await client.listSumeragiEvidence(options)).items[0];
}

test("SCCP evidence retains exact DATA for every rule and optional anchor", async () => {
  for (const rule of ["E1", "E2", "E3", "E4"]) {
    for (const anchored of [false, true]) {
      const record = sccpForgeryEvidenceRecord();
      record.value.record.rule.rule = rule;
      if (!anchored) record.value.record.evidence.anchor = null;
      assert.deepEqual(await readEvidence(record), record);
    }
  }
  const native = canonicalSumeragiEvidenceRecord({ scope: laneEvidenceScope() });
  assert.deepEqual(await readEvidence(native), native);
});

test("Sumeragi evidence accepts both exact filters and rejects response substitution", async () => {
  for (const item of [canonicalSumeragiEvidenceRecord(), sccpForgeryEvidenceRecord()]) {
    for (const kind of [undefined, "NativeSumeragiEvidence", "SccpForgeryEvidence"]) {
      let calls = 0;
      const client = new ToriiClient(BASE_URL, { fetchImpl: async (url) => {
        calls += 1;
        assert.equal(url, `${BASE_URL}/v1/sumeragi/evidence${kind === undefined ? "" : `?kind=${kind}`}`);
        return createResponse({ status: 200, jsonData: { total: 1, items: [item] } });
      } });
      if (kind === undefined || kind === item.kind) {
        assert.deepEqual((await client.listSumeragiEvidence({ kind })).items[0], item);
      } else {
        await assert.rejects(() => client.listSumeragiEvidence({ kind }), /kind differs from the requested filter/);
      }
      assert.equal(calls, 1);
    }
  }
});

test("Sumeragi evidence has one closed envelope and no retired flat layout", async () => {
  for (const item of [canonicalSumeragiEvidenceRecord(), sccpForgeryEvidenceRecord()]) {
    await assert.rejects(() => readEvidence({ kind: item.kind, ...item.value }), /exact server fields/);
    await assert.rejects(() => readEvidence({ ...item, unknown: null }), /unexpected unknown/);
    for (const kind of ["UnknownEvidence", "sccp_forgery", "SccpForgeryEvidence ", null]) {
      await assert.rejects(() => readEvidence({ ...item, kind }));
    }
    for (const value of [null, [], 1, "payload"]) {
      await assert.rejects(() => readEvidence({ ...item, value }), /must be an object/);
    }
  }
});

test("SCCP and lane evidence reject unknown and missing fields at every nesting level", async () => {
  const sources = [
    [sccpForgeryEvidenceRecord(), [[], ["value"], ["value", "record"], ["value", "record", "evidence"],
      ["value", "record", "evidence", "anchor"], ["value", "record", "rule"], ["value", "record", "offenders", 0],
      ["value", "attribution"], ["value", "attribution", "scope"], ["value", "attribution", "scope", "value"],
      ["value", "attribution", "offenders", 0], ["value", "penalty_status"]]],
    [canonicalSumeragiEvidenceRecord({ scope: laneEvidenceScope() }), [["value", "scope"], ["value", "scope", "value"]]],
  ];
  for (const [source, paths] of sources) {
    for (const path of paths) {
      const fields = Object.keys(path.reduce((value, key) => value[key], source));
      for (const field of [null, ...fields]) {
        const item = structuredClone(source);
        const nested = path.reduce((value, key) => value[key], item);
        if (field === null) nested.unknown = null;
        else delete nested[field];
        await assert.rejects(() => readEvidence(item), /exact server fields/);
      }
    }
  }
});

test("SCCP evidence rejects malformed bytes, attribution joins and liability shape", async () => {
  const cases = [
    [["record", "evidence", "qc"], "A1".repeat(115)],
    [["record", "evidence", "header"], Array(221).fill(0)],
    [["record", "evidence", "aggregate_signature"], "GG".repeat(96)],
    [["record", "evidence", "anchor", "core_hash"], "0x" + "00".repeat(32)],
    [["record", "evidence", "anchor", "result"], "00".repeat(31)],
    [["record", "evidence", "anchor", "path"], Array(11).fill("00".repeat(32))],
    [["record", "evidence", "anchor", "path"], Array(13).fill("00".repeat(32))],
    [["record", "evidence", "anchor", "path", 0], []],
    [["record", "rule", "rule"], "E5"], [["record", "rule", "detail"], {}],
    [["record", "generation"], 0], [["record", "start_height"], 0],
    [["record", "generation"], "7"], [["record", "generation"], true],
    [["record", "offenders"], []],
    [["record", "offenders", 0, "signer"], 31], [["record", "offenders", 0, "lane_id"], 4294967296],
    [["record", "offenders", 0, "validator"], "invalid"],
    [["record", "offenders", 0, "activation_height"], 0], [["record", "offenders", 0, "activation_height"], 24],
    [["attribution", "scope"], { kind: "root", value: null }],
    [["attribution", "scope", "value", "generation"], 8], [["attribution", "height"], 24],
    [["attribution", "offenders"], []], [["attribution", "offenders", 0, "signer"], 1],
    [["attribution", "offenders", 0, "peer_id"], "invalid"], [["attribution", "offenders", 0, "lane_stake"], {}],
    [["attribution", "instance"], []], [["attribution", "context_id"], "AA".repeat(31)],
    [["attribution", "authority_generation"], "zz".repeat(32)], [["attribution", "epoch"], -1],
    [["attribution", "safety_violation"], 1], [["recorded_ms"], null],
    [["penalty_status", "status"], "cancelled"], [["penalty_status", "details"], {}],
  ];
  for (const [path, value] of cases) {
    const item = sccpForgeryEvidenceRecord();
    const parent = path.slice(0, -1).reduce((nested, key) => nested[key], item.value);
    parent[path.at(-1)] = value;
    await assert.rejects(() => readEvidence(item), undefined, path.join("."));
  }
  for (const count of [2, 32]) {
    const item = sccpForgeryEvidenceRecord();
    item.value.record.offenders = Array.from({ length: count }, (_, signer) => ({ ...item.value.record.offenders[0], signer }));
    await assert.rejects(() => readEvidence(item), /registration must be unique|between 1 and 31/);
  }
  const unordered = sccpForgeryEvidenceRecord();
  unordered.value.record.offenders.push({ ...unordered.value.record.offenders[0], lane_id: 2 });
  await assert.rejects(() => readEvidence(unordered), /signer must increase strictly/);
});

test("native scope rejects malformed lane anchors and SCCP scope substitution", async () => {
  for (const scope of [
    { kind: "root", value: {} }, { kind: "sccp_generation", value: { generation: 7 } },
    { kind: "unknown", value: null },
  ]) {
    await assert.rejects(() => readEvidence(canonicalSumeragiEvidenceRecord({ scope })));
  }
  for (const [field, value] of [
    ["lane", 4294967296], ["incarnation", []], ["created_at", -1], ["admission_parent_height", true],
    ["admission_parent_hash", "hash:" + "00".repeat(32) + "#0000"],
    ["admission_parent_core_hash", "zz".repeat(32)], ["admission_parent_result", "00".repeat(31)],
  ]) {
    const scope = laneEvidenceScope();
    scope.value[field] = value;
    await assert.rejects(() => readEvidence(canonicalSumeragiEvidenceRecord({ scope })));
  }
});

test("SCCP evidence retains full u64 fields without rewriting certificate bytes", async () => {
  const item = sccpForgeryEvidenceRecord();
  const marker = "__U64_MAX__";
  item.value.record.generation = marker;
  item.value.record.start_height = marker;
  item.value.record.offenders[0].activation_height = marker;
  item.value.attribution.scope.value.generation = marker;
  for (const field of ["height", "epoch"]) item.value.attribution[field] = marker;
  for (const field of ["recorded_height", "recorded_view", "recorded_ms", "consensus_admitted_height"]) item.value[field] = marker;
  item.value.penalty_status = { status: "applied", details: { height: marker } };
  const body = JSON.stringify({ total: 1, items: [item] }).replaceAll(`"${marker}"`, "18446744073709551615");
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200, textBody: body, headers: { "content-type": "application/json" } }) });
  const value = (await client.listSumeragiEvidence()).items[0].value;
  assert.equal(value.record.generation, 18446744073709551615n);
  assert.equal(value.record.start_height, 18446744073709551615n);
  assert.equal(value.record.offenders[0].activation_height, 18446744073709551615n);
  assert.equal(value.attribution.scope.value.generation, 18446744073709551615n);
  for (const field of ["height", "epoch"]) assert.equal(value.attribution[field], 18446744073709551615n);
  for (const field of ["recorded_height", "recorded_view", "recorded_ms", "consensus_admitted_height"]) assert.equal(value[field], 18446744073709551615n);
  assert.equal(value.penalty_status.details.height, 18446744073709551615n);
  assert.deepEqual(value.record.evidence, item.value.record.evidence);
});
