import test from "node:test";
import assert from "node:assert/strict";
import { ToriiClient as SourceToriiClient } from "../src/toriiClient.js";
import { ToriiClient as DistToriiClient } from "../dist/toriiClient.js";

const BASE_URL = "https://localhost:8080";

function createResponse({ status, textBody, headers }) {
  return new Response(textBody, { status, headers });
}

for (const [label, ToriiClient] of [["source", SourceToriiClient], ["dist", DistToriiClient]]) {
  test(`${label}: SoraFS reputation validation rejects adversarial shapes, bounds, and polluted fields`, async () => {
    const snapshotIdHex = "ab".repeat(16);
    const merkleRootHex = "cd".repeat(32);
    const witness = Buffer.from("canonical-witness", "utf8").toString("base64");
    const auth = { headers: { "X-Iroha-Witness": witness } };
    const snapshot = () => ({
      snapshot_id_hex: snapshotIdHex,
      generated_at_unix: 1_800_000_000,
      previous_snapshot_id_hex: null,
      merkle_root_hex: merkleRootHex,
      provider_count: 1,
      returned_provider_count: 1,
      limit: 50,
      truncated_providers: false,
      alpha_bps: 8500,
      current_score_weight_bps: 7000,
      weights: {
        version: 1,
        por_success_bps: 2200,
        pdp_success_bps: 2000,
        potr_success_bps: 1800,
        latency_bps: 1500,
        dispute_bps: 1000,
        token_violation_bps: 500,
        repair_breach_bps: 1000,
      },
      providers: [
        {
          provider_id: "provider:alpha",
          score_bps: 9800,
          degradation_flags: [],
          raw_metrics: {
            version: 1,
            por_success_bps: 9900,
            pdp_success_bps: 9800,
            potr_success_bps: 9700,
            latency_health_bps: 9600,
            dispute_rate_bps: 100,
            token_violation_rate_bps: 0,
            repair_breach_rate_bps: 0,
          },
          raw_metrics_hash_hex: "ef".repeat(32),
        },
      ],
    });
    const clientForText = (textBody) =>
      new ToriiClient(BASE_URL, {
        fetchImpl: async () =>
          createResponse({
            status: 200,
            textBody,
            headers: { "content-type": "application/json" },
          }),
      });
    const rejectSnapshot = async (payload, pattern) => {
      await assert.rejects(
        () =>
          clientForText(
            typeof payload === "string" ? payload : JSON.stringify(payload),
          ).getSorafsReputationLatest(auth),
        pattern,
      );
    };

    await rejectSnapshot([], /latest endpoint must be an object/);

    const metricsArray = snapshot();
    metricsArray.providers[0].raw_metrics = [];
    await rejectSnapshot(metricsArray, /raw_metrics must be an object/);

    const flagsObject = snapshot();
    flagsObject.providers[0].degradation_flags = {};
    await rejectSnapshot(flagsObject, /degradation_flags must be an array/);

    const unsupportedFlag = snapshot();
    unsupportedFlag.providers[0].degradation_flags = [
      { flag: "attacker_defined", value: null },
    ];
    const originalIndexOf = Array.prototype.indexOf;
    try {
      Array.prototype.indexOf = () => 0;
      await rejectSnapshot(
        unsupportedFlag,
        /degradation_flags\[0\]\.flag is unsupported/,
      );
    } finally {
      Array.prototype.indexOf = originalIndexOf;
    }

    const lowScore = snapshot();
    lowScore.providers[0].score_bps = 499;
    await rejectSnapshot(lowScore, /score_bps must be between 500 and 9900/);

    const highMetric = snapshot();
    highMetric.providers[0].raw_metrics.por_success_bps = 10_001;
    await rejectSnapshot(
      highMetric,
      /raw_metrics\.por_success_bps must be between 0 and 10000/,
    );

    const wrongVersion = snapshot();
    wrongVersion.weights.version = 2;
    await rejectSnapshot(
      wrongVersion,
      /weights\.version must be between 1 and 1/,
    );

    const negativeZero = JSON.stringify(snapshot()).replace(
      '"generated_at_unix":1800000000',
      '"generated_at_unix":-0',
    );
    await rejectSnapshot(
      negativeZero,
      /negative zero is forbidden/,
    );

    const aboveU64 = JSON.stringify(snapshot()).replace(
      '"generated_at_unix":1800000000',
      '"generated_at_unix":18446744073709551616',
    );
    await rejectSnapshot(
      aboveU64,
      /generated_at_unix must be between 1 and 18446744073709551615/,
    );

    const extraPrototypeKey = snapshot();
    Object.defineProperty(extraPrototypeKey, "__proto__", {
      value: { returned_provider_count: 1 },
      enumerable: true,
    });
    await rejectSnapshot(
      extraPrototypeKey,
      /fields are not canonical.*extra=\[__proto__\]/,
    );

    const precedence = snapshot();
    delete precedence.returned_provider_count;
    precedence.alpha_bps = 1;
    await rejectSnapshot(
      precedence,
      /fields are not canonical.*missing=\[returned_provider_count\]/,
    );

    Object.prototype.returned_provider_count = 1;
    try {
      const inheritedField = snapshot();
      delete inheritedField.returned_provider_count;
      await rejectSnapshot(
        inheritedField,
        /fields are not canonical.*missing=\[returned_provider_count\]/,
      );
    } finally {
      delete Object.prototype.returned_provider_count;
    }

    Object.prototype["X-Iroha-Witness"] = witness;
    try {
      await assert.rejects(
        () =>
          clientForText(JSON.stringify(snapshot())).getSorafsReputationLatest({
            headers: {},
          }),
        /requires canonicalAuth or an exact X-Iroha-Witness header/,
      );
    } finally {
      delete Object.prototype["X-Iroha-Witness"];
    }
  });

  test(`${label}: Torii validation captures intrinsic statics against later monkey-patching`, async () => {
    const snapshotIdHex = "ab".repeat(16);
    const snapshot = {
      snapshot_id_hex: snapshotIdHex,
      generated_at_unix: 1_800_000_000,
      previous_snapshot_id_hex: null,
      merkle_root_hex: "cd".repeat(32),
      provider_count: 1,
      returned_provider_count: 1,
      limit: 50,
      truncated_providers: false,
      alpha_bps: 8500,
      current_score_weight_bps: 7000,
      weights: {
        version: 1,
        por_success_bps: 2200,
        pdp_success_bps: 2000,
        potr_success_bps: 1800,
        latency_bps: 1500,
        dispute_bps: 1000,
        token_violation_bps: 500,
        repair_breach_bps: 1000,
      },
      providers: [
        {
          provider_id: "provider:alpha",
          score_bps: 9800,
          degradation_flags: [],
          raw_metrics: {
            version: 1,
            por_success_bps: 9900,
            pdp_success_bps: 9800,
            potr_success_bps: 9700,
            latency_health_bps: 9600,
            dispute_rate_bps: 100,
            token_violation_rate_bps: 0,
            repair_breach_rate_bps: 0,
          },
          raw_metrics_hash_hex: "ef".repeat(32),
        },
      ],
    };
    const bodyBytes = new TextEncoder().encode(JSON.stringify(snapshot));
    const response = {
      status: 200,
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(bodyBytes);
          controller.close();
        },
      }),
      headers: {
        get(name) {
          return name.toLowerCase() === "content-type"
            ? "application/json"
            : null;
        },
      },
    };
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => response,
    });
    const witness = Buffer.from("canonical-witness", "utf8").toString("base64");
    const originals = {
      arrayIsArray: Array.isArray,
      numberIsFinite: Number.isFinite,
      numberIsInteger: Number.isInteger,
      numberIsSafeInteger: Number.isSafeInteger,
      objectEntries: Object.entries,
      objectFreeze: Object.freeze,
      objectGetOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
      objectHasOwn: Object.hasOwn,
      objectKeys: Object.keys,
    };
    const poisoned = () => {
      throw new Error("poisoned intrinsic must not be called");
    };
    try {
      Array.isArray = poisoned;
      Number.isFinite = poisoned;
      Number.isInteger = poisoned;
      Number.isSafeInteger = poisoned;
      Object.entries = poisoned;
      Object.freeze = poisoned;
      Object.getOwnPropertyDescriptor = poisoned;
      Object.hasOwn = poisoned;
      Object.keys = poisoned;
      const parsed = await client.getSorafsReputationLatest({
        headers: { "X-Iroha-Witness": witness },
      });
      assert.equal(parsed?.snapshot_id_hex, snapshotIdHex);
    } finally {
      Array.isArray = originals.arrayIsArray;
      Number.isFinite = originals.numberIsFinite;
      Number.isInteger = originals.numberIsInteger;
      Number.isSafeInteger = originals.numberIsSafeInteger;
      Object.entries = originals.objectEntries;
      Object.freeze = originals.objectFreeze;
      Object.getOwnPropertyDescriptor = originals.objectGetOwnPropertyDescriptor;
      Object.hasOwn = originals.objectHasOwn;
      Object.keys = originals.objectKeys;
    }
  });

}
