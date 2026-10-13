import { test as baseTest } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  BOND_COUPON_FREQUENCIES,
  BOND_MAX_CASHFLOWS,
  bondHolderPayment,
  bondVaultAccountId,
  buildBondSchedule,
  buildCallBondInstruction,
  buildClaimBondCashflowInstruction,
  buildCloseBondCashflowInstruction,
  buildDeclareBondDefaultInstruction,
  buildFundBondCashflowInstruction,
  buildRecordBondCashflowInstruction,
  buildRegisterBondInstruction,
  validateBondTerms,
} from "../src/bond.js";
import * as builders from "../src/instructionBuilders.js";
import * as sdk from "../src/index.js";
import {
  noritoDecodeInstruction,
  noritoDecodeInstructionBoxArchive,
  noritoEncodeInstruction,
  noritoEncodeInstructionBoxArchive,
} from "../src/norito.js";
import { KotodamaQuantity } from "../src/numericV1.js";
import { ToriiClient } from "../src/toriiClient.js";
import { ToriiBrowserClient } from "../src/toriiBrowserClient.js";
import { makeNativeTest } from "./helpers/native.js";

const test = makeNativeTest(baseTest, {
  require: [
    "noritoEncodeInstruction",
    "noritoDecodeInstruction",
    "noritoEncodeInstructionBoxArchive",
    "noritoDecodeInstructionBoxArchive",
    "bondVaultAccountId",
  ],
});

/** Vectors generated from the Rust data model by `iroha_js_codec` (bond_instruction_tests.rs). */
const FIXTURE = JSON.parse(
  readFileSync(new URL("./fixtures/bond-v1-codec.json", import.meta.url), "utf8"),
);
const PREFIX = FIXTURE.network_prefix;
const instructionVector = (name) => FIXTURE.instructions.find((vector) => vector.name === name);

function cashflowInput(native) {
  return {
    index: native.index,
    kind: native.kind,
    recordDateMs: native.record_date_ms,
    paymentDateMs: native.payment_date_ms,
    amountPerUnit: native.amount_per_unit,
  };
}

/** Map native snake_case `BondTerms` JSON to the builder's camelCase input. */
function termsInput(native) {
  return {
    issuer: native.issuer,
    payingAgent: native.paying_agent,
    paymentAsset: native.payment_asset,
    denomination: native.denomination,
    couponRateBps: native.coupon_rate_bps,
    couponFrequency: native.coupon_frequency,
    dayCount: native.day_count,
    issueDateMs: native.issue_date_ms,
    maturityDateMs: native.maturity_date_ms,
    redemptionPriceBps: native.redemption_price_bps,
    call: native.call === null ? null : {
      firstCallDateMs: native.call.first_call_date_ms,
      priceBps: native.call.price_bps,
      noticeMs: native.call.notice_ms,
    },
    cashflows: native.cashflows.map(cashflowInput),
    identifiers: {
      isin: native.identifiers.isin,
      cfi: native.identifiers.cfi,
      issuerLei: native.identifiers.issuer_lei,
      bdtVersion: native.identifiers.bdt_version,
      bdtDocumentSha256: native.identifiers.bdt_document_sha256,
    },
    termsSha256: native.terms_sha256,
  };
}

function build(name, payload) {
  switch (name) {
    case "Register":
    case "RegisterZeroCoupon":
      return buildRegisterBondInstruction({ bondId: payload.bond, terms: termsInput(payload.terms) });
    case "RecordCashflow":
      return buildRecordBondCashflowInstruction({ bondId: payload.bond, index: payload.index });
    case "FundCashflow":
      return buildFundBondCashflowInstruction({
        bondId: payload.bond,
        index: payload.index,
        sourceAssetHoldingId: payload.source,
      });
    case "ClaimCashflow":
      return buildClaimBondCashflowInstruction({
        bondId: payload.bond,
        index: payload.index,
        holder: payload.holder,
      });
    case "CloseCashflow":
      return buildCloseBondCashflowInstruction({ bondId: payload.bond, index: payload.index });
    case "Call":
      return buildCallBondInstruction({ bondId: payload.bond, callDateMs: payload.call_date_ms });
    case "DeclareDefault":
      return buildDeclareBondDefaultInstruction({
        bondId: payload.bond,
        index: payload.index,
        evidenceSha256: payload.evidence_sha256,
      });
    default:
      throw new Error(`unknown vector ${name}`);
  }
}

baseTest("bond helpers are exported from the package and the instruction-builders subpath", () => {
  for (const name of [
    "buildRegisterBondInstruction",
    "buildRecordBondCashflowInstruction",
    "buildFundBondCashflowInstruction",
    "buildClaimBondCashflowInstruction",
    "buildCloseBondCashflowInstruction",
    "buildCallBondInstruction",
    "buildDeclareBondDefaultInstruction",
  ]) {
    assert.equal(typeof builders[name], "function", name);
    assert.equal(sdk[name], builders[name], name);
  }
  for (const name of ["buildBondSchedule", "validateBondTerms", "bondHolderPayment", "bondVaultAccountId"]) {
    assert.equal(typeof sdk[name], "function", name);
  }
  assert.deepEqual(BOND_COUPON_FREQUENCIES, [0, 1, 2, 4, 12]);
  assert.equal(BOND_MAX_CASHFLOWS, 400);
});

baseTest("buildBondSchedule reproduces every Rust fixed_rate_bullet_schedule vector", () => {
  assert.ok(FIXTURE.schedules.length >= 10);
  for (const vector of FIXTURE.schedules) {
    if (vector.error !== undefined) {
      assert.throws(() => buildBondSchedule(vector.request), (error) => {
        assert.equal(error.message, vector.error, vector.name);
        return true;
      }, vector.name);
      continue;
    }
    assert.deepEqual(
      buildBondSchedule(vector.request),
      vector.cashflows.map(cashflowInput),
      vector.name,
    );
  }
});

baseTest("buildBondSchedule admits 399 monthly coupons and refuses the 400th, as Core does", () => {
  const request = {
    denomination: "1200",
    couponRateBps: 600,
    couponFrequency: 12,
    issueDateMs: Date.UTC(2026, 0, 15),
    maturityDateMs: Date.UTC(2059, 3, 15),
    redemptionPriceBps: 10_000,
    recordOffsetMs: 86_400_000,
  };
  const cashflows = buildBondSchedule(request);
  assert.equal(cashflows.length, BOND_MAX_CASHFLOWS);
  assert.equal(cashflows.at(-1).kind, "Redemption");
  assert.equal(cashflows[0].amountPerUnit, "6");
  assert.throws(
    () => buildBondSchedule({ ...request, maturityDateMs: Date.UTC(2059, 4, 15) }),
    /^ValidationError: bond.invalid_terms: schedule exceeds the cash-flow limit$/u,
  );
});

baseTest("buildBondSchedule accepts lossless inputs and rejects lossy or unknown fields", () => {
  const base = FIXTURE.schedules[0].request;
  const expected = buildBondSchedule(base);
  assert.deepEqual(
    buildBondSchedule({
      ...base,
      denomination: new KotodamaQuantity(50n, 0),
      issueDateMs: BigInt(base.issueDateMs),
      maturityDateMs: String(base.maturityDateMs),
    }),
    expected,
  );
  assert.deepEqual(buildBondSchedule({ ...base, denomination: 50n }), expected);
  assert.throws(() => buildBondSchedule({ ...base, denomination: 50 }), /JavaScript numbers are not lossless/u);
  assert.throws(() => buildBondSchedule({ ...base, denomination: "50.0" }), /canonical non-negative quantity/u);
  assert.throws(() => buildBondSchedule({ ...base, legacy: true }), /legacy is not supported/u);
  const { recordOffsetMs: _omitted, ...missing } = base;
  assert.throws(() => buildBondSchedule(missing), /recordOffsetMs is required/u);
  assert.throws(() => buildBondSchedule({ ...base, couponFrequency: 256 }), /must not exceed 255/u);
  assert.throws(() => buildBondSchedule({ ...base, issueDateMs: 1.5 }), /safe integer/u);
});

baseTest("bondHolderPayment rounds down exactly like Core's holder_payment", () => {
  for (const vector of FIXTURE.holder_payments) {
    assert.equal(
      bondHolderPayment({
        units: vector.units,
        amountPerUnit: vector.amountPerUnit,
        paymentScale: vector.paymentScale,
      }),
      vector.payment,
      JSON.stringify(vector),
    );
  }
  assert.throws(
    () => bondHolderPayment({ units: "1", amountPerUnit: "1", paymentScale: 29 }),
    /must not exceed 28/u,
  );
});

test("validateBondTerms agrees with BondTerms::validate on every Rust vector", () => {
  assert.ok(FIXTURE.terms_validation.length >= 30);
  for (const vector of FIXTURE.terms_validation) {
    const input = termsInput(vector.terms);
    if (vector.error === null) {
      assert.deepEqual(validateBondTerms(input), vector.terms, vector.name);
      continue;
    }
    assert.throws(() => validateBondTerms(input), (error) => {
      assert.equal(error.message, vector.error, vector.name);
      assert.equal(error.name, "ValidationError");
      return true;
    }, vector.name);
  }
});

test("schedules from buildBondSchedule register under validateBondTerms", () => {
  const base = termsInput(instructionVector("Register").json.Bond.Register.terms);
  for (const vector of FIXTURE.schedules.filter((entry) => entry.cashflows !== undefined)) {
    const request = vector.request;
    const terms = {
      ...base,
      denomination: request.denomination,
      couponRateBps: request.couponFrequency === 0 ? 0 : request.couponRateBps,
      couponFrequency: request.couponFrequency,
      issueDateMs: request.issueDateMs,
      maturityDateMs: request.maturityDateMs,
      redemptionPriceBps: request.redemptionPriceBps,
      call: null,
      cashflows: buildBondSchedule(request),
    };
    assert.equal(validateBondTerms(terms).cashflows.length, vector.cashflows.length, vector.name);
  }
});

test("bond builders reproduce the Rust envelopes, archives and frames exactly", () => {
  assert.equal(FIXTURE.instructions.length, 8);
  for (const vector of FIXTURE.instructions) {
    const [variant] = Object.keys(vector.json.Bond);
    const built = build(vector.name, vector.json.Bond[variant]);
    assert.deepEqual(built, vector.json, vector.name);
    const archive = noritoEncodeInstructionBoxArchive(built, PREFIX);
    assert.equal(Buffer.from(archive).toString("hex"), vector.archive_hex, vector.name);
    assert.deepEqual(
      noritoDecodeInstructionBoxArchive(Buffer.from(vector.archive_hex, "hex"), PREFIX),
      vector.json,
      vector.name,
    );
    const frame = noritoEncodeInstruction(built, PREFIX);
    assert.equal(Buffer.from(frame).toString("hex"), vector.frame_hex, vector.name);
    assert.deepEqual(
      noritoDecodeInstruction(Buffer.from(vector.frame_hex, "hex"), PREFIX),
      vector.json,
      vector.name,
    );
  }
});

test("the native codec refuses non-canonical bond envelopes", () => {
  const record = instructionVector("RecordCashflow").json;
  const declare = instructionVector("DeclareDefault").json;
  const cases = [
    { Bond: { RecordCashflow: { ...record.Bond.RecordCashflow, legacy: 1 } } },
    { Bond: { RecordCashflow: { bond: record.Bond.RecordCashflow.bond } } },
    { Bond: { Record: record.Bond.RecordCashflow } },
    { Bond: { ...record.Bond, CloseCashflow: record.Bond.RecordCashflow } },
    { Bond: {} },
    { ...record, Extra: null },
    { RecordBondCashflow: record.Bond.RecordCashflow },
    {
      Bond: {
        DeclareDefault: {
          ...declare.Bond.DeclareDefault,
          evidence_sha256: declare.Bond.DeclareDefault.evidence_sha256.toUpperCase(),
        },
      },
    },
  ];
  for (const instruction of cases) {
    assert.throws(() => noritoEncodeInstructionBoxArchive(instruction, PREFIX), JSON.stringify(instruction));
  }
});

test("bond builders normalize digests and refuse malformed or out-of-contract input", () => {
  const declare = instructionVector("DeclareDefault").json.Bond.DeclareDefault;
  const fromBytes = buildDeclareBondDefaultInstruction({
    bondId: declare.bond,
    index: 1,
    evidenceSha256: Uint8Array.from(Buffer.from(declare.evidence_sha256, "hex")),
  });
  assert.deepEqual(fromBytes, instructionVector("DeclareDefault").json);
  assert.deepEqual(
    buildDeclareBondDefaultInstruction({
      bondId: declare.bond,
      index: "1",
      evidenceSha256: declare.evidence_sha256.toUpperCase(),
    }),
    instructionVector("DeclareDefault").json,
  );
  assert.throws(
    () => buildDeclareBondDefaultInstruction({ bondId: declare.bond, index: 1, evidenceSha256: "ab" }),
    /64 hexadecimal digits/u,
  );
  assert.throws(
    () => buildRecordBondCashflowInstruction({ bondId: declare.bond, index: 65_536 }),
    /must not exceed 65535/u,
  );
  assert.throws(
    () => buildRecordBondCashflowInstruction({ bondId: declare.bond, index: 0, extra: 1 }),
    /extra is not supported/u,
  );
  assert.throws(() => buildCloseBondCashflowInstruction({ bondId: "si_bond#bondpoc.universal", index: 0 }));
  const fund = instructionVector("FundCashflow").json.Bond.FundCashflow;
  assert.throws(
    () => buildFundBondCashflowInstruction({
      bondId: fund.bond,
      index: 0,
      sourceAssetHoldingId: `${fund.source}#dataspace:7`,
    }),
    /global \(unscoped\) balance/u,
  );
  const register = instructionVector("Register").json.Bond.Register;
  assert.throws(
    () => buildRegisterBondInstruction({
      bondId: register.terms.payment_asset,
      terms: termsInput(register.terms),
    }),
    /^ValidationError: bond.invalid_terms: the payment asset must differ from the bond$/u,
  );
  assert.throws(
    () => buildRegisterBondInstruction({
      bondId: register.bond,
      terms: { ...termsInput(register.terms), dayCount: "actual" },
    }),
    /dayCount must be one of/u,
  );
  const withoutCall = termsInput(register.terms);
  delete withoutCall.call;
  assert.equal(buildRegisterBondInstruction({ bondId: register.bond, terms: withoutCall }).Bond.Register.terms.call, null);
  assert.throws(
    () => buildRegisterBondInstruction({
      bondId: register.bond,
      terms: { ...termsInput(register.terms), cashflows: buildBondSchedule({
        ...FIXTURE.schedules[0].request,
        couponFrequency: 2,
      }) },
    }),
    /^ValidationError: bond.invalid_terms: coupon 0 amount per unit must be 3.25$/u,
  );
});

test("bondVaultAccountId matches the native vault derivation", () => {
  for (const vault of FIXTURE.vaults) {
    assert.equal(bondVaultAccountId(vault.bond, PREFIX), vault.account);
  }
  assert.notEqual(bondVaultAccountId(FIXTURE.bond, 753), FIXTURE.vaults[0].account);
  assert.throws(() => bondVaultAccountId(FIXTURE.bond, 65_536), /must not exceed 65535/u);
  assert.throws(() => bondVaultAccountId("not-a-bond", PREFIX));
});

function jsonResponse(status, body) {
  return new Response(body == null ? null : JSON.stringify(body), {
    status,
    headers: body == null ? undefined : { "Content-Type": "application/json" },
  });
}

for (const [label, Client] of [["ToriiClient", ToriiClient], ["ToriiBrowserClient", ToriiBrowserClient]]) {
  test(`${label}.listBonds and getBond return native bond records`, async () => {
    const record = FIXTURE.record;
    const requests = [];
    const client = new Client("https://torii.example", {
      fetchImpl: async (input, init) => {
        const path = new URL(input).pathname;
        requests.push([init?.method ?? "GET", path]);
        if (path === "/v1/bonds") return jsonResponse(200, [record]);
        if (path === `/v1/bonds/${record.id}`) return jsonResponse(200, record);
        if (path === `/v1/bonds/${FIXTURE.payment_asset}`) return jsonResponse(404, null);
        return jsonResponse(200, { ...record, id: FIXTURE.payment_asset });
      },
    });
    // Records are parsed losslessly (null-prototype objects); compare their JSON.
    const plain = (value) => JSON.parse(JSON.stringify(value));
    assert.deepEqual(plain(await client.listBonds()), [record]);
    assert.deepEqual(plain(await client.getBond(record.id)), record);
    assert.equal(await client.getBond(FIXTURE.payment_asset), null);
    assert.deepEqual(requests.slice(0, 3), [
      ["GET", "/v1/bonds"],
      ["GET", `/v1/bonds/${record.id}`],
      ["GET", `/v1/bonds/${FIXTURE.payment_asset}`],
    ]);
    await assert.rejects(() => client.getBond("si_bond#bondpoc.universal"));
    await assert.rejects(() => client.listBonds({ extra: true }));
  });

  test(`${label} refuses responses that are not the requested bond record`, async () => {
    const record = FIXTURE.record;
    const respond = (body) => new Client("https://torii.example", {
      fetchImpl: async () => jsonResponse(200, body),
    });
    await assert.rejects(
      () => respond({ ...record, id: FIXTURE.payment_asset }).getBond(record.id),
      /not the requested bond/u,
    );
    await assert.rejects(() => respond({ total: 1, items: [] }).listBonds(), /array of bond records/u);
    await assert.rejects(
      () => respond({ ...record, state: { ...record.state, lifecycle: "Paused" } }).getBond(record.id),
      /lifecycle/u,
    );
  });
}
