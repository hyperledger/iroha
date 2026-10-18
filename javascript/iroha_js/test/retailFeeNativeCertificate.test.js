import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { normalizeParliamentGovernanceCertificateV1 } from "../src/parliamentApiV1.js";

// Hand-reduced public-body-shape sample of the native certificate JSON: one
// public-finding body and no private-jury binding, because the SDK has no parser
// for the private-jury result binding until the anonymous-ballot binding is
// supported. This tests the wire contract; it is synthetic and cannot establish
// finality or authorize production fees.
// TODO(parliament anonymous ballot, P4): replace this sample with a native
// serialization that includes the anonymous private-jury result binding.
const fixture = JSON.parse(readFileSync(new URL("./fixtures/retail_fee_native_certificate_v1.json", import.meta.url), "utf8"));

test("fee policy disclosure accepts the exact native Parliament certificate JSON", () => {
  assert.deepEqual(normalizeParliamentGovernanceCertificateV1(fixture), fixture);
  assert.ok(Array.isArray(fixture.effect_preimage_hash));
  assert.deepEqual(fixture.risk_tier, { tier: "Standard", details: null });
  assert.deepEqual(fixture.body_bindings.map(({ body }) => body), ["rules-committee"]);
  assert.equal(fixture.body_bindings[0].ballot, null);
});

test("certificate validation rejects altered native unit and commitment encodings", () => {
  for (const mutate of [
    value => { delete value.risk_tier.details; },
    value => { value.risk_tier.details = { approved: true }; },
    value => { value.effect_preimage_hash = Buffer.from(value.effect_preimage_hash).toString("hex"); },
    value => {
      value.body_bindings[0].public_finding.endorsement_root =
        Buffer.from(value.body_bindings[0].public_finding.endorsement_root).toString("hex");
    },
    value => { value.body_bindings[0].sortition_request.governance_attempt_id = "ee".repeat(32); },
  ]) {
    const candidate = structuredClone(fixture);
    mutate(candidate);
    assert.throws(() => normalizeParliamentGovernanceCertificateV1(candidate));
  }
});

test("certificate validation rejects a private-jury binding until the anonymous-ballot binding is supported", () => {
  for (const body of ["policy-jury", "confirmation-jury"]) {
    const candidate = structuredClone(fixture);
    candidate.body_bindings[0].body = body;
    candidate.body_bindings[0].sortition_request.body = body;
    assert.throws(
      () => normalizeParliamentGovernanceCertificateV1(candidate),
      {
        name: "TypeError",
        message: "certificate.body_bindings[0] private-jury result binding is not admitted until the anonymous-ballot result binding is supported",
      },
      body,
    );
  }
});
