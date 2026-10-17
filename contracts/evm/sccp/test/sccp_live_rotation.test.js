"use strict";

// Structural replay-adapter tests use public fixtures and unsigned header edits.
// They do not claim native-network or signature qualification of those edits.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const m = require("./sccp_v1_model.js");
const { certificate, decodeBundle } = require("./sccp_live_heartbeat.js");
const vectors = require("../../../../fixtures/sccp/finality_v1.json");

function row(label) {
  const source = vectors.certificates.find((item) => item.label === label);
  const keys = source.evm.committee.slice(2).match(/.{96}/g).map((key) => `0x${key}`);
  return { source, keys, certificate: { height: source.header_fields.height, committee: keys,
    qc: source.evm.qc, header: source.evm.header, aggregate_signature: source.aggregate_signature.compressed } };
}

function sequence(role) {
  const old = row("n4_lowest_q");
  const next = role === "heartbeat" ? old : row("n7_lowest_q");
  const normal = m.parseHeader(old.certificate.header);
  const rotation = { ...normal, height: normal.height + 1n, timestampMs: normal.timestampMs + 3_600_000n,
    flags: m.FLAG_ACTIVE | m.FLAG_ROTATION, nextCommitteeRoot: m.committeeRoot(next.keys), validityMs: 1_209_600_000n };
  const successor = { ...normal, height: normal.height + 2n, timestampMs: rotation.timestampMs + 1_000n,
    generation: normal.generation + 1n, committeeRoot: m.committeeRoot(next.keys) };
  return { version: 1, chain_id: "structural-test-only", signed_genesis_wire: [1],
    network_id: normal.networkId, consensus_instance: vectors.verification_context.consensus_instance,
    initial_generation: { ...old.source.pin, deadline_ms: old.source.pin.until_ms, keys: old.keys },
    certificate_roles: ["normal", role, "successor"], certificates: [old.certificate,
      { ...old.certificate, height: Number(rotation.height), header: m.encodeHeader(rotation) },
      { ...next.certificate, height: Number(successor.height), header: m.encodeHeader(successor) }] };
}

test("certificate adapter retains original QC, header and compressed-signature point", () => {
  const input = row("n4_lowest_q");
  const decoded = certificate(input.certificate, input.source.header_fields.network_id, input.keys);
  assert.equal(decoded.encoded[0], input.certificate.qc);
  assert.equal(decoded.encoded[1], input.certificate.header);
  assert.equal(decoded.encoded[2], input.source.evm.signature);
});

for (const role of ["heartbeat", "key_change"]) {
  test(`accepts the original committees of a structurally valid ${role}`, () => {
    const decoded = decodeBundle(sequence(role));
    assert.equal(decoded.role, role);
    assert.equal(decoded.successor.generation, decoded.normal.generation + 1n);
    assert.equal(decoded.root === decoded.nextRoot, role === "heartbeat");
  });
}

test("refuses role substitution", () => {
  const input = sequence("heartbeat"); input.certificate_roles[1] = "key_change";
  assert.throws(() => decodeBundle(input));
});
test("refuses successor committee order substitution", () => {
  const input = sequence("key_change"); input.certificates[2].committee.reverse();
  assert.throws(() => decodeBundle(input));
});
test("refuses outgoing committee substitution", () => {
  const input = sequence("key_change"); input.certificates[1].committee = input.certificates[2].committee;
  assert.throws(() => decodeBundle(input));
});
test("refuses a successor header outside the signed next root", () => {
  const input = sequence("key_change");
  const parsed = m.parseHeader(input.certificates[1].header);
  input.certificates[1].header = m.encodeHeader({ ...parsed, nextCommitteeRoot: parsed.committeeRoot });
  assert.throws(() => decodeBundle(input));
});
test("refuses generation expiry before replay", () => {
  const input = sequence("heartbeat"); input.initial_generation.deadline_ms = 1;
  assert.throws(() => decodeBundle(input));
});
test("refuses duplicate or unnamed sequence roles", () => {
  const input = sequence("heartbeat"); input.certificate_roles[2] = "normal";
  assert.throws(() => decodeBundle(input));
});
test("refuses quorum bits outside the original committee", () => {
  const input = row("n4_lowest_q");
  const qc = m.ethers.getBytes(input.certificate.qc); qc.fill(0, 112); qc[115] = 0x43;
  assert.throws(() => certificate({ ...input.certificate, qc: Array.from(qc) }, input.source.header_fields.network_id, input.keys));
});
