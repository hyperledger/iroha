"use strict";

// Consume the unmodified Torii certificates exported after a real four-peer
// idle/Keepalive heartbeat or native key change. This exercises generation handoff and
// never installs a route or manufactures a monetary authorization.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const m = require("./sccp_v1_model.js");
const h = require("./sccp_edr_harness.js");
const { bytes } = require("./sccp_live_fourpeer.js");

function certificate(input, network, keys) {
  assert.deepEqual(input.committee.map((key) => bytes(key, 48, "committee key")), keys);
  const qc = bytes(input.qc, 116, "original QC");
  const header = bytes(input.header, 221, "original X");
  const parsed = m.parseHeader(header);
  assert.equal(parsed.networkId, network);
  assert.equal(parsed.height, BigInt(input.height));
  assert.equal(parsed.active, true);
  assert.equal(parsed.committeeRoot, m.committeeRoot(keys));
  const signers = m.signerIndices(m.parseQcFixed(qc).signers);
  assert.equal(signers.length, m.quorum(keys.length));
  assert(signers.every((index) => index < keys.length), "signers belong to the original committee");
  const signature = m.bls.G2.ProjectivePoint.fromHex(
    m.ethers.getBytes(bytes(input.aggregate_signature, 96, "original signature")),
  );
  signature.assertValidity();
  return {
    parsed,
    encoded: [qc, header, m.g2Evm192(signature), m.ethers.concat(keys), m.signerYs(keys, signers)],
  };
}

function decodeBundle(source) {
  assert.equal(source.version, 1);
  assert.equal(typeof source.chain_id, "string");
  assert(source.chain_id.length > 0);
  assert(source.signed_genesis_wire.length > 0, "retain the original signed genesis");
  assert.equal(source.certificates.length, 3, "normal, rotation, successor certificates");
  const role = source.certificate_roles[1];
  assert(["heartbeat", "key_change"].includes(role), "a named native transition is required");
  assert.deepEqual(source.certificate_roles, ["normal", role, "successor"]);
  const network = bytes(source.network_id, 32, "original network id");
  const instance = bytes(source.consensus_instance, 32, "original consensus instance");
  const initial = source.initial_generation;
  const keys = initial.keys.map((key) => bytes(key, 48, "original generation key"));
  assert.equal(keys.length, 4, "the source run uses four original validators");
  const root = bytes(initial.committee_root, 32, "original committee root");
  assert.equal(m.committeeRoot(keys), root);
  const nextKeys = source.certificates[2].committee.map((key) => bytes(key, 48, "successor key"));
  if (role === "heartbeat") assert.deepEqual(nextKeys, keys, "heartbeat preserves original ordered keys");
  else assert.equal(nextKeys.length, 7, "the native key-change scenario expands four validators to seven");
  const nextRoot = m.committeeRoot(nextKeys);
  if (role === "key_change") assert.notEqual(nextRoot, root, "key change requires a new committee");
  const certificates = source.certificates.map((input, index) => certificate(input, network, index === 2 ? nextKeys : keys));
  const [normal, rotation, successor] = certificates.map((item) => item.parsed);
  assert.equal(normal.rotation, false);
  assert.equal(rotation.rotation, true);
  assert.equal(successor.rotation, false);
  assert.equal(normal.generation, BigInt(initial.generation));
  assert.equal(rotation.generation, normal.generation, "the outgoing generation signs the rotation");
  assert.equal(rotation.nextCommitteeRoot, nextRoot, "the signed rotation binds the successor's ordered keys");
  assert.equal(successor.generation, rotation.generation + 1n);
  assert(rotation.height > normal.height);
  assert.equal(successor.height, rotation.height + 1n);
  assert(rotation.timestampMs > normal.timestampMs);
  assert(successor.timestampMs > rotation.timestampMs);
  const initialDeadline = BigInt(initial.deadline_ms);
  const renewedDeadline = rotation.timestampMs + rotation.validityMs;
  const successorDeadline = renewedDeadline > m.U64_MAX ? m.U64_MAX : renewedDeadline;
  assert(successorDeadline > initialDeadline, "the actual rotation renews validity");
  for (const [index, item] of certificates.entries()) {
    assert(((item.parsed.timestampMs + 999n) / 1000n) * 1000n <= (index < 2 ? initialDeadline : successorDeadline), "generation remains live at replay time");
  }
  const deployment = {
    tairaNetworkId: network, consensusInstance: instance,
    networkTag: m.PROFILES.ethereum.tag, routeRevision: 1,
    maxWrappedSupply: 1_000_000_000_000_000_000n,
    initialGeneration: BigInt(initial.generation), initialCommitteeRoot: root,
    initialStartHeight: BigInt(initial.start_height), initialUntilMs: initialDeadline,
  };
  return { role, certificates, normal, successor, initial, root, nextRoot, initialDeadline, successorDeadline, deployment };
}

async function replay(file) {
  const raw = fs.readFileSync(file);
  const source = JSON.parse(raw.toString("utf8"));
  const { role, certificates, normal, successor, initial, root, nextRoot, initialDeadline, successorDeadline, deployment } = decodeBundle(source);
  const results = [];
  for (const hardfork of ["prague", "osaka"]) {
    const chain = await h.Chain.open(m.PROFILES.ethereum, { hardfork, allowBlocksWithSameTimestamp: true });
    try {
      assert.equal(BigInt(await chain.rpc("eth_chainId", [])), 1n);
      const { destination, address } = await h.deploy(chain, deployment, {
        at: (normal.timestampMs + 999n) / 1000n,
      });
      assert.equal(address, m.create2Address(h.initCode(deployment)));
      assert.equal(await chain.rpc("eth_getCode", [address, "latest"]), h.expectedRuntime(h.immutableWords(deployment)));
      const steps = [];
      for (const [index, item] of certificates.entries()) {
        const { parsed, encoded } = item;
        const at = (parsed.timestampMs + 999n) / 1000n;
        const forgedQc = m.ethers.getBytes(encoded[0]);
        forgedQc[80] ^= 1;
        await h.expectRevert(destination.tx("submitCheckpoints", [[[m.ethers.hexlify(forgedQc), ...encoded.slice(1)]]], { at }), "BadSignature");
        const foreign = [...encoded];
        const foreignHeader = m.ethers.getBytes(encoded[1]);
        foreignHeader[16] ^= 1;
        foreign[1] = m.ethers.hexlify(foreignHeader);
        await h.expectRevert(destination.tx("submitCheckpoints", [[foreign]], { at }), "BadHeader");
        assert.equal(await destination.view("checkpointHeader", [parsed.height]), m.ZERO32);
        const receipt = await destination.tx("submitCheckpoints", [[encoded]], { at });
        assert.equal(await destination.view("checkpointHeader", [parsed.height]), m.checkpointId(encoded[1]));
        const published = destination.events(receipt, "SccpCertificate");
        assert.equal(published.length, 1);
        assert.deepEqual(Array.from(published[0].parsed.args), [parsed.height, parsed.generation, ...encoded.slice(0, 3)]);
        const checkpointed = destination.events(receipt, "SccpCheckpointed");
        assert.equal(checkpointed.length, 1);
        assert.deepEqual(Array.from(checkpointed[0].parsed.args), [parsed.height, m.checkpointId(encoded[1])]);
        const [currentRoot, untilMs, start, high, generation] = await destination.view("committeeState");
        assert.equal(currentRoot, index === 0 ? root : nextRoot);
        assert.equal(high, parsed.height);
        assert.equal(generation, index === 0 ? normal.generation : successor.generation);
        assert.equal(start, index === 0 ? BigInt(initial.start_height) : successor.height);
        assert.equal(untilMs, index === 0 ? initialDeadline : successorDeadline);
        const rotated = destination.events(receipt, "SccpCommitteeRotated");
        assert.equal(rotated.length, index === 1 ? 1 : 0);
        if (rotated.length > 0) {
          assert.deepEqual(Array.from(rotated[0].parsed.args), [successor.generation, nextRoot, successorDeadline, successor.height]);
        }
        const duplicateError = index === 1 ? "CommitteeNotAccepted" : "NothingToDo";
        await h.expectRevert(destination.tx("submitCheckpoints", [[encoded]], { at }), duplicateError);
        assert.equal(await destination.view("totalSupply"), 0n);
        assert.equal(await destination.view("opCount"), 0n);
        steps.push({ height: parsed.height.toString(), generation: parsed.generation.toString(), rotation: parsed.rotation, checkpoint: m.checkpointId(encoded[1]), gas_used: BigInt(receipt.gasUsed).toString(), duplicate_refusal: duplicateError });
      }
      const at = (successor.timestampMs + 999n) / 1000n;
      await h.expectRevert(destination.tx("submitCheckpoints", [[certificates[0].encoded]], { at }), "CommitteeNotAccepted");
      await h.expectRevert(destination.tx("submitCheckpoints", [[certificates[2].encoded]], { at: successorDeadline / 1000n + 1n }), "CommitteeNotAccepted");
      assert.equal(await destination.view("totalSupply"), 0n);
      assert.equal(await destination.view("opCount"), 0n);
      assert.equal(await destination.view("equivocated"), false);
      results.push({ hardfork, chain_id: 1, address, steps, successor_deadline_ms: successorDeadline.toString(), old_generation_refused: true, expired_successor_refused: true, monetary_effects: 0 });
    } finally {
      await chain.close();
    }
  }
  return { scope: `actual native ${role} and successor certificates to local chain-1 CREATE2 checkpoints; no route or monetary authority`, source_sha256: m.sha256(raw), source_chain_id: source.chain_id, results };
}

if (require.main === module) {
  assert.equal(process.argv.length, 3, "pass the actual native heartbeat or key-change export");
  replay(process.argv[2]).then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)).catch((error) => {
    process.stderr.write(`${error.stack}\n`);
    process.exitCode = 1;
  });
}

module.exports = { certificate, decodeBundle, replay };
