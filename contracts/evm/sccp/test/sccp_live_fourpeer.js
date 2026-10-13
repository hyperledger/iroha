"use strict";

// Replay the public output of integration_tests/tests/sccp_lanes/main.rs on
// the actual locked CREATE2 destination. The input is emitted only after all
// four real peers verify the original native certificate and the launch gate.
// This qualifies native checkpoint interoperability; it does not install a route.
// Run after the four-peer test:
// node contracts/evm/sccp/test/sccp_live_fourpeer.js target/sccp-continuation/live-fourpeer-sccp.json

const assert = require("node:assert/strict");
const fs = require("node:fs");
const m = require("./sccp_v1_model.js");
const h = require("./sccp_edr_harness.js");

function bytes(value, length, name) {
  if (typeof value !== "string") {
    assert(Array.isArray(value), `${name}: bytes must be a JSON array or hex string`);
    assert(value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255), `${name}: canonical byte values`);
  }
  if (typeof value === "string") {
    const digits = value.startsWith("0x") ? value.slice(2) : value;
    assert(/^[0-9a-fA-F]+$/.test(digits) && digits.length % 2 === 0, `${name}: canonical hex bytes`);
    value = `0x${digits}`;
  }
  const encoded = m.ethers.hexlify(typeof value === "string" ? value : Uint8Array.from(value));
  assert.equal(m.ethers.getBytes(encoded).length, length, name);
  return encoded;
}

async function replay(file) {
  const raw = fs.readFileSync(file);
  const source = JSON.parse(raw.toString("utf8"));
  assert.equal(source.version, 1);
  assert.equal(typeof source.chain_id, "string");
  assert(source.chain_id.length > 0);
  assert(source.signed_genesis_wire.length > 0, "the source retains original SignedBlockWire");
  const generation = source.initial_generation;
  const cert = source.certificate;
  const keys = cert.committee.map((key) => bytes(key, 48, "committee key"));
  const originalKeys = generation.keys.map((key) => bytes(key, 48, "original generation key"));
  assert.deepEqual(keys, originalKeys, "the real block is signed by the pinned original generation");
  const qc = bytes(cert.qc, 116, "original QC");
  const header = bytes(cert.header, 221, "original X");
  const parsed = m.parseHeader(header);
  const network = bytes(source.network_id, 32, "original network id");
  const instance = bytes(source.consensus_instance, 32, "original consensus instance");
  assert.equal(parsed.networkId, network);
  assert.equal(parsed.height, BigInt(cert.height));
  assert.equal(parsed.active, true);
  assert.equal(parsed.rotation, false);
  assert.equal(parsed.generation, BigInt(generation.generation));
  assert.equal(parsed.committeeRoot, bytes(generation.committee_root, 32, "original root"));
  assert.equal(m.committeeRoot(keys), parsed.committeeRoot);
  const indices = m.signerIndices(m.parseQcFixed(qc).signers);
  assert.equal(indices.length, m.quorum(keys.length), "native exact quorum");
  const signature = m.bls.G2.ProjectivePoint.fromHex(m.ethers.getBytes(bytes(cert.aggregate_signature, 96, "original signature")));
  signature.assertValidity();
  const certificate = [qc, header, m.g2Evm192(signature), m.ethers.concat(keys), m.signerYs(keys, indices)];
  const deployment = {
    tairaNetworkId: network, consensusInstance: instance,
    networkTag: m.PROFILES.ethereum.tag, routeRevision: 1,
    maxWrappedSupply: 1_000_000_000_000_000_000n,
    initialGeneration: BigInt(generation.generation),
    initialCommitteeRoot: parsed.committeeRoot,
    initialStartHeight: BigInt(generation.start_height),
    initialUntilMs: BigInt(generation.deadline_ms),
  };
  const at = (parsed.timestampMs + 999n) / 1000n;
  assert(at * 1000n <= deployment.initialUntilMs, "the original generation is live at replay time");
  const results = [];
  for (const hardfork of ["prague", "osaka"]) {
    const chain = await h.Chain.open(m.PROFILES.ethereum, { hardfork, allowBlocksWithSameTimestamp: true });
    try {
      assert.equal(BigInt(await chain.rpc("eth_chainId", [])), 1n);
      const { destination, address } = await h.deploy(chain, deployment, { at });
      assert.equal(address, m.create2Address(h.initCode(deployment)));
      assert.equal(await chain.rpc("eth_getCode", [address, "latest"]), h.expectedRuntime(h.immutableWords(deployment)));
      const forged = m.ethers.getBytes(qc);
      forged[80] ^= 1;
      await h.expectRevert(destination.tx("submitCheckpoints", [[[m.ethers.hexlify(forged), ...certificate.slice(1)]]], { at }), "BadSignature");
      const foreignHeader = m.ethers.getBytes(header);
      foreignHeader[16] ^= 1;
      const foreign = [...certificate];
      foreign[1] = m.ethers.hexlify(foreignHeader);
      await h.expectRevert(destination.tx("submitCheckpoints", [[foreign]], { at }), "BadHeader");
      assert.equal(await destination.view("checkpointHeader", [parsed.height]), m.ZERO32);
      const receipt = await destination.tx("submitCheckpoints", [[certificate]], { at });
      assert.equal(await destination.view("checkpointHeader", [parsed.height]), m.checkpointId(header));
      assert.equal((await destination.view("committeeState"))[3], parsed.height);
      // A duplicate carries no progress and is rejected without changing the stored result.
      await h.expectRevert(destination.tx("submitCheckpoints", [[certificate]], { at }), "NothingToDo");
      assert.equal(await destination.view("totalSupply"), 0n);
      assert.equal(await destination.view("opCount"), 0n);
      assert.equal(await destination.view("checkpointHeader", [parsed.height]), m.checkpointId(header));
      const expiredAt = deployment.initialUntilMs / 1000n + 1n;
      await h.expectRevert(destination.tx("submitCheckpoints", [[certificate]], { at: expiredAt }), "CommitteeNotAccepted");
      assert.equal(await destination.view("checkpointHeader", [parsed.height]), m.checkpointId(header));
      assert.equal(await destination.view("totalSupply"), 0n);
      assert.equal(await destination.view("opCount"), 0n);
      results.push({ hardfork, chain_id: 1, address, height: parsed.height.toString(), checkpoint: m.checkpointId(header), gas_used: BigInt(receipt.gasUsed).toString(), rejections: ["BadSignature", "BadHeader", "NothingToDo", "CommitteeNotAccepted"] });
    } finally {
      await chain.close();
    }
  }
  return { scope: "real-four-peer certificate to chain-1 CREATE2 checkpoint; route activation remains closed by Parliament", source_sha256: m.sha256(raw), source_chain_id: source.chain_id, results };
}

if (require.main === module) {
  assert.equal(process.argv.length, 3, "pass the actual four-peer public export path");
  replay(process.argv[2]).then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)).catch((error) => {
    process.stderr.write(`${error.stack}\n`);
    process.exitCode = 1;
  });
}

module.exports = { bytes, replay };
