import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519";
import { AccountAddress, NetworkId, deriveMultisigProposalId } from "../src/index.js";
import * as browser from "../src/browser.js";

const network = NetworkId.parse("hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0");
const account = seed => AccountAddress.fromAccount({publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(seed))}).toI105(753);

test("native occurrence identity is stable for retries and distinct for nonce, network and account", () => {
  const nonce = "01".repeat(32), owner = account(7);
  const original = deriveMultisigProposalId(network, owner, nonce);
  assert.match(original, /^[0-9a-f]{64}$/);
  assert.equal(deriveMultisigProposalId(network, owner, nonce), original);
  assert.notEqual(deriveMultisigProposalId(network, owner, "02".repeat(32)), original);
  assert.notEqual(deriveMultisigProposalId(network, account(8), nonce), original);
  assert.notEqual(deriveMultisigProposalId(NetworkId.fromBytes(new Uint8Array(32).fill(3)), owner, nonce), original);
});

test("the native occurrence helper rejects malformed nonce and identity literals", () => {
  for (const nonce of ["00".repeat(32), "AB".repeat(32), "01".repeat(31), ` ${"01".repeat(32)}`]) {
    assert.throws(() => deriveMultisigProposalId(network, account(7), nonce), /nonce/i);
  }
  assert.throws(() => deriveMultisigProposalId(network, `${account(7)} `, "01".repeat(32)), /accountId/);
  assert.throws(() => deriveMultisigProposalId(network, "alice@wonderland", "01".repeat(32)));
  assert.throws(() => deriveMultisigProposalId(network.toString(), account(7), "01".repeat(32)), /NetworkId/);
});

test("portable browser exports transport admission and no native occurrence derivation", () => {
  assert.equal("deriveMultisigProposalId" in browser, false);
  assert.equal(typeof browser.requestNativeMultisigViaTransport, "function");
});
