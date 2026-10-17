import test from "node:test";
import assert from "node:assert/strict";

import { NetworkId } from "../src/networkId.js";
import {
  discoverNetworkIdentity,
  NetworkIdentityMismatchError,
} from "../src/networkIdentityDiscovery.js";
import { ToriiClient } from "../src/toriiClient.js";

const GENESIS = NetworkId.parse(
  "hash:5C3E66C94E079079FF4FC46F59810B9C4EC7B2646DD45CE937831C0FDCE20C9B#44D9",
);
const OTHER = NetworkId.fromBytes(new Uint8Array(32).fill(0xa5));

const json = (value, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });

function capabilities(networkId, networkPrefix = 369) {
  return {
    schema_version: 1,
    network_id: networkId.toString(),
    network_prefix: networkPrefix,
    allowed_signing: ["ed25519"],
    default_signing: "ed25519",
  };
}

function block(hash, overrides = {}) {
  return {
    hash,
    height: 1,
    created_at: "2026-10-01T00:00:00Z",
    prev_block_hash: null,
    transactions_hash: null,
    transactions_rejected: 0,
    transactions_total: 3,
    ...overrides,
  };
}

function client({ advertised, genesis, prefix }) {
  const paths = [];
  const torii = new ToriiClient("https://taira.example", {
    fetchImpl: async (url) => {
      const { pathname } = new URL(url);
      paths.push(pathname);
      if (pathname === "/v1/accounts/capabilities") return json(capabilities(advertised, prefix));
      if (pathname === "/v1/explorer/blocks/1") {
        return genesis === null ? json({ code: "not_found" }, 404) : json(genesis);
      }
      return json({ code: "not_found" }, 404);
    },
  });
  return { torii, paths };
}

test("discoverNetworkIdentity accepts agreeing capabilities and genesis block", async () => {
  const { torii, paths } = client({ advertised: GENESIS, genesis: block(GENESIS.toString()) });
  const identity = await discoverNetworkIdentity(torii);
  assert.ok(identity.networkId instanceof NetworkId);
  assert.equal(identity.networkId.toString(), GENESIS.toString());
  assert.equal(identity.networkPrefix, 369);
  assert.equal(
    identity.genesisHashHex,
    "5c3e66c94e079079ff4fc46f59810b9c4ec7b2646dd45ce937831c0fdce20c9b",
  );
  assert.ok(Object.isFrozen(identity));
  assert.deepEqual(paths, ["/v1/accounts/capabilities", "/v1/explorer/blocks/1"]);
  const wide = client({ advertised: GENESIS, genesis: block(GENESIS.toString()), prefix: 65_535 });
  assert.equal((await discoverNetworkIdentity(wide.torii)).networkPrefix, 65_535);
});

test("discoverNetworkIdentity fails closed when the sources disagree or are incomplete", async () => {
  const mismatch = client({ advertised: GENESIS, genesis: block(OTHER.toString()) });
  await assert.rejects(discoverNetworkIdentity(mismatch.torii), (error) => {
    assert.ok(error instanceof NetworkIdentityMismatchError);
    assert.match(error.message, /differs from the genesis block hash/u);
    assert.deepEqual(error.details, { capabilities: GENESIS.toString(), genesis: OTHER.toString() });
    return true;
  });
  const notGenesis = client({
    advertised: GENESIS,
    genesis: block(GENESIS.toString(), { prev_block_hash: OTHER.toString() }),
  });
  await assert.rejects(discoverNetworkIdentity(notGenesis.torii), NetworkIdentityMismatchError);
  const wrongHeight = client({ advertised: GENESIS, genesis: block(GENESIS.toString(), { height: 2 }) });
  await assert.rejects(discoverNetworkIdentity(wrongHeight.torii), NetworkIdentityMismatchError);
  const missing = client({ advertised: GENESIS, genesis: null });
  await assert.rejects(discoverNetworkIdentity(missing.torii), NetworkIdentityMismatchError);
  const malformed = client({ advertised: GENESIS, genesis: block("DEADBEEF") });
  await assert.rejects(discoverNetworkIdentity(malformed.torii), /hash/u);
  await assert.rejects(discoverNetworkIdentity({}), /ToriiClient/u);
});
