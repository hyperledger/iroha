// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Endpoint network identity discovery from two independent public reads.
 *
 * Public deployments are reset periodically, and a reset changes the genesis
 * block and therefore the transaction-binding `NetworkId`. This reads
 * `GET /v1/accounts/capabilities` (`network_id`, `network_prefix`) and the
 * genesis block `GET /v1/explorer/blocks/1`, whose hash literal is the
 * `NetworkId`, and fails closed unless they agree. Pin storage (trust on first
 * use) belongs to the caller.
 */

import { Buffer } from "buffer";

import { NetworkId } from "./networkId.js";

/** Raised when the two public identity sources disagree or are incomplete. */
export class NetworkIdentityMismatchError extends Error {
  constructor(message, details = null) {
    super(message);
    this.name = "NetworkIdentityMismatchError";
    this.details = details;
  }
}

/**
 * Discover and cross-check an endpoint's network identity.
 * @param {import("./toriiClient.js").ToriiClient} torii
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<{ networkId: NetworkId, networkPrefix: number, genesisHashHex: string }>}
 */
export async function discoverNetworkIdentity(torii, options = {}) {
  if (!torii || typeof torii.getAccountCapabilities !== "function" || typeof torii.getBlock !== "function") {
    throw new TypeError("torii must be a ToriiClient");
  }
  const { signal } = options;
  const capabilities = await torii.getAccountCapabilities({ signal });
  // The capabilities reader already enforces the exact V1 shape and u16 prefix.
  const advertised = NetworkId.parse(capabilities.network_id);
  const networkPrefix = capabilities.network_prefix;
  const genesis = await torii.getBlock(1, { signal });
  if (genesis === null || genesis.height !== 1 || genesis.prevBlockHash !== null) {
    throw new NetworkIdentityMismatchError("the endpoint does not serve its genesis block at height 1");
  }
  if (genesis.hash !== advertised.toString()) {
    throw new NetworkIdentityMismatchError(
      "account capabilities network_id differs from the genesis block hash",
      { capabilities: advertised.toString(), genesis: genesis.hash },
    );
  }
  return Object.freeze({
    networkId: advertised,
    networkPrefix,
    genesisHashHex: Buffer.from(advertised.toBytes()).toString("hex"),
  });
}
