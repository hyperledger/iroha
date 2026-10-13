// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Identifier helpers for asset definitions, conditional escrows, atomic
 * settlements and repo agreements.
 *
 * Each helper returns the exact JSON literal its native type accepts:
 * - `AssetDefinitionId`: canonical versioned, checksummed Base58 UUIDv4 address;
 * - `EscrowId`: canonical `hash:<HEX>#<CRC>` literal of an Iroha hash;
 * - `SettlementId` and `RepoAgreementId`: canonical Iroha `Name` text.
 */

import { blake3 } from "@noble/hashes/blake3";
import { Buffer } from "buffer";

import { blake2b256 } from "./blake2b.js";
import { canonicalizeDomainId } from "./domainId.js";
import { assertCanonicalIrohaName, canonicalHashLiteral } from "./instructionBuilderPrimitives.js";
import { assetDefinitionAddressFromUuidBytes } from "./norito.js";

const UTF8 = new TextEncoder();
const SETTLEMENT_ID_DOMAIN = "iroha-js:settlement-id:v1\0";
const REPO_AGREEMENT_ID_DOMAIN = "iroha-js:repo-agreement-id:v1\0";

function randomBytes(length) {
  const cryptoImpl = globalThis.crypto;
  if (!cryptoImpl || typeof cryptoImpl.getRandomValues !== "function") {
    throw new Error("a Web Crypto getRandomValues implementation is required");
  }
  return cryptoImpl.getRandomValues(new Uint8Array(length));
}

function seedBytes(seed, context) {
  if (typeof seed === "string") {
    if (seed.length === 0) {
      throw new TypeError(`${context} must be a non-empty string or byte array`);
    }
    return UTF8.encode(seed);
  }
  if (seed instanceof Uint8Array) {
    if (seed.length === 0) {
      throw new TypeError(`${context} must be a non-empty string or byte array`);
    }
    return Uint8Array.from(seed);
  }
  throw new TypeError(`${context} must be a non-empty string or byte array`);
}

function concatBytes(...parts) {
  return Uint8Array.from(Buffer.concat(parts.map((part) => Buffer.from(part))));
}

function uuidV4(bytes) {
  const uuid = Uint8Array.from(bytes.subarray(0, 16));
  uuid[6] = (uuid[6] & 0x0f) | 0x40;
  uuid[8] = (uuid[8] & 0x3f) | 0x80;
  return uuid;
}

/**
 * Generate a random canonical asset-definition id (UUIDv4 Base58 address).
 * @returns {string}
 */
export function generateAssetDefinitionId() {
  return assetDefinitionAddressFromUuidBytes(uuidV4(randomBytes(16)));
}

/**
 * Derive a deterministic canonical asset-definition id.
 *
 * The derivation is the native `AssetDefinitionId::derive_from_components`
 * rule: the first 16 bytes of BLAKE3(seed) with UUIDv4 version and variant
 * bits forced. `{ domain, name }` hashes the native component literal
 * `"<name>#<domain>.<dataspace>"`, so it equals the Rust derivation for the
 * same components; a string or byte seed is hashed exactly as given.
 * @param {string | Uint8Array | { domain: string, name: string }} seed
 * @returns {string}
 */
export function assetDefinitionIdFromSeed(seed) {
  let bytes;
  if (seed !== null && typeof seed === "object" && !(seed instanceof Uint8Array)) {
    const keys = Object.keys(seed).sort();
    if (keys.length !== 2 || keys[0] !== "domain" || keys[1] !== "name") {
      throw new TypeError("assetDefinitionIdFromSeed components must be exactly { domain, name }");
    }
    const name = assertCanonicalIrohaName(seed.name, "assetDefinitionIdFromSeed.name");
    const domain = canonicalizeDomainId(seed.domain, "assetDefinitionIdFromSeed.domain");
    bytes = UTF8.encode(`${name}#${domain}`);
  } else {
    bytes = seedBytes(seed, "assetDefinitionIdFromSeed seed");
  }
  return assetDefinitionAddressFromUuidBytes(uuidV4(blake3(bytes)));
}

/**
 * Create a canonical `EscrowId` hash literal.
 *
 * Without a seed the 32 bytes are random. With a seed the id equals the native
 * `EscrowId::new(Hash::new(seed))` (BLAKE2b-256 with the Iroha marker bit).
 * @param {string | Uint8Array} [seed]
 * @returns {string}
 */
export function newEscrowId(seed) {
  const bytes = seed === undefined
    ? randomBytes(32)
    : blake2b256(seedBytes(seed, "newEscrowId seed"));
  return canonicalHashLiteral(bytes);
}

function derivedName(prefix, domain, seed, context) {
  const entropy = seed === undefined
    ? randomBytes(16)
    : blake2b256(concatBytes(UTF8.encode(domain), seedBytes(seed, context))).subarray(0, 16);
  return `${prefix}${Buffer.from(entropy).toString("hex")}`;
}

/**
 * Create a canonical one-shot `SettlementId` name (`settlement-<32 hex>`).
 *
 * Without a seed the suffix is random; with a seed it is the first 16 bytes of
 * BLAKE2b-256 over a fixed domain separator and the seed.
 * @param {string | Uint8Array} [seed]
 * @returns {string}
 */
export function newSettlementId(seed) {
  return derivedName("settlement-", SETTLEMENT_ID_DOMAIN, seed, "newSettlementId seed");
}

/**
 * Create a canonical `RepoAgreementId` name (`repo-<32 hex>`).
 *
 * A repo's consent permissions use this same name as their `settlement_id`.
 * @param {string | Uint8Array} [seed]
 * @returns {string}
 */
export function newRepoAgreementId(seed) {
  return derivedName("repo-", REPO_AGREEMENT_ID_DOMAIN, seed, "newRepoAgreementId seed");
}
