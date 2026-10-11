import { requireNetworkPrefix } from "./networkPrefix.js";
import { parseCanonicalContractAddress } from "./contractAddress.js";
import {
  _createCryptoApi,
  normalizeCryptoAlgorithm,
} from "./crypto.js";
import { ToriiClient } from "./toriiClient.js";
import {
  _createNoritoInstructionApi,
  exactFinalizeElectionTallyJson,
  exactPublicPlainBallotJson,
  exactRegisterDataspaceAssetDefinitionJson,
} from "./norito.js";
import { networkIdBytes } from "./networkId.js";
import { parseStrictLosslessJson } from "./strictLosslessJson.js";
import {
  defaultNativeRuntime,
  resolveNativeRuntimeBinding,
} from "./nativeRuntime.js";
import {
  buildBurnAssetInstruction,
  buildMintAssetInstruction,
  buildMintTriggerRepetitionsInstruction,
  buildBurnTriggerRepetitionsInstruction,
  buildTransferAssetInstruction,
  buildTransferAssetDefinitionInstruction,
  buildTransferDomainInstruction,
  buildTransferNftInstruction,
  buildRegisterRwaInstruction,
  buildTransferRwaInstruction,
  buildMergeRwasInstruction,
  buildRedeemRwaInstruction,
  buildFreezeRwaInstruction,
  buildUnfreezeRwaInstruction,
  buildHoldRwaInstruction,
  buildReleaseRwaInstruction,
  buildForceTransferRwaInstruction,
  buildSetRwaControlsInstruction,
  buildSetRwaKeyValueInstruction,
  buildRemoveRwaKeyValueInstruction,
  buildRegisterDomainInstruction,
  buildRegisterAccountInstruction,
  buildRegisterMultisigInstruction,
  buildCreateKaigiInstruction,
  buildJoinKaigiInstruction,
  buildLeaveKaigiInstruction,
  buildEndKaigiInstruction,
  buildRecordKaigiUsageInstruction,
  buildSetKaigiRelayManifestInstruction,
  buildRegisterKaigiRelayInstruction,
  buildUnregisterKaigiRelayInstruction,
  buildReportKaigiRelayHealthInstruction,
  buildRegisterSmartContractCodeInstruction,
  buildRegisterSmartContractBytesInstruction,
  buildRemoveSmartContractBytesInstruction,
  buildProposeDeployContractInstruction,
  buildCastZkBallotInstruction,
  buildCastPlainBallotInstruction,
  buildUpdatePlainConvictionInstruction,
  buildRegisterZkAssetInstruction,
  buildScheduleConfidentialPolicyTransitionInstruction,
  buildCancelConfidentialPolicyTransitionInstruction,
  buildCreateElectionInstruction,
  buildSubmitBallotInstruction,
  buildFinalizeElectionInstruction,
  normalizeAccountId,
} from "./instructionBuilders.js";
import { createRegisterAssetDefinitionInstructionBuilder } from "./assetDefinitionRegistration.js";

function normalizeAuthority(authority) {
  const raw = String(authority ?? "");
  if (raw.length === 0) {
    return normalizeAccountId(authority, "authority");
  }
  if (raw.trim() !== raw) {
    throw new TypeError("authority must not contain surrounding whitespace");
  }
  return normalizeAccountId(raw, "authority");
}

const TRANSACTION_CONTEXTS = new WeakSet();
function createTransactionContext(nativeRuntime) {
  const context = Object.freeze({
    nativeRuntime,
    crypto: _createCryptoApi(nativeRuntime),
    norito: _createNoritoInstructionApi(nativeRuntime),
  });
  TRANSACTION_CONTEXTS.add(context);
  return context;
}

const DEFAULT_TRANSACTION_CONTEXT = /* @__PURE__ */ createTransactionContext(
  defaultNativeRuntime,
);

function transactionContext(receiver) {
  return TRANSACTION_CONTEXTS.has(receiver)
    ? receiver
    : DEFAULT_TRANSACTION_CONTEXT;
}

function resolveNativeBinding(receiver) {
  return resolveNativeRuntimeBinding(
    transactionContext(receiver).nativeRuntime,
  );
}

const RETIRED_TRANSACTION_DOMAIN_FIELDS = Object.freeze([
  "chain",
  "chainId",
  "chain_id",
]);

const RETIRED_TRANSACTION_FINALITY_FIELDS = Object.freeze([
  "allowShortHash",
  "endpoints",
  "failureStatuses",
  "scope",
  "statusEndpoints",
  "successStatuses",
  "terminalStatuses",
  "transactionStatusScope",
]);

function rejectRetiredTransactionFinalityFields(options, context) {
  for (const field of RETIRED_TRANSACTION_FINALITY_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(options, field)) {
      throw new TypeError(
        `${context}.${field} is unsupported; transaction finality is fixed to global state-resolved Applied`,
      );
    }
  }
}

function transactionNetworkIdBytes(input, context) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError(`${context} must be an object`);
  }
  for (const field of RETIRED_TRANSACTION_DOMAIN_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(input, field)) {
      throw new TypeError(
        `${context}.${field} is unsupported; provide the nominal networkId field`,
      );
    }
  }
  return Buffer.from(networkIdBytes(input.networkId, `${context}.networkId`));
}

function composeAssetHoldingIdFromDefinitionAndAccount(
  assetDefinitionId,
  accountId,
  context,
  dataspaceId = null,
) {
  const definition = normalizeTransactionAssetDefinitionId(
    assetDefinitionId,
    `${context}.assetDefinitionId`,
  );
  const normalizedAccountId = normalizeAccountId(
    accountId,
    `${context}.accountId`,
  );
  const scope = dataspaceId === null ? "" : `#dataspace:${dataspaceId}`;
  return `${definition}#${normalizedAccountId}${scope}`;
}

function normalizeTransactionAssetDefinitionId(assetDefinitionId, context) {
  const rawDefinition = String(assetDefinitionId ?? "");
  const definition = rawDefinition.trim();
  if (!definition) {
    throw new TypeError(`${context} must be a non-empty string`);
  }
  if (definition !== rawDefinition) {
    throw new TypeError(`${context} must not contain surrounding whitespace`);
  }
  if (
    /\s/.test(definition) ||
    definition.includes("%") ||
    definition.includes("/") ||
    definition.includes("?") ||
    definition.includes(":")
  ) {
    throw new TypeError(
      `${context} must be a canonical unprefixed Base58 asset definition id`,
    );
  }
  return definition;
}

function serializeInstructionPayloads(instructions, context) {
  if (!Array.isArray(instructions) || instructions.length === 0) {
    throw new Error(`${context ?? "instructions"} must be a non-empty array`);
  }
  return instructions.map((instruction, index) => {
    if (typeof instruction === "string") {
      return instruction;
    }
    if (instruction && typeof instruction === "object") {
      return exactFinalizeElectionTallyJson(instruction)
        ?? exactPublicPlainBallotJson(instruction)
        ?? exactRegisterDataspaceAssetDefinitionJson(instruction)
        ?? JSON.stringify(instruction);
    }
    throw new TypeError(
      `${context ?? "instructions"}[${index}] must be an object or JSON string`,
    );
  });
}

// Visit only Native instruction positions, never similarly named metadata keys.
function directDataspaceInstructionSlots(payload) {
  const executable = payload?.instructions;
  const slots = [];
  const add = (parent, key) => {
    const instruction = parent?.[key];
    if (instruction && typeof instruction === "object" &&
        Object.prototype.hasOwnProperty.call(instruction, "RegisterDataspaceAssetDefinition")) {
      slots.push({ parent, key, instruction });
    }
  };
  if (Array.isArray(executable?.Instructions)) {
    executable.Instructions.forEach((_instruction, index) => add(executable.Instructions, index));
  }
  if (Array.isArray(executable?.Batch)) {
    executable.Batch.forEach((entry) => add(entry, "Instruction"));
  }
  return slots;
}

function parseTransactionPayloadJson(json, signed = false) {
  const parsed = JSON.parse(json);
  const slots = directDataspaceInstructionSlots(signed ? parsed?.payload : parsed);
  if (slots.length === 0) return parsed;
  // Native owns this schema. Read its original numeric tokens, then replace
  // only direct instruction views; all other public projections stay unchanged.
  const exact = parseStrictLosslessJson(`{"transaction":${json}}`, "Native transaction JSON", {
    floatingPointPaths: [["transaction"]],
  }).transaction;
  const exactSlots = directDataspaceInstructionSlots(signed ? exact?.payload : exact);
  slots.forEach(({ parent, key }, index) => {
    const instruction = exactSlots[index].instruction;
    exactRegisterDataspaceAssetDefinitionJson(instruction);
    parent[key] = instruction;
  });
  return parsed;
}

function serializeTransactionPayloadJson(payload) {
  const slots = directDataspaceInstructionSlots(payload);
  if (slots.length === 0) return JSON.stringify(payload);
  const replacements = new Map();
  const exact = slots.map(({ parent, key, instruction }, index) => {
    const fields = replacements.get(parent) ?? new Map();
    fields.set(String(key), `__iroha-direct-dataspace-instruction-${index}__`);
    replacements.set(parent, fields);
    return exactRegisterDataspaceAssetDefinitionJson(instruction);
  });
  const seen = new Uint8Array(slots.length);
  const json = JSON.stringify(payload, function (key, value) {
    return replacements.get(this)?.get(key) ?? value;
  }).replace(/"__iroha-direct-dataspace-instruction-(\d+)__"/gu, (_token, indexText) => {
    const index = Number(indexText);
    if (!Number.isSafeInteger(index) || index >= exact.length || seen[index] !== 0) {
      throw new TypeError("direct-dataspace instruction exact-number marker collision");
    }
    seen[index] = 1;
    return exact[index];
  });
  if (seen.some((count) => count !== 1)) {
    throw new TypeError("direct-dataspace instruction exact-number marker collision");
  }
  return json;
}

const MAX_CONTRACT_ARGUMENT_RECORD_BYTES = 1024 * 1024;

function normalizeExecutableBatchHash(value, context) {
  let hash;
  if (typeof value === "string") {
    const literal = value.startsWith("0x") ? value.slice(2) : value;
    if (!/^[0-9a-fA-F]{64}$/u.test(literal)) {
      throw new TypeError(`${context} must be exactly 32 hexadecimal bytes`);
    }
    hash = Buffer.from(literal, "hex");
  } else {
    hash = toBuffer(value, context);
  }
  if (hash.length !== 32) {
    throw new TypeError(`${context} must be exactly 32 bytes`);
  }
  if ((hash[31] & 1) === 0) {
    throw new TypeError(`${context} must carry the canonical Iroha hash marker bit`);
  }
  return hash;
}

function serializeExecutableBatchEntries(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new TypeError("entries must be a non-empty array");
  }
  let containsContractCall = false;
  const serialized = entries.map((value, index) => {
    const entry = normalizePlainObject(value, `entries[${index}]`);
    if (entry.kind === "instruction") {
      if (entry.instruction === undefined) {
        throw new TypeError(`entries[${index}].instruction is required`);
      }
      const instruction = entry.instruction;
      if (
        typeof instruction !== "string" &&
        (!instruction || typeof instruction !== "object" || Array.isArray(instruction))
      ) {
        throw new TypeError(
          `entries[${index}].instruction must be an object or JSON string`,
        );
      }
      const instructionJson = typeof instruction === "string"
        ? JSON.stringify(instruction)
        : serializeInstructionPayloads([instruction], `entries[${index}].instruction`)[0];
      return `{"kind":"instruction","instruction":${instructionJson}}`;
    }
    if (entry.kind !== "contractCall") {
      throw new TypeError(
        `entries[${index}].kind must be instruction or contractCall`,
      );
    }
    containsContractCall = true;
    const contractAddress = parseCanonicalContractAddress(
      entry.contractAddress,
      `entries[${index}].contractAddress`,
    ).literal;
    if (
      typeof entry.entrypoint !== "string" ||
      entry.entrypoint.length === 0 ||
      entry.entrypoint.trim() !== entry.entrypoint
    ) {
      throw new TypeError(
        `entries[${index}].entrypoint must be a non-empty exact string`,
      );
    }
    const expectedCodeHash = normalizeExecutableBatchHash(
      entry.expectedCodeHash,
      `entries[${index}].expectedCodeHash`,
    );
    const argumentsBytes =
      entry.arguments === undefined || entry.arguments === null
        ? null
        : toBuffer(entry.arguments, `entries[${index}].arguments`);
    if (
      argumentsBytes !== null &&
      argumentsBytes.length > MAX_CONTRACT_ARGUMENT_RECORD_BYTES
    ) {
      throw new RangeError(
        `entries[${index}].arguments exceeds ${MAX_CONTRACT_ARGUMENT_RECORD_BYTES} bytes`,
      );
    }
    return JSON.stringify({
      kind: "contractCall",
      contractAddress,
      expectedCodeHash: expectedCodeHash.toString("hex").toUpperCase(),
      entrypoint: entry.entrypoint,
      arguments: argumentsBytes === null ? null : Array.from(argumentsBytes),
    });
  });
  return { serialized, containsContractCall };
}

function requireExecutableBatchGasLimit(feePayment, containsContractCall) {
  const feePaymentJson = feePaymentIntentToNoritoJson(feePayment);
  if (
    containsContractCall &&
    JSON.parse(feePaymentJson).value.gas_limit === null
  ) {
    throw new TypeError(
      "feePayment.gasLimit is required when entries contain a contract call",
    );
  }
  return feePaymentJson;
}

function normalizeMetadataPayload(metadata, context) {
  if (metadata === null || metadata === undefined) {
    return null;
  }
  if (typeof metadata === "string") {
    return metadata;
  }
  if (typeof metadata === "object" && !Array.isArray(metadata)) {
    return JSON.stringify(metadata);
  }
  throw new TypeError(
    `${context} must be an object or JSON string when provided`,
  );
}

function canonicalFeeUnsigned(value, context, { nonZero = false } = {}) {
  let literal;
  if (typeof value === "bigint") {
    literal = value.toString(10);
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError(`${context} must be a safe integer, bigint, or decimal string`);
    }
    literal = String(value);
  } else if (typeof value === "string" && /^(?:0|[1-9]\d*)$/u.test(value)) {
    literal = value;
  } else {
    throw new TypeError(`${context} must be a canonical unsigned integer`);
  }
  const parsed = BigInt(literal);
  if (parsed > 0xffff_ffff_ffff_ffffn || (nonZero && parsed === 0n)) {
    throw new RangeError(`${context} is outside its canonical u64 range`);
  }
  return literal;
}

function canonicalFeeQuantity(value, context) {
  if (typeof value === "number") {
    throw new TypeError(`${context} must not use a JavaScript number`);
  }
  let literal;
  if (typeof value === "string" || typeof value === "bigint") {
    literal = String(value);
  } else if (value && typeof value.toString === "function") {
    literal = value.toString();
  } else {
    throw new TypeError(`${context} must be a canonical positive quantity`);
  }
  if (!/^(?:0|[1-9]\d*)(?:\.\d*[1-9])?$/u.test(literal) || literal === "0") {
    throw new TypeError(`${context} must be a canonical positive quantity`);
  }
  return literal;
}

/**
 * Convert the ergonomic JavaScript fee-payment shape into the exact Norito
 * JSON representation accepted by the native signer.
 */
export function feePaymentIntentToNoritoJson(feePayment) {
  const input = normalizePlainObject(feePayment, "feePayment");
  if (input.payer !== "authority" && input.payer !== "sponsor") {
    throw new TypeError("feePayment.payer must be authority or sponsor");
  }
  if (!Array.isArray(input.chargeLimits)) {
    throw new TypeError("feePayment.chargeLimits must be an array");
  }
  let previousKind = -1;
  const chargeLimits = input.chargeLimits.map((value, index) => {
    const limit = normalizePlainObject(value, `feePayment.chargeLimits[${index}]`);
    const kind = limit.kind === "nexus" ? 0 : limit.kind === "pipelineGas" ? 1 : -1;
    if (kind < 0) {
      throw new TypeError(
        `feePayment.chargeLimits[${index}].kind must be nexus or pipelineGas`,
      );
    }
    if (kind <= previousKind) {
      throw new TypeError(
        "feePayment.chargeLimits must be unique and ordered nexus before pipelineGas",
      );
    }
    previousKind = kind;
    const assetDefinitionId = normalizeTransactionAssetDefinitionId(
      limit.assetDefinitionId,
      `feePayment.chargeLimits[${index}].assetDefinitionId`,
    );
    return {
      kind: { kind: kind === 0 ? "nexus" : "pipeline_gas", value: null },
      asset_definition_id: assetDefinitionId,
      max_amount: canonicalFeeQuantity(
        limit.maxAmount,
        `feePayment.chargeLimits[${index}].maxAmount`,
      ),
    };
  });
  const gasLimit =
    input.gasLimit === undefined || input.gasLimit === null
      ? null
      : canonicalFeeUnsigned(input.gasLimit, "feePayment.gasLimit", {
          nonZero: true,
        });
  const common = `"charge_limits":${JSON.stringify(chargeLimits)},"gas_limit":${gasLimit ?? "null"}`;
  if (input.payer === "authority") {
    if (input.programId !== undefined || input.programRevision !== undefined) {
      throw new TypeError(
        "authority feePayment must not include programId or programRevision",
      );
    }
    return `{"payer":"authority","value":{${common}}}`;
  }
  if (typeof input.programId !== "string" || input.programId.trim() !== input.programId) {
    throw new TypeError("feePayment.programId must be an exact sponsor/program string");
  }
  const slash = input.programId.indexOf("/");
  if (slash <= 0 || slash === input.programId.length - 1) {
    throw new TypeError("feePayment.programId must use sponsor/program");
  }
  const sponsor = input.programId.slice(0, slash);
  const name = input.programId.slice(slash + 1);
  const revision = canonicalFeeUnsigned(
    input.programRevision,
    "feePayment.programRevision",
    { nonZero: true },
  );
  return `{"payer":"sponsor","value":{"program_id":{"sponsor":${JSON.stringify(
    sponsor,
  )},"name":${JSON.stringify(name)}},"program_revision":${revision},${common}}}`;
}

function normalizeJsonObjectPayload(value, context) {
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      throw new TypeError(`${context} must not be an empty JSON string`);
    }
    return trimmed;
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return JSON.stringify(value);
  }
  throw new TypeError(`${context} must be an object or JSON string`);
}

function normalizePlainObject(value, context) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value;
  }
  throw new TypeError(`${context} must be a non-null object`);
}

function normalizeOptionalPositiveInteger(value, context) {
  if (value === null || value === undefined) {
    return null;
  }
  return ToriiClient._normalizeUnsignedInteger(value, context, {
    allowZero: false,
  });
}

function normalizePrivateKeyAlgorithm(
  value,
  context = "privateKeyAlgorithm",
  defaultAlgorithm = null,
) {
  if (value === undefined) {
    return defaultAlgorithm;
  }
  if (value === null || typeof value !== "string") {
    throw new TypeError(`${context} must be a supported crypto algorithm string`);
  }
  if (value.trim() !== value) {
    throw new TypeError(`${context} must not contain surrounding whitespace`);
  }
  return normalizeCryptoAlgorithm(value);
}

/**
 * Compute the canonical transaction hash (blake2b-256) for an exact canonical
 * VersionedSignedTransaction V1 wire.
 * @param {ArrayBufferView | ArrayBuffer | Buffer} signedTransaction
 * @param {{ encoding?: BufferEncoding }} [options]
 * @returns {string | Buffer} Hex string by default, Buffer when `encoding` is `"buffer"`.
 */
export function hashSignedTransaction(signedTransaction, options = {}) {
  const native = resolveNativeBinding(this);
  if (!native || typeof native.hashSignedTransaction !== "function") {
    throw new Error("native binding 'hashSignedTransaction' is unavailable");
  }
  const buffer = toBuffer(signedTransaction);
  const hashBuffer = Buffer.from(native.hashSignedTransaction(buffer));
  if (options.encoding === "buffer") {
    return hashBuffer;
  }
  const encoding = options.encoding ?? "hex";
  return hashBuffer.toString(encoding);
}

/**
 * Compute the detached-signature preimage used by Torii for an exact canonical
 * VersionedSignedTransaction V1 wire (`HashOf::new(tx.payload())`).
 * @param {ArrayBufferView | ArrayBuffer | Buffer} signedTransaction
 * @param {{ encoding?: BufferEncoding }} [options]
 * @returns {string | Buffer} Hex string by default, Buffer when `encoding` is `"buffer"`.
 */
export function hashSignedTransactionPayload(signedTransaction, options = {}) {
  const native = resolveNativeBinding(this);
  if (!native || typeof native.hashSignedTransactionPayload !== "function") {
    throw new Error(
      "native binding 'hashSignedTransactionPayload' is unavailable",
    );
  }
  const buffer = toBuffer(signedTransaction);
  const hashBuffer = Buffer.from(native.hashSignedTransactionPayload(buffer));
  if (options.encoding === "buffer") {
    return hashBuffer;
  }
  const encoding = options.encoding ?? "hex";
  return hashBuffer.toString(encoding);
}

/**
 * Decode an exact canonical VersionedSignedTransaction V1 wire into JSON.
 * This is intended for wallet policy checks before signing an untrusted
 * transaction scaffold.
 * @param {ArrayBufferView | ArrayBuffer | Buffer} signedTransaction
 * @param {number} networkPrefix Canonical I105 network prefix.
 * @returns {Record<string, unknown>}
 */
export function decodeSignedTransaction(signedTransaction, networkPrefix) {
  requireNetworkPrefix(networkPrefix);
  const native = resolveNativeBinding(this);
  if (!native || typeof native.decodeSignedTransactionJson !== "function") {
    throw new Error(
      "native binding 'decodeSignedTransactionJson' is unavailable",
    );
  }
  const decoded = parseTransactionPayloadJson(
    native.decodeSignedTransactionJson(toBuffer(signedTransaction), networkPrefix),
    true,
  );
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new Error("decoded signed transaction must be an object");
  }
  return decoded;
}

/**
 * Encode an entrypoint payload with the exact Kotodama ABI schema into the
 * canonical argument bytes that must be present in a signed contract call.
 * @param {Record<string, unknown>} argumentSchema
 * @param {Record<string, unknown>} payload
 * @param {number} networkPrefix Canonical I105 network prefix.
 * @returns {Buffer}
 */
export function encodeContractArgumentRecord(argumentSchema, payload, networkPrefix) {
  requireNetworkPrefix(networkPrefix);
  const native = resolveNativeBinding(this);
  if (!native || typeof native.encodeContractArgumentRecordJson !== "function") {
    throw new Error(
      "native binding 'encodeContractArgumentRecordJson' is unavailable",
    );
  }
  let schemaJson;
  let payloadJson;
  try {
    schemaJson = JSON.stringify(argumentSchema);
    payloadJson = JSON.stringify(payload);
  } catch (error) {
    throw new TypeError(`contract argument input is not JSON serializable: ${error}`);
  }
  if (typeof schemaJson !== "string" || typeof payloadJson !== "string") {
    throw new TypeError("contract argument schema and payload must be JSON values");
  }
  return Buffer.from(
    native.encodeContractArgumentRecordJson(schemaJson, payloadJson, networkPrefix),
  );
}

/**
 * Compute the canonical proposal identity for an authorized instruction batch
 * (`HashOf::new(&Vec<InstructionBox>)`). This is the value Torii exposes as
 * both `instructions_hash` and `proposal_id` for multisig proposals.
 * @param {Array<object | string>} instructions
 * @param {number} networkPrefix Canonical I105 network prefix.
 * @param {{ encoding?: BufferEncoding }} [options]
 * @returns {string | Buffer} Hex string by default, Buffer when `encoding` is `"buffer"`.
 */
export function hashInstructionBatch(instructions, networkPrefix, options = {}) {
  requireNetworkPrefix(networkPrefix);
  const native = resolveNativeBinding(this);
  if (!native || typeof native.hashInstructionBatch !== "function") {
    throw new Error("native binding 'hashInstructionBatch' is unavailable");
  }
  const normalizedInstructions = serializeInstructionPayloads(
    instructions,
    "instructions",
  );
  const hashBuffer = Buffer.from(
    native.hashInstructionBatch(normalizedInstructions, networkPrefix),
  );
  if (options.encoding === "buffer") {
    return hashBuffer;
  }
  const encoding = options.encoding ?? "hex";
  return hashBuffer.toString(encoding);
}

/**
 * Re-sign an exact canonical VersionedSignedTransaction V1 wire for one exact
 * NetworkId with the provided Ed25519 private key. Foreign-network and genesis
 * payloads are rejected by the native boundary before signing.
 * @param {import("./networkId.js").NetworkId} networkId
 * @param {ArrayBufferView | ArrayBuffer | Buffer} signedTransaction
 * @param {ArrayBufferView | ArrayBuffer | Buffer} privateKey 32- or 64-byte Ed25519 key.
 * @returns {Buffer}
 */
export function resignSignedTransaction(networkId, signedTransaction, privateKey) {
  const native = resolveNativeBinding(this);
  if (!native || typeof native.signTransaction !== "function") {
    throw new Error("native binding 'signTransaction' is unavailable");
  }
  const expectedNetworkId = Buffer.from(
    networkIdBytes(networkId, "networkId"),
  );
  const txBuffer = toBuffer(signedTransaction);
  const keyBuffer = toBuffer(privateKey);
  if (keyBuffer.byteLength !== 32 && keyBuffer.byteLength !== 64) {
    throw new Error("private key must be a 32- or 64-byte Ed25519 key");
  }
  return Buffer.from(
    native.signTransaction(expectedNetworkId, txBuffer, keyBuffer),
  );
}

/**
 * Build and sign a RegisterDomain transaction via the native helper.
 * @param {{
 *   networkId: import("./networkId.js").NetworkId,
 *   authority: string,
 *   domainId: string,
 *   feePayment: object,
 *   metadata?: object | string | null,
 *   creationTimeMs?: number,
 *   ttlMs?: number,
 *   nonce?: number,
 *   privateKey: ArrayBufferView | ArrayBuffer | Buffer,
 *   privateKeyAlgorithm?: import("../index.js").CryptoAlgorithm
 * }} input
 * @returns {{signedTransaction: Buffer, hash: Buffer}}
 */
export function buildRegisterDomainTransaction(input) {
  const networkId = transactionNetworkIdBytes(input, "input");
  const native = resolveNativeBinding(this);
  if (!native || typeof native.buildRegisterDomainTransaction !== "function") {
    throw new Error(
      "native binding 'build_register_domain_transaction' is unavailable",
    );
  }
  const {
    authority,
    domainId,
    feePayment,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;

  const canonicalAuthority = normalizeAuthority(authority);

  const metadataPayload =
    metadata === null || metadata === undefined
      ? null
      : typeof metadata === "string"
        ? metadata
        : JSON.stringify(metadata);

  const result = native.buildRegisterDomainTransaction(
    networkId,
    canonicalAuthority,
    domainId,
    feePaymentIntentToNoritoJson(feePayment),
    metadataPayload,
    creationTimeMs,
    ttlMs,
    nonce,
    toBuffer(privateKey),
    normalizePrivateKeyAlgorithm(privateKeyAlgorithm),
  );
  const signed =
    result?.signed_transaction ?? result?.signedTransaction ?? null;
  const hashBytes = result?.hash ?? result?.hashBytes ?? null;
  if (!signed || !hashBytes) {
    throw new Error(
      "native binding 'build_register_domain_transaction' returned missing fields",
    );
  }
  return {
    signedTransaction: Buffer.from(signed),
    hash: Buffer.from(hashBytes),
  };
}

/**
 * Build and sign a transaction from arbitrary instruction payloads.
 * @param {{
 *   networkId: import("./networkId.js").NetworkId,
 *   authority: string,
 *   instructions: Array<object | string>,
 *   feePayment: object,
 *   metadata?: object | string | null,
 *   creationTimeMs?: number,
 *   ttlMs?: number,
 *   nonce?: number,
 *   privateKey: ArrayBufferView | ArrayBuffer | Buffer,
 *   privateKeyAlgorithm?: import("../index.js").CryptoAlgorithm
 * }} input
 * @returns {{signedTransaction: Buffer, hash: Buffer}}
 */
export function buildTransaction(input) {
  const networkId = transactionNetworkIdBytes(input, "input");
  const native = resolveNativeBinding(this);
  if (!native || typeof native.buildTransaction !== "function") {
    throw new Error("native binding 'build_transaction' is unavailable");
  }

  const {
    authority,
    instructions,
    feePayment,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;

  const normalizedInstructions = serializeInstructionPayloads(
    instructions,
    "instructions",
  );

  const metadataPayload = normalizeMetadataPayload(
    metadata,
    "transaction metadata",
  );

  const canonicalAuthority = normalizeAuthority(authority);

  const result = native.buildTransaction(
    networkId,
    canonicalAuthority,
    normalizedInstructions,
    feePaymentIntentToNoritoJson(feePayment),
    metadataPayload,
    creationTimeMs,
    ttlMs,
    nonce,
    toBuffer(privateKey),
    normalizePrivateKeyAlgorithm(privateKeyAlgorithm),
  );

  const signed =
    result?.signed_transaction ?? result?.signedTransaction ?? null;
  const hashBytes = result?.hash ?? result?.hashBytes ?? null;
  if (!signed || !hashBytes) {
    throw new Error(
      "native binding 'build_transaction' returned missing fields",
    );
  }

  return {
    signedTransaction: Buffer.from(signed),
    hash: Buffer.from(hashBytes),
  };
}

/**
 * Build and sign one ordered, atomic mix of native instructions and deployed
 * contract calls. Instruction-only callers should keep using
 * {@link buildTransaction} for the canonical native-instruction executable.
 *
 * @param {object} input
 * @returns {{signedTransaction: Buffer, hash: Buffer}}
 */
export function buildExecutableBatchTransaction(input) {
  const networkId = transactionNetworkIdBytes(input, "input");
  const native = resolveNativeBinding(this);
  if (
    !native ||
    typeof native.buildExecutableBatchTransaction !== "function"
  ) {
    throw new Error(
      "native binding 'build_executable_batch_transaction' is unavailable",
    );
  }
  const {
    authority,
    entries,
    feePayment,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const { serialized, containsContractCall } =
    serializeExecutableBatchEntries(entries);
  const feePaymentJson = requireExecutableBatchGasLimit(
    feePayment,
    containsContractCall,
  );
  const result = native.buildExecutableBatchTransaction(
    networkId,
    normalizeAuthority(authority),
    serialized,
    feePaymentJson,
    normalizeMetadataPayload(metadata, "transaction metadata"),
    creationTimeMs,
    ttlMs,
    nonce,
    toBuffer(privateKey, "privateKey"),
    normalizePrivateKeyAlgorithm(privateKeyAlgorithm),
  );
  const signed =
    result?.signed_transaction ?? result?.signedTransaction ?? null;
  const hashBytes = result?.hash ?? result?.hashBytes ?? null;
  if (!signed || !hashBytes) {
    throw new Error(
      "native binding 'build_executable_batch_transaction' returned missing fields",
    );
  }
  return {
    signedTransaction: Buffer.from(signed),
    hash: Buffer.from(hashBytes),
  };
}

/**
 * Build, but do not sign, the exact payload submitted to `/v1/fees/quote`.
 * Only the returned payload's `fee_payment` field may be replaced before
 * calling {@link signQuotedTransactionPayload}.
 *
 * @param {{
 *   networkId: import("./networkId.js").NetworkId,
 *   authority: string,
 *   instructions: Array<object | string>,
 *   feePayment: object,
 *   metadata?: object | string | null,
 *   creationTimeMs?: number,
 *   ttlMs?: number,
 *   nonce?: number
 * }} input
 * @returns {{payload: object, payloadJson: string, payloadBytes: Buffer, payloadHash: Buffer}}
 */
export function buildTransactionPayload(input) {
  const networkId = transactionNetworkIdBytes(input, "input");
  const native = resolveNativeBinding(this);
  if (!native || typeof native.buildTransactionPayload !== "function") {
    throw new Error("native binding 'build_transaction_payload' is unavailable");
  }
  const {
    authority,
    instructions,
    feePayment,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
  } = input;
  const result = native.buildTransactionPayload(
    networkId,
    normalizeAuthority(authority),
    serializeInstructionPayloads(instructions, "instructions"),
    feePaymentIntentToNoritoJson(feePayment),
    normalizeMetadataPayload(metadata, "transaction metadata"),
    creationTimeMs,
    ttlMs,
    nonce,
  );
  const payloadJson = result?.payload_json ?? result?.payloadJson ?? null;
  const payloadBytes = result?.payload_bytes ?? result?.payloadBytes ?? null;
  const payloadHash = result?.payload_hash ?? result?.payloadHash ?? null;
  if (typeof payloadJson !== "string" || !payloadBytes || !payloadHash) {
    throw new Error(
      "native binding 'build_transaction_payload' returned missing fields",
    );
  }
  return {
    payload: parseTransactionPayloadJson(payloadJson),
    payloadJson,
    payloadBytes: Buffer.from(payloadBytes),
    payloadHash: Buffer.from(payloadHash),
  };
}

/** Build an exact unsigned ordered mixed executable-batch payload. */
export function buildExecutableBatchTransactionPayload(input) {
  const networkId = transactionNetworkIdBytes(input, "input");
  const native = resolveNativeBinding(this);
  if (
    !native ||
    typeof native.buildExecutableBatchTransactionPayload !== "function"
  ) {
    throw new Error(
      "native binding 'build_executable_batch_transaction_payload' is unavailable",
    );
  }
  const {
    authority,
    entries,
    feePayment,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
  } = input;
  const { serialized, containsContractCall } =
    serializeExecutableBatchEntries(entries);
  const result = native.buildExecutableBatchTransactionPayload(
    networkId,
    normalizeAuthority(authority),
    serialized,
    requireExecutableBatchGasLimit(feePayment, containsContractCall),
    normalizeMetadataPayload(metadata, "transaction metadata"),
    creationTimeMs,
    ttlMs,
    nonce,
  );
  const payloadJson = result?.payload_json ?? result?.payloadJson ?? null;
  const payloadBytes = result?.payload_bytes ?? result?.payloadBytes ?? null;
  const payloadHash = result?.payload_hash ?? result?.payloadHash ?? null;
  if (typeof payloadJson !== "string" || !payloadBytes || !payloadHash) {
    throw new Error(
      "native binding 'build_executable_batch_transaction_payload' returned missing fields",
    );
  }
  return {
    payload: parseTransactionPayloadJson(payloadJson),
    payloadJson,
    payloadBytes: Buffer.from(payloadBytes),
    payloadHash: Buffer.from(payloadHash),
  };
}

/**
 * Replace only the fee intent in an exact unsigned draft and sign the result.
 * The native boundary rejects any quote that changes the selected authority
 * payer or exact sponsor program and revision.
 *
 * @param {{
 *   networkId: import("./networkId.js").NetworkId,
 *   payload: object | {payload?: object, payloadJson?: string},
 *   quotedFeePayment: object | string,
 *   privateKey: ArrayBufferView | ArrayBuffer | Buffer,
 *   privateKeyAlgorithm?: import("../index.js").CryptoAlgorithm
 * }} input
 * @returns {{signedTransaction: Buffer, hash: Buffer}}
 */
export function signQuotedTransactionPayload(input) {
  const networkId = transactionNetworkIdBytes(input, "input");
  const native = resolveNativeBinding(this);
  if (!native || typeof native.signQuotedTransactionPayload !== "function") {
    throw new Error(
      "native binding 'sign_quoted_transaction_payload' is unavailable",
    );
  }
  const draft = input?.payload;
  const payloadJson =
    typeof draft?.payloadJson === "string"
      ? draft.payloadJson
      : serializeTransactionPayloadJson(draft?.payload ?? draft);
  const quoted = input?.quotedFeePayment;
  const quotedFeePaymentJson =
    typeof quoted === "string"
      ? quoted
      : quoted && typeof quoted === "object" && "payer" in quoted && "value" in quoted
        ? JSON.stringify(quoted)
        : feePaymentIntentToNoritoJson(quoted);
  const result = native.signQuotedTransactionPayload(
    networkId,
    payloadJson,
    quotedFeePaymentJson,
    toBuffer(input?.privateKey),
    normalizePrivateKeyAlgorithm(
      input?.privateKeyAlgorithm,
      "input.privateKeyAlgorithm",
    ),
  );
  const signed = result?.signed_transaction ?? result?.signedTransaction ?? null;
  const hashBytes = result?.hash ?? result?.hashBytes ?? null;
  if (!signed || !hashBytes) {
    throw new Error(
      "native binding 'sign_quoted_transaction_payload' returned missing fields",
    );
  }
  return {
    signedTransaction: Buffer.from(signed),
    hash: Buffer.from(hashBytes),
  };
}

/**
 * Guided fee flow: freeze one unsigned payload, quote it through Torii, replace
 * only the fee limits, and sign the exact result.
 *
 * @param {ToriiClient} client
 * @param {object} input {@link buildTransactionPayload} fields plus private key material
 * @param {{canonicalAuth?: {accountId: string, privateKey: ArrayBufferView | ArrayBuffer | Buffer}, signal?: AbortSignal}} [options]
 * @returns {Promise<{signedTransaction: Buffer, hash: Buffer, draft: object, quote: object}>}
 */
export async function quoteAndSignTransaction(client, input, options = {}) {
  if (!client || typeof client.quoteFees !== "function") {
    throw new TypeError("client must provide quoteFees(payload, options)");
  }
  const {
    privateKey,
    privateKeyAlgorithm,
    ...draftInput
  } = input ?? {};
  const draft = buildTransactionPayload.call(this, draftInput);
  const canonicalAuth = options.canonicalAuth ?? {
    accountId: draftInput.authority,
    privateKey,
  };
  const quote = ToriiClient._validateFeeQuoteForDraft(
    draft,
    await client.quoteFees(draft, {
      canonicalAuth,
      signal: options.signal,
    }),
    "quoteAndSignTransaction fee quote",
  );
  const signed = signQuotedTransactionPayload.call(this, {
    networkId: draftInput.networkId,
    payload: draft,
    quotedFeePayment: quote.intent,
    privateKey,
    privateKeyAlgorithm,
  });
  return { ...signed, draft, quote };
}

const SORAFS_PIN_REGISTER_MAX_MANIFEST_BYTES = 512 * 1024;
const SORAFS_PIN_REGISTER_MAX_ALIAS_PROOF_BYTES = 1024 * 1024;

function rejectRetiredSorafsPinRegisterEpoch(input) {
  if (
    input !== null &&
    typeof input === "object" &&
    (Object.prototype.hasOwnProperty.call(input, "submittedEpoch") ||
      Object.prototype.hasOwnProperty.call(input, "submitted_epoch"))
  ) {
    throw new TypeError(
      "RegisterPinManifest no longer accepts a submitted epoch; consensus time is authoritative",
    );
  }
}

function normalizeSorafsPinRegisterSegment(value, context) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.trim() !== value ||
    value.length > 128 ||
    !/^[a-z0-9._-]+$/u.test(value)
  ) {
    throw new TypeError(
      `${context} must contain 1..=128 lowercase ASCII letters, digits, '.', '-', or '_'`,
    );
  }
  return value;
}

function normalizeSorafsPinRegisterSuccessor(value) {
  if (value === null || value === undefined) {
    return null;
  }
  let bytes;
  if (typeof value === "string") {
    const exact = value.startsWith("0x") ? value.slice(2) : value;
    if (!/^[0-9a-fA-F]{64}$/u.test(exact)) {
      throw new TypeError("successorOf must be exactly 32 hexadecimal bytes");
    }
    bytes = Buffer.from(exact, "hex");
  } else {
    bytes = toBuffer(value, "successorOf");
  }
  if (bytes.length !== 32 || bytes.every((byte) => byte === 0)) {
    throw new TypeError("successorOf must be exactly 32 non-zero bytes");
  }
  return Array.from(bytes);
}

/**
 * Build the exact native instruction accepted by the signed pin-registration route.
 *
 * @param {{
 *   manifestPayload: ArrayBufferView | ArrayBuffer | Buffer,
 *   alias?: {namespace: string, name: string, proof: ArrayBufferView | ArrayBuffer | Buffer} | null,
 *   successorOf?: string | ArrayBufferView | ArrayBuffer | Buffer | null
 * }} input
 * @returns {{RegisterPinManifest: object}}
 */
export function buildRegisterPinManifestInstruction(input) {
  rejectRetiredSorafsPinRegisterEpoch(input);
  const manifestPayload = toBuffer(input?.manifestPayload, "manifestPayload");
  if (
    manifestPayload.length === 0 ||
    manifestPayload.length > SORAFS_PIN_REGISTER_MAX_MANIFEST_BYTES
  ) {
    throw new TypeError(
      `manifestPayload must contain 1..=${SORAFS_PIN_REGISTER_MAX_MANIFEST_BYTES} bytes`,
    );
  }
  let alias = null;
  if (input?.alias !== null && input?.alias !== undefined) {
    const proof = toBuffer(input.alias.proof, "alias.proof");
    if (
      proof.length === 0 ||
      proof.length > SORAFS_PIN_REGISTER_MAX_ALIAS_PROOF_BYTES
    ) {
      throw new TypeError(
        `alias.proof must contain 1..=${SORAFS_PIN_REGISTER_MAX_ALIAS_PROOF_BYTES} bytes`,
      );
    }
    alias = {
      name: normalizeSorafsPinRegisterSegment(input.alias.name, "alias.name"),
      namespace: normalizeSorafsPinRegisterSegment(
        input.alias.namespace,
        "alias.namespace",
      ),
      proof: proof.toString("base64"),
    };
  }
  return {
    RegisterPinManifest: {
      manifest_payload: manifestPayload.toString("base64"),
      alias,
      successor_of: normalizeSorafsPinRegisterSuccessor(input?.successorOf),
    },
  };
}

/**
 * Fee-quote and locally sign one pin-registration transaction.
 *
 * @param {ToriiClient} client
 * @param {object} input Transaction draft fields plus pin registration fields.
 * @param {object} [options] Guided quote/sign options.
 * @returns {Promise<{signedTransaction: Buffer, hash: Buffer, draft: object, quote: object}>}
 */
export function buildRegisterPinManifestTransaction(client, input, options = {}) {
  rejectRetiredSorafsPinRegisterEpoch(input);
  if (input && Object.prototype.hasOwnProperty.call(input, "instructions")) {
    throw new TypeError(
      "buildRegisterPinManifestTransaction fixes instructions to one RegisterPinManifest",
    );
  }
  const {
    manifestPayload,
    alias = null,
    successorOf = null,
    ...transactionInput
  } = input ?? {};
  const instruction = buildRegisterPinManifestInstruction({
    manifestPayload,
    alias,
    successorOf,
  });
  return quoteAndSignTransaction.call(
    this,
    client,
    { ...transactionInput, instructions: [instruction] },
    options,
  );
}

/**
 * Build, but do not sign, the exact proved-IVM payload submitted to
 * `/v1/fees/quote`.
 *
 * @param {{
 *   networkId: import("./networkId.js").NetworkId,
 *   authority: string,
 *   proved: object | string,
 *   attachment: object | string,
 *   feePayment: object,
 *   metadata?: object | string | null,
 *   creationTimeMs?: number,
 *   ttlMs?: number,
 *   nonce?: number
 * }} input
 * @returns {{payload: object, payloadJson: string, payloadBytes: Buffer, payloadHash: Buffer, attachment: object, attachmentJson: string}}
 */
export function buildIvmProvedTransactionPayload(input) {
  const networkId = transactionNetworkIdBytes(input, "input");
  const native = resolveNativeBinding(this);
  if (
    !native ||
    typeof native.buildIvmProvedTransactionPayload !== "function"
  ) {
    throw new Error(
      "native binding 'build_ivm_proved_transaction_payload' is unavailable",
    );
  }

  const {
    authority,
    proved,
    attachment,
    feePayment,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
  } = input;
  const canonicalAuthority = normalizeAuthority(authority);
  const provedPayload = normalizeJsonObjectPayload(proved, "proved");
  const attachmentPayload = normalizeJsonObjectPayload(
    attachment,
    "attachment",
  );
  const result = native.buildIvmProvedTransactionPayload(
    networkId,
    canonicalAuthority,
    provedPayload,
    attachmentPayload,
    feePaymentIntentToNoritoJson(feePayment),
    normalizeMetadataPayload(metadata, "transaction metadata"),
    creationTimeMs,
    ttlMs,
    nonce,
  );
  const payloadJson = result?.payload_json ?? result?.payloadJson ?? null;
  const payloadBytes = result?.payload_bytes ?? result?.payloadBytes ?? null;
  const payloadHash = result?.payload_hash ?? result?.payloadHash ?? null;
  if (typeof payloadJson !== "string" || !payloadBytes || !payloadHash) {
    throw new Error(
      "native binding 'build_ivm_proved_transaction_payload' returned missing fields",
    );
  }
  return {
    payload: JSON.parse(payloadJson),
    payloadJson,
    payloadBytes: Buffer.from(payloadBytes),
    payloadHash: Buffer.from(payloadHash),
    attachment: JSON.parse(attachmentPayload),
    attachmentJson: attachmentPayload,
  };
}

/**
 * Apply a quote to an exact proved-IVM draft, reattach its proof, and sign it.
 *
 * @param {{
 *   networkId: import("./networkId.js").NetworkId,
 *   payload: object | {payload?: object, payloadJson?: string, attachment?: object | string},
 *   attachment?: object | string,
 *   quotedFeePayment: object | string,
 *   privateKey: ArrayBufferView | ArrayBuffer | Buffer,
 *   privateKeyAlgorithm?: import("../index.js").CryptoAlgorithm
 * }} input
 * @returns {{signedTransaction: Buffer, hash: Buffer}}
 */
export function signQuotedIvmProvedTransactionPayload(input) {
  const networkId = transactionNetworkIdBytes(input, "input");
  const native = resolveNativeBinding(this);
  if (
    !native ||
    typeof native.signQuotedIvmProvedTransactionPayload !== "function"
  ) {
    throw new Error(
      "native binding 'sign_quoted_ivm_proved_transaction_payload' is unavailable",
    );
  }
  const draft = input?.payload;
  const payloadJson =
    typeof draft?.payloadJson === "string"
      ? draft.payloadJson
      : JSON.stringify(draft?.payload ?? draft);
  const attachment = input?.attachment ?? draft?.attachment;
  const quoted = input?.quotedFeePayment;
  const quotedFeePaymentJson =
    typeof quoted === "string"
      ? quoted
      : quoted && typeof quoted === "object" && "payer" in quoted && "value" in quoted
        ? JSON.stringify(quoted)
        : feePaymentIntentToNoritoJson(quoted);
  const result = native.signQuotedIvmProvedTransactionPayload(
    networkId,
    payloadJson,
    normalizeJsonObjectPayload(attachment, "attachment"),
    quotedFeePaymentJson,
    toBuffer(input?.privateKey),
    normalizePrivateKeyAlgorithm(
      input?.privateKeyAlgorithm,
      "input.privateKeyAlgorithm",
    ),
  );
  const signed =
    result?.signed_transaction ?? result?.signedTransaction ?? null;
  const hashBytes = result?.hash ?? result?.hashBytes ?? null;
  if (!signed || !hashBytes) {
    throw new Error(
      "native binding 'sign_quoted_ivm_proved_transaction_payload' returned missing fields",
    );
  }
  return {
    signedTransaction: Buffer.from(signed),
    hash: Buffer.from(hashBytes),
  };
}

/**
 * Build and sign a transaction whose executable is `Executable::IvmProved`.
 * @param {{
 *   networkId: import("./networkId.js").NetworkId,
 *   authority: string,
 *   proved: object | string,
 *   attachment: object | string,
 *   feePayment: object,
 *   metadata?: object | string | null,
 *   creationTimeMs?: number,
 *   ttlMs?: number,
 *   nonce?: number,
 *   privateKey: ArrayBufferView | ArrayBuffer | Buffer
 * }} input
 * @returns {{signedTransaction: Buffer, hash: Buffer}}
 */
export function buildIvmProvedTransaction(input) {
  const networkId = transactionNetworkIdBytes(input, "input");
  const native = resolveNativeBinding(this);
  if (!native || typeof native.buildIvmProvedTransaction !== "function") {
    throw new Error(
      "native binding 'build_ivm_proved_transaction' is unavailable",
    );
  }

  const {
    authority,
    proved,
    attachment,
    feePayment,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;

  const canonicalAuthority = normalizeAuthority(authority);
  const provedPayload = normalizeJsonObjectPayload(proved, "proved");
  const attachmentPayload = normalizeJsonObjectPayload(
    attachment,
    "attachment",
  );
  const metadataPayload = normalizeMetadataPayload(
    metadata,
    "transaction metadata",
  );
  const result = native.buildIvmProvedTransaction(
    networkId,
    canonicalAuthority,
    provedPayload,
    attachmentPayload,
    feePaymentIntentToNoritoJson(feePayment),
    metadataPayload,
    creationTimeMs,
    ttlMs,
    nonce,
    toBuffer(privateKey),
    normalizePrivateKeyAlgorithm(privateKeyAlgorithm),
  );

  const signed =
    result?.signed_transaction ?? result?.signedTransaction ?? null;
  const hashBytes = result?.hash ?? result?.hashBytes ?? null;
  if (!signed || !hashBytes) {
    throw new Error(
      "native binding 'build_ivm_proved_transaction' returned missing fields",
    );
  }

  return {
    signedTransaction: Buffer.from(signed),
    hash: Buffer.from(hashBytes),
  };
}

export function buildTimeTriggerAction(options) {
  if (!options || typeof options !== "object") {
    throw new TypeError("buildTimeTriggerAction options must be an object");
  }
  const {
    authority,
    instructions,
    startTimestampMs,
    periodMs = null,
    repeats = null,
    metadata = null,
  } = options;
  const native = resolveNativeBinding(this);
  if (!native || typeof native.buildTimeTriggerAction !== "function") {
    throw new Error("native binding 'buildTimeTriggerAction' is unavailable");
  }
  const canonicalAuthority = normalizeAuthority(authority);
  const instructionPayloads = serializeInstructionPayloads(
    instructions,
    "buildTimeTriggerAction.instructions",
  );
  const startMs = ToriiClient._normalizeUnsignedInteger(
    startTimestampMs,
    "buildTimeTriggerAction.startTimestampMs",
    { allowZero: false },
  );
  const periodValue =
    periodMs === null || periodMs === undefined
      ? null
      : ToriiClient._normalizeUnsignedInteger(
          periodMs,
          "buildTimeTriggerAction.periodMs",
          { allowZero: false },
        );
  const repeatsValue = normalizeOptionalPositiveInteger(
    repeats,
    "buildTimeTriggerAction.repeats",
  );
  const metadataPayload = normalizeMetadataPayload(
    metadata,
    "buildTimeTriggerAction.metadata",
  );
  return native.buildTimeTriggerAction(
    canonicalAuthority,
    instructionPayloads,
    startMs,
    periodValue,
    repeatsValue,
    metadataPayload,
  );
}

export function buildPrecommitTriggerAction(options) {
  if (!options || typeof options !== "object") {
    throw new TypeError(
      "buildPrecommitTriggerAction options must be an object",
    );
  }
  const { authority, instructions, repeats = null, metadata = null } = options;
  const native = resolveNativeBinding(this);
  if (!native || typeof native.buildPrecommitTriggerAction !== "function") {
    throw new Error(
      "native binding 'buildPrecommitTriggerAction' is unavailable",
    );
  }
  const canonicalAuthority = normalizeAuthority(authority);
  const instructionPayloads = serializeInstructionPayloads(
    instructions,
    "buildPrecommitTriggerAction.instructions",
  );
  const repeatsValue = normalizeOptionalPositiveInteger(
    repeats,
    "buildPrecommitTriggerAction.repeats",
  );
  const metadataPayload = normalizeMetadataPayload(
    metadata,
    "buildPrecommitTriggerAction.metadata",
  );
  return native.buildPrecommitTriggerAction(
    canonicalAuthority,
    instructionPayloads,
    repeatsValue,
    metadataPayload,
  );
}

/**
 * Convenience helper to build a transaction with a single `Mint::Asset` instruction.
 * Additional transaction parameters mirror {@link buildTransaction}.
 */
export function buildMintAssetTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    assetHoldingId,
    assetId,
    quantity,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildMintAssetInstruction({
    assetHoldingId: assetHoldingId ?? assetId,
    quantity,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Convenience helper to build a transaction with a single `Burn::Asset` instruction.
 * Additional transaction parameters mirror {@link buildTransaction}.
 */
export function buildBurnAssetTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    assetHoldingId,
    assetId,
    quantity,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildBurnAssetInstruction({
    assetHoldingId: assetHoldingId ?? assetId,
    quantity,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Burn::TriggerRepetitions` instruction.
 */
export function buildBurnTriggerTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    triggerId,
    repetitions,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildBurnTriggerRepetitionsInstruction({
    triggerId,
    repetitions,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Mint::TriggerRepetitions` instruction.
 */
export function buildMintTriggerTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    triggerId,
    repetitions,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildMintTriggerRepetitionsInstruction({
    triggerId,
    repetitions,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Transfer::Asset` instruction.
 */
export function buildTransferAssetTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    sourceAssetHoldingId,
    sourceAssetId,
    quantity,
    destinationAccountId,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildTransferAssetInstruction({
    sourceAssetHoldingId: sourceAssetHoldingId ?? sourceAssetId,
    quantity,
    destinationAccountId,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build instructions combining a domain registration with an optional mint.
 */
function buildRegisterDomainInstructions({ domain, mints = [] }) {
  const instructions = [];
  instructions.push(
    buildRegisterDomainInstruction({
      domainId: domain.domainId,
      logo: domain.logo,
      metadata: domain.metadata,
    }),
  );
  mints.forEach((mint) => {
    instructions.push(
      buildMintAssetInstruction({
        assetHoldingId: mint.assetHoldingId ?? mint.assetId,
        quantity: mint.quantity,
      }),
    );
  });
  return instructions;
}

/**
 * Build instructions combining an account registration with a follow-up transfer.
 */
function buildRegisterAccountInstructions({ account, transfers = [] }) {
  if (account.domainId !== undefined || account.domain !== undefined) {
    throw new TypeError(
      "account registration is domainless; bind account aliases separately",
    );
  }
  const instructions = [];
  instructions.push(
    buildRegisterAccountInstruction({
      accountId: account.accountId,
      metadata: account.metadata,
    }),
  );
  transfers.forEach((transfer) => {
    const sourceAssetHoldingId =
      transfer.sourceAssetHoldingId ?? transfer.sourceAssetId;
    if (!sourceAssetHoldingId) {
      throw new TypeError("transfer.sourceAssetHoldingId is required");
    }
    instructions.push(
      buildTransferAssetInstruction({
        sourceAssetHoldingId,
        quantity: transfer.quantity,
        destinationAccountId: transfer.destinationAccountId,
      }),
    );
  });
  return instructions;
}

/**
 * Build a transaction containing a multisig registration (custom instruction).
 */
export function buildRegisterMultisigTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    accountId,
    spec,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildRegisterMultisigInstruction({ accountId, spec });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build instructions combining an asset definition registration with an optional mint.
 */
const buildRegisterAssetDefinitionInstructions =
  createRegisterAssetDefinitionInstructionBuilder({
    normalizeTransactionAssetDefinitionId,
    buildMintAssetInstruction,
  });

function resolveAssetHoldingIdForMint(
  assetDefinitionId,
  mint,
  context = "mint",
  dataspaceId = null,
) {
  const providedAssetHoldingId = mint.assetHoldingId ?? mint.assetId;
  if (providedAssetHoldingId) {
    const normalizedAssetHoldingId = ToriiClient._normalizeAssetHoldingId(
      providedAssetHoldingId,
      mint.assetHoldingId !== undefined
        ? `${context}.assetHoldingId`
        : `${context}.assetId`,
    );
    if (!mint.accountId) {
      return normalizedAssetHoldingId;
    }
    const derivedAssetHoldingId = composeAssetHoldingIdFromDefinitionAndAccount(
      assetDefinitionId,
      mint.accountId,
      context,
    );
    // An explicit bilateral bucket is independent of the definition home.
    const explicitDefinitionAndAccount = normalizedAssetHoldingId
      .split("#").slice(0, 2).join("#");
    if (explicitDefinitionAndAccount !== derivedAssetHoldingId) {
      throw new TypeError(
        `${context}.assetHoldingId must match ${context}.assetDefinitionId + ${context}.accountId`,
      );
    }
    return normalizedAssetHoldingId;
  }
  if (!mint.accountId) {
    throw new TypeError(
      `${context}.assetId, ${context}.assetHoldingId, or ${context}.accountId must be provided`,
    );
  }
  return composeAssetHoldingIdFromDefinitionAndAccount(
    assetDefinitionId,
    mint.accountId,
    context,
    dataspaceId,
  );
}

function normalizeDomainMintSpec(value, context) {
  if (!value || typeof value !== "object") {
    throw new TypeError(`${context} must be an object`);
  }
  const assetHoldingId = value.assetHoldingId ?? value.assetId;
  if (typeof assetHoldingId !== "string" || assetHoldingId.length === 0) {
    throw new TypeError(`${context}.assetId must be a non-empty string`);
  }
  return {
    assetHoldingId: ToriiClient._normalizeAssetHoldingId(
      assetHoldingId,
      value.assetHoldingId !== undefined
        ? `${context}.assetHoldingId`
        : `${context}.assetId`,
    ),
    quantity: value.quantity,
  };
}

function normalizeDomainMintSpecs(value, context) {
  if (!Array.isArray(value)) {
    throw new TypeError(`${context} must be an array of mint descriptors`);
  }
  return value.map((item, index) =>
    normalizeDomainMintSpec(item, `${context}[${index}]`),
  );
}

function normalizeAssetDefinitionMintSpec(
  assetDefinitionId,
  value,
  context,
  dataspaceId = null,
) {
  if (!value || typeof value !== "object") {
    throw new TypeError(`${context} must be an object`);
  }
  const assetHoldingId = resolveAssetHoldingIdForMint(
    assetDefinitionId,
    value,
    context,
    dataspaceId,
  );
  return {
    assetHoldingId,
    accountId:
      value.accountId === undefined || value.accountId === null
        ? null
        : normalizeAccountId(value.accountId, `${context}.accountId`),
    quantity: value.quantity,
  };
}

function normalizeAssetDefinitionMintSpecs(
  assetDefinitionId,
  value,
  context,
  dataspaceId = null,
) {
  if (!Array.isArray(value)) {
    throw new TypeError(
      `${context} must be an array of asset mint descriptors`,
    );
  }
  if (value.length === 0) {
    throw new TypeError(`${context} must contain at least one entry`);
  }
  return value.map((item, index) =>
    normalizeAssetDefinitionMintSpec(
      assetDefinitionId,
      item,
      `${context}[${index}]`,
      dataspaceId,
    ),
  );
}

function normalizeTransferSpec(value, context, options = {}) {
  const { requireSource = false } = options;
  if (!value || typeof value !== "object") {
    throw new TypeError(`${context} must be an object`);
  }
  const spec = {
    sourceAssetHoldingId: value.sourceAssetHoldingId ?? value.sourceAssetId,
    quantity: value.quantity,
    destinationAccountId: value.destinationAccountId,
  };
  if (requireSource && !spec.sourceAssetHoldingId) {
    throw new TypeError(
      `${context}.sourceAssetId is required (or ${context}.sourceAssetHoldingId)`,
    );
  }
  return spec;
}

function normalizeTransferSpecs(value, context, options) {
  if (!Array.isArray(value)) {
    throw new TypeError(`${context} must be an array of transfer descriptors`);
  }
  return value.map((item, index) =>
    normalizeTransferSpec(item, `${context}[${index}]`, options),
  );
}

/**
 * Build a transaction that first mints an asset and then transfers part of it.
 * Accepts either a single transfer descriptor or an array of transfers.
 */
export function buildMintAndTransferTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    mint,
    transfer,
    transfers,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  if (!mint || typeof mint !== "object") {
    throw new TypeError("mint options are required");
  }
  if (transfer && transfers) {
    throw new TypeError("provide either transfer or transfers, but not both");
  }
  const transferSpecs =
    transfers !== undefined
      ? normalizeTransferSpecs(transfers, "transfers")
      : transfer
        ? [normalizeTransferSpec(transfer, "transfer")]
        : [];
  if (transferSpecs.length === 0) {
    throw new TypeError("transfer or transfers options are required");
  }
  const mintInstruction = buildMintAssetInstruction(mint);
  const defaultSource = mint.assetHoldingId ?? mint.assetId;
  if (
    !defaultSource &&
    transferSpecs.some((spec) => spec.sourceAssetHoldingId === undefined)
  ) {
    throw new TypeError(
      "mint.assetHoldingId is required when transfer sourceAssetHoldingId is omitted",
    );
  }
  const instructions = [mintInstruction];
  for (const spec of transferSpecs) {
    const sourceAssetHoldingId = spec.sourceAssetHoldingId ?? defaultSource;
    instructions.push(
      buildTransferAssetInstruction({
        sourceAssetHoldingId,
        quantity: spec.quantity,
        destinationAccountId: spec.destinationAccountId,
      }),
    );
  }
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions,
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction that registers a domain and optionally mints an asset.
 */
export function buildRegisterDomainAndMintTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    domain,
    mint,
    mints,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  if (!domain || typeof domain !== "object") {
    throw new TypeError("domain registration parameters are required");
  }
  if (mint && mints) {
    throw new TypeError("provide either mint or mints, but not both");
  }
  const mintSpecs =
    mints !== undefined
      ? normalizeDomainMintSpecs(mints, "mints")
      : mint
        ? [normalizeDomainMintSpec(mint, "mint")]
        : [];
  const instructions = buildRegisterDomainInstructions({
    domain,
    mints: mintSpecs,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions,
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction that registers a new account and optionally transfers an asset.
 */
export function buildRegisterAccountAndTransferTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    account,
    transfer,
    transfers,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  if (!account || typeof account !== "object") {
    throw new TypeError("account registration parameters are required");
  }
  if (transfer && transfers) {
    throw new TypeError("provide either transfer or transfers, but not both");
  }
  const transferSpecs =
    transfers !== undefined
      ? normalizeTransferSpecs(transfers, "transfers", { requireSource: true })
      : transfer
        ? [normalizeTransferSpec(transfer, "transfer", { requireSource: true })]
        : [];
  const instructions = buildRegisterAccountInstructions({
    account,
    transfers: transferSpecs,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions,
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Transfer::AssetDefinition` instruction.
 */
export function buildTransferAssetDefinitionTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    sourceAccountId,
    assetDefinitionId,
    destinationAccountId,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildTransferAssetDefinitionInstruction({
    sourceAccountId,
    assetDefinitionId,
    destinationAccountId,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction that registers an asset definition and optionally mints to an account.
 */
export function buildRegisterAssetDefinitionAndMintTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    assetDefinition,
    mint,
    mints,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  if (!assetDefinition || typeof assetDefinition !== "object") {
    throw new TypeError("assetDefinition registration parameters are required");
  }
  if (mint && mints) {
    throw new TypeError("provide either mint or mints, but not both");
  }
  const instructions = buildRegisterAssetDefinitionInstructions({ assetDefinition });
  const directRegistration = instructions[0].RegisterDataspaceAssetDefinition;
  const mintDataspaceId =
    directRegistration?.object.balance_scope_policy === "DataspaceRestricted"
      ? directRegistration.dataspace_id
      : null;
  const mintSpecs =
    mints !== undefined
      ? normalizeAssetDefinitionMintSpecs(
          assetDefinition.assetDefinitionId,
          mints,
          "mints",
          mintDataspaceId,
        )
      : mint
        ? [
            normalizeAssetDefinitionMintSpec(
              assetDefinition.assetDefinitionId,
              mint,
              "mint",
              mintDataspaceId,
            ),
          ]
        : [];
  instructions.push(
    ...mintSpecs.map(({ assetHoldingId, quantity }) =>
      buildMintAssetInstruction({ assetHoldingId, quantity }),
    ),
  );
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions,
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction that registers an asset definition, mints, and optionally transfers it.
 * Supports either a single `transfer` descriptor or an array of `transfers` for batching.
 */
export function buildRegisterAssetDefinitionMintAndTransferTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    assetDefinition,
    mint,
    mints,
    transfer,
    transfers,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  if (!assetDefinition || typeof assetDefinition !== "object") {
    throw new TypeError("assetDefinition registration parameters are required");
  }
  if (mint && mints) {
    throw new TypeError("provide either mint or mints, but not both");
  }
  if (!mint && (mints === undefined || mints.length === 0)) {
    throw new TypeError("mint or mints parameters are required");
  }
  const instructions = buildRegisterAssetDefinitionInstructions({ assetDefinition });
  const directRegistration = instructions[0].RegisterDataspaceAssetDefinition;
  const mintDataspaceId =
    directRegistration?.object.balance_scope_policy === "DataspaceRestricted"
      ? directRegistration.dataspace_id
      : null;
  const mintSpecs =
    mints !== undefined
      ? normalizeAssetDefinitionMintSpecs(
          assetDefinition.assetDefinitionId,
          mints,
          "mints",
          mintDataspaceId,
        )
      : [
          normalizeAssetDefinitionMintSpec(
            assetDefinition.assetDefinitionId,
            mint,
            "mint",
            mintDataspaceId,
          ),
        ];

  instructions.push(
    ...mintSpecs.map(({ assetHoldingId, quantity }) =>
      buildMintAssetInstruction({ assetHoldingId, quantity }),
    ),
  );

  if (transfer && transfers) {
    throw new TypeError("provide either transfer or transfers, but not both");
  }

  const transferSpecs =
    transfers !== undefined
      ? normalizeTransferSpecs(transfers, "transfers")
      : transfer
        ? [normalizeTransferSpec(transfer, "transfer")]
        : [];

  if (transferSpecs.length > 0) {
    const defaultSourceAssetHoldingId = mintSpecs[0].assetHoldingId;
    for (const spec of transferSpecs) {
      instructions.push(
        buildTransferAssetInstruction({
          sourceAssetHoldingId:
            spec.sourceAssetHoldingId ?? defaultSourceAssetHoldingId,
          quantity: spec.quantity,
          destinationAccountId: spec.destinationAccountId,
        }),
      );
    }
  }

  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions,
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Transfer::Domain` instruction.
 */
export function buildTransferDomainTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    sourceAccountId,
    domainId,
    destinationAccountId,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildTransferDomainInstruction({
    sourceAccountId,
    domainId,
    destinationAccountId,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Transfer::Nft` instruction.
 */
export function buildTransferNftTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    sourceAccountId,
    nftId,
    destinationAccountId,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildTransferNftInstruction({
    sourceAccountId,
    nftId,
    destinationAccountId,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `RegisterRwa` instruction.
 */
export function buildRegisterRwaTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    rwa,
    rwaJson,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildRegisterRwaInstruction({ rwa, rwaJson });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `TransferRwa` instruction.
 */
export function buildTransferRwaTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    sourceAccountId,
    rwaId,
    quantity,
    destinationAccountId,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildTransferRwaInstruction({
    sourceAccountId,
    rwaId,
    quantity,
    destinationAccountId,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `MergeRwas` instruction.
 */
export function buildMergeRwasTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    merge,
    mergeJson,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildMergeRwasInstruction({ merge, mergeJson });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `RedeemRwa` instruction.
 */
export function buildRedeemRwaTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    rwaId,
    quantity,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildRedeemRwaInstruction({ rwaId, quantity });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `FreezeRwa` instruction.
 */
export function buildFreezeRwaTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    rwaId,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildFreezeRwaInstruction({ rwaId });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing an `UnfreezeRwa` instruction.
 */
export function buildUnfreezeRwaTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    rwaId,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildUnfreezeRwaInstruction({ rwaId });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `HoldRwa` instruction.
 */
export function buildHoldRwaTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    rwaId,
    quantity,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildHoldRwaInstruction({ rwaId, quantity });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `ReleaseRwa` instruction.
 */
export function buildReleaseRwaTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    rwaId,
    quantity,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildReleaseRwaInstruction({ rwaId, quantity });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `ForceTransferRwa` instruction.
 */
export function buildForceTransferRwaTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    rwaId,
    quantity,
    destinationAccountId,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildForceTransferRwaInstruction({
    rwaId,
    quantity,
    destinationAccountId,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `SetRwaControls` instruction.
 */
export function buildSetRwaControlsTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    rwaId,
    controls,
    controlsJson,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildSetRwaControlsInstruction({
    rwaId,
    controls,
    controlsJson,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `SetRwaKeyValue` instruction.
 */
export function buildSetRwaKeyValueTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    rwaId,
    key,
    value,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildSetRwaKeyValueInstruction({ rwaId, key, value });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `RemoveRwaKeyValue` instruction.
 */
export function buildRemoveRwaKeyValueTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    rwaId,
    key,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildRemoveRwaKeyValueInstruction({ rwaId, key });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Kaigi::CreateKaigi` instruction.
 */
export function buildCreateKaigiTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    call,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildCreateKaigiInstruction(call);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Kaigi::JoinKaigi` instruction.
 */
export function buildJoinKaigiTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    join,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildJoinKaigiInstruction(join);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Kaigi::LeaveKaigi` instruction.
 */
export function buildLeaveKaigiTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    leave,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildLeaveKaigiInstruction(leave);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Kaigi::EndKaigi` instruction.
 */
export function buildEndKaigiTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    end,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildEndKaigiInstruction(end);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Kaigi::RecordKaigiUsage` instruction.
 */
export function buildRecordKaigiUsageTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    usage,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildRecordKaigiUsageInstruction(usage);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Kaigi::SetKaigiRelayManifest` instruction.
 */
export function buildSetKaigiRelayManifestTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    manifest,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildSetKaigiRelayManifestInstruction(manifest);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Kaigi::RegisterKaigiRelay` instruction.
 */
export function buildRegisterKaigiRelayTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    relay,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildRegisterKaigiRelayInstruction(relay);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Kaigi::UnregisterKaigiRelay` instruction.
 */
export function buildUnregisterKaigiRelayTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    relayId,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildUnregisterKaigiRelayInstruction({ relayId });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `Kaigi::ReportKaigiRelayHealth` instruction.
 */
export function buildReportKaigiRelayHealthTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    report,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildReportKaigiRelayHealthInstruction(report);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `ProposeDeployContract` instruction.
 */
export function buildProposeDeployContractTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    proposal,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildProposeDeployContractInstruction(proposal);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `CastZkBallot` instruction.
 */
export function buildCastZkBallotTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    ballot,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildCastZkBallotInstruction(ballot);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `CastPlainBallot` instruction.
 */
export function buildCastPlainBallotTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    ballot,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildCastPlainBallotInstruction(ballot);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing one choice-free `UpdatePlainConviction` instruction.
 */
export function buildUpdatePlainConvictionTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    update,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildUpdatePlainConvictionInstruction(update);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

export function buildRegisterZkAssetTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    registration,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildRegisterZkAssetInstruction(registration);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

export function buildScheduleConfidentialPolicyTransitionTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    transition,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction =
    buildScheduleConfidentialPolicyTransitionInstruction(transition);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

export function buildCancelConfidentialPolicyTransitionTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    cancellation,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction =
    buildCancelConfidentialPolicyTransitionInstruction(cancellation);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

export function buildCreateElectionTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    election,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildCreateElectionInstruction(election);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

export function buildSubmitBallotTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    ballot,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildSubmitBallotInstruction(ballot);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

export function buildFinalizeElectionTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    finalization,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildFinalizeElectionInstruction(finalization);
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `RegisterSmartContractCode` instruction.
 */
export function buildRegisterSmartContractCodeTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    artifactId,
    manifest,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildRegisterSmartContractCodeInstruction({ artifactId, manifest });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `RegisterSmartContractBytes` instruction.
 */
export function buildRegisterSmartContractBytesTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    artifactId,
    code,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildRegisterSmartContractBytesInstruction({
    artifactId,
    code,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Build a transaction containing a `RemoveSmartContractBytes` instruction.
 */
export function buildRemoveSmartContractBytesTransaction(input) {
  transactionNetworkIdBytes(input, "input");
  const {
    networkId,
    authority,
    feePayment,
    artifactId,
    reason = null,
    metadata = null,
    creationTimeMs = null,
    ttlMs = null,
    nonce = null,
    privateKey,
    privateKeyAlgorithm,
  } = input;
  const instruction = buildRemoveSmartContractBytesInstruction({
    artifactId,
    reason,
  });
  return buildTransaction.call(this, {
    networkId,
    authority,
    feePayment,
    instructions: [instruction],
    metadata,
    creationTimeMs,
    ttlMs,
    nonce,
    privateKey,
    privateKeyAlgorithm,
  });
}

/**
 * Submit an exact canonical VersionedSignedTransaction V1 wire and optionally
 * wait for authoritative Applied finality.
 * @param {ToriiClient} client
 * @param {ArrayBufferView | ArrayBuffer | Buffer} signedTransaction
 * @param {{ waitForCommit?: boolean, pollIntervalMs?: number, timeoutMs?: number, networkId?: import("./networkId.js").NetworkId, privateKey?: ArrayBufferView | ArrayBuffer | Buffer }} [options]
 * @returns {Promise<{hash: string, submission: any, status?: any}>}
 */
export async function submitSignedTransaction(
  client,
  signedTransaction,
  options = {},
) {
  if (!(client instanceof ToriiClient)) {
    throw new TypeError("client must be an instance of ToriiClient");
  }
  rejectRetiredTransactionFinalityFields(options, "options");
  for (const field of RETIRED_TRANSACTION_DOMAIN_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(options, field)) {
      throw new TypeError(
        `options.${field} is unsupported; provide networkId when re-signing`,
      );
    }
  }
  let txBuffer = toBuffer(signedTransaction);
  if (Object.prototype.hasOwnProperty.call(options, "privateKey")) {
    txBuffer = resignSignedTransaction.call(
      this,
      options.networkId,
      txBuffer,
      options.privateKey,
    );
  }
  const hashHex = hashSignedTransaction.call(this, txBuffer);
  const submission = await client.submitTransaction(txBuffer);

  if (!options.waitForCommit) {
    return { hash: hashHex, submission };
  }

  const status = await waitForAuthoritativeApplied(client, hashHex, options);
  return { hash: hashHex, submission, status };
}

async function waitForAuthoritativeApplied(client, hashHex, options) {
  const pollOptions = {
    intervalMs: options.pollIntervalMs ?? 500,
    timeoutMs: options.timeoutMs ?? 30_000,
  };
  return client.waitForTransactionStatus(hashHex, pollOptions);
}

/** @internal Source-level test facade; intentionally absent from package exports. */
export function _createTransactionApi(nativeRuntime) {
  const context = createTransactionContext(nativeRuntime);
  const bind = (fn) => fn.bind(context);
  return Object.freeze({
    feePaymentIntentToNoritoJson: bind(feePaymentIntentToNoritoJson),
    hashSignedTransaction: bind(hashSignedTransaction),
    hashSignedTransactionPayload: bind(hashSignedTransactionPayload),
    decodeSignedTransaction: bind(decodeSignedTransaction),
    encodeContractArgumentRecord: bind(encodeContractArgumentRecord),
    hashInstructionBatch: bind(hashInstructionBatch),
    resignSignedTransaction: bind(resignSignedTransaction),
    buildRegisterDomainTransaction: bind(buildRegisterDomainTransaction),
    buildTransaction: bind(buildTransaction),
    buildExecutableBatchTransaction: bind(buildExecutableBatchTransaction),
    buildTransactionPayload: bind(buildTransactionPayload),
    buildExecutableBatchTransactionPayload: bind(
      buildExecutableBatchTransactionPayload,
    ),
    signQuotedTransactionPayload: bind(signQuotedTransactionPayload),
    quoteAndSignTransaction: bind(quoteAndSignTransaction),
    buildRegisterPinManifestInstruction: bind(
      buildRegisterPinManifestInstruction,
    ),
    buildRegisterPinManifestTransaction: bind(
      buildRegisterPinManifestTransaction,
    ),
    buildIvmProvedTransactionPayload: bind(buildIvmProvedTransactionPayload),
    signQuotedIvmProvedTransactionPayload: bind(
      signQuotedIvmProvedTransactionPayload,
    ),
    buildIvmProvedTransaction: bind(buildIvmProvedTransaction),
    buildTimeTriggerAction: bind(buildTimeTriggerAction),
    buildPrecommitTriggerAction: bind(buildPrecommitTriggerAction),
    buildMintAssetTransaction: bind(buildMintAssetTransaction),
    buildBurnAssetTransaction: bind(buildBurnAssetTransaction),
    buildBurnTriggerTransaction: bind(buildBurnTriggerTransaction),
    buildMintTriggerTransaction: bind(buildMintTriggerTransaction),
    buildTransferAssetTransaction: bind(buildTransferAssetTransaction),
    buildRegisterMultisigTransaction: bind(buildRegisterMultisigTransaction),
    buildMintAndTransferTransaction: bind(buildMintAndTransferTransaction),
    buildRegisterDomainAndMintTransaction: bind(
      buildRegisterDomainAndMintTransaction,
    ),
    buildRegisterAccountAndTransferTransaction: bind(
      buildRegisterAccountAndTransferTransaction,
    ),
    buildTransferAssetDefinitionTransaction: bind(
      buildTransferAssetDefinitionTransaction,
    ),
    buildRegisterAssetDefinitionAndMintTransaction: bind(
      buildRegisterAssetDefinitionAndMintTransaction,
    ),
    buildRegisterAssetDefinitionMintAndTransferTransaction: bind(
      buildRegisterAssetDefinitionMintAndTransferTransaction,
    ),
    buildTransferDomainTransaction: bind(buildTransferDomainTransaction),
    buildTransferNftTransaction: bind(buildTransferNftTransaction),
    buildRegisterRwaTransaction: bind(buildRegisterRwaTransaction),
    buildTransferRwaTransaction: bind(buildTransferRwaTransaction),
    buildMergeRwasTransaction: bind(buildMergeRwasTransaction),
    buildRedeemRwaTransaction: bind(buildRedeemRwaTransaction),
    buildFreezeRwaTransaction: bind(buildFreezeRwaTransaction),
    buildUnfreezeRwaTransaction: bind(buildUnfreezeRwaTransaction),
    buildHoldRwaTransaction: bind(buildHoldRwaTransaction),
    buildReleaseRwaTransaction: bind(buildReleaseRwaTransaction),
    buildForceTransferRwaTransaction: bind(buildForceTransferRwaTransaction),
    buildSetRwaControlsTransaction: bind(buildSetRwaControlsTransaction),
    buildSetRwaKeyValueTransaction: bind(buildSetRwaKeyValueTransaction),
    buildRemoveRwaKeyValueTransaction: bind(
      buildRemoveRwaKeyValueTransaction,
    ),
    buildCreateKaigiTransaction: bind(buildCreateKaigiTransaction),
    buildJoinKaigiTransaction: bind(buildJoinKaigiTransaction),
    buildLeaveKaigiTransaction: bind(buildLeaveKaigiTransaction),
    buildEndKaigiTransaction: bind(buildEndKaigiTransaction),
    buildRecordKaigiUsageTransaction: bind(buildRecordKaigiUsageTransaction),
    buildSetKaigiRelayManifestTransaction: bind(
      buildSetKaigiRelayManifestTransaction,
    ),
    buildRegisterKaigiRelayTransaction: bind(
      buildRegisterKaigiRelayTransaction,
    ),
    buildUnregisterKaigiRelayTransaction: bind(
      buildUnregisterKaigiRelayTransaction,
    ),
    buildReportKaigiRelayHealthTransaction: bind(
      buildReportKaigiRelayHealthTransaction,
    ),
    buildProposeDeployContractTransaction: bind(
      buildProposeDeployContractTransaction,
    ),
    buildCastZkBallotTransaction: bind(buildCastZkBallotTransaction),
    buildCastPlainBallotTransaction: bind(buildCastPlainBallotTransaction),
    buildUpdatePlainConvictionTransaction: bind(buildUpdatePlainConvictionTransaction),
    buildRegisterZkAssetTransaction: bind(buildRegisterZkAssetTransaction),
    buildScheduleConfidentialPolicyTransitionTransaction: bind(
      buildScheduleConfidentialPolicyTransitionTransaction,
    ),
    buildCancelConfidentialPolicyTransitionTransaction: bind(
      buildCancelConfidentialPolicyTransitionTransaction,
    ),
    buildCreateElectionTransaction: bind(buildCreateElectionTransaction),
    buildSubmitBallotTransaction: bind(buildSubmitBallotTransaction),
    buildFinalizeElectionTransaction: bind(buildFinalizeElectionTransaction),
    buildRegisterSmartContractCodeTransaction: bind(
      buildRegisterSmartContractCodeTransaction,
    ),
    buildRegisterSmartContractBytesTransaction: bind(
      buildRegisterSmartContractBytesTransaction,
    ),
    buildRemoveSmartContractBytesTransaction: bind(
      buildRemoveSmartContractBytesTransaction,
    ),
    submitSignedTransaction: bind(submitSignedTransaction),
  });
}

function toBuffer(value, context = "signedTransaction") {
  if (Buffer.isBuffer(value)) {
    return Buffer.from(value);
  }
  if (ArrayBuffer.isView(value)) {
    return Buffer.from(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
  }
  if (value instanceof ArrayBuffer) {
    return Buffer.from(new Uint8Array(value));
  }
  throw new TypeError(`${context} must be a Buffer or ArrayBuffer view`);
}

// Retained privacy builders must invoke this guard with native-validated
// canonical manifest bytes before constructing any proof-bearing transaction.
export {
  requirePrivacyExact12CapabilityAdmissionV1,
} from "./privacyCapabilityAdmission.js";
