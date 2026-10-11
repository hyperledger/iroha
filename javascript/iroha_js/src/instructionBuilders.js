import { normalizeRetailFeeAssessment, rejectUnknownRetailFeeFields } from "./retailFeeAssessment.js";
import { createContractManifestNormalizer } from "./contractManifestNormalizer.js";
import { kaigiScalarBytesV1 } from "./kaigiScalarV1.js";
import { Buffer } from "buffer";
import { blake2b256 } from "./blake2b.js";
import { KAIGI_MAX_PARTICIPANTS_V1 } from "./commonLiterals.js";
import {
  noritoEncodeInstruction,
  validateSorafsReplicationOrderPayloadV1,
} from "./norito.js";
import { ensureCanonicalAccountId, normalizeAccountAliasLiteral, normalizeAccountId, normalizeAssetDefinitionId, normalizeAssetId, normalizeAssetHoldingId, normalizeRwaId } from "./normalizers.js";
import { MultisigSpec, MultisigSpecBuilder } from "./multisig.js";


import {
  createValidationError,
  ValidationErrorCode,
} from "./validationError.js";
import { canonicalizeDomainIdLabel } from "./domainId.js";

import { parseCanonicalContractAddress } from "./contractAddress.js";
import { stringifyStrictLosslessIntegerJson } from "./strictLosslessJson.js";
export {
  buildActivateRetailDailyLimitV1InstructionJson,
  buildBindRetailIdentityV1InstructionJson,
  buildRetailMonetaryMovementV1InstructionJson,
} from "./retailDailyLimitInstructions.js";
import { KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS, isCanonicalKotodamaDynamicAccessBaseKey, isKotodamaV1DynamicAccessBoundKind, isKotodamaV1StateMapKeyTypeName, kotodamaV1StateMapKeyTypeName } from "./kotodamaIdentifiers.js";
import {
  KotodamaQuantity,
  NumericV1,
  NumericV1Error,
} from "./numericV1.js";
import {
  LANE_PRIVACY_MERKLE_MAX_DEPTH,
  PROOF_BOX_MAX_ENCODED_BYTES,
  canonicalBase64DecodedLength,
  isPortableVerifyingKeyIdField,
  laneMerkleLeafIndexFitsDepth,
  proofBoxFitsEncodedBudget,
  proofBoxMaxProofBytes,
} from "./proofAttachment.js";
import {
  assertAllowedFields,
  assertExactNonBlankString,
  assertExactFields,
  assertString,
  assertWellFormedUtf16,
  canonicalHashLiteral,
  normalizeAssetDefinitionName,
  normalizeGovernanceSelectorV1,
  parseHashLiteral,
  parseHashLiteralToBuffer,
} from "./instructionBuilderPrimitives.js";

const TEXT_ASSET_DEFINITION_ID_2 = "assetDefinitionId";
const TEXT_MUST_BE = " must be ";
const TEXT_NON_NEGATIVE_INTEGER = "non-negative integer";
const TEXT_ACCOUNT_ID = "accountId";
const TEXT_SIGNER_ACCOUNT_ID = "signerAccountId";
const TEXT_VALID_BASE64_STRING = "valid base64 string";
const TEXT_UNSIGNED_INTEGER_BIGINT_OR_CANONICAL_DECIMAL_STRING = "unsigned integer, bigint, or canonical decimal string";
const TEXT_IS_REQUIRED = " is required";
const TEXT_UNSIGNED_64_BIT_INTEGER = " unsigned 64-bit integer";
const TEXT_CHUNK_COUNT_MUST_EQUAL_CEIL_TOTAL_SIZE_65536 = "chunkCount must equal ceil(totalSize / 65536)";
const TEXT_CONTRACT_ADDRESS = "contractAddress";
const TEXT_MUST_CONTAIN = " must contain ";
const TEXT_MUST_NOT_CONTAIN = " must not contain ";
const TEXT_NON_EMPTY_BYTE_ARRAY = "non-empty byte array";


const TEXT_UPLOAD_SMART_CONTRACT_CODE_CHUNK = "uploadSmartContractCodeChunk.";
const TEXT_REGISTER_ASSET_DEFINITION = "registerAssetDefinition.";
const TEXT_EXCEEDS_JAVA_SCRIPT_SAFE_INTEGER_RANGE = " exceeds JavaScript safe integer range";
const TEXT_MUST_FIT_IN_JAVA_SCRIPT_S_SAFE_INTEGER_RANGE = " must fit in JavaScript's safe integer range";
const TEXT_SET_ASSET_TRANSFER_AVAILABILITY = "setAssetTransferAvailability.";
const TEXT_LANE_PRIVACY_MERKLE = ".lanePrivacy.merkle.";
const TEXT_SET_ASSET_TRANSFER_CONTROL = "setAssetTransferControl.";
const TEXT_MUST_BE_A = (TEXT_MUST_BE + "a ");
const TEXT_MULTISIG_CONTRACT_CALL_PROPOSE = "multisigContractCallPropose.";
const TEXT_MULTISIG_CONTRACT_CALL_APPROVE = "multisigContractCallApprove.";
const TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_2 = "multisigContractCallPropose";
const TEXT_SCHEDULE_CONFIDENTIAL_POLICY_TRANSITION = "scheduleConfidentialPolicyTransition.";
const TEXT_MULTISIG_CONTRACT_CALL_APPROVE_2 = "multisigContractCallApprove";
const TEXT_FINALIZE_SMART_CONTRACT_CODE_UPLOAD = "finalizeSmartContractCodeUpload.";
const TEXT_SET_ASSET_TRANSFER_BLACKLIST = "setAssetTransferBlacklist.";
const TEXT_COMPLETE_REPLICATION_ORDER = "completeReplicationOrder.";
const TEXT_COMMIT_CONTRACT_DEPLOYMENT = "commitContractDeployment.";
const TEXT_ISSUE_REPLICATION_ORDER = "issueReplicationOrder.";
const TEXT_DESTINATION_ACCOUNT_ID = "destinationAccountId";
const TEXT_MUST_BE_EXACT_STANDARD_BASE64 = (TEXT_MUST_BE + "exact standard-base64");
const TEXT_MUST_BE_AN = (TEXT_MUST_BE + "an ");
const TEXT_REPORT_KAIGI_RELAY_HEALTH = "reportKaigiRelayHealth.";
const TEXT_REGISTER_SMART_CONTRACT_BYTES = "registerSmartContractBytes.";
const TEXT_ASSET_DEFINITION_ID = TEXT_ASSET_DEFINITION_ID_2;
const TEXT_MUST_CONTAIN_EXACTLY = (TEXT_MUST_CONTAIN + "exactly ");
const TEXT_CREATE_ELECTION = "createElection.";
const MIN_ELECTION_OPTIONS_V1 = 2;
const MAX_ELECTION_OPTIONS_V1 = 64;
const TEXT_MUST_BE_GREATER_THAN_ZERO = (TEXT_MUST_BE + "greater than zero");
const TEXT_MULTISIG_PROPOSE_2 = "multisigPropose";
const TEXT_GRANT_ACCOUNT_PERMISSION = "grantAccountPermission.";
const TEXT_INCLUSIVE_FOR_DETERMINISTIC_JSON_ENCODING = " (inclusive) for deterministic JSON encoding";
const TEXT_VALUE_PROGRAM = ".value.program_";
const TEXT_MUST_FIT_IN_AN_UNSIGNED_32_BIT_INTEGER = " must fit in an unsigned 32-bit integer";
const TEXT_MUST_BE_BETWEEN_0_AND = (TEXT_MUST_BE + "between 0 and ");
const TEXT_MUST_BE_AN_INTEGER_BETWEEN_0_AND_255 = ("]" + TEXT_MUST_BE + "an integer between 0 and 255");
const TEXT_PROPOSE_DEPLOY_CONTRACT = "proposeDeployContract";
const TEXT_SOURCE_ACCOUNT_ID = "sourceAccountId";
const TEXT_MUST_BE_EXACTLY = (TEXT_MUST_BE + "exactly ");
const TEXT_RECORD_KAIGI_USAGE = "recordKaigiUsage.";
const TEXT_VALUE_CHARGE = ".value.charge_";
const TEXT_PROPOSE_DEPLOY_CONTRACT_2 = "proposeDeployContract.";


// Alias the immutable public diagnostic codes without changing their values.
const V_CODE_INVALID_OBJECT = ValidationErrorCode.INVALID_OBJECT;
const V_CODE_INVALID_NUMERIC = ValidationErrorCode.INVALID_NUMERIC;
const V_CODE_VALUE_OUT_OF_RANGE = ValidationErrorCode.VALUE_OUT_OF_RANGE;
const V_CODE_INVALID_JSON_VALUE = ValidationErrorCode.INVALID_JSON_VALUE;
const V_CODE_INVALID_ACCOUNT_ID = ValidationErrorCode.INVALID_ACCOUNT_ID;
const V_CODE_INVALID_HEX = ValidationErrorCode.INVALID_HEX;
const V_CODE_INVALID_STRING = ValidationErrorCode.INVALID_STRING;
const V_CODE_INVALID_MULTIHASH = ValidationErrorCode.INVALID_MULTIHASH;

const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const MAX_SAFE_INTEGER_BIGINT = BigInt(MAX_SAFE_INTEGER);
const UINT64_MAX_BIGINT = 0xffff_ffff_ffff_ffffn;
const UINT128_MAX_BIGINT = (1n << 128n) - 1n;
const UINT32_MAX = 0xffff_ffff;
const GOVERNANCE_PRIVATE_KEY_FIELDS = new Set([
  "private_key",
  "privateKey",
  "private_key_hex",
  "privateKeyHex",
  "private_key_bytes",
  "privateKeyBytes",
  "private_key_seed",
  "privateKeySeed",
  "private_key_multihash",
  "privateKeyMultihash",
  "private_key_algorithm",
  "privateKeyAlgorithm",
]);
// Match the native Norito JSON map's lexicographic key order so the embedded
// public-input text is unchanged by canonical instruction encode/decode.
const GOVERNANCE_ZK_PUBLIC_INPUT_FIELDS = Object.freeze([
  "amount",
  "direction",
  "duration_blocks",
  "nullifier",
  "owner",
  "root_hint",
]);
export const SORAFS_REPLICATION_ORDER_MAX_PAYLOAD_BYTES_V1 = 1024 * 1024;
/** Maximum UTF-8 bytes accepted for a CancelAssetLock lock-id preimage. */
export const CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1 = 4_096;
/** Maximum UTF-8 bytes accepted for an asset-transfer availability reason. */
export const ASSET_TRANSFER_AVAILABILITY_MAX_REASON_BYTES_V1 = 512;
/** Maximum concurrent participants excluding the host in a first-release Kaigi call. */
export { KAIGI_MAX_PARTICIPANTS_V1 };
/** Maximum relay hops accepted by a first-release Kaigi manifest. */
export const KAIGI_RELAY_MANIFEST_MAX_HOPS_V1 = 8;
/** Maximum decoded bytes accepted for a first-release Kaigi HPKE public key. */
export const KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1 = 4_096;
const SORAFS_REPLICATION_ORDER_MAX_PAYLOAD_BASE64_CHARS_V1 =
  4 * Math.ceil(SORAFS_REPLICATION_ORDER_MAX_PAYLOAD_BYTES_V1 / 3);
function fail(code, message, path) {
  throw createValidationError(code, message, path);
}



function readSingleAlias(source, aliases, name, description) {
  const present = aliases.filter((key) => Object.prototype.hasOwnProperty.call(source, key));
  if (present.length > 1) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${name} must not include multiple ${description} aliases: ${present.join(", ")}`,
      name,
    );
  }
  if (present.length === 0) {
    return { key: null, value: undefined };
  }
  return { key: present[0], value: source[present[0]] };
}

function asQuantity(value, name) {
  try {
    if (value instanceof KotodamaQuantity) {
      return NumericV1.encodeQuantityJson(value);
    }
    if (typeof value === "string") {
      return NumericV1.decodeQuantityJson(value).toString();
    }
    if (typeof value === "bigint") {
      return new KotodamaQuantity(value, 0).toString();
    }
    fail(
      V_CODE_INVALID_NUMERIC,
      `${name}${TEXT_MUST_BE_A}KotodamaQuantity, canonical quantity string, or bigint; JavaScript numbers are not lossless quantity inputs`,
      name,
    );
  } catch (error) {
    if (!(error instanceof NumericV1Error)) throw error;
    const rangeFailure = error.code === "mantissa_overflow" || error.code === "invalid_scale";
    fail(
      rangeFailure ? V_CODE_VALUE_OUT_OF_RANGE : V_CODE_INVALID_NUMERIC,
      `${name}${TEXT_MUST_BE_A}canonical non-negative Kotodama V1 quantity (${error.code})`,
      name,
    );
  }
}

function asPositiveQuantity(value, name) {
  const canonical = asQuantity(value, name);
  if (NumericV1.decodeQuantityJson(canonical).mantissa <= 0n) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name}${TEXT_MUST_BE_GREATER_THAN_ZERO}`,
      name,
    );
  }
  return canonical;
}

function normalizeAssetLockId(value, name) {
  const lockId = assertExactNonBlankString(value, name);
  assertWellFormedUtf16(lockId, name);
  const lockIdBytes = Buffer.from(lockId, "utf8");
  if (lockIdBytes.length > CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name}${TEXT_MUST_BE}at most ${CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1} UTF-8 bytes`,
      name,
    );
  }
  return canonicalHashLiteral(blake2b256(lockIdBytes));
}

function asU128JsonNumber(value, name) {
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value) || value < 0) {
      fail(V_CODE_INVALID_NUMERIC, `${name}${TEXT_MUST_BE_A}${TEXT_NON_NEGATIVE_INTEGER}`, name);
    }
    if (!Number.isSafeInteger(value)) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name}${TEXT_MUST_BE_BETWEEN_0_AND}${MAX_SAFE_INTEGER}${TEXT_INCLUSIVE_FOR_DETERMINISTIC_JSON_ENCODING}`,
        name,
      );
    }
    return value;
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > MAX_SAFE_INTEGER_BIGINT) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name}${TEXT_MUST_BE_BETWEEN_0_AND}${MAX_SAFE_INTEGER}${TEXT_INCLUSIVE_FOR_DETERMINISTIC_JSON_ENCODING}`,
        name,
      );
    }
    return Number(value);
  }
  if (typeof value === "string") {
    if (!/^[0-9]+$/.test(value)) {
      fail(V_CODE_INVALID_NUMERIC, `${name}${TEXT_MUST_BE_A}non-negative integer string`, name);
    }
    const numeric = BigInt(value);
    if (numeric > MAX_SAFE_INTEGER_BIGINT) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name} exceeds the maximum JSON-safe integer (${MAX_SAFE_INTEGER}); supply a smaller value`,
        name,
      );
    }
    return Number(numeric);
  }
  fail(V_CODE_INVALID_NUMERIC, `${name}${TEXT_MUST_BE_A}${TEXT_NON_NEGATIVE_INTEGER}`, name);
}

function asPositiveInteger(value, name) {
  if (typeof value === "bigint") {
    if (value <= 0n) {
      fail(V_CODE_VALUE_OUT_OF_RANGE, `${name}${TEXT_MUST_BE_GREATER_THAN_ZERO}`, name);
    }
    if (value > MAX_SAFE_INTEGER_BIGINT) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name}${TEXT_EXCEEDS_JAVA_SCRIPT_SAFE_INTEGER_RANGE}`,
        name,
      );
    }
    return Number(value);
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value <= 0) {
      fail(V_CODE_INVALID_NUMERIC, `${name}${TEXT_MUST_BE_A}positive integer`, name);
    }
    if (!Number.isSafeInteger(value)) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name}${TEXT_EXCEEDS_JAVA_SCRIPT_SAFE_INTEGER_RANGE}`,
        name,
      );
    }
    return value;
  }
  if (typeof value === "string") {
    if (!/^[1-9]\d*$/.test(value)) {
      fail(V_CODE_INVALID_NUMERIC, `${name}${TEXT_MUST_BE_A}positive integer`, name);
    }
    const numeric = BigInt(value);
    if (numeric > MAX_SAFE_INTEGER_BIGINT) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name}${TEXT_EXCEEDS_JAVA_SCRIPT_SAFE_INTEGER_RANGE}`,
        name,
      );
    }
    return Number(numeric);
  }
  fail(V_CODE_INVALID_NUMERIC, `${name}${TEXT_MUST_BE_A}positive integer`, name);
}

function assertPlainObject(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_MUST_BE_A}plain object`, name);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_MUST_BE_A}plain object`, name);
  }
  return value;
}

function rejectGovernancePrivateKeyFieldsDeep(value, context) {
  const pending = [{ value, path: context }];
  const visited = new WeakSet();
  while (pending.length > 0) {
    const { value: candidate, path } = pending.pop();
    if (candidate === null || typeof candidate !== "object") {
      continue;
    }
    if (visited.has(candidate)) {
      continue;
    }
    visited.add(candidate);
    const prototype = Object.getPrototypeOf(candidate);
    if (
      !Array.isArray(candidate) &&
      prototype !== Object.prototype &&
      prototype !== null
    ) {
      continue;
    }
    for (const key of Reflect.ownKeys(candidate)) {
      if (key === "length") {
        continue;
      }
      const field = typeof key === "string" ? key : key.toString();
      if (typeof key === "string" && GOVERNANCE_PRIVATE_KEY_FIELDS.has(key)) {
        fail(
          V_CODE_INVALID_OBJECT,
          `${path} does not accept private-key field ${key}; sign the transaction locally`,
          `${path}.${key}`,
        );
      }
      const descriptor = Object.getOwnPropertyDescriptor(candidate, key);
      if (descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")) {
        pending.push({ value: descriptor.value, path: `${path}.${field}` });
      }
    }
  }
}

function normalizeJsonValue(value, path) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail(V_CODE_INVALID_JSON_VALUE, `${path}${TEXT_MUST_NOT_CONTAIN}non-finite numbers`, path);
    }
    return value;
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map((entry, index) =>
      normalizeJsonValue(entry, `${path}[${index}]`),
    );
  }
  if (typeof value === "object") {
    const result = {};
    for (const [key, nested] of Object.entries(value)) {
      if (typeof key !== "string" || key.length === 0) {
        fail(V_CODE_INVALID_JSON_VALUE, `${path} keys${TEXT_MUST_BE}non-empty strings`, path);
      }
      result[key] = normalizeJsonValue(nested, `${path}.${key}`);
    }
    return result;
  }
  fail(
    V_CODE_INVALID_JSON_VALUE,
    `${path} contains unsupported value type: ${typeof value}`,
    path,
  );
}

function normalizeMetadata(metadata) {
  if (metadata === undefined || metadata === null) {
    return {};
  }
  const base = assertPlainObject(metadata, "metadata");
  return normalizeJsonValue(base, "metadata");
}

function normalizeBooleanFlag(value, name) {
  if (value === undefined || value === null) {
    return false;
  }
  if (typeof value !== "boolean") {
    fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_MUST_BE_A}boolean`, name);
  }
  return value;
}

function normalizeJsonObjectLike(value, name) {
  if (typeof value === "string") {
    let parsed;
    try {
      parsed = JSON.parse(value);
    } catch (error) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}${TEXT_MUST_BE_A}plain object or JSON object string`,
        name,
      );
    }
    return assertPlainObject(parsed, name);
  }
  return assertPlainObject(value, name);
}

function normalizeOptionalString(value, name) {
  if (value === undefined || value === null) {
    return null;
  }
  return assertString(value, name);
}

function normalizeRwaParentRefs(value, path) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    fail(V_CODE_INVALID_OBJECT, `${path}${TEXT_MUST_BE_AN}array`, path);
  }
  return value.map((entry, index) => {
    const source = normalizeJsonObjectLike(entry, `${path}[${index}]`);
    return {
      rwa: normalizeRwaId(source.rwa, `${path}[${index}].rwa`),
      quantity: asQuantity(source.quantity, `${path}[${index}].quantity`),
    };
  });
}

function normalizeRwaControlPolicy(value, path) {
  const source =
    value === undefined || value === null ? {} : normalizeJsonObjectLike(value, path);
  const controllerAccountsInput =
    source.controllerAccounts ?? source.controller_accounts ?? [];
  const controllerRolesInput = source.controllerRoles ?? source.controller_roles ?? [];
  if (!Array.isArray(controllerAccountsInput)) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${path}.controllerAccounts${TEXT_MUST_BE}an array`,
      `${path}.controllerAccounts`,
    );
  }
  if (!Array.isArray(controllerRolesInput)) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${path}.controllerRoles${TEXT_MUST_BE}an array`,
      `${path}.controllerRoles`,
    );
  }
  return {
    controller_accounts: controllerAccountsInput.map((accountId, index) =>
      normalizeAccountId(accountId, `${path}.controllerAccounts[${index}]`),
    ),
    controller_roles: controllerRolesInput.map((roleId, index) =>
      assertString(roleId, `${path}.controllerRoles[${index}]`),
    ),
    freeze_enabled: normalizeBooleanFlag(
      source.freezeEnabled ?? source.freeze_enabled,
      `${path}.freezeEnabled`,
    ),
    hold_enabled: normalizeBooleanFlag(
      source.holdEnabled ?? source.hold_enabled,
      `${path}.holdEnabled`,
    ),
    force_transfer_enabled: normalizeBooleanFlag(
      source.forceTransferEnabled ?? source.force_transfer_enabled,
      `${path}.forceTransferEnabled`,
    ),
    redeem_enabled: normalizeBooleanFlag(
      source.redeemEnabled ?? source.redeem_enabled,
      `${path}.redeemEnabled`,
    ),
  };
}

function normalizeRegisterRwaPayload(value, path = "rwa") {
  const source = normalizeJsonObjectLike(value, path);
  return {
    domain: assertString(source.domain, `${path}.domain`),
    quantity: asQuantity(source.quantity, `${path}.quantity`),
    spec: normalizeJsonValue(assertPlainObject(source.spec, `${path}.spec`), `${path}.spec`),
    primary_reference: assertString(
      source.primaryReference ?? source.primary_reference,
      `${path}.primaryReference`,
    ),
    status: normalizeOptionalString(source.status, `${path}.status`),
    metadata:
      source.metadata === undefined || source.metadata === null
        ? {}
        : normalizeJsonValue(assertPlainObject(source.metadata, `${path}.metadata`), `${path}.metadata`),
    parents: normalizeRwaParentRefs(source.parents, `${path}.parents`),
    controls: normalizeRwaControlPolicy(source.controls, `${path}.controls`),
  };
}

function normalizeMergeRwasPayload(value, path = "merge") {
  const source = normalizeJsonObjectLike(value, path);
  return {
    parents: normalizeRwaParentRefs(source.parents, `${path}.parents`),
    primary_reference: assertString(
      source.primaryReference ?? source.primary_reference,
      `${path}.primaryReference`,
    ),
    status: normalizeOptionalString(source.status, `${path}.status`),
    metadata:
      source.metadata === undefined || source.metadata === null
        ? {}
        : normalizeJsonValue(assertPlainObject(source.metadata, `${path}.metadata`), `${path}.metadata`),
  };
}

function normalizeMultisigSpecPayload(spec, path) {
  if (spec instanceof MultisigSpec) {
    return spec.toPayload();
  }
  const source = assertPlainObject(spec, path);
  const builder = new MultisigSpecBuilder();
  const quorum = source.quorum ?? source.quorumRaw;
  if (quorum === undefined || quorum === null) {
    fail(
      V_CODE_INVALID_NUMERIC,
      `${path}.quorum${TEXT_IS_REQUIRED}`,
      `${path}.quorum`,
    );
  }
  builder.setQuorum(quorum);

  const ttl =
    source.transaction_ttl_ms ??
    source.transactionTtlMs ??
    source.transaction_ttl ??
    source.transactionTtl;
  if (ttl === undefined || ttl === null) {
    fail(
      V_CODE_INVALID_NUMERIC,
      `${path}.transaction_ttl_ms${TEXT_IS_REQUIRED}`,
      `${path}.transaction_ttl_ms`,
    );
  }
  builder.setTransactionTtlMs(ttl);

  const rawSignatories = source.signatories ?? source.members;
  const signatories = assertPlainObject(
    rawSignatories,
    `${path}.signatories`,
  );
  const entries = Object.entries(signatories);
  if (entries.length === 0) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${path}.signatories${TEXT_MUST_CONTAIN}at least one entry`,
      `${path}.signatories`,
    );
  }
  for (const [accountId, weight] of entries) {
    builder.addSignatory(accountId, weight);
  }
  return builder.build().toPayload();
}

function normalizeSafeIntegerJson(value, name, { allowNegative = false } = {}) {
  if (typeof value === "bigint") {
    if ((!allowNegative && value < 0n) || value < BigInt(Number.MIN_SAFE_INTEGER)) {
      fail(V_CODE_VALUE_OUT_OF_RANGE, `${name}${TEXT_MUST_FIT_IN_JAVA_SCRIPT_S_SAFE_INTEGER_RANGE}`, name);
    }
    if (value > MAX_SAFE_INTEGER_BIGINT) {
      fail(V_CODE_VALUE_OUT_OF_RANGE, `${name}${TEXT_MUST_FIT_IN_JAVA_SCRIPT_S_SAFE_INTEGER_RANGE}`, name);
    }
    return Number(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value)) {
      fail(V_CODE_INVALID_NUMERIC, `${name}${TEXT_MUST_BE_AN}integer`, name);
    }
    if (!allowNegative && value < 0) {
      fail(V_CODE_VALUE_OUT_OF_RANGE, `${name}${TEXT_MUST_BE}non-negative`, name);
    }
    if (!Number.isSafeInteger(value)) {
      fail(V_CODE_VALUE_OUT_OF_RANGE, `${name}${TEXT_MUST_FIT_IN_JAVA_SCRIPT_S_SAFE_INTEGER_RANGE}`, name);
    }
    return value;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    const pattern = allowNegative ? /^-?\d+$/ : /^\d+$/;
    if (!pattern.test(trimmed)) {
      fail(V_CODE_INVALID_NUMERIC, `${name}${TEXT_MUST_BE_AN}integer literal`, name);
    }
    const numeric = BigInt(trimmed);
    if ((!allowNegative && numeric < 0n) || numeric < BigInt(Number.MIN_SAFE_INTEGER)) {
      fail(V_CODE_VALUE_OUT_OF_RANGE, `${name}${TEXT_MUST_FIT_IN_JAVA_SCRIPT_S_SAFE_INTEGER_RANGE}`, name);
    }
    if (numeric > MAX_SAFE_INTEGER_BIGINT) {
      fail(V_CODE_VALUE_OUT_OF_RANGE, `${name}${TEXT_MUST_FIT_IN_JAVA_SCRIPT_S_SAFE_INTEGER_RANGE}`, name);
    }
    return Number(numeric);
  }
  fail(V_CODE_INVALID_NUMERIC, `${name}${TEXT_MUST_BE_AN}integer`, name);
}

function normalizeExecuteTriggerBuilderInput(triggerOrOptions, args, context = "executeTrigger") {
  if (typeof triggerOrOptions === "string") {
    return {
      trigger: assertString(triggerOrOptions, `${context}.trigger`),
      args:
        args === undefined
          ? null
          : normalizeJsonValue(args, `${context}.args`),
    };
  }
  const source = assertPlainObject(triggerOrOptions, context);
  return {
    trigger: assertString(
      source.trigger ?? source.triggerId,
      `${context}.trigger`,
    ),
    args:
      source.args === undefined
        ? null
        : normalizeJsonValue(source.args, `${context}.args`),
  };
}

function resolveMultisigTriggerArgs(options, context) {
  if (options.args !== undefined) {
    return normalizeJsonValue(options.args, `${context}.args`);
  }
  const preset = options.argPreset ?? options.preset;
  if (preset === undefined || preset === null) {
    return null;
  }
  return buildMultisigTriggerArgs(
    preset,
    options.argInput ?? options.presetInput ?? options.input ?? {},
  );
}

function normalizeMultisigExecuteTriggerOptions(options, context) {
  const source = assertPlainObject(options, context);
  const normalized = {
    trigger: assertString(source.trigger, `${context}.trigger`),
    args: resolveMultisigTriggerArgs(source, context),
    signerAccountId:
      source.signerAccountId === undefined || source.signerAccountId === null
        ? null
        : normalizeAccountId(source.signerAccountId, `${context}.${TEXT_SIGNER_ACCOUNT_ID}`),
    strictSignerCheck: Boolean(source.strictSignerCheck ?? source.strict_signer_check),
    multisigSpec:
      source.multisigSpec === undefined && source.spec === undefined
        ? null
        : normalizeMultisigSpecPayload(
            source.multisigSpec ?? source.spec,
            `${context}.multisigSpec`,
          ),
  };

  if (normalized.strictSignerCheck) {
    if (!normalized.multisigSpec) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${context}.multisigSpec is required when strictSignerCheck is true`,
        `${context}.multisigSpec`,
      );
    }
    if (!normalized.signerAccountId) {
      fail(
        V_CODE_INVALID_ACCOUNT_ID,
        `${context}.signerAccountId is required when strictSignerCheck is true`,
        `${context}.${TEXT_SIGNER_ACCOUNT_ID}`,
      );
    }
    if (!isMultisigSignerAuthorized(normalized.multisigSpec, normalized.signerAccountId)) {
      fail(
        V_CODE_INVALID_ACCOUNT_ID,
        `${context}.signerAccountId is not present in multisigSpec.signatories`,
        `${context}.${TEXT_SIGNER_ACCOUNT_ID}`,
      );
    }
  }

  return normalized;
}

function normalizeMultisigAccountSelectorInput(source, context) {
  const hasAccountId =
    source.multisigAccountId !== undefined ||
    source.multisig_account_id !== undefined;
  const hasAlias =
    source.multisigAccountAlias !== undefined ||
    source.multisig_account_alias !== undefined;
  if ((hasAccountId ? 1 : 0) + (hasAlias ? 1 : 0) !== 1) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${context} requires exactly one of multisigAccountId or multisigAccountAlias`,
      context,
    );
  }
  if (hasAccountId) {
    return {
      multisig_account_id: normalizeAccountId(
        source.multisigAccountId ?? source.multisig_account_id,
        `${context}.multisigAccountId`,
      ),
    };
  }
  const alias = normalizeAccountAliasLiteral(
    source.multisigAccountAlias ?? source.multisig_account_alias,
    `${context}.multisigAccountAlias`,
  );
  return {
    multisig_account_alias: alias,
  };
}

function rejectInlinePrivateKeyForMultisigRequest(source, context) {
  const retired = new Set([
    "privateKey",
    "private_key",
    "privateKeyHex",
    "private_key_hex",
    "privateKeyBytes",
    "private_key_bytes",
    "privateKeyMultihash",
    "private_key_multihash",
    "privateKeyAlgorithm",
    "private_key_algorithm",
  ]);
  const fields = Object.keys(source).filter((field) => retired.has(field));
  if (fields.length !== 0) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${context} does not accept private-key fields (${fields.join(", ")}); sign the returned transaction draft locally`,
      `${context}.privateKey`,
    );
  }
}

function normalizeOptionalHexString(value, name) {
  const literal = assertString(value, name);
  const compact = literal.replace(/^0x/i, "");
  if (!/^[0-9A-Fa-f]{64}$/.test(compact)) {
    fail(V_CODE_INVALID_HEX, `${name}${TEXT_MUST_BE_A}32-byte hex string`, name);
  }
  return compact.toLowerCase();
}

function normalizeOptionalExactBase64String(value, name) {
  const literal = assertString(value, name);
  if (literal.length === 0 || literal.trim() !== literal || /\s/u.test(literal)) {
    fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_EXACT_STANDARD_BASE64}`, name);
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(literal) || literal.length % 4 !== 0) {
    fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_EXACT_STANDARD_BASE64}`, name);
  }
  try {
    const decoded = Buffer.from(literal, "base64");
    if (decoded.length === 0 || decoded.toString("base64") !== literal) {
      fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_EXACT_STANDARD_BASE64}`, name);
    }
  } catch (error) {
    fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_EXACT_STANDARD_BASE64}`, name);
  }
  return literal;
}

function asNonNegativeInteger(value, name) {
  if (typeof value === "bigint") {
    if (value < 0n) {
      fail(V_CODE_VALUE_OUT_OF_RANGE, `${name}${TEXT_MUST_BE}greater than or equal to zero`, name);
    }
    if (value > MAX_SAFE_INTEGER_BIGINT) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name}${TEXT_EXCEEDS_JAVA_SCRIPT_SAFE_INTEGER_RANGE}`,
        name,
      );
    }
    const asNumber = Number(value);
    return asNumber;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      fail(V_CODE_INVALID_NUMERIC, `${name}${TEXT_MUST_BE_A}${TEXT_NON_NEGATIVE_INTEGER}`, name);
    }
    if (!Number.isSafeInteger(value)) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name}${TEXT_EXCEEDS_JAVA_SCRIPT_SAFE_INTEGER_RANGE}`,
        name,
      );
    }
    return value;
  }
  if (typeof value === "string") {
    if (!/^(?:0|[1-9]\d*)$/.test(value)) {
      fail(V_CODE_INVALID_NUMERIC, `${name}${TEXT_MUST_BE_A}${TEXT_NON_NEGATIVE_INTEGER}`, name);
    }
    const numeric = BigInt(value);
    if (numeric > MAX_SAFE_INTEGER_BIGINT) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name}${TEXT_EXCEEDS_JAVA_SCRIPT_SAFE_INTEGER_RANGE}`,
        name,
      );
    }
    return Number(numeric);
  }
  fail(V_CODE_INVALID_NUMERIC, `${name}${TEXT_MUST_BE_A}${TEXT_NON_NEGATIVE_INTEGER}`, name);
}

function asElectionTallyU128(value, name) {
  let integer;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail(V_CODE_INVALID_NUMERIC, `${name} must be a lossless non-negative integer`, name);
    }
    integer = BigInt(value);
  } else if (typeof value === "bigint") {
    integer = value;
  } else if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value)) {
    integer = BigInt(value);
  } else {
    fail(V_CODE_INVALID_NUMERIC, `${name} must be a canonical non-negative integer`, name);
  }
  if (integer < 0n || integer > UINT128_MAX_BIGINT) {
    fail(V_CODE_VALUE_OUT_OF_RANGE, `${name} must fit in unsigned 128 bits`, name);
  }
  return integer <= MAX_SAFE_INTEGER_BIGINT ? Number(integer) : integer;
}

function asKaigiU64(value, name) {
  const canonical = normalizeCanonicalU64(value, name);
  const numeric = BigInt(canonical);
  return numeric <= MAX_SAFE_INTEGER_BIGINT ? Number(numeric) : canonical;
}

function asPositiveKaigiU64(value, name) {
  const normalized = asKaigiU64(value, name);
  if (normalized === 0) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name}${TEXT_MUST_BE_GREATER_THAN_ZERO}`,
      name,
    );
  }
  return normalized;
}

function asKaigiParticipantLimit(value, name) {
  const canonical = normalizeCanonicalU64(value, name);
  const numeric = BigInt(canonical);
  if (numeric === 0n || numeric > BigInt(KAIGI_MAX_PARTICIPANTS_V1)) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name}${TEXT_MUST_BE_AN}integer between 1 and ${KAIGI_MAX_PARTICIPANTS_V1}`,
      name,
    );
  }
  return Number(numeric);
}

function asByte(value, name) {
  const numeric = asNonNegativeInteger(value, name);
  if (numeric > 0xff) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name}${TEXT_MUST_BE_AN}integer between 0 and 255`,
      name,
    );
  }
  return numeric;
}

function asNonZeroByte(value, name) {
  const numeric = asByte(value, name);
  if (numeric === 0) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name}${TEXT_MUST_BE_AN}integer between 1 and 255`,
      name,
    );
  }
  return numeric;
}

function toBinaryBuffer(value, name) {
  if (Buffer.isBuffer(value)) {
    return Buffer.from(value);
  }
  if (ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return Buffer.from(value);
  }
  if (Array.isArray(value)) {
    return Buffer.from(normalizeByteArray(value, name));
  }
  if (value && typeof value.length === "number" && typeof value !== "string") {
    return Buffer.from(normalizeByteArray(Array.from(value), name));
  }
  fail(
    V_CODE_INVALID_OBJECT,
    `${name}${TEXT_MUST_BE_A}Buffer, ArrayBuffer view, or byte array`,
    name,
  );
}

function normalizeHash(value, name) {
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.startsWith("hash:")) {
      return parseHashLiteral(trimmed, name);
    }
    if (!/^[0-9A-Fa-f]{64}$/.test(trimmed)) {
      fail(
        V_CODE_INVALID_HEX,
        `${name}${TEXT_MUST_BE_A}64-character hexadecimal string or hash literal`,
        name,
      );
    }
    return canonicalHashLiteral(Buffer.from(trimmed, "hex"));
  }
  const buffer = toBinaryBuffer(value, name);
  if (buffer.length !== 32) {
    fail(V_CODE_INVALID_HEX, `${name}${TEXT_MUST_BE}32 bytes`, name);
  }
  return canonicalHashLiteral(buffer);
}

function normalizeOptionalHash(value, name) {
  if (value === undefined || value === null) {
    return null;
  }
  return normalizeHash(value, name);
}

function normalizeKeyedHashInput(value, name) {
  const source = assertPlainObject(value, name);
  const pepperId =
    source.pepper_id ??
    source.pepperId ??
    source.pepper_id_hex ??
    source.pepper ??
    null;
  const digestValue =
    source.digest ??
    source.hash ??
    source.value ??
    source.bindingHash ??
    source.binding_hash;
  const pepper = assertString(
    pepperId,
    `${name}.pepperId`,
  );
  const digest = normalizeHash(
    digestValue,
    `${name}.digest`,
  );
  return {
    pepper_id: pepper,
    digest,
  };
}

function normalizeFixedBytes(value, name, length = 32) {
  if (value === undefined || value === null) {
    fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_IS_REQUIRED}`, name);
  }
  if (Array.isArray(value)) {
    if (value.length !== length) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name}${TEXT_MUST_CONTAIN_EXACTLY}${length} elements`,
        name,
      );
    }
    return value.map((byte, index) => {
      if (!Number.isInteger(byte) || byte < 0 || byte > 0xff) {
        fail(
          V_CODE_VALUE_OUT_OF_RANGE,
          `${name}[${index}${TEXT_MUST_BE_AN_INTEGER_BETWEEN_0_AND_255}`,
          `${name}[${index}]`,
        );
      }
      return byte;
    });
  }

  let buffer;
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.length === 0) {
      fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_A}non-empty string`, name);
    }
    if (trimmed.startsWith("hash:")) {
      buffer = parseHashLiteralToBuffer(trimmed, name);
    } else if (/^[0-9A-Fa-f]+$/.test(trimmed) && trimmed.length === length * 2) {
      buffer = Buffer.from(trimmed, "hex");
    } else {
      buffer = decodeBase64Strict(trimmed, name);
    }
  } else {
    buffer = toBinaryBuffer(value, name);
  }

  if (buffer.length !== length) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name}${TEXT_MUST_BE}${length} bytes; received ${buffer.length}`,
      name,
    );
  }

  return Array.from(buffer.values());
}

function normalizeOptionalFixedBytes(value, name, length = 32) {
  if (value === undefined || value === null) {
    return null;
  }
  return normalizeFixedBytes(value, name, length);
}

function normalizeByteArray(value, name) {
  if (value === undefined || value === null) {
    fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_IS_REQUIRED}`, name);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_A}${TEXT_NON_EMPTY_BYTE_ARRAY}`, name);
    }
    return value.map((byte, index) => {
      if (!Number.isInteger(byte) || byte < 0 || byte > 0xff) {
        fail(
          V_CODE_VALUE_OUT_OF_RANGE,
          `${name}[${index}${TEXT_MUST_BE_AN_INTEGER_BETWEEN_0_AND_255}`,
          `${name}[${index}]`,
        );
      }
      return byte;
    });
  }
  if (Buffer.isBuffer(value)) {
    if (value.length === 0) {
      fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_A}${TEXT_NON_EMPTY_BYTE_ARRAY}`, name);
    }
    return Array.from(value.values());
  }
  if (typeof value === "string") {
    const b64 = normalizeBase64(value, name);
    return Array.from(Buffer.from(b64, "base64").values());
  }
  const buffer = toBinaryBuffer(value, name);
  if (buffer.length === 0) {
    fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_A}${TEXT_NON_EMPTY_BYTE_ARRAY}`, name);
  }
  return Array.from(buffer.values());
}

function normalizeHexHashString(value, name) {
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!/^[0-9A-Fa-f]{64}$/.test(trimmed)) {
      fail(
        V_CODE_INVALID_HEX,
        `${name}${TEXT_MUST_BE_A}64-character hexadecimal string`,
        name,
      );
    }
    return trimmed.toLowerCase();
  }
  const buffer = toBinaryBuffer(value, name);
  if (buffer.length !== 32) {
    fail(V_CODE_INVALID_HEX, `${name}${TEXT_MUST_BE}32 bytes`, name);
  }
  return Buffer.from(buffer).toString("hex");
}

function normalizeGovernanceHex32(value, name) {
  if (typeof value !== "string") {
    return normalizeHexHashString(value, name);
  }
  const literal = assertString(value, name);
  let body = literal;
  const separator = literal.indexOf(":");
  if (separator !== -1) {
    const scheme = literal.slice(0, separator);
    if (scheme.length === 0 || scheme.toLowerCase() !== "blake2b32") {
      fail(
        V_CODE_INVALID_HEX,
        `${name} must use the optional blake2b32: scheme`,
        name,
      );
    }
    body = literal.slice(separator + 1);
  }
  if (body.startsWith("0x") || body.startsWith("0X")) {
    body = body.slice(2);
  }
  if (body.length !== 64 || !/^[0-9A-Fa-f]{64}$/u.test(body)) {
    fail(
      V_CODE_INVALID_HEX,
      `${name}${TEXT_MUST_BE_EXACTLY}32-byte hexadecimal with no whitespace`,
      name,
    );
  }
  return body.toLowerCase();
}

function normalizeGovernanceU64(value, name) {
  let integer;
  if (typeof value === "bigint") {
    integer = value;
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail(
        V_CODE_INVALID_NUMERIC,
        `${name}${TEXT_MUST_BE_A}lossless${TEXT_UNSIGNED_64_BIT_INTEGER}`,
        name,
      );
    }
    integer = BigInt(value);
  } else if (typeof value === "string") {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) {
      fail(
        V_CODE_INVALID_NUMERIC,
        `${name}${TEXT_MUST_BE_A}canonical${TEXT_UNSIGNED_64_BIT_INTEGER}`,
        name,
      );
    }
    integer = BigInt(value);
  } else {
    fail(
      V_CODE_INVALID_NUMERIC,
      `${name}${TEXT_MUST_BE_A}lossless${TEXT_UNSIGNED_64_BIT_INTEGER}`,
      name,
    );
  }
  if (integer < 0n || integer > UINT64_MAX_BIGINT) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name}${TEXT_MUST_BE}at most ${UINT64_MAX_BIGINT.toString(10)}`,
      name,
    );
  }
  return integer;
}

function asGovernanceU64JsonValue(value, name) {
  const integer = normalizeGovernanceU64(value, name);
  return integer <= MAX_SAFE_INTEGER_BIGINT ? Number(integer) : integer;
}

function normalizeVerifyingKeyId(value, name) {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value === "string") {
    const raw = value;
    if (raw.trim().length === 0) {
      fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_A}non-empty string`, name);
    }
    const parts = raw.split(":");
    if (parts.length !== 2 || parts[0].length === 0 || parts[1].length === 0) {
      fail(
        V_CODE_INVALID_STRING,
        `${name}${TEXT_MUST_BE}in 'backend:name' format`,
        name,
      );
    }
    const backend = parts[0];
    const keyName = parts[1];
    if (
      backend.trim().length === 0 ||
      keyName.trim().length === 0 ||
      backend.trim() !== backend ||
      keyName.trim() !== keyName
    ) {
      fail(
        V_CODE_INVALID_STRING,
        `${name}${TEXT_MUST_BE}in clean 'backend:name' format`,
        name,
      );
    }
    return {
      backend,
      name: keyName,
    };
  }
  const object = assertPlainObject(value, name);
  const allowedFields = new Set(["backend", "backendId", "name", "id", "key"]);
  for (const field of Object.keys(object)) {
    if (!allowedFields.has(field)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}.${field} is not supported`,
        `${name}.${field}`,
      );
    }
  }
  const backendAlias = readSingleAlias(
    object,
    ["backend", "backendId"],
    `${name}.backend`,
    "backend",
  );
  const nameAlias = readSingleAlias(
    object,
    ["name", "id", "key"],
    `${name}.name`,
    "name",
  );
  const backend = assertExactNonBlankString(backendAlias.value, `${name}.backend`);
  const keyName = assertExactNonBlankString(nameAlias.value, `${name}.name`);
  return { backend, name: keyName };
}

function normalizeConfidentialPolicyMode(value, name) {
  const raw = value ?? "Convertible";
  const normalized = String(raw)
    .trim()
    .toLowerCase()
    .replace(/[-_]/g, "");
  switch (normalized) {
    case "transparentonly":
      return "TransparentOnly";
    case "shieldedonly":
      return "ShieldedOnly";
    case "convertible":
      return "Convertible";
    default:
      fail(
        V_CODE_INVALID_STRING,
        `${name}${TEXT_MUST_BE}TransparentOnly, ShieldedOnly, or Convertible`,
        name,
      );
  }
}

function normalizeProofAttachment(value, name) {
  const source = assertPlainObject(value, name);
  const allowedFields = new Set([
    "backend",
    "proof",
    "verifyingKeyRef",
    "verifyingKeyCommitment",
    "envelopeHash",
    "lanePrivacy",
  ]);
  for (const field of Object.keys(source)) {
    if (!allowedFields.has(field)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}.${field} is not supported by the canonical ProofAttachment input`,
        `${name}.${field}`,
      );
    }
  }
  const backend = normalizePortableProofIdField(source.backend, `${name}.backend`);
  const proofBytes = normalizeBoundedProofBytes(source.proof, backend, `${name}.proof`);
  const proofBox = { backend, bytes: proofBytes };

  if (!Object.prototype.hasOwnProperty.call(source, "verifyingKeyRef")) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${name} must include verifyingKeyRef`,
      name,
    );
  }
  const payload = {
    backend,
    proof: proofBox,
    vk_commitment: null,
    envelope_hash: null,
    lane_privacy: null,
  };
  payload.vk_ref = normalizePortableProofVerifyingKeyId(
    source.verifyingKeyRef,
    `${name}.verifyingKeyRef`,
  );
  if (payload.vk_ref.backend !== backend) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${name}.verifyingKeyRef.backend must match ${name}.backend`,
      `${name}.verifyingKeyRef.backend`,
    );
  }

  const commitment = normalizeOptionalFixedBytes(
    source.verifyingKeyCommitment,
    `${name}.verifyingKeyCommitment`,
    32,
  );
  if (commitment) {
    assertNonZeroProofDigest(commitment, `${name}.verifyingKeyCommitment`);
    payload.vk_commitment = commitment;
  }
  const envelopeHash = normalizeOptionalFixedBytes(
    source.envelopeHash,
    `${name}.envelopeHash`,
    32,
  );
  if (envelopeHash) {
    assertNonZeroProofDigest(envelopeHash, `${name}.envelopeHash`);
    const expected = Array.from(blake2b256(Buffer.from(proofBytes)));
    expected[31] |= 1;
    if (!envelopeHash.every((byte, index) => byte === expected[index])) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}.envelopeHash must match the proof bytes`,
        `${name}.envelopeHash`,
      );
    }
    payload.envelope_hash = envelopeHash;
  }
  const lanePrivacy = source.lanePrivacy;
  if (lanePrivacy !== undefined && lanePrivacy !== null) {
    const lp = assertPlainObject(lanePrivacy, `${name}.lanePrivacy`);
    assertOnlyProofObjectKeys(
      lp,
      ["commitmentId", "merkle"],
      `${name}.lanePrivacy`,
    );
    const commitmentId = asNonNegativeInteger(
      lp.commitmentId,
      `${name}.lanePrivacy.commitmentId`,
    );
    if (commitmentId > 0xffff) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name}.lanePrivacy.commitmentId must fit within a u16`,
        `${name}.lanePrivacy.commitmentId`,
      );
    }
    const merklePayload = assertPlainObject(
      lp.merkle,
      `${name}.lanePrivacy.merkle`,
    );
    assertOnlyProofObjectKeys(
      merklePayload,
      ["leaf", "leafIndex", "auditPath"],
      `${name}.lanePrivacy.merkle`,
    );
    const leaf = normalizeFixedBytes(
      merklePayload.leaf,
      `${name}${TEXT_LANE_PRIVACY_MERKLE}leaf`,
      32,
    );
    const leafIndex = asNonNegativeInteger(
      merklePayload.leafIndex,
      `${name}${TEXT_LANE_PRIVACY_MERKLE}leafIndex`,
    );
    if (leafIndex > UINT32_MAX) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name}${TEXT_LANE_PRIVACY_MERKLE}leafIndex must fit within a u32`,
        `${name}${TEXT_LANE_PRIVACY_MERKLE}leafIndex`,
      );
    }
    const rawAudit = merklePayload.auditPath;
    if (!Array.isArray(rawAudit)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}${TEXT_LANE_PRIVACY_MERKLE}auditPath${TEXT_MUST_BE}an array`,
        `${name}${TEXT_LANE_PRIVACY_MERKLE}auditPath`,
      );
    }
    if (
      rawAudit.length === 0 ||
      rawAudit.length > LANE_PRIVACY_MERKLE_MAX_DEPTH
    ) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}${TEXT_LANE_PRIVACY_MERKLE}auditPath${TEXT_MUST_CONTAIN}1..=${LANE_PRIVACY_MERKLE_MAX_DEPTH} siblings`,
        `${name}${TEXT_LANE_PRIVACY_MERKLE}auditPath`,
      );
    }
    const auditPath = rawAudit.map((entry, index) => {
      if (entry === null || entry === undefined) {
        fail(
          V_CODE_INVALID_OBJECT,
          `${name}${TEXT_LANE_PRIVACY_MERKLE}auditPath[${index}]${TEXT_MUST_CONTAIN}a sibling`,
          `${name}${TEXT_LANE_PRIVACY_MERKLE}auditPath[${index}]`,
        );
      }
      return canonicalHashLiteral(
        normalizeFixedBytes(
          entry,
          `${name}${TEXT_LANE_PRIVACY_MERKLE}auditPath[${index}]`,
          32,
        ),
      );
    });
    if (!laneMerkleLeafIndexFitsDepth(leafIndex, auditPath.length)) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name}${TEXT_LANE_PRIVACY_MERKLE}leafIndex is impossible for the Merkle path depth`,
        `${name}${TEXT_LANE_PRIVACY_MERKLE}leafIndex`,
      );
    }
    // Match the native LaneCommitmentId tuple and HashOf JSON literal owners.
    payload.lane_privacy = {
      commitment_id: [commitmentId],
      witness: {
        kind: "merkle",
        payload: {
          leaf,
          proof: {
            leaf_index: leafIndex,
            audit_path: auditPath,
          },
        },
      },
    };
  }
  return payload;
}

function normalizePortableProofIdField(value, name) {
  if (!isPortableVerifyingKeyIdField(value)) {
    fail(
      V_CODE_INVALID_STRING,
      `${name} must use the exact portable verifier-key registry grammar`,
      name,
    );
  }
  return value;
}

function normalizePortableProofVerifyingKeyId(value, name) {
  const object = assertPlainObject(value, name);
  assertOnlyProofObjectKeys(object, ["backend", "name"], name);
  return {
    backend: normalizePortableProofIdField(object.backend, `${name}.backend`),
    name: normalizePortableProofIdField(object.name, `${name}.name`),
  };
}

function assertOnlyProofObjectKeys(value, expectedKeys, name) {
  const actualKeys = Object.keys(value);
  if (
    actualKeys.length !== expectedKeys.length ||
    expectedKeys.some((key) => !Object.prototype.hasOwnProperty.call(value, key))
  ) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${name}${TEXT_MUST_CONTAIN_EXACTLY}${expectedKeys.join(", ")}`,
      name,
    );
  }
}

function normalizeBoundedProofBytes(value, backend, name) {
  const maxProofBytes = proofBoxMaxProofBytes(backend);
  if (typeof value === "string") {
    const maxBase64Length = Math.ceil(maxProofBytes / 3) * 4;
    if (value.length > maxBase64Length) {
      failProofBoxBudget(name);
    }
    let decodedLength;
    try {
      decodedLength = canonicalBase64DecodedLength(value, name);
    } catch {
      fail(
        V_CODE_INVALID_STRING,
        `${name}${TEXT_MUST_BE}canonical standard base64`,
        name,
      );
    }
    if (decodedLength > maxProofBytes) {
      failProofBoxBudget(name);
    }
    const decoded = Buffer.from(value, "base64");
    if (decoded.toString("base64") !== value) {
      fail(
        V_CODE_INVALID_STRING,
        `${name}${TEXT_MUST_BE}canonical standard base64`,
        name,
      );
    }
    return Array.from(decoded.values());
  }

  const declaredLength = proofBinaryByteLength(value);
  if (declaredLength !== null && declaredLength > maxProofBytes) {
    failProofBoxBudget(name);
  }
  const proof = normalizeByteArray(value, name);
  if (!proofBoxFitsEncodedBudget(backend, proof.length)) {
    failProofBoxBudget(name);
  }
  return proof;
}

function proofBinaryByteLength(value) {
  if (Array.isArray(value) || Buffer.isBuffer(value)) {
    return value.length;
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    return value.byteLength;
  }
  return null;
}

function failProofBoxBudget(name) {
  fail(
    V_CODE_VALUE_OUT_OF_RANGE,
    `${name} exceeds the complete ${PROOF_BOX_MAX_ENCODED_BYTES}-byte ProofBox limit`,
    name,
  );
}

function assertNonZeroProofDigest(bytes, name) {
  if (bytes.every((byte) => byte === 0)) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${name}${TEXT_MUST_BE}non-zero`,
      name,
    );
  }
}

function normalizeU32(value, name) {
  const numeric = asNonNegativeInteger(value, name);
  if (numeric > UINT32_MAX) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name}${TEXT_MUST_FIT_IN_AN_UNSIGNED_32_BIT_INTEGER}`,
      name,
    );
  }
  return numeric;
}

function normalizePositiveU32(value, name) {
  const numeric = asPositiveInteger(value, name);
  if (numeric > UINT32_MAX) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name}${TEXT_MUST_FIT_IN_AN_UNSIGNED_32_BIT_INTEGER}`,
      name,
    );
  }
  return numeric;
}

function normalizeAccessSetHints(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  const hints = assertPlainObject(value, context);
  const normalizeKeys = (keys, name) => {
    if (keys === undefined || keys === null) {
      return [];
    }
    if (!Array.isArray(keys)) {
      fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_MUST_BE_AN}array of strings`, name);
    }
    return keys.map((entry, index) =>
      assertString(entry, `${name}[${index}]`),
    );
  };
  const normalizeDynamicHints = (entries, name) => {
    if (entries === undefined || entries === null) {
      return [];
    }
    if (!Array.isArray(entries)) {
      fail(V_CODE_INVALID_OBJECT, `${name}${TEXT_MUST_BE_AN}array of dynamic access hints`, name);
    }
    return entries.map((entry, index) => {
      const hint = assertPlainObject(entry, `${name}[${index}]`);
      const hintName = `${name}[${index}]`;
      const maxKeys = asNonNegativeInteger(
        selectEqualManifestAlias(
          hint,
          "max_keys",
          "maxKeys",
          `${hintName}.maxKeys`,
        ),
        `${hintName}.maxKeys`,
      );
      if (maxKeys === 0) {
        fail(
          V_CODE_VALUE_OUT_OF_RANGE,
          `${hintName}.maxKeys${TEXT_MUST_BE}positive`,
          `${hintName}.maxKeys`,
        );
      }
      if (maxKeys > KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS) {
        fail(
          V_CODE_VALUE_OUT_OF_RANGE,
          `${hintName}.maxKeys${TEXT_MUST_BE}at most ${KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS}`,
          `${hintName}.maxKeys`,
        );
      }
      const keyType = assertString(
        selectEqualManifestAlias(
          hint,
          "key_type",
          "keyType",
          `${hintName}.keyType`,
        ),
        `${hintName}.keyType`,
      );
      if (!isKotodamaV1StateMapKeyTypeName(keyType)) {
        fail(
          V_CODE_INVALID_STRING,
          `${hintName}.keyType${TEXT_MUST_BE}an exact Kotodama V1 StateMap key scalar`,
          `${hintName}.keyType`,
        );
      }
      const baseKey = assertString(
        selectEqualManifestAlias(
          hint,
          "base_key",
          "baseKey",
          `${hintName}.baseKey`,
        ),
        `${hintName}.baseKey`,
      );
      if (!isCanonicalKotodamaDynamicAccessBaseKey(baseKey)) {
        fail(
          V_CODE_INVALID_STRING,
          `${hintName}.baseKey${TEXT_MUST_BE}state: plus one canonical state declaration identifier`,
          `${hintName}.baseKey`,
        );
      }
      const boundKind = assertString(
        selectEqualManifestAlias(
          hint,
          "bound_kind",
          "boundKind",
          `${hintName}.boundKind`,
        ),
        `${hintName}.boundKind`,
      );
      if (!isKotodamaV1DynamicAccessBoundKind(boundKind)) {
        fail(
          V_CODE_INVALID_STRING,
          `${hintName}.boundKind must be exactly take or page`,
          `${hintName}.boundKind`,
        );
      }
      return {
        base_key: baseKey,
        key_type: keyType,
        bound_kind: boundKind,
        max_keys: maxKeys,
      };
    });
  };
  return {
    read_keys: normalizeKeys(
      hints.read_keys ?? hints.readKeys,
      `${context}.readKeys`,
    ),
    write_keys: normalizeKeys(
      hints.write_keys ?? hints.writeKeys,
      `${context}.writeKeys`,
    ),
    dynamic_reads: normalizeDynamicHints(
      hints.dynamic_reads ?? hints.dynamicReads,
      `${context}.dynamicReads`,
    ),
    dynamic_writes: normalizeDynamicHints(
      hints.dynamic_writes ?? hints.dynamicWrites,
      `${context}.dynamicWrites`,
    ),
  };
}

function validateManifestDynamicAccessHintStateMaps(manifest) {
  const hints = manifest.access_set_hints;
  if (hints === null) {
    return;
  }
  const stateMaps = new Map();
  for (const state of manifest.states ?? []) {
    const keyType = kotodamaV1StateMapKeyTypeName(state.type_name);
    if (keyType !== null) {
      stateMaps.set(state.name, keyType);
    }
  }
  for (const field of ["dynamic_reads", "dynamic_writes"]) {
    const seen = new Set();
    hints[field].forEach((hint, index) => {
      const hintName = `manifest.accessSetHints.${field === "dynamic_reads" ? "dynamicReads" : "dynamicWrites"}[${index}]`;
      const identity = JSON.stringify([
        hint.base_key,
        hint.key_type,
        hint.bound_kind,
        hint.max_keys,
      ]);
      if (seen.has(identity)) {
        fail(
          V_CODE_INVALID_OBJECT,
          `${hintName} duplicates an earlier dynamic access hint`,
          hintName,
        );
      }
      seen.add(identity);
      const stateName = hint.base_key.slice("state:".length);
      const expectedKeyType = stateMaps.get(stateName);
      if (expectedKeyType === undefined) {
        fail(
          V_CODE_INVALID_OBJECT,
          `${hintName}.baseKey must reference a declared top-level StateMap`,
          `${hintName}.baseKey`,
        );
      }
      if (hint.key_type !== expectedKeyType) {
        fail(
          V_CODE_INVALID_OBJECT,
          `${hintName}.keyType ${hint.key_type} does not match declared StateMap key type ${expectedKeyType}`,
          `${hintName}.keyType`,
        );
      }
    });
  }
}

function selectEqualManifestAlias(source, snakeCase, camelCase, name) {
  const hasSnakeCase = Object.prototype.hasOwnProperty.call(source, snakeCase);
  const hasCamelCase = Object.prototype.hasOwnProperty.call(source, camelCase);
  if (
    hasSnakeCase &&
    hasCamelCase &&
    !Object.is(source[snakeCase], source[camelCase])
  ) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${name} contains conflicting ${snakeCase}/${camelCase} aliases`,
      name,
    );
  }
  if (hasSnakeCase) {
    return source[snakeCase];
  }
  return hasCamelCase ? source[camelCase] : undefined;
}

function decodeBase64Strict(value, name) {
  const compact = value.replace(/\s+/g, "");
  if (compact.length === 0) {
    fail(
      V_CODE_INVALID_STRING,
      `${name}${TEXT_MUST_BE_A}non-empty base64 string`,
      name,
    );
  }

  let padded = compact;
  const paddingIndex = compact.indexOf("=");
  if (paddingIndex !== -1) {
    const head = compact.slice(0, paddingIndex);
    const padding = compact.slice(paddingIndex);
    if (!/^[0-9A-Za-z+/]*$/.test(head) || !/^={1,2}$/.test(padding)) {
      fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_A}${TEXT_VALID_BASE64_STRING}`, name);
    }
    if (compact.length % 4 !== 0) {
      fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_A}${TEXT_VALID_BASE64_STRING}`, name);
    }
  } else {
    if (!/^[0-9A-Za-z+/]+$/.test(compact) || compact.length % 4 === 1) {
      fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_A}${TEXT_VALID_BASE64_STRING}`, name);
    }
    const padLength = (4 - (compact.length % 4)) % 4;
    padded = compact + "=".repeat(padLength);
  }

  const decoded = Buffer.from(padded, "base64");
  if (decoded.toString("base64") !== padded) {
    fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_A}${TEXT_VALID_BASE64_STRING}`, name);
  }
  return decoded;
}

function normalizeBase64(value, name) {
  if (typeof value === "string") {
    return decodeBase64Strict(value.trim(), name).toString("base64");
  }
  const buffer = toBinaryBuffer(value, name);
  if (buffer.length === 0) {
    fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_A}non-empty base64 string`, name);
  }
  return buffer.toString("base64");
}

function normalizeOptionalBase64(value, name) {
  if (value === undefined || value === null) {
    return null;
  }
  return normalizeBase64(value, name);
}

function normalizeKaigiHpkePublicKey(value, name) {
  const key =
    typeof value === "string"
      ? decodeBase64Strict(value.trim(), name)
      : toBinaryBuffer(value, name);
  if (key.length === 0) {
    fail(
      V_CODE_INVALID_STRING,
      `${name}${TEXT_MUST_BE_A}non-empty HPKE public key`,
      name,
    );
  }
  if (key.length > KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name} must not exceed ${KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1} decoded bytes`,
      name,
    );
  }
  return key.toString("base64");
}

function normalizeKaigiId(value, name) {
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.length === 0 || !trimmed.includes(":")) {
      fail(
        V_CODE_INVALID_STRING,
        `${name}${TEXT_MUST_BE}in 'domain:callName' format`,
        name,
      );
    }
    const [domain, ...rest] = trimmed.split(":");
    const call = rest.join(":");
    return {
      domain_id: assertString(domain, `${name}.domain_id`),
      call_name: assertString(call, `${name}.call_name`),
    };
  }
  const object = assertPlainObject(value, name);
  const domainId = object.domain_id ?? object.domainId;
  const callName = object.call_name ?? object.callName ?? object.name;
  return {
    domain_id: assertString(domainId, `${name}.domain_id`),
    call_name: assertString(callName, `${name}.call_name`),
  };
}

function normalizeCanonicalKaigiId(value, name) {
  const normalized = normalizeKaigiId(value, name);
  const domainSegments = normalized.domain_id.split(".");
  if (domainSegments.length !== 2 || domainSegments.some((segment) => segment.length === 0)) {
    fail(
      V_CODE_INVALID_STRING,
      `${name}.domain_id must use the exact domain.dataspace form`,
      `${name}.domain_id`,
    );
  }
  let domainId;
  try {
    domainId = domainSegments
      .map((segment) => canonicalizeDomainIdLabel(segment, `${name}.domain_id label`))
      .join(".");
  } catch {
    fail(
      V_CODE_INVALID_STRING,
      `${name}.domain_id${TEXT_MUST_BE}a valid domain.dataspace identifier`,
      `${name}.domain_id`,
    );
  }

  assertWellFormedUtf16(normalized.call_name, `${name}.call_name`);
  const callName = normalized.call_name.normalize("NFC");
  if (
    Buffer.byteLength(callName, "utf8") > 255 ||
    /[\p{Cc}\p{White_Space}@#$]/u.test(callName) ||
    /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(callName)
  ) {
    fail(
      V_CODE_INVALID_STRING,
      `${name}.call_name${TEXT_MUST_BE}a canonical Iroha Name`,
      `${name}.call_name`,
    );
  }
  return { domain_id: domainId, call_name: callName };
}

function normalizeKaigiRelayHop(value, context) {
  const hop = assertPlainObject(value, context);
  const relayId = hop.relay_id ?? hop.relayId;
  const hpkeKey = hop.hpke_public_key ?? hop.hpkePublicKey;
  return {
    relay_id: normalizeAccountId(relayId, `${context}.relayId`),
    hpke_public_key: normalizeKaigiHpkePublicKey(
      hpkeKey,
      `${context}.hpkePublicKey`,
    ),
    weight: asNonZeroByte(hop.weight ?? 1, `${context}.weight`),
  };
}

function normalizeKaigiRelayManifest(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  const manifest = assertPlainObject(value, context);
  const expiryMs = manifest.expiry_ms ?? manifest.expiryMs;
  const hopsValue = manifest.hops;
  if (!Array.isArray(hopsValue)) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${context}.hops${TEXT_MUST_BE}an array`,
      `${context}.hops`,
    );
  }
  if (hopsValue.length < 3) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${context}.hops must include at least three relay hops`,
      `${context}.hops`,
    );
  }
  if (hopsValue.length > KAIGI_RELAY_MANIFEST_MAX_HOPS_V1) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${context}.hops must not exceed ${KAIGI_RELAY_MANIFEST_MAX_HOPS_V1} relay hops`,
      `${context}.hops`,
    );
  }
  for (let index = 0; index < hopsValue.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(hopsValue, index)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${context}.hops${TEXT_MUST_BE}a dense array`,
        `${context}.hops[${index}]`,
      );
    }
  }
  const hops = hopsValue.map((hop, index) =>
    normalizeKaigiRelayHop(hop, `${context}.hops[${index}]`),
  );
  const seenRelayIds = new Set();
  for (let index = 0; index < hops.length; index += 1) {
    const relayId = hops[index].relay_id;
    if (seenRelayIds.has(relayId)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${context}.hops${TEXT_MUST_NOT_CONTAIN}duplicate relays`,
        `${context}.hops[${index}].relayId`,
      );
    }
    seenRelayIds.add(relayId);
  }
  return {
    hops,
    expiry_ms: asKaigiU64(expiryMs, `${context}.expiryMs`),
  };
}

function normalizePrivacyMode(value) {
  if (value && typeof value === "object") {
    const modeValue = value.mode ?? value.Mode ?? value.privacyMode ?? value.state;
    if (value.state !== undefined && value.state !== null) {
      fail(
        V_CODE_INVALID_OBJECT,
        ("privacyMode.state" + TEXT_MUST_BE + "null because Kaigi privacy modes are unit variants"),
        "privacyMode.state",
      );
    }
    return {
      mode: normalizePrivacyModeTag(modeValue),
      state: null,
    };
  }
  return {
    mode: normalizePrivacyModeTag(value),
    state: null,
  };
}

function normalizePrivacyModeTag(value) {
  if (value === undefined || value === null) {
    return "Transparent";
  }
  const normalized = String(value).trim().toLowerCase();
  if (normalized === "transparent") {
    return "Transparent";
  }
  if (
    normalized === "zkrosterv1" ||
    normalized === "zk_roster_v1" ||
    normalized === "zk-roster-v1" ||
    normalized === "zkroster-v1"
  ) {
    return "ZkRosterV1";
  }
  fail(
    V_CODE_INVALID_STRING,
    ("privacyMode" + TEXT_MUST_BE + "either 'Transparent' or 'ZkRosterV1'"),
  );
}

function normalizeRoomPolicy(value) {
  if (value && typeof value === "object") {
    const policyValue =
      value.policy ?? value.Policy ?? value.roomPolicy ?? value.state;
    if (value.state !== undefined && value.state !== null) {
      fail(
        V_CODE_INVALID_OBJECT,
        ("roomPolicy.state" + TEXT_MUST_BE + "null because Kaigi room policies are unit variants"),
        "roomPolicy.state",
      );
    }
    return {
      policy: normalizeRoomPolicyTag(policyValue),
      state: null,
    };
  }
  return {
    policy: normalizeRoomPolicyTag(value),
    state: null,
  };
}

function normalizeRoomPolicyTag(value) {
  if (value === undefined || value === null) {
    return "Authenticated";
  }
  const normalized = String(value).trim().toLowerCase();
  if (
    normalized === "public" ||
    normalized === "read-only" ||
    normalized === "read_only" ||
    normalized === "open"
  ) {
    return "Public";
  }
  if (
    normalized === "authenticated" ||
    normalized === "auth" ||
    normalized === "protected"
  ) {
    return "Authenticated";
  }
  fail(
    V_CODE_INVALID_STRING,
    ("roomPolicy" + TEXT_MUST_BE + "either 'Public' or 'Authenticated'"),
  );
}

function normalizeOptionalKaigiScalarV1(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  try {
    return Array.from(kaigiScalarBytesV1(value, context));
  } catch (error) {
    fail(V_CODE_INVALID_OBJECT, error.message, context);
  }
}

function normalizeKaigiParticipantCommitment(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  const commitment = assertPlainObject(value, context);
  if (Object.keys(commitment).length !== 1 || !("commitment" in commitment)) {
    fail(V_CODE_INVALID_OBJECT, `${context} requires only commitment`, context);
  }
  const scalar = normalizeOptionalKaigiScalarV1(commitment.commitment, `${context}.commitment`);
  if (scalar === null) {
    fail(V_CODE_INVALID_OBJECT, `${context}.commitment${TEXT_IS_REQUIRED}`, context);
  }
  return { commitment: scalar };
}

function normalizeKaigiParticipantNullifier(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  const nullifier = assertPlainObject(value, context);
  if (Object.keys(nullifier).length !== 1 || !("digest" in nullifier)) {
    fail(V_CODE_INVALID_OBJECT, `${context} requires only digest`, context);
  }
  const digest = normalizeOptionalKaigiScalarV1(nullifier.digest, `${context}.digest`);
  if (digest === null) {
    fail(V_CODE_INVALID_OBJECT, `${context}.digest${TEXT_IS_REQUIRED}`, context);
  }
  return { digest };
}

function normalizeNewKaigi(options) {
  const source = assertPlainObject(options, "createKaigi.call");
  const idValue = source.id ?? source.callId ?? source.call_id;
  const hostValue = source.host ?? source.hostAccountId ?? source.authority;
  const titleValue = source.title ?? null;
  const descriptionValue = source.description ?? null;
  const maxParticipantsValue = source.max_participants ?? source.maxParticipants;
  const gasRateValue =
    source.gas_rate_per_minute ?? source.gasRatePerMinute ?? source.gasRate ?? 0;
  const scheduledStartValue =
    source.scheduled_start_ms ?? source.scheduledStartMs ?? null;
  const billingAccountValue =
    source.billing_account ?? source.billingAccount ?? null;
  const privacyValue =
    source.privacy_mode ?? source.privacyMode ?? source.privacy ?? "Transparent";
  const roomPolicyValue =
    source.room_policy ?? source.roomPolicy ?? source.roomAccess ?? "authenticated";
  const relayManifestValue =
    source.relay_manifest ?? source.relayManifest ?? null;

  const call = {
    id: normalizeKaigiId(idValue, "call.id"),
    host: normalizeAccountId(hostValue, "call.host"),
    title:
      titleValue === undefined || titleValue === null
        ? null
        : assertString(titleValue, "call.title"),
    description:
      descriptionValue === undefined || descriptionValue === null
        ? null
        : assertString(descriptionValue, "call.description"),
    max_participants:
      maxParticipantsValue === undefined || maxParticipantsValue === null
        ? null
        : asKaigiParticipantLimit(maxParticipantsValue, "call.maxParticipants"),
    gas_rate_per_minute: asKaigiU64(
      gasRateValue,
      "call.gasRatePerMinute",
    ),
    metadata: normalizeMetadata(source.metadata),
    scheduled_start_ms:
      scheduledStartValue === undefined || scheduledStartValue === null
        ? null
        : asKaigiU64(
            scheduledStartValue,
            "call.scheduledStartMs",
          ),
    billing_account:
      billingAccountValue === undefined || billingAccountValue === null
        ? null
        : normalizeAccountId(
            billingAccountValue,
            "call.billingAccount",
          ),
    privacy_mode: normalizePrivacyMode(privacyValue),
    room_policy: normalizeRoomPolicy(roomPolicyValue),
    relay_manifest: normalizeKaigiRelayManifest(
      relayManifestValue,
      "call.relayManifest",
    ),
  };

  return call;
}

function normalizeCreateKaigiInput(options) {
  const source = assertPlainObject(options, "createKaigi");
  const callSource =
    source.call && typeof source.call === "object" && !Array.isArray(source.call)
      ? source.call
      : source;
  return {
    call: normalizeNewKaigi(callSource),
    commitment: normalizeKaigiParticipantCommitment(
      source.commitment,
      "createKaigi.commitment",
    ),
    nullifier: normalizeKaigiParticipantNullifier(
      source.nullifier,
      "createKaigi.nullifier",
    ),
    roster_root: normalizeOptionalHash(
      source.roster_root ?? source.rosterRoot,
      "createKaigi.rosterRoot",
    ),
    proof: normalizeOptionalBase64(
      source.proof,
      "createKaigi.proof",
    ),
  };
}

function normalizeJoinOrLeaveInput(type, options) {
  const source = assertPlainObject(options, type);
  const callId = source.call_id ?? source.callId ?? source.id;
  const participant = source.participant ?? source.accountId;
  const normalized = {
    call_id: normalizeKaigiId(callId, `${type}.callId`),
    participant: normalizeAccountId(
      participant,
      `${type}.participant`,
    ),
    commitment: normalizeKaigiParticipantCommitment(
      source.commitment,
      `${type}.commitment`,
    ),
    nullifier: normalizeKaigiParticipantNullifier(
      source.nullifier,
      `${type}.nullifier`,
    ),
    roster_root: normalizeOptionalHash(
      source.roster_root ?? source.rosterRoot,
      `${type}.rosterRoot`,
    ),
    proof: normalizeOptionalBase64(source.proof, `${type}.proof`),
  };
  return normalized;
}

function normalizeEndKaigiInput(options) {
  const source = assertPlainObject(options, "endKaigi");
  const callId = source.call_id ?? source.callId ?? source.id;
  const endedValue =
    source.ended_at_ms ?? source.endedAtMs ?? source.endedAt ?? null;
  return {
    call_id: normalizeKaigiId(callId, "endKaigi.callId"),
    ended_at_ms:
      endedValue === null || endedValue === undefined
        ? null
        : asKaigiU64(endedValue, "endKaigi.endedAtMs"),
    commitment: normalizeKaigiParticipantCommitment(
      source.commitment,
      "endKaigi.commitment",
    ),
    nullifier: normalizeKaigiParticipantNullifier(
      source.nullifier,
      "endKaigi.nullifier",
    ),
    roster_root: normalizeOptionalHash(
      source.roster_root ?? source.rosterRoot,
      "endKaigi.rosterRoot",
    ),
    proof: normalizeOptionalBase64(source.proof, "endKaigi.proof"),
  };
}

function normalizeKaigiUsageInput(options) {
  const source = assertPlainObject(options, "recordKaigiUsage");
  const callId = source.call_id ?? source.callId ?? source.id;
  return {
    call_id: normalizeKaigiId(callId, (TEXT_RECORD_KAIGI_USAGE + "callId")),
    duration_ms: asPositiveKaigiU64(
      source.duration_ms ?? source.durationMs ?? source.duration,
      (TEXT_RECORD_KAIGI_USAGE + "durationMs"),
    ),
    billed_gas: asKaigiU64(
      source.billed_gas ?? source.billedGas ?? source.gas ?? 0,
      (TEXT_RECORD_KAIGI_USAGE + "billedGas"),
    ),
    usage_commitment: normalizeOptionalKaigiScalarV1(
      source.usage_commitment ?? source.usageCommitment,
      (TEXT_RECORD_KAIGI_USAGE + "usageCommitment"),
    ),
    proof: normalizeOptionalBase64(
      source.proof,
      (TEXT_RECORD_KAIGI_USAGE + "proof"),
    ),
  };
}

function normalizeSetRelayManifestInput(options) {
  const source = assertPlainObject(options, "setKaigiRelayManifest");
  const callId = source.call_id ?? source.callId ?? source.id;
  return {
    call_id: normalizeKaigiId(callId, "setKaigiRelayManifest.callId"),
    relay_manifest: normalizeKaigiRelayManifest(
      source.relay_manifest ?? source.relayManifest,
      "setKaigiRelayManifest.relayManifest",
    ),
  };
}

function normalizeRegisterRelayInput(options) {
  const source = assertPlainObject(options, "registerKaigiRelay");
  const relay = source.relay ?? source.registration ?? source;
  const relayId = relay.relay_id ?? relay.relayId ?? source.relayId;
  const hpkeKey =
    relay.hpke_public_key ??
    relay.hpkePublicKey ??
    source.hpke_public_key ??
    source.hpkePublicKey;
  const bandwidthValue =
    relay.bandwidth_class ?? relay.bandwidthClass ?? source.bandwidthClass;
  return {
    relay: {
      relay_id: normalizeAccountId(
        relayId,
        "registerKaigiRelay.relayId",
      ),
      hpke_public_key: normalizeKaigiHpkePublicKey(
        hpkeKey,
        "registerKaigiRelay.hpkePublicKey",
      ),
      bandwidth_class: asNonZeroByte(
        bandwidthValue,
        "registerKaigiRelay.bandwidthClass",
      ),
    },
  };
}

function normalizeUnregisterRelayInput(options) {
  const source = assertPlainObject(options, "unregisterKaigiRelay");
  const relayId = source.relay_id ?? source.relayId;
  return {
    relay_id: normalizeAccountId(
      relayId,
      "unregisterKaigiRelay.relayId",
    ),
  };
}

function normalizeKaigiRelayHealthStatus(value, name) {
  if (value !== "Healthy" && value !== "Degraded" && value !== "Unavailable") {
    fail(
      V_CODE_INVALID_STRING,
      `${name}${TEXT_MUST_BE_EXACTLY}"Healthy", "Degraded", or "Unavailable"`,
      name,
    );
  }
  return { status: value, state: null };
}

function normalizeKaigiRelayHealthNotes(value, name) {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== "string") {
    fail(V_CODE_INVALID_STRING, `${name}${TEXT_MUST_BE_A}string`, name);
  }
  assertWellFormedUtf16(value, name);
  let scalarCount = 0;
  for (const _character of value) {
    scalarCount += 1;
    if (scalarCount > 512) {
      fail(
        V_CODE_VALUE_OUT_OF_RANGE,
        `${name} must not exceed 512 Unicode scalar values`,
        name,
      );
    }
  }
  return value;
}

function normalizeReportKaigiRelayHealthInput(options) {
  const source = assertPlainObject(options, "reportKaigiRelayHealth");
  return {
    call_id: normalizeCanonicalKaigiId(
      source.call_id ?? source.callId,
      (TEXT_REPORT_KAIGI_RELAY_HEALTH + "callId"),
    ),
    relay_id: normalizeAccountId(
      source.relay_id ?? source.relayId,
      (TEXT_REPORT_KAIGI_RELAY_HEALTH + "relayId"),
    ),
    status: normalizeKaigiRelayHealthStatus(
      source.status,
      (TEXT_REPORT_KAIGI_RELAY_HEALTH + "status"),
    ),
    reported_at_ms: asKaigiU64(
      source.reported_at_ms ?? source.reportedAtMs,
      (TEXT_REPORT_KAIGI_RELAY_HEALTH + "reportedAtMs"),
    ),
    notes: normalizeKaigiRelayHealthNotes(
      source.notes,
      (TEXT_REPORT_KAIGI_RELAY_HEALTH + "notes"),
    ),
  };
}

const contractManifestNormalizers = /* @__PURE__ */ createContractManifestNormalizer(
  TEXT_MUST_BE,
  TEXT_MUST_BE_A,
  TEXT_MUST_BE_AN,
  TEXT_MUST_CONTAIN,
  TEXT_MUST_CONTAIN_EXACTLY,
  V_CODE_INVALID_HEX,
  V_CODE_INVALID_MULTIHASH,
  V_CODE_INVALID_OBJECT,
  V_CODE_INVALID_STRING,
  V_CODE_VALUE_OUT_OF_RANGE,
  asByte,
  asNonNegativeInteger,
  assertPlainObject,
  fail,
  normalizeAccessSetHints,
  normalizeByteArray,
  normalizeJsonValue,
  normalizeOptionalExactBase64String,
  normalizeOptionalHash,
  selectEqualManifestAlias,
  validateManifestDynamicAccessHintStateMaps,
);

function normalizeJsonPayload(value, name) {
  if (value === null || value === undefined) {
    return "{}";
  }
  const normalized = normalizeZkBallotPublicInputs(value, name);
  return stringifyStrictLosslessIntegerJson(normalized, name);
}

function normalizeZkBallotPublicInputs(value, name) {
  const source = assertPlainObject(value, name);
  rejectGovernancePrivateKeyFieldsDeep(source, name);
  assertAllowedFields(source, new Set(GOVERNANCE_ZK_PUBLIC_INPUT_FIELDS), name);

  const normalized = {};
  for (const field of GOVERNANCE_ZK_PUBLIC_INPUT_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(source, field)) {
      continue;
    }
    const entry = source[field];
    if (entry === null) {
      normalized[field] = null;
      continue;
    }
    switch (field) {
      case "root_hint":
      case "nullifier":
        normalized[field] = normalizeGovernanceHex32(entry, `${name}.${field}`);
        break;
      case "owner":
        normalized.owner = ensureCanonicalAccountId(entry, `${name}.owner`);
        break;
      case "amount":
        normalized.amount = asQuantity(entry, `${name}.amount`);
        break;
      case "duration_blocks":
        normalized.duration_blocks = normalizeGovernanceU64(
          entry,
          `${name}.duration_blocks`,
        );
        break;
      case "direction":
        normalized.direction = normalizeGovernanceBallotDirection(
          entry,
          `${name}.direction`,
        );
        break;
      default:
        throw new Error(`unhandled governance public input ${field}`);
    }
  }

  const hasOwner = normalized.owner !== undefined && normalized.owner !== null;
  const hasAmount = normalized.amount !== undefined && normalized.amount !== null;
  const hasDuration =
    normalized.duration_blocks !== undefined && normalized.duration_blocks !== null;
  const hasAnyLockHint = hasOwner || hasAmount || hasDuration;
  if (hasAnyLockHint && !(hasOwner && hasAmount && hasDuration)) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${name} must include owner, amount, and duration_blocks when providing lock hints`,
      name,
    );
  }
  return normalized;
}

function normalizeGovernanceBallotDirection(value, name) {
  if (value === "Aye" || value === "Nay" || value === "Abstain") {
    return value;
  }
  fail(
    V_CODE_INVALID_STRING,
    `${name}${TEXT_MUST_BE_EXACTLY}Aye, Nay, or Abstain`,
    name,
  );
}

function normalizeDirection(value, name) {
  if (value === undefined || value === null) {
    return 0;
  }
  if (typeof value === "number") {
    const byte = asByte(value, name);
    if (byte > 2) {
      fail(V_CODE_VALUE_OUT_OF_RANGE, `${name}${TEXT_MUST_BE_BETWEEN_0_AND}2`, name);
    }
    return byte;
  }
  const normalized = String(value).trim().toLowerCase();
  if (normalized === "aye" || normalized === "yes" || normalized === "for") {
    return 0;
  }
  if (normalized === "nay" || normalized === "no" || normalized === "against") {
    return 1;
  }
  if (normalized === "abstain") {
    return 2;
  }
  fail(
    V_CODE_INVALID_STRING,
    `${name}${TEXT_MUST_BE}0, 1, 2 or a recognized direction string`,
    name,
  );
}

function normalizeSorafsReplicationIdentifier(value, name) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    fail(
      V_CODE_INVALID_HEX,
      `${name}${TEXT_MUST_CONTAIN_EXACTLY}64 lowercase hexadecimal characters`,
      name,
    );
  }
  if (/^0{64}$/u.test(value)) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name} must not be the zero identifier`,
      name,
    );
  }
  return value;
}

function normalizeSorafsProviderOwner(value, name) {
  if (typeof value !== "string" || value.trim() !== value) {
    fail(
      V_CODE_INVALID_ACCOUNT_ID,
      `${name}${TEXT_MUST_BE_AN}exact canonical I105 account id`,
      name,
    );
  }
  const normalized = normalizeAccountId(value, name);
  if (normalized !== value) {
    fail(
      V_CODE_INVALID_ACCOUNT_ID,
      `${name}${TEXT_MUST_BE_AN}exact canonical I105 account id`,
      name,
    );
  }
  return normalized;
}

function normalizeProviderIngestCompletionSignerPolicy(value, name) {
  const source = assertPlainObject(value, name);
  assertExactFields(
    source,
    ["policyId", "revision", "predecessorDigest", "policyDigest"],
    name,
  );
  const revision = asPositiveInteger(source.revision, `${name}.revision`);
  const predecessorDigest = source.predecessorDigest;
  if (revision === 1) {
    if (predecessorDigest !== null) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}.predecessorDigest${TEXT_MUST_BE}null at revision 1`,
        `${name}.predecessorDigest`,
      );
    }
  } else if (predecessorDigest === null) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${name}.predecessorDigest is required after revision 1`,
      `${name}.predecessorDigest`,
    );
  }
  return {
    policy_id: normalizeSorafsReplicationIdentifier(
      source.policyId,
      `${name}.policyId`,
    ),
    revision,
    predecessor_digest:
      predecessorDigest === null
        ? null
        : normalizeSorafsReplicationIdentifier(
            predecessorDigest,
            `${name}.predecessorDigest`,
          ),
    policy_digest: normalizeSorafsReplicationIdentifier(
      source.policyDigest,
      `${name}.policyDigest`,
    ),
  };
}

function normalizeProviderIngestCompletionAuthority(value, name) {
  const source = assertPlainObject(value, name);
  assertExactFields(source, ["providerOwner", "completionSigner", "signerPolicy"], name);
  return {
    provider_owner: normalizeSorafsProviderOwner(
      source.providerOwner,
      `${name}.providerOwner`,
    ),
    completion_signer: normalizeSorafsProviderOwner(
      source.completionSigner,
      `${name}.completionSigner`,
    ),
    signer_policy: normalizeProviderIngestCompletionSignerPolicy(
      source.signerPolicy,
      `${name}.signerPolicy`,
    ),
  };
}

function normalizeProviderIngestFinalizedAnchor(value, name) {
  const source = assertPlainObject(value, name);
  assertExactFields(source, ["height", "blockHash"], name);
  return {
    height: asPositiveInteger(source.height, `${name}.height`),
    block_hash: normalizeSorafsReplicationIdentifier(
      source.blockHash,
      `${name}.blockHash`,
    ),
  };
}

function normalizeSorafsReplicationPayload(value, name) {
  if (
    typeof value === "string" &&
    value.length > SORAFS_REPLICATION_ORDER_MAX_PAYLOAD_BASE64_CHARS_V1
  ) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name} encoded form exceeds the ${SORAFS_REPLICATION_ORDER_MAX_PAYLOAD_BYTES_V1}-byte decoded limit`,
      name,
    );
  }
  const canonical = normalizeOptionalExactBase64String(value, name);
  const decoded = Buffer.from(canonical, "base64");
  const decodedLength = decoded.length;
  if (decodedLength > SORAFS_REPLICATION_ORDER_MAX_PAYLOAD_BYTES_V1) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name} exceeds the ${SORAFS_REPLICATION_ORDER_MAX_PAYLOAD_BYTES_V1}-byte decoded limit`,
      name,
    );
  }
  return { canonical, decoded };
}

/**
 * Build the canonical native `IssueReplicationOrder` instruction.
 *
 * The returned object uses the Rust/Norito field names. `orderPayload` must be
 * exact standard base64 containing between 1 byte and 1 MiB.
 *
 * @param {{orderId: string, orderPayload: string, issuedEpoch: number|string|bigint, deadlineEpoch: number|string|bigint, musubiArchiveId?: string|null}} options
 * @returns {{IssueReplicationOrder: {order_id: string, order_payload: string, issued_epoch: number, deadline_epoch: number, musubi_archive: string|null}}}
 */
export function buildIssueReplicationOrderInstruction(options) {
  const source = assertPlainObject(options, "issueReplicationOrder");
  assertAllowedFields(
    source,
    new Set([
      "orderId",
      "orderPayload",
      "issuedEpoch",
      "deadlineEpoch",
      "musubiArchiveId",
    ]),
    "issueReplicationOrder",
  );
  const issuedEpoch = asNonNegativeInteger(
    source.issuedEpoch,
    (TEXT_ISSUE_REPLICATION_ORDER + "issuedEpoch"),
  );
  const deadlineEpoch = asNonNegativeInteger(
    source.deadlineEpoch,
    (TEXT_ISSUE_REPLICATION_ORDER + "deadlineEpoch"),
  );
  if (deadlineEpoch <= issuedEpoch) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      (TEXT_ISSUE_REPLICATION_ORDER + "deadlineEpoch" + TEXT_MUST_BE + "greater than issuedEpoch"),
      (TEXT_ISSUE_REPLICATION_ORDER + "deadlineEpoch"),
    );
  }
  const orderId = normalizeSorafsReplicationIdentifier(
    source.orderId,
    (TEXT_ISSUE_REPLICATION_ORDER + "orderId"),
  );
  const { canonical: orderPayload, decoded: orderPayloadBytes } =
    normalizeSorafsReplicationPayload(
      source.orderPayload,
      (TEXT_ISSUE_REPLICATION_ORDER + "orderPayload"),
    );
  validateSorafsReplicationOrderPayloadV1(orderPayloadBytes, orderId);
  const musubiArchive = source.musubiArchiveId == null
    ? null
    : normalizeSorafsReplicationIdentifier(
      source.musubiArchiveId,
      (TEXT_ISSUE_REPLICATION_ORDER + "musubiArchiveId"),
    );
  return {
    IssueReplicationOrder: {
      order_id: orderId,
      order_payload: orderPayload,
      issued_epoch: issuedEpoch,
      deadline_epoch: deadlineEpoch,
      musubi_archive: musubiArchive,
    },
  };
}

/**
 * Build the canonical provider-specific `CompleteReplicationOrder` instruction.
 *
 * The six top-level fields bind the completion to the exact owner, dedicated completion signer,
 * governed signer-policy chain, assignment revision, and finalized chain prefix that
 * were checked before submission.
 *
 * @param {{orderId: string, providerId: string, completionEpoch: number|string|bigint, expectedAuthority: {providerOwner: string, completionSigner: string, signerPolicy: {policyId: string, revision: number|string|bigint, predecessorDigest: string|null, policyDigest: string}}, expectedAssignmentRevision: number|string|bigint, finalizedAnchor: {height: number|string|bigint, blockHash: string}}} options
 * @returns {{CompleteReplicationOrder: {order_id: string, provider_id: string, completion_epoch: number, expected_authority: {provider_owner: string, completion_signer: string, signer_policy: {policy_id: string, revision: number, predecessor_digest: string|null, policy_digest: string}}, expected_assignment_revision: number, finalized_anchor: {height: number, block_hash: string}}}}
 */
export function buildCompleteReplicationOrderInstruction(options) {
  const source = assertPlainObject(options, "completeReplicationOrder");
  assertExactFields(
    source,
    [
      "orderId",
      "providerId",
      "completionEpoch",
      "expectedAuthority",
      "expectedAssignmentRevision",
      "finalizedAnchor",
    ],
    "completeReplicationOrder",
  );
  return {
    CompleteReplicationOrder: {
      order_id: normalizeSorafsReplicationIdentifier(
        source.orderId,
        (TEXT_COMPLETE_REPLICATION_ORDER + "orderId"),
      ),
      provider_id: normalizeSorafsReplicationIdentifier(
        source.providerId,
        (TEXT_COMPLETE_REPLICATION_ORDER + "providerId"),
      ),
      completion_epoch: asNonNegativeInteger(
        source.completionEpoch,
        (TEXT_COMPLETE_REPLICATION_ORDER + "completionEpoch"),
      ),
      expected_authority: normalizeProviderIngestCompletionAuthority(
        source.expectedAuthority,
        (TEXT_COMPLETE_REPLICATION_ORDER + "expectedAuthority"),
      ),
      expected_assignment_revision: asPositiveInteger(
        source.expectedAssignmentRevision,
        (TEXT_COMPLETE_REPLICATION_ORDER + "expectedAssignmentRevision"),
      ),
      finalized_anchor: normalizeProviderIngestFinalizedAnchor(
        source.finalizedAnchor,
        (TEXT_COMPLETE_REPLICATION_ORDER + "finalizedAnchor"),
      ),
    },
  };
}

/**
 * Build the canonical native `ExpireReplicationOrder` instruction.
 *
 * @param {{orderId: string, expirationEpoch: number|string|bigint}} options
 * @returns {{ExpireReplicationOrder: {order_id: string, expiration_epoch: number}}}
 */
export function buildExpireReplicationOrderInstruction(options) {
  const source = assertPlainObject(options, "expireReplicationOrder");
  assertAllowedFields(
    source,
    new Set(["orderId", "expirationEpoch"]),
    "expireReplicationOrder",
  );
  return {
    ExpireReplicationOrder: {
      order_id: normalizeSorafsReplicationIdentifier(
        source.orderId,
        "expireReplicationOrder.orderId",
      ),
      expiration_epoch: asNonNegativeInteger(
        source.expirationEpoch,
        "expireReplicationOrder.expirationEpoch",
      ),
    },
  };
}

/**
 * Build the canonical compare-and-cancel `CancelAssetLock` instruction.
 *
 * `lockId` is exact, nonempty text without surrounding whitespace or a BOM,
 * is bounded by {@link CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1} UTF-8
 * bytes, and is hashed with the native Blake2b-256 escrow-id derivation. The
 * expected remaining amount is mandatory, positive, and encoded using the
 * exact canonical Quantity spelling observed in finalized ledger state.
 *
 * @param {{lockId: string, expectedRemainingAmount: KotodamaQuantity|string|bigint}} options
 * @returns {{CancelAssetLock: {escrow_id: string, expected_remaining_amount: string}}}
 */
export function buildCancelAssetLockInstruction(options) {
  const source = assertPlainObject(options, "cancelAssetLock");
  assertAllowedFields(
    source,
    new Set(["lockId", "expectedRemainingAmount"]),
    "cancelAssetLock",
  );
  return {
    CancelAssetLock: {
      escrow_id: normalizeAssetLockId(
        source.lockId,
        "cancelAssetLock.lockId",
      ),
      expected_remaining_amount: asPositiveQuantity(
        source.expectedRemainingAmount,
        "cancelAssetLock.expectedRemainingAmount",
      ),
    },
  };
}

function normalizeAssetTransferAvailability(value, name) {
  if (value !== "Enabled" && value !== "Disabled") {
    fail(
      V_CODE_INVALID_STRING,
      `${name}${TEXT_MUST_BE_EXACTLY}"Enabled" or "Disabled"`,
      name,
    );
  }
  return value;
}

function normalizeAssetTransferAvailabilityReason(value, name) {
  const reason = assertExactNonBlankString(value, name);
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(reason)) {
    fail(
      V_CODE_INVALID_STRING,
      `${name}${TEXT_MUST_NOT_CONTAIN}control characters`,
      name,
    );
  }
  if (
    Buffer.byteLength(reason, "utf8") >
    ASSET_TRANSFER_AVAILABILITY_MAX_REASON_BYTES_V1
  ) {
    throw new RangeError(`${name} exceeds 512 UTF-8 bytes`);
  }
  return reason;
}

/**
 * Build the canonical compare-and-set directional asset-availability instruction.
 *
 * Both directions are written atomically. `expectedRevision` binds the mutation
 * to the exact currently observed control record so concurrent operators cannot
 * silently overwrite each other.
 *
 * @param {{
 *   accountId: string,
 *   assetDefinitionId: string,
 *   expectedRevision: number|string|bigint,
 *   incoming: "Enabled"|"Disabled",
 *   outgoing: "Enabled"|"Disabled",
 *   reason?: string|null,
 * }} options
 * @returns {{SetAssetTransferAvailability: {
 *   account_id: string,
 *   asset_definition_id: string,
 *   expected_revision: string,
 *   incoming: "Enabled"|"Disabled",
 *   outgoing: "Enabled"|"Disabled",
 *   reason: string|null,
 * }}}
 */
export function buildSetAssetTransferAvailabilityInstruction(options) {
  const source = assertPlainObject(options, "setAssetTransferAvailability");
  assertAllowedFields(
    source,
    new Set([
      TEXT_ACCOUNT_ID,
      TEXT_ASSET_DEFINITION_ID,
      "expectedRevision",
      "incoming",
      "outgoing",
      "reason",
    ]),
    "setAssetTransferAvailability",
  );
  const accountLiteral = assertExactNonBlankString(
    source.accountId,
    (TEXT_SET_ASSET_TRANSFER_AVAILABILITY + TEXT_ACCOUNT_ID),
  );
  const assetDefinitionLiteral = assertExactNonBlankString(
    source.assetDefinitionId,
    (TEXT_SET_ASSET_TRANSFER_AVAILABILITY + TEXT_ASSET_DEFINITION_ID_2),
  );
  const reason =
    source.reason === undefined || source.reason === null
      ? null
      : normalizeAssetTransferAvailabilityReason(
          source.reason,
          (TEXT_SET_ASSET_TRANSFER_AVAILABILITY + "reason"),
        );
  return {
    SetAssetTransferAvailability: {
      account_id: ensureCanonicalAccountId(
        accountLiteral,
        (TEXT_SET_ASSET_TRANSFER_AVAILABILITY + TEXT_ACCOUNT_ID),
      ),
      asset_definition_id: normalizeAssetDefinitionId(
        assetDefinitionLiteral,
        (TEXT_SET_ASSET_TRANSFER_AVAILABILITY + TEXT_ASSET_DEFINITION_ID_2),
      ),
      expected_revision: normalizeCanonicalU64(
        source.expectedRevision,
        (TEXT_SET_ASSET_TRANSFER_AVAILABILITY + "expectedRevision"),
      ),
      incoming: normalizeAssetTransferAvailability(
        source.incoming,
        (TEXT_SET_ASSET_TRANSFER_AVAILABILITY + "incoming"),
      ),
      outgoing: normalizeAssetTransferAvailability(
        source.outgoing,
        (TEXT_SET_ASSET_TRANSFER_AVAILABILITY + "outgoing"),
      ),
      reason,
    },
  };
}

/**
 * Build the canonical outbound-transfer blacklist instruction.
 *
 * @param {{accountId: string, assetDefinitionId: string, blacklisted: boolean}} options
 * @returns {{SetAssetTransferBlacklist: {
 *   account_id: string,
 *   asset_definition_id: string,
 *   blacklisted: boolean,
 * }}}
 */
export function buildSetAssetTransferBlacklistInstruction(options) {
  const source = assertPlainObject(options, "setAssetTransferBlacklist");
  assertAllowedFields(
    source,
    new Set([TEXT_ACCOUNT_ID, TEXT_ASSET_DEFINITION_ID, "blacklisted"]),
    "setAssetTransferBlacklist",
  );
  const accountLiteral = assertExactNonBlankString(
    source.accountId,
    (TEXT_SET_ASSET_TRANSFER_BLACKLIST + TEXT_ACCOUNT_ID),
  );
  const assetDefinitionLiteral = assertExactNonBlankString(
    source.assetDefinitionId,
    (TEXT_SET_ASSET_TRANSFER_BLACKLIST + TEXT_ASSET_DEFINITION_ID_2),
  );
  if (typeof source.blacklisted !== "boolean") {
    fail(
      V_CODE_INVALID_OBJECT,
      (TEXT_SET_ASSET_TRANSFER_BLACKLIST + "blacklisted" + TEXT_MUST_BE + "a boolean"),
      (TEXT_SET_ASSET_TRANSFER_BLACKLIST + "blacklisted"),
    );
  }
  return {
    SetAssetTransferBlacklist: {
      account_id: ensureCanonicalAccountId(
        accountLiteral,
        (TEXT_SET_ASSET_TRANSFER_BLACKLIST + TEXT_ACCOUNT_ID),
      ),
      asset_definition_id: normalizeAssetDefinitionId(
        assetDefinitionLiteral,
        (TEXT_SET_ASSET_TRANSFER_BLACKLIST + TEXT_ASSET_DEFINITION_ID_2),
      ),
      blacklisted: source.blacklisted,
    },
  };
}

const ASSET_TRANSFER_CONTROL_WINDOW = Object.freeze({
  DAY: Object.freeze({ wire: "Day", rank: 0 }),
  WEEK: Object.freeze({ wire: "Week", rank: 1 }),
  MONTH: Object.freeze({ wire: "Month", rank: 2 }),
});

function normalizeAssetTransferControlWindow(value, name) {
  if (
    typeof value !== "string" ||
    !Object.prototype.hasOwnProperty.call(ASSET_TRANSFER_CONTROL_WINDOW, value)
  ) {
    fail(
      V_CODE_INVALID_STRING,
      `${name}${TEXT_MUST_BE_EXACTLY}"DAY", "WEEK", or "MONTH"`,
      name,
    );
  }
  return ASSET_TRANSFER_CONTROL_WINDOW[value];
}

/**
 * Build the canonical complete replacement for calendar-window outbound caps.
 *
 * Limits are unique and emitted in DAY/WEEK/MONTH order. A null `capAmount`
 * clears that window, while an empty list clears every transfer cap.
 *
 * @param {{
 *   accountId: string,
 *   assetDefinitionId: string,
 *   limits: ReadonlyArray<{
 *     window: "DAY"|"WEEK"|"MONTH",
 *     capAmount: KotodamaQuantity|string|bigint|null,
 *   }>,
 * }} options
 * @returns {{SetAssetTransferControl: {
 *   account_id: string,
 *   asset_definition_id: string,
 *   limits: Array<{
 *     window: "Day"|"Week"|"Month",
 *     cap_amount: string|null,
 *   }>,
 * }}}
 */
export function buildSetAssetTransferControlInstruction(options) {
  const source = assertPlainObject(options, "setAssetTransferControl");
  assertAllowedFields(
    source,
    new Set([TEXT_ACCOUNT_ID, TEXT_ASSET_DEFINITION_ID, "limits"]),
    "setAssetTransferControl",
  );
  const accountLiteral = assertExactNonBlankString(
    source.accountId,
    (TEXT_SET_ASSET_TRANSFER_CONTROL + TEXT_ACCOUNT_ID),
  );
  const assetDefinitionLiteral = assertExactNonBlankString(
    source.assetDefinitionId,
    (TEXT_SET_ASSET_TRANSFER_CONTROL + TEXT_ASSET_DEFINITION_ID_2),
  );
  if (!Array.isArray(source.limits)) {
    fail(
      V_CODE_INVALID_OBJECT,
      (TEXT_SET_ASSET_TRANSFER_CONTROL + "limits" + TEXT_MUST_BE + "an array"),
      (TEXT_SET_ASSET_TRANSFER_CONTROL + "limits"),
    );
  }
  for (let index = 0; index < source.limits.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(source.limits, index)) {
      fail(
        V_CODE_INVALID_OBJECT,
        (TEXT_SET_ASSET_TRANSFER_CONTROL + "limits" + TEXT_MUST_NOT_CONTAIN + "holes"),
        (TEXT_SET_ASSET_TRANSFER_CONTROL + "limits"),
      );
    }
  }
  const windows = new Set();
  const limits = source.limits.map((limit, index) => {
    const name = `${TEXT_SET_ASSET_TRANSFER_CONTROL}limits[${index}]`;
    const item = assertPlainObject(limit, name);
    assertAllowedFields(item, new Set(["window", "capAmount"]), name);
    if (!Object.prototype.hasOwnProperty.call(item, "capAmount")) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}.capAmount is required; use null to clear the window`,
        `${name}.capAmount`,
      );
    }
    const window = normalizeAssetTransferControlWindow(
      item.window,
      `${name}.window`,
    );
    if (windows.has(window.wire)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${name}.window duplicates ${item.window}`,
        `${name}.window`,
      );
    }
    windows.add(window.wire);
    return {
      rank: window.rank,
      value: {
        window: window.wire,
        cap_amount:
          item.capAmount === null
            ? null
            : asQuantity(item.capAmount, `${name}.capAmount`),
      },
    };
  });
  limits.sort((left, right) => left.rank - right.rank);
  return {
    SetAssetTransferControl: {
      account_id: ensureCanonicalAccountId(
        accountLiteral,
        (TEXT_SET_ASSET_TRANSFER_CONTROL + TEXT_ACCOUNT_ID),
      ),
      asset_definition_id: normalizeAssetDefinitionId(
        assetDefinitionLiteral,
        (TEXT_SET_ASSET_TRANSFER_CONTROL + TEXT_ASSET_DEFINITION_ID_2),
      ),
      limits: limits.map(({ value }) => value),
    },
  };
}

/**
 * Build a `Mint::Asset` instruction payload.
 * @param {{ assetHoldingId: string, quantity: KotodamaQuantity|string|bigint }} options
 * @returns {{Mint: {Asset: {object: string, destination: string}}}}
 */
export function buildMintAssetInstruction({ assetHoldingId, assetId, quantity }) {
  const destination = normalizeAssetHoldingId(
    assetHoldingId ?? assetId,
    assetHoldingId !== undefined ? "assetHoldingId" : "assetId",
  );
  const object = asQuantity(quantity, "quantity");
  return {
    Mint: {
      Asset: {
        object,
        destination,
      },
    },
  };
}

/**
 * Build a `Burn::Asset` instruction payload.
 * @param {{ assetHoldingId: string, quantity: KotodamaQuantity|string|bigint }} options
 * @returns {{Burn: {Asset: {object: string, destination: string}}}}
 */
export function buildBurnAssetInstruction({ assetHoldingId, assetId, quantity }) {
  const destination = normalizeAssetHoldingId(
    assetHoldingId ?? assetId,
    assetHoldingId !== undefined ? "assetHoldingId" : "assetId",
  );
  const object = asQuantity(quantity, "quantity");
  return {
    Burn: {
      Asset: {
        object,
        destination,
      },
    },
  };
}

/**
 * Build a `Mint::TriggerRepetitions` instruction payload.
 * @param {{ triggerId: string, repetitions: number|string|bigint }} options
 * @returns {{Mint: {TriggerRepetitions: {object: number, destination: string}}}}
 */
export function buildMintTriggerRepetitionsInstruction({
  triggerId,
  repetitions,
}) {
  const destination = assertString(triggerId, "triggerId");
  const object = asPositiveInteger(repetitions, "repetitions");
  return {
    Mint: {
      TriggerRepetitions: {
        object,
        destination,
      },
    },
  };
}

/**
 * Build a `Burn::TriggerRepetitions` instruction payload.
 * @param {{ triggerId: string, repetitions: number|string|bigint }} options
 * @returns {{Burn: {TriggerRepetitions: {object: number, destination: string}}}}
 */
export function buildBurnTriggerRepetitionsInstruction({
  triggerId,
  repetitions,
}) {
  const destination = assertString(triggerId, "triggerId");
  const object = asPositiveInteger(repetitions, "repetitions");
  return {
    Burn: {
      TriggerRepetitions: {
        object,
        destination,
      },
    },
  };
}

/**
 * Build a `Transfer::Asset` instruction payload.
 * @param {{ sourceAssetHoldingId: string, quantity: KotodamaQuantity|string|bigint, destinationAccountId: string }} options
 * @returns {{Transfer: {Asset: {source: string, object: string, destination: string}}}}
 */
export function buildTransferAssetInstruction({
  sourceAssetHoldingId,
  sourceAssetId,
  quantity,
  destinationAccountId,
}) {
  const source = normalizeAssetHoldingId(
    sourceAssetHoldingId ?? sourceAssetId,
    sourceAssetHoldingId !== undefined ? "sourceAssetHoldingId" : "sourceAssetId",
  );
  const destination = normalizeAccountId(
    destinationAccountId,
    TEXT_DESTINATION_ACCOUNT_ID,
  );
  const object = asQuantity(quantity, "quantity");
  return {
    Transfer: {
      Asset: {
        source,
        object,
        destination,
      },
    },
  };
}

/**
 * Build a `Transfer::Domain` instruction payload.
 * @param {{ sourceAccountId: string, domainId: string, destinationAccountId: string }} options
 * @returns {{Transfer: {Domain: {source: string, object: string, destination: string}}}}
 */
export function buildTransferDomainInstruction({
  sourceAccountId,
  domainId,
  destinationAccountId,
}) {
  const source = normalizeAccountId(sourceAccountId, TEXT_SOURCE_ACCOUNT_ID);
  const object = assertString(domainId, "domainId");
  const destination = normalizeAccountId(
    destinationAccountId,
    TEXT_DESTINATION_ACCOUNT_ID,
  );
  return {
    Transfer: {
      Domain: {
        source,
        object,
        destination,
      },
    },
  };
}

/**
 * Build a `Transfer::AssetDefinition` instruction payload.
 * @param {{ sourceAccountId: string, assetDefinitionId: string, destinationAccountId: string }} options
 * @returns {{Transfer: {AssetDefinition: {source: string, object: string, destination: string}}}}
 */
export function buildTransferAssetDefinitionInstruction({
  sourceAccountId,
  assetDefinitionId,
  destinationAccountId,
}) {
  const source = normalizeAccountId(sourceAccountId, TEXT_SOURCE_ACCOUNT_ID);
  const object = assertString(assetDefinitionId, TEXT_ASSET_DEFINITION_ID);
  const destination = normalizeAccountId(
    destinationAccountId,
    TEXT_DESTINATION_ACCOUNT_ID,
  );
  return {
    Transfer: {
      AssetDefinition: {
        source,
        object,
        destination,
      },
    },
  };
}

/**
 * Build a `Transfer::Nft` instruction payload.
 * @param {{ sourceAccountId: string, nftId: string, destinationAccountId: string }} options
 * @returns {{Transfer: {Nft: {source: string, object: string, destination: string}}}}
 */
export function buildTransferNftInstruction({
  sourceAccountId,
  nftId,
  destinationAccountId,
}) {
  const source = normalizeAccountId(sourceAccountId, TEXT_SOURCE_ACCOUNT_ID);
  const object = assertString(nftId, "nftId");
  const destination = normalizeAccountId(
    destinationAccountId,
    TEXT_DESTINATION_ACCOUNT_ID,
  );
  return {
    Transfer: {
      Nft: {
        source,
        object,
        destination,
      },
    },
  };
}

/**
 * Build a `RegisterRwa` instruction payload.
 * @param {object} options
 * @returns {{RegisterRwa: {rwa: object}}}
 */
export function buildRegisterRwaInstruction(options) {
  const source = assertPlainObject(options, "registerRwa");
  return {
    RegisterRwa: {
      rwa: normalizeRegisterRwaPayload(source.rwa ?? source.rwaJson ?? source, "registerRwa.rwa"),
    },
  };
}

/**
 * Build a `TransferRwa` instruction payload.
 * @param {{ sourceAccountId: string, rwaId: string, quantity: KotodamaQuantity|string|bigint, destinationAccountId: string }} options
 * @returns {{TransferRwa: {source: string, rwa: string, quantity: string, destination: string}}}
 */
export function buildTransferRwaInstruction({
  sourceAccountId,
  rwaId,
  quantity,
  destinationAccountId,
}) {
  return {
    TransferRwa: {
      source: normalizeAccountId(sourceAccountId, TEXT_SOURCE_ACCOUNT_ID),
      rwa: normalizeRwaId(rwaId, "rwaId"),
      quantity: asQuantity(quantity, "quantity"),
      destination: normalizeAccountId(destinationAccountId, TEXT_DESTINATION_ACCOUNT_ID),
    },
  };
}

/**
 * Build a `MergeRwas` instruction payload.
 * @param {object} options
 * @returns {{MergeRwas: object}}
 */
export function buildMergeRwasInstruction(options) {
  const source = assertPlainObject(options, "mergeRwas");
  return {
    MergeRwas: normalizeMergeRwasPayload(
      source.merge ?? source.mergeJson ?? source,
      "mergeRwas.merge",
    ),
  };
}

/**
 * Build a `RedeemRwa` instruction payload.
 * @param {{ rwaId: string, quantity: KotodamaQuantity|string|bigint }} options
 * @returns {{RedeemRwa: {rwa: string, quantity: string}}}
 */
export function buildRedeemRwaInstruction({ rwaId, quantity }) {
  return {
    RedeemRwa: {
      rwa: normalizeRwaId(rwaId, "rwaId"),
      quantity: asQuantity(quantity, "quantity"),
    },
  };
}

/**
 * Build a `FreezeRwa` instruction payload.
 * @param {{ rwaId: string }} options
 * @returns {{FreezeRwa: {rwa: string}}}
 */
export function buildFreezeRwaInstruction({ rwaId }) {
  return {
    FreezeRwa: {
      rwa: normalizeRwaId(rwaId, "rwaId"),
    },
  };
}

/**
 * Build an `UnfreezeRwa` instruction payload.
 * @param {{ rwaId: string }} options
 * @returns {{UnfreezeRwa: {rwa: string}}}
 */
export function buildUnfreezeRwaInstruction({ rwaId }) {
  return {
    UnfreezeRwa: {
      rwa: normalizeRwaId(rwaId, "rwaId"),
    },
  };
}

/**
 * Build a `HoldRwa` instruction payload.
 * @param {{ rwaId: string, quantity: KotodamaQuantity|string|bigint }} options
 * @returns {{HoldRwa: {rwa: string, quantity: string}}}
 */
export function buildHoldRwaInstruction({ rwaId, quantity }) {
  return {
    HoldRwa: {
      rwa: normalizeRwaId(rwaId, "rwaId"),
      quantity: asQuantity(quantity, "quantity"),
    },
  };
}

/**
 * Build a `ReleaseRwa` instruction payload.
 * @param {{ rwaId: string, quantity: KotodamaQuantity|string|bigint }} options
 * @returns {{ReleaseRwa: {rwa: string, quantity: string}}}
 */
export function buildReleaseRwaInstruction({ rwaId, quantity }) {
  return {
    ReleaseRwa: {
      rwa: normalizeRwaId(rwaId, "rwaId"),
      quantity: asQuantity(quantity, "quantity"),
    },
  };
}

/**
 * Build a `ForceTransferRwa` instruction payload.
 * @param {{ rwaId: string, quantity: KotodamaQuantity|string|bigint, destinationAccountId: string }} options
 * @returns {{ForceTransferRwa: {rwa: string, quantity: string, destination: string}}}
 */
export function buildForceTransferRwaInstruction({
  rwaId,
  quantity,
  destinationAccountId,
}) {
  return {
    ForceTransferRwa: {
      rwa: normalizeRwaId(rwaId, "rwaId"),
      quantity: asQuantity(quantity, "quantity"),
      destination: normalizeAccountId(destinationAccountId, TEXT_DESTINATION_ACCOUNT_ID),
    },
  };
}

/**
 * Build a `SetRwaControls` instruction payload.
 * @param {{ rwaId: string, controls?: object|string, controlsJson?: string }} options
 * @returns {{SetRwaControls: {rwa: string, controls: object}}}
 */
export function buildSetRwaControlsInstruction(options) {
  const source = assertPlainObject(options, "setRwaControls");
  return {
    SetRwaControls: {
      rwa: normalizeRwaId(source.rwaId, "rwaId"),
      controls: normalizeRwaControlPolicy(
        source.controls ?? source.controlsJson,
        "setRwaControls.controls",
      ),
    },
  };
}

/**
 * Build a `SetRwaKeyValue` instruction payload.
 * @param {{ rwaId: string, key: string, value: unknown }} options
 * @returns {{SetRwaKeyValue: {rwa: string, key: string, value: unknown}}}
 */
export function buildSetRwaKeyValueInstruction({ rwaId, key, value }) {
  return {
    SetRwaKeyValue: {
      rwa: normalizeRwaId(rwaId, "rwaId"),
      key: assertString(key, "key"),
      value: normalizeJsonValue(value, "value"),
    },
  };
}

/**
 * Build a `RemoveRwaKeyValue` instruction payload.
 * @param {{ rwaId: string, key: string }} options
 * @returns {{RemoveRwaKeyValue: {rwa: string, key: string}}}
 */
export function buildRemoveRwaKeyValueInstruction({ rwaId, key }) {
  return {
    RemoveRwaKeyValue: {
      rwa: normalizeRwaId(rwaId, "rwaId"),
      key: assertString(key, "key"),
    },
  };
}

/**
 * Build a `Register::Domain` instruction payload.
 * @param {{ domainId: string, logo?: string | null, metadata?: object | null }} options
 * @returns {{Register: {Domain: {id: string, logo: string | null, metadata: object}}}}
 */
export function buildRegisterDomainInstruction({ domainId, logo = null, metadata }) {
  const id = assertString(domainId, "domainId");
  const normalizedLogo =
    logo === null || logo === undefined ? null : assertString(logo, "logo");
  const normalizedMetadata = normalizeMetadata(metadata);
  return {
    Register: {
      Domain: {
        id,
        logo: normalizedLogo,
        metadata: normalizedMetadata,
      },
    },
  };
}

/**
 * Build a `Register::Account` instruction payload.
 * @param {{ accountId: string, metadata?: object | null }} options
 * @returns {{Register: {Account: {id: string, label: null, uaid: null, opaque_ids: [], metadata: object}}}}
 */
export function buildRegisterAccountInstruction({
  accountId,
  domainId,
  domain,
  metadata,
}) {
  if (domainId !== undefined || domain !== undefined) {
    throw new TypeError("account registration is domainless; bind account aliases separately");
  }
  const id = normalizeAccountId(accountId, TEXT_ACCOUNT_ID);
  const normalizedMetadata = normalizeMetadata(metadata);
  return {
    Register: {
      Account: {
        id,
        label: null,
        uaid: null,
        opaque_ids: [],
        metadata: normalizedMetadata,
      },
    },
  };
}

/**
 * Build a `Register::AssetDefinition` instruction payload.
 * @param {{
 *   assetDefinitionId?: string,
 *   id?: string,
 *   name?: string,
 *   description?: string | null,
 *   alias?: string | null,
 *   logo?: string | null,
 *   scale?: number|string|bigint|null,
 *   mintable?: string,
 *   mintOnce?: boolean,
 *   metadata?: object | null,
 *   balanceScopePolicy: string,
 *   balance_scope_policy?: string,
 *   owningDomain?: string | null,
 *   owning_domain?: string | null
 * }} options
 * @returns {{Register: {AssetDefinition: object}}}
 */
export function buildRegisterAssetDefinitionInstruction(options = {}) {
  return { Register: { AssetDefinition: buildAssetDefinitionRegistrationPayload(options, false) } };
}

/** Build the distinct Native direct-dataspace instruction, preserving exact u64 namespace identity. */
export function buildRegisterDataspaceAssetDefinitionInstruction(options = {}) {
  const source = assertPlainObject(options, "registerDataspaceAssetDefinition");
  for (const key of ["owningDomain", "owning_domain"]) {
    if (source[key] !== undefined && source[key] !== null) {
      throw new TypeError("direct-dataspace registration cannot also specify owning_domain");
    }
  }
  const exactId = (value, label) => {
    if (typeof value === "string" && value.length > 20) {
      throw new RangeError(`${label} must fit in u64`);
    }
    const normalized = normalizeCanonicalU64(value, label);
    if (typeof value === "string" && normalized !== value) {
      throw new TypeError(`${label} must be a canonical u64 decimal string`);
    }
    return normalized;
  };
  const rawId = source.dataspaceId ?? source.dataspace_id;
  const id = exactId(rawId, "registerDataspaceAssetDefinition.dataspaceId");
  if (id === "0") throw new RangeError("direct dataspaceId must be nonzero");
  if (source.dataspaceId !== undefined && source.dataspace_id !== undefined &&
      (exactId(source.dataspaceId, "dataspaceId") !== id ||
       exactId(source.dataspace_id, "dataspace_id") !== id)) {
    throw new TypeError("dataspace ID aliases disagree");
  }
  return {
    RegisterDataspaceAssetDefinition: {
      dataspace_id: BigInt(id),
      object: buildAssetDefinitionRegistrationPayload(
        { ...source, owningDomain: null, owning_domain: null }, true,
      ),
    },
  };
}

function buildAssetDefinitionRegistrationPayload(options, directDataspace) {
  const source = assertPlainObject(options, "registerAssetDefinition");
  if (
    Object.prototype.hasOwnProperty.call(source, "confidentialPolicy") ||
    Object.prototype.hasOwnProperty.call(source, "confidential_policy")
  ) {
    throw new TypeError(
      "registerAssetDefinition cannot carry confidential policy; use RegisterZkAsset with canonical verifier bindings",
    );
  }
  const hasOwningDomain = Object.prototype.hasOwnProperty.call(source, "owningDomain");
  const hasSnakeOwningDomain = Object.prototype.hasOwnProperty.call(source, "owning_domain");
  if (!hasOwningDomain && !hasSnakeOwningDomain) {
    throw new TypeError(
      (TEXT_REGISTER_ASSET_DEFINITION + "owningDomain is required; use null for an intentionally unowned global definition"),
    );
  }
  if (
    hasOwningDomain &&
    hasSnakeOwningDomain &&
    source.owningDomain !== source.owning_domain
  ) {
    throw new TypeError("registerAssetDefinition ownership aliases disagree");
  }
  const rawOwningDomain = hasOwningDomain ? source.owningDomain : source.owning_domain;
  const owningDomain = rawOwningDomain === null
    ? null
    : assertString(rawOwningDomain, (TEXT_REGISTER_ASSET_DEFINITION + "owningDomain"));
  const scale = source.scale === undefined || source.scale === null
    ? null
    : asU128JsonNumber(source.scale, (TEXT_REGISTER_ASSET_DEFINITION + "scale"));
  const description = source.description === undefined || source.description === null
    ? null
    : assertString(source.description, (TEXT_REGISTER_ASSET_DEFINITION + "description"));
  const alias = source.alias === undefined || source.alias === null
    ? null
    : assertString(source.alias, (TEXT_REGISTER_ASSET_DEFINITION + "alias"));
  const logo = source.logo === undefined || source.logo === null
    ? null
    : assertString(source.logo, (TEXT_REGISTER_ASSET_DEFINITION + "logo"));
  const hasBalanceScopePolicy = Object.prototype.hasOwnProperty.call(
    source,
    "balanceScopePolicy",
  );
  const hasSnakeBalanceScopePolicy = Object.prototype.hasOwnProperty.call(
    source,
    "balance_scope_policy",
  );
  if (!hasBalanceScopePolicy && !hasSnakeBalanceScopePolicy) {
    throw new TypeError((TEXT_REGISTER_ASSET_DEFINITION + "balanceScopePolicy" + TEXT_IS_REQUIRED));
  }
  if (
    hasBalanceScopePolicy &&
    hasSnakeBalanceScopePolicy &&
    source.balanceScopePolicy !== source.balance_scope_policy
  ) {
    throw new TypeError("registerAssetDefinition balance-scope policy aliases disagree");
  }
  const balanceScopePolicy = assertString(
    hasBalanceScopePolicy ? source.balanceScopePolicy : source.balance_scope_policy,
    (TEXT_REGISTER_ASSET_DEFINITION + "balanceScopePolicy"),
  );
  if (balanceScopePolicy !== "Global" && balanceScopePolicy !== "DataspaceRestricted") {
    throw new TypeError(
      (TEXT_REGISTER_ASSET_DEFINITION + "balanceScopePolicy" + TEXT_MUST_BE + "Global or DataspaceRestricted"),
    );
  }
  if (!directDataspace && balanceScopePolicy === "DataspaceRestricted" && owningDomain === null) {
    throw new TypeError(
      (TEXT_REGISTER_ASSET_DEFINITION + "owningDomain is required for DataspaceRestricted balances"),
    );
  }
  return {
        id: assertString(
          source.assetDefinitionId ?? source.asset_definition_id ?? source.id,
          (TEXT_REGISTER_ASSET_DEFINITION + TEXT_ASSET_DEFINITION_ID_2),
        ),
        name: normalizeAssetDefinitionName(source.name, (TEXT_REGISTER_ASSET_DEFINITION + "name")),
        description,
        alias,
        spec: { scale },
        mintable: source.mintOnce === true
          ? "Once"
          : assertString(source.mintable ?? "Infinitely", (TEXT_REGISTER_ASSET_DEFINITION + "mintable")),
        logo,
        metadata: normalizeMetadata(source.metadata),
        balance_scope_policy: balanceScopePolicy,
        owning_domain: owningDomain,

  };
}
/**
 * Build a `Grant::Permission` instruction payload for an account.
 * @param {{ accountId?: string, destinationAccountId?: string, permission?: object, name?: string, payload?: any }} options
 * @returns {{Grant: {Permission: {object: {name: string, payload: any}, destination: string}}}}
 */
export function buildGrantAccountPermissionInstruction(options = {}) {
  const source = assertPlainObject(options, "grantAccountPermission");
  const permissionSource = source.permission === undefined || source.permission === null
    ? source
    : assertPlainObject(source.permission, (TEXT_GRANT_ACCOUNT_PERMISSION + "permission"));
  return {
    Grant: {
      Permission: {
        object: {
          name: assertString(
            permissionSource.name,
            (TEXT_GRANT_ACCOUNT_PERMISSION + "permission.name"),
          ),
          payload: permissionSource.payload === undefined
            ? null
            : normalizeJsonValue(
                permissionSource.payload,
                (TEXT_GRANT_ACCOUNT_PERMISSION + "permission.payload"),
              ),
        },
        destination: normalizeAccountId(
          source.accountId ?? source.destinationAccountId ?? source.destination,
          (TEXT_GRANT_ACCOUNT_PERMISSION + TEXT_ACCOUNT_ID),
        ),
      },
    },
  };
}

/**
 * Build a `SetKeyValue::Account` instruction payload.
 *
 * This is an on-ledger account metadata mutation. It is useful when a signed
 * instruction batch needs a protocol-visible, deterministic identity marker.
 *
 * @param {{ accountId: string, key: string, value: any }} options
 * @returns {{SetKeyValue: {Account: {object: string, key: string, value: any}}}}
 */
export function buildSetAccountKeyValueInstruction(options = {}) {
  const source = assertPlainObject(options, "setAccountKeyValue");
  return {
    SetKeyValue: {
      Account: {
        object: normalizeAccountId(
          source.accountId,
          ("setAccountKeyValue." + TEXT_ACCOUNT_ID),
        ),
        key: assertString(source.key, "setAccountKeyValue.key"),
        value: normalizeJsonValue(source.value, "setAccountKeyValue.value"),
      },
    },
  };
}

/**
 * Build a `SetAssetDefinitionAlias` instruction payload.
 * @param {{ assetDefinitionId?: string, asset_definition_id?: string, alias?: string | null, leaseExpiryMs?: number|string|bigint|null, lease_expiry_ms?: number|string|bigint|null }} options
 * @returns {{SetAssetDefinitionAlias: {asset_definition_id: string, alias: string | null, lease_expiry_ms: number | null}}}
 */
export function buildSetAssetDefinitionAliasInstruction(options = {}) {
  const source = assertPlainObject(options, "setAssetDefinitionAlias");
  const leaseExpiryMs = source.leaseExpiryMs ?? source.lease_expiry_ms;
  return {
    SetAssetDefinitionAlias: {
      asset_definition_id: assertString(
        source.assetDefinitionId ?? source.asset_definition_id,
        ("setAssetDefinitionAlias." + TEXT_ASSET_DEFINITION_ID_2),
      ),
      alias: source.alias === undefined || source.alias === null
        ? null
        : assertString(source.alias, "setAssetDefinitionAlias.alias"),
      lease_expiry_ms: leaseExpiryMs === undefined || leaseExpiryMs === null
        ? null
        : asU128JsonNumber(leaseExpiryMs, "setAssetDefinitionAlias.leaseExpiryMs"),
    },
  };
}

/**
 * Build an `ExecuteTrigger` instruction payload.
 * @param {string | { trigger: string, args?: any }} triggerOrOptions
 * @param {any} [args]
 * @returns {{ExecuteTrigger: {trigger: string, args: any}}}
 */
export function buildExecuteTriggerInstruction(triggerOrOptions, args) {
  const normalized = normalizeExecuteTriggerBuilderInput(
    triggerOrOptions,
    args,
    "executeTrigger",
  );
  return {
    ExecuteTrigger: normalized,
  };
}

/**
 * Encode an `ExecuteTrigger` instruction payload to canonical Norito.
 * @param {string | { trigger: string, args?: any }} triggerOrOptions
 * @param {number} networkPrefix Canonical I105 network prefix.
 * @param {any} [args]
 * @returns {Buffer}
 */
export function buildExecuteTriggerNorito(triggerOrOptions, networkPrefix, args) {
  return noritoEncodeInstruction(buildExecuteTriggerInstruction(triggerOrOptions, args), networkPrefix);
}

/**
 * Build common Kotodama trigger-argument payloads for multisig/direct-contract flows.
 * @param {"lifecycle" | "lookup"} preset
 * @param {object} [input]
 * @returns {object}
 */
export function buildMultisigTriggerArgs(preset, input = {}) {
  const normalizedPreset = assertString(preset, "preset");
  const source = assertPlainObject(input, "input");
  if (normalizedPreset === "lifecycle") {
    const payload = {
      action: assertString(source.action, "input.action"),
      request_id: assertString(
        source.requestId ?? source.request_id,
        "input.requestId",
      ),
    };
    const fiId = source.fiId ?? source.fi_id;
    if (fiId !== undefined && fiId !== null) {
      payload.fi_id = assertString(fiId, "input.fiId");
    }
    const toAccountId = source.toAccountId ?? source.to_account_id;
    if (toAccountId !== undefined && toAccountId !== null) {
      payload.to_account_id = normalizeAccountId(toAccountId, "input.toAccountId");
    }
    const amountI64 = source.amountI64 ?? source.amount_i64;
    if (amountI64 !== undefined && amountI64 !== null) {
      payload.amount_i64 = normalizeSafeIntegerJson(amountI64, "input.amountI64", {
        allowNegative: true,
      });
    }
    const requestedByActorId =
      source.requestedByActorId ?? source.requested_by_actor_id;
    if (requestedByActorId !== undefined) {
      payload.requested_by_actor_id = normalizeJsonValue(
        requestedByActorId,
        "input.requestedByActorId",
      );
    }
    const createdAtMs = source.createdAtMs ?? source.created_at_ms;
    if (createdAtMs !== undefined && createdAtMs !== null) {
      payload.created_at_ms = asNonNegativeInteger(createdAtMs, "input.createdAtMs");
    }
    const expiresAtMs = source.expiresAtMs ?? source.expires_at_ms;
    if (expiresAtMs !== undefined && expiresAtMs !== null) {
      payload.expires_at_ms = asNonNegativeInteger(expiresAtMs, "input.expiresAtMs");
    }
    return payload;
  }
  if (normalizedPreset === "lookup") {
    const payload = {
      request_id: assertString(
        source.requestId ?? source.request_id,
        "input.requestId",
      ),
    };
    const requestedByActorId =
      source.requestedByActorId ?? source.requested_by_actor_id;
    if (requestedByActorId !== undefined) {
      payload.requested_by_actor_id = normalizeJsonValue(
        requestedByActorId,
        "input.requestedByActorId",
      );
    }
    return payload;
  }
  fail(
    V_CODE_INVALID_STRING,
    ("preset" + TEXT_MUST_BE + "either \"lifecycle\" or \"lookup\""),
    "preset",
  );
}

/**
 * Check whether a signer is present in a multisig spec.
 * @param {MultisigSpec | object} spec
 * @param {string} signerAccountId
 * @returns {boolean}
 */
export function isMultisigSignerAuthorized(spec, signerAccountId) {
  const normalizedSpec = normalizeMultisigSpecPayload(spec, "spec");
  const normalizedSigner = normalizeAccountId(signerAccountId, TEXT_SIGNER_ACCOUNT_ID);
  return Object.prototype.hasOwnProperty.call(
    normalizedSpec.signatories,
    normalizedSigner,
  );
}

/**
 * Build an `ExecuteTrigger` instruction with optional strict signer validation against a multisig spec.
 * @param {{ trigger: string, args?: any, argPreset?: "lifecycle" | "lookup", argInput?: object, signerAccountId?: string, multisigSpec?: MultisigSpec | object, spec?: MultisigSpec | object, strictSignerCheck?: boolean }} options
 * @returns {{ExecuteTrigger: {trigger: string, args: any}}}
 */
export function buildMultisigExecuteTriggerInstruction(options) {
  const normalized = normalizeMultisigExecuteTriggerOptions(
    options,
    "multisigExecuteTrigger",
  );
  return buildExecuteTriggerInstruction(normalized.trigger, normalized.args);
}

/**
 * Encode an `ExecuteTrigger` instruction with optional strict signer validation against a multisig spec.
 * @param {{ trigger: string, args?: any, argPreset?: "lifecycle" | "lookup", argInput?: object, signerAccountId?: string, multisigSpec?: MultisigSpec | object, spec?: MultisigSpec | object, strictSignerCheck?: boolean }} options
 * @returns {Buffer}
 */
export function buildMultisigExecuteTriggerNorito(options, networkPrefix) {
  return noritoEncodeInstruction(buildMultisigExecuteTriggerInstruction(options), networkPrefix);
}

/**
 * Build a multisig registration instruction payload.
 * @param {{ accountId: string, spec: MultisigSpec | object }} options
 * @returns {{Custom: {payload: {Register: {account: string, spec: object, uaid: null}}}}}
 */
export function buildRegisterMultisigInstruction({ accountId, spec }) {
  const controller = normalizeAccountId(accountId, TEXT_ACCOUNT_ID);
  const normalizedSpec = normalizeMultisigSpecPayload(spec, "spec");
  return {
    Custom: {
      payload: {
        Register: {
          account: controller,
          spec: normalizedSpec,
          uaid: null,
        },
      },
    },
  };
}

/**
 * Build a multisig proposal instruction payload with TTL enforcement against the policy cap.
 * @param {{ accountId: string, instructions: any[], spec: MultisigSpec | object, transactionTtlMs?: number }} options
 * @returns {{Custom: {payload: {Propose: {account: string, instructions: any[], transaction_ttl_ms?: number}}}}}
 */
export function buildProposeMultisigInstruction({
  accountId,
  instructions,
  spec,
  transactionTtlMs,
}) {
  const controller = normalizeAccountId(accountId, TEXT_ACCOUNT_ID);
  if (!Array.isArray(instructions) || instructions.length === 0) {
    throw new TypeError(("instructions" + TEXT_MUST_BE + "a non-empty array"));
  }
  const normalizedSpec = normalizeMultisigSpecPayload(spec, "spec");

  const policyCap = normalizedSpec.transaction_ttl_ms;
  if (policyCap === undefined || policyCap === null) {
    throw new Error("spec.transaction_ttl_ms is required to enforce the policy TTL cap");
  }
  if (
    transactionTtlMs !== undefined &&
    transactionTtlMs !== null &&
    Number(transactionTtlMs) > Number(policyCap)
  ) {
    throw new RangeError(
      `Requested multisig TTL ${transactionTtlMs} ms exceeds the policy cap ${policyCap} ms; choose a value at or below the cap.`,
    );
  }

  const payload = {
    account: controller,
    instructions,
  };
  if (transactionTtlMs !== undefined && transactionTtlMs !== null) {
    payload.transaction_ttl_ms = transactionTtlMs;
  }

  return {
    Custom: {
      payload: {
        Propose: payload,
      },
    },
  };
}

/**
 * Build a multisig proposal wrapping a single `ExecuteTrigger` instruction.
 * @param {{ accountId: string, trigger: string, args?: any, argPreset?: "lifecycle" | "lookup", argInput?: object, spec: MultisigSpec | object, signerAccountId?: string, strictSignerCheck?: boolean, transactionTtlMs?: number | null }} options
 * @returns {{Custom: {payload: {Propose: {account: string, instructions: object[], transaction_ttl_ms?: number}}}}}
 */
export function buildProposeMultisigExecuteTriggerInstruction(options) {
  const source = assertPlainObject(options, "proposeMultisigExecuteTrigger");
  const normalized = normalizeMultisigExecuteTriggerOptions(
    {
      trigger: source.trigger,
      args: source.args,
      argPreset: source.argPreset ?? source.preset,
      argInput: source.argInput ?? source.presetInput,
      signerAccountId: source.signerAccountId,
      multisigSpec: source.spec,
      strictSignerCheck: source.strictSignerCheck,
    },
    "proposeMultisigExecuteTrigger",
  );
  return buildProposeMultisigInstruction({
    accountId: source.accountId,
    instructions: [buildExecuteTriggerInstruction(normalized.trigger, normalized.args)],
    spec: source.spec,
    transactionTtlMs: source.transactionTtlMs ?? source.transaction_ttl_ms,
  });
}

/**
 * Encode a multisig proposal wrapping a single `ExecuteTrigger` instruction.
 * @param {{ accountId: string, trigger: string, args?: any, argPreset?: "lifecycle" | "lookup", argInput?: object, spec: MultisigSpec | object, signerAccountId?: string, strictSignerCheck?: boolean, transactionTtlMs?: number | null }} options
 * @returns {Buffer}
 */
export function buildProposeMultisigExecuteTriggerNorito(options, networkPrefix) {
  return noritoEncodeInstruction(buildProposeMultisigExecuteTriggerInstruction(options), networkPrefix);
}

function normalizeMultisigProposeInstructionInput(value, context) {
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${context}${TEXT_MUST_BE_A}JSON instruction object or native Norito instruction payload input`,
        context,
      );
    }
    return trimmed;
  }
  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    return value;
  }
  if (Array.isArray(value)) {
    return Buffer.from(normalizeByteArray(value, context));
  }
  return assertPlainObject(value, context);
}

function rejectRetiredFeeRequestFields(source, context) {
  for (const field of [
    "gasAssetId",
    "gas_asset_id",
    "feeSponsor",
    "fee_sponsor",
    "gasLimit",
    "gas_limit",
  ]) {
    if (Object.prototype.hasOwnProperty.call(source, field)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${context}.${field} is retired; use feePayment`,
        `${context}.${field}`,
      );
    }
  }
}

function normalizeFeePaymentRequest(value, context, { requireGasLimit = false } = {}) {
  const intent = assertPlainObject(value, context);
  assertAllowedFields(intent, new Set(["payer", "value"]), context);
  const payer = assertExactNonBlankString(intent.payer, `${context}.payer`);
  if (payer !== "authority" && payer !== "sponsor") {
    fail(
      V_CODE_INVALID_OBJECT,
      `${context}.payer${TEXT_MUST_BE}authority or sponsor`,
      `${context}.payer`,
    );
  }
  const rawValue = assertPlainObject(intent.value, `${context}.value`);
  const allowedValueFields = new Set(["charge_limits", "gas_limit"]);
  if (payer === "sponsor") {
    allowedValueFields.add("program_id");
    allowedValueFields.add("program_revision");
  }
  assertAllowedFields(rawValue, allowedValueFields, `${context}.value`);
  if (!Array.isArray(rawValue.charge_limits)) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${context}${TEXT_VALUE_CHARGE}limits${TEXT_MUST_BE}an array`,
      `${context}${TEXT_VALUE_CHARGE}limits`,
    );
  }
  let previousKind = -1;
  const chargeLimits = Array.from(rawValue.charge_limits, (entry, index) => {
    if (!Object.prototype.hasOwnProperty.call(rawValue.charge_limits, index)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${context}${TEXT_VALUE_CHARGE}limits${TEXT_MUST_NOT_CONTAIN}holes`,
        `${context}${TEXT_VALUE_CHARGE}limits[${index}]`,
      );
    }
    const itemContext = `${context}${TEXT_VALUE_CHARGE}limits[${index}]`;
    const item = assertPlainObject(entry, itemContext);
    assertAllowedFields(
      item,
      new Set(["kind", "asset_definition_id", "max_amount"]),
      itemContext,
    );
    const taggedKind = assertPlainObject(item.kind, `${itemContext}.kind`);
    assertAllowedFields(
      taggedKind,
      new Set(["kind", "value"]),
      `${itemContext}.kind`,
    );
    const kind = assertExactNonBlankString(
      taggedKind.kind,
      `${itemContext}.kind.kind`,
    );
    const kindIndex = kind === "nexus" ? 0 : kind === "pipeline_gas" ? 1 : -1;
    if (kindIndex < 0 || taggedKind.value !== null) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${itemContext}.kind${TEXT_MUST_BE}the canonical nexus or pipeline_gas tagged unit`,
        `${itemContext}.kind`,
      );
    }
    if (kindIndex <= previousKind) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${context}${TEXT_VALUE_CHARGE}limits${TEXT_MUST_BE}unique and ordered nexus before pipeline_gas`,
        `${context}${TEXT_VALUE_CHARGE}limits`,
      );
    }
    previousKind = kindIndex;
    const maxAmount = asQuantity(item.max_amount, `${itemContext}.max_amount`);
    if (NumericV1.decodeQuantityJson(maxAmount).mantissa <= 0n) {
      fail(
        V_CODE_INVALID_NUMERIC,
        `${itemContext}.max_amount${TEXT_MUST_BE}greater than zero`,
        `${itemContext}.max_amount`,
      );
    }
    return {
      kind: { kind, value: null },
      asset_definition_id: normalizeAssetId(
        item.asset_definition_id,
        `${itemContext}.asset_definition_id`,
      ),
      max_amount: maxAmount,
    };
  });
  const gasLimit =
    rawValue.gas_limit === undefined || rawValue.gas_limit === null
      ? null
      : asPositiveInteger(rawValue.gas_limit, `${context}.value.gas_limit`);
  if (requireGasLimit && gasLimit === null) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${context}.value.gas_limit is required for contract execution`,
      `${context}.value.gas_limit`,
    );
  }
  const normalizedValue = { charge_limits: chargeLimits, gas_limit: gasLimit };
  if (payer === "sponsor") {
    const programId = assertPlainObject(
      rawValue.program_id,
      `${context}${TEXT_VALUE_PROGRAM}id`,
    );
    assertAllowedFields(
      programId,
      new Set(["sponsor", "name"]),
      `${context}${TEXT_VALUE_PROGRAM}id`,
    );
    const sponsor = normalizeAccountId(
      programId.sponsor,
      `${context}${TEXT_VALUE_PROGRAM}id.sponsor`,
    );
    const name = assertExactNonBlankString(
      programId.name,
      `${context}${TEXT_VALUE_PROGRAM}id.name`,
    );
    if (name.normalize("NFC") !== name || /[\s@#$\/]/u.test(name)) {
      fail(
        V_CODE_INVALID_STRING,
        `${context}${TEXT_VALUE_PROGRAM}id.name${TEXT_MUST_BE}a canonical Iroha Name`,
        `${context}${TEXT_VALUE_PROGRAM}id.name`,
      );
    }
    normalizedValue.program_id = { sponsor, name };
    normalizedValue.program_revision = asPositiveInteger(
      rawValue.program_revision,
      `${context}${TEXT_VALUE_PROGRAM}revision`,
    );
  }
  return { payer, value: normalizedValue };
}

/**
 * Build a normalized payload for `ToriiClient.proposeMultisig(...)`.
 * @param {object} options
 * @returns {object}
 */
export function buildMultisigProposeRequest(options) {
  const source = assertPlainObject(options, TEXT_MULTISIG_PROPOSE_2);
  rejectInlinePrivateKeyForMultisigRequest(source, TEXT_MULTISIG_PROPOSE_2);
  rejectUnknownRetailFeeFields(source, TEXT_MULTISIG_PROPOSE_2);
  rejectRetiredFeeRequestFields(source, TEXT_MULTISIG_PROPOSE_2);
  const instructions = source.instructions;
  if (!Array.isArray(instructions) || instructions.length === 0) {
    fail(
      V_CODE_INVALID_OBJECT,
      "multisigPropose.instructions must be a non-empty array",
      "multisigPropose.instructions",
    );
  }
  const payload = {
    ...normalizeMultisigAccountSelectorInput(source, "multisigPropose"),
    signer_account_id: normalizeAccountId(
      source.signerAccountId ?? source.signer_account_id,
      "multisigPropose.signerAccountId",
    ),
    instructions: instructions.map((instruction, index) =>
      normalizeMultisigProposeInstructionInput(
        instruction,
        `multisigPropose.instructions[${index}]`,
      ),
    ),
  };
  payload.fee_payment = normalizeFeePaymentRequest(
    source.feePayment ?? source.fee_payment,
    "multisigPropose.feePayment",
  );
  const publicKeyHex = source.publicKeyHex ?? source.public_key_hex;
  if (publicKeyHex !== undefined && publicKeyHex !== null) {
    payload.public_key_hex = normalizeOptionalHexString(publicKeyHex, "multisigPropose.publicKeyHex");
  }
  const signatureB64 = source.signatureB64 ?? source.signature_b64;
  if (signatureB64 !== undefined && signatureB64 !== null) {
    payload.signature_b64 = normalizeOptionalExactBase64String(
      signatureB64,
      "multisigPropose.signatureB64",
    );
  }
  const creationTimeMs = source.creationTimeMs ?? source.creation_time_ms;
  if (creationTimeMs !== undefined && creationTimeMs !== null) {
    payload.creation_time_ms = asNonNegativeInteger(creationTimeMs, "multisigPropose.creationTimeMs");
  }
  if (Object.hasOwn(source, "validation_fee_assessment")) {
    if (source.validation_fee_assessment === null || source.validation_fee_assessment === undefined) {
      fail(V_CODE_INVALID_OBJECT, "multisigPropose.validation_fee_assessment requires a typed assessment", "multisigPropose.validation_fee_assessment");
    }
    payload.validation_fee_assessment = normalizeRetailFeeAssessment(source.validation_fee_assessment);
  }
  if (source.memo !== undefined && source.memo !== null) {
    if (typeof source.memo !== "string") throw new TypeError("multisig memo must be a string");
    payload.memo = source.memo;
  }
  return payload;
}

/**
 * Build a normalized payload for `ToriiClient.proposeMultisigContractCall(...)`.
 * @param {object} options
 * @returns {object}
 */
export function buildMultisigContractCallProposeRequest(options) {
  const source = assertPlainObject(options, TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_2);
  rejectInlinePrivateKeyForMultisigRequest(source, TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_2);
  rejectRetiredFeeRequestFields(source, TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_2);
  const selector = normalizeMultisigAccountSelectorInput(
    source,
    TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_2,
  );
  const normalized = normalizeMultisigExecuteTriggerOptions(
    {
      trigger: source.trigger,
      args: source.args,
      argPreset: source.argPreset ?? source.preset,
      argInput: source.argInput ?? source.presetInput,
      signerAccountId: source.signerAccountId,
      multisigSpec: source.multisigSpec ?? source.spec,
      strictSignerCheck: source.strictSignerCheck,
    },
    TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_2,
  );
  const payload = {
    ...selector,
    signer_account_id: normalized.signerAccountId ?? normalizeAccountId(
      source.signerAccountId,
      (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE + TEXT_SIGNER_ACCOUNT_ID),
    ),
    ...normalizeContractTargetSelectorInput(source, TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_2),
    entrypoint: assertString(
      source.entrypoint,
      (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE + "entrypoint"),
    ),
    payload:
      source.payload !== undefined
        ? normalizeJsonValue(source.payload, (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE + "payload"))
        : {
            trigger: normalized.trigger,
            args: normalized.args,
          },
  };

  payload.payload = assertPlainObject(
    payload.payload,
    "multisigContractCallPropose.payload",
  );
  payload.fee_payment = normalizeFeePaymentRequest(
    source.feePayment ?? source.fee_payment,
    (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE + "feePayment"),
    { requireGasLimit: true },
  );
  const publicKeyHex = source.publicKeyHex ?? source.public_key_hex;
  if (publicKeyHex !== undefined && publicKeyHex !== null) {
    payload.public_key_hex = normalizeOptionalHexString(
      publicKeyHex,
      (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE + "publicKeyHex"),
    );
  }
  const signatureB64 = source.signatureB64 ?? source.signature_b64;
  if (signatureB64 !== undefined && signatureB64 !== null) {
    payload.signature_b64 = normalizeOptionalExactBase64String(
      signatureB64,
      (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE + "signatureB64"),
    );
  }
  const creationTimeMs = source.creationTimeMs ?? source.creation_time_ms;
  if (creationTimeMs !== undefined && creationTimeMs !== null) {
    payload.creation_time_ms = asNonNegativeInteger(
      creationTimeMs,
      (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE + "creationTimeMs"),
    );
  }
  return payload;
}

function normalizeContractTargetSelectorInput(source, context) {
  const contractAlias = source.contractAlias ?? source.contract_alias;
  if (contractAlias == null || source.contractAddress != null || source.contract_address != null) {
    fail(
      V_CODE_INVALID_OBJECT,
      `${context} requires exact contractAlias without contractAddress`,
      context,
    );
  }
  return {
    contract_alias: assertString(contractAlias, `${context}.contractAlias`),
  };
}

function normalizeGovernanceContractAddress(value, name) {
  const literal = assertExactNonBlankString(value, name);
  parseCanonicalContractAddress(literal, name);
  return literal;
}

function normalizeGovernanceManifestProvenance(value, name) {
  const source = assertPlainObject(value, name);
  assertExactFields(source, ["signer", "signature"], name);
  return (0, contractManifestNormalizers[1])(source, name);
}

function normalizeGovernanceProof(value, name) {
  if (typeof value === "string") {
    return decodeBase64Strict(value, name).toString("base64");
  }
  return normalizeBase64(value, name);
}

/**
 * Build a normalized payload for `ToriiClient.approveMultisigContractCall(...)`.
 * @param {object} options
 * @returns {object}
 */
export function buildMultisigContractCallApproveRequest(options) {
  const source = assertPlainObject(options, TEXT_MULTISIG_CONTRACT_CALL_APPROVE_2);
  rejectInlinePrivateKeyForMultisigRequest(source, TEXT_MULTISIG_CONTRACT_CALL_APPROVE_2);
  rejectRetiredFeeRequestFields(source, TEXT_MULTISIG_CONTRACT_CALL_APPROVE_2);
  const selector = normalizeMultisigAccountSelectorInput(
    source,
    TEXT_MULTISIG_CONTRACT_CALL_APPROVE_2,
  );
  const payload = {
    ...selector,
    signer_account_id: normalizeAccountId(
      source.signerAccountId ?? source.signer_account_id,
      (TEXT_MULTISIG_CONTRACT_CALL_APPROVE + TEXT_SIGNER_ACCOUNT_ID),
    ),
  };
  const proposalId = source.proposalId ?? source.proposal_id;
  if (proposalId !== undefined && proposalId !== null) {
    payload.proposal_id = assertString(
      proposalId,
      (TEXT_MULTISIG_CONTRACT_CALL_APPROVE + "proposalId"),
    );
  }
  const instructionsHash = source.instructionsHash ?? source.instructions_hash;
  if (instructionsHash !== undefined && instructionsHash !== null) {
    payload.instructions_hash = normalizeOptionalHexString(
      instructionsHash,
      (TEXT_MULTISIG_CONTRACT_CALL_APPROVE + "instructionsHash"),
    );
  }
  if (!payload.proposal_id && !payload.instructions_hash) {
    fail(
      V_CODE_INVALID_OBJECT,
      "multisigContractCallApprove requires proposalId or instructionsHash",
      TEXT_MULTISIG_CONTRACT_CALL_APPROVE_2,
    );
  }
  const publicKeyHex = source.publicKeyHex ?? source.public_key_hex;
  if (publicKeyHex !== undefined && publicKeyHex !== null) {
    payload.public_key_hex = normalizeOptionalHexString(
      publicKeyHex,
      (TEXT_MULTISIG_CONTRACT_CALL_APPROVE + "publicKeyHex"),
    );
  }
  const signatureB64 = source.signatureB64 ?? source.signature_b64;
  if (signatureB64 !== undefined && signatureB64 !== null) {
    payload.signature_b64 = normalizeOptionalExactBase64String(
      signatureB64,
      (TEXT_MULTISIG_CONTRACT_CALL_APPROVE + "signatureB64"),
    );
  }
  const creationTimeMs = source.creationTimeMs ?? source.creation_time_ms;
  if (creationTimeMs !== undefined && creationTimeMs !== null) {
    payload.creation_time_ms = asNonNegativeInteger(
      creationTimeMs,
      (TEXT_MULTISIG_CONTRACT_CALL_APPROVE + "creationTimeMs"),
    );
  }
  payload.fee_payment = normalizeFeePaymentRequest(
    source.feePayment ?? source.fee_payment,
    (TEXT_MULTISIG_CONTRACT_CALL_APPROVE + "feePayment"),
  );
  payload.contract_alias = assertString(
    source.contract_alias,
    "multisigContractCallApprove.contract_alias",
  );
  payload.entrypoint = assertString(
    source.entrypoint,
    "multisigContractCallApprove.entrypoint",
  );
  payload.payload = assertPlainObject(
    source.payload,
    "multisigContractCallApprove.payload",
  );
  return payload;
}

/**
 * Build a `Kaigi::CreateKaigi` instruction payload.
 * @param {object} call
 * @returns {{Kaigi: {CreateKaigi: {call: object}}}}
 */
export function buildCreateKaigiInstruction(call) {
  const normalizedCall = normalizeCreateKaigiInput(call);
  return {
    Kaigi: {
      CreateKaigi: normalizedCall,
    },
  };
}

/**
 * Build a `Kaigi::JoinKaigi` instruction payload.
 * @param {object} options
 * @returns {{Kaigi: {JoinKaigi: object}}}
 */
export function buildJoinKaigiInstruction(options) {
  const normalized = normalizeJoinOrLeaveInput("joinKaigi", options);
  return {
    Kaigi: {
      JoinKaigi: normalized,
    },
  };
}

/**
 * Build a `Kaigi::LeaveKaigi` instruction payload.
 * @param {object} options
 * @returns {{Kaigi: {LeaveKaigi: object}}}
 */
export function buildLeaveKaigiInstruction(options) {
  const normalized = normalizeJoinOrLeaveInput("leaveKaigi", options);
  return {
    Kaigi: {
      LeaveKaigi: normalized,
    },
  };
}

/**
 * Build a `Kaigi::EndKaigi` instruction payload.
 * @param {object} options
 * @returns {{Kaigi: {EndKaigi: object}}}
 */
export function buildEndKaigiInstruction(options) {
  const normalized = normalizeEndKaigiInput(options);
  return {
    Kaigi: {
      EndKaigi: normalized,
    },
  };
}

/**
 * Build a `Kaigi::RecordKaigiUsage` instruction payload.
 * @param {object} options
 * @returns {{Kaigi: {RecordKaigiUsage: object}}}
 */
export function buildRecordKaigiUsageInstruction(options) {
  const normalized = normalizeKaigiUsageInput(options);
  return {
    Kaigi: {
      RecordKaigiUsage: normalized,
    },
  };
}

/**
 * Build a `Kaigi::SetKaigiRelayManifest` instruction payload.
 * @param {object} options
 * @returns {{Kaigi: {SetKaigiRelayManifest: object}}}
 */
export function buildSetKaigiRelayManifestInstruction(options) {
  const normalized = normalizeSetRelayManifestInput(options);
  return {
    Kaigi: {
      SetKaigiRelayManifest: normalized,
    },
  };
}

/**
 * Build a `Kaigi::RegisterKaigiRelay` instruction payload.
 * @param {object} options
 * @returns {{Kaigi: {RegisterKaigiRelay: {relay: object}}}}
 */
export function buildRegisterKaigiRelayInstruction(options) {
  const normalized = normalizeRegisterRelayInput(options);
  return {
    Kaigi: {
      RegisterKaigiRelay: normalized,
    },
  };
}

/**
 * Build a `Kaigi::UnregisterKaigiRelay` instruction payload.
 * @param {object} options
 * @returns {{Kaigi: {UnregisterKaigiRelay: {relay_id: string}}}}
 */
export function buildUnregisterKaigiRelayInstruction(options) {
  const normalized = normalizeUnregisterRelayInput(options);
  return {
    Kaigi: {
      UnregisterKaigiRelay: normalized,
    },
  };
}

/**
 * Build a `Kaigi::ReportKaigiRelayHealth` instruction payload.
 * @param {object} options
 * @returns {{Kaigi: {ReportKaigiRelayHealth: object}}}
 */
export function buildReportKaigiRelayHealthInstruction(options) {
  const normalized = normalizeReportKaigiRelayHealthInput(options);
  return {
    Kaigi: {
      ReportKaigiRelayHealth: normalized,
    },
  };
}

/**
 * Build a `ProposeDeployContract` instruction payload.
 * @param {object} options
 * @returns {{ProposeDeployContract: object}}
 */
export function buildProposeDeployContractInstruction(options) {
  const source = assertPlainObject(options, TEXT_PROPOSE_DEPLOY_CONTRACT);
  rejectGovernancePrivateKeyFieldsDeep(source, TEXT_PROPOSE_DEPLOY_CONTRACT);
  assertAllowedFields(
    source,
    new Set([
      TEXT_CONTRACT_ADDRESS,
      "codeHash",
      "abiHash",
      "abiVersion",
      "manifestProvenance",
    ]),
    TEXT_PROPOSE_DEPLOY_CONTRACT,
  );
  for (const field of [TEXT_CONTRACT_ADDRESS, "codeHash", "abiHash"]) {
    if (!Object.prototype.hasOwnProperty.call(source, field)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `${TEXT_PROPOSE_DEPLOY_CONTRACT_2}${field}${TEXT_IS_REQUIRED}`,
        `${TEXT_PROPOSE_DEPLOY_CONTRACT_2}${field}`,
      );
    }
  }
  const abiVersion = Object.prototype.hasOwnProperty.call(source, "abiVersion")
    ? source.abiVersion
    : 1;
  if (abiVersion !== 1) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      ("abiVersion" + TEXT_MUST_BE + "exactly 1"),
      "abiVersion",
    );
  }
  const payload = {
    contract_address: normalizeGovernanceContractAddress(
      source.contractAddress,
      (TEXT_PROPOSE_DEPLOY_CONTRACT_2 + TEXT_CONTRACT_ADDRESS),
    ),
    code_hash: normalizeGovernanceHex32(source.codeHash, "codeHash"),
    abi_hash: normalizeGovernanceHex32(source.abiHash, "abiHash"),
    abi_version: abiVersion,
  };
  if (
    Object.prototype.hasOwnProperty.call(source, "manifestProvenance") &&
    source.manifestProvenance !== undefined &&
    source.manifestProvenance !== null
  ) {
    payload.manifest_provenance = normalizeGovernanceManifestProvenance(
      source.manifestProvenance,
      "manifestProvenance",
    );
  }
  return { ProposeDeployContract: payload };
}

/**
 * Build a `CastZkBallot` instruction payload.
 * @param {object} options
 * @returns {{CastZkBallot: object}}
 */
export function buildCastZkBallotInstruction(options) {
  const source = assertPlainObject(options, "castZkBallot");
  rejectGovernancePrivateKeyFieldsDeep(source, "castZkBallot");
  assertAllowedFields(
    source,
    new Set(["electionId", "proof", "publicInputs"]),
    "castZkBallot",
  );
  for (const field of ["electionId", "proof"]) {
    if (!Object.prototype.hasOwnProperty.call(source, field)) {
      fail(
        V_CODE_INVALID_OBJECT,
        `castZkBallot.${field}${TEXT_IS_REQUIRED}`,
        `castZkBallot.${field}`,
      );
    }
  }
  return {
    CastZkBallot: {
      election_id: normalizeGovernanceSelectorV1(source.electionId, "electionId"),
      proof_b64: normalizeGovernanceProof(source.proof, "proof"),
      public_inputs_json: normalizeJsonPayload(
        Object.prototype.hasOwnProperty.call(source, "publicInputs")
          ? source.publicInputs
          : undefined,
        "publicInputs",
      ),
    },
  };
}

/**
 * Build a `CastPlainBallot` instruction payload.
 * @param {object} options
 * @returns {{CastPlainBallot: object}}
 */
export function buildCastPlainBallotInstruction(options) {
  const source = assertPlainObject(options, "castPlainBallot");
  const fields = ["referendumId", "owner", "amount", "durationBlocks", "direction"];
  if (
    Object.keys(source).length !== fields.length ||
    fields.some((field) => !Object.prototype.hasOwnProperty.call(source, field))
  ) {
    fail(
      V_CODE_INVALID_OBJECT,
      `castPlainBallot must contain exactly ${fields.join(", ")}`,
      "castPlainBallot",
    );
  }
  return {
    CastPlainBallot: {
      referendum_id: normalizeGovernanceSelectorV1(source.referendumId, "referendumId"),
      owner: normalizeAccountId(source.owner, "owner"),
      amount: asQuantity(source.amount, "amount"),
      duration_blocks: asGovernanceU64JsonValue(source.durationBlocks, "durationBlocks"),
      direction: normalizeDirection(source.direction, "direction"),
    },
  };
}

/**
 * Build the choice-free update for an existing public standalone ballot.
 * A second cast is never an update, and the choice is read from the retained lock.
 * @param {object} options
 * @returns {{UpdatePlainConviction: object}}
 */
export function buildUpdatePlainConvictionInstruction(options) {
  const source = assertPlainObject(options, "updatePlainConviction");
  const fields = ["referendumId", "owner", "amount", "durationBlocks"];
  if (
    Object.keys(source).length !== fields.length ||
    fields.some((field) => !Object.prototype.hasOwnProperty.call(source, field))
  ) {
    fail(
      V_CODE_INVALID_OBJECT,
      `updatePlainConviction must contain exactly ${fields.join(", ")}`,
      "updatePlainConviction",
    );
  }
  return {
    UpdatePlainConviction: {
      referendum_id: normalizeGovernanceSelectorV1(source.referendumId, "referendumId"),
      owner: normalizeAccountId(source.owner, "owner"),
      amount: asQuantity(source.amount, "amount"),
      duration_blocks: asGovernanceU64JsonValue(source.durationBlocks, "durationBlocks"),
    },
  };
}

/**
 * Build a `ClaimTwitterFollowReward` instruction payload.
 * @param {{ bindingHash: object }} options
 * @returns {{ClaimTwitterFollowReward: { binding_hash: object }}}
 */
export function buildClaimTwitterFollowRewardInstruction(options) {
  const source = assertPlainObject(options, "claimTwitterFollowReward");
  const binding =
    source.binding_hash ??
    source.bindingHash ??
    source.binding ??
    source.hash;
  return {
    ClaimTwitterFollowReward: {
      binding_hash: normalizeKeyedHashInput(
        binding,
        "claimTwitterFollowReward.bindingHash",
      ),
    },
  };
}

/**
 * Build a `SendToTwitter` instruction payload.
 * @param {{ bindingHash: object, amount: KotodamaQuantity|string|bigint }} options
 * @returns {{SendToTwitter: { binding_hash: object, amount: string }}}
 */
export function buildSendToTwitterInstruction(options) {
  const source = assertPlainObject(options, "sendToTwitter");
  const binding =
    source.binding_hash ??
    source.bindingHash ??
    source.binding ??
    source.hash;
  const amountValue = source.amount ?? source.quantity;
  return {
    SendToTwitter: {
      binding_hash: normalizeKeyedHashInput(
        binding,
        "sendToTwitter.bindingHash",
      ),
      amount: asQuantity(amountValue, "sendToTwitter.amount"),
    },
  };
}

/**
 * Build a `CancelTwitterEscrow` instruction payload.
 * @param {{ bindingHash: object }} options
 * @returns {{CancelTwitterEscrow: { binding_hash: object }}}
 */
export function buildCancelTwitterEscrowInstruction(options) {
  const source = assertPlainObject(options, "cancelTwitterEscrow");
  const binding =
    source.binding_hash ??
    source.bindingHash ??
    source.binding ??
    source.hash;
  return {
    CancelTwitterEscrow: {
      binding_hash: normalizeKeyedHashInput(
        binding,
        "cancelTwitterEscrow.bindingHash",
      ),
    },
  };
}

/**
 * Build a `SubmitAgendaProposal` instruction payload.
 * @param {{ proposal: object }} options
 * @returns {{SubmitAgendaProposal: { proposal: object }}}
 */
export function buildSubmitAgendaProposalInstruction(options) {
  const source = assertPlainObject(options, "submitAgendaProposal");
  const proposal = assertPlainObject(
    source.proposal,
    "submitAgendaProposal.proposal",
  );
  return {
    SubmitAgendaProposal: {
      proposal,
    },
  };
}

/**
 * Build a `RegisterSmartContractCode` instruction payload.
 * @param {{artifactId: {dataspaceId: number|bigint|string, codeHash: string|Buffer}, manifest: object}} options
 * @returns {{RegisterSmartContractCode: {artifact_id: {dataspace_id: string, code_hash: string}, manifest: object}}}
 */
export function buildRegisterSmartContractCodeInstruction(options) {
  if (!options || typeof options !== "object") {
    fail(
      V_CODE_INVALID_OBJECT,
      ("buildRegisterSmartContractCodeInstruction options" + TEXT_MUST_BE + "an object"),
    );
  }
  const manifest = options.manifest;
  const normalized = (0, contractManifestNormalizers[0])(manifest);
  const artifactId = normalizeContractArtifactId(options.artifactId);
  if (normalized.code_hash !== artifactId.code_hash) {
    throw new TypeError("artifactId.codeHash must equal manifest.code_hash");
  }
  return {
    RegisterSmartContractCode: {
      artifact_id: artifactId,
      manifest: normalized,
    },
  };
}

/**
 * Build a `RegisterSmartContractBytes` instruction payload.
 * @param {{artifactId: {dataspaceId: number|bigint|string, codeHash: string|Buffer}, code: ArrayBufferView|ArrayBuffer|Buffer|string}} options
 * @returns {{RegisterSmartContractBytes: {artifact_id: {dataspace_id: string, code_hash: string}, code: string}}}
 */
export function buildRegisterSmartContractBytesInstruction(options) {
  if (!options || typeof options !== "object") {
    fail(
      V_CODE_INVALID_OBJECT,
      ("buildRegisterSmartContractBytesInstruction options" + TEXT_MUST_BE + "an object"),
    );
  }
  const code = normalizeBase64(options.code, (TEXT_REGISTER_SMART_CONTRACT_BYTES + "code"));
  if (code.length === 0) {
    fail(
      V_CODE_INVALID_STRING,
      (TEXT_REGISTER_SMART_CONTRACT_BYTES + "code" + TEXT_MUST_BE + "a non-empty base64 string"),
      (TEXT_REGISTER_SMART_CONTRACT_BYTES + "code"),
    );
  }
  return {
    RegisterSmartContractBytes: {
      artifact_id: normalizeContractArtifactId(options.artifactId),
      code,
    },
  };
}

const SMART_CONTRACT_CODE_CHUNK_BYTES = 65_536;
const U64_MAX_VALUE = 0xffff_ffff_ffff_ffffn;

function normalizeCanonicalU64(value, name) {
  let normalized;
  if (typeof value === "bigint") {
    normalized = value;
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      fail(
        V_CODE_INVALID_NUMERIC,
        `${name}${TEXT_MUST_BE_A}safe ${TEXT_UNSIGNED_INTEGER_BIGINT_OR_CANONICAL_DECIMAL_STRING}`,
        name,
      );
    }
    normalized = BigInt(value);
  } else if (typeof value === "string" && /^(?:0|[1-9]\d*)$/u.test(value)) {
    normalized = BigInt(value);
  } else {
    fail(
      V_CODE_INVALID_NUMERIC,
      `${name}${TEXT_MUST_BE_AN}${TEXT_UNSIGNED_INTEGER_BIGINT_OR_CANONICAL_DECIMAL_STRING}`,
      name,
    );
  }
  if (normalized < 0n || normalized > U64_MAX_VALUE) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name} must fit in an${TEXT_UNSIGNED_64_BIT_INTEGER}`,
      name,
    );
  }
  return normalized.toString();
}

/** Normalize one explicitly scoped artifact input to its canonical Norito record. */
function normalizeContractArtifactId(value) {
  const source = assertPlainObject(value, "artifactId");
  assertExactFields(source, ["dataspaceId", "codeHash"], "artifactId");
  if (typeof source.dataspaceId === "string" && source.dataspaceId.length > 20) {
    throw new TypeError("artifactId.dataspaceId must fit u64");
  }
  return {
    dataspace_id: normalizeCanonicalU64(source.dataspaceId, "artifactId.dataspaceId"),
    code_hash: normalizeHash(source.codeHash, "artifactId.codeHash"),
  };
}

function normalizeSmartContractExactString(value, name) {
  const literal = assertString(value, name);
  if (literal.length === 0 || literal.trim() !== literal || /[\u0000-\u001F\u007F]/u.test(literal)) {
    fail(
      V_CODE_INVALID_STRING,
      `${name}${TEXT_MUST_BE_A}non-empty exact string without control characters`,
      name,
    );
  }
  return literal;
}

function normalizeSmartContractChunk(value, name) {
  let buffer;
  if (typeof value === "string") {
    const canonical = normalizeBase64(value, name);
    buffer = Buffer.from(canonical, "base64");
  } else {
    buffer = toBinaryBuffer(value, name);
  }
  if (buffer.length === 0 || buffer.length > SMART_CONTRACT_CODE_CHUNK_BYTES) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      `${name}${TEXT_MUST_CONTAIN}1..=${SMART_CONTRACT_CODE_CHUNK_BYTES} bytes`,
      name,
    );
  }
  return buffer.toString("base64");
}

/**
 * Build one bounded `UploadSmartContractCodeChunk` instruction.
 * @param {{artifactId: {dataspaceId: bigint|string|number, codeHash: string|Buffer}, totalSize: number|bigint|string, chunkIndex: number, chunkCount: number, chunk: ArrayBufferView|ArrayBuffer|Buffer|string}} options
 */
export function buildUploadSmartContractCodeChunkInstruction(options) {
  const source = assertPlainObject(options, "uploadSmartContractCodeChunk");
  const totalSize = normalizeCanonicalU64(
    source.totalSize ?? source.total_size,
    (TEXT_UPLOAD_SMART_CONTRACT_CODE_CHUNK + "totalSize"),
  );
  const chunkIndex = normalizeU32(
    source.chunkIndex ?? source.chunk_index,
    (TEXT_UPLOAD_SMART_CONTRACT_CODE_CHUNK + "chunkIndex"),
  );
  const chunkCount = normalizePositiveU32(
    source.chunkCount ?? source.chunk_count,
    (TEXT_UPLOAD_SMART_CONTRACT_CODE_CHUNK + "chunkCount"),
  );
  if (chunkIndex >= chunkCount) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      (TEXT_UPLOAD_SMART_CONTRACT_CODE_CHUNK + "chunkIndex" + TEXT_MUST_BE + "less than chunkCount"),
      (TEXT_UPLOAD_SMART_CONTRACT_CODE_CHUNK + "chunkIndex"),
    );
  }
  const chunk = normalizeSmartContractChunk(
    source.chunk,
    (TEXT_UPLOAD_SMART_CONTRACT_CODE_CHUNK + "chunk"),
  );
  const totalSizeBigInt = BigInt(totalSize);
  const expectedChunkCount =
    (totalSizeBigInt + BigInt(SMART_CONTRACT_CODE_CHUNK_BYTES) - 1n) /
    BigInt(SMART_CONTRACT_CODE_CHUNK_BYTES);
  if (totalSizeBigInt === 0n || expectedChunkCount !== BigInt(chunkCount)) {
    fail(
      V_CODE_INVALID_NUMERIC,
      (TEXT_UPLOAD_SMART_CONTRACT_CODE_CHUNK + TEXT_CHUNK_COUNT_MUST_EQUAL_CEIL_TOTAL_SIZE_65536),
      (TEXT_UPLOAD_SMART_CONTRACT_CODE_CHUNK + "chunkCount"),
    );
  }
  const chunkBytes = Buffer.from(chunk, "base64").length;
  const expectedChunkBytes =
    chunkIndex + 1 === chunkCount
      ? Number(totalSizeBigInt - BigInt(chunkIndex) * BigInt(SMART_CONTRACT_CODE_CHUNK_BYTES))
      : SMART_CONTRACT_CODE_CHUNK_BYTES;
  if (chunkBytes !== expectedChunkBytes) {
    fail(
      V_CODE_INVALID_NUMERIC,
      `${TEXT_UPLOAD_SMART_CONTRACT_CODE_CHUNK}chunk${TEXT_MUST_CONTAIN}exactly ${expectedChunkBytes} bytes for this descriptor`,
      (TEXT_UPLOAD_SMART_CONTRACT_CODE_CHUNK + "chunk"),
    );
  }
  return {
    UploadSmartContractCodeChunk: {
      artifact_id: normalizeContractArtifactId(source.artifactId),
      total_size: totalSize,
      chunk_index: chunkIndex,
      chunk_count: chunkCount,
      chunk,
    },
  };
}

/** Build a `FinalizeSmartContractCodeUpload` instruction. */
export function buildFinalizeSmartContractCodeUploadInstruction(options) {
  const source = assertPlainObject(options, "finalizeSmartContractCodeUpload");
  const totalSize = normalizeCanonicalU64(
    source.totalSize ?? source.total_size,
    (TEXT_FINALIZE_SMART_CONTRACT_CODE_UPLOAD + "totalSize"),
  );
  const chunkCount = normalizePositiveU32(
    source.chunkCount ?? source.chunk_count,
    (TEXT_FINALIZE_SMART_CONTRACT_CODE_UPLOAD + "chunkCount"),
  );
  const expectedChunkCount =
    (BigInt(totalSize) + BigInt(SMART_CONTRACT_CODE_CHUNK_BYTES) - 1n) /
    BigInt(SMART_CONTRACT_CODE_CHUNK_BYTES);
  if (BigInt(totalSize) === 0n || expectedChunkCount !== BigInt(chunkCount)) {
    fail(
      V_CODE_INVALID_NUMERIC,
      (TEXT_FINALIZE_SMART_CONTRACT_CODE_UPLOAD + TEXT_CHUNK_COUNT_MUST_EQUAL_CEIL_TOTAL_SIZE_65536),
      (TEXT_FINALIZE_SMART_CONTRACT_CODE_UPLOAD + "chunkCount"),
    );
  }
  return {
    FinalizeSmartContractCodeUpload: {
      artifact_id: normalizeContractArtifactId(source.artifactId),
      total_size: totalSize,
      chunk_count: chunkCount,
    },
  };
}

/** Build an owner-scoped `CancelSmartContractCodeUpload` instruction. */
export function buildCancelSmartContractCodeUploadInstruction(options) {
  const source = assertPlainObject(options, "cancelSmartContractCodeUpload");
  return {
    CancelSmartContractCodeUpload: {
      artifact_id: normalizeContractArtifactId(source.artifactId),
    },
  };
}

/** Build the nonce- and alias-CAS guarded `CommitContractDeployment` instruction. */
export function buildCommitContractDeploymentInstruction(options) {
  const source = assertPlainObject(options, "commitContractDeployment");
  const leaseExpiry = source.leaseExpiryMs ?? source.lease_expiry_ms;
  const previousAddress =
    source.expectedPreviousContractAddress ??
    source.expected_previous_contract_address;
  return {
    CommitContractDeployment: {
      expected_deploy_nonce: normalizeCanonicalU64(
        source.expectedDeployNonce ?? source.expected_deploy_nonce,
        (TEXT_COMMIT_CONTRACT_DEPLOYMENT + "expectedDeployNonce"),
      ),
      contract_address: normalizeSmartContractExactString(
        source.contractAddress ?? source.contract_address,
        (TEXT_COMMIT_CONTRACT_DEPLOYMENT + TEXT_CONTRACT_ADDRESS),
      ),
      code_hash: normalizeHash(
        source.codeHash ?? source.code_hash,
        (TEXT_COMMIT_CONTRACT_DEPLOYMENT + "codeHash"),
      ),
      contract_alias: normalizeSmartContractExactString(
        source.contractAlias ?? source.contract_alias,
        (TEXT_COMMIT_CONTRACT_DEPLOYMENT + "contractAlias"),
      ),
      lease_expiry_ms:
        leaseExpiry === undefined || leaseExpiry === null
          ? null
          : normalizeCanonicalU64(
              leaseExpiry,
              (TEXT_COMMIT_CONTRACT_DEPLOYMENT + "leaseExpiryMs"),
            ),
      expected_previous_contract_address:
        previousAddress === undefined || previousAddress === null
          ? null
          : normalizeSmartContractExactString(
              previousAddress,
              (TEXT_COMMIT_CONTRACT_DEPLOYMENT + "expectedPreviousContractAddress"),
            ),
    },
  };
}

/**
 * Build a `RemoveSmartContractBytes` instruction payload.
 * @param {{artifactId: {dataspaceId: number|bigint|string, codeHash: string|Buffer}, reason?: string | null}} options
 * @returns {{RemoveSmartContractBytes: {artifact_id: {dataspace_id: string, code_hash: string}, reason?: string}}}
 */
export function buildRemoveSmartContractBytesInstruction(options) {
  const source = assertPlainObject(options, "removeSmartContractBytes");
  const payload = {
    artifact_id: normalizeContractArtifactId(source.artifactId),
  };
  const reason = source.reason ?? source.reasonText ?? source.reason_text;
  if (reason !== undefined && reason !== null) {
    payload.reason = assertString(
      reason,
      "removeSmartContractBytes.reason",
    );
  }
  return {
    RemoveSmartContractBytes: payload,
  };
}

/**
 * Build a `zk::RegisterZkAsset` instruction payload.
 * @param {object} options
 * @returns {{zk: {RegisterZkAsset: object}}}
 */
export function buildRegisterZkAssetInstruction(options) {
  const source = assertPlainObject(options, "registerZkAsset");
  assertAllowedFields(
    source,
    new Set([
      TEXT_ASSET_DEFINITION_ID,
      "asset_definition_id",
      "asset",
      "definitionId",
      "unshieldVerifyingKey",
      "vkUnshield",
      "vk_unshield",
    ]),
    "registerZkAsset",
  );
  const asset =
    source.assetDefinitionId ??
    source.asset_definition_id ??
    source.asset ??
    source.definitionId;
  const vkUnshield = normalizeVerifyingKeyId(
    source.unshieldVerifyingKey ?? source.vkUnshield ?? source.vk_unshield,
    "registerZkAsset.vkUnshield",
  );
  const payload = {
    asset: assertString(asset, "registerZkAsset.asset"),
    vk_unshield: vkUnshield,
  };
  return {
    zk: {
      RegisterZkAsset: payload,
    },
  };
}

/**
 * Build a `zk::ScheduleConfidentialPolicyTransition` instruction payload.
 * @param {object} options
 * @returns {{zk: {ScheduleConfidentialPolicyTransition: object}}}
 */
export function buildScheduleConfidentialPolicyTransitionInstruction(options) {
  const source = assertPlainObject(options, "scheduleConfidentialPolicyTransition");
  const asset =
    source.assetDefinitionId ??
    source.asset_definition_id ??
    source.asset ??
    source.definitionId;
  const conversionWindow =
    source.conversionWindow ?? source.conversion_window ?? source.window;
  const payload = {
    asset: assertString(asset, (TEXT_SCHEDULE_CONFIDENTIAL_POLICY_TRANSITION + "asset")),
    new_mode: normalizeConfidentialPolicyMode(
      source.newMode ?? source.mode ?? source.new_mode,
      (TEXT_SCHEDULE_CONFIDENTIAL_POLICY_TRANSITION + "newMode"),
    ),
    effective_height: asNonNegativeInteger(
      source.effectiveHeight ?? source.effective_height,
      (TEXT_SCHEDULE_CONFIDENTIAL_POLICY_TRANSITION + "effectiveHeight"),
    ),
    transition_id: normalizeHash(
      source.transitionId ?? source.transition_id,
      (TEXT_SCHEDULE_CONFIDENTIAL_POLICY_TRANSITION + "transitionId"),
    ),
    conversion_window:
      conversionWindow === undefined || conversionWindow === null
        ? null
        : asNonNegativeInteger(
            conversionWindow,
            (TEXT_SCHEDULE_CONFIDENTIAL_POLICY_TRANSITION + "conversionWindow"),
          ),
  };
  return {
    zk: {
      ScheduleConfidentialPolicyTransition: payload,
    },
  };
}

/**
 * Build a `zk::CancelConfidentialPolicyTransition` instruction payload.
 * @param {object} options
 * @returns {{zk: {CancelConfidentialPolicyTransition: object}}}
 */
export function buildCancelConfidentialPolicyTransitionInstruction(options) {
  const source = assertPlainObject(options, "cancelConfidentialPolicyTransition");
  const asset =
    source.assetDefinitionId ??
    source.asset_definition_id ??
    source.asset ??
    source.definitionId;
  return {
    zk: {
      CancelConfidentialPolicyTransition: {
        asset: assertString(asset, "cancelConfidentialPolicyTransition.asset"),
        transition_id: normalizeHash(
          source.transitionId ?? source.transition_id,
          "cancelConfidentialPolicyTransition.transitionId",
        ),
      },
    },
  };
}

/**
 * Build a `zk::CreateElection` instruction payload with 2–64 options.
 * @param {object} options
 * @returns {{zk: {CreateElection: object}}}
 */
export function buildCreateElectionInstruction(options) {
  const source = assertPlainObject(options, "createElection");
  const electionId = normalizeGovernanceSelectorV1(
    source.electionId ?? source.election_id,
    (TEXT_CREATE_ELECTION + "electionId"),
  );
  const optionCount = asPositiveInteger(source.options, (TEXT_CREATE_ELECTION + "options"));
  if (optionCount < MIN_ELECTION_OPTIONS_V1 || optionCount > MAX_ELECTION_OPTIONS_V1) {
    fail(V_CODE_VALUE_OUT_OF_RANGE, "createElection.options must be between 2 and 64", "createElection.options");
  }
  const payload = {
    election_id: electionId,
    options: optionCount,
    eligible_root: normalizeFixedBytes(source.eligibleRoot ?? source.eligible_root, (TEXT_CREATE_ELECTION + "eligibleRoot"), 32),
    start_ts: asNonNegativeInteger(source.startTs ?? source.start_ts ?? source.startTimestampMs, (TEXT_CREATE_ELECTION + "startTs")),
    end_ts: asNonNegativeInteger(source.endTs ?? source.end_ts ?? source.endTimestampMs, (TEXT_CREATE_ELECTION + "endTs")),
    vk_ballot: normalizeVerifyingKeyId(source.vkBallot ?? source.ballotVerifyingKey, (TEXT_CREATE_ELECTION + "vkBallot")),
    vk_tally: normalizeVerifyingKeyId(source.vkTally ?? source.tallyVerifyingKey, (TEXT_CREATE_ELECTION + "vkTally")),
    domain_tag: assertString(source.domainTag ?? source.domain_tag ?? "zk", (TEXT_CREATE_ELECTION + "domainTag")),
  };
  return {
    zk: {
      CreateElection: payload,
    },
  };
}

/**
 * Build a `zk::SubmitBallot` instruction payload.
 * @param {object} options
 * @returns {{zk: {SubmitBallot: object}}}
 */
export function buildSubmitBallotInstruction(options) {
  const source = assertPlainObject(options, "submitBallot");
  const payload = {
    election_id: normalizeGovernanceSelectorV1(
      source.electionId ?? source.election_id,
      "submitBallot.electionId",
    ),
    ciphertext: normalizeByteArray(
      source.ciphertext ?? source.ciphertextBytes ?? source.ciphertext_b64 ?? source.ciphertextB64,
      "submitBallot.ciphertext",
    ),
    ballot_proof: normalizeProofAttachment(
      source.ballotProof ?? source.proof ?? source.ballot_proof,
      "submitBallot.ballotProof",
    ),
    nullifier: normalizeFixedBytes(source.nullifier, "submitBallot.nullifier", 32),
  };
  return {
    zk: {
      SubmitBallot: payload,
    },
  };
}

/**
 * Build a `zk::FinalizeElection` instruction payload with 2–64 exact u128 tally weights.
 * Large weights remain bigint until the Norito encoder emits their exact JSON numeric tokens.
 * @param {object} options
 * @returns {{zk: {FinalizeElection: object}}}
 */
export function buildFinalizeElectionInstruction(options) {
  const source = assertPlainObject(options, "finalizeElection");
  const tallyInput = Array.isArray(source.tally) ? source.tally : [];
  if (tallyInput.length < MIN_ELECTION_OPTIONS_V1 || tallyInput.length > MAX_ELECTION_OPTIONS_V1) {
    fail(
      V_CODE_VALUE_OUT_OF_RANGE,
      "finalizeElection.tally must contain between 2 and 64 entries",
      "finalizeElection.tally",
    );
  }
  const tally = tallyInput.map((entry, index) =>
    asElectionTallyU128(entry, `finalizeElection.tally[${index}]`),
  );
  if (tally.reduce((sum, weight) => sum + BigInt(weight), 0n) > UINT128_MAX_BIGINT) {
    fail(V_CODE_VALUE_OUT_OF_RANGE, "finalizeElection.tally total must fit in unsigned 128 bits", "finalizeElection.tally");
  }
  const payload = {
    election_id: normalizeGovernanceSelectorV1(
      source.electionId ?? source.election_id,
      "finalizeElection.electionId",
    ),
    tally,
    tally_proof: normalizeProofAttachment(source.tallyProof ?? source.proof ?? source.tally_proof, "finalizeElection.tallyProof"),
  };
  return {
    zk: {
      FinalizeElection: payload,
    },
  };
}

export { normalizeAccountId, normalizeAssetId, normalizeAssetHoldingId, normalizeRwaId };
