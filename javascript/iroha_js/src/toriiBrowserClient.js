import { requireNetworkPrefix } from "./networkPrefix.js";
import { rejectError, rejectRange, rejectType } from "./validationThrow.js";
import { ToriiHttpError, ToriiStreamGapError, toriiHttpErrorFromResponseText } from "./toriiErrors.js";
import { createToriiCollections } from "./query/collections.js";
import { decodePageText, stringifyRequestJson } from "./query/page.js";
import { filterQueryText } from "./query/listQuery.js";
import { decodeEventFrames } from "./toriiEventStream.js";
import { Buffer } from "buffer";

import { blake2b256 } from "./blake2b.js";
import { computeHashLiteralCrc } from "./hashLiteralCrc.js";
import {
  NumericV1,
  NumericV1Error,
} from "./numericV1.js";
import { parseStrictLosslessIntegerJson } from "./strictLosslessJson.js";
import { readAccountCapabilitiesResponseV1 } from "./accountCapabilities.js";
import {
  noritoDecodeBlockProofs,
  noritoEncodeMultisigContractCallApproveRequest,
  noritoEncodeMultisigContractCallProposeRequest,
  noritoEncodeMultisigProposeRequest,
} from "./norito.js";
import { browserSignedTransactionHashHex } from "./transactionCodec.js";
import { buildCanonicalJsonRequest } from "./canonicalRequest.js";
import { requireCanonicalAuthAccount } from "./canonicalAccount.js";
import { rejectPrecomputedCanonicalHeaders } from "./applicationPostAuth.js";
import { networkIdBytes } from "./networkId.js";
import {
  applyOperatorGetHeaders,
  requireOperatorSigningContext,
} from "./operatorRequest.browser.js";
import { ensureCanonicalAccountId } from "./normalizers.js";
import {
  SUMERAGI_LANES_TYPED_JSON_MAX_BYTES,
  SUMERAGI_STATUS_TYPED_JSON_MAX_BYTES,
} from "./sumeragiTypedLimits.js";
import {
  AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1,
  AUTHENTICATED_BLOCK_PROOFS_MAX_PROOF_BYTES_V1,
} from "./authenticatedBlockProofs.browser.js";

export {
  FilterSyntaxError,
  ListQueryError,
  ToriiError,
  ToriiHttpError,
  ToriiStreamGapError,
} from "./toriiErrors.js";
export * from "./query/index.js";

const TEXT_MUST_BE_AN = " must be an ";
const TEXT_MUST_BE_A_2 = " must be a ";
const TEXT_DOES_NOT_MATCH_THE = " does not match the ";
const TEXT_POSITIVE_DECIMAL_INTEGER = "positive decimal integer";
const TEXT_REQUIRES_TORII_BROWSER_CLIENT_OPTIONS_NETWORK_ID = "requires ToriiBrowserClient options.networkId";
const TEXT_CONTAINS_RETIRED_OR_UNSUPPORTED_FIELDS = " contains retired or unsupported fields: ";
const TEXT_CANONICAL_KOTODAMA_V1_QUANTITY_STRING = "canonical Kotodama V1 quantity string";
const TEXT_AUTHENTICATION_ONLY_SUPPORTS_EMPTY_BODY_GETS = " authentication only supports empty-body GETs";


const TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE = "contract deployment-state response ";
const TEXT_TORII_BROWSER_CLIENT = "ToriiBrowserClient ";
const TEXT_V1_EXPLORER = "/v1/explorer/";
const TEXT_GET_CONTRACT_DEPLOYMENT_STATE = "getContractDeploymentState ";
const TEXT_MUST_BE_A = TEXT_MUST_BE_A_2;
const TEXT_CONTRACT_DEPLOYMENT_STATE = "contract deployment-state ";
const TEXT_TORII_ONE_SHOT_REQUEST_MUST_NOT_ACCEPT_A_REDIRECTED_RESPONSE = "Torii one-shot request must not accept a redirected response";
const TEXT_STATUS_BLOCK_HEIGHT_MUST_BE_A_POSITIVE_SAFE_INTEGER = (".status.block_height" + TEXT_MUST_BE_A_2 + "positive safe integer");
const TEXT_SUBMIT_MULTISIG_CONTRACT_CALL_PROPOSE = "submitMultisigContractCallPropose ";
const TEXT_SUBMIT_MULTISIG_CONTRACT_CALL_APPROVE = "submitMultisigContractCallApprove ";
const TEXT_SUBMIT_TRANSACTION_AND_WAIT = "submitTransactionAndWait ";
const TEXT_CONTAINS_UNSUPPORTED_OPTION = " contains unsupported option ";
const TEXT_STATUS_KIND_IS_NOT_A_CURRENT_PIPELINE_STATUS = ".status.kind is not a current pipeline status";
const TEXT_RESOLVED_FROM_IS_NOT_A_CURRENT_STATUS_SOURCE = ".resolved_from is not a current status source";
const TEXT_V1_ACCOUNTS = "/v1/accounts/";
const TEXT_V1_CONTRACTS = "/v1/contracts/";


// Reuse exact wire names and diagnostic fields throughout this module.
const FIELD_AUTHORITY = "authority";
const WIRE_FIELD_ASSET_ID = "asset_id";
const FIELD_TRANSACTION_HASH = "transactionHash";
const FIELD_RESULT_OK = "resultOk";
const FIELD_SINCE_TIMESTAMP_MS = "sinceTimestampMs";
const FIELD_UNTIL_TIMESTAMP_MS = "untilTimestampMs";
const FIELD_CONTRACT_ADDRESS = "contractAddress";
const WIRE_FIELD_CONTRACT_ADDRESS = "contract_address";
const WIRE_FIELD_CONTRACT_ALIAS = "contract_alias";
const WIRE_FIELD_SINCE_TIMESTAMP_MS = "since_timestamp_ms";
const WIRE_FIELD_UNTIL_TIMESTAMP_MS = "until_timestamp_ms";
const WIRE_FIELD_RESULT_OK = "result_ok";
const FIELD_ACCOUNT_ID = "accountId";
const FIELD_FUNCTION = "function";
const WIRE_FIELD_TOTAL_QUANTITY = "total_quantity";
const WIRE_FIELD_LOCKED_QUANTITY = "locked_quantity";
const WIRE_FIELD_CIRCULATING_QUANTITY = "circulating_quantity";
const FIELD_APPLICATION_JSON = "application/json";
const CONTEXT_KAIGI_RELAY_LIST_RESPONSE = "kaigi relay list response";
const WIRE_FIELD_REGISTRATIONS_TOTAL = "registrations_total";
const WIRE_FIELD_FAILOVERS_TOTAL = "failovers_total";
const CONTEXT_KAIGI_RELAY_DETAIL_RESPONSE = "kaigi relay detail response";
const CONTEXT_KAIGI_RELAY_HEALTH_RESPONSE = "kaigi relay health response";
const FIELD_CONTENT_TYPE = "content-type";
const FIELD_APPLICATION_X_NORITO = "application/x-norito";
const FIELD_V1_CONTRACTS_DEPLOYMENT_STATE = (TEXT_V1_CONTRACTS + "deployment-state");
const FIELD_QUANTITY = "quantity";
const FIELD_ASSET_DEFINITION_ID = "assetDefinitionId";

const DEFAULT_SUCCESS_STATUSES = Object.freeze([200]);
const BOUNDED_RESPONSE_MAX_STREAM_CHUNKS = 16_384;
const DEFAULT_JSON_RESPONSE_MAX_BYTES = 8 * 1024 * 1024;
const DEFAULT_BINARY_RESPONSE_MAX_BYTES = 64 * 1024 * 1024;
const KAIGI_JSON_RESPONSE_MAX_BYTES = 64 * 1024 * 1024;
const KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS = 500;
const MAX_UINT64_BIGINT = (1n << 64n) - 1n;
const MAX_SAFE_INTEGER_BIGINT = 9_007_199_254_740_991n;
const KAIGI_HEALTH_STATUS_VALUES = new Set(["healthy", "degraded", "unavailable"]);
const PIPELINE_SUCCESS_STATUS = "Applied";
const PIPELINE_STATUS_VALUES = new Set([
  "Queued",
  "Approved",
  "Committed",
  PIPELINE_SUCCESS_STATUS,
  "Rejected",
  "Expired",
]);
const PIPELINE_FAILURE_STATUSES = new Set(["Rejected", "Expired"]);
const PIPELINE_STATUS_RESOLUTION_VALUES = new Set(["queue", "cache", "state"]);
const TRANSACTION_ADMISSION_SUCCESS_STATUSES = Object.freeze([202]);
const TORII_BROWSER_CLIENT_OPTION_KEYS = new Set([
  "allowInsecure",
  "canonicalRequestAuth",
  "defaultHeaders",
  "fetchImpl",
  "networkId",
  "networkPrefix",
  "operatorSigningContext",
  "timeoutMs",
]);
const TRANSACTION_SUBMISSION_OPTION_KEYS = new Set(["signal", "headers"]);
const TRANSACTION_STATUS_READ_OPTION_KEYS = new Set(["signal", "headers", "scope"]);
const TRANSACTION_STATUS_POLL_OPTION_KEYS = new Set([
  "signal",
  "headers",
  "intervalMs",
  "timeoutMs",
  "maxAttempts",
]);
const SUBMIT_TRANSACTION_AND_WAIT_OPTION_KEYS = new Set([
  ...TRANSACTION_STATUS_POLL_OPTION_KEYS,
  "hashHex",
]);
const HASH_LITERAL_PATTERN = /^hash:([0-9A-F]{64})#([0-9A-F]{4})$/u;
const MULTISIG_PROPOSAL_STATUS_VALUES = new Set([
  "COLLECTING_SIGNATURES",
  "FINALIZED",
  "CANCELED",
  "EXPIRED",
]);
const CONTRACT_EVENT_FILTER_OPTION_KEYS = new Set([
  FIELD_AUTHORITY,
  FIELD_CONTRACT_ADDRESS,
  WIRE_FIELD_CONTRACT_ADDRESS,
  "eventKind",
  "event_kind",
  "participant",
  "assetId",
  WIRE_FIELD_ASSET_ID,
  "provenance",
  FIELD_SINCE_TIMESTAMP_MS,
  WIRE_FIELD_SINCE_TIMESTAMP_MS,
  FIELD_UNTIL_TIMESTAMP_MS,
  WIRE_FIELD_UNTIL_TIMESTAMP_MS,
  FIELD_RESULT_OK,
  WIRE_FIELD_RESULT_OK,
]);
const EVENT_STREAM_OPTION_KEYS = new Set(["signal", "filter"]);
const COLLECTION_QUERY_OPTION_KEYS = new Set(["signal", "headers"]);
const CONTRACT_EVENT_STREAM_OPTION_KEYS = new Set([
  "signal",
  ...CONTRACT_EVENT_FILTER_OPTION_KEYS,
]);
const LEDGER_HEADERS_OPTION_KEYS = new Set(["from", "limit", "signal"]);
const LEDGER_READ_OPTION_KEYS = new Set(["signal"]);

function normalizeBaseUrl(baseUrl) {
  if (typeof baseUrl !== "string" && !(baseUrl instanceof URL)) {
    rejectType((TEXT_TORII_BROWSER_CLIENT + "baseUrl" + TEXT_MUST_BE_A_2 + "string or URL"));
  }
  const raw = typeof baseUrl === "string" ? baseUrl : baseUrl.toString();
  if (raw.length === 0 || raw.trim() !== raw) {
    rejectType((TEXT_TORII_BROWSER_CLIENT + "baseUrl" + TEXT_MUST_BE_A_2 + "non-empty URL"));
  }
  const parsed = new URL(raw);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    rejectType((TEXT_TORII_BROWSER_CLIENT + "baseUrl must use http or https"));
  }
  if (parsed.username !== "" || parsed.password !== "") {
    rejectType((TEXT_TORII_BROWSER_CLIENT + "baseUrl must not contain credentials"));
  }
  if (parsed.search !== "" || parsed.hash !== "") {
    rejectType((TEXT_TORII_BROWSER_CLIENT + "baseUrl must not contain a query or fragment"));
  }
  const pathname = parsed.pathname.replace(/\/+$/u, "");
  if (/\/v1(?:\/explorer)?$/iu.test(pathname)) {
    rejectType((TEXT_TORII_BROWSER_CLIENT + "baseUrl must be the Torii root, without /v1 or /v1/explorer"));
  }
  return `${parsed.origin}${pathname}`;
}

function appendSearchParams(url, params) {
  if (!params) return;
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    if (typeof value === "string" && value.trim() === "") continue;
    url.searchParams.set(key, String(value));
  }
}

function requireObject(value, context) {
  if (value === undefined || value === null) return {};
  if (typeof value !== "object" || Array.isArray(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN}object`);
  }
  return value;
}

function requirePlainObject(value, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_A}plain object`);
  }
  return value;
}

function normalizeDefaultHeaders(value, context) {
  if (value === undefined) {
    return {};
  }
  const source = requirePlainObject(value, context);
  const headers = {};
  for (const [name, headerValue] of Object.entries(source)) {
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u.test(name)) {
      rejectType(`${context} contains invalid header name ${name}`);
    }
    if (typeof headerValue !== "string" || /[\0\r\n]/u.test(headerValue)) {
      rejectType(`${context}.${name}${TEXT_MUST_BE_A}single-line string`);
    }
    Object.defineProperty(headers, name, {
      configurable: true,
      enumerable: true,
      value: headerValue,
      writable: true,
    });
  }
  return headers;
}

function headersContainCredentials(headers) {
  const headerNames = Object.keys(headers).map((name) => name.toLowerCase());
  return [
    "authorization",
    "x-api-token",
    "x-iroha-account",
    "x-iroha-signature",
    "x-iroha-timestamp-ms",
    "x-iroha-nonce",
    "x-iroha-witness",
  ].some((name) => headerNames.includes(name));
}

function normalizeTransactionStatusScope(value, context) {
  const scope = value === undefined ? "global" : value;
  if (scope !== "local" && scope !== "global") {
    rejectType(`${context} must be local or global`);
  }
  return scope;
}

function rejectRemovedWaitScope(options, context) {
  if (Object.prototype.hasOwnProperty.call(options, "scope")) {
    rejectType(`${context}.scope is not supported; finality waits are global`);
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireNonEmptyString(value, context) {
  if (typeof value !== "string") {
    rejectType(`${context}${TEXT_MUST_BE_A}string`);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    rejectType(`${context} must not be empty`);
  }
  return trimmed;
}

function normalizeBrowserCanonicalRequestAuth(value, networkId) {
  if (value === undefined || value === null) return null;
  if (!isPlainObject(value)) {
    rejectType((TEXT_TORII_BROWSER_CLIENT + "options.canonicalRequestAuth" + TEXT_MUST_BE_A_2 + "plain object"));
  }
  const keys = Object.keys(value).sort();
  if (
    keys.length !== 2
    || keys[0] !== FIELD_ACCOUNT_ID
    || keys[1] !== "sign"
  ) {
    rejectType((TEXT_TORII_BROWSER_CLIENT + "options.canonicalRequestAuth requires exactly accountId and sign"));
  }
  if (networkId === null) {
    rejectType((TEXT_TORII_BROWSER_CLIENT + "options.canonicalRequestAuth requires options.networkId"));
  }
  const accountId = requireCanonicalAuthAccount(
    value.accountId,
    (TEXT_TORII_BROWSER_CLIENT + "options.canonicalRequestAuth.accountId"),
  );
  if (typeof value.sign !== FIELD_FUNCTION) {
    rejectType((TEXT_TORII_BROWSER_CLIENT + "options.canonicalRequestAuth.sign" + TEXT_MUST_BE_A_2 + "function"));
  }
  return Object.freeze({ accountId, sign: value.sign });
}

function normalizeContractDeploymentStateRequest(value) {
  if (!isPlainObject(value)) {
    rejectType((TEXT_CONTRACT_DEPLOYMENT_STATE + "request" + TEXT_MUST_BE_A_2 + "plain object"));
  }
  const keys = Object.keys(value).sort();
  if (
    keys.length !== 2 ||
    keys[0] !== FIELD_AUTHORITY ||
    keys[1] !== WIRE_FIELD_CONTRACT_ALIAS
  ) {
    rejectType((TEXT_CONTRACT_DEPLOYMENT_STATE + "request requires exactly authority and contract_alias"));
  }
  const authority = requireNonEmptyString(
    value.authority,
    (TEXT_CONTRACT_DEPLOYMENT_STATE + "authority"),
  );
  const contractAlias = requireNonEmptyString(
    value.contract_alias,
    (TEXT_CONTRACT_DEPLOYMENT_STATE + "contract_alias"),
  );
  if (authority !== value.authority || contractAlias !== value.contract_alias) {
    rejectType((TEXT_CONTRACT_DEPLOYMENT_STATE + "identifiers must be exact strings"));
  }
  return {
    authority,
    contract_alias: contractAlias,
  };
}

function requireCanonicalDecimalString(value, context, { positive = false } = {}) {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d*)$/u.test(value)) {
    rejectType(`${context}${TEXT_MUST_BE_A}canonical decimal string`);
  }
  if (positive && value === "0") {
    rejectType(`${context} must be positive`);
  }
  return value;
}

function normalizeContractDeploymentStateResponse(value, request) {
  if (!isPlainObject(value)) {
    rejectType((TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "must be a plain object"));
  }
  const fields = [
    FIELD_AUTHORITY,
    WIRE_FIELD_CONTRACT_ALIAS,
    "deploy_nonce",
    "dataspace_alias",
    "dataspace_id",
    "previous_contract_address",
    "observed_block_height",
    "observed_block_hash",
    "ledger_time_ms",
    "chain_discriminant",
  ];
  const keys = Object.keys(value).sort();
  if (keys.length !== fields.length || keys.some((key) => !fields.includes(key))) {
    rejectType((TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "has missing or unsupported fields"));
  }
  if (value.authority !== request.authority) {
    rejectError((TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "authority mismatch"));
  }
  if (value.contract_alias !== request.contract_alias) {
    rejectError((TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "alias mismatch"));
  }
  const dataspaceAlias = requireNonEmptyString(
    value.dataspace_alias,
    (TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "dataspace_alias"),
  );
  if (dataspaceAlias !== value.dataspace_alias) {
    rejectType((TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "dataspace_alias must be exact"));
  }
  const observedBlockHash = requireNonEmptyString(
    value.observed_block_hash,
    (TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "observed_block_hash"),
  );
  const hashMatch = HASH_LITERAL_PATTERN.exec(observedBlockHash);
  if (
    hashMatch === null ||
    computeHashLiteralCrc("hash", hashMatch[1]) !== hashMatch[2]
  ) {
    rejectType((TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "observed_block_hash must be canonical"));
  }
  const previous = value.previous_contract_address;
  if (previous !== null) {
    const exactPrevious = requireNonEmptyString(
      previous,
      (TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "previous_contract_address"),
    );
    if (exactPrevious !== previous) {
      rejectType((TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "previous_contract_address must be exact"));
    }
  }
  const chainDiscriminant = requireCanonicalDecimalString(
    value.chain_discriminant,
    (TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "chain_discriminant"),
  );
  if (BigInt(chainDiscriminant) > 0xffffn) {
    rejectRange((TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "chain_discriminant exceeds u16"));
  }
  return Object.freeze({
    authority: value.authority,
    contract_alias: value.contract_alias,
    deploy_nonce: requireCanonicalDecimalString(
      value.deploy_nonce,
      (TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "deploy_nonce"),
    ),
    dataspace_alias: dataspaceAlias,
    dataspace_id: requireCanonicalDecimalString(
      value.dataspace_id,
      (TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "dataspace_id"),
    ),
    previous_contract_address: previous,
    observed_block_height: requireCanonicalDecimalString(
      value.observed_block_height,
      (TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "observed_block_height"),
      { positive: true },
    ),
    observed_block_hash: observedBlockHash,
    ledger_time_ms: requireCanonicalDecimalString(
      value.ledger_time_ms,
      (TEXT_CONTRACT_DEPLOYMENT_STATE_RESPONSE + "ledger_time_ms"),
    ),
    chain_discriminant: chainDiscriminant,
  });
}

function requireExactHashHex(value, context) {
  if (typeof value !== "string" || !/^[0-9a-f]{63}[13579bdf]$/u.test(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN}exact canonical lowercase 32-byte Iroha hash`);
  }
  return value;
}

function requireMatchingReceiptHashHeader(response, name, expectedHash) {
  const value = response.headers.get(name);
  if (typeof value !== "string" || !/^[0-9a-f]{63}[13579bdf]$/u.test(value)) {
    rejectError(`${name} must occur exactly once as a canonical lowercase Iroha hash`);
  }
  if (value !== expectedHash) {
    rejectError(`${name}${TEXT_DOES_NOT_MATCH_THE}locally signed transaction`);
  }
}

function requireTransactionBytes(value, context) {
  let bytes;
  if (value instanceof Uint8Array) {
    bytes = new Uint8Array(value);
  } else if (ArrayBuffer.isView(value)) {
    bytes = new Uint8Array(
      value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength),
    );
  } else if (value instanceof ArrayBuffer) {
    bytes = new Uint8Array(value.slice(0));
  } else {
    rejectType(`${context} must be transaction bytes`);
  }
  if (bytes.length < 2 || bytes[0] !== 1) {
    rejectType(`${context}${TEXT_MUST_BE_AN}exact version-1 signed transaction payload`);
  }
  return bytes;
}

function normalizePublicPipelineStatusEnvelope(value, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_A}pipeline status object`);
  }
  const rootFields = new Set(["hash", "status", "scope", "resolved_from"]);
  const unexpectedRootFields = Object.keys(value).filter(
    (field) => !rootFields.has(field),
  );
  if (unexpectedRootFields.length > 0) {
    rejectType(`${context}${TEXT_CONTAINS_RETIRED_OR_UNSUPPORTED_FIELDS}${unexpectedRootFields.join(", ")}`);
  }
  const hash = requireExactHashHex(value.hash, `${context}.hash`);
  if (!isPlainObject(value.status)) {
    rejectType(`${context}.status${TEXT_MUST_BE_AN}object`);
  }
  const statusFields = new Set(["kind", "block_height"]);
  const unexpectedStatusFields = Object.keys(value.status).filter(
    (field) => !statusFields.has(field),
  );
  if (unexpectedStatusFields.length > 0) {
    rejectType(`${context}.status${TEXT_CONTAINS_RETIRED_OR_UNSUPPORTED_FIELDS}${unexpectedStatusFields.join(", ")}`);
  }
  if (
    typeof value.status.kind !== "string" ||
    !PIPELINE_STATUS_VALUES.has(value.status.kind)
  ) {
    rejectType(`${context}${TEXT_STATUS_KIND_IS_NOT_A_CURRENT_PIPELINE_STATUS}`);
  }
  const status = { kind: value.status.kind };
  if (value.status.block_height !== undefined) {
    if (
      !Number.isSafeInteger(value.status.block_height) ||
      value.status.block_height < 1
    ) {
      rejectType(`${context}${TEXT_STATUS_BLOCK_HEIGHT_MUST_BE_A_POSITIVE_SAFE_INTEGER}`);
    }
    status.block_height = value.status.block_height;
  }
  if (!["local", "global"].includes(value.scope)) {
    rejectType(`${context}.scope is not a current status scope`);
  }
  if (!PIPELINE_STATUS_RESOLUTION_VALUES.has(value.resolved_from)) {
    rejectType(`${context}${TEXT_RESOLVED_FROM_IS_NOT_A_CURRENT_STATUS_SOURCE}`);
  }
  return Object.freeze({
    hash,
    status: Object.freeze(status),
    scope: value.scope,
    resolved_from: value.resolved_from,
  });
}

function classifyGlobalPipelineStatusEnvelope(value, requestedHash, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_A}pipeline status object`);
  }
  const hash = requireExactHashHex(value.hash, `${context}.hash`);
  if (hash !== requestedHash) {
    rejectError(`${context}.hash${TEXT_DOES_NOT_MATCH_THE}requested transaction`);
  }
  if (value.scope !== "global") {
    rejectError(`${context}.scope must be global`);
  }
  if (!isPlainObject(value.status) || typeof value.status.kind !== "string") {
    rejectType(`${context}.status.kind${TEXT_MUST_BE_A_2}string`);
  }
  if (!PIPELINE_STATUS_VALUES.has(value.status.kind)) {
    rejectError(`${context}${TEXT_STATUS_KIND_IS_NOT_A_CURRENT_PIPELINE_STATUS}`);
  }
  if (!PIPELINE_STATUS_RESOLUTION_VALUES.has(value.resolved_from)) {
    rejectError(`${context}${TEXT_RESOLVED_FROM_IS_NOT_A_CURRENT_STATUS_SOURCE}`);
  }
  const kind = value.status.kind;
  if (kind === PIPELINE_SUCCESS_STATUS) {
    const blockHeight = value.status.block_height;
    if (!Number.isSafeInteger(blockHeight) || blockHeight < 1) {
      rejectError(`${context}${TEXT_STATUS_BLOCK_HEIGHT_MUST_BE_A_POSITIVE_SAFE_INTEGER}`);
    }
  }
  return {
    kind,
    authoritative: value.resolved_from === "state",
  };
}

function abortError() {
  if (typeof DOMException === FIELD_FUNCTION) {
    return new DOMException("The operation was aborted", "AbortError");
  }
  const error = new Error("The operation was aborted");
  error.name = "AbortError";
  return error;
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw signal.reason ?? abortError();
}

function delayWithSignal(milliseconds, signal) {
  throwIfAborted(signal);
  if (milliseconds === 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    const onAbort = () => {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", onAbort);
      reject(signal.reason ?? abortError());
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function requireCanonicalQuantity(value, context) {
  if (typeof value !== "string") {
    rejectType(`${context}${TEXT_MUST_BE_A}${TEXT_CANONICAL_KOTODAMA_V1_QUANTITY_STRING}`);
  }
  try {
    return NumericV1.decodeQuantityJson(value).toString();
  } catch (error) {
    if (!(error instanceof NumericV1Error)) throw error;
    rejectType(`${context}${TEXT_MUST_BE_A}canonical non-negative Kotodama V1 quantity (${error.code})`);
  }
}

function normalizeQuantityRecord(value, context, fields, { optional = false } = {}) {
  const record = requireObject(value, context);
  const normalized = { ...record };
  for (const field of fields) {
    if (normalized[field] === undefined || normalized[field] === null) {
      if (!optional) {
        rejectType(`${context}.${field}${TEXT_MUST_BE_A}${TEXT_CANONICAL_KOTODAMA_V1_QUANTITY_STRING}`);
      }
    } else {
      normalized[field] = requireCanonicalQuantity(
        normalized[field],
        `${context}.${field}`,
      );
    }
  }
  return normalized;
}

function normalizeExplorerAssetDefinitionRecord(value, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN}object`);
  }
  const fields = [
    "id",
    "owning_domain",
    "owning_dataspace",
    "mintable",
    "logo",
    "metadata",
    "owned_by",
    "assets",
    WIRE_FIELD_TOTAL_QUANTITY,
    WIRE_FIELD_LOCKED_QUANTITY,
    WIRE_FIELD_CIRCULATING_QUANTITY,
  ];
  const keys = Object.keys(value);
  if (keys.length !== fields.length || keys.some((key) => !fields.includes(key))) {
    rejectType(`${context} has missing or unsupported fields`);
  }
  for (const field of ["id", "mintable", "owned_by"]) {
    const normalized = requireNonEmptyString(value[field], `${context}.${field}`);
    if (normalized !== value[field]) {
      rejectType(`${context}.${field}${TEXT_MUST_BE_AN}exact string`);
    }
  }
  if (value.owning_domain !== null) {
    const owningDomain = requireNonEmptyString(
      value.owning_domain,
      `${context}.owning_domain`,
    );
    if (owningDomain !== value.owning_domain) {
      rejectType(`${context}.owning_domain${TEXT_MUST_BE_AN}exact string or null`);
    }
  }
  if (value.owning_dataspace !== null) {
    if (
      typeof value.owning_dataspace !== "string" ||
      value.owning_dataspace.length > 20 ||
      !/^[1-9][0-9]*$/.test(value.owning_dataspace) ||
      BigInt(value.owning_dataspace).toString() !== value.owning_dataspace ||
      BigInt(value.owning_dataspace) > 0xffff_ffff_ffff_ffffn
    ) {
      rejectType(`${context}.owning_dataspace must be a canonical nonzero u64 decimal string or null`);
    }
    if (value.owning_domain !== null) {
      rejectType(`${context} cannot carry both domain and dataspace homes`);
    }
  }
  for (const field of ["logo", WIRE_FIELD_LOCKED_QUANTITY, WIRE_FIELD_CIRCULATING_QUANTITY]) {
    if (value[field] !== null && typeof value[field] !== "string") {
      rejectType(`${context}.${field}${TEXT_MUST_BE_A}string or null`);
    }
  }
  if (!Number.isInteger(value.assets) || value.assets < 0 || value.assets > 0xffff_ffff) {
    rejectType(`${context}.assets${TEXT_MUST_BE_A_2}uint32`);
  }
  if (!isPlainObject(value.metadata)) {
    rejectType(`${context}.metadata${TEXT_MUST_BE_AN}object`);
  }
  const normalized = normalizeQuantityRecord(value, context, [WIRE_FIELD_TOTAL_QUANTITY]);
  for (const field of [WIRE_FIELD_LOCKED_QUANTITY, WIRE_FIELD_CIRCULATING_QUANTITY]) {
    if (normalized[field] !== null) {
      normalized[field] = requireCanonicalQuantity(
        normalized[field],
        `${context}.${field}`,
      );
    }
  }
  return normalized;
}

function normalizePositiveInteger(value, context, fallback) {
  if (value === undefined || value === null) return fallback;
  const numeric = normalizeSafeInteger(value, context);
  if (numeric < 1) {
    rejectType(`${context}${TEXT_MUST_BE_A}positive safe integer`);
  }
  return numeric;
}

function normalizeOffset(value, context, fallback = 0) {
  if (value === undefined || value === null) return fallback;
  const numeric = normalizeSafeInteger(value, context);
  if (numeric < 0) {
    rejectType(`${context}${TEXT_MUST_BE_A}non-negative safe integer`);
  }
  return numeric;
}

function normalizeSafeInteger(value, context) {
  if (typeof value === "number") {
    if (Number.isSafeInteger(value)) {
      return value;
    }
  } else if (typeof value === "bigint") {
    if (value >= 0n && value <= MAX_SAFE_INTEGER_BIGINT) {
      return Number(value);
    }
  } else if (typeof value === "string" && /^(?:0|[1-9]\d*)$/u.test(value)) {
    const parsed = BigInt(value);
    if (parsed <= MAX_SAFE_INTEGER_BIGINT) {
      return Number(parsed);
    }
  }
  rejectType(`${context}${TEXT_MUST_BE_A}safe integer`);
}

function normalizeBoolean(value, context) {
  if (typeof value !== "boolean") {
    rejectType(`${context}${TEXT_MUST_BE_A}boolean`);
  }
  return value;
}

function requireSupportedOptions(value, context, supportedKeys) {
  const options = requireObject(value, context);
  const unsupported = Object.keys(options).find((key) => !supportedKeys.has(key));
  if (unsupported !== undefined) {
    rejectType(`${context}${TEXT_CONTAINS_UNSUPPORTED_OPTION}${unsupported}`);
  }
  return options;
}

function optionAlias(options, camelCase, snakeCase) {
  return options[camelCase] ?? options[snakeCase];
}

function normalizeOptionalString(value, context) {
  if (value === undefined || value === null) return undefined;
  return requireNonEmptyString(value, context);
}

function normalizeOptionalUnsignedInteger(value, context) {
  if (value === undefined || value === null) return undefined;
  return normalizeOffset(value, context);
}

function normalizeOptionalBoolean(value, context) {
  if (value === undefined || value === null) return undefined;
  return normalizeBoolean(value, context);
}

function normalizeLedgerHeight(value, context) {
  let integer;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      rejectType(`${context}${TEXT_MUST_BE_A}positive safe integer number or an exact decimal string/bigint`);
    }
    integer = BigInt(value);
  } else if (typeof value === "bigint") {
    integer = value;
  } else if (typeof value === "string") {
    const trimmed = value.trim();
    if (!/^[0-9]+$/u.test(trimmed)) {
      rejectType(`${context}${TEXT_MUST_BE_A}${TEXT_POSITIVE_DECIMAL_INTEGER}`);
    }
    integer = BigInt(trimmed);
  } else {
    rejectType(`${context}${TEXT_MUST_BE_A}${TEXT_POSITIVE_DECIMAL_INTEGER}`);
  }
  if (integer <= 0n) {
    rejectType(`${context}${TEXT_MUST_BE_A}${TEXT_POSITIVE_DECIMAL_INTEGER}`);
  }
  if (integer > MAX_UINT64_BIGINT) {
    rejectRange(`${context} must not exceed ${MAX_UINT64_BIGINT.toString(10)}`);
  }
  return integer.toString(10);
}

function normalizeLedgerEntryHash(value, context) {
  const literal = requireNonEmptyString(String(value), context);
  const normalized = literal.startsWith("0x") ? literal.slice(2) : literal;
  if (!/^[0-9a-fA-F]{64}$/u.test(normalized)) {
    rejectType(`${context} must be exactly 32 bytes of hexadecimal`);
  }
  return normalized.toLowerCase();
}

/** The only provenance Torii's call-derived contract-event feed reports. */
const CONTRACT_EVENT_PROVENANCE = "emitted";

function normalizeContractEventFilterParams(options, context) {
  const provenance = normalizeOptionalString(options.provenance, `${context}.provenance`);
  // Only committed native emissions are exposed in contract event history.
  if (provenance !== undefined && provenance !== CONTRACT_EVENT_PROVENANCE) {
    rejectType(`${context}.provenance must be ${CONTRACT_EVENT_PROVENANCE}`);
  }
  return {
    authority: normalizeOptionalString(options.authority, `${context}.authority`),
    contract_address: normalizeOptionalString(
      optionAlias(options, FIELD_CONTRACT_ADDRESS, WIRE_FIELD_CONTRACT_ADDRESS),
      `${context}.contractAddress`,
    ),
    event_kind: normalizeOptionalString(
      optionAlias(options, "eventKind", "event_kind"),
      `${context}.eventKind`,
    ),
    participant: normalizeOptionalString(options.participant, `${context}.participant`),
    asset_id: normalizeOptionalString(
      optionAlias(options, "assetId", WIRE_FIELD_ASSET_ID),
      `${context}.assetId`,
    ),
    provenance,
    since_timestamp_ms: normalizeOptionalUnsignedInteger(
      optionAlias(options, FIELD_SINCE_TIMESTAMP_MS, WIRE_FIELD_SINCE_TIMESTAMP_MS),
      `${context}.sinceTimestampMs`,
    ),
    until_timestamp_ms: normalizeOptionalUnsignedInteger(
      optionAlias(options, FIELD_UNTIL_TIMESTAMP_MS, WIRE_FIELD_UNTIL_TIMESTAMP_MS),
      `${context}.untilTimestampMs`,
    ),
    result_ok: normalizeOptionalBoolean(
      optionAlias(options, FIELD_RESULT_OK, WIRE_FIELD_RESULT_OK),
      `${context}.resultOk`,
    ),
  };
}

function signalFrom(options) {
  return options.signal === undefined ? undefined : options.signal;
}

function signalOnlyOptions(options, context) {
  const item = requireObject(options, context);
  const unknown = Object.keys(item).filter((key) => key !== "signal");
  if (unknown.length > 0) {
    rejectType(`${context}${TEXT_CONTAINS_UNSUPPORTED_OPTION}${unknown[0]}`);
  }
  return item;
}

function rejectSuccessStatuses(options, context) {
  if (Object.hasOwn(options, "successStatuses")) {
    rejectType(`${context}${TEXT_CONTAINS_UNSUPPORTED_OPTION}successStatuses`);
  }
}

function normalizeMultisigSelectorBody(value, context) {
  const source = requireObject(value, context);
  for (const unsupported of ["headers", "signal", "successStatuses"]) {
    if (Object.hasOwn(source, unsupported)) {
      rejectType(`${context} contains unsupported field ${unsupported}`);
    }
  }
  const body = { ...source };
  if (
    source.multisigAccountId !== undefined &&
    body.multisig_account_id !== undefined
  ) {
    rejectType(`${context} must not duplicate multisigAccountId`);
  }
  if (
    source.multisigAccountAlias !== undefined &&
    body.multisig_account_alias !== undefined
  ) {
    rejectType(`${context} must not duplicate multisigAccountAlias`);
  }
  if (source.multisigAccountId !== undefined && body.multisig_account_id === undefined) {
    body.multisig_account_id = requireNonEmptyString(
      source.multisigAccountId,
      `${context}.multisigAccountId`,
    );
  }
  if (source.multisigAccountAlias !== undefined && body.multisig_account_alias === undefined) {
    body.multisig_account_alias = requireNonEmptyString(
      source.multisigAccountAlias,
      `${context}.multisigAccountAlias`,
    );
  }
  delete body.multisigAccountId;
  delete body.multisigAccountAlias;
  if (body.multisig_account_id !== undefined) {
    body.multisig_account_id = requireNonEmptyString(
      body.multisig_account_id,
      `${context}.multisig_account_id`,
    );
  }
  if (body.multisig_account_alias !== undefined) {
    body.multisig_account_alias = requireNonEmptyString(
      body.multisig_account_alias,
      `${context}.multisig_account_alias`,
    );
  }
  const hasAccountId = body.multisig_account_id !== undefined;
  const hasAccountAlias = body.multisig_account_alias !== undefined;
  if (hasAccountId === hasAccountAlias) {
    rejectType(`${context} requires exactly one of multisigAccountId or multisigAccountAlias`);
  }
  return body;
}

function normalizeMultisigProposalsQueryBody(value, context) {
  const source = requireObject(value, context);
  const body = normalizeMultisigSelectorBody(source, context);
  if (source.status !== undefined) {
    if (!Array.isArray(source.status)) {
      rejectType(`${context}.status${TEXT_MUST_BE_AN}array`);
    }
    body.status = source.status.map((value, index) => {
      const status = requireNonEmptyString(value, `${context}.status[${index}]`).toUpperCase();
      if (!MULTISIG_PROPOSAL_STATUS_VALUES.has(status)) {
        rejectType(`${context}.status[${index}] must be one of ${[
            ...MULTISIG_PROPOSAL_STATUS_VALUES,
          ].join(", ")}`);
      }
      return status;
    });
  }
  if (body.cursor !== undefined && body.cursor !== null) {
    body.cursor = requireNonEmptyString(body.cursor, `${context}.cursor`);
  }
  if (body.limit !== undefined && body.limit !== null) {
    body.limit = normalizePositiveInteger(body.limit, `${context}.limit`, undefined);
  }
  return body;
}

function normalizeMultisigProposalsResolveBody(value, context) {
  const source = requireObject(value, context);
  const body = normalizeMultisigSelectorBody(source, context);
  if (source.proposalId !== undefined && body.proposal_id === undefined) {
    body.proposal_id = source.proposalId;
  }
  if (source.instructionsHash !== undefined && body.instructions_hash === undefined) {
    body.instructions_hash = source.instructionsHash;
  }
  delete body.proposalId;
  delete body.instructionsHash;
  if (body.proposal_id !== undefined) {
    body.proposal_id = requireNonEmptyString(body.proposal_id, `${context}.proposal_id`);
  }
  if (body.instructions_hash !== undefined) {
    body.instructions_hash = requireNonEmptyString(
      body.instructions_hash,
      `${context}.instructions_hash`,
    );
  }
  const hasProposalId = body.proposal_id !== undefined;
  const hasInstructionsHash = body.instructions_hash !== undefined;
  if (hasProposalId === hasInstructionsHash) {
    rejectType(`${context} requires exactly one of proposalId or instructionsHash`);
  }
  return body;
}

function responseStatus(response) {
  if (typeof response?.status === "number") return response.status;
  return response?.ok === true ? 200 : 0;
}

async function responseText(response) {
  if (typeof response?.text === FIELD_FUNCTION) {
    return response.text().catch(() => "");
  }
  if (typeof response?.json === FIELD_FUNCTION) {
    try {
      return JSON.stringify(await response.json());
    } catch {
      return "";
    }
  }
  return "";
}

function requestSignal(options, timeoutMs) {
  const callerSignal = options.signal;
  if (!(timeoutMs > 0) || typeof AbortController !== FIELD_FUNCTION) {
    return { signal: callerSignal, cleanup() {} };
  }
  const controller = new AbortController();
  const onCallerAbort = () => controller.abort(callerSignal.reason);
  if (callerSignal) {
    if (callerSignal.aborted) {
      onCallerAbort();
    } else {
      callerSignal.addEventListener("abort", onCallerAbort, { once: true });
    }
  }
  const timeoutId = controller.signal.aborted
    ? undefined
    : setTimeout(
        () => controller.abort(new Error(`Torii request timed out after ${timeoutMs} ms`)),
        timeoutMs,
      );
  let cleaned = false;
  return {
    signal: controller.signal,
    cleanup() {
      if (cleaned) return;
      cleaned = true;
      if (timeoutId !== undefined) clearTimeout(timeoutId);
      callerSignal?.removeEventListener("abort", onCallerAbort);
    },
  };
}

function normalizeSuccessStatuses(value, context) {
  if (value === undefined) {
    return DEFAULT_SUCCESS_STATUSES;
  }
  if (!Array.isArray(value) || value.length === 0) {
    rejectType(`${context}${TEXT_MUST_BE_A}non-empty status array`);
  }
  return value.map((status, index) => {
    if (!Number.isSafeInteger(status) || status < 100 || status > 599) {
      rejectType(`${context}[${index}]${TEXT_MUST_BE_AN}HTTP status integer`);
    }
    return status;
  });
}

/**
 * Dispatch one request. On success the caller owns `cleanupSignal` and must
 * call it once the body has been read, so the timeout and the caller's abort
 * signal keep covering the body; on failure it is released here.
 */
async function fetchToriiResponse(
  fetchImpl,
  url,
  init,
  successStatuses,
  cleanupSignal,
) {
  let response;
  try {
    response = await Reflect.apply(fetchImpl, undefined, [url, init]);
  } catch (error) {
    cleanupSignal();
    throw error;
  }
  if (init.redirect === "error" && response?.redirected === true) {
    cleanupSignal();
    rejectType(TEXT_TORII_ONE_SHOT_REQUEST_MUST_NOT_ACCEPT_A_REDIRECTED_RESPONSE);
  }
  const status = responseStatus(response);
  if (!successStatuses.includes(status)) {
    try {
      throw await toriiHttpErrorFromResponse(response, status, successStatuses);
    } finally {
      cleanupSignal();
    }
  }
  return { response, status };
}

async function toriiHttpErrorFromResponse(response, status, expected) {
  const bodyText = await responseText(response);
  return toriiHttpErrorFromResponseText({
    status,
    statusText: typeof response?.statusText === "string" && response.statusText ? response.statusText : null,
    expected,
    bodyText,
    contentType: response?.headers?.get?.(FIELD_CONTENT_TYPE) ?? null,
    rejectCodeHeader: response?.headers?.get?.("x-iroha-reject-code") ?? null,
  });
}

function requireExactJsonContentType(contentType, context) {
  const mediaType = typeof contentType === "string"
    ? contentType.split(";", 1)[0].trim()
    : "";
  if (mediaType.toLowerCase() !== FIELD_APPLICATION_JSON) {
    rejectType(`${context} must use the application/json media type`);
  }
}

function requireExactKaigiString(value, context) {
  const normalized = requireNonEmptyString(value, context);
  if (normalized !== value) {
    rejectType(`${context} must not contain surrounding whitespace`);
  }
  return value;
}

function requireExactKaigiAccountId(value, context) {
  const literal = requireExactKaigiString(value, context);
  const canonical = ensureCanonicalAccountId(literal, context);
  if (canonical !== literal) {
    rejectType(`${context}${TEXT_MUST_BE_A}canonical I105 account id`);
  }
  return literal;
}

function requireExactKaigiObject(value, requiredFields, optionalFields, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN}object`);
  }
  const allowed = new Set([...requiredFields, ...optionalFields]);
  const missing = requiredFields.filter(
    (field) => !Object.prototype.hasOwnProperty.call(value, field),
  );
  const extra = Object.keys(value).filter((field) => !allowed.has(field));
  if (missing.length !== 0 || extra.length !== 0) {
    rejectType(`${context} fields are not canonical; missing=[${missing.join(", ")}] extra=[${extra.join(", ")}]`);
  }
  return value;
}

function requireDenseBrowserKaigiArray(value, context) {
  if (!Array.isArray(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN}array`);
  }
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(value, index)) {
      rejectType(`${context}${TEXT_MUST_BE_A}dense array`);
    }
  }
  return value;
}

function normalizeBrowserKaigiU64(value, context) {
  let integer;
  if (
    typeof value === "number"
    && Number.isSafeInteger(value)
    && !Object.is(value, -0)
  ) {
    integer = BigInt(value);
  } else if (typeof value === "bigint") {
    integer = value;
  } else {
    rejectType(`${context}${TEXT_MUST_BE_A}canonical unsigned integer`);
  }
  if (integer < 0n || integer > MAX_UINT64_BIGINT) {
    rejectRange(`${context} must be between 0 and ${MAX_UINT64_BIGINT}`);
  }
  return integer <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(integer) : integer;
}

function requireBrowserKaigiFingerprint(value, context) {
  const literal = requireExactKaigiString(value, context);
  if (!/^[0-9a-f]{64}$/u.test(literal)) {
    rejectType(`${context} must be exact lowercase 32-byte hex`);
  }
  if ((Number.parseInt(literal.slice(-2), 16) & 1) !== 1) {
    rejectType(`${context} must set the Iroha Hash marker bit`);
  }
  return literal;
}

function normalizeBrowserKaigiRelaySummary(value, context) {
  const record = requireExactKaigiObject(
    value,
    ["relay_id", "domain", "bandwidth_class", "hpke_fingerprint_hex"],
    ["status", "reported_at_ms"],
    context,
  );
  if (
    typeof record.bandwidth_class !== "number"
    || !Number.isInteger(record.bandwidth_class)
    || record.bandwidth_class < 1
    || record.bandwidth_class > 0xff
  ) {
    rejectRange(`${context}.bandwidth_class must be between 1 and 255`);
  }
  const hasStatus = Object.prototype.hasOwnProperty.call(record, "status");
  const hasReportedAt = Object.prototype.hasOwnProperty.call(record, "reported_at_ms");
  if (hasStatus !== hasReportedAt) {
    rejectType(`${context}.status and reported_at_ms must be present together`);
  }
  let status = null;
  let reportedAtMs = null;
  if (hasStatus) {
    status = requireExactKaigiString(record.status, `${context}.status`);
    if (!KAIGI_HEALTH_STATUS_VALUES.has(status)) {
      rejectType(`${context}.status must be exact lowercase healthy, degraded, or unavailable`);
    }
    reportedAtMs = normalizeBrowserKaigiU64(
      record.reported_at_ms,
      `${context}.reported_at_ms`,
    );
  }
  return {
    relay_id: requireExactKaigiAccountId(record.relay_id, `${context}.relay_id`),
    domain: requireExactKaigiString(record.domain, `${context}.domain`),
    bandwidth_class: record.bandwidth_class,
    hpke_fingerprint_hex: requireBrowserKaigiFingerprint(
      record.hpke_fingerprint_hex,
      `${context}.hpke_fingerprint_hex`,
    ),
    status,
    reported_at_ms: reportedAtMs,
  };
}

function normalizeBrowserKaigiRelayList(value) {
  const context = CONTEXT_KAIGI_RELAY_LIST_RESPONSE;
  const record = requireExactKaigiObject(value, ["total", "items"], [], context);
  const rawItems = requireDenseBrowserKaigiArray(record.items, `${context}.items`);
  if (rawItems.length > KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS) {
    rejectRange(`${context}.items must contain at most ${KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS} entries`);
  }
  const items = rawItems.map((item, index) =>
    normalizeBrowserKaigiRelaySummary(item, `${context}.items[${index}]`),
  );
  const total = normalizeBrowserKaigiU64(record.total, `${context}.total`);
  if (BigInt(total) !== BigInt(items.length)) {
    rejectRange(`${context}.total must equal items.length`);
  }
  if (new Set(items.map((item) => item.relay_id)).size !== items.length) {
    rejectType(`${context}.items must contain unique relay_id values`);
  }
  return { total, items };
}

function normalizeBrowserKaigiDomainMetrics(value, context) {
  const fields = [
    "domain",
    WIRE_FIELD_REGISTRATIONS_TOTAL,
    "manifest_updates_total",
    WIRE_FIELD_FAILOVERS_TOTAL,
    "health_reports_total",
  ];
  const record = requireExactKaigiObject(value, fields, [], context);
  return {
    domain: requireExactKaigiString(record.domain, `${context}.domain`),
    registrations_total: normalizeBrowserKaigiU64(
      record.registrations_total,
      `${context}.registrations_total`,
    ),
    manifest_updates_total: normalizeBrowserKaigiU64(
      record.manifest_updates_total,
      `${context}.manifest_updates_total`,
    ),
    failovers_total: normalizeBrowserKaigiU64(
      record.failovers_total,
      `${context}.failovers_total`,
    ),
    health_reports_total: normalizeBrowserKaigiU64(
      record.health_reports_total,
      `${context}.health_reports_total`,
    ),
  };
}

function normalizeBrowserKaigiRelayDetail(value) {
  const context = CONTEXT_KAIGI_RELAY_DETAIL_RESPONSE;
  const record = requireExactKaigiObject(
    value,
    ["relay", "hpke_public_key_b64"],
    ["reported_call", "reported_by", "notes", "metrics"],
    context,
  );
  const relay = normalizeBrowserKaigiRelaySummary(record.relay, `${context}.relay`);
  const hpkePublicKey = requireExactKaigiString(
    record.hpke_public_key_b64,
    `${context}.hpke_public_key_b64`,
  );
  const hpkeBytes = Buffer.from(hpkePublicKey, "base64");
  if (hpkeBytes.length === 0 || hpkeBytes.toString("base64") !== hpkePublicKey) {
    rejectType(`${context}.hpke_public_key_b64 must be exact standard-base64`);
  }
  const expectedFingerprint = Buffer.from(blake2b256(hpkeBytes));
  expectedFingerprint[expectedFingerprint.length - 1] |= 1;
  if (relay.hpke_fingerprint_hex !== expectedFingerprint.toString("hex")) {
    rejectType(`${context}.relay.hpke_fingerprint_hex must match the marked HPKE key`);
  }
  const hasFeedback = relay.status !== null;
  const hasReportedCall = Object.prototype.hasOwnProperty.call(record, "reported_call");
  const hasReportedBy = Object.prototype.hasOwnProperty.call(record, "reported_by");
  const hasNotes = Object.prototype.hasOwnProperty.call(record, "notes");
  if (hasReportedCall !== hasFeedback || hasReportedBy !== hasFeedback || (hasNotes && !hasFeedback)) {
    rejectType(`${context} feedback fields must agree with relay feedback`);
  }
  let reportedCall = null;
  if (hasReportedCall) {
    const call = requireExactKaigiObject(
      record.reported_call,
      ["domain_id", "call_name"],
      [],
      `${context}.reported_call`,
    );
    reportedCall = {
      domain_id: requireExactKaigiString(call.domain_id, `${context}.reported_call.domain_id`),
      call_name: requireExactKaigiString(call.call_name, `${context}.reported_call.call_name`),
    };
  }
  const reportedBy = hasReportedBy
    ? requireExactKaigiAccountId(record.reported_by, `${context}.reported_by`)
    : null;
  if (hasNotes && typeof record.notes !== "string") {
    rejectType(`${context}.notes${TEXT_MUST_BE_A_2}string`);
  }
  const notes = hasNotes ? record.notes : null;
  const metrics = Object.prototype.hasOwnProperty.call(record, "metrics")
    ? normalizeBrowserKaigiDomainMetrics(record.metrics, `${context}.metrics`)
    : null;
  if (metrics !== null && metrics.domain !== relay.domain) {
    rejectType(`${context}.metrics.domain must match relay.domain`);
  }
  return {
    relay,
    hpke_public_key_b64: hpkePublicKey,
    reported_call: reportedCall,
    reported_by: reportedBy,
    notes,
    metrics,
  };
}

function normalizeBrowserKaigiHealth(value) {
  const context = CONTEXT_KAIGI_RELAY_HEALTH_RESPONSE;
  const fields = [
    "healthy_total",
    "degraded_total",
    "unavailable_total",
    "reports_total",
    WIRE_FIELD_REGISTRATIONS_TOTAL,
    WIRE_FIELD_FAILOVERS_TOTAL,
    "domains",
  ];
  const record = requireExactKaigiObject(value, fields, [], context);
  const rawDomains = requireDenseBrowserKaigiArray(record.domains, `${context}.domains`);
  if (rawDomains.length > KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS) {
    rejectRange(`${context}.domains must contain at most ${KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS} entries`);
  }
  const domains = rawDomains.map((domain, index) =>
    normalizeBrowserKaigiDomainMetrics(domain, `${context}.domains[${index}]`),
  );
  for (let index = 1; index < domains.length; index += 1) {
    if (domains[index - 1].domain >= domains[index].domain) {
      rejectType(`${context}.domains must be sorted with unique domain values`);
    }
  }
  const snapshot = {
    healthy_total: normalizeBrowserKaigiU64(record.healthy_total, `${context}.healthy_total`),
    degraded_total: normalizeBrowserKaigiU64(record.degraded_total, `${context}.degraded_total`),
    unavailable_total: normalizeBrowserKaigiU64(
      record.unavailable_total,
      `${context}.unavailable_total`,
    ),
    reports_total: normalizeBrowserKaigiU64(record.reports_total, `${context}.reports_total`),
    registrations_total: normalizeBrowserKaigiU64(
      record.registrations_total,
      `${context}.registrations_total`,
    ),
    failovers_total: normalizeBrowserKaigiU64(record.failovers_total, `${context}.failovers_total`),
    domains,
  };
  if (
    BigInt(snapshot.healthy_total)
      + BigInt(snapshot.degraded_total)
      + BigInt(snapshot.unavailable_total)
    > BigInt(KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS)
  ) {
    rejectRange(`${context} current status totals must not exceed ${KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS}`);
  }
  for (const [totalField, domainField] of [
    ["reports_total", "health_reports_total"],
    [WIRE_FIELD_REGISTRATIONS_TOTAL, WIRE_FIELD_REGISTRATIONS_TOTAL],
    [WIRE_FIELD_FAILOVERS_TOTAL, WIRE_FIELD_FAILOVERS_TOTAL],
  ]) {
    let expected = 0n;
    for (const domain of domains) {
      expected += BigInt(domain[domainField]);
      if (expected > MAX_UINT64_BIGINT) expected = MAX_UINT64_BIGINT;
    }
    if (BigInt(snapshot[totalField]) !== expected) {
      rejectRange(`${context}.${totalField} must equal the saturated domain sum`);
    }
  }
  return snapshot;
}

async function readBoundedResponseBytes(response, maximumBodyBytes, context, signal) {
  if (!Number.isSafeInteger(maximumBodyBytes) || maximumBodyBytes < 0) {
    rejectType(`${context} response byte-size bound is invalid`);
  }
  const rawContentLength = response?.headers?.get?.("content-length");
  let declaredLength = null;
  if (rawContentLength !== null && rawContentLength !== undefined) {
    if (
      typeof rawContentLength !== "string"
      || !/^(?:0|[1-9][0-9]*)$/u.test(rawContentLength)
    ) {
      rejectType(`${context} Content-Length${TEXT_MUST_BE_A_2}canonical unsigned decimal integer`);
    }
    declaredLength = Number(rawContentLength);
    if (
      !Number.isSafeInteger(declaredLength)
      || declaredLength > maximumBodyBytes
    ) {
      rejectRange(`${context} exceeds its ${maximumBodyBytes}-byte response limit`);
    }
  }
  if (typeof response?.body?.getReader !== FIELD_FUNCTION) {
    rejectType(`${context} requires a byte-stream response body so its size can be bounded`);
  }

  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;
  let complete = false;
  let rejectAbort;
  const aborted = new Promise((_, reject) => {
    rejectAbort = reject;
  });
  aborted.catch(() => {});
  const onAbort = () => rejectAbort(abortReasonOf(signal));
  if (signal) {
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
  }
  try {
    while (true) {
      const result = await Promise.race([reader.read(), aborted]);
      if (!result || typeof result.done !== "boolean") {
        rejectType(`${context} returned an invalid response stream result`);
      }
      if (result.done) {
        complete = true;
        break;
      }
      if (!(result.value instanceof Uint8Array)) {
        rejectType(`${context} returned a non-byte response stream chunk`);
      }
      if (chunks.length >= BOUNDED_RESPONSE_MAX_STREAM_CHUNKS) {
        rejectRange(`${context} returned too many fragmented response chunks`);
      }
      if (result.value.byteLength > maximumBodyBytes - totalBytes) {
        rejectRange(`${context} exceeds its ${maximumBodyBytes}-byte response limit`);
      }
      totalBytes += result.value.byteLength;
      chunks.push(new Uint8Array(result.value));
    }
  } catch (error) {
    if (!complete && typeof reader.cancel === FIELD_FUNCTION) {
      try {
        await reader.cancel(error);
      } catch {
        // Preserve the deterministic validation failure.
      }
    }
    throw error;
  } finally {
    signal?.removeEventListener?.("abort", onAbort);
    if (typeof reader.releaseLock === FIELD_FUNCTION) {
      try {
        reader.releaseLock();
      } catch {
        // A cancelled reader may still hold a settled read request.
      }
    }
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  if (declaredLength !== null && declaredLength !== totalBytes) {
    rejectType(`${context} Content-Length${TEXT_DOES_NOT_MATCH_THE}response body`);
  }
  return bytes;
}

function abortReasonOf(signal) {
  if (signal?.reason !== undefined) return signal.reason;
  const error = new Error("The operation was aborted");
  error.name = "AbortError";
  return error;
}

async function readBoundedResponseText(response, maximumBodyBytes, context, signal) {
  const bytes = await readBoundedResponseBytes(response, maximumBodyBytes, context, signal);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    rejectType(`${context} must be valid UTF-8`, { cause: error });
  }
}

function streamRequestHeaders(defaultHeaders) {
  const headers = {};
  for (const [name, value] of Object.entries(defaultHeaders)) {
    const normalizedName = name.toLowerCase();
    if (normalizedName === "accept" || normalizedName === "last-event-id") continue;
    headers[name] = value;
  }
  headers.Accept = "text/event-stream";
  return headers;
}

function parseSseEventFrame(rawFrame) {
  let event = null;
  let id = null;
  let retry = null;
  const dataLines = [];
  for (const line of rawFrame.split(/\r\n|\r|\n/u)) {
    if (line === "" || line.startsWith(":")) continue;
    const separator = line.indexOf(":");
    const field = separator === -1 ? line : line.slice(0, separator);
    let value = separator === -1 ? "" : line.slice(separator + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "event") {
      event = value || null;
    } else if (field === "data") {
      dataLines.push(value);
    } else if (field === "id" && !value.includes("\0")) {
      id = value || null;
    } else if (field === "retry" && /^\d+$/u.test(value)) {
      const parsed = Number(value);
      if (Number.isSafeInteger(parsed)) retry = parsed;
    }
  }
  if (dataLines.length === 0 && event === null && id === null) return null;
  const raw = dataLines.length > 0 ? dataLines.join("\n") : null;
  let data = raw ?? "";
  if (raw !== null && raw.trim() !== "") {
    try {
      data = JSON.parse(raw);
    } catch {
      data = raw;
    }
  }
  return { event, data, id, retry, raw };
}

function extractSseFrames(buffer) {
  const frames = [];
  let remainder = buffer;
  while (true) {
    const boundary = /\r\n\r\n|\r\r|\n\n/u.exec(remainder);
    if (boundary === null) break;
    const parsed = parseSseEventFrame(remainder.slice(0, boundary.index));
    if (parsed !== null) frames.push(parsed);
    remainder = remainder.slice(boundary.index + boundary[0].length);
  }
  return { frames, remainder };
}

function streamGapFromEvent(event, label) {
  const payload = isPlainObject(event.data) ? event.data : null;
  const code =
    typeof payload?.code === "string" && payload.code.trim() !== ""
      ? payload.code
      : "stream_error";
  const message =
    typeof payload?.message === "string" && payload.message.trim() !== ""
      ? payload.message
      : `${label}reported a non-replayable gap.`;
  const droppedMessages =
    Number.isSafeInteger(payload?.dropped_messages) && payload.dropped_messages >= 0
      ? payload.dropped_messages
      : null;
  const replayAvailable = payload?.replay_available === true;
  return new ToriiStreamGapError(message, {
    code,
    droppedMessages,
    replayAvailable,
    payload: payload === null
      ? null
      : {
          code,
          message,
          dropped_messages: droppedMessages,
          replay_available: replayAvailable,
        },
  });
}


export class ToriiBrowserClient {
  #baseUrl;
  #canonicalRequestAuth;
  #collections;
  #defaultHeaders;
  #fetchImpl;
  #networkId;
  #networkPrefix;
  #operatorSigningContext;
  #timeoutMs;

  constructor(baseUrl, options = {}) {
    const normalizedOptions = requireSupportedOptions(
      requirePlainObject(options, (TEXT_TORII_BROWSER_CLIENT + "options")),
      (TEXT_TORII_BROWSER_CLIENT + "options"),
      TORII_BROWSER_CLIENT_OPTION_KEYS,
    );
    this.#baseUrl = normalizeBaseUrl(baseUrl);
    this.#fetchImpl = normalizedOptions.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    if (typeof this.#fetchImpl !== FIELD_FUNCTION) {
      rejectType((TEXT_TORII_BROWSER_CLIENT + "requires a fetch implementation"));
    }
    const defaultHeaders = normalizeDefaultHeaders(
      normalizedOptions.defaultHeaders,
      (TEXT_TORII_BROWSER_CLIENT + "options.defaultHeaders"),
    );
    rejectPrecomputedCanonicalHeaders(defaultHeaders);
    this.#defaultHeaders = Object.freeze(defaultHeaders);
    const allowInsecure = normalizedOptions.allowInsecure ?? false;
    if (typeof allowInsecure !== "boolean") {
      rejectType((TEXT_TORII_BROWSER_CLIENT + "options.allowInsecure" + TEXT_MUST_BE_A_2 + "boolean"));
    }
    const protocol = new URL(this.#baseUrl).protocol.toLowerCase();
    if (
      headersContainCredentials(this.#defaultHeaders) &&
      protocol !== "https:" &&
      !allowInsecure
    ) {
      rejectError("ToriiBrowserClient: credential headers require an https base URL; pass allowInsecure: true for local/dev use only.");
    }
    this.#timeoutMs = normalizeOffset(
      normalizedOptions.timeoutMs,
      (TEXT_TORII_BROWSER_CLIENT + "options.timeoutMs"),
      null,
    );
    this.#networkPrefix = normalizedOptions.networkPrefix === undefined
      ? null
      : requireNetworkPrefix(normalizedOptions.networkPrefix, "ToriiBrowserClient options.networkPrefix");
    this.#networkId = normalizedOptions.networkId ?? null;
    if (this.#networkId !== null) {
      networkIdBytes(this.#networkId, (TEXT_TORII_BROWSER_CLIENT + "options.networkId"));
    }
    this.#canonicalRequestAuth = normalizeBrowserCanonicalRequestAuth(
      normalizedOptions.canonicalRequestAuth,
      this.#networkId,
    );
    const operatorSigningContext = normalizedOptions.operatorSigningContext ?? null;
    this.#operatorSigningContext = operatorSigningContext === null
      ? null
      : requireOperatorSigningContext(
          operatorSigningContext,
          (TEXT_TORII_BROWSER_CLIENT + "options.operatorSigningContext"),
        );
    this.#collections = createToriiCollections((path, query, requestOptions) =>
      this.#queryCollection(path, query, requestOptions),
      {
        explorerAssetDefinitions: (row) => normalizeExplorerAssetDefinitionRecord(row, "explorer asset definition row"),
        explorerAssets: (row) => normalizeQuantityRecord(row, "explorer asset row", ["value"]),
        explorerRwas: (row) => normalizeQuantityRecord(row, "explorer rwa row", ["quantity", "held_quantity"]),
      },
    );
  }

  get baseUrl() {
    return this.#baseUrl;
  }

  get networkId() {
    return this.#networkId;
  }

  /** Domains (`POST /v1/domains/query`). */
  get domains() {
    return this.#collections.domains;
  }

  /** Accounts (`POST /v1/accounts/query`). */
  get accounts() {
    return this.#collections.accounts;
  }

  /** Asset definitions (`POST /v1/assets/definitions/query`). */
  get assetDefinitions() {
    return this.#collections.assetDefinitions;
  }

  /** NFTs (`POST /v1/nfts/query`). */
  get nfts() {
    return this.#collections.nfts;
  }

  /** RWA lots (`POST /v1/rwas/query`). */
  get rwas() {
    return this.#collections.rwas;
  }

  /** Committed contract calls, newest first, with history cursors. */
  /** Bounded Explorer accounts collection with shared query controls. */
  get explorerAccounts() { return this.#collections.explorerAccounts; }

  /** Bounded Explorer domains collection with shared query controls. */
  get explorerDomains() { return this.#collections.explorerDomains; }

  /** Bounded Explorer asset-definitions collection with shared query controls. */
  get explorerAssetDefinitions() { return this.#collections.explorerAssetDefinitions; }

  /** Bounded Explorer assets collection with shared query controls. */
  get explorerAssets() { return this.#collections.explorerAssets; }

  /** Bounded Explorer nfts collection with shared query controls. */
  get explorerNfts() { return this.#collections.explorerNfts; }

  /** Bounded Explorer rwas collection with shared query controls. */
  get explorerRwas() { return this.#collections.explorerRwas; }

  /** Bounded Explorer blocks collection with shared query controls. */
  get explorerBlocks() { return this.#collections.explorerBlocks; }

  /** Bounded Explorer transactions collection with shared query controls. */
  get explorerTransactions() { return this.#collections.explorerTransactions; }

  /** Bounded Explorer transactions/latest collection with shared query controls. */
  get explorerLatestTransactions() { return this.#collections.explorerLatestTransactions; }

  /** Bounded Explorer instructions collection with shared query controls. */
  get explorerInstructions() { return this.#collections.explorerInstructions; }

  /** Bounded Explorer instructions/latest collection with shared query controls. */
  get explorerLatestInstructions() { return this.#collections.explorerLatestInstructions; }

  get contractActivity() {
    return this.#collections.contractActivity;
  }

  /** Committed contract events, newest first, with history cursors. */
  get contractEvents() {
    return this.#collections.contractEvents;
  }

  /** Subscription plans (`POST /v1/subscriptions/plans/query`). */
  get subscriptionPlans() {
    return this.#collections.subscriptionPlans;
  }

  /** Subscriptions (`POST /v1/subscriptions/query`). */
  get subscriptions() {
    return this.#collections.subscriptions;
  }

  /** Effective direct and role-inherited permissions for one account. */
  /** Indexed account movements, newest first by block and movement position. */
  accountHistory(accountId) {
    return this.#collections.accountHistory(accountId);
  }

  accountPermissions(accountId) {
    return this.#collections.accountPermissions(accountId);
  }

  /** Space Directory manifest rows for one UAID. */
  uaidManifests(uaid) {
    return this.#collections.uaidManifests(uaid);
  }

  /** Repo agreements (`POST /v1/repo/agreements/query`). */
  get repoAgreements() {
    return this.#collections.repoAgreements;
  }

  /** Committed transactions, newest first (`POST /v1/transactions/query`); a history collection. */
  get transactions() {
    return this.#collections.transactions;
  }

  /** Asset balances of one account (`POST /v1/accounts/{account_id}/assets/query`). */
  accountAssets(accountId) {
    return this.#collections.accountAssets(accountId);
  }

  /** Holders of one asset definition (`POST /v1/assets/{definition_id}/holders/query`). */
  assetHolders(assetDefinitionId) {
    return this.#collections.assetHolders(assetDefinitionId);
  }

  /** Transactions of one account, newest first (`POST /v1/accounts/{account_id}/transactions/query`); a history collection. */
  accountTransactions(accountId) {
    return this.#collections.accountTransactions(accountId);
  }

  /**
   * Execute one collection query, signing it with the configured canonical
   * account credentials when present (collection routes never require them).
   */
  async #queryCollection(path, query, options) {
    const context = `${path} query options`;
    const opts = requireSupportedOptions(options ?? {}, context, COLLECTION_QUERY_OPTION_KEYS);
    const target = `${path}/query`;
    const bodyText = stringifyRequestJson(query.toJSON(), `${target} body`);
    let headers = opts.headers;
    let oneShot = false;
    if (this.#canonicalRequestAuth !== null) {
      rejectPrecomputedCanonicalHeaders({ ...this.#defaultHeaders, ...(opts.headers ?? {}) });
      const signed = await buildCanonicalJsonRequest({
        accountId: this.#canonicalRequestAuth.accountId,
        networkId: this.#networkId,
        method: "POST",
        path: target,
        baseUrl: this.#baseUrl,
        bodyText,
        headers: opts.headers,
        sign: this.#canonicalRequestAuth.sign,
      });
      headers = signed.headers;
      oneShot = true;
    }
    return this._json("POST", target, {
      rawBody: bodyText,
      contentType: FIELD_APPLICATION_JSON,
      headers,
      oneShot,
      omitCredentials: true,
      signal: signalFrom(opts),
      jsonParser: (text) => decodePageText(text, `${target} response`),
    });
  }

  /** Discover account bootstrap policy without using configured credentials or signing callbacks. */
  async getAccountCapabilities(options = {}) {
    const opts = signalOnlyOptions(options, "getAccountCapabilities options");
    const { signal, cleanup } = requestSignal(opts, this.#timeoutMs);
    try {
      const response = await Reflect.apply(this.#fetchImpl, undefined, [
        this._url((TEXT_V1_ACCOUNTS + "capabilities")),
        {
          method: "GET",
          headers: { Accept: FIELD_APPLICATION_JSON },
          credentials: "omit",
          cache: "no-store",
          redirect: "error",
          signal,
        },
      ]);
      return await readAccountCapabilitiesResponseV1(response, { signal });
    } finally {
      cleanup();
    }
  }

  _url(path, params) {
    const normalizedPath = requireNonEmptyString(path, "path").replace(/^\/+/, "");
    const base = new URL(`${this.#baseUrl}/`);
    const url = new URL(normalizedPath, base);
    appendSearchParams(url, params);
    return url;
  }

  async _applyDataspaceReadIdentity(url, init) {
    if (init.method !== "GET" || init.body !== undefined) {
      rejectType(("browser dataspace" + TEXT_AUTHENTICATION_ONLY_SUPPORTS_EMPTY_BODY_GETS));
    }
    rejectPrecomputedCanonicalHeaders(init.headers);
    init.credentials = "omit";
    if (this.#canonicalRequestAuth === null) return;
    const signed = await buildCanonicalJsonRequest({
      accountId: this.#canonicalRequestAuth.accountId,
      networkId: this.#networkId,
      method: "GET",
      path: url.pathname,
      query: url.search.startsWith("?") ? url.search.slice(1) : url.search,
      headers: init.headers,
      sign: this.#canonicalRequestAuth.sign,
    });
    init.headers = signed.headers;
    init.redirect = "error";
  }

  async _json(method, path, options = {}) {
    const normalizedOptions = requireObject(options, `${method} ${path} options`);
    const successStatuses = normalizeSuccessStatuses(
      normalizedOptions.successStatuses,
      `${method} ${path} successStatuses`,
    );
    const headers = {
      Accept: FIELD_APPLICATION_JSON,
      ...this.#defaultHeaders,
      ...(normalizedOptions.headers ?? {}),
    };
    const { signal, cleanup } = requestSignal(normalizedOptions, this.#timeoutMs);
    const init = {
      method,
      cache: "no-store",
      headers,
      signal,
    };
    const hasCanonicalNonce = Object.keys(headers).some(
      (name) => name.toLowerCase() === "x-iroha-nonce",
    );
    if (normalizedOptions.oneShot === true || hasCanonicalNonce) {
      init.redirect = "error";
    }
    if (normalizedOptions.rawBody !== undefined) {
      init.body = normalizedOptions.rawBody;
      init.headers = {
        ...headers,
        ...(normalizedOptions.contentType ? { "Content-Type": normalizedOptions.contentType } : {}),
      };
    } else if (normalizedOptions.body !== undefined) {
      init.body = JSON.stringify(normalizedOptions.body);
      init.headers = {
        ...headers,
        "Content-Type": FIELD_APPLICATION_JSON,
      };
    }
    const url = this._url(path, normalizedOptions.params);
    if (normalizedOptions.omitCredentials === true) {
      init.credentials = "omit";
    }
    if (normalizedOptions.dataspaceVisible === true) {
      await this._applyDataspaceReadIdentity(url, init);
    }
    if (normalizedOptions.operatorSigningContext !== undefined) {
      if (method !== "GET" || init.body !== undefined) {
        rejectType(("browser operator" + TEXT_AUTHENTICATION_ONLY_SUPPORTS_EMPTY_BODY_GETS));
      }
      await applyOperatorGetHeaders(
        init.headers,
        requireOperatorSigningContext(
          normalizedOptions.operatorSigningContext,
          `${method} ${path}`,
        ),
        url,
      );
      init.credentials = "omit";
      init.redirect = "error";
    }
    const { response, status } = await fetchToriiResponse(
      this.#fetchImpl,
      url,
      init,
      successStatuses,
      cleanup,
    );
    try {
      if (normalizedOptions.responseObserver !== undefined) {
        if (typeof normalizedOptions.responseObserver !== FIELD_FUNCTION) {
          rejectType(`${method} ${path} responseObserver${TEXT_MUST_BE_A_2}function`);
        }
        normalizedOptions.responseObserver(response);
      }
      if (
        status === 204
        || normalizedOptions.nullStatuses?.includes(status)
      ) return null;
      const jsonParser = normalizedOptions.jsonParser ?? JSON.parse;
      if (typeof jsonParser !== FIELD_FUNCTION) {
        rejectType(`${method} ${path} jsonParser${TEXT_MUST_BE_A_2}function`);
      }
      const text = await readBoundedResponseText(
        response,
        normalizedOptions.maximumBodyBytes ?? DEFAULT_JSON_RESPONSE_MAX_BYTES,
        `${method} ${path}`,
        signal,
      );
      if (text === "" && normalizedOptions.jsonParser === undefined) return null;
      return jsonParser(text);
    } finally {
      cleanup();
    }
  }

  async _bytes(method, path, options = {}) {
    const normalizedOptions = requireObject(options, `${method} ${path} options`);
    const headers = {
      ...this.#defaultHeaders,
      ...(normalizedOptions.headers ?? {}),
      Accept: FIELD_APPLICATION_X_NORITO,
    };
    const { signal, cleanup } = requestSignal(normalizedOptions, this.#timeoutMs);
    const { response } = await fetchToriiResponse(
      this.#fetchImpl,
      this._url(path, normalizedOptions.params),
      {
        method,
        cache: "no-store",
        headers,
        signal,
      },
      DEFAULT_SUCCESS_STATUSES,
      cleanup,
    );
    try {
      const contentType = response.headers?.get?.(FIELD_CONTENT_TYPE) ?? "";
      if (!/^application\/x-norito(?:\s*;|$)/iu.test(contentType)) {
        rejectType(`${method} ${path} must return application/x-norito`);
      }
      return Buffer.from(
        await readBoundedResponseBytes(
          response,
          normalizedOptions.maximumBodyBytes ?? DEFAULT_BINARY_RESPONSE_MAX_BYTES,
          `${method} ${path}`,
          signal,
        ),
      );
    } finally {
      cleanup();
    }
  }

  async _canonicalJson(method, path, body, options) {
    const opts = requireObject(options, `${method} ${path} canonical options`);
    rejectSuccessStatuses(opts, `${method} ${path} canonical options`);
    if (typeof opts.sign !== FIELD_FUNCTION) {
      rejectType(`${method} ${path} options.sign is required`);
    }
    if (this.#networkId === null) {
      rejectType(`${method} ${path} ${TEXT_REQUIRES_TORII_BROWSER_CLIENT_OPTIONS_NETWORK_ID}`);
    }
    const signed = await buildCanonicalJsonRequest({
      accountId: requireNonEmptyString(opts.authAccountId, `${method} ${path} options.authAccountId`),
      networkId: this.#networkId,
      method,
      path,
      baseUrl: this.#baseUrl,
      body,
      headers: opts.headers,
      sign: opts.sign,
      timestampMs: opts.timestampMs,
      nonce: opts.nonce,
    });
    return this._json(method, path, {
      rawBody: signed.body || undefined,
      contentType: body === undefined ? undefined : FIELD_APPLICATION_JSON,
      headers: signed.headers,
      oneShot: true,
      signal: signalFrom(opts),
    });
  }

  /** Submit exact locally signed version-1 transaction bytes to the pipeline. */
  submitTransaction(signedTransaction, options = {}) {
    const opts = requireSupportedOptions(
      options,
      "submitTransaction options",
      TRANSACTION_SUBMISSION_OPTION_KEYS,
    );
    const body = requireTransactionBytes(
      signedTransaction,
      "submitTransaction signedTransaction",
    );
    const expectedEntrypointHash = browserSignedTransactionHashHex(body, this.#networkPrefix);
    return this._json("POST", "/v1/pipeline/transactions", {
      rawBody: body,
      contentType: FIELD_APPLICATION_X_NORITO,
      headers: {
        Accept: FIELD_APPLICATION_JSON,
        ...(opts.headers ?? {}),
      },
      oneShot: true,
      signal: signalFrom(opts),
      successStatuses: TRANSACTION_ADMISSION_SUCCESS_STATUSES,
      responseObserver: (response) => {
        requireMatchingReceiptHashHeader(
          response,
          "x-iroha-entrypoint-hash",
          expectedEntrypointHash,
        );
        requireMatchingReceiptHashHeader(
          response,
          "x-iroha-signed-transaction-hash",
          expectedEntrypointHash,
        );
      },
    });
  }

  /** Fetch one exact pipeline status by transaction hash. */
  async getTransactionStatus(hashHex, options = {}) {
    const opts = requireSupportedOptions(
      options,
      "getTransactionStatus options",
      TRANSACTION_STATUS_READ_OPTION_KEYS,
    );
    const hash = requireExactHashHex(hashHex, "getTransactionStatus hashHex");
    const scope = normalizeTransactionStatusScope(
      opts.scope,
      "getTransactionStatus options.scope",
    );
    try {
      const payload = await this._json("GET", "/v1/pipeline/transactions/status", {
        params: {
          hash,
          scope,
        },
        headers: opts.headers,
        signal: signalFrom(opts),
      });
      return normalizePublicPipelineStatusEnvelope(
        payload,
        "pipeline transaction status",
      );
    } catch (error) {
      if (error instanceof ToriiHttpError && error.status === 404) {
        return null;
      }
      throw error;
    }
  }

  /** Poll until global chain state proves the exact transaction was applied. */
  async waitForTransactionStatus(hashHex, options = {}) {
    const context = "waitForTransactionStatus options";
    const opts = requireObject(options, context);
    const hash = requireExactHashHex(hashHex, "waitForTransactionStatus hashHex");
    rejectRemovedWaitScope(opts, context);
    requireSupportedOptions(opts, context, TRANSACTION_STATUS_POLL_OPTION_KEYS);
    const intervalMs = normalizeOffset(
      opts.intervalMs,
      "waitForTransactionStatus.intervalMs",
      250,
    );
    const timeoutMs = normalizePositiveInteger(
      opts.timeoutMs,
      "waitForTransactionStatus.timeoutMs",
      60_000,
    );
    const maxAttempts = normalizePositiveInteger(
      opts.maxAttempts,
      "waitForTransactionStatus.maxAttempts",
      Math.max(1, Math.ceil(timeoutMs / Math.max(1, intervalMs))),
    );
    const signal = signalFrom(opts);
    const deadline = Date.now() + timeoutMs;
    let lastStatus = null;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      throwIfAborted(signal);
      lastStatus = await this.getTransactionStatus(hash, {
        signal,
        scope: "global",
        headers: opts.headers,
      });
      if (lastStatus === null) {
        if (attempt >= maxAttempts || Date.now() >= deadline) break;
        await delayWithSignal(
          Math.min(intervalMs, Math.max(0, deadline - Date.now())),
          signal,
        );
        continue;
      }
      const classified = classifyGlobalPipelineStatusEnvelope(
        lastStatus,
        hash,
        "pipeline transaction status",
      );
      if (
        classified.kind === PIPELINE_SUCCESS_STATUS &&
        classified.authoritative
      ) {
        return lastStatus;
      }
      if (PIPELINE_FAILURE_STATUSES.has(classified.kind)) {
        const error = new Error(
          `Transaction ${hash} reached fixed failure status ${classified.kind}`,
        );
        error.name = "ToriiBrowserTransactionStatusError";
        error.hashHex = hash;
        error.status = classified.kind;
        error.payload = lastStatus;
        throw error;
      }
      if (attempt >= maxAttempts || Date.now() >= deadline) break;
      await delayWithSignal(Math.min(intervalMs, Math.max(0, deadline - Date.now())), signal);
    }
    const error = new Error(
      `Transaction ${hash} did not reach global state-resolved Applied finality within ${timeoutMs}ms`,
    );
    error.name = "ToriiBrowserTransactionTimeoutError";
    error.hashHex = hash;
    error.payload = lastStatus;
    throw error;
  }

  /** Submit exact locally signed bytes and wait for global state-resolved Applied finality. */
  async submitTransactionAndWait(signedTransaction, options = {}) {
    const context = (TEXT_SUBMIT_TRANSACTION_AND_WAIT + "options");
    const opts = requireObject(options, context);
    rejectRemovedWaitScope(opts, context);
    requireSupportedOptions(opts, context, SUBMIT_TRANSACTION_AND_WAIT_OPTION_KEYS);
    const body = requireTransactionBytes(
      signedTransaction,
      (TEXT_SUBMIT_TRANSACTION_AND_WAIT + "signedTransaction"),
    );
    const hashHex = browserSignedTransactionHashHex(body, this.#networkPrefix);
    if (opts.hashHex !== undefined) {
      const assertedHash = requireExactHashHex(
        opts.hashHex,
        (TEXT_SUBMIT_TRANSACTION_AND_WAIT + "options.hashHex"),
      );
      if (assertedHash !== hashHex) {
        rejectError((TEXT_SUBMIT_TRANSACTION_AND_WAIT + "options.hashHex does not match signedTransaction"));
      }
    }
    await this.submitTransaction(body, {
      signal: signalFrom(opts),
      headers: opts.headers,
    });
    return this.waitForTransactionStatus(hashHex, {
      signal: opts.signal,
      headers: opts.headers,
      intervalMs: opts.intervalMs,
      timeoutMs: opts.timeoutMs,
      maxAttempts: opts.maxAttempts,
    });
  }

  /**
   * Read the public node capability advert (`GET /v1/node/capabilities`)
   * before constructing deployment bytes. The route needs no credentials and
   * none are sent.
   */
  async getNodeCapabilities(options = {}) {
    const opts = requireSupportedOptions(options, "getNodeCapabilities options", LEDGER_READ_OPTION_KEYS);
    return this._json("GET", "/v1/node/capabilities", {
      signal: signalFrom(opts),
      omitCredentials: true,
    });
  }

  /** Resolve a contract alias; caller-supplied canonical signing headers are preserved. */
  resolveContractAlias(contractAlias, options) {
    return this._canonicalJson("POST", (TEXT_V1_CONTRACTS + "aliases/resolve"), {
        contract_alias: requireNonEmptyString(
          contractAlias,
          "resolveContractAlias contractAlias",
        ),
      }, options);
  }

  /** Read the exact one-view deployment CAS state through canonical app auth. */
  async getContractDeploymentState(request, options = {}) {
    const body = normalizeContractDeploymentStateRequest(request);
    const opts = requireObject(options, (TEXT_GET_CONTRACT_DEPLOYMENT_STATE + "options"));
    rejectSuccessStatuses(opts, (TEXT_GET_CONTRACT_DEPLOYMENT_STATE + "options"));
    if (opts.sign !== undefined) {
      if (typeof opts.sign !== FIELD_FUNCTION) {
        rejectType((TEXT_GET_CONTRACT_DEPLOYMENT_STATE + "options.sign" + TEXT_MUST_BE_A_2 + "function"));
      }
      if (this.#networkId === null) {
        rejectType((TEXT_GET_CONTRACT_DEPLOYMENT_STATE + TEXT_REQUIRES_TORII_BROWSER_CLIENT_OPTIONS_NETWORK_ID));
      }
      const signed = await buildCanonicalJsonRequest({
        accountId: requireNonEmptyString(
          opts.authAccountId,
          (TEXT_GET_CONTRACT_DEPLOYMENT_STATE + "options.authAccountId"),
        ),
        networkId: this.#networkId,
        method: "POST",
        path: FIELD_V1_CONTRACTS_DEPLOYMENT_STATE,
        baseUrl: this.#baseUrl,
        body,
        headers: opts.headers,
        sign: opts.sign,
        timestampMs: opts.timestampMs,
        nonce: opts.nonce,
      });
      const response = await this._json("POST", FIELD_V1_CONTRACTS_DEPLOYMENT_STATE, {
        rawBody: signed.body,
        contentType: FIELD_APPLICATION_JSON,
        headers: signed.headers,
        oneShot: true,
        signal: signalFrom(opts),
      });
      return normalizeContractDeploymentStateResponse(response, body);
    }
    const response = await this._json("POST", FIELD_V1_CONTRACTS_DEPLOYMENT_STATE, {
      body,
      headers: opts.headers,
      signal: signalFrom(opts),
    });
    return normalizeContractDeploymentStateResponse(response, body);
  }

  /** Read exact account state, using the configured canonical signer when present. */
  getAccount(accountId, options = {}) {
    const opts = requireObject(options, "getAccount options");
    rejectSuccessStatuses(opts, "getAccount options");
    return this._json(
      "GET",
      `${TEXT_V1_ACCOUNTS}${encodeURIComponent(requireNonEmptyString(accountId, FIELD_ACCOUNT_ID))}`,
      {
        headers: opts.headers,
        dataspaceVisible: true,
        signal: signalFrom(opts),
      },
    );
  }


  getExplorerAccount(accountId, options = {}) {
    const opts = requireObject(options, "getExplorerAccount options");
    return this._json("GET", `${TEXT_V1_EXPLORER}accounts/${encodeURIComponent(requireNonEmptyString(accountId, FIELD_ACCOUNT_ID))}`, {
      params: { address_format: opts.addressFormat ?? opts.address_format },
      dataspaceVisible: true,
      signal: signalFrom(opts),
    });
  }


  getExplorerDomain(domainId, options = {}) {
    const opts = requireObject(options, "getExplorerDomain options");
    return this._json("GET", `${TEXT_V1_EXPLORER}domains/${encodeURIComponent(requireNonEmptyString(domainId, "domainId"))}`, {
      dataspaceVisible: true,
      signal: signalFrom(opts),
    });
  }


  getExplorerAsset(assetId, options = {}) {
    const opts = requireObject(options, "getExplorerAsset options");
    return this._json("GET", `${TEXT_V1_EXPLORER}assets/${encodeURIComponent(requireNonEmptyString(assetId, "assetId"))}`, {
      dataspaceVisible: true,
      signal: signalFrom(opts),
    }).then((payload) =>
      normalizeQuantityRecord(payload, "explorer asset response", [FIELD_QUANTITY]),
    );
  }

  /**
   * Open one non-replayable fetch stream for generic contract events.
   * Stream gaps and an unrequested EOF are terminal; callers must explicitly resubscribe.
   */
  streamContractEvents(options = {}) {
    const context = "streamContractEvents options";
    const opts = requireSupportedOptions(options, context, CONTRACT_EVENT_STREAM_OPTION_KEYS);
    const params = normalizeContractEventFilterParams(opts, context);
    return this.#streamSse(TEXT_V1_CONTRACTS + "events/sse", params, opts, "The contract event stream ");
  }

  /**
   * Stream pipeline and data events from `/v1/events/sse`. `options.filter`
   * uses the collection-query text grammar over event fields (`tx_hash`,
   * `tx_status`, `block_height`, ...): a `Filter`, a text filter or the JSON
   * form. Each frame's `data` is one JSON object with `category` and
   * `event`; integers beyond `Number.MAX_SAFE_INTEGER` are `bigint`. A
   * `stream_error` event or an unexpected end of the stream raises a
   * `ToriiStreamGapError`.
   */
  streamEvents(options = {}) {
    const opts = requireSupportedOptions(options, "streamEvents options", EVENT_STREAM_OPTION_KEYS);
    const filter = filterQueryText(opts.filter);
    return decodeEventFrames(
      this.#streamSse(
        "/v1/events/sse",
        filter === undefined ? {} : { filter },
        opts,
        "The event stream ",
      ),
      "The event stream",
    );
  }

  #streamSse(path, params, opts, label) {
    const client = this;
    return (async function* sseIterator() {
      const url = client._url(path, params);
      const init = {
        method: "GET",
        cache: "no-store",
        headers: streamRequestHeaders(client.#defaultHeaders),
        signal: signalFrom(opts),
      };
      await client._applyDataspaceReadIdentity(url, init);
      const response = await Reflect.apply(client.#fetchImpl, undefined, [url, init]);
      if (init.redirect === "error" && response?.redirected === true) {
        rejectType(TEXT_TORII_ONE_SHOT_REQUEST_MUST_NOT_ACCEPT_A_REDIRECTED_RESPONSE);
      }
      const status = responseStatus(response);
      if (status !== 200) {
        throw await toriiHttpErrorFromResponse(response, status, [200]);
      }
      if (typeof response?.body?.getReader !== FIELD_FUNCTION) {
        throw new ToriiStreamGapError(
          `${label}ended without a readable response body.`,
          { code: "stream_unexpected_eof" },
        );
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let ended = false;
      // Abort pending reads even when the fetch implementation does not tie
      // the body to the request signal.
      const signal = init.signal;
      let rejectAbort;
      const aborted = new Promise((_, reject) => {
        rejectAbort = reject;
      });
      aborted.catch(() => {});
      const onAbort = () => rejectAbort(abortReasonOf(signal));
      if (signal) {
        if (signal.aborted) onAbort();
        else signal.addEventListener("abort", onAbort, { once: true });
      }
      try {
        while (!ended) {
          const chunk = await Promise.race([reader.read(), aborted]);
          ended = chunk.done === true;
          if (chunk.value !== undefined) {
            buffer += decoder.decode(chunk.value, { stream: !ended });
          }
          if (ended) buffer += decoder.decode();
          const parsed = extractSseFrames(buffer);
          buffer = parsed.remainder;
          for (const event of parsed.frames) {
            if (event.event === "stream_error") throw streamGapFromEvent(event, label);
            yield event;
          }
        }
        if (opts.signal?.aborted === true) return;
        throw new ToriiStreamGapError(
          `${label}ended unexpectedly and cannot be resumed.`,
          { code: "stream_unexpected_eof" },
        );
      } finally {
        signal?.removeEventListener("abort", onAbort);
        if (!ended && typeof reader.cancel === FIELD_FUNCTION) {
          try {
            await reader.cancel();
          } catch {
            // Preserve the stream error or consumer cancellation that entered this block.
          }
        }
        if (typeof reader.releaseLock === FIELD_FUNCTION) {
          try {
            reader.releaseLock();
          } catch {
            // A cancelled reader may still hold a settled read request.
          }
        }
      }
    })();
  }

  getAssetDefinition(assetDefinitionId, options = {}) {
    const opts = requireObject(options, "getAssetDefinition options");
    return this._json("GET", `/v1/assets/definitions/${encodeURIComponent(requireNonEmptyString(assetDefinitionId, FIELD_ASSET_DEFINITION_ID))}`, {
      signal: signalFrom(opts),
    }).then((payload) =>
      normalizeQuantityRecord(
        payload,
        "asset definition response",
        [WIRE_FIELD_TOTAL_QUANTITY],
        { optional: true },
      ),
    );
  }

  resolveAlias(aliasOrRequest, options = {}) {
    const opts = requireObject(options, "resolveAlias options");
    const body =
      typeof aliasOrRequest === "string"
        ? { alias: requireNonEmptyString(aliasOrRequest, "alias") }
        : requireObject(aliasOrRequest, "resolveAlias request");
    return this._json("POST", "/v1/aliases/resolve", {
      body,
      signal: signalFrom(opts),
    });
  }

  resolveAssetAlias(aliasOrRequest, options = {}) {
    const opts = requireObject(options, "resolveAssetAlias options");
    const body =
      typeof aliasOrRequest === "string"
        ? { alias: requireNonEmptyString(aliasOrRequest, "alias") }
        : requireObject(aliasOrRequest, "resolveAssetAlias request");
    return this._json("POST", "/v1/assets/aliases/resolve", {
      body,
      signal: signalFrom(opts),
    });
  }


  getExplorerAssetDefinitionEconometrics(assetDefinitionId, options = {}) {
    const opts = requireObject(options, "getExplorerAssetDefinitionEconometrics options");
    return this._json("GET", `${TEXT_V1_EXPLORER}asset-definitions/${encodeURIComponent(requireNonEmptyString(assetDefinitionId, FIELD_ASSET_DEFINITION_ID))}/econometrics`, {
      dataspaceVisible: true,
      signal: signalFrom(opts),
    });
  }

  getExplorerAssetDefinitionSnapshot(assetDefinitionId, options = {}) {
    const opts = requireObject(options, "getExplorerAssetDefinitionSnapshot options");
    return this._json("GET", `${TEXT_V1_EXPLORER}asset-definitions/${encodeURIComponent(requireNonEmptyString(assetDefinitionId, FIELD_ASSET_DEFINITION_ID))}/snapshot`, {
      dataspaceVisible: true,
      signal: signalFrom(opts),
    });
  }


  getExplorerNft(nftId, options = {}) {
    const opts = requireObject(options, "getExplorerNft options");
    return this._json("GET", `${TEXT_V1_EXPLORER}nfts/${encodeURIComponent(requireNonEmptyString(nftId, "nftId"))}`, {
      dataspaceVisible: true,
      signal: signalFrom(opts),
    });
  }


  getExplorerRwa(rwaId, options = {}) {
    const opts = requireObject(options, "getExplorerRwa options");
    return this._json("GET", `${TEXT_V1_EXPLORER}rwas/${encodeURIComponent(requireNonEmptyString(rwaId, "rwaId"))}`, {
      dataspaceVisible: true,
      signal: signalFrom(opts),
    }).then((payload) =>
      normalizeQuantityRecord(payload, "explorer rwa response", [FIELD_QUANTITY, "held_quantity"]),
    );
  }


  getExplorerBlock(identifier, options = {}) {
    const opts = requireObject(options, "getExplorerBlock options");
    return this._json("GET", `${TEXT_V1_EXPLORER}blocks/${encodeURIComponent(String(identifier))}`, {
      dataspaceVisible: true,
      signal: signalFrom(opts),
    });
  }

  /** List newest-first canonical ledger headers with Torii's bounded window. */
  listLedgerHeaders(options = {}) {
    const context = "listLedgerHeaders options";
    const opts = requireSupportedOptions(options, context, LEDGER_HEADERS_OPTION_KEYS);
    return this._json("GET", "/v1/ledger/headers", {
      params: {
        from: opts.from === undefined
          ? undefined
          : normalizeLedgerHeight(opts.from, `${context}.from`),
        limit: opts.limit === undefined
          ? undefined
          : normalizePositiveInteger(opts.limit, `${context}.limit`, undefined),
      },
      signal: signalFrom(opts),
    });
  }

  /** Fetch exact Sumeragi-v2 finality carrying the authenticated post-state root. */
  getLedgerStateRoot(height, options = {}) {
    const context = "getLedgerStateRoot options";
    const opts = requireSupportedOptions(options, context, LEDGER_READ_OPTION_KEYS);
    const normalizedHeight = normalizeLedgerHeight(height, "getLedgerStateRoot height");
    return this._json("GET", `/v1/ledger/state/${normalizedHeight}`, {
      signal: signalFrom(opts),
    });
  }

  /** Fetch the same exact Sumeragi-v2 state-finality carrier for proof consumers. */
  getLedgerStateProof(height, options = {}) {
    const context = "getLedgerStateProof options";
    const opts = requireSupportedOptions(options, context, LEDGER_READ_OPTION_KEYS);
    const normalizedHeight = normalizeLedgerHeight(height, "getLedgerStateProof height");
    return this._json("GET", `/v1/ledger/state-proof/${normalizedHeight}`, {
      signal: signalFrom(opts),
    });
  }

  /** Fetch the exact canonical result-bearing SignedBlockWire at a finalized height. */
  async getLedgerExecutedBlockWire(height, options = {}) {
    const context = "getLedgerExecutedBlockWire options";
    const opts = requireSupportedOptions(options, context, LEDGER_READ_OPTION_KEYS);
    const normalizedHeight = normalizeLedgerHeight(
      height,
      "getLedgerExecutedBlockWire height",
    );
    const bytes = await this._bytes(
      "GET",
      `/v1/ledger/block/${normalizedHeight}`,
      {
        signal: signalFrom(opts),
        maximumBodyBytes: AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1,
      },
    );
    if (bytes.byteLength === 0) {
      rejectType("executed block wire response must not be empty");
    }
    return bytes;
  }

  /** Fetch and decode the canonical Norito block inclusion/execution proof. */
  async getLedgerBlockProof(height, entryHash, options = {}) {
    const context = "getLedgerBlockProof options";
    const opts = requireSupportedOptions(options, context, LEDGER_READ_OPTION_KEYS);
    const normalizedHeight = normalizeLedgerHeight(height, "getLedgerBlockProof height");
    const normalizedHash = normalizeLedgerEntryHash(
      entryHash,
      "getLedgerBlockProof entryHash",
    );
    const bytes = await this._bytes(
      "GET",
      `/v1/ledger/block/${normalizedHeight}/proof/${normalizedHash}`,
      {
        signal: signalFrom(opts),
        maximumBodyBytes: AUTHENTICATED_BLOCK_PROOFS_MAX_PROOF_BYTES_V1,
      },
    );
    return noritoDecodeBlockProofs(bytes);
  }

  getExplorerMetrics(options = {}) {
    const opts = requireObject(options, "getExplorerMetrics options");
    return this._json("GET", (TEXT_V1_EXPLORER + "metrics"), {
      dataspaceVisible: true,
      signal: signalFrom(opts),
    });
  }

  getExplorerHealth(options = {}) {
    const opts = requireObject(options, "getExplorerHealth options");
    return this._json("GET", (TEXT_V1_EXPLORER + "health"), { signal: signalFrom(opts) });
  }



  getExplorerTransaction(hash, options = {}) {
    const opts = requireObject(options, "getExplorerTransaction options");
    return this._json("GET", `${TEXT_V1_EXPLORER}transactions/${encodeURIComponent(requireNonEmptyString(hash, "hash"))}`, {
      params: { address_format: opts.addressFormat ?? opts.address_format },
      dataspaceVisible: true,
      signal: signalFrom(opts),
    });
  }



  getExplorerInstruction(transactionHash, index, options = {}) {
    const opts = requireObject(options, "getExplorerInstruction options");
    return this._json("GET", `${TEXT_V1_EXPLORER}instructions/${encodeURIComponent(requireNonEmptyString(transactionHash, FIELD_TRANSACTION_HASH))}/${encodeURIComponent(String(index))}`, {
      params: { address_format: opts.addressFormat ?? opts.address_format },
      dataspaceVisible: true,
      signal: signalFrom(opts),
    });
  }

  getExplorerInstructionContractView(transactionHash, index, options = {}) {
    const opts = requireObject(options, "getExplorerInstructionContractView options");
    return this._json("GET", `${TEXT_V1_EXPLORER}instructions/${encodeURIComponent(requireNonEmptyString(transactionHash, FIELD_TRANSACTION_HASH))}/${encodeURIComponent(String(index))}/contract-view`, {
      dataspaceVisible: true,
      signal: signalFrom(opts),
    });
  }

  getMultisigSpec(selector, options) {
    return this._canonicalJson("POST", "/v1/multisig/spec",
      normalizeMultisigSelectorBody(selector, "getMultisigSpec selector"), options);
  }

  queryMultisigProposals(selector, options) {
    return this._canonicalJson("POST", "/v1/multisig/proposals/query",
      normalizeMultisigProposalsQueryBody(
        selector,
        "queryMultisigProposals selector",
      ), options);
  }

  resolveMultisigProposal(request, options) {
    const normalizedRequest = normalizeMultisigProposalsResolveBody(
      request,
      "resolveMultisigProposal request",
    );
    return this._canonicalJson(
      "POST", "/v1/multisig/proposals/resolve", normalizedRequest, options,
    );
  }

  async submitMultisigPropose(request, options = {}) {
    const opts = requireObject(options, "submitMultisigPropose options");
    rejectSuccessStatuses(opts, "submitMultisigPropose options");
    return this._json("POST", "/v1/multisig/propose", {
      rawBody: noritoEncodeMultisigProposeRequest(requireObject(request, "submitMultisigPropose request"), this.#networkPrefix),
      contentType: FIELD_APPLICATION_X_NORITO,
      headers: { Accept: FIELD_APPLICATION_JSON, ...(opts.headers ?? {}) },
      signal: signalFrom(opts),
      successStatuses: [200, 202],
    });
  }

  async submitMultisigContractCallPropose(request, options = {}) {
    const opts = requireObject(options, (TEXT_SUBMIT_MULTISIG_CONTRACT_CALL_PROPOSE + "options"));
    rejectSuccessStatuses(opts, (TEXT_SUBMIT_MULTISIG_CONTRACT_CALL_PROPOSE + "options"));
    return this._json("POST", (TEXT_V1_CONTRACTS + "call/multisig/propose"), {
      rawBody: noritoEncodeMultisigContractCallProposeRequest(
        requireObject(request, (TEXT_SUBMIT_MULTISIG_CONTRACT_CALL_PROPOSE + "request")),
        this.#networkPrefix,
      ),
      contentType: FIELD_APPLICATION_X_NORITO,
      headers: { Accept: FIELD_APPLICATION_JSON, ...(opts.headers ?? {}) },
      signal: signalFrom(opts),
      successStatuses: [200, 202],
    });
  }

  async submitMultisigContractCallApprove(request, options = {}) {
    const opts = requireObject(options, (TEXT_SUBMIT_MULTISIG_CONTRACT_CALL_APPROVE + "options"));
    rejectSuccessStatuses(opts, (TEXT_SUBMIT_MULTISIG_CONTRACT_CALL_APPROVE + "options"));
    return this._json("POST", (TEXT_V1_CONTRACTS + "call/multisig/approve"), {
      rawBody: noritoEncodeMultisigContractCallApproveRequest(
        requireObject(request, (TEXT_SUBMIT_MULTISIG_CONTRACT_CALL_APPROVE + "request")),
        this.#networkPrefix,
      ),
      contentType: FIELD_APPLICATION_X_NORITO,
      headers: { Accept: FIELD_APPLICATION_JSON, ...(opts.headers ?? {}) },
      signal: signalFrom(opts),
      successStatuses: [200, 202],
    });
  }

  getSumeragiStatus(options = {}) {
    const opts = requireObject(options, "getSumeragiStatus options");
    return this._json("GET", "/v1/sumeragi/status", {
      signal: signalFrom(opts),
      operatorSigningContext: requireOperatorSigningContext(
        this.#operatorSigningContext,
        "getSumeragiStatus",
      ),
    });
  }

  getSumeragiStatusTyped(options = {}) {
    const opts = signalOnlyOptions(options, "getSumeragiStatusTyped options");
    return this._json("GET", "/v1/sumeragi/status", {
      headers: { Accept: FIELD_APPLICATION_JSON },
      signal: signalFrom(opts),
      operatorSigningContext: requireOperatorSigningContext(
        this.#operatorSigningContext,
        "getSumeragiStatusTyped",
      ),
      maximumBodyBytes: SUMERAGI_STATUS_TYPED_JSON_MAX_BYTES,
      responseObserver: (response) => {
        requireExactJsonContentType(
          response.headers.get(FIELD_CONTENT_TYPE),
          "Sumeragi typed status response",
        );
      },
      jsonParser: (text) => import("./sumeragiTyped.js").then(
        ({ parseSumeragiStatusJson }) => parseSumeragiStatusJson(
          text,
          "Sumeragi typed status",
        ),
      ),
    });
  }

  getSumeragiLanes(options = {}) {
    const opts = signalOnlyOptions(options, "getSumeragiLanes options");
    return this._json("GET", "/v1/sumeragi/lanes", {
      headers: { Accept: FIELD_APPLICATION_JSON },
      signal: signalFrom(opts),
      operatorSigningContext: requireOperatorSigningContext(
        this.#operatorSigningContext,
        "getSumeragiLanes",
      ),
      maximumBodyBytes: SUMERAGI_LANES_TYPED_JSON_MAX_BYTES,
      responseObserver: (response) => {
        requireExactJsonContentType(
          response.headers.get(FIELD_CONTENT_TYPE),
          "Sumeragi lanes response",
        );
      },
      jsonParser: (text) => import("./sumeragiTyped.js").then(
        ({ parseSumeragiLanesJson }) => parseSumeragiLanesJson(text, "Sumeragi lanes"),
      ),
    });
  }

  listKaigiRelays(options = {}) {
    const opts = signalOnlyOptions(options, "listKaigiRelays options");
    return this._json("GET", "/v1/kaigi/relays", {
      signal: signalFrom(opts),
      operatorSigningContext: requireOperatorSigningContext(
        this.#operatorSigningContext,
        "listKaigiRelays",
      ),
      maximumBodyBytes: KAIGI_JSON_RESPONSE_MAX_BYTES,
      jsonParser: (text) => parseStrictLosslessIntegerJson(
        text,
        CONTEXT_KAIGI_RELAY_LIST_RESPONSE,
      ),
      responseObserver: (response) => requireExactJsonContentType(
        response.headers?.get?.(FIELD_CONTENT_TYPE),
        CONTEXT_KAIGI_RELAY_LIST_RESPONSE,
      ),
    }).then(normalizeBrowserKaigiRelayList);
  }

  getKaigiRelay(relayId, options = {}) {
    const opts = signalOnlyOptions(options, "getKaigiRelay options");
    const normalizedRelayId = requireExactKaigiAccountId(relayId, "relayId");
    return this._json("GET", `/v1/kaigi/relays/${encodeURIComponent(normalizedRelayId)}`, {
      signal: signalFrom(opts),
      operatorSigningContext: requireOperatorSigningContext(
        this.#operatorSigningContext,
        "getKaigiRelay",
      ),
      maximumBodyBytes: KAIGI_JSON_RESPONSE_MAX_BYTES,
      successStatuses: [200, 404],
      nullStatuses: [404],
      jsonParser: (text) => parseStrictLosslessIntegerJson(
        text,
        CONTEXT_KAIGI_RELAY_DETAIL_RESPONSE,
      ),
      responseObserver: (response) => {
        if (responseStatus(response) === 404) {
          return;
        }
        requireExactJsonContentType(
          response.headers?.get?.(FIELD_CONTENT_TYPE),
          CONTEXT_KAIGI_RELAY_DETAIL_RESPONSE,
        );
      },
    }).then((payload) => payload === null ? null : normalizeBrowserKaigiRelayDetail(payload));
  }

  getKaigiRelaysHealth(options = {}) {
    const opts = signalOnlyOptions(options, "getKaigiRelaysHealth options");
    return this._json("GET", "/v1/kaigi/relays/health", {
      signal: signalFrom(opts),
      operatorSigningContext: requireOperatorSigningContext(
        this.#operatorSigningContext,
        "getKaigiRelaysHealth",
      ),
      maximumBodyBytes: KAIGI_JSON_RESPONSE_MAX_BYTES,
      jsonParser: (text) => parseStrictLosslessIntegerJson(
        text,
        CONTEXT_KAIGI_RELAY_HEALTH_RESPONSE,
      ),
      responseObserver: (response) => requireExactJsonContentType(
        response.headers?.get?.(FIELD_CONTENT_TYPE),
        CONTEXT_KAIGI_RELAY_HEALTH_RESPONSE,
      ),
    }).then(normalizeBrowserKaigiHealth);
  }

}
