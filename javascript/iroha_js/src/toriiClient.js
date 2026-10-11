import { validateManifestDeclarationsV1, validateManifestEntrypointIdentityV1, validateManifestFieldsV1 } from "./contractManifestRules.js";
import { normalizeValidationFeePolicy as parseGovernanceValidationFeePolicy, normalizeValidationFeePayoutLifecycle as parseGovernanceValidationFeePayoutLifecycle } from "./governanceProposalV1.js";
import { normalizeRetailFeeAssessment, rejectUnknownRetailFeeFields } from "./retailFeeAssessment.js";
import { parseGovernanceReferendumResponseV1, parseGovernanceTallyResponseV1, parseGovernanceLocksResponseV1 } from "./governancePlainV1.js";
import { parseElectionTallyResponseV1 } from "./electionTallyV1.js";
import { createSorafsAliasResponseNormalizers } from "./sorafsAliasResponses.js";
import { normalizeContractErrorMessagesV1, normalizeContractErrorTypeV1, normalizeContractErrorTypesV1, validateManifestErrorTypeBindingsV1 } from "./contractErrorTypes.js";
import { rejectError, rejectRange, rejectType } from "./validationThrow.js";
import { timingSafeEqual } from "node:crypto";
import { JS_TYPE_BIGINT, JS_TYPE_FUNCTION, JS_TYPE_NUMBER, JS_TYPE_OBJECT, JS_TYPE_STRING, KAIGI_MAX_PARTICIPANTS_V1 } from "./commonLiterals.js";
import { readAccountCapabilitiesResponseV1 } from "./accountCapabilities.js";
import {
  resolveToriiClientConfig,
  extractConfidentialGasConfig,
} from "./config.js";
import {
  createNativeRuntime,
  defaultNativeRuntime,
  resolveNativeRuntimeBinding,
  resolveOptionalNativeRuntimeBinding,
} from "./nativeRuntime.js";
import {
  TORII_TEST_HOOKS,
  TORII_TEST_NATIVE_BINDING,
} from "./toriiTestHooks.js";
import { computeHashLiteralCrc } from "./hashLiteralCrc.js";
import {
  canonicalizeMultihashHex,
  ensureCanonicalAccountId,
  normalizeAccountAliasFqn,
  normalizeAccountAliasLiteral,
  normalizeAccountId,
  normalizeAssetDefinitionId,
  normalizeAssetId,
  normalizeAssetHoldingId,
  normalizeRwaId,
} from "./normalizers.js";
import {
  AccountAddress,
  AccountAddressError,
  curveIdToAlgorithm,
  ensureCurveIdEnabled,
  normalizeBytes,
  parseCanonicalI105AccountLiteral,
  validatePublicKeyForCurve,
} from "./address.js";
import {
  _createDataAvailabilityApi,
  buildDaIngestRequest,
  emitDaProofSummaryArtifact,
} from "./dataAvailability.js";
import {
  _createSorafsGatewayApi,
  normaliseGatewayProvider,
} from "./sorafs.js";
import { normalizeIsoWeekLabel } from "./sorafsPorWeek.js";
import { createSorafsPinDetailNormalizer, normalizeSorafsPinU64 } from "./sorafsPinDetail.js";
import { buildPacs008Message, buildPacs009Message } from "./isoBridge.js";
import { looksLikeIban, normalizeIban } from "./identifiers.js";
import {
  KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS,
  isCanonicalKotodamaDynamicAccessBaseKey,
  isCanonicalKotodamaEntrypoint,
  isCanonicalKotodamaIdentifier,
  isCanonicalKotodamaStateTypeName,
  isKotodamaV1DynamicAccessBoundKind,
  isKotodamaV1StateMapKeyTypeName,
  kotodamaV1StateMapKeyTypeName,
} from "./kotodamaIdentifiers.js";
import { analyzeEntrypointValueTypeV1, MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1 } from "./entrypointSchema.js";
import {
  createValidationError,
  ValidationErrorCode,
} from "./validationError.js";
import {
  normalizeTransactionStatusScope,
  readHeaderValue,
} from "./toriiClientPrimitives.js";
import {
  NODE_CAPABILITIES_JSON_MAX_BYTES,
  ToriiDataModelMismatchError,
  ensureNodeDataModelCompatibility,
  normalizeNodeCapabilitiesResponse,
} from "./toriiCompatibility.js";
import { registerPrivacyExact12CapabilityManifestTransportV1 } from "./privacyCapabilityTransport.js";
import {
  parseStrictLosslessJson,
  parseStrictLosslessIntegerJson,
  stringifyStrictLosslessIntegerJson,
} from "./strictLosslessJson.js";
import {
  SUMERAGI_LANES_TYPED_JSON_MAX_BYTES,
  SUMERAGI_STATUS_TYPED_JSON_MAX_BYTES,
} from "./sumeragiTypedLimits.js";
import { buildCanonicalRequestHeaders } from "./canonicalRequest.js";
import { requireCanonicalAuthAccount } from "./canonicalAccount.js";
import { normalizeCanonicalWitnessHeader } from "./canonicalWitness.js";
import {
  applyOperatorRequestHeaders,
  installOperatorSigningContext,
  OperatorSigningContext,
  rejectMixedRequestAuth,
  rejectRetiredIsoAuthHeaders,
  requireIsoOperatorSigningContext,
  requireOperatorSigningContext,
  resolveOperatorSigningContext,
} from "./operatorRequest.js";
import {
  getIsoStatusTransport,
  normalizeIsoOptionalString,
  normalizeIsoProfile,
  normalizeIsoStatus,
  normalizeIsoStringArray,
  normalizePacs002Code,
  submitIsoTransport,
} from "./iso20022Transport.js";
import { blake2b256 } from "./blake2b.js";
import { NetworkId, networkIdBytes } from "./networkId.js";
import { generateConnectSid, validateConnectSessionResponseIdentity } from "./connectSession.js";
import { isCanonicalGovernanceSelectorV1 } from "./governanceSelector.js";
import { parseCanonicalContractAddress } from "./contractAddress.js";
import { contractPayloadDigestHex } from "./contractPayload.js";
import {
  createToriiGovernanceNormalizers,
  VERIFYING_KEY_PRIVATE_KEY_FIELDS,
} from "./toriiGovernanceNormalizers.js";
import { createSubscriptionResponseNormalizers } from "./subscriptionResponses.js";
import {
  decodeExactSoracloudJsonResponse,
  normalizeSoracloudMutationDraftResponse,
  requestSoracloudAppInfraStatus,
} from "./soracloud.js";
import {
  normalizeCanonicalApplicationPostOptions,
  rejectPrecomputedCanonicalHeaders,
  requireCanonicalApplicationAuthority,
} from "./applicationPostAuth.js";
import { strictDecodeBase64 } from "./toriiClientEncoding.js";
import {
  isExactJsonMediaType,
  maybeBoundedJsonResponse, maybeJsonResponse,
  PIPELINE_FASTPQ_RECOVERY_JSON_MAX_BYTES,
  PIPELINE_RECOVERY_JSON_MAX_BYTES,
} from "./toriiBoundedResponse.js";
import {
  KotodamaQuantity,
  NumericV1,
  NumericV1Error,
} from "./numericV1.js";
import { SM2_DEFAULT_DISTINGUISHED_ID, verifyEd25519, verifySm2 } from "./crypto.js";
import {
  getCurveEntryByPublicKeyMulticodec,
} from "./curveRegistry.js";
import { computeIvmArtifactHashes, IVM_ARTIFACT_MAX_BYTES } from "./ivmArtifact.js";
import { AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1 } from "./authenticatedBlockProofs.js";
import { createVpnSchema } from "./vpnSchema.js";
import {
  assertSorafsOrderbookFixedHeaders,
  createSorafsOrderbookSubmissionDeadline,
  prepareSorafsOrderbookSubmission,
  sorafsOrderbookHeaderFingerprint,
  validateSorafsOrderbookSubmissionTransport,
} from "./sorafsOrderbookPreflight.js";
import {
  normalizeValidationFeeCheckpointV1,
  normalizeValidationFeeLedgerBindingV1,
} from "./validationFeeTrust.js";
import { SorafsOrderbookSubmissionAmbiguousError } from "./sorafsOrderbookAmbiguousError.js";
import { ToriiHttpError, extractToriiErrorFields } from "./toriiErrors.js";
import { createToriiCollections } from "./query/collections.js";
import { decodePageText, stringifyRequestJson } from "./query/page.js";
import { filterQueryText } from "./query/listQuery.js";
import { decodeEventFrames } from "./toriiEventStream.js";
export { SorafsOrderbookSubmissionAmbiguousError };
export {
  FilterSyntaxError,
  ListQueryError,
  ToriiError,
  ToriiHttpError,
  ToriiStreamGapError,
} from "./toriiErrors.js";
export * from "./query/index.js";

const CANONICAL_AUTH_FIELD = "canonicalAuth";
const COLLECTION_QUERY_OPTION_KEYS = new Set(["signal", CANONICAL_AUTH_FIELD]);
const EXPECTED_FINALIZED_HASH_FIELD = "expectedFinalizedBlockHashHex";
const EXPECTED_FINALIZED_HEIGHT_FIELD = "expectedFinalizedHeight";
const GOVERNANCE_MANIFEST_ADMISSION_CONTEXT = "governance.manifest_admission";
const DEFAULT_PAGE_SIZE = 100;
const EXPLORER_CURSOR_PATTERN = /^[A-Za-z0-9_-]+$/u;
const EXPLORER_CURSOR_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const SORAFS_POR_PAGE_DEFAULT_LIMIT = 100;
const SORAFS_POR_PAGE_MAX_LIMIT = 1_000;
const SORAFS_POR_PAGE_DEFAULT_MAX_BYTES = 4_194_304;
const SORAFS_POR_CURSOR_MAX_LENGTH = 256;
const APPLICATION_JSON = "application/json";
const APPLICATION_NORITO = "application/x-norito";
const JSON_ACCEPT_HEADERS = Object.freeze({ Accept: APPLICATION_JSON });
const JSON_REQUEST_HEADERS = Object.freeze({
  "Content-Type": APPLICATION_JSON,
  Accept: APPLICATION_JSON,
});
const PROPOSE_DEPLOY_CONTRACT_WIRE_ID =
  "iroha.instruction.v1::governance::ProposeDeployContract";

const AUTHORITATIVE_PIPELINE_STATUS_KINDS = new Set([
  "Queued",
  "Approved",
  "Committed",
  "Applied",
  "Rejected",
  "Expired",
]);
const DEFAULT_TX_STATUS_POLL_INTERVAL_MS = 1_000;
const DEFAULT_TX_STATUS_TIMEOUT_MS = 30_000;
const IVM_ARTIFACT_MAX_BASE64_LENGTH =
  Math.ceil(IVM_ARTIFACT_MAX_BYTES / 3) * 4;
const CONTRACT_CODE_BYTES_JSON_MAX_BYTES =
  IVM_ARTIFACT_MAX_BASE64_LENGTH + 1024;
const CONTRACT_MANIFEST_JSON_MAX_BYTES =
  IVM_ARTIFACT_MAX_BASE64_LENGTH + 256 * 1024;
const CONTRACT_CALL_SIMULATION_JSON_MAX_BYTES = 8 * 1024 * 1024;
const VERIFYING_KEY_TRANSACTION_PAYLOAD_MAX_BYTES = 16 * 1024 * 1024;
const VERIFYING_KEY_CLIENT_URL = new URL(
  "./verifyingKeyClient.js",
  import.meta.url,
).href;
const PRIVACY_EXACT12_CAPABILITY_MANIFEST_MAX_BYTES = 256 * 1024;
const FEE_QUOTE_JSON_MAX_BYTES = 64 * 1024;
const FEE_SPONSOR_PROGRAM_JSON_MAX_BYTES = 64 * 1024;
const PIPELINE_RECEIPT_MAX_BYTES = 1024 * 1024;
const PIPELINE_STATUS_JSON_MAX_BYTES = 1024 * 1024;
const SORAFS_REPUTATION_JSON_MAX_BYTES = 4 * 1024 * 1024;
const SORAFS_REPUTATION_EVENT_DEFAULT_LIMIT_V1 = 50;
const SORAFS_HEDGING_BILLING_JSON_MAX_BYTES = 1024 * 1024;
const SORAFS_BILLING_STATEMENT_MAX_BYTES = 22 * 1024 * 1024;
const BOUNDED_JSON_MAX_STREAM_CHUNKS = 64 * 1024;
const JSON_CLONE_MAX_DEPTH = 128;
const JSON_CLONE_MAX_NODES = 100_000;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayBufferGetter = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  "buffer",
).get;
const typedArrayByteOffsetGetter = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  "byteOffset",
).get;
const typedArrayByteLengthGetter = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  "byteLength",
).get;
const typedArrayTagGetter = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  Symbol.toStringTag,
).get;
const typedArraySet = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  "set",
).value;
const Uint8ArrayIntrinsic = Uint8Array;
const sharedArrayBufferByteLengthGetter =
  typeof SharedArrayBuffer === "undefined"
    ? null
    : Object.getOwnPropertyDescriptor(
        SharedArrayBuffer.prototype,
        "byteLength",
      ).get;
const responseBodyGetter =
  typeof Response === "undefined"
    ? null
    : (Object.getOwnPropertyDescriptor(Response.prototype, "body")?.get ?? null);
const responseHeadersGetter =
  typeof Response === "undefined"
    ? null
    : (Object.getOwnPropertyDescriptor(Response.prototype, "headers")?.get ?? null);
const responseStatusGetter =
  typeof Response === "undefined"
    ? null
    : (Object.getOwnPropertyDescriptor(Response.prototype, "status")?.get ?? null);
const responseStatusTextGetter =
  typeof Response === "undefined"
    ? null
    : (Object.getOwnPropertyDescriptor(Response.prototype, "statusText")?.get ??
      null);
const responseUrlGetter =
  typeof Response === "undefined"
    ? null
    : (Object.getOwnPropertyDescriptor(Response.prototype, "url")?.get ?? null);
const responseRedirectedGetter =
  typeof Response === "undefined"
    ? null
    : (Object.getOwnPropertyDescriptor(Response.prototype, "redirected")?.get ??
      null);
const headersGet =
  typeof Headers === "undefined" ? null : Headers.prototype.get;
const readableStreamGetReader =
  typeof ReadableStream === "undefined"
    ? null
    : ReadableStream.prototype.getReader;
const readableStreamCancel =
  typeof ReadableStream === "undefined"
    ? null
    : ReadableStream.prototype.cancel;
const readableStreamLockedGetter =
  typeof ReadableStream === "undefined"
    ? null
    : (Object.getOwnPropertyDescriptor(
        ReadableStream.prototype,
        "locked",
      )?.get ?? null);
const readerRead =
  typeof ReadableStreamDefaultReader === "undefined"
    ? null
    : ReadableStreamDefaultReader.prototype.read;
const readerCancel =
  typeof ReadableStreamDefaultReader === "undefined"
    ? null
    : ReadableStreamDefaultReader.prototype.cancel;
const readerReleaseLock =
  typeof ReadableStreamDefaultReader === "undefined"
    ? null
    : ReadableStreamDefaultReader.prototype.releaseLock;
const abortSignalAbortedGetter =
  typeof AbortSignal === "undefined"
    ? null
    : (Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get ??
      null);
const abortSignalReasonGetter =
  typeof AbortSignal === "undefined"
    ? null
    : (Object.getOwnPropertyDescriptor(AbortSignal.prototype, "reason")?.get ??
      null);
const eventTargetAddEventListener =
  typeof EventTarget === "undefined" ? null : EventTarget.prototype.addEventListener;
const eventTargetRemoveEventListener =
  typeof EventTarget === "undefined"
    ? null
    : EventTarget.prototype.removeEventListener;
const AbortControllerConstructor = globalThis.AbortController;
const abortControllerAbort = AbortControllerConstructor?.prototype?.abort ?? null;
const abortControllerSignalGetter = AbortControllerConstructor
  ? Object.getOwnPropertyDescriptor(
      AbortControllerConstructor.prototype,
      "signal",
    )?.get ?? null
  : null;
const scheduleTimeout = globalThis.setTimeout;
const cancelTimeout = globalThis.clearTimeout;
const BOUNDED_JSON_MAX_READ_TIMEOUT_MS = 30_000;
const HTTP_ERROR_BODY_MAX_BYTES = 64 * 1024;
const DEFAULT_ISO_POLL_INTERVAL_MS = 2_000;
const DEFAULT_ISO_POLL_ATTEMPTS = 12;
// Bounded JSON response limits are part of the client-side resource boundary.
// They apply to bytes emitted by the decoded response stream, not just advertised
// Content-Length values, so compressed or chunked responses cannot bypass them.
const JSON_RESPONSE_MAX_BYTES = 64 * 1024 * 1024;
const ELECTION_TALLY_JSON_RESPONSE_MAX_BYTES = 8 * 1024;
const SUMERAGI_EVIDENCE_COUNT_JSON_RESPONSE_MAX_BYTES = 1024;
// The maximum 1,000-record fixed evidence envelope remains below this ceiling,
// including full-width u64 integers and terminal penalty details.
const SUMERAGI_EVIDENCE_LIST_JSON_RESPONSE_MAX_BYTES = 1024 * 1024;
const MIN_ISO_POLL_INTERVAL_MS = 10;
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const MAX_SAFE_INTEGER_BIGINT = BigInt(MAX_SAFE_INTEGER);
const MAX_UINT64_BIGINT = (1n << 64n) - 1n;

// These optional async surfaces share a sizeable governance-validation graph.
// Keep one literal boundary so ordinary Torii clients avoid its startup cost.
function loadToriiOptionalModule() {
  return import("./toriiOptional.js");
}
const UINT64_MASK = 0xffff_ffff_ffff_ffffn;

const DA_FETCH_ARTIFACT_PREFIX = "artifacts/da/fetch_";
const DA_PROVE_ARTIFACT_PREFIX = "artifacts/da/prove_availability_";
const TX_STATUS_POLL_OPTION_KEYS = new Set([
  "signal",
  "intervalMs",
  "timeoutMs",
  "maxAttempts",
  "onStatus",
]);
const PLAIN_TEXT_PROBE_MAX_BYTES = 4 * 1024;
const METRICS_TEXT_MAX_BYTES = 16 * 1024 * 1024;
const CONNECT_APP_LIST_OPTION_KEYS = new Set(["limit", "cursor", "signal"]);
const GET_TX_STATUS_OPTION_KEYS = new Set(["signal", "scope"]);
const ALIAS_CANONICAL_AUTH_OPTION_KEYS = new Set([CANONICAL_AUTH_FIELD]);
const ALIAS_BY_ACCOUNT_OPTION_KEYS = new Set([
  "dataspace",
  "domain",
  CANONICAL_AUTH_FIELD,
]);

const RETAIL_RECIPIENT_LOOKUP_REQUEST_KEYS = new Set([
  "accountId",
  "account_id",
  "aliasFqn",
  "alias_fqn",
]);
const RETAIL_RECIPIENT_LOOKUP_RESPONSE_KEYS = new Set([
  "resolved",
  "account_id",
  "alias_fqn",
  "fi_id",
  "full_name",
]);
const RETAIL_RECIPIENT_ROUTE_RESPONSE_KEYS = new Set([
  "account_id",
  "alias_fqn",
  "fi_id",
]);
const FEE_SPONSOR_PROGRAM_RESPONSE_KEYS = new Set([
  "id",
  "payout_account",
  "lifecycle",
  "active_revision",
  "staged_revision",
  "scheduled_activation",
]);
const FEE_QUOTE_RESPONSE_KEYS = new Set([
  "intent",
  "observation",
  "components",
  "capacities",
  "decision",
]);
const ISO_NON_TERMINAL_STATUS_VALUES = new Set(["pending", "accepted"]);
const MULTISIG_PROPOSAL_STATUS_VALUES = new Set([
  "COLLECTING_SIGNATURES",
  "FINALIZED",
  "CANCELED",
  "EXPIRED",
]);
function resolveNativeBinding(nativeRuntime) {
  return resolveNativeRuntimeBinding(nativeRuntime);
}

function resolveOptionalNativeBinding(nativeRuntime) {
  return resolveOptionalNativeRuntimeBinding(nativeRuntime);
}

function decodeTransactionReceiptPayload(payload, nativeRuntime) {
  let native;
  try {
    native = resolveNativeBinding(nativeRuntime);
  } catch (cause) {
    rejectError("cannot decode a non-empty Norito transaction receipt: the native decoder is unavailable", { cause });
  }
  if (typeof native.decodeTransactionReceiptJson !== JS_TYPE_FUNCTION) {
    rejectError("cannot decode a non-empty Norito transaction receipt: the native binding does not expose decodeTransactionReceiptJson");
  }
  let json;
  try {
    json = native.decodeTransactionReceiptJson(payload);
  } catch (cause) {
    rejectError("failed to decode the non-empty Norito transaction receipt", {
      cause,
    });
  }
  try {
    return JSON.parse(json);
  } catch (cause) {
    rejectError("native transaction receipt decoder returned invalid JSON", {
      cause,
    });
  }
}

const HEADER_SORA_PDP_COMMITMENT = "sora-pdp-commitment";

const EVIDENCE_KIND = "NativeSumeragiEvidence";
const EVIDENCE_CLASS_VALUES = new Set([
  "proposal", "phase_vote", "timeout_vote", "invalid_proposal", "conflicting_certificates",
]);
const EVIDENCE_RECORD_FIELDS = Object.freeze([
  "kind", "class", "instance", "height", "epoch", "context_id", "authority_generation",
  "offenders", "safety_violation", "native_frame_hash", "recorded_height", "recorded_view",
  "recorded_ms", "consensus_admitted_height", "penalty_status",
]);

const KAIGI_HEALTH_STATUS_VALUES = new Set(["healthy", "degraded", "unavailable"]);
const KAIGI_EVENT_KIND_VALUES = new Set([
  "registration",
  "unregistration",
  "health",
]);
const KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS = 500;
const KAIGI_CALL_SIGNALS_CURSOR_MAX_BYTES = 1024;
const KAIGI_RELAY_SUMMARY_REQUIRED_FIELDS = new Set([
  "relay_id",
  "domain",
  "bandwidth_class",
  "hpke_fingerprint_hex",
]);
const KAIGI_RELAY_SUMMARY_FIELDS = new Set([
  ...KAIGI_RELAY_SUMMARY_REQUIRED_FIELDS,
  "status",
  "reported_at_ms",
]);
const KAIGI_RELAY_DETAIL_REQUIRED_FIELDS = new Set([
  "relay",
  "hpke_public_key_b64",
]);
const KAIGI_RELAY_DETAIL_FIELDS = new Set([
  ...KAIGI_RELAY_DETAIL_REQUIRED_FIELDS,
  "reported_call",
  "reported_by",
  "notes",
  "metrics",
]);
const KAIGI_RELAY_DOMAIN_METRICS_FIELDS = new Set([
  "domain",
  "registrations_total",
  "manifest_updates_total",
  "failovers_total",
  "health_reports_total",
]);
const KAIGI_RELAY_HEALTH_SNAPSHOT_FIELDS = new Set([
  "healthy_total",
  "degraded_total",
  "unavailable_total",
  "reports_total",
  "registrations_total",
  "failovers_total",
  "domains",
]);
const KAIGI_CALL_VIEW_REQUIRED_FIELDS = new Set([
  "call_id",
  "domain",
  "call_name",
  "gas_rate_per_minute",
  "metadata",
  "privacy_mode",
  "room_policy",
  "roster_root_hex",
  "commitment_count",
  "nullifier_count",
  "usage_commitment_count",
  "status",
  "created_at_ms",
  "total_duration_ms",
  "total_billed_gas",
  "segments_recorded",
]);
const KAIGI_CALL_VIEW_FIELDS = new Set([
  ...KAIGI_CALL_VIEW_REQUIRED_FIELDS,
  "host_account_id",
  "billing_account_id",
  "title",
  "description",
  "max_participants",
  "scheduled_start_ms",
  "relay_manifest",
  "participant_count",
  "ended_at_ms",
]);
const KAIGI_CALL_SIGNAL_REQUIRED_FIELDS = new Set([
  "entrypoint_hash",
  "timestamp_ms",
  "call_id",
  "signal_kind",
  "created_at_ms",
  "metadata",
]);
const KAIGI_CALL_SIGNAL_FIELDS = new Set([
  ...KAIGI_CALL_SIGNAL_REQUIRED_FIELDS,
  "authority",
  "host_account_id",
  "participant_account_id",
]);
const KAIGI_SIGNAL_SCHEMA_V1 = "iroha-demo-kaigi-chain-signal/v1";

function ownDataMethod(target, name) {
  if (target === null || (typeof target !== JS_TYPE_OBJECT && typeof target !== JS_TYPE_FUNCTION)) {
    return null;
  }
  const descriptor = Object.getOwnPropertyDescriptor(target, name);
  return descriptor && "value" in descriptor && typeof descriptor.value === JS_TYPE_FUNCTION
    ? descriptor.value
    : null;
}

function callIntrinsicOrOwnMethod(target, intrinsic, name, ...args) {
  const isStreamIntrinsic =
    intrinsic === readableStreamGetReader || intrinsic === readableStreamCancel;
  let branded = true;
  if (isStreamIntrinsic && readableStreamLockedGetter !== null) {
    try {
      readableStreamLockedGetter.call(target);
    } catch {
      branded = false;
    }
  }
  if (typeof intrinsic === JS_TYPE_FUNCTION && branded) {
    return Reflect.apply(intrinsic, target, args);
  }
  const own = ownDataMethod(target, name);
  if (own === null) {
    rejectType(`${name} is unavailable`);
  }
  return Reflect.apply(own, target, args);
}

function responseBodyWithoutUserGetter(response) {
  if (responseBodyGetter !== null) {
    try {
      return responseBodyGetter.call(response);
    } catch {
      // Custom fetch responses may expose an own data property instead.
    }
  }
  const descriptor = Object.getOwnPropertyDescriptor(response, "body");
  return descriptor && "value" in descriptor ? descriptor.value : null;
}

function responseHeadersWithoutUserGetter(response) {
  if (responseHeadersGetter !== null) {
    try {
      return responseHeadersGetter.call(response);
    } catch {
      // Custom fetch responses may expose an own data property instead.
    }
  }
  const descriptor = Object.getOwnPropertyDescriptor(response, "headers");
  return descriptor && "value" in descriptor ? descriptor.value : null;
}

function headerValueWithoutUserGetter(headers, name) {
  if (!headers) return null;
  if (headersGet !== null) {
    try {
      return Reflect.apply(headersGet, headers, [name]);
    } catch {
      // Custom header bags may expose an own data method instead.
    }
  }
  const get = ownDataMethod(headers, "get");
  if (get === null) return null;
  return Reflect.apply(get, headers, [name]);
}

function responseStatusWithoutUserGetter(response) {
  let status;
  if (responseStatusGetter !== null) {
    try {
      status = responseStatusGetter.call(response);
    } catch {
      // Custom fetch responses may expose an own data property instead.
    }
  }
  if (status === undefined) {
    const descriptor = Object.getOwnPropertyDescriptor(response, "status");
    if (!descriptor || !("value" in descriptor)) {
      rejectType("Torii response status must be an own data property");
    }
    status = descriptor.value;
  }
  if (!Number.isInteger(status) || status < 0 || status > 999) {
    rejectType("Torii response status must be an integer HTTP status");
  }
  return status;
}

function responseStatusTextWithoutUserGetter(response) {
  if (responseStatusTextGetter !== null) {
    try {
      return responseStatusTextGetter.call(response);
    } catch {
      // Custom fetch responses may expose an own data property instead.
    }
  }
  const descriptor = Object.getOwnPropertyDescriptor(response, "statusText");
  return descriptor && "value" in descriptor && typeof descriptor.value === JS_TYPE_STRING
    ? descriptor.value
    : null;
}

function responseUrlWithoutUserGetter(response) {
  let url;
  if (responseUrlGetter !== null) {
    try {
      url = responseUrlGetter.call(response);
    } catch {
      // Custom fetch responses may expose an own data property instead.
    }
  }
  if (url === undefined) {
    const descriptor = Object.getOwnPropertyDescriptor(response, "url");
    if (!descriptor || !("value" in descriptor)) {
      rejectType("Torii response URL must be an own data property");
    }
    url = descriptor.value;
  }
  if (typeof url !== JS_TYPE_STRING || url.length === 0) {
    rejectType("Torii response URL must be a non-empty string");
  }
  return url;
}

function responseRedirectedWithoutUserGetter(response) {
  let redirected;
  if (responseRedirectedGetter !== null) {
    try {
      redirected = responseRedirectedGetter.call(response);
    } catch {
      // Custom fetch responses may expose an own data property instead.
    }
  }
  if (redirected === undefined) {
    const descriptor = Object.getOwnPropertyDescriptor(response, "redirected");
    if (!descriptor || !("value" in descriptor)) {
      rejectType("Torii response redirected flag must be an own data property");
    }
    redirected = descriptor.value;
  }
  if (typeof redirected !== "boolean") {
    rejectType("Torii response redirected flag must be a boolean");
  }
  return redirected;
}



function ignoreCancellationResult(result) {
  if (result && typeof result.then === JS_TYPE_FUNCTION) {
    Promise.resolve(result).catch(() => {});
  }
}

function cancelReadableBodyBestEffort(body, reason) {
  if (!body) return;
  try {
    ignoreCancellationResult(
      callIntrinsicOrOwnMethod(body, readableStreamCancel, "cancel", reason),
    );
  } catch {
    // Cancellation is cleanup and must not replace the authoritative error.
  }
}

function cancelResponseBodyBestEffort(response, reason) {
  cancelReadableBodyBestEffort(responseBodyWithoutUserGetter(response), reason);
}
function discardResponseBody(response, reason, signal) {
  cancelResponseBodyBestEffort(response, reason);
  throwIfAborted(signal);
  return null;
}
function cancelReaderBestEffort(reader, reason, genuineReader = false) {
  try {
    ignoreCancellationResult(
      callIntrinsicOrOwnMethod(
        reader,
        genuineReader ? readerCancel : null,
        "cancel",
        reason,
      ),
    );
  } catch {
    // Cancellation is cleanup and must not replace the authoritative error.
  }
}

function hasReadableStreamBrand(value) {
  if (readableStreamLockedGetter === null) return false;
  try {
    readableStreamLockedGetter.call(value);
    return true;
  } catch {
    return false;
  }
}

function hasAbortSignalBrand(value) {
  if (abortSignalAbortedGetter === null) return false;
  try {
    abortSignalAbortedGetter.call(value);
    return true;
  } catch {
    return false;
  }
}

function signalIsAborted(signal) {
  if (!signal) return false;
  if (hasAbortSignalBrand(signal)) {
    return abortSignalAbortedGetter.call(signal);
  }
  const descriptor = Object.getOwnPropertyDescriptor(signal, "aborted");
  if (!descriptor || !("value" in descriptor) || typeof descriptor.value !== "boolean") {
    rejectType("signal.aborted must be an own boolean data property");
  }
  return descriptor.value;
}

function signalAbortReason(signal) {
  if (!signal) return undefined;
  if (hasAbortSignalBrand(signal)) {
    return abortSignalReasonGetter === null
      ? undefined
      : abortSignalReasonGetter.call(signal);
  }
  const descriptor = Object.getOwnPropertyDescriptor(signal, "reason");
  return descriptor && "value" in descriptor ? descriptor.value : undefined;
}

function addSignalAbortListener(signal, listener) {
  if (!signal) return;
  if (hasAbortSignalBrand(signal) && eventTargetAddEventListener !== null) {
    Reflect.apply(eventTargetAddEventListener, signal, ["abort", listener, { once: true }]);
    return;
  }
  const add = ownDataMethod(signal, "addEventListener");
  if (add === null) rejectType("signal.addEventListener is unavailable");
  Reflect.apply(add, signal, ["abort", listener, { once: true }]);
}

function removeSignalAbortListener(signal, listener) {
  if (!signal) return;
  try {
    if (hasAbortSignalBrand(signal) && eventTargetRemoveEventListener !== null) {
      Reflect.apply(eventTargetRemoveEventListener, signal, ["abort", listener]);
      return;
    }
    const remove = ownDataMethod(signal, "removeEventListener");
    if (remove !== null) Reflect.apply(remove, signal, ["abort", listener]);
  } catch {
    // Listener removal is cleanup and must not replace the authoritative error.
  }
}

const RESPONSE_CALLER_SIGNALS = new WeakMap();

function rememberResponseCallerSignal(response, signal) {
  if (signal && response !== null && (typeof response === JS_TYPE_OBJECT || typeof response === JS_TYPE_FUNCTION)) {
    RESPONSE_CALLER_SIGNALS.set(response, signal);
  }
}

function responseCallerSignal(response) {
  return response !== null && (typeof response === JS_TYPE_OBJECT || typeof response === JS_TYPE_FUNCTION)
    ? RESPONSE_CALLER_SIGNALS.get(response)
    : undefined;
}

function bodyReadAbortError(signal, context) {
  const reason = signalAbortReason(signal);
  if (reason instanceof Error) return reason;
  const error = new Error(`${context} body read was aborted`);
  error.name = "AbortError";
  return error;
}

function copyArrayBufferBytes(buffer, byteOffset, byteLength) {
  const source = new Uint8ArrayIntrinsic(buffer, byteOffset, byteLength);
  const copy = new Uint8ArrayIntrinsic(byteLength);
  Reflect.apply(typedArraySet, copy, [source]);
  return copy;
}

const KAIGI_CALL_EVENT_KIND_VALUES = new Set(["roster_updated", "ended"]);
const SORAFS_REPLICATION_STATUS_VALUES = new Set(["pending", "completed", "cancelled", "expired"]);
const SORAFS_PIN_STATUS_VALUES = new Set(["pending", "approved", "retired"]);
const SORAFS_PIN_LIST_MAX_ITEMS = 256;
const SORAFS_PIN_LIST_MIN_PAGE_BYTES = 1024;
const SORAFS_PIN_LIST_MAX_PAGE_BYTES = 256 * 1024;
const UAID_MANIFEST_STATUS_VALUES = new Set(["Pending", "Active", "Expired", "Revoked"]);
const UAID_MANIFEST_ROLE_VALUES = new Set(["Initiator", "Participant"]);
const UAID_MANIFEST_ALLOWANCE_WINDOW_VALUES = new Set([
  "PerSlot",
  "PerMinute",
  "PerDay",
]);
function encodeCanonicalVersionedSignedTransactionV1(payload, nativeRuntime) {
  const native = resolveNativeBinding(nativeRuntime);
  if (
    !native ||
    typeof native.encodeSignedTransactionVersioned !== JS_TYPE_FUNCTION
  ) {
    rejectError("Canonical VersionedSignedTransaction V1 validation requires native encodeSignedTransactionVersioned.");
  }
  const input = Buffer.from(payload);
  const encoded = Buffer.from(native.encodeSignedTransactionVersioned(input));
  if (encoded.length === 0 || encoded[0] !== 1) {
    rejectError("Native signed transaction encoder did not return VersionedSignedTransaction V1 bytes.");
  }
  if (!encoded.equals(input)) {
    rejectError("Signed transaction input was not the exact canonical VersionedSignedTransaction V1 encoding.");
  }
  return encoded;
}

async function encodeTransactionPayloadBatch(payloads, nativeRuntime) {
  const native = resolveOptionalNativeBinding(nativeRuntime);
  if (
    native &&
    typeof native.encodeTransactionPayloadBatch === JS_TYPE_FUNCTION
  ) {
    const encoded = Buffer.from(
      native.encodeTransactionPayloadBatch(
        payloads.map((payload) => Buffer.from(payload)),
      ),
    );
    if (encoded.length === 0) {
      rejectError("Native transaction batch encoder returned an empty payload.");
    }
    return encoded;
  }
  const { noritoEncodeTransactionPayloadBatch } = await loadToriiOptionalModule();
  return noritoEncodeTransactionPayloadBatch(payloads);
}

function isSecureProtocol(protocol) {
  return protocol === "https:" || protocol === "wss:";
}

function isAbsoluteUrl(candidate) {
  if (!candidate) {
    return false;
  }
  if (candidate instanceof URL) {
    return true;
  }
  if (typeof candidate !== JS_TYPE_STRING) {
    return false;
  }
  return /^[a-z][a-z0-9+.-]*:\/\//iu.test(candidate);
}

/**
 * Resolve a Torii route below the configured base URL, keeping any base path
 * prefix (`https://gateway.example/torii` + `/v1/domains` →
 * `https://gateway.example/torii/v1/domains`). The base URL's query and
 * fragment are not part of the prefix.
 */
function resolveBaseRelativeUrl(baseUrl, path) {
  const base = new URL(baseUrl);
  base.search = "";
  base.hash = "";
  if (!base.pathname.endsWith("/")) base.pathname = `${base.pathname}/`;
  const relative = String(path).replace(/^\/(?!\/)/u, "");
  return new URL(relative, base);
}

const SNS_CONTROLLER_TYPES = new Set(["Account", "Multisig", "ResolverTemplate", "ExternalLink"]);
const SNS_NAME_STATUS_VALUES = new Set(["Active", "GracePeriod", "Redemption", "Frozen", "Tombstoned"]);
const SNS_SUFFIX_STATUS_VALUES = new Set(["Active", "Paused", "Revoked"]);
const SNS_AUCTION_KIND_VALUES = new Set(["VickreyCommitReveal", "DutchReopen"]);
const ITERABLE_LIST_OPTION_KEYS = new Set([
  "limit",
  "offset",
  "filter",
  "sort",
  "countMode",
  "count_mode",
  "signal",
  CANONICAL_AUTH_FIELD,
]);
const ITERABLE_OPTION_KEYS = new Set([
  "limit",
  "offset",
  "filter",
  "sort",
  "signal",
  "fetchSize",
  "fetch_size",
  "countMode",
  "count_mode",
  "queryName",
  "query_name",
  "select",
  "pageSize",
  "maxItems",
  "contains",
  "hashPrefix",
  "hash_prefix",
  "namespace",
  "controllerId",
  "receiverId",
  "depositAccountId",
  "assetId",
  "authority",
  "resultOk",
  "sinceTimestampMs",
  "untilTimestampMs",
  "certificateExpiresBeforeMs",
  "certificateExpiresAfterMs",
  "policyExpiresBeforeMs",
  "policyExpiresAfterMs",
  "refreshBeforeMs",
  "refreshAfterMs",
  "verdictIdHex",
  "attestationNonceHex",
  "certificateIdHex",
  "requireVerdict",
  "onlyMissingVerdict",
  "platformPolicy",
  "includeExpired",
  CANONICAL_AUTH_FIELD,
]);
const SORAFS_ALIAS_ITERATOR_OPTION_KEYS = new Set([
  "namespace",
  "manifestDigestHex",
  "limit",
  "offset",
  "pageSize",
  "maxItems",
  "signal",
  CANONICAL_AUTH_FIELD,
]);
const SORAFS_PIN_ITERATOR_OPTION_KEYS = new Set([
  "status",
  "limit",
  "maxBytes",
  "afterDigestHex",
  EXPECTED_FINALIZED_HEIGHT_FIELD,
  EXPECTED_FINALIZED_HASH_FIELD,
  "pageSize",
  "maxItems",
  "signal",
]);
const SORAFS_REPLICATION_ITERATOR_OPTION_KEYS = new Set([
  "status",
  "manifestDigestHex",
  "limit",
  "offset",
  "pageSize",
  "maxItems",
  "signal",
  CANONICAL_AUTH_FIELD,
]);
const SORAFS_REPUTATION_CACHE_OPTION_KEYS = new Set([
  "ifNoneMatch",
  "headers",
  CANONICAL_AUTH_FIELD,
]);
const SORAFS_REPUTATION_EVENT_OPTION_KEYS = new Set([
  "since",
  "limit",
  "ifNoneMatch",
  "headers",
  CANONICAL_AUTH_FIELD,
]);
const SORAFS_REPUTATION_STREAM_OPTION_KEYS = new Set([
  "since",
  "limit",
  "headers",
  CANONICAL_AUTH_FIELD,
]);
const SORAFS_HEDGING_BILLING_AUTH_OPTION_KEYS = new Set([CANONICAL_AUTH_FIELD]);
const SORAFS_BILLING_STATEMENT_LIST_OPTION_KEYS = new Set([
  "expectedCheckpointFingerprintHex",
  "afterStatementIdHex",
  "limit",
  CANONICAL_AUTH_FIELD,
]);
const SORAFS_HEDGING_PROJECTION_OPTION_KEYS = new Set([
  "expectedCheckpointFingerprintHex",
  "afterHex",
  "limit",
  CANONICAL_AUTH_FIELD,
]);
const SORAFS_ORDERBOOK_READ_OPTION_KEYS = new Set([
  "limit",
  EXPECTED_FINALIZED_HEIGHT_FIELD,
  EXPECTED_FINALIZED_HASH_FIELD,
  "afterIdHex",
  "headers",
]);
const SORAFS_ORDERBOOK_EVENT_OPTION_KEYS = new Set([
  "limit",
  EXPECTED_FINALIZED_HEIGHT_FIELD,
  EXPECTED_FINALIZED_HASH_FIELD,
  "afterSequence",
  "afterBlockHeight",
  "afterBlockHashHex",
  "afterEventIndex",
  "ifNoneMatch",
  "headers",
]);
const SORAFS_ORDERBOOK_STREAM_OPTION_KEYS = new Set([
  "limit",
  EXPECTED_FINALIZED_HEIGHT_FIELD,
  EXPECTED_FINALIZED_HASH_FIELD,
  "afterSequence",
  "afterBlockHeight",
  "afterBlockHashHex",
  "afterEventIndex",
]);
const SORAFS_ORDERBOOK_WEBSOCKET_OPTION_KEYS = new Set([
  "limit",
  EXPECTED_FINALIZED_HEIGHT_FIELD,
  EXPECTED_FINALIZED_HASH_FIELD,
  "afterSequence",
  "afterBlockHeight",
  "afterBlockHashHex",
  "afterEventIndex",
  "endpointPath",
]);
const SORAFS_ORDERBOOK_WEBSOCKET_DIAL_OPTION_KEYS = new Set([
  "limit",
  EXPECTED_FINALIZED_HEIGHT_FIELD,
  EXPECTED_FINALIZED_HASH_FIELD,
  "afterSequence",
  "afterBlockHeight",
  "afterBlockHashHex",
  "afterEventIndex",
  "endpointPath",
  "protocols",
  "websocketOptions",
  "WebSocketImpl",
]);
const SORAFS_ORDERBOOK_WEBSOCKET_STREAM_OPTION_KEYS = new Set([
  "limit",
  EXPECTED_FINALIZED_HEIGHT_FIELD,
  EXPECTED_FINALIZED_HASH_FIELD,
  "afterSequence",
  "afterBlockHeight",
  "afterBlockHashHex",
  "afterEventIndex",
  "endpointPath",
  "protocols",
  "websocketOptions",
  "WebSocketImpl",
  "signal",
  "closeOnReturn",
]);
const SORAFS_XOR_QUANTITY_MAX_TEXT_LENGTH = 155;
const ITERABLE_QUERY_OPTION_KEYS = new Set([
  "limit",
  "offset",
  "filter",
  "sort",
  "fetchSize",
  "countMode",
  "queryName",
  "select",
  "signal",
  CANONICAL_AUTH_FIELD,
]);
const UPLOAD_ATTACHMENT_OPTION_KEYS = new Set(["contentType", "content_type", "signal", CANONICAL_AUTH_FIELD]);
export class TransactionStatusError extends Error {
  constructor(hashHex, status, payload) {
    const statusLabel = status == null ? "unknown" : String(status);
    super(`Transaction ${hashHex} reported failure status ${statusLabel}`);
    this.name = "TransactionStatusError";
    this.hashHex = hashHex;
    this.status = status;
    this.payload = payload;
  }
}

export class TransactionTimeoutError extends Error {
  constructor(message, hashHex, attempts, payload) {
    super(message);
    this.name = "TransactionTimeoutError";
    this.hashHex = hashHex;
    this.attempts = attempts;
    this.payload = payload;
  }
}

export class TransactionBatchAdmissionAmbiguousError extends Error {
  constructor(message, expectedCount, acceptedCount = null, cause) {
    super(message);
    this.name = "TransactionBatchAdmissionAmbiguousError";
    this.expectedCount = expectedCount;
    this.acceptedCount = acceptedCount;
    this.ambiguous = true;
    this.retryable = false;
    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}

export class IsoMessageTimeoutError extends Error {
  constructor(messageId, attempts, lastStatus) {
    super(`ISO message ${messageId} did not reach a terminal status after ${attempts} attempts`);
    this.name = "IsoMessageTimeoutError";
    this.messageId = messageId;
    this.attempts = attempts;
    this.lastStatus = lastStatus ?? null;
  }
}

export { ToriiDataModelMismatchError };

/**
 * Extract the pipeline status kind from a Torii pipeline payload.
 * @param {unknown} payload
 * @returns {string | null}
 */
export function extractPipelineStatusKind(payload) {
  if (!payload || typeof payload !== JS_TYPE_OBJECT) {
    return null;
  }
  const status = payload.status;
  if (!status || typeof status !== JS_TYPE_OBJECT || Array.isArray(status)) {
    return null;
  }
  return typeof status.kind === JS_TYPE_STRING ? status.kind : null;
}

export function decodePdpCommitmentHeader(headers) {
  const raw = readHeaderValue(headers, HEADER_SORA_PDP_COMMITMENT);
  if (raw == null) {
    return null;
  }
  const value = String(raw).trim();
  if (!value) {
    rejectError("Failed to decode Sora-PDP-Commitment header: payload is empty");
  }
  try {
    return strictDecodeBase64(value);
  } catch (err) {
    const message = err && typeof err.message === JS_TYPE_STRING ? err.message : String(err);
    rejectError(`Failed to decode Sora-PDP-Commitment header: ${message}`);
  }
}

/**
 * Torii HTTP client for typed queries, transaction submission, status
 * inspection, event streams, attachments, and prover reports.
 *
 * Request and response validation follows the canonical Norito-backed data
 * model exposed by this package.
 */

/**
 * @typedef {Object} BlockListOptions
 * @property {string} [cursor]
 * @property {number} [limit]
 * @property {AbortSignal} [signal]
 *
 * @typedef {Object} EventStreamOptions
 * @property {string | Record<string, unknown>} [filter]
 * @property {AbortSignal} [signal]
 *
 * @typedef {Object} IterableListOptions
 * @property {number} [limit]
 * @property {number} [offset]
 * @property {string | Record<string, unknown>} [filter]
 * @property {string | ReadonlyArray<{key: string, order?: "asc" | "desc"}>} [sort]
 * @property {"bounded" | "exact"} [countMode]
 * @property {"bounded" | "exact"} [count_mode]
 * @property {AbortSignal} [signal]
 * @property {CanonicalRequestAuth | null} [canonicalAuth]
 * @property {string} [assetId]
 * @property {number} [certificateExpiresBeforeMs]
 * @property {number} [certificateExpiresAfterMs]
 * @property {number} [policyExpiresBeforeMs]
 * @property {number} [policyExpiresAfterMs]
 * @property {string} [verdictIdHex]
 * @property {boolean} [requireVerdict]
 * @property {boolean} [onlyMissingVerdict]
 *
 * @typedef {IterableListOptions & {
 *   fetchSize?: number;
 *   fetch_size?: number;
 *   queryName?: string;
 *   query_name?: string;
 *   select?: ReadonlyArray<string | Record<string, unknown>>;
 * }} IterableQueryOptions
 *
 * @typedef {IterableListOptions & {
 *   pageSize?: number;
 *   maxItems?: number;
 * }} PaginationIteratorOptions
 *
 * @typedef {IterableListOptions & { assetId?: string; }} AccountAssetListOptions
 * @typedef {IterableListOptions & { assetId?: string; }} AccountTransactionListOptions
 * @typedef {IterableListOptions & { assetId?: string; }} AssetHolderListOptions
 *
 * @typedef {PaginationIteratorOptions & { assetId?: string; }} AccountAssetIteratorOptions
 * @typedef {PaginationIteratorOptions & { assetId?: string; }} AccountTransactionIteratorOptions
 * @typedef {PaginationIteratorOptions & { assetId?: string; }} AssetHolderIteratorOptions
 *
 * Immutable local context used to validate server-prepared drafts before
 * exposing them to a signer.
 */
export class LocalSigningContext {
  #networkId; #chainDiscriminant;

  /**
   * @param {import("./networkId.js").NetworkId} networkId Exact NetworkId expected in every draft.
   * @param {number} chainDiscriminant Exact I105 deployment discriminant.
   */
  constructor(networkId, chainDiscriminant) {
    networkIdBytes(networkId, "LocalSigningContext.networkId");
    if (!Number.isInteger(chainDiscriminant)
      || chainDiscriminant < 0 || chainDiscriminant > 0xffff) {
      rejectType("LocalSigningContext.chainDiscriminant must fit in u16");
    }
    this.#networkId = networkId; this.#chainDiscriminant = chainDiscriminant;
    Object.freeze(this);
  }

  /** @returns {import("./networkId.js").NetworkId} */
  get networkId() {
    return this.#networkId;
  }

  /** @returns {number} */ get chainDiscriminant() { return this.#chainDiscriminant; }
}

export { OperatorSigningContext };
/**
 * @template [T=unknown]
 * @typedef {Object} SseEvent
 * @property {string | null} event
 * @property {T | string} data
 * @property {string | null} id
 * @property {number | null | undefined} [retry]
 * @property {string | null} raw
 */
export class ToriiClient {
  #allowInsecure;
  #baseHost;
  #baseProtocol;
  #canonicalRequestAuth;
  #config;
  #dataModelState = {
    dataModelValidation: { status: "unknown", actual: null },
    dataModelValidationPromise: null,
  };
  #statusState = createStatusSnapshotState();
  #collections;

  /**
   * @param {string} baseUrl Base Torii URL (e.g. http://localhost:8080).
   * @param {object} [options]
   * @param {typeof fetch} [options.fetchImpl] Custom fetch implementation. It must honor
   * `redirect: "error"` and must not retry requests carrying one-shot bodies or canonical auth.
   * @param {Record<string, unknown>} [options.config] Optional iroha_config payload.
   * @param {number} [options.timeoutMs]
   * @param {number} [options.maxRetries]
   * @param {number} [options.backoffInitialMs]
   * @param {number} [options.backoffMultiplier]
   * @param {number} [options.maxBackoffMs]
   * @param {ReadonlyArray<number>} [options.retryStatuses]
   * @param {ReadonlyArray<string>} [options.retryMethods]
   * @param {Record<string, string>} [options.defaultHeaders]
   * @param {string} [options.authToken]
   * @param {string} [options.apiToken]
   * @param {LocalSigningContext} [options.localSigningContext] Immutable context required by local-signing APIs.
   * @param {OperatorSigningContext} [options.operatorSigningContext] Immutable exact-network signer required by operator-only APIs.
   * @param {CanonicalRequestAuth} [options.canonicalRequestAuth] Default exact-network signer for authenticated calls, including expensive query POSTs and optional-auth dataspace reads.
 */
  constructor(baseUrl, options = {}) {
    if (!baseUrl) {
      rejectError("baseUrl is required");
    }
    const opts =
      options === undefined || options === null
        ? {}
        : requirePlainObjectOption(options, "ToriiClient options");
    for (const field of ["chain", "chainId", "chain_id", "networkId"]) {
      if (Object.prototype.hasOwnProperty.call(opts, field)) {
        throw createValidationError(
          ValidationErrorCode.INVALID_OBJECT,
          `ToriiClient options.${field} is not supported; use a LocalSigningContext`,
          `ToriiClient.options.${field}`,
        );
      }
    }
    for (const field of [
      "sorafsAliasPolicy",
      "onSorafsAliasWarning",
      "__nativeBinding",
      "sorafsGatewayFetch",
      "generateDaProofSummary",
    ]) {
      if (Object.prototype.hasOwnProperty.call(opts, field)) {
        throw createValidationError(
          ValidationErrorCode.INVALID_OBJECT,
          `ToriiClient options.${field} is not a public option`,
          `ToriiClient.options.${field}`,
        );
      }
    }
    const localSigningContext = opts.localSigningContext;
    if (
      localSigningContext !== undefined &&
      !(localSigningContext instanceof LocalSigningContext)
    ) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "ToriiClient options.localSigningContext must be a LocalSigningContext",
        "ToriiClient.options.localSigningContext",
      );
    }
    Object.defineProperty(this, "_localSigningContext", {
      value:
        localSigningContext === undefined ? null : localSigningContext,
      writable: false,
      configurable: false,
      enumerable: false,
    });
    installOperatorSigningContext(this, opts.operatorSigningContext);
    this.#canonicalRequestAuth = ToriiClient._normalizeCanonicalAuth(
      opts.canonicalRequestAuth,
      "ToriiClient options.canonicalRequestAuth",
    );
    const normalizedBaseUrl = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
    // Never invoke fetch as a method of the client: WebIDL fetch rejects a
    // foreign `this` ("Illegal invocation") in browsers and edge runtimes.
    const fetchImpl = opts.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    if (typeof fetchImpl !== JS_TYPE_FUNCTION) {
      rejectError("fetch implementation is required");
    }
    Object.defineProperties(this, { _baseUrl: { value: normalizedBaseUrl }, _fetch: { value: fetchImpl } });
    registerPrivacyExact12CapabilityManifestTransportV1(
      this,
      (requestOptions) => this.#fetchPrivacyExact12CapabilityManifestV1(requestOptions),
    );
    if (
      opts[TORII_TEST_NATIVE_BINDING] !== undefined &&
      (opts[TORII_TEST_NATIVE_BINDING] === null ||
        typeof opts[TORII_TEST_NATIVE_BINDING] !== JS_TYPE_OBJECT)
    ) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "ToriiClient internal native binding must be an object when provided",
        "ToriiClient.testNativeBinding",
      );
    }
    const injectedNativeBinding = opts[TORII_TEST_NATIVE_BINDING];
    Object.defineProperty(this, "_nativeRuntime", {
      value:
        injectedNativeBinding === undefined
          ? defaultNativeRuntime
          : createNativeRuntime(injectedNativeBinding),
      writable: false,
      configurable: false,
      enumerable: false,
    });
    const dataAvailabilityApi = _createDataAvailabilityApi(
      this._nativeRuntime,
    );
    const sorafsGatewayApi = _createSorafsGatewayApi(this._nativeRuntime);
    const testHooks = opts[TORII_TEST_HOOKS] ?? {};
    if (testHooks === null || typeof testHooks !== JS_TYPE_OBJECT || Array.isArray(testHooks)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "ToriiClient internal test hooks must be an object",
        "ToriiClient.testHooks",
      );
    }
    if (
      testHooks.sorafsGatewayFetch !== undefined &&
      typeof testHooks.sorafsGatewayFetch !== JS_TYPE_FUNCTION
    ) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "ToriiClient internal sorafsGatewayFetch hook must be a function",
        "ToriiClient.testHooks.sorafsGatewayFetch",
      );
    }
    if (
      testHooks.generateDaProofSummary !== undefined &&
      typeof testHooks.generateDaProofSummary !== JS_TYPE_FUNCTION
    ) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "ToriiClient internal generateDaProofSummary hook must be a function",
        "ToriiClient.testHooks.generateDaProofSummary",
      );
    }
    Object.defineProperties(this, {
      _sorafsGatewayFetch: {
        value:
          testHooks.sorafsGatewayFetch ??
          sorafsGatewayApi.sorafsGatewayFetch,
        writable: false,
        configurable: false,
        enumerable: false,
      },
      _generateDaProofSummary: {
        value:
          testHooks.generateDaProofSummary ??
          dataAvailabilityApi.generateDaProofSummary,
        writable: false,
        configurable: false,
        enumerable: false,
      },
      _deriveDaChunkerHandle: {
        value: dataAvailabilityApi.deriveDaChunkerHandle,
        writable: false,
        configurable: false,
        enumerable: false,
      },
    });
    const allowInsecure =
      opts.allowInsecure ??
      (opts.config &&
        typeof opts.config === JS_TYPE_OBJECT &&
        opts.config.allowInsecure) ??
      false;
    this.#allowInsecure = requireExactBoolean(
      allowInsecure,
      "ToriiClient options.allowInsecure",
    );
    const overrides = { ...opts };
    delete overrides.fetchImpl;
    delete overrides.config;
    delete overrides.allowInsecure;
    delete overrides[TORII_TEST_HOOKS];
    delete overrides[TORII_TEST_NATIVE_BINDING];
    delete overrides.localSigningContext;
    delete overrides.operatorSigningContext;
    delete overrides.canonicalRequestAuth;
    this.#config = resolveToriiClientConfig({
      config: opts.config,
      overrides,
    });
    const parsedBase = new URL(this._baseUrl.endsWith("/") ? this._baseUrl : `${this._baseUrl}/`);
    this.#baseHost = parsedBase.host;
    this.#baseProtocol = parsedBase.protocol.toLowerCase();
    const hasCredentials =
      Boolean(this.#config.authToken || this.#config.apiToken) ||
      headersContainCredentials(this.#config.defaultHeaders);
    if (hasCredentials && !this.#allowInsecure && !isSecureProtocol(this.#baseProtocol)) {
      rejectError("ToriiClient: auth/api tokens require an https base URL; pass allowInsecure: true for local/dev use only.");
    }
    this.#collections = createToriiCollections((path, query, requestOptions) =>
      this.#queryCollection(path, query, requestOptions),
      {
        accountPermission: (row) => normalizeAccountPermissionItem(row, "account permission row"),
        uaidManifest: (row, uaid) => normalizeUaidManifestRecord(row, uaid, "uaid manifest row"),
        contractActivity: (row) => normalizeContractActivityListItem(row, "contract activity row"),
        contractEvents: (row) => normalizeContractEventListItem(row, "contract event row"),
        explorerRwas: (row) => {
          normalizeExplorerRwaRecord(row, "explorer rwa row");
          return row;
        },

      },
    );
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
    return this.#collections.accountPermissions(normalizeAccountPathLiteral(accountId, "accountId"));
  }

  /** Space Directory manifest rows for one UAID. */
  uaidManifests(uaid) {
    return this.#collections.uaidManifests(normalizeUaidLiteral(uaid, "uaidManifests.uaid"));
  }

  /** Repo agreements (`POST /v1/repo/agreements/query`). */
  get repoAgreements() {
    return this.#collections.repoAgreements;
  }

  /**
   * Committed transactions, newest first (`POST /v1/transactions/query`).
   * A history collection: `sort`, `includeTotal` and `aggregate` are rejected.
   */
  get transactions() {
    return this.#collections.transactions;
  }

  /**
   * Asset balances of one account (`POST /v1/accounts/{account_id}/assets/query`).
   * @param {string} accountId canonical I105 account id or account alias
   */
  accountAssets(accountId) {
    return this.#collections.accountAssets(accountId);
  }

  /**
   * Holders of one asset definition (`POST /v1/assets/{definition_id}/holders/query`).
   * @param {string} assetDefinitionId asset definition id or alias
   */
  assetHolders(assetDefinitionId) {
    return this.#collections.assetHolders(assetDefinitionId);
  }

  /**
   * Transactions of one account, newest first
   * (`POST /v1/accounts/{account_id}/transactions/query`). A history
   * collection: `sort`, `includeTotal` and `aggregate` are rejected.
   * @param {string} accountId canonical I105 account id or account alias
   */
  accountTransactions(accountId) {
    return this.#collections.accountTransactions(accountId);
  }

  /**
   * Execute one collection query. The request is signed with the per-call or
   * configured canonical account credentials when present; collection routes
   * never require them (a signature only widens dataspace visibility).
   */
  async #queryCollection(path, query, options) {
    const context = `${path} query options`;
    const record =
      options === undefined || options === null
        ? {}
        : requirePlainObjectOption(options, context);
    assertSupportedOptionKeys(record, COLLECTION_QUERY_OPTION_KEYS, context);
    const { signal } = normalizeSignalOption(record, `${path} query`);
    const canonicalAuth =
      record.canonicalAuth === undefined
        ? this.#canonicalRequestAuth
        : ToriiClient.#normalizeCanonicalAuth(record.canonicalAuth);
    const target = `${path}/query`;
    const response = await this.#request("POST", target, {
      headers: JSON_REQUEST_HEADERS,
      body: stringifyRequestJson(query.toJSON(), `${target} body`),
      signal,
      canonicalAuth: canonicalAuth ?? undefined,
    });
    await this.#expectStatus(response, [200], { signal });
    const { bytes } = await this.#readBoundedResponseBytes(
      response,
      JSON_RESPONSE_MAX_BYTES,
      `${target} response`,
      { signal },
    );
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (error) {
      rejectType(`${target} response must be valid UTF-8`, { cause: error });
    }
    return decodePageText(text, `${target} response`);
  }

  /** Discover exact network identity and the explicit V1 account-signing default without credentials. */
  async getAccountCapabilities(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(options, "getAccountCapabilities");
    assertSupportedOptionKeys(rest, new Set([]), "getAccountCapabilities options");
    const response = await this._request("GET", "/v1/accounts/capabilities", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      redirect: "error",
      disableRetries: true,
      publicRequest: true,
    });
    return readAccountCapabilitiesResponseV1(response, { signal });
  }

  /**
   * Get explorer detail for a single RWA (`GET /v1/explorer/rwas/{rwaId}`).
   * @param {string} rwaId
   * @param {{ signal?: AbortSignalLike }} [options]
   * @returns {Promise<object>}
   */
  async getExplorerRwaDetail(rwaId, options = {}) {
    const normalizedId = normalizeRwaId(rwaId, "rwaId");
    const { signal } = ToriiClient._normalizeOptionsWithSignal(options, "getExplorerRwaDetail");
    const response = await this._request(
      "GET",
      `/v1/explorer/rwas/${encodeURIComponent(normalizedId)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
        canonicalAuth: this.#canonicalRequestAuth,
      },
    );
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("explorer rwa detail endpoint returned no payload");
    }
    return normalizeExplorerRwaRecord(payload, "explorer rwa detail response");
  }




  /**
   * Upload an attachment to Torii.
   * @param {ArrayBufferView | ArrayBuffer | string} data Attachment bytes.
   * @param {{contentType: string, signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options Attachment metadata and exact-network authentication.
   * @returns {Promise<ToriiAttachmentMetadata>} Attachment metadata returned by Torii.
   */
  async uploadAttachment(data, options = {}) {
    const normalizedOptions =
      options === undefined || options === null
        ? {}
        : requirePlainObjectOption(options, "uploadAttachment options");
    assertSupportedOptionKeys(
      normalizedOptions,
      UPLOAD_ATTACHMENT_OPTION_KEYS,
      "uploadAttachment options",
    );
    const normalizedContentType = requireNonEmptyString(
      pickOverride(normalizedOptions, "content_type", "contentType"),
      "uploadAttachment options.contentType",
    );
    const body = normalizeAttachmentUploadPayload(data, "uploadAttachment data");
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(normalizedOptions, "uploadAttachment", UPLOAD_ATTACHMENT_OPTION_KEYS);
    const response = await this._request("POST", "/v1/zk/attachments", {
      headers: { "Content-Type": normalizedContentType },
      body, signal, canonicalAuth,
    });
    await this._expectStatus(response, [201]);
    const payload = await this._maybeJson(response);
    return normalizeAttachmentMetadataRecord(payload, "upload attachment response");
  }
  /**
   * List stored attachments.
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ReadonlyArray<ToriiAttachmentMetadata>>}
   */
  async listAttachments(options = {}) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "listAttachments");
    const response = await this._request("GET", "/v1/zk/attachments", { signal, canonicalAuth });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeAttachmentMetadataList(payload);
  }
  /**
   * Fetch an attachment and its optional content type.
   * @param {string} attachmentId Attachment identifier.
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<{data: Buffer, contentType: string | null}>}
   */
  async getAttachment(attachmentId, options = {}) {
    const normalizedId = requireNonEmptyString(attachmentId, "attachmentId");
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getAttachment");
    const response = await this._request("GET", `/v1/zk/attachments/${encodeURIComponent(normalizedId)}`, {
      signal, canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const arrayBuffer = await response.arrayBuffer();
    const contentType = this._getHeader(response, "content-type");
    return { data: Buffer.from(arrayBuffer), contentType: contentType ?? null };
  }
  /**
   * Delete an attachment by id.
   * @param {string} attachmentId
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   */
  async deleteAttachment(attachmentId, options = {}) {
    const normalizedId = requireNonEmptyString(attachmentId, "attachmentId");
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "deleteAttachment");
    const response = await this._request("DELETE", `/v1/zk/attachments/${encodeURIComponent(normalizedId)}`, {
      signal, canonicalAuth,
    });
    await this._expectStatus(response, [200, 202, 204, 404]);
  }

  /**
   * List verifying keys stored in the registry (`GET /v1/zk/vk`).
   * @param {ToriiVerifyingKeyListOptions} [options]
   * @returns {Promise<ReadonlyArray<ToriiVerifyingKeyListItem>>}
   */
  async listVerifyingKeys(options = {}) {
    const verifyingKeys = await loadVerifyingKeyClient();
    const { signal, params } = verifyingKeys.listQuery(options);
    const response = await this._request("GET", "/v1/zk/vk", {
      headers: JSON_ACCEPT_HEADERS,
      params,
      signal,
    });
    await this._expectStatus(response, [200]);
    return verifyingKeys.list(await this._maybeJson(response));
  }

  /**
   * Iterate verifying-key registry entries with offset-based pagination.
   * @param {{pageSize?: number, maxItems?: number, signal?: AbortSignal} & ToriiVerifyingKeyListOptions} [options]
   * @returns {AsyncGenerator<ToriiVerifyingKeyListItem, void, unknown>}
   */
  iterateVerifyingKeys(options = {}) {
    const fetchPage = async (pageOptions = {}) => {
      const items = await this.listVerifyingKeys(pageOptions);
      return { items: items ?? [] };
    };
    return this._iterateOffsetIterable(
      fetchPage,
      options,
      VERIFYING_KEY_ITERATOR_OPTION_KEYS,
    );
  }

  /**
   * Fetch a verifying key record (`GET /v1/zk/vk/{backend}/{name}`).
   * @param {string} backend
   * @param {string} name
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ToriiVerifyingKeyDetail>}
   */
  async getVerifyingKey(backend, name, options = {}) {
    const verifyingKeys = await loadVerifyingKeyClient();
    const normalizedBackend = encodeURIComponent(
      verifyingKeys.backend(
        backend,
        "getVerifyingKey backend",
      ),
    );
    const normalizedName = encodeURIComponent(
      verifyingKeys.name(name, "getVerifyingKey name"),
    );
    const { signal } = normalizeSignalOnlyOption(options, "getVerifyingKey");
    const response = await this._request(
      "GET",
      `/v1/zk/vk/${normalizedBackend}/${normalizedName}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
      },
    );
    await this._expectStatus(response, [200]);
    return verifyingKeys.detail(await this._maybeJson(response));
  }

  /**
   * Prepare a verifying key registration transaction for local signing
   * (`POST /v1/zk/vk/register`).
   * @param {ToriiVerifyingKeyRegisterPayload} payload
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ToriiVerifyingKeyTransactionDraft>}
   */
  async registerVerifyingKey(payload, options = {}) {
    const verifyingKeys = await loadVerifyingKeyClient();
    const normalizedPayload = verifyingKeys.register(payload);
    const signingContext = verifyingKeys.signingContext(
      this._localSigningContext,
      "registerVerifyingKey",
    );
    const body = JSON.stringify(normalizedPayload);
    const { signal } = normalizeSignalOnlyOption(
      options,
      "registerVerifyingKey",
    );
    const response = await this._request("POST", "/v1/zk/vk/register", {
      headers: JSON_REQUEST_HEADERS,
      body,
      signal,
    });
    await this._expectStatus(response, [200]);
    return verifyingKeys.draft(
      await this._maybeJson(response),
      "registerVerifyingKey response",
      {
        networkId: signingContext.networkId,
        networkPrefix: signingContext.chainDiscriminant,
        operation: "register",
        request: normalizedPayload,
      },
    );
  }

  /**
   * Prepare a verifying key update transaction for local signing
   * (`POST /v1/zk/vk/update`).
   * @param {ToriiVerifyingKeyUpdatePayload} payload
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiVerifyingKeyTransactionDraft>}
   */
  async updateVerifyingKey(payload, options = {}) {
    const verifyingKeys = await loadVerifyingKeyClient();
    const normalizedPayload = verifyingKeys.update(payload);
    const signingContext = verifyingKeys.signingContext(
      this._localSigningContext,
      "updateVerifyingKey",
    );
    const body = JSON.stringify(normalizedPayload);
    const { signal } = normalizeSignalOnlyOption(options, "updateVerifyingKey");
    const response = await this._request("POST", "/v1/zk/vk/update", {
      headers: JSON_REQUEST_HEADERS,
      body,
      signal,
    });
    await this._expectStatus(response, [200]);
    return verifyingKeys.draft(
      await this._maybeJson(response),
      "updateVerifyingKey response",
      {
        networkId: signingContext.networkId,
        networkPrefix: signingContext.chainDiscriminant,
        operation: "update",
        request: normalizedPayload,
      },
    );
  }

  /**
   * Resolve an ISO bridge alias (`POST /v1/aliases/resolve`).
   * Returns null when the alias is missing (404). Throws when the runtime is disabled (503).
  * @param {string} alias
  * @param {{signal?: AbortSignal, canonicalAuth?: CanonicalRequestAuth}} [options]
  * @returns {Promise<Record<string, unknown> | null>}
  */
  async resolveAlias(alias, options = {}) {
    const aliasInput = requireNonEmptyString(alias, "alias");
    const normalizedAlias = looksLikeIban(aliasInput)
      ? normalizeIban(aliasInput, "alias")
      : aliasInput;
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(options, "resolveAlias");
    assertSupportedOptionKeys(
      rest,
      ALIAS_CANONICAL_AUTH_OPTION_KEYS,
      "resolveAlias options",
    );
    const canonicalAuth = ToriiClient._normalizeCanonicalAuth(rest.canonicalAuth);
    const payload = { alias: normalizedAlias };
    const response = await this._request("POST", "/v1/aliases/resolve", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
      canonicalAuth,
    });
    if (response.status === 404) {
      return null;
    }
    if (response.status === 503) {
      rejectError("ISO bridge runtime is disabled on the target node");
    }
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("alias resolve endpoint returned no payload");
    }
    return normalizeAliasResolutionResponse(body, "alias resolve response");
  }

  /**
   * Resolve an ISO bridge alias by deterministic index (`POST /v1/aliases/resolve-index`).
   * Returns null when the index is unknown (404). Throws when the runtime is disabled (503).
   * @param {number | string | bigint} index
   * @param {{signal?: AbortSignal, canonicalAuth?: CanonicalRequestAuth}} [options]
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async resolveAliasByIndex(index, options = {}) {
    const payload = {
      index: ToriiClient._normalizeUnsignedInteger(index, "index", { allowZero: true }),
    };
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "resolveAliasByIndex",
    );
    assertSupportedOptionKeys(
      rest,
      ALIAS_CANONICAL_AUTH_OPTION_KEYS,
      "resolveAliasByIndex options",
    );
    const canonicalAuth = ToriiClient._normalizeCanonicalAuth(rest.canonicalAuth);
    const response = await this._request("POST", "/v1/aliases/resolve-index", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
      canonicalAuth,
    });
    if (response.status === 404) {
      return null;
    }
    if (response.status === 503) {
      rejectError("ISO bridge runtime is disabled on the target node");
    }
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("alias resolve_index endpoint returned no payload");
    }
    return normalizeAliasResolutionResponse(body, "alias resolve_index response");
  }

  /**
   * List aliases bound to a canonical account id (`POST /v1/aliases/by-account`).
   * Returns null when the account is unknown (404).
   * @param {string} accountId
   * @param {{dataspace?: string, domain?: string, signal?: AbortSignal, canonicalAuth?: CanonicalRequestAuth}} [options]
   * @returns {Promise<{account_id: string, total: number, items: Array<{alias: string, dataspace: string, domain: string | null, is_primary: boolean}>} | null>}
   */
  async lookupAliasesByAccount(accountId, options = {}) {
    const normalizedAccountId = ToriiClient._requireAccountId(accountId, "accountId");
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "lookupAliasesByAccount",
    );
    assertSupportedOptionKeys(
      rest,
      ALIAS_BY_ACCOUNT_OPTION_KEYS,
      "lookupAliasesByAccount options",
    );
    const canonicalAuth = ToriiClient._normalizeCanonicalAuth(rest.canonicalAuth);
    const dataspace =
      rest.dataspace === undefined
        ? undefined
        : requireNonEmptyString(rest.dataspace, "lookupAliasesByAccount.options.dataspace");
    const domain =
      rest.domain === undefined
        ? undefined
        : requireNonEmptyString(rest.domain, "lookupAliasesByAccount.options.domain");
    const response = await this._request("POST", "/v1/aliases/by-account", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify({
        account_id: normalizedAccountId,
        ...(dataspace ? { dataspace } : {}),
        ...(domain ? { domain } : {}),
      }),
      signal,
      canonicalAuth,
    });
    if (response.status === 404) {
      return null;
    }
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("alias by-account endpoint returned no payload");
    }
    return normalizeAliasLookupByAccountResponse(body, "alias by-account response");
  }

  /**
   * Resolve the deterministic eligible FI route for an I105 recipient.
   * @param {string} accountId
   * @param {{signal?: AbortSignal, canonicalAuth?: CanonicalRequestAuth}} [options]
   * @returns {Promise<{account_id: string, alias_fqn: string, fi_id: "hbl.sbp" | "ubl.sbp"}>}
   */
  async routeRetailRecipient(accountId, options = {}) {
    const normalizedAccountId = ToriiClient._requireAccountId(
      accountId,
      "routeRetailRecipient.accountId",
    );
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "routeRetailRecipient",
    );
    assertSupportedOptionKeys(
      rest,
      ALIAS_CANONICAL_AUTH_OPTION_KEYS,
      "routeRetailRecipient options",
    );
    const canonicalAuth = ToriiClient._normalizeCanonicalAuth(rest.canonicalAuth);
    const response = await this._request("POST", "/v1/retail/recipients/route", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify({ account_id: normalizedAccountId }),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("retail recipient route endpoint returned no payload");
    }
    const route = normalizeRetailRecipientRouteResponse(
      body,
      "retail recipient route response",
    );
    if (route.account_id !== normalizedAccountId) {
      rejectType("retail recipient route response.account_id does not match the requested account");
    }
    return route;
  }

  /** Read one exact on-chain sponsor-program lifecycle record. */
  async findFeeSponsorProgramById(programId, options = {}) {
    const normalizedProgramId = normalizeFeeSponsorProgramId(
      programId,
      "findFeeSponsorProgramById.programId",
    );
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      options,
      "findFeeSponsorProgramById",
    );
    const response = await this._request("POST", "/v1/fee-sponsor-programs/by-id", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify({ program_id: normalizedProgramId.literal }),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200, 404], {
      signal,
      maximumBodyBytes: FEE_SPONSOR_PROGRAM_JSON_MAX_BYTES,
      responseLabel: "fee sponsor program",
    });
    if (responseStatusWithoutUserGetter(response) === 404) {
      await this._readBoundedResponseBytes(
        response,
        FEE_SPONSOR_PROGRAM_JSON_MAX_BYTES,
        "fee sponsor program response",
        { signal },
      );
      return null;
    }
    const body = await this._readBoundedLosslessIntegerJson(
      response,
      FEE_SPONSOR_PROGRAM_JSON_MAX_BYTES,
      "fee sponsor program response",
      { signal },
    );
    const program = normalizeFeeSponsorProgramResponse(body, "fee sponsor program response");
    if (
      !feeQuoteAccountIdsHaveSameIdentity(
        program.id.sponsor,
        normalizedProgramId.sponsor,
      ) ||
      program.id.name !== normalizedProgramId.name
    ) {
      rejectType("fee sponsor program response.id does not match the requested exact program id");
    }
    return program;
  }

  /**
   * Observe exact staking signing inputs. This signs/submits no transaction and
   * authenticates no ledger state. The expected XOR definition is an explicit
   * operator pin; neither an alias nor the server response establishes that pin.
   */
  async preparePublicLanePlan(request, xorAssetDefinitionId, options = {}) {
    const context = requireLocalDraftSigningContext(this._localSigningContext, "preparePublicLanePlan");
    const opts = requirePlainObjectOption(options, "preparePublicLanePlan options");
    if (Object.keys(opts).some((key) => key !== "signal")) rejectType("preparePublicLanePlan only accepts signal");
    const configuredTimeoutMs = Number(this.#config.timeoutMs);
    const timeoutMs = Number.isFinite(configuredTimeoutMs) && configuredTimeoutMs > 0
      ? Math.min(configuredTimeoutMs, BOUNDED_JSON_MAX_READ_TIMEOUT_MS)
      : BOUNDED_JSON_MAX_READ_TIMEOUT_MS;
    // Keep one original deadline alive across module preparation, headers, and
    // every success/error body read. Per-attempt/header cleanup cannot reset it.
    const operation = composeRequestSignal(opts.signal, timeoutMs);
    const { signal } = operation;
    try {
      throwIfAborted(signal);
      const xor = normalizeAssetDefinitionId(xorAssetDefinitionId, "staking preparation XOR pin");
      const { encodeValidatorStakingPreparationFrameV1: encode, decodeValidatorStakingPreparationFrameV1: decode,
        validateValidatorStakingPreparationV1: validate } = await waitForPromiseWithSignal(loadToriiOptionalModule(), signal);
      const body = encode("PreparationRequest", request);
      const retainedRequest = decode("PreparationRequest", body);
      throwIfAborted(signal);
      const response = await waitForResponseWithSignal(this._request("POST", "/v1/nexus/staking/prepare", {
        headers: { "Content-Type": APPLICATION_NORITO, Accept: APPLICATION_NORITO },
        body, signal, disableRetries: true, redirect: "error",
      }), signal, "staking preparation");
      await this._expectStatus(response, [200], { signal, maximumBodyBytes: 256 * 1024, responseLabel: "staking preparation" });
      const type = this._getHeader(response, "content-type") ?? "";
      if (!/^[ \t]*application\/x-norito[ \t]*$/iu.test(type)) {
        cancelResponseBodyBestEffort(response, "staking preparation requires application/x-norito");
        rejectType("staking preparation requires application/x-norito");
      }
      const { bytes } = await this._readBoundedResponseBytes(response, 256 * 1024, "staking preparation", { signal });
      const prepared = decode("Preparation", bytes);
      validate(prepared, retainedRequest, context.networkId, xor);
      throwIfAborted(signal);
      return prepared;
    } finally {
      operation.cleanup();
    }
  }

  /**
   * Quote the exact unsigned payload that will subsequently be signed.
   * The account in `canonicalAuth` must identify the payload authority. Exact
   * aliases are resolved and enforced by Torii; I105 literals are compared by
   * their domainless controller identity before the request is sent.
   */
  async quoteFees(payloadOrDraft, options = {}) {
    const candidate = payloadOrDraft?.payload ?? payloadOrDraft;
    const payload = ensureRecord(candidate, "quoteFees payload");
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      options,
      "quoteFees",
    );
    const draft = normalizeFeeQuoteDraft(payload, "quoteFees payload");
    if (
      !canonicalAuth.accountId.includes("@")
      && !feeQuoteAccountIdsHaveSameIdentity(canonicalAuth.accountId, draft.authority)
    ) {
      rejectType("quoteFees canonicalAuth.accountId must identify the payload authority");
    }
    const response = await this._request("POST", "/v1/fees/quote", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify({ payload }),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200], {
      signal,
      maximumBodyBytes: FEE_QUOTE_JSON_MAX_BYTES,
      responseLabel: "fee quote",
    });
    const body = await this._readBoundedLosslessIntegerJson(
      response,
      FEE_QUOTE_JSON_MAX_BYTES,
      "fee quote response",
      { signal, plainObjects: true },
    );
    return validateFeeQuoteForDraft(payload, body, "fee quote response");
  }

  /**
   * Fetch and locally verify one bounded validation-fee consensus proof page.
   *
   * @param {object} binding exact immutable ledger binding
   * @param {object | null} checkpoint durable checkpoint, or null for binding.checkpoint
   * @param {{signal?: AbortSignal}} [options]
   */
  async getValidationFeeCurrentPolicyProofPage(
    binding,
    checkpoint = null,
    options,
  ) {
    const signingContext = requireLocalDraftSigningContext(this._localSigningContext, "getValidationFeeCurrentPolicyProofPage");
    const normalizedBinding = normalizeValidationFeeLedgerBindingV1(binding);
    const normalizedCheckpoint =
      checkpoint === null || checkpoint === undefined
        ? normalizedBinding.checkpoint
        : normalizeValidationFeeCheckpointV1(checkpoint);
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      options,
      "getValidationFeeCurrentPolicyProofPage",
    );
    const sendRequest = this._request.bind(this);
    const nativeRuntime = this._nativeRuntime;
    const {
      VALIDATION_FEE_CURRENT_POLICY_PROOF_PATH,
      VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES,
      createValidationFeeConsensusApi,
    } = await loadToriiOptionalModule();
    const {
      encodeValidationFeeCurrentPolicyProofRequestV1,
      verifyValidationFeeCurrentPolicyProofV1,
    } = createValidationFeeConsensusApi(nativeRuntime);
    const request = encodeValidationFeeCurrentPolicyProofRequestV1(
      normalizedCheckpoint,
    );
    const response = await sendRequest(
      "POST",
      VALIDATION_FEE_CURRENT_POLICY_PROOF_PATH,
      {
        headers: {
          "Content-Type": APPLICATION_NORITO,
          Accept: APPLICATION_NORITO,
        },
        body: request,
        signal, canonicalAuth,
      },
    );
    await this._expectStatus(response, [200]);
    const contentType = this._getHeader(response, "content-type") ?? "";
    if (!/^application\/x-norito(?:\s*;|$)/iu.test(contentType)) {
      const error = new TypeError(
        "validation-fee proof response must use application/x-norito",
      );
      await cancelResponseBody(response, error);
      throw error;
    }
    const proofNorito = Buffer.from(
      await readBoundedResponseBody(
        response,
        VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES,
        "validation-fee proof",
      ),
    );
    const { projection, promotedCheckpoint } = verifyValidationFeeCurrentPolicyProofV1(
      proofNorito,
      normalizedBinding,
      normalizedCheckpoint,
      signingContext.chainDiscriminant,
    );
    return Object.freeze({
      proofNorito,
      projection,
      promotedCheckpoint,
    });
  }

  /**
   * Repeatedly verify bounded pages until Torii's observed ledger tip.
   *
   * Persist each page's `promotedCheckpoint` yourself when crash-durable
   * promotion is required; this convenience method promotes only in memory.
   */
  async catchUpValidationFeeCurrentPolicyProof(binding, options) {
    const normalizedBinding = normalizeValidationFeeLedgerBindingV1(binding);
    const normalizedOptions = ensureRecord(
      options,
      "catchUpValidationFeeCurrentPolicyProof options",
    );
    assertSupportedOptionKeys(
      normalizedOptions,
      new Set(["checkpoint", "maxPages", "signal", CANONICAL_AUTH_FIELD]),
      "catchUpValidationFeeCurrentPolicyProof options",
    );
    const selectedCheckpoint = normalizedOptions.checkpoint;
    const selectedMaxPages = normalizedOptions.maxPages;
    const { signal } = normalizeSignalOption(normalizedOptions, "catchUpValidationFeeCurrentPolicyProof");
    const canonicalAuth = ToriiClient._normalizeCanonicalAuth(
      normalizedOptions.canonicalAuth, "catchUpValidationFeeCurrentPolicyProof.canonicalAuth",
    );
    const readPage = this.getValidationFeeCurrentPolicyProofPage.bind(this);
    let checkpoint =
      selectedCheckpoint === undefined
        ? normalizedBinding.checkpoint
        : normalizeValidationFeeCheckpointV1(selectedCheckpoint);
    const maxPages =
      selectedMaxPages === undefined
        ? 4096
        : ToriiClient._normalizeUnsignedInteger(
            selectedMaxPages,
            "catchUpValidationFeeCurrentPolicyProof.maxPages",
            { allowZero: false },
          );
    if (maxPages > 4096) {
      rejectType("catchUpValidationFeeCurrentPolicyProof.maxPages must not exceed 4096");
    }
    for (let pagesVerified = 1; pagesVerified <= maxPages; pagesVerified += 1) {
      const page = await readPage(
        normalizedBinding,
        checkpoint,
        { signal, canonicalAuth },
      );
      if (
        page.projection.evaluated_block_height < page.projection.trusted_checkpoint_height ||
        (page.projection.more_available &&
          page.projection.evaluated_block_height === page.projection.trusted_checkpoint_height)
      ) {
        rejectError("validation-fee checkpoint promotion did not advance");
      }
      checkpoint = page.promotedCheckpoint;
      if (!page.projection.more_available) {
        return Object.freeze({
          ...page,
          binding: normalizedBinding,
          pagesVerified,
        });
      }
    }
    rejectError(`validation-fee checkpoint promotion exceeded ${maxPages} pages`);
  }

  /**
   * Lookup a retail recipient name through Torii (`POST /v1/retail/recipients/lookup`).
   * @param {{accountId?: string, account_id?: string, aliasFqn?: string, alias_fqn?: string}} request
   * @param {{signal?: AbortSignal, canonicalAuth?: CanonicalRequestAuth}} [options]
   * @returns {Promise<{resolved: boolean, account_id: string, alias_fqn: string, fi_id: "hbl.sbp" | "ubl.sbp", full_name?: string}>}
   */
  async lookupRetailRecipient(request, options = {}) {
    const requestRecord = ensureRecord(request, "lookupRetailRecipient request");
    assertSupportedOptionKeys(
      requestRecord,
      RETAIL_RECIPIENT_LOOKUP_REQUEST_KEYS,
      "lookupRetailRecipient request",
    );
    if (
      Object.prototype.hasOwnProperty.call(requestRecord, "accountId") &&
      Object.prototype.hasOwnProperty.call(requestRecord, "account_id") &&
      requestRecord.accountId !== requestRecord.account_id
    ) {
      rejectType("lookupRetailRecipient request accountId and account_id must match when both are supplied");
    }
    if (
      Object.prototype.hasOwnProperty.call(requestRecord, "aliasFqn") &&
      Object.prototype.hasOwnProperty.call(requestRecord, "alias_fqn") &&
      requestRecord.aliasFqn !== requestRecord.alias_fqn
    ) {
      rejectType("lookupRetailRecipient request aliasFqn and alias_fqn must match when both are supplied");
    }
    const accountId = ToriiClient._requireAccountId(
      requestRecord.accountId ?? requestRecord.account_id,
      "lookupRetailRecipient.accountId",
    );
    const requestedAliasFqn = requireNonEmptyString(
      requestRecord.aliasFqn ?? requestRecord.alias_fqn,
      "lookupRetailRecipient.aliasFqn",
    );
    const aliasFqn = normalizeAccountAliasFqn(
      requestedAliasFqn,
      "lookupRetailRecipient.aliasFqn",
    );
    if (aliasFqn !== requestedAliasFqn) {
      rejectType("lookupRetailRecipient.aliasFqn must be canonical");
    }
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "lookupRetailRecipient",
    );
    assertSupportedOptionKeys(
      rest,
      ALIAS_CANONICAL_AUTH_OPTION_KEYS,
      "lookupRetailRecipient options",
    );
    const canonicalAuth = ToriiClient._normalizeCanonicalAuth(rest.canonicalAuth);
    const response = await this._request("POST", "/v1/retail/recipients/lookup", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify({
        account_id: accountId,
        alias_fqn: aliasFqn,
      }),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("retail recipient lookup endpoint returned no payload");
    }
    const result = normalizeRetailRecipientLookupResponse(
      body,
      "retail recipient lookup response",
    );
    if (result.account_id !== accountId || result.alias_fqn !== aliasFqn) {
      rejectType("retail recipient lookup response does not match the requested account and alias");
    }
    return result;
  }

  /**
   * List globally registered identifier policies (`GET /v1/identifier-policies`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<{total: number, items: Array<Record<string, unknown>>}>}
   */
  async listIdentifierPolicies(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "listIdentifierPolicies",
    );
    assertSupportedOptionKeys(rest, new Set([]), "listIdentifierPolicies options");
    const response = await this._request("GET", "/v1/identifier-policies", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      JSON_RESPONSE_MAX_BYTES,
      "identifier policy list response",
      { signal },
    );
    if (!payload) {
      rejectError("identifier policy list endpoint returned no payload");
    }
    return normalizeIdentifierPolicyListResponse(payload, "identifier policy list response");
  }

  /**
   * List globally registered RAM-LFE program policies (`GET /v1/ram-lfe/program-policies`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<{total: number, items: Array<Record<string, unknown>>}>}
   */
  async listRamLfeProgramPolicies(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "listRamLfeProgramPolicies",
    );
    assertSupportedOptionKeys(rest, new Set([]), "listRamLfeProgramPolicies options");
    const response = await this._request("GET", "/v1/ram-lfe/program-policies", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      JSON_RESPONSE_MAX_BYTES,
      "ram-lfe program policy list response",
      { signal },
    );
    if (!payload) {
      rejectError("ram-lfe program policy list endpoint returned no payload");
    }
    return normalizeRamLfeProgramPolicyListResponse(
      payload,
      "ram-lfe program policy list response",
    );
  }

  /**
   * Resolve an identifier through a hidden-function policy (`POST /v1/identifiers/resolve`).
   * Returns null when the policy or identifier binding is missing (404).
   * @param {{policyId: string, encryptedInput: string, outputOpening: Record<string, unknown>, signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async resolveIdentifier(options) {
    const { signal, canonicalAuth, rest } = normalizeCanonicalApplicationPostOptions(options, "resolveIdentifier", ToriiClient);
    const payload = buildIdentifierResolveRequest(rest, "resolveIdentifier");
    const response = await this._request("POST", "/v1/identifiers/resolve", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
      canonicalAuth,
    });
    if (response.status === 404) {
      return null;
    }
    if (response.status === 409) {
      rejectError("Identifier policy is inactive or the target binding is unavailable");
    }
    if (response.status === 503) {
      rejectError("Identifier resolver runtime is disabled on the target node");
    }
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("identifier resolve endpoint returned no payload");
    }
    return normalizeIdentifierResolveResponse(body, "identifier resolve response");
  }

  /**
   * Execute one RAM-LFE program from BFV-encrypted input
   * (`POST /v1/ram-lfe/programs/{program_id}/execute`).
   * Returns null when the program policy is missing (404).
   * @param {string} programId
   * @param {{encryptedInput: string, signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async executeRamLfeProgram(programId, options) {
    const normalizedProgramId = requireNonEmptyString(
      programId,
      "executeRamLfeProgram.programId",
    );
    const { signal, canonicalAuth, rest } = normalizeCanonicalApplicationPostOptions(options, "executeRamLfeProgram", ToriiClient);
    const payload = buildRamLfeExecuteRequest(rest, "executeRamLfeProgram");
    const response = await this._request(
      "POST",
      `/v1/ram-lfe/programs/${encodeURIComponent(normalizedProgramId)}/execute`,
      {
        headers: JSON_REQUEST_HEADERS,
        body: JSON.stringify(payload),
        signal,
        canonicalAuth,
      },
    );
    if (response.status === 404) {
      return null;
    }
    if (response.status === 409) {
      rejectError("RAM-LFE program policy is inactive");
    }
    if (response.status === 503) {
      rejectError("RAM-LFE runtime is disabled on the target node");
    }
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("ram-lfe execute endpoint returned no payload");
    }
    return normalizeRamLfeExecuteResponse(body, "ram-lfe execute response");
  }

  /**
   * Look up a persisted identifier claim by its receipt hash (`GET /v1/identifiers/receipts/{receipt_hash}`).
   * Returns null when the receipt hash is unknown (404).
   * @param {string} receiptHash
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async getIdentifierClaimByReceiptHash(receiptHash, options = {}) {
    const normalizedReceiptHash = normalizeHex32String(
      receiptHash,
      "getIdentifierClaimByReceiptHash.receiptHash",
    );
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "getIdentifierClaimByReceiptHash",
    );
    assertSupportedOptionKeys(
      rest,
      new Set([]),
      "getIdentifierClaimByReceiptHash options",
    );
    const response = await this._request(
      "GET",
      `/v1/identifiers/receipts/${encodeURIComponent(normalizedReceiptHash)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
      },
    );
    if (response.status === 404) {
      return null;
    }
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("identifier receipt lookup endpoint returned no payload");
    }
    return normalizeIdentifierClaimLookupResponse(
      body,
      "identifier claim lookup response",
    );
  }

  /**
   * Issue a signed on-chain claim receipt for an account identifier binding.
   * Returns null when the policy or account is missing (404).
   * @param {string} accountId
   * @param {{policyId: string, encryptedInput: string, outputOpening: Record<string, unknown>, signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async issueIdentifierClaimReceipt(accountId, options) {
    const { signal, canonicalAuth, rest } = normalizeCanonicalApplicationPostOptions(options, "issueIdentifierClaimReceipt", ToriiClient);
    const normalizedAccountId = requireCanonicalApplicationAuthority(canonicalAuth, accountId, "issueIdentifierClaimReceipt");
    const payload = buildIdentifierResolveRequest(rest, "issueIdentifierClaimReceipt");
    const response = await this._request(
      "POST",
      `/v1/accounts/${encodeURIComponent(normalizedAccountId)}/identifiers/claim-receipt`,
      {
        headers: JSON_REQUEST_HEADERS,
        body: JSON.stringify(payload),
        signal,
        canonicalAuth,
      },
    );
    if (response.status === 404) {
      return null;
    }
    if (response.status === 409) {
      rejectError("Identifier claim receipt cannot be issued for this account or policy");
    }
    if (response.status === 503) {
      rejectError("Identifier resolver runtime is disabled on the target node");
    }
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("identifier claim-receipt endpoint returned no payload");
    }
    return normalizeIdentifierResolveResponse(body, "identifier claim receipt response");
  }

  /**
   * Verify a RAM-LFE execution receipt against the node's registered program policy
   * (`POST /v1/ram-lfe/receipts/verify`).
   * @param {{receipt: Record<string, unknown>, outputHex?: string, signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<Record<string, unknown>>}
   */
  async verifyRamLfeReceipt(options) {
    const { signal, canonicalAuth, rest } = normalizeCanonicalApplicationPostOptions(options, "verifyRamLfeReceipt", ToriiClient);
    const payload = buildRamLfeReceiptVerifyRequest(rest, "verifyRamLfeReceipt");
    const response = await this._request("POST", "/v1/ram-lfe/receipts/verify", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("ram-lfe receipt verify endpoint returned no payload");
    }
    return normalizeRamLfeReceiptVerifyResponse(
      body,
      "ram-lfe receipt verify response",
    );
  }

  /**
   * List SoraFS alias bindings with attestation metadata (`GET /v1/sorafs/aliases`).
   * @param {{namespace?: string, manifestDigestHex?: string, limit?: number, offset?: number, signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<SorafsAliasListResponse>}
   */
  async listSorafsAliases(options) {
    const { signal, rest, canonicalAuth } = normalizeSorafsInventoryReadOptions(
      options,
      "listSorafsAliases",
    );
    const params = buildSorafsAliasListParams(rest);
    const response = await this._request("GET", "/v1/sorafs/aliases", {
      headers: JSON_ACCEPT_HEADERS,
      params,
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      JSON_RESPONSE_MAX_BYTES,
      "sorafs alias list response",
      { signal },
    );
    if (!payload) {
      rejectError("sorafs alias list endpoint returned no payload");
    }
    return normalizeSorafsAliasListResponse(payload);
  }

  /**
   * Iterate SoraFS alias bindings with offset-based pagination.
   * @param {{pageSize?: number, maxItems?: number, signal?: AbortSignal} & SorafsAliasListOptions} options
   * @returns {AsyncGenerator<SorafsAliasRecord, void, unknown>}
   */
  iterateSorafsAliases(options) {
    return this._iterateOffsetIterable(
      this.listSorafsAliases,
      options,
      SORAFS_ALIAS_ITERATOR_OPTION_KEYS,
      ["aliases"],
    );
  }

  /**
   * List SoraFS manifests registered in the pin registry (`GET /v1/sorafs/pin`).
   * Pages are anchored to finalized state and use an exclusive digest cursor.
   * @param {SorafsPinListOptions} [options]
   * @returns {Promise<SorafsPinListResponse>}
   */
  async listSorafsPinManifests(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "listSorafsPinManifests",
    );
    const params = buildSorafsPinListParams(rest);
    const response = await this._request("GET", "/v1/sorafs/pin", {
      headers: JSON_ACCEPT_HEADERS,
      params,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response, JSON_RESPONSE_MAX_BYTES, "sorafs pin list response", { signal },
    );
    if (!payload) {
      rejectError("sorafs pin list endpoint returned no payload");
    }
    return normalizeSorafsPinListResponse(payload, params);
  }

  /**
   * Iterate bounded SoraFS pin summaries at one immutable finalized anchor.
   * @param {{pageSize?: number, maxItems?: number, signal?: AbortSignal} & SorafsPinListOptions} [options]
   * @returns {AsyncGenerator<SorafsPinManifestSummaryV1, void, unknown>}
   */
  iterateSorafsPinManifests(options = {}) {
    const normalizedOptions = ToriiClient._normalizeIterableOptions(
      options,
      "listSorafsPinManifests iterator options",
      SORAFS_PIN_ITERATOR_OPTION_KEYS,
    );
    assertSupportedOptionKeys(
      normalizedOptions,
      SORAFS_PIN_ITERATOR_OPTION_KEYS,
      "listSorafsPinManifests iterator options",
    );
    const {
      pageSize: rawPageSize,
      maxItems: rawMaxItems,
      signal,
      ...baseOptions
    } = normalizedOptions;
    const maxItems =
      rawMaxItems === undefined || rawMaxItems === null
        ? null
        : ToriiClient._normalizeUnsignedInteger(rawMaxItems, "maxItems", {
            allowZero: false,
          });
    const preferredPageSize =
      rawPageSize === undefined || rawPageSize === null
        ? baseOptions.limit
        : rawPageSize;
    const pageSize = ToriiClient._normalizeUnsignedInteger(
      preferredPageSize ?? DEFAULT_PAGE_SIZE,
      preferredPageSize === undefined ? "pageSize" : "limit",
      { allowZero: false, max: SORAFS_PIN_LIST_MAX_ITEMS },
    );
    delete baseOptions.limit;

    const self = this;
    return (async function* iterator() {
      let remaining = maxItems;
      let afterDigestHex = baseOptions.afterDigestHex;
      let expectedFinalizedHeight = baseOptions.expectedFinalizedHeight;
      let expectedFinalizedBlockHashHex = baseOptions.expectedFinalizedBlockHashHex;

      while (true) {
        const limit = remaining === null ? pageSize : Math.min(pageSize, remaining);
        if (limit <= 0) return;
        const page = await self.listSorafsPinManifests({
          ...baseOptions,
          afterDigestHex,
          expectedFinalizedHeight,
          expectedFinalizedBlockHashHex,
          limit,
          signal,
        });

        if (expectedFinalizedHeight === undefined || expectedFinalizedHeight === null) {
          expectedFinalizedHeight = page.finalized_cursor.height;
          expectedFinalizedBlockHashHex = exactJsonBytesToLowerHex(
            page.finalized_cursor.block_hash,
          );
        }

        for (const manifest of page.manifests) {
          yield manifest;
          if (remaining !== null) {
            remaining -= 1;
            if (remaining === 0) return;
          }
        }
        if (!page.has_more) return;

        const nextAfterDigestHex = exactJsonBytesToLowerHex(page.next_after_digest);
        if (nextAfterDigestHex === afterDigestHex) {
          rejectError("sorafs pin list endpoint repeated its exclusive cursor");
        }
        afterDigestHex = nextAfterDigestHex;
      }
    })();
  }

  /**
   * List SoraFS replication orders with attestation metadata (`GET /v1/sorafs/replication`).
   * @param {SorafsReplicationListOptions} options
   * @returns {Promise<SorafsReplicationListResponse>}
   */
  async listSorafsReplicationOrders(options) {
    const { signal, rest, canonicalAuth } = normalizeSorafsInventoryReadOptions(
      options,
      "listSorafsReplicationOrders",
    );
    const params = buildSorafsReplicationListParams(rest);
    const response = await this._request("GET", "/v1/sorafs/replication", {
      headers: JSON_ACCEPT_HEADERS,
      params,
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response, JSON_RESPONSE_MAX_BYTES, "sorafs replication list response", { signal },
    );
    if (!payload) {
      rejectError("sorafs replication list endpoint returned no payload");
    }
    const { createSorafsReplicationResponseNormalizer } = await loadToriiOptionalModule();
    return createSorafsReplicationResponseNormalizer({
      account: (value, context) => ToriiClient._requireAccountId(value, context),
    }).normalize(payload, params);
  }

  /**
   * Iterate SoraFS replication orders via the list endpoint.
   * @param {{pageSize?: number, maxItems?: number, signal?: AbortSignal} & SorafsReplicationListOptions} options
   * @returns {AsyncGenerator<SorafsReplicationOrderRecord, void, unknown>}
   */
  iterateSorafsReplicationOrders(options) {
    return this._iterateOffsetIterable(
      this.listSorafsReplicationOrders,
      options,
      SORAFS_REPLICATION_ITERATOR_OPTION_KEYS,
      ["replication_orders"],
    );
  }

  /**
   * Submit a caller-signed transaction containing exactly one
   * `SubmitSorafsOrderbookOrder` instruction.
   * @param {Buffer|Uint8Array|ArrayBuffer|ArrayBufferView} signedTransaction
   * @param {{expectedReceiptSigner: string, signal?: AbortSignal}} options
   * @returns {Promise<SorafsOrderbookSubmissionReceipt>}
   */
  async submitSorafsOrderbookOrder(signedTransaction, options = {}) {
    return this._submitSorafsOrderbookTransaction(
      "/v1/sorafs/orderbook/orders",
      "order",
      signedTransaction,
      options,
      "submitSorafsOrderbookOrder",
    );
  }

  /**
   * Submit a caller-signed transaction containing exactly one
   * `CancelSorafsOrderbookOrder` instruction.
   * @param {Buffer|Uint8Array|ArrayBuffer|ArrayBufferView} signedTransaction
   * @param {{expectedReceiptSigner: string, signal?: AbortSignal}} options
   * @returns {Promise<SorafsOrderbookSubmissionReceipt>}
   */
  async submitSorafsOrderbookCancel(signedTransaction, options = {}) {
    return this._submitSorafsOrderbookTransaction(
      "/v1/sorafs/orderbook/cancel",
      "cancel",
      signedTransaction,
      options,
      "submitSorafsOrderbookCancel",
    );
  }

  /**
   * Submit a caller-signed transaction containing exactly one
   * `RecordSorafsOrderbookSettlementReceipt` instruction.
   * @param {Buffer|Uint8Array|ArrayBuffer|ArrayBufferView} signedTransaction
   * @param {{expectedReceiptSigner: string, signal?: AbortSignal}} options
   * @returns {Promise<SorafsOrderbookSubmissionReceipt>}
   */
  async submitSorafsOrderbookReceipt(signedTransaction, options = {}) {
    return this._submitSorafsOrderbookTransaction(
      "/v1/sorafs/orderbook/receipts",
      "receipt",
      signedTransaction,
      options,
      "submitSorafsOrderbookReceipt",
    );
  }

  /**
   * Fetch authoritative orderbook status and a finalized order page.
   * @param {SorafsOrderbookReadOptions} [options]
   * @returns {Promise<SorafsOrderbookBookResponse>}
   */
  async getSorafsOrderbook(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "getSorafsOrderbook",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_ORDERBOOK_READ_OPTION_KEYS,
      "getSorafsOrderbook options",
    );
    const response = await this._request("GET", "/v1/sorafs/orderbook/book", {
      headers: buildSorafsOrderbookHeaders(rest, "getSorafsOrderbook"),
      params: buildSorafsOrderbookReadParams(rest, "getSorafsOrderbook"),
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("sorafs orderbook book endpoint returned no payload");
    }
    return normalizeSorafsOrderbookBookResponse(payload);
  }

  /**
   * List authoritative trades at a finalized block.
   * @param {SorafsOrderbookReadOptions} [options]
   * @returns {Promise<SorafsOrderbookTradesResponse>}
   */
  async listSorafsOrderbookTrades(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "listSorafsOrderbookTrades",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_ORDERBOOK_READ_OPTION_KEYS,
      "listSorafsOrderbookTrades options",
    );
    const response = await this._request("GET", "/v1/sorafs/orderbook/trades", {
      headers: buildSorafsOrderbookHeaders(rest, "listSorafsOrderbookTrades"),
      params: buildSorafsOrderbookReadParams(rest, "listSorafsOrderbookTrades"),
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("sorafs orderbook trades endpoint returned no payload");
    }
    return normalizeSorafsOrderbookPageResponse(
      payload,
      "trades",
      "next_after_trade_id",
      "sorafs orderbook trades response",
    );
  }

  /**
   * List authoritative settlement channels at a finalized block.
   * @param {SorafsOrderbookReadOptions} [options]
   * @returns {Promise<SorafsOrderbookChannelsResponse>}
   */
  async listSorafsOrderbookChannels(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "listSorafsOrderbookChannels",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_ORDERBOOK_READ_OPTION_KEYS,
      "listSorafsOrderbookChannels options",
    );
    const response = await this._request("GET", "/v1/sorafs/orderbook/channels", {
      headers: buildSorafsOrderbookHeaders(rest, "listSorafsOrderbookChannels"),
      params: buildSorafsOrderbookReadParams(rest, "listSorafsOrderbookChannels"),
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("sorafs orderbook channels endpoint returned no payload");
    }
    return normalizeSorafsOrderbookPageResponse(
      payload,
      "channels",
      "next_after_channel_id",
      "sorafs orderbook channels response",
    );
  }

  /**
   * List authoritative settlement receipts at a finalized block.
   * @param {SorafsOrderbookReadOptions} [options]
   * @returns {Promise<SorafsOrderbookReceiptsResponse>}
   */
  async listSorafsOrderbookReceipts(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "listSorafsOrderbookReceipts",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_ORDERBOOK_READ_OPTION_KEYS,
      "listSorafsOrderbookReceipts options",
    );
    const response = await this._request("GET", "/v1/sorafs/orderbook/receipts", {
      headers: buildSorafsOrderbookHeaders(rest, "listSorafsOrderbookReceipts"),
      params: buildSorafsOrderbookReadParams(rest, "listSorafsOrderbookReceipts"),
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("sorafs orderbook receipts endpoint returned no payload");
    }
    return normalizeSorafsOrderbookPageResponse(
      payload,
      "receipts",
      "next_after_receipt_id",
      "sorafs orderbook receipts response",
    );
  }

  /**
   * List committed orderbook events using a complete finalized event cursor.
   * Returns `null` when `If-None-Match` returns 304.
   * @param {SorafsOrderbookEventsOptions} [options]
   * @returns {Promise<SorafsOrderbookEventsResponse | null>}
   */
  async listSorafsOrderbookEvents(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "listSorafsOrderbookEvents",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_ORDERBOOK_EVENT_OPTION_KEYS,
      "listSorafsOrderbookEvents options",
    );
    const response = await this._request("GET", "/v1/sorafs/orderbook/events", {
      headers: buildSorafsOrderbookHeaders(rest, "listSorafsOrderbookEvents", {
        cache: true,
      }),
      params: buildSorafsOrderbookEventsParams(rest, "listSorafsOrderbookEvents"),
      signal,
    });
    await this._expectStatus(response, [200, 304]);
    if (response.status === 304) {
      return null;
    }
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("sorafs orderbook events endpoint returned no payload");
    }
    return normalizeSorafsOrderbookEventsResponse(payload);
  }

  /**
   * Stream committed orderbook events via SSE.
   * @param {SorafsOrderbookEventStreamOptions} [options]
   * @returns {AsyncGenerator<SseEvent<SorafsOrderbookFinalizedEvent>, void, unknown>}
   */
  streamSorafsOrderbookEvents(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "streamSorafsOrderbookEvents",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_ORDERBOOK_STREAM_OPTION_KEYS,
      "streamSorafsOrderbookEvents options",
    );
    return normalizeSorafsOrderbookEventStream(
      this._streamSse("/v1/sorafs/orderbook/events/stream", {
        params: buildSorafsOrderbookEventsParams(rest, "streamSorafsOrderbookEvents"),
        signal,
      }),
    );
  }

  /**
   * Build a WebSocket URL for the committed SoraFS orderbook event stream.
   * @param {SorafsOrderbookEventsWebSocketParams} [options]
   * @returns {string}
   */
  buildSorafsOrderbookEventsWebSocketUrl(options = {}) {
    return buildSorafsOrderbookEventsWebSocketUrlInternal(
      this._baseUrl,
      options,
      "ToriiClient.buildSorafsOrderbookEventsWebSocketUrl",
    );
  }

  /**
   * Open the committed SoraFS orderbook event WebSocket.
   * @template [T=unknown]
   * @param {ClientSorafsOrderbookEventsWebSocketOptions<T>} [options]
   * @returns {T}
   */
  openSorafsOrderbookEventsWebSocket(options = {}) {
    return openSorafsOrderbookEventsWebSocketInternal(
      { ...options, baseUrl: this._baseUrl },
      "ToriiClient.openSorafsOrderbookEventsWebSocket",
    );
  }

  /**
   * Stream committed SoraFS orderbook events from the WebSocket JSON frame route.
   * @template [T=unknown]
   * @param {SorafsOrderbookEventsWebSocketStreamOptions<T>} [options]
   * @returns {AsyncGenerator<WebSocketEventFrame<SorafsOrderbookFinalizedEvent>, void, unknown>}
   */
  streamSorafsOrderbookEventsWebSocket(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "streamSorafsOrderbookEventsWebSocket",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_ORDERBOOK_WEBSOCKET_STREAM_OPTION_KEYS,
      "streamSorafsOrderbookEventsWebSocket options",
    );
    const { closeOnReturn, ...dialOptions } = rest;
    const socket = this.openSorafsOrderbookEventsWebSocket(dialOptions);
    return normalizeSorafsOrderbookWebSocketEventStream(
      streamWebSocketJsonEvents(socket, {
        signal,
        closeOnReturn,
        context: "streamSorafsOrderbookEventsWebSocket",
      }),
    );
  }

  /**
   * Fetch the latest SoraFS reputation snapshot summary (`GET /v1/sorafs/reputation/latest`).
   * Returns `null` when Torii has no snapshot yet or when `If-None-Match` returns 304.
   * @param {{ifNoneMatch?: string, headers?: Record<string, string>, canonicalAuth?: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async getSorafsReputationLatest(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "getSorafsReputationLatest",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_REPUTATION_CACHE_OPTION_KEYS,
      "getSorafsReputationLatest options",
    );
    const auth = buildSorafsReputationRequestAuth(
      rest,
      this.#config.defaultHeaders,
      "getSorafsReputationLatest",
    );
    const response = await this._request("GET", "/v1/sorafs/reputation/latest", {
      headers: auth.headers,
      canonicalAuth: auth.canonicalAuth,
      disableRetries: true,
      redirect: "error",
      signal,
    });
    await this._expectStatus(response, [200, 304, 404]);
    if (response.status === 304 || response.status === 404) {
      return null;
    }
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      SORAFS_REPUTATION_JSON_MAX_BYTES,
      "sorafs reputation latest endpoint",
      { signal },
    );
    return parseSorafsReputationSnapshot(payload, "sorafs reputation latest endpoint");
  }

  /**
   * Fetch a provider reputation record and Merkle proof from the latest snapshot.
   * Returns `null` for 404 or 304 responses.
   * @param {string} providerId
   * @param {{ifNoneMatch?: string, headers?: Record<string, string>, canonicalAuth?: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async getSorafsReputationProvider(providerId, options = {}) {
    const normalizedProvider = normalizeSorafsReputationProviderId(
      providerId,
      "getSorafsReputationProvider.providerId",
    );
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "getSorafsReputationProvider",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_REPUTATION_CACHE_OPTION_KEYS,
      "getSorafsReputationProvider options",
    );
    const auth = buildSorafsReputationRequestAuth(
      rest,
      this.#config.defaultHeaders,
      "getSorafsReputationProvider",
    );
    const response = await this._request(
      "GET",
      `/v1/sorafs/reputation/providers/${normalizedProvider}`,
      {
        headers: auth.headers,
        canonicalAuth: auth.canonicalAuth,
        disableRetries: true,
        redirect: "error",
        signal,
      },
    );
    await this._expectStatus(response, [200, 304, 404]);
    if (response.status === 304 || response.status === 404) {
      return null;
    }
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      SORAFS_REPUTATION_JSON_MAX_BYTES,
      "sorafs reputation provider endpoint",
      { signal },
    );
    return parseSorafsReputationProviderResponse(
      payload,
      "sorafs reputation provider endpoint",
      normalizedProvider,
    );
  }

  /**
   * Fetch a historical SoraFS reputation snapshot by its 16-byte id.
   * Returns `null` for 404 or 304 responses.
   * @param {string} snapshotIdHex
   * @param {{ifNoneMatch?: string, headers?: Record<string, string>, canonicalAuth?: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async getSorafsReputationSnapshot(snapshotIdHex, options = {}) {
    const normalizedSnapshotId = normalizeReputationSnapshotIdHex(
      snapshotIdHex,
      "getSorafsReputationSnapshot.snapshotIdHex",
    );
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "getSorafsReputationSnapshot",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_REPUTATION_CACHE_OPTION_KEYS,
      "getSorafsReputationSnapshot options",
    );
    const auth = buildSorafsReputationRequestAuth(
      rest,
      this.#config.defaultHeaders,
      "getSorafsReputationSnapshot",
    );
    const response = await this._request(
      "GET",
      `/v1/sorafs/reputation/snapshots/${normalizedSnapshotId}`,
      {
        headers: auth.headers,
        canonicalAuth: auth.canonicalAuth,
        disableRetries: true,
        redirect: "error",
        signal,
      },
    );
    await this._expectStatus(response, [200, 304, 404]);
    if (response.status === 304 || response.status === 404) {
      return null;
    }
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      SORAFS_REPUTATION_JSON_MAX_BYTES,
      "sorafs reputation snapshot endpoint",
      { signal },
    );
    return parseSorafsReputationSnapshot(
      payload,
      "sorafs reputation snapshot endpoint",
      { expectedSnapshotId: normalizedSnapshotId },
    );
  }

  /**
   * Fetch active SoraFS reputation scoring weights.
   * Returns `null` when Torii has no snapshot yet or when `If-None-Match` returns 304.
   * @param {{ifNoneMatch?: string, headers?: Record<string, string>, canonicalAuth?: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async getSorafsReputationWeights(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "getSorafsReputationWeights",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_REPUTATION_CACHE_OPTION_KEYS,
      "getSorafsReputationWeights options",
    );
    const auth = buildSorafsReputationRequestAuth(
      rest,
      this.#config.defaultHeaders,
      "getSorafsReputationWeights",
    );
    const response = await this._request("GET", "/v1/sorafs/reputation/weights", {
      headers: auth.headers,
      canonicalAuth: auth.canonicalAuth,
      disableRetries: true,
      redirect: "error",
      signal,
    });
    await this._expectStatus(response, [200, 304, 404]);
    if (response.status === 304 || response.status === 404) {
      return null;
    }
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      SORAFS_REPUTATION_JSON_MAX_BYTES,
      "sorafs reputation weights endpoint",
      { signal },
    );
    return parseSorafsReputationWeightsResponse(
      payload,
      "sorafs reputation weights endpoint",
    );
  }

  /**
   * List SoraFS reputation snapshot events.
   * Returns `null` when `If-None-Match` returns 304.
   * @param {{since?: number | string | bigint, limit?: number | string | bigint, ifNoneMatch?: string, headers?: Record<string, string>, canonicalAuth?: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async listSorafsReputationEvents(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "listSorafsReputationEvents",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_REPUTATION_EVENT_OPTION_KEYS,
      "listSorafsReputationEvents options",
    );
    const params = buildSorafsReputationEventsParams(
      {
        since: rest.since,
        limit: rest.limit,
      },
      "listSorafsReputationEvents",
    );
    const auth = buildSorafsReputationRequestAuth(
      rest,
      this.#config.defaultHeaders,
      "listSorafsReputationEvents",
    );
    const response = await this._request("GET", "/v1/sorafs/reputation/events", {
      headers: auth.headers,
      canonicalAuth: auth.canonicalAuth,
      disableRetries: true,
      params,
      redirect: "error",
      signal,
    });
    await this._expectStatus(response, [200, 304]);
    if (response.status === 304) {
      return null;
    }
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      SORAFS_REPUTATION_JSON_MAX_BYTES,
      "sorafs reputation events endpoint",
      { signal },
    );
    return parseSorafsReputationEventPage(
      payload,
      "sorafs reputation events endpoint",
      {
        expectedSince: params?.since ?? null,
        expectedLimit: Number(
          params?.limit ?? SORAFS_REPUTATION_EVENT_DEFAULT_LIMIT_V1,
        ),
      },
    );
  }

  /**
   * Stream SoraFS reputation snapshot events via SSE.
   * The hard-cut endpoint rejects `Last-Event-ID`; use the finalized `since`
   * cursor and establish a newly authenticated request instead.
   * @param {{since?: number | string | bigint, limit?: number | string | bigint, headers?: Record<string, string>, canonicalAuth?: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {AsyncGenerator<SseEvent<Record<string, unknown>>, void, unknown>}
   */
  streamSorafsReputationEvents(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "streamSorafsReputationEvents",
    );
    assertSupportedOptionKeys(
      rest,
      SORAFS_REPUTATION_STREAM_OPTION_KEYS,
      "streamSorafsReputationEvents options",
    );
    const params = buildSorafsReputationEventsParams(
      {
        since: rest.since,
        limit: rest.limit,
      },
      "streamSorafsReputationEvents",
    );
    const auth = buildSorafsReputationRequestAuth(
      rest,
      this.#config.defaultHeaders,
      "streamSorafsReputationEvents",
      { accept: "text/event-stream" },
    );
    rejectSorafsReputationResumeHeader(
      auth.headers,
      this.#config.defaultHeaders,
      "streamSorafsReputationEvents",
    );
    const streamOptions = {
      params,
      headers: auth.headers,
      canonicalAuth: auth.canonicalAuth,
      disableRetries: true,
      redirect: "error",
      signal,
      strictUtf8: true,
    };
    return validateSorafsReputationSseStream(
      this._streamSse("/v1/sorafs/reputation/events/stream", streamOptions),
      params?.since ?? "0",
    );
  }

  _requireSorafsHedgingBillingIdentityEncoding(response, context) {
    let contentEncoding;
    try {
      contentEncoding = this._getHeader(response, "content-encoding");
    } catch (error) {
      cancelResponseBodyBestEffort(
        response,
        `${context} rejected an unreadable Content-Encoding header`,
      );
      throw error;
    }
    if (
      contentEncoding !== null &&
      contentEncoding.toLowerCase() !== "identity"
    ) {
      cancelResponseBodyBestEffort(
        response,
        `${context} rejected a transformed response body`,
      );
      rejectType(`${context} Content-Encoding must be identity`);
    }
  }

  async _getSorafsHedgingBillingJson(
    path,
    { params, canonicalAuth, signal, context },
  ) {
    const auth = buildSorafsReputationRequestAuth(
      { canonicalAuth },
      this.#config.defaultHeaders,
      context,
    );
    setHeader(auth.headers, "Accept-Encoding", "identity");
    const response = await this._request("GET", path, {
      headers: auth.headers,
      canonicalAuth: auth.canonicalAuth,
      disableRetries: true,
      params,
      redirect: "error",
      signal,
    });
    await this._expectStatus(response, [200]);
    this._requireSorafsHedgingBillingIdentityEncoding(response, context);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      SORAFS_HEDGING_BILLING_JSON_MAX_BYTES,
      context,
      { signal },
    );
    return ensureRecord(payload, `${context} response`);
  }

  /**
   * Fetch the authenticated supervised SoraFS billing-projector status.
   * @param {{canonicalAuth: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {Promise<Record<string, unknown>>}
   */
  async getSorafsBillingStatus(options) {
    const { signal, canonicalAuth } = normalizeSorafsHedgingBillingOptions(
      options,
      "getSorafsBillingStatus",
      SORAFS_HEDGING_BILLING_AUTH_OPTION_KEYS,
    );
    return this._getSorafsHedgingBillingJson("/v1/sorafs/billing/status", {
      canonicalAuth,
      context: "SoraFS billing status endpoint",
      signal,
    });
  }

  /**
   * List one exact-checkpoint page of statements owned by the authenticated account.
   * @param {{expectedCheckpointFingerprintHex: string, afterStatementIdHex?: string, limit: number, canonicalAuth: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {Promise<Record<string, unknown>>}
   */
  async listSorafsBillingStatements(options) {
    const { signal, rest, canonicalAuth } =
      normalizeSorafsHedgingBillingOptions(
        options,
        "listSorafsBillingStatements",
        SORAFS_BILLING_STATEMENT_LIST_OPTION_KEYS,
      );
    const params = {
      expected_checkpoint_fingerprint: normalizeSorafsHedgingBillingDigest(
        rest.expectedCheckpointFingerprintHex,
        "listSorafsBillingStatements.expectedCheckpointFingerprintHex",
      ),
    };
    if (
      rest.afterStatementIdHex !== undefined &&
      rest.afterStatementIdHex !== null
    ) {
      params.after_statement_id = normalizeSorafsHedgingBillingDigest(
        rest.afterStatementIdHex,
        "listSorafsBillingStatements.afterStatementIdHex",
      );
    }
    params.limit = normalizeSorafsHedgingBillingLimit(
      rest.limit,
      "listSorafsBillingStatements.limit",
    );
    return this._getSorafsHedgingBillingJson(
      "/v1/sorafs/billing/statements",
      {
        canonicalAuth,
        context: "SoraFS billing statements endpoint",
        params,
        signal,
      },
    );
  }

  /**
   * Fetch one exact owned published billing statement as canonical Norito bytes.
   * @param {string} statementIdHex
   * @param {string} expectedCheckpointFingerprintHex
   * @param {{canonicalAuth: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {Promise<Buffer>}
   */
  async getSorafsBillingStatement(
    statementIdHex,
    expectedCheckpointFingerprintHex,
    options,
  ) {
    const normalizedStatementId = normalizeSorafsHedgingBillingDigest(
      statementIdHex,
      "getSorafsBillingStatement.statementIdHex",
    );
    const normalizedCheckpoint = normalizeSorafsHedgingBillingDigest(
      expectedCheckpointFingerprintHex,
      "getSorafsBillingStatement.expectedCheckpointFingerprintHex",
    );
    const { signal, canonicalAuth } = normalizeSorafsHedgingBillingOptions(
      options,
      "getSorafsBillingStatement",
      SORAFS_HEDGING_BILLING_AUTH_OPTION_KEYS,
    );
    const context = "SoraFS billing statement endpoint";
    const auth = buildSorafsReputationRequestAuth(
      { canonicalAuth },
      this.#config.defaultHeaders,
      "getSorafsBillingStatement",
      { accept: APPLICATION_NORITO },
    );
    setHeader(auth.headers, "Accept-Encoding", "identity");
    const response = await this._request(
      "GET",
      `/v1/sorafs/billing/statements/${normalizedStatementId}`,
      {
        headers: auth.headers,
        canonicalAuth: auth.canonicalAuth,
        disableRetries: true,
        params: {
          expected_checkpoint_fingerprint: normalizedCheckpoint,
        },
        redirect: "error",
        signal,
      },
    );
    await this._expectStatus(response, [200]);
    this._requireSorafsHedgingBillingIdentityEncoding(response, context);
    let contentType;
    try {
      contentType = this._getHeader(response, "content-type");
    } catch (error) {
      cancelResponseBodyBestEffort(
        response,
        `${context} rejected an unreadable Content-Type header`,
      );
      throw error;
    }
    if (contentType !== APPLICATION_NORITO) {
      cancelResponseBodyBestEffort(
        response,
        `${context} rejected a non-Norito response body`,
      );
      rejectType(`${context} must use the application/x-norito media type`);
    }
    const { bytes } = await this._readBoundedResponseBytes(
      response,
      SORAFS_BILLING_STATEMENT_MAX_BYTES,
      context,
      { signal },
    );
    return Buffer.from(bytes);
  }

  /**
   * Submit one canonical owner acknowledgement for a published statement.
   * @param {string} statementIdHex
   * @param {string} expectedCheckpointFingerprintHex
   * @param {{requestNonceHex: string, authenticationProof: ArrayBufferView | ArrayBuffer | Buffer}} proof
   * @param {{canonicalAuth: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {Promise<Record<string, unknown>>}
   */
  async acknowledgeSorafsBillingStatement(
    statementIdHex,
    expectedCheckpointFingerprintHex,
    proof,
    options,
  ) {
    const normalizedStatementId = normalizeSorafsHedgingBillingDigest(
      statementIdHex,
      "acknowledgeSorafsBillingStatement.statementIdHex",
    );
    const normalizedCheckpoint = normalizeSorafsHedgingBillingDigest(
      expectedCheckpointFingerprintHex,
      "acknowledgeSorafsBillingStatement.expectedCheckpointFingerprintHex",
    );
    const { noritoEncodeSorafsBillingAcknowledgementProofV1 } =
      await loadToriiOptionalModule();
    const body = noritoEncodeSorafsBillingAcknowledgementProofV1(proof);
    const { signal, canonicalAuth } = normalizeSorafsHedgingBillingOptions(
      options,
      "acknowledgeSorafsBillingStatement",
      SORAFS_HEDGING_BILLING_AUTH_OPTION_KEYS,
    );
    const context = "SoraFS billing acknowledgement endpoint";
    const auth = buildSorafsReputationRequestAuth(
      { canonicalAuth },
      this.#config.defaultHeaders,
      "acknowledgeSorafsBillingStatement",
    );
    setHeader(auth.headers, "Content-Type", APPLICATION_NORITO);
    setHeader(auth.headers, "Accept-Encoding", "identity");
    const response = await this._request(
      "POST",
      `/v1/sorafs/billing/statements/${normalizedStatementId}/acknowledgements`,
      {
        body,
        canonicalAuth: auth.canonicalAuth,
        disableRetries: true,
        headers: auth.headers,
        params: {
          expected_checkpoint_fingerprint: normalizedCheckpoint,
        },
        redirect: "error",
        signal,
      },
    );
    await this._expectStatus(response, [200]);
    this._requireSorafsHedgingBillingIdentityEncoding(response, context);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      SORAFS_HEDGING_BILLING_JSON_MAX_BYTES,
      context,
      { signal },
    );
    return ensureRecord(payload, `${context} response`);
  }

  /**
   * Fetch payload-free billing delivery reconciliation status.
   * @param {{canonicalAuth: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {Promise<Record<string, unknown>>}
   */
  async getSorafsBillingReconciliation(options) {
    const { signal, canonicalAuth } = normalizeSorafsHedgingBillingOptions(
      options,
      "getSorafsBillingReconciliation",
      SORAFS_HEDGING_BILLING_AUTH_OPTION_KEYS,
    );
    return this._getSorafsHedgingBillingJson(
      "/v1/sorafs/billing/reconciliation",
      {
        canonicalAuth,
        context: "SoraFS billing reconciliation endpoint",
        signal,
      },
    );
  }

  /**
   * Fetch one exact-checkpoint page of finalized SoraFS hedging exposure.
   * @param {{expectedCheckpointFingerprintHex: string, afterHex?: string, limit: number, canonicalAuth: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {Promise<Record<string, unknown>>}
   */
  async getSorafsHedgingExposure(options) {
    return this._getSorafsHedgingProjection(
      "/v1/sorafs/hedging/exposure",
      options,
      "getSorafsHedgingExposure",
      "SoraFS hedging exposure endpoint",
    );
  }

  /**
   * Fetch one exact-checkpoint page of governed SoraFS hedge intents.
   * This read-only method cannot submit automatic hedge execution.
   * @param {{expectedCheckpointFingerprintHex: string, afterHex?: string, limit: number, canonicalAuth: CanonicalRequestAuth, signal?: AbortSignal}} options
   * @returns {Promise<Record<string, unknown>>}
   */
  async getSorafsHedgingIntents(options) {
    return this._getSorafsHedgingProjection(
      "/v1/sorafs/hedging/intents",
      options,
      "getSorafsHedgingIntents",
      "SoraFS hedging intents endpoint",
    );
  }

  async _getSorafsHedgingProjection(path, options, methodContext, responseContext) {
    const { signal, rest, canonicalAuth } =
      normalizeSorafsHedgingBillingOptions(
        options,
        methodContext,
        SORAFS_HEDGING_PROJECTION_OPTION_KEYS,
      );
    const params = {
      expected_checkpoint_fingerprint: normalizeSorafsHedgingBillingDigest(
        rest.expectedCheckpointFingerprintHex,
        `${methodContext}.expectedCheckpointFingerprintHex`,
      ),
    };
    if (rest.afterHex !== undefined && rest.afterHex !== null) {
      params.after = normalizeSorafsHedgingBillingDigest(
        rest.afterHex,
        `${methodContext}.afterHex`,
      );
    }
    params.limit = normalizeSorafsHedgingBillingLimit(
      rest.limit,
      `${methodContext}.limit`,
    );
    return this._getSorafsHedgingBillingJson(path, {
      canonicalAuth,
      context: responseContext,
      params,
      signal,
    });
  }

  /**
   * Fetch the finalized native SoraFS pin record (`GET /v1/sorafs/pin/{digest}`).
   * @param {string} digestHex Manifest digest (hex string).
   * @param {SorafsPinManifestReadOptions} [options]
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async getSorafsPinManifest(digestHex, options = {}) {
    const normalized = requireNonZeroLowerHex32String(digestHex, "digestHex");
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "getSorafsPinManifest",
    );
    assertSupportedOptionKeys(rest, new Set([
      "headers", EXPECTED_FINALIZED_HEIGHT_FIELD, EXPECTED_FINALIZED_HASH_FIELD,
    ]), "getSorafsPinManifest options");
    const expected = { digestHex: normalized };
    const hasHeight = rest.expectedFinalizedHeight !== undefined;
    const hasHash = rest.expectedFinalizedBlockHashHex !== undefined;
    if (hasHeight !== hasHash) {
      rejectType("expectedFinalizedHeight and expectedFinalizedBlockHashHex must be supplied together");
    }
    let params;
    if (hasHeight) {
      expected.height = normalizeSorafsPinU64(
        rest.expectedFinalizedHeight, EXPECTED_FINALIZED_HEIGHT_FIELD,
      );
      if (expected.height === 0) rejectType("expectedFinalizedHeight must be positive");
      expected.blockHashHex = requireNonZeroLowerHex32String(
        rest.expectedFinalizedBlockHashHex, EXPECTED_FINALIZED_HASH_FIELD,
      );
      params = {
        expected_finalized_height: String(expected.height),
        expected_finalized_block_hash_hex: expected.blockHashHex,
      };
    }
    const response = await this._request("GET", `/v1/sorafs/pin/${normalized}`, {
      headers: { Accept: APPLICATION_JSON, ...(rest.headers ?? {}) },
      params,
      signal,
    });
    await this._expectStatus(response, [200, 404]);
    if (response.status === 404) {
      return discardResponseBody(response, "sorafs pin manifest was not found", signal);
    }
    const payload = await this._readBoundedLosslessIntegerJson(
      response, JSON_RESPONSE_MAX_BYTES, "sorafs pin manifest response",
      { signal, floatingPointPaths: [["manifest", "metadata"]] },
    );
    sorafsPinDetail.normalize(payload, expected);
    return payload;
  }

  /**
   * Fetch a SoraFS pin manifest with typed output.
   * @param {string} digestHex
   * @param {SorafsPinManifestReadOptions} [options]
   * @returns {Promise<SorafsPinManifestResponse>}
   */
  async getSorafsPinManifestTyped(digestHex, options = {}) {
    const payload = await this.getSorafsPinManifest(digestHex, options);
    if (!payload) {
      rejectError("sorafs pin manifest endpoint returned 404");
    }
    return sorafsPinDetail.normalize(payload);
  }

  /**
   * Submit one exact canonical VersionedSignedTransaction V1 for SoraFS pin registration.
   * @param {ArrayBufferView | ArrayBuffer | Buffer} signedTransaction
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<Record<string, unknown>>}
   */
  async registerSorafsPinManifest(signedTransaction, options = {}) {
    const { signal } = normalizeSignalOnlyOption(
      options,
      "registerSorafsPinManifest",
    );
    if (
      !Buffer.isBuffer(signedTransaction) &&
      !ArrayBuffer.isView(signedTransaction) &&
      !(signedTransaction instanceof ArrayBuffer)
    ) {
      rejectType("signedTransaction must be a Buffer, ArrayBuffer, or ArrayBuffer view");
    }
    const rawTransaction = toBuffer(signedTransaction, "signedTransaction");
    throwIfAborted(signal);
    const body = encodeCanonicalVersionedSignedTransactionV1(
      rawTransaction,
      this._nativeRuntime,
    );
    await waitForPromiseWithSignal(this._ensureDataModelValidation(), signal);
    throwIfAborted(signal);
    const response = await this._request("POST", "/v1/sorafs/pin/register", {
      headers: {
        "Content-Type": APPLICATION_NORITO,
        Accept: APPLICATION_JSON,
      },
      body,
      disableRetries: true,
      redirect: "error",
      signal,
    });
    await this._expectStatus(response, [202]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("sorafs pin register endpoint returned no payload");
    }
    return payload;
  }

  /**
   * Submit one caller-signed SoraFS pin-registration transaction and return its admission identity.
   * @param {ArrayBufferView | ArrayBuffer | Buffer} signedTransaction
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<SorafsPinRegisterResponse>}
   */
  async registerSorafsPinManifestTyped(signedTransaction, options = {}) {
    const payload = await this.registerSorafsPinManifest(
      signedTransaction,
      options,
    );
    return normalizeSorafsPinRegisterResponse(payload);
  }

  /**
   * Fetch the latest storage state snapshot (`GET /v1/sorafs/storage/state`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<SorafsStorageStateResponse>}
   */
  async getSorafsStorageState(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getSorafsStorageState");
    const operatorSigningContext = resolveOperatorSigningContext(
      this._operatorSigningContext,
      "getSorafsStorageState operatorSigningContext",
    );
    if (operatorSigningContext === null) {
      rejectType("getSorafsStorageState requires ToriiClient options.operatorSigningContext");
    }
    const response = await this._request("GET", "/v1/sorafs/storage/state", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      operatorSigningContext,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("sorafs storage state endpoint returned no payload");
    }
    return normalizeSorafsStorageStateResponse(payload);
  }

  /**
   * Fetch a stored manifest (`GET /v1/sorafs/storage/manifest/{manifest_id_hex}`).
   * @param {string} manifestIdHex
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<SorafsManifestResponse>}
   */
  async getSorafsManifest(manifestIdHex, options = {}) {
    const normalized = requireHexString(manifestIdHex, "manifestIdHex");
    const { signal } = normalizeSignalOnlyOption(options, "getSorafsManifest");
    const response = await this._request(
      "GET",
      `/v1/sorafs/storage/manifest/${normalized}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
      },
    );
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("sorafs manifest endpoint returned no payload");
    }
    return normalizeSorafsManifestResponse(payload);
  }

  /**
   * Fetch the canonical DA manifest + chunk plan for a storage ticket (`GET /v1/da/manifests/{ticket}`).
   * @param {string} storageTicketHex
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<DaManifestFetchResponse>}
   */
  async getDaManifest(storageTicketHex, options = {}) {
    const normalizedTicket = normalizeStorageTicketHex(
      storageTicketHex,
      "storageTicketHex",
    );
    const { signal } = normalizeSignalOnlyOption(options, "getDaManifest");
    const path = `/v1/da/manifests/${normalizedTicket}`;
    const response = await this._request(
      "GET",
      path,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
      },
    );
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("da manifest endpoint returned no payload");
    }
    return normalizeDaManifestFetchResponse(payload);
  }

  /**
   * Fetch a DA manifest bundle and persist the CLI-style artefacts to disk.
   * Writes `manifest_<ticket>.norito`, `manifest_<ticket>.json`, and `chunk_plan_<ticket>.json`
   * into `options.outputDir` (defaults to `artifacts/da/fetch_<timestamp>`).
   * @param {string} storageTicketHex
   * @param {{outputDir?: string, signal?: AbortSignal, label?: string}} [options]
   * @returns {Promise<{manifest: DaManifestFetchResponse, paths: {manifestPath: string, manifestJsonPath: string, chunkPlanPath: string, label: string}, outputDir: string}>}
   */
  async getDaManifestToDir(storageTicketHex, options = {}) {
    const opts = ensureRecord(options ?? {}, "getDaManifestToDir options");
    assertSupportedOptionKeys(
      opts,
      new Set(["outputDir", "output_dir", "signal", "label", "ticketLabel", "ticket_label"]),
      "getDaManifestToDir options",
    );
    const outputDir = await resolveDaOutputDir(
      opts.outputDir ?? opts.output_dir,
      DA_FETCH_ARTIFACT_PREFIX,
    );
    const manifest = await this.getDaManifest(storageTicketHex, {
      signal: opts.signal,
    });
    const label =
      opts.label ??
      opts.ticketLabel ??
      opts.ticket_label ??
      manifest.manifest_hash_hex ??
      manifest.storage_ticket_hex;
    const paths = await persistDaManifestBundle(manifest, outputDir, label);
    return { manifest, paths, outputDir };
  }

  /**
   * Submit a DA ingest request (`POST /v1/da/ingest`).
   * Mirrors the `iroha da submit` flow so callers can push blobs without shelling out to the CLI.
   * @param {DaIngestRequestInput & {signal?: AbortSignal}} options
   * @returns {Promise<DaIngestSubmitResponse>}
   */
  async submitDaBlob(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "submitDaBlob",
    );
    const { request, artifacts } = buildDaIngestRequest(rest);
    const artifactDir = normalizeOptionalPathInput(
      rest.artifactDir ?? rest.artifact_dir,
      "submitDaBlob.artifactDir",
    );
    const noSubmit =
      rest.noSubmit === true || rest.no_submit === true || rest.dryRun === true;
    let artifactPaths = null;
    if (artifactDir) {
      artifactPaths = await persistDaRequestArtifacts(artifactDir, request);
    }
    if (noSubmit) {
      return {
        status: "prepared",
        duplicate: false,
        receipt: null,
        artifacts,
        pdpCommitmentHeader: null,
        artifactPaths,
      };
    }
    const response = await this._request("POST", "/v1/da/ingest", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(request),
      signal,
    });
    await this._expectStatus(response, [202]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("da ingest endpoint returned no payload");
    }
    const normalized = normalizeDaIngestResponse(payload);
    const pdpHeader =
      response.headers && typeof response.headers.get === JS_TYPE_FUNCTION
        ? response.headers.get(HEADER_SORA_PDP_COMMITMENT)
        : null;
    if (artifactDir) {
      artifactPaths = await persistDaReceiptArtifacts(
        artifactDir,
        normalized,
        pdpHeader,
        artifactPaths,
      );
    }
    return {
      ...normalized,
      artifacts,
      pdpCommitmentHeader: pdpHeader ?? null,
      artifactPaths,
    };
  }

  /**
   * Fetch a DA payload via the multi-source orchestrator and return the gateway summary.
   * Mirrors the `iroha da prove-availability` manifest+fetch portion.
   * @param {{
   *   storageTicketHex?: string;
   *   manifestBundle?: DaManifestFetchResponse;
   *   chunkPlan?: SorafsChunkFetchPlanV1;
   *   planJson?: string;
   *   chunkerHandle?: string;
   *   gatewayProviders: ReadonlyArray<SorafsGatewayProviderSpec>;
   *   fetchOptions?: SorafsGatewayFetchOptions;
   *   proofSummary?: boolean | { sampleCount?: number; sampleSeed?: number | bigint; leafIndexes?: ReadonlyArray<number | bigint>; };
   *   signal?: AbortSignal;
   * }} [options]
   * @returns {Promise<DaGatewayFetchSession>}
   */
  async fetchDaPayloadViaGateway(options = {}) {
    const record = ensureRecord(options ?? {}, "fetchDaPayloadViaGateway options");
    const { signal } = normalizeSignalOption(record, "fetchDaPayloadViaGateway");
    const providers = normalizeDaGatewayProviders(
      record.gatewayProviders ?? record.providers ?? record.gateway_providers,
      "fetchDaPayloadViaGateway.gatewayProviders",
    );
    let manifestBundle = record.manifestBundle ?? null;
    if (!manifestBundle) {
      const ticket =
        record.storageTicketHex ??
        record.storageTicket ??
        record.ticketHex ??
        record.ticket;
      if (!ticket) {
        throw createValidationError(
          ValidationErrorCode.INVALID_OBJECT,
          "fetchDaPayloadViaGateway.storageTicketHex is required when manifestBundle is not provided",
          "fetchDaPayloadViaGateway.storageTicketHex",
        );
      }
      manifestBundle = await this.getDaManifest(ticket, { signal });
  }
  const manifestIdSource =
    record.manifestIdHex ??
    record.manifest_id_hex ??
    manifestBundle.manifest_hash_hex;
    const manifestIdHex = normalizeHex32String(
      manifestIdSource,
      "fetchDaPayloadViaGateway.manifestIdHex",
    );

    const chunkPlanInput =
      record.planJson ??
      record.chunkPlan ??
      record.chunk_plan ??
      manifestBundle.chunk_plan;
    const { planJson, planObject } = normaliseChunkPlanPayload(
      chunkPlanInput,
      "fetchDaPayloadViaGateway.chunkPlan",
    );
    if (
      manifestBundle.blob_hash_hex !== undefined &&
      manifestBundle.blob_hash_hex !== null
    ) {
      const expectedPayloadDigest = normalizeHex32String(
        manifestBundle.blob_hash_hex,
        "fetchDaPayloadViaGateway.manifestBundle.blob_hash_hex",
      );
      if (planObject.payload_digest_blake3_hex !== expectedPayloadDigest) {
        rejectType("fetchDaPayloadViaGateway.chunkPlan payload digest must match manifestBundle.blob_hash_hex");
      }
    }

    const chunkerHandle = normaliseChunkerHandle(
      record.chunkerHandle,
      manifestBundle,
      "fetchDaPayloadViaGateway",
      this._deriveDaChunkerHandle,
    );

    const proofSummaryOptions = normalizeProofSummaryOption(
      record.proofSummary,
      "fetchDaPayloadViaGateway.proofSummary",
    );

    const fetchOptions = record.fetchOptions ?? {};
    const gatewayResult = await this._sorafsGatewayFetch(
      manifestIdHex,
      chunkerHandle,
      planJson,
      providers,
      fetchOptions,
    );

    let proofSummary = null;
    if (proofSummaryOptions) {
      const manifestBytes = extractManifestBytesForProof(
        manifestBundle,
        "fetchDaPayloadViaGateway.proofSummary",
      );
      if (!manifestBytes) {
        rejectError("fetchDaPayloadViaGateway.proofSummary requires manifestBundle.manifest_bytes or manifestBundle.manifest_b64");
      }
      const payloadBuffer = gatewayResult?.payload;
      if (!Buffer.isBuffer(payloadBuffer)) {
        rejectError("fetchDaPayloadViaGateway.proofSummary requires the gateway payload buffer; ensure sorafsGatewayFetch returned binary payloads");
      }
      proofSummary = await this._generateDaProofSummary(
        manifestBytes,
        payloadBuffer,
        proofSummaryOptions,
      );
    }

    return {
      manifest: manifestBundle,
      manifestIdHex,
      chunkerHandle,
      chunkPlan: planObject,
      chunkPlanJson: planJson,
      gatewayResult,
      proofSummary,
    };
  }

  /**
   * End-to-end DA availability check mirroring `iroha da prove-availability`.
   * Downloads the manifest bundle (unless provided), fetches the payload via the gateway,
   * and writes the artefacts (`manifest_*`, `chunk_plan_*`, `payload_*.car`, `scoreboard.json`,
   * `proof_summary_*.json`) to `options.outputDir` (defaults to `artifacts/da/prove_availability_<timestamp>`).
   * @param {{
   *   storageTicketHex?: string;
   *   manifestBundle?: DaManifestFetchResponse;
   *   gatewayProviders: ReadonlyArray<SorafsGatewayProviderSpec>;
   *   fetchOptions?: SorafsGatewayFetchOptions;
   *   proofSummary?: boolean | { sampleCount?: number; sampleSeed?: number | bigint; leafIndexes?: ReadonlyArray<number | bigint>; } | Record<string, unknown>;
   *   outputDir?: string;
   *   chunkerHandle?: string;
   *   signal?: AbortSignal;
   *   scoreboardPath?: string;
   * }} [options]
   * @returns {Promise<{
   *   manifest: DaManifestFetchResponse;
   *   manifestPaths: {manifestPath: string, manifestJsonPath: string, chunkPlanPath: string, label: string};
   *   payloadPath: string;
   *   scoreboardPath: string | null;
   *   proofSummaryPath: string | null;
   *   proofSummaryArtifact: unknown | null;
   *   proofSummary: unknown | null;
   *   gatewayResult: DaGatewayFetchResult;
   *   outputDir: string;
   * }>}
   */
  async proveDaAvailabilityToDir(options = {}) {
    const record = ensureRecord(options ?? {}, "proveDaAvailabilityToDir options");
    const outputDir = await resolveDaOutputDir(
      record.outputDir,
      DA_PROVE_ARTIFACT_PREFIX,
    );
    const providers = normalizeDaGatewayProviders(
      record.gatewayProviders,
      "proveDaAvailabilityToDir.gatewayProviders",
    );

    let manifest = record.manifestBundle ?? null;
    if (!manifest) {
      const ticket =
        record.storageTicketHex ??
        record.storageTicket ??
        record.ticketHex ??
        record.ticket;
      if (!ticket) {
        throw createValidationError(
          ValidationErrorCode.INVALID_OBJECT,
          "proveDaAvailabilityToDir.storageTicketHex is required when manifestBundle is not provided",
          "proveDaAvailabilityToDir.storageTicketHex",
        );
      }
      manifest = await this.getDaManifest(ticket, { signal: record.signal });
    }

    const label =
      record.label ??
      record.ticketLabel ??
      record.ticket_label ??
      manifest.storage_ticket_hex;
    const manifestPaths = await persistDaManifestBundle(manifest, outputDir, label);

    const fetchOptions =
      record.fetchOptions ?? {};
    const scoreboardPath =
      normalizeOptionalPathInput(
        record.scoreboardPath ??
          record.scoreboard_path ??
          fetchOptions.scoreboardOutPath ??
          fetchOptions.scoreboard_out_path,
        "proveDaAvailabilityToDir.scoreboardPath",
      ) ?? (await makeDefaultScoreboardPath(outputDir));
    const mergedFetchOptions = {
      ...fetchOptions,
      scoreboardOutPath: scoreboardPath,
    };

    const proofSummaryRequest = record.proofSummary ?? true;
    const session = await this.fetchDaPayloadViaGateway({
      manifestBundle: manifest,
      chunkerHandle: record.chunkerHandle,
      gatewayProviders: providers,
      fetchOptions: mergedFetchOptions,
      proofSummary: proofSummaryRequest,
      signal: record.signal,
    });

    const pathModule = await getPathModule();
    const payloadPath = pathModule.join(
      outputDir,
      `payload_${manifestPaths.label}.car`,
    );
    await writeBufferFile(payloadPath, session.gatewayResult.payload);

    if (scoreboardPath) {
      await writeJsonFile(
        scoreboardPath,
        session.gatewayResult.scoreboard ?? null,
      );
    }

    let proofSummaryPath = null;
    let proofSummaryArtifact = null;
    if (proofSummaryRequest !== false) {
      if (session.proofSummary === null) {
        rejectError("proveDaAvailabilityToDir requested a proof summary but none was generated");
      }
      proofSummaryPath = pathModule.join(
        outputDir,
        `proof_summary_${manifestPaths.label}.json`,
      );
      const proofResult = await emitDaProofSummaryArtifact({
        summary: session.proofSummary,
        manifestPath: manifestPaths.manifestPath,
        payloadPath,
        outputPath: proofSummaryPath,
      });
      proofSummaryArtifact = proofResult.artifact;
    }

    return {
      manifest,
      manifestPaths,
      payloadPath,
      scoreboardPath,
      proofSummaryPath,
      proofSummaryArtifact,
      proofSummary: session.proofSummary,
      gatewayResult: session.gatewayResult,
      outputDir,
    };
  }

  /**
   * Record a PoR proof submitted by a provider (`POST /v1/sorafs/capacity/por-proof`).
   * @param {{proof?: string | ArrayBuffer | ArrayBufferView | Buffer, proofB64?: string, signal?: AbortSignal}} [input]
   * @returns {Promise<SorafsPorSubmissionResponse>}
   */
  async recordSorafsPorProof(input = {}) {
    const normalizedInput = ensureRecord(
      input ?? {},
      "recordSorafsPorProof input",
    );
    const { signal } = normalizeSignalOption(
      normalizedInput,
      "recordSorafsPorProof",
    );
    const { signal: _ignored, ...record } = normalizedInput;
    assertSupportedOptionKeys(
      record,
      new Set(["proof", "proof_b64", "proofB64"]),
      "recordSorafsPorProof input",
    );
    const payload = {
      proof_b64: normalizeRequiredBase64Payload(
        record.proof ?? record.proof_b64 ?? record.proofB64,
        "recordSorafsPorProof.proof",
      ),
    };
    const response = await this._request("POST", "/v1/sorafs/capacity/por-proof", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
    });
    await this._expectStatus(response, [200]);
    const json = await this._maybeJson(response);
    if (!json) {
      rejectError("sorafs capacity por-proof endpoint returned no payload");
    }
    return normalizeSorafsPorSubmissionResponse(json, "sorafs por proof response");
  }

  /**
   * Record an audit verdict for a PoR challenge (`POST /v1/sorafs/capacity/por-verdict`).
   * @param {{verdict?: string | ArrayBuffer | ArrayBufferView | Buffer, verdictB64?: string, signal?: AbortSignal}} [input]
   * @returns {Promise<SorafsPorVerdictResponse>}
   */
  async recordSorafsPorVerdict(input = {}) {
    const normalizedInput = ensureRecord(
      input ?? {},
      "recordSorafsPorVerdict input",
    );
    const { signal } = normalizeSignalOption(
      normalizedInput,
      "recordSorafsPorVerdict",
    );
    const { signal: _ignored, ...record } = normalizedInput;
    assertSupportedOptionKeys(
      record,
      new Set(["verdict", "verdict_b64", "verdictB64"]),
      "recordSorafsPorVerdict input",
    );
    const payload = {
      verdict_b64: normalizeRequiredBase64Payload(
        record.verdict ?? record.verdict_b64 ?? record.verdictB64,
        "recordSorafsPorVerdict.verdict",
      ),
    };
    const response = await this._request("POST", "/v1/sorafs/capacity/por-verdict", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
    });
    await this._expectStatus(response, [200]);
    const json = await this._maybeJson(response);
    if (!json) {
      rejectError("sorafs capacity por-verdict endpoint returned no payload");
    }
    return normalizeSorafsPorVerdictResponse(json);
  }

  /**
   * Fetch PoR challenge status snapshots (`GET /v1/sorafs/por/status`).
   * Returns the raw Norito bytes for downstream decoding.
   * @param {SorafsPorStatusOptions} [options]
   * @returns {Promise<Buffer>}
   */
  async getSorafsPorStatus(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "getSorafsPorStatus",
    );
    const params = buildSorafsPorStatusParams(rest);
    const response = await this._request("GET", "/v1/sorafs/por/status", {
      headers: { Accept: "application/x-norito" },
      params,
      signal,
    });
    await this._expectStatus(response, [200]);
    return Buffer.from(await response.arrayBuffer());
  }

  /**
   * Export PoR challenge history (`GET /v1/sorafs/por/export`).
   * Returns Norito bytes covering the requested epoch range.
   * @param {SorafsPorExportOptions} [options]
   * @returns {Promise<Buffer>}
   */
  async exportSorafsPorStatus(options = {}) {
    const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
      options,
      "exportSorafsPorStatus",
    );
    const params = buildSorafsPorExportParams(rest);
    const response = await this._request("GET", "/v1/sorafs/por/export", {
      headers: { Accept: "application/x-norito" },
      params,
      signal,
    });
    await this._expectStatus(response, [200]);
    return Buffer.from(await response.arrayBuffer());
  }

  /**
   * Fetch the weekly PoR report (`GET /v1/sorafs/por/report/{iso_week}`).
   * Returns Norito bytes for the requested ISO week (e.g., `2026-W05`).
   * @param {SorafsIsoWeekInput} isoWeek
  * @param {{signal?: AbortSignal}} [options]
  * @returns {Promise<Buffer>}
  */
  async getSorafsPorWeeklyReport(isoWeek, options = {}) {
    const { signal } = normalizeSignalOnlyOption(
      options,
      "getSorafsPorWeeklyReport",
    );
    const label = normalizeIsoWeekLabel(
      isoWeek,
      "getSorafsPorWeeklyReport.isoWeek",
      ToriiClient,
    );
    const response = await this._request(
      "GET",
      `/v1/sorafs/por/report/${encodeURIComponent(label)}`,
      {
        headers: { Accept: "application/x-norito" },
        signal,
      },
    );
    await this._expectStatus(response, [200]);
    return Buffer.from(await response.arrayBuffer());
  }

  /**
   * Fetch aggregated holdings for a UAID (`GET /v1/accounts/{uaid}/portfolio`).
   * @param {string} uaid
   * @param {{assetId?: string, signal?: AbortSignal}} [options]
   * @returns {Promise<UaidPortfolioResponse>}
   */
  async getUaidPortfolio(uaid, options = {}) {
    const canonicalUaid = normalizeUaidLiteral(uaid, "getUaidPortfolio.uaid");
    const { signal, assetId } = normalizeUaidPortfolioOptions(
      options,
      "getUaidPortfolio",
    );
    const params = {};
    if (assetId !== undefined) {
      params.asset_id = assetId;
    }
    const response = await this._request(
      "GET",
      `/v1/accounts/${encodeURIComponent(canonicalUaid)}/portfolio`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
        params: Object.keys(params).length === 0 ? undefined : params,
      },
    );
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("uaid portfolio endpoint returned no payload");
    }
    return normalizeUaidPortfolioResponse(payload, canonicalUaid);
  }

  /**
   * Fetch UAID dataspace bindings (`GET /v1/space-directory/uaids/{uaid}`).
   * @param {string} uaid
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<UaidBindingsResponse>}
   */
  async getUaidBindings(uaid, options = {}) {
    const canonicalUaid = normalizeUaidLiteral(uaid, "getUaidBindings.uaid");
    const { signal } = normalizeSignalOnlyOption(options, "getUaidBindings");
    const response = await this._request(
      "GET",
      `/v1/space-directory/uaids/${encodeURIComponent(canonicalUaid)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
      },
    );
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("uaid bindings endpoint returned no payload");
    }
    return normalizeUaidBindingsResponse(payload, canonicalUaid);
  }

  /**
   * Publish (or rotate) a Space Directory manifest (`POST /v1/space-directory/manifests`).
   * @param {PublishSpaceDirectoryManifestRequest} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<AppApiTransactionDraft>}
   */
  async publishSpaceDirectoryManifest(request = {}, options) {
    const { signal, canonicalAuth, rest } = normalizeCanonicalApplicationPostOptions(options, "publishSpaceDirectoryManifest", ToriiClient);
    assertSupportedOptionKeys(rest, new Set([]), "publishSpaceDirectoryManifest options");
    const payload = normalizePublishSpaceDirectoryManifestRequest(request);
    payload.authority = requireCanonicalApplicationAuthority(canonicalAuth, request.authority, "publishSpaceDirectoryManifest");
    const response = await this._request("POST", "/v1/space-directory/manifests", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    return normalizeAppApiTransactionDraft(
      await this._maybeJson(response),
      "publishSpaceDirectoryManifest response",
    );
  }

  /**
   * Revoke an active Space Directory manifest (`POST /v1/space-directory/manifests/revoke`).
   * @param {RevokeSpaceDirectoryManifestRequest} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<AppApiTransactionDraft>}
   */
  async revokeSpaceDirectoryManifest(request = {}, options) {
    const { signal, canonicalAuth, rest } = normalizeCanonicalApplicationPostOptions(options, "revokeSpaceDirectoryManifest", ToriiClient);
    assertSupportedOptionKeys(rest, new Set([]), "revokeSpaceDirectoryManifest options");
    const payload = normalizeRevokeSpaceDirectoryManifestRequest(request);
    payload.authority = requireCanonicalApplicationAuthority(canonicalAuth, request.authority, "revokeSpaceDirectoryManifest");
    const response = await this._request(
      "POST",
      "/v1/space-directory/manifests/revoke",
      {
        headers: JSON_REQUEST_HEADERS,
        body: JSON.stringify(payload),
        signal,
        canonicalAuth,
      },
    );
    await this._expectStatus(response, [200]);
    return normalizeAppApiTransactionDraft(
      await this._maybeJson(response),
      "revokeSpaceDirectoryManifest response",
    );
  }

  /**
   * Submit one exact canonical VersionedSignedTransaction V1 payload.
   * Throws ToriiDataModelMismatchError when the node data model version mismatches.
   * @param {ArrayBufferView | ArrayBuffer | Buffer} payload
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<any>} Submission receipt (decoded from Norito) or JSON when present; otherwise null.
   */
  async submitTransaction(payload, options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "submitTransaction");
    throwIfAborted(signal);
    const rawPayload = toBuffer(payload);
    const pipelinePayload = encodeCanonicalVersionedSignedTransactionV1(
      rawPayload,
      this._nativeRuntime,
    );
    await waitForPromiseWithSignal(this._ensureDataModelValidation(), signal);
    throwIfAborted(signal);
    const requestOptions = {
      headers: {
        "Content-Type": "application/x-norito",
        Accept: "application/x-norito, application/json",
      },
      body: pipelinePayload,
      disableRetries: true,
      redirect: "error",
      signal,
    };
    const response = await this._request(
      "POST",
      "/v1/pipeline/transactions",
      requestOptions,
    );
    await this._expectStatus(response, [200, 201, 202, 204], { signal });
    return this._decodeTransactionIngressResponse(response, signal);
  }

  async _decodeTransactionIngressResponse(response, signal) {
    const route = this._extractSubmissionRoute(response);
    const contentType = this._getHeader(response, "content-type");
    const enrichSubmission = (value) => {
      if (!route) {
        return value;
      }
      if (value === null || value === undefined) {
        return { route };
      }
      if (typeof value === JS_TYPE_OBJECT && !Array.isArray(value)) {
        return { ...value, route };
      }
      return { value, route };
    };
    if (response.status === 204) {
      cancelResponseBodyBestEffort(
        response,
        "discarding empty transaction submission response body",
      );
      return enrichSubmission(null);
    }
    if (contentType && contentType.toLowerCase().includes("application/x-norito")) {
      const { bytes } = await this._readBoundedResponseBytes(
        response,
        PIPELINE_RECEIPT_MAX_BYTES,
        "transaction submission receipt",
        { signal },
      );
      const body = Buffer.from(bytes);
      if (body.length === 0) {
        return enrichSubmission(null);
      }
      return enrichSubmission(decodeTransactionReceiptPayload(body, this._nativeRuntime));
    }
    return enrichSubmission(
      await this._maybeBoundedJson(
        response,
        PIPELINE_RECEIPT_MAX_BYTES,
        "transaction submission receipt",
        { signal },
      ),
    );
  }

  /**
   * Submit an input-ordered batch of exact canonical VersionedSignedTransaction V1 payloads.
   * Throws ToriiDataModelMismatchError when the node data model version mismatches.
   * @param {ReadonlyArray<ArrayBufferView | ArrayBuffer | Buffer>} payloads
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<{acceptedCount: number, route?: object, outcomes?: Array<{signed_transaction_hash: string, status: number, reject_code: string | null}>}>}
   */
  async submitTransactionBatch(payloads, options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "submitTransactionBatch");
    if (!Array.isArray(payloads)) {
      rejectType("submitTransactionBatch payloads must be an array");
    }
    if (payloads.length === 0) {
      rejectType("submitTransactionBatch requires at least one payload");
    }
    const versionedPayloads = payloads.map((payload) =>
      encodeCanonicalVersionedSignedTransactionV1(
        toBuffer(payload),
        this._nativeRuntime,
      ),
    );
    throwIfAborted(signal);
    await waitForPromiseWithSignal(this._ensureDataModelValidation(), signal);
    throwIfAborted(signal);
    const batchPayload = await encodeTransactionPayloadBatch(
      versionedPayloads,
      this._nativeRuntime,
    );
    let response;
    try {
      response = await this._request(
        "POST",
        "/v1/pipeline/transactions/batch",
        {
          headers: {
            "Content-Type": "application/x-norito",
            Accept: APPLICATION_JSON,
          },
          body: batchPayload,
          disableRetries: true,
          redirect: "error",
          signal,
        },
      );
    } catch (cause) {
      throw new TransactionBatchAdmissionAmbiguousError(
        `Torii transaction batch admission response was not received for ${versionedPayloads.length} prepared transaction(s); do not resubmit until every prepared transaction hash has been reconciled.`,
        versionedPayloads.length,
        null,
        cause,
      );
    }
    await this._expectStatus(response, [202, 207], { signal });
    const acceptedHeader = this._getHeader(response, "x-iroha-transactions-accepted");
    const acceptedText = acceptedHeader == null ? "" : String(acceptedHeader);
    let acceptedCount = null;
    try {
      if (!/^(?:0|[1-9][0-9]*)$/u.test(acceptedText)) {
        rejectType("submitTransactionBatch.acceptedCount must be a canonical non-negative decimal integer");
      }
      acceptedCount = ToriiClient._normalizeUnsignedInteger(
        acceptedText,
        "submitTransactionBatch.acceptedCount",
        { allowZero: true, max: versionedPayloads.length },
      );
    } catch (cause) {
      cancelResponseBodyBestEffort(
        response,
        "discarding transaction batch response with ambiguous admission header",
      );
      throw new TransactionBatchAdmissionAmbiguousError(
        `Torii transaction batch admission returned a missing, malformed, or out-of-range x-iroha-transactions-accepted header (submitTransactionBatch.acceptedCount) for ${versionedPayloads.length} prepared transaction(s); do not resubmit until every prepared transaction hash has been reconciled.`,
        versionedPayloads.length,
        null,
        cause,
      );
    }
    if (response.status === 207) {
      try {
        const native = resolveNativeRuntimeBinding(this._nativeRuntime);
        if (typeof native.hashSignedTransaction !== JS_TYPE_FUNCTION) {
          throw new TypeError("native transaction identity computation is unavailable");
        }
        const hashes = versionedPayloads.map((payload) => Buffer.from(native.hashSignedTransaction(payload)).toString("hex"));
        const outcomes = await this._maybeBoundedJson(
          response, 1024 * 1024, "transaction batch outcomes", { signal },
        );
        if (!Array.isArray(outcomes) || outcomes.length !== versionedPayloads.length ||
            outcomes.some((entry, index) => !entry || typeof entry.signed_transaction_hash !== JS_TYPE_STRING ||
              entry.signed_transaction_hash.toLowerCase() !== hashes[index] ||
              !/^[a-fA-F0-9]{64}$/u.test(entry.signed_transaction_hash) ||
              !Number.isInteger(entry.status) ||
              !(entry.status === 202 || (entry.status >= 400 && entry.status <= 599)) ||
              !(entry.reject_code === null || typeof entry.reject_code === JS_TYPE_STRING)) ||
            outcomes.filter((entry) => entry.status === 202).length !== acceptedCount ||
            acceptedCount === versionedPayloads.length) {
          throw new TypeError("transaction batch outcome identities/statuses/count are malformed");
        }
        return { acceptedCount, outcomes };
      } catch (cause) {
        throw new TransactionBatchAdmissionAmbiguousError(
          "Torii returned invalid transaction batch outcomes; reconcile every submitted hash before retrying.",
          versionedPayloads.length, null, cause,
        );
      }
    }
    if (acceptedCount !== versionedPayloads.length) {
      cancelResponseBodyBestEffort(response, "discarding contradictory all-accepted batch response");
      throw new TransactionBatchAdmissionAmbiguousError(
        "Torii returned 202 without accepting the complete batch; reconcile every submitted hash.",
        versionedPayloads.length, acceptedCount,
      );
    }
    const route = this._extractSubmissionRoute(response);
    cancelResponseBodyBestEffort(
      response,
      "discarding transaction batch submission response body",
    );
    return route ? { acceptedCount, route } : { acceptedCount };
  }

  _extractSubmissionRoute(response) {
    const laneRaw = this._getHeader(response, "x-iroha-route-lane-id");
    const dataspaceRaw = this._getHeader(response, "x-iroha-route-dataspace-id");
    let laneId = null;
    if (laneRaw != null && String(laneRaw).trim() !== "") {
      try {
        laneId = ToriiClient._normalizeUnsignedInteger(
          laneRaw,
          "submitTransaction.route.laneId",
        );
      } catch {
        laneId = null;
      }
    }
    let dataspaceId = null;
    if (dataspaceRaw != null && String(dataspaceRaw).trim() !== "") {
      try {
        dataspaceId = ToriiClient._normalizeUnsignedInteger(
          dataspaceRaw,
          "submitTransaction.route.dataspaceId",
        );
      } catch {
        dataspaceId = null;
      }
    }
    if (laneId === null && dataspaceId === null) {
      return null;
    }
    return {
      acceptedBy: this._baseUrl,
      laneId,
      dataspaceId,
    };
  }

  async _ensureDataModelValidation(signal) {
    return ensureNodeDataModelCompatibility(this.#dataModelState, () =>
      this.getNodeCapabilities({ signal }),
    );
  }

  /**
   * Query pipeline status for a transaction hash (hex encoded).
   * @param {string} hashHex
   * @param {{
   *   signal?: AbortSignal,
   *   scope?: "local" | "global",
   * }} [options]
   * @returns {Promise<any>} Parsed JSON if present; otherwise null.
  */
  async getTransactionStatus(hashHex, options = {}) {
    const optionRecord =
      options === undefined || options === null
        ? {}
        : requirePlainObjectOption(options, "getTransactionStatus options");
    assertSupportedOptionKeys(
      optionRecord,
      GET_TX_STATUS_OPTION_KEYS,
      "getTransactionStatus options",
    );
    const scope = normalizeTransactionStatusScope(
      optionRecord.scope,
      "getTransactionStatus options.scope",
    );
    const { signal } = normalizeSignalOption(
      optionRecord,
      "getTransactionStatus",
    );
    const normalizedHash = requireCanonicalTransactionHashString(
      hashHex,
      "getTransactionStatus.hashHex",
    );
    return this._fetchTransactionStatus(normalizedHash, { signal, scope });
  }

  async _fetchTransactionStatus(normalizedHash, options = {}) {
    const { signal, scope } = options;
    const response = await this._request(
      "GET",
      "/v1/pipeline/transactions/status",
      {
        params: { hash: normalizedHash, scope },
        retryProfile: "pipeline",
        signal,
      },
    );
    if (response.status === 404) {
      cancelResponseBodyBestEffort(
        response,
        "discarding transaction status not-found response body",
      );
      return null;
    }
    await this._expectStatus(response, [200], { signal });
    const payload = await this._maybeBoundedJson(
      response,
      PIPELINE_STATUS_JSON_MAX_BYTES,
      "transaction status response",
      { signal },
    );
    return assertPipelineTransactionStatusMatchesHash(
      normalizePipelineTransactionStatus(payload),
      normalizedHash,
      "transaction status response",
    );
  }

  /**
   * Poll until global chain state reports exact state-resolved Applied finality.
   * @param {string} hashHex
   * @param {{
   *   signal?: AbortSignal,
   *   intervalMs?: number,
   *   timeoutMs?: number | null,
   *   maxAttempts?: number | null,
   *   onStatus?: (status: string | null, payload: any, attempt: number) => (void | Promise<void>)
   * }} [options]
  * @returns {Promise<any>}
  * @throws {TransactionStatusError} when the transaction reports Rejected or Expired.
  * @throws {TransactionTimeoutError} when timeout or max attempts elapse.
  */
  async waitForTransactionStatus(hashHex, options = {}) {
    const normalizedHash = requireCanonicalTransactionHashString(
      hashHex,
      "waitForTransactionStatus.hashHex",
    );
    const {
      intervalMs,
      timeoutMs,
      maxAttempts,
      signal,
      onStatus,
    } = ToriiClient._normalizeTransactionStatusPollOptions(
      options,
      "waitForTransactionStatus options",
    );

    const hasTimeout = timeoutMs !== null;
    const timeoutBudgetMs = hasTimeout ? timeoutMs : Number.POSITIVE_INFINITY;
    const deadline = hasTimeout ? Date.now() + timeoutBudgetMs : Number.POSITIVE_INFINITY;

    let attempts = 0;
    let lastPayload = null;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      throwIfAborted(signal);
      attempts += 1;
      lastPayload = await this.getTransactionStatus(normalizedHash, {
        signal,
        scope: "global",
      });
      let statusResolution = null;
      if (lastPayload !== null) {
        assertPipelineTransactionStatusMatchesHash(
          lastPayload,
          normalizedHash,
          "waitForTransactionStatus response",
        );
        statusResolution = classifyPipelineTransactionStatusResolution(
          lastPayload,
          normalizedHash,
          "waitForTransactionStatus response",
        );
      }
      const status = extractPipelineStatusKind(lastPayload);
      if (onStatus) {
        await onStatus(status, lastPayload, attempts);
      }
      throwIfAborted(signal);
      if (status !== null) {
        if (
          status === "Applied" &&
          statusResolution?.resolvedFrom === "state"
        ) {
          return lastPayload;
        }
        const isFixedFailure = status === "Rejected" || status === "Expired";
        if (isFixedFailure) {
          throw new TransactionStatusError(normalizedHash, status, lastPayload);
        }
      }

      if (maxAttempts !== null && attempts >= maxAttempts) {
        throw new TransactionTimeoutError(
          `Transaction ${normalizedHash} did not reach state-resolved Applied finality after ${attempts} attempts`,
          normalizedHash,
          attempts,
          lastPayload,
        );
      }

      if (hasTimeout && Date.now() >= deadline) {
        throw new TransactionTimeoutError(
          `Transaction ${normalizedHash} did not reach state-resolved Applied finality within ${timeoutBudgetMs}ms`,
          normalizedHash,
          attempts,
          lastPayload,
        );
      }

      if (intervalMs > 0) {
        await delay(intervalMs, signal);
      }
    }
  }

  /**
   * Submit a signed transaction and await exact state-resolved Applied finality.
   * The transaction hash is derived from the signed bytes; an optional
   * `hashHex` is checked against it before anything is sent.
   * @param {ArrayBufferView | ArrayBuffer | Buffer} payload
   * @param {{
   *   hashHex?: string,
   *   intervalMs?: number,
   *   timeoutMs?: number | null,
   *   maxAttempts?: number | null,
   *   signal?: AbortSignal,
   *   onStatus?: (status: string | null, payload: any, attempt: number) => (void | Promise<void>)
   * }} [options]
   * @returns {Promise<ToriiAppliedTransactionStatus>}
   */
  async submitTransactionAndWait(payload, options = {}) {
    const record = ToriiClient._requirePlainObject(
      options,
      "submitTransactionAndWait options",
    );
    const { hashHex, ...pollOptions } = record;
    ToriiClient._normalizeTransactionStatusPollOptions(
      pollOptions,
      "submitTransactionAndWait options",
    );
    const asserted =
      hashHex === undefined
        ? undefined
        : requireCanonicalTransactionHashString(hashHex, "options.hashHex");
    const transactionHash = this.#signedTransactionHashHex(payload);
    if (asserted !== undefined) {
      if (asserted !== transactionHash) {
        throw createValidationError(
          ValidationErrorCode.INVALID_HEX,
          `submitTransactionAndWait options.hashHex ${asserted} does not match the signed transaction hash ${transactionHash}`,
          "submitTransactionAndWait.options.hashHex",
        );
      }
    }
    await this.submitTransaction(payload, { signal: pollOptions.signal });
    return this.waitForTransactionStatus(transactionHash, pollOptions);
  }

  /** Canonical entrypoint hash of exact VersionedSignedTransaction V1 bytes. */
  #signedTransactionHashHex(payload) {
    const native = resolveNativeBinding(this._nativeRuntime);
    if (!native || typeof native.hashSignedTransaction !== JS_TYPE_FUNCTION) {
      rejectError(
        "Deriving the transaction hash requires the native hashSignedTransaction codec.",
      );
    }
    const hashHex = Buffer.from(native.hashSignedTransaction(toBuffer(payload))).toString("hex");
    return requireCanonicalTransactionHashString(hashHex, "signed transaction hash");
  }

  /**
   * Fetch the pipeline recovery sidecar for a block height (`GET /v1/pipeline/recovery/{height}`).
   * Returns null when the node has no recovery artefacts for the requested height.
   * @param {number | string | bigint} height
   * @param {{ signal?: AbortSignal }} [options]
   * @returns {Promise<any | null>}
   */
  async getPipelineRecovery(height, options = {}) {
    const normalizedHeight = ToriiClient._normalizeUnsignedInteger(height, "height", {
      allowZero: true,
    });
    const { signal } = normalizeSignalOnlyOption(options, "getPipelineRecovery");
    const response = await this._request(
      "GET",
      `/v1/pipeline/recovery/${normalizedHeight}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
        operatorSigningContext: requireOperatorSigningContext(
          this._operatorSigningContext,
          "getPipelineRecovery",
        ),
      },
    );
    if (response.status === 404) return discardResponseBody(response, "discarding 404 response body", signal);
    await this._expectStatus(response, [200], { signal });
    const payload = await this._maybeBoundedJson(
      response,
      PIPELINE_RECOVERY_JSON_MAX_BYTES,
      "pipeline recovery response",
      { signal },
    );
    if (!payload) {
      rejectError("pipeline recovery endpoint returned no payload");
    }
    return payload;
  }

  /**
   * Fetch a pipeline recovery sidecar and normalise it into typed fields.
   * @param {number | string | bigint} height
   * @param {{ signal?: AbortSignal }} [options]
   * @returns {Promise<ToriiPipelineRecoverySidecar | null>}
   */
  async getPipelineRecoveryTyped(height, options = {}) {
    const payload = await this.getPipelineRecovery(height, options);
    if (!payload) {
      return null;
    }
    return normalizePipelineRecoverySidecar(payload);
  }

  /**
   * Fetch pipeline preflight diagnostics (`GET /v1/pipeline/preflight`).
   * The body must carry exactly the fields Torii serves; the returned
   * `stallThresholdMs` is derived from `sumeragi.block_cadence_ms`
   * (twenty target block cadences) and drives `isStatusStalled`.
   * @param {{ signal?: AbortSignal }} [options]
   * @returns {Promise<ToriiPipelinePreflight>}
   */
  async getPipelinePreflight(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getPipelinePreflight");
    const response = await this._request("GET", "/v1/pipeline/preflight", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      operatorSigningContext: requireOperatorSigningContext(
        this._operatorSigningContext,
        "getPipelinePreflight",
      ),
    });
    await this._expectStatus(response, [200], { signal });
    const payload = await this._maybeBoundedJson(
      response,
      JSON_RESPONSE_MAX_BYTES,
      "pipeline preflight response",
      { signal },
    );
    if (!payload) {
      rejectError("pipeline preflight endpoint returned no payload");
    }
    return normalizePipelinePreflight(payload);
  }

  /**
   * Fetch committed FASTPQ proof batches for a block height
   * (`GET /v1/pipeline/recovery/{height}/fastpq-proofs`).
   * Returns null when the node has no recovery artefacts for the requested height.
   * @param {number | string | bigint} height
   * @param {{ signal?: AbortSignal }} [options]
   * @returns {Promise<any | null>}
   */
  async getPipelineRecoveryFastpqProofs(height, options = {}) {
    const normalizedHeight = ToriiClient._normalizeUnsignedInteger(height, "height", {
      allowZero: true,
    });
    const { signal } = normalizeSignalOnlyOption(
      options,
      "getPipelineRecoveryFastpqProofs",
    );
    const response = await this._request(
      "GET",
      `/v1/pipeline/recovery/${normalizedHeight}/fastpq-proofs`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
        operatorSigningContext: requireOperatorSigningContext(
          this._operatorSigningContext,
          "getPipelineRecoveryFastpqProofs",
        ),
      },
    );
    if (response.status === 404) return discardResponseBody(response, "discarding 404 response body", signal);
    await this._expectStatus(response, [200], { signal });
    const payload = await this._maybeBoundedJson(
      response,
      PIPELINE_FASTPQ_RECOVERY_JSON_MAX_BYTES,
      "pipeline recovery FASTPQ proofs response",
      { signal },
    );
    if (!payload) {
      rejectError("pipeline recovery FASTPQ proofs endpoint returned no payload");
    }
    return payload;
  }

  /**
   * Fetch committed FASTPQ proof batches and normalise them into typed fields.
   * @param {number | string | bigint} height
   * @param {{ signal?: AbortSignal }} [options]
   * @returns {Promise<ToriiPipelineRecoveryFastpqProofs | null>}
   */
  async getPipelineRecoveryFastpqProofsTyped(height, options = {}) {
    const payload = await this.getPipelineRecoveryFastpqProofs(height, options);
    if (!payload) {
      return null;
    }
    return normalizePipelineRecoveryFastpqProofs(payload);
  }

  /**
   * Check Torii liveness (`GET /health`, a plain-text probe such as `Healthy`).
   * @param {{ signal?: AbortSignal }} [options]
   * @returns {Promise<{status: string}>}
   */
  async getHealth(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getHealth");
    const response = await this._request("GET", "/health", {
      headers: { Accept: "text/plain" },
      signal,
    });
    await this._expectStatus(response, [200], { signal });
    const text = await this.#readBoundedText(
      response,
      PLAIN_TEXT_PROBE_MAX_BYTES,
      "health response",
      signal,
    );
    return { status: requireNonEmptyString(text.trim(), "health response") };
  }

  /**
   * Fetch Torii configuration snapshot (`GET /v1/configuration`).
   * @returns {Promise<any | null>} Parsed JSON when available, otherwise null.
   */
  async getConfiguration() {
    const response = await this._request("GET", "/v1/configuration", {
      headers: JSON_ACCEPT_HEADERS,
    });
    if (response.status === 404 || response.status === 503) {
      return null;
    }
    await this._expectStatus(response, [200]);
    return this._maybeJson(response);
  }

  /**
   * Fetch Torii configuration snapshot (`GET /v1/configuration`) with typed fields.
   * @returns {Promise<ToriiConfigurationSnapshot | null>}
   */
  async getConfigurationTyped() {
    const payload = await this.getConfiguration();
    if (payload === null) {
      return null;
    }
    return normalizeConfigurationSnapshot(payload);
  }

  /**
   * Convenience helper returning the confidential gas schedule if present.
   * @returns {Promise<{
   *   proofBase: number;
   *   perPublicInput: number;
   *   perProofByte: number;
   *   perNullifier: number;
   *   perCommitment: number;
   * } | null>}
   */
  async getConfidentialGasSchedule() {
    const config = await this.getConfiguration();
    if (!config) {
      return null;
    }
    return extractConfidentialGasConfig({ config });
  }

  /**
   * Fetch Torii status snapshot (`GET /status`) with typed governance breakdown.
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiStatusSnapshot>}
   */
  async getStatusSnapshot(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getStatusSnapshot");
    const response = await this._request("GET", "/status", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeStatusSnapshot(payload, this.#statusState);
  }

  /**
   * Submit a canonical Soracloud app-infra deployment request.
   * @param {Record<string, unknown>} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<unknown>}
   */
  async deploySoracloudAppInfra(request, options = {}) {
    return this._submitSoracloudAppInfraMutation(
      "/v1/soracloud/apps/deploy",
      request,
      options,
      "deploySoracloudAppInfra",
    );
  }

  /**
   * Submit a canonical Soracloud app-infra upgrade request.
   * @param {Record<string, unknown>} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<unknown>}
   */
  async upgradeSoracloudAppInfra(request, options = {}) {
    return this._submitSoracloudAppInfraMutation(
      "/v1/soracloud/apps/upgrade",
      request,
      options,
      "upgradeSoracloudAppInfra",
    );
  }

  /**
   * Fetch authoritative Soracloud app-infra status.
   * @param {{appName?: string, auditLimit?: number | string | bigint, signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<unknown>}
   */
  async getSoracloudAppInfraStatus(options = {}) {
    return requestSoracloudAppInfraStatus(this, options);
  }

  /**
   * Fetch authoritative Soracloud app-infra status for one app.
   * @param {string} appName
   * @param {{auditLimit?: number | string | bigint, signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<unknown>}
   */
  async getSoracloudNamedAppInfraStatus(appName, options = {}) {
    return requestSoracloudAppInfraStatus(this, options, appName);
  }

  async _submitSoracloudAppInfraMutation(path, request, options, context) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, context);
    if (request == null || typeof request !== JS_TYPE_OBJECT || Array.isArray(request)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "request must be an object",
        "request",
      );
    }
    const response = await this._request("POST", path, {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(request),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await decodeExactSoracloudJsonResponse(
      this,
      response,
      context,
      signal,
    );
    return normalizeSoracloudMutationDraftResponse(payload);
  }

  /**
   * Fetch the Network Time Service now snapshot (`GET /v1/time/now`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiNetworkTimeNow>}
   */
  async getNetworkTimeNow(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getNetworkTimeNow");
    const response = await this._request("GET", "/v1/time/now", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeTimeNowResponse(payload);
  }

  /**
   * Fetch Network Time Service diagnostics (`GET /v1/time/status`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiNetworkTimeStatus>}
   */
  async getNetworkTimeStatus(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getNetworkTimeStatus");
    const response = await this._request("GET", "/v1/time/status", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      operatorSigningContext: requireOperatorSigningContext(
        this._operatorSigningContext,
        "getNetworkTimeStatus",
      ),
    });
    await this._expectStatus(response, [200], { signal });
    const payload = await this._maybeBoundedJson(
      response,
      JSON_RESPONSE_MAX_BYTES,
      "network time status response",
      { signal },
    );
    return normalizeTimeStatusResponse(payload);
  }

  /**
   * Fetch the public node capability advert (`GET /v1/node/capabilities`).
   * The route needs no credentials and none are sent.
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiNodeCapabilities>}
   */
  async getNodeCapabilities(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getNodeCapabilities");
    const response = await this._request("GET", "/v1/node/capabilities", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      publicRequest: true,
    });
    await this._expectStatus(response, [200], { signal });
    const payload = await this._maybeBoundedJson(
      response,
      NODE_CAPABILITIES_JSON_MAX_BYTES,
      "node capabilities response",
      { signal },
    );
    return normalizeNodeCapabilitiesResponse(payload);
  }

  /** @internal Raw bounded canonical manifest transport for N-API admission. */
  async #fetchPrivacyExact12CapabilityManifestV1(options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      options,
      "getPrivacyExact12CapabilityManifestV1",
      VPN_SESSION_OPTION_KEYS,
      (auth, context) => ToriiClient.#normalizeCanonicalAuth(auth, context),
    );
    const origin = new URL(this._baseUrl);
    if (origin.protocol !== "https:" || origin.username || origin.password) {
      rejectType("Exact12 capability admission requires an HTTPS Torii origin without URL credentials");
    }
    const expectedNetworkId = networkIdBytes(
      this._localSigningContext?.networkId,
      "Exact12 capability admission LocalSigningContext.networkId",
    );
    const expectedUrl = resolveBaseRelativeUrl(this._baseUrl, "/v1/privacy/capabilities").href;
    const context = "Exact12 capability manifest response";
    const response = await this.#request("GET", "/v1/privacy/capabilities", {
      headers: { Accept: APPLICATION_NORITO, "Cache-Control": "no-store" },
      disableRetries: true,
      redirect: "error",
      cache: "no-store",
      signal, canonicalAuth,
    });
    let responseRedirected;
    let responseUrl;
    try {
      responseRedirected = responseRedirectedWithoutUserGetter(response);
      responseUrl = responseUrlWithoutUserGetter(response);
    } catch (error) {
      cancelResponseBodyBestEffort(response, `${context} rejected unreadable origin metadata`);
      throw error;
    }
    if (responseRedirected || responseUrl !== expectedUrl) {
      cancelResponseBodyBestEffort(response, `${context} rejected redirected or other-origin bytes`);
      rejectType(`${context} must come from the exact authenticated URL without redirects`);
    }
    await this.#expectStatus(response, [200], { signal });
    let contentType;
    try {
      contentType = this.#getHeader(response, "content-type");
    } catch (error) {
      cancelResponseBodyBestEffort(
        response,
        `${context} rejected an unreadable Content-Type header`,
      );
      throw error;
    }
    if (contentType !== APPLICATION_NORITO) {
      cancelResponseBodyBestEffort(response, `${context} rejected non-Norito bytes`);
      rejectType(`${context} must use exactly ${APPLICATION_NORITO}`);
    }
    const { bytes } = await this.#readBoundedResponseBytes(
      response,
      PRIVACY_EXACT12_CAPABILITY_MANIFEST_MAX_BYTES,
      context,
      { signal },
    );
    return Object.freeze({
      archive: Buffer.from(bytes),
      expectedNetworkId: Uint8Array.from(expectedNetworkId),
      origin: origin.origin,
    });
  }

  /**
   * Fetch the active ABI version (`GET /v1/runtime/abi/active`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiRuntimeAbiActiveResponse>}
   */
  async getRuntimeAbiActive(options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getRuntimeAbiActive");
    const response = await this._request("GET", "/v1/runtime/abi/active", {
      headers: JSON_ACCEPT_HEADERS,
      signal, canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeRuntimeAbiActiveResponse(payload);
  }

  /**
   * Fetch the canonical ABI hash for the active policy (`GET /v1/runtime/abi/hash`).
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ToriiRuntimeAbiHashResponse>}
   */
  async getRuntimeAbiHash(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getRuntimeAbiHash");
    const response = await this._request("GET", "/v1/runtime/abi/hash", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeRuntimeAbiHashResponse(payload);
  }

  /**
   * Fetch runtime metrics summary (`GET /v1/runtime/metrics`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiRuntimeMetrics>}
   */
  async getRuntimeMetrics(options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getRuntimeMetrics");
    const response = await this._request("GET", "/v1/runtime/metrics", {
      headers: JSON_ACCEPT_HEADERS,
      signal, canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeRuntimeMetricsResponse(payload);
  }

  /**
   * List recorded runtime upgrades (`GET /v1/runtime/upgrades`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ReadonlyArray<ToriiRuntimeUpgradeListItem>>}
   */
  async listRuntimeUpgrades(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "listRuntimeUpgrades");
    const response = await this._request("GET", "/v1/runtime/upgrades", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeRuntimeUpgradesListResponse(payload);
  }

  /**
   * Propose a runtime upgrade manifest (`POST /v1/runtime/upgrades/propose`).
   * @param {ToriiRuntimeUpgradeManifestInput} manifest
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiRuntimeUpgradeTxResponse>}
   */
  async proposeRuntimeUpgrade(manifest, options = {}) {
    const { signal } = normalizeSignalOnlyOption(
      options,
      "proposeRuntimeUpgrade",
    );
    const payload = normalizeRuntimeUpgradeManifestPayload(
      manifest,
      "proposeRuntimeUpgrade.manifest",
    );
    const response = await this._request("POST", "/v1/runtime/upgrades/propose", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
    });
    await this._expectStatus(response, [200]);
    const json = await this._maybeJson(response);
    return normalizeRuntimeUpgradeTxResponse(json, "runtime upgrade propose response");
  }

  /**
   * Build activation instructions for a runtime upgrade (`POST /v1/runtime/upgrades/activate/{id}`).
   * @param {string | BinaryLike} idHex
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiRuntimeUpgradeTxResponse>}
   */
  async activateRuntimeUpgrade(idHex, options = {}) {
    const hash = normalizeHex32String(idHex, "activateRuntimeUpgrade.idHex");
    const { signal } = normalizeSignalOnlyOption(options, "activateRuntimeUpgrade");
    const response = await this._request(
      "POST",
      `/v1/runtime/upgrades/activate/0x${hash}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
      },
    );
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeRuntimeUpgradeTxResponse(payload, "runtime upgrade activate response");
  }

  /**
   * Build cancellation instructions for a runtime upgrade (`POST /v1/runtime/upgrades/cancel/{id}`).
   * @param {string | BinaryLike} idHex
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiRuntimeUpgradeTxResponse>}
   */
  async cancelRuntimeUpgrade(idHex, options = {}) {
    const hash = normalizeHex32String(idHex, "cancelRuntimeUpgrade.idHex");
    const { signal } = normalizeSignalOnlyOption(options, "cancelRuntimeUpgrade");
    const response = await this._request(
      "POST",
      `/v1/runtime/upgrades/cancel/0x${hash}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
      },
    );
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeRuntimeUpgradeTxResponse(payload, "runtime upgrade cancel response");
  }

  /**
   * List currently online peers (`GET /v1/peers`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ReadonlyArray<Record<string, unknown>>>}
   */
  async listPeers(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "listPeers");
    const response = await this._request("GET", "/v1/peers", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      operatorSigningContext: requireOperatorSigningContext(
        this._operatorSigningContext,
        "listPeers",
      ),
    });
    await this._expectStatus(response, [200], { signal });
    return this._maybeBoundedJson(
      response,
      JSON_RESPONSE_MAX_BYTES,
      "peer list response",
      { signal },
    );
  }

  /**
   * List online peers and normalise their metadata.
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ReadonlyArray<{address: string, public_key_hex: string}>>}
   */
  async listPeersTyped(options = {}) {
    const payload = await this.listPeers(options);
    return normalizePeerListResponse(payload);
  }

  /**
   * List telemetry peer metadata (`GET /v1/telemetry/peers-info`).
  * @param {{signal?: AbortSignal}} [options]
  * @returns {Promise<ReadonlyArray<ToriiTelemetryPeerInfo>>}
  */
  async listTelemetryPeersInfo(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "listTelemetryPeersInfo", {
      allowExtras: false,
    });
    const response = await this._request("GET", "/v1/telemetry/peers-info", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("telemetry peers endpoint returned no payload");
    }
    return normalizeTelemetryPeersInfoList(payload);
  }

  /**
   * Fetch Torii explorer network metrics (`GET /v1/explorer/metrics`).
   * Returns null when telemetry outputs are disabled or gated.
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiExplorerMetricsSnapshot | null>}
   */
  async getExplorerMetrics(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getExplorerMetrics");
    const response = await this._request("GET", "/v1/explorer/metrics", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      canonicalAuth: this.#canonicalRequestAuth,
    });
    if (response.status === 403 || response.status === 404 || response.status === 503) {
      return null;
    }
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("explorer metrics endpoint returned no payload");
    }
    return normalizeExplorerMetricsResponse(payload);
  }

  /**
   * Fetch the share-ready Explorer QR payload for an account (`GET /v1/explorer/accounts/{account_id}/qr`).
   * @param {string} accountId
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiExplorerAccountQrSnapshot>}
   */
  async getExplorerAccountQr(accountId, options = {}) {
    const { signal } = normalizeExplorerRequestOptions(options);
    const normalizedId = normalizeAccountPathLiteral(accountId, "accountId");
    const response = await this._request(
      "GET",
      `/v1/explorer/accounts/${encodeURIComponent(normalizedId)}/qr`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
        canonicalAuth: this.#canonicalRequestAuth,
      },
    );
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("explorer account QR endpoint returned no payload");
    }
    return normalizeExplorerAccountQrResponse(payload, "explorer account qr response");
  }

  async _vpnRequest(method, path, options = {}) {
    const protocol = new URL(this._baseUrl).protocol.toLowerCase();
    if (protocol !== "https:") {
      rejectError("Sora VPN requests require an HTTPS Torii base URL");
    }
    return this._request(method, path, { ...options, redirect: "error" });
  }

  /**
   * Fetch the public Sora VPN profile (`GET /v1/vpn/profile`).
   * Returns null when the control plane is unavailable.
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiVpnProfile | null>}
   */
  async getVpnProfile(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getVpnProfile");
    const response = await this._vpnRequest("GET", "/v1/vpn/profile", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
    });
    if (response.status === 404 || response.status === 503) {
      return null;
    }
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("vpn profile endpoint returned no payload");
    }
    return normalizeVpnProfileResponse(payload);
  }

  /**
   * Create a signed Sora VPN quote (`POST /v1/vpn/quotes`).
   * The returned required `openLeaseInstruction` is the native
   * `OpenVpnLeaseEscrow` instruction that the wallet must submit before creating
   * the session.
   * @param {{exitClass?: string, meteringPublicKeyHex: string}} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ToriiVpnQuote>}
   */
  async createVpnQuote(request, options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      options,
      "createVpnQuote",
    );
    const response = await this._vpnRequest("POST", "/v1/vpn/quotes", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(normalizeVpnQuoteCreateRequest(request)),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [201]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("vpn quote endpoint returned no payload");
    }
    return normalizeVpnQuoteResponse(payload);
  }

  /**
   * Create a signed Sora VPN session after the quoted lease-open transaction commits
   * (`POST /v1/vpn/sessions`).
   * @param {{exitClass?: string, quoteId: string, paymentTxHash: string, meteringPublicKeyHex: string}} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ToriiVpnSession>}
   */
  async createVpnSession(request = {}, options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      options,
      "createVpnSession",
    );
    const response = await this._vpnRequest("POST", "/v1/vpn/sessions", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(normalizeVpnSessionCreateRequest(request)),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [201]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("vpn session endpoint returned no payload");
    }
    return normalizeVpnSessionResponse(payload);
  }

  /**
   * Fetch an authenticated active Sora VPN session (`GET /v1/vpn/sessions/{session_id}`).
   * Returns null when the session is already absent.
   * @param {string} sessionId canonical 16-byte session ID as hexadecimal text
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ToriiVpnSession | null>}
   */
  async getVpnSession(sessionId, options) {
    const normalizedSessionId = normalizeHex16String(sessionId, "sessionId");
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      options,
      "getVpnSession",
    );
    const response = await this._vpnRequest(
      "GET",
      `/v1/vpn/sessions/${encodeURIComponent(normalizedSessionId)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
        canonicalAuth,
      },
    );
    if (response.status === 404) {
      return null;
    }
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("vpn session status endpoint returned no payload");
    }
    return normalizeVpnSessionResponse(payload, "vpn session status response");
  }

  /**
   * Submit relay/client metering evidence for native VPN lease settlement
   * (`POST /v1/vpn/receipts`).
   * @param {{relayReceiptHex: string, clientVoucherHex: string, leaseIdHex?: string}} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ToriiVpnReceipt>}
   */
  async submitVpnReceipt(request, options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      options,
      "submitVpnReceipt",
    );
    const response = await this._vpnRequest("POST", "/v1/vpn/receipts", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(normalizeVpnReceiptSubmitRequest(request)),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [201]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("vpn receipt submit endpoint returned no payload");
    }
    return normalizeVpnReceiptResponse(payload, "vpn receipt submit response");
  }

  /**
   * Fetch canonical Sora VPN receipt history for the authenticated account (`GET /v1/vpn/receipts`).
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ToriiVpnReceiptListResponse>}
   */
  async listVpnReceipts(options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      options,
      "listVpnReceipts",
    );
    const response = await this._vpnRequest("GET", "/v1/vpn/receipts", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("vpn receipts endpoint returned no payload");
    }
    return normalizeVpnReceiptListResponse(payload);
  }

  /**
   * Fetch the suffix policy for a Sora Name Service suffix (`GET /v1/sns/policies/{suffix_id}`).
   * @param {number} suffixId
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<SnsSuffixPolicy>}
   */
  async getSnsPolicy(suffixId, options = {}) {
    const resolvedId = ToriiClient._normalizeUnsignedInteger(suffixId, "suffixId", { allowZero: true });
    if (resolvedId > 0xffff) {
      throw createValidationError(
        ValidationErrorCode.INVALID_NUMERIC,
        "suffixId must fit within a u16",
        "suffixId",
      );
    }
    const { signal } = normalizeSignalOnlyOption(options, "getSnsPolicy");
    const response = await this._request("GET", `/v1/sns/policies/${resolvedId}`, {
      headers: JSON_ACCEPT_HEADERS,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("sns policy endpoint returned no payload");
    }
    return normalizeSnsSuffixPolicy(payload);
  }

  _normalizeSnsDomainSelector(selector, context) {
    const normalizedSelector = requireExactNonEmptyString(selector, "selector");
    const dotIndex = normalizedSelector.indexOf(".");
    if (dotIndex <= 0 || dotIndex === normalizedSelector.length - 1) {
      throw createValidationError(
        ValidationErrorCode.INVALID_FIELD,
        `${context} selector must be of the form label.suffix`,
        "selector",
      );
    }
    return normalizedSelector.slice(0, dotIndex);
  }

  /**
   * Fetch a Sora Name Service registration (`GET /v1/sns/names/domain/{literal}`).
   * @param {string} selector
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<SnsNameRecord>}
   */
  async getSnsRegistration(selector, options = {}) {
    const literal = this._normalizeSnsDomainSelector(selector, "getSnsRegistration");
    const { signal } = normalizeSignalOnlyOption(
      options,
      "getSnsRegistration",
    );
    const response = await this._request(
      "GET",
      `/v1/sns/names/domain/${encodeURIComponent(literal)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
      },
    );
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("sns registration endpoint returned no payload");
    }
    return normalizeSnsNameRecord(payload, "sns registration response");
  }

  /**
   * Fetch a governance proposal (`GET /v1/gov/proposals/{id}`).
   * @param {string} proposalId
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async getGovernanceProposal(proposalId, options) {
    const normalized = requireExactLowerHex32String(proposalId, "proposalId");
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getGovernanceProposal");
    const response = await this._request(
      "GET",
      `/v1/gov/proposals/${encodeURIComponent(normalized)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal, canonicalAuth,
      },
    );
    await this._expectStatus(response, [200, 404]);
    if (response.status === 404) {
      return null;
    }
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("governance proposal endpoint returned no payload");
    }
    return payload;
  }

  /**
   * Fetch a governance proposal and normalise the payload.
   * @param {string} proposalId
   * @returns {Promise<ToriiGovernanceProposalResult>}
   */
  async getGovernanceProposalTyped(proposalId, options) {
    const payload = await this.getGovernanceProposal(proposalId, options);
    if (!payload) {
      return { found: false, proposal: null };
    }
    return parseGovernanceProposalResult(payload);
  }

  /**
   * Fetch an exact governance referendum and its required frozen context/result.
   * Unsigned integers above Number.MAX_SAFE_INTEGER are returned as bigint.
   * @param {string} referendumId
   * @returns {Promise<ToriiGovernanceReferendumResponse | null>}
   */
  async getGovernanceReferendum(referendumId, options) {
    const normalized = requireGovernanceSelectorString(referendumId, "referendumId");
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getGovernanceReferendum");
    const response = await this._request(
      "GET",
      `/v1/gov/referenda/${encodeURIComponent(normalized)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal, canonicalAuth,
      },
    );
    if (response.status === 404) {
      return null;
    }
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response, JSON_RESPONSE_MAX_BYTES, "governance referendum response", { signal },
    );
    if (!payload) {
      rejectError("governance referendum endpoint returned no payload");
    }
    return parseGovernanceReferendumResponseV1(payload);
  }

  /**
   * Fetch a referendum and normalise the payload.
   * @param {string} referendumId
   * @returns {Promise<ToriiGovernanceReferendumResult>}
   */
  async getGovernanceReferendumTyped(referendumId, options) {
    const payload = await this.getGovernanceReferendum(referendumId, options);
    if (!payload) {
      return { found: false, referendum: null };
    }
    return { found: payload.found, referendum: payload.found ? payload.referendum : null };
  }

  /**
   * Fetch exact standalone-election weights and their authoritative block coordinates.
   * Integers above Number.MAX_SAFE_INTEGER are returned as bigint.
   * @param {string} electionId
   * @returns {Promise<ToriiElectionTally | null>}
   */
  async getElectionTally(electionId, options) {
    const normalized = requireGovernanceSelectorString(electionId, "electionId");
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getElectionTally");
    const response = await this._request("POST", "/v1/zk/vote/tally", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify({ election_id: normalized }),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200, 404], {
      signal,
      maximumBodyBytes: ELECTION_TALLY_JSON_RESPONSE_MAX_BYTES,
      responseLabel: "election tally",
    });
    if (response.status === 404) {
      return null;
    }
    const payload = await this._readBoundedLosslessIntegerJson(
      response, ELECTION_TALLY_JSON_RESPONSE_MAX_BYTES, "election tally response", { signal },
    );
    return parseElectionTallyResponseV1(payload);
  }

  /**
   * Fetch exact referendum counts and their authoritative evaluated block coordinates.
   * Unsigned integers above Number.MAX_SAFE_INTEGER are returned as bigint.
   * @param {string} referendumId
   * @returns {Promise<ToriiGovernanceTally | null>}
   */
  async getGovernanceTally(referendumId, options) {
    const normalized = requireGovernanceSelectorString(referendumId, "referendumId");
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getGovernanceTally");
    const response = await this._request(
      "GET",
      `/v1/gov/tally/${encodeURIComponent(normalized)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal, canonicalAuth,
      },
    );
    await this._expectStatus(response, [200, 404]);
    if (response.status === 404) {
      return null;
    }
    const payload = await this._readBoundedLosslessIntegerJson(
      response, JSON_RESPONSE_MAX_BYTES, "governance tally response", { signal },
    );
    if (!payload) {
      rejectError("governance tally endpoint returned no payload");
    }
    return parseGovernanceTallyResponseV1(payload, normalized);
  }

  /**
   * Fetch referendum tally (`GET /v1/gov/tally/{id}`) with typed output.
   * @param {string} referendumId
   * @returns {Promise<ToriiGovernanceTallyResult>}
   */
  async getGovernanceTallyTyped(referendumId, options) {
    const normalizedId = requireGovernanceSelectorString(referendumId, "referendumId");
    const payload = await this.getGovernanceTally(normalizedId, options);
    if (!payload) {
      return createEmptyGovernanceTallyResult(normalizedId);
    }
    const tally = payload;
    return { found: true, referendum_id: tally.referendum_id, tally };
  }

  /**
   * Fetch the exact nested Core lock corpus, including required duration and custody.
   * Unsigned integers above Number.MAX_SAFE_INTEGER are returned as bigint.
   * @param {string} referendumId
   * @returns {Promise<ToriiGovernanceLocksResponse | null>}
   */
  async getGovernanceLocks(referendumId, options) {
    const normalized = requireGovernanceSelectorString(referendumId, "referendumId");
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getGovernanceLocks");
    const response = await this._request(
      "GET",
      `/v1/gov/locks/${encodeURIComponent(normalized)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal, canonicalAuth,
      },
    );
    await this._expectStatus(response, [200, 404]);
    if (response.status === 404) {
      return null;
    }
    const payload = await this._readBoundedLosslessIntegerJson(
      response, JSON_RESPONSE_MAX_BYTES, "governance locks response", { signal },
    );
    if (!payload) {
      rejectError("governance locks endpoint returned no payload");
    }
    return parseGovernanceLocksResponseV1(payload, normalized);
  }

  /**
   * Fetch referendum locks with typed output.
   * @param {string} referendumId
   * @returns {Promise<ToriiGovernanceLocksResult>}
   */
  async getGovernanceLocksTyped(referendumId, options) {
    const normalizedId = requireGovernanceSelectorString(referendumId, "referendumId");
    const payload = await this.getGovernanceLocks(normalizedId, options);
    if (!payload) {
      return createEmptyGovernanceLocksResult(normalizedId);
    }
    return { found: payload.found, referendum_id: payload.referendum_id,
      locks: payload.found ? payload.locks.locks : {} };
  }

  /**
   * Fetch unlock sweep statistics (`GET /v1/gov/unlocks/stats`).
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async getGovernanceUnlockStats(options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getGovernanceUnlockStats");
    const response = await this._request("GET", "/v1/gov/unlocks/stats", {
      headers: JSON_ACCEPT_HEADERS,
      signal, canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("governance unlock stats endpoint returned no payload");
    }
    return payload;
  }

  /**
   * Fetch unlock sweep statistics with typed output.
   * @returns {Promise<ToriiGovernanceUnlockStats>}
   */
  async getGovernanceUnlockStatsTyped(options) {
    const payload = await this.getGovernanceUnlockStats(options);
    if (!payload) {
      rejectError("governance unlock stats endpoint returned no payload");
    }
    return parseGovernanceUnlockStats(payload);
  }

  /**
   * Build one authenticated Parliament attempt-creation instruction draft.
   * The caller supplies the independently derived IDs that the response must
   * match before any payload is exposed for local signing.
   */
  async draftParliamentAttemptV1(proposal, attemptSequence, options) {
    const context = "draftParliamentAttemptV1";
    const normalizedOptions = ensureRecord(options, `${context} options`);
    assertSupportedOptionKeys(
      normalizedOptions,
      new Set([
        "signal",
        CANONICAL_AUTH_FIELD,
        "expectedProposalContentId",
        "expectedGovernanceAttemptId",
      ]),
      `${context} options`,
    );
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      {
        signal: normalizedOptions.signal,
        canonicalAuth: normalizedOptions.canonicalAuth,
      },
      context,
    );
    const {
      PARLIAMENT_ATTEMPT_DRAFT_PATH_V1,
      buildParliamentAttemptDraftRequestV1,
      normalizeParliamentAttemptDraftResponseV1,
    } = await loadToriiOptionalModule();
    const request = buildParliamentAttemptDraftRequestV1(proposal, attemptSequence);
    const response = await this._request("POST", PARLIAMENT_ATTEMPT_DRAFT_PATH_V1, {
      headers: JSON_REQUEST_HEADERS,
      body: stringifyStrictLosslessIntegerJson(request, `${context} request`),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      1024 * 1024,
      `${context} response`,
      { signal },
    );
    return normalizeParliamentAttemptDraftResponseV1(payload, {
      expectedProposalContentId: normalizedOptions.expectedProposalContentId,
      expectedGovernanceAttemptId: normalizedOptions.expectedGovernanceAttemptId,
    });
  }

  /** Fetch and strictly validate one authenticated Parliament attempt read. */
  async getParliamentAttemptV1(governanceAttemptId, options) {
    const context = "getParliamentAttemptV1";
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, context);
    const {
      PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1,
      normalizeParliamentAttemptReadResponseV1,
      parliamentAttemptReadPathV1,
    } = await loadToriiOptionalModule();
    const path = parliamentAttemptReadPathV1(governanceAttemptId);
    const response = await this._request("GET", path, {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      2 * PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1 + 2 * 1024 * 1024,
      `${context} response`,
      { signal },
    );
    return normalizeParliamentAttemptReadResponseV1(payload, governanceAttemptId);
  }

  /** Fetch one replay-validated public timed-OVN wallet preparation context. */
  async getParliamentTimedOvnCastingContextV1(ballotAttemptId, options) {
    const context = "getParliamentTimedOvnCastingContextV1";
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, context);
    const {
      PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1,
      normalizeParliamentTimedOvnCastingContextResponseV1,
      parliamentTimedOvnCastingContextReadPathV1,
    } = await loadToriiOptionalModule();
    const path = parliamentTimedOvnCastingContextReadPathV1(ballotAttemptId);
    const response = await this._request("GET", path, {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      4 * PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1,
      `${context} response`,
      { signal },
    );
    return normalizeParliamentTimedOvnCastingContextResponseV1(payload, ballotAttemptId);
  }

  /** Transport one bounded finality-bound casting-proof page for native verification. */
  async getParliamentTimedOvnCastingProofPageV1(
    ballotAttemptId,
    trustedCheckpointHeight,
    options,
  ) {
    const context = "getParliamentTimedOvnCastingProofPageV1";
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, context);
    const {
      PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_MAX_BYTES_V1,
      encodeParliamentTimedOvnCastingProofRequestV1,
      parliamentTimedOvnCastingProofPathV1,
      validateParliamentTimedOvnCastingProofResponseFrameV1,
    } = await loadToriiOptionalModule();
    const path = parliamentTimedOvnCastingProofPathV1(ballotAttemptId);
    const body = encodeParliamentTimedOvnCastingProofRequestV1(trustedCheckpointHeight);
    const response = await this._request("POST", path, {
      headers: {
        "Content-Type": APPLICATION_NORITO,
        Accept: APPLICATION_NORITO,
        "Accept-Encoding": "identity",
      },
      body,
      canonicalAuth,
      disableRetries: true,
      redirect: "error",
      signal,
    });
    await this._expectStatus(response, [200], {
      maximumBodyBytes: PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_MAX_BYTES_V1,
      responseLabel: `${context} response`,
      signal,
    });

    let contentType;
    let contentEncoding;
    try {
      contentType = this._getHeader(response, "content-type");
      contentEncoding = this._getHeader(response, "content-encoding");
    } catch (error) {
      cancelResponseBodyBestEffort(response, `${context} rejected unreadable headers`);
      throw error;
    }
    if (contentType !== APPLICATION_NORITO) {
      cancelResponseBodyBestEffort(response, `${context} rejected non-Norito bytes`);
      rejectType(`${context} must use exactly ${APPLICATION_NORITO}`);
    }
    if (contentEncoding !== null && contentEncoding.toLowerCase() !== "identity") {
      cancelResponseBodyBestEffort(response, `${context} rejected transformed bytes`);
      rejectType(`${context} Content-Encoding must be identity`);
    }
    const { bytes } = await this._readBoundedResponseBytes(
      response,
      PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_MAX_BYTES_V1,
      context,
      { signal },
    );
    return validateParliamentTimedOvnCastingProofResponseFrameV1(bytes);
  }

  /** Fetch one Core-authorized bounded public Parliament TLE release context. */
  async getParliamentTleReleaseContextV1(ballotAttemptId, options) {
    const context = "getParliamentTleReleaseContextV1";
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, context);
    const {
      normalizeParliamentTleReleaseContextResponseV1,
      parliamentTleReleaseContextReadPathV1,
    } = await loadToriiOptionalModule();
    const path = parliamentTleReleaseContextReadPathV1(ballotAttemptId);
    const response = await this._request("GET", path, {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      1024 * 1024,
      `${context} response`,
      { signal },
    );
    return normalizeParliamentTleReleaseContextResponseV1(payload, ballotAttemptId);
  }

  /** Request and strictly bind this node's proof-carrying public TLE partial. */
  async requestParliamentTlePartialReleaseV1(ballotAttemptId, options) {
    const context = "requestParliamentTlePartialReleaseV1";
    const normalizedOptions = ensureRecord(options, `${context} options`);
    assertSupportedOptionKeys(
      normalizedOptions,
      new Set([
        "signal", CANONICAL_AUTH_FIELD, "expectedKeySessionId", "expectedIdentityDigest",
        "committeeSize",
      ]),
      `${context} options`,
    );
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      {
        signal: normalizedOptions.signal,
        canonicalAuth: normalizedOptions.canonicalAuth,
      },
      context,
    );
    const {
      normalizeParliamentTlePartialReleaseShareV1,
      parliamentTlePartialReleasePathV1,
    } = await loadToriiOptionalModule();
    const path = parliamentTlePartialReleasePathV1(ballotAttemptId);
    const response = await this._request("POST", path, {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      16 * 1024,
      `${context} response`,
      { signal },
    );
    return normalizeParliamentTlePartialReleaseShareV1(payload, {
      expectedKeySessionId: normalizedOptions.expectedKeySessionId,
      expectedIdentityDigest: normalizedOptions.expectedIdentityDigest,
      committeeSize: normalizedOptions.committeeSize,
    });
  }

  /**
   * Build one authenticated public Parliament lifecycle-transition draft.
   * Automatic execution outcomes are deliberately rejected by the builder.
   */
  async draftParliamentTransitionV1(governanceAttemptId, transition, options) {
    const context = "draftParliamentTransitionV1";
    const normalizedOptions = ensureRecord(options, `${context} options`);
    assertSupportedOptionKeys(
      normalizedOptions,
      new Set(["signal", CANONICAL_AUTH_FIELD, "expectedTransitionDigest"]),
      `${context} options`,
    );
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      {
        signal: normalizedOptions.signal,
        canonicalAuth: normalizedOptions.canonicalAuth,
      },
      context,
    );
    const {
      PARLIAMENT_TRANSITION_DRAFT_PATH_V1,
      buildParliamentTransitionDraftRequestV1,
      normalizeParliamentTransitionDraftResponseV1,
    } = await loadToriiOptionalModule();
    const request = buildParliamentTransitionDraftRequestV1(
      governanceAttemptId,
      transition,
    );
    const response = await this._request("POST", PARLIAMENT_TRANSITION_DRAFT_PATH_V1, {
      headers: JSON_REQUEST_HEADERS,
      body: stringifyStrictLosslessIntegerJson(request, `${context} request`),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      1024 * 1024,
      `${context} response`,
      { signal },
    );
    return normalizeParliamentTransitionDraftResponseV1(payload, {
      expectedGovernanceAttemptId: governanceAttemptId,
      expectedTransitionKind: transition?.transition,
      expectedTransitionDigest: normalizedOptions.expectedTransitionDigest,
    });
  }

  /**
   * Draft a Ministry agenda proposal submission transaction (`POST /v1/ministry/agenda/proposals/draft`).
   * @param {{ proposal: Record<string, unknown>, authority: string }} payload
   * @returns {Promise<Record<string, unknown>>}
   */
  async draftMinistryAgendaProposal(payload, options) {
    const normalized = normalizeMinistryAgendaProposalDraftRequest(payload);
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "draftMinistryAgendaProposal");
    if (canonicalAuth.accountId !== normalized.authority) rejectType("draftMinistryAgendaProposal canonicalAuth.accountId must equal payload.authority");
    const body = stringifyStrictLosslessIntegerJson(
      normalized,
      "draftMinistryAgendaProposal request",
    );
    const response = await this._request(
      "POST",
      "/v1/ministry/agenda/proposals/draft",
      {
        headers: JSON_REQUEST_HEADERS,
        body,
        signal, canonicalAuth,
      },
    );
    await this._expectStatus(response, [200]);
    const draft = await this._maybeJson(response);
    return normalizeMinistryAgendaProposalDraftResponse(draft);
  }

  /**
   * Fetch a submitted Ministry agenda proposal record (`GET /v1/ministry/agenda/proposals/{proposal_id}`).
   * @param {string} proposalId
   * @returns {Promise<Record<string, unknown>>}
   */
  async getMinistryAgendaProposal(proposalId, options) {
    const normalizedProposalId = requireNonEmptyString(
      proposalId,
      "getMinistryAgendaProposal.proposalId",
    );
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      options,
      "getMinistryAgendaProposal",
    );
    const response = await this._request(
      "GET",
      `/v1/ministry/agenda/proposals/${encodeURIComponent(normalizedProposalId)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal, canonicalAuth,
      },
    );
    if (response.status === 404) {
      return normalizeMinistryAgendaProposalGetResponse(
        { found: false, record: null },
        "ministry agenda proposal lookup response",
      );
    }
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeMinistryAgendaProposalGetResponse(payload);
  }

  /**
   * Draft a governance deployment proposal (`POST /v1/gov/proposals/deploy-contract`).
   * @param {ToriiGovernanceDeployContractProposalRequest} payload
   * @returns {Promise<ToriiGovernanceProposalDraftResponseV1>}
   */
  async governanceProposeDeployContract(payload, options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(
      options,
      "governanceProposeDeployContract",
    );
    const normalized = normalizeGovernanceDeployContractProposalPayload(payload);
    if (canonicalAuth.accountId !== normalized.proposal_operator) {
      rejectType("governanceProposeDeployContract canonicalAuth.accountId must equal the exact proposalOperator");
    }
    const body = stringifyStrictLosslessIntegerJson(
      normalized,
      "governance deploy-contract request",
    );
    const response = await this._request("POST", "/v1/gov/proposals/deploy-contract", {
      headers: JSON_REQUEST_HEADERS,
      body,
      signal, canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const draft = await this._maybeJson(response);
    if (!draft) {
      rejectError("governance deploy-contract endpoint returned no payload");
    }
    return normalizeGovernanceProposalDraftResponseV1(
      draft,
      PROPOSE_DEPLOY_CONTRACT_WIRE_ID,
      "governance deploy-contract response",
    );
  }

  /**
   * Draft a plain governance ballot instruction (`POST /v1/gov/ballots/plain`).
   * @param {ToriiGovernancePlainBallotRequest} payload
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ToriiGovernanceBallotResponse>}
   */
  async governanceSubmitPlainBallot(payload, options) {
    const normalized = normalizeGovernancePlainBallotPayload(payload);
    const requestIdentity = normalizeGovernanceBallotIdentity(
      normalized, options, this._localSigningContext, "governanceSubmitPlainBallot",
    );
    const body = stringifyStrictLosslessIntegerJson(
      normalized,
      "governance plain-ballot request",
    );
    const response = await this._request("POST", "/v1/gov/ballots/plain", {
      headers: JSON_REQUEST_HEADERS,
      body,
      ...requestIdentity,
    });
    await this._expectStatus(response, [200]);
    const draft = await this._maybeJson(response);
    if (!draft) {
      rejectError("governance plain ballot endpoint returned no payload");
    }
    return normalizeGovernanceBallotResponse(draft, "governance plain ballot response");
  }

  /**
   * Draft a ZK ballot instruction using the v1 envelope DTO (`POST /v1/gov/ballots/zk-v1`).
   * @param {ToriiGovernanceZkBallotV1Request} payload
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ToriiGovernanceBallotResponse>}
   */
  async governanceSubmitZkBallotV1(payload, options) {
    const normalized = normalizeGovernanceZkBallotV1Payload(payload);
    const requestIdentity = normalizeGovernanceBallotIdentity(
      normalized, options, this._localSigningContext, "governanceSubmitZkBallotV1",
    );
    const body = stringifyStrictLosslessIntegerJson(
      normalized,
      "governance ZK-v1 ballot request",
    );
    const response = await this._request("POST", "/v1/gov/ballots/zk-v1", {
      headers: JSON_REQUEST_HEADERS,
      body,
      ...requestIdentity,
    });
    await this._expectStatus(response, [200]);
    const draft = await this._maybeJson(response);
    if (!draft) {
      rejectError("governance zk ballot v1 endpoint returned no payload");
    }
    return normalizeGovernanceBallotResponse(draft, "governance zk ballot v1 response");
  }

  /**
   * Draft an instruction from a BallotProof payload (`POST /v1/gov/ballots/zk-v1/ballot-proof`).
   * @param {ToriiGovernanceZkBallotProofRequest} payload
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ToriiGovernanceBallotResponse>}
   */
  async governanceSubmitZkBallotProofV1(payload, options) {
    const normalized = normalizeGovernanceZkBallotProofPayload(payload);
    const requestIdentity = normalizeGovernanceBallotIdentity(
      normalized, options, this._localSigningContext, "governanceSubmitZkBallotProofV1",
    );
    const body = stringifyStrictLosslessIntegerJson(
      normalized,
      "governance BallotProof request",
    );
    const response = await this._request("POST", "/v1/gov/ballots/zk-v1/ballot-proof", {
      headers: JSON_REQUEST_HEADERS,
      body,
      ...requestIdentity,
    });
    await this._expectStatus(response, [200]);
    const draft = await this._maybeJson(response);
    if (!draft) {
      rejectError("governance zk ballot proof endpoint returned no payload");
    }
    return normalizeGovernanceBallotResponse(
      draft,
      "governance zk ballot proof response",
    );
  }

  /**
   * Apply the `gov_protected_namespaces` parameter (`POST /v1/gov/protected-namespaces`).
   * @param {string | string[]} namespaces
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ProtectedNamespacesApplyResponse>}
   */
  async setProtectedNamespaces(namespaces, options = {}) {
    const values = normalizeProtectedNamespaceList(namespaces);
    const { signal } = normalizeSignalOnlyOption(options, "setProtectedNamespaces");
    const response = await this._request("POST", "/v1/gov/protected-namespaces", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify({ namespaces: values }),
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("protected namespaces apply endpoint returned no payload");
    }
    return normalizeProtectedNamespacesApplyResponse(payload);
  }

  /**
   * Fetch the current `gov_protected_namespaces` setting (`GET /v1/gov/protected-namespaces`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ProtectedNamespacesGetResponse>}
   */
  async getProtectedNamespaces(options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getProtectedNamespaces");
    const response = await this._request("GET", "/v1/gov/protected-namespaces", {
      headers: JSON_ACCEPT_HEADERS,
      signal, canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("protected namespaces endpoint returned no payload");
    }
    return normalizeProtectedNamespacesGetResponse(payload);
  }

  /**
   * Fetch Sumeragi consensus status (`GET /v1/sumeragi/status`).
   * JSON is the native protocol-1 observation; it is not a finality proof.
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<any>}
   */

  async getSumeragiStatus(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getSumeragiStatus");
    const response = await this._request("GET", "/v1/sumeragi/status", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      operatorSigningContext: requireOperatorSigningContext(
        this._operatorSigningContext,
        "getSumeragiStatus",
      ),
    });
    await this._expectStatus(response, [200]);
    return this._maybeJson(response);
  }

  /**
   * Fetch and fail-closed validate the native protocol-1 status.
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiSumeragiStatus>}
   */
  async getSumeragiStatusTyped(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getSumeragiStatusTyped");
    const response = await this._request("GET", "/v1/sumeragi/status", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      operatorSigningContext: requireOperatorSigningContext(
        this._operatorSigningContext,
        "getSumeragiStatusTyped",
      ),
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      SUMERAGI_STATUS_TYPED_JSON_MAX_BYTES,
      "Sumeragi typed status",
      { signal },
    );
    const { parseSumeragiStatusPayload } = await import("./sumeragiTyped.js");
    return parseSumeragiStatusPayload(payload);
  }

  /**
   * Fetch and fail-closed validate every lane of the committed global-chain state with the
   * status of this node's instance of it (`GET /v1/sumeragi/lanes`). Lane statuses are
   * observations, not finality proofs.
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ReadonlyArray<ToriiSumeragiLaneStatus>>}
   */
  async getSumeragiLanes(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getSumeragiLanes");
    const response = await this._request("GET", "/v1/sumeragi/lanes", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      operatorSigningContext: requireOperatorSigningContext(
        this._operatorSigningContext,
        "getSumeragiLanes",
      ),
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      SUMERAGI_LANES_TYPED_JSON_MAX_BYTES,
      "Sumeragi lanes",
      { signal },
    );
    const { parseSumeragiLanesPayload } = await import("./sumeragiTyped.js");
    return parseSumeragiLanesPayload(payload);
  }

  /**
   * Fetch network→BLS key mapping (`GET /v1/sumeragi/bls-keys`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<Record<string, string | null>>}
   */
  async getSumeragiBlsKeys(options = {}) {
    const { signal } = normalizeSignalOnlyOption(
      options,
      "getSumeragiBlsKeys",
    );
    const response = await this._request("GET", "/v1/sumeragi/bls-keys", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      operatorSigningContext: requireOperatorSigningContext(
        this._operatorSigningContext,
        "getSumeragiBlsKeys",
      ),
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("sumeragi BLS keys endpoint returned no payload");
    }
    return normalizeSumeragiBlsKeysMap(payload);
  }

  /**
   * Fetch the on-chain Sumeragi parameter snapshot (`GET /v1/sumeragi/params`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiSumeragiParamsSnapshot>}
   */
  async getSumeragiParams(options = {}) {
    const { signal } = normalizeSignalOnlyOption(
      options,
      "getSumeragiParams",
    );
    const response = await this._request("GET", "/v1/sumeragi/params", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      operatorSigningContext: requireOperatorSigningContext(
        this._operatorSigningContext,
        "getSumeragiParams",
      ),
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("sumeragi params endpoint returned no payload");
    }
   return normalizeSumeragiParamsSnapshot(payload);
  }

  /**
   * List committed consensus evidence (`GET /v1/sumeragi/evidence`).
   * @param {SumeragiEvidenceListOptions} [options]
   * @returns {Promise<SumeragiEvidenceListResponse>}
    */
  async listSumeragiEvidence(options = {}) {
    const resolvedOptions =
      options === undefined || options === null
        ? {}
        : requirePlainObjectOption(options, "listSumeragiEvidence options");
    assertSupportedOptionKeys(
      resolvedOptions,
      new Set(["limit", "offset", "kind", "signal"]),
      "listSumeragiEvidence options",
    );
    const { signal } = normalizeSignalOption(resolvedOptions, "listSumeragiEvidence");
    const params = {};
    if (resolvedOptions.limit !== undefined && resolvedOptions.limit !== null) {
      const limit = ToriiClient._normalizeUnsignedInteger(resolvedOptions.limit, "limit", {
        allowZero: false,
      });
      if (limit > 1000) {
        rejectRange("limit must be <= 1000");
      }
      params.limit = limit;
    }
    if (resolvedOptions.offset !== undefined && resolvedOptions.offset !== null) {
      const offset = ToriiClient._normalizeUnsignedInteger(resolvedOptions.offset, "offset", {
        allowZero: true,
      });
      if (offset > 10000) {
        rejectRange("offset must be <= 10000");
      }
      params.offset = offset;
    }
    if (resolvedOptions.kind !== undefined && resolvedOptions.kind !== null) {
      const kind = requireExactNonEmptyString(resolvedOptions.kind, "kind");
      if (kind !== EVIDENCE_KIND) {
        rejectRange(`kind must be ${EVIDENCE_KIND}`);
      }
      params.kind = kind;
    }
    const response = await this._request("GET", "/v1/sumeragi/evidence", {
      headers: JSON_ACCEPT_HEADERS,
      params: Object.keys(params).length > 0 ? params : undefined,
      signal,
      operatorSigningContext: requireOperatorSigningContext(
        this._operatorSigningContext,
        "listSumeragiEvidence",
      ),
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      SUMERAGI_EVIDENCE_LIST_JSON_RESPONSE_MAX_BYTES,
      "Sumeragi evidence list response",
      { signal },
    );
    return normalizeSumeragiEvidenceListResponse(
      payload,
      params.limit ?? 50,
      params.offset ?? 0,
    );
  }

  /**
   * Retrieve the total number of evidence entries (`GET /v1/sumeragi/evidence/count`).
   * @returns {Promise<SumeragiEvidenceCountResponse>}
   */
  async getSumeragiEvidenceCount() {
    const response = await this._request("GET", "/v1/sumeragi/evidence/count", {
      headers: JSON_ACCEPT_HEADERS,
      operatorSigningContext: requireOperatorSigningContext(this._operatorSigningContext, "getSumeragiEvidenceCount"),
    });
    await this._expectStatus(response, [200]);
    const payload = ensureRecord(
      await this._readBoundedLosslessIntegerJson(
        response,
        SUMERAGI_EVIDENCE_COUNT_JSON_RESPONSE_MAX_BYTES,
        "Sumeragi evidence count response",
      ),
      "sumeragi evidence count response",
    );
    assertExactSumeragiEvidenceFields(
      payload,
      "sumeragi evidence count response",
      ["count"],
    );
    return {
      count: requireSumeragiEvidenceUnsigned(
        payload.count,
        "sumeragi evidence count response.count",
      ),
    };
  }

  /**
   * Fetch Prometheus metrics (`GET /metrics`, text exposition format).
   * @param {{ signal?: AbortSignal }} [options]
   * @returns {Promise<string>}
   */
  async getMetrics(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getMetrics");
    const response = await this._request("GET", "/metrics", {
      headers: { Accept: "text/plain" },
      signal,
    });
    await this._expectStatus(response, [200], { signal });
    return this.#readBoundedText(response, METRICS_TEXT_MAX_BYTES, "metrics response", signal);
  }

  async #readBoundedText(response, maxBytes, context, signal) {
    const { bytes } = await this.#readBoundedResponseBytes(response, maxBytes, context, {
      signal,
    });
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (error) {
      rejectType(`${context} must be valid UTF-8`, { cause: error });
    }
  }

  /**
   * Fetch the exact canonical result-bearing SignedBlockWire at a finalized height.
   * @param {number | string | bigint} height
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<Buffer>}
   */
  async getLedgerExecutedBlockWire(height, options = {}) {
    const normalizedHeight = normalizeUint64DecimalString(
      height,
      "getLedgerExecutedBlockWire.height",
      { allowZero: false },
    );
    const { signal } = normalizeSignalOnlyOption(
      options,
      "getLedgerExecutedBlockWire",
    );
    const context = "executed block wire endpoint";
    const response = await this._request(
      "GET",
      `/v1/ledger/block/${normalizedHeight}`,
      {
        headers: { Accept: APPLICATION_NORITO },
        signal,
      },
    );
    await this._expectStatus(response, [200]);
    let contentType;
    try {
      contentType = this._getHeader(response, "content-type");
    } catch (error) {
      cancelResponseBodyBestEffort(
        response,
        `${context} rejected an unreadable Content-Type header`,
      );
      throw error;
    }
    if (contentType !== APPLICATION_NORITO) {
      cancelResponseBodyBestEffort(
        response,
        `${context} rejected a non-Norito response body`,
      );
      rejectType(`${context} must use the application/x-norito media type`);
    }
    const declaredLength = this._getHeader(response, "content-length");
    const { bytes } = await this._readBoundedResponseBytes(
      response,
      AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1,
      context,
      { signal },
    );
    if (declaredLength !== null && Number(declaredLength) !== bytes.byteLength) {
      rejectType(`${context} Content-Length does not match the response body`);
    }
    if (bytes.byteLength === 0) {
      rejectType(`${context} must not be empty`);
    }
    return Buffer.from(bytes);
  }

  /**
   * Fetch an Explorer block by height or hash (`GET /v1/explorer/blocks/{identifier}`).
   * @param {number | string | bigint} identifier
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<any>}
   */
  async getBlock(identifier, options = {}) {
    const normalized = requireNonEmptyString(String(identifier), "getBlock.identifier");
    const { signal } = normalizeSignalOnlyOption(options, "getBlock");
    const response = await this._request("GET", `/v1/explorer/blocks/${encodeURIComponent(normalized)}`, {
      signal,
      headers: JSON_ACCEPT_HEADERS,
      canonicalAuth: this.#canonicalRequestAuth,
    });
    if (response.status === 404) {
      return null;
    }
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("explorer block endpoint returned no payload");
    }
    return normalizeExplorerBlockRecord(payload, "explorer block response");
  }


  /**
   * Stream JSON events from `/v1/events/sse`. `options.filter` uses the
   * collection-query text grammar over event fields (`tx_hash`, `tx_status`,
   * `tx_block_height`, `block_height`, `proof_backend`, ...): pass a `Filter`
   * built with `field()`, a text filter such as
   * `tx_status in ["Approved", "Rejected"]`, or the JSON form. Each payload
   * frame's `data` is one JSON object with `category` and `event`; integers
   * beyond `Number.MAX_SAFE_INTEGER` are `bigint`. A terminal
   * `event: stream_error` frame is yielded before the stream ends.
   * @template [T=unknown]
   * @param {EventStreamOptions} [options]
   * @returns {AsyncGenerator<SseEvent<T>, void, unknown>}
   */
  streamEvents(options) {
    const { signal } = normalizeEventStreamOptions(
      options,
      "streamEvents",
      ["filter"],
      false,
    );
    const params = {};
    const filter = filterQueryText(
      options && typeof options === JS_TYPE_OBJECT ? options.filter : undefined,
    );
    if (filter !== undefined) {
      params.filter = filter;
    }
    return decodeEventFrames(
      this._streamSse("/v1/events/sse", {
        params: Object.keys(params).length > 0 ? params : undefined,
        signal,
        canonicalAuth: this.#canonicalRequestAuth,
      }),
      "The event stream",
    );
  }

  /**
   * Stream generic contract events from `/v1/contracts/events/sse`.
   * @template [T=unknown]
   * @param {ContractEventStreamOptions} [options]
   * @returns {AsyncGenerator<SseEvent<T>, void, unknown>}
   */
  streamContractEvents(options = {}) {
    const { signal } = normalizeEventStreamOptions(
      options,
      "streamContractEvents",
      [
        "authority",
        "contractAddress",
        "contractAlias",
        "module",
        "eventKind",
        "participant",
        "assetId",
        "provenance",
        "sinceTimestampMs",
        "untilTimestampMs",
        "resultOk",
      ],
      false,
    );
    const params = {};
    if (options && typeof options === JS_TYPE_OBJECT) {
      if (options.authority !== undefined && options.authority !== null) {
        params.authority = ToriiClient._normalizeAccountId(options.authority, "authority");
      }
      if (options.contractAddress !== undefined && options.contractAddress !== null) {
        params.contract_address = requireExactNonEmptyString(
          options.contractAddress,
          "contractAddress",
        );
      }
      if (options.contractAlias !== undefined && options.contractAlias !== null) {
        params.contract_alias = requireExactNonEmptyString(options.contractAlias, "contractAlias");
      }
      if (options.module !== undefined && options.module !== null) {
        params.module = requireNonEmptyString(options.module, "module");
      }
      if (options.eventKind !== undefined && options.eventKind !== null) {
        params.event_kind = requireNonEmptyString(options.eventKind, "eventKind");
      }
      if (options.participant !== undefined && options.participant !== null) {
        params.participant = requireExactNonEmptyString(options.participant, "participant");
      }
      if (options.assetId !== undefined && options.assetId !== null) {
        params.asset_id = requireExactNonEmptyString(options.assetId, "assetId");
      }
      if (options.provenance !== undefined && options.provenance !== null) {
        params.provenance = requireNonEmptyString(options.provenance, "provenance");
      }
      if (options.sinceTimestampMs !== undefined && options.sinceTimestampMs !== null) {
        params.since_timestamp_ms = ToriiClient._normalizeUnsignedInteger(
          options.sinceTimestampMs,
          "sinceTimestampMs",
          { allowZero: true },
        );
      }
      if (options.untilTimestampMs !== undefined && options.untilTimestampMs !== null) {
        params.until_timestamp_ms = ToriiClient._normalizeUnsignedInteger(
          options.untilTimestampMs,
          "untilTimestampMs",
          { allowZero: true },
        );
      }
      if (options.resultOk !== undefined && options.resultOk !== null) {
        params.result_ok = requireBooleanLike(options.resultOk, "resultOk");
      }
    }
    return this._streamSse("/v1/contracts/events/sse", {
      params: Object.keys(params).length > 0 ? params : undefined,
      signal,
      canonicalAuth: this.#canonicalRequestAuth,
    });
  }

  /**
   * Stream Sumeragi status events (`/v1/sumeragi/status/sse`).
   * @template [T=unknown]
   * @param {Omit<EventStreamOptions, "filter">} [options]
   * @returns {AsyncGenerator<SseEvent<T>, void, unknown>}
   */
  streamSumeragiStatus(options) {
    const { signal, lastEventId } = normalizeEventStreamOptions(
      options,
      "streamSumeragiStatus",
    );
    const operatorSigningContext = requireOperatorSigningContext(
      this._operatorSigningContext,
      "streamSumeragiStatus",
    );
    return this._streamSse("/v1/sumeragi/status/sse", {
      lastEventId,
      signal,
      operatorSigningContext,
      disableRetries: true,
      redirect: "error",
    });
  }

  /**
   * Fetch the current Kaigi call view (`GET /v1/kaigi/calls/{call_id}`).
   * @param {string} callId
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<KaigiCallView | null>}
   */
  async getKaigiCall(callId, options = {}) {
    const normalizedCallId = requireExactNonEmptyString(callId, "callId");
    const { signal } = normalizeSignalOnlyOption(options, "getKaigiCall");
    const response = await this._request(
      "GET",
      `/v1/kaigi/calls/${encodeURIComponent(normalizedCallId)}`,
      { headers: JSON_ACCEPT_HEADERS, signal },
    );
    if (response.status === 404) {
      return null;
    }
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      JSON_RESPONSE_MAX_BYTES,
      "kaigi call endpoint",
      { signal },
    );
    return normalizeKaigiCallView(payload, normalizedCallId);
  }

  /**
   * Fetch committed Kaigi signal metadata for a call (`GET /v1/kaigi/calls/{call_id}/signals`).
   * @param {string} callId
   * @param {KaigiCallSignalsOptions} [options]
   * @returns {Promise<KaigiCallSignalsList>}
   */
  async listKaigiCallSignals(callId, options = {}) {
    const normalizedCallId = requireExactNonEmptyString(callId, "callId");
    const {
      signal,
      params,
      canonicalAuth: requestedCanonicalAuth,
    } = buildKaigiCallSignalsQuery(options);
    const canonicalAuth = ToriiClient._normalizeCanonicalAuth(
      requestedCanonicalAuth === undefined
        ? this.#canonicalRequestAuth
        : requestedCanonicalAuth,
      "listKaigiCallSignals.canonicalAuth",
    );
    if (!canonicalAuth) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "listKaigiCallSignals canonicalAuth is required when the client has no canonicalRequestAuth",
        "listKaigiCallSignals.canonicalAuth",
      );
    }
    const response = await this._request(
      "GET",
      `/v1/kaigi/calls/${encodeURIComponent(normalizedCallId)}/signals`,
      {
        headers: JSON_ACCEPT_HEADERS,
        params,
        signal,
        canonicalAuth,
      },
    );
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      JSON_RESPONSE_MAX_BYTES,
      "kaigi call signals endpoint",
      { signal },
    );
    return normalizeKaigiCallSignalsList(payload, normalizedCallId);
  }

  /**
   * Stream Kaigi call lifecycle updates (`/v1/kaigi/calls/{call_id}/events`).
   * @param {string} callId
   * @param {KaigiCallEventsOptions} [options]
   * @returns {AsyncGenerator<SseEvent<KaigiCallEventPayload>, void, unknown>}
   */
  streamKaigiCallEvents(callId, options) {
    const normalizedCallId = requireExactNonEmptyString(callId, "callId");
    const { signal, lastEventId } = normalizeEventStreamOptions(
      options,
      "streamKaigiCallEvents",
      ["kind"],
    );
    const params = buildKaigiCallEventParams(options);
    const iterator = this._streamSse(
      `/v1/kaigi/calls/${encodeURIComponent(normalizedCallId)}/events`,
      {
        params,
        lastEventId,
        signal,
      },
    );
    return (async function* mapEvents() {
      for await (const event of iterator) {
        const data = normalizeKaigiCallEventData(
          parseKaigiSseEventPayload(event, "kaigi call event"),
          normalizedCallId,
        );
        yield {
          ...event,
          data,
        };
      }
    })();
  }

  /**
   * Fetch operator-authenticated Kaigi relay summaries (`GET /v1/kaigi/relays`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<KaigiRelaySummaryList>}
   */
  async listKaigiRelays(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "listKaigiRelays");
    const response = await this._request("GET", "/v1/kaigi/relays", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      operatorSigningContext: requireOperatorSigningContext(this._operatorSigningContext, "listKaigiRelays"),
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      JSON_RESPONSE_MAX_BYTES,
      "kaigi relay list endpoint",
      { signal },
    );
    return normalizeKaigiRelaySummaryList(payload);
  }

  /**
   * Fetch operator-authenticated metadata for a Kaigi relay (`GET /v1/kaigi/relays/{relay_id}`).
   * @param {string} relayId
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<KaigiRelayDetail | null>}
   */
  async getKaigiRelay(relayId, options = {}) {
    const normalizedRelay = ToriiClient._requireAccountId(relayId, "relayId");
    const { signal } = normalizeSignalOnlyOption(options, "getKaigiRelay");
    const response = await this._request(
      "GET",
      `/v1/kaigi/relays/${encodeURIComponent(normalizedRelay)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
        operatorSigningContext: requireOperatorSigningContext(this._operatorSigningContext, "getKaigiRelay"),
      },
    );
    if (response.status === 404) {
      return null;
    }
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      JSON_RESPONSE_MAX_BYTES,
      "kaigi relay detail endpoint",
      { signal },
    );
    return normalizeKaigiRelayDetail(payload);
  }

  /**
   * Fetch operator-authenticated aggregate Kaigi relay health metrics.
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<KaigiRelayHealthSnapshot>}
   */
  async getKaigiRelaysHealth(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getKaigiRelaysHealth");
    const response = await this._request("GET", "/v1/kaigi/relays/health", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
      operatorSigningContext: requireOperatorSigningContext(this._operatorSigningContext, "getKaigiRelaysHealth"),
    });
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      JSON_RESPONSE_MAX_BYTES,
      "kaigi relay health endpoint",
      { signal },
    );
    return normalizeKaigiRelayHealthSnapshot(payload);
  }

  /**
   * Stream Kaigi relay registration/health updates (`/v1/kaigi/relays/events`).
   * @param {KaigiRelayEventsOptions} [options]
   * @returns {AsyncGenerator<SseEvent<KaigiRelayEventPayload>, void, unknown>}
   */
  streamKaigiRelayEvents(options) {
    const { signal, lastEventId } = normalizeEventStreamOptions(
      options,
      "streamKaigiRelayEvents",
      ["domain", "relay", "kind"],
    );
    const params = buildKaigiRelayEventParams(options);
    const iterator = this._streamSse("/v1/kaigi/relays/events", {
      params,
      lastEventId,
      signal,
    });
    return (async function* mapEvents() {
      for await (const event of iterator) {
        const data = normalizeKaigiRelayEventData(
          parseKaigiSseEventPayload(event, "kaigi relay event"),
        );
        yield {
          ...event,
          data,
        };
      }
    })();
  }

  /**
   * List prover reports with optional filters.
   * @param {Record<string, unknown>} filters
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ReadonlyArray<ToriiProverReport>>}
   * @throws When the server projection omits report fields (e.g. `ids_only=true`).
   */
  async listProverReports(filters = {}, options = {}) {
    const normalizedFilters = ToriiClient._encodeProverFilters(filters);
    const { signal } = normalizeSignalOnlyOption(options, "listProverReports");
    const response = await this._request("GET", "/v1/zk/prover/reports", {
      params: normalizedFilters,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeProverReportList(payload, normalizedFilters, "prover reports response");
  }

  /**
   * Iterate prover reports with offset-based pagination and typed projections.
   * @param {ToriiProverReportFilters} [filters]
   * @param {PaginationIteratorOptions & {signal?: AbortSignal}} [options]
   * @returns {AsyncGenerator<ToriiProverReport | string | ToriiProverReportMessageSummary, void, unknown>}
   */
  iterateProverReports(filters = {}, options = {}) {
    const fetchPage = async (pageOptions = {}) => {
      const { signal, ...rest } = pageOptions ?? {};
      const pageFilters = { ...filters, ...rest };
      const result = await this.listProverReports(pageFilters, { signal });
      if (result.kind === "ids") {
        return { items: result.ids ?? [] };
      }
      if (result.kind === "messages") {
        return { items: result.messages ?? [] };
      }
      return { items: result.reports ?? [] };
    };
    return this._iterateOffsetIterable(
      fetchPage,
      options,
      PROVER_REPORT_ITERATOR_OPTION_KEYS,
    );
  }

  /**
   * Fetch operator-only Connect aggregate status (`GET /v1/connect/status/aggregate`).
   * Requires the immutable exact-network operator signing context configured on this client.
   * Returns null when Connect is disabled on the node.
   * @returns {Promise<any | null>}
   */
  async getConnectStatus() {
    const response = await this._request("GET", "/v1/connect/status/aggregate", {
      headers: JSON_ACCEPT_HEADERS,
      operatorSigningContext: requireOperatorSigningContext(this._operatorSigningContext, "getConnectStatusAggregate"),
    });
    if (response.status === 404) {
      return null;
    }
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("connect status response missing JSON body");
    }
    return normalizeConnectStatusSnapshot(payload, "connect status response");
  }

  /**
   * Create a Connect session and retrieve deeplink URIs (`POST /v1/connect/session`).
   * @param {{ sid: string; networkId: import("./networkId.js").NetworkId; appPublicKey: Uint8Array; nonce: Uint8Array; node?: string | null }} input
   * @returns {Promise<ConnectSessionResponse>}
   */
  async createConnectSession(input) {
    if (!input || typeof input !== JS_TYPE_OBJECT) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "createConnectSession input must be an object",
        "createConnectSession.input",
      );
    }
    const appPublicKey = normalizeBytes(input.appPublicKey);
    const nonce = normalizeBytes(input.nonce);
    if (appPublicKey.length !== 32 || nonce.length !== 16) {
      rejectType("Connect appPublicKey and nonce must be exactly 32 and 16 bytes");
    }
    networkIdBytes(input.networkId, "networkId");
    const sid = normalizeConnectSid(input.sid, "sid");
    const expectedSid = generateConnectSid({
      networkId: input.networkId,
      appPublicKey,
      nonce,
    }).sidBase64Url;
    if (sid !== expectedSid) {
      rejectType("Connect sid must bind the exact networkId, appPublicKey, and nonce");
    }
    const payload = {
      sid,
      network_id: input.networkId.toString(),
      app_pk: Buffer.from(appPublicKey).toString("base64url"),
      nonce: Buffer.from(nonce).toString("base64url"),
    };
    if (input.node !== undefined && input.node !== null) {
      payload.node = requireNonEmptyString(input.node, "node");
    }
    const response = await this._request("POST", "/v1/connect/session", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
    });
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("connect session response missing JSON body");
    }
    const session = normalizeConnectSessionResponse(body, "connect session response");
    validateConnectSessionResponseIdentity(session, {
      sid: payload.sid,
      networkId: payload.network_id,
      appPk: payload.app_pk,
      nonce: payload.nonce,
      node: payload.node,
    });
    return session;
  }

  /**
   * Delete a Connect session (`DELETE /v1/connect/session/{sid}`).
   * @param {{sid:string, tokenManagement?:string, token_management?:string}} sid
   * @returns {Promise<boolean>} True when the session existed.
   */
  async deleteConnectSession(sid) {
    const input = typeof sid === JS_TYPE_OBJECT && sid !== null ? sid : { sid };
    const normalizedSid = normalizeConnectSid(input.sid, "sid");
    const tokenManagement = requireNonEmptyString(
      input.tokenManagement ?? input.token_management,
      "tokenManagement",
    );
    const response = await this._request(
      "DELETE",
      `/v1/connect/session/${encodeURIComponent(normalizedSid)}`,
      {
        headers: {
          Authorization: `Bearer ${tokenManagement}`,
        },
      },
    );
    if (response.status === 404) {
      return false;
    }
    await this._expectStatus(response, [204]);
    return true;
  }

  /**
   * List registered Connect applications (`GET /v1/connect/app/apps`).
   * @param {{limit?: number, cursor?: string, signal?: AbortSignal}} [options]
   * @returns {Promise<ConnectAppRegistryPage>}
   */
  async listConnectApps(options = {}) {
    const resolvedOptions =
      options === undefined || options === null
        ? {}
        : requirePlainObjectOption(options, "connect app list options");
    assertSupportedOptionKeys(
      resolvedOptions,
      CONNECT_APP_LIST_OPTION_KEYS,
      "listConnectApps options",
    );
    const { signal } = normalizeSignalOption(resolvedOptions, "listConnectApps");
    const params = {};
    if (resolvedOptions.limit !== undefined && resolvedOptions.limit !== null) {
      params.limit = ToriiClient._normalizeUnsignedInteger(
        resolvedOptions.limit,
        "connectApps.limit",
        { allowZero: false },
      );
    }
    if (resolvedOptions.cursor !== undefined && resolvedOptions.cursor !== null) {
      params.cursor = requireNonEmptyString(resolvedOptions.cursor, "connectApps.cursor");
    }
    const response = await this._request("GET", "/v1/connect/app/apps", {
      headers: JSON_ACCEPT_HEADERS,
      params: Object.keys(params).length === 0 ? undefined : params,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeConnectAppRegistryPage(payload);
  }

  /**
   * Iterate Connect applications with cursor-based pagination.
   * @param {ConnectAppIteratorOptions} [options]
   * @returns {AsyncGenerator<ConnectAppRecord, void, unknown>}
   */
  iterateConnectApps(options = {}) {
    return this._iterateCursorIterable(this.listConnectApps, options);
  }

  /**
   * Fetch a single Connect application (`GET /v1/connect/app/apps/{app_id}`).
   * @param {string} appId
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ConnectAppRecord>}
  */
  async getConnectApp(appId, options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getConnectApp");
    const normalizedId = requireNonEmptyString(appId, "appId");
    const response = await this._request(
      "GET",
      `/v1/connect/app/apps/${encodeURIComponent(normalizedId)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
      },
    );
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeConnectAppRecord(payload, "connect app response");
  }

  /**
   * Register or update a Connect application (`POST /v1/connect/app/apps`).
   * @param {ConnectAppUpsertInput} record
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ConnectAppRecord | null>}
   */
  async registerConnectApp(record, options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "registerConnectApp");
    const payload = toConnectAppWritePayload(record, "registerConnectApp.record");
    const response = await this._request("POST", "/v1/connect/app/apps", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
    });
    await this._expectStatus(response, [200, 201, 202]);
    const body = await this._maybeJson(response);
    if (!body) {
      return null;
    }
    return normalizeConnectAppRecord(body, "connect app response");
  }

  /**
   * Delete a Connect application (`DELETE /v1/connect/app/apps/{app_id}`).
   * @param {string} appId
   * @returns {Promise<boolean>} True when the record existed.
   */
  async deleteConnectApp(appId) {
    const normalizedId = requireNonEmptyString(appId, "appId");
    const response = await this._request(
      "DELETE",
      `/v1/connect/app/apps/${encodeURIComponent(normalizedId)}`,
    );
    if (response.status === 404) {
      return false;
    }
    await this._expectStatus(response, [200, 202, 204]);
    return true;
  }

  /**
   * Fetch mutable Connect policy toggles (`GET /v1/connect/app/policy`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ConnectAppPolicyControls>}
   */
  async getConnectAppPolicy(options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "getConnectAppPolicy");
    const response = await this._request("GET", "/v1/connect/app/policy", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeConnectAppPolicyControls(payload, "connect app policy response");
  }

  /**
   * Update Connect policy toggles (`POST /v1/connect/app/policy`).
   * @param {ConnectAppPolicyUpdate} updates
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ConnectAppPolicyControls>}
   */
  async updateConnectAppPolicy(updates, options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "updateConnectAppPolicy");
    const payload = toConnectAppPolicyPayload(updates, "updateConnectAppPolicy.updates");
    const response = await this._request("POST", "/v1/connect/app/policy", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
    });
    await this._expectStatus(response, [200, 202]);
    const body = await this._maybeJson(response);
    return normalizeConnectAppPolicyControls(body, "connect app policy response");
  }

  /**
   * Fetch the Connect admission manifest (`GET /v1/connect/app/manifest`).
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ConnectAdmissionManifest>}
   */
  async getConnectAdmissionManifest(options = {}) {
    const { signal } = normalizeSignalOnlyOption(
      options,
      "getConnectAdmissionManifest",
    );
    const response = await this._request("GET", "/v1/connect/app/manifest", {
      headers: JSON_ACCEPT_HEADERS,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeConnectAdmissionManifest(payload, "connect admission manifest");
  }

  /**
   * Replace the Connect admission manifest (`PUT /v1/connect/app/manifest`).
   * @param {ConnectAdmissionManifestInput} manifest
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ConnectAdmissionManifest>}
   */
  async setConnectAdmissionManifest(manifest, options = {}) {
    const { signal } = normalizeSignalOnlyOption(
      options,
      "setConnectAdmissionManifest",
    );
    const payload = toConnectAdmissionManifestPayload(
      manifest,
      "setConnectAdmissionManifest.manifest",
    );
    const response = await this._request("PUT", "/v1/connect/app/manifest", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
    });
    await this._expectStatus(response, [200, 202]);
    const body = await this._maybeJson(response);
    return normalizeConnectAdmissionManifest(body, "connect admission manifest");
  }

  /**
   * Build a Connect WebSocket URL using the client's base Torii URL.
   * @param {{sid: string, role: string, token: string, endpointPath?: string}} options
   * @returns {string}
   */
  buildConnectWebSocketUrl(options = {}) {
    return buildConnectWebSocketUrlInternal(
      this._baseUrl,
      options,
      "ToriiClient.buildConnectWebSocketUrl",
    );
  }

  /**
   * Open a Connect WebSocket (`/v1/connect/ws`) using the provided implementation.
   * @param {{
   *   sid: string,
   *   role: string,
   *   token: string,
   *   endpointPath?: string,
   *   protocols?: string | ReadonlyArray<string>,
   *   websocketOptions?: unknown,
   *   WebSocketImpl?: typeof WebSocket
   * }} options
   * @returns {unknown}
   */
  openConnectWebSocket(options = {}) {
    const normalizedOptions =
      options === undefined
        ? {}
        : requirePlainObjectOption(options, "ToriiClient.openConnectWebSocket options", {
            message: "must be an object",
          });
    const {
      insecureTransportTelemetryHook,
      ...rest
    } = normalizedOptions;
    const allowInsecure = rest.allowInsecure ?? this.#allowInsecure;
    const telemetryHook =
      insecureTransportTelemetryHook ?? this.#config.insecureTransportTelemetryHook;
    return openConnectWebSocketInternal(
      {
        ...rest,
        allowInsecure,
        baseUrl: this._baseUrl,
        insecureTransportTelemetryHook: telemetryHook,
      },
      "ToriiClient.openConnectWebSocket",
    );
  }

  /**
   * Build a Connect WebSocket URL for an arbitrary Torii base.
   * @param {string} baseUrl
   * @param {{sid: string, role: string, token: string, endpointPath?: string}} options
   * @returns {string}
   */
  static buildConnectWebSocketUrl(baseUrl, options = {}) {
    return buildConnectWebSocketUrlInternal(
      baseUrl,
      options,
      "ToriiClient.buildConnectWebSocketUrl",
    );
  }

  /**
   * Bind, update, or clear a contract alias (`POST /v1/contracts/aliases`).
   * @param {SetContractAliasRequest} request
   * @returns {Promise<SetContractAliasResponse>}
   */
  async setContractAlias(request = {}) {
    const payload = normalizeSetContractAliasRequest(request);
    const response = await this._request("POST", "/v1/contracts/aliases", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
    });
    await this._expectStatus(response, [200]);
    return normalizeSetContractAliasResponse(await this._maybeJson(response));
  }

  /**
   * Prepare an unsigned contract-call transaction for local signing
   * (`POST /v1/contracts/call`).
   * @param {ContractCallRequest} request
   * @param {{signal?: AbortSignal, canonicalAuth?: CanonicalRequestAuth}} [options]
   * @returns {Promise<ContractCallResponse>}
  */
  async prepareContractCall(request = {}, options = {}) {
    const { signal, canonicalAuth, rest } = normalizeCanonicalApplicationPostOptions(
      options, "prepareContractCall", ToriiClient, this.#canonicalRequestAuth,
    );
    assertSupportedOptionKeys(rest, new Set([]), "prepareContractCall options");
    const payload = normalizeContractCallRequest(request);
    const draftIntent = normalizeContractCallDraftIntent(
      request,
      "prepareContractCall",
    );
    if (
      payload.contract_address !== undefined
      && payload.contract_address !== draftIntent.contractAddress
    ) {
      rejectType("prepareContractCall draftIntent.contractAddress must match the requested address");
    }
    const requestPayloadDigest = contractPayloadDigestHex(payload.payload);
    if (draftIntent.payloadDigestHex !== requestPayloadDigest) {
      rejectType("prepareContractCall draftIntent.payloadDigestHex must match the exact request payload");
    }
    requireLocalDraftSigningContext(
      this._localSigningContext,
      "prepareContractCall",
    );
    requireCanonicalApplicationAuthority(canonicalAuth, payload.authority, "prepareContractCall");
    const response = await this._request("POST", "/v1/contracts/call", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("contract call endpoint returned no payload");
    }
    return normalizeContractCallDraftResponse(
      body,
      payload,
      draftIntent,
      this._localSigningContext,
    );
  }

  /**
   * Execute a deployed contract call against the current state without submitting it
   * (`POST /v1/contracts/call/simulate`).
   * @param {object} request
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<object>}
   */
  async simulateContractCall(request = {}, options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "simulateContractCall");
    const payload = normalizeContractCallSimulateRequest(request);
    const response = await this._request("POST", "/v1/contracts/call/simulate", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
    });
    await this._expectStatus(response, [200], { signal });
    const body = await this._maybeBoundedJson(
      response,
      CONTRACT_CALL_SIMULATION_JSON_MAX_BYTES,
      "contract call simulation response",
      { signal },
    );
    if (!body) {
      rejectError("contract call simulation endpoint returned no payload");
    }
    return normalizeContractCallSimulateResponse(body);
  }

  /**
   * Propose a generic multisig instruction batch (`POST /v1/multisig/propose`).
   * Sends the whole request DTO as native Norito (`application/x-norito`).
   * @param {object} request
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<object>}
   */
  async proposeMultisig(request = {}, options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "proposeMultisig");
    const payload = normalizeMultisigProposeRequest(request);
    // Complete native request validation before consulting the off-wire trust
    // intent so malformed instruction archives fail before any network I/O.
    const { noritoEncodeMultisigProposeRequest } = await loadToriiOptionalModule();
    requireLocalDraftSigningContext(this._localSigningContext, "proposeMultisig");
    const requestBody = noritoEncodeMultisigProposeRequest(payload, this._localSigningContext.chainDiscriminant);
    const draftIntent = normalizeLocalTransactionDraftIntent(
      request,
      "proposeMultisig",
      payload.signature_b64 === undefined,
    );
    if (draftIntent !== null) {
      requireLocalDraftSigningContext(this._localSigningContext, "proposeMultisig");
    }
    const response = await this._request("POST", "/v1/multisig/propose", {
      headers: {
        "Content-Type": "application/x-norito",
        Accept: APPLICATION_JSON,
      },
      body: requestBody,
      signal,
    });
    await this._expectStatus(response, [200, 202]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("multisig propose endpoint returned no payload");
    }
    return validateMultisigResponseRequestBinding(
      normalizeMultisigContractCallResponse(body, "multisig propose response"),
      payload,
      "multisig propose response",
      draftIntent,
      this._localSigningContext,
    );
  }

  /**
   * Propose a contract call through a multisig authority (`POST /v1/contracts/call/multisig/propose`).
   * @param {object} request
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<object>}
   */
  async proposeMultisigContractCall(request = {}, options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "proposeMultisigContractCall");
    const payload = normalizeMultisigContractCallProposeRequest(request);
    const draftIntent = normalizeLocalTransactionDraftIntent(
      request,
      "proposeMultisigContractCall",
      payload.signature_b64 === undefined,
    );
    if (draftIntent !== null) {
      requireLocalDraftSigningContext(
        this._localSigningContext,
        "proposeMultisigContractCall",
      );
    }
    const response = await this._request("POST", "/v1/contracts/call/multisig/propose", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
    });
    await this._expectStatus(response, [200, 202]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("multisig contract propose endpoint returned no payload");
    }
    return validateMultisigResponseRequestBinding(
      normalizeMultisigContractCallResponse(
        body,
        "multisig contract propose response",
      ),
      payload,
      "multisig contract propose response",
      draftIntent,
      this._localSigningContext,
    );
  }

  /**
   * Approve a multisig contract call proposal (`POST /v1/contracts/call/multisig/approve`).
   * @param {object} request
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<object>}
   */
  async approveMultisigContractCall(request = {}, options = {}) {
    const { signal } = normalizeSignalOnlyOption(options, "approveMultisigContractCall");
    const payload = normalizeMultisigContractCallApproveRequest(request);
    const draftIntent = normalizeLocalTransactionDraftIntent(
      request,
      "approveMultisigContractCall",
      payload.signature_b64 === undefined,
    );
    if (draftIntent !== null) {
      requireLocalDraftSigningContext(
        this._localSigningContext,
        "approveMultisigContractCall",
      );
    }
    const response = await this._request("POST", "/v1/contracts/call/multisig/approve", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
    });
    await this._expectStatus(response, [200, 202]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("multisig contract approve endpoint returned no payload");
    }
    return validateMultisigResponseRequestBinding(
      normalizeMultisigContractCallResponse(
        body,
        "multisig contract approve response",
      ),
      payload,
      "multisig contract approve response",
      draftIntent,
      this._localSigningContext,
    );
  }

  /**
   * Resolve the current multisig spec through an alias-aware selector (`POST /v1/multisig/spec`).
   * @param {object} request
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<object>}
   */
  async getMultisigSpec(request = {}, options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getMultisigSpec");
    const payload = normalizeMultisigSelectorOnlyRequest(request, "getMultisigSpec request");
    const requestBody = JSON.stringify(payload);
    const response = await this._request("POST", "/v1/multisig/spec", {
      headers: JSON_REQUEST_HEADERS,
      body: requestBody,
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200], { signal });
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("multisig spec endpoint returned no payload");
    }
    return normalizeMultisigSpecResponse(body);
  }

  /**
   * Query multisig proposals for a selector, optionally filtered by lifecycle status (`POST /v1/multisig/proposals/query`).
   * @param {object} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<object>}
   */
  async queryMultisigProposals(request = {}, options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "queryMultisigProposals");
    const payload = normalizeMultisigProposalsQueryRequest(
      request,
      "queryMultisigProposals request",
    );
    const requestBody = JSON.stringify(payload);
    const response = await this._request("POST", "/v1/multisig/proposals/query", {
      headers: JSON_REQUEST_HEADERS,
      body: requestBody,
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("multisig proposals query endpoint returned no payload");
    }
    return normalizeMultisigProposalsQueryResponse(body);
  }

  /**
   * Resolve one multisig proposal by proposal id or instructions hash (`POST /v1/multisig/proposals/resolve`).
   * @param {object} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<object>}
   */
  async resolveMultisigProposal(request = {}, options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "resolveMultisigProposal");
    const payload = normalizeMultisigProposalsResolveRequest(request);
    const requestBody = JSON.stringify(payload);
    const response = await this._request("POST", "/v1/multisig/proposals/resolve", {
      headers: JSON_REQUEST_HEADERS,
      body: requestBody,
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const body = await this._maybeJson(response);
    if (!body) {
      rejectError("multisig proposal resolve endpoint returned no payload");
    }
    return normalizeMultisigProposalResolveResponse(body);
  }

  /**
   * Fetch an authenticated dataspace-scoped contract manifest.
   * @param {{dataspaceId: bigint|string|number, codeHash: string|Uint8Array}} artifactId
   * @returns {Promise<ContractManifestRecord | null>}
   */
  async getContractManifest(artifactId, options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getContractManifest");
    const requested = normalizeContractArtifactRequest(artifactId);
    const response = await this._request("GET", `/v1/contracts/artifacts/${requested.dataspace_id}/${requested.code_hash}`, {
      headers: JSON_ACCEPT_HEADERS, signal, canonicalAuth,
    });
    if (response.status === 404) {
      cancelResponseBodyBestEffort(
        response,
        "contract manifest response was not found",
      );
      return null;
    }
    await this._expectStatus(response, [200]);
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      CONTRACT_MANIFEST_JSON_MAX_BYTES,
      "contract manifest response",
      { signal },
    );
    if (!payload) {
      return null;
    }
    return normalizeContractManifestResponse(payload, requested, this._localSigningContext.networkId);
  }

  /**
   * Fetch authenticated dataspace-scoped contract code bytes.
   * @param {{dataspaceId: bigint|string|number, codeHash: string|Uint8Array}} artifactId
   * @param {{signal?: AbortSignalLike, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ContractCodeBytesRecord | null>}
   */
  async getContractCodeBytes(artifactId, options) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getContractCodeBytes");
    const requested = normalizeContractArtifactRequest(artifactId);
    const response = await this._request(
      "GET",
      `/v1/contracts/artifacts/${requested.dataspace_id}/${requested.code_hash}/bytes`,
      { headers: JSON_ACCEPT_HEADERS, signal, canonicalAuth },
    );
    if (response.status === 404) {
      cancelResponseBodyBestEffort(
        response,
        "contract code bytes response was not found",
      );
      return null;
    }
    await this._expectStatus(response, [200], { signal });
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      CONTRACT_CODE_BYTES_JSON_MAX_BYTES,
      "contract code bytes response",
      { signal },
    );
    if (!payload) {
      return null;
    }
    return normalizeContractCodeBytesResponse(payload, requested, this._localSigningContext.networkId);
  }

  /**
   * Read the governance binding for one contract address (`GET /v1/gov/contracts/{contract_address}`).
   * @param {string} contractAddress
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<ToriiGovernanceContractResponse>}
   */
  async getGovernanceContract(contractAddress, options) {
    const normalizedAddress = requireNonEmptyString(contractAddress, "contractAddress");
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, "getGovernanceContract");
    const response = await this._request(
      "GET",
      `/v1/gov/contracts/${encodeURIComponent(normalizedAddress)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal: signal ?? undefined,
        canonicalAuth,
      },
    );
    await this._expectStatus(response, [200], { signal });
    const payload = await this._readBoundedLosslessIntegerJson(
      response,
      JSON_RESPONSE_MAX_BYTES,
      "governance contract response",
      { signal },
    );
    return normalizeGovernanceContractResponse(payload);
  }

  /**
   * List registered triggers (`GET /v1/triggers`).
   * @param {TriggerListOptions} [options]
   * @returns {Promise<ToriiTriggerListPage>}
   */
  async listTriggers(options = {}) {
    const { signal, params } = buildTriggerListQuery(options);
    const response = await this._request("GET", "/v1/triggers", {
      headers: JSON_ACCEPT_HEADERS,
      params,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeTriggerListResponse(payload, "trigger list response");
  }

  /**
   * Fetch a trigger definition (`GET /v1/triggers/{trigger_id}`).
   * @param {string} triggerId
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiTriggerRecord | null>}
  */
  async getTrigger(triggerId, options = {}) {
    const normalizedId = requireNonEmptyString(triggerId, "triggerId");
    const { signal } = normalizeSignalOnlyOption(options, "getTrigger");
    const response = await this._request(
      "GET",
      `/v1/triggers/${encodeURIComponent(normalizedId)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
      },
    );
    if (response.status === 404) {
      return null;
    }
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      return null;
    }
    return normalizeTriggerRecord(payload, "trigger response");
  }

  /**
   * Register or update a trigger (`POST /v1/triggers`).
   * @param {ToriiTriggerUpsertRequest} trigger
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async registerTrigger(trigger, options = {}) {
    const payload = normalizeTriggerUpsertPayload(trigger);
    const { signal } = normalizeSignalOnlyOption(options, "registerTrigger");
    const response = await this._request("POST", "/v1/triggers", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
    });
    await this._expectStatus(response, [200, 201, 202]);
    return this._maybeJson(response);
  }

  /**
   * Register or update a trigger and normalise the response payload.
   * @param {ToriiTriggerUpsertRequest} trigger
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiTriggerMutationResponse | null>}
   */
  async registerTriggerTyped(trigger, options = {}) {
    const payload = await this.registerTrigger(trigger, options);
    if (!payload) {
      return null;
    }
    return normalizeTriggerMutationResponse(payload, "registerTrigger response");
  }

  /**
   * Delete a trigger (`DELETE /v1/triggers/{trigger_id}`).
   * @param {string} triggerId
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async deleteTrigger(triggerId, options = {}) {
    const normalizedId = requireNonEmptyString(triggerId, "triggerId");
    const { signal } = normalizeSignalOnlyOption(options, "deleteTrigger");
    const response = await this._request(
      "DELETE",
      `/v1/triggers/${encodeURIComponent(normalizedId)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
      },
    );
    await this._expectStatus(response, [200, 202, 204, 404]);
    return this._maybeJson(response);
  }

  /**
   * Delete a trigger and normalise the response payload when available.
   * @param {string} triggerId
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiTriggerMutationResponse | null>}
   */
  async deleteTriggerTyped(triggerId, options = {}) {
    const payload = await this.deleteTrigger(triggerId, options);
    if (!payload) {
      return null;
    }
    return normalizeTriggerMutationResponse(payload, "deleteTrigger response");
  }

  /**
   * Query triggers with structured filters (`POST /v1/triggers/query`).
   * @param {IterableQueryOptions} [options]
   * @returns {Promise<ToriiTriggerListPage>}
   */
  async queryTriggers(options = {}) {
    const normalizedOptions = normalizeIterableQueryOptions(
      options,
      "trigger query options",
    );
    const { signal, ...rest } = normalizedOptions;
    const envelope = ToriiClient._buildIterableQueryEnvelope(rest);
    const response = await this._request("POST", "/v1/triggers/query", {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(envelope),
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    return normalizeTriggerListResponse(payload, "trigger query response");
  }

  /**
   * Iterate triggers using the `GET /v1/triggers` endpoint.
   * @param {TriggerIteratorOptions} [options]
   * @returns {AsyncGenerator<ToriiTriggerRecord, void, unknown>}
   */
  iterateTriggers(options = {}) {
    return this._iterateIterable(this.listTriggers, options);
  }

  /**
   * Iterate triggers using the structured query endpoint.
   * @param {TriggerQueryIteratorOptions} [options]
   * @returns {AsyncGenerator<ToriiTriggerRecord, void, unknown>}
   */
  iterateTriggersQuery(options = {}) {
    return this._iterateIterable(this.queryTriggers, options);
  }

  /**
   * Create a subscription plan (`POST /v1/subscriptions/plans`).
   * @param {SubscriptionPlanCreateRequest} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<SubscriptionPlanCreateResponse>}
   */
  async createSubscriptionPlan(request, options = {}) {
    const payload = normalizeSubscriptionPlanCreateRequest(request);
    const body = await this._submitSubscriptionMutation(
      "/v1/subscriptions/plans", payload, options, "createSubscriptionPlan", [200],
    );
    return normalizeSubscriptionPlanCreateResponse(body, payload.plan_id);
  }

  /**
   * Create a subscription (`POST /v1/subscriptions`).
   * @param {SubscriptionCreateRequest} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<SubscriptionCreateResponse>}
   */
  async createSubscription(request, options = {}) {
    const payload = normalizeSubscriptionCreateRequest(request);
    const body = await this._submitSubscriptionMutation(
      "/v1/subscriptions", payload, options, "createSubscription", [200],
    );
    return normalizeSubscriptionCreateResponse(body, payload);
  }

  /**
   * Fetch a subscription (`GET /v1/subscriptions/{subscription_id}`).
   * @param {string} subscriptionId
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<SubscriptionGetResponse | null>}
   */
  async getSubscription(subscriptionId, options = {}) {
    const normalizedId = requireNonEmptyString(subscriptionId, "subscriptionId");
    const { signal } = normalizeSignalOnlyOption(options, "getSubscription");
    const response = await this._request(
      "GET",
      `/v1/subscriptions/${encodeURIComponent(normalizedId)}`,
      {
        headers: JSON_ACCEPT_HEADERS,
        signal,
      },
    );
    if (response.status === 404) {
      return null;
    }
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      return null;
    }
    return normalizeSubscriptionGetResponse(payload);
  }

  /**
   * Pause a subscription (`POST /v1/subscriptions/{subscription_id}/pause`).
   * @param {string} subscriptionId
   * @param {SubscriptionActionRequest} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<SubscriptionActionResponse>}
   */
  async pauseSubscription(subscriptionId, request, options = {}) {
    const normalizedId = requireNonEmptyString(subscriptionId, "subscriptionId");
    const payload = normalizeSubscriptionActionRequest(request, "pauseSubscription");
    const body = await this._submitSubscriptionMutation(
      `/v1/subscriptions/${encodeURIComponent(normalizedId)}/pause`,
      payload, options, "pauseSubscription", [200],
    );
    return normalizeSubscriptionActionResponse(
      body,
      "pause",
      payload.authority,
      normalizedId,
      "pauseSubscription response",
    );
  }

  /**
   * Resume a subscription (`POST /v1/subscriptions/{subscription_id}/resume`).
   * @param {string} subscriptionId
   * @param {SubscriptionActionRequest} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<SubscriptionActionResponse>}
   */
  async resumeSubscription(subscriptionId, request, options = {}) {
    const normalizedId = requireNonEmptyString(subscriptionId, "subscriptionId");
    const payload = normalizeSubscriptionActionRequest(request, "resumeSubscription");
    const body = await this._submitSubscriptionMutation(
      `/v1/subscriptions/${encodeURIComponent(normalizedId)}/resume`,
      payload, options, "resumeSubscription", [200],
    );
    return normalizeSubscriptionActionResponse(
      body,
      "resume",
      payload.authority,
      normalizedId,
      "resumeSubscription response",
    );
  }

  /**
   * Cancel a subscription (`POST /v1/subscriptions/{subscription_id}/cancel`).
   * @param {string} subscriptionId
   * @param {SubscriptionActionRequest} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<SubscriptionActionResponse>}
   */
  async cancelSubscription(subscriptionId, request, options = {}) {
    const normalizedId = requireNonEmptyString(subscriptionId, "subscriptionId");
    const payload = normalizeSubscriptionActionRequest(request, "cancelSubscription");
    const body = await this._submitSubscriptionMutation(
      `/v1/subscriptions/${encodeURIComponent(normalizedId)}/cancel`,
      payload, options, "cancelSubscription", [200],
    );
    return normalizeSubscriptionActionResponse(
      body,
      "cancel",
      payload.authority,
      normalizedId,
      "cancelSubscription response",
    );
  }

  /**
   * Keep a subscription (`POST /v1/subscriptions/{subscription_id}/keep`).
   * @param {string} subscriptionId
   * @param {SubscriptionActionRequest} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<SubscriptionActionResponse>}
   */
  async keepSubscription(subscriptionId, request, options = {}) {
    const normalizedId = requireNonEmptyString(subscriptionId, "subscriptionId");
    const payload = normalizeSubscriptionActionRequest(request, "keepSubscription");
    const body = await this._submitSubscriptionMutation(
      `/v1/subscriptions/${encodeURIComponent(normalizedId)}/keep`,
      payload, options, "keepSubscription", [200],
    );
    return normalizeSubscriptionActionResponse(
      body,
      "keep",
      payload.authority,
      normalizedId,
      "keepSubscription response",
    );
  }

  /**
   * Charge a subscription immediately (`POST /v1/subscriptions/{subscription_id}/charge-now`).
   * @param {string} subscriptionId
   * @param {SubscriptionActionRequest} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<SubscriptionActionResponse>}
   */
  async chargeSubscriptionNow(subscriptionId, request, options = {}) {
    const normalizedId = requireNonEmptyString(subscriptionId, "subscriptionId");
    const payload = normalizeSubscriptionActionRequest(
      request,
      "chargeSubscriptionNow",
    );
    const body = await this._submitSubscriptionMutation(
      `/v1/subscriptions/${encodeURIComponent(normalizedId)}/charge-now`,
      payload, options, "chargeSubscriptionNow", [200],
    );
    return normalizeSubscriptionActionResponse(
      body,
      "charge_now",
      payload.authority,
      normalizedId,
      "chargeSubscriptionNow response",
    );
  }

  /**
   * Record subscription usage (`POST /v1/subscriptions/{subscription_id}/usage`).
   * @param {string} subscriptionId
   * @param {SubscriptionUsageRequest} request
   * @param {{signal?: AbortSignal, canonicalAuth: CanonicalRequestAuth}} options
   * @returns {Promise<SubscriptionUsageDraft>}
   */
  async recordSubscriptionUsage(subscriptionId, request, options = {}) {
    const normalizedId = requireNonEmptyString(subscriptionId, "subscriptionId");
    const payload = normalizeSubscriptionUsageRequest(request, "recordSubscriptionUsage");
    const body = await this._submitSubscriptionMutation(
      `/v1/subscriptions/${encodeURIComponent(normalizedId)}/usage`,
      payload, options, "recordSubscriptionUsage", [200],
    );
    return normalizeSubscriptionUsageDraft(
      body,
      normalizedId,
      "recordSubscriptionUsage response",
    );
  }

  async _submitSubscriptionMutation(path, payload, options, context, expectedStatus) {
    const { signal, canonicalAuth } = normalizeVpnSessionOptions(options, context);
    if (canonicalAuth.accountId !== payload.authority) {
      rejectType(`${context} canonicalAuth.accountId must equal payload.authority`);
    }
    const response = await this._request("POST", path, {
      headers: JSON_REQUEST_HEADERS,
      body: JSON.stringify(payload),
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, expectedStatus);
    const body = await this._maybeJson(response);
    if (!body) rejectError(`${context} endpoint returned no payload`);
    return body;
  }

  /**
   * Fetch a single prover report.
   * @param {string} reportId
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<ToriiProverReport>}
   */
  async getProverReport(reportId, options = {}) {
    const normalizedId = requireNonEmptyString(reportId, "reportId");
    const { signal } = normalizeSignalOnlyOption(options, "getProverReport");
    const response = await this._request(
      "GET",
      `/v1/zk/prover/reports/${encodeURIComponent(normalizedId)}`,
      { signal },
    );
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload) {
      rejectError("prover report response missing JSON body");
    }
    return normalizeProverReportRecord(payload, "prover report response");
  }

  /**
   * Delete a prover report by id.
   * @param {string} reportId
   */
  async deleteProverReport(reportId, options = {}) {
    const normalizedId = requireNonEmptyString(reportId, "reportId");
    const { signal } = normalizeSignalOnlyOption(options, "deleteProverReport");
    const response = await this._request(
      "DELETE",
      `/v1/zk/prover/reports/${encodeURIComponent(normalizedId)}`,
      { signal },
    );
    await this._expectStatus(response, [204, 404]);
  }

  /**
   * Submit an ISO 20022 pacs.008 message (`POST /v1/iso20022/pacs008`).
   * @param {ArrayBufferView | ArrayBuffer | Buffer | string} message XML payload
   * @param {{contentType?: string, profile?: string, signal?: AbortSignal}} [options]
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async submitIsoPacs008(message, options = {}) {
    const transportOptions = normalizeIsoSubmissionOptions(
      options,
      "submitIsoPacs008",
    );
    const body = normalizeIsoPayload(message, "submitIsoPacs008.message");
    const payload = await submitIsoTransport(this, "pacs008", body, {
      ...transportOptions,
      operatorSigningContext: this._operatorSigningContext,
    });
    return payload == null
      ? null
      : normalizeIsoSubmissionResponse(payload, "ISO pacs008 submission");
  }

  /**
   * Submit an ISO 20022 pacs.009 message (`POST /v1/iso20022/pacs009`).
   * @param {ArrayBufferView | ArrayBuffer | Buffer | string} message XML payload
   * @param {{contentType?: string, profile?: string, signal?: AbortSignal}} [options]
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async submitIsoPacs009(message, options = {}) {
    const transportOptions = normalizeIsoSubmissionOptions(
      options,
      "submitIsoPacs009",
    );
    const body = normalizeIsoPayload(message, "submitIsoPacs009.message");
    const payload = await submitIsoTransport(this, "pacs009", body, {
      ...transportOptions,
      operatorSigningContext: this._operatorSigningContext,
    });
    return payload == null
      ? null
      : normalizeIsoSubmissionResponse(payload, "ISO pacs009 submission");
  }

  /**
   * Fetch ISO 20022 message status (`GET /v1/iso20022/messages/{msg_id}`).
   * @param {string} messageId
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async getIsoMessageStatus(messageId, options = {}) {
    const normalizedId = requireNonEmptyString(messageId, "messageId");
    const transportOptions = normalizeIsoStatusOptions(options, "getIsoMessageStatus");
    const payload = await getIsoStatusTransport(this, normalizedId, {
      ...transportOptions,
      operatorSigningContext: this._operatorSigningContext,
    });
    if (!payload) {
      return null;
    }
    return normalizeIsoStatusResponse(payload, "ISO status response");
  }

  /**
   * Wait for an ISO bridge message to reach a terminal state.
   * @param {string} messageId
   * @param {IsoMessageWaitOptions} [options]
   * @returns {Promise<Record<string, unknown>>}
   */
  async waitForIsoMessageStatus(messageId, options = {}) {
    const normalizedId = requireNonEmptyString(messageId, "messageId");
    const optionPath = "waitForIsoMessageStatus.options";
    const resolvedOptions =
      options === undefined || options === null
        ? {}
        : requireIsoPlainObject(options, optionPath);
    const allowedKeys = new Set([
      "pollIntervalMs",
      "maxAttempts",
      "resolveOnAcceptedWithoutTransaction",
      "resolveOnAccepted",
      "onPoll",
      "signal",
      "retryProfile",
    ]);
    const unsupportedKeys = Object.keys(resolvedOptions).filter((key) => !allowedKeys.has(key));
    if (unsupportedKeys.length > 0) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${optionPath} contains unsupported fields: ${unsupportedKeys.join(", ")}`,
        optionPath,
      );
    }
    const pollIntervalMs =
      resolvedOptions.pollIntervalMs === undefined
        ? DEFAULT_ISO_POLL_INTERVAL_MS
        : ToriiClient._normalizeUnsignedInteger(
            resolvedOptions.pollIntervalMs,
            "wait.pollIntervalMs",
            {
              allowZero: true,
              min: MIN_ISO_POLL_INTERVAL_MS,
            },
          );
    const maxAttempts =
      resolvedOptions.maxAttempts === undefined
        ? DEFAULT_ISO_POLL_ATTEMPTS
        : ToriiClient._normalizeUnsignedInteger(resolvedOptions.maxAttempts, "wait.maxAttempts", {
            allowZero: false,
          });
    const resolveAlias = resolvedOptions.resolveOnAccepted;
    const resolveCanonical = resolvedOptions.resolveOnAcceptedWithoutTransaction;
    if (resolveCanonical !== undefined && typeof resolveCanonical !== "boolean") {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "wait.resolveOnAcceptedWithoutTransaction must be a boolean",
        `${optionPath}.resolveOnAcceptedWithoutTransaction`,
      );
    }
    if (resolveAlias !== undefined && typeof resolveAlias !== "boolean") {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "wait.resolveOnAccepted must be a boolean",
        `${optionPath}.resolveOnAccepted`,
      );
    }
    if (
      resolveCanonical !== undefined &&
      resolveAlias !== undefined &&
      resolveCanonical !== resolveAlias
    ) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "wait.resolveOnAccepted and wait.resolveOnAcceptedWithoutTransaction must match when both are provided",
        `${optionPath}.resolveOnAccepted`,
      );
    }
    const resolveOnAccepted =
      resolveCanonical !== undefined ? resolveCanonical : resolveAlias ?? false;
    let retryProfile;
    if (resolvedOptions.retryProfile !== undefined && resolvedOptions.retryProfile !== null) {
      retryProfile = requireNonEmptyString(
        resolvedOptions.retryProfile,
        `${optionPath}.retryProfile`,
      );
    }
    const onPoll =
      resolvedOptions.onPoll === undefined || resolvedOptions.onPoll === null
        ? undefined
        : resolvedOptions.onPoll;
    if (onPoll !== undefined && typeof onPoll !== JS_TYPE_FUNCTION) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "wait.onPoll must be a function",
        `${optionPath}.onPoll`,
      );
    }
    let signal;
    try {
      ({ signal } = normalizeSignalOption(
        resolvedOptions,
        "waitForIsoMessageStatus",
      ));
    } catch (error) {
      if (error instanceof TypeError) {
        throw createValidationError(
          ValidationErrorCode.INVALID_OBJECT,
          error.message,
          `${optionPath}.signal`,
          error,
        );
      }
      throw error;
    }
    let lastStatus = null;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      throwIfAborted(signal);
      const status = await this.getIsoMessageStatus(normalizedId, { signal, retryProfile });
      lastStatus = status ?? null;
      if (onPoll) {
        // Allow async callbacks for telemetry/logging hooks.
        // eslint-disable-next-line no-await-in-loop
        await onPoll({ attempt, status: lastStatus });
      }
      if (ToriiClient._isIsoStatusTerminal(lastStatus, resolveOnAccepted)) {
        return lastStatus;
      }
      if (attempt < maxAttempts) {
        throwIfAborted(signal);
        // eslint-disable-next-line no-await-in-loop
        await delay(pollIntervalMs);
      }
    }
    throw new IsoMessageTimeoutError(normalizedId, maxAttempts, lastStatus);
  }

  /**
   * Submit an ISO 20022 pacs.008 message and wait for a terminal status.
   * @param {ArrayBufferView | ArrayBuffer | Buffer | string} message
   * @param {{contentType?: string, signal?: AbortSignal, wait?: IsoMessageWaitOptions}} [options]
   * @returns {Promise<Record<string, unknown>>}
   */
  async submitIsoPacs008AndWait(message, options = {}) {
    const record =
      options === undefined || options === null
        ? {}
        : requireIsoPlainObject(options, "submitIsoPacs008AndWait.options");
    const { wait: waitOptions, ...submitOptions } = record;
    let normalizedWait =
      waitOptions === undefined || waitOptions === null
        ? undefined
        : requireIsoPlainObject(waitOptions, "submitIsoPacs008AndWait.options.wait");
    if (normalizedWait) {
      const needsSignal = normalizedWait.signal === undefined && submitOptions.signal !== undefined;
      const needsRetryProfile =
        normalizedWait.retryProfile === undefined && submitOptions.retryProfile !== undefined;
      if (needsSignal || needsRetryProfile) {
        normalizedWait = { ...normalizedWait };
        if (needsSignal) {
          normalizedWait.signal = submitOptions.signal;
        }
        if (needsRetryProfile) {
          normalizedWait.retryProfile = submitOptions.retryProfile;
        }
      }
    }
    const submission = await this.submitIsoPacs008(message, submitOptions);
    const messageId = submission?.message_id;
    if (!messageId) {
      rejectError("ISO pacs.008 submission did not return a message_id");
    }
    return this.waitForIsoMessageStatus(messageId, normalizedWait);
  }

  /**
   * Submit an ISO 20022 pacs.009 message and wait for a terminal status.
   * @param {ArrayBufferView | ArrayBuffer | Buffer | string} message
   * @param {{contentType?: string, signal?: AbortSignal, wait?: IsoMessageWaitOptions}} [options]
   * @returns {Promise<Record<string, unknown>>}
   */
  async submitIsoPacs009AndWait(message, options = {}) {
    const record =
      options === undefined || options === null
        ? {}
        : requireIsoPlainObject(options, "submitIsoPacs009AndWait.options");
    const { wait: waitOptions, ...submitOptions } = record;
    let normalizedWait =
      waitOptions === undefined || waitOptions === null
        ? undefined
        : requireIsoPlainObject(waitOptions, "submitIsoPacs009AndWait.options.wait");
    if (normalizedWait) {
      const needsSignal = normalizedWait.signal === undefined && submitOptions.signal !== undefined;
      const needsRetryProfile =
        normalizedWait.retryProfile === undefined && submitOptions.retryProfile !== undefined;
      if (needsSignal || needsRetryProfile) {
        normalizedWait = { ...normalizedWait };
        if (needsSignal) {
          normalizedWait.signal = submitOptions.signal;
        }
        if (needsRetryProfile) {
          normalizedWait.retryProfile = submitOptions.retryProfile;
        }
      }
    }
    const submission = await this.submitIsoPacs009(message, submitOptions);
    const messageId = submission?.message_id;
    if (!messageId) {
      rejectError("ISO pacs.009 submission did not return a message_id");
    }
    return this.waitForIsoMessageStatus(messageId, normalizedWait);
  }

  /**
   * Build and submit an ISO 20022 message from structured fields.
   * @param {import("./index").BuildPacs008Options | import("./index").BuildPacs009Options} fields
   * @param {{kind?: string, contentType?: string, profile?: string, signal?: AbortSignal, wait?: IsoMessageWaitOptions}} [options]
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async submitIsoMessage(fields, options = {}) {
    const resolvedOptions =
      options === undefined || options === null
        ? {}
        : requireIsoPlainObject(options, "submitIsoMessage.options");
    const normalizedKind =
      resolvedOptions.kind === undefined || resolvedOptions.kind === null
        ? null
        : normalizeIsoMessageKind(
            resolvedOptions.kind,
            "submitIsoMessage options.kind",
          );
    const normalizedMessageKind =
      resolvedOptions.messageKind === undefined || resolvedOptions.messageKind === null
        ? null
        : normalizeIsoMessageKind(
            resolvedOptions.messageKind,
            "submitIsoMessage options.messageKind",
          );
    if (
      normalizedKind !== null &&
      normalizedMessageKind !== null &&
      normalizedKind !== normalizedMessageKind
    ) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "submitIsoMessage options.kind and options.messageKind must match when both are provided",
        "submitIsoMessage.options.kind",
      );
    }
    const kind = normalizedKind ?? normalizedMessageKind ?? "pacs.008";
    const { signal, contentType, retryProfile, profile } = normalizeIsoSubmissionOptions(
      resolvedOptions,
      "submitIsoMessage",
      ["kind", "messageKind", "wait", "retryProfile"],
    );
    const normalizedFields =
      fields === undefined || fields === null ? {} : { ...fields };
    const xml =
      kind === "pacs.009"
        ? buildPacs009Message(normalizedFields)
        : buildPacs008Message(normalizedFields);
    const submissionOptions = {
      signal,
      contentType:
        contentType ??
        (kind === "pacs.009" ? "application/pacs009+xml" : "application/pacs008+xml"),
      profile,
      retryProfile,
    };
    let waitOptions = resolvedOptions.wait;
    if (waitOptions !== undefined && waitOptions !== null) {
      waitOptions = requireIsoPlainObject(waitOptions, "submitIsoMessage.options.wait");
      const needsSignal = waitOptions.signal === undefined && submissionOptions.signal;
      const needsRetryProfile =
        waitOptions.retryProfile === undefined && submissionOptions.retryProfile;
      if (needsSignal || needsRetryProfile) {
        waitOptions = { ...waitOptions };
        if (needsSignal) {
          waitOptions.signal = submissionOptions.signal;
        }
        if (needsRetryProfile) {
          waitOptions.retryProfile = submissionOptions.retryProfile;
        }
      }
      return kind === "pacs.009"
        ? this.submitIsoPacs009AndWait(xml, { ...submissionOptions, wait: waitOptions })
        : this.submitIsoPacs008AndWait(xml, { ...submissionOptions, wait: waitOptions });
    }
    return kind === "pacs.009"
      ? this.submitIsoPacs009(xml, submissionOptions)
      : this.submitIsoPacs008(xml, submissionOptions);
  }

  /**
   * Count prover reports with optional filters.
   * @param {Record<string, unknown>} filters
   * @param {{signal?: AbortSignal}} [options]
   * @returns {Promise<number>}
   */
  async countProverReports(filters = {}, options = {}) {
    const normalizedFilters = ToriiClient._encodeProverFilters(filters);
    const { signal } = normalizeSignalOnlyOption(options, "countProverReports");
    const response = await this._request("GET", "/v1/zk/prover/reports/count", {
      params: normalizedFilters,
      signal,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    if (!payload || typeof payload.count === "undefined") {
      rejectError("invalid prover count payload");
    }
    return ToriiClient._normalizeUnsignedInteger(payload.count, "prover count", {
      allowZero: true,
    });
  }

  async _request(method, path, options = {}) {
    return this.#request(method, path, options);
  }

  async #request(method, path, options = {}) {
    const pathIsAbsolute = isAbsoluteUrl(path);
    const url = pathIsAbsolute ? new URL(path) : resolveBaseRelativeUrl(this._baseUrl, path);
    const protocol = url.protocol.toLowerCase();
    const originMatches =
      url.host === this.#baseHost && protocol === this.#baseProtocol;
    // Bootstrap discovery must never inherit account, API, operator, or cookie credentials.
    const initHeaders = options.publicRequest === true
      ? { ...options.headers }
      : this.#createHeaders(options.headers);
    const operatorSigningContext = options.requireIsoOperatorAuth === true
      ? requireIsoOperatorSigningContext(options.operatorSigningContext, initHeaders)
      : resolveOperatorSigningContext(options.operatorSigningContext);
    const hasCredentials = headersContainCredentials(initHeaders);
    const canonicalAuth = options.canonicalAuth
      ? ToriiClient.#normalizeCanonicalAuth(options.canonicalAuth)
      : null;
    const hasCanonicalAuth = canonicalAuth !== null;
    const hasOperatorAuth = operatorSigningContext !== null;
    rejectMixedRequestAuth(canonicalAuth, operatorSigningContext);
    if (hasOperatorAuth) {
      rejectRetiredIsoAuthHeaders(initHeaders, "operator request");
    }
    if (hasCanonicalAuth) rejectPrecomputedCanonicalHeaders(initHeaders);
    const exactNetworkId = options.exactNetworkId ?? null;
    let signingNetworkId = null;
    if (hasCanonicalAuth) {
      if (!(this._localSigningContext instanceof LocalSigningContext)) {
        rejectType("ToriiClient: canonicalAuth requires an immutable LocalSigningContext");
      }
      signingNetworkId = this._localSigningContext.networkId;
    }
    if (exactNetworkId !== null) {
      const exactBytes = Buffer.from(networkIdBytes(exactNetworkId, "exactNetworkId"));
      if (!hasCanonicalAuth) {
        rejectType("ToriiClient: exactNetworkId requires canonicalAuth for a signed request");
      }
      const configuredBytes = Buffer.from(
        networkIdBytes(signingNetworkId, "localSigningContext.networkId"),
      );
      if (!exactBytes.equals(configuredBytes)) {
        rejectType("ToriiClient: exactNetworkId must equal localSigningContext.networkId");
      }
    }
    const hasCanonicalNonce = hasHeader(initHeaders, "x-iroha-nonce");
    const hasOperatorNonce = hasHeader(initHeaders, "x-iroha-operator-nonce");
    const hasOneShotAuth = hasCanonicalAuth || hasOperatorAuth || hasCanonicalNonce || hasOperatorNonce;
    const hasSensitiveBody = bodyContainsSensitiveKeyMaterial(options.body, initHeaders);
    const hasSensitiveTransport = hasCredentials || hasCanonicalAuth || hasOperatorAuth || hasSensitiveBody;
    const allowAbsoluteUrl = options.allowAbsoluteUrl === true;
    const methodUpper = String(method).toUpperCase();
    if (hasSensitiveTransport) {
      if (protocol !== this.#baseProtocol) {
        rejectError(`ToriiClient: refusing to send sensitive request material over mismatched scheme ${url.protocol}; use ${this.#baseProtocol.replace(":", "")} URLs derived from the client base URL.`);
      }
      if (pathIsAbsolute && url.host !== this.#baseHost) {
        rejectError(`ToriiClient: refusing to send sensitive request material to mismatched host ${url.host} (expected ${this.#baseHost}); use relative paths on the configured base URL.`);
      }
      if (!this.#allowInsecure && !isSecureProtocol(protocol)) {
        rejectError(`ToriiClient: refusing to send sensitive request material over insecure protocol ${url.protocol}; use https or allowInsecure: true.`);
      }
    } else if (pathIsAbsolute && !originMatches && !allowAbsoluteUrl) {
      rejectError("ToriiClient: absolute URLs are blocked when no credentials are attached; pass allowAbsoluteUrl: true to override.");
    }
    if (hasSensitiveTransport && this.#allowInsecure && !isSecureProtocol(protocol)) {
      this._emitInsecureTransportTelemetry({
        client: "torii",
        method: methodUpper,
        hasCredentials,
        hasSensitiveBody,
        hasCanonicalAuth,
        allowInsecure: true,
        url: url.toString(),
        baseUrl: this._baseUrl,
        host: url.host,
        protocol,
        pathIsAbsolute,
        originMatches,
      });
    }
    if (options.params && Object.keys(options.params).length > 0) {
      const search = new URLSearchParams();
      for (const [key, value] of Object.entries(options.params)) {
        if (Array.isArray(value)) {
          for (const item of value) {
            search.append(key, String(item));
          }
        } else if (typeof value !== "undefined") {
          search.append(key, String(value));
        }
      }
      url.search = search.toString();
    }
    const init = {
      method: methodUpper,
      headers: initHeaders,
      body: options.body,
      ...(options.cache === "no-store" ? { cache: "no-store" } : {}),
      ...(options.publicRequest === true ? { credentials: "omit" } : {}),
    };
    // Canonical authentication and caller-supplied nonce headers are one-shot.
    // It is unsafe to replay them after dispatch or to let Fetch follow a
    // redirect after the original endpoint may already have admitted the body.
    if (hasOneShotAuth) {
      init.redirect = "error";
    } else if (options.redirect !== undefined) {
      init.redirect = options.redirect;
    }
    if (canonicalAuth) {
      const bodyForSigning =
        init.body === undefined || init.body === null
          ? Buffer.alloc(0)
          : Buffer.isBuffer(init.body)
            ? init.body
            : Buffer.from(init.body);
      const canonicalHeaders = buildCanonicalRequestHeaders({
        accountId: canonicalAuth.accountId,
        networkId: signingNetworkId,
        method: methodUpper,
        path: url.pathname,
        query: url.search.startsWith("?") ? url.search.slice(1) : url.search,
        body: bodyForSigning,
        privateKey: canonicalAuth.privateKey,
      });
      for (const [key, value] of Object.entries(canonicalHeaders)) {
        setHeader(initHeaders, key, value);
      }
    }
    // Sign only after the final URL query and request body are fixed.
    await applyOperatorRequestHeaders(initHeaders, operatorSigningContext, methodUpper, url, init.body);
    const retryProfileName =
      typeof options.retryProfile === JS_TYPE_STRING && options.retryProfile
        ? options.retryProfile
        : "default";
    const retryPolicy =
      (this.#config.retryProfiles && this.#config.retryProfiles[retryProfileName]) ||
      this.#config.retryProfiles?.default ||
      null;
    const policyMaxRetries =
      retryPolicy && typeof retryPolicy.maxRetries === JS_TYPE_NUMBER
        ? retryPolicy.maxRetries
        : this.#config.maxRetries;
    const policyBackoffInitial =
      retryPolicy && typeof retryPolicy.backoffInitialMs === JS_TYPE_NUMBER
        ? retryPolicy.backoffInitialMs
        : this.#config.backoffInitialMs;
    const policyBackoffMultiplier =
      retryPolicy && typeof retryPolicy.backoffMultiplier === JS_TYPE_NUMBER
        ? retryPolicy.backoffMultiplier
        : this.#config.backoffMultiplier;
    const policyMaxBackoffMs =
      retryPolicy && typeof retryPolicy.maxBackoffMs === JS_TYPE_NUMBER
        ? retryPolicy.maxBackoffMs
        : this.#config.maxBackoffMs;
    const maxRetries = options.disableRetries === true || hasOneShotAuth
      ? 0
      : Math.max(0, Number(policyMaxRetries) || 0);
    let attempt = 0;
    let backoffMs = Math.max(0, policyBackoffInitial || 0);
    let lastError;

    // eslint-disable-next-line no-constant-condition
    while (true) {
      attempt += 1;
      const attemptStartedAt = Date.now();
      const callerSignal = options.signal ?? null;
      const attemptSignal = composeRequestSignal(
        callerSignal,
        this.#config.timeoutMs,
      );
      const signal = attemptSignal.signal;
      try {
        const response = await Reflect.apply(this._fetch, undefined, [url.toString(), {
          ...init,
          // Give fetch a fresh header bag for each retry attempt. Reusing the
          // same object across retries can break native fetch implementations.
          headers: cloneHeadersForFetch(initHeaders),
          signal: signal ?? undefined,
        }]);
        attemptSignal.cleanup();
        let responseStatus;
        try {
          responseStatus = responseStatusWithoutUserGetter(response);
        } catch (error) {
          cancelResponseBodyBestEffort(
            response,
            "discarding Torii response with an invalid status field",
          );
          throw error;
        }
        if (
          !this._shouldRetryResponse(methodUpper, responseStatus, retryPolicy) ||
          attempt > maxRetries
        ) {
          rememberResponseCallerSignal(response, callerSignal);
          return response;
        }
        cancelResponseBodyBestEffort(
          response,
          "discarding retryable Torii response body",
        );
        const durationMs = Math.max(0, Date.now() - attemptStartedAt);
        lastError = new Error(`retryable status ${responseStatus}`);
        this._emitRetryTelemetry({
          phase: "response",
          attempt,
          nextAttempt: attempt + 1,
          maxRetries,
          method: methodUpper,
          url: url.toString(),
          status: responseStatus,
          backoffMs,
          profile: retryProfileName,
          durationMs,
        });
      } catch (error) {
        attemptSignal.cleanup();
        if (options.signal && signalIsAborted(options.signal)) {
          throw error;
        }
        if (
          !this._shouldRetryError(
            error,
            methodUpper,
            attemptSignal.didTimeout(),
            retryPolicy,
          ) ||
          attempt > maxRetries
        ) {
          throw error;
        }
        const durationMs = Math.max(0, Date.now() - attemptStartedAt);
        lastError = error;
        this._emitRetryTelemetry({
          phase: attemptSignal.didTimeout() ? "timeout" : "network",
          attempt,
          nextAttempt: attempt + 1,
          maxRetries,
          method: methodUpper,
          url: url.toString(),
          errorName: error?.name ?? null,
          errorMessage: error?.message ?? null,
          timedOut: attemptSignal.didTimeout(),
          backoffMs,
          profile: retryProfileName,
          durationMs,
        });
      }

      if (attempt > maxRetries) {
        throw lastError ?? new Error("request failed after maximum retries");
      }

      if (backoffMs > 0) {
        await delay(backoffMs, callerSignal);
        const multiplier = policyBackoffMultiplier || 1;
        backoffMs = Math.min(
          Math.max(backoffMs * multiplier, policyBackoffInitial || 0),
          policyMaxBackoffMs || backoffMs,
        );
      }
    }
  }

  _emitRetryTelemetry(event) {
    const hook = this.#config.retryTelemetryHook;
    if (typeof hook !== JS_TYPE_FUNCTION) {
      return;
    }
    const payload = {
      ...event,
      timestampMs: Date.now(),
    };
    try {
      hook(payload);
    } catch {
      // No-op: telemetry hooks must never break retries.
    }
  }

  _emitInsecureTransportTelemetry(event) {
    const hook = this.#config.insecureTransportTelemetryHook;
    if (typeof hook !== JS_TYPE_FUNCTION) {
      return;
    }
    try {
      hook({ ...event, timestampMs: Date.now() });
    } catch {
      // No-op: telemetry hooks must never break requests.
    }
  }

  _createHeaders(provided = {}) {
    return this.#createHeaders(provided);
  }

  #createHeaders(provided = {}) {
    const headers = {};
    const applyEntries = (source) => {
      if (!source) {
        return;
      }
      if (typeof Headers === JS_TYPE_FUNCTION && source instanceof Headers) {
        source.forEach((value, key) => {
          setHeader(headers, key, value);
        });
        return;
      }
      if (
        typeof source[Symbol.iterator] === JS_TYPE_FUNCTION &&
        !isPlainObject(source)
      ) {
        for (const entry of source) {
          if (!entry) {
            continue;
          }
          const [key, value] = entry;
          if (key === undefined) {
            continue;
          }
          if (value === null) {
            deleteHeader(headers, key);
          } else if (value !== undefined) {
            setHeader(headers, key, value);
          }
        }
        return;
      }
      if (typeof source === JS_TYPE_OBJECT) {
        for (const [key, value] of Object.entries(source)) {
          if (value === null) {
            deleteHeader(headers, key);
            continue;
          }
          if (value !== undefined) {
            setHeader(headers, key, value);
          }
        }
      }
    };
    applyEntries(this.#config.defaultHeaders);
    applyEntries(provided);
    if (this.#config.apiToken) {
      if (!hasHeader(headers, "x-api-token")) {
        headers["X-API-Token"] = this.#config.apiToken;
      }
    }
    if (this.#config.authToken && !hasHeader(headers, "authorization")) {
      headers.Authorization = `Bearer ${this.#config.authToken}`;
    }
    attachHeaderAccessors(headers);
    return headers;
  }

  _hasClientCredentials() {
    return (
      Boolean(this.#config?.authToken) ||
      Boolean(this.#config?.apiToken) ||
      headersContainCredentials(this.#config?.defaultHeaders)
    );
  }

  _assertPermissionRequirement(requirePermissions, contextPath) {
    if (!requirePermissions) {
      return;
    }
    if (this._hasClientCredentials()) {
      return;
    }
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${contextPath} requires authToken or apiToken when requirePermissions is true`,
      `${contextPath}.requirePermissions`,
    );
  }

  _shouldRetryResponse(method, status, policy) {
    const activePolicy =
      policy ||
      this.#config.retryProfiles?.default || {
        retryMethods: this.#config.retryMethods,
        retryStatuses: this.#config.retryStatuses,
      };
    const methods = activePolicy.retryMethods ?? this.#config.retryMethods;
    const statuses = activePolicy.retryStatuses ?? this.#config.retryStatuses;
    return methods.has(method.toUpperCase()) && statuses.has(Number(status));
  }

  _shouldRetryError(error, method, timedOut, policy) {
    const activePolicy =
      policy ||
      this.#config.retryProfiles?.default || {
        retryMethods: this.#config.retryMethods,
      };
    const methods = activePolicy.retryMethods ?? this.#config.retryMethods;
    if (!methods.has(method.toUpperCase())) {
      return false;
    }
    if (timedOut) {
      return true;
    }
    if (this._isAbortError(error)) {
      return timedOut;
    }
    const errorCode =
      error && typeof error.code === JS_TYPE_STRING
        ? error.code.trim().toUpperCase()
        : "";
    const errorMessage =
      error && typeof error.message === JS_TYPE_STRING
        ? error.message.toUpperCase()
        : "";
    if (
      error &&
      (error.name === "TypeError" ||
        errorCode === "ECONNRESET" ||
        errorCode === "EPIPE" ||
        /\b(?:ECONNRESET|EPIPE)\b/u.test(errorMessage))
    ) {
      return true;
    }
    return false;
  }

  _isAbortError(error) {
    if (!error) {
      return false;
    }
    if (typeof DOMException !== "undefined" && error instanceof DOMException) {
      return error.name === "AbortError";
    }
    return error.name === "AbortError";
  }

  async _expectStatus(response, expected, options = {}) {
    return this.#expectStatus(response, expected, options);
  }

  async #expectStatus(response, expected, options = {}) {
    if (expected.includes(responseStatusWithoutUserGetter(response))) {
      return;
    }
    throw await this._buildHttpError(response, expected, options);
  }

  async _buildHttpError(response, expected, options = {}) {
    const { bodyText, bodyJson } = await this._readErrorBody(response, options);
    const fields = extractToriiErrorFields({
      bodyText,
      bodyJson,
      rejectCodeHeader: this._getHeader(response, "x-iroha-reject-code"),
    });
    return new ToriiHttpError({
      status: responseStatusWithoutUserGetter(response),
      statusText: responseStatusTextWithoutUserGetter(response),
      expected,
      ...fields,
      bodyText,
      bodyJson,
    });
  }

  async _readErrorBody(response, options = {}) {
    const { signal, maximumBodyBytes, responseLabel = "Torii" } = options;
    let contentType;
    try {
      contentType = this._getHeader(response, "content-type");
    } catch (error) {
      cancelResponseBodyBestEffort(
        response,
        "Torii HTTP error response had unreadable headers",
      );
      throw error;
    }
    const looksLikeJson =
      maximumBodyBytes !== undefined || isExactJsonMediaType(contentType);
    const maxBytes = maximumBodyBytes ?? HTTP_ERROR_BODY_MAX_BYTES;
    const context =
      maximumBodyBytes === undefined
        ? "Torii HTTP error response"
        : `${responseLabel} error`;
    let bytes;
    try {
      ({ bytes } = await this._readBoundedResponseBytes(
        response,
        maxBytes,
        context,
        { signal },
      ));
    } catch (error) {
      if (
        signalIsAborted(signal) ||
        error?.name === "AbortError" ||
        error?.name === "TimeoutError"
      ) {
        throw error;
      }
      if (maximumBodyBytes !== undefined) {
        if (
          error instanceof RangeError ||
          /Content-Length exceeds the safe integer range/u.test(error?.message ?? "")
        ) {
          rejectType(`${context} response exceeds its ${maxBytes}-byte size bound`, { cause: error });
        }
        if (/Content-Length header/u.test(error?.message ?? "")) {
          rejectType(`${context} response Content-Length must be a canonical unsigned decimal integer`, { cause: error });
        }
        throw error;
      }
      return { bodyText: null, bodyJson: null };
    }
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (error) {
      if (maximumBodyBytes !== undefined) {
        rejectType(`${context} response body must be strict UTF-8`, {
          cause: error,
        });
      }
      return { bodyText: null, bodyJson: null };
    }
    if (!text) {
      return { bodyText: null, bodyJson: null };
    }
    const trimmed = text.trim();
    if (!trimmed) {
      return { bodyText: "", bodyJson: null };
    }
    if (!looksLikeJson) return { bodyText: text, bodyJson: null };
    try {
      return { bodyText: text, bodyJson: JSON.parse(trimmed) };
    } catch {
      return { bodyText: text, bodyJson: null };
    }
  }

  static _encodeProverFilters(filters) {
    if (filters === undefined || filters === null) {
      return {};
    }
    const record = ToriiClient._requirePlainObject(filters, "prover filters");
    const params = {};
    for (const [rawKey, rawValue] of Object.entries(record)) {
      if (rawValue === undefined || rawValue === null) {
        continue;
      }
      const entry = PROVER_FILTER_ALIAS_MAP.get(rawKey);
      if (!entry) {
        throw createValidationError(
          ValidationErrorCode.INVALID_OBJECT,
          `unknown prover filter '${rawKey}'`,
          `proverFilters.${rawKey}`,
        );
      }
      const { key, spec } = entry;
      if (spec.type === "boolean") {
        const flag = normalizeProverFilterBoolean(rawValue, `proverFilters.${rawKey}`);
        if (flag) {
          params[key] = true;
        }
        continue;
      }
      if (spec.type === JS_TYPE_STRING) {
        params[key] = normalizeProverFilterString(rawValue, `proverFilters.${rawKey}`);
        continue;
      }
      if (spec.type === "integer") {
        params[key] = ToriiClient._normalizeUnsignedInteger(
          rawValue,
          `proverFilters.${rawKey}`,
          { allowZero: Boolean(spec.allowZero) },
        );
        continue;
      }
      if (spec.type === "enum") {
        params[key] = normalizeProverFilterEnum(
          rawValue,
          `proverFilters.${rawKey}`,
          spec.values,
        );
        continue;
      }
    }
    return params;
  }

  async _submitSorafsOrderbookTransaction(path, route, signedTransaction, options, context) {
    const normalized = requirePlainObjectOption(options, `${context} options`); assertSupportedOptionKeys(normalized, new Set(["signal", "expectedReceiptSigner"]), `${context} options`);
    const { signal } = normalizeSignalOption(normalized, context); if (!(this._localSigningContext instanceof LocalSigningContext)) {
      rejectType(`${context} requires ToriiClient options.localSigningContext`);
    }
    const request = this._request.bind(this); const validateDataModel = this._ensureDataModelValidation.bind(this);
    validateSorafsOrderbookSubmissionTransport(this._baseUrl, this.#allowInsecure, path, (event) => this._emitInsecureTransportTelemetry(event), context);
    assertSorafsOrderbookFixedHeaders(this.#config.defaultHeaders, `${context} defaultHeaders`);
    const fixedHeaders = { "Content-Type": APPLICATION_NORITO, Accept: APPLICATION_NORITO, "Accept-Encoding": "identity" };
    const requestHeaders = this._createHeaders(fixedHeaders);
    const headerFingerprint = sorafsOrderbookHeaderFingerprint(requestHeaders);
    const prepared = prepareSorafsOrderbookSubmission({
      route, signedTransaction,
      expectedNetworkIdBytes: networkIdBytes(this._localSigningContext.networkId, `${context}.networkId`),
      expectedChainDiscriminant: this._localSigningContext.chainDiscriminant,
      expectedReceiptSigner: normalized.expectedReceiptSigner,
      native: resolveOptionalNativeBinding(this._nativeRuntime), context,
    });
    const operation = createSorafsOrderbookSubmissionDeadline(signal, this.#config.timeoutMs, context, { addAbortListener: addSignalAbortListener, removeAbortListener: removeSignalAbortListener, isAborted: signalIsAborted, abortReason: signalAbortReason });
    try {
      throwIfAborted(operation.signal);
      await waitForPromiseWithSignal(validateDataModel(operation.signal), operation.signal);
      const {
        SORAFS_ORDERBOOK_RECEIPT_MAX_BYTES_V1,
        validateSorafsOrderbookSubmissionHeaders,
        verifySorafsOrderbookSubmissionReceipt,
      } = await waitForPromiseWithSignal(loadToriiOptionalModule(), operation.signal);
      throwIfAborted(operation.signal);
      assertSorafsOrderbookFixedHeaders(this.#config.defaultHeaders, `${context} defaultHeaders`);
      if (sorafsOrderbookHeaderFingerprint(this._createHeaders(fixedHeaders)) !== headerFingerprint) {
        rejectType(`${context} effective request headers changed during preflight`);
      }
      let response;
      try {
        response = await waitForResponseWithSignal(request("POST", path, {
          headers: requestHeaders,
          body: prepared.body, disableRetries: true, redirect: "error", signal: operation.signal,
        }), operation.signal, context);
        if (responseStatusWithoutUserGetter(response) !== 202) rejectError(`${context} expected HTTP status 202`);
        validateSorafsOrderbookSubmissionHeaders({
          contentType: this._getHeader(response, "content-type"), contentEncoding: this._getHeader(response, "content-encoding"),
          entrypointHash: this._getHeader(response, "x-iroha-entrypoint-hash"),
          signedTransactionHash: this._getHeader(response, "x-iroha-signed-transaction-hash"),
        }, prepared.identity);
        const { bytes } = await this._readBoundedResponseBytes(response,
          SORAFS_ORDERBOOK_RECEIPT_MAX_BYTES_V1, `${context} receipt`, { signal: operation.signal });
        return verifySorafsOrderbookSubmissionReceipt(Buffer.from(bytes), prepared);
      } catch (error) {
        if (response !== undefined) cancelResponseBodyBestEffort(response, `${context} outcome is ambiguous`);
        throw new SorafsOrderbookSubmissionAmbiguousError(route, prepared.identity, error);
      }
    } finally {
      operation.dispose();
    }
  }

  /**
   * @template [T=unknown]
   * @param {string} path
   * @param {EventStreamOptions & { params?: Record<string, unknown> }} [options]
   * @returns {AsyncGenerator<SseEvent<T>, void, unknown>}
   */
  _streamSse(path, options = {}) {
    const { signal } = normalizeSignalOption(options, "_streamSse");
    const params = options.params;
    const headers = this._createHeaders({
      ...(options.headers ?? {}),
      Accept: "text/event-stream",
    });
    if (options.lastEventId) {
      headers["Last-Event-ID"] = options.lastEventId;
    }
    const requestOptions = {
      params,
      headers,
      signal,
      retryProfile: "streaming",
      canonicalAuth: options.canonicalAuth,
      operatorSigningContext: options.operatorSigningContext,
      disableRetries: options.disableRetries === true,
      redirect: options.redirect,
    };
    const self = this;
    return (async function* iterator() {
      const response = await self._request("GET", path, requestOptions);
      await self._expectStatus(response, [200]);
      const decoder = new TextDecoder("utf-8", {
        fatal: options.strictUtf8 === true,
      });
      let buffer = "";
      for await (const chunk of readBodyChunks(responseBodyWithoutUserGetter(response), signal)) {
        buffer += decoder.decode(chunk, { stream: true });
        const { events, remainder } = flushSseBuffer(buffer);
        buffer = remainder;
        for (const event of events) {
          yield event;
        }
      }
      buffer += decoder.decode();
      if (buffer.length > 0) {
        const { events } = flushSseBuffer(`${buffer}\n\n`);
        for (const event of events) {
          yield event;
        }
      }
    })();
  }

  /**
   * @template [T=unknown]
   * @param {string} raw
   * @returns {SseEvent<T> | null}
   */
  static _parseSseEvent(raw) {
    const lines = raw.split(/\r?\n/);
    let event = null;
    let id = null;
    let retry = null;
    const dataLines = [];
    for (const line of lines) {
      if (!line || line.startsWith(":")) {
        continue;
      }
      const colonIndex = line.indexOf(":");
      const field = colonIndex === -1 ? line : line.slice(0, colonIndex);
      let value = colonIndex === -1 ? "" : line.slice(colonIndex + 1);
      if (value.startsWith(" ")) {
        value = value.slice(1);
      }
      switch (field) {
        case "event":
          event = value || null;
          break;
        case "data":
          dataLines.push(value);
          break;
        case "id":
          id = value || null;
          break;
        case "retry": {
          const parsed = Number(value);
          if (Number.isFinite(parsed)) {
            retry = parsed;
          }
          break;
        }
        default:
          break;
      }
    }
    if (dataLines.length === 0 && !event && !id) {
      return null;
    }
    const rawData = dataLines.join("\n");
    let data = rawData;
    const trimmed = rawData.trim();
    if (trimmed.length > 0) {
      try {
        data = JSON.parse(trimmed);
      } catch {
        data = rawData;
      }
    }
    return {
      event,
      data,
      id,
      retry,
      raw: rawData.length > 0 ? rawData : null,
    };
  }

  _getHeader(response, name) {
    return this.#getHeader(response, name);
  }

  #getHeader(response, name) {
    const headers = responseHeadersWithoutUserGetter(response);
    const value = headerValueWithoutUserGetter(headers, name);
    return value === undefined ? null : value;
  }

  _acceptHeader() {
    const headers = this.#config?.defaultHeaders ?? {};
    for (const [key, value] of Object.entries(headers)) {
      if (value !== undefined && value !== null && key.toLowerCase() === "accept") {
        return String(value);
      }
    }
    return APPLICATION_JSON;
  }

  async _maybeJson(
    response,
    {
      maxBytes = JSON_RESPONSE_MAX_BYTES,
      context = "Torii JSON response",
      signal,
    } = {},
  ) {
    return maybeJsonResponse(
      this._maybeBoundedJson.bind(this),
      response,
      { maxBytes, context, signal, signalIsAborted },
    );
  }

  async _maybeBoundedJson(response, maxBytes, context, { signal } = {}) {
    return maybeBoundedJsonResponse(response, maxBytes, context, {
      signal,
      getHeader: this._getHeader.bind(this),
      readBoundedResponseBytes: this._readBoundedResponseBytes.bind(this),
      cancelResponseBodyBestEffort,
      cancelReadableBodyBestEffort,
      signalIsAborted,
      bodyReadAbortError,
    });
  }

  async _readBoundedLosslessIntegerJson(
    response,
    maxBytes,
    context,
    { signal, plainObjects = false, includeSourceBytes = false, floatingPointPaths } = {},
  ) {
    let contentType;
    try {
      contentType = this._getHeader(response, "content-type");
    } catch (error) {
      cancelResponseBodyBestEffort(
        response,
        `${context} rejected an unreadable Content-Type header`,
      );
      throw error;
    }
    if (!isExactJsonMediaType(contentType)) {
      cancelResponseBodyBestEffort(
        response,
        `${context} rejected a non-JSON response body`,
      );
      rejectType(`${context} must use the application/json media type`);
    }
    const { bytes, body } = await this._readBoundedResponseBytes(
      response,
      maxBytes,
      context,
      { signal },
    );
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (error) {
      cancelReadableBodyBestEffort(body, `${context} rejected invalid UTF-8`);
      rejectType(`${context} must be valid UTF-8`, { cause: error });
    }
    try {
      const parsed = floatingPointPaths === undefined
        ? parseStrictLosslessIntegerJson(text, context)
        : parseStrictLosslessJson(text, context, { floatingPointPaths });
      if (signalIsAborted(signal)) {
        cancelReadableBodyBestEffort(body, `${context} was aborted`);
        throw bodyReadAbortError(signal, context);
      }
      const payload = plainObjects ? JSON.parse(text) : parsed;
      return includeSourceBytes
        ? Object.freeze({ payload, sourceBytes: new Uint8Array(bytes) })
        : payload;
    } catch (error) {
      if (signalIsAborted(signal) || error?.name === "AbortError") {
        cancelReadableBodyBestEffort(body, `${context} was aborted`);
        throw error;
      }
      cancelReadableBodyBestEffort(body, `${context} rejected invalid JSON`);
      throw error;
    }
  }

  async _readBoundedResponseBytes(response, maxBytes, context, { signal } = {}) {
    return this.#readBoundedResponseBytes(response, maxBytes, context, { signal });
  }

  async #readBoundedResponseBytes(response, maxBytes, context, options = {}) {
    // Body reads stay abortable after the headers arrived: default to the
    // signal the request was issued with.
    const signal = options.signal ?? responseCallerSignal(response);
    const rejectResponse = (error) => {
      cancelResponseBodyBestEffort(response, `${context} rejected its response body`);
      throw error;
    };
    if (signalIsAborted(signal)) {
      rejectResponse(bodyReadAbortError(signal, context));
    }
    let contentLength;
    try {
      contentLength = this.#getHeader(response, "content-length");
    } catch (error) {
      rejectResponse(error);
    }
    if (contentLength !== null) {
      if (typeof contentLength !== JS_TYPE_STRING) {
        rejectResponse(
          new TypeError(`${context} has a non-string Content-Length header`),
        );
      }
      if (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength)) {
        rejectResponse(
          new TypeError(`${context} has an invalid Content-Length header`),
        );
      }
      const declaredBytes = Number(contentLength);
      if (!Number.isSafeInteger(declaredBytes)) {
        rejectResponse(
          new RangeError(
            `${context} Content-Length exceeds the safe integer range`,
          ),
        );
      }
      if (declaredBytes > maxBytes) {
        rejectResponse(
          new RangeError(
            `${context} exceeds the ${maxBytes}-byte response limit`,
          ),
        );
      }
    }

    const body = responseBodyWithoutUserGetter(response);
    if (!body) {
      rejectResponse(
        new TypeError(
          `${context} requires a byte-stream response body so its size can be bounded`,
        ),
      );
    }
    const genuineReader = hasReadableStreamBrand(body);
    let reader;
    try {
      reader = callIntrinsicOrOwnMethod(
        body,
        readableStreamGetReader,
        "getReader",
      );
    } catch (error) {
      cancelReadableBodyBestEffort(
        body,
        `${context} could not acquire a bounded body reader`,
      );
      rejectType(`${context} requires a byte-stream response body so its size can be bounded`, { cause: error });
    }

    const configuredTimeoutMs = Number(this.#config?.timeoutMs);
    const readTimeoutMs =
      Number.isFinite(configuredTimeoutMs) && configuredTimeoutMs > 0
        ? Math.min(configuredTimeoutMs, BOUNDED_JSON_MAX_READ_TIMEOUT_MS)
        : BOUNDED_JSON_MAX_READ_TIMEOUT_MS;
    let rejectDeadline;
    const deadline = new Promise((_, reject) => {
      rejectDeadline = reject;
    });
    // A rejection may race with synchronous completion; keep it handled even
    // after all read races have settled.
    deadline.catch(() => {});
    const timeoutId = setTimeout(() => {
      const error = new Error(
        `${context} body read timed out after ${readTimeoutMs}ms`,
      );
      error.name = "TimeoutError";
      rejectDeadline(error);
    }, readTimeoutMs);
    const onAbort = () => rejectDeadline(bodyReadAbortError(signal, context));

    const chunks = [];
    let byteLength = 0;
    let abortListenerAttempted = false;
    try {
      if (signal) {
        abortListenerAttempted = true;
        addSignalAbortListener(signal, onAbort);
        if (signalIsAborted(signal)) onAbort();
      }
      while (true) {
        const read = Promise.resolve().then(() =>
          callIntrinsicOrOwnMethod(
            reader,
            genuineReader ? readerRead : null,
            "read",
          ),
        );
        const readResult = exactEnumerableDataRecord(
          await Promise.race([read, deadline]),
          ["done", "value"],
          `${context} body stream read result`,
        );
        if (typeof readResult.done !== "boolean") {
          rejectType(`${context} body stream read result.done must be a boolean`);
        }
        if (readResult.done) {
          if (readResult.value !== undefined) {
            rejectType(`${context} completed body stream read must not return a value`);
          }
          break;
        }
        const value = readResult.value;
        let buffer;
        let byteOffset;
        let chunkByteLength;
        try {
          if (typedArrayTagGetter.call(value) !== "Uint8Array") {
            rejectType("not Uint8Array");
          }
          buffer = typedArrayBufferGetter.call(value);
          byteOffset = typedArrayByteOffsetGetter.call(value);
          chunkByteLength = typedArrayByteLengthGetter.call(value);
        } catch {
          rejectType(`${context} body stream returned a non-byte chunk`);
        }
        let isShared = false;
        if (sharedArrayBufferByteLengthGetter !== null) {
          try {
            sharedArrayBufferByteLengthGetter.call(buffer);
            isShared = true;
          } catch {
            // A normal ArrayBuffer fails the SharedArrayBuffer brand check.
          }
        }
        if (isShared) {
          rejectType(`${context} body stream must not use SharedArrayBuffer-backed chunks`);
        }
        if (chunkByteLength === 0) {
          rejectType(`${context} body stream returned an empty non-progress chunk`);
        }
        if (chunks.length >= BOUNDED_JSON_MAX_STREAM_CHUNKS) {
          rejectRange(`${context} body stream returned too many fragmented chunks`);
        }
        byteLength += chunkByteLength;
        if (byteLength > maxBytes) {
          rejectRange(`${context} exceeds the ${maxBytes}-byte response limit`);
        }
        // Snapshot immediately: custom readers may reuse or mutate their views.
        chunks.push(copyArrayBufferBytes(buffer, byteOffset, chunkByteLength));
      }
    } catch (error) {
      cancelReaderBestEffort(
        reader,
        `${context} rejected its response body`,
        genuineReader,
      );
      throw error;
    } finally {
      clearTimeout(timeoutId);
      try {
        callIntrinsicOrOwnMethod(
          reader,
          genuineReader ? readerReleaseLock : null,
          "releaseLock",
        );
      } catch {
        // Some custom readers do not implement lock release correctly.
      }
      if (abortListenerAttempted) {
        removeSignalAbortListener(signal, onAbort);
      }
    }
    const bytes = new Uint8ArrayIntrinsic(byteLength);
    let offset = 0;
    for (const chunk of chunks) {
      Reflect.apply(typedArraySet, bytes, [chunk, offset]);
      offset += typedArrayByteLengthGetter.call(chunk);
    }
    if (signalIsAborted(signal)) {
      rejectResponse(bodyReadAbortError(signal, context));
    }
    if (contentLength !== null && Number(contentLength) !== byteLength) {
      rejectResponse(new TypeError(`${context} Content-Length does not match its body`));
    }
    return { bytes, body };
  }

  async _listIterable(
    path,
    options = {},
    normalizePage,
    allowedKeys = ITERABLE_LIST_OPTION_KEYS,
    defaultCanonicalAuth = null,
  ) {
    const optionContext = `options for ${path}`;
    const normalizedOptions = normalizeIterableListOptions(
      options,
      optionContext,
      allowedKeys,
    );
    const canonicalAuth = normalizedOptions.canonicalAuth === undefined
      ? defaultCanonicalAuth
      : ToriiClient._normalizeCanonicalAuth(normalizedOptions.canonicalAuth);
    const { signal, canonicalAuth: _ignoredCanonical, ...rest } = normalizedOptions;
    const params = ToriiClient._encodeIterableListParams(rest, optionContext, allowedKeys);
    const response = await this._request("GET", path, {
      params: params ?? undefined,
      headers: JSON_ACCEPT_HEADERS,
      signal,
      canonicalAuth,
    });
    await this._expectStatus(response, [200]);
    const payload = await this._maybeJson(response);
    const base = ToriiClient._validateIterablePayload(payload);
    return typeof normalizePage === JS_TYPE_FUNCTION ? normalizePage(base) : base;
  }

  _iterateIterable(fetchPage, options = {}) {
    const iteratorLabel =
      typeof fetchPage === JS_TYPE_FUNCTION && fetchPage.name
        ? `${fetchPage.name} iterator options`
        : "iterator options";
    const normalizedOptions = ToriiClient._normalizeIterableOptions(
      options,
      iteratorLabel,
    );
    const {
      pageSize: rawPageSize,
      maxItems,
      signal,
      ...rest
    } = normalizedOptions;
    const normalizedOffset = ToriiClient._normalizeOffset(rest.offset);
    const baseOptions = { ...rest };
    if (baseOptions.offset !== undefined) {
      delete baseOptions.offset;
    }
    const overallLimit =
      maxItems === undefined || maxItems === null
        ? null
        : ToriiClient._normalizeUnsignedInteger(maxItems, "maxItems", {
            allowZero: false,
          });
    const preferredPageSize =
      rawPageSize === undefined || rawPageSize === null
        ? baseOptions.limit
        : rawPageSize;
    const defaultPageSize = ToriiClient._normalizeUnsignedInteger(
      preferredPageSize ?? DEFAULT_PAGE_SIZE,
      preferredPageSize === undefined ? "pageSize" : "limit",
      { allowZero: false },
    );
    if (baseOptions.limit !== undefined) {
      delete baseOptions.limit;
    }
    const self = this;
    return (async function* iterator() {
      let offset = normalizedOffset;
      let remaining = overallLimit;
      let produced = 0;
      let knownTotal = null;
      while (true) {
        let pageLimit = defaultPageSize;
        if (remaining !== null) {
          pageLimit = Math.min(pageLimit, remaining);
          if (pageLimit <= 0) {
            return;
          }
        }
        const pageOptions = {
          ...baseOptions,
          limit: pageLimit,
          offset,
          signal,
        };
        const page = await fetchPage.call(self, pageOptions);
        if (page && page.total !== undefined && page.total !== null) {
          const parsedTotal = Number(page.total);
          if (Number.isFinite(parsedTotal)) {
            knownTotal = Math.max(0, parsedTotal);
          }
        }
        const items = Array.isArray(page?.items) ? page.items : [];
        if (items.length === 0) {
          return;
        }
        for (const item of items) {
          yield item;
          produced += 1;
          if (remaining !== null) {
            remaining -= 1;
            if (remaining <= 0) {
              return;
            }
          }
        }
        if (
          page?.hasMore === false ||
          (knownTotal !== null && produced >= knownTotal) ||
          items.length < pageLimit
        ) {
          return;
        }
        offset += items.length;
      }
    })();
  }

  _iterateOffsetIterable(
    fetchPage,
    options = {},
    allowedKeys = ITERABLE_OPTION_KEYS,
    itemKeys = ["items"],
  ) {
    const iteratorLabel =
      typeof fetchPage === JS_TYPE_FUNCTION && fetchPage.name
        ? `${fetchPage.name} iterator options`
        : "iterator options";
    const mergedAllowed = new Set([
      ...allowedKeys,
      "pageSize",
      "maxItems",
      "limit",
      "offset",
      "signal",
    ]);
    const normalizedOptions = ToriiClient._normalizeIterableOptions(
      options,
      iteratorLabel,
      mergedAllowed,
    );
    const normalizedItemKeys = normalizeItemKeyList(itemKeys, iteratorLabel);
    const {
      pageSize: rawPageSize,
      maxItems,
      signal,
      ...rest
    } = normalizedOptions;
    const normalizedOffset = ToriiClient._normalizeOffset(rest.offset);
    const baseOptions = { ...rest };
    if (baseOptions.offset !== undefined) {
      delete baseOptions.offset;
    }
    const overallLimit =
      maxItems === undefined || maxItems === null
        ? null
        : ToriiClient._normalizeUnsignedInteger(maxItems, "maxItems", {
            allowZero: false,
          });
    const preferredPageSize =
      rawPageSize === undefined || rawPageSize === null ? baseOptions.limit : rawPageSize;
    const defaultPageSize = ToriiClient._normalizeUnsignedInteger(
      preferredPageSize ?? DEFAULT_PAGE_SIZE,
      preferredPageSize === undefined ? "pageSize" : "limit",
      { allowZero: false },
    );
    if (baseOptions.limit !== undefined) {
      delete baseOptions.limit;
    }
    const self = this;
    return (async function* iterator() {
      let offset = normalizedOffset;
      let remaining = overallLimit;
      while (true) {
        let pageLimit = defaultPageSize;
        if (remaining !== null) {
          pageLimit = Math.min(pageLimit, remaining);
          if (pageLimit <= 0) {
            return;
          }
        }
        const pageOptions = {
          ...baseOptions,
          limit: pageLimit,
          offset,
          signal,
        };
        const page = await fetchPage.call(self, pageOptions);
        const items = extractOffsetItems(page);
        if (items.length === 0) {
          return;
        }
        for (const item of items) {
          yield item;
          if (remaining !== null) {
            remaining -= 1;
            if (remaining <= 0) {
              return;
            }
          }
        }
        if (items.length < pageLimit) {
          return;
        }
        offset += items.length;
      }
    })();

    function extractOffsetItems(page) {
      if (Array.isArray(page)) {
        return page;
      }
      if (!page || typeof page !== JS_TYPE_OBJECT) {
        return [];
      }
      for (const key of normalizedItemKeys) {
        if (Array.isArray(page[key])) {
          return page[key];
        }
      }
      const expectedLabel =
        normalizedItemKeys.length === 0
          ? ""
          : ` (expected: ${normalizedItemKeys.join(", ")})`;
      rejectError(`offset iterator response is missing iterable items${expectedLabel}`);
    }

    function normalizeItemKeyList(rawKeys, contextLabel) {
      if (rawKeys === undefined || rawKeys === null) {
        return ["items"];
      }
      if (typeof rawKeys === JS_TYPE_STRING) {
        const trimmed = rawKeys.trim();
        if (!trimmed) {
          rejectError(`${contextLabel} item key must be a non-empty string`);
        }
        return [trimmed];
      }
      if (!Array.isArray(rawKeys)) {
        rejectError(`${contextLabel} item keys must be a string or array of strings`);
      }
      const keys = [];
      for (const entry of rawKeys) {
        if (typeof entry !== JS_TYPE_STRING) {
          rejectError(`${contextLabel} item keys must be strings`);
        }
        const trimmed = entry.trim();
        if (!trimmed) {
          rejectError(`${contextLabel} item keys must be non-empty strings`);
        }
        if (!keys.includes(trimmed)) {
          keys.push(trimmed);
        }
      }
      return keys.length > 0 ? keys : ["items"];
    }
  }

  _iterateCursorIterable(fetchPage, options = {}) {
    const iteratorLabel =
      typeof fetchPage === JS_TYPE_FUNCTION && fetchPage.name
        ? `${fetchPage.name} iterator options`
        : "iterator options";
    const normalizedOptions = ToriiClient._normalizeIterableOptions(
      options,
      iteratorLabel,
    );
    const {
      pageSize: rawPageSize,
      maxItems,
      signal,
      cursor: initialCursor,
      ...rest
    } = normalizedOptions;
    const baseOptions = { ...rest };
    if (baseOptions.limit !== undefined) {
      delete baseOptions.limit;
    }
    if (baseOptions.cursor !== undefined) {
      delete baseOptions.cursor;
    }
    const overallLimit =
      maxItems === undefined || maxItems === null
        ? null
        : ToriiClient._normalizeUnsignedInteger(maxItems, "maxItems", {
            allowZero: false,
          });
    const preferredPageSize =
      rawPageSize === undefined || rawPageSize === null ? rest.limit : rawPageSize;
    const defaultPageSize = ToriiClient._normalizeUnsignedInteger(
      preferredPageSize ?? DEFAULT_PAGE_SIZE,
      preferredPageSize === undefined ? "pageSize" : "limit",
      { allowZero: false },
    );
    let startingCursor = null;
    if (initialCursor !== undefined && initialCursor !== null) {
      startingCursor = requireNonEmptyString(initialCursor, "cursor");
    }
    const self = this;
    return (async function* iterator() {
      let cursor = startingCursor;
      let remaining = overallLimit;
      while (true) {
        let pageLimit = defaultPageSize;
        if (remaining !== null) {
          pageLimit = Math.min(pageLimit, remaining);
          if (pageLimit <= 0) {
            return;
          }
        }
        const pageOptions = {
          ...baseOptions,
          limit: pageLimit,
          cursor: cursor ?? undefined,
          signal,
        };
        const page = await fetchPage.call(self, pageOptions);
        const items = Array.isArray(page?.items) ? page.items : [];
        if (items.length === 0) {
          return;
        }
        for (const item of items) {
          yield item;
          if (remaining !== null) {
            remaining -= 1;
            if (remaining <= 0) {
              return;
            }
          }
        }
        if (!page || page.nextCursor === null || page.nextCursor === undefined) {
          if (items.length < pageLimit) {
            return;
          }
          return;
        }
        cursor = page.nextCursor;
      }
    })();
  }

  _iterateContractInstancePages(fetchPage, options = {}) {
    const iteratorLabel =
      typeof fetchPage === JS_TYPE_FUNCTION && fetchPage.name
        ? `${fetchPage.name} iterator options`
        : "iterator options";
    const normalizedOptions = ToriiClient._normalizeIterableOptions(
      options,
      iteratorLabel,
    );
    const {
      pageSize: rawPageSize,
      maxItems,
      signal,
      ...rest
    } = normalizedOptions;
    const normalizedOffset = ToriiClient._normalizeOffset(rest.offset);
    const baseOptions = { ...rest };
    if (baseOptions.offset !== undefined) {
      delete baseOptions.offset;
    }
    const overallLimit =
      maxItems === undefined || maxItems === null
        ? null
        : ToriiClient._normalizeUnsignedInteger(maxItems, "maxItems", {
            allowZero: false,
          });
    const preferredPageSize =
      rawPageSize === undefined || rawPageSize === null ? baseOptions.limit : rawPageSize;
    const defaultPageSize = ToriiClient._normalizeUnsignedInteger(
      preferredPageSize ?? DEFAULT_PAGE_SIZE,
      preferredPageSize === undefined ? "pageSize" : "limit",
      { allowZero: false },
    );
    if (baseOptions.limit !== undefined) {
      delete baseOptions.limit;
    }
    const self = this;
    return (async function* iterator() {
      let offset = normalizedOffset;
      let remaining = overallLimit;
      while (true) {
        let pageLimit = defaultPageSize;
        if (remaining !== null) {
          pageLimit = Math.min(pageLimit, remaining);
          if (pageLimit <= 0) {
            return;
          }
        }
        const pageOptions = {
          ...baseOptions,
          offset,
          limit: pageLimit,
          signal,
        };
        const page = await fetchPage.call(self, pageOptions);
        const items = Array.isArray(page?.instances) ? page.instances : [];
        if (items.length === 0) {
          return;
        }
        for (const instance of items) {
          yield instance;
          if (remaining !== null) {
            remaining -= 1;
            if (remaining <= 0) {
              return;
            }
          }
        }
        if (items.length < pageLimit) {
          return;
        }
        offset += items.length;
      }
    })();
  }

  static _validateIterablePayload(payload) {
    if (!payload || typeof payload !== JS_TYPE_OBJECT || !Array.isArray(payload.items)) {
      rejectError("iterable endpoint returned unexpected payload");
    }
    const hasTotal = payload.total !== undefined && payload.total !== null;
    if (
      payload.has_more !== undefined &&
      payload.has_more !== null &&
      typeof payload.has_more !== "boolean"
    ) {
      rejectError("iterable endpoint returned invalid has_more flag");
    }
    const hasMore =
      payload.has_more === undefined || payload.has_more === null
        ? undefined
        : payload.has_more;
    const countMode =
      payload.count_mode === undefined || payload.count_mode === null
        ? undefined
        : ToriiClient._normalizeCountModeOption(payload.count_mode, "count_mode");
    const totalValue = hasTotal
      ? Number(payload.total)
      : hasMore === undefined
        ? payload.items.length
        : null;
    if (
      totalValue !== null &&
      (!Number.isFinite(totalValue) || totalValue < 0 || !Number.isInteger(totalValue))
    ) {
      rejectError("iterable endpoint returned invalid total count");
    }
    const result = {
      items: payload.items,
      total: totalValue,
    };
    if (hasMore !== undefined) {
      result.hasMore = hasMore;
    }
    if (countMode !== undefined) {
      result.countMode = countMode;
    }
    if (payload.indexed_height !== undefined && payload.indexed_height !== null) {
      result.indexedHeight = ToriiClient._normalizeUnsignedInteger(
        payload.indexed_height,
        "indexed_height",
        { allowZero: true },
      );
    }
    if (payload.indexed_block_hash !== undefined) {
      result.indexedBlockHash = payload.indexed_block_hash ?? null;
    }
    if (payload.query_source !== undefined && payload.query_source !== null) {
      result.querySource = requireNonEmptyString(payload.query_source, "query_source");
    }
    return result;
  }

  static _requireNonEmptyString(value, name) {
    if (typeof value !== JS_TYPE_STRING || value.trim().length === 0) {
      throw createValidationError(
        ValidationErrorCode.INVALID_STRING,
        `${name} must be a non-empty string`,
        name,
      );
    }
    return value;
  }

  static _requirePlainObject(value, name) {
    if (!isPlainObject(value)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${name} must be a plain object`,
        name,
      );
    }
    return value;
  }

  static _requireAccountId(accountId, name = "accountId") {
    return normalizeAccountId(accountId, name);
  }

  static _normalizeAccountId(accountId, name = "accountId") {
    try {
      return ToriiClient._requireAccountId(accountId, name);
    } catch (error) {
      if (
        error &&
        !(error instanceof AccountAddressError) &&
        error.cause instanceof AccountAddressError
      ) {
        throw error.cause;
      }
      throw error;
    }
  }

  static _requireAssetId(assetId, name = "assetId") {
    return normalizeAssetId(assetId, name);
  }

  static _normalizeAssetId(assetId, name = "assetId") {
    return ToriiClient._requireAssetId(assetId, name);
  }

  static _requireAssetHoldingId(assetHoldingId, name = "assetHoldingId") {
    return normalizeAssetHoldingId(assetHoldingId, name);
  }

  static _normalizeAssetHoldingId(assetHoldingId, name = "assetHoldingId") {
    return ToriiClient._requireAssetHoldingId(assetHoldingId, name);
  }

  static _requireAssetDefinitionId(assetDefinitionId) {
    return ToriiClient._requireNonEmptyString(assetDefinitionId, "assetDefinitionId");
  }

  static _validateFeeQuoteForDraft(
    payloadOrDraft,
    quote,
    context = "fee quote response",
  ) {
    return validateFeeQuoteForDraft(payloadOrDraft, quote, context);
  }

  static _requireDomainId(domainId, context = "domainId") {
    return ToriiClient._requireNonEmptyString(domainId, context);
  }

  static _normalizeIterableOptions(options, context = "options", allowedKeys = ITERABLE_OPTION_KEYS) {
    if (options === undefined || options === null) {
      return {};
    }
    const record = requirePlainObjectOption(options, context);
    assertSupportedOptionKeys(record, allowedKeys, context);
    const normalized = { ...record };
    const { signal } = normalizeSignalOption(record, context);
    if (signal !== undefined) {
      normalized.signal = signal;
    } else {
      delete normalized.signal;
    }
    return normalized;
  }

  static _normalizePrivateKey(value, context = "canonicalAuth.privateKey") {
    return ToriiClient.#normalizePrivateKey(value, context);
  }

  static #normalizePrivateKey(value, context = "canonicalAuth.privateKey") {
    const path = typeof context === JS_TYPE_STRING ? context.replace(/\s+/g, ".") : CANONICAL_AUTH_FIELD;
    if (value === undefined || value === null) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${path} must be provided`,
        path,
      );
    }
    let buffer;
    if (Buffer.isBuffer(value)) {
      buffer = Buffer.from(value);
    } else if (typeof value === JS_TYPE_STRING) {
      const trimmed = value.trim();
      const hex = trimmed.startsWith("0x") || trimmed.startsWith("0X")
        ? trimmed.slice(2)
        : trimmed;
      if (/^[0-9a-fA-F]+$/u.test(hex) && hex.length % 2 === 0) {
        buffer = Buffer.from(hex, "hex");
      } else {
        buffer = Buffer.from(trimmed, "utf8");
      }
    } else if (ArrayBuffer.isView(value)) {
      buffer = Buffer.from(
        new Uint8Array(value.buffer, value.byteOffset, value.byteLength),
      );
    } else if (value instanceof ArrayBuffer) {
      buffer = Buffer.from(new Uint8Array(value));
    } else if (Array.isArray(value)) {
      buffer = normalizeByteArray(value, path);
    } else {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${path} must be a Buffer, byte array, ArrayBuffer view, ArrayBuffer, or hex string`,
        path,
      );
    }
    if (buffer.length !== 32 && buffer.length !== 64) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${path} must contain a 32- or 64-byte ed25519 private key`,
        path,
      );
    }
    return buffer;
  }

  static _normalizeCanonicalAuth(auth, context = CANONICAL_AUTH_FIELD) {
    return ToriiClient.#normalizeCanonicalAuth(auth, context);
  }

  static #normalizeCanonicalAuth(auth, context = CANONICAL_AUTH_FIELD) {
    if (auth === undefined || auth === null) {
      return null;
    }
    const record = requirePlainObjectOption(auth, `${context} options`);
    const rawAccountId = record.accountId;
    if (rawAccountId === undefined || rawAccountId === null) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${context}.accountId is required`,
        `${context}.accountId`,
      );
    }
    let accountId;
    try {
      accountId = requireCanonicalAuthAccount(rawAccountId, `${context}.accountId`);
    } catch (error) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${context}.accountId must be an exact canonical I105 account or ASCII account alias`,
        `${context}.accountId`,
        error,
      );
    }
    const privateKey = ToriiClient.#normalizePrivateKey(
      record.privateKey,
      `${context}.privateKey`,
    );
    return { accountId, privateKey };
  }

  static _splitPermissionedIterableOptions(options, context = "iterable options") {
    if (options === undefined || options === null) {
      return { requirePermissions: false, options: {} };
    }
    const record = requirePlainObjectOption(options, `${context} options`);
    const { requirePermissions, ...rest } = record;
    if (requirePermissions !== undefined && requirePermissions !== null) {
      if (typeof requirePermissions !== "boolean") {
        throw createValidationError(
          ValidationErrorCode.INVALID_OBJECT,
          `${context}.requirePermissions must be a boolean when provided`,
          `${context}.requirePermissions`,
        );
      }
    }
    return {
      requirePermissions: requirePermissions === true,
      options: rest,
    };
  }

  static _normalizeOptionsWithSignal(options, context) {
    if (options === undefined) {
      return { signal: undefined, rest: {} };
    }
    const record = ensureRecord(options, `${context} options`);
    const { signal } = normalizeSignalOption(record, context);
    const { signal: _ignored, ...rest } = record;
    return { signal, rest };
  }






  static _normalizeTransactionStatusPollOptions(options, context = "transaction status options") {
    if (options === undefined || options === null) {
      return {
        signal: undefined,
        intervalMs: DEFAULT_TX_STATUS_POLL_INTERVAL_MS,
        timeoutMs: DEFAULT_TX_STATUS_TIMEOUT_MS,
        maxAttempts: null,
        onStatus: null,
      };
    }
    const record = requirePlainObjectOption(options, context);
    assertSupportedOptionKeys(record, TX_STATUS_POLL_OPTION_KEYS, context);
    const signalContext =
      typeof context === JS_TYPE_STRING && context.endsWith(" options")
        ? context.slice(0, -8)
        : context;
    const { signal } = normalizeSignalOption(record, signalContext);
    let intervalMs = DEFAULT_TX_STATUS_POLL_INTERVAL_MS;
    if (record.intervalMs !== undefined && record.intervalMs !== null) {
      intervalMs = ToriiClient._normalizeUnsignedInteger(
        record.intervalMs,
        `${context}.intervalMs`,
        { allowZero: true },
      );
    }
    let timeoutMs = DEFAULT_TX_STATUS_TIMEOUT_MS;
    if (record.timeoutMs === null) {
      timeoutMs = null;
    } else if (record.timeoutMs !== undefined) {
      timeoutMs = ToriiClient._normalizeUnsignedInteger(
        record.timeoutMs,
        `${context}.timeoutMs`,
        { allowZero: true },
      );
    }
    let maxAttempts = null;
    if (record.maxAttempts === null) {
      maxAttempts = null;
    } else if (record.maxAttempts !== undefined) {
      maxAttempts = ToriiClient._normalizeUnsignedInteger(
        record.maxAttempts,
        `${context}.maxAttempts`,
      );
    }
    let onStatus = null;
    if (record.onStatus !== undefined && record.onStatus !== null) {
      if (typeof record.onStatus !== JS_TYPE_FUNCTION) {
        throw createValidationError(
          ValidationErrorCode.INVALID_OBJECT,
          `${context}.onStatus must be a function`,
          `${context}.onStatus`,
        );
      }
      onStatus = record.onStatus;
    }
    return {
      signal,
      intervalMs,
      timeoutMs,
      maxAttempts,
      onStatus,
    };
  }

  static _encodeIterableListParams(
    options = {},
    context = "iterable list options",
    allowedKeys = ITERABLE_LIST_OPTION_KEYS,
  ) {
    const optionPath = context ?? "options";
    const normalizedOptions = ToriiClient._normalizeIterableOptions(
      options,
      context,
      allowedKeys,
    );
    const params = {};
    if (normalizedOptions.limit !== undefined && normalizedOptions.limit !== null) {
      params.limit = ToriiClient._normalizeUnsignedInteger(normalizedOptions.limit, "limit", {
        allowZero: true,
      });
    }
    if (normalizedOptions.offset !== undefined && normalizedOptions.offset !== null) {
      params.offset = ToriiClient._normalizeOffset(normalizedOptions.offset);
    }
    const countMode = ToriiClient._normalizeCountModeOption(
      normalizedOptions.countMode ?? normalizedOptions.count_mode,
      "countMode",
    );
    if (countMode !== undefined) {
      params.count_mode = countMode;
    }
    const filterParam = ToriiClient._normalizeFilterParam(normalizedOptions.filter);
    if (filterParam !== undefined) {
      params.filter = filterParam;
    }
    const sortParam = ToriiClient._encodeSortQueryParam(normalizedOptions.sort);
    if (sortParam !== undefined) {
      params.sort = sortParam;
    }
    if (normalizedOptions.controllerId !== undefined && normalizedOptions.controllerId !== null) {
      params.controller_id = ToriiClient._normalizeAccountId(
        normalizedOptions.controllerId,
        "controllerId",
      );
    }
    if (normalizedOptions.receiverId !== undefined && normalizedOptions.receiverId !== null) {
      params.receiver_id = ToriiClient._normalizeAccountId(
        normalizedOptions.receiverId,
        "receiverId",
      );
    }
    if (
      normalizedOptions.depositAccountId !== undefined &&
      normalizedOptions.depositAccountId !== null
    ) {
      params.deposit_account_id = ToriiClient._normalizeAccountId(
        normalizedOptions.depositAccountId,
        "depositAccountId",
      );
    }
    if (normalizedOptions.assetId !== undefined && normalizedOptions.assetId !== null) {
      params.asset_id = ToriiClient._normalizeAssetId(normalizedOptions.assetId, "assetId");
    }
    if (normalizedOptions.authority !== undefined && normalizedOptions.authority !== null) {
      params.authority = ToriiClient._normalizeAccountId(
        normalizedOptions.authority,
        "authority",
      );
    }
    if (
      normalizedOptions.contractAddress !== undefined &&
      normalizedOptions.contractAddress !== null
    ) {
      params.contract_address = requireExactNonEmptyString(
        normalizedOptions.contractAddress,
        "contractAddress",
      );
    }
    if (normalizedOptions.contractAlias !== undefined && normalizedOptions.contractAlias !== null) {
      params.contract_alias = requireExactNonEmptyString(
        normalizedOptions.contractAlias,
        "contractAlias",
      );
    }
    if (normalizedOptions.module !== undefined && normalizedOptions.module !== null) {
      params.module = requireNonEmptyString(normalizedOptions.module, "module");
    }
    if (normalizedOptions.eventKind !== undefined && normalizedOptions.eventKind !== null) {
      params.event_kind = requireNonEmptyString(normalizedOptions.eventKind, "eventKind");
    }
    if (normalizedOptions.participant !== undefined && normalizedOptions.participant !== null) {
      params.participant = requireExactNonEmptyString(
        normalizedOptions.participant,
        "participant",
      );
    }
    if (normalizedOptions.provenance !== undefined && normalizedOptions.provenance !== null) {
      params.provenance = requireNonEmptyString(
        normalizedOptions.provenance,
        "provenance",
      );
    }
    if (
      normalizedOptions.contractEntrypoint !== undefined &&
      normalizedOptions.contractEntrypoint !== null
    ) {
      params.contract_entrypoint = requireNonEmptyString(
        normalizedOptions.contractEntrypoint,
        "contractEntrypoint",
      );
    }
    if (
      normalizedOptions.sinceTimestampMs !== undefined &&
      normalizedOptions.sinceTimestampMs !== null
    ) {
      params.since_timestamp_ms = ToriiClient._normalizeUnsignedInteger(
        normalizedOptions.sinceTimestampMs,
        "sinceTimestampMs",
        { allowZero: true },
      );
    }
    if (
      normalizedOptions.untilTimestampMs !== undefined &&
      normalizedOptions.untilTimestampMs !== null
    ) {
      params.until_timestamp_ms = ToriiClient._normalizeUnsignedInteger(
        normalizedOptions.untilTimestampMs,
        "untilTimestampMs",
        { allowZero: true },
      );
    }
    if (normalizedOptions.resultOk !== undefined && normalizedOptions.resultOk !== null) {
      params.result_ok = requireBooleanLike(normalizedOptions.resultOk, "resultOk");
    }
    if (
      normalizedOptions.certificateExpiresBeforeMs !== undefined &&
      normalizedOptions.certificateExpiresBeforeMs !== null
    ) {
      params.certificate_expires_before_ms = ToriiClient._normalizeUnsignedInteger(
        normalizedOptions.certificateExpiresBeforeMs,
        "certificateExpiresBeforeMs",
        { allowZero: true },
      );
    }
    if (
      normalizedOptions.certificateExpiresAfterMs !== undefined &&
      normalizedOptions.certificateExpiresAfterMs !== null
    ) {
      params.certificate_expires_after_ms = ToriiClient._normalizeUnsignedInteger(
        normalizedOptions.certificateExpiresAfterMs,
        "certificateExpiresAfterMs",
        { allowZero: true },
      );
    }
    if (
      normalizedOptions.policyExpiresBeforeMs !== undefined &&
      normalizedOptions.policyExpiresBeforeMs !== null
    ) {
      params.policy_expires_before_ms = ToriiClient._normalizeUnsignedInteger(
        normalizedOptions.policyExpiresBeforeMs,
        "policyExpiresBeforeMs",
        { allowZero: true },
      );
    }
    if (
      normalizedOptions.policyExpiresAfterMs !== undefined &&
      normalizedOptions.policyExpiresAfterMs !== null
    ) {
      params.policy_expires_after_ms = ToriiClient._normalizeUnsignedInteger(
        normalizedOptions.policyExpiresAfterMs,
        "policyExpiresAfterMs",
        { allowZero: true },
      );
    }
    if (
      normalizedOptions.refreshBeforeMs !== undefined &&
      normalizedOptions.refreshBeforeMs !== null
    ) {
      params.refresh_before_ms = ToriiClient._normalizeUnsignedInteger(
        normalizedOptions.refreshBeforeMs,
        "refreshBeforeMs",
        { allowZero: true },
      );
    }
    if (
      normalizedOptions.refreshAfterMs !== undefined &&
      normalizedOptions.refreshAfterMs !== null
    ) {
      params.refresh_after_ms = ToriiClient._normalizeUnsignedInteger(
        normalizedOptions.refreshAfterMs,
        "refreshAfterMs",
        { allowZero: true },
      );
    }
    const verdictIdHex = ToriiClient._normalizeOptionalString(
      normalizedOptions.verdictIdHex,
      `${optionPath}.verdictIdHex`,
    );
    const attestationNonceHex = ToriiClient._normalizeOptionalString(
      normalizedOptions.attestationNonceHex,
      `${optionPath}.attestationNonceHex`,
    );
    const certificateIdHex = ToriiClient._normalizeOptionalString(
      normalizedOptions.certificateIdHex,
      `${optionPath}.certificateIdHex`,
    );
    const requireVerdict = ToriiClient._normalizeBooleanOption(
      normalizedOptions.requireVerdict,
      `${optionPath}.requireVerdict`,
    );
    const onlyMissingVerdict = ToriiClient._normalizeBooleanOption(
      normalizedOptions.onlyMissingVerdict,
      `${optionPath}.onlyMissingVerdict`,
    );
    if (requireVerdict && onlyMissingVerdict) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${optionPath}.onlyMissingVerdict cannot be combined with ${optionPath}.requireVerdict`,
        `${optionPath}.onlyMissingVerdict`,
      );
    }
    if (onlyMissingVerdict && verdictIdHex !== undefined) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${optionPath}.verdictIdHex cannot be combined with ${optionPath}.onlyMissingVerdict`,
        `${optionPath}.verdictIdHex`,
      );
    }
    if (verdictIdHex !== undefined) {
      params.verdict_id_hex = verdictIdHex.toLowerCase();
    }
    if (attestationNonceHex !== undefined) {
      params.attestation_nonce_hex = attestationNonceHex.toLowerCase();
    }
    if (certificateIdHex !== undefined) {
      params.certificate_id_hex = certificateIdHex.toLowerCase();
    }
    if (requireVerdict) {
      params.require_verdict = "true";
    }
    if (onlyMissingVerdict) {
      params.only_missing_verdict = "true";
    }
    const platformPolicy = ToriiClient._normalizeOptionalString(
      normalizedOptions.platformPolicy,
      `${optionPath}.platformPolicy`,
    );
    if (platformPolicy !== undefined) {
      params.platform_policy = platformPolicy.toLowerCase();
    }
    if (
      ToriiClient._normalizeBooleanOption(
        normalizedOptions.includeExpired,
        `${optionPath}.includeExpired`,
      )
    ) {
      params.include_expired = "true";
    }
    return Object.keys(params).length === 0 ? undefined : params;
  }

  static _normalizeOptionalString(value, context) {
    if (value === undefined || value === null) {
      return undefined;
    }
    if (typeof value !== JS_TYPE_STRING) {
      throw createValidationError(
        ValidationErrorCode.INVALID_STRING,
        `${context} must be a string`,
        context,
      );
    }
    const trimmed = value.trim();
    return trimmed.length === 0 ? undefined : trimmed;
  }

  static _normalizeBooleanOption(value, context) {
    if (value === undefined || value === null) {
      return false;
    }
    if (typeof value !== "boolean") {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${context} must be a boolean`,
        context,
      );
    }
    return value;
  }

  static _normalizeFilterParam(filter) {
    if (filter === undefined || filter === null) {
      return undefined;
    }
    if (typeof filter === JS_TYPE_STRING) {
      const trimmed = filter.trim();
      if (!trimmed) {
        throw createValidationError(
          ValidationErrorCode.INVALID_STRING,
          "filter must not be an empty string",
          "filter",
        );
      }
      return trimmed;
    }
    if (typeof filter === JS_TYPE_OBJECT) {
      const plain = ToriiClient._requirePlainObject(filter, "filter");
      try {
        return JSON.stringify(plain);
      } catch (error) {
        throw createValidationError(
          ValidationErrorCode.INVALID_JSON_VALUE,
          `failed to serialise filter object: ${
            error instanceof Error ? error.message : String(error)
          }`,
          "filter",
          error instanceof Error ? error : undefined,
        );
      }
    }
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      "filter must be a string or plain object",
      "filter",
    );
  }

  static _encodeSortQueryParam(sort) {
    if (sort === undefined || sort === null) {
      return undefined;
    }
    if (typeof sort === JS_TYPE_STRING) {
      const trimmed = sort.trim();
      if (!trimmed) {
        throw createValidationError(
          ValidationErrorCode.INVALID_STRING,
          "sort string must be non-empty",
          "sort",
        );
      }
      const tokens = trimmed
        .split(",")
        .map((token) => token.trim())
        .filter((token) => token.length > 0);
      if (tokens.length === 0) {
        throw createValidationError(
          ValidationErrorCode.INVALID_OBJECT,
          "sort string must include at least one key",
          "sort",
        );
      }
      tokens.forEach((token) => {
        const [rawKey, rawOrder] = token.split(":");
        if (!rawKey || !rawKey.trim()) {
          throw createValidationError(
            ValidationErrorCode.INVALID_OBJECT,
            `sort token "${token}" must include a key`,
            "sort",
          );
        }
        if (rawOrder !== undefined) {
          ToriiClient._normalizeSortOrder(
            rawOrder,
            `sort token "${token}" order`,
          );
        }
      });
      return trimmed;
    }
    if (Array.isArray(sort)) {
      if (sort.length === 0) {
        return undefined;
      }
      const parts = sort.map((entry, index) => {
        if (!entry || typeof entry !== JS_TYPE_OBJECT || typeof entry.key !== JS_TYPE_STRING) {
          throw createValidationError(
            ValidationErrorCode.INVALID_OBJECT,
            `sort[${index}] must provide a key`,
            `sort[${index}]`,
          );
        }
        const key = entry.key.trim();
        if (!key) {
          throw createValidationError(
            ValidationErrorCode.INVALID_STRING,
            `sort[${index}] key must be non-empty`,
            `sort[${index}].key`,
          );
        }
        const order = ToriiClient._normalizeSortOrder(
          entry.order,
          `sort[${index}].order`,
        );
        return `${key}:${order}`;
      });
      return parts.join(",");
    }
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      "sort must be a string or array of {key, order}",
      "sort",
    );
  }

  static _buildIterableQueryEnvelope(options = {}) {
    const pagination = {
      offset: ToriiClient._normalizeOffset(options.offset),
    };
    if (options.limit !== undefined && options.limit !== null) {
      pagination.limit = ToriiClient._normalizeUnsignedInteger(options.limit, "limit", {
        allowZero: true,
      });
    }
    const envelope = {
      pagination,
      sort: ToriiClient._encodeSortArray(options.sort),
    };
    const filterObject = ToriiClient._normalizeFilterObject(options.filter);
    if (filterObject !== undefined) {
      envelope.filter = filterObject;
    }
    if (options.fetchSize !== undefined && options.fetchSize !== null) {
      envelope.fetch_size = ToriiClient._normalizeUnsignedInteger(
        options.fetchSize,
        "fetchSize",
        { allowZero: false },
      );
    }
    const countMode = ToriiClient._normalizeCountModeOption(options.countMode, "countMode");
    if (countMode !== undefined) {
      envelope.count_mode = countMode;
    }
    if (options.queryName !== undefined && options.queryName !== null) {
      const name = String(options.queryName).trim();
      if (!name) {
        throw createValidationError(
          ValidationErrorCode.INVALID_STRING,
          "queryName must be a non-empty string",
          "queryName",
        );
      }
      envelope.query = name;
    }
    if (options.select !== undefined && options.select !== null) {
      if (!Array.isArray(options.select)) {
        throw createValidationError(
          ValidationErrorCode.INVALID_OBJECT,
          "select must be an array of projection field paths or objects",
          "select",
        );
      }
      envelope.select = options.select.map((entry, index) =>
        ToriiClient._normalizeSelectEntry(entry, `select[${index}]`),
      );
    }
    return envelope;
  }

  static _normalizeSelectEntry(entry, context) {
    if (typeof entry === JS_TYPE_STRING) {
      const fieldPath = entry.trim();
      if (!fieldPath) {
        throw createValidationError(
          ValidationErrorCode.INVALID_STRING,
          `${context} must be a non-empty field path`,
          context,
        );
      }
      return fieldPath;
    }
    if (isPlainObject(entry)) {
      return entry;
    }
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} must be a field-path string or plain object`,
      context,
    );
  }

  static _normalizeCountModeOption(value, context = "countMode") {
    if (value === undefined || value === null) {
      return undefined;
    }
    const normalized = String(value).trim().toLowerCase();
    if (normalized === "bounded" || normalized === "exact") {
      return normalized;
    }
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} must be "bounded" or "exact"`,
      context,
    );
  }

  static _normalizeFilterObject(filter) {
    if (filter === undefined || filter === null) {
      return undefined;
    }
    if (typeof filter === JS_TYPE_STRING) {
      const trimmed = filter.trim();
      if (!trimmed) {
        throw createValidationError(
          ValidationErrorCode.INVALID_STRING,
          "filter string must be non-empty",
          "filter",
        );
      }
      let parsed;
      try {
        parsed = JSON.parse(trimmed);
      } catch (error) {
        throw createValidationError(
          ValidationErrorCode.INVALID_JSON_VALUE,
          `failed to parse filter JSON: ${
            error instanceof Error ? error.message : String(error)
          }`,
          "filter",
          error instanceof Error ? error : undefined,
        );
      }
      return ToriiClient._requirePlainObject(parsed, "filter");
    }
    if (typeof filter === JS_TYPE_OBJECT) {
      return ToriiClient._requirePlainObject(filter, "filter");
    }
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      "filter must be a string or plain object",
      "filter",
    );
  }

  static _encodeSortArray(sort) {
    if (sort === undefined || sort === null) {
      return [];
    }
    if (Array.isArray(sort)) {
      return sort.map((entry, index) => {
        if (!entry || typeof entry !== JS_TYPE_OBJECT || typeof entry.key !== JS_TYPE_STRING) {
          throw createValidationError(
            ValidationErrorCode.INVALID_OBJECT,
            `sort[${index}] must provide a key`,
            `sort[${index}]`,
          );
        }
        const key = entry.key.trim();
        if (!key) {
          throw createValidationError(
            ValidationErrorCode.INVALID_STRING,
            `sort[${index}] key must be non-empty`,
            `sort[${index}].key`,
          );
        }
        const order = ToriiClient._normalizeSortOrder(
          entry.order,
          `sort[${index}].order`,
        );
        return { key, order };
      });
    }
    if (typeof sort === JS_TYPE_STRING) {
      return sort
        .split(",")
        .map((token) => token.trim())
        .filter((token) => token.length > 0)
        .map((token, index) => {
          const [rawKey, rawOrder] = token.split(":");
          if (!rawKey) {
            throw createValidationError(
              ValidationErrorCode.INVALID_OBJECT,
              `sort token at index ${index} must include a key`,
              `sort[${index}]`,
            );
          }
          const key = rawKey.trim();
          if (!key) {
            throw createValidationError(
              ValidationErrorCode.INVALID_STRING,
              `sort token at index ${index} must include a key`,
              `sort[${index}]`,
            );
          }
          const order =
            rawOrder === undefined
              ? "asc"
              : ToriiClient._normalizeSortOrder(
                  rawOrder,
                  `sort token at index ${index} order`,
                );
          return { key, order };
        });
    }
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      "sort must be a string or array of {key, order}",
      "sort",
    );
  }

  static _normalizeSortOrder(value, context = "sort order") {
    if (value === undefined || value === null) {
      return "asc";
    }
    const normalized = String(value).trim().toLowerCase();
    if (!normalized) {
      return "asc";
    }
    if (normalized === "asc" || normalized === "desc") {
      return normalized;
    }
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} must be "asc" or "desc"`,
      normalizeErrorPath(context),
    );
  }

  static _isIsoStatusTerminal(status, resolveOnAcceptedWithoutTransaction) {
    if (!status) {
      return false;
    }
    if (status.transaction_hash) {
      return true;
    }
    const label = status.status ? String(status.status).toLowerCase() : "";
    if (!label) {
      return false;
    }
    if (ISO_NON_TERMINAL_STATUS_VALUES.has(label)) {
      if (label === "accepted" && resolveOnAcceptedWithoutTransaction) {
        return true;
      }
      return false;
    }
    return true;
  }

  static _encodePaginationParams(options = {}) {
    const params = {};
    if (options.limit !== undefined && options.limit !== null) {
      params.limit = ToriiClient._normalizeUnsignedInteger(options.limit, "limit", {
        allowZero: true,
      });
    }
    if (options.offset !== undefined && options.offset !== null) {
      params.offset = ToriiClient._normalizeOffset(options.offset);
    }
    return Object.keys(params).length === 0 ? undefined : params;
  }

  static _normalizeOffset(value) {
    if (value === undefined || value === null) {
      return 0;
    }
    return ToriiClient._normalizeUnsignedInteger(value, "offset", { allowZero: true });
  }

  static _normalizeUnsignedInteger(value, name, options = {}) {
    const allowZero = Boolean(options.allowZero);
    const min = options.min;
    const max = options.max;
    let numeric;
    if (typeof value === JS_TYPE_NUMBER) {
      if (!Number.isFinite(value) || !Number.isInteger(value)) {
        const qualifier = allowZero ? "non-negative integer" : "positive integer";
        throw createValidationError(
          ValidationErrorCode.INVALID_NUMERIC,
          `${name} must be a ${qualifier}`,
          name,
        );
      }
      if (value < 0 || (!allowZero && value === 0)) {
        const qualifier = allowZero ? "non-negative integer" : "positive integer";
        throw createValidationError(
          ValidationErrorCode.INVALID_NUMERIC,
          `${name} must be a ${qualifier}`,
          name,
        );
      }
      if (!Number.isSafeInteger(value)) {
        throw createValidationError(
          ValidationErrorCode.VALUE_OUT_OF_RANGE,
          `${name} must be at most ${MAX_SAFE_INTEGER}`,
          name,
        );
      }
      numeric = value;
    } else if (typeof value === JS_TYPE_BIGINT) {
      if (value < 0n || (!allowZero && value === 0n)) {
        const qualifier = allowZero ? "non-negative integer" : "positive integer";
        throw createValidationError(
          ValidationErrorCode.INVALID_NUMERIC,
          `${name} must be a ${qualifier}`,
          name,
        );
      }
      if (value > MAX_SAFE_INTEGER_BIGINT) {
        throw createValidationError(
          ValidationErrorCode.VALUE_OUT_OF_RANGE,
          `${name} must be at most ${MAX_SAFE_INTEGER}`,
          name,
        );
      }
      numeric = Number(value);
    } else if (typeof value === JS_TYPE_STRING) {
      const trimmed = value.trim();
      if (!/^[0-9]+$/.test(trimmed)) {
        const qualifier = allowZero ? "non-negative integer" : "positive integer";
        throw createValidationError(
          ValidationErrorCode.INVALID_NUMERIC,
          `${name} must be a ${qualifier}`,
          name,
        );
      }
      const bigint = BigInt(trimmed);
      if (bigint < 0n || (!allowZero && bigint === 0n)) {
        const qualifier = allowZero ? "non-negative integer" : "positive integer";
        throw createValidationError(
          ValidationErrorCode.INVALID_NUMERIC,
          `${name} must be a ${qualifier}`,
          name,
        );
      }
      if (bigint > MAX_SAFE_INTEGER_BIGINT) {
        throw createValidationError(
          ValidationErrorCode.VALUE_OUT_OF_RANGE,
          `${name} must be at most ${MAX_SAFE_INTEGER}`,
          name,
        );
      }
      numeric = Number(bigint);
    } else {
      const qualifier = allowZero ? "non-negative" : "positive";
      throw createValidationError(
        ValidationErrorCode.INVALID_NUMERIC,
        `${name} must be a ${qualifier} integer`,
        name,
      );
    }
    if (numeric === 0) {
      return 0;
    }
    if (min !== undefined && numeric < min) {
      const qualifier = allowZero ? `at least ${min} or zero` : `at least ${min}`;
      throw createValidationError(
        ValidationErrorCode.VALUE_OUT_OF_RANGE,
        `${name} must be ${qualifier}`,
        name,
      );
    }
    if (max !== undefined && numeric > max) {
      throw createValidationError(
        ValidationErrorCode.VALUE_OUT_OF_RANGE,
        `${name} must be at most ${max}`,
        name,
      );
    }
    return Math.floor(numeric);
  }
}

function normalizeUint64DecimalString(value, name, options = {}) {
  const allowZero = options.allowZero !== false;
  let integer;
  if (typeof value === JS_TYPE_NUMBER) {
    if (!Number.isFinite(value) || !Number.isInteger(value) || !Number.isSafeInteger(value)) {
      const qualifier = allowZero ? "non-negative integer" : "positive integer";
      throw createValidationError(
        ValidationErrorCode.INVALID_NUMERIC,
        `${name} must be a ${qualifier}`,
        name,
      );
    }
    integer = BigInt(value);
  } else if (typeof value === JS_TYPE_BIGINT) {
    integer = value;
  } else if (typeof value === JS_TYPE_STRING) {
    const trimmed = value.trim();
    if (!/^[0-9]+$/.test(trimmed)) {
      const qualifier = allowZero ? "non-negative integer" : "positive integer";
      throw createValidationError(
        ValidationErrorCode.INVALID_NUMERIC,
        `${name} must be a ${qualifier}`,
        name,
      );
    }
    integer = BigInt(trimmed);
  } else {
    const qualifier = allowZero ? "non-negative" : "positive";
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${name} must be a ${qualifier} integer`,
      name,
    );
  }
  if (integer < 0n || (!allowZero && integer === 0n)) {
    const qualifier = allowZero ? "non-negative integer" : "positive integer";
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${name} must be a ${qualifier}`,
      name,
    );
  }
  if (integer > MAX_UINT64_BIGINT) {
    throw createValidationError(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${name} must be at most ${MAX_UINT64_BIGINT.toString(10)}`,
      name,
    );
  }
  return integer.toString(10);
}

function normalizeGovernanceUint64Integer(value, name, options = {}) {
  let integer;
  if (typeof value === JS_TYPE_NUMBER) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw createValidationError(
        ValidationErrorCode.INVALID_NUMERIC,
        `${name} must be a lossless unsigned 64-bit integer`,
        name,
      );
    }
    integer = BigInt(value);
  } else if (typeof value === JS_TYPE_BIGINT) {
    integer = value;
  } else {
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${name} must be an unsigned 64-bit JSON integer token`,
      name,
    );
  }
  if (
    integer < 0n
    || (options.allowZero === false && integer === 0n)
    || integer > MAX_UINT64_BIGINT
  ) {
    throw createValidationError(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${name} must be ${options.allowZero === false ? "positive and " : ""}at most ${MAX_UINT64_BIGINT.toString(10)}`,
      name,
    );
  }
  return integer <= MAX_SAFE_INTEGER_BIGINT ? Number(integer) : integer;
}

function normalizeIsoSubmissionResponse(payload, context, options = {}) {
  const record = ToriiClient._requirePlainObject(payload, context);
  const rawMessageId = record.message_id;
  if (typeof rawMessageId !== JS_TYPE_STRING || rawMessageId.trim().length === 0) {
    rejectError(`${context} did not return a message_id`);
  }
  const messageId = rawMessageId.trim();
  const status = normalizeIsoStatus(record.status, `${context}.status`);
  let pacs002Code = null;
  if (record.pacs002_code !== undefined && record.pacs002_code !== null) {
    pacs002Code = normalizePacs002Code(record.pacs002_code, `${context}.pacs002_code`);
  }

  const base = {
    message_id: messageId,
    status,
    pacs002_code: pacs002Code,
    transaction_hash: normalizeIsoOptionalString(record.transaction_hash, `${context}.transaction_hash`),
    profile_id: normalizeIsoOptionalString(record.profile_id, `${context}.profile_id`),
    message_type: normalizeIsoOptionalString(record.message_type, `${context}.message_type`),
    business_service: normalizeIsoOptionalString(
      record.business_service,
      `${context}.business_service`,
    ),
    business_message_id: normalizeIsoOptionalString(
      record.business_message_id,
      `${context}.business_message_id`,
    ),
    uetr: normalizeIsoOptionalString(record.uetr, `${context}.uetr`),
    payload_hash: normalizeIsoOptionalString(record.payload_hash, `${context}.payload_hash`),
    reference_snapshot_id: normalizeIsoOptionalString(
      record.reference_snapshot_id,
      `${context}.reference_snapshot_id`,
    ),
    embedded_signature_detected:
      record.embedded_signature_detected === undefined ||
      record.embedded_signature_detected === null
        ? false
        : coerceBoolean(
            record.embedded_signature_detected,
            `${context}.embedded_signature_detected`,
          ),
    originator_participant_id: normalizeIsoOptionalString(
      record.originator_participant_id,
      `${context}.originator_participant_id`,
    ),
    counterparty_participant_id: normalizeIsoOptionalString(
      record.counterparty_participant_id,
      `${context}.counterparty_participant_id`,
    ),
    admitting_participant_id: normalizeIsoOptionalString(
      record.admitting_participant_id,
      `${context}.admitting_participant_id`,
    ),
    admitting_operator_key: normalizeIsoOptionalString(
      record.admitting_operator_key,
      `${context}.admitting_operator_key`,
    ),
    pinned_profile_id: normalizeIsoOptionalString(
      record.pinned_profile_id,
      `${context}.pinned_profile_id`,
    ),
    pinned_signature_policy: normalizeIsoOptionalString(
      record.pinned_signature_policy,
      `${context}.pinned_signature_policy`,
    ),
    status_history: normalizeIsoStatusHistory(record.status_history, `${context}.status_history`),
    hold_reason_code: normalizeIsoOptionalString(record.hold_reason_code, `${context}.hold_reason_code`),
    change_reason_codes: normalizeIsoStringArray(
      record.change_reason_codes,
      `${context}.change_reason_codes`,
    ),
    rejection_reason_code: normalizeIsoOptionalString(
      record.rejection_reason_code,
      `${context}.rejection_reason_code`,
    ),
    ledger_id: normalizeIsoOptionalString(record.ledger_id, `${context}.ledger_id`),
    source_account_id: normalizeIsoOptionalString(
      record.source_account_id,
      `${context}.source_account_id`,
    ),
    source_account_address: normalizeIsoOptionalString(
      record.source_account_address,
      `${context}.source_account_address`,
    ),
    target_account_id: normalizeIsoOptionalString(
      record.target_account_id,
      `${context}.target_account_id`,
    ),
    target_account_address: normalizeIsoOptionalString(
      record.target_account_address,
      `${context}.target_account_address`,
    ),
    asset_definition_id: normalizeIsoOptionalString(
      record.asset_definition_id,
      `${context}.asset_definition_id`,
    ),
    asset_id: normalizeIsoOptionalString(record.asset_id, `${context}.asset_id`),
    settlement_amount: normalizeIsoOptionalString(
      record.settlement_amount,
      `${context}.settlement_amount`,
    ),
    settlement_currency: normalizeIsoOptionalString(
      record.settlement_currency,
      `${context}.settlement_currency`,
    ),
    settlement_date: normalizeIsoOptionalString(
      record.settlement_date,
      `${context}.settlement_date`,
    ),
    settlement_quantity: normalizeIsoOptionalString(
      record.settlement_quantity,
      `${context}.settlement_quantity`,
    ),
    settlement_movement_type: normalizeIsoOptionalString(
      record.settlement_movement_type,
      `${context}.settlement_movement_type`,
    ),
    settlement_payment_type: normalizeIsoOptionalString(
      record.settlement_payment_type,
      `${context}.settlement_payment_type`,
    ),
    security_instrument_id: normalizeIsoOptionalString(
      record.security_instrument_id,
      `${context}.security_instrument_id`,
    ),
    collateral_obligation_id: normalizeIsoOptionalString(
      record.collateral_obligation_id,
      `${context}.collateral_obligation_id`,
    ),
    collateral_original_amount: normalizeIsoOptionalString(
      record.collateral_original_amount,
      `${context}.collateral_original_amount`,
    ),
    collateral_original_currency: normalizeIsoOptionalString(
      record.collateral_original_currency,
      `${context}.collateral_original_currency`,
    ),
    collateral_original_instrument_id: normalizeIsoOptionalString(
      record.collateral_original_instrument_id,
      `${context}.collateral_original_instrument_id`,
    ),
    collateral_substitute_amount: normalizeIsoOptionalString(
      record.collateral_substitute_amount,
      `${context}.collateral_substitute_amount`,
    ),
    collateral_substitute_currency: normalizeIsoOptionalString(
      record.collateral_substitute_currency,
      `${context}.collateral_substitute_currency`,
    ),
    collateral_substitute_instrument_id: normalizeIsoOptionalString(
      record.collateral_substitute_instrument_id,
      `${context}.collateral_substitute_instrument_id`,
    ),
    collateral_effective_date: normalizeIsoOptionalString(
      record.collateral_effective_date,
      `${context}.collateral_effective_date`,
    ),
    collateral_substitution_type: normalizeIsoOptionalString(
      record.collateral_substitution_type,
      `${context}.collateral_substitution_type`,
    ),
    collateral_haircut: normalizeIsoOptionalString(
      record.collateral_haircut,
      `${context}.collateral_haircut`,
    ),
    collateral_reason_code: normalizeIsoOptionalString(
      record.collateral_reason_code,
      `${context}.collateral_reason_code`,
    ),
    plan_execution_order: normalizeIsoOptionalString(
      record.plan_execution_order,
      `${context}.plan_execution_order`,
    ),
    plan_atomicity: normalizeIsoOptionalString(
      record.plan_atomicity,
      `${context}.plan_atomicity`,
    ),
  };

  if (options.includeStatusFields) {
    base.detail = normalizeIsoOptionalString(record.detail, `${context}.detail`, {
      allowEmpty: true,
    });
    if (record.updated_at_ms === undefined || record.updated_at_ms === null) {
      base.updated_at_ms = null;
    } else {
      base.updated_at_ms = ToriiClient._normalizeUnsignedInteger(
        record.updated_at_ms,
        `${context}.updated_at_ms`,
        { allowZero: true },
      );
    }
  }

  return base;
}

function normalizeIsoStatusResponse(payload, context) {
  return normalizeIsoSubmissionResponse(payload, context, { includeStatusFields: true });
}

function normalizeIsoStatusHistory(value, context) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  return value.map((entry, index) => {
    const record = ToriiClient._requirePlainObject(entry, `${context}[${index}]`);
    return {
      status: normalizeIsoStatus(record.status, `${context}[${index}].status`),
      pacs002_code: normalizePacs002Code(
        record.pacs002_code,
        `${context}[${index}].pacs002_code`,
      ),
      updated_at_ms:
        record.updated_at_ms === undefined || record.updated_at_ms === null
          ? null
          : ToriiClient._normalizeUnsignedInteger(
              record.updated_at_ms,
              `${context}[${index}].updated_at_ms`,
              { allowZero: true },
            ),
      detail: normalizeIsoOptionalString(record.detail, `${context}[${index}].detail`, {
        allowEmpty: true,
      }),
      reason_code: normalizeIsoOptionalString(
        record.reason_code,
        `${context}[${index}].reason_code`,
      ),
    };
  });
}

function normalizeIsoMessageKind(value, context) {
  const normalizedPath =
    typeof context === JS_TYPE_STRING ? context.replace(/\s+/g, ".") : context;
  if (typeof value !== JS_TYPE_STRING) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} must be 'pacs.008' or 'pacs.009'`,
      normalizedPath,
    );
  }
  const normalized = value.trim().toLowerCase();
  if (normalized === "pacs.008" || normalized === "pacs.009") {
    return normalized;
  }
  throw createValidationError(
    ValidationErrorCode.INVALID_STRING,
    `${context} must be 'pacs.008' or 'pacs.009'`,
    normalizedPath,
  );
}

function normalizeIsoSubmissionOptions(options, context, extraAllowedKeys = []) {
  if (options === undefined) {
    return { signal: undefined, contentType: undefined, retryProfile: undefined, profile: undefined };
  }
  const optionPath = `${context}.options`;
  const unsupportedLabel = context === "submitIsoMessage" ? `${context} options` : optionPath;
  if (!isPlainObject(options)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${optionPath} must be a plain object`,
      optionPath,
    );
  }
  const allowedKeys = new Set(["signal", "contentType", "retryProfile", "profile", ...extraAllowedKeys]);
  const extras = Object.keys(options).filter((key) => !allowedKeys.has(key));
  if (extras.length > 0) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${unsupportedLabel} contains unsupported fields: ${extras.join(", ")}`,
      optionPath,
    );
  }
  const rawSignal = options.signal;
  let signal;
  if (rawSignal !== undefined && rawSignal !== null) {
    if (!isAbortSignalLike(rawSignal)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${optionPath}.signal must be an AbortSignal`,
        `${optionPath}.signal`,
      );
    }
    signal = rawSignal;
  }
  let contentType;
  if (options.contentType !== undefined && options.contentType !== null) {
    if (typeof options.contentType !== JS_TYPE_STRING) {
      throw createValidationError(
        ValidationErrorCode.INVALID_STRING,
        `${optionPath}.contentType must be a string`,
        `${optionPath}.contentType`,
      );
    }
    const trimmed = options.contentType.trim();
    if (!trimmed) {
      throw createValidationError(
        ValidationErrorCode.INVALID_STRING,
        `${optionPath}.contentType must not be empty`,
        `${optionPath}.contentType`,
      );
    }
    contentType = trimmed;
  }
  let retryProfile;
  if (options.retryProfile !== undefined && options.retryProfile !== null) {
    retryProfile = requireNonEmptyString(options.retryProfile, `${optionPath}.retryProfile`);
  }
  let profile;
  if (options.profile !== undefined && options.profile !== null) {
    profile = normalizeIsoProfile(options.profile, `${optionPath}.profile`);
  }
  return { signal, contentType, retryProfile, profile };
}

function normalizeIsoStatusOptions(options, context) {
  if (options === undefined) {
    return { signal: undefined, retryProfile: undefined };
  }
  const optionPath = `${context}.options`;
  if (!isPlainObject(options)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${optionPath} must be a plain object`,
      optionPath,
    );
  }
  const extras = Object.keys(options).filter(
    (key) => key !== "signal" && key !== "retryProfile",
  );
  if (extras.length > 0) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${optionPath} contains unsupported fields: ${extras.join(", ")}`,
      optionPath,
    );
  }
  const { signal } = normalizeSignalOption(options, context);
  let retryProfile;
  if (options.retryProfile !== undefined && options.retryProfile !== null) {
    retryProfile = requireNonEmptyString(options.retryProfile, `${optionPath}.retryProfile`);
  }
  return { signal, retryProfile };
}

function requireIsoPlainObject(value, context) {
  if (!isPlainObject(value)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} must be a plain object`,
      context,
    );
  }
  return value;
}

function normalizeIsoPayload(message, context) {
  if (message === undefined || message === null) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} is required`,
      context,
    );
  }
  try {
    return toXmlBuffer(message, context);
  } catch (error) {
    if (error instanceof TypeError) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        error.message,
        context,
        error,
      );
    }
    throw error;
  }
}

function normalizeStatusSnapshot(payload, state) {
  if (!isPlainObject(payload)) {
    rejectType("status response must be a JSON object");
  }
  const statusPayload = parseStatusPayload(payload);
  const metrics =
    state && typeof state.record === JS_TYPE_FUNCTION
      ? state.record(statusPayload)
      : computeStatusMetrics(null, statusPayload);
  return {
    timestamp: monotonicTimestamp(),
    status: statusPayload,
    metrics,
  };
}

function createStatusSnapshotState() {
  let previous = null;
  return {
    record(current) {
      const metrics = computeStatusMetrics(previous, current);
      previous = current;
      return metrics;
    },
  };
}

function normalizeTimeNowResponse(payload) {
  const record = ensureRecord(payload ?? {}, "time now response");
  return {
    timestampMs: ToriiClient._normalizeUnsignedInteger(
      record.now,
      "time now response.now",
      { allowZero: true },
    ),
    offsetMs: coerceInteger(record.offset_ms, "time now response.offset_ms"),
    confidenceMs: coerceInteger(record.confidence_ms, "time now response.confidence_ms"),
  };
}

function normalizeTimeStatusResponse(payload) {
  const record = ensureRecord(payload ?? {}, "time status response");
  const peers = ToriiClient._normalizeUnsignedInteger(
    record.peers ?? 0,
    "time status response.peers",
    { allowZero: true },
  );
  const rawSamples = record.samples === undefined ? [] : record.samples;
  if (!Array.isArray(rawSamples)) {
    rejectType("time status response.samples must be an array");
  }
  const samples = rawSamples.map((entry, index) => {
    const sample = ensureRecord(entry, `time status response.samples[${index}]`);
    return {
      peer: requireNonEmptyString(sample.peer, `time status response.samples[${index}].peer`),
      lastOffsetMs: coerceInteger(
        sample.last_offset_ms,
        `time status response.samples[${index}].last_offset_ms`,
      ),
      lastRttMs: coerceInteger(
        sample.last_rtt_ms,
        `time status response.samples[${index}].last_rtt_ms`,
      ),
      count: ToriiClient._normalizeUnsignedInteger(
        sample.count ?? 0,
        `time status response.samples[${index}].count`,
        { allowZero: true },
      ),
    };
  });
  const rttRecord = ensureRecord(record.rtt ?? {}, "time status response.rtt");
  const rawBuckets =
    rttRecord.buckets === undefined ? [] : rttRecord.buckets;
  if (!Array.isArray(rawBuckets)) {
    rejectType("time status response.rtt.buckets must be an array");
  }
  const buckets = rawBuckets.map((entry, index) => {
    const bucket = ensureRecord(entry, `time status response.rtt.buckets[${index}]`);
    return {
      le: coerceInteger(bucket.le, `time status response.rtt.buckets[${index}].le`),
      count: ToriiClient._normalizeUnsignedInteger(
        bucket.count ?? 0,
        `time status response.rtt.buckets[${index}].count`,
        { allowZero: true },
      ),
    };
  });
  const rtt = {
    buckets,
    sumMs: ToriiClient._normalizeUnsignedInteger(
      rttRecord.sum_ms ?? 0,
      "time status response.rtt.sum_ms",
      { allowZero: true },
    ),
    count: ToriiClient._normalizeUnsignedInteger(
      rttRecord.count ?? 0,
      "time status response.rtt.count",
      { allowZero: true },
    ),
  };
  return {
    peers,
    samples,
    rtt,
    note: optionalString(record.note, "time status response.note"),
  };
}

function parseStatusPayload(payload) {
  for (const field of ["lane_commitments", "dataspace_commitments", "pipeline_execution"]) {
    if (Object.hasOwn(payload, field)) {
      rejectType(`status.${field} is retired and unsupported`);
    }
  }
  return {
    observed_at_ms: coerceStatusInt(payload.observed_at_ms, "status.observed_at_ms"),
    peers: coerceStatusInt(payload.peers, "status.peers"),
    queue_size: coerceStatusInt(payload.queue_size, "status.queue_size"),
    queue_queued: coerceStatusInt(payload.queue_queued, "status.queue_queued"),
    queue_inflight: coerceStatusInt(payload.queue_inflight, "status.queue_inflight"),
    last_block_committed_at_ms: coerceStatusInt(
      payload.last_block_committed_at_ms,
      "status.last_block_committed_at_ms",
    ),
    last_non_empty_block_committed_at_ms: coerceStatusInt(
      payload.last_non_empty_block_committed_at_ms,
      "status.last_non_empty_block_committed_at_ms",
    ),
    time_since_last_block_ms: coerceStatusInt(
      payload.time_since_last_block_ms,
      "status.time_since_last_block_ms",
    ),
    time_since_last_non_empty_block_ms: coerceStatusInt(
      payload.time_since_last_non_empty_block_ms,
      "status.time_since_last_non_empty_block_ms",
    ),
    commit_time_ms: coerceStatusInt(payload.commit_time_ms, "status.commit_time_ms"),
    txs_approved: coerceStatusInt(payload.txs_approved, "status.txs_approved"),
    txs_rejected: coerceStatusInt(payload.txs_rejected, "status.txs_rejected"),
    view_changes: coerceStatusInt(payload.view_changes, "status.view_changes"),
    governance: parseGovernanceSnapshot(payload.governance),
    lane_governance: parseLaneGovernance(payload.lane_governance),
    dataspace_catalog: parseDataspaceCatalog(payload.dataspace_catalog),
    lane_governance_sealed_total: coerceStatusInt(
      payload.lane_governance_sealed_total,
      "status.lane_governance_sealed_total",
    ),
    lane_governance_sealed_aliases: parseStringArray(
      payload.lane_governance_sealed_aliases,
      "status.lane_governance_sealed_aliases",
    ),
    raw: Object.freeze({ ...payload }),
  };
}

function parseGovernanceSnapshot(payload) {
  if (payload == null) {
    return null;
  }
  const record = ensureRecord(payload, "governance payload");
  const proposals = ensureRecord(record.proposals, "governance.proposals");
  const protectedNamespace = ensureRecord(
    record.protected_namespace,
    "governance.protected_namespace",
  );
  const manifestAdmission = ensureRecord(
    record.manifest_admission,
    GOVERNANCE_MANIFEST_ADMISSION_CONTEXT,
  );
  const manifestQuorum = ensureRecord(
    record.manifest_quorum,
    "governance.manifest_quorum",
  );
  const recentActivations = parseGovernanceActivations(
    record.recent_manifest_activations,
  );
  return {
    proposals: {
      proposed: coerceNestedInt(proposals, "proposed", "governance.proposals"),
      rejected: coerceNestedInt(proposals, "rejected", "governance.proposals"),
      enacted: coerceNestedInt(proposals, "enacted", "governance.proposals"),
      superseded: coerceNestedInt(proposals, "superseded", "governance.proposals"),
      execution_failed: coerceNestedInt(
        proposals,
        "execution_failed",
        "governance.proposals",
      ),
    },
    protected_namespace: {
      total_checks: coerceNestedInt(
        protectedNamespace,
        "total_checks",
        "governance.protected_namespace",
      ),
      allowed: coerceNestedInt(
        protectedNamespace,
        "allowed",
        "governance.protected_namespace",
      ),
      rejected: coerceNestedInt(
        protectedNamespace,
        "rejected",
        "governance.protected_namespace",
      ),
    },
    manifest_admission: {
      total_checks: coerceNestedInt(
        manifestAdmission,
        "total_checks",
        GOVERNANCE_MANIFEST_ADMISSION_CONTEXT,
      ),
      allowed: coerceNestedInt(
        manifestAdmission,
        "allowed",
        GOVERNANCE_MANIFEST_ADMISSION_CONTEXT,
      ),
      missing_manifest: coerceNestedInt(
        manifestAdmission,
        "missing_manifest",
        GOVERNANCE_MANIFEST_ADMISSION_CONTEXT,
      ),
      non_validator_authority: coerceNestedInt(
        manifestAdmission,
        "non_validator_authority",
        GOVERNANCE_MANIFEST_ADMISSION_CONTEXT,
      ),
      quorum_rejected: coerceNestedInt(
        manifestAdmission,
        "quorum_rejected",
        GOVERNANCE_MANIFEST_ADMISSION_CONTEXT,
      ),
      protected_namespace_rejected: coerceNestedInt(
        manifestAdmission,
        "protected_namespace_rejected",
        GOVERNANCE_MANIFEST_ADMISSION_CONTEXT,
      ),
      runtime_hook_rejected: coerceNestedInt(
        manifestAdmission,
        "runtime_hook_rejected",
        GOVERNANCE_MANIFEST_ADMISSION_CONTEXT,
      ),
    },
    manifest_quorum: {
      total_checks: coerceNestedInt(
        manifestQuorum,
        "total_checks",
        "governance.manifest_quorum",
      ),
      satisfied: coerceNestedInt(
        manifestQuorum,
        "satisfied",
        "governance.manifest_quorum",
      ),
      rejected: coerceNestedInt(
        manifestQuorum,
        "rejected",
        "governance.manifest_quorum",
      ),
    },
    recent_manifest_activations: recentActivations,
  };
}

function parseGovernanceActivations(payload) {
  if (payload == null) {
    return [];
  }
  if (!Array.isArray(payload)) {
    rejectType("governance.recent_manifest_activations must be an array");
  }
  return payload.map((entry, index) => {
    if (!isPlainObject(entry)) {
      rejectType(`governance.recent_manifest_activations[${index}] must be an object`);
    }
    const contractAddress =
      entry.contract_address === undefined || entry.contract_address === null
        ? ""
        : String(entry.contract_address);
    const codeHash =
      entry.code_hash_hex === undefined || entry.code_hash_hex === null
        ? ""
        : String(entry.code_hash_hex);
    const abiHash =
      entry.abi_hash_hex === undefined || entry.abi_hash_hex === null
        ? null
        : String(entry.abi_hash_hex);
    return {
      contract_address: contractAddress,
      code_hash_hex: codeHash,
      abi_hash_hex: abiHash,
      height: coerceNestedInt(
        entry,
        "height",
        `governance.recent_manifest_activations[${index}]`,
      ),
      activated_at_ms: coerceNestedInt(
        entry,
        "activated_at_ms",
        `governance.recent_manifest_activations[${index}]`,
      ),
    };
  });
}

function parseDataspaceCatalog(payload) {
  if (payload == null) {
    return [];
  }
  if (!Array.isArray(payload)) {
    rejectType("status.dataspace_catalog must be an array");
  }
  return payload.map((entry, index) => {
    const record = ensureRecord(entry, `status.dataspace_catalog[${index}]`);
    const manifestRequired = coerceBoolean(
      record.manifest_required,
      `status.dataspace_catalog[${index}].manifest_required`,
    );
    const manifestReady = coerceBoolean(
      record.manifest_ready,
      `status.dataspace_catalog[${index}].manifest_ready`,
    );
    return {
      lane_id: coerceNestedInt(record, "lane_id", `status.dataspace_catalog[${index}]`),
      lane_alias:
        record.lane_alias === undefined || record.lane_alias === null
          ? ""
          : String(record.lane_alias),
      dataspace_id: coerceNestedInt(
        record,
        "dataspace_id",
        `status.dataspace_catalog[${index}]`,
      ),
      alias:
        record.alias === undefined || record.alias === null
          ? ""
          : String(record.alias),
      visibility:
        record.visibility === undefined || record.visibility === null
          ? ""
          : String(record.visibility),
      storage_profile:
        record.storage_profile === undefined || record.storage_profile === null
          ? ""
          : String(record.storage_profile),
      manifest_required: manifestRequired,
      manifest_ready: manifestReady,
      sealed:
        record.sealed === undefined || record.sealed === null
          ? manifestRequired && !manifestReady
          : coerceBoolean(record.sealed, `status.dataspace_catalog[${index}].sealed`),
      manifest_path: optionalString(
        record.manifest_path,
        `status.dataspace_catalog[${index}].manifest_path`,
      ),
      protected_namespaces: parseStringArray(
        record.protected_namespaces,
        `status.dataspace_catalog[${index}].protected_namespaces`,
      ),
    };
  });
}

function parseLanePrivacyCommitments(payload, context) {
  if (payload == null) {
    return [];
  }
  if (!Array.isArray(payload)) {
    rejectType(`${context} must be an array`);
  }
  return payload.map((entry, index) =>
    parseLanePrivacyCommitment(entry, `${context}[${index}]`),
  );
}

function parseLanePrivacyCommitment(entry, context) {
  const record = ensureRecord(entry, context);
  const id = coerceNestedInt(record, "id", context);
  const scheme =
    record.scheme === undefined || record.scheme === null ? "" : String(record.scheme);
  if (scheme !== "merkle") {
    rejectType(`${context}.scheme must be "merkle"`);
  }
  const merkleRecord = ensureRecord(record.merkle, `${context}.merkle`);
  const merkle = {
    root:
      merkleRecord.root === undefined || merkleRecord.root === null
        ? ""
        : String(merkleRecord.root),
    max_depth: coerceNestedInt(merkleRecord, "max_depth", `${context}.merkle`),
  };
  return { id, scheme, merkle };
}

function parseLaneGovernance(payload) {
  if (payload == null) {
    return [];
  }
  if (!Array.isArray(payload)) {
    rejectType("status.lane_governance must be an array");
  }
  return payload.map((entry, index) => {
    const record = ensureRecord(entry, `status.lane_governance[${index}]`);
    const runtimePayload = record.runtime_upgrade;
    let runtimeUpgrade = null;
    if (runtimePayload != null) {
      const runtimeRecord = ensureRecord(
        runtimePayload,
        `status.lane_governance[${index}].runtime_upgrade`,
      );
      runtimeUpgrade = {
        allow: coerceBoolean(
          runtimeRecord.allow,
          `status.lane_governance[${index}].runtime_upgrade.allow`,
        ),
        require_metadata: coerceBoolean(
          runtimeRecord.require_metadata,
          `status.lane_governance[${index}].runtime_upgrade.require_metadata`,
        ),
        metadata_key:
          runtimeRecord.metadata_key === undefined || runtimeRecord.metadata_key === null
            ? null
            : String(runtimeRecord.metadata_key),
        allowed_ids: parseStringArray(
          runtimeRecord.allowed_ids,
          `status.lane_governance[${index}].runtime_upgrade.allowed_ids`,
        ),
      };
    }
    return {
      lane_id: coerceNestedInt(record, "lane_id", `status.lane_governance[${index}]`),
      alias:
        record.alias === undefined || record.alias === null ? "" : String(record.alias),
      dataspace_id: coerceNestedInt(
        record,
        "dataspace_id",
        `status.lane_governance[${index}]`,
      ),
      visibility:
        record.visibility === undefined || record.visibility === null
          ? ""
          : String(record.visibility),
      storage_profile:
        record.storage_profile === undefined || record.storage_profile === null
          ? ""
          : String(record.storage_profile),
      governance:
        record.governance === undefined || record.governance === null
          ? null
          : String(record.governance),
      manifest_required: coerceBoolean(
        record.manifest_required,
        `status.lane_governance[${index}].manifest_required`,
      ),
      manifest_ready: coerceBoolean(
        record.manifest_ready,
        `status.lane_governance[${index}].manifest_ready`,
      ),
      manifest_path:
        record.manifest_path === undefined || record.manifest_path === null
          ? null
          : String(record.manifest_path),
      validator_ids: parseStringArray(
        record.validator_ids,
        `status.lane_governance[${index}].validator_ids`,
      ),
      quorum: coerceOptionalInt(
        record.quorum,
        `status.lane_governance[${index}].quorum`,
      ),
      protected_namespaces: parseStringArray(
        record.protected_namespaces,
        `status.lane_governance[${index}].protected_namespaces`,
      ),
      runtime_upgrade: runtimeUpgrade,
      privacy_commitments: parseLanePrivacyCommitments(
        record.privacy_commitments,
        `status.lane_governance[${index}].privacy_commitments`,
      ),
    };
  });
}

function normalizeStringArray(payload, context) {
  if (!Array.isArray(payload)) {
    rejectType(`${context} must be an array`);
  }
  return payload.map((value, index) =>
    requireNonEmptyString(value, `${context}[${index}]`),
  );
}

function normalizeSumeragiBlsKeysMap(payload) {
  const record = ensureRecord(payload, "sumeragi BLS keys payload");
  const normalized = {};
  for (const [key, value] of Object.entries(record)) {
    const peerId = requireNonEmptyString(key, "sumeragi BLS key peer id");
    if (value == null) {
      normalized[peerId] = null;
    } else {
      normalized[peerId] = requireNonEmptyString(value, `sumeragi BLS key["${peerId}"]`);
    }
  }
  return normalized;
}

const SUMERAGI_PARAMS_FIELDS = Object.freeze([
  "block_cadence_ms",
  "max_clock_drift_ms",
  "chain_height",
]);

function normalizeSumeragiParamsSnapshot(payload) {
  const context = "sumeragi params response";
  const record = ensureRecord(payload, context);
  const unknown = Object.keys(record).filter(
    (field) => !SUMERAGI_PARAMS_FIELDS.includes(field),
  );
  if (unknown.length !== 0) {
    rejectType(`${context} contains unsupported fields: ${unknown.sort().join(", ")}`);
  }
  const blockCadenceMs = requireNonNegativeIntegerLike(
    record.block_cadence_ms,
    "sumeragi params.block_cadence_ms",
  );
  if (blockCadenceMs === 0) {
    rejectRange("sumeragi params.block_cadence_ms must be nonzero");
  }
  return {
    block_cadence_ms: blockCadenceMs,
    max_clock_drift_ms: requireNonNegativeIntegerLike(
      record.max_clock_drift_ms,
      "sumeragi params.max_clock_drift_ms",
    ),
    chain_height: requireNonNegativeIntegerLike(
      record.chain_height,
      "sumeragi params.chain_height",
    ),
  };
}

const GOVERNANCE_PROPOSAL_STATUSES = new Set([
  "Proposed",
  "Rejected",
  "Enacted",
  "Superseded",
  "ExecutionFailed",
]);

async function parseGovernanceProposalResult(payload) {
  const record = ensureRecord(payload, "governance proposal payload");
  if (typeof record.found !== "boolean") {
    rejectType("governance proposal payload missing bool `found` field");
  }
  if (record.proposal == null) {
    return { found: record.found, proposal: null };
  }
  const proposalRecord = ensureRecord(record.proposal, "governance proposal payload.proposal");
  return {
    found: record.found,
    proposal: await parseGovernanceProposalRecord(proposalRecord),
  };
}

async function parseGovernanceProposalRecord(payload) {
  const record = requireExactGovernanceProposalRecord(
    payload,
    ["proposer", "kind", "created_height", "status"],
    "governance proposal record",
  );
  const proposer = requireCanonicalGovernanceAccountId(
    record.proposer,
    "governance.proposal.proposer",
  );
  const createdHeight = requireExactJsonUnsignedInteger(
    record.created_height,
    "governance.proposal.created_height",
  );
  const statusValue = record.status;
  if (typeof statusValue !== JS_TYPE_STRING || !GOVERNANCE_PROPOSAL_STATUSES.has(statusValue)) {
    rejectType("governance proposal status must be one of Proposed, Rejected, Enacted, Superseded, ExecutionFailed");
  }
  const kindPayload = ensureRecord(record.kind, "governance.proposal.kind");
  const kind = await parseGovernanceProposalKind(
    kindPayload,
    "governance.proposal.kind",
  );
  let proposalOperator = null;
  if (kind.variant === "DeployContract") {
    proposalOperator = kind.deploy_contract.proposal_operator;
  } else if (kind.variant === "RuntimeUpgrade") {
    proposalOperator = kind.runtime_upgrade.proposal_operator;
  } else if (kind.variant === "ContractLifecycleGovernance") {
    proposalOperator = kind.contract_lifecycle_governance.proposal_operator;
  } else if (kind.variant === "ValidationFeePolicy") {
    proposalOperator = kind.validation_fee_policy.proposal_operator;
  } else if (kind.variant === "ValidationFeePayoutLifecycle") {
    proposalOperator = kind.validation_fee_payout_lifecycle.proposal_operator;
  }
  if (proposalOperator !== null && proposalOperator !== proposer) {
    rejectType("governance proposal operator must match the retained proposer");
  }
  return {
    proposer,
    created_height: createdHeight,
    status: statusValue,
    kind,
  };
}

async function parseGovernanceProposalKind(payload, context) {
  const record = requireExactGovernanceProposalRecord(
    payload,
    ["kind", "payload"],
    context,
  );
  const variant = requireExactNonEmptyString(record.kind, `${context}.kind`);
  const details = ensureRecord(record.payload, `${context}.payload`);
  switch (variant) {
    case "DeployContract":
      return {
        variant,
        deploy_contract: parseGovernanceDeployContract(
          details,
          `${context}.payload`,
        ),
      };
    case "RuntimeUpgrade":
      return {
        variant,
        runtime_upgrade: parseGovernanceRuntimeUpgrade(details, `${context}.payload`),
      };
    case "SccpRouteGovernance":
      return {
        variant,
        sccp_route_governance: parseGovernanceSccpRouteGovernance(
          details,
          `${context}.payload`,
        ),
      };
    case "ValidationFeePolicy":
      return {
        variant,
        validation_fee_policy: parseGovernanceValidationFeePolicy(
          details,
          `${context}.payload`,
        ),
      };
    case "ValidationFeePayoutLifecycle":
      return {
        variant,
        validation_fee_payout_lifecycle: parseGovernanceValidationFeePayoutLifecycle(
          details,
          `${context}.payload`,
        ),
      };
    case "MusubiRegistryGovernance":
      return {
        variant,
        musubi_registry_governance: parseGovernanceMusubiAction(
          details,
          `${context}.payload`,
        ),
      };
    case "SorafsProviderGovernance":
      return {
        variant,
        sorafs_provider_governance: parseGovernanceSorafsProvider(
          details,
          `${context}.payload`,
        ),
      };
    case "ContractLifecycleGovernance": {
      const { normalizeGovernanceProposalWireV1 } = await loadToriiOptionalModule();
      return {
        variant,
        contract_lifecycle_governance: normalizeGovernanceProposalWireV1(
          record,
          context,
        ).payload,
      };
    }
    case "ContractEmergencyHold": {
      const { normalizeGovernanceProposalWireV1 } = await loadToriiOptionalModule();
      return {
        variant,
        contract_emergency_hold: normalizeGovernanceProposalWireV1(
          record,
          context,
        ).payload,
      };
    }
    case "GlobalDataTriggerPermissionGovernance": {
      const { normalizeGovernanceProposalWireV1 } = await loadToriiOptionalModule();
      return {
        variant,
        global_data_trigger_permission_governance: normalizeGovernanceProposalWireV1(
          record,
          context,
        ).payload,
      };
    }
    default:
      rejectType(`${context}.kind contains unsupported proposal variant: ${variant}`);
  }
}

function parseGovernanceDeployContract(payload, context) {
  const record = requireExactGovernanceProposalRecord(
    payload,
    [
      "proposal_operator",
      "contract_address",
      "code_hash",
      "abi_hash",
      "abi_version",
      "manifest_provenance",
    ],
    context,
  );
  if (record.abi_version !== 1) {
    rejectType(`${context}.abi_version must be the number 1`);
  }
  const contractAddress = requireExactNonEmptyString(
    record.contract_address,
    `${context}.contract_address`,
  );
  parseCanonicalContractAddress(contractAddress, `${context}.contract_address`);
  return {
    proposal_operator: requireCanonicalGovernanceAccountId(
      record.proposal_operator,
      `${context}.proposal_operator`,
    ),
    contract_address: contractAddress,
    code_hash: requireExactLowerHex32String(record.code_hash, `${context}.code_hash`),
    abi_hash: requireExactLowerHex32String(record.abi_hash, `${context}.abi_hash`),
    abi_version: 1,
    manifest_provenance:
      record.manifest_provenance === null
        ? null
        : parseGovernanceManifestProvenance(
            record.manifest_provenance,
            `${context}.manifest_provenance`,
          ),
  };
}

function parseGovernanceManifestProvenance(payload, context) {
  const record = requireExactGovernanceProposalRecord(
    payload,
    ["signer", "signature"],
    context,
  );
  return {
    signer: requireExactNonEmptyString(record.signer, `${context}.signer`),
    signature: requireExactNonEmptyString(record.signature, `${context}.signature`),
  };
}

function parseGovernanceRuntimeUpgrade(payload, context) {
  const record = requireExactGovernanceProposalRecord(
    payload,
    ["proposal_operator", "manifest"],
    context,
  );
  const manifestContext = `${context}.manifest`;
  const manifest = requireExactGovernanceProposalRecord(
    record.manifest,
    [
      "name",
      "description",
      "abi_version",
      "abi_hash",
      "added_syscalls",
      "added_pointer_types",
      "start_height",
      "end_height",
      "sbom_digests",
      "slsa_attestation",
      "provenance",
    ],
    manifestContext,
  );
  if (manifest.abi_version !== 1) {
    rejectType(`${manifestContext}.abi_version must be the number 1`);
  }
  const addedSyscalls = parseGovernanceUint16Array(
    manifest.added_syscalls,
    `${manifestContext}.added_syscalls`,
  );
  const addedPointerTypes = parseGovernanceUint16Array(
    manifest.added_pointer_types,
    `${manifestContext}.added_pointer_types`,
  );
  if (addedSyscalls.length !== 0 || addedPointerTypes.length !== 0) {
    rejectType(`${manifestContext} ABI delta lists must be empty in V1`);
  }
  const startHeight = requireExactJsonUnsignedInteger(
    manifest.start_height,
    `${manifestContext}.start_height`,
  );
  const endHeight = requireExactJsonUnsignedInteger(
    manifest.end_height,
    `${manifestContext}.end_height`,
  );
  if (endHeight <= startHeight) {
    rejectType(`${manifestContext}.end_height must be greater than start_height`);
  }
  return {
    proposal_operator: requireCanonicalGovernanceAccountId(
      record.proposal_operator,
      `${context}.proposal_operator`,
    ),
    manifest: {
      name: requireExactNonEmptyString(manifest.name, `${manifestContext}.name`),
      description: requireExactString(manifest.description, `${manifestContext}.description`),
      abi_version: 1,
      abi_hash: requireExactGovernanceByteArray(
        manifest.abi_hash,
        32,
        `${manifestContext}.abi_hash`,
      ),
      added_syscalls: addedSyscalls,
      added_pointer_types: addedPointerTypes,
      start_height: startHeight,
      end_height: endHeight,
      sbom_digests: parseGovernanceSbomDigests(
        manifest.sbom_digests,
        `${manifestContext}.sbom_digests`,
      ),
      slsa_attestation: requireCanonicalGovernanceBase64(
        manifest.slsa_attestation,
        `${manifestContext}.slsa_attestation`,
      ),
      provenance: requireGovernanceArray(
        manifest.provenance,
        `${manifestContext}.provenance`,
      ).map((item, index) => parseGovernanceManifestProvenance(
        item,
        `${manifestContext}.provenance[${index}]`,
      )),
    },
  };
}

function parseGovernanceSbomDigests(payload, context) {
  return requireGovernanceArray(payload, context).map((item, index) => {
    const itemContext = `${context}[${index}]`;
    const record = requireExactGovernanceProposalRecord(
      item,
      ["algorithm", "digest"],
      itemContext,
    );
    return {
      algorithm: requireExactNonEmptyString(record.algorithm, `${itemContext}.algorithm`),
      digest: requireCanonicalGovernanceBase64(record.digest, `${itemContext}.digest`),
    };
  });
}

const SCCP_GOVERNANCE_MAX_ACTIONS_V1 = 16;

function parseGovernanceSccpRouteGovernance(payload, context) {
  const record = requireExactGovernanceProposalRecord(payload, ["proposal"], context);
  const proposalContext = `${context}.proposal`;
  const proposal = requireExactGovernanceProposalRecord(
    record.proposal,
    ["network_id", "base_revisions", "actions"],
    proposalContext,
  );
  const networkId = requireExactNonEmptyString(
    proposal.network_id,
    `${proposalContext}.network_id`,
  );
  NetworkId.parse(networkId);
  const baseRevisions = requireGovernanceArray(
    proposal.base_revisions,
    `${proposalContext}.base_revisions`,
  );
  const actions = requireGovernanceArray(proposal.actions, `${proposalContext}.actions`);
  if (actions.length === 0 || actions.length > SCCP_GOVERNANCE_MAX_ACTIONS_V1) {
    rejectType(
      `${proposalContext}.actions must contain 1..${SCCP_GOVERNANCE_MAX_ACTIONS_V1} actions`,
    );
  }
  // TODO: validate each SccpGovernanceBaseRevisionV1 and SccpGovernanceActionV1
  // entry statically (specs/sccp.md §4.14.3) once the SDK carries typed SCCP
  // governance codecs; Torii and the node remain authoritative for them today.
  return {
    proposal: {
      network_id: networkId,
      base_revisions: baseRevisions,
      actions,
    },
  };
}











function parseGovernanceMusubiAction(payload, context) {
  const record = requireExactGovernanceProposalRecord(payload, ["kind", "value"], context);
  const valueContext = `${context}.value`;
  switch (record.kind) {
    case "RecoverPackageOwners": {
      const value = requireExactGovernanceProposalRecord(
        record.value,
        ["package", "owners", "expected_revision"],
        valueContext,
      );
      const owners = requireGovernanceArray(value.owners, `${valueContext}.owners`).map(
        (owner, index) => requireCanonicalGovernanceAccountId(
          owner,
          `${valueContext}.owners[${index}]`,
        ),
      );
      if (owners.length === 0 || owners.length > 64 || new Set(owners).size !== owners.length) {
        rejectType(`${valueContext}.owners must contain 1-64 unique accounts`);
      }
      return {
        kind: "RecoverPackageOwners",
        value: {
          package: parseGovernanceMusubiPackage(value.package, `${valueContext}.package`),
          owners,
          expected_revision: requireExactJsonUnsignedInteger(
            value.expected_revision,
            `${valueContext}.expected_revision`,
            { allowZero: false },
          ),
        },
      };
    }
    case "RetargetAlias": {
      const value = requireExactGovernanceProposalRecord(
        record.value,
        ["alias", "target", "expected_revision"],
        valueContext,
      );
      return {
        kind: "RetargetAlias",
        value: {
          alias: requireGovernanceAsciiKebab(
            requireExactGovernanceStringTuple(value.alias, `${valueContext}.alias`),
            `${valueContext}.alias[0]`,
            32,
          ),
          target: parseGovernanceMusubiPackage(value.target, `${valueContext}.target`),
          expected_revision: requireExactJsonUnsignedInteger(
            value.expected_revision,
            `${valueContext}.expected_revision`,
            { allowZero: false },
          ),
        },
      };
    }
    case "TakedownArtifact": {
      const value = requireExactGovernanceProposalRecord(
        record.value,
        ["release", "reason", "expected_artifact_governance_revision"],
        valueContext,
      );
      return {
        kind: "TakedownArtifact",
        value: {
          release: parseGovernanceMusubiRelease(value.release, `${valueContext}.release`),
          reason: requireGovernanceBoundedReason(
            requireExactGovernanceStringTuple(value.reason, `${valueContext}.reason`),
            `${valueContext}.reason[0]`,
          ),
          expected_artifact_governance_revision: requireExactJsonUnsignedInteger(
            value.expected_artifact_governance_revision,
            `${valueContext}.expected_artifact_governance_revision`,
            { allowZero: false },
          ),
        },
      };
    }
    case "SetRegistryPolicy": {
      const value = requireExactGovernanceProposalRecord(
        record.value,
        ["policy", "expected_revision"],
        valueContext,
      );
      const expectedRevision = requireExactJsonUnsignedInteger(
        value.expected_revision,
        `${valueContext}.expected_revision`,
        { allowZero: false },
      );
      const policy = parseGovernanceMusubiRegistryPolicy(
        value.policy,
        `${valueContext}.policy`,
      );
      if (policy.revision !== expectedRevision + 1) {
        rejectType(`${valueContext}.policy.revision must follow expected_revision`);
      }
      return {
        kind: "SetRegistryPolicy",
        value: { policy, expected_revision: expectedRevision },
      };
    }
    default:
      rejectType(`${context}.kind contains an unsupported Musubi action`);
  }
}

function parseGovernanceMusubiPackage(payload, context) {
  const record = requireExactGovernanceProposalRecord(
    payload,
    ["home_dataspace", "scope", "name"],
    context,
  );
  const scope = requireExactGovernanceProposalRecord(
    record.scope,
    ["kind", "value"],
    `${context}.scope`,
  );
  let normalizedScope;
  if (scope.kind === "DataspaceRoot" && scope.value === null) {
    normalizedScope = { kind: "DataspaceRoot", value: null };
  } else if (scope.kind === "Domain") {
    normalizedScope = {
      kind: "Domain",
      value: requireCanonicalGovernanceName(scope.value, `${context}.scope.value`),
    };
  } else {
    rejectType(`${context}.scope contains an unsupported package scope`);
  }
  return {
    home_dataspace: requireExactJsonUnsignedInteger(
      record.home_dataspace,
      `${context}.home_dataspace`,
    ),
    scope: normalizedScope,
    name: requireGovernanceAsciiKebab(
      requireExactGovernanceStringTuple(record.name, `${context}.name`),
      `${context}.name[0]`,
      64,
    ),
  };
}

function parseGovernanceMusubiRelease(payload, context) {
  const record = requireExactGovernanceProposalRecord(
    payload,
    ["package", "version"],
    context,
  );
  const version = requireExactGovernanceProposalRecord(
    record.version,
    ["major", "minor", "patch", "prerelease"],
    `${context}.version`,
  );
  const prerelease = requireGovernanceArray(
    version.prerelease,
    `${context}.version.prerelease`,
  ).map((item, index) => {
    const itemContext = `${context}.version.prerelease[${index}]`;
    const identifier = requireExactGovernanceProposalRecord(item, ["kind", "value"], itemContext);
    if (identifier.kind === "Numeric") {
      return {
        kind: "Numeric",
        value: requireExactJsonUnsignedInteger(identifier.value, `${itemContext}.value`),
      };
    }
    if (
      identifier.kind === "AlphaNumeric" &&
      typeof identifier.value === JS_TYPE_STRING &&
      identifier.value.length <= 64 &&
      /^(?=.*[A-Za-z-])[A-Za-z0-9-]+$/u.test(identifier.value)
    ) {
      return { kind: "AlphaNumeric", value: identifier.value };
    }
    rejectType(`${itemContext} contains an unsupported prerelease identifier`);
  });
  if (prerelease.length > 16) {
    rejectType(`${context}.version.prerelease exceeds the V1 bound`);
  }
  return {
    package: parseGovernanceMusubiPackage(record.package, `${context}.package`),
    version: {
      major: requireExactJsonUnsignedInteger(version.major, `${context}.version.major`),
      minor: requireExactJsonUnsignedInteger(version.minor, `${context}.version.minor`),
      patch: requireExactJsonUnsignedInteger(version.patch, `${context}.version.patch`),
      prerelease,
    },
  };
}

function parseGovernanceMusubiRegistryPolicy(payload, context) {
  const record = requireExactGovernanceProposalRecord(
    payload,
    ["version", "revision", "mode", "allowlisted_dataspaces", "alias_pricing"],
    context,
  );
  if (record.version !== 1) {
    rejectType(`${context}.version must be the number 1`);
  }
  const mode = requireExactGovernanceProposalRecord(
    record.mode,
    ["kind", "value"],
    `${context}.mode`,
  );
  if (!["Closed", "Allowlisted", "Open"].includes(mode.kind) || mode.value !== null) {
    rejectType(`${context}.mode contains an unsupported registry mode`);
  }
  const allowlistedDataspaces = requireGovernanceArray(
    record.allowlisted_dataspaces,
    `${context}.allowlisted_dataspaces`,
  ).map((value, index) => requireExactJsonUnsignedInteger(
    value,
    `${context}.allowlisted_dataspaces[${index}]`,
  ));
  if (
    new Set(allowlistedDataspaces).size !== allowlistedDataspaces.length ||
    allowlistedDataspaces.some((value, index) => index > 0 && allowlistedDataspaces[index - 1] >= value)
  ) {
    rejectType(`${context}.allowlisted_dataspaces must be sorted and unique`);
  }
  if (mode.kind !== "Allowlisted" && allowlistedDataspaces.length > 0) {
    rejectType(`${context}.allowlisted_dataspaces does not match mode`);
  }
  const pricing = requireExactGovernanceProposalRecord(
    record.alias_pricing,
    [
      "revision",
      "length_1_xor",
      "length_2_xor",
      "length_3_xor",
      "length_4_xor",
      "length_5_to_32_xor",
    ],
    `${context}.alias_pricing`,
  );
  const normalizedPricing = {};
  for (const field of [
    "revision",
    "length_1_xor",
    "length_2_xor",
    "length_3_xor",
    "length_4_xor",
    "length_5_to_32_xor",
  ]) {
    normalizedPricing[field] = requireExactJsonUnsignedInteger(
      pricing[field],
      `${context}.alias_pricing.${field}`,
      { allowZero: false },
    );
  }
  const revision = requireExactJsonUnsignedInteger(
    record.revision,
    `${context}.revision`,
    { allowZero: false },
  );
  return {
    version: 1,
    revision,
    mode: { kind: mode.kind, value: null },
    allowlisted_dataspaces: allowlistedDataspaces,
    alias_pricing: normalizedPricing,
  };
}

function parseGovernanceSorafsProvider(payload, context) {
  const record = requireExactGovernanceProposalRecord(payload, ["action"], context);
  const actionContext = `${context}.action`;
  const action = requireExactGovernanceProposalRecord(
    record.action,
    ["action", "value"],
    actionContext,
  );
  const valueContext = `${actionContext}.value`;
  if (action.action === "establish") {
    const value = requireExactGovernanceProposalRecord(
      action.value,
      ["provider_id", "owner"],
      valueContext,
    );
    return {
      action: {
        action: "establish",
        value: {
          provider_id: requireExactGovernanceProviderId(
            value.provider_id,
            `${valueContext}.provider_id`,
          ),
          owner: requireCanonicalGovernanceAccountId(value.owner, `${valueContext}.owner`),
        },
      },
    };
  }
  if (action.action === "rebind") {
    const value = requireExactGovernanceProposalRecord(
      action.value,
      ["provider_id", "expected_owner", "next_owner"],
      valueContext,
    );
    const expectedOwner = requireCanonicalGovernanceAccountId(
      value.expected_owner,
      `${valueContext}.expected_owner`,
    );
    const nextOwner = requireCanonicalGovernanceAccountId(
      value.next_owner,
      `${valueContext}.next_owner`,
    );
    if (expectedOwner === nextOwner) {
      rejectType(`${valueContext}.next_owner must differ from expected_owner`);
    }
    return {
      action: {
        action: "rebind",
        value: {
          provider_id: requireExactGovernanceProviderId(
            value.provider_id,
            `${valueContext}.provider_id`,
          ),
          expected_owner: expectedOwner,
          next_owner: nextOwner,
        },
      },
    };
  }
  if (action.action === "remove") {
    const value = requireExactGovernanceProposalRecord(
      action.value,
      ["provider_id", "expected_owner"],
      valueContext,
    );
    return {
      action: {
        action: "remove",
        value: {
          provider_id: requireExactGovernanceProviderId(
            value.provider_id,
            `${valueContext}.provider_id`,
          ),
          expected_owner: requireCanonicalGovernanceAccountId(
            value.expected_owner,
            `${valueContext}.expected_owner`,
          ),
        },
      },
    };
  }
  rejectType(`${actionContext}.action contains an unsupported provider action`);
}

function requireGovernanceArray(value, context) {
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  return value;
}

function requireExactGovernanceByteArray(value, length, context, options = {}) {
  const bytes = requireGovernanceArray(value, context);
  if (
    bytes.length !== length ||
    bytes.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)
  ) {
    rejectType(`${context} must contain exactly ${length} JSON byte values`);
  }
  if (options.nonZero === true && bytes.every((byte) => byte === 0)) {
    rejectType(`${context} must not be all zero`);
  }
  return [...bytes];
}

function requireExactGovernanceProviderId(value, context) {
  const tuple = requireGovernanceArray(value, context);
  if (tuple.length !== 1) {
    rejectType(`${context} must be the exact one-field ProviderId tuple`);
  }
  return requireExactGovernanceByteArray(tuple[0], 32, `${context}[0]`, {
    nonZero: true,
  });
}

function requireExactGovernanceStringTuple(value, context) {
  if (!Array.isArray(value) || value.length !== 1 || typeof value[0] !== JS_TYPE_STRING) {
    rejectType(`${context} must be the exact one-field string tuple`);
  }
  return value[0];
}

function parseGovernanceUint16Array(value, context) {
  return requireGovernanceArray(value, context).map((item, index) => {
    const parsed = requireExactJsonUnsignedInteger(item, `${context}[${index}]`);
    if (parsed > 0xffff) {
      rejectType(`${context}[${index}] must fit in an unsigned 16-bit integer`);
    }
    return parsed;
  });
}



function requireCanonicalGovernanceAccountId(value, context) {
  const literal = requireExactNonEmptyString(value, context);
  const canonical = ensureCanonicalAccountId(literal, context);
  if (canonical !== literal) {
    rejectType(`${context} must use the canonical account literal`);
  }
  return literal;
}



function requireCanonicalGovernanceBase64(value, context) {
  if (typeof value !== JS_TYPE_STRING) {
    rejectType(`${context} must be a canonical base64 string`);
  }
  if (value === "") return value;
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    rejectType(`${context} must be canonical padded base64`);
  }
  try {
    strictDecodeBase64(value);
  } catch {
    rejectType(`${context} must be canonical padded base64`);
  }
  return value;
}



function requireExactString(value, context) {
  if (typeof value !== JS_TYPE_STRING) {
    rejectType(`${context} must be a string`);
  }
  return value;
}

function requireGovernanceAsciiKebab(value, context, maxBytes) {
  const literal = requireExactNonEmptyString(value, context);
  if (
    Buffer.byteLength(literal, "utf8") > maxBytes ||
    !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(literal)
  ) {
    rejectType(`${context} must be canonical lowercase ASCII kebab text`);
  }
  return literal;
}

function requireCanonicalGovernanceName(value, context) {
  const literal = requireExactNonEmptyString(value, context);
  if (
    Buffer.byteLength(literal, "utf8") > 255 ||
    literal.normalize("NFC") !== literal ||
    /[\s@#$\p{Cc}\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(literal)
  ) {
    rejectType(`${context} must be a canonical Iroha Name`);
  }
  return literal;
}

function requireGovernanceBoundedReason(value, context) {
  const literal = requireExactNonEmptyString(value, context);
  if (
    literal.trim() !== literal ||
    Buffer.byteLength(literal, "utf8") > 1024 ||
    /[\u0000-\u001f\u007f]/u.test(literal)
  ) {
    rejectType(`${context} must be bounded canonical public text`);
  }
  return literal;
}

function requireExactGovernanceProposalRecord(payload, fields, context) {
  const record = ensureRecord(payload, context);
  const expected = new Set(fields);
  const unknown = Object.keys(record).filter((field) => !expected.has(field));
  if (unknown.length !== 0) {
    rejectType(`${context} contains unsupported fields: ${unknown.sort().join(", ")}`);
  }
  const missing = fields.filter(
    (field) => !Object.prototype.hasOwnProperty.call(record, field),
  );
  if (missing.length !== 0) {
    rejectType(`${context} is missing required fields: ${missing.join(", ")}`);
  }
  return record;
}

function createEmptyGovernanceTallyResult(referendumId) {
  return { found: false, referendum_id: referendumId, tally: null };
}

function createEmptyGovernanceLocksResult(referendumId) {
  return { found: false, referendum_id: referendumId, locks: {} };
}

function parseGovernanceUnlockStats(payload) {
  const record = ensureRecord(payload, "governance unlock stats payload");
  return {
    height_current: coerceInteger(record.height_current, "governance.unlock_stats.height_current"),
    expired_locks_now: coerceInteger(
      record.expired_locks_now,
      "governance.unlock_stats.expired_locks_now",
    ),
    referenda_with_expired: coerceInteger(
      record.referenda_with_expired,
      "governance.unlock_stats.referenda_with_expired",
    ),
    last_sweep_height: coerceInteger(
      record.last_sweep_height,
      "governance.unlock_stats.last_sweep_height",
    ),
  };
}

function normalizeErrorPath(context) {
  return typeof context === JS_TYPE_STRING ? context.replace(/\s+/g, ".") : context;
}

function normalizeProtectedNamespaceList(input) {
  if (input === undefined || input === null) {
    rejectType("protected namespaces input is required");
  }
  const values = Array.isArray(input) ? input : [input];
  if (values.length === 0) {
    rejectType("protected namespaces list must not be empty");
  }
  return values.map((entry, index) =>
    requireExactAsciiTokenString(entry, `namespaces[${index}]`),
  );
}

function normalizeProtectedNamespacesApplyResponse(payload) {
  const record = ensureRecord(payload, "protected namespaces apply response");
  return {
    ok: coerceBoolean(record.ok, "protected namespaces apply response.ok"),
    applied: coerceInteger(record.applied ?? 0, "protected namespaces apply response.applied"),
  };
}

function normalizeProtectedNamespacesGetResponse(payload) {
  const record = ensureRecord(payload, "protected namespaces response");
  return {
    found: coerceBoolean(record.found, "protected namespaces response.found"),
    namespaces: parseStringArray(
      record.namespaces,
      "protected namespaces response.namespaces",
    ).map((value, index) =>
      requireExactAsciiTokenString(value, `protected namespaces response.namespaces[${index}]`),
    ),
  };
}

function normalizeConfigurationSnapshot(payload) {
  const record = ensureRecord(payload, "configuration response");
  const publicKeyHex = requireNonEmptyString(
    record.public_key,
    "configuration response.public_key",
  );
  const logger = normalizeConfigurationLogger(record.logger, "configuration response.logger");
  const network = normalizeConfigurationNetwork(record.network, "configuration response.network");
  const queue = normalizeConfigurationQueue(record.queue, "configuration response.queue");
  const confidentialGas = normalizeConfigurationConfidentialGas(
    record.confidential_gas,
    "configuration response.confidential_gas",
  );
  const transport = normalizeConfigurationTransport(
    record.transport,
    "configuration response.transport",
  );
  const nexus = normalizeConfigurationNexus(record.nexus, "configuration response.nexus");
  return {
    publicKeyHex,
    logger,
    network,
    queue,
    confidentialGas,
    transport,
    nexus,
  };
}

function normalizeConfigurationLogger(value, context) {
  const record = ensureRecord(value ?? {}, context);
  return {
    level: requireNonEmptyString(record.level ?? "", `${context}.level`),
    filter: optionalString(record.filter ?? null, `${context}.filter`),
  };
}

function normalizeConfigurationNetwork(value, context) {
  const record = ensureRecord(value ?? {}, context);
  return {
    blockGossipSize: ToriiClient._normalizeUnsignedInteger(
      record.block_gossip_size,
      `${context}.block_gossip_size`,
    ),
    blockGossipPeriodMs: ToriiClient._normalizeUnsignedInteger(
      record.block_gossip_period_ms,
      `${context}.block_gossip_period_ms`,
    ),
    transactionGossipSize: ToriiClient._normalizeUnsignedInteger(
      record.transaction_gossip_size,
      `${context}.transaction_gossip_size`,
    ),
    transactionGossipPeriodMs: ToriiClient._normalizeUnsignedInteger(
      record.transaction_gossip_period_ms,
      `${context}.transaction_gossip_period_ms`,
    ),
  };
}

function normalizeConfigurationQueue(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  const record = ensureRecord(value, context);
  return {
    capacity: ToriiClient._normalizeUnsignedInteger(record.capacity, `${context}.capacity`, {
      allowZero: false,
    }),
  };
}

function normalizeConfigurationConfidentialGas(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  const record = ensureRecord(value, context);
  return {
    proofBase: ToriiClient._normalizeUnsignedInteger(
      record.proof_base,
      `${context}.proof_base`,
      { allowZero: true },
    ),
    perPublicInput: ToriiClient._normalizeUnsignedInteger(
      record.per_public_input,
      `${context}.per_public_input`,
      { allowZero: true },
    ),
    perProofByte: ToriiClient._normalizeUnsignedInteger(
      record.per_proof_byte,
      `${context}.per_proof_byte`,
      { allowZero: true },
    ),
    perNullifier: ToriiClient._normalizeUnsignedInteger(
      record.per_nullifier,
      `${context}.per_nullifier`,
      { allowZero: true },
    ),
    perCommitment: ToriiClient._normalizeUnsignedInteger(
      record.per_commitment,
      `${context}.per_commitment`,
      { allowZero: true },
    ),
  };
}

function normalizeConfigurationTransport(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  const record = ensureRecord(value, context);
  const noritoRpc = normalizeConfigurationTransportNoritoRpc(
    record.norito_rpc,
    `${context}.norito_rpc`,
  );
  return { noritoRpc };
}

function normalizeConfigurationTransportNoritoRpc(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  const record = ensureRecord(value, context);
  return {
    enabled: coerceBoolean(record.enabled ?? false, `${context}.enabled`),
    stage: requireNonEmptyString(record.stage ?? "", `${context}.stage`),
    requireMtls: coerceBoolean(
      record.require_mtls ?? false,
      `${context}.require_mtls`,
    ),
    canaryAllowlistSize: ToriiClient._normalizeUnsignedInteger(
      record.canary_allowlist_size ?? 0,
      `${context}.canary_allowlist_size`,
      { allowZero: true },
    ),
  };
}

function normalizeConfigurationNexus(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  const record = ensureRecord(value, context);
  const axt = normalizeConfigurationNexusAxt(record.axt, `${context}.axt`);
  return { axt };
}

function normalizeConfigurationNexusAxt(value, context) {
  const record = ensureRecord(value ?? {}, context);
  const slotLengthMs = ToriiClient._normalizeUnsignedInteger(
    record.slot_length_ms,
    `${context}.slot_length_ms`,
    { allowZero: false },
  );
  const maxClockSkewMs = ToriiClient._normalizeUnsignedInteger(
    record.max_clock_skew_ms ?? 0,
    `${context}.max_clock_skew_ms`,
    { allowZero: true },
  );
  const proofCacheTtlSlots = ToriiClient._normalizeUnsignedInteger(
    record.proof_cache_ttl_slots,
    `${context}.proof_cache_ttl_slots`,
    { allowZero: false },
  );
  const replayRetentionSlots = ToriiClient._normalizeUnsignedInteger(
    record.replay_retention_slots,
    `${context}.replay_retention_slots`,
    { allowZero: false },
  );
  return {
    slotLengthMs,
    maxClockSkewMs,
    proofCacheTtlSlots,
    replayRetentionSlots,
  };
}

function normalizeRuntimeAbiActiveResponse(payload) {
  const record = ensureRecord(payload, "runtime abi active response");
  return {
    abiVersion: ToriiClient._normalizeUnsignedInteger(
      record.abi_version,
      "runtime abi active response.abi_version",
      { allowZero: false },
    ),
  };
}

function normalizeRuntimeAbiHashResponse(payload) {
  const record = ensureRecord(payload, "runtime abi hash response");
  return {
    policy: requireNonEmptyString(record.policy, "runtime abi hash response.policy"),
    abiHashHex: requireHexString(record.abi_hash_hex ?? "", "runtime abi hash response.abi_hash_hex"),
  };
}

function normalizeRuntimeMetricsResponse(payload) {
  const record = ensureRecord(payload, "runtime metrics response");
  const counters = ensureRecord(
    record.upgrade_events_total ?? {},
    "runtime metrics response.upgrade_events_total",
  );
  return {
    abiVersion: ToriiClient._normalizeUnsignedInteger(
      record.abi_version,
      "runtime metrics response.abi_version",
      { allowZero: false },
    ),
    upgradeEventsTotal: {
      proposed: ToriiClient._normalizeUnsignedInteger(
        counters.proposed ?? 0,
        "runtime metrics response.upgrade_events_total.proposed",
        { allowZero: true },
      ),
      activated: ToriiClient._normalizeUnsignedInteger(
        counters.activated ?? 0,
        "runtime metrics response.upgrade_events_total.activated",
        { allowZero: true },
      ),
      canceled: ToriiClient._normalizeUnsignedInteger(
        counters.canceled ?? 0,
        "runtime metrics response.upgrade_events_total.canceled",
        { allowZero: true },
      ),
    },
  };
}

function normalizeExplorerMetricsResponse(payload) {
  const record = ensureRecord(payload ?? {}, "explorer metrics response");
  const avgCommit = normalizeExplorerDurationMs(
    record.avg_commit_time,
    "explorer metrics response.avg_commit_time",
  );
  const avgBlock = normalizeExplorerDurationMs(
    record.avg_block_time,
    "explorer metrics response.avg_block_time",
  );
  return {
    peers: ToriiClient._normalizeUnsignedInteger(record.peers ?? 0, "explorer metrics response.peers", {
      allowZero: true,
    }),
    domains: ToriiClient._normalizeUnsignedInteger(
      record.domains ?? 0,
      "explorer metrics response.domains",
      { allowZero: true },
    ),
    accounts: ToriiClient._normalizeUnsignedInteger(
      record.accounts ?? 0,
      "explorer metrics response.accounts",
      { allowZero: true },
    ),
    assets: ToriiClient._normalizeUnsignedInteger(
      record.assets ?? 0,
      "explorer metrics response.assets",
      { allowZero: true },
    ),
    transactionsAccepted: ToriiClient._normalizeUnsignedInteger(
      record.transactions_accepted ?? 0,
      "explorer metrics response.transactions_accepted",
      { allowZero: true },
    ),
    transactionsRejected: ToriiClient._normalizeUnsignedInteger(
      record.transactions_rejected ?? 0,
      "explorer metrics response.transactions_rejected",
      { allowZero: true },
    ),
    blockHeight: ToriiClient._normalizeUnsignedInteger(
      record.block ?? 0,
      "explorer metrics response.block",
      { allowZero: true },
    ),
    blockCreatedAt: optionalString(
      record.block_created_at ?? null,
      "explorer metrics response.block_created_at",
    ),
    finalizedBlockHeight: ToriiClient._normalizeUnsignedInteger(
      record.finalized_block ?? 0,
      "explorer metrics response.finalized_block",
      { allowZero: true },
    ),
    averageCommitTimeMs: avgCommit ?? null,
    averageBlockTimeMs: avgBlock ?? null,
  };
}

const EXPLORER_ACCOUNT_QR_OPTION_KEYS = new Set(["signal"]);
const VPN_SESSION_OPTION_KEYS = new Set(["signal", CANONICAL_AUTH_FIELD]);
const {
  VPN_HELPER_TICKET_BYTES,
  VPN_HELPER_TICKET_HEX_LENGTH,
  VPN_EXIT_CLASSES,
  VPN_SESSION_STATUSES,
  VPN_RECEIPT_STATUSES,
  VPN_RECEIPT_SOURCES,
  VPN_LEASE_SECONDS_MAX,
  VPN_QUOTE_CREATE_REQUEST_KEYS,
  VPN_SESSION_CREATE_REQUEST_KEYS,
  VPN_RECEIPT_SUBMIT_REQUEST_KEYS,
  VPN_TX_INSTRUCTION_RESPONSE_FIELDS,
  VPN_PROFILE_RESPONSE_FIELDS,
  VPN_QUOTE_RESPONSE_FIELDS,
  VPN_SESSION_RESPONSE_FIELDS,
  VPN_RECEIPT_RESPONSE_FIELDS,
  VPN_RECEIPT_LIST_RESPONSE_FIELDS,
  normalizeVpnTrustTuple,
  requireVpnRelayEndpoint,
  requireVpnEnum,
  requireVpnProfileExitClasses,
} = createVpnSchema({
  requireExactLowerHex32String,
  requireExactNonEmptyString,
});

function normalizeExplorerRequestOptions(options) {
  if (options === undefined) {
    return { signal: undefined };
  }
  const record = ensureRecord(options, "getExplorerAccountQr options");
  assertSupportedOptionKeys(
    record,
    EXPLORER_ACCOUNT_QR_OPTION_KEYS,
    "getExplorerAccountQr options",
  );
  const { signal } = normalizeSignalOption(record, "getExplorerAccountQr");
  return { signal };
}

function normalizeVpnProfileResponse(payload) {
  const record = ensureRecord(payload ?? {}, "vpn profile response");
  assertVpnResponseFields(record, VPN_PROFILE_RESPONSE_FIELDS, "vpn profile response");
  const available = coerceBoolean(record.available, "vpn profile response.available");
  const trust = normalizeVpnTrustTuple(record, "vpn profile response", {
    allowEmpty: !available,
  });
  return {
    available,
    relayEndpoint: requireVpnRelayEndpoint(
      record.relay_endpoint,
      "vpn profile response.relay_endpoint",
      { allowEmpty: !available },
    ),
    supportedExitClasses: requireVpnProfileExitClasses(
      record.supported_exit_classes,
      "vpn profile response.supported_exit_classes",
    ),
    defaultExitClass: requireVpnEnum(
      record.default_exit_class,
      VPN_EXIT_CLASSES,
      "vpn profile response.default_exit_class",
    ),
    leaseSecs: requireVpnUnsignedInteger(
      record.lease_secs,
      "vpn profile response.lease_secs",
      { min: 1, max: VPN_LEASE_SECONDS_MAX },
    ),
    dnsPushIntervalSecs: requireVpnUnsignedInteger(
      record.dns_push_interval_secs,
      "vpn profile response.dns_push_interval_secs",
      { min: 30 },
    ),
    meterFamily: requireNonEmptyString(
      record.meter_family,
      "vpn profile response.meter_family",
    ),
    routePushes: requireStringArray(
      record.route_pushes,
      "vpn profile response.route_pushes",
    ),
    excludedRoutes: requireStringArray(
      record.excluded_routes,
      "vpn profile response.excluded_routes",
    ),
    dnsServers: requireStringArray(
      record.dns_servers,
      "vpn profile response.dns_servers",
    ),
    tunnelAddresses: requireStringArray(
      record.tunnel_addresses,
      "vpn profile response.tunnel_addresses",
    ),
    mtuBytes: requireVpnNumericConstant(
      record.mtu_bytes,
      "vpn profile response.mtu_bytes",
      1280,
    ),
    displayBillingLabel: requireNonEmptyString(
      record.display_billing_label,
      "vpn profile response.display_billing_label",
    ),
    operatorAccountId: requireNonEmptyString(
      record.operator_account_id,
      "vpn profile response.operator_account_id",
    ),
    leaseFee: requireCanonicalQuantity(
      record.lease_fee,
      "vpn profile response.lease_fee",
    ),
    settlementGraceSecs: requireVpnUnsignedInteger(
      record.settlement_grace_secs,
      "vpn profile response.settlement_grace_secs",
      { min: 1 },
    ),
    flowLabelBits: requireVpnNumericConstant(
      record.flow_label_bits,
      "vpn profile response.flow_label_bits",
      24,
    ),
    paddingBudgetMs: requireVpnUnsignedInteger(
      record.padding_budget_ms,
      "vpn profile response.padding_budget_ms",
      { min: 1, max: 65535 },
    ),
    ...trust,
  };
}

function requireVpnNumericConstant(value, context, expected) {
  const numeric = requireVpnUnsignedInteger(value, context);
  if (numeric !== expected) {
    throw createValidationError(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${context} must equal ${expected}`,
      context,
    );
  }
  return numeric;
}

function requireVpnUnsignedInteger(value, context, options = {}) {
  if (typeof value !== JS_TYPE_NUMBER) {
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${context} must be a JSON integer`,
      context,
    );
  }
  return ToriiClient._normalizeUnsignedInteger(value, context, options);
}

function normalizeVpnQuoteCreateRequest(input) {
  const record = ensureRecord(input, "createVpnQuote request");
  assertSupportedOptionKeys(record, VPN_QUOTE_CREATE_REQUEST_KEYS, "createVpnQuote request");
  const exitClassValue = record.exitClass ?? record.exit_class;
  const exitClass =
    exitClassValue === undefined
      ? ""
      : exitClassValue === ""
        ? ""
        : requireVpnEnum(
            exitClassValue,
            VPN_EXIT_CLASSES,
            "createVpnQuote request.exitClass",
          );
  return {
    exit_class: exitClass,
    metering_public_key_hex: normalizeHex32String(
      record.meteringPublicKeyHex ?? record.metering_public_key_hex,
      "createVpnQuote request.meteringPublicKeyHex",
    ),
  };
}

function normalizeVpnSessionCreateRequest(input) {
  const record = ensureRecord(input, "createVpnSession request");
  assertSupportedOptionKeys(
    record,
    VPN_SESSION_CREATE_REQUEST_KEYS,
    "createVpnSession request",
  );
  const exitClassValue = record.exitClass ?? record.exit_class;
  const exitClass =
    exitClassValue === undefined
      ? ""
      : exitClassValue === ""
        ? ""
        : requireVpnEnum(
            exitClassValue,
            VPN_EXIT_CLASSES,
            "createVpnSession request.exitClass",
          );
  return {
    exit_class: exitClass,
    quote_id: requireExactLowerHex32String(
      record.quoteId ?? record.quote_id,
      "createVpnSession request.quoteId",
    ),
    payment_tx_hash: requireCanonicalTransactionHashString(
      record.paymentTxHash ?? record.payment_tx_hash,
      "createVpnSession request.paymentTxHash",
    ),
    metering_public_key_hex: normalizeHex32String(
      record.meteringPublicKeyHex ?? record.metering_public_key_hex,
      "createVpnSession request.meteringPublicKeyHex",
    ),
  };
}

function normalizeVpnReceiptSubmitRequest(input) {
  const record = ensureRecord(input, "submitVpnReceipt request");
  assertSupportedOptionKeys(
    record,
    VPN_RECEIPT_SUBMIT_REQUEST_KEYS,
    "submitVpnReceipt request",
  );
  const payload = {
    relay_receipt_hex: normalizeArbitraryHex(
      record.relayReceiptHex ?? record.relay_receipt_hex,
      "submitVpnReceipt request.relayReceiptHex",
    ),
    client_voucher_hex: normalizeArbitraryHex(
      record.clientVoucherHex ?? record.client_voucher_hex,
      "submitVpnReceipt request.clientVoucherHex",
    ),
  };
  const leaseIdValue = record.leaseIdHex ?? record.lease_id_hex;
  if (leaseIdValue !== undefined && leaseIdValue !== null && leaseIdValue !== "") {
    payload.lease_id_hex = normalizeHex32String(
      leaseIdValue,
      "submitVpnReceipt request.leaseIdHex",
    );
  }
  return payload;
}

function normalizeVpnTxInstruction(payload, context) {
  const record = ensureRecord(payload, context);
  assertVpnResponseFields(record, VPN_TX_INSTRUCTION_RESPONSE_FIELDS, context);
  return {
    wireId: requireNonEmptyString(record.wire_id, `${context}.wire_id`),
    payloadHex: requireExactLowerEvenHexString(
      record.payload_hex,
      `${context}.payload_hex`,
    ),
  };
}

function normalizeVpnOptionalTxInstruction(payload, context) {
  if (payload === undefined || payload === null) {
    return null;
  }
  return normalizeVpnTxInstruction(payload, context);
}

function normalizeVpnQuoteResponse(payload, context = "vpn quote response") {
  const record = ensureRecord(payload ?? {}, context);
  assertVpnResponseFields(record, VPN_QUOTE_RESPONSE_FIELDS, context);
  const trust = normalizeVpnTrustTuple(record, context);
  return {
    quoteId: requireExactLowerHex32String(record.quote_id, `${context}.quote_id`),
    leaseIdHex: requireExactLowerHex32String(
      record.lease_id_hex,
      `${context}.lease_id_hex`,
    ),
    sessionIdHex: requireExactLowerHexBytesString(
      record.session_id_hex,
      `${context}.session_id_hex`,
      16,
    ),
    paymentReference: requireNonEmptyString(
      record.payment_reference ?? "",
      `${context}.payment_reference`,
    ),
    accountId: requireNonEmptyString(record.account_id ?? "", `${context}.account_id`),
    exitClass: requireVpnEnum(
      record.exit_class,
      VPN_EXIT_CLASSES,
      `${context}.exit_class`,
    ),
    relayEndpoint: requireVpnRelayEndpoint(
      record.relay_endpoint,
      `${context}.relay_endpoint`,
    ),
    leaseSecs: requireVpnUnsignedInteger(
      record.lease_secs,
      `${context}.lease_secs`,
      { min: 1, max: VPN_LEASE_SECONDS_MAX },
    ),
    quoteExpiresAtMs: requireVpnUnsignedInteger(
      record.quote_expires_at_ms,
      `${context}.quote_expires_at_ms`,
      { allowZero: true },
    ),
    feeAssetId: requireNonEmptyString(record.fee_asset_id, `${context}.fee_asset_id`),
    escrowAccountId: requireNonEmptyString(
      record.escrow_account_id,
      `${context}.escrow_account_id`,
    ),
    operatorAccountId: requireNonEmptyString(
      record.operator_account_id,
      `${context}.operator_account_id`,
    ),
    leaseFee: requireCanonicalQuantity(
      record.lease_fee,
      `${context}.lease_fee`,
    ),
    routePushes: requireStringArray(record.route_pushes, `${context}.route_pushes`),
    excludedRoutes: requireStringArray(
      record.excluded_routes,
      `${context}.excluded_routes`,
    ),
    dnsServers: requireStringArray(record.dns_servers, `${context}.dns_servers`),
    tunnelAddresses: requireStringArray(
      record.tunnel_addresses,
      `${context}.tunnel_addresses`,
    ),
    mtuBytes: requireVpnNumericConstant(
      record.mtu_bytes,
      `${context}.mtu_bytes`,
      1280,
    ),
    meterFamily: requireNonEmptyString(record.meter_family, `${context}.meter_family`),
    flowLabelBits: requireVpnNumericConstant(
      record.flow_label_bits,
      `${context}.flow_label_bits`,
      24,
    ),
    paddingBudgetMs: requireVpnUnsignedInteger(
      record.padding_budget_ms,
      `${context}.padding_budget_ms`,
      { min: 1, max: 65535 },
    ),
    ...trust,
    meteringPublicKeyHex: requireExactLowerHex32String(
      record.metering_public_key_hex,
      `${context}.metering_public_key_hex`,
    ),
    openLeaseInstruction: normalizeVpnTxInstruction(
      record.open_lease_instruction,
      `${context}.open_lease_instruction`,
    ),
  };
}

function normalizeVpnSessionResponse(payload, context = "vpn session response") {
  const record = ensureRecord(payload ?? {}, context);
  assertVpnResponseFields(record, VPN_SESSION_RESPONSE_FIELDS, context);
  const trust = normalizeVpnTrustTuple(record, context);
  return {
    sessionId: requireExactLowerHexBytesString(
      record.session_id,
      `${context}.session_id`,
      16,
    ),
    accountId: requireNonEmptyString(record.account_id, `${context}.account_id`),
    exitClass: requireVpnEnum(
      record.exit_class,
      VPN_EXIT_CLASSES,
      `${context}.exit_class`,
    ),
    relayEndpoint: requireVpnRelayEndpoint(
      record.relay_endpoint,
      `${context}.relay_endpoint`,
    ),
    leaseSecs: requireVpnUnsignedInteger(
      record.lease_secs,
      `${context}.lease_secs`,
      { min: 1, max: VPN_LEASE_SECONDS_MAX },
    ),
    expiresAtMs: requireVpnUnsignedInteger(
      record.expires_at_ms,
      `${context}.expires_at_ms`,
      { allowZero: true },
    ),
    connectedAtMs: requireVpnUnsignedInteger(
      record.connected_at_ms,
      `${context}.connected_at_ms`,
      { allowZero: true },
    ),
    meterFamily: requireNonEmptyString(record.meter_family, `${context}.meter_family`),
    quoteId: requireExactLowerHex32String(record.quote_id, `${context}.quote_id`),
    paymentReference: requireNonEmptyString(
      record.payment_reference ?? "",
      `${context}.payment_reference`,
    ),
    paymentTxHash: requireCanonicalTransactionHashString(
      record.payment_tx_hash,
      `${context}.payment_tx_hash`,
    ),
    feeAssetId: requireNonEmptyString(record.fee_asset_id, `${context}.fee_asset_id`),
    escrowAccountId: requireNonEmptyString(
      record.escrow_account_id,
      `${context}.escrow_account_id`,
    ),
    operatorAccountId: requireNonEmptyString(
      record.operator_account_id,
      `${context}.operator_account_id`,
    ),
    leaseFee: requireCanonicalQuantity(
      record.lease_fee,
      `${context}.lease_fee`,
    ),
    flowLabelBits: requireVpnNumericConstant(
      record.flow_label_bits,
      `${context}.flow_label_bits`,
      24,
    ),
    paddingBudgetMs: requireVpnUnsignedInteger(
      record.padding_budget_ms,
      `${context}.padding_budget_ms`,
      { min: 1, max: 65535 },
    ),
    ...trust,
    routePushes: requireStringArray(record.route_pushes, `${context}.route_pushes`),
    excludedRoutes: requireStringArray(
      record.excluded_routes,
      `${context}.excluded_routes`,
    ),
    dnsServers: requireStringArray(record.dns_servers, `${context}.dns_servers`),
    tunnelAddresses: requireStringArray(
      record.tunnel_addresses,
      `${context}.tunnel_addresses`,
    ),
    mtuBytes: requireVpnNumericConstant(
      record.mtu_bytes,
      `${context}.mtu_bytes`,
      1280,
    ),
    helperTicketHex: requireVpnHelperTicketHex(
      record.helper_ticket_hex,
      `${context}.helper_ticket_hex`,
    ),
    bytesIn: requireVpnUnsignedInteger(
      record.bytes_in,
      `${context}.bytes_in`,
      { allowZero: true },
    ),
    bytesOut: requireVpnUnsignedInteger(
      record.bytes_out,
      `${context}.bytes_out`,
      { allowZero: true },
    ),
    status: requireVpnEnum(record.status, VPN_SESSION_STATUSES, `${context}.status`),
  };
}

function normalizeVpnReceiptResponse(payload, context = "vpn receipt response") {
  const record = ensureRecord(payload ?? {}, context);
  assertVpnResponseFields(record, VPN_RECEIPT_RESPONSE_FIELDS, context);
  return {
    sessionId: requireExactLowerHexBytesString(
      record.session_id,
      `${context}.session_id`,
      16,
    ),
    accountId: requireNonEmptyString(record.account_id, `${context}.account_id`),
    exitClass: requireVpnEnum(
      record.exit_class,
      VPN_EXIT_CLASSES,
      `${context}.exit_class`,
    ),
    relayEndpoint: requireNonEmptyString(
      record.relay_endpoint,
      `${context}.relay_endpoint`,
    ),
    meterFamily: requireNonEmptyString(record.meter_family, `${context}.meter_family`),
    connectedAtMs: requireVpnUnsignedInteger(
      record.connected_at_ms,
      `${context}.connected_at_ms`,
      { allowZero: true },
    ),
    disconnectedAtMs: requireVpnUnsignedInteger(
      record.disconnected_at_ms,
      `${context}.disconnected_at_ms`,
      { allowZero: true },
    ),
    durationMs: requireVpnUnsignedInteger(
      record.duration_ms,
      `${context}.duration_ms`,
      { allowZero: true },
    ),
    bytesIn: requireVpnUnsignedInteger(
      record.bytes_in,
      `${context}.bytes_in`,
      { allowZero: true },
    ),
    bytesOut: requireVpnUnsignedInteger(
      record.bytes_out,
      `${context}.bytes_out`,
      { allowZero: true },
    ),
    status: requireVpnEnum(record.status, VPN_RECEIPT_STATUSES, `${context}.status`),
    receiptSource: requireVpnEnum(
      record.receipt_source,
      VPN_RECEIPT_SOURCES,
      `${context}.receipt_source`,
    ),
    quoteId: requireExactLowerHex32String(record.quote_id, `${context}.quote_id`),
    paymentTxHash: requireCanonicalTransactionHashString(
      record.payment_tx_hash,
      `${context}.payment_tx_hash`,
    ),
    feeAssetId: requireNonEmptyString(record.fee_asset_id, `${context}.fee_asset_id`),
    escrowAccountId: requireNonEmptyString(
      record.escrow_account_id,
      `${context}.escrow_account_id`,
    ),
    operatorAccountId: requireNonEmptyString(
      record.operator_account_id,
      `${context}.operator_account_id`,
    ),
    leaseFee: requireCanonicalQuantity(
      record.lease_fee,
      `${context}.lease_fee`,
    ),
    earnedFee: requireCanonicalQuantity(
      record.earned_fee,
      `${context}.earned_fee`,
    ),
    refundedFee: requireCanonicalQuantity(
      record.refunded_fee,
      `${context}.refunded_fee`,
    ),
    leaseIdHex: requireExactLowerHex32String(
      record.lease_id_hex,
      `${context}.lease_id_hex`,
    ),
    settleLeaseInstruction: normalizeVpnOptionalTxInstruction(
      record.settle_lease_instruction,
      `${context}.settle_lease_instruction`,
    ),
  };
}

function normalizeVpnReceiptListResponse(payload) {
  const record = ensureRecord(payload ?? {}, "vpn receipts response");
  assertVpnResponseFields(
    record,
    VPN_RECEIPT_LIST_RESPONSE_FIELDS,
    "vpn receipts response",
  );
  if (!Array.isArray(record.items)) {
    rejectType("vpn receipts response.items must be an array");
  }
  if (record.items.length > 24) {
    throw createValidationError(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      "vpn receipts response.items must contain at most 24 receipts",
      "vpn.receipts.response.items",
    );
  }
  const total = requireVpnUnsignedInteger(record.total, "vpn receipts response.total", {
    allowZero: true,
    max: 24,
  });
  const items = record.items.map((item, index) =>
    normalizeVpnReceiptResponse(item, `vpn receipts response.items[${index}]`),
  );
  return { items, total };
}

function assertVpnResponseFields(record, requiredFields, context) {
  assertSupportedOptionKeys(record, requiredFields, context);
  const missing = [...requiredFields].filter(
    (field) => !Object.prototype.hasOwnProperty.call(record, field),
  );
  if (missing.length > 0) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} is missing required fields: ${missing.join(", ")}`,
      context.replace(/\s+/gu, "."),
    );
  }
}

function normalizeVpnSessionOptions(
  options, context, supportedKeys = VPN_SESSION_OPTION_KEYS,
  normalizeCanonicalAuth = ToriiClient._normalizeCanonicalAuth,
) {
  if (options === undefined) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} options.canonicalAuth is required`,
      `${context}.canonicalAuth`,
    );
  }
  const record = ensureRecord(options, `${context} options`);
  assertSupportedOptionKeys(record, supportedKeys, `${context} options`);
  const { signal } = normalizeSignalOption(record, context);
  const canonicalAuth = normalizeCanonicalAuth(
    record.canonicalAuth,
    `${context}.canonicalAuth`,
  );
  if (!canonicalAuth) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} options.canonicalAuth is required`,
      `${context}.canonicalAuth`,
    );
  }
  return { signal, canonicalAuth };
}

function normalizeSnsSuffixPolicy(payload) {
  const record = ensureRecord(payload ?? {}, "sns suffix policy");
  const suffixId = ToriiClient._normalizeUnsignedInteger(record.suffix_id, "sns suffix policy.suffix_id", {
    allowZero: true,
  });
  const suffix = requireNonEmptyString(record.suffix, "sns suffix policy.suffix").toLowerCase();
  const steward = ToriiClient._normalizeAccountId(record.steward, "sns suffix policy.steward");
  const statusRaw = requireNonEmptyString(record.status, "sns suffix policy.status");
  if (!SNS_SUFFIX_STATUS_VALUES.has(statusRaw)) {
    rejectType(`sns suffix policy.status must be one of ${Array.from(SNS_SUFFIX_STATUS_VALUES).join(", ")}`);
  }
  const minTermYears = ToriiClient._normalizeUnsignedInteger(record.min_term_years, "sns suffix policy.min_term_years");
  const maxTermYears = ToriiClient._normalizeUnsignedInteger(record.max_term_years, "sns suffix policy.max_term_years");
  const graceDays = ToriiClient._normalizeUnsignedInteger(record.grace_period_days, "sns suffix policy.grace_period_days", {
    allowZero: true,
  });
  const redemptionDays = ToriiClient._normalizeUnsignedInteger(
    record.redemption_period_days,
    "sns suffix policy.redemption_period_days",
    { allowZero: true },
  );
  const referralCap = ToriiClient._normalizeUnsignedInteger(
    record.referral_cap_bps,
    "sns suffix policy.referral_cap_bps",
    { allowZero: true },
  );
  const reservedLabels = Array.isArray(record.reserved_labels)
    ? record.reserved_labels.map((entry, index) => normalizeReservedLabel(entry, `sns suffix policy.reserved_labels[${index}]`))
    : [];
  const paymentAssetId = requireNonEmptyString(record.payment_asset_id, "sns suffix policy.payment_asset_id");
  const pricing = Array.isArray(record.pricing)
    ? record.pricing.map((entry, index) => normalizeSnsPricingTier(entry, `sns suffix policy.pricing[${index}]`))
    : [];
  const feeSplit = normalizeSnsFeeSplit(record.fee_split, "sns suffix policy.fee_split");
  const fundSplitter = ToriiClient._normalizeAccountId(
    record.fund_splitter_account,
    "sns suffix policy.fund_splitter_account",
  );
  const policyVersion = ToriiClient._normalizeUnsignedInteger(
    record.policy_version,
    "sns suffix policy.policy_version",
    { allowZero: true },
  );
  const metadata = normalizeOptionalMetadata(record.metadata, "sns suffix policy.metadata");
  return {
    suffixId,
    suffix,
    steward,
    status: statusRaw,
    minTermYears,
    maxTermYears,
    gracePeriodDays: graceDays,
    redemptionPeriodDays: redemptionDays,
    referralCapBps: referralCap,
    reservedLabels,
    paymentAssetId,
    pricing,
    feeSplit,
    fundSplitterAccount: fundSplitter,
    policyVersion,
    metadata,
  };
}

function normalizeReservedLabel(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const normalizedLabel = requireNonEmptyString(record.normalized_label, `${context}.normalized_label`).toLowerCase();
  const assignedTo =
    record.assigned_to === undefined || record.assigned_to === null
      ? null
      : ToriiClient._normalizeAccountId(record.assigned_to, `${context}.assigned_to`);
  const releaseAtMs =
    record.release_at_ms === undefined || record.release_at_ms === null
      ? null
      : ToriiClient._normalizeUnsignedInteger(record.release_at_ms, `${context}.release_at_ms`, { allowZero: true });
  const note = requireNonEmptyString(record.note ?? "", `${context}.note`);
  return {
    normalizedLabel,
    assignedTo,
    releaseAtMs,
    note,
  };
}

function normalizeSnsTokenValue(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const assetId = ToriiClient._normalizeAssetId(record.asset_id, `${context}.asset_id`);
  const amount = requireCanonicalQuantity(record.amount, `${context}.amount`);
  return { assetId, amount };
}

function normalizeSnsPricingTier(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const tierId = ToriiClient._normalizeUnsignedInteger(record.tier_id, `${context}.tier_id`, { allowZero: true });
  const regex = requireNonEmptyString(record.label_regex, `${context}.label_regex`);
  const basePrice = normalizeSnsTokenValue(record.base_price, `${context}.base_price`);
  const auctionKindRaw = requireNonEmptyString(record.auction_kind, `${context}.auction_kind`);
  if (!SNS_AUCTION_KIND_VALUES.has(auctionKindRaw)) {
    rejectType(`${context}.auction_kind must be one of ${Array.from(SNS_AUCTION_KIND_VALUES).join(", ")}`);
  }
  const dutchFloor =
    record.dutch_floor === undefined || record.dutch_floor === null
      ? null
      : normalizeSnsTokenValue(record.dutch_floor, `${context}.dutch_floor`);
  const minDurationYears = ToriiClient._normalizeUnsignedInteger(
    record.min_duration_years,
    `${context}.min_duration_years`,
    { allowZero: true },
  );
  const maxDurationYears = ToriiClient._normalizeUnsignedInteger(
    record.max_duration_years,
    `${context}.max_duration_years`,
    { allowZero: true },
  );
  return {
    tierId,
    labelRegex: regex,
    basePrice,
    auctionKind: auctionKindRaw,
    dutchFloor,
    minDurationYears,
    maxDurationYears,
  };
}

function normalizeSnsFeeSplit(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    treasuryBps: ToriiClient._normalizeUnsignedInteger(record.treasury_bps, `${context}.treasury_bps`, {
      allowZero: true,
    }),
    stewardBps: ToriiClient._normalizeUnsignedInteger(record.steward_bps, `${context}.steward_bps`, {
      allowZero: true,
    }),
    referralMaxBps: ToriiClient._normalizeUnsignedInteger(
      record.referral_max_bps,
      `${context}.referral_max_bps`,
      { allowZero: true },
    ),
    escrowBps: ToriiClient._normalizeUnsignedInteger(record.escrow_bps, `${context}.escrow_bps`, { allowZero: true }),
  };
}

function normalizeSnsSelector(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const version = ToriiClient._normalizeUnsignedInteger(record.version ?? 1, `${context}.version`, { allowZero: true });
  const suffixId = ToriiClient._normalizeUnsignedInteger(record.suffix_id, `${context}.suffix_id`, { allowZero: true });
  const label = requireNonEmptyString(record.label, `${context}.label`);
  return {
    version,
    suffix_id: suffixId,
    label,
  };
}

function normalizeSnsControllers(value, context) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array of controllers`);
  }
  return value.map((entry, index) => normalizeSnsController(entry, `${context}[${index}]`));
}

function normalizeSnsController(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const kind = requireNonEmptyString(record.controller_type, `${context}.controller_type`);
  if (!SNS_CONTROLLER_TYPES.has(kind)) {
    rejectType(`${context}.controller_type must be one of ${Array.from(SNS_CONTROLLER_TYPES).join(", ")}`);
  }
  const accountAddress =
    record.account_address === undefined || record.account_address === null
      ? null
      : requireNonEmptyString(record.account_address, `${context}.account_address`);
  const resolverTemplateId =
    record.resolver_template_id === undefined || record.resolver_template_id === null
      ? null
      : requireNonEmptyString(record.resolver_template_id, `${context}.resolver_template_id`);
  const payloadMetadata = normalizeOptionalMetadata(record.payload, `${context}.payload`);
  return {
    controller_type: kind,
    account_address: accountAddress ?? undefined,
    resolver_template_id: resolverTemplateId ?? undefined,
    payload: payloadMetadata,
  };
}

function normalizeSnsNameRecord(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const selector = normalizeSnsSelector(record.selector, `${context}.selector`);
  const nameHash = normalizeHex32String(record.name_hash, `${context}.name_hash`);
  const owner = ToriiClient._normalizeAccountId(record.owner, `${context}.owner`);
  const controllers = normalizeSnsControllers(record.controllers, `${context}.controllers`);
  const status = normalizeSnsNameStatus(record.status, `${context}.status`);
  const pricingClass = ToriiClient._normalizeUnsignedInteger(
    record.pricing_class,
    `${context}.pricing_class`,
    { allowZero: true },
  );
  const registeredAtMs = ToriiClient._normalizeUnsignedInteger(record.registered_at_ms, `${context}.registered_at_ms`, {
    allowZero: true,
  });
  const expiresAtMs = ToriiClient._normalizeUnsignedInteger(record.expires_at_ms, `${context}.expires_at_ms`, {
    allowZero: true,
  });
  const graceExpiresAtMs = ToriiClient._normalizeUnsignedInteger(
    record.grace_expires_at_ms,
    `${context}.grace_expires_at_ms`,
    { allowZero: true },
  );
  const redemptionExpiresAtMs = ToriiClient._normalizeUnsignedInteger(
    record.redemption_expires_at_ms,
    `${context}.redemption_expires_at_ms`,
    { allowZero: true },
  );
  const metadata = normalizeOptionalMetadata(record.metadata, `${context}.metadata`);
  const auction =
    record.auction === undefined || record.auction === null
      ? null
      : normalizeSnsAuction(record.auction, `${context}.auction`);
  return {
    selector,
    nameHash,
    owner,
    controllers,
    status,
    pricingClass,
    registeredAtMs,
    expiresAtMs,
    graceExpiresAtMs,
    redemptionExpiresAtMs,
    metadata,
    auction,
  };
}

function normalizeSnsAuction(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const kindRaw = requireNonEmptyString(record.kind, `${context}.kind`);
  if (!SNS_AUCTION_KIND_VALUES.has(kindRaw)) {
    rejectType(`${context}.kind must be one of ${Array.from(SNS_AUCTION_KIND_VALUES).join(", ")}`);
  }
  const openedAtMs = ToriiClient._normalizeUnsignedInteger(record.opened_at_ms, `${context}.opened_at_ms`, {
    allowZero: true,
  });
  const closesAtMs = ToriiClient._normalizeUnsignedInteger(record.closes_at_ms, `${context}.closes_at_ms`, {
    allowZero: true,
  });
  const floorPrice = normalizeSnsTokenValue(record.floor_price, `${context}.floor_price`);
  const highestCommitment =
    record.highest_commitment === undefined || record.highest_commitment === null
      ? null
      : normalizeHex32String(record.highest_commitment, `${context}.highest_commitment`);
  const settlementTx =
    record.settlement_tx === undefined || record.settlement_tx === null
      ? null
      : record.settlement_tx;
  return {
    kind: kindRaw,
    openedAtMs,
    closesAtMs,
    floorPrice,
    highestCommitment,
    settlementTx,
  };
}

function normalizeSnsNameStatus(payload, context) {
  if (typeof payload === JS_TYPE_STRING) {
    if (!SNS_NAME_STATUS_VALUES.has(payload)) {
      rejectType(`${context} must be one of ${Array.from(SNS_NAME_STATUS_VALUES).join(", ")}`);
    }
    return { status: payload };
  }
  const record = ensureRecord(payload ?? {}, context);
  const status = requireNonEmptyString(record.status ?? "", `${context}.status`);
  if (!SNS_NAME_STATUS_VALUES.has(status)) {
    rejectType(`${context}.status must be one of ${Array.from(SNS_NAME_STATUS_VALUES).join(", ")}`);
  }
  if (status === "Frozen") {
    const frozen = ensureRecord(record.detail ?? record, `${context}.frozen`);
    return {
      status,
      reason: requireNonEmptyString(
        frozen.reason,
        `${context}.frozen.reason`,
      ),
      untilMs: ToriiClient._normalizeUnsignedInteger(
        frozen.until_ms ?? frozen.untilMs,
        `${context}.frozen.until_ms`,
        {
        allowZero: true,
      },
      ),
    };
  }
  if (status === "Tombstoned") {
    const tombstone = ensureRecord(record.detail ?? record, `${context}.tombstone`);
    return {
      status,
      reason: requireNonEmptyString(tombstone.reason, `${context}.tombstone.reason`),
    };
  }
  return { status };
}

function normalizeExplorerRwaRecord(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const id = requireNonEmptyString(record.id ?? "", `${context}.id`);
  const ownedBy = requireNonEmptyString(record.owned_by ?? "", `${context}.owned_by`);
  const quantity = requireCanonicalQuantity(record.quantity, `${context}.quantity`);
  const heldQuantity = requireCanonicalQuantity(
    record.held_quantity ?? "",
    `${context}.held_quantity`,
  );
  const primaryReference = requireNonEmptyString(
    record.primary_reference ?? "",
    `${context}.primary_reference`,
  );
  if (typeof record.is_frozen !== "boolean") {
    rejectType(`${context}.is_frozen must be a boolean`);
  }
  let status = null;
  if (record.status !== undefined && record.status !== null) {
    status = requireNonEmptyString(record.status, `${context}.status`);
  }
  const metadata =
    record.metadata === undefined || record.metadata === null
      ? {}
      : cloneJsonValue(record.metadata, `${context}.metadata`);
  return {
    id,
    ownedBy,
    quantity,
    heldQuantity,
    primaryReference,
    status,
    isFrozen: record.is_frozen,
    metadata,
    raw: cloneJsonValue(record, `${context}.raw`),
  };
}

function normalizeExplorerAccountQrResponse(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const canonicalId = requireNonEmptyString(
    record.canonical_id ?? "",
    `${context}.canonical_id`,
  );
  const literal = requireNonEmptyString(record.literal ?? "", `${context}.literal`);
  const networkPrefix = ToriiClient._normalizeUnsignedInteger(
    record.network_prefix ?? 0,
    `${context}.network_prefix`,
    { allowZero: false },
  );
  const errorCorrection = requireNonEmptyString(
    record.error_correction ?? "",
    `${context}.error_correction`,
  );
  const modules = ToriiClient._normalizeUnsignedInteger(
    record.modules ?? 0,
    `${context}.modules`,
    { allowZero: false },
  );
  const qrVersion = ToriiClient._normalizeUnsignedInteger(
    record.qr_version ?? 0,
    `${context}.qr_version`,
    { allowZero: false },
  );
  const svg = requireNonEmptyString(record.svg ?? "", `${context}.svg`);
  return {
    canonicalId,
    literal,
    networkPrefix,
    errorCorrection,
    modules,
    qrVersion,
    svg,
  };
}

function normalizeExplorerBlockRecord(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const prevBlockHashRaw = record.prev_block_hash ?? null;
  const transactionsHashRaw = record.transactions_hash ?? null;
  return {
    hash: requireHexString(record.hash ?? "", `${context}.hash`),
    height: ToriiClient._normalizeUnsignedInteger(record.height ?? 1, `${context}.height`, {
      allowZero: false,
    }),
    createdAt: requireNonEmptyString(
      record.created_at ?? "",
      `${context}.created_at`,
    ),
    prevBlockHash:
      prevBlockHashRaw === null || prevBlockHashRaw === undefined
        ? null
        : requireHexString(prevBlockHashRaw, `${context}.prev_block_hash`),
    transactionsHash:
      transactionsHashRaw === null || transactionsHashRaw === undefined
        ? null
        : requireHexString(transactionsHashRaw, `${context}.transactions_hash`),
    transactionsRejected: ToriiClient._normalizeUnsignedInteger(
      record.transactions_rejected ?? 0,
      `${context}.transactions_rejected`,
      { allowZero: true },
    ),
    transactionsTotal: ToriiClient._normalizeUnsignedInteger(
      record.transactions_total ?? 0,
      `${context}.transactions_total`,
      { allowZero: true },
    ),
  };
}

function normalizeRuntimeUpgradesListResponse(payload) {
  const record = ensureRecord(payload, "runtime upgrades list response");
  const items = record.items ?? [];
  if (!Array.isArray(items)) {
    rejectType("runtime upgrades list response.items must be an array");
  }
  return items.map((item, index) =>
    normalizeRuntimeUpgradeListItem(item, index, "runtime upgrades list response.items"),
  );
}

function normalizeRuntimeUpgradeListItem(value, index, context) {
  const record = ensureRecord(value, `${context}[${index}]`);
  const idHex = requireHexString(record.id_hex ?? "", `${context}[${index}].id_hex`);
  const normalizedRecord = normalizeRuntimeUpgradeRecord(
    record.record,
    `${context}[${index}].record`,
  );
  return { idHex, record: normalizedRecord };
}

function normalizeRuntimeUpgradeRecord(value, context) {
  const record = ensureRecord(value, context);
  return {
    manifest: normalizeRuntimeUpgradeManifest(record.manifest, `${context}.manifest`),
    status: normalizeRuntimeUpgradeStatus(record.status, `${context}.status`),
    proposer: requireNonEmptyString(record.proposer, `${context}.proposer`),
    createdHeight: ToriiClient._normalizeUnsignedInteger(
      record.created_height,
      `${context}.created_height`,
      { allowZero: true },
    ),
  };
}

function normalizeRuntimeUpgradeManifest(value, context) {
  const record = ensureRecord(value, context);
  const abiVersion = ToriiClient._normalizeUnsignedInteger(
    record.abi_version,
    `${context}.abi_version`,
    { allowZero: false },
  );
  const addedSyscalls = parseIntegerArray(
    record.added_syscalls,
    `${context}.added_syscalls`,
  );
  const addedPointerTypes = parseIntegerArray(
    record.added_pointer_types,
    `${context}.added_pointer_types`,
  );
  assertFirstReleaseRuntimeUpgradeManifest({
    abiVersion,
    addedSyscalls,
    addedPointerTypes,
    context,
  });
  return {
    name: requireNonEmptyString(record.name, `${context}.name`),
    description: requireNonEmptyString(record.description, `${context}.description`),
    abiVersion,
    abiHashHex: requireHexString(
      record.abi_hash ?? "",
      `${context}.abi_hash`,
    ),
    addedSyscalls,
    addedPointerTypes,
    startHeight: ToriiClient._normalizeUnsignedInteger(
      record.start_height,
      `${context}.start_height`,
      { allowZero: true },
    ),
    endHeight: ToriiClient._normalizeUnsignedInteger(
      record.end_height,
      `${context}.end_height`,
      { allowZero: true },
    ),
  };
}

function normalizeRuntimeUpgradeStatus(value, context) {
  const record = ensureRecord(value, context);
  const keys = Object.keys(record);
  if (keys.length !== 1) {
    rejectType(`${context} must contain exactly one status key`);
  }
  const kind = keys[0];
  const payload = record[kind];
  if (kind === "Proposed" || kind === "Canceled") {
    return { kind };
  }
  if (kind === "ActivatedAt") {
    const height = ToriiClient._normalizeUnsignedInteger(
      payload,
      `${context}.ActivatedAt`,
      { allowZero: true },
    );
    return { kind: "ActivatedAt", activatedHeight: height };
  }
  rejectType(`${context} contains unsupported variant ${kind}`);
}

function normalizeRuntimeUpgradeManifestPayload(value, context) {
  const record = ensureRecord(value, context);
  const abiVersion = record.abi_version ?? record.abiVersion;
  const abiHashValue =
    record.abi_hash ?? record.abiHash ?? record.abiHashHex;
  const startValue = record.start_height ?? record.startHeight;
  const endValue = record.end_height ?? record.endHeight;
  if (abiVersion === undefined || abiVersion === null) {
    rejectType(`${context}.abi_version is required`);
  }
  if (abiHashValue === undefined || abiHashValue === null) {
    rejectType(`${context}.abi_hash is required`);
  }
  const startHeight = ToriiClient._normalizeUnsignedInteger(
    startValue,
    `${context}.start_height`,
    { allowZero: true },
  );
  const endHeight = ToriiClient._normalizeUnsignedInteger(
    endValue,
    `${context}.end_height`,
    { allowZero: true },
  );
  if (endHeight <= startHeight) {
    rejectType(`${context}.end_height must be greater than start_height`);
  }
  const normalizedAbiVersion = ToriiClient._normalizeUnsignedInteger(
    abiVersion,
    `${context}.abi_version`,
    { allowZero: false },
  );
  const addedSyscalls = parseIntegerArray(
    record.added_syscalls ?? record.addedSyscalls ?? [],
    `${context}.added_syscalls`,
  );
  const addedPointerTypes = parseIntegerArray(
    record.added_pointer_types ?? record.addedPointerTypes ?? [],
    `${context}.added_pointer_types`,
  );
  assertFirstReleaseRuntimeUpgradeManifest({
    abiVersion: normalizedAbiVersion,
    addedSyscalls,
    addedPointerTypes,
    context,
  });
  return {
    name: requireNonEmptyString(record.name, `${context}.name`),
    description: requireNonEmptyString(
      record.description,
      `${context}.description`,
    ),
    abi_version: normalizedAbiVersion,
    abi_hash: normalizeHex32String(abiHashValue, `${context}.abi_hash`),
    added_syscalls: addedSyscalls,
    added_pointer_types: addedPointerTypes,
    start_height: startHeight,
    end_height: endHeight,
  };
}

function assertFirstReleaseRuntimeUpgradeManifest({
  abiVersion,
  addedSyscalls,
  addedPointerTypes,
  context,
}) {
  if (abiVersion !== 1) {
    rejectType(`${context}.abi_version must be 1 in the first release`);
  }
  if (addedSyscalls.length > 0) {
    rejectType(`${context}.added_syscalls must be empty in the first release`);
  }
  if (addedPointerTypes.length > 0) {
    rejectType(`${context}.added_pointer_types must be empty in the first release`);
  }
}

function normalizeRuntimeUpgradeTxResponse(payload, context) {
  const base = normalizeGovernanceDraftResponse(payload, context);
  return {
    ok: base.ok,
    tx_instructions: base.tx_instructions,
  };
}

function parseIntegerArray(value, context) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  return value.map((entry, index) => {
    const numeric = coerceIntegerLike(entry, `${context}[${index}]`);
    if (numeric < 0) {
      rejectRange(`${context}[${index}] must be non-negative`);
    }
    return numeric;
  });
}

function coerceStatusInt(value, context) {
  if (value === undefined || value === null) {
    return 0;
  }
  const numeric = coerceIntegerLike(value, context);
  if (numeric < 0) {
    rejectRange(`${context} must be non-negative`);
  }
  return numeric;
}

function coerceNestedInt(mapping, key, context) {
  if (!isPlainObject(mapping)) {
    rejectType(`${context} must be an object`);
  }
  const value = mapping[key];
  if (value === undefined || value === null) {
    return 0;
  }
  const numeric = coerceIntegerLike(value, `${context}.${key}`);
  if (numeric < 0) {
    rejectRange(`${context}.${key} must be non-negative`);
  }
  return numeric;
}

function ensureRecord(value, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context} must be an object`);
  }
  return value;
}

function normalizeOptionalMetadata(value, context) {
  if (value === undefined || value === null) {
    return {};
  }
  if (!isPlainObject(value)) {
    rejectType(`${context} must be a plain object when provided`);
  }
  return { ...value };
}

function coerceInteger(value, context) {
  if (value === undefined || value === null || value === "") {
    rejectType(`${context} must be numeric`);
  }
  return coerceIntegerLike(value, context);
}

function coerceBoolean(value, context) {
  if (value === undefined || value === null || value === "") {
    return false;
  }
  if (typeof value === "boolean") {
    return value;
  }
  if (value === 1 || value === "1") {
    return true;
  }
  if (value === 0 || value === "0") {
    return false;
  }
  if (typeof value === JS_TYPE_STRING) {
    const lower = value.toLowerCase();
    if (lower === "true") {
      return true;
    }
    if (lower === "false") {
      return false;
    }
  }
  rejectType(`${context} must be boolean`);
}

function requireBooleanLike(value, context) {
  if (value === undefined || value === null || value === "") {
    rejectType(`${context} must be boolean`);
  }
  return coerceBoolean(value, context);
}

function coerceOptionalInt(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  return coerceIntegerLike(value, context);
}

function parseStringArray(value, context) {
  if (value == null) {
    return [];
  }
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array of strings`);
  }
  return value.map((entry, index) => {
    if (entry === undefined || entry === null || typeof entry !== JS_TYPE_STRING) {
      rejectType(`${context}[${index}] must be a string`);
    }
    return entry;
  });
}

function isPlainObject(value) {
  if (value === null || typeof value !== JS_TYPE_OBJECT || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function optionalString(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value === JS_TYPE_STRING) {
    return value;
  }
  rejectType(`${context} must be a string when present`);
}

function optionalBoolean(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  return coerceBoolean(value, context);
}

function requireStringArray(value, context) {
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  return value.map((entry, index) => {
    if (typeof entry !== JS_TYPE_STRING) {
      rejectType(`${context}[${index}] must be a string`);
    }
    return entry;
  });
}

function normalizeUaidLiteral(value, context = "uaid") {
  const literal = requireExactNonEmptyString(value, context);
  if (!/^uaid:[0-9a-f]{64}$/u.test(literal)) {
    rejectType(`${context} must be an exact canonical uaid:<64 lowercase hex> literal`);
  }
  if (!/[13579bdf]$/u.test(literal)) {
    rejectType(`${context} must have least significant bit set to 1`);
  }
  return literal;
}

function normalizeUaidPortfolioOptions(options, context = "getUaidPortfolio") {
  if (options === undefined) {
    return { signal: undefined, assetId: undefined };
  }
  const record = ensureRecord(options, `${context} options`);
  assertSupportedOptionKeys(record, new Set(["signal", "assetId"]), `${context} options`);
  const { signal } = normalizeSignalOption(record, context);
  let assetId;
  if (record.assetId !== undefined) {
    assetId = requireExactAssetHoldingId(record.assetId, `${context}.assetId`);
  }
  return { signal, assetId };
}

function requireExactUaidRecord(
  value,
  requiredFields,
  optionalFields,
  context,
) {
  const record = ensureRecord(value, context);
  const required = new Set(requiredFields);
  const allowed = new Set([...requiredFields, ...optionalFields]);
  const missing = [...required].filter(
    (field) => !Object.prototype.hasOwnProperty.call(record, field),
  );
  const unexpected = Reflect.ownKeys(record).filter(
    (field) => typeof field !== JS_TYPE_STRING || !allowed.has(field),
  );
  if (missing.length > 0 || unexpected.length > 0) {
    const details = [];
    if (missing.length > 0) details.push(`missing ${missing.join(", ")}`);
    if (unexpected.length > 0) {
      details.push(`unexpected ${unexpected.map(String).sort().join(", ")}`);
    }
    rejectType(`${context} must use the exact server fields (${details.join("; ")})`);
  }
  return record;
}

function requireExactEnumString(value, allowed, context) {
  const literal = requireExactNonEmptyString(value, context);
  if (!allowed.has(literal)) {
    rejectType(`${context} must be one of ${Array.from(allowed).join(", ")}`);
  }
  return literal;
}

function requireJsonNullableString(value, context) {
  if (value === null) return null;
  if (typeof value !== JS_TYPE_STRING) {
    rejectType(`${context} must be a string or null`);
  }
  return value;
}

function requireExactNullableUnsignedInteger(value, context) {
  return value === null
    ? null
    : requireExactJsonUnsignedInteger(value, context, { allowZero: true });
}

function requireExactAssetHoldingId(value, context) {
  const literal = requireExactNonEmptyString(value, context);
  const canonical = normalizeAssetHoldingId(literal, context);
  if (canonical !== literal) {
    rejectType(`${context} must be an exact canonical asset holding id`);
  }
  const parts = literal.split("#");
  if (parts.length === 3) {
    const match = /^dataspace:(0|[1-9][0-9]*)$/u.exec(parts[2]);
    if (match === null) {
      rejectType(`${context} must use a canonical dataspace scope`);
    }
  }
  return literal;
}

function requireExactAssetDefinitionId(value, context) {
  const literal = requireExactNonEmptyString(value, context);
  const canonical = normalizeAssetDefinitionId(literal, context);
  if (canonical !== literal) {
    rejectType(`${context} must be an exact canonical asset definition id`);
  }
  return literal;
}

function requireCanonicalUaidManifestName(value, context) {
  const name = requireExactNonEmptyString(value, context);
  if (
    Buffer.byteLength(name, "utf8") > 255 ||
    /[\p{Cc}\p{White_Space}@#$]/u.test(name) ||
    /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(name) ||
    name.normalize("NFC") !== name
  ) {
    rejectType(`${context} must be a canonical Iroha Name`);
  }
  return name;
}

function requireExactAccountArray(value, context) {
  return requireDenseArray(value, context).map((entry, index) =>
    requireExactAccountId(entry, `${context}[${index}]`),
  );
}

function normalizeUaidPortfolioResponse(payload, expectedUaid) {
  const record = requireExactUaidRecord(
    payload,
    ["uaid", "totals", "dataspaces"],
    [],
    "uaid portfolio response",
  );
  const uaid = normalizeUaidLiteral(record.uaid, "uaid portfolio response.uaid");
  if (expectedUaid !== undefined && uaid !== expectedUaid) {
    rejectType("uaid portfolio response.uaid does not match the requested UAID");
  }
  const totalsRecord = requireExactUaidRecord(
    record.totals,
    ["accounts", "positions"],
    [],
    "uaid portfolio response.totals",
  );
  const totals = {
    accounts: requireExactJsonUnsignedInteger(
      totalsRecord.accounts,
      "uaid portfolio response.totals.accounts",
      { allowZero: true },
    ),
    positions: requireExactJsonUnsignedInteger(
      totalsRecord.positions,
      "uaid portfolio response.totals.positions",
      { allowZero: true },
    ),
  };
  const dataspacesValue = requireDenseArray(
    record.dataspaces,
    "uaid portfolio response.dataspaces",
  );
  const dataspaces = dataspacesValue.map((entry, index) =>
    normalizeUaidPortfolioDataspace(
      entry,
      `uaid portfolio response.dataspaces[${index}]`,
    ),
  );
  const accounts = new Set();
  let positions = 0;
  for (const dataspace of dataspaces) {
    for (const account of dataspace.accounts) {
      accounts.add(account.account_id);
      positions += account.assets.length;
    }
  }
  if (accounts.size > 1) {
    rejectType("uaid portfolio response must contain at most one universal account");
  }
  if (totals.accounts !== accounts.size || totals.positions !== positions) {
    rejectType("uaid portfolio response.totals do not match the portfolio tree");
  }
  return { uaid, totals, dataspaces };
}

function normalizeUaidPortfolioDataspace(value, context) {
  const record = requireExactUaidRecord(
    value,
    ["dataspace_id", "dataspace_alias", "accounts"],
    [],
    context,
  );
  const dataspaceId = requireExactJsonUnsignedInteger(
    record.dataspace_id,
    `${context}.dataspace_id`,
    { allowZero: true },
  );
  const accountsValue = requireDenseArray(record.accounts, `${context}.accounts`);
  return {
    dataspace_id: dataspaceId,
    dataspace_alias: requireJsonNullableString(
      record.dataspace_alias,
      `${context}.dataspace_alias`,
    ),
    accounts: accountsValue.map((entry, index) =>
      normalizeUaidPortfolioAccount(
        entry,
        dataspaceId,
        `${context}.accounts[${index}]`,
      ),
    ),
  };
}

function normalizeUaidPortfolioAccount(value, dataspaceId, context) {
  const record = requireExactUaidRecord(
    value,
    ["account_id", "label", "assets"],
    [],
    context,
  );
  const accountId = requireExactAccountId(record.account_id, `${context}.account_id`);
  const assetsValue = requireDenseArray(record.assets, `${context}.assets`);
  return {
    account_id: accountId,
    label: requireJsonNullableString(record.label, `${context}.label`),
    assets: assetsValue.map((entry, index) =>
      normalizeUaidPortfolioAsset(
        entry,
        accountId,
        dataspaceId,
        `${context}.assets[${index}]`,
      ),
    ),
  };
}

function normalizeUaidPortfolioAsset(value, accountId, dataspaceId, context) {
  const record = requireExactUaidRecord(
    value,
    ["asset_id", "asset_definition_id", "quantity"],
    [],
    context,
  );
  const assetId = requireExactAssetHoldingId(record.asset_id, `${context}.asset_id`);
  const assetDefinitionId = requireExactAssetDefinitionId(
    record.asset_definition_id,
    `${context}.asset_definition_id`,
  );
  const [holdingDefinitionId, holdingAccountId, scope] = assetId.split("#");
  if (holdingDefinitionId !== assetDefinitionId || holdingAccountId !== accountId) {
    rejectType(`${context}.asset_id does not match its account and definition`);
  }
  if (scope !== undefined) {
    const scopeId = BigInt(scope.slice("dataspace:".length));
    if (scopeId !== BigInt(dataspaceId)) {
      rejectType(`${context}.asset_id dataspace scope does not match its row`);
    }
  }
  return {
    asset_id: assetId,
    asset_definition_id: assetDefinitionId,
    quantity: requireCanonicalQuantity(record.quantity, `${context}.quantity`),
  };
}

function normalizeUaidBindingsResponse(payload, expectedUaid) {
  const record = requireExactUaidRecord(
    payload,
    ["uaid", "dataspaces"],
    [],
    "uaid bindings response",
  );
  const uaid = normalizeUaidLiteral(record.uaid, "uaid bindings response.uaid");
  if (expectedUaid !== undefined && uaid !== expectedUaid) {
    rejectType("uaid bindings response.uaid does not match the requested UAID");
  }
  const dataspacesValue = requireDenseArray(
    record.dataspaces,
    "uaid bindings response.dataspaces",
  );
  const dataspaces = dataspacesValue.map((entry, index) =>
    normalizeUaidBindingsDataspace(
      entry,
      `uaid bindings response.dataspaces[${index}]`,
    ),
  );
  const uniqueAccounts = new Set(dataspaces.flatMap((entry) => entry.accounts));
  if (uniqueAccounts.size > 1) {
    rejectType("uaid bindings response must contain at most one universal account");
  }
  return { uaid, dataspaces };
}

function normalizeUaidBindingsDataspace(value, context) {
  const record = requireExactUaidRecord(
    value,
    ["dataspace_id", "dataspace_alias", "accounts"],
    [],
    context,
  );
  const accounts = requireExactAccountArray(record.accounts, `${context}.accounts`);
  if (accounts.length > 1) {
    rejectType(`${context}.accounts must contain at most one universal account`);
  }
  return {
    dataspace_id: requireExactJsonUnsignedInteger(
      record.dataspace_id,
      `${context}.dataspace_id`,
      { allowZero: true },
    ),
    dataspace_alias: requireJsonNullableString(
      record.dataspace_alias,
      `${context}.dataspace_alias`,
    ),
    accounts,
  };
}

function normalizeUaidManifestRecord(value, expectedUaid, context) {
  const record = requireExactUaidRecord(
    value,
    [
      "dataspace_id",
      "dataspace_alias",
      "manifest_hash",
      "status",
      "lifecycle",
      "accounts",
      "manifest",
    ],
    [],
    context,
  );
  const status = requireExactEnumString(
    record.status,
    UAID_MANIFEST_STATUS_VALUES,
    `${context}.status`,
  );
  const dataspaceId = requireExactJsonUnsignedInteger(
    record.dataspace_id,
    `${context}.dataspace_id`,
    { allowZero: true },
  );
  const lifecycle = normalizeUaidManifestLifecycle(
    record.lifecycle,
    `${context}.lifecycle`,
  );
  const derivedStatus = lifecycle.revocation !== null
    ? "Revoked"
    : lifecycle.expired_epoch !== null
      ? "Expired"
      : lifecycle.activated_epoch !== null
        ? "Active"
        : "Pending";
  if (status !== derivedStatus) {
    rejectType(`${context}.status does not match its lifecycle`);
  }
  const accounts = requireExactAccountArray(record.accounts, `${context}.accounts`);
  if (accounts.length > 1) {
    rejectType(`${context}.accounts must contain at most one universal account`);
  }
  const manifest = normalizeUaidManifest(record.manifest, `${context}.manifest`);
  if (manifest.uaid !== expectedUaid || manifest.dataspace !== dataspaceId) {
    rejectType(`${context}.manifest identity does not match its row`);
  }
  return {
    dataspace_id: dataspaceId,
    dataspace_alias: requireJsonNullableString(
      record.dataspace_alias,
      `${context}.dataspace_alias`,
    ),
    manifest_hash: requireExactLowerHex32String(
      record.manifest_hash,
      `${context}.manifest_hash`,
    ),
    status,
    lifecycle,
    accounts,
    manifest,
  };
}

function normalizeUaidManifestLifecycle(value, context) {
  const record = requireExactUaidRecord(
    value,
    ["activated_epoch", "expired_epoch", "revocation"],
    [],
    context,
  );
  const activated = requireExactNullableUnsignedInteger(
    record.activated_epoch,
    `${context}.activated_epoch`,
  );
  const expired = requireExactNullableUnsignedInteger(
    record.expired_epoch,
    `${context}.expired_epoch`,
  );
  const revocationValue = record.revocation;
  let revocation = null;
  if (revocationValue !== null) {
    const rev = requireExactUaidRecord(
      revocationValue,
      ["epoch", "reason"],
      [],
      `${context}.revocation`,
    );
    revocation = {
      epoch: requireExactJsonUnsignedInteger(
        rev.epoch,
        `${context}.revocation.epoch`,
        { allowZero: true },
      ),
      reason: requireJsonNullableString(
        rev.reason,
        `${context}.revocation.reason`,
      ),
    };
  }
  return {
    activated_epoch: activated,
    expired_epoch: expired,
    revocation,
  };
}

function normalizeUaidManifest(value, context) {
  const record = requireExactUaidRecord(
    value,
    ["version", "uaid", "dataspace", "issued_ms", "activation_epoch", "entries"],
    ["expiry_epoch"],
    context,
  );
  if (record.version !== 1) {
    rejectType(`${context}.version must be the unsigned integer 1`);
  }
  const normalized = {
    version: 1,
    uaid: normalizeUaidLiteral(record.uaid, `${context}.uaid`),
    dataspace: requireExactJsonUnsignedInteger(
      record.dataspace,
      `${context}.dataspace`,
      { allowZero: true },
    ),
    issued_ms: requireExactJsonUnsignedInteger(
      record.issued_ms,
      `${context}.issued_ms`,
      { allowZero: true },
    ),
    activation_epoch: requireExactJsonUnsignedInteger(
      record.activation_epoch,
      `${context}.activation_epoch`,
      { allowZero: true },
    ),
    entries: requireDenseArray(record.entries, `${context}.entries`).map((entry, index) =>
      normalizeUaidManifestEntry(entry, `${context}.entries[${index}]`),
    ),
  };
  if (Object.prototype.hasOwnProperty.call(record, "expiry_epoch")) {
    if (record.expiry_epoch === null) {
      rejectType(`${context}.expiry_epoch must be omitted instead of null`);
    }
    normalized.expiry_epoch = requireExactJsonUnsignedInteger(
      record.expiry_epoch,
      `${context}.expiry_epoch`,
      { allowZero: true },
    );
  }
  return normalized;
}

function normalizeUaidManifestEntry(value, context) {
  const record = requireExactUaidRecord(
    value,
    ["scope", "effect"],
    ["notes"],
    context,
  );
  const normalized = {
    scope: normalizeUaidManifestScope(record.scope, `${context}.scope`),
    effect: normalizeUaidManifestEffect(record.effect, `${context}.effect`),
  };
  if (Object.prototype.hasOwnProperty.call(record, "notes")) {
    if (record.notes === null) {
      rejectType(`${context}.notes must be omitted instead of null`);
    }
    if (typeof record.notes !== JS_TYPE_STRING) {
      rejectType(`${context}.notes must be a string`);
    }
    normalized.notes = record.notes;
  }
  return normalized;
}

function normalizeUaidManifestScope(value, context) {
  const record = requireExactUaidRecord(
    value,
    [],
    ["dataspace", "program", "method", "asset", "role"],
    context,
  );
  const normalized = {};
  for (const field of ["dataspace", "program", "method", "asset", "role"]) {
    if (!Object.prototype.hasOwnProperty.call(record, field)) continue;
    const fieldContext = `${context}.${field}`;
    if (record[field] === null) {
      rejectType(`${fieldContext} must be omitted instead of null`);
    }
    if (field === "dataspace") {
      normalized[field] = requireExactJsonUnsignedInteger(record[field], fieldContext, {
        allowZero: true,
      });
    } else if (field === "program" || field === "method") {
      normalized[field] = requireCanonicalUaidManifestName(record[field], fieldContext);
    } else if (field === "asset") {
      normalized[field] = requireExactAssetDefinitionId(record[field], fieldContext);
    } else {
      normalized[field] = requireExactEnumString(
        record[field],
        UAID_MANIFEST_ROLE_VALUES,
        fieldContext,
      );
    }
  }
  return normalized;
}

function normalizeUaidManifestEffect(value, context) {
  const record = requireExactUaidRecord(value, [], ["Allow", "Deny"], context);
  const decisions = Object.keys(record);
  if (decisions.length !== 1) {
    rejectType(`${context} must contain exactly one Allow or Deny decision`);
  }
  if (decisions[0] === "Allow") {
    const allowance = requireExactUaidRecord(
      record.Allow,
      ["window"],
      ["max_amount"],
      `${context}.Allow`,
    );
    const normalized = {
      window: requireExactEnumString(
        allowance.window,
        UAID_MANIFEST_ALLOWANCE_WINDOW_VALUES,
        `${context}.Allow.window`,
      ),
    };
    if (Object.prototype.hasOwnProperty.call(allowance, "max_amount")) {
      if (allowance.max_amount === null) {
        rejectType(`${context}.Allow.max_amount must be omitted instead of null`);
      }
      normalized.max_amount = requireCanonicalQuantity(
        allowance.max_amount,
        `${context}.Allow.max_amount`,
      );
    }
    return { Allow: normalized };
  }
  const denial = requireExactUaidRecord(
    record.Deny,
    [],
    ["reason"],
    `${context}.Deny`,
  );
  const normalized = {};
  if (Object.prototype.hasOwnProperty.call(denial, "reason")) {
    if (denial.reason === null) {
      rejectType(`${context}.Deny.reason must be omitted instead of null`);
    }
    if (typeof denial.reason !== JS_TYPE_STRING) {
      rejectType(`${context}.Deny.reason must be a string`);
    }
    normalized.reason = denial.reason;
  }
  return { Deny: normalized };
}

function normalizeProverFilterBoolean(value, name) {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === JS_TYPE_NUMBER) {
    if (value === 1) {
      return true;
    }
    if (value === 0) {
      return false;
    }
  }
  if (typeof value === JS_TYPE_STRING) {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true" || normalized === "1" || normalized === "yes") {
      return true;
    }
    if (normalized === "false" || normalized === "0" || normalized === "no") {
      return false;
    }
  }
  rejectType(`${name} must be a boolean`);
}

function normalizeProverFilterString(value, name) {
  if (typeof value !== JS_TYPE_STRING) {
    rejectType(`${name} must be a string`);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    rejectType(`${name} must be a non-empty string`);
  }
  return trimmed;
}

function normalizeProverFilterEnum(value, name, allowed) {
  const normalized = normalizeProverFilterString(value, name).toLowerCase();
  if (!allowed.includes(normalized)) {
    rejectType(`${name} must be one of: ${allowed.join(", ")}`);
  }
  return normalized;
}

function isTruthyFilter(filters, key) {
  if (!filters || typeof filters !== JS_TYPE_OBJECT) {
    return false;
  }
  if (key in filters) {
    return Boolean(filters[key]);
  }
  const camelKey = key.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
  if (camelKey in filters) {
    return Boolean(filters[camelKey]);
  }
  return false;
}

function extractExtraFields(record, recognizedKeys) {
  const extra = {};
  for (const [key, value] of Object.entries(record)) {
    if (!recognizedKeys.has(key)) {
      extra[key] = value;
    }
  }
  return extra;
}

function computeStatusMetrics(previous, current) {
  const metrics = {
    commit_latency_ms: current.commit_time_ms,
    queue_size: current.queue_size,
    queue_queued: current.queue_queued,
    queue_inflight: current.queue_inflight,
    queue_delta: previous ? current.queue_size - previous.queue_size : 0,
    time_since_last_block_ms: current.time_since_last_block_ms,
    time_since_last_non_empty_block_ms:
      current.time_since_last_non_empty_block_ms,
    tx_approved_delta: previous
      ? Math.max(0, current.txs_approved - previous.txs_approved)
      : 0,
    tx_rejected_delta: previous
      ? Math.max(0, current.txs_rejected - previous.txs_rejected)
      : 0,
    view_change_delta: previous
      ? Math.max(0, current.view_changes - previous.view_changes)
      : 0,
  };
  metrics.has_activity = Boolean(
    metrics.queue_delta ||
      metrics.tx_approved_delta ||
      metrics.tx_rejected_delta ||
      metrics.view_change_delta,
  );
  return metrics;
}

/**
 * Milliseconds since the peer last committed a non-empty block
 * (`time_since_last_non_empty_block_ms`), or since its last block
 * (`time_since_last_block_ms`) while it has not reported a non-empty one.
 * @param {ToriiStatusPayload | Record<string, unknown>} status `/status` payload.
 * @returns {number}
 */
export function statusLivenessElapsedMs(status) {
  const record = ensureRecord(status, "status");
  const nonEmptyElapsed = coerceStatusInt(
    record.time_since_last_non_empty_block_ms,
    "status.time_since_last_non_empty_block_ms",
  );
  if (nonEmptyElapsed > 0) {
    return nonEmptyElapsed;
  }
  return coerceStatusInt(
    record.time_since_last_block_ms,
    "status.time_since_last_block_ms",
  );
}

/**
 * Report a queue stall: the peer tracks queued work (`queue_size > 0`) and
 * `statusLivenessElapsedMs(status)` exceeds `stallThresholdMs`.
 * `ToriiPipelinePreflight.isStatusStalled` applies the threshold derived from
 * the served `sumeragi.block_cadence_ms`; pass an explicit threshold here when
 * the deployment's local consensus timers are known.
 * @param {ToriiStatusPayload | Record<string, unknown>} status `/status` payload.
 * @param {number | string | bigint} stallThresholdMs Threshold in milliseconds.
 * @returns {boolean}
 */
export function isStatusQueueStalled(status, stallThresholdMs) {
  const record = ensureRecord(status, "status");
  const queueSize = coerceStatusInt(record.queue_size, "status.queue_size");
  const threshold = coerceIntegerLike(
    stallThresholdMs,
    "stallThresholdMs",
  );
  return queueSize > 0 && statusLivenessElapsedMs(record) > threshold;
}

function monotonicTimestamp() {
  if (
    typeof performance === JS_TYPE_OBJECT &&
    performance &&
    typeof performance.now === JS_TYPE_FUNCTION
  ) {
    return performance.now();
  }
  if (
    typeof process === JS_TYPE_OBJECT &&
    process &&
    typeof process.hrtime === JS_TYPE_FUNCTION
  ) {
    const [seconds, nanoseconds] = process.hrtime();
    return seconds * 1_000 + nanoseconds / 1_000_000;
  }
  return Date.now();
}

const PROVER_FILTER_DEFINITIONS = {
  ok_only: { type: "boolean", aliases: ["okOnly"] },
  failed_only: { type: "boolean", aliases: ["failedOnly"] },
  errors_only: { type: "boolean", aliases: ["errorsOnly"] },
  ids_only: { type: "boolean", aliases: ["idsOnly"] },
  messages_only: { type: "boolean", aliases: ["messagesOnly"] },
  latest: { type: "boolean", aliases: ["latest"] },
  content_type: { type: JS_TYPE_STRING, aliases: ["contentType"] },
  has_tag: { type: JS_TYPE_STRING, aliases: ["hasTag"] },
  id: { type: JS_TYPE_STRING, aliases: ["id"] },
  limit: { type: "integer", aliases: ["limit"], allowZero: false },
  offset: { type: "integer", aliases: ["offset"], allowZero: true },
  since_ms: { type: "integer", aliases: ["sinceMs"], allowZero: true },
  before_ms: { type: "integer", aliases: ["beforeMs"], allowZero: true },
  order: { type: "enum", aliases: ["order"], values: ["asc", "desc"] },
};

const PROVER_FILTER_ALIAS_MAP = (() => {
  const map = new Map();
  for (const [key, spec] of Object.entries(PROVER_FILTER_DEFINITIONS)) {
    map.set(key, { key, spec });
    const aliases = Array.isArray(spec.aliases) ? spec.aliases : [];
    for (const alias of aliases) {
      map.set(alias, { key, spec });
    }
  }
  return map;
})();
const PROVER_REPORT_ITERATOR_OPTION_KEYS = (() => {
  const keys = new Set(["pageSize", "maxItems", "limit", "offset", "signal"]);
  for (const key of PROVER_FILTER_ALIAS_MAP.keys()) {
    keys.add(key);
  }
  return keys;
})();

/**
 * Yield the chunks of a streaming response body until it ends, the caller
 * aborts `signal`, or the consumer stops iterating. Aborting or leaving the
 * loop early cancels the body so the underlying connection is released.
 */
async function* readBodyChunks(body, signal) {
  if (!body) {
    return;
  }
  throwIfAborted(signal);
  if (typeof body.getReader === JS_TYPE_FUNCTION) {
    const reader = body.getReader();
    try {
      yield* pumpBodyChunks(
        () => reader.read(),
        (reason) => bestEffortCleanup(() => reader.cancel?.(reason)),
        signal,
      );
    } finally {
      try {
        reader.releaseLock?.();
      } catch {
        // Some custom readers do not implement lock release correctly.
      }
    }
    return;
  }
  if (typeof body[Symbol.asyncIterator] === JS_TYPE_FUNCTION) {
    const iterator = body[Symbol.asyncIterator]();
    yield* pumpBodyChunks(
      () => iterator.next(),
      () => bestEffortCleanup(() => iterator.return?.()),
      signal,
    );
    return;
  }
  rejectError("SSE response body is not async iterable");
}

function bestEffortCleanup(action) {
  try {
    Promise.resolve(action()).catch(() => {});
  } catch {
    // Cleanup must never replace the authoritative outcome.
  }
}

async function* pumpBodyChunks(read, cancel, signal) {
  let finished = false;
  let rejectAbort;
  const aborted = new Promise((_, reject) => {
    rejectAbort = reject;
  });
  aborted.catch(() => {});
  const onAbort = () => {
    rejectAbort(signalAbortReason(signal) ?? createAbortError());
    cancel(signalAbortReason(signal));
  };
  if (signal) addSignalAbortListener(signal, onAbort);
  try {
    while (true) {
      const { done, value } = await Promise.race([read(), aborted]);
      if (done) {
        finished = true;
        break;
      }
      if (value) {
        yield value;
      }
    }
  } finally {
    if (signal) removeSignalAbortListener(signal, onAbort);
    if (!finished) cancel();
  }
  throwIfAborted(signal);
}

function flushSseBuffer(buffer) {
  /** @type {Array<SseEvent>} */
  const events = [];
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const index = buffer.indexOf("\n\n");
    if (index === -1) {
      break;
    }
    const raw = buffer.slice(0, index);
    buffer = buffer.slice(index + 2);
    const parsed = ToriiClient._parseSseEvent(raw);
    if (parsed) {
      events.push(parsed);
    }
  }
  return { events, remainder: buffer };
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return Buffer.from(value);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return Buffer.alloc(0);
    }
    return normalizeByteArray(value, "payload");
  }
  rejectType("payload must be a Buffer or ArrayBuffer view");
}

function normalizeByteArray(value, context) {
  const bytes = value.map((entry, index) => {
    if (!Number.isInteger(entry) || entry < 0 || entry > 255) {
      throw createValidationError(
        ValidationErrorCode.VALUE_OUT_OF_RANGE,
        `${context}[${index}] must be an integer between 0 and 255`,
        `${context}[${index}]`,
      );
    }
    return entry;
  });
  return Buffer.from(bytes);
}

function toXmlBuffer(value, name) {
  if (typeof value === JS_TYPE_STRING) {
    if (!value.trim()) {
      rejectType(`${name} must be a non-empty string or binary payload`);
    }
    return Buffer.from(value, "utf8");
  }
  return toBuffer(value);
}

function attachHeaderAccessors(headers) {
  if (!headers || typeof headers !== JS_TYPE_OBJECT) {
    return;
  }
  if (typeof headers.get !== JS_TYPE_FUNCTION) {
    Object.defineProperty(headers, "get", {
      value(name) {
        const key = findHeaderKey(headers, name);
        return key ? headers[key] : undefined;
      },
      enumerable: false,
    });
  }
  if (typeof headers.has !== JS_TYPE_FUNCTION) {
    Object.defineProperty(headers, "has", {
      value(name) {
        return findHeaderKey(headers, name) !== null;
      },
      enumerable: false,
    });
  }
}

function findHeaderKey(headers, name) {
  if (!headers || typeof headers !== JS_TYPE_OBJECT || name == null) {
    return null;
  }
  const target = String(name).toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === target) {
      return key;
    }
  }
  return null;
}

function setHeader(headers, name, value) {
  if (name == null) {
    return;
  }
  const normalized = String(value);
  const existing = findHeaderKey(headers, name);
  const key = existing ?? String(name);
  headers[key] = normalized;
}

function deleteHeader(headers, name) {
  const key = findHeaderKey(headers, name);
  if (key) {
    delete headers[key];
  }
}

function hasHeader(headers, name) {
  return findHeaderKey(headers, name) !== null;
}

function cloneHeadersForFetch(headers) {
  const clone = {};
  if (headers && typeof headers === JS_TYPE_OBJECT) {
    for (const [key, value] of Object.entries(headers)) {
      clone[key] = value;
    }
  }
  return clone;
}

function headersContainCredentials(headers) {
  if (!headers || typeof headers !== JS_TYPE_OBJECT) {
    return false;
  }
  return [
    "authorization",
    "x-api-token",
    "x-iroha-account",
    "x-iroha-signature",
    "x-iroha-timestamp-ms",
    "x-iroha-nonce",
    "x-iroha-witness",
  ].some((name) => hasHeader(headers, name));
}

function bodyContainsSensitiveKeyMaterial(body, headers) {
  if (body == null) {
    return false;
  }
  const contentTypeKey = findHeaderKey(headers, "content-type");
  const contentType =
    contentTypeKey && headers[contentTypeKey] != null
      ? String(headers[contentTypeKey]).toLowerCase()
      : null;
  const shouldInspectAsText =
    typeof body === JS_TYPE_STRING || Boolean(contentType && contentType.includes("json"));
  if (!shouldInspectAsText) {
    return false;
  }
  let text;
  if (typeof body === JS_TYPE_STRING) {
    text = body;
  } else if (Buffer.isBuffer(body)) {
    text = body.toString("utf8");
  } else if (body instanceof Uint8Array) {
    text = Buffer.from(body).toString("utf8");
  } else if (ArrayBuffer.isView(body)) {
    text = Buffer.from(body.buffer, body.byteOffset, body.byteLength).toString("utf8");
  } else if (body instanceof ArrayBuffer) {
    text = Buffer.from(body).toString("utf8");
  } else {
    return false;
  }
  return /"(?:private_key|privateKey|private_key_hex|privateKeyHex|private_key_bytes|privateKeyBytes|private_key_multihash|privateKeyMultihash)"\s*:/u.test(
    text,
  );
}

function composeRequestSignal(callerSignal, timeoutMs) {
  if (
    typeof AbortControllerConstructor !== JS_TYPE_FUNCTION ||
    typeof abortControllerAbort !== JS_TYPE_FUNCTION ||
    typeof abortControllerSignalGetter !== JS_TYPE_FUNCTION ||
    !(typeof timeoutMs === JS_TYPE_NUMBER && timeoutMs > 0)
  ) {
    return {
      signal: callerSignal,
      cleanup() {},
      didTimeout: () => false,
    };
  }
  const controller = new AbortControllerConstructor();
  const composedSignal = Reflect.apply(abortControllerSignalGetter, controller, []);
  let timedOut = false;
  let timeoutId;
  const onCallerAbort = () => {
    Reflect.apply(abortControllerAbort, controller, [signalAbortReason(callerSignal)]);
  };
  if (callerSignal) {
    if (signalIsAborted(callerSignal)) {
      onCallerAbort();
    } else {
      addSignalAbortListener(callerSignal, onCallerAbort);
    }
  }
  if (!signalIsAborted(composedSignal)) {
    timeoutId = scheduleTimeout(() => {
      timedOut = true;
      Reflect.apply(abortControllerAbort, controller, [
        new Error(`Torii request timed out after ${timeoutMs} ms`),
      ]);
    }, timeoutMs);
  }
  let cleaned = false;
  return {
    signal: composedSignal,
    cleanup() {
      if (cleaned) return;
      cleaned = true;
      if (timeoutId !== undefined) cancelTimeout(timeoutId);
      if (callerSignal) removeSignalAbortListener(callerSignal, onCallerAbort);
    },
    didTimeout: () => timedOut,
  };
}

function delay(ms, signal) {
  if (!signal) {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  }
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      removeSignalAbortListener(signal, onAbort);
      reject(signalAbortReason(signal) ?? new Error("The operation was aborted"));
    };
    const timer = setTimeout(() => {
      removeSignalAbortListener(signal, onAbort);
      resolve();
    }, ms);
    addSignalAbortListener(signal, onAbort);
    if (signalIsAborted(signal)) onAbort();
  });
}

function createAbortError() {
  if (typeof DOMException === JS_TYPE_FUNCTION) {
    return new DOMException("The operation was aborted", "AbortError");
  }
  const error = new Error("The operation was aborted");
  error.name = "AbortError";
  return error;
}

function throwIfAborted(signal) {
  if (!signal) {
    return;
  }
  if (signalIsAborted(signal)) {
    throw signalAbortReason(signal) ?? createAbortError();
  }
}

function waitForPromiseWithSignal(promise, signal) {
  if (!signal) {
    return promise;
  }
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      removeSignalAbortListener(signal, onAbort);
      callback(value);
    };
    const onAbort = () =>
      finish(
        reject,
        signalAbortReason(signal) instanceof Error
          ? signalAbortReason(signal)
          : createAbortError(),
      );
    addSignalAbortListener(signal, onAbort);
    if (signalIsAborted(signal)) onAbort();
    Promise.resolve(promise).then(
      (value) => finish(resolve, value),
      (error) => finish(reject, error),
    );
  });
}

function waitForResponseWithSignal(promise, signal, context) {
  // Install disposal before observing cancellation: a custom fetch callback may
  // abort synchronously and still produce a response after the caller returns.
  Promise.resolve(promise).then((response) => {
    if (signalIsAborted(signal)) cancelResponseBodyBestEffort(response, `${context} late response`);
  }, () => {});
  return waitForPromiseWithSignal(promise, signal);
}

const CONNECT_SID_BYTES = 32;
const BASE64URL_BODY_PATTERN = /^[A-Za-z0-9_-]+$/;

function normalizeConnectSid(value, name) {
  const trimmed = requireNonEmptyString(value, name);
  const hexBody =
    trimmed.startsWith("0x") || trimmed.startsWith("0X")
      ? trimmed.slice(2)
      : trimmed;
  if (
    hexBody.length === CONNECT_SID_BYTES * 2 &&
    /^[0-9a-fA-F]+$/.test(hexBody)
  ) {
    return hexBody.toLowerCase();
  }
  const { body, padding } = splitBase64Url(trimmed);
  if (!body || !BASE64URL_BODY_PATTERN.test(body)) {
    throw connectSidTypeError(name);
  }
  if (padding) {
    throw connectSidTypeError(name);
  }
  let decoded;
  try {
    decoded = decodeBase64UrlBody(body);
  } catch {
    throw connectSidTypeError(name);
  }
  if (decoded.length !== CONNECT_SID_BYTES) {
    throw connectSidTypeError(name);
  }
  return trimmed;
}

function connectSidTypeError(name) {
  return new TypeError(
    `${name} must be a 32-byte base64url string (no padding) or hex string`,
  );
}

function splitBase64Url(value) {
  const match = value.match(/=+$/u);
  if (!match) {
    return { body: value, padding: "" };
  }
  const padding = match[0];
  return {
    body: value.slice(0, -padding.length),
    padding,
  };
}

function decodeBase64UrlBody(body) {
  let padded = body.replace(/-/g, "+").replace(/_/g, "/");
  const remainder = padded.length % 4;
  if (remainder === 1) {
    rejectType("invalid base64url length");
  }
  if (remainder === 2) {
    padded += "==";
  } else if (remainder === 3) {
    padded += "=";
  }
  return Buffer.from(padded, "base64");
}

function requireNonEmptyString(value, name) {
  if (typeof value !== JS_TYPE_STRING) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${name} must be a string`,
      name,
    );
  }
  const trimmed = value.trim();
  if (!trimmed) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${name} must not be empty`,
      name,
    );
  }
  return trimmed;
}

function requireExactNonEmptyString(value, name) {
  const trimmed = requireNonEmptyString(value, name);
  if (trimmed !== value) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${name} must not contain surrounding whitespace`,
      name,
    );
  }
  return value;
}

function requireExactTokenString(value, name) {
  const exact = requireExactNonEmptyString(value, name);
  if (/\s|\p{Cc}/u.test(exact)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${name} must not contain whitespace or control characters`,
      name,
    );
  }
  return exact;
}

function requireGovernanceSelectorString(value, name) {
  const exact = requireExactTokenString(value, name);
  if (!isCanonicalGovernanceSelectorV1(exact)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${name} must be 1-128 RFC 3986 unreserved ASCII characters and must not start with a dot`,
      name,
    );
  }
  return exact;
}

function requireExactAsciiTokenString(value, name) {
  const exact = requireExactTokenString(value, name);
  if (!/^[!-~]+$/u.test(exact)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${name} must contain only non-whitespace ASCII characters`,
      name,
    );
  }
  return exact;
}

function requireCanonicalQuantity(value, name) {
  if (typeof value !== JS_TYPE_STRING) {
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${name} must be a canonical Kotodama V1 quantity string`,
      name,
    );
  }
  try {
    return NumericV1.decodeQuantityJson(value).toString();
  } catch (error) {
    if (!(error instanceof NumericV1Error)) throw error;
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${name} must be a canonical non-negative Kotodama V1 quantity (${error.code})`,
      name,
    );
  }
}

function normalizeQuantityInput(value, name) {
  try {
    if (value instanceof KotodamaQuantity) {
      return NumericV1.encodeQuantityJson(value);
    }
    if (typeof value === JS_TYPE_STRING) {
      return NumericV1.decodeQuantityJson(value).toString();
    }
    if (typeof value === JS_TYPE_BIGINT) {
      return new KotodamaQuantity(value, 0).toString();
    }
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${name} must be a KotodamaQuantity, canonical quantity string, or bigint; JavaScript numbers are rejected`,
      name,
    );
  } catch (error) {
    if (!(error instanceof NumericV1Error)) throw error;
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${name} must be a canonical non-negative Kotodama V1 quantity (${error.code})`,
      name,
    );
  }
}

function requireExactBoolean(value, name) {
  if (typeof value !== "boolean") {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${name} must be a boolean`,
      name,
    );
  }
  return value;
}

function requireExactJsonUnsignedInteger(value, name, options = {}) {
  const minimum = options.allowZero === false ? 1 : 0;
  if (
    typeof value !== JS_TYPE_NUMBER ||
    !Number.isSafeInteger(value) ||
    value < minimum
  ) {
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${name} must be a ${minimum === 0 ? "non-negative" : "positive"} JSON safe integer`,
      name,
    );
  }
  return value;
}

function requireExactLowerHex32String(value, name) {
  return requireExactLowerHexBytesString(value, name, 32);
}

function requireCanonicalTransactionHashString(value, name) {
  const literal = requireExactLowerHex32String(value, name);
  if (!/[13579bdf]$/u.test(literal)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must carry the canonical Iroha hash marker`,
      name,
    );
  }
  return literal;
}

function requireNonZeroLowerHex32String(value, name) {
  const literal = requireExactLowerHex32String(value, name);
  if (/^0{64}$/u.test(literal)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must not be the all-zero digest`,
      name,
    );
  }
  return literal;
}

function requireOptionalExactLowerHex32String(value, name) {
  return value === undefined || value === null
    ? null
    : requireExactLowerHex32String(value, name);
}

function requireExactLowerHexBytesString(value, name, expectedBytes) {
  const literal = requireExactNonEmptyString(value, name);
  if (
    literal.length !== expectedBytes * 2 ||
    !/^[0-9a-f]+$/u.test(literal)
  ) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must be an exact lowercase ${expectedBytes}-byte hex string`,
      name,
    );
  }
  return literal;
}

function requireExactLowerEvenHexString(value, name) {
  const literal = requireExactNonEmptyString(value, name);
  if (literal.length % 2 !== 0 || !/^[0-9a-f]+$/u.test(literal)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must be an exact lowercase even-length hex string`,
      name,
    );
  }
  return literal;
}

function requireVpnHelperTicketHex(value, name) {
  if (
    typeof value !== JS_TYPE_STRING ||
    value.length !== VPN_HELPER_TICKET_HEX_LENGTH ||
    !/^[0-9a-f]+$/u.test(value)
  ) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must contain exactly ${VPN_HELPER_TICKET_HEX_LENGTH} lowercase hexadecimal characters (${VPN_HELPER_TICKET_BYTES} bytes)`,
      name,
    );
  }
  return value;
}

function requireHexString(value, name) {
  if (typeof value !== JS_TYPE_STRING) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must be a hex string`,
      name,
    );
  }
  const normalized = value.trim();
  if (!normalized) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must be a hex string`,
      name,
    );
  }
  const hasPrefix =
    normalized.startsWith("0x") || normalized.startsWith("0X");
  const hex = hasPrefix ? normalized.slice(2) : normalized;
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must be a hex string`,
      name,
    );
  }
  return normalized;
}

function requireExactHexString(value, name) {
  const normalized = requireHexString(value, name);
  if (normalized !== value) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must not contain surrounding whitespace`,
      name,
    );
  }
  return normalized.startsWith("0x") || normalized.startsWith("0X")
    ? normalized.slice(2)
    : normalized;
}

function normalizeStorageTicketHex(value, name) {
  const normalized = requireHexString(value, name);
  const hex = normalized.startsWith("0x") || normalized.startsWith("0X")
    ? normalized.slice(2)
    : normalized;
  if (hex.length !== 64) {
    rejectType(`${name} must contain 64 hex characters`);
  }
  return hex.toLowerCase();
}

function coerceIntegerLike(value, context) {
  if (typeof value === JS_TYPE_NUMBER) {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      rejectRange(`${context} must be a safe integer`);
    }
    return value;
  }
  if (typeof value === JS_TYPE_BIGINT) {
    const numeric = Number(value);
    if (!Number.isSafeInteger(numeric)) {
      rejectRange(`${context} must be a safe integer`);
    }
    return numeric;
  }
  if (typeof value === JS_TYPE_STRING) {
    const trimmed = value.trim();
    if (!trimmed) {
      rejectType(`${context} must be an integer`);
    }
    const numeric = Number(trimmed);
    if (!Number.isFinite(numeric) || !Number.isSafeInteger(numeric)) {
      rejectRange(`${context} must be a safe integer`);
    }
    return numeric;
  }
  rejectType(`${context} must be an integer`);
}

function requireNonNegativeIntegerLike(value, context) {
  if (value === undefined || value === null) {
    rejectType(`${context} is required`);
  }
  const numeric = coerceIntegerLike(value, context);
  if (numeric < 0) {
    rejectRange(`${context} must be >= 0`);
  }
  return numeric;
}

function pickOverride(source, snakeName, camelName) {
  if (!source || typeof source !== JS_TYPE_OBJECT) {
    return undefined;
  }
  if (Object.prototype.hasOwnProperty.call(source, snakeName)) {
    return source[snakeName];
  }
  if (Object.prototype.hasOwnProperty.call(source, camelName)) {
    return source[camelName];
  }
  return undefined;
}



function rejectPrivateKeyFields(record, context) {
  rejectVerifyingKeyPrivateKeyFields(record, context);
}

function normalizeSecretFreeAuthority(source, context) {
  const record = ensureRecord(source, context);
  rejectPrivateKeyFields(record, context);
  return {
    authority: ToriiClient._normalizeAccountId(
      record.authority,
      `${context}.authority`,
    ),
  };
}

function requireCanonicalKotodamaIdentifier(value, context, options) {
  const identifier = requireExactNonEmptyString(value, context);
  if (!isCanonicalKotodamaIdentifier(identifier, options)) {
    rejectType(`${context} must be a canonical Kotodama V1 identifier`);
  }
  return identifier;
}

function requireCanonicalKotodamaEntrypoint(value, context) {
  const name = requireExactNonEmptyString(value, context);
  if (!isCanonicalKotodamaEntrypoint(name)) {
    rejectType(`${context} must be a canonical Kotodama V1 identifier or branded lifecycle selector`);
  }
  return name;
}

function exactManifestResponseRecord(value, allowedFields, context) {
  const record = ensureRecord(value, context);
  const allowed = new Set(allowedFields);
  const unknownFields = Reflect.ownKeys(record).filter(
    (field) => typeof field !== JS_TYPE_STRING || !allowed.has(field),
  );
  if (unknownFields.length !== 0) {
    rejectType(`${context} contains unsupported fields: ${unknownFields
        .map((field) => String(field))
        .sort()
        .join(", ")}`);
  }
  return record;
}

function assertExactManifestResponseValueType(value, context) {
  if (value === undefined || value === null) {
    return;
  }
  const record = exactManifestResponseRecord(value, ["nodes"], context);
  if (!Array.isArray(record.nodes)) {
    return;
  }
  record.nodes.forEach((node, index) => {
    const nodeContext = `${context}.nodes[${index}]`;
    const nodeRecord = exactManifestResponseRecord(node, ["kind", "value"], nodeContext);
    if (nodeRecord.kind === "Struct") {
      exactManifestResponseRecord(
        nodeRecord.value,
        ["name", "fields"],
        `${nodeContext}.value`,
      );
    } else if (nodeRecord.kind === "List") {
      exactManifestResponseRecord(nodeRecord.value, ["capacity"], `${nodeContext}.value`);
    } else if (nodeRecord.kind === "Leaf") {
      exactManifestResponseRecord(
        nodeRecord.value,
        ["kind", "value"],
        `${nodeContext}.value`,
      );
    }
  });
}

function assertExactManifestResponseShape(value, context) {
  const manifest = exactManifestResponseRecord(
    value,
    [
      "seiyaku_name",
      "code_hash",
      "abi_hash",
      "compiler_fingerprint",
      "features_bitmap",
      "access_set_hints",
      "entrypoints",
      "states",
      "error_types",
      "error_messages",
      "kotoba",
      "provenance",
    ],
    context,
  );

  if (manifest.access_set_hints !== undefined && manifest.access_set_hints !== null) {
    const access = exactManifestResponseRecord(
      manifest.access_set_hints,
      ["read_keys", "write_keys", "dynamic_reads", "dynamic_writes"],
      `${context}.access_set_hints`,
    );
    for (const [field, hints] of [
      ["dynamic_reads", access.dynamic_reads],
      ["dynamic_writes", access.dynamic_writes],
    ]) {
      if (!Array.isArray(hints)) {
        continue;
      }
      hints.forEach((hint, index) => {
        exactManifestResponseRecord(
          hint,
          ["base_key", "key_type", "bound_kind", "max_keys"],
          `${context}.access_set_hints.${field}[${index}]`,
        );
      });
    }
  }

  if (Array.isArray(manifest.entrypoints)) {
    manifest.entrypoints.forEach((entrypoint, index) => {
      const entrypointContext = `${context}.entrypoints[${index}]`;
      const entrypointRecord = exactManifestResponseRecord(
        entrypoint,
        [
          "name",
          "kind",
          "params",
          "argument_schema",
          "return_type",
          "return_schema",
          "permission",
          "read_keys",
          "write_keys",
          "access_hints_complete",
          "access_hints_skipped",
          "triggers",
        ],
        entrypointContext,
      );
      exactManifestResponseRecord(
        entrypointRecord.kind,
        ["kind", "value"],
        `${entrypointContext}.kind`,
      );
      if (Array.isArray(entrypointRecord.params)) {
        entrypointRecord.params.forEach((param, paramIndex) => {
          exactManifestResponseRecord(
            param,
            ["name", "type_name"],
            `${entrypointContext}.params[${paramIndex}]`,
          );
        });
      }
      if (
        entrypointRecord.argument_schema !== undefined &&
        entrypointRecord.argument_schema !== null
      ) {
        const argumentSchema = exactManifestResponseRecord(
          entrypointRecord.argument_schema,
          ["fields"],
          `${entrypointContext}.argument_schema`,
        );
        if (Array.isArray(argumentSchema.fields)) {
          argumentSchema.fields.forEach((field, fieldIndex) => {
            const fieldContext =
              `${entrypointContext}.argument_schema.fields[${fieldIndex}]`;
            const fieldRecord = exactManifestResponseRecord(
              field,
              ["name", "ty"],
              fieldContext,
            );
            assertExactManifestResponseValueType(fieldRecord.ty, `${fieldContext}.ty`);
          });
        }
      }
      assertExactManifestResponseValueType(
        entrypointRecord.return_schema,
        `${entrypointContext}.return_schema`,
      );
      if (Array.isArray(entrypointRecord.triggers)) {
        entrypointRecord.triggers.forEach((trigger, triggerIndex) => {
          const triggerContext = `${entrypointContext}.triggers[${triggerIndex}]`;
          const triggerRecord = exactManifestResponseRecord(
            trigger,
            ["id", "repeats", "filter", "authority", "metadata", "callback"],
            triggerContext,
          );
          exactManifestResponseRecord(
            triggerRecord.repeats,
            ["Indefinitely", "Exactly"],
            `${triggerContext}.repeats`,
          );
          exactManifestResponseRecord(
            triggerRecord.callback,
            ["namespace", "entrypoint"],
            `${triggerContext}.callback`,
          );
        });
      }
    });
  }

  if (Array.isArray(manifest.states)) {
    manifest.states.forEach((state, index) => {
      exactManifestResponseRecord(
        state,
        ["name", "type_name"],
        `${context}.states[${index}]`,
      );
    });
  }
  normalizeContractErrorTypesV1(manifest.error_types, `${context}.error_types`);
  if (Array.isArray(manifest.kotoba)) {
    manifest.kotoba.forEach((entry, index) => {
      const entryContext = `${context}.kotoba[${index}]`;
      const entryRecord = exactManifestResponseRecord(
        entry,
        ["msg_id", "translations"],
        entryContext,
      );
      if (Array.isArray(entryRecord.translations)) {
        entryRecord.translations.forEach((translation, translationIndex) => {
          exactManifestResponseRecord(
            translation,
            ["lang", "text"],
            `${entryContext}.translations[${translationIndex}]`,
          );
        });
      }
    });
  }
  if (manifest.provenance !== undefined && manifest.provenance !== null) {
    exactManifestResponseRecord(
      manifest.provenance,
      ["signer", "signature"],
      `${context}.provenance`,
    );
  }
  return manifest;
}

function normalizeManifestPayload(manifest, context) {
  if (!isPlainObject(manifest)) {
    rejectType(`${context} must be an object`);
  }
  validateManifestFieldsV1(manifest, context);
  const hasField = (...keys) =>
    keys.some((key) => Object.prototype.hasOwnProperty.call(manifest, key));
  const getField = (...keys) => {
    const present = keys.filter((key) =>
      Object.prototype.hasOwnProperty.call(manifest, key),
    );
    return present.length === 0 ? undefined : manifest[present[0]];
  };
  const normalized = {
    seiyaku_name: null,
    code_hash: null,
    abi_hash: null,
    compiler_fingerprint: null,
    features_bitmap: null,
    access_set_hints: null,
    entrypoints: null,
    states: null,
    error_types: null,
    error_messages: null,
    kotoba: null,
    provenance: null,
  };
  if (hasField("seiyaku_name", "seiyakuName")) {
    const seiyakuName = getField("seiyaku_name", "seiyakuName") ?? null;
    normalized.seiyaku_name =
      seiyakuName === null
        ? null
        : requireCanonicalKotodamaIdentifier(
            seiyakuName,
            `${context}.seiyaku_name`,
            { typeDeclaration: true },
          );
  }
  if (hasField("code_hash", "codeHash")) {
    normalized.code_hash = normalizeOptionalHex32(
      getField("code_hash", "codeHash"),
      `${context}.code_hash`,
    );
  }
  if (hasField("abi_hash", "abiHash")) {
    normalized.abi_hash = normalizeOptionalHex32(
      getField("abi_hash", "abiHash"),
      `${context}.abi_hash`,
    );
  }
  if (hasField("compiler_fingerprint", "compilerFingerprint")) {
    const fingerprint = getField("compiler_fingerprint", "compilerFingerprint") ?? null;
    normalized.compiler_fingerprint =
      fingerprint === null
        ? null
        : requireNonEmptyString(fingerprint, `${context}.compiler_fingerprint`);
  }
  if (hasField("features_bitmap", "featuresBitmap")) {
    const features = getField("features_bitmap", "featuresBitmap") ?? null;
    if (features === null) {
      normalized.features_bitmap = null;
    } else {
      const bitmap = ToriiClient._normalizeUnsignedInteger(
        features,
        `${context}.features_bitmap`,
        { allowZero: true },
      );
      if (bitmap > 3) {
        rejectType(`${context}.features_bitmap contains unsupported Kotodama V1 feature bits`);
      }
      normalized.features_bitmap = bitmap;
    }
  }
  if (hasField("access_set_hints", "accessSetHints")) {
    const hints = getField("access_set_hints", "accessSetHints");
    normalized.access_set_hints =
      hints === null
        ? null
        : normalizeAccessSetHintsPayload(hints, `${context}.access_set_hints`);
  }
  if (hasField("entrypoints", "entryPoints")) {
    const entries = getField("entrypoints", "entryPoints");
    if (entries === null) {
      normalized.entrypoints = null;
    } else if (!Array.isArray(entries)) {
      rejectType(`${context}.entrypoints must be an array`);
    } else {
      normalized.entrypoints = entries.map((entry, index) => {
        return normalizeManifestEntrypointPayload(
          entry,
          `${context}.entrypoints[${index}]`,
        );
      });
    }
  }
  if (hasField("states")) {
    const states = getField("states");
    normalized.states =
      states === null ? null : normalizeManifestStatesPayload(states, `${context}.states`);
  }
  if (hasField("error_types", "errorTypes")) {
    const errorTypes = getField("error_types", "errorTypes");
    normalized.error_types =
      errorTypes === null
        ? null
        : normalizeManifestErrorTypesPayload(errorTypes, `${context}.error_types`);
  }
  normalized.error_messages = normalizeContractErrorMessagesV1(getField("error_messages", "errorMessages"), normalized.error_types, `${context}.error_messages`);
  if (hasField("kotoba")) {
    const kotoba = getField("kotoba");
    normalized.kotoba =
      kotoba === null ? null : normalizeManifestKotobaPayload(kotoba, `${context}.kotoba`);
  }
  if (hasField("provenance")) {
    const provenance = getField("provenance");
    normalized.provenance =
      provenance === null
        ? null
        : normalizeManifestProvenancePayload(provenance, `${context}.provenance`);
  }
  validateNormalizedManifestPayload(normalized, context);
  return normalized;
}

function validateNormalizedManifestPayload(manifest, context) {
  validateManifestDeclarationsV1(manifest, context);
  validateManifestDynamicAccessHintStateMaps(
    manifest.access_set_hints,
    manifest.states,
    `${context}.access_set_hints`,
  );

  validateManifestErrorTypeBindingsV1(manifest, context);
}

function validateManifestDynamicAccessHintStateMaps(accessSetHints, states, context) {
  if (accessSetHints === null) {
    return;
  }
  const stateMaps = new Map();
  for (const state of states ?? []) {
    const keyType = kotodamaV1StateMapKeyTypeName(state.type_name);
    if (keyType !== null) {
      stateMaps.set(state.name, keyType);
    }
  }
  for (const field of ["dynamic_reads", "dynamic_writes"]) {
    const seen = new Set();
    accessSetHints[field].forEach((hint, index) => {
      const hintContext = `${context}.${field}[${index}]`;
      const identity = JSON.stringify([
        hint.base_key,
        hint.key_type,
        hint.bound_kind,
        hint.max_keys,
      ]);
      if (seen.has(identity)) {
        rejectType(`${context}.${field} contains a duplicate dynamic access hint`);
      }
      seen.add(identity);
      const stateName = hint.base_key.slice("state:".length);
      const expectedKeyType = stateMaps.get(stateName);
      if (expectedKeyType === undefined) {
        rejectType(`${hintContext}.base_key must reference a declared top-level StateMap`);
      }
      if (hint.key_type !== expectedKeyType) {
        rejectType(`${hintContext}.key_type ${hint.key_type} does not match declared StateMap key type ${expectedKeyType}`);
      }
    });
  }
}

function normalizeManifestKotobaPayload(value, context) {
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  return value.map((entry, index) => {
    const record = ensureRecord(entry, `${context}[${index}]`);
    return {
      msg_id: requireExactNonEmptyString(
        record.msg_id ?? record.msgId,
        `${context}[${index}].msg_id`,
      ),
      translations: normalizeManifestKotobaTranslationsPayload(
        record.translations,
        `${context}[${index}].translations`,
      ),
    };
  });
}

function normalizeManifestKotobaTranslationsPayload(value, context) {
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  return value.map((translation, index) => {
    const record = ensureRecord(translation, `${context}[${index}]`);
    return {
      lang: requireExactNonEmptyString(record.lang, `${context}[${index}].lang`),
      text:
        typeof record.text === JS_TYPE_STRING
          ? record.text
          : (() => {
              rejectType(`${context}[${index}].text must be a string`);
            })(),
    };
  });
}

function normalizeManifestPublicKeyPayload(value, context) {
  const literal = requireExactNonEmptyString(value, context);
  let prefixedAlgorithm = null;
  let multihashLiteral = literal;
  const separator = literal.indexOf(":");
  if (separator > 0) {
    prefixedAlgorithm = literal.slice(0, separator).toLowerCase();
    multihashLiteral = literal.slice(separator + 1);
  }
  const canonical = canonicalizeMultihashHex(multihashLiteral, context);
  const bytes = Buffer.from(canonical, "hex");
  const functionCode = decodeVarintBuffer(bytes, 0, context);
  const digestLength = decodeVarintBuffer(bytes, functionCode.nextIndex, context);
  const payload = bytes.subarray(digestLength.nextIndex);
  if (payload.length !== digestLength.value) {
    rejectError(`${context} multihash payload length does not match its digest header`);
  }
  const entry = getCurveEntryByPublicKeyMulticodec(functionCode.value);
  if (!entry) {
    rejectError(`${context} uses unsupported multihash code 0x${functionCode.value.toString(16)}`);
  }
  if (
    prefixedAlgorithm &&
    prefixedAlgorithm !== entry.algorithm &&
    !(prefixedAlgorithm === "mldsa" && entry.algorithm === "ml-dsa")
  ) {
    rejectError(`${context} algorithm prefix does not match the multihash payload`);
  }
  validatePublicKeyForCurve(entry.id, payload, context);
  const fnHex = bytes.subarray(0, functionCode.nextIndex).toString("hex");
  const lenHex = bytes.subarray(functionCode.nextIndex, digestLength.nextIndex).toString("hex");
  const payloadHex = payload.toString("hex").toUpperCase();
  return `${fnHex}${lenHex}${payloadHex}`;
}

function normalizeManifestSignaturePayload(value, context) {
  let body;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    body = Buffer.from(value).toString("hex");
  } else if (Array.isArray(value)) {
    body = normalizeByteArray(value, context).toString("hex");
  } else {
    const literal = requireNonEmptyString(value, context).trim();
    body =
      literal.includes(":") && literal.indexOf(":") > 0
        ? literal.slice(literal.indexOf(":") + 1)
        : literal;
  }
  if (body.length === 0 || body.length % 2 !== 0 || !/^[0-9A-Fa-f]+$/u.test(body)) {
    rejectType(`${context} must be an even-length hexadecimal string`);
  }
  const canonical = body.toUpperCase();
  if (/^0+$/u.test(canonical)) {
    rejectType(`${context} must not be all zero`);
  }
  return canonical;
}

function normalizeManifestProvenancePayload(value, context) {
  const record = ensureRecord(value, context);
  return {
    signer: normalizeManifestPublicKeyPayload(record.signer, `${context}.signer`),
    signature: normalizeManifestSignaturePayload(record.signature, `${context}.signature`),
  };
}

function normalizeAccessSetHintsPayload(payload, context) {
  const record = ensureRecord(payload, context);
  const normalizeKeys = (value, name) => {
    if (value === undefined || value === null) {
      return [];
    }
    if (!Array.isArray(value)) {
      rejectType(`${name} must be an array of strings`);
    }
    return value.map((entry, index) =>
      requireNonEmptyString(entry, `${name}[${index}]`),
    );
  };
  const normalizeDynamicHints = (value, name) => {
    if (value === undefined || value === null) {
      return [];
    }
    if (!Array.isArray(value)) {
      rejectType(`${name} must be an array of dynamic access hints`);
    }
    return value.map((entry, index) => {
      const hint = ensureRecord(entry, `${name}[${index}]`);
      const hintContext = `${name}[${index}]`;
      const maxKeys = ToriiClient._normalizeUnsignedInteger(
        selectEqualManifestAlias(
          hint,
          "max_keys",
          "maxKeys",
          `${hintContext}.max_keys`,
        ),
        `${hintContext}.max_keys`,
        { max: KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS },
      );
      const keyType = requireExactNonEmptyString(
        selectEqualManifestAlias(
          hint,
          "key_type",
          "keyType",
          `${hintContext}.key_type`,
        ),
        `${hintContext}.key_type`,
      );
      if (!isKotodamaV1StateMapKeyTypeName(keyType)) {
        rejectType(`${hintContext}.key_type must be an exact Kotodama V1 StateMap key scalar`);
      }
      const baseKey = requireExactNonEmptyString(
        selectEqualManifestAlias(
          hint,
          "base_key",
          "baseKey",
          `${hintContext}.base_key`,
        ),
        `${hintContext}.base_key`,
      );
      if (!isCanonicalKotodamaDynamicAccessBaseKey(baseKey)) {
        rejectType(`${hintContext}.base_key must be state: plus one canonical state declaration identifier`);
      }
      const boundKind = requireExactNonEmptyString(
        selectEqualManifestAlias(
          hint,
          "bound_kind",
          "boundKind",
          `${hintContext}.bound_kind`,
        ),
        `${hintContext}.bound_kind`,
      );
      if (!isKotodamaV1DynamicAccessBoundKind(boundKind)) {
        rejectType(`${hintContext}.bound_kind must be exactly take or page`);
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
      record.read_keys ?? record.readKeys,
      `${context}.read_keys`,
    ),
    write_keys: normalizeKeys(
      record.write_keys ?? record.writeKeys,
      `${context}.write_keys`,
    ),
    dynamic_reads: normalizeDynamicHints(
      record.dynamic_reads ?? record.dynamicReads,
      `${context}.dynamic_reads`,
    ),
    dynamic_writes: normalizeDynamicHints(
      record.dynamic_writes ?? record.dynamicWrites,
      `${context}.dynamic_writes`,
    ),
  };
}

function selectEqualManifestAlias(record, snakeCase, camelCase, context) {
  const hasSnakeCase = Object.prototype.hasOwnProperty.call(record, snakeCase);
  const hasCamelCase = Object.prototype.hasOwnProperty.call(record, camelCase);
  if (
    hasSnakeCase &&
    hasCamelCase &&
    !Object.is(record[snakeCase], record[camelCase])
  ) {
    rejectType(`${context} contains conflicting ${snakeCase}/${camelCase} aliases`);
  }
  if (hasSnakeCase) {
    return record[snakeCase];
  }
  return hasCamelCase ? record[camelCase] : undefined;
}

function normalizeManifestEntrypointPayload(value, context) {
  const record = ensureRecord(value, context);
  const name = requireCanonicalKotodamaEntrypoint(record.name, `${context}.name`);
  const kind = normalizeManifestEntrypointKind(record.kind, `${context}.kind`);
  const permission = normalizeOptionalManifestString(
    record.permission,
    `${context}.permission`,
  );
  validateManifestEntrypointIdentityV1(name, kind.kind, permission, context);
  const params = normalizeManifestEntrypointParams(record.params, `${context}.params`);
  const argumentSchema = normalizeManifestArgumentSchema(
    record.argument_schema ?? record.argumentSchema,
    `${context}.argument_schema`,
  );
  if (params.length === 0 && argumentSchema !== null) {
    rejectType(`${context} has an argument schema but no parameters`);
  }
  if (params.length !== 0 && argumentSchema === null) {
    rejectType(`${context} has parameters but no exact argument schema`);
  }
  if (
    argumentSchema !== null &&
    (argumentSchema.fields.length !== params.length ||
      argumentSchema.fields.some(
        (field, index) =>
          field.name !== params[index].name ||
          analyzeManifestValueType(field.ty, `${context}.argument_schema.fields[${index}].ty`)
            .canonicalName !== params[index].type_name,
      ))
  ) {
    rejectType(`${context}.argument_schema does not exactly match its parameters`);
  }
  const returnType = normalizeOptionalManifestString(
    record.return_type ?? record.returnType,
    `${context}.return_type`,
  );
  const returnSchema = normalizeManifestValueType(
    record.return_schema ?? record.returnSchema,
    `${context}.return_schema`,
  );
  if (returnType === null || returnSchema === null) {
    rejectType(`${context} must declare return_type and return_schema together`);
  }
  if (
    returnSchema !== null
  ) {
    const analysis = analyzeManifestValueType(returnSchema, `${context}.return_schema`);
    if (analysis.canonicalName !== returnType) {
      rejectType(`${context}.return_schema does not match return_type`);
    }
    if (analysis.wordCount > MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1) {
      rejectType(`${context}.return_schema exceeds the V1 8192-word result table`);
    }
  }
  return {
    name,
    kind,
    params,
    argument_schema: argumentSchema,
    return_type: returnType,
    return_schema: returnSchema,
    permission,
    read_keys: normalizeManifestStringArray(
      record.read_keys ?? record.readKeys,
      `${context}.read_keys`,
    ),
    write_keys: normalizeManifestStringArray(
      record.write_keys ?? record.writeKeys,
      `${context}.write_keys`,
    ),
    access_hints_complete: normalizeOptionalManifestBoolean(
      record.access_hints_complete ?? record.accessHintsComplete,
      `${context}.access_hints_complete`,
    ),
    access_hints_skipped: normalizeManifestStringArray(
      record.access_hints_skipped ?? record.accessHintsSkipped,
      `${context}.access_hints_skipped`,
    ),
    triggers: normalizeManifestTriggersPayload(record.triggers, `${context}.triggers`),
  };
}

function normalizeManifestEntrypointParams(value, context) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  if (value.length > MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1) {
    rejectType(`${context} exceeds the V1 8192-parameter limit`);
  }
  const names = new Set();
  return value.map((param, index) => {
    const record = ensureRecord(param, `${context}[${index}]`);
    const name = requireCanonicalKotodamaIdentifier(
      record.name,
      `${context}[${index}].name`,
    );
    if (names.has(name)) {
      rejectType(`${context} contains duplicate parameter ${name}`);
    }
    names.add(name);
    return {
      name,
      type_name: requireExactNonEmptyString(
        selectEqualManifestAlias(
          record,
          "type_name",
          "typeName",
          `${context}[${index}].type_name`,
        ),
        `${context}[${index}].type_name`,
      ),
    };
  });
}

function normalizeManifestArgumentSchema(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  const record = ensureRecord(value, context);
  if (!Array.isArray(record.fields)) {
    rejectType(`${context}.fields must be an array`);
  }
  if (record.fields.length === 0 || record.fields.length > MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1) {
    rejectType(`${context}.fields must contain 1..8192 entries`);
  }
  const names = new Set();
  let wordCount = 0;
  const fields = record.fields.map((field, index) => {
      const fieldRecord = ensureRecord(field, `${context}.fields[${index}]`);
      const name = requireCanonicalKotodamaIdentifier(
        fieldRecord.name,
        `${context}.fields[${index}].name`,
      );
      if (names.has(name)) {
        rejectType(`${context}.fields contains duplicate name ${name}`);
      }
      names.add(name);
      const ty = normalizeRequiredManifestValueType(
        fieldRecord.ty,
        `${context}.fields[${index}].ty`,
      );
      wordCount += analyzeManifestValueType(ty, `${context}.fields[${index}].ty`).wordCount;
      return { name, ty };
    });
  if (wordCount > MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1) {
    rejectType(`${context} exceeds the V1 8192-word argument table`);
  }
  return { fields };
}

function normalizeManifestValueType(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  return normalizeRequiredManifestValueType(value, context);
}

function normalizeRequiredManifestValueType(value, context) {
  const record = ensureRecord(value, context);
  if (!Array.isArray(record.nodes)) {
    rejectType(`${context}.nodes must be an array`);
  }
  const normalized = {
    nodes: record.nodes.map((node, index) =>
      normalizeManifestValueTypeNode(node, `${context}.nodes[${index}]`),
    ),
  };
  analyzeManifestValueType(normalized, context);
  return normalized;
}

function normalizeManifestValueTypeNode(value, context) {
  const record = ensureRecord(value, context);
  const kind = requireNonEmptyString(record.kind, `${context}.kind`);
  switch (kind) {
    case "Struct": {
      const struct = ensureRecord(record.value, `${context}.value`);
      return {
        kind,
        value: {
          name: requireNonEmptyString(struct.name, `${context}.value.name`),
          fields: normalizeManifestStringArray(
            struct.fields,
            `${context}.value.fields`,
          ),
        },
      };
    }
    case "Tuple": {
      const arity = ToriiClient._normalizeUnsignedInteger(
        record.value,
        `${context}.value`,
        { allowZero: true },
      );
      if (arity > 0xffff) {
        rejectType(`${context}.value must fit in u16`);
      }
      return { kind, value: arity };
    }
    case "Unit":
    case "Option":
    case "Result":
      requireManifestNull(record.value, `${context}.value`);
      return { kind, value: null };
    case "List": {
      const list = ensureRecord(record.value, `${context}.value`);
      const fields = Object.keys(list);
      if (fields.length !== 1 || fields[0] !== "capacity") {
        rejectType(`${context}.value must contain exactly capacity; the element subtree follows in the nodes tape`);
      }
      const capacity = ToriiClient._normalizeUnsignedInteger(
        list.capacity,
        `${context}.value.capacity`,
        { allowZero: true },
      );
      if (capacity < 1 || capacity > 64) {
        rejectType(`${context}.value.capacity must be in the V1 range 1..64`);
      }
      return {
        kind,
        value: { capacity },
      };
    }
    case "Error":
      return { kind, value: normalizeContractErrorTypeV1(record.value, `${context}.value`) };
    case "Leaf":
      return {
        kind,
        value: normalizeManifestValueKind(record.value, `${context}.value`),
      };
    default:
      rejectType(`${context}.kind is not a V1 entrypoint value-type node`);
  }
}

function normalizeManifestValueKind(value, context) {
  const record = ensureRecord(value, context);
  const kind = requireNonEmptyString(record.kind, `${context}.kind`);
  const allowed = new Set([
    "Int",
    "Decimal",
    "Quantity",
    "Bool",
    "String",
    "Json",
    "Name",
    "AccountId",
    "AssetDefinitionId",
    "AssetId",
    "DomainId",
    "NftId",
    "DataSpaceId",
    "Blob",
  ]);
  if (!allowed.has(kind)) {
    rejectType(`${context}.kind is not a V1 entrypoint value kind`);
  }
  requireManifestNull(record.value, `${context}.value`);
  return { kind, value: null };
}

function analyzeManifestValueType(value, context) {
  return analyzeEntrypointValueTypeV1(value, context);
}
function normalizeOptionalManifestString(value, context) {
  return value === undefined || value === null
    ? null
    : requireExactNonEmptyString(value, context);
}

function normalizeOptionalManifestBoolean(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== "boolean") {
    rejectType(`${context} must be a boolean`);
  }
  return value;
}

function normalizeManifestStringArray(value, context) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  return value.map((entry, index) =>
    requireExactNonEmptyString(entry, `${context}[${index}]`),
  );
}

function requireManifestNull(value, context) {
  if (value !== undefined && value !== null) {
    rejectType(`${context} must be null`);
  }
}

function normalizeManifestStatesPayload(value, context) {
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  return value.map((state, index) => {
    const record = ensureRecord(state, `${context}[${index}]`);
    const typeName = requireExactNonEmptyString(
      selectEqualManifestAlias(
        record,
        "type_name",
        "typeName",
        `${context}[${index}].type_name`,
      ),
      `${context}[${index}].type_name`,
    );
    if (!isCanonicalKotodamaStateTypeName(typeName)) {
      rejectType(`${context}[${index}].type_name must be a canonical Kotodama V1 state type`);
    }
    return {
      name: requireCanonicalKotodamaIdentifier(
        record.name,
        `${context}[${index}].name`,
        { declaration: true },
      ),
      type_name: typeName,
    };
  });
}

function normalizeManifestErrorTypesPayload(value, context) {
  return normalizeContractErrorTypesV1(value, context);
}

function normalizeManifestTriggersPayload(value, context) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  return value.map((trigger, index) => {
    const record = ensureRecord(trigger, `${context}[${index}]`);
    const callback = ensureRecord(record.callback, `${context}[${index}].callback`);
    const metadata = ensureRecord(record.metadata ?? {}, `${context}[${index}].metadata`);
    const id = requireCanonicalKotodamaIdentifier(
      record.id,
      `${context}[${index}].id`,
      { declaration: true },
    );
    const namespace =
      callback.namespace === undefined || callback.namespace === null
        ? null
        : requireCanonicalKotodamaIdentifier(
            callback.namespace,
            `${context}[${index}].callback.namespace`,
            { typeDeclaration: true },
          );
    return {
      id,
      repeats: normalizeManifestRepeatsPayload(
        record.repeats,
        `${context}[${index}].repeats`,
      ),
      filter: normalizeRequiredExactBase64Payload(
        record.filter,
        `${context}[${index}].filter`,
      ),
      authority:
        record.authority === undefined || record.authority === null
          ? null
          : normalizeAccountId(record.authority, `${context}[${index}].authority`),
      metadata: cloneJsonValue(metadata, `${context}[${index}].metadata`),
      callback: {
        namespace,
        entrypoint: requireCanonicalKotodamaEntrypoint(
          callback.entrypoint,
          `${context}[${index}].callback.entrypoint`,
        ),
      },
    };
  });
}

function normalizeManifestRepeatsPayload(value, context) {
  const record = ensureRecord(value, context);
  const keys = Object.keys(record);
  if (keys.length !== 1) {
    rejectType(`${context} must contain exactly one repeat variant`);
  }
  if (keys[0] === "Indefinitely") {
    requireManifestNull(record.Indefinitely, `${context}.Indefinitely`);
    return { Indefinitely: null };
  }
  if (keys[0] === "Exactly") {
    const count = ToriiClient._normalizeUnsignedInteger(
      record.Exactly,
      `${context}.Exactly`,
      { allowZero: true },
    );
    if (count > 0xffff_ffff) {
      rejectType(`${context}.Exactly must fit in u32`);
    }
    return { Exactly: count };
  }
  rejectType(`${context} must be Indefinitely or Exactly`);
}

function normalizeOptionalExactBase64Payload(value, name) {
  return value === undefined || value === null
    ? null
    : normalizeRequiredExactBase64Payload(value, name);
}

function normalizeRequiredBase64Payload(value, name) {
  if (typeof value === JS_TYPE_STRING) {
    const trimmed = value.trim();
    if (!trimmed) {
      throw createValidationError(
        ValidationErrorCode.INVALID_STRING,
        `${name} must be a non-empty base64 string`,
        name,
      );
    }
    try {
      const decoded = strictDecodeBase64(trimmed);
      return Buffer.from(decoded).toString("base64");
    } catch (error) {
      throw createValidationError(
        ValidationErrorCode.INVALID_STRING,
        `${name} must be a valid base64 string`,
        name,
        error instanceof Error ? error : undefined,
      );
    }
  }
  const buffer = toBuffer(value);
  if (buffer.length === 0) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${name} must be a non-empty base64 string`,
      name,
    );
  }
  return Buffer.from(buffer).toString("base64");
}

function normalizeRequiredExactBase64Payload(value, name) {
  if (typeof value === JS_TYPE_STRING) {
    if (!value || value.trim() !== value || /\s/u.test(value)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_STRING,
        `${name} must be exact standard-base64`,
        name,
      );
    }
    try {
      const decoded = strictDecodeBase64(value);
      const canonical = Buffer.from(decoded).toString("base64");
      if (canonical !== value) {
        rejectError("noncanonical base64 payload");
      }
      return canonical;
    } catch (error) {
      throw createValidationError(
        ValidationErrorCode.INVALID_STRING,
        `${name} must be exact standard-base64`,
        name,
        error instanceof Error ? error : undefined,
      );
    }
  }
  const buffer = toBuffer(value);
  if (buffer.length === 0) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${name} must be exact standard-base64`,
      name,
    );
  }
  return Buffer.from(buffer).toString("base64");
}

function normalizeOptionalHex32(value, name) {
  if (value === undefined) {
    return undefined;
  }
  if (value === null) {
    return null;
  }
  return normalizeIrohaHashHex32(value, name);
}

function normalizeIrohaHashHex32(value, name) {
  const hex = normalizeHex32String(value, name);
  if ((Number.parseInt(hex.slice(-2), 16) & 1) !== 1) {
    rejectType(`${name} must set the Iroha Hash marker bit`);
  }
  return hex;
}

function normalizeHex32String(value, name, options = {}) {
    const allowShort = options.allowShort === true;
    const allowScheme = options.allowScheme === true;
    const exactString = options.exactString === true;
  const schemeName =
    typeof options.scheme === JS_TYPE_STRING && options.scheme.trim()
      ? options.scheme.trim().toLowerCase()
      : "blake2b32";
  if (Buffer.isBuffer(value)) {
    return normalizeHex32String(value.toString("hex"), name, options);
  }
  if (ArrayBuffer.isView(value)) {
    return normalizeHex32String(
      Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString("hex"),
      name,
      options,
    );
  }
  if (value instanceof ArrayBuffer) {
    return normalizeHex32String(Buffer.from(value).toString("hex"), name, options);
  }
  if (Array.isArray(value)) {
    return normalizeHex32String(normalizeByteArray(value, name).toString("hex"), name, options);
  }
  let normalized = exactString
    ? requireExactNonEmptyString(value, name)
    : requireNonEmptyString(value, name);
  if (allowScheme && normalized.includes(":")) {
    const separator = normalized.indexOf(":");
    const scheme = normalized.slice(0, separator);
    const rest = normalized.slice(separator + 1);
    if (!scheme || scheme.toLowerCase() !== schemeName) {
      throw createValidationError(
        ValidationErrorCode.INVALID_HEX,
        `${name} must be a 32-byte hex string`,
        name,
      );
    }
    normalized = exactString ? rest : rest.trim();
  }
  const hex =
    normalized.startsWith("0x") || normalized.startsWith("0X")
      ? normalized.slice(2)
      : normalized;
  const isValidLength =
    allowShort && hex.length > 0 && hex.length % 2 === 0 ? hex.length <= 64 : hex.length === 64;
  if (!isValidLength || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must be a 32-byte hex string`,
      name,
    );
  }
  return hex.toLowerCase();
}

function normalizeHex16String(value, name) {
  if (Buffer.isBuffer(value)) {
    return normalizeHex16String(value.toString("hex"), name);
  }
  if (ArrayBuffer.isView(value)) {
    return normalizeHex16String(
      Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString("hex"),
      name,
    );
  }
  if (value instanceof ArrayBuffer) {
    return normalizeHex16String(Buffer.from(value).toString("hex"), name);
  }
  if (Array.isArray(value)) {
    return normalizeHex16String(normalizeByteArray(value, name).toString("hex"), name);
  }
  const normalized = requireNonEmptyString(value, name);
  const hex =
    normalized.startsWith("0x") || normalized.startsWith("0X")
      ? normalized.slice(2)
      : normalized;
  if (hex.length !== 32 || !/^[0-9a-fA-F]+$/u.test(hex)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must be a 16-byte hex string`,
      name,
    );
  }
  return hex.toLowerCase();
}

function normalizeNonZeroHex32String(value, name) {
  return normalizeNonZeroHexBytesString(value, name, 32);
}

function normalizeHexBytesString(value, name) {
  if (Buffer.isBuffer(value)) {
    return value.toString("hex");
  }
  if (ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString("hex");
  }
  if (value instanceof ArrayBuffer) {
    return Buffer.from(value).toString("hex");
  }
  if (Array.isArray(value)) {
    return normalizeByteArray(value, name).toString("hex");
  }
  const normalized = requireHexString(value, name);
  const hex =
    normalized.startsWith("0x") || normalized.startsWith("0X")
      ? normalized.slice(2)
      : normalized;
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must be a non-empty byte-aligned hex string`,
      name,
    );
  }
  return hex.toLowerCase();
}

function normalizeNonZeroHexBytesString(value, name, expectedByteLength) {
  const hex = normalizeHexBytesString(value, name);
  if (hex.length === 0) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must be a non-empty byte-aligned hex string`,
      name,
    );
  }
  if (/^(?:00)+$/.test(hex)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must not be all zero`,
      name,
    );
  }
  if (expectedByteLength !== undefined && hex.length !== expectedByteLength * 2) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must be a ${expectedByteLength}-byte hex string`,
      name,
    );
  }
  return hex;
}

function parseHashLiteralToHex(literal, name) {
  const match = /^hash:([0-9A-Fa-f]{64})#([0-9A-Fa-f]{4})$/.exec(literal);
  if (!match) {
    rejectType(`${name} must be a canonical "hash:<HEX>#<CRC>" literal or hex string`);
  }
  const [, body, checksum] = match;
  const expected = computeHashLiteralCrc("hash", body.toUpperCase());
  if (expected !== checksum.toUpperCase()) {
    rejectType(`${name} has invalid checksum; expected ${expected}`);
  }
  const hex = body.toLowerCase();
  if ((Number.parseInt(hex.slice(-2), 16) & 1) !== 1) {
    rejectType(`${name} must set the Iroha Hash marker bit`);
  }
  return hex;
}

function cloneJsonValue(value, path, { nullPrototype = false } = {}) {
  return cloneJsonValueInternal(value, path, {
    ancestors: new Set(),
    nodes: 0,
    nullPrototype,
  }, 0);
}

function cloneJsonValueInternal(value, path, state, depth) {
  state.nodes += 1;
  if (state.nodes > JSON_CLONE_MAX_NODES) {
    rejectRange(`${path} exceeds the ${JSON_CLONE_MAX_NODES}-node JSON value limit`);
  }
  if (depth > JSON_CLONE_MAX_DEPTH) {
    rejectRange(`${path} exceeds the ${JSON_CLONE_MAX_DEPTH}-level JSON nesting limit`);
  }
  if (
    value === null ||
    typeof value === JS_TYPE_STRING ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === JS_TYPE_NUMBER) {
    if (!Number.isFinite(value)) {
      rejectType(`${path} must not contain non-finite numbers`);
    }
    return value;
  }
  if (typeof value === JS_TYPE_BIGINT) {
    return value.toString(10);
  }
  if (typeof value !== JS_TYPE_OBJECT) {
    rejectType(`${path} contains unsupported value type: ${typeof value}`);
  }
  if (state.ancestors.has(value)) {
    rejectType(`${path} must not contain cyclic references`);
  }
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
      const length = lengthDescriptor?.value;
      if (!Number.isSafeInteger(length) || length < 0) {
        rejectType(`${path} must be an exact JSON array`);
      }
      if (length > JSON_CLONE_MAX_NODES) {
        rejectRange(`${path} exceeds the ${JSON_CLONE_MAX_NODES}-node JSON value limit`);
      }
      const ownKeys = Reflect.ownKeys(value);
      if (
        ownKeys.length !== length + 1 ||
        ownKeys.some(
          (key, index) =>
            (index < length && key !== String(index)) ||
            (index === length && key !== "length"),
        )
      ) {
        rejectType(`${path} must be a dense exact JSON array`);
      }
      const result = new Array(length);
      for (let index = 0; index < length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
          rejectType(`${path}[${index}] must be an enumerable data property`);
        }
        result[index] = cloneJsonValueInternal(
          descriptor.value,
          `${path}[${index}]`,
          state,
          depth + 1,
        );
      }
      return result;
    }
    const result = state.nullPrototype ? Object.create(null) : {};
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== JS_TYPE_STRING) {
        rejectType(`${path} keys must be strings without symbols`);
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        rejectType(`${path}.${key} must be an enumerable data property`);
      }
      Object.defineProperty(result, key, {
        value: cloneJsonValueInternal(
          descriptor.value,
          `${path}.${key}`,
          state,
          depth + 1,
        ),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return result;
  } finally {
    state.ancestors.delete(value);
  }
}

function normalizeSpaceDirectoryManifestPayload(input, context) {
  const manifest = cloneJsonValue(input, context);
  return normalizeUaidManifest(manifest, context);
}


function normalizePublishSpaceDirectoryManifestRequest(input) {
  const candidate = ensureRecord(input, "publishSpaceDirectoryManifest request");
  rejectPrivateKeyFields(candidate, "publishSpaceDirectoryManifest");
  const record = requireExactUaidRecord(
    candidate,
    ["authority", "manifest"],
    ["reason"],
    "publishSpaceDirectoryManifest request",
  );
  const manifest = normalizeSpaceDirectoryManifestPayload(
    record.manifest,
    "publishSpaceDirectoryManifest.manifest",
  );
  const payload = {
    authority: requireExactAccountId(
      record.authority,
      "publishSpaceDirectoryManifest.authority",
    ),
    manifest,
  };
  if (Object.prototype.hasOwnProperty.call(record, "reason")) {
    if (record.reason === null) {
      rejectType("publishSpaceDirectoryManifest.reason must be omitted instead of null");
    }
    if (typeof record.reason !== JS_TYPE_STRING) {
      rejectType("publishSpaceDirectoryManifest.reason must be a string");
    }
    payload.reason = record.reason;
  }
  return payload;
}

function normalizeRevokeSpaceDirectoryManifestRequest(input) {
  const candidate = ensureRecord(input, "revokeSpaceDirectoryManifest request");
  rejectPrivateKeyFields(candidate, "revokeSpaceDirectoryManifest");
  const record = requireExactUaidRecord(
    candidate,
    ["authority", "uaid", "dataspaceId", "revokedEpoch"],
    ["reason"],
    "revokeSpaceDirectoryManifest request",
  );
  const uaid = normalizeUaidLiteral(
    record.uaid,
    "revokeSpaceDirectoryManifest.uaid",
  );
  const dataspace = requireExactJsonUnsignedInteger(
    record.dataspaceId,
    "revokeSpaceDirectoryManifest.dataspace",
    { allowZero: true },
  );
  const revokedEpoch = requireExactJsonUnsignedInteger(
    record.revokedEpoch,
    "revokeSpaceDirectoryManifest.revokedEpoch",
    { allowZero: true },
  );
  const payload = {
    authority: requireExactAccountId(
      record.authority,
      "revokeSpaceDirectoryManifest.authority",
    ),
    uaid,
    dataspace,
    revoked_epoch: revokedEpoch,
  };
  if (Object.prototype.hasOwnProperty.call(record, "reason")) {
    if (record.reason === null) {
      rejectType("revokeSpaceDirectoryManifest.reason must be omitted instead of null");
    }
    if (typeof record.reason !== JS_TYPE_STRING) {
      rejectType("revokeSpaceDirectoryManifest.reason must be a string");
    }
    payload.reason = record.reason;
  }
  return payload;
}


function normalizeSetContractAliasRequest(input) {
  const record = ensureRecord(input, "setContractAlias request");
  const credentials = normalizeSecretFreeAuthority(record, "setContractAlias");
  const contractAddress = record.contract_address ?? record.contractAddress;
  const payload = {
    ...credentials,
    contract_address: requireNonEmptyString(
      contractAddress,
      "setContractAlias.contractAddress",
    ),
    contract_alias: null,
  };
  const contractAlias = record.contract_alias ?? record.contractAlias;
  if (contractAlias !== undefined && contractAlias !== null) {
    payload.contract_alias = requireNonEmptyString(
      contractAlias,
      "setContractAlias.contractAlias",
    );
  }
  const leaseExpiryValue = record.lease_expiry_ms ?? record.leaseExpiryMs;
  if (leaseExpiryValue !== undefined && leaseExpiryValue !== null) {
    if (payload.contract_alias === null) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        "setContractAlias.leaseExpiryMs requires contractAlias",
        "setContractAlias.leaseExpiryMs",
      );
    }
    const leaseExpiryMs = coerceInteger(
      leaseExpiryValue,
      "setContractAlias.leaseExpiryMs",
    );
    if (leaseExpiryMs < 0) {
      throw createValidationError(
        ValidationErrorCode.INVALID_NUMERIC,
        "setContractAlias.leaseExpiryMs must be a non-negative integer",
        "setContractAlias.leaseExpiryMs",
      );
    }
    payload.lease_expiry_ms = leaseExpiryMs;
  }
  return payload;
}

function normalizeSetContractAliasResponse(payload) {
  const record = ensureRecord(payload, "setContractAlias response");
  const draft = normalizeAppApiTransactionDraft(
    record,
    "setContractAlias response",
    ["contract_alias", "contract_address", "dataspace"],
  );
  return {
    ...draft,
    contract_alias:
      record.contract_alias === undefined || record.contract_alias === null
        ? null
        : requireNonEmptyString(
            record.contract_alias,
            "setContractAlias.response.contract_alias",
          ),
    contract_address: requireNonEmptyString(
      record.contract_address,
      "setContractAlias.response.contract_address",
    ),
    dataspace: requireNonEmptyString(
      record.dataspace,
      "setContractAlias.response.dataspace",
    ),
  };
}

function normalizeAppApiTransactionDraft(
  input,
  context,
  additionalFields = [],
) {
  const record = ensureRecord(input, context);
  assertSupportedOptionKeys(
    record,
    new Set([
      "submitted",
      "transaction_payload_b64",
      "signing_message_b64",
      ...additionalFields,
    ]),
    context,
  );
  if (requireExactBoolean(record.submitted, `${context}.submitted`) !== false) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.submitted must be false`,
      `${context}.submitted`,
    );
  }
  const transactionPayloadB64 = record.transaction_payload_b64;
  const transactionPayload = decodeVerifyingKeyDraftBase64(
    transactionPayloadB64,
    `${context}.transaction_payload_b64`,
    {
      maxBytes: VERIFYING_KEY_TRANSACTION_PAYLOAD_MAX_BYTES,
      limitLabel: "transaction payload",
    },
  );
  const signingMessageB64 = record.signing_message_b64;
  const signingMessage = decodeVerifyingKeyDraftBase64(
    signingMessageB64,
    `${context}.signing_message_b64`,
    { exactBytes: 32 },
  );
  if (!timingSafeEqual(signingMessage, irohaPrehash(transactionPayload))) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.signing_message_b64 must equal the canonical Iroha HashOf(transaction_payload_b64)`,
      `${context}.signing_message_b64`,
    );
  }
  return {
    submitted: false,
    transaction_payload_b64: transactionPayloadB64,
    signing_message_b64: signingMessageB64,
  };
}

const {
  normalizeGovernanceBallotIdentity,
  normalizeGovernanceBallotResponse,
  normalizeGovernanceDeployContractProposalPayload,
  normalizeGovernanceDraftResponse,
  normalizeGovernanceProposalDraftResponseV1,
  normalizeGovernancePlainBallotPayload,
  normalizeGovernanceZkBallotProofPayload,
  normalizeGovernanceZkBallotV1Payload,
  normalizeMinistryAgendaProposalDraftRequest,
  normalizeMinistryAgendaProposalDraftResponse,
  normalizeMinistryAgendaProposalGetResponse,
  normalizeTriggerMutationResponse,
} = createToriiGovernanceNormalizers({
  LocalSigningContext,
  NetworkId,
  ToriiClient,
  ValidationErrorCode,
  assertSupportedOptionKeys,
  createValidationError,
  ensureCanonicalAccountId,
  ensureRecord,
  isPlainObject,
  normalizeArbitraryHex,
  normalizeErrorPath,
  normalizeGovernanceUint64Integer,
  normalizeHex32String,
  normalizeManifestProvenancePayload,
  normalizeNetworkId(value, context) {
    networkIdBytes(value, context);
    return value.toString();
  },
  normalizeVpnSessionOptions,
  networkIdBytes,
  normalizeQuantityInput,
  normalizeRequiredBase64Payload,
  normalizeUint64DecimalString,
  requireCanonicalTransactionHashString,
  requireExactNonEmptyString,
  requireExactTokenString,
  requireGovernanceSelectorString,
  requireNonEmptyString,
});

function normalizeArbitraryHex(value, name) {
  const normalized = requireHexString(value, name);
  const hex =
    normalized.startsWith("0x") || normalized.startsWith("0X")
      ? normalized.slice(2)
      : normalized;
  return hex.toLowerCase();
}

function contractAliasDataspaceSegment(value, context) {
  const literal = requireExactNonEmptyString(value, context);
  if (/[@#$\s]/u.test(literal)) {
    rejectType(`${context} must use canonical contract-alias syntax`);
  }
  const separator = literal.indexOf("::");
  if (
    separator <= 0
    || separator !== literal.lastIndexOf("::")
    || separator + 2 >= literal.length
  ) {
    rejectType(`${context} must use <name>::<dataspace> or <name>::<domain>.<dataspace>`);
  }
  const name = literal.slice(0, separator);
  const scopeParts = literal.slice(separator + 2).split(".");
  if (
    scopeParts.length < 1
    || scopeParts.length > 2
    || [name, ...scopeParts].some(
      (segment) => segment.length === 0 || segment.includes(":"),
    )
  ) {
    rejectType(`${context} contains an invalid alias segment`);
  }
  return scopeParts[scopeParts.length - 1];
}

function normalizeContractTargetSelector(record, context) {
  const contractAddress = pickOverride(record, "contract_address", "contractAddress");
  const contractAlias = pickOverride(record, "contract_alias", "contractAlias");
  const hasContractAddress = contractAddress !== undefined && contractAddress !== null;
  const hasContractAlias = contractAlias !== undefined && contractAlias !== null;
  if (hasContractAddress === hasContractAlias) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} requires exactly one of contract_address or contract_alias`,
      normalizeErrorPath(context),
    );
  }
  if (hasContractAddress) {
    const normalizedAddress = requireExactNonEmptyString(
      contractAddress,
      `${context}.contract_address`,
    );
    parseCanonicalContractAddress(
      normalizedAddress,
      `${context}.contract_address`,
    );
    return {
      contract_address: normalizedAddress,
    };
  }
  const normalizedAlias = requireExactNonEmptyString(
    contractAlias,
    `${context}.contract_alias`,
  );
  contractAliasDataspaceSegment(
    normalizedAlias,
    `${context}.contract_alias`,
  );
  return {
    contract_alias: normalizedAlias,
  };
}

function normalizeLocalTransactionDraftIntent(input, context, required) {
  const record = ensureRecord(input, `${context} request`);
  const raw = pickOverride(record, "draft_intent", "draftIntent");
  if (raw === undefined || raw === null) {
    if (required) {
      rejectType(`${context} requires a caller-trusted draftIntent for unsigned preparation`);
    }
    return null;
  }
  const intent = ensureRecord(raw, `${context}.draftIntent`);
  assertSupportedOptionKeys(
    intent,
    new Set(["executableB64", "metadataB64"]),
    `${context}.draftIntent`,
  );
  const executableB64 = normalizeRequiredExactBase64Payload(
    intent.executableB64,
    `${context}.draftIntent.executableB64`,
  );
  const metadataB64 = normalizeRequiredExactBase64Payload(
    intent.metadataB64,
    `${context}.draftIntent.metadataB64`,
  );
  return Object.freeze({
    executableArchive: Buffer.from(strictDecodeBase64(executableB64)),
    metadataArchive: Buffer.from(strictDecodeBase64(metadataB64)),
  });
}

function normalizeContractCallDraftIntent(input, context) {
  const record = ensureRecord(input, `${context} request`);
  const raw = pickOverride(record, "draft_intent", "draftIntent");
  if (raw === undefined || raw === null) {
    rejectType(`${context} requires a caller-trusted draftIntent for unsigned preparation`);
  }
  const intent = ensureRecord(raw, `${context}.draftIntent`);
  assertSupportedOptionKeys(
    intent,
    new Set([
      "executableB64",
      "metadataB64",
      "contractAddress",
      "codeHashHex",
      "payloadDigestHex",
    ]),
    `${context}.draftIntent`,
  );
  const executableB64 = normalizeRequiredExactBase64Payload(
    intent.executableB64,
    `${context}.draftIntent.executableB64`,
  );
  const metadataB64 = normalizeRequiredExactBase64Payload(
    intent.metadataB64,
    `${context}.draftIntent.metadataB64`,
  );
  const contractAddress = requireExactNonEmptyString(
    intent.contractAddress,
    `${context}.draftIntent.contractAddress`,
  );
  parseCanonicalContractAddress(
    contractAddress,
    `${context}.draftIntent.contractAddress`,
  );
  return Object.freeze({
    executableArchive: Buffer.from(strictDecodeBase64(executableB64)),
    metadataArchive: Buffer.from(strictDecodeBase64(metadataB64)),
    contractAddress,
    codeHashHex: requireExactLowerHex32String(
      intent.codeHashHex,
      `${context}.draftIntent.codeHashHex`,
    ),
    payloadDigestHex: requireExactLowerHex32String(
      intent.payloadDigestHex,
      `${context}.draftIntent.payloadDigestHex`,
    ),
  });
}

function requireLocalDraftSigningContext(localSigningContext, context) {
  if (!(localSigningContext instanceof LocalSigningContext)) {
    rejectType(`${context} requires ToriiClient options.localSigningContext`);
  }
  return localSigningContext;
}

function normalizeContractCallRequest(input) {
  const record = ensureRecord(input, "contractCall request");
  rejectPrivateKeyFields(record, "contractCall");
  rejectRetiredFeeSelectionFields(record, "contractCall request", {
    allowGasLimit: false,
  });
  const normalized = {
    authority: ToriiClient._normalizeAccountId(
      record.authority,
      "contractCall.authority",
    ),
    ...normalizeContractTargetSelector(record, "contractCall"),
  };
  normalized.entrypoint = requireNonEmptyString(
    record.entrypoint,
    "contractCall.entrypoint",
  );
  if (record.payload !== undefined) {
    normalized.payload = cloneJsonValue(record.payload, "contractCall.payload");
  }
  if (record.metadata !== undefined) {
    normalized.metadata = cloneJsonValue(
      ensureRecord(record.metadata, "contractCall.metadata"),
      "contractCall.metadata",
    );
  }
  const creationTimeMs = record.creation_time_ms ?? record.creationTimeMs;
  if (creationTimeMs !== undefined && creationTimeMs !== null) {
    normalized.creation_time_ms = ToriiClient._normalizeUnsignedInteger(
      creationTimeMs,
      "contractCall.creationTimeMs",
      { allowZero: false },
    );
  }
  const transactionTtlMs =
    record.transaction_ttl_ms ?? record.transactionTtlMs;
  if (transactionTtlMs !== undefined && transactionTtlMs !== null) {
    normalized.transaction_ttl_ms = ToriiClient._normalizeUnsignedInteger(
      transactionTtlMs,
      "contractCall.transactionTtlMs",
    );
  }
  normalized.fee_payment = normalizeFeePaymentIntentValue(
    record.fee_payment ?? record.feePayment,
    "contractCall.fee_payment",
    { requireGasLimit: true },
  );
  return normalized;
}

function normalizeContractOperationReceipt(payload, context) {
  const receipt = ensureRecord(payload, context);
  assertSupportedOptionKeys(
    receipt,
    new Set([
      "operation_kind",
      "status",
      "transport",
      "dataspace",
      "contract_alias",
      "contract_address",
      "code_hash_hex",
      "abi_hash_hex",
      "tx_hash_hex",
      "entrypoint",
      "entrypoint_hash_hex",
      "gas_limit",
      "gas_used",
      "fee_payment",
      "payload_digest_hex",
    ]),
    context,
  );
  const optionalString = (value, field) =>
    value === undefined || value === null
      ? null
      : requireExactNonEmptyString(value, field);
  const optionalHash = (value, field) =>
    value === undefined || value === null
      ? null
      : requireExactLowerHex32String(value, field);
  return {
    operation_kind: requireExactNonEmptyString(
      receipt.operation_kind,
      `${context}.operation_kind`,
    ),
    status: requireExactNonEmptyString(receipt.status, `${context}.status`),
    transport: requireExactNonEmptyString(receipt.transport, `${context}.transport`),
    dataspace: requireExactNonEmptyString(receipt.dataspace, `${context}.dataspace`),
    contract_alias: optionalString(receipt.contract_alias, `${context}.contract_alias`),
    contract_address: optionalString(receipt.contract_address, `${context}.contract_address`),
    code_hash_hex: optionalHash(receipt.code_hash_hex, `${context}.code_hash_hex`),
    abi_hash_hex: optionalHash(receipt.abi_hash_hex, `${context}.abi_hash_hex`),
    tx_hash_hex:
      receipt.tx_hash_hex === undefined || receipt.tx_hash_hex === null
        ? null
        : requireCanonicalTransactionHashString(
            receipt.tx_hash_hex,
            `${context}.tx_hash_hex`,
          ),
    entrypoint: optionalString(receipt.entrypoint, `${context}.entrypoint`),
    entrypoint_hash_hex: optionalHash(
      receipt.entrypoint_hash_hex,
      `${context}.entrypoint_hash_hex`,
    ),
    gas_limit:
      receipt.gas_limit === undefined || receipt.gas_limit === null
        ? null
        : requireExactJsonUnsignedInteger(receipt.gas_limit, `${context}.gas_limit`, {
            allowZero: false,
          }),
    gas_used:
      receipt.gas_used === undefined || receipt.gas_used === null
        ? null
        : requireExactJsonUnsignedInteger(receipt.gas_used, `${context}.gas_used`, {
            allowZero: true,
          }),
    fee_payment:
      receipt.fee_payment === undefined || receipt.fee_payment === null
        ? null
        : normalizeFeePaymentIntentValue(
            receipt.fee_payment,
            `${context}.fee_payment`,
          ),
    payload_digest_hex: requireExactLowerHex32String(
      receipt.payload_digest_hex,
      `${context}.payload_digest_hex`,
    ),
  };
}

function normalizeContractCallResponse(payload) {
  const context = "contractCall response";
  const record = ensureRecord(payload, context);
  assertSupportedOptionKeys(
    record,
    new Set([
      "ok",
      "submitted",
      "dataspace",
      "contract_address",
      "code_hash_hex",
      "abi_hash_hex",
      "creation_time_ms",
      "transaction_ttl_ms",
      "tx_hash_hex",
      "pipeline_status",
      "entrypoint_hash_hex",
      "transaction_payload_b64",
      "signing_message_b64",
      "entrypoint",
      "operation_receipt",
    ]),
    context,
  );
  const normalized = {
    ok: requireExactBoolean(record.ok, `${context}.ok`),
    submitted: requireExactBoolean(record.submitted, `${context}.submitted`),
    dataspace: requireExactNonEmptyString(record.dataspace, `${context}.dataspace`),
    code_hash_hex: requireExactLowerHex32String(record.code_hash_hex, `${context}.code_hash_hex`),
    abi_hash_hex: requireExactLowerHex32String(record.abi_hash_hex, `${context}.abi_hash_hex`),
    creation_time_ms: requireExactJsonUnsignedInteger(record.creation_time_ms, `${context}.creation_time_ms`, { allowZero: true }),
    transaction_ttl_ms:
      record.transaction_ttl_ms === undefined || record.transaction_ttl_ms === null
        ? null
        : requireExactJsonUnsignedInteger(
            record.transaction_ttl_ms,
            `${context}.transaction_ttl_ms`,
            { allowZero: false },
          ),
  };
  if (record.contract_address !== undefined && record.contract_address !== null) {
    normalized.contract_address = requireExactNonEmptyString(
      record.contract_address,
      `${context}.contract_address`,
    );
  }
  normalized.tx_hash_hex =
    record.tx_hash_hex === undefined || record.tx_hash_hex === null
      ? null
      : requireCanonicalTransactionHashString(
          record.tx_hash_hex,
          `${context}.tx_hash_hex`,
        );
  normalized.entrypoint_hash_hex =
    record.entrypoint_hash_hex === undefined || record.entrypoint_hash_hex === null
      ? null
      : requireCanonicalTransactionHashString(
          record.entrypoint_hash_hex,
          `${context}.entrypoint_hash_hex`,
        );
  normalized.entrypoint =
    record.entrypoint === undefined || record.entrypoint === null
      ? null
      : requireExactNonEmptyString(
          record.entrypoint,
          `${context}.entrypoint`,
        );
  normalized.transaction_payload_b64 = normalizeOptionalExactBase64Payload(record.transaction_payload_b64, `${context}.transaction_payload_b64`);
  normalized.signing_message_b64 = normalizeOptionalExactBase64Payload(record.signing_message_b64, `${context}.signing_message_b64`);
  if (record.pipeline_status !== undefined) {
    normalized.pipeline_status =
      record.pipeline_status === null
        ? null
        : normalizePipelineTransactionStatus(
            record.pipeline_status,
            `${context}.pipeline_status`,
          );
  }

  normalized.operation_receipt = normalizeContractOperationReceipt(record.operation_receipt, `${context}.operation_receipt`);
  return normalized;
}

async function normalizeContractCallDraftResponse(
  payload,
  request,
  draftIntent,
  localSigningContext,
) {
  const response = normalizeContractCallResponse(payload);
  const receipt = response.operation_receipt;
  if (!response.ok || response.submitted) {
    rejectType("contractCall draft must be successful and not submitted");
  }
  if (
    response.tx_hash_hex !== null ||
    response.entrypoint_hash_hex !== null ||
    response.pipeline_status != null
  ) {
    rejectType("contractCall draft must not contain submission state");
  }
  normalizeAppApiTransactionDraft(
    {
      submitted: response.submitted,
      transaction_payload_b64: response.transaction_payload_b64,
      signing_message_b64: response.signing_message_b64,
    },
    "contractCall response",
  );
  if (
    response.entrypoint !== request.entrypoint ||
    receipt.operation_kind !== "contract_call" ||
    receipt.status !== "pending_signature" ||
    receipt.entrypoint !== request.entrypoint ||
    receipt.tx_hash_hex !== null ||
    receipt.entrypoint_hash_hex !== null
  ) {
    rejectType("contractCall draft is not bound to the requested entrypoint");
  }
  if (
    receipt.transport !== "torii"
    || receipt.dataspace !== response.dataspace
    || receipt.gas_used !== null
  ) {
    rejectType("contractCall operation_receipt does not match the exact pending draft context");
  }
  const expectedResponseTtl = request.transaction_ttl_ms ?? null;
  if (response.transaction_ttl_ms !== expectedResponseTtl) {
    rejectType("contractCall draft transaction_ttl_ms is not bound to the request");
  }
  if (
    request.creation_time_ms !== undefined
    && response.creation_time_ms !== request.creation_time_ms
  ) {
    rejectType("contractCall draft creation_time_ms is not bound to the request");
  }
  if (
    response.contract_address !== draftIntent.contractAddress
    || receipt.contract_address !== draftIntent.contractAddress
  ) {
    rejectType("contractCall draft resolved address changed the caller-trusted draftIntent");
  }
  const expectedAlias = request.contract_alias ?? null;
  if (receipt.contract_alias !== expectedAlias) {
    rejectType("contractCall draft is not bound to the requested alias");
  }
  if (
    expectedAlias !== null
    && response.dataspace !== contractAliasDataspaceSegment(
      expectedAlias,
      "contractCall request.contract_alias",
    )
  ) {
    rejectType("contractCall draft dataspace does not match the requested alias");
  }
  if (
    response.contract_address !== receipt.contract_address
    || response.code_hash_hex !== receipt.code_hash_hex
    || response.abi_hash_hex !== receipt.abi_hash_hex
  ) {
    rejectType("contractCall draft receipt does not match the resolved contract binding");
  }
  if (response.code_hash_hex !== draftIntent.codeHashHex) {
    rejectType("contractCall draft code hash changed the caller-trusted draftIntent");
  }
  if (
    receipt.fee_payment === null
    || !feeQuoteSelectionsMatch(receipt.fee_payment, request.fee_payment)
  ) {
    rejectType("contractCall draft fee_payment changed the requested payer, sponsor revision, or gas bound");
  }
  if (receipt.gas_limit !== receipt.fee_payment.value.gas_limit) {
    rejectType("contractCall operation_receipt gas_limit does not match its fee_payment");
  }
  if (receipt.payload_digest_hex !== draftIntent.payloadDigestHex) {
    rejectType("contractCall operation_receipt payload digest changed the caller-trusted draftIntent");
  }
  await validateUnsignedResponsePayloadBinding(
    response,
    request.authority,
    receipt.fee_payment,
    request.transaction_ttl_ms ?? 100_000,
    draftIntent,
    localSigningContext,
    "contractCall draft",
  );
  return response;
}

function normalizeContractCallSimulateRequest(input) {
  const record = ensureRecord(input, "contractCall simulation request");
  rejectRetiredFeeSelectionFields(record, "contractCall simulation request", {
    allowGasLimit: true,
  });
  const normalized = {
    authority: ToriiClient._normalizeAccountId(
      record.authority,
      "contractCall simulation.authority",
    ),
    ...normalizeContractTargetSelector(record, "contractCall simulation"),
  };
  if (record.entrypoint !== undefined && record.entrypoint !== null) {
    normalized.entrypoint = requireNonEmptyString(
      record.entrypoint,
      "contractCall simulation.entrypoint",
    );
  }
  if (record.payload !== undefined) {
    normalized.payload = cloneJsonValue(
      record.payload,
      "contractCall simulation.payload",
    );
  }
  normalized.gas_limit = ToriiClient._normalizeUnsignedInteger(
    record.gas_limit ?? record.gasLimit,
    "contractCall simulation.gasLimit",
    { allowZero: false },
  );
  return normalized;
}

function normalizeContractCallSimulateResponse(payload) {
  const record = ensureRecord(payload, "contractCall simulation response");
  if (typeof record.ok !== "boolean") {
    rejectType("contractCall simulation response.ok must be a boolean");
  }
  const error =
    record.error === undefined || record.error === null
      ? null
      : requireNonEmptyString(
          record.error,
          "contractCall simulation response.error",
        );
  if (record.ok && error !== null) {
    rejectType("successful contractCall simulation response must not contain an error");
  }
  if (!record.ok && error === null) {
    rejectType("failed contractCall simulation response must contain a non-empty error");
  }
  const normalized = {
    ok: record.ok,
    dataspace: requireNonEmptyString(
      record.dataspace,
      "contractCall simulation response.dataspace",
    ),
    contract_address:
      record.contract_address === undefined || record.contract_address === null
        ? null
        : requireNonEmptyString(
            record.contract_address,
            "contractCall simulation response.contract_address",
          ),
    code_hash_hex: normalizeHex32String(
      record.code_hash_hex,
      "contractCall simulation response.code_hash_hex",
    ),
    abi_hash_hex: normalizeHex32String(
      record.abi_hash_hex,
      "contractCall simulation response.abi_hash_hex",
    ),
    entrypoint: requireNonEmptyString(
      record.entrypoint,
      "contractCall simulation response.entrypoint",
    ),
    normalized_payload:
      record.normalized_payload === undefined || record.normalized_payload === null
        ? null
        : cloneJsonValue(
            record.normalized_payload,
            "contractCall simulation response.normalized_payload",
          ),
    gas_limit: ToriiClient._normalizeUnsignedInteger(
      record.gas_limit,
      "contractCall simulation response.gas_limit",
      { allowZero: false },
    ),
    gas_used: ToriiClient._normalizeUnsignedInteger(
      record.gas_used,
      "contractCall simulation response.gas_used",
      { allowZero: true },
    ),
    queued_instructions: Array.isArray(record.queued_instructions)
      ? record.queued_instructions.map((instruction, index) =>
          cloneJsonValue(
            instruction,
            `contractCall simulation response.queued_instructions[${index}]`,
          ),
        )
      : (() => {
          rejectType("contractCall simulation response.queued_instructions must be an array");
        })(),
    result:
      record.result === undefined || record.result === null
        ? null
        : cloneJsonValue(record.result, "contractCall simulation response.result"),
    error,
    vm_diagnostic:
      record.vm_diagnostic === undefined || record.vm_diagnostic === null
        ? null
        : cloneJsonValue(
            record.vm_diagnostic,
            "contractCall simulation response.vm_diagnostic",
          ),
  };
  return normalized;
}

function exactEnumerableDataRecord(value, expectedKeys, context) {
  const record = ensureRecord(value, context);
  const expected = new Set(expectedKeys);
  const ownKeys = Reflect.ownKeys(record);
  if (
    ownKeys.length !== expectedKeys.length ||
    ownKeys.some((key) => typeof key !== JS_TYPE_STRING || !expected.has(key))
  ) {
    rejectType(`${context} must contain exactly: ${expectedKeys.join(", ")}`);
  }
  const snapshot = {};
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      rejectType(`${context}.${key} must be an enumerable data property`);
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function normalizeExactJsonByteArray(
  value,
  context,
  { exactLength = null, maxLength = null } = {},
) {
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an exact byte array`);
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (!lengthDescriptor || !("value" in lengthDescriptor)) {
    rejectType(`${context} must be an exact byte array`);
  }
  const length = lengthDescriptor.value;
  if (exactLength !== null && length !== exactLength) {
    rejectType(`${context} must be an exact ${exactLength}-byte array`);
  }
  if (maxLength !== null && length > maxLength) {
    rejectRange(`${context} exceeds the ${maxLength}-byte proof limit`);
  }
  if (length === 0) {
    rejectType(`${context} must not be empty`);
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    rejectType(`${context} must be an exact byte array`);
  }
  const bytes = new Uint8ArrayIntrinsic(length);
  let enumerableKeys = 0;
  for (const key in value) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      rejectType(`${context} must not inherit enumerable fields`);
    }
    if (key !== String(enumerableKeys) || enumerableKeys >= length) {
      rejectType(`${context} must be a dense exact byte array`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    const byte = descriptor && "value" in descriptor ? descriptor.value : null;
    if (
      !descriptor?.enumerable ||
      typeof byte !== JS_TYPE_NUMBER ||
      !Number.isInteger(byte) ||
      byte < 0 ||
      byte > 0xff
    ) {
      rejectType(`${context}[${key}] must be an unsigned byte`);
    }
    bytes[enumerableKeys] = byte;
    enumerableKeys += 1;
  }
  if (enumerableKeys !== length) {
    rejectType(`${context} must be a dense exact byte array`);
  }
  return bytes;
}

function normalizeMultisigAccountSelector(input, context) {
  const record = ensureRecord(input, context);
  const multisigAccountId = pickOverride(
    record,
    "multisig_account_id",
    "multisigAccountId",
  );
  const multisigAccountAlias = pickOverride(
    record,
    "multisig_account_alias",
    "multisigAccountAlias",
  );
  const hasAccountId = multisigAccountId !== undefined && multisigAccountId !== null;
  const hasAlias = multisigAccountAlias !== undefined && multisigAccountAlias !== null;
  if (hasAccountId === hasAlias) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} requires exactly one of multisig_account_id or multisig_account_alias`,
      normalizeErrorPath(context),
    );
  }
  if (hasAccountId) {
    return {
      multisig_account_id: ToriiClient._normalizeAccountId(
        multisigAccountId,
        `${context}.multisig_account_id`,
      ),
    };
  }
  return {
    multisig_account_alias: normalizeMultisigAccountAliasLiteral(
      multisigAccountAlias,
      `${context}.multisig_account_alias`,
    ),
  };
}

function normalizeMultisigAccountAliasLiteral(value, context) {
  return normalizeAccountAliasLiteral(value, context);
}

function normalizeAccountPathLiteral(value, context) {
  const literal = requireNonEmptyString(value, context).trim();
  if (literal.includes("@")) {
    return normalizeMultisigAccountAliasLiteral(literal, context);
  }
  return normalizeAccountId(literal, context);
}

function normalizeMultisigSelectorOnlyRequest(input, context) {
  return normalizeMultisigAccountSelector(input, context);
}

function normalizeMultisigProposalStatus(value, context) {
  const status = requireNonEmptyString(value, context).trim().toUpperCase();
  if (!MULTISIG_PROPOSAL_STATUS_VALUES.has(status)) {
    rejectType(`${context} must be one of ${[...MULTISIG_PROPOSAL_STATUS_VALUES].join(", ")}`);
  }
  return status;
}

function normalizeMultisigProposalsQueryRequest(input, context) {
  const record = ensureRecord(input, context);
  const payload = normalizeMultisigAccountSelector(record, context);
  if (record.status !== undefined) {
    if (!Array.isArray(record.status)) {
      rejectType(`${context}.status must be an array`);
    }
    payload.status = record.status.map((status, index) =>
      normalizeMultisigProposalStatus(status, `${context}.status[${index}]`),
    );
  }
  if (record.cursor !== undefined && record.cursor !== null) {
    payload.cursor = requireNonEmptyString(record.cursor, `${context}.cursor`);
  }
  if (record.limit !== undefined && record.limit !== null) {
    payload.limit = ToriiClient._normalizeUnsignedInteger(
      record.limit,
      `${context}.limit`,
      { allowZero: false },
    );
  }
  return payload;
}

function normalizeMultisigProposeInstructionInput(value, context) {
  if (
    typeof value === JS_TYPE_STRING ||
    Buffer.isBuffer(value) ||
    ArrayBuffer.isView(value) ||
    value instanceof ArrayBuffer ||
    Array.isArray(value)
  ) {
    return value;
  }
  if (value && typeof value === JS_TYPE_OBJECT) {
    return value;
  }
  throw createValidationError(
    ValidationErrorCode.INVALID_OBJECT,
    `${context} must be a JSON instruction object or native Norito instruction payload input`,
    normalizeErrorPath(context),
  );
}

function normalizeMultisigProposeRequest(input) {
  const record = ensureRecord(input, "proposeMultisig request");
  rejectPrivateKeyFields(record, "proposeMultisig request");
  rejectUnknownRetailFeeFields(record, "proposeMultisig request");
  rejectRetiredFeeSelectionFields(record, "proposeMultisig request");
  const selector = normalizeMultisigAccountSelector(record, "proposeMultisig request");
  const instructionsValue = pickOverride(record, "instructions", "instructions");
  if (!Array.isArray(instructionsValue) || instructionsValue.length === 0) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      "proposeMultisig request.instructions must be a non-empty array",
      "proposeMultisig.request.instructions",
    );
  }
  const payload = {
    ...selector,
    signer_account_id: ToriiClient._normalizeAccountId(
      record.signer_account_id ?? record.signerAccountId,
      "proposeMultisig request.signer_account_id",
    ),
    instructions: instructionsValue.map((instruction, index) =>
      normalizeMultisigProposeInstructionInput(
        instruction,
        `proposeMultisig request.instructions[${index}]`,
      ),
    ),
  };
  const publicKeyHex = pickOverride(record, "public_key_hex", "publicKeyHex");
  if (publicKeyHex !== undefined && publicKeyHex !== null) {
    payload.public_key_hex = normalizeHex32String(
      publicKeyHex,
      "proposeMultisig request.public_key_hex",
    );
  }
  const signatureB64 = pickOverride(record, "signature_b64", "signatureB64");
  if (signatureB64 !== undefined && signatureB64 !== null) {
    payload.signature_b64 = normalizeRequiredExactBase64Payload(
      signatureB64,
      "proposeMultisig request.signature_b64",
    );
  }
  const creationTimeMs = pickOverride(record, "creation_time_ms", "creationTimeMs");
  if (creationTimeMs !== undefined && creationTimeMs !== null) {
    payload.creation_time_ms = ToriiClient._normalizeUnsignedInteger(
      creationTimeMs,
      "proposeMultisig request.creation_time_ms",
      { allowZero: true },
    );
  }
  payload.fee_payment = normalizeFeePaymentIntentValue(
    record.fee_payment ?? record.feePayment,
    "proposeMultisig request.fee_payment",
  );
  if (Object.hasOwn(record, "validation_fee_assessment")) {
    if (record.validation_fee_assessment === null || record.validation_fee_assessment === undefined) {
      rejectType("proposeMultisig request.validation_fee_assessment requires a typed assessment");
    }
    payload.validation_fee_assessment = normalizeRetailFeeAssessment(record.validation_fee_assessment);
  }
  if (record.memo !== undefined && record.memo !== null) {
    if (typeof record.memo !== "string") throw new TypeError("multisig memo must be a string");
    payload.memo = record.memo;
  }
  return payload;
}

function normalizeMultisigContractCallProposeRequest(input) {
  const record = ensureRecord(input, "proposeMultisigContractCall request");
  rejectPrivateKeyFields(record, "proposeMultisigContractCall request");
  rejectRetiredFeeSelectionFields(
    record,
    "proposeMultisigContractCall request",
  );
  const selector = normalizeMultisigAccountSelector(
    record,
    "proposeMultisigContractCall request",
  );
  const payload = {
    ...selector,
    signer_account_id: ToriiClient._normalizeAccountId(
      record.signer_account_id ?? record.signerAccountId,
      "proposeMultisigContractCall request.signer_account_id",
    ),
    contract_alias: requireNonEmptyString(
      record.contract_alias ?? record.contractAlias,
      "proposeMultisigContractCall request.contract_alias",
    ),
    entrypoint: requireNonEmptyString(
      record.entrypoint,
      "proposeMultisigContractCall request.entrypoint",
    ),
  };
  const publicKeyHex = pickOverride(record, "public_key_hex", "publicKeyHex");
  if (publicKeyHex !== undefined && publicKeyHex !== null) {
    payload.public_key_hex = normalizeHex32String(
      publicKeyHex,
      "proposeMultisigContractCall request.public_key_hex",
    );
  }
  const signatureB64 = pickOverride(record, "signature_b64", "signatureB64");
  if (signatureB64 !== undefined && signatureB64 !== null) {
    payload.signature_b64 = normalizeRequiredExactBase64Payload(
      signatureB64,
      "proposeMultisigContractCall request.signature_b64",
    );
  }
  const creationTimeMs = pickOverride(record, "creation_time_ms", "creationTimeMs");
  if (creationTimeMs !== undefined && creationTimeMs !== null) {
    payload.creation_time_ms = ToriiClient._normalizeUnsignedInteger(
      creationTimeMs,
      "proposeMultisigContractCall request.creation_time_ms",
      { allowZero: true },
    );
  }
  if (record.contract_address != null || record.contractAddress != null) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      "proposeMultisigContractCall requires contract_alias without contract_address",
      "proposeMultisigContractCall.request.contract_alias",
    );
  }
  payload.payload = ensureRecord(
    record.payload,
    "proposeMultisigContractCall request.payload",
  );
  payload.fee_payment = normalizeFeePaymentIntentValue(
    record.fee_payment ?? record.feePayment,
    "proposeMultisigContractCall request.fee_payment",
    { requireGasLimit: true },
  );
  return payload;
}

function normalizeMultisigContractCallApproveRequest(input) {
  const record = ensureRecord(input, "approveMultisigContractCall request");
  rejectPrivateKeyFields(record, "approveMultisigContractCall request");
  rejectRetiredFeeSelectionFields(
    record,
    "approveMultisigContractCall request",
  );
  const selector = normalizeMultisigAccountSelector(
    record,
    "approveMultisigContractCall request",
  );
  const payload = {
    ...selector,
    signer_account_id: ToriiClient._normalizeAccountId(
      record.signer_account_id ?? record.signerAccountId,
      "approveMultisigContractCall request.signer_account_id",
    ),
  };
  const publicKeyHex = pickOverride(record, "public_key_hex", "publicKeyHex");
  if (publicKeyHex !== undefined && publicKeyHex !== null) {
    payload.public_key_hex = normalizeHex32String(
      publicKeyHex,
      "approveMultisigContractCall request.public_key_hex",
    );
  }
  const signatureB64 = pickOverride(record, "signature_b64", "signatureB64");
  if (signatureB64 !== undefined && signatureB64 !== null) {
    payload.signature_b64 = normalizeRequiredExactBase64Payload(
      signatureB64,
      "approveMultisigContractCall request.signature_b64",
    );
  }
  const creationTimeMs = pickOverride(record, "creation_time_ms", "creationTimeMs");
  if (creationTimeMs !== undefined && creationTimeMs !== null) {
    payload.creation_time_ms = ToriiClient._normalizeUnsignedInteger(
      creationTimeMs,
      "approveMultisigContractCall request.creation_time_ms",
      { allowZero: true },
    );
  }
  const proposalId = pickOverride(record, "proposal_id", "proposalId");
  if (proposalId !== undefined && proposalId !== null) {
    payload.proposal_id = requireNonEmptyString(
      proposalId,
      "approveMultisigContractCall request.proposal_id",
    );
  }
  const instructionsHash = pickOverride(
    record,
    "instructions_hash",
    "instructionsHash",
  );
  if (instructionsHash !== undefined && instructionsHash !== null) {
    payload.instructions_hash = normalizeHex32String(
      instructionsHash,
      "approveMultisigContractCall request.instructions_hash",
    );
  }
  if (!payload.proposal_id && !payload.instructions_hash) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      "approveMultisigContractCall request requires proposal_id or instructions_hash",
      "approveMultisigContractCall.request",
    );
  }
  payload.fee_payment = normalizeFeePaymentIntentValue(
    record.fee_payment ?? record.feePayment,
    "approveMultisigContractCall request.fee_payment",
  );
  payload.contract_alias = requireNonEmptyString(
    record.contract_alias,
    "approveMultisigContractCall request.contract_alias",
  );
  payload.entrypoint = requireNonEmptyString(
    record.entrypoint,
    "approveMultisigContractCall request.entrypoint",
  );
  payload.payload = ensureRecord(
    record.payload,
    "approveMultisigContractCall request.payload",
  );
  return payload;
}

function normalizeMultisigContractCallResponse(
  payload,
  context = "multisig contract call response",
) {
  const record = ensureRecord(payload, context);
  if (record.ok !== true) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.ok must be true`,
      `${context}.ok`,
    );
  }
  for (const retired of ["transaction_scaffold_b64", "signed_transaction_b64"]) {
    if (Object.hasOwn(record, retired)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${context} contains retired field ${retired}`,
        `${context}.${retired}`,
      );
    }
  }
  const normalized = {
    ok: true,
    resolved_multisig_account_id: requireExactAccountId(
      record.resolved_multisig_account_id,
      `${context}.resolved_multisig_account_id`,
    ),
    submitted: requireExactBoolean(record.submitted, `${context}.submitted`),
    proposal_id: requireOptionalExactLowerHex32String(
      record.proposal_id,
      `${context}.proposal_id`,
    ),
    instructions_hash: requireOptionalExactLowerHex32String(
      record.instructions_hash,
      `${context}.instructions_hash`,
    ),
    tx_hash_hex:
      record.tx_hash_hex === undefined || record.tx_hash_hex === null
        ? null
        : requireCanonicalTransactionHashString(
            record.tx_hash_hex,
            `${context}.tx_hash_hex`,
          ),
    executed_tx_hash_hex:
      record.executed_tx_hash_hex === undefined || record.executed_tx_hash_hex === null
        ? null
        : requireCanonicalTransactionHashString(
            record.executed_tx_hash_hex,
            `${context}.executed_tx_hash_hex`,
          ),
    creation_time_ms:
      record.creation_time_ms === undefined || record.creation_time_ms === null
        ? null
        : ToriiClient._normalizeUnsignedInteger(
            record.creation_time_ms,
            `${context}.creation_time_ms`,
            { allowZero: true },
          ),
    fee_payment: normalizeFeePaymentIntentResponse(
      record.fee_payment,
      `${context}.fee_payment`,
    ),
    transaction_payload_b64: normalizeOptionalExactBase64Payload(
      record.transaction_payload_b64,
      `${context}.transaction_payload_b64`,
    ),
    signing_message_b64: normalizeOptionalExactBase64Payload(
      record.signing_message_b64,
      `${context}.signing_message_b64`,
    ),
  };
  if (
    normalized.proposal_id !== null
    && normalized.instructions_hash !== null
    && normalized.proposal_id !== normalized.instructions_hash
  ) {
    rejectType(`${context}.proposal_id and instructions_hash must identify the same proposal`);
  }
  if (normalized.submitted) {
    if (
      normalized.tx_hash_hex === null ||
      normalized.transaction_payload_b64 !== null ||
      normalized.signing_message_b64 !== null
    ) {
      rejectType(`${context} submitted response must contain only the final transaction hash`);
    }
  } else {
    if (normalized.tx_hash_hex !== null) {
      rejectType(`${context} unsigned response must contain exactly one payload and signing-message pair`);
    }
    normalizeAppApiTransactionDraft(
      {
        submitted: normalized.submitted,
        transaction_payload_b64: normalized.transaction_payload_b64,
        signing_message_b64: normalized.signing_message_b64,
      },
      context,
    );
  }
  return normalized;
}

function exactArchiveEquals(left, right) {
  return left.length === right.length && timingSafeEqual(left, right);
}

async function validateUnsignedResponsePayloadBinding(
  response,
  authority,
  feePayment,
  expectedTtlMs,
  draftIntent,
  localSigningContext,
  context,

) {
  if (draftIntent === null) {
    rejectType(`${context} requires a caller-trusted draftIntent`);
  }
  requireLocalDraftSigningContext(localSigningContext, context);
  const {
    inspectCanonicalTransactionPayloadBindings,
    noritoEncodeFeePaymentIntentArchive,
  } = await loadToriiOptionalModule();
  let bindings;
  try {
    bindings = inspectCanonicalTransactionPayloadBindings(
      strictDecodeBase64(response.transaction_payload_b64),
      authority,

      localSigningContext.chainDiscriminant,
    );
  } catch (error) {
    rejectType(`${context}.transaction_payload_b64 must contain one canonical transaction payload bound to the requested signer`, { cause: error });
  }
  const expectedNetworkId = Buffer.from(
    networkIdBytes(localSigningContext.networkId, `${context}.networkId`),
  );
  if (!exactArchiveEquals(expectedNetworkId, bindings.networkId)) {
    rejectType(`${context} transaction payload changed caller-trusted networkId`);
  }
  const encodedResponseFee = Buffer.from(
    noritoEncodeFeePaymentIntentArchive(feePayment),
  );
  for (const [field, expected, actual] of [
    ["executable", draftIntent.executableArchive, bindings.executableArchive],
    ["fee_payment", encodedResponseFee, bindings.feePaymentArchive],
    ["metadata", draftIntent.metadataArchive, bindings.metadataArchive],
  ]) {
    if (!exactArchiveEquals(expected, actual)) {
      rejectType(`${context} transaction payload changed caller-trusted ${field}`);
    }
  }
  if (
    response.creation_time_ms === null
    || BigInt(response.creation_time_ms) !== bindings.creationTimeMs
  ) {
    rejectType(`${context}.creation_time_ms does not match the exact transaction payload`);
  }
  if (BigInt(expectedTtlMs) !== bindings.ttlMs) {
    rejectType(`${context} transaction payload changed caller-trusted ttlMs`);
  }
}

async function validateMultisigResponseRequestBinding(
  response,
  request,
  context,
  draftIntent,
  localSigningContext,
) {
  if (!feeQuoteSelectionsMatch(response.fee_payment, request.fee_payment)) {
    rejectType(`${context}.fee_payment changed the requested payer, sponsor revision, or gas bound`);
  }
  if (
    request.creation_time_ms !== undefined
    && response.creation_time_ms !== request.creation_time_ms
  ) {
    rejectType(`${context}.creation_time_ms is not bound to the request`);
  }
  if (!response.submitted) {
    await validateUnsignedResponsePayloadBinding(
      response,
      request.signer_account_id,
      response.fee_payment,
      100_000,
      draftIntent,
      localSigningContext,
      context,
    );
  }
  return response;
}

function normalizeMultisigSpecResponse(payload, context = "multisig spec response") {
  const record = ensureRecord(payload, context);
  return {
    resolved_multisig_account_id: requireExactAccountId(
      record.resolved_multisig_account_id,
      `${context}.resolved_multisig_account_id`,
    ),
    spec: cloneJsonValue(record.spec, `${context}.spec`),
  };
}

function normalizeMultisigProposalEntry(payload, context) {
  const record = ensureRecord(payload, context);
  return {
    proposal_id: requireNonEmptyString(record.proposal_id, `${context}.proposal_id`),
    instructions_hash: normalizeHex32String(
      record.instructions_hash,
      `${context}.instructions_hash`,
    ),
    operation_type: requireNonEmptyString(
      record.operation_type,
      `${context}.operation_type`,
    ),
    intent:
      record.intent === undefined || record.intent === null
        ? null
        : cloneJsonValue(record.intent, `${context}.intent`),
    proposal: cloneJsonValue(record.proposal, `${context}.proposal`),
    status: normalizeMultisigProposalStatus(record.status, `${context}.status`),
    terminal_at_ms:
      record.terminal_at_ms === undefined || record.terminal_at_ms === null
        ? null
        : ToriiClient._normalizeUnsignedInteger(
            record.terminal_at_ms,
            `${context}.terminal_at_ms`,
            { allowZero: true },
          ),
  };
}

function normalizeMultisigProposalsQueryResponse(
  payload,
  context = "multisig proposals query response",
) {
  const record = ensureRecord(payload, context);
  const proposalsValue = record.proposals;
  if (!Array.isArray(proposalsValue)) {
    rejectType(`${context}.proposals must be an array`);
  }
  return {
    resolved_multisig_account_id: requireExactAccountId(
      record.resolved_multisig_account_id,
      `${context}.resolved_multisig_account_id`,
    ),
    proposals: proposalsValue.map((entry, index) =>
      normalizeMultisigProposalEntry(entry, `${context}.proposals[${index}]`),
    ),
    next_cursor:
      record.next_cursor === undefined || record.next_cursor === null
        ? null
        : requireNonEmptyString(record.next_cursor, `${context}.next_cursor`),
  };
}

function normalizeMultisigProposalsResolveRequest(input) {
  const record = ensureRecord(input, "resolveMultisigProposal request");
  const payload = normalizeMultisigAccountSelector(record, "resolveMultisigProposal request");
  const proposalId = pickOverride(record, "proposal_id", "proposalId");
  if (proposalId !== undefined && proposalId !== null) {
    payload.proposal_id = requireNonEmptyString(
      proposalId,
      "resolveMultisigProposal request.proposal_id",
    );
  }
  const instructionsHash = pickOverride(
    record,
    "instructions_hash",
    "instructionsHash",
  );
  if (instructionsHash !== undefined && instructionsHash !== null) {
    payload.instructions_hash = normalizeHex32String(
      instructionsHash,
      "resolveMultisigProposal request.instructions_hash",
    );
  }
  const hasProposalId = payload.proposal_id !== undefined;
  const hasInstructionsHash = payload.instructions_hash !== undefined;
  if (hasProposalId === hasInstructionsHash) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      "resolveMultisigProposal request requires exactly one of proposal_id or instructions_hash",
      "resolveMultisigProposal.request",
    );
  }
  return payload;
}

function normalizeMultisigProposalResolveResponse(
  payload,
  context = "multisig proposal resolve response",
) {
  const record = ensureRecord(payload, context);
  return {
    resolved_multisig_account_id: requireExactAccountId(
      record.resolved_multisig_account_id,
      `${context}.resolved_multisig_account_id`,
    ),
    ...normalizeMultisigProposalEntry(record, context),
  };
}

function normalizeContractManifestResponse(payload, requested, networkId) {
  const record = exactEnumerableDataRecord(
    payload,
    ["network_id", "artifact_id", "manifest", ...["code_hash", "abi_hash", "code_bytes"].filter((key) => Object.hasOwn(ensureRecord(payload, "contract manifest response"), key))],
    "contract manifest response",
  );
  const identity = validateContractArtifactResponseIdentity(record, requested, networkId);
  const manifestRecord = assertExactManifestResponseShape(
    record.manifest,
    "contract manifest response.manifest",
  );
  const manifest = normalizeManifestPayload(
    {
      ...manifestRecord,
      code_hash: normalizeCanonicalManifestHash(
        manifestRecord.code_hash,
        "manifest.code_hash",
      ),
      abi_hash: normalizeCanonicalManifestHash(
        manifestRecord.abi_hash,
        "manifest.abi_hash",
      ),
    },
    "manifest",
  );
  const codeHash = record.code_hash === undefined ? manifest.code_hash : normalizeOptionalHex32(record.code_hash, "contractManifest.code_hash");
  const abiHash = record.abi_hash === undefined ? manifest.abi_hash : normalizeOptionalHex32(record.abi_hash, "contractManifest.abi_hash");
  if (codeHash !== manifest.code_hash) {
    rejectType("contractManifest.code_hash does not match manifest.code_hash");
  }
  if (abiHash !== manifest.abi_hash) {
    rejectType("contractManifest.abi_hash does not match manifest.abi_hash");
  }
  if (codeHash !== requested.code_hash) rejectType("contract manifest artifact hash differs from requested artifact");
  let inlineCode;
  if (record.code_bytes !== undefined) {
    inlineCode = normalizeIvmArtifactBase64String(record.code_bytes, "contract manifest response.code_bytes");
    if (computeIvmArtifactHashes(Buffer.from(inlineCode, "base64")).codeHashHex !== requested.code_hash) {
      rejectType("contract manifest inline bytes hash differs from requested artifact");
    }
  }
  return {
    ...identity,
    ...(inlineCode === undefined ? {} : { code_bytes: inlineCode }),
    manifest,
    code_hash: codeHash,
    abi_hash: abiHash,
  };
}

function normalizeCanonicalManifestHash(value, name) {
  if (value === undefined || value === null) {
    return null;
  }
  const literal = requireExactNonEmptyString(value, name);
  if (!/^hash:[0-9A-F]{64}#[0-9A-F]{4}$/u.test(literal)) {
    rejectType(`${name} must be a canonical uppercase Norito Hash literal`);
  }
  return parseHashLiteralToHex(literal, name);
}

function normalizeContractCodeBytesResponse(payload, requested, networkId) {
  const record = exactEnumerableDataRecord(payload, ["network_id", "artifact_id", "code_b64"], "contract code bytes response");
  const identity = validateContractArtifactResponseIdentity(record, requested, networkId);
  const code = normalizeIvmArtifactBase64String(record.code_b64, "contractCodeBytes.code_b64");
  if (computeIvmArtifactHashes(Buffer.from(code, "base64")).codeHashHex !== requested.code_hash) {
    rejectType("contract code bytes hash differs from requested artifact");
  }
  return { ...identity, code_b64: code };
}

function contractArtifactDataspace(value, context) {
  if (typeof value === "number" && !Number.isSafeInteger(value)) rejectType(`${context} must be an exact u64`);
  if (!((typeof value === "number" && value >= 0) || typeof value === "bigint" || (typeof value === "string" && value.length <= 20 && /^(0|[1-9][0-9]*)$/u.test(value)))) rejectType(`${context} must be a canonical u64`);
  const integer = BigInt(value);
  if (integer < 0n || integer > 0xffff_ffff_ffff_ffffn) rejectType(`${context} must fit u64`);
  return integer.toString();
}

function normalizeContractArtifactRequest(value) {
  const record = exactEnumerableDataRecord(value, ["dataspaceId", "codeHash"], "artifactId");
  return {
    dataspace_id: contractArtifactDataspace(record.dataspaceId, "artifactId.dataspaceId"),
    code_hash: typeof record.codeHash === "string" && record.codeHash.startsWith("hash:")
      ? normalizeCanonicalManifestHash(record.codeHash, "artifactId.codeHash")
      : normalizeIrohaHashHex32(record.codeHash, "artifactId.codeHash"),
  };
}

function validateContractArtifactResponseIdentity(record, requested, networkId) {
  const returnedNetwork = NetworkId.parse(record.network_id);
  if (!Buffer.from(networkIdBytes(returnedNetwork)).equals(Buffer.from(networkIdBytes(networkId)))) rejectType("contract artifact response network differs from authenticated network");
  const artifact = exactEnumerableDataRecord(record.artifact_id, ["dataspace_id", "code_hash"], "contract artifact response.artifact_id");
  const dataspace = contractArtifactDataspace(artifact.dataspace_id, "contract artifact response.dataspace_id");
  const hash = normalizeCanonicalManifestHash(artifact.code_hash, "contract artifact response.code_hash");
  if (dataspace !== requested.dataspace_id || hash !== requested.code_hash) rejectType("contract artifact response identity differs from requested artifact");
  return { network_id: record.network_id, artifact_id: { dataspace_id: dataspace, code_hash: artifact.code_hash } };
}

function normalizeIvmArtifactBase64String(value, name) {
  return normalizeBoundedCanonicalBase64String(
    value,
    name,
    IVM_ARTIFACT_MAX_BYTES,
    "artifact",
  );
}

function normalizeBoundedCanonicalBase64String(
  value,
  name,
  maxBytes,
  limitLabel = "payload",
) {
  if (typeof value !== JS_TYPE_STRING) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${name} must be a base64 string`,
      name,
    );
  }
  const maxEncodedLength = Math.ceil(maxBytes / 3) * 4;
  if (value.length > maxEncodedLength) {
    rejectRange(`${name} exceeds the ${maxBytes}-byte ${limitLabel} limit`);
  }
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  if (
    value.length % 4 === 0 &&
    (value.length / 4) * 3 - padding > maxBytes
  ) {
    rejectRange(`${name} exceeds the ${maxBytes}-byte ${limitLabel} limit`);
  }
  if (!hasExactStandardBase64Shape(value)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${name} must be canonical standard base64`,
      name,
    );
  }
  return value;
}

function hasExactStandardBase64Shape(value) {
  if (value.length === 0 || value.length % 4 !== 0) return false;
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const dataLength = value.length - padding;
  for (let index = 0; index < dataLength; index += 1) {
    const code = value.charCodeAt(index);
    if (standardBase64Sextet(code) < 0) {
      return false;
    }
  }
  const trailingSextet = standardBase64Sextet(
    value.charCodeAt(dataLength - 1),
  );
  if (padding === 2 && (trailingSextet & 0x0f) !== 0) return false;
  if (padding === 1 && (trailingSextet & 0x03) !== 0) return false;
  return true;
}

function standardBase64Sextet(code) {
  if (code >= 0x41 && code <= 0x5a) return code - 0x41;
  if (code >= 0x61 && code <= 0x7a) return code - 0x61 + 26;
  if (code >= 0x30 && code <= 0x39) return code - 0x30 + 52;
  if (code === 0x2b) return 62;
  if (code === 0x2f) return 63;
  return -1;
}

function normalizeManifestEntrypointKind(value, name) {
  if (value === undefined || value === null) {
    rejectType(`${name} is required`);
  }
  if (typeof value === JS_TYPE_STRING) {
    const canonical = requireExactNonEmptyString(value, name);
    return { kind: canonicalManifestEntrypointKind(canonical, name), value: null };
  }
  const record = ensureRecord(value, name);
  const kind = canonicalManifestEntrypointKind(
    requireExactNonEmptyString(record.kind, `${name}.kind`),
    `${name}.kind`,
  );
  if (record.value !== undefined && record.value !== null) {
    rejectType(`${name}.value must be null`);
  }
  return { kind, value: null };
}

function canonicalManifestEntrypointKind(value, name) {
  switch (value) {
    case "Kotoage":
      return "Kotoage";
    case "View":
      return "View";
    case "Hajimari":
      return "Hajimari";
    case "Kaizen":
      return "Kaizen";
    default:
      rejectType(`${name} must be Kotoage, View, Hajimari, or Kaizen`);
  }
}

function normalizeGovernanceContractResponse(payload) {
  const context = "governanceContract";
  const record = ensureRecord(payload ?? {}, "governance contract response");
  assertSupportedOptionKeys(
    record,
    new Set([
      "found",
      "contract_address",
      "contract_subject_account",
      "dataspace",
      "active",
      "lifecycle",
      "emergency_hold_active",
      "code_hash_hex",
      "abi_hash_hex",
      "public_entrypoints",
    ]),
    "governance contract response",
  );
  const found = requireExactBoolean(record.found, "governanceContract.found");
  const active = found
    ? requireExactBoolean(record.active, `${context}.active`)
    : null;
  const fields = found
    ? active
      ? [
          "found",
          "contract_address",
          "contract_subject_account",
          "dataspace",
          "active",
          "lifecycle",
          "emergency_hold_active",
          "code_hash_hex",
          "abi_hash_hex",
          "public_entrypoints",
        ]
      : [
          "found",
          "contract_address",
          "contract_subject_account",
          "dataspace",
          "active",
          "lifecycle",
          "emergency_hold_active",
        ]
    : ["found", "contract_address", "dataspace"];
  requireExactGovernanceProposalRecord(record, fields, "governance contract response");
  const result = {
    found,
    contract_address: requireExactNonEmptyString(
      record.contract_address,
      `${context}.contract_address`,
    ),
    contract_subject_account: found
      ? requireCanonicalGovernanceAccountId(
          record.contract_subject_account,
          `${context}.contract_subject_account`,
        )
      : null,
    dataspace: requireExactNonEmptyString(record.dataspace, `${context}.dataspace`),
    active,
    lifecycle:
      !found
        ? null
        : normalizeGovernanceContractLifecycle(
            record.lifecycle,
            `${context}.lifecycle`,
          ),
    emergency_hold_active: found
      ? requireExactBoolean(
          record.emergency_hold_active,
          `${context}.emergency_hold_active`,
        )
      : null,
    code_hash_hex:
      !active
        ? null
        : requireExactLowerHex32String(
            record.code_hash_hex,
            `${context}.code_hash_hex`,
          ),
    abi_hash_hex:
      !active
        ? null
        : requireExactLowerHex32String(
            record.abi_hash_hex,
            `${context}.abi_hash_hex`,
          ),
    public_entrypoints:
      !active
        ? null
        : normalizeGovernancePublicEntrypoints(
            record.public_entrypoints,
            `${context}.public_entrypoints`,
          ),
  };
  if (found) {
    if (result.active) {
      if (result.lifecycle.active_code_hash_hex !== result.code_hash_hex) {
        rejectType(`${context}.lifecycle.active_code_hash_hex must match code_hash_hex`);
      }
    } else if (result.lifecycle.active_code_hash_hex !== null) {
      rejectType(`${context}.lifecycle.active_code_hash_hex must be null for an inactive contract`);
    }
    if (result.emergency_hold_active && result.lifecycle.emergency_hold === null) {
      rejectType(`${context}.emergency_hold_active requires a retained emergency hold`);
    }
  }
  return result;
}

function normalizeGovernanceContractLifecycle(value, context) {
  const record = requireExactGovernanceProposalRecord(
    value,
    [
      "version",
      "origin",
      "origin_account",
      "origin_proposal_content_id_hex",
      "origin_governance_attempt_id_hex",
      "owner",
      "pending_owner",
      "parliament_delegated",
      "active_code_hash_hex",
      "revision",
      "emergency_hold",
    ],
    context,
  );
  if (record.version !== 1) {
    rejectType(`${context}.version must be the number 1`);
  }
  const origin = requireExactNonEmptyString(record.origin, `${context}.origin`);
  if (origin !== "direct" && origin !== "parliament") {
    rejectType(`${context}.origin must be direct or parliament`);
  }
  const lifecycle = {
    version: 1,
    origin,
    origin_account: requireCanonicalGovernanceAccountId(
      record.origin_account,
      `${context}.origin_account`,
    ),
    origin_proposal_content_id_hex:
      record.origin_proposal_content_id_hex == null
        ? null
        : requireExactLowerHex32String(
            record.origin_proposal_content_id_hex,
            `${context}.origin_proposal_content_id_hex`,
          ),
    origin_governance_attempt_id_hex:
      record.origin_governance_attempt_id_hex == null
        ? null
        : requireExactLowerHex32String(
            record.origin_governance_attempt_id_hex,
            `${context}.origin_governance_attempt_id_hex`,
          ),
    owner: normalizeGovernanceContractOwner(record.owner, `${context}.owner`),
    pending_owner:
      record.pending_owner == null
        ? null
        : normalizeGovernanceContractOwner(
            record.pending_owner,
            `${context}.pending_owner`,
          ),
    parliament_delegated: requireExactBoolean(
      record.parliament_delegated,
      `${context}.parliament_delegated`,
    ),
    active_code_hash_hex:
      record.active_code_hash_hex == null
        ? null
        : requireExactLowerHex32String(
            record.active_code_hash_hex,
            `${context}.active_code_hash_hex`,
          ),
    revision: normalizeGovernanceUint64Integer(record.revision, `${context}.revision`, {
      allowZero: false,
    }),
    emergency_hold:
      record.emergency_hold == null
        ? null
        : normalizeGovernanceContractEmergencyHold(
            record.emergency_hold,
            `${context}.emergency_hold`,
          ),
  };
  const hasProposalContentId = lifecycle.origin_proposal_content_id_hex !== null;
  const hasAttemptId = lifecycle.origin_governance_attempt_id_hex !== null;
  if (origin === "direct" && (hasProposalContentId || hasAttemptId)) {
    rejectType(`${context} direct origin must not carry Parliament identifiers`);
  }
  if (origin === "parliament" && (!hasProposalContentId || !hasAttemptId)) {
    rejectType(`${context} Parliament origin requires both governance identifiers`);
  }
  return lifecycle;
}

function normalizeGovernanceContractEmergencyHold(value, context) {
  const record = requireExactGovernanceProposalRecord(
    value,
    [
      "incident_digest_hex",
      "proposal_content_id_hex",
      "governance_attempt_id_hex",
      "reason",
      "imposed_at_height",
      "expires_at_height",
    ],
    context,
  );
  const imposedAtHeight = normalizeGovernanceUint64Integer(
    record.imposed_at_height,
    `${context}.imposed_at_height`,
    { allowZero: false },
  );
  const expiresAtHeight = normalizeGovernanceUint64Integer(
    record.expires_at_height,
    `${context}.expires_at_height`,
    { allowZero: false },
  );
  if (expiresAtHeight <= imposedAtHeight) {
    rejectType(`${context}.expires_at_height must follow imposed_at_height`);
  }
  return {
    incident_digest_hex: requireExactLowerHex32String(
      record.incident_digest_hex,
      `${context}.incident_digest_hex`,
    ),
    proposal_content_id_hex: requireExactLowerHex32String(
      record.proposal_content_id_hex,
      `${context}.proposal_content_id_hex`,
    ),
    governance_attempt_id_hex: requireExactLowerHex32String(
      record.governance_attempt_id_hex,
      `${context}.governance_attempt_id_hex`,
    ),
    reason: requireExactNonEmptyString(record.reason, `${context}.reason`),
    imposed_at_height: imposedAtHeight,
    expires_at_height: expiresAtHeight,
  };
}

function normalizeGovernanceContractOwner(value, context) {
  const literal = requireExactNonEmptyString(value, context);
  return literal === "parliament"
    ? literal
    : requireCanonicalGovernanceAccountId(literal, context);
}

function normalizeGovernancePublicEntrypoints(value, context) {
  const entries = requireStringArray(value, context).map((entry, index) => {
    const literal = requireExactNonEmptyString(entry, `${context}[${index}]`);
    if (!/^[a-z][a-z0-9_]{0,127}$/u.test(literal)) {
      rejectType(`${context}[${index}] must be a canonical public entrypoint name`);
    }
    return literal;
  });
  if (entries.length === 0) {
    rejectType(`${context} must not be empty`);
  }
  for (let index = 1; index < entries.length; index += 1) {
    if (entries[index - 1] >= entries[index]) {
      rejectType(`${context} must be sorted and contain no duplicates`);
    }
  }
  return entries;
}

function normalizeAliasResolutionResponse(
  payload,
  context = "alias resolution response",
) {
  const record = ensureRecord(payload ?? {}, context);
  assertSupportedOptionKeys(
    record,
    new Set(["alias", "account_id", "index", "source"]),
    context,
  );
  const alias = requireExactNonEmptyString(record.alias, `${context}.alias`);
  const normalizedAlias = looksLikeIban(alias)
    ? normalizeIban(alias, `${context}.alias`)
    : alias;
  if (normalizedAlias !== alias) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context}.alias must be canonical`,
      `${context}.alias`,
    );
  }
  const rawAccountId = requireExactNonEmptyString(
    record.account_id,
    `${context}.account_id`,
  );
  const accountId = ToriiClient._requireAccountId(
    rawAccountId,
    `${context}.account_id`,
  );
  if (accountId !== rawAccountId) {
    throw createValidationError(
      ValidationErrorCode.INVALID_ACCOUNT_ID,
      `${context}.account_id must be canonical`,
      `${context}.account_id`,
    );
  }
  const result = {
    alias: normalizedAlias,
    account_id: accountId,
  };
  if (record.index !== undefined && record.index !== null) {
    result.index = requireExactJsonUnsignedInteger(
      record.index,
      `${context}.index`,
      { allowZero: true },
    );
  }
  const sourceValue = record.source;
  if (sourceValue !== undefined && sourceValue !== null) {
    result.source = requireExactNonEmptyString(sourceValue, `${context}.source`);
  }
  return result;
}

function normalizeAliasLookupByAccountResponse(
  payload,
  context = "alias by-account response",
) {
  const record = ensureRecord(payload ?? {}, context);
  const accountId = ToriiClient._requireAccountId(record.account_id, `${context}.account_id`);
  const rawItems = Array.isArray(record.items) ? record.items : [];
  const items = rawItems.map((item, index) => {
    const aliasRecord = ensureRecord(item, `${context}.items[${index}]`);
    const alias = requireNonEmptyString(aliasRecord.alias, `${context}.items[${index}].alias`);
    const dataspace = requireNonEmptyString(
      aliasRecord.dataspace,
      `${context}.items[${index}].dataspace`,
    );
    const rawDomain = aliasRecord.domain;
    const domain =
      rawDomain == null
        ? null
        : requireNonEmptyString(rawDomain, `${context}.items[${index}].domain`);
    const rawIsPrimary = aliasRecord.is_primary ?? aliasRecord.isPrimary;
    if (typeof rawIsPrimary !== "boolean") {
      rejectType(`${context}.items[${index}].is_primary must be a boolean`);
    }
    return {
      alias,
      dataspace,
      domain,
      is_primary: rawIsPrimary,
    };
  });
  const total =
    record.total === undefined
      ? items.length
      : ToriiClient._normalizeUnsignedInteger(record.total, `${context}.total`, {
          allowZero: true,
        });
  return {
    account_id: accountId,
    total,
    items,
  };
}

function normalizeRetailRecipientLookupResponse(
  payload,
  context = "retail recipient lookup response",
) {
  const record = ensureRecord(payload ?? {}, context);
  assertSupportedOptionKeys(record, RETAIL_RECIPIENT_LOOKUP_RESPONSE_KEYS, context);
  if (typeof record.resolved !== "boolean") {
    rejectType(`${context}.resolved must be a boolean`);
  }
  const accountId = ToriiClient._requireAccountId(
    record.account_id,
    `${context}.account_id`,
  );
  const aliasFqn = normalizeAccountAliasFqn(record.alias_fqn, `${context}.alias_fqn`);
  if (aliasFqn !== record.alias_fqn) {
    rejectType(`${context}.alias_fqn must be canonical`);
  }
  const fiId = requireNonEmptyString(record.fi_id, `${context}.fi_id`);
  if (fiId !== "hbl.sbp" && fiId !== "ubl.sbp") {
    rejectType(`${context}.fi_id must be hbl.sbp or ubl.sbp`);
  }
  if (aliasFqn.slice(aliasFqn.indexOf("@") + 1) !== fiId) {
    rejectType(`${context}.alias_fqn must use the returned FI domain`);
  }
  const result = {
    resolved: record.resolved,
    account_id: accountId,
    alias_fqn: aliasFqn,
    fi_id: fiId,
  };
  if (record.full_name !== undefined && record.full_name !== null) {
    result.full_name = requireNonEmptyString(record.full_name, `${context}.full_name`);
  }
  if (record.resolved && result.full_name === undefined) {
    rejectType(`${context}.full_name is required when resolved is true`);
  }
  return result;
}

function normalizeRetailRecipientRouteResponse(
  payload,
  context = "retail recipient route response",
) {
  const record = ensureRecord(payload ?? {}, context);
  assertSupportedOptionKeys(record, RETAIL_RECIPIENT_ROUTE_RESPONSE_KEYS, context);
  const accountId = ToriiClient._requireAccountId(
    record.account_id,
    `${context}.account_id`,
  );
  const aliasFqn = normalizeAccountAliasFqn(record.alias_fqn, `${context}.alias_fqn`);
  if (aliasFqn !== record.alias_fqn) {
    rejectType(`${context}.alias_fqn must be canonical`);
  }
  const fiId = requireNonEmptyString(record.fi_id, `${context}.fi_id`);
  if (fiId !== "hbl.sbp" && fiId !== "ubl.sbp") {
    rejectType(`${context}.fi_id must be hbl.sbp or ubl.sbp`);
  }
  if (aliasFqn.slice(aliasFqn.indexOf("@") + 1) !== fiId) {
    rejectType(`${context}.alias_fqn must use the returned FI domain`);
  }
  return {
    account_id: accountId,
    alias_fqn: aliasFqn,
    fi_id: fiId,
  };
}

function normalizeFeeSponsorProgramId(value, context) {
  const literal = requireExactNonEmptyString(value, context);
  const separator = literal.lastIndexOf("/");
  if (separator <= 0 || separator === literal.length - 1) {
    rejectType(`${context} must be an exact sponsor/program literal`);
  }
  const sponsorLiteral = literal.slice(0, separator);
  const sponsor = ToriiClient._requireAccountId(sponsorLiteral, `${context}.sponsor`);
  if (sponsor !== sponsorLiteral) {
    rejectType(`${context}.sponsor must be a canonical I105 account id`);
  }
  const name = requireCanonicalIrohaName(literal.slice(separator + 1), `${context}.name`);
  return { literal, sponsor, name };
}

function normalizeTaggedUnit(value, tag, allowed, context) {
  const record = ensureRecord(value, context);
  assertSupportedOptionKeys(record, new Set([tag, "value"]), context);
  const kind = requireExactNonEmptyString(record[tag], `${context}.${tag}`);
  if (!allowed.has(kind) || record.value !== null) {
    rejectType(`${context} must contain a supported tagged unit value`);
  }
  return kind;
}

function normalizeFeeSponsorProgramResponse(
  payload,
  context = "fee sponsor program response",
) {
  const record = ensureRecord(payload ?? {}, context);
  assertSupportedOptionKeys(record, FEE_SPONSOR_PROGRAM_RESPONSE_KEYS, context);
  const id = ensureRecord(record.id, `${context}.id`);
  assertSupportedOptionKeys(id, new Set(["sponsor", "name"]), `${context}.id`);
  const sponsor = ToriiClient._requireAccountId(id.sponsor, `${context}.id.sponsor`);
  if (sponsor !== id.sponsor) {
    rejectType(`${context}.id.sponsor must be a canonical I105 account id`);
  }
  requireCanonicalIrohaName(id.name, `${context}.id.name`);
  const payoutAccount = ToriiClient._requireAccountId(
    record.payout_account,
    `${context}.payout_account`,
  );
  if (payoutAccount !== record.payout_account) {
    rejectType(`${context}.payout_account must be a canonical I105 account id`);
  }
  const lifecycle = normalizeTaggedUnit(
    record.lifecycle,
    "state",
    new Set(["staged", "paused", "active", "closing", "closed"]),
    `${context}.lifecycle`,
  );
  const normalized = {
    id: { sponsor, name: id.name },
    payout_account: payoutAccount,
    lifecycle: { state: lifecycle, value: null },
  };
  for (const field of ["active_revision", "staged_revision"]) {
    if (Object.prototype.hasOwnProperty.call(record, field)) {
      if (record[field] === null || record[field] === undefined) {
        rejectType(`${context}.${field} must be omitted or a positive integer`);
      }
      normalized[field] = normalizeFeeSponsorPositiveU64(
        record[field],
        `${context}.${field}`,
      );
    }
  }
  if (Object.prototype.hasOwnProperty.call(record, "scheduled_activation")) {
    if (record.scheduled_activation === null || record.scheduled_activation === undefined) {
      rejectType(`${context}.scheduled_activation must be omitted or an exact object`);
    }
    const activation = ensureRecord(
      record.scheduled_activation,
      `${context}.scheduled_activation`,
    );
    assertSupportedOptionKeys(
      activation,
      new Set(["revision", "activate_at_height"]),
      `${context}.scheduled_activation`,
    );
    const revision = normalizeFeeSponsorPositiveU64(
      activation.revision,
      `${context}.scheduled_activation.revision`,
    );
    const activateAtHeight = normalizeFeeSponsorPositiveU64(
      activation.activate_at_height,
      `${context}.scheduled_activation.activate_at_height`,
    );
    normalized.scheduled_activation = {
      revision,
      activate_at_height: activateAtHeight,
    };
  }
  return normalized;
}

function normalizeFeeSponsorPositiveU64(value, context) {
  const normalized = normalizeKaigiU64(value, context);
  if (BigInt(normalized) === 0n) {
    rejectType(`${context} must be a positive unsigned integer`);
  }
  return normalized;
}

function rejectRetiredFeeSelectionFields(
  record,
  context,
  { allowGasLimit = false } = {},
) {
  const retired = [
    ["gas_asset_id", "fee_payment"],
    ["gasAssetId", "feePayment"],
    ["fee_sponsor", "fee_payment"],
    ["feeSponsor", "feePayment"],
  ];
  if (!allowGasLimit) {
    retired.push(["gas_limit", "fee_payment.value.gas_limit"]);
    retired.push(["gasLimit", "feePayment.value.gas_limit"]);
  }
  for (const [field, replacement] of retired) {
    if (Object.prototype.hasOwnProperty.call(record, field)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${context}.${field} is retired; use ${replacement}`,
        normalizeErrorPath(`${context}.${field}`),
      );
    }
  }
}

function requireExactFeeQuoteObject(value, expectedFields, context) {
  const record = ensureRecord(value, context);
  assertSupportedOptionKeys(record, expectedFields, context);
  const missing = [...expectedFields].filter(
    (field) => !Object.prototype.hasOwnProperty.call(record, field),
  );
  if (missing.length !== 0) {
    rejectType(`${context} is missing required fields: ${missing.join(", ")}`);
  }
  return record;
}

function normalizeFeePaymentIntentValue(
  intent,
  context,
  { requireGasLimit = false } = {},
) {
  const record = requireExactFeeQuoteObject(
    intent,
    new Set(["payer", "value"]),
    context,
  );
  const payer = requireExactNonEmptyString(record.payer, `${context}.payer`);
  if (payer !== "authority" && payer !== "sponsor") {
    rejectType(`${context}.payer must be authority or sponsor`);
  }
  const valueFields = new Set(["charge_limits", "gas_limit"]);
  if (payer === "sponsor") {
    valueFields.add("program_id");
    valueFields.add("program_revision");
  }
  const value = requireExactFeeQuoteObject(
    record.value,
    valueFields,
    `${context}.value`,
  );
  const normalizedValue = {};
  if (payer === "sponsor") {
    const programId = requireExactFeeQuoteObject(
      value.program_id,
      new Set(["sponsor", "name"]),
      `${context}.value.program_id`,
    );
    const sponsor = ensureCanonicalAccountId(
      programId.sponsor,
      `${context}.value.program_id.sponsor`,
    );
    if (sponsor !== programId.sponsor) {
      rejectType(`${context}.value.program_id.sponsor must be a canonical I105 account id`);
    }
    const name = requireCanonicalIrohaName(
      programId.name,
      `${context}.value.program_id.name`,
    );
    normalizedValue.program_id = { sponsor, name };
    normalizedValue.program_revision = ToriiClient._normalizeUnsignedInteger(
      value.program_revision,
      `${context}.value.program_revision`,
      { allowZero: false },
    );
  }
  let previousKind = -1;
  normalizedValue.charge_limits = requireDenseArray(
    value.charge_limits,
    `${context}.value.charge_limits`,
  ).map((limit, index) => {
    const limitContext = `${context}.value.charge_limits[${index}]`;
    const item = requireExactFeeQuoteObject(
      limit,
      new Set(["kind", "asset_definition_id", "max_amount"]),
      limitContext,
    );
    const taggedKind = requireExactFeeQuoteObject(
      item.kind,
      new Set(["kind", "value"]),
      `${limitContext}.kind`,
    );
    const kind = normalizeTaggedUnit(
      taggedKind,
      "kind",
      new Set(["nexus", "pipeline_gas"]),
      `${limitContext}.kind`,
    );
    const kindIndex = kind === "nexus" ? 0 : 1;
    if (kindIndex <= previousKind) {
      rejectType(`${context}.value.charge_limits must be unique and ordered nexus before pipeline_gas`);
    }
    previousKind = kindIndex;
    const assetDefinitionId = normalizeAssetDefinitionId(
      item.asset_definition_id,
      `${limitContext}.asset_definition_id`,
    );
    if (assetDefinitionId !== item.asset_definition_id) {
      rejectType(`${limitContext}.asset_definition_id must be an exact canonical asset definition id`);
    }
    const maxAmount = requireCanonicalQuantity(
      item.max_amount,
      `${limitContext}.max_amount`,
    );
    if (NumericV1.decodeQuantityJson(maxAmount).mantissa === 0n) {
      rejectType(`${limitContext}.max_amount must be greater than zero`);
    }
    return {
      kind: { kind, value: null },
      asset_definition_id: assetDefinitionId,
      max_amount: maxAmount,
    };
  });
  if (value.gas_limit !== null) {
    normalizedValue.gas_limit = ToriiClient._normalizeUnsignedInteger(
      value.gas_limit,
      `${context}.value.gas_limit`,
      { allowZero: false },
    );
  } else {
    normalizedValue.gas_limit = null;
  }
  if (requireGasLimit && normalizedValue.gas_limit === null) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.value.gas_limit is required for contract execution`,
      normalizeErrorPath(`${context}.value.gas_limit`),
    );
  }
  return { payer, value: normalizedValue };
}

function normalizeFeePaymentIntentResponse(intent, context) {
  return normalizeFeePaymentIntentValue(intent, context);
}

function normalizeFeeQuoteDraft(payload, context) {
  const record = ensureRecord(payload, context);
  const authority = ensureCanonicalAccountId(
    record.authority,
    `${context}.authority`,
  );
  if (record.authority !== authority) {
    rejectType(`${context}.authority must be an exact canonical I105 account id`);
  }
  return {
    authority,
    intent: normalizeFeePaymentIntentValue(
      record.fee_payment,
      `${context}.fee_payment`,
    ),
  };
}

function feeQuoteSelectionsMatch(quotedIntent, draftIntent) {
  if (
    quotedIntent.payer !== draftIntent.payer
    || quotedIntent.value.gas_limit !== draftIntent.value.gas_limit
  ) {
    return false;
  }
  if (quotedIntent.payer === "authority") {
    return true;
  }
  return (
    quotedIntent.value.program_revision === draftIntent.value.program_revision
    && feeQuoteAccountIdsHaveSameIdentity(
      quotedIntent.value.program_id.sponsor,
      draftIntent.value.program_id.sponsor,
    )
    && quotedIntent.value.program_id.name === draftIntent.value.program_id.name
  );
}

function feeQuoteAccountIdsHaveSameIdentity(left, right) {
  try {
    return (
      parseCanonicalI105AccountLiteral(left).canonicalHex
      === parseCanonicalI105AccountLiteral(right).canonicalHex
    );
  } catch {
    return false;
  }
}

function parseFeeQuoteQuantity(value, context) {
  return NumericV1.decodeQuantityJson(requireCanonicalQuantity(value, context));
}

function addFeeQuoteQuantities(left, right, context) {
  const scale = Math.max(left.scale, right.scale);
  const leftMantissa = left.mantissa * 10n ** BigInt(scale - left.scale);
  const rightMantissa = right.mantissa * 10n ** BigInt(scale - right.scale);
  try {
    return new KotodamaQuantity(leftMantissa + rightMantissa, scale);
  } catch (error) {
    if (!(error instanceof NumericV1Error)) throw error;
    rejectType(`${context} is outside the exact Quantity domain (${error.code})`);
  }
}

function compareFeeQuoteQuantities(left, right) {
  const scale = Math.max(left.scale, right.scale);
  const leftMantissa = left.mantissa * 10n ** BigInt(scale - left.scale);
  const rightMantissa = right.mantissa * 10n ** BigInt(scale - right.scale);
  return leftMantissa < rightMantissa ? -1 : leftMantissa > rightMantissa ? 1 : 0;
}

function normalizeFeeQuoteComponent(value, context) {
  const item = requireExactFeeQuoteObject(
    value,
    new Set(["kind", "asset_definition_id", "max_amount"]),
    context,
  );
  const taggedKind = requireExactFeeQuoteObject(
    item.kind,
    new Set(["kind", "value"]),
    `${context}.kind`,
  );
  const kind = normalizeTaggedUnit(
    taggedKind,
    "kind",
    new Set(["nexus", "pipeline_gas"]),
    `${context}.kind`,
  );
  const assetDefinitionId = normalizeAssetDefinitionId(
    item.asset_definition_id,
    `${context}.asset_definition_id`,
  );
  if (assetDefinitionId !== item.asset_definition_id) {
    rejectType(`${context}.asset_definition_id must be an exact canonical asset definition id`);
  }
  const maxAmount = requireCanonicalQuantity(
    item.max_amount,
    `${context}.max_amount`,
  );
  if (NumericV1.decodeQuantityJson(maxAmount).mantissa === 0n) {
    rejectType(`${context}.max_amount must be greater than zero`);
  }
  return { kind, assetDefinitionId, maxAmount };
}

function normalizeFeeQuoteCapacity(value, context) {
  const item = requireExactFeeQuoteObject(
    value,
    new Set([
      "asset_definition_id",
      "vault_balance",
      "reserve_floor",
      "block_remaining",
      "program_epoch_remaining",
      "beneficiary_epoch_remaining",
    ]),
    context,
  );
  const assetDefinitionId = normalizeAssetDefinitionId(
    item.asset_definition_id,
    `${context}.asset_definition_id`,
  );
  if (assetDefinitionId !== item.asset_definition_id) {
    rejectType(`${context}.asset_definition_id must be an exact canonical asset definition id`);
  }
  return {
    assetDefinitionId,
    vaultBalance: parseFeeQuoteQuantity(item.vault_balance, `${context}.vault_balance`),
    reserveFloor: parseFeeQuoteQuantity(item.reserve_floor, `${context}.reserve_floor`),
    blockRemaining: parseFeeQuoteQuantity(item.block_remaining, `${context}.block_remaining`),
    programEpochRemaining: parseFeeQuoteQuantity(
      item.program_epoch_remaining,
      `${context}.program_epoch_remaining`,
    ),
    beneficiaryEpochRemaining: parseFeeQuoteQuantity(
      item.beneficiary_epoch_remaining,
      `${context}.beneficiary_epoch_remaining`,
    ),
  };
}

function normalizeFeeQuoteDecision(value, context) {
  const decision = requireExactFeeQuoteObject(
    value,
    new Set(["status", "value"]),
    context,
  );
  if (decision.status !== "accepted") {
    rejectType(`${context}.status must be accepted`);
  }
  const decisionValue = requireExactFeeQuoteObject(
    decision.value,
    new Set(["debit_source", "program_revision"]),
    `${context}.value`,
  );
  const debitSource = requireExactFeeQuoteObject(
    decisionValue.debit_source,
    new Set(["kind", "value"]),
    `${context}.value.debit_source`,
  );
  const kind = requireExactNonEmptyString(
    debitSource.kind,
    `${context}.value.debit_source.kind`,
  );
  if (kind !== "account" && kind !== "sponsor_program") {
    rejectType(`${context}.value.debit_source.kind is unsupported`);
  }
  return {
    kind,
    value: debitSource.value,
    programRevision: decisionValue.program_revision,
  };
}

function validateSponsorFeeQuoteCapacities(components, capacities, context) {
  if ((components.length === 0) !== (capacities.length === 0)) {
    rejectType(`${context}.capacities must be empty exactly when sponsored components are empty`);
  }
  const aggregateByAsset = new Map();
  for (const component of components) {
    const quantity = NumericV1.decodeQuantityJson(component.maxAmount);
    const current = aggregateByAsset.get(component.assetDefinitionId);
    aggregateByAsset.set(
      component.assetDefinitionId,
      current === undefined
        ? quantity
        : addFeeQuoteQuantities(
            current,
            quantity,
            `${context}.components aggregate for ${component.assetDefinitionId}`,
          ),
    );
  }
  // Canonical asset-definition addresses encode the same fixed 21-byte width.
  // Standard Base58 alphabet order therefore matches byte order and JS code-unit order.
  const assetDefinitionIds = [...aggregateByAsset.keys()].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  if (capacities.length !== assetDefinitionIds.length) {
    rejectType(`${context}.capacities must contain exactly one entry per component asset`);
  }
  capacities.forEach((capacity, index) => {
    const assetDefinitionId = assetDefinitionIds[index];
    if (capacity.assetDefinitionId !== assetDefinitionId) {
      rejectType(`${context}.capacities are duplicated, unrelated, or not in canonical asset order`);
    }
    const aggregate = aggregateByAsset.get(assetDefinitionId);
    const requiredVaultBalance = addFeeQuoteQuantities(
      capacity.reserveFloor,
      aggregate,
      `${context}.capacities[${index}] required vault balance`,
    );
    if (compareFeeQuoteQuantities(capacity.vaultBalance, requiredVaultBalance) < 0) {
      rejectType(`${context}.capacities[${index}].vault_balance does not cover reserve_floor plus the aggregate charge`);
    }
    for (const [field, remaining] of [
      ["block_remaining", capacity.blockRemaining],
      ["program_epoch_remaining", capacity.programEpochRemaining],
      ["beneficiary_epoch_remaining", capacity.beneficiaryEpochRemaining],
    ]) {
      if (compareFeeQuoteQuantities(remaining, aggregate) < 0) {
        rejectType(`${context}.capacities[${index}].${field} does not cover the aggregate charge`);
      }
    }
  });
}

function validateFeeQuoteForDraft(
  payloadOrDraft,
  quote,
  context = "fee quote response",
) {
  const candidate = payloadOrDraft?.payload ?? payloadOrDraft;
  const draft = normalizeFeeQuoteDraft(candidate, "fee quote draft payload");
  const record = requireExactFeeQuoteObject(
    quote,
    FEE_QUOTE_RESPONSE_KEYS,
    context,
  );
  const intent = normalizeFeePaymentIntentResponse(
    record.intent,
    `${context}.intent`,
  );
  if (!feeQuoteSelectionsMatch(intent, draft.intent)) {
    rejectType(`${context}.intent changed the draft payer, sponsor revision, or gas bound`);
  }
  const observation = requireExactFeeQuoteObject(
    record.observation,
    new Set(["ledger_time_ms", "next_block_height", "route_dataspace_id"]),
    `${context}.observation`,
  );
  ToriiClient._normalizeUnsignedInteger(
    observation.ledger_time_ms,
    `${context}.observation.ledger_time_ms`,
    { allowZero: true },
  );
  ToriiClient._normalizeUnsignedInteger(
    observation.next_block_height,
    `${context}.observation.next_block_height`,
    { allowZero: false },
  );
  ToriiClient._normalizeUnsignedInteger(
    observation.route_dataspace_id,
    `${context}.observation.route_dataspace_id`,
    { allowZero: true },
  );
  const components = requireDenseArray(
    record.components,
    `${context}.components`,
  ).map((component, index) =>
    normalizeFeeQuoteComponent(component, `${context}.components[${index}]`),
  );
  if (components.length !== intent.value.charge_limits.length) {
    rejectType(`${context}.components differ from the quoted intent`);
  }
  components.forEach((component, index) => {
    const limit = intent.value.charge_limits[index];
    if (
      component.kind !== limit.kind.kind
      || component.assetDefinitionId !== limit.asset_definition_id
      || component.maxAmount !== limit.max_amount
    ) {
      rejectType(`${context}.components differ from the quoted intent`);
    }
  });
  const capacities = requireDenseArray(
    record.capacities,
    `${context}.capacities`,
  ).map((capacity, index) =>
    normalizeFeeQuoteCapacity(capacity, `${context}.capacities[${index}]`),
  );
  const decision = normalizeFeeQuoteDecision(record.decision, `${context}.decision`);
  if (intent.payer === "authority") {
    if (decision.kind !== "account" || decision.programRevision !== null) {
      rejectType(`${context}.decision is inconsistent with authority payment`);
    }
    const account = ensureCanonicalAccountId(
      decision.value,
      `${context}.decision.value.debit_source.value`,
    );
    if (
      decision.value !== account
      || !feeQuoteAccountIdsHaveSameIdentity(account, draft.authority)
    ) {
      rejectType(`${context}.decision is inconsistent with authority payment`);
    }
    if (capacities.length !== 0) {
      rejectType(`${context}.capacities must be empty for authority payment`);
    }
    return record;
  }
  if (decision.kind !== "sponsor_program") {
    rejectType(`${context}.decision is inconsistent with sponsor payment`);
  }
  const decisionProgramId = requireExactFeeQuoteObject(
    decision.value,
    new Set(["sponsor", "name"]),
    `${context}.decision.value.debit_source.value`,
  );
  const decisionSponsor = ensureCanonicalAccountId(
    decisionProgramId.sponsor,
    `${context}.decision.value.debit_source.value.sponsor`,
  );
  const decisionName = requireCanonicalIrohaName(
    decisionProgramId.name,
    `${context}.decision.value.debit_source.value.name`,
  );
  const decisionRevision = ToriiClient._normalizeUnsignedInteger(
    decision.programRevision,
    `${context}.decision.value.program_revision`,
    { allowZero: false },
  );
  if (
    decisionSponsor !== decisionProgramId.sponsor
    || !feeQuoteAccountIdsHaveSameIdentity(
      decisionSponsor,
      intent.value.program_id.sponsor,
    )
    || decisionName !== intent.value.program_id.name
    || decisionRevision !== intent.value.program_revision
  ) {
    rejectType(`${context}.decision is inconsistent with sponsor payment`);
  }
  validateSponsorFeeQuoteCapacities(components, capacities, context);
  return record;
}

function requireDenseArray(value, context) {
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(value, index)) {
      rejectType(`${context} must be a dense array`);
    }
  }
  return value;
}

function requireCanonicalIrohaName(value, context) {
  const name = requireExactNonEmptyString(value, context);
  let hasUnpairedSurrogate = false;
  for (let index = 0; index < name.length; index += 1) {
    const codeUnit = name.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = name.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        hasUnpairedSurrogate = true;
        break;
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      hasUnpairedSurrogate = true;
      break;
    }
  }
  const hasBidiControl = Array.from(name).some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint === 0x061c
      || codePoint === 0x200e
      || codePoint === 0x200f
      || (codePoint >= 0x202a && codePoint <= 0x202e)
      || (codePoint >= 0x2066 && codePoint <= 0x2069);
  });
  if (
    hasUnpairedSurrogate
    || Buffer.byteLength(name, "utf8") > 255
    || /[\p{Cc}\p{White_Space}@#$\/]/u.test(name)
    || hasBidiControl
    || name.normalize("NFC") !== name
  ) {
    rejectType(`${context} must be a canonical Iroha Name`);
  }
  return name;
}

function buildIdentifierResolveRequest(options, context) {
  const record = ensureRecord(options, `${context} options`);
  assertSupportedOptionKeys(
    record,
    new Set(["policyId", "input", "encryptedInput", "outputOpening"]),
    `${context} options`,
  );
  const policyId = requireNonEmptyString(record.policyId, `${context}.policyId`);
  if (policyId.startsWith("phone#")) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} requires signed canonicality attestation support for phone policies`,
      `${context}.policyId`,
    );
  }
  if (record.input !== undefined && record.input !== null) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} options are encrypted-only; use encryptedInput`,
      `${context}.input`,
    );
  }
  if (record.encryptedInput === undefined || record.encryptedInput === null) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} options must supply encryptedInput`,
      `${context}.encryptedInput`,
    );
  }
  if (record.outputOpening === undefined || record.outputOpening === null) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} options must supply outputOpening`,
      `${context}.outputOpening`,
    );
  }
  return {
    policy_id: policyId,
    encrypted_input: requireHexString(
      record.encryptedInput,
      `${context}.encryptedInput`,
    ),
    output_opening: normalizeRamLfeOutputOpening(
      record.outputOpening,
      `${context}.outputOpening`,
    ),
  };
}

function buildRamLfeExecuteRequest(options, context) {
  const record = ensureRecord(options, `${context} options`);
  assertSupportedOptionKeys(
    record,
    new Set(["encryptedInput"]),
    `${context} options`,
  );
  if (record.encryptedInput === undefined || record.encryptedInput === null) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} options must supply encryptedInput`,
      `${context}.encryptedInput`,
    );
  }
  return {
    encrypted_input: requireHexString(
      record.encryptedInput,
      `${context}.encryptedInput`,
    ),
  };
}

function buildRamLfeReceiptVerifyRequest(options, context) {
  const record = ensureRecord(options, `${context} options`);
  assertSupportedOptionKeys(
    record,
    new Set(["receipt", "outputHex"]),
    `${context} options`,
  );
  if (record.receipt === undefined || record.receipt === null) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} options must supply a receipt object`,
      `${context}.receipt`,
    );
  }
  const payload = {
    receipt: ensureRecord(record.receipt, `${context}.receipt`),
  };
  if (record.outputHex !== undefined && record.outputHex !== null) {
    payload.output_hex = requireHexString(record.outputHex, `${context}.outputHex`);
  }
  return payload;
}

function irohaHashBytes(parts) {
  const digest = Buffer.from(blake2b256(Buffer.concat(parts.map((part) => Buffer.from(part)))));
  digest[digest.length - 1] |= 1;
  return digest;
}

function requireBfvUint(value, name, options = {}) {
  const allowZero = options.allowZero !== false;
  let integer;
  if (typeof value === JS_TYPE_BIGINT) {
    integer = value;
  } else if (typeof value === JS_TYPE_NUMBER) {
    if (!Number.isFinite(value) || !Number.isInteger(value) || !Number.isSafeInteger(value)) {
      throw createValidationError(
        ValidationErrorCode.VALUE_OUT_OF_RANGE,
        `${name} must be a safe integer number, bigint, or decimal string`,
        name,
      );
    }
    integer = BigInt(value);
  } else if (typeof value === JS_TYPE_STRING) {
    const trimmed = value.trim();
    if (!/^[0-9]+$/.test(trimmed)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_NUMERIC,
        `${name} must be a non-negative integer`,
        name,
      );
    }
    integer = BigInt(trimmed);
  } else {
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${name} must be a non-negative integer`,
      name,
    );
  }
  if (integer < 0n || (!allowZero && integer === 0n)) {
    const qualifier = allowZero ? "non-negative integer" : "positive integer";
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${name} must be a ${qualifier}`,
      name,
    );
  }
  return integer;
}

function requireSafeBfvUint(value, name, options = {}) {
  const integer = requireBfvUint(value, name, options);
  if (integer > MAX_SAFE_INTEGER_BIGINT) {
    throw createValidationError(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${name} must be at most ${MAX_SAFE_INTEGER}`,
      name,
    );
  }
  return integer;
}

function normalizeIdentifierBfvUint(value, name, options = {}) {
  const integer = options.safe
    ? requireSafeBfvUint(value, name, options)
    : requireBfvUint(value, name, options);
  return integer <= MAX_SAFE_INTEGER_BIGINT ? Number(integer) : integer;
}

function normalizeIdentifierBfvUintArray(value, context) {
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  return value.map((entry, index) =>
    normalizeIdentifierBfvUint(entry, `${context}[${index}]`, { allowZero: true }),
  );
}

function normalizeIdentifierBfvParameters(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    polynomial_degree: normalizeIdentifierBfvUint(
      record.polynomial_degree,
      `${context}.polynomial_degree`,
      { allowZero: false, safe: true },
    ),
    plaintext_modulus: normalizeIdentifierBfvUint(
      record.plaintext_modulus,
      `${context}.plaintext_modulus`,
      { allowZero: false },
    ),
    ciphertext_modulus: normalizeIdentifierBfvUint(
      record.ciphertext_modulus,
      `${context}.ciphertext_modulus`,
      { allowZero: false },
    ),
    decomposition_base_log: normalizeIdentifierBfvUint(
      record.decomposition_base_log,
      `${context}.decomposition_base_log`,
      { allowZero: false, safe: true },
    ),
  };
}

function normalizeIdentifierBfvPublicKey(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    b: normalizeIdentifierBfvUintArray(record.b, `${context}.b`),
    a: normalizeIdentifierBfvUintArray(record.a, `${context}.a`),
  };
}

function normalizeIdentifierBfvPublicParameters(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const normalized = {
    parameters: normalizeIdentifierBfvParameters(
      record.parameters,
      `${context}.parameters`,
    ),
    public_key: normalizeIdentifierBfvPublicKey(
      record.public_key,
      `${context}.public_key`,
    ),
    max_input_bytes: normalizeIdentifierBfvUint(
      record.max_input_bytes,
      `${context}.max_input_bytes`,
      { allowZero: false, safe: true },
    ),
  };
  if (
    record.norito_length_encoding !== undefined &&
    record.norito_length_encoding !== null
  ) {
    normalized.norito_length_encoding = requireExactNonEmptyString(
      record.norito_length_encoding,
      `${context}.norito_length_encoding`,
    );
  }
  return normalized;
}

function normalizeIdentifierPolicyListResponse(
  payload,
  context = "identifier policy list response",
) {
  const record = ensureRecord(payload ?? {}, context);
  const itemsValue = record.items;
  if (!Array.isArray(itemsValue)) {
    rejectError(`${context}.items must be an array`);
  }
  return {
    total: ToriiClient._normalizeUnsignedInteger(record.total ?? itemsValue.length, `${context}.total`, {
      allowZero: true,
    }),
    items: itemsValue.map((item, index) =>
      normalizeIdentifierPolicySummary(item, `${context}.items[${index}]`),
    ),
  };
}

function normalizeRamLfeProgramPolicyListResponse(
  payload,
  context = "ram-lfe program policy list response",
) {
  const record = ensureRecord(payload ?? {}, context);
  const itemsValue = record.items;
  if (!Array.isArray(itemsValue)) {
    rejectError(`${context}.items must be an array`);
  }
  return {
    total: ToriiClient._normalizeUnsignedInteger(record.total ?? itemsValue.length, `${context}.total`, {
      allowZero: true,
    }),
    items: itemsValue.map((item, index) =>
      normalizeRamLfeProgramPolicySummary(item, `${context}.items[${index}]`),
    ),
  };
}

const RAM_LFE_BACKEND_TAGS = new Set([
  "hkdf-sha3-512-prf-v1",
  "bfv-affine-v1",
  "bfv-programmed-v1",
]);
const RAM_LFE_VERIFICATION_MODES = new Set(["signed", "proof"]);

function requireExactRamLfeTag(value, context, tags, kind) {
  const tag = requireExactNonEmptyString(value, context);
  if (tag !== tag.toLowerCase()) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} must be an exact lowercase RAM-LFE ${kind}`,
      context,
    );
  }
  if (!tags.has(tag)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} must be one of: ${[...tags].join(", ")}`,
      context,
    );
  }
  return tag;
}

function requireExactRamLfeBackend(value, context) {
  return requireExactRamLfeTag(value, context, RAM_LFE_BACKEND_TAGS, "backend tag");
}

function requireExactRamLfeVerificationMode(value, context) {
  return requireExactRamLfeTag(value, context, RAM_LFE_VERIFICATION_MODES, "verification mode");
}

function normalizeRamLfeProgramPolicySummary(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const backend = requireExactRamLfeBackend(record.backend, `${context}.backend`);
  const verificationMode = requireExactRamLfeVerificationMode(
    record.verification_mode,
    `${context}.verification_mode`,
  );
  const result = {
    program_id: requireExactNonEmptyString(record.program_id, `${context}.program_id`),
    owner: requireExactAccountId(record.owner, `${context}.owner`),
    active: record.active === true,
    resolver_public_key: requireExactNonEmptyString(
      record.resolver_public_key,
      `${context}.resolver_public_key`,
    ),
    output_opening_public_key: requireExactNonEmptyString(
      record.output_opening_public_key,
      `${context}.output_opening_public_key`,
    ),
    backend,
    verification_mode: verificationMode,
  };
  if (record.input_encryption !== undefined && record.input_encryption !== null) {
    result.input_encryption = requireExactNonEmptyString(
      record.input_encryption,
      `${context}.input_encryption`,
    );
  }
  if (
    record.input_encryption_public_parameters !== undefined &&
    record.input_encryption_public_parameters !== null
  ) {
    result.input_encryption_public_parameters = requireExactHexString(
      record.input_encryption_public_parameters,
      `${context}.input_encryption_public_parameters`,
    );
  }
  if (
    record.input_encryption_public_parameters_decoded !== undefined &&
    record.input_encryption_public_parameters_decoded !== null
  ) {
    result.input_encryption_public_parameters_decoded =
      normalizeIdentifierBfvPublicParameters(
        record.input_encryption_public_parameters_decoded,
        `${context}.input_encryption_public_parameters_decoded`,
      );
  }
  if (record.proof_verifier !== undefined && record.proof_verifier !== null) {
    result.proof_verifier = normalizeRamLfeProofVerifierMetadata(
      record.proof_verifier,
      `${context}.proof_verifier`,
    );
  }
  if (record.ram_fhe_profile !== undefined && record.ram_fhe_profile !== null) {
    result.ram_fhe_profile = normalizeRamLfeProgramProfile(
      record.ram_fhe_profile,
      `${context}.ram_fhe_profile`,
    );
  }
  if (record.note !== undefined && record.note !== null) {
    result.note = requireNonEmptyString(record.note, `${context}.note`);
  }
  return result;
}

function normalizeRamLfeProofVerifierMetadata(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    proof_backend: requireExactNonEmptyString(record.proof_backend, `${context}.proof_backend`),
    circuit_id: requireExactNonEmptyString(record.circuit_id, `${context}.circuit_id`),
    public_inputs_schema_hash: requireExactReceiptHash(
      record.public_inputs_schema_hash,
      `${context}.public_inputs_schema_hash`,
    ),
    verifying_key_bytes_b64: requireExactNonEmptyString(
      record.verifying_key_bytes_b64,
      `${context}.verifying_key_bytes_b64`,
    ),
  };
}

function normalizeRamLfeProgramProfile(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  assertSupportedOptionKeys(record, new Set([
    "initializer_descriptor_hash", "profile_version", "register_count", "memory_lane_count",
    "ciphertext_mul_per_step", "encrypted_input_mode", "min_ciphertext_modulus",
  ]), context);
  const encryptedInputMode = requireExactNonEmptyString(
    record.encrypted_input_mode,
    `${context}.encrypted_input_mode`,
  );
  if (encryptedInputMode !== "encrypted_envelope_v1") {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context}.encrypted_input_mode must be encrypted_envelope_v1`,
      `${context}.encrypted_input_mode`,
    );
  }
  const dimension = (field, maximum) => {
    const name = `${context}.${field}`;
    const value = BigInt(normalizeGovernanceUint64Integer(record[field], name, { allowZero: false }));
    if (value > maximum) {
      throw createValidationError(
        ValidationErrorCode.VALUE_OUT_OF_RANGE,
        `${name} must be at most ${maximum}`,
        name,
      );
    }
    return value <= MAX_SAFE_INTEGER_BIGINT ? Number(value) : value;
  };
  return {
    profile_version: dimension("profile_version", 255n),
    register_count: dimension("register_count", 65535n),
    memory_lane_count: dimension("memory_lane_count", 65535n),
    ciphertext_mul_per_step: dimension("ciphertext_mul_per_step", 255n),
    encrypted_input_mode: encryptedInputMode,
    min_ciphertext_modulus: dimension("min_ciphertext_modulus", (1n << 64n) - 1n),
    initializer_descriptor_hash: normalizeIrohaHashHex32(
      requireExactReceiptHash(record.initializer_descriptor_hash, `${context}.initializer_descriptor_hash`),
      `${context}.initializer_descriptor_hash`,
    ),
  };
}

function normalizeIdentifierPolicySummary(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const normalization = requireExactNonEmptyString(
    record.normalization,
    `${context}.normalization`,
  );
  if (normalization !== normalization.toLowerCase()) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context}.normalization must be an exact lowercase identifier normalization`,
      `${context}.normalization`,
    );
  }
  const backend = requireExactRamLfeBackend(record.backend, `${context}.backend`);
  const result = {
    policy_id: requireIdentifierPolicyId(record.policy_id, `${context}.policy_id`),
    owner: requireExactAccountId(record.owner, `${context}.owner`),
    active: record.active === true,
    normalization,
    resolver_public_key: requireExactNonEmptyString(
      record.resolver_public_key,
      `${context}.resolver_public_key`,
    ),
    backend,
  };
  result.program_id = requireExactTokenString(
    record.program_id,
    `${context}.program_id`,
  );
  result.output_opening_public_key = requireExactTokenString(
    record.output_opening_public_key,
    `${context}.output_opening_public_key`,
  );
  if (record.phone_retail_attestor_public_key !== undefined && record.phone_retail_attestor_public_key !== null) {
    result.phone_retail_attestor_public_key = requireExactNonEmptyString(
      record.phone_retail_attestor_public_key,
      `${context}.phone_retail_attestor_public_key`,
    );
  }
  if (record.input_encryption !== undefined && record.input_encryption !== null) {
    const inputEncryption = requireExactNonEmptyString(
      record.input_encryption,
      `${context}.input_encryption`,
    );
    if (inputEncryption !== inputEncryption.toLowerCase()) {
      throw createValidationError(
        ValidationErrorCode.INVALID_STRING,
        `${context}.input_encryption must be an exact lowercase identifier encryption tag`,
        `${context}.input_encryption`,
      );
    }
    result.input_encryption = inputEncryption;
  }
  if (
    record.input_encryption_public_parameters !== undefined &&
    record.input_encryption_public_parameters !== null
  ) {
    result.input_encryption_public_parameters = requireExactHexString(
      record.input_encryption_public_parameters,
      `${context}.input_encryption_public_parameters`,
    );
  }
  if (
    record.input_encryption_public_parameters_decoded !== undefined &&
    record.input_encryption_public_parameters_decoded !== null
  ) {
    result.input_encryption_public_parameters_decoded =
      normalizeIdentifierBfvPublicParameters(
        record.input_encryption_public_parameters_decoded,
        `${context}.input_encryption_public_parameters_decoded`,
      );
  }
  if (record.proof_verifier !== undefined && record.proof_verifier !== null) {
    result.proof_verifier = normalizeRamLfeProofVerifierMetadata(
      record.proof_verifier,
      `${context}.proof_verifier`,
    );
  }
  if (record.ram_fhe_profile !== undefined && record.ram_fhe_profile !== null) {
    result.ram_fhe_profile = normalizeRamLfeProgramProfile(
      record.ram_fhe_profile,
      `${context}.ram_fhe_profile`,
    );
  }
  if (record.note !== undefined && record.note !== null) {
    result.note = requireExactNonEmptyString(record.note, `${context}.note`);
  }
  return result;
}

function normalizeIdentifierResolutionPayload(
  payload,
  context = "identifier resolution payload",
) {
  const record = ensureRecord(payload ?? {}, context);
  assertSupportedOptionKeys(
    record,
    new Set([
      "policy_id",
      "execution",
      "opening",
      "opaque_id",
      "receipt_hash",
      "uaid",
      "account_id",
    ]),
    context,
  );
  return {
    policy_id: requireIdentifierPolicyId(record.policy_id, `${context}.policy_id`),
    execution: normalizeIdentifierResolutionExecutionPayload(
      record.execution,
      `${context}.execution`,
    ),
    opening: normalizeRamLfeOutputOpening(record.opening, `${context}.opening`),
    opaque_id: requireExactReceiptPrefixedHash(record.opaque_id, "opaque:", `${context}.opaque_id`),
    receipt_hash: requireExactReceiptHash(record.receipt_hash, `${context}.receipt_hash`),
    uaid: requireExactReceiptUaid(record.uaid, `${context}.uaid`),
    account_id: requireExactAccountId(record.account_id, `${context}.account_id`),
  };
}

function requireExactReceiptHash(value, name) {
  return requireExactLowerHex32String(value, name);
}

function requireExactReceiptPrefixedHash(value, prefix, name) {
  const literal = requireExactNonEmptyString(value, name);
  if (!literal.startsWith(prefix)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must start with ${prefix}`,
      name,
    );
  }
  return `${prefix}${requireExactLowerHex32String(literal.slice(prefix.length), name)}`;
}

function requireExactReceiptUaid(value, name) {
  const uaid = requireExactReceiptPrefixedHash(value, "uaid:", name);
  if (!/[13579bdf]$/iu.test(uaid)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${name} must have least significant bit set to 1`,
      name,
    );
  }
  return uaid;
}

function requireExactAccountId(value, name) {
  const literal = requireExactNonEmptyString(value, name);
  const normalized = normalizeAccountId(literal, name);
  if (normalized !== literal) {
    throw createValidationError(
      ValidationErrorCode.INVALID_ACCOUNT_ID,
      `${name} must be a canonical I105 account id`,
      name,
    );
  }
  return literal;
}

function requireIdentifierPolicyId(value, name) {
  const literal = requireExactNonEmptyString(value, name);
  const parts = literal.split("#", 2);
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${name} must use kind#rule`,
      name,
    );
  }
  if (parts[0].trim() !== parts[0]) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${name}.kind must not contain surrounding whitespace`,
      `${name}.kind`,
    );
  }
  if (parts[1].trim() !== parts[1]) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${name}.rule must not contain surrounding whitespace`,
      `${name}.rule`,
    );
  }
  return literal;
}

function requireExactReceiptUnsignedInteger(value, name) {
  return requireExactJsonUnsignedInteger(value, name, { allowZero: true });
}

function normalizeIdentifierResolutionExecutionPayload(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  assertSupportedOptionKeys(
    record,
    new Set([
      "program_id",
      "program_digest",
      "backend",
      "verification_mode",
      "input_ciphertext_hash",
      "output_ciphertext_hash",
      "parameter_digest",
      "evaluation_key_digest",
      "output_hash",
      "associated_data_hash",
      "executed_at_ms",
      "expires_at_ms",
    ]),
    context,
  );
  const backend = requireExactRamLfeBackend(record.backend, `${context}.backend`);
  const verificationMode = requireExactRamLfeVerificationMode(
    record.verification_mode,
    `${context}.verification_mode`,
  );
  return {
    program_id: requireExactNonEmptyString(record.program_id, `${context}.program_id`),
    program_digest: requireExactReceiptHash(record.program_digest, `${context}.program_digest`),
    backend,
    verification_mode: verificationMode,
    input_ciphertext_hash: requireExactReceiptHash(
      record.input_ciphertext_hash,
      `${context}.input_ciphertext_hash`,
    ),
    output_ciphertext_hash: requireExactReceiptHash(
      record.output_ciphertext_hash,
      `${context}.output_ciphertext_hash`,
    ),
    parameter_digest: requireExactReceiptHash(
      record.parameter_digest,
      `${context}.parameter_digest`,
    ),
    evaluation_key_digest: requireExactReceiptHash(
      record.evaluation_key_digest,
      `${context}.evaluation_key_digest`,
    ),
    output_hash: requireExactReceiptHash(record.output_hash, `${context}.output_hash`),
    associated_data_hash: requireExactReceiptHash(
      record.associated_data_hash,
      `${context}.associated_data_hash`,
    ),
    executed_at_ms: requireExactReceiptUnsignedInteger(
      record.executed_at_ms,
      `${context}.executed_at_ms`,
    ),
    expires_at_ms:
      record.expires_at_ms === undefined || record.expires_at_ms === null
        ? null
        : requireExactReceiptUnsignedInteger(
          record.expires_at_ms,
          `${context}.expires_at_ms`,
        ),
  };
}

function normalizeRamLfeOutputOpening(opening, context) {
  const record = ensureRecord(opening ?? {}, context);
  const payload = ensureRecord(record.payload ?? {}, `${context}.payload`);
  assertSupportedOptionKeys(record, new Set(["payload", "signature"]), context);
  assertSupportedOptionKeys(
    payload,
    new Set([
      "program_id",
      "input_ciphertext_hash",
      "output_ciphertext_hash",
      "parameter_digest",
      "evaluation_key_digest",
      "opened_output_hash",
      "opened_at_ms",
      "expires_at_ms",
    ]),
    `${context}.payload`,
  );
  const signature = requireExactHexString(record.signature, `${context}.signature`);
  if (signature !== signature.toLowerCase()) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${context}.signature must be exact lowercase hex`,
      `${context}.signature`,
    );
  }
  return {
    payload: {
      program_id: requireExactNonEmptyString(payload.program_id, `${context}.payload.program_id`),
      input_ciphertext_hash: requireExactReceiptHash(
        payload.input_ciphertext_hash,
        `${context}.payload.input_ciphertext_hash`,
      ),
      output_ciphertext_hash: requireExactReceiptHash(
        payload.output_ciphertext_hash,
        `${context}.payload.output_ciphertext_hash`,
      ),
      parameter_digest: requireExactReceiptHash(
        payload.parameter_digest,
        `${context}.payload.parameter_digest`,
      ),
      evaluation_key_digest: requireExactReceiptHash(
        payload.evaluation_key_digest,
        `${context}.payload.evaluation_key_digest`,
      ),
      opened_output_hash: requireExactReceiptHash(
        payload.opened_output_hash,
        `${context}.payload.opened_output_hash`,
      ),
      opened_at_ms: requireExactReceiptUnsignedInteger(
        payload.opened_at_ms,
        `${context}.payload.opened_at_ms`,
      ),
      expires_at_ms:
        payload.expires_at_ms === undefined || payload.expires_at_ms === null
          ? null
          : requireExactReceiptUnsignedInteger(
            payload.expires_at_ms,
            `${context}.payload.expires_at_ms`,
          ),
    },
    signature,
  };
}

function normalizeIdentifierReceiptAttestation(attestation, context) {
  const record = ensureRecord(attestation ?? {}, context);
  const kind = requireExactNonEmptyString(record.kind, `${context}.kind`);
  if (kind === "signed") {
    assertSupportedOptionKeys(record, new Set(["kind", "signature"]), context);
    const signature = requireExactHexString(record.signature, `${context}.signature`);
    if (signature !== signature.toUpperCase()) {
      throw createValidationError(
        ValidationErrorCode.INVALID_HEX,
        `${context}.signature must be exact uppercase hex`,
        `${context}.signature`,
      );
    }
    return {
      kind,
      signature,
    };
  }
  if (kind === "proof") {
    assertSupportedOptionKeys(
      record,
      new Set(["kind", "proof_backend", "proof_b64"]),
      context,
    );
    return {
      kind,
      proof_backend: requireExactNonEmptyString(record.proof_backend, `${context}.proof_backend`),
      proof_b64: normalizeRequiredExactBase64Payload(
        record.proof_b64,
        `${context}.proof_b64`,
      ),
    };
  }
  throw createValidationError(
    ValidationErrorCode.INVALID_OBJECT,
    `${context}.kind must be signed or proof`,
    `${context}.kind`,
  );
}

function normalizeIdentifierResolveResponse(
  payload,
  context = "identifier resolve response",
) {
  const record = ensureRecord(payload ?? {}, context);
  assertSupportedOptionKeys(record, new Set(["payload", "attestation"]), context);
  return {
    payload: normalizeIdentifierResolutionPayload(record.payload, `${context}.payload`),
    attestation: normalizeIdentifierReceiptAttestation(
      record.attestation,
      `${context}.attestation`,
    ),
  };
}

function normalizeIdentifierClaimLookupResponse(
  payload,
  context = "identifier claim lookup response",
) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    policy_id: requireIdentifierPolicyId(record.policy_id, `${context}.policy_id`),
    opaque_id: requireExactReceiptPrefixedHash(record.opaque_id, "opaque:", `${context}.opaque_id`),
    receipt_hash: requireExactReceiptHash(record.receipt_hash, `${context}.receipt_hash`),
    uaid: requireExactReceiptUaid(record.uaid, `${context}.uaid`),
    account_id: requireExactAccountId(record.account_id, `${context}.account_id`),
    verified_at_ms: ToriiClient._normalizeUnsignedInteger(
      record.verified_at_ms,
      `${context}.verified_at_ms`,
      { allowZero: true },
    ),
    expires_at_ms:
      record.expires_at_ms === undefined || record.expires_at_ms === null
        ? null
        : ToriiClient._normalizeUnsignedInteger(
          record.expires_at_ms,
          `${context}.expires_at_ms`,
          { allowZero: true },
    ),
  };
}

function normalizeRamLfeExecuteResponse(
  payload,
  context = "ram-lfe execute response",
) {
  const record = ensureRecord(payload ?? {}, context);
  assertSupportedOptionKeys(
    record,
    new Set([
      "program_id",
      "opaque_hash",
      "receipt_hash",
      "output_ciphertext",
      "output_hash",
      "associated_data_hash",
      "executed_at_ms",
      "expires_at_ms",
      "backend",
      "verification_mode",
      "receipt",
    ]),
    context,
  );
  const backend = requireExactRamLfeBackend(record.backend, `${context}.backend`);
  const verificationMode = requireExactRamLfeVerificationMode(
    record.verification_mode,
    `${context}.verification_mode`,
  );
  const receiptRecord = ensureRecord(record.receipt ?? {}, `${context}.receipt`);
  assertSupportedOptionKeys(
    receiptRecord,
    new Set(["payload", "attestation"]),
    `${context}.receipt`,
  );
  const normalized = {
    program_id: requireExactNonEmptyString(record.program_id, `${context}.program_id`),
    opaque_hash: requireExactReceiptHash(record.opaque_hash, `${context}.opaque_hash`),
    receipt_hash: requireExactReceiptHash(record.receipt_hash, `${context}.receipt_hash`),
    output_ciphertext: requireExactHexString(
      record.output_ciphertext,
      `${context}.output_ciphertext`,
    ),
    output_hash: requireExactReceiptHash(record.output_hash, `${context}.output_hash`),
    associated_data_hash: requireExactReceiptHash(
      record.associated_data_hash,
      `${context}.associated_data_hash`,
    ),
    executed_at_ms: requireExactJsonUnsignedInteger(
      record.executed_at_ms,
      `${context}.executed_at_ms`,
      { allowZero: true },
    ),
    expires_at_ms:
      record.expires_at_ms === undefined || record.expires_at_ms === null
        ? null
        : requireExactJsonUnsignedInteger(
          record.expires_at_ms,
          `${context}.expires_at_ms`,
          { allowZero: true },
        ),
    backend,
    verification_mode: verificationMode,
    receipt: {
      payload: normalizeIdentifierResolutionExecutionPayload(
        receiptRecord.payload,
        `${context}.receipt.payload`,
      ),
      attestation: normalizeIdentifierReceiptAttestation(
        receiptRecord.attestation,
        `${context}.receipt.attestation`,
      ),
    },
  };
  const receiptPayload = normalized.receipt.payload;
  const matchingTopLevelFields = [
    "program_id",
    "output_hash",
    "associated_data_hash",
    "executed_at_ms",
    "expires_at_ms",
    "backend",
    "verification_mode",
  ];
  for (const field of matchingTopLevelFields) {
    if (normalized[field] !== receiptPayload[field]) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${context}.${field} does not match ${context}.receipt.payload.${field}`,
        `${context}.${field}`,
      );
    }
  }
  return normalized;
}

function normalizeRamLfeReceiptVerifyResponse(
  payload,
  context = "ram-lfe receipt verify response",
) {
  const record = ensureRecord(payload ?? {}, context);
  const backend = requireExactRamLfeBackend(record.backend, `${context}.backend`);
  const verificationMode = requireExactRamLfeVerificationMode(
    record.verification_mode,
    `${context}.verification_mode`,
  );
  const result = {
    valid: record.valid === true,
    program_id: requireExactNonEmptyString(record.program_id, `${context}.program_id`),
    backend,
    verification_mode: verificationMode,
    output_hash: requireExactReceiptHash(record.output_hash, `${context}.output_hash`),
    associated_data_hash: requireExactReceiptHash(
      record.associated_data_hash,
      `${context}.associated_data_hash`,
    ),
  };
  if (record.output_hash_matches !== undefined && record.output_hash_matches !== null) {
    result.output_hash_matches = record.output_hash_matches === true;
  }
  if (record.error !== undefined && record.error !== null) {
    result.error = requireNonEmptyString(record.error, `${context}.error`);
  }
  return result;
}

function normalizeSorafsInventoryReadOptions(options, context) {
  const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(options, context);
  const canonicalAuth = ToriiClient._normalizeCanonicalAuth(
    rest.canonicalAuth,
    `${context}.canonicalAuth`,
  );
  if (!canonicalAuth) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} options.canonicalAuth is required`,
      `${context}.canonicalAuth`,
    );
  }
  const { canonicalAuth: _ignoredCanonicalAuth, ...filterOptions } = rest;
  return { signal, canonicalAuth, rest: filterOptions };
}

function buildSorafsAliasListParams(options = {}) {
  const record = ensureRecord(options, "listSorafsAliases options");
  assertSupportedOptionKeys(
    record,
    new Set(["namespace", "manifestDigestHex", "limit", "offset"]),
    "listSorafsAliases options",
  );
  const params = {};
  if (record.namespace !== undefined && record.namespace !== null) {
    params.namespace = requireNonEmptyString(
      record.namespace,
      "sorafsAliasList.namespace",
    );
  }
  if (record.manifestDigestHex !== undefined && record.manifestDigestHex !== null) {
    params.manifest_digest = normalizeHex32String(
      record.manifestDigestHex,
      "sorafsAliasList.manifestDigestHex",
    );
  }
  if (record.limit !== undefined && record.limit !== null) {
    params.limit = ToriiClient._normalizeUnsignedInteger(
      record.limit,
      "sorafsAliasList.limit",
      { allowZero: false },
    );
  }
  if (record.offset !== undefined && record.offset !== null) {
    params.offset = ToriiClient._normalizeUnsignedInteger(
      record.offset,
      "sorafsAliasList.offset",
      { allowZero: true },
    );
  }
  return Object.keys(params).length === 0 ? undefined : params;
}

function buildSorafsPinListParams(options = {}) {
  const record = ensureRecord(options, "listSorafsPinManifests options");
  assertSupportedOptionKeys(
    record,
    new Set([
      "status",
      "limit",
      "maxBytes",
      "afterDigestHex",
      EXPECTED_FINALIZED_HEIGHT_FIELD,
      EXPECTED_FINALIZED_HASH_FIELD,
    ]),
    "listSorafsPinManifests options",
  );
  const params = {};
  if (record.status !== undefined && record.status !== null) {
    const status = requireNonEmptyString(
      record.status,
      "sorafsPinList.status",
    );
    if (!SORAFS_PIN_STATUS_VALUES.has(status)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_STRING,
        "sorafsPinList.status must be exactly pending, approved, or retired",
        "sorafsPinList.status",
      );
    }
    params.status = status;
  }
  if (record.limit !== undefined && record.limit !== null) {
    params.limit = ToriiClient._normalizeUnsignedInteger(
      record.limit,
      "sorafsPinList.limit",
      { allowZero: false, max: SORAFS_PIN_LIST_MAX_ITEMS },
    );
  }
  if (record.maxBytes !== undefined && record.maxBytes !== null) {
    params.max_bytes = ToriiClient._normalizeUnsignedInteger(
      record.maxBytes,
      "sorafsPinList.maxBytes",
      {
        allowZero: false,
        min: SORAFS_PIN_LIST_MIN_PAGE_BYTES,
        max: SORAFS_PIN_LIST_MAX_PAGE_BYTES,
      },
    );
  }
  if (record.afterDigestHex !== undefined && record.afterDigestHex !== null) {
    params.after_digest_hex = requireNonZeroLowerHex32String(
      record.afterDigestHex,
      "sorafsPinList.afterDigestHex",
    );
  }

  const hasExpectedHeight =
    record.expectedFinalizedHeight !== undefined;
  const hasExpectedBlockHash =
    record.expectedFinalizedBlockHashHex !== undefined;
  if (hasExpectedHeight !== hasExpectedBlockHash) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      "sorafsPinList.expectedFinalizedHeight and sorafsPinList.expectedFinalizedBlockHashHex must be supplied together",
      "sorafsPinList.expectedFinalizedHeight",
    );
  }
  if (hasExpectedHeight) {
    const height = normalizeSorafsPinU64(record.expectedFinalizedHeight, "sorafsPinList.expectedFinalizedHeight");
    if (height === 0) rejectType("sorafsPinList.expectedFinalizedHeight must be positive");
    params.expected_finalized_height = String(height);
    params.expected_finalized_block_hash_hex = requireNonZeroLowerHex32String(
      record.expectedFinalizedBlockHashHex,
      "sorafsPinList.expectedFinalizedBlockHashHex",
    );
  }
  return Object.keys(params).length === 0 ? undefined : params;
}

function buildSorafsReplicationListParams(options = {}) {
  const record = ensureRecord(options, "listSorafsReplicationOrders options");
  assertSupportedOptionKeys(
    record,
    new Set(["status", "manifestDigestHex", "limit", "offset"]),
    "listSorafsReplicationOrders options",
  );
  const params = {};
  if (record.status !== undefined) {
    const normalized = requireExactNonEmptyString(
      record.status,
      "sorafsReplicationList.status",
    );
    if (!SORAFS_REPLICATION_STATUS_VALUES.has(normalized)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_STRING,
        "sorafsReplicationList.status must be exactly pending, completed, cancelled, or expired",
        "sorafsReplicationList.status",
      );
    }
    params.status = normalized;
  }
  if (record.manifestDigestHex !== undefined) {
    params.manifest_digest = requireNonZeroLowerHex32String(
      record.manifestDigestHex,
      "sorafsReplicationList.manifestDigestHex",
    );
  }
  if (record.limit !== undefined) {
    params.limit = normalizeSorafsPinU64(record.limit, "sorafsReplicationList.limit", 500n);
    if (params.limit === 0) rejectType("sorafsReplicationList.limit must be positive");
  }
  if (record.offset !== undefined) {
    params.offset = normalizeSorafsPinU64(record.offset, "sorafsReplicationList.offset", 0xffff_ffffn);
  }
  return Object.keys(params).length === 0 ? undefined : params;
}

function normalizeSorafsReputationProviderId(value, context) {
  const providerId = requireExactNonEmptyString(value, context);
  if (providerId.length > 256) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} must be at most 256 characters`,
      context,
    );
  }
  if (!/^[0-9A-Za-z_.:-]+$/u.test(providerId)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} contains unsupported characters`,
      context,
    );
  }
  if (providerId === "." || providerId === "..") {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} must not be a URL dot segment`,
      context,
    );
  }
  return providerId;
}

function normalizeReputationSnapshotIdHex(value, context) {
  if (typeof value !== JS_TYPE_STRING || !/^[0-9a-f]{32}$/u.test(value)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${context} must be exactly 32 lowercase hexadecimal characters`,
      context,
    );
  }
  if (/^0{32}$/u.test(value)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${context} must be nonzero`,
      context,
    );
  }
  return value;
}

function normalizeSorafsHedgingBillingDigest(value, context) {
  const digest = requireExactLowerHex32String(value, context);
  if (/^0{64}$/u.test(digest)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${context} must be nonzero`,
      context,
    );
  }
  return digest;
}

function normalizeSorafsHedgingBillingLimit(value, context) {
  if (
    typeof value !== JS_TYPE_NUMBER ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > 100
  ) {
    throw createValidationError(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${context} must be an integer from 1 through 100`,
      context,
    );
  }
  return value;
}

function normalizeSorafsHedgingBillingOptions(
  options,
  context,
  allowedKeys,
) {
  const { signal, rest } = ToriiClient._normalizeOptionsWithSignal(
    options,
    context,
  );
  assertSupportedOptionKeys(rest, allowedKeys, `${context} options`);
  const canonicalAuth = ToriiClient._normalizeCanonicalAuth(
    rest.canonicalAuth,
    `${context}.canonicalAuth`,
  );
  if (!canonicalAuth) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} options.canonicalAuth is required`,
      `${context}.canonicalAuth`,
    );
  }
  return { signal, rest, canonicalAuth };
}

const SORAFS_REPUTATION_CANONICAL_AUTH_HEADERS = new Set([
  "x-iroha-account",
  "x-iroha-signature",
  "x-iroha-timestamp-ms",
  "x-iroha-nonce",
  "x-iroha-witness",
]);

function sorafsReputationCanonicalAuthEntries(headers, context) {
  if (headers === undefined || headers === null) {
    return new Map();
  }
  const entries = new Map();
  for (const [rawName, rawValue] of Object.entries(headers)) {
    const normalizedName = String(rawName).toLowerCase();
    if (!SORAFS_REPUTATION_CANONICAL_AUTH_HEADERS.has(normalizedName)) {
      continue;
    }
    if (entries.has(normalizedName)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${context} contains duplicate canonical authentication header ${rawName}`,
        context,
      );
    }
    entries.set(normalizedName, { name: rawName, value: rawValue });
  }
  return entries;
}

function buildSorafsReputationRequestAuth(
  options,
  defaultHeaders,
  context,
  { accept = APPLICATION_JSON } = {},
) {
  const defaultAuth = sorafsReputationCanonicalAuthEntries(
    defaultHeaders,
    "ToriiClient.options.defaultHeaders",
  );
  if (defaultAuth.size !== 0) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} requires per-request canonical authentication; canonical auth headers are not accepted through defaultHeaders`,
      `${context}.headers`,
    );
  }

  const headers = buildSorafsReputationHeaders(options, context, { accept });
  const authHeaders = sorafsReputationCanonicalAuthEntries(
    headers,
    `${context}.headers`,
  );
  if (options.canonicalAuth !== undefined && options.canonicalAuth !== null) {
    if (authHeaders.size !== 0) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${context} accepts exactly one canonical authentication mode`,
        `${context}.canonicalAuth`,
      );
    }
    return {
      headers,
      canonicalAuth: ToriiClient._normalizeCanonicalAuth(
        options.canonicalAuth,
        `${context}.canonicalAuth`,
      ),
    };
  }

  const witness = authHeaders.get("x-iroha-witness");
  const signatureProofHeaders = [
    "x-iroha-signature",
    "x-iroha-timestamp-ms",
    "x-iroha-nonce",
  ].filter((name) => authHeaders.has(name));
  if (signatureProofHeaders.length !== 0) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.headers cannot supply signature proof fields directly; use canonicalAuth`,
      `${context}.headers`,
    );
  }
  if (!witness) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} requires canonicalAuth or an exact X-Iroha-Witness header`,
      `${context}.canonicalAuth`,
    );
  }
  if (typeof witness.value !== JS_TYPE_STRING) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context}.headers.X-Iroha-Witness must be exact standard-base64`,
      `${context}.headers.X-Iroha-Witness`,
    );
  }
  setHeader(
    headers,
    "X-Iroha-Witness",
    normalizeCanonicalWitnessHeader(witness.value, `${context}.headers.X-Iroha-Witness`),
  );
  const account = authHeaders.get("x-iroha-account");
  if (account) {
    const canonicalAccount = requireCanonicalAuthAccount(
      account.value,
      `${context}.headers.X-Iroha-Account`,
    );
    setHeader(headers, "X-Iroha-Account", canonicalAccount.includes("@") ? canonicalAccount : AccountAddress.parseEncoded(canonicalAccount).address.canonicalHex());
  }
  return { headers, canonicalAuth: null };
}

function rejectSorafsReputationResumeHeader(headers, defaultHeaders, context) {
  if (
    hasHeader(headers, "last-event-id") ||
    hasHeader(defaultHeaders, "last-event-id")
  ) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} does not accept Last-Event-ID; use the finalized since cursor`,
      `${context}.headers`,
    );
  }
}

function buildSorafsReputationHeaders(
  options = {},
  context,
  { accept = APPLICATION_JSON } = {},
) {
  const headers = {};
  if (options.headers !== undefined && options.headers !== null) {
    if (!isPlainObject(options.headers)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${context}.headers must be an object`,
        `${context}.headers`,
      );
    }
    for (const [key, value] of Object.entries(options.headers)) {
      if (value !== undefined && value !== null) {
        headers[key] = SORAFS_REPUTATION_CANONICAL_AUTH_HEADERS.has(
          key.toLowerCase(),
        )
          ? value
          : String(value);
      }
    }
  }
  setHeader(headers, "Accept", accept);
  if (
    options.ifNoneMatch !== undefined &&
    options.ifNoneMatch !== null &&
    hasHeader(headers, "if-none-match")
  ) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} accepts If-None-Match only through ifNoneMatch`,
      `${context}.ifNoneMatch`,
    );
  }
  const ifNoneMatch = options.ifNoneMatch;
  if (ifNoneMatch !== undefined && ifNoneMatch !== null) {
    headers["If-None-Match"] = requireExactNonEmptyString(
      ifNoneMatch,
      `${context}.ifNoneMatch`,
    );
  }
  return headers;
}

function normalizeSorafsReputationDecimal(
  value,
  context,
  { allowZero, max = MAX_UINT64_BIGINT },
) {
  let integer;
  if (typeof value === JS_TYPE_NUMBER) {
    if (!Number.isSafeInteger(value)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_NUMERIC,
        `${context} must be a safe integer, bigint, or canonical decimal string`,
        context,
      );
    }
    integer = BigInt(value);
  } else if (typeof value === JS_TYPE_BIGINT) {
    integer = value;
  } else if (
    typeof value === JS_TYPE_STRING &&
    /^(?:0|[1-9][0-9]*)$/u.test(value)
  ) {
    integer = BigInt(value);
  } else {
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${context} must be a canonical unsigned decimal integer`,
      context,
    );
  }
  if (integer < 0n || (!allowZero && integer === 0n)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_NUMERIC,
      `${context} must be ${allowZero ? "non-negative" : "positive"}`,
      context,
    );
  }
  if (integer > max) {
    throw createValidationError(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${context} must be at most ${max.toString(10)}`,
      context,
    );
  }
  return integer.toString(10);
}

function buildSorafsReputationEventsParams(options = {}, context) {
  const params = {};
  if (options.since !== undefined && options.since !== null) {
    params.since = normalizeSorafsReputationDecimal(
      options.since,
      `${context}.since`,
      { allowZero: true, max: MAX_UINT64_BIGINT },
    );
  }
  if (options.limit !== undefined && options.limit !== null) {
    params.limit = normalizeSorafsReputationDecimal(
      options.limit,
      `${context}.limit`,
      { allowZero: false, max: 500n },
    );
  }
  return Object.keys(params).length === 0 ? undefined : params;
}

function buildSorafsOrderbookHeaders(options = {}, context, { cache = false } = {}) {
  const headers = { Accept: APPLICATION_JSON };
  if (options.headers !== undefined && options.headers !== null) {
    if (!isPlainObject(options.headers)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${context}.headers must be an object`,
        `${context}.headers`,
      );
    }
    for (const [key, value] of Object.entries(options.headers)) {
      if (value !== undefined && value !== null) {
        headers[key] = String(value);
      }
    }
  }
  if (!cache) {
    return headers;
  }
  const ifNoneMatch = options.ifNoneMatch;
  if (ifNoneMatch !== undefined && ifNoneMatch !== null) {
    headers["If-None-Match"] = requireNonEmptyString(
      ifNoneMatch,
      `${context}.ifNoneMatch`,
    );
  }
  return headers;
}

function normalizeSorafsOrderbookQueryLimit(value, context) {
  const limit = ToriiClient._normalizeUnsignedInteger(value, context, {
    allowZero: false,
    max: 500,
  });
  return limit;
}

function appendSorafsOrderbookFinalizedAnchor(params, options, context) {
  const hasHeight =
    options.expectedFinalizedHeight !== undefined &&
    options.expectedFinalizedHeight !== null;
  const hasHash =
    options.expectedFinalizedBlockHashHex !== undefined &&
    options.expectedFinalizedBlockHashHex !== null;
  if (hasHeight !== hasHash) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} requires expectedFinalizedHeight and expectedFinalizedBlockHashHex together`,
      `${context}.expectedFinalizedHeight`,
    );
  }
  if (!hasHeight) {
    return;
  }
  params.expected_finalized_height = ToriiClient._normalizeUnsignedInteger(
    options.expectedFinalizedHeight,
    `${context}.expectedFinalizedHeight`,
    { allowZero: false },
  );
  params.expected_finalized_block_hash_hex = normalizeNonZeroHex32String(
    options.expectedFinalizedBlockHashHex,
    `${context}.expectedFinalizedBlockHashHex`,
  );
}

function buildSorafsOrderbookReadParams(options = {}, context) {
  const params = {};
  appendSorafsOrderbookFinalizedAnchor(params, options, context);
  if (options.limit !== undefined && options.limit !== null) {
    params.limit = normalizeSorafsOrderbookQueryLimit(
      options.limit,
      `${context}.limit`,
    );
  }
  if (options.afterIdHex !== undefined && options.afterIdHex !== null) {
    params.after_id_hex = normalizeHex32String(
      options.afterIdHex,
      `${context}.afterIdHex`,
    );
  }
  return Object.keys(params).length === 0 ? undefined : params;
}

function appendSorafsOrderbookEventCursor(params, options, context) {
  const cursorFields = [
    ["afterSequence", "after_sequence"],
    ["afterBlockHeight", "after_block_height"],
    ["afterBlockHashHex", "after_block_hash_hex"],
    ["afterEventIndex", "after_event_index"],
  ];
  const present = cursorFields.map(
    ([field]) => options[field] !== undefined && options[field] !== null,
  );
  if (present.some(Boolean) && !present.every(Boolean)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} requires the complete afterSequence/afterBlockHeight/afterBlockHashHex/afterEventIndex cursor`,
      `${context}.afterSequence`,
    );
  }
  if (!present.every(Boolean)) {
    return;
  }
  params.after_sequence = ToriiClient._normalizeUnsignedInteger(
    options.afterSequence,
    `${context}.afterSequence`,
    { allowZero: false },
  );
  params.after_block_height = ToriiClient._normalizeUnsignedInteger(
    options.afterBlockHeight,
    `${context}.afterBlockHeight`,
    { allowZero: false },
  );
  params.after_block_hash_hex = normalizeNonZeroHex32String(
    options.afterBlockHashHex,
    `${context}.afterBlockHashHex`,
  );
  params.after_event_index = ToriiClient._normalizeUnsignedInteger(
    options.afterEventIndex,
    `${context}.afterEventIndex`,
    { allowZero: true, max: 0xffff_ffff },
  );
}

function buildSorafsOrderbookEventsParams(options = {}, context) {
  const params = {};
  appendSorafsOrderbookFinalizedAnchor(params, options, context);
  if (options.limit !== undefined && options.limit !== null) {
    params.limit = normalizeSorafsOrderbookQueryLimit(
      options.limit,
      `${context}.limit`,
    );
  }
  appendSorafsOrderbookEventCursor(params, options, context);
  return Object.keys(params).length === 0 ? undefined : params;
}

function normalizeSorafsOrderbookFinalizedSource(value, context) {
  const source = requireNonEmptyString(value, context);
  if (source !== "finalized_chain") {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} must be finalized_chain`,
      context,
    );
  }
  return source;
}

function normalizeSorafsOrderbookFinalizedCursor(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    height: ToriiClient._normalizeUnsignedInteger(
      record.height,
      `${context}.height`,
      { allowZero: false },
    ),
    block_hash: normalizeNonZeroHex32String(
      record.block_hash,
      `${context}.block_hash`,
    ),
  };
}

function normalizeSorafsOrderbookLedgerStatus(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const normalized = {};
  for (const field of [
    "open_orders",
    "partially_filled_orders",
    "filled_orders",
    "cancelled_orders",
    "expired_orders",
    "trades",
    "settlement_receipts",
    "settlement_channels",
    "open_settlement_channels",
    "book_revision",
    "next_admission_sequence",
    "next_trade_sequence",
    "updated_at_unix",
  ]) {
    normalized[field] = ToriiClient._normalizeUnsignedInteger(
      record[field],
      `${context}.${field}`,
      { allowZero: true },
    );
  }
  return normalized;
}

function normalizeSorafsOrderbookRecordArray(value, context) {
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  return value.map((entry, index) => ({
    ...ensureRecord(entry, `${context}[${index}]`),
  }));
}

function normalizeSorafsOrderbookPage(
  payload,
  itemsField,
  nextField,
  context,
) {
  const record = ensureRecord(payload ?? {}, context);
  if (typeof record.has_more !== "boolean") {
    rejectType(`${context}.has_more must be a boolean`);
  }
  const next =
    record[nextField] === undefined || record[nextField] === null
      ? null
      : normalizeHex32String(record[nextField], `${context}.${nextField}`);
  if (record.has_more !== (next !== null)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.has_more must agree with ${nextField}`,
      `${context}.has_more`,
    );
  }
  return {
    finalized_cursor: normalizeSorafsOrderbookFinalizedCursor(
      record.finalized_cursor,
      `${context}.finalized_cursor`,
    ),
    [itemsField]: normalizeSorafsOrderbookRecordArray(
      record[itemsField],
      `${context}.${itemsField}`,
    ),
    has_more: record.has_more,
    [nextField]: next,
  };
}

function normalizeSorafsOrderbookBookResponse(
  payload,
  context = "sorafs orderbook book response",
) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    source: normalizeSorafsOrderbookFinalizedSource(
      record.source,
      `${context}.source`,
    ),
    status: normalizeSorafsOrderbookLedgerStatus(
      record.status,
      `${context}.status`,
    ),
    orders: normalizeSorafsOrderbookPage(
      record.orders,
      "orders",
      "next_after_order_id",
      `${context}.orders`,
    ),
  };
}

function normalizeSorafsOrderbookPageResponse(
  payload,
  field,
  nextField,
  context,
) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    source: normalizeSorafsOrderbookFinalizedSource(
      record.source,
      `${context}.source`,
    ),
    [field]: normalizeSorafsOrderbookPage(
      record[field],
      field,
      nextField,
      `${context}.${field}`,
    ),
  };
}

function normalizeSorafsOrderbookFinalizedEvent(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    sequence: ToriiClient._normalizeUnsignedInteger(
      record.sequence,
      `${context}.sequence`,
      { allowZero: false },
    ),
    block_height: ToriiClient._normalizeUnsignedInteger(
      record.block_height,
      `${context}.block_height`,
      { allowZero: false },
    ),
    block_hash: normalizeNonZeroHex32String(
      record.block_hash,
      `${context}.block_hash`,
    ),
    event_index: ToriiClient._normalizeUnsignedInteger(
      record.event_index,
      `${context}.event_index`,
      { allowZero: true, max: 0xffff_ffff },
    ),
    event: {
      ...ensureRecord(record.event, `${context}.event`),
    },
  };
}

function normalizeSorafsOrderbookFinalizedEventCursor(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    sequence: ToriiClient._normalizeUnsignedInteger(
      record.sequence,
      `${context}.sequence`,
      { allowZero: false },
    ),
    block_height: ToriiClient._normalizeUnsignedInteger(
      record.block_height,
      `${context}.block_height`,
      { allowZero: false },
    ),
    block_hash: normalizeNonZeroHex32String(
      record.block_hash,
      `${context}.block_hash`,
    ),
    event_index: ToriiClient._normalizeUnsignedInteger(
      record.event_index,
      `${context}.event_index`,
      { allowZero: true, max: 0xffff_ffff },
    ),
  };
}

function normalizeSorafsOrderbookEventsResponse(
  payload,
  context = "sorafs orderbook events response",
) {
  const record = ensureRecord(payload ?? {}, context);
  const page = ensureRecord(record.events, `${context}.events`);
  if (!Array.isArray(page.events)) {
    rejectType(`${context}.events.events must be an array`);
  }
  if (typeof page.has_more !== "boolean") {
    rejectType(`${context}.events.has_more must be a boolean`);
  }
  const nextAfter =
    page.next_after === undefined || page.next_after === null
      ? null
      : normalizeSorafsOrderbookFinalizedEventCursor(
          page.next_after,
          `${context}.events.next_after`,
        );
  if (page.has_more !== (nextAfter !== null)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.events.has_more must agree with next_after`,
      `${context}.events.has_more`,
    );
  }
  return {
    source: normalizeSorafsOrderbookFinalizedSource(
      record.source,
      `${context}.source`,
    ),
    events: {
      finalized_cursor: normalizeSorafsOrderbookFinalizedCursor(
        page.finalized_cursor,
        `${context}.events.finalized_cursor`,
      ),
      events: page.events.map((event, index) =>
        normalizeSorafsOrderbookFinalizedEvent(
          event,
          `${context}.events.events[${index}]`,
        ),
      ),
      has_more: page.has_more,
      next_after: nextAfter,
    },
  };
}

async function* normalizeSorafsOrderbookEventStream(events) {
  for await (const event of events) {
    yield {
      ...event,
      data: normalizeSorafsOrderbookFinalizedEvent(
        event?.data,
        `sorafs orderbook stream event${event?.id ? ` ${event.id}` : ""}`,
      ),
    };
  }
}

async function* normalizeSorafsOrderbookWebSocketEventStream(events) {
  for await (const event of events) {
    yield {
      ...event,
      data: normalizeSorafsOrderbookFinalizedEvent(
        event?.data,
        `sorafs orderbook websocket event ${event?.event ?? ""}`.trim(),
      ),
    };
  }
}

function normalizeSorafsXorQuantity(value, context) {
  if (typeof value === JS_TYPE_STRING && value.length > SORAFS_XOR_QUANTITY_MAX_TEXT_LENGTH) {
    throw createValidationError(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${context} exceeds the canonical XOR quantity text bound`,
      context,
    );
  }
  const normalized = requireCanonicalQuantity(value, context);
  const quantity = NumericV1.decodeQuantityJson(normalized);
  if (quantity.scale > 9) {
    throw createValidationError(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${context} must have at most 9 fractional decimal places`,
      context,
    );
  }
  return normalized;
}

function rejectRetiredSorafsMonetaryFields(record, retiredNames, context) {
  const present = retiredNames.filter((name) =>
    Object.prototype.hasOwnProperty.call(record, name),
  );
  if (present.length > 0) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} contains retired monetary field${present.length === 1 ? "" : "s"}: ${present.join(", ")}`,
      context,
    );
  }
}

const SORAFS_REPUTATION_SNAPSHOT_FIELDS = new Set([
  "snapshot_id_hex",
  "generated_at_unix",
  "previous_snapshot_id_hex",
  "merkle_root_hex",
  "provider_count",
  "returned_provider_count",
  "limit",
  "truncated_providers",
  "alpha_bps",
  "current_score_weight_bps",
  "weights",
  "providers",
]);
const SORAFS_REPUTATION_PROVIDER_RESPONSE_FIELDS = new Set([
  "snapshot_id_hex",
  "generated_at_unix",
  "merkle_root_hex",
  "provider",
  "proof",
]);
const SORAFS_REPUTATION_WEIGHTS_RESPONSE_FIELDS = new Set([
  "snapshot_id_hex",
  "generated_at_unix",
  "alpha_bps",
  "current_score_weight_bps",
  "weights",
]);
const SORAFS_REPUTATION_WEIGHTS_FIELDS = new Set([
  "version",
  "por_success_bps",
  "pdp_success_bps",
  "potr_success_bps",
  "latency_bps",
  "dispute_bps",
  "token_violation_bps",
  "repair_breach_bps",
]);
const SORAFS_REPUTATION_PROVIDER_FIELDS = new Set([
  "provider_id",
  "score_bps",
  "degradation_flags",
  "raw_metrics",
  "raw_metrics_hash_hex",
]);
const SORAFS_REPUTATION_PROVIDER_METRICS_FIELDS = new Set([
  "version",
  "por_success_bps",
  "pdp_success_bps",
  "potr_success_bps",
  "latency_health_bps",
  "dispute_rate_bps",
  "token_violation_rate_bps",
  "repair_breach_rate_bps",
]);
const SORAFS_REPUTATION_DEGRADATION_FLAG_FIELDS = new Set(["flag", "value"]);
const SORAFS_REPUTATION_PROOF_FIELDS = new Set([
  "provider_id",
  "leaf_index",
  "leaf_count",
  "siblings_hex",
]);
const SORAFS_REPUTATION_EVENT_FIELDS = new Set([
  "version",
  "sequence",
  "snapshot_id_hex",
  "generated_at_unix",
  "merkle_root_hex",
  "provider_count",
  "previous_snapshot_id_hex",
]);
const SORAFS_REPUTATION_EVENT_PAGE_FIELDS = new Set([
  "since",
  "limit",
  "count",
  "next_since",
  "events",
]);
const SORAFS_REPUTATION_DEGRADATION_FLAG_ORDER = Object.freeze([
  "reserve_warning",
  "reserve_grace",
  "reserve_delinquent",
  "reserve_default",
  "proof_success_below90",
  "proof_success_below80",
  "active_dispute",
  "slashing_event",
  "low_score",
]);
const SORAFS_REPUTATION_DEGRADATION_FLAG_INDEX = new Map(
  SORAFS_REPUTATION_DEGRADATION_FLAG_ORDER.map((flag, index) => [flag, index]),
);

function requireSorafsReputationExactObject(value, expectedFields, context) {
  const record = ensureRecord(value, context);
  const actualFields = Object.keys(record);
  const missing = [...expectedFields].filter(
    (field) => !Object.prototype.hasOwnProperty.call(record, field),
  );
  const extra = actualFields.filter((field) => !expectedFields.has(field));
  if (missing.length !== 0 || extra.length !== 0) {
    rejectType(`${context} fields are not canonical; missing=[${missing.join(
        ", ",
      )}] extra=[${extra.join(", ")}]`);
  }
  return record;
}

function requireSorafsReputationArray(value, context) {
  if (!Array.isArray(value)) {
    rejectType(`${context} must be an array`);
  }
  return value;
}

function parseSorafsReputationU64(
  value,
  context,
  { minimum = 0n, maximum = MAX_UINT64_BIGINT } = {},
) {
  let integer;
  if (
    typeof value === JS_TYPE_NUMBER &&
    Number.isSafeInteger(value) &&
    !Object.is(value, -0)
  ) {
    integer = BigInt(value);
  } else if (typeof value === JS_TYPE_BIGINT) {
    integer = value;
  } else {
    rejectType(`${context} must be a canonical unsigned integer`);
  }
  if (integer < minimum || integer > maximum) {
    rejectRange(`${context} must be between ${minimum.toString(10)} and ${maximum.toString(
        10,
      )}`);
  }
  return integer <= MAX_SAFE_INTEGER_BIGINT ? Number(integer) : integer;
}

function parseSorafsReputationBoundedInteger(value, context, minimum, maximum) {
  return Number(
    parseSorafsReputationU64(value, context, {
      minimum: BigInt(minimum),
      maximum: BigInt(maximum),
    }),
  );
}

function parseSorafsReputationExactInteger(value, context, expected) {
  const parsed = parseSorafsReputationBoundedInteger(
    value,
    context,
    expected,
    expected,
  );
  if (parsed !== expected) {
    rejectRange(`${context} must equal ${expected}`);
  }
  return parsed;
}

function parseSorafsReputationSnapshotId(value, context) {
  return normalizeReputationSnapshotIdHex(value, context);
}

function parseSorafsReputationOptionalSnapshotId(value, context) {
  return value === null ? null : parseSorafsReputationSnapshotId(value, context);
}

function parseSorafsReputationDigest(value, context) {
  if (typeof value !== JS_TYPE_STRING || !/^[0-9a-f]{64}$/u.test(value)) {
    rejectType(`${context} must be exactly 64 lowercase hexadecimal characters`);
  }
  return value;
}

function parseSorafsReputationWeights(value, context) {
  const weights = requireSorafsReputationExactObject(
    value,
    SORAFS_REPUTATION_WEIGHTS_FIELDS,
    context,
  );
  const parsed = {
    version: parseSorafsReputationExactInteger(
      weights.version,
      `${context}.version`,
      1,
    ),
    por_success_bps: parseSorafsReputationBoundedInteger(
      weights.por_success_bps,
      `${context}.por_success_bps`,
      0,
      10_000,
    ),
    pdp_success_bps: parseSorafsReputationBoundedInteger(
      weights.pdp_success_bps,
      `${context}.pdp_success_bps`,
      0,
      10_000,
    ),
    potr_success_bps: parseSorafsReputationBoundedInteger(
      weights.potr_success_bps,
      `${context}.potr_success_bps`,
      0,
      10_000,
    ),
    latency_bps: parseSorafsReputationBoundedInteger(
      weights.latency_bps,
      `${context}.latency_bps`,
      0,
      10_000,
    ),
    dispute_bps: parseSorafsReputationBoundedInteger(
      weights.dispute_bps,
      `${context}.dispute_bps`,
      0,
      10_000,
    ),
    token_violation_bps: parseSorafsReputationBoundedInteger(
      weights.token_violation_bps,
      `${context}.token_violation_bps`,
      0,
      10_000,
    ),
    repair_breach_bps: parseSorafsReputationBoundedInteger(
      weights.repair_breach_bps,
      `${context}.repair_breach_bps`,
      0,
      10_000,
    ),
  };
  const total =
    parsed.por_success_bps +
    parsed.pdp_success_bps +
    parsed.potr_success_bps +
    parsed.latency_bps +
    parsed.dispute_bps +
    parsed.token_violation_bps +
    parsed.repair_breach_bps;
  if (total !== 10_000) {
    rejectRange(`${context} basis-point fields must sum to exactly 10000`);
  }
  return parsed;
}

function parseSorafsReputationProviderMetrics(value, context) {
  const metrics = requireSorafsReputationExactObject(
    value,
    SORAFS_REPUTATION_PROVIDER_METRICS_FIELDS,
    context,
  );
  return {
    version: parseSorafsReputationExactInteger(
      metrics.version,
      `${context}.version`,
      1,
    ),
    por_success_bps: parseSorafsReputationBoundedInteger(
      metrics.por_success_bps,
      `${context}.por_success_bps`,
      0,
      10_000,
    ),
    pdp_success_bps: parseSorafsReputationBoundedInteger(
      metrics.pdp_success_bps,
      `${context}.pdp_success_bps`,
      0,
      10_000,
    ),
    potr_success_bps: parseSorafsReputationBoundedInteger(
      metrics.potr_success_bps,
      `${context}.potr_success_bps`,
      0,
      10_000,
    ),
    latency_health_bps: parseSorafsReputationBoundedInteger(
      metrics.latency_health_bps,
      `${context}.latency_health_bps`,
      0,
      10_000,
    ),
    dispute_rate_bps: parseSorafsReputationBoundedInteger(
      metrics.dispute_rate_bps,
      `${context}.dispute_rate_bps`,
      0,
      10_000,
    ),
    token_violation_rate_bps: parseSorafsReputationBoundedInteger(
      metrics.token_violation_rate_bps,
      `${context}.token_violation_rate_bps`,
      0,
      10_000,
    ),
    repair_breach_rate_bps: parseSorafsReputationBoundedInteger(
      metrics.repair_breach_rate_bps,
      `${context}.repair_breach_rate_bps`,
      0,
      10_000,
    ),
  };
}

function parseSorafsReputationProvider(value, context) {
  const provider = requireSorafsReputationExactObject(
    value,
    SORAFS_REPUTATION_PROVIDER_FIELDS,
    context,
  );
  const flags = requireSorafsReputationArray(
    provider.degradation_flags,
    `${context}.degradation_flags`,
  );
  if (flags.length > 5) {
    rejectRange(`${context}.degradation_flags must contain at most five entries`);
  }
  let previousFlagIndex = -1;
  const parsedFlags = flags.map((value, index) => {
    const flagContext = `${context}.degradation_flags[${index}]`;
    const flag = requireSorafsReputationExactObject(
      value,
      SORAFS_REPUTATION_DEGRADATION_FLAG_FIELDS,
      flagContext,
    );
    if (flag.value !== null) {
      rejectType(`${flagContext}.value must be null`);
    }
    if (typeof flag.flag !== JS_TYPE_STRING) {
      rejectType(`${flagContext}.flag must be a string`);
    }
    const flagIndex = SORAFS_REPUTATION_DEGRADATION_FLAG_INDEX.get(flag.flag);
    if (flagIndex === undefined) {
      rejectType(`${flagContext}.flag is unsupported`);
    }
    if (flagIndex <= previousFlagIndex) {
      rejectType(`${context}.degradation_flags must use canonical enum order without duplicates`);
    }
    previousFlagIndex = flagIndex;
    return { flag: flag.flag, value: null };
  });
  return {
    provider_id: normalizeSorafsReputationProviderId(
      provider.provider_id,
      `${context}.provider_id`,
    ),
    score_bps: parseSorafsReputationBoundedInteger(
      provider.score_bps,
      `${context}.score_bps`,
      500,
      9_900,
    ),
    degradation_flags: parsedFlags,
    raw_metrics: parseSorafsReputationProviderMetrics(
      provider.raw_metrics,
      `${context}.raw_metrics`,
    ),
    raw_metrics_hash_hex: parseSorafsReputationDigest(
      provider.raw_metrics_hash_hex,
      `${context}.raw_metrics_hash_hex`,
    ),
  };
}

function sorafsReputationMerkleDepth(leafCount) {
  let width = leafCount;
  let depth = 0;
  while (width > 1) {
    width = Math.ceil(width / 2);
    depth += 1;
  }
  return depth;
}

function parseSorafsReputationProof(value, context) {
  const proof = requireSorafsReputationExactObject(
    value,
    SORAFS_REPUTATION_PROOF_FIELDS,
    context,
  );
  const leafIndex = parseSorafsReputationBoundedInteger(
    proof.leaf_index,
    `${context}.leaf_index`,
    0,
    65_535,
  );
  const leafCount = parseSorafsReputationBoundedInteger(
    proof.leaf_count,
    `${context}.leaf_count`,
    1,
    65_536,
  );
  if (leafIndex >= leafCount) {
    rejectRange(`${context}.leaf_index must be less than leaf_count`);
  }
  const siblings = requireSorafsReputationArray(
    proof.siblings_hex,
    `${context}.siblings_hex`,
  ).map((sibling, index) =>
    parseSorafsReputationDigest(
      sibling,
      `${context}.siblings_hex[${index}]`,
    ),
  );
  if (siblings.length !== sorafsReputationMerkleDepth(leafCount)) {
    rejectRange(`${context}.siblings_hex must have the exact Merkle depth for leaf_count`);
  }
  return {
    provider_id: normalizeSorafsReputationProviderId(
      proof.provider_id,
      `${context}.provider_id`,
    ),
    leaf_index: leafIndex,
    leaf_count: leafCount,
    siblings_hex: siblings,
  };
}

function parseSorafsReputationEvent(value, context) {
  const event = requireSorafsReputationExactObject(
    value,
    SORAFS_REPUTATION_EVENT_FIELDS,
    context,
  );
  const snapshotId = parseSorafsReputationSnapshotId(
    event.snapshot_id_hex,
    `${context}.snapshot_id_hex`,
  );
  const previousSnapshotId = parseSorafsReputationOptionalSnapshotId(
    event.previous_snapshot_id_hex,
    `${context}.previous_snapshot_id_hex`,
  );
  if (previousSnapshotId === snapshotId) {
    rejectType(`${context}.previous_snapshot_id_hex must differ from snapshot_id_hex`);
  }
  return {
    version: parseSorafsReputationExactInteger(
      event.version,
      `${context}.version`,
      1,
    ),
    sequence: parseSorafsReputationU64(event.sequence, `${context}.sequence`, {
      minimum: 1n,
    }),
    snapshot_id_hex: snapshotId,
    generated_at_unix: parseSorafsReputationU64(
      event.generated_at_unix,
      `${context}.generated_at_unix`,
      { minimum: 1n },
    ),
    merkle_root_hex: parseSorafsReputationDigest(
      event.merkle_root_hex,
      `${context}.merkle_root_hex`,
    ),
    provider_count: parseSorafsReputationBoundedInteger(
      event.provider_count,
      `${context}.provider_count`,
      1,
      65_536,
    ),
    previous_snapshot_id_hex: previousSnapshotId,
  };
}

function parseSorafsReputationSnapshot(value, context, options = {}) {
  const snapshot = requireSorafsReputationExactObject(
    value,
    SORAFS_REPUTATION_SNAPSHOT_FIELDS,
    context,
  );
  const snapshotId = parseSorafsReputationSnapshotId(
    snapshot.snapshot_id_hex,
    `${context}.snapshot_id_hex`,
  );
  if (
    options.expectedSnapshotId !== undefined &&
    snapshotId !== options.expectedSnapshotId
  ) {
    rejectType(`${context} does not match the requested snapshot`);
  }
  const previousSnapshotId = parseSorafsReputationOptionalSnapshotId(
    snapshot.previous_snapshot_id_hex,
    `${context}.previous_snapshot_id_hex`,
  );
  if (previousSnapshotId === snapshotId) {
    rejectType(`${context}.previous_snapshot_id_hex must differ from snapshot_id_hex`);
  }
  const providerCount = parseSorafsReputationBoundedInteger(
    snapshot.provider_count,
    `${context}.provider_count`,
    1,
    65_536,
  );
  const returnedProviderCount = parseSorafsReputationBoundedInteger(
    snapshot.returned_provider_count,
    `${context}.returned_provider_count`,
    1,
    500,
  );
  const limit = parseSorafsReputationBoundedInteger(
    snapshot.limit,
    `${context}.limit`,
    1,
    500,
  );
  const providers = requireSorafsReputationArray(
    snapshot.providers,
    `${context}.providers`,
  ).map((provider, index) =>
    parseSorafsReputationProvider(
      provider,
      `${context}.providers[${index}]`,
    ),
  );
  if (providers.length !== returnedProviderCount) {
    rejectRange(`${context}.returned_provider_count must equal providers.length`);
  }
  if (returnedProviderCount !== Math.min(providerCount, limit)) {
    rejectRange(`${context}.returned_provider_count must equal min(provider_count, limit)`);
  }
  for (let index = 1; index < providers.length; index += 1) {
    if (providers[index - 1].provider_id >= providers[index].provider_id) {
      rejectType(`${context}.providers must be strictly ordered by provider_id`);
    }
  }
  if (typeof snapshot.truncated_providers !== "boolean") {
    rejectType(`${context}.truncated_providers must be a boolean`);
  }
  if (
    snapshot.truncated_providers !==
    (providerCount > returnedProviderCount)
  ) {
    rejectType(`${context}.truncated_providers is inconsistent with provider counts`);
  }
  return {
    snapshot_id_hex: snapshotId,
    generated_at_unix: parseSorafsReputationU64(
      snapshot.generated_at_unix,
      `${context}.generated_at_unix`,
      { minimum: 1n },
    ),
    previous_snapshot_id_hex: previousSnapshotId,
    merkle_root_hex: parseSorafsReputationDigest(
      snapshot.merkle_root_hex,
      `${context}.merkle_root_hex`,
    ),
    provider_count: providerCount,
    returned_provider_count: returnedProviderCount,
    limit,
    truncated_providers: snapshot.truncated_providers,
    alpha_bps: parseSorafsReputationExactInteger(
      snapshot.alpha_bps,
      `${context}.alpha_bps`,
      8_500,
    ),
    current_score_weight_bps: parseSorafsReputationExactInteger(
      snapshot.current_score_weight_bps,
      `${context}.current_score_weight_bps`,
      7_000,
    ),
    weights: parseSorafsReputationWeights(
      snapshot.weights,
      `${context}.weights`,
    ),
    providers,
  };
}

function parseSorafsReputationProviderResponse(
  value,
  context,
  expectedProviderId,
) {
  const response = requireSorafsReputationExactObject(
    value,
    SORAFS_REPUTATION_PROVIDER_RESPONSE_FIELDS,
    context,
  );
  const provider = parseSorafsReputationProvider(
    response.provider,
    `${context}.provider`,
  );
  const proof = parseSorafsReputationProof(
    response.proof,
    `${context}.proof`,
  );
  if (provider.provider_id !== proof.provider_id) {
    rejectType(`${context}.proof must reference the returned provider`);
  }
  if (provider.provider_id !== expectedProviderId) {
    rejectType(`${context} does not match the requested provider`);
  }
  return {
    snapshot_id_hex: parseSorafsReputationSnapshotId(
      response.snapshot_id_hex,
      `${context}.snapshot_id_hex`,
    ),
    generated_at_unix: parseSorafsReputationU64(
      response.generated_at_unix,
      `${context}.generated_at_unix`,
      { minimum: 1n },
    ),
    merkle_root_hex: parseSorafsReputationDigest(
      response.merkle_root_hex,
      `${context}.merkle_root_hex`,
    ),
    provider,
    proof,
  };
}

function parseSorafsReputationWeightsResponse(value, context) {
  const response = requireSorafsReputationExactObject(
    value,
    SORAFS_REPUTATION_WEIGHTS_RESPONSE_FIELDS,
    context,
  );
  return {
    snapshot_id_hex: parseSorafsReputationSnapshotId(
      response.snapshot_id_hex,
      `${context}.snapshot_id_hex`,
    ),
    generated_at_unix: parseSorafsReputationU64(
      response.generated_at_unix,
      `${context}.generated_at_unix`,
      { minimum: 1n },
    ),
    alpha_bps: parseSorafsReputationExactInteger(
      response.alpha_bps,
      `${context}.alpha_bps`,
      8_500,
    ),
    current_score_weight_bps: parseSorafsReputationExactInteger(
      response.current_score_weight_bps,
      `${context}.current_score_weight_bps`,
      7_000,
    ),
    weights: parseSorafsReputationWeights(
      response.weights,
      `${context}.weights`,
    ),
  };
}

function parseSorafsReputationOptionalU64(value, context, options = {}) {
  return value === null
    ? null
    : parseSorafsReputationU64(value, context, options);
}

function sorafsReputationU64BigInt(value) {
  return typeof value === JS_TYPE_BIGINT ? value : BigInt(value);
}

function parseSorafsReputationEventPage(value, context, options = {}) {
  const page = requireSorafsReputationExactObject(
    value,
    SORAFS_REPUTATION_EVENT_PAGE_FIELDS,
    context,
  );
  const since = parseSorafsReputationOptionalU64(
    page.since,
    `${context}.since`,
  );
  const expectedSince =
    options.expectedSince === null || options.expectedSince === undefined
      ? null
      : BigInt(options.expectedSince);
  if (
    (since === null) !== (expectedSince === null) ||
    (since !== null && sorafsReputationU64BigInt(since) !== expectedSince)
  ) {
    rejectType(`${context}.since does not match the requested cursor`);
  }
  const limit = parseSorafsReputationBoundedInteger(
    page.limit,
    `${context}.limit`,
    1,
    500,
  );
  if (
    options.expectedLimit !== undefined &&
    limit !== options.expectedLimit
  ) {
    rejectType(`${context}.limit does not match the requested limit`);
  }
  const count = parseSorafsReputationBoundedInteger(
    page.count,
    `${context}.count`,
    0,
    500,
  );
  const events = requireSorafsReputationArray(
    page.events,
    `${context}.events`,
  ).map((event, index) =>
    parseSorafsReputationEvent(event, `${context}.events[${index}]`),
  );
  if (count !== events.length) {
    rejectRange(`${context}.count must equal events.length`);
  }
  if (count > limit) {
    rejectRange(`${context}.count must not exceed limit`);
  }
  const nextSince = parseSorafsReputationOptionalU64(
    page.next_since,
    `${context}.next_since`,
    { minimum: 1n },
  );
  if (
    (events.length === 0 && nextSince !== null) ||
    (events.length !== 0 &&
      (nextSince === null ||
        sorafsReputationU64BigInt(nextSince) !==
          sorafsReputationU64BigInt(events.at(-1).sequence)))
  ) {
    rejectType(`${context}.next_since must equal the last event sequence`);
  }
  let previousSequence = since === null ? 0n : sorafsReputationU64BigInt(since);
  for (let index = 0; index < events.length; index += 1) {
    const sequence = sorafsReputationU64BigInt(events[index].sequence);
    if (
      (index === 0 && sequence <= previousSequence) ||
      (index > 0 && sequence !== previousSequence + 1n)
    ) {
      rejectRange(`${context} sequences must increase after since and be contiguous within the page`);
    }
    previousSequence = sequence;
  }
  for (let index = 1; index < events.length; index += 1) {
    const previous = events[index - 1];
    const current = events[index];
    if (current.previous_snapshot_id_hex !== previous.snapshot_id_hex) {
      rejectType(`${context} previous_snapshot_id_hex must link adjacent events`);
    }
    if (
      sorafsReputationU64BigInt(current.generated_at_unix) <=
      sorafsReputationU64BigInt(previous.generated_at_unix)
    ) {
      rejectRange(`${context} generated_at_unix must strictly increase`);
    }
  }
  return { since, limit, count, next_since: nextSince, events };
}

function parseSorafsReputationSseU64(raw, context) {
  if (
    typeof raw !== JS_TYPE_STRING ||
    !/^[1-9][0-9]{0,19}$/u.test(raw)
  ) {
    rejectType(`${context} must be a positive canonical u64`);
  }
  const parsed = parseStrictLosslessIntegerJson(raw, context);
  return parseSorafsReputationU64(parsed, context, { minimum: 1n });
}

async function* validateSorafsReputationSseStream(events, requestedSince) {
  const since = BigInt(requestedSince);
  for await (const event of events) {
    const context = "sorafs reputation SSE event";
    if (event.retry !== null) {
      rejectType(`${context} must not carry a retry field`);
    }
    if (event.event === "reputation_snapshot") {
      if (
        typeof event.raw !== JS_TYPE_STRING ||
        event.raw.length === 0 ||
        /\s/u.test(event.raw)
      ) {
        rejectType(`${context}.data must be exact compact JSON`);
      }
      const data = parseSorafsReputationEvent(
        parseStrictLosslessIntegerJson(event.raw, `${context}.data`),
        `${context}.data`,
      );
      const eventId = parseSorafsReputationSseU64(
        event.id,
        `${context}.id`,
      );
      const sequence = sorafsReputationU64BigInt(data.sequence);
      if (sorafsReputationU64BigInt(eventId) !== sequence) {
        rejectType(`${context}.id must equal data.sequence`);
      }
      if (sequence <= since) {
        rejectRange(`${context}.data.sequence must be greater than the requested since cursor`);
      }
      yield { ...event, data };
      continue;
    }
    if (event.event === "lagged") {
      if (event.id !== null) {
        rejectType(`${context} lagged frames must not carry an id`);
      }
      const data = parseSorafsReputationSseU64(
        event.raw,
        `${context}.lagged_count`,
      );
      yield { ...event, data };
      continue;
    }
    rejectType(`${context} type ${String(event.event)} is unsupported`);
  }
}

function buildSorafsPorStatusParams(options = {}) {
  const record = ensureRecord(options, "getSorafsPorStatus options");
  assertSupportedOptionKeys(
    record,
    new Set([
      "manifest",
      "manifestHex",
      "provider",
      "providerHex",
      "epoch",
      "status",
      "limit",
      "max_bytes",
      "maxBytes",
      "cursor",
    ]),
    "getSorafsPorStatus options",
  );
  const params = {};
  const manifest = record.manifest ?? record.manifestHex;
  if (manifest !== undefined && manifest !== null) {
    params.manifest = requireHexString(
      manifest,
      "sorafsPorStatus.manifestHex",
    );
  }
  const provider = record.provider ?? record.providerHex;
  if (provider !== undefined && provider !== null) {
    params.provider = requireHexString(
      provider,
      "sorafsPorStatus.providerHex",
    );
  }
  if (record.epoch !== undefined && record.epoch !== null) {
    params.epoch = ToriiClient._normalizeUnsignedInteger(
      record.epoch,
      "sorafsPorStatus.epoch",
      { allowZero: false },
    );
  }
  if (record.status !== undefined && record.status !== null) {
    params.status = requireNonEmptyString(
      record.status,
      "sorafsPorStatus.status",
    ).trim();
  }
  params.limit = ToriiClient._normalizeUnsignedInteger(
    record.limit ?? SORAFS_POR_PAGE_DEFAULT_LIMIT,
    "sorafsPorStatus.limit",
    { allowZero: false, max: SORAFS_POR_PAGE_MAX_LIMIT },
  );
  params.max_bytes = ToriiClient._normalizeUnsignedInteger(
    record.max_bytes ?? record.maxBytes ?? SORAFS_POR_PAGE_DEFAULT_MAX_BYTES,
    "sorafsPorStatus.maxBytes",
    { allowZero: false, max: SORAFS_POR_PAGE_DEFAULT_MAX_BYTES },
  );
  if (record.cursor !== undefined && record.cursor !== null) {
    params.cursor = normalizeSorafsPorCursor(record.cursor, "sorafsPorStatus.cursor");
  }
  return params;
}

function buildSorafsPorExportParams(options = {}) {
  const record = ensureRecord(options, "exportSorafsPorStatus options");
  assertSupportedOptionKeys(
    record,
    new Set([
      "start_epoch",
      "startEpoch",
      "end_epoch",
      "endEpoch",
      "limit",
      "max_bytes",
      "maxBytes",
      "cursor",
    ]),
    "exportSorafsPorStatus options",
  );
  const params = {};
  const startEpoch = record.start_epoch ?? record.startEpoch;
  const endEpoch = record.end_epoch ?? record.endEpoch;
  if ((startEpoch == null) !== (endEpoch == null)) {
    rejectType("sorafsPorExport.startEpoch and sorafsPorExport.endEpoch must be supplied together");
  }
  if (startEpoch != null) {
    params.start_epoch = ToriiClient._normalizeUnsignedInteger(
      startEpoch,
      "sorafsPorExport.startEpoch",
      { allowZero: false },
    );
  }
  if (endEpoch != null) {
    params.end_epoch = ToriiClient._normalizeUnsignedInteger(
      endEpoch,
      "sorafsPorExport.endEpoch",
      { allowZero: false },
    );
  }
  params.limit = ToriiClient._normalizeUnsignedInteger(
    record.limit ?? SORAFS_POR_PAGE_DEFAULT_LIMIT,
    "sorafsPorExport.limit",
    { allowZero: false, max: SORAFS_POR_PAGE_MAX_LIMIT },
  );
  params.max_bytes = ToriiClient._normalizeUnsignedInteger(
    record.max_bytes ?? record.maxBytes ?? SORAFS_POR_PAGE_DEFAULT_MAX_BYTES,
    "sorafsPorExport.maxBytes",
    { allowZero: false, max: SORAFS_POR_PAGE_DEFAULT_MAX_BYTES },
  );
  if (record.cursor !== undefined && record.cursor !== null) {
    params.cursor = normalizeSorafsPorCursor(record.cursor, "sorafsPorExport.cursor");
  }
  return params;
}

function normalizeSorafsPorCursor(value, context) {
  if (
    typeof value !== JS_TYPE_STRING ||
    value.length === 0 ||
    value.length > SORAFS_POR_CURSOR_MAX_LENGTH ||
    value.length % 4 === 1 ||
    !EXPLORER_CURSOR_PATTERN.test(value)
  ) {
    rejectType(`${context} must be canonical base64url without padding and at most ${SORAFS_POR_CURSOR_MAX_LENGTH} characters`);
  }
  const trailingSextet = EXPLORER_CURSOR_ALPHABET.indexOf(value[value.length - 1]);
  const remainder = value.length % 4;
  if (
    (remainder === 2 && (trailingSextet & 0x0f) !== 0) ||
    (remainder === 3 && (trailingSextet & 0x03) !== 0)
  ) {
    rejectType(`${context} must use canonical base64url trailing bits`);
  }
  return value;
}

function normalizeSorafsPinListResponse(
  payload,
  requestParams = undefined,
  context = "sorafs pin list response",
) {
  const record = requireExactSorafsPinObjectFields(
    ensureRecord(payload ?? {}, context),
    ["finalized_cursor", "charged_usage", "manifests", "has_more", "next_after_digest"],
    [],
    context,
  );
  const finalizedCursor = normalizeSorafsPinFinalizedCursor(
    record.finalized_cursor,
    `${context}.finalized_cursor`,
  );
  const chargedUsage = normalizeSorafsPinResourceUsage(
    record.charged_usage,
    `${context}.charged_usage`,
  );
  if (!Array.isArray(record.manifests)) {
    rejectType(`${context}.manifests must be an array`);
  }
  if (record.manifests.length > SORAFS_PIN_LIST_MAX_ITEMS) {
    rejectRange(`${context}.manifests exceeds the ${SORAFS_PIN_LIST_MAX_ITEMS}-item limit`);
  }
  const manifests = record.manifests.map((entry, index) =>
    normalizeSorafsPinManifestSummary(entry, `${context}.manifests[${index}]`),
  );
  for (let index = 1; index < manifests.length; index += 1) {
    if (compareExactJsonBytes(manifests[index - 1].digest, manifests[index].digest) >= 0) {
      rejectType(`${context}.manifests must be strictly digest-ordered`);
    }
  }
  if (typeof record.has_more !== "boolean") {
    rejectType(`${context}.has_more must be a boolean`);
  }
  const nextAfterDigest =
    record.next_after_digest === null
      ? null
      : normalizeExactJsonByteArray(
          record.next_after_digest,
          `${context}.next_after_digest`,
          { exactLength: 32 },
        );
  if (record.has_more !== (nextAfterDigest !== null)) {
    rejectType(`${context}.has_more must agree with ${context}.next_after_digest`);
  }
  if (record.has_more) {
    if (manifests.length === 0) {
      rejectType(`${context}.has_more cannot be true for an empty page`);
    }
    const lastDigest = manifests[manifests.length - 1].digest;
    if (compareExactJsonBytes(lastDigest, nextAfterDigest) !== 0) {
      rejectType(`${context}.next_after_digest must equal the last returned digest`);
    }
  }

  if (manifests.length > (requestParams?.limit ?? 50)) {
    rejectType(`${context}.manifests exceeds the requested limit`);
  }
  if (requestParams !== undefined) {
    if (
      requestParams.expected_finalized_height !== undefined &&
      BigInt(finalizedCursor.height) !== BigInt(requestParams.expected_finalized_height)
    ) {
      rejectType(`${context}.finalized_cursor.height does not match the request anchor`);
    }
    if (
      requestParams.expected_finalized_block_hash_hex !== undefined &&
      exactJsonBytesToLowerHex(finalizedCursor.block_hash) !==
        requestParams.expected_finalized_block_hash_hex
    ) {
      rejectType(`${context}.finalized_cursor.block_hash does not match the request anchor`);
    }
    if (requestParams.limit !== undefined && manifests.length > requestParams.limit) {
      rejectType(`${context}.manifests exceeds the requested limit`);
    }
    if (requestParams.status !== undefined) {
      const expectedStatus = sorafsPinStatusWireTag(requestParams.status);
      const mismatched = manifests.find(
        (manifest) => manifest.status.status !== expectedStatus,
      );
      if (mismatched !== undefined) {
        rejectType(`${context}.manifests violates the requested status filter`);
      }
    }
    if (requestParams.after_digest_hex !== undefined && manifests.length > 0) {
      const firstDigestHex = exactJsonBytesToLowerHex(manifests[0].digest);
      if (firstDigestHex <= requestParams.after_digest_hex) {
        rejectType(`${context}.manifests does not advance the exclusive digest cursor`);
      }
    }
  }

  return {
    finalized_cursor: finalizedCursor,
    charged_usage: chargedUsage,
    manifests,
    has_more: record.has_more,
    next_after_digest: nextAfterDigest,
  };
}

function requireExactSorafsPinObjectFields(
  record,
  requiredFields,
  optionalFields,
  context,
) {
  const allowed = new Set([...requiredFields, ...optionalFields]);
  const unknown = Object.keys(record).find((field) => !allowed.has(field));
  if (unknown !== undefined) {
    rejectType(`${context} contains unknown field ${unknown}`);
  }
  const missing = requiredFields.find(
    (field) => !Object.prototype.hasOwnProperty.call(record, field),
  );
  if (missing !== undefined) {
    rejectType(`${context} is missing required field ${missing}`);
  }
  return record;
}

function normalizeSorafsPinFinalizedCursor(payload, context) {
  return sorafsPinDetail.cursor(payload, context);
}

function normalizeSorafsPinResourceUsage(payload, context) {
  const record = requireExactSorafsPinObjectFields(
    ensureRecord(payload ?? {}, context),
    ["manifest_count", "content_bytes"],
    [],
    context,
  );
  return {
    manifest_count: normalizeSorafsPinU64(
      record.manifest_count,
      `${context}.manifest_count`,
    ),
    content_bytes: normalizeSorafsPinU64(
      record.content_bytes,
      `${context}.content_bytes`,
    ),
  };
}

function normalizeSorafsPinManifestSummary(payload, context) {
  const record = requireExactSorafsPinObjectFields(ensureRecord(payload, context), [
    "digest", "submitted_by", "submitted_epoch", "approved_epoch", "content_length",
    "retention_epoch", "status", "successor_of",
  ], [], context);
  const result = {
    digest: normalizeExactJsonByteArray(record.digest, `${context}.digest`, { exactLength: 32 }),
    submitted_by: ToriiClient._requireAccountId(record.submitted_by, `${context}.submitted_by`),
    submitted_epoch: normalizeSorafsPinU64(record.submitted_epoch, `${context}.submitted_epoch`),
    approved_epoch: record.approved_epoch === null ? null : normalizeSorafsPinU64(record.approved_epoch, `${context}.approved_epoch`),
    content_length: normalizeSorafsPinU64(record.content_length, `${context}.content_length`),
    retention_epoch: normalizeSorafsPinU64(record.retention_epoch, `${context}.retention_epoch`),
    status: sorafsPinDetail.status(record.status, `${context}.status`),
    successor_of: record.successor_of === null ? null : normalizeExactJsonByteArray(record.successor_of, `${context}.successor_of`, { exactLength: 32 }),
  };
  if (result.submitted_by !== record.submitted_by) rejectType(`${context}.submitted_by must use its exact canonical identity`);
  const submitted = BigInt(result.submitted_epoch), retention = BigInt(result.retention_epoch);
  const approved = result.approved_epoch === null ? null : BigInt(result.approved_epoch);
  const status = result.status;
  const valid = status.status === "Pending" ? approved === null
    : status.status === "Approved" ? approved === BigInt(status.value) && approved >= submitted && approved < retention
    : BigInt(status.value) >= submitted && (approved === null || approved >= submitted && approved <= BigInt(status.value) && approved < retention);
  if (!valid) rejectType(`${context} has inconsistent retained approval history`);
  if (exactJsonBytesAreZero(result.digest) || result.successor_of !== null && exactJsonBytesAreZero(result.successor_of)) rejectType(`${context} has a zero digest`);
  return result;
}

function sorafsPinStatusWireTag(status) {
  return `${status[0].toUpperCase()}${status.slice(1)}`;
}

function compareExactJsonBytes(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

function exactJsonBytesAreZero(bytes) {
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  return true;
}

function exactJsonBytesToLowerHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

const sorafsPinDetail = createSorafsPinDetailNormalizer({
  bytes: normalizeExactJsonByteArray,
  account: (value, context) => ToriiClient._requireAccountId(value, context),
  asset: normalizeAssetDefinitionId,
  quantity: requireCanonicalQuantity,
});

const { normalizeSorafsAliasListResponse } =
  createSorafsAliasResponseNormalizers({
    requireAccountId: (value, context) => ToriiClient._requireAccountId(value, context),
  });

function normalizeSorafsPinRegisterResponse(
  payload,
  context = "sorafs pin register response",
) {
  const record = ensureRecord(payload ?? {}, context);
  assertSupportedOptionKeys(
    record,
    new Set(["status", "tx_hash_hex", "manifest_digest_hex"]),
    context,
  );
  if (record.status !== "submitted") {
    rejectType(`${context}.status must be submitted`);
  }
  return {
    status: "submitted",
    tx_hash_hex: requireCanonicalTransactionHashString(
      record.tx_hash_hex,
      `${context}.tx_hash_hex`,
    ),
    manifest_digest_hex: normalizeHex32String(
      record.manifest_digest_hex,
      `${context}.manifest_digest_hex`,
    ),
  };
}

function normalizePipelineTransactionStatus(
  payload,
  context = "pipeline transaction status response",
) {
  const record = ensureRecord(payload ?? {}, context);
  assertSupportedOptionKeys(
    record,
    new Set(["hash", "status", "scope", "resolved_from"]),
    context,
  );
  const hash = requireCanonicalTransactionHashString(record.hash, `${context}.hash`);
  const statusRecord = ensureRecord(record.status, `${context}.status`);
  assertSupportedOptionKeys(
    statusRecord,
    new Set(["kind", "block_height"]),
    `${context}.status`,
  );
  const statusKind = requireExactNonEmptyString(
    statusRecord.kind,
    `${context}.status.kind`,
  );
  if (!AUTHORITATIVE_PIPELINE_STATUS_KINDS.has(statusKind)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.status.kind is unsupported`,
      `${context}.status.kind`,
    );
  }
  const scope = requireExactNonEmptyString(record.scope, `${context}.scope`);
  if (!["local", "global"].includes(scope)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.scope is unsupported`,
      `${context}.scope`,
    );
  }
  const resolvedFrom = requireExactNonEmptyString(
    record.resolved_from,
    `${context}.resolved_from`,
  );
  if (!["cache", "queue", "state"].includes(resolvedFrom)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.resolved_from is unsupported`,
      `${context}.resolved_from`,
    );
  }
  const normalizedStatus = { kind: statusKind };
  if (statusRecord.block_height !== undefined) {
    normalizedStatus.block_height = requireExactJsonUnsignedInteger(
      statusRecord.block_height,
      `${context}.status.block_height`,
      { allowZero: false },
    );
  }
  return Object.freeze({
    hash,
    status: Object.freeze(normalizedStatus),
    scope,
    resolved_from: resolvedFrom,
  });
}

function assertPipelineTransactionStatusMatchesHash(payload, expectedHash, context) {
  const record = ensureRecord(payload, context);
  const observedHash = requireCanonicalTransactionHashString(
    record.hash,
    `${context}.hash`,
  );
  if (observedHash !== expectedHash) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${context}.hash does not match requested transaction ${expectedHash}`,
      `${context}.hash`,
    );
  }
  return payload;
}

function classifyPipelineTransactionStatusResolution(
  payload,
  expectedHash,
  context,
) {
  const record = ensureRecord(payload, context);
  const observedHash = requireCanonicalTransactionHashString(
    record.hash,
    `${context}.hash`,
  );
  if (observedHash !== expectedHash) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${context}.hash does not match requested transaction ${expectedHash}`,
      `${context}.hash`,
    );
  }
  if (record.scope !== "global") {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.scope must be global`,
      `${context}.scope`,
    );
  }
  const status = ensureRecord(record.status, `${context}.status`);
  const kind = status.kind;
  if (
    typeof kind !== JS_TYPE_STRING ||
    !AUTHORITATIVE_PIPELINE_STATUS_KINDS.has(kind)
  ) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.status.kind is missing or unsupported`,
      `${context}.status.kind`,
    );
  }
  const resolvedFrom = record.resolved_from;
  if (typeof resolvedFrom !== JS_TYPE_STRING) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.resolved_from must be a string`,
      `${context}.resolved_from`,
    );
  }
  if (!["queue", "cache", "state"].includes(resolvedFrom)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}.resolved_from is unsupported`,
      `${context}.resolved_from`,
    );
  }
  if (kind === "Applied") {
    if (
      !Number.isSafeInteger(status.block_height) ||
      status.block_height <= 0
    ) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${context} Applied status must have a positive block height`,
        `${context}.status`,
      );
    }
  }
  return { kind, resolvedFrom };
}

/**
 * Target block cadences a peer with queued work may go without committing a
 * non-empty block before `ToriiPipelinePreflight.isStatusStalled` reports a stall.
 *
 * `GET /v1/pipeline/preflight` serves one consensus timing value,
 * `sumeragi.block_cadence_ms` (the signed-genesis target block time), so the
 * stall threshold is `PIPELINE_STALL_BLOCK_CADENCES * block_cadence_ms`. With
 * work queued a healthy chain commits about once per cadence. At the Sumeragi
 * defaults (1 s block time, 5 s payload retry, 2-3 s base view timer) one
 * crashed leader delays the next commit by roughly 11-14 s plus execution
 * (`specs/sumeragi.md` §8.2 P4, §9.3); twenty cadences keep such a single view
 * change from being reported as a stall. Callers that know their deployment's
 * local timers pass their own threshold to `isStatusQueueStalled`.
 */
const PIPELINE_STALL_BLOCK_CADENCES = 20;

/** Exact field sets of the `GET /v1/pipeline/preflight` JSON body (Torii `PipelinePreflightResponse`). */
const PIPELINE_PREFLIGHT_FIELDS = Object.freeze({
  root: Object.freeze([
    "schema_version",
    "chain_height",
    "sumeragi",
    "admission",
    "block",
    "pipeline",
    "queue",
    "fees",
  ]),
  sumeragi: Object.freeze(["block_cadence_ms"]),
  admission: Object.freeze([
    "max_signatures",
    "max_instructions",
    "max_tx_bytes",
    "max_decompressed_bytes",
    "max_metadata_depth",
  ]),
  block: Object.freeze(["max_transactions"]),
  pipeline: Object.freeze([
    "signature_batch_max_ed25519",
    "signature_batch_max_secp256k1",
    "signature_batch_max_pqc",
    "signature_batch_max_bls",
    "overlay_max_instructions",
    "ivm_max_cycles_upper_bound",
    "ivm_admission_cycle_limit",
    "ivm_max_decoded_instructions",
  ]),
  queue: Object.freeze(["size", "queued", "inflight"]),
  fees: Object.freeze([
    "fee_asset_id",
    "fee_sink_account_id",
    "base_fee",
    "per_byte_fee",
    "per_instruction_fee",
    "per_gas_unit_fee",
    "sponsor_vault_custody_account_id",
    "settlement_mode",
    "successful_claim_fee_exempt_authorities",
  ]),
});

const PIPELINE_PREFLIGHT_SETTLEMENT_MODES = Object.freeze(["direct", "lane_relay_burn"]);

/** Require `mapping` to be an object that carries no field outside `allowed`. */
function requirePipelinePreflightRecord(mapping, allowed, context) {
  const record = ensureRecord(mapping, context);
  const unknownField = Object.keys(record).find((field) => !allowed.includes(field));
  if (unknownField !== undefined) {
    rejectType(`${context} contains unknown field ${unknownField}`);
  }
  return record;
}

/** Require a JSON integer (never a numeric string) that fits a safe `u64` range. */
function requirePipelinePreflightUnsigned(
  mapping,
  key,
  context,
  { positive = false } = {},
) {
  const record = ensureRecord(mapping, context);
  const value = record[key];
  if (value === undefined || value === null) {
    rejectType(`${context}.${key} is required`);
  }
  if (typeof value !== JS_TYPE_NUMBER && typeof value !== JS_TYPE_BIGINT) {
    rejectType(`${context}.${key} must be an integer`);
  }
  const numeric = requireNonNegativeIntegerLike(value, `${context}.${key}`);
  if (positive && numeric === 0) {
    rejectRange(`${context}.${key} must be positive`);
  }
  return numeric;
}

function requirePipelinePreflightString(mapping, key, context) {
  const value = mapping[key];
  if (typeof value !== JS_TYPE_STRING || value.length === 0) {
    rejectType(`${context}.${key} must be a non-empty string`);
  }
  return value;
}

function requirePipelinePreflightSettlementMode(fees, context) {
  const mode = requirePipelinePreflightString(fees, "settlement_mode", context);
  if (!PIPELINE_PREFLIGHT_SETTLEMENT_MODES.includes(mode)) {
    rejectType(
      `${context}.settlement_mode must be one of: ${PIPELINE_PREFLIGHT_SETTLEMENT_MODES.join(", ")}`,
    );
  }
  return mode;
}

function requirePipelinePreflightArray(mapping, key, context) {
  const value = mapping[key];
  if (!Array.isArray(value)) {
    rejectType(`${context}.${key} must be an array of strings`);
  }
  return value;
}

/**
 * Stall threshold derived from the served target block time: the product of
 * `PIPELINE_STALL_BLOCK_CADENCES` and `block_cadence_ms`, saturated at
 * `Number.MAX_SAFE_INTEGER`.
 */
function pipelineStallThresholdMs(blockCadenceMs) {
  return Math.min(
    blockCadenceMs * PIPELINE_STALL_BLOCK_CADENCES,
    Number.MAX_SAFE_INTEGER,
  );
}

/**
 * Parse the exact `GET /v1/pipeline/preflight` JSON body. Every object is
 * closed: a field Torii does not serve is rejected as protocol drift.
 */
function normalizePipelinePreflight(payload, context = "pipeline preflight response") {
  const fields = PIPELINE_PREFLIGHT_FIELDS;
  const record = requirePipelinePreflightRecord(payload ?? {}, fields.root, context);
  const sumeragi = requirePipelinePreflightRecord(
    record.sumeragi,
    fields.sumeragi,
    `${context}.sumeragi`,
  );
  const admission = requirePipelinePreflightRecord(
    record.admission,
    fields.admission,
    `${context}.admission`,
  );
  const block = requirePipelinePreflightRecord(record.block, fields.block, `${context}.block`);
  const pipeline = requirePipelinePreflightRecord(
    record.pipeline,
    fields.pipeline,
    `${context}.pipeline`,
  );
  const queue = requirePipelinePreflightRecord(record.queue, fields.queue, `${context}.queue`);
  const fees = requirePipelinePreflightRecord(record.fees, fields.fees, `${context}.fees`);
  // Object literal properties evaluate in order, so validation follows Torii's
  // field order and the fee accounts are decoded last.
  const normalized = {
    schema_version: requirePipelinePreflightUnsigned(
      record,
      "schema_version",
      context,
      { positive: true },
    ),
    chain_height: requirePipelinePreflightUnsigned(record, "chain_height", context),
    sumeragi: {
      block_cadence_ms: requirePipelinePreflightUnsigned(
        sumeragi,
        "block_cadence_ms",
        `${context}.sumeragi`,
        { positive: true },
      ),
    },
    admission: {
      max_signatures: requirePipelinePreflightUnsigned(
        admission,
        "max_signatures",
        `${context}.admission`,
      ),
      max_instructions: requirePipelinePreflightUnsigned(
        admission,
        "max_instructions",
        `${context}.admission`,
      ),
      max_tx_bytes: requirePipelinePreflightUnsigned(
        admission,
        "max_tx_bytes",
        `${context}.admission`,
      ),
      max_decompressed_bytes: requirePipelinePreflightUnsigned(
        admission,
        "max_decompressed_bytes",
        `${context}.admission`,
      ),
      max_metadata_depth: requirePipelinePreflightUnsigned(
        admission,
        "max_metadata_depth",
        `${context}.admission`,
      ),
    },
    block: {
      max_transactions: requirePipelinePreflightUnsigned(
        block,
        "max_transactions",
        `${context}.block`,
      ),
    },
    pipeline: {
      signature_batch_max_ed25519: requirePipelinePreflightUnsigned(
        pipeline,
        "signature_batch_max_ed25519",
        `${context}.pipeline`,
      ),
      signature_batch_max_secp256k1: requirePipelinePreflightUnsigned(
        pipeline,
        "signature_batch_max_secp256k1",
        `${context}.pipeline`,
      ),
      signature_batch_max_pqc: requirePipelinePreflightUnsigned(
        pipeline,
        "signature_batch_max_pqc",
        `${context}.pipeline`,
      ),
      signature_batch_max_bls: requirePipelinePreflightUnsigned(
        pipeline,
        "signature_batch_max_bls",
        `${context}.pipeline`,
      ),
      overlay_max_instructions: requirePipelinePreflightUnsigned(
        pipeline,
        "overlay_max_instructions",
        `${context}.pipeline`,
      ),
      ivm_max_cycles_upper_bound: requirePipelinePreflightUnsigned(
        pipeline,
        "ivm_max_cycles_upper_bound",
        `${context}.pipeline`,
        { positive: true },
      ),
      ivm_admission_cycle_limit: requirePipelinePreflightUnsigned(
        pipeline,
        "ivm_admission_cycle_limit",
        `${context}.pipeline`,
        { positive: true },
      ),
      ivm_max_decoded_instructions: requirePipelinePreflightUnsigned(
        pipeline,
        "ivm_max_decoded_instructions",
        `${context}.pipeline`,
      ),
    },
    queue: {
      size: requirePipelinePreflightUnsigned(queue, "size", `${context}.queue`),
      queued: requirePipelinePreflightUnsigned(queue, "queued", `${context}.queue`),
      inflight: requirePipelinePreflightUnsigned(queue, "inflight", `${context}.queue`),
    },
    fees: {
      fee_asset_id: requirePipelinePreflightString(fees, "fee_asset_id", `${context}.fees`),
      fee_sink_account_id: requireExactAccountId(
        fees.fee_sink_account_id,
        `${context}.fees.fee_sink_account_id`,
      ),
      base_fee: requirePipelinePreflightString(fees, "base_fee", `${context}.fees`),
      per_byte_fee: requirePipelinePreflightString(fees, "per_byte_fee", `${context}.fees`),
      per_instruction_fee: requirePipelinePreflightString(
        fees,
        "per_instruction_fee",
        `${context}.fees`,
      ),
      per_gas_unit_fee: requirePipelinePreflightString(
        fees,
        "per_gas_unit_fee",
        `${context}.fees`,
      ),
      sponsor_vault_custody_account_id: requireExactAccountId(
        fees.sponsor_vault_custody_account_id,
        `${context}.fees.sponsor_vault_custody_account_id`,
      ),
      settlement_mode: requirePipelinePreflightSettlementMode(fees, `${context}.fees`),
      successful_claim_fee_exempt_authorities: parseStringArray(
        requirePipelinePreflightArray(
          fees,
          "successful_claim_fee_exempt_authorities",
          `${context}.fees`,
        ),
        `${context}.fees.successful_claim_fee_exempt_authorities`,
      ).map((authority, index) =>
        requireExactAccountId(
          authority,
          `${context}.fees.successful_claim_fee_exempt_authorities[${index}]`,
        )),
    },
    raw: Object.freeze({ ...record }),
  };
  const stallThresholdMs = pipelineStallThresholdMs(normalized.sumeragi.block_cadence_ms);
  return Object.freeze({
    ...normalized,
    stallThresholdMs,
    isStatusStalled(status) {
      return isStatusQueueStalled(status, stallThresholdMs);
    },
  });
}

function normalizePipelineRecoverySidecar(payload, context = "pipeline recovery response") {
  const record = ensureRecord(payload ?? {}, context);
  const format = requireNonEmptyString(
    record.format ?? "",
    `${context}.format`,
  );
  const height = ToriiClient._normalizeUnsignedInteger(record.height, `${context}.height`, {
    allowZero: true,
  });
  const dag = normalizePipelineDagSnapshot(record.dag, `${context}.dag`);
  const rawTxs = record.txs ?? [];
  if (!Array.isArray(rawTxs)) {
    rejectType(`${context}.txs must be an array`);
  }
  return {
    format,
    height,
    dag,
    txs: rawTxs.map((entry, index) =>
      normalizePipelineTxSnapshot(entry, `${context}.txs[${index}]`),
    ),
  };
}

function normalizePipelineRecoveryFastpqProofs(
  payload,
  context = "pipeline recovery FASTPQ proofs response",
) {
  const record = ensureRecord(payload ?? {}, context);
  const rawProofs = record.proofs ?? [];
  if (!Array.isArray(rawProofs)) {
    rejectType(`${context}.proofs must be an array`);
  }
  return {
    height: ToriiClient._normalizeUnsignedInteger(record.height, `${context}.height`, {
      allowZero: true,
    }),
    blockHashHex: normalizeHex32String(record.block_hash ?? "", `${context}.block_hash`),
    proofs: rawProofs.map((entry, index) =>
      normalizePipelineRecoveryFastpqProof(
        entry,
        `${context}.proofs[${index}]`,
      ),
    ),
  };
}

function normalizePipelineRecoveryFastpqProof(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    entryHash: normalizeHex32String(record.entry_hash ?? "", `${context}.entry_hash`),
    batchIndex: ToriiClient._normalizeUnsignedInteger(
      record.batch_index,
      `${context}.batch_index`,
      { allowZero: true },
    ),
    parameter: requireNonEmptyString(record.parameter ?? "", `${context}.parameter`),
    transitionCount: ToriiClient._normalizeUnsignedInteger(
      record.transition_count,
      `${context}.transition_count`,
      { allowZero: true },
    ),
    traceCommitment: normalizeHex32String(
      record.trace_commitment ?? "",
      `${context}.trace_commitment`,
    ),
    proofDigest: normalizeHex32String(
      record.proof_digest ?? "",
      `${context}.proof_digest`,
    ),
    batchBase64: optionalString(record.batch, `${context}.batch`),
    proofBase64: optionalString(record.proof, `${context}.proof`),
    batchCompact: optionalBoolean(record.batch_compact, `${context}.batch_compact`),
    batchReconstructedFromBlock: optionalBoolean(
      record.batch_reconstructed_from_block,
      `${context}.batch_reconstructed_from_block`,
    ),
    batchReconstructionError: optionalString(
      record.batch_reconstruction_error,
      `${context}.batch_reconstruction_error`,
    ),
    raw: Object.freeze({ ...record }),
  };
}

function normalizePipelineDagSnapshot(payload, context = "pipeline recovery dag") {
  const record = ensureRecord(payload ?? {}, context);
  return {
    fingerprintHex: normalizeHex32String(
      record.fingerprint ?? "",
      `${context}.fingerprint`,
    ),
    keyCount: ToriiClient._normalizeUnsignedInteger(
      record.key_count,
      `${context}.key_count`,
      { allowZero: true },
    ),
  };
}

function normalizePipelineTxSnapshot(payload, context = "pipeline recovery tx") {
  const record = ensureRecord(payload ?? {}, context);
  return {
    hashHex: normalizeHex32String(
      record.hash ?? "",
      `${context}.hash`,
    ),
    reads: normalizeStringArray(record.reads ?? [], `${context}.reads`),
    writes: normalizeStringArray(record.writes ?? [], `${context}.writes`),
  };
}

function normalizeSorafsStorageStateResponse(
  payload,
  context = "sorafs storage state response",
) {
  const record = ensureRecord(payload ?? {}, context);
  const normalize = (field, allowZero = true) =>
    ToriiClient._normalizeUnsignedInteger(record[field], `${context}.${field}`, {
      allowZero,
    });
  return {
    bytes_used: normalize("bytes_used"),
    bytes_capacity: normalize("bytes_capacity"),
    pin_queue_depth: normalize("pin_queue_depth"),
    fetch_inflight: normalize("fetch_inflight"),
    fetch_bytes_per_sec: normalize("fetch_bytes_per_sec"),
    por_inflight: normalize("por_inflight"),
    por_samples_success_total: normalize("por_samples_success_total"),
    por_samples_failed_total: normalize("por_samples_failed_total", true),
    fetch_utilisation_bps: normalize("fetch_utilisation_bps"),
    pin_queue_utilisation_bps: normalize("pin_queue_utilisation_bps"),
    por_utilisation_bps: normalize("por_utilisation_bps"),
  };
}

function normalizeSorafsManifestResponse(
  payload,
  context = "sorafs manifest response",
) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    manifest_id_hex: normalizeHex32String(
      record.manifest_id_hex ?? "",
      `${context}.manifest_id_hex`,
    ),
    manifest_b64: normalizeRequiredBase64Payload(
      record.manifest_b64,
      `${context}.manifest_b64`,
    ),
    manifest_digest_hex: normalizeHex32String(
      record.manifest_digest_hex ?? "",
      `${context}.manifest_digest_hex`,
    ),
    payload_digest_hex: normalizeHex32String(
      record.payload_digest_hex ?? "",
      `${context}.payload_digest_hex`,
    ),
    content_length: ToriiClient._normalizeUnsignedInteger(
      record.content_length,
      `${context}.content_length`,
      { allowZero: true },
    ),
    chunk_count: ToriiClient._normalizeUnsignedInteger(
      record.chunk_count,
      `${context}.chunk_count`,
      { allowZero: true },
    ),
    chunk_profile_handle: requireNonEmptyString(
      record.chunk_profile_handle ?? "",
      `${context}.chunk_profile_handle`,
    ),
    stored_at_unix_secs: ToriiClient._normalizeUnsignedInteger(
      record.stored_at_unix_secs,
      `${context}.stored_at_unix_secs`,
      { allowZero: true },
    ),
  };
}

function normalizeDaManifestFetchResponse(payload, context = "da manifest response") {
  const record = ensureRecord(payload ?? {}, context);
  const storageTicketHex = normalizeHex32String(
    record.storage_ticket ?? "",
    `${context}.storage_ticket`,
  );
  const manifestHashHex = normalizeHex32String(
    record.manifest_hash ?? "",
    `${context}.manifest_hash`,
  );
  const manifestB64 = normalizeRequiredBase64Payload(
    record.manifest_norito,
    `${context}.manifest_norito`,
  );
  const blobHashHex = normalizeHex32String(
    record.blob_hash ?? "",
    `${context}.blob_hash`,
  );
  const chunkPlan = normalizeChunkPlanForPersistence(
    record.chunk_plan,
    blobHashHex,
  );
  return {
    storage_ticket_hex: storageTicketHex,
    client_blob_id_hex: normalizeHex32String(
      record.client_blob_id ?? "",
      `${context}.client_blob_id`,
    ),
    manifest_hash_hex: manifestHashHex,
    blob_hash_hex: blobHashHex,
    chunk_root_hex: normalizeHex32String(
      record.chunk_root ?? "",
      `${context}.chunk_root`,
    ),
    lane_id: ToriiClient._normalizeUnsignedInteger(
      record.lane_id,
      `${context}.lane_id`,
      { allowZero: true },
    ),
    epoch: ToriiClient._normalizeUnsignedInteger(
      record.epoch,
      `${context}.epoch`,
      { allowZero: true },
    ),
    manifest_len: ToriiClient._normalizeUnsignedInteger(
      record.manifest_len ?? 0,
      `${context}.manifest_len`,
      { allowZero: true },
    ),
    manifest_b64: manifestB64,
    manifest_bytes: Buffer.from(manifestB64, "base64"),
    manifest_json:
      record.manifest ?? null,
    chunk_plan: chunkPlan,
  };
}

async function persistDaManifestBundle(manifestBundle, outputDir, labelInput) {
  if (!manifestBundle) {
    rejectError("manifestBundle is required");
  }
  if (
    !manifestBundle.manifest_bytes ||
    !Buffer.isBuffer(manifestBundle.manifest_bytes)
  ) {
    rejectError("manifestBundle.manifest_bytes must be a Buffer");
  }
  const pathModule = await getPathModule();
  const fs = await getFsModule();
  const label = sanitizeTicketLabel(
    labelInput ??
      manifestBundle.manifest_hash_hex ??
      manifestBundle.storage_ticket_hex,
    "manifest ticket label",
  );
  const manifestPath = pathModule.join(outputDir, `manifest_${label}.norito`);
  const manifestJsonPath = pathModule.join(outputDir, `manifest_${label}.json`);
  const chunkPlanPath = pathModule.join(outputDir, `chunk_plan_${label}.json`);

  await fs.mkdir(outputDir, { recursive: true });
  await writeBufferFile(manifestPath, manifestBundle.manifest_bytes);
  await writeJsonFile(manifestJsonPath, manifestBundle.manifest_json ?? {});
  const chunkPlan = normalizeChunkPlanForPersistence(
    manifestBundle.chunk_plan,
    manifestBundle.blob_hash_hex,
  );
  await writeJsonFile(chunkPlanPath, chunkPlan);

  return {
    manifestPath,
    manifestJsonPath,
    chunkPlanPath,
    label,
  };
}

async function persistDaRequestArtifacts(artifactDir, request) {
  const pathModule = await getPathModule();
  const requestJsonPath = pathModule.join(artifactDir, "da_request.json");
  await writeJsonFile(requestJsonPath, request);
  return {
    requestJsonPath,
    receiptJsonPath: null,
    responseHeadersPath: null,
  };
}

async function persistDaReceiptArtifacts(
  artifactDir,
  response,
  pdpHeader,
  existing,
) {
  const pathModule = await getPathModule();
  const next = existing ?? {
    requestJsonPath: null,
    receiptJsonPath: null,
    responseHeadersPath: null,
  };
  if (response.receipt) {
    const receiptPath = pathModule.join(artifactDir, "da_receipt.json");
    await writeJsonFile(receiptPath, response.receipt);
    next.receiptJsonPath = receiptPath;
  }
  if (pdpHeader) {
    const headersPath = pathModule.join(artifactDir, "da_response_headers.json");
    await writeJsonFile(headersPath, { [HEADER_SORA_PDP_COMMITMENT]: pdpHeader });
    next.responseHeadersPath = headersPath;
  }
  return next;
}

async function resolveDaOutputDir(inputDir, prefix) {
  const pathModule = await getPathModule();
  if (inputDir === undefined || inputDir === null) {
    return pathModule.resolve(`${prefix}${Date.now()}`);
  }
  const trimmed = String(inputDir).trim();
  if (!trimmed) {
    return pathModule.resolve(`${prefix}${Date.now()}`);
  }
  return pathModule.resolve(trimmed);
}

async function getPathModule() {
  if (!getPathModule.cache) {
    getPathModule.cache = await import("node:path");
  }
  return getPathModule.cache;
}
getPathModule.cache = null;

async function getFsModule() {
  if (!getFsModule.cache) {
    getFsModule.cache = await import("node:fs/promises");
  }
  return getFsModule.cache;
}
getFsModule.cache = null;

async function writeJsonFile(filePath, value) {
  const fs = await getFsModule();
  const pathModule = await getPathModule();
  const dir = pathModule.dirname(filePath);
  if (dir && dir !== ".") {
    await fs.mkdir(dir, { recursive: true });
  }
  const body = `${JSON.stringify(value, null, 2)}\n`;
  await fs.writeFile(filePath, body, "utf8");
}

async function writeBufferFile(filePath, buffer) {
  const fs = await getFsModule();
  const pathModule = await getPathModule();
  const dir = pathModule.dirname(filePath);
  if (dir && dir !== ".") {
    await fs.mkdir(dir, { recursive: true });
  }
  await fs.writeFile(filePath, buffer);
}

const CHUNK_FETCH_PLAN_SCHEMA_V1 = "sorafs.chunk_fetch_plan.v1";
const CHUNK_FETCH_PLAN_V1_FIELDS = new Set([
  "schema",
  "payload_digest_blake3_hex",
  "chunk_fetch_specs",
]);

function normalizeChunkFetchPlanV1(plan, context) {
  if (!isPlainObject(plan)) {
    rejectType(`${context} must be a canonical chunk fetch plan object`);
  }
  for (const field of Object.keys(plan)) {
    if (!CHUNK_FETCH_PLAN_V1_FIELDS.has(field)) {
      rejectType(`${context} contains unsupported field ${field}`);
    }
  }
  if (plan.schema !== CHUNK_FETCH_PLAN_SCHEMA_V1) {
    rejectType(`${context}.schema must be ${CHUNK_FETCH_PLAN_SCHEMA_V1}`);
  }
  if (
    typeof plan.payload_digest_blake3_hex !== JS_TYPE_STRING ||
    !/^[0-9a-f]{64}$/.test(plan.payload_digest_blake3_hex) ||
    /^0{64}$/.test(plan.payload_digest_blake3_hex)
  ) {
    rejectType(`${context}.payload_digest_blake3_hex must be a non-zero canonical lowercase 32-byte hex digest`);
  }
  if (!Array.isArray(plan.chunk_fetch_specs)) {
    rejectType(`${context}.chunk_fetch_specs must be an array`);
  }
  return plan;
}

function normalizeChunkPlanForPersistence(plan, expectedPayloadDigestHex = null) {
  let normalized;
  if (typeof plan === JS_TYPE_STRING) {
    let parsed;
    try {
      parsed = JSON.parse(plan);
    } catch {
      rejectType("DA manifest chunk_plan string must contain valid JSON");
    }
    normalized = normalizeChunkFetchPlanV1(parsed, "DA manifest chunk_plan");
  } else {
    normalized = normalizeChunkFetchPlanV1(plan, "DA manifest chunk_plan");
  }
  if (expectedPayloadDigestHex !== null && expectedPayloadDigestHex !== undefined) {
    const expected = normalizeHex32String(
      expectedPayloadDigestHex,
      "DA manifest blob_hash_hex",
    );
    if (normalized.payload_digest_blake3_hex !== expected) {
      rejectType("DA manifest chunk_plan.payload_digest_blake3_hex must match blob_hash_hex");
    }
  }
  return normalized;
}

function sanitizeTicketLabel(value, context = "ticket label") {
  const normalized = String(value ?? "")
    .trim()
    .replace(/^0x/i, "")
    .toLowerCase();
  if (!normalized) {
    rejectType(`${context} must not be empty`);
  }
  if (!/^[a-z0-9_-]+$/.test(normalized)) {
    rejectType(`${context} may only contain ASCII letters, numbers, underscores, or dashes`);
  }
  return normalized;
}

function normalizeOptionalPathInput(value, context) {
  if (value === undefined || value === null) {
    return null;
  }
  const trimmed = String(value).trim();
  if (!trimmed) {
    rejectType(`${context} must not be an empty string`);
  }
  return trimmed;
}

async function makeDefaultScoreboardPath(outputDir) {
  const pathModule = await getPathModule();
  return pathModule.join(outputDir, "scoreboard.json");
}

function normaliseChunkPlanPayload(plan, context) {
  if (plan === undefined || plan === null) {
    rejectType(`${context} must be provided`);
  }
  if (typeof plan === JS_TYPE_STRING) {
    const trimmed = plan.trim();
    if (!trimmed) {
      rejectType(`${context} must not be an empty string`);
    }
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (error) {
      rejectType(`${context} string must contain valid JSON`);
    }
    const planObject = normalizeChunkFetchPlanV1(parsed, context);
    return { planJson: JSON.stringify(planObject), planObject };
  }
  if (isPlainObject(plan)) {
    const planObject = normalizeChunkFetchPlanV1(plan, context);
    let rendered;
    try {
      rendered = JSON.stringify(planObject);
    } catch (error) {
      rejectType(`${context} could not be serialised to JSON: ${error?.message ?? error}`);
    }
    return { planJson: rendered, planObject };
  }
  rejectType(`${context} must be a canonical chunk fetch plan JSON string or object`);
}

function normaliseChunkerHandle(
  explicitHandle,
  manifestBundle,
  context,
  deriveChunkerHandle,
) {
  if (explicitHandle !== undefined && explicitHandle !== null) {
    const handle = requireNonEmptyString(explicitHandle, "fetchDaPayloadViaGateway.chunkerHandle").trim();
    if (!handle) {
      rejectType("fetchDaPayloadViaGateway.chunkerHandle must not be empty");
    }
    return handle;
  }
  const bundleHandle =
    manifestBundle && typeof manifestBundle === JS_TYPE_OBJECT
      ? manifestBundle.chunker_handle ??
        manifestBundle.chunkerHandle ??
        manifestBundle.chunk_profile_handle ??
        manifestBundle.chunkProfileHandle ??
        null
      : null;
  if (bundleHandle && typeof bundleHandle === JS_TYPE_STRING && bundleHandle.trim()) {
    return bundleHandle.trim();
  }
  const manifestJson =
    manifestBundle && typeof manifestBundle === JS_TYPE_OBJECT
      ? manifestBundle.manifest_json ?? manifestBundle.manifest ?? null
      : null;
  const inferred = inferChunkerHandleFromManifest(manifestJson);
  if (inferred) {
    return inferred;
  }
  const manifestBytes = extractManifestBytesForProof(
    manifestBundle,
    `${context}.chunkerHandle`,
  );
	  if (manifestBytes) {
	    try {
	      return deriveChunkerHandle(manifestBytes);
	    } catch (error) {
	      rejectType(`${context}.chunkerHandle could not be derived from manifest bytes`, { cause: error });
	    }
	  }
  rejectType(`${context}.chunkerHandle is required when the manifest bundle does not expose chunker metadata or manifest bytes`);
}

function normalizeProofSummaryOption(value, context) {
  if (value === undefined || value === null || value === false) {
    return null;
  }
  if (value === true) {
    return {};
  }
  const record = ensureRecord(value, context);
  const sampleCount =
    record.sampleCount ?? undefined;
  const sampleSeed =
    record.sampleSeed ?? undefined;
  const leafIndexes =
    record.leafIndexes ?? undefined;
  const normalized = {};
  if (sampleCount !== undefined) {
    normalized.sampleCount = sampleCount;
  }
  if (sampleSeed !== undefined) {
    normalized.sampleSeed = sampleSeed;
  }
  if (leafIndexes !== undefined) {
    if (!Array.isArray(leafIndexes)) {
      rejectType(`${context}.leafIndexes must be an array`);
    }
    normalized.leafIndexes = leafIndexes.slice();
  }
  return normalized;
}

function extractManifestBytesForProof(bundle, context) {
  if (!bundle || typeof bundle !== JS_TYPE_OBJECT) {
    rejectType(`${context} requires a manifest bundle object`);
  }
  const direct =
    tryBufferFrom(bundle.manifest_bytes) ?? tryBufferFrom(bundle.manifestBytes);
  if (direct) {
    return direct;
  }
  let manifestB64 = null;
  let manifestField = null;
  if (typeof bundle.manifest_b64 === JS_TYPE_STRING && bundle.manifest_b64.trim()) {
    manifestB64 = bundle.manifest_b64;
    manifestField = "manifest_b64";
  } else if (typeof bundle.manifestB64 === JS_TYPE_STRING && bundle.manifestB64.trim()) {
    manifestB64 = bundle.manifestB64;
    manifestField = "manifestB64";
  }
  if (manifestB64) {
    const normalized = normalizeRequiredBase64Payload(
      manifestB64,
      `${context}.${manifestField}`,
    );
    return Buffer.from(normalized, "base64");
  }
  return null;
}

function tryBufferFrom(value) {
  if (!value) {
    return null;
  }
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (ArrayBuffer.isView && ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
    return Buffer.from(value);
  }
  return null;
}

function inferChunkerHandleFromManifest(manifestJson) {
  if (!isPlainObject(manifestJson)) {
    return null;
  }
  if (
    typeof manifestJson.chunker_handle === JS_TYPE_STRING &&
    manifestJson.chunker_handle.trim()
  ) {
    return manifestJson.chunker_handle.trim();
  }
  if (
    typeof manifestJson.chunk_profile_handle === JS_TYPE_STRING &&
    manifestJson.chunk_profile_handle.trim()
  ) {
    return manifestJson.chunk_profile_handle.trim();
  }
  const chunking =
    manifestJson.chunking ??
    manifestJson.chunk_profile ??
    manifestJson.chunkProfile ??
    null;
  if (isPlainObject(chunking)) {
    const namespace =
      chunking.namespace ??
      chunking.ns ??
      chunking.profile_namespace ??
      chunking.profileNamespace;
    const name =
      chunking.name ??
      chunking.profile ??
      chunking.handle ??
      chunking.chunker ??
      chunking.id;
    const version =
      chunking.semver ??
      chunking.version ??
      chunking.profile_version ??
      chunking.rev ??
      chunking.release;
    if (
      typeof namespace === JS_TYPE_STRING &&
      namespace.trim() &&
      typeof name === JS_TYPE_STRING &&
      name.trim() &&
      typeof version === JS_TYPE_STRING &&
      version.trim()
    ) {
      return `${namespace.trim()}.${name.trim()}@${version.trim()}`;
    }
  }
  return null;
}

function normalizeDaGatewayProviders(value, context) {
  if (!Array.isArray(value) || value.length === 0) {
    rejectType(`${context} must be a non-empty array`);
  }
  return value.map((entry, index) => {
    const record = ensureRecord(entry, `${context}[${index}]`);
    const native = normaliseGatewayProvider({
      name: record.name,
      providerIdHex:
        record.providerIdHex ??
        record.provider_id_hex ??
        record.providerId ??
        record.provider_id,
      gatewayPublicKeyHex:
        record.gatewayPublicKeyHex ??
        record.gateway_public_key_hex ??
        record.gatewayPublicKey ??
        record.gateway_public_key,
      baseUrl: record.baseUrl,
      streamTokenB64:
        record.streamTokenB64 ??
        record.stream_token_b64 ??
        record.streamToken ??
        record.stream_token,
      privacyEventsUrl: record.privacyEventsUrl ?? record.privacy_events_url,
    });
    return {
      name: native.name,
      providerIdHex: native.provider_id_hex,
      gatewayPublicKeyHex: native.gateway_public_key_hex,
      baseUrl: native.base_url,
      streamTokenB64: native.stream_token_b64,
      privacyEventsUrl: native.privacy_events_url ?? null,
    };
  });
}

function normalizeDaIngestResponse(payload, context = "da ingest response") {
  const record = ensureRecord(payload ?? {}, context);
  const status = requireNonEmptyString(record.status, `${context}.status`);
  const duplicate = requireBooleanLike(record.duplicate, `${context}.duplicate`);
  const receipt = record.receipt
    ? normalizeDaIngestReceipt(record.receipt, `${context}.receipt`)
    : null;
  return { status, duplicate, receipt };
}

function normalizeDaIngestReceipt(payload, context = "da ingest receipt") {
  const record = ensureRecord(payload ?? {}, context);
  assertSupportedOptionKeys(
    record,
    new Set([
      "client_blob_id",
      "lane_id",
      "epoch",
      "blob_hash",
      "chunk_root",
      "manifest_hash",
      "storage_ticket",
      "pdp_commitment",
      "stripe_layout",
      "queued_at_unix",
      "rent_quote",
      "operator_signature",
    ]),
    context,
  );
  const clientBlobId = decodeDaDigestTuple(
    record.client_blob_id,
    32,
    `${context}.client_blob_id`,
  );
  const blobHash = decodeDaDigestTuple(
    record.blob_hash,
    32,
    `${context}.blob_hash`,
  );
  const chunkRoot = decodeDaDigestTuple(
    record.chunk_root,
    32,
    `${context}.chunk_root`,
  );
  const manifestHash = decodeDaDigestTuple(
    record.manifest_hash,
    32,
    `${context}.manifest_hash`,
  );
  const storageTicket = decodeDaDigestTuple(
    record.storage_ticket,
    32,
    `${context}.storage_ticket`,
  );
  const stripeLayoutRecord = record.stripe_layout;
  if (stripeLayoutRecord === null || stripeLayoutRecord === undefined) {
    rejectType(`${context}.stripe_layout is required`);
  }
  const stripeLayout = (() => {
    const layout = ensureRecord(stripeLayoutRecord, `${context}.stripe_layout`);
    assertSupportedOptionKeys(
      layout,
      new Set(["total_stripes", "shards_per_stripe", "row_parity_stripes"]),
      `${context}.stripe_layout`,
    );
    const totalStripes = ToriiClient._normalizeUnsignedInteger(
      layout.total_stripes,
      `${context}.stripe_layout.total_stripes`,
      { allowZero: true, max: 0xffff_ffff },
    );
    const shardsPerStripe = ToriiClient._normalizeUnsignedInteger(
      layout.shards_per_stripe,
      `${context}.stripe_layout.shards_per_stripe`,
      { allowZero: true, max: 0xffff_ffff },
    );
    const rowParityStripes = ToriiClient._normalizeUnsignedInteger(
      layout.row_parity_stripes,
      `${context}.stripe_layout.row_parity_stripes`,
      { allowZero: true, max: 0xffff },
    );
    return {
      total_stripes: totalStripes,
      shards_per_stripe: shardsPerStripe,
      row_parity_stripes: rowParityStripes,
    };
  })();
  if (!Object.prototype.hasOwnProperty.call(record, "pdp_commitment")) {
    rejectType(`${context}.pdp_commitment is required and must be null or a base64 string`);
  }
  const pdpCommitment = record.pdp_commitment;
  let pdpCommitmentBytes = null;
  let pdpCommitmentB64 = null;
  if (pdpCommitment !== null && pdpCommitment !== undefined) {
    if (typeof pdpCommitment !== JS_TYPE_STRING) {
      rejectType(`${context}.pdp_commitment must be a base64 string when present`);
    }
    const trimmed = pdpCommitment.trim();
    try {
      const decoded = strictDecodeBase64(trimmed);
      pdpCommitmentBytes = Buffer.from(decoded);
      pdpCommitmentB64 = Buffer.from(decoded).toString("base64");
    } catch {
      rejectType(`${context}.pdp_commitment must be a valid base64 string`);
    }
  }
  if (record.rent_quote === null || record.rent_quote === undefined) {
    rejectType(`${context}.rent_quote is required`);
  }
  const rentQuote = normalizeDaRentQuote(
    record.rent_quote,
    `${context}.rent_quote`,
  );
  return {
    client_blob_id_hex: bufferToUpperHex(clientBlobId),
    client_blob_id_bytes: clientBlobId,
    lane_id: ToriiClient._normalizeUnsignedInteger(
      record.lane_id,
      `${context}.lane_id`,
      { allowZero: true },
    ),
    epoch: ToriiClient._normalizeUnsignedInteger(
      record.epoch,
      `${context}.epoch`,
      { allowZero: true },
    ),
    blob_hash_hex: bufferToUpperHex(blobHash),
    blob_hash_bytes: blobHash,
    chunk_root_hex: bufferToUpperHex(chunkRoot),
    chunk_root_bytes: chunkRoot,
    manifest_hash_hex: bufferToUpperHex(manifestHash),
    manifest_hash_bytes: manifestHash,
    storage_ticket_hex: bufferToUpperHex(storageTicket),
    storage_ticket_bytes: storageTicket,
    stripe_layout: stripeLayout,
    pdp_commitment_b64: pdpCommitmentB64 ?? (pdpCommitment ?? null),
    pdp_commitment_bytes: pdpCommitmentBytes,
    queued_at_unix: ToriiClient._normalizeUnsignedInteger(
      record.queued_at_unix,
      `${context}.queued_at_unix`,
      { allowZero: true },
    ),
    operator_signature_hex: normalizeUpperHex(
      record.operator_signature ?? "",
      `${context}.operator_signature`,
    ),
    rent_quote: rentQuote,
  };
}

function normalizeDaRentQuote(payload, context = "da rent quote") {
  if (payload === null || payload === undefined) {
    return null;
  }
  const record = ensureRecord(payload, context);
  rejectRetiredSorafsMonetaryFields(
    record,
    [
      "base_rent_micro",
      "protocol_reserve_micro",
      "provider_reward_micro",
      "pdp_bonus_micro",
      "potr_bonus_micro",
      "egress_credit_per_gib_micro",
    ],
    context,
  );
  return {
    base_rent: normalizeSorafsXorQuantity(
      record.base_rent,
      `${context}.base_rent`,
    ),
    protocol_reserve: normalizeSorafsXorQuantity(
      record.protocol_reserve,
      `${context}.protocol_reserve`,
    ),
    provider_reward: normalizeSorafsXorQuantity(
      record.provider_reward,
      `${context}.provider_reward`,
    ),
    pdp_bonus: normalizeSorafsXorQuantity(
      record.pdp_bonus,
      `${context}.pdp_bonus`,
    ),
    potr_bonus: normalizeSorafsXorQuantity(
      record.potr_bonus,
      `${context}.potr_bonus`,
    ),
    egress_credit_per_gib: normalizeSorafsXorQuantity(
      record.egress_credit_per_gib,
      `${context}.egress_credit_per_gib`,
    ),
  };
}

function decodeDaDigestTuple(value, expectedLength, name) {
  if (!Array.isArray(value) || value.length === 0) {
    rejectType(`${name} must be an array`);
  }
  const bytes = Array.isArray(value[0]) ? value[0] : value;
  if (bytes.length !== expectedLength) {
    rejectType(`${name} must contain ${expectedLength} entries`);
  }
  const buffer = normalizeByteArray(bytes, name);
  if (buffer.length !== expectedLength) {
    rejectType(`${name} must decode to ${expectedLength} bytes`);
  }
  return buffer;
}

function bufferToUpperHex(buffer) {
  return Buffer.from(buffer).toString("hex").toUpperCase();
}

function normalizeUpperHex(value, name) {
  const trimmed = requireNonEmptyString(String(value ?? ""), name).replace(/^0x/i, "");
  if (trimmed.length === 0 || trimmed.length % 2 !== 0) {
    rejectType(`${name} must be an even-length hex string`);
  }
  if (!/^([0-9A-Fa-f]{2})+$/.test(trimmed)) {
    rejectType(`${name} must be a hex string`);
  }
  return trimmed.toUpperCase();
}

function normalizeSorafsPorSubmissionResponse(
  payload,
  context = "sorafs por submission response",
) {
  const record = ensureRecord(payload ?? {}, context);
  return {
    status: requireNonEmptyString(record.status, `${context}.status`),
  };
}

function normalizeSorafsPorVerdictResponse(
  payload,
  context = "sorafs por verdict response",
) {
  return normalizeSorafsPorSubmissionResponse(payload, context);
}

function normalizePeerListResponse(payload, context = "peer list response") {
  if (!Array.isArray(payload)) {
    rejectType(`${context} must be an array`);
  }
  return payload.map((entry, index) => {
    const record = ensureRecord(entry, `${context}[${index}]`);
    const address = requireNonEmptyString(
      record.address,
      `${context}[${index}].address`,
    );
    const idRecord = ensureRecord(
      record.id,
      `${context}[${index}].id`,
    );
    const publicKeyHex = normalizeHex32String(
      idRecord.public_key,
      `${context}[${index}].id.public_key`,
    );
    return {
      address,
      public_key_hex: publicKeyHex,
    };
  });
}

function normalizeTelemetryPeersInfoList(payload) {
  if (!Array.isArray(payload)) {
    rejectType("telemetry peers response must be an array");
  }
  return payload.map((entry, index) =>
    normalizeTelemetryPeerInfo(entry, `telemetry peers response[${index}]`),
  );
}

function normalizeTelemetryPeerInfo(value, context) {
  const record = ensureRecord(value, context);
  const url = requireNonEmptyString(record.url, `${context}.url`);
  const connected = requireBooleanLike(record.connected, `${context}.connected`);
  const telemetryUnsupported = requireBooleanLike(
    record.telemetry_unsupported ?? false,
    `${context}.telemetry_unsupported`,
  );
  const configValue = record.config ?? null;
  const locationValue = record.location ?? null;
  const result = {
    url,
    connected,
    telemetryUnsupported,
  };
  if (configValue !== null) {
    result.config = normalizeTelemetryPeerConfig(configValue, `${context}.config`);
  }
  if (locationValue !== null) {
    result.location = normalizeTelemetryPeerLocation(locationValue, `${context}.location`);
  }
  if (record.connected_peers !== undefined && record.connected_peers !== null) {
    if (!Array.isArray(record.connected_peers)) {
      rejectType(`${context}.connected_peers must be an array`);
    }
    result.connectedPeers = record.connected_peers.map((entry, idx) =>
      requireNonEmptyString(entry, `${context}.connected_peers[${idx}]`),
    );
  }
  return result;
}

function normalizeTelemetryPeerConfig(value, context) {
  const record = ensureRecord(value, context);
  const config = {
    publicKey: requireNonEmptyString(
      record.public_key ?? "",
      `${context}.public_key`,
    ),
  };
  const queueCapacity = record.queue_capacity;
  if (queueCapacity !== undefined && queueCapacity !== null) {
    config.queueCapacity = ToriiClient._normalizeUnsignedInteger(
      queueCapacity,
      `${context}.queue_capacity`,
      { allowZero: true },
    );
  }
  const blockSize = record.network_block_gossip_size;
  if (blockSize !== undefined && blockSize !== null) {
    config.networkBlockGossipSize = ToriiClient._normalizeUnsignedInteger(
      blockSize,
      `${context}.network_block_gossip_size`,
      { allowZero: true },
    );
  }
  const txSize = record.network_tx_gossip_size;
  if (txSize !== undefined && txSize !== null) {
    config.networkTxGossipSize = ToriiClient._normalizeUnsignedInteger(
      txSize,
      `${context}.network_tx_gossip_size`,
      { allowZero: true },
    );
  }
  const blockPeriod = normalizeExplorerDurationMs(
    record.network_block_gossip_period,
    `${context}.network_block_gossip_period`,
  );
  if (blockPeriod !== undefined) {
    config.networkBlockGossipPeriodMs = blockPeriod;
  }
  const txPeriod = normalizeExplorerDurationMs(
    record.network_tx_gossip_period,
    `${context}.network_tx_gossip_period`,
  );
  if (txPeriod !== undefined) {
    config.networkTxGossipPeriodMs = txPeriod;
  }
  return config;
}

function normalizeTelemetryPeerLocation(value, context) {
  const record = ensureRecord(value, context);
  return {
    lat: requireFiniteNumber(record.lat, `${context}.lat`),
    lon: requireFiniteNumber(record.lon, `${context}.lon`),
    country: requireNonEmptyString(record.country, `${context}.country`),
    city: requireNonEmptyString(record.city, `${context}.city`),
  };
}

function normalizeExplorerDurationMs(value, context) {
  if (value === undefined || value === null) {
    return undefined;
  }
  const record = ensureRecord(value, context);
  return ToriiClient._normalizeUnsignedInteger(record.ms, `${context}.ms`, {
    allowZero: true,
  });
}

function requireFiniteNumber(value, context) {
  if (typeof value !== JS_TYPE_NUMBER || Number.isNaN(value) || !Number.isFinite(value)) {
    rejectType(`${context} must be a finite number`);
  }
  return value;
}

function requireKaigiResponseObject(
  value,
  requiredFields,
  allowedFields,
  context,
) {
  const record = ensureRecord(value, context);
  const missing = [...requiredFields].filter(
    (field) => !Object.prototype.hasOwnProperty.call(record, field),
  );
  const extra = Object.keys(record).filter((field) => !allowedFields.has(field));
  if (missing.length !== 0 || extra.length !== 0) {
    rejectType(`${context} fields are not canonical; missing=[${missing.join(", ")}] extra=[${extra.join(", ")}]`);
  }
  return record;
}

function normalizeKaigiU64(value, context) {
  let integer;
  if (
    typeof value === JS_TYPE_NUMBER
    && Number.isSafeInteger(value)
    && !Object.is(value, -0)
  ) {
    integer = BigInt(value);
  } else if (typeof value === JS_TYPE_BIGINT) {
    integer = value;
  } else {
    rejectType(`${context} must be a canonical unsigned integer`);
  }
  if (integer < 0n || integer > MAX_UINT64_BIGINT) {
    rejectRange(`${context} must be between 0 and ${MAX_UINT64_BIGINT}`);
  }
  return integer <= MAX_SAFE_INTEGER_BIGINT ? Number(integer) : integer;
}

function normalizeKaigiBoundedUnsignedInteger(value, context, maximum) {
  const normalized = normalizeKaigiU64(value, context);
  if (BigInt(normalized) > BigInt(maximum)) {
    rejectRange(`${context} must be between 0 and ${maximum}`);
  }
  return Number(normalized);
}

function requireKaigiMarkedHash(value, context) {
  const literal = requireExactLowerHex32String(value, context);
  if ((Number.parseInt(literal.slice(-2), 16) & 1) !== 1) {
    rejectType(`${context} must set the Iroha Hash marker bit`);
  }
  return literal;
}

function parseKaigiSseEventPayload(event, context) {
  if (typeof event?.raw !== JS_TYPE_STRING || event.raw.length === 0) {
    rejectType(`${context}.data must be a JSON object`);
  }
  return parseStrictLosslessIntegerJson(event.raw, `${context}.data`);
}

function normalizeKaigiRelaySummaryList(payload) {
  const context = "kaigi relay summary response";
  const record = requireKaigiResponseObject(
    payload,
    new Set(["total", "items"]),
    new Set(["total", "items"]),
    context,
  );
  const rawItems = requireDenseArray(
    record.items,
    `${context}.items`,
  );
  if (rawItems.length > KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS) {
    rejectRange(`kaigi relay summary response.items must not exceed ${KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS} entries`);
  }
  const items = rawItems.map((entry, index) =>
    normalizeKaigiRelaySummary(entry, `${context}.items[${index}]`),
  );
  const total = normalizeKaigiU64(record.total, `${context}.total`);
  if (BigInt(total) !== BigInt(items.length)) {
    rejectRange(`${context}.total must equal items.length`);
  }
  const relayIds = new Set(items.map((item) => item.relay_id));
  if (relayIds.size !== items.length) {
    rejectType(`${context}.items must contain unique relay_id values`);
  }
  return {
    total,
    items,
  };
}

function normalizeKaigiRelaySummary(payload, context) {
  const record = requireKaigiResponseObject(
    payload,
    KAIGI_RELAY_SUMMARY_REQUIRED_FIELDS,
    KAIGI_RELAY_SUMMARY_FIELDS,
    context,
  );
  const relayId = requireExactAccountId(record.relay_id, `${context}.relay_id`);
  const domain = requireExactNonEmptyString(record.domain, `${context}.domain`);
  const bandwidthClass = normalizeKaigiBandwidthClass(
    record.bandwidth_class,
    `${context}.bandwidth_class`,
  );
  const hpkeFingerprintContext = `${context}.hpke_fingerprint_hex`;
  const hpkeFingerprint = requireKaigiMarkedHash(
    record.hpke_fingerprint_hex,
    hpkeFingerprintContext,
  );
  const hasStatus = Object.prototype.hasOwnProperty.call(record, "status");
  const hasReportedAt = Object.prototype.hasOwnProperty.call(record, "reported_at_ms");
  if (hasStatus !== hasReportedAt) {
    rejectType(`${context}.status and reported_at_ms must be present together`);
  }
  let status = null;
  if (hasStatus) {
    const value = requireExactNonEmptyString(record.status, `${context}.status`);
    if (!KAIGI_HEALTH_STATUS_VALUES.has(value)) {
      rejectType(`${context}.status must be exact lowercase healthy, degraded, or unavailable`);
    }
    status = value;
  }
  let reportedAtMs = null;
  if (hasReportedAt) {
    reportedAtMs = normalizeKaigiU64(
      record.reported_at_ms,
      `${context}.reported_at_ms`,
    );
  }
  return {
    relay_id: relayId,
    domain,
    bandwidth_class: bandwidthClass,
    hpke_fingerprint_hex: hpkeFingerprint,
    status,
    reported_at_ms: reportedAtMs,
  };
}

function normalizeKaigiBandwidthClass(value, context) {
  const normalized = normalizeKaigiBoundedUnsignedInteger(value, context, 0xff);
  if (normalized === 0) {
    rejectRange(`${context} must be between 1 and 255`);
  }
  return normalized;
}

function normalizeKaigiRelayDetail(payload) {
  const context = "kaigi relay detail";
  const record = requireKaigiResponseObject(
    payload,
    KAIGI_RELAY_DETAIL_REQUIRED_FIELDS,
    KAIGI_RELAY_DETAIL_FIELDS,
    context,
  );
  const relaySummary = normalizeKaigiRelaySummary(record.relay, "kaigi relay detail.relay");
  const hpkePublicKeyContext = "kaigi relay detail.hpke_public_key_b64";
  const hpkePublicKey = normalizeRequiredExactBase64Payload(
    requireExactNonEmptyString(record.hpke_public_key_b64, hpkePublicKeyContext),
    hpkePublicKeyContext,
  );
  const hpkePublicKeyBytes = Buffer.from(strictDecodeBase64(hpkePublicKey));
  const expectedFingerprint = Buffer.from(blake2b256(hpkePublicKeyBytes));
  expectedFingerprint[expectedFingerprint.length - 1] |= 1;
  if (relaySummary.hpke_fingerprint_hex !== expectedFingerprint.toString("hex")) {
    rejectType("kaigi relay detail.relay.hpke_fingerprint_hex must match the marked HPKE public-key fingerprint");
  }
  const hasReportedCall = Object.prototype.hasOwnProperty.call(record, "reported_call");
  const hasReportedBy = Object.prototype.hasOwnProperty.call(record, "reported_by");
  const hasNotes = Object.prototype.hasOwnProperty.call(record, "notes");
  const hasFeedback = relaySummary.status !== null;
  if (
    hasReportedCall !== hasFeedback
    || hasReportedBy !== hasFeedback
    || (hasNotes && !hasFeedback)
  ) {
    rejectType("kaigi relay detail feedback fields must agree with relay status and reported_at_ms");
  }
  let reportedCall = null;
  if (hasReportedCall) {
    const callContext = "kaigi relay detail.reported_call";
    const callRecord = requireKaigiResponseObject(
      record.reported_call,
      new Set(["domain_id", "call_name"]),
      new Set(["domain_id", "call_name"]),
      callContext,
    );
    reportedCall = {
      domain_id: requireExactNonEmptyString(
        callRecord.domain_id,
        `${callContext}.domain_id`,
      ),
      call_name: requireExactNonEmptyString(
        callRecord.call_name,
        `${callContext}.call_name`,
      ),
    };
  }
  let reportedBy = null;
  if (hasReportedBy) {
    reportedBy = requireExactAccountId(
      record.reported_by,
      "kaigi relay detail.reported_by",
    );
  }
  let notes = null;
  if (hasNotes) {
    if (typeof record.notes !== JS_TYPE_STRING) {
      rejectType("kaigi relay detail.notes must be a string");
    }
    notes = record.notes;
  }
  let metrics = null;
  if (Object.prototype.hasOwnProperty.call(record, "metrics")) {
    metrics = normalizeKaigiRelayDomainMetrics(record.metrics, "kaigi relay detail.metrics");
    if (metrics.domain !== relaySummary.domain) {
      rejectType("kaigi relay detail.metrics.domain must match relay.domain");
    }
  }
  return {
    relay: relaySummary,
    hpke_public_key_b64: hpkePublicKey,
    reported_call: reportedCall,
    reported_by: reportedBy,
    notes,
    metrics,
  };
}

function normalizeKaigiRelayDomainMetrics(payload, context) {
  const record = requireKaigiResponseObject(
    payload,
    KAIGI_RELAY_DOMAIN_METRICS_FIELDS,
    KAIGI_RELAY_DOMAIN_METRICS_FIELDS,
    context,
  );
  return {
    domain: requireExactNonEmptyString(
      record.domain,
      `${context}.domain`,
    ),
    registrations_total: normalizeKaigiU64(
      record.registrations_total,
      `${context}.registrations_total`,
    ),
    manifest_updates_total: normalizeKaigiU64(
      record.manifest_updates_total,
      `${context}.manifest_updates_total`,
    ),
    failovers_total: normalizeKaigiU64(
      record.failovers_total,
      `${context}.failovers_total`,
    ),
    health_reports_total: normalizeKaigiU64(
      record.health_reports_total,
      `${context}.health_reports_total`,
    ),
  };
}

function normalizeKaigiRelayHealthSnapshot(payload) {
  const context = "kaigi relay health snapshot";
  const record = requireKaigiResponseObject(
    payload,
    KAIGI_RELAY_HEALTH_SNAPSHOT_FIELDS,
    KAIGI_RELAY_HEALTH_SNAPSHOT_FIELDS,
    context,
  );
  const rawDomains = requireDenseArray(
    record.domains,
    "kaigi relay health snapshot.domains",
  );
  if (rawDomains.length > KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS) {
    rejectRange(`kaigi relay health snapshot.domains must not exceed ${KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS} entries`);
  }
  const domains = rawDomains.map((entry, index) =>
    normalizeKaigiRelayDomainMetrics(entry, `kaigi relay health snapshot.domains[${index}]`),
  );
  for (let index = 1; index < domains.length; index += 1) {
    if (domains[index - 1].domain >= domains[index].domain) {
      rejectType(`${context}.domains must be sorted with unique domain values`);
    }
  }
  const snapshot = {
    healthy_total: normalizeKaigiU64(
      record.healthy_total,
      `${context}.healthy_total`,
    ),
    degraded_total: normalizeKaigiU64(
      record.degraded_total,
      `${context}.degraded_total`,
    ),
    unavailable_total: normalizeKaigiU64(
      record.unavailable_total,
      `${context}.unavailable_total`,
    ),
    reports_total: normalizeKaigiU64(
      record.reports_total,
      `${context}.reports_total`,
    ),
    registrations_total: normalizeKaigiU64(
      record.registrations_total,
      `${context}.registrations_total`,
    ),
    failovers_total: normalizeKaigiU64(
      record.failovers_total,
      `${context}.failovers_total`,
    ),
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
  const aggregateFields = [
    ["reports_total", "health_reports_total"],
    ["registrations_total", "registrations_total"],
    ["failovers_total", "failovers_total"],
  ];
  for (const [totalField, domainField] of aggregateFields) {
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

function requireKaigiEnum(value, allowedValues, context) {
  const literal = requireExactNonEmptyString(value, context);
  if (!allowedValues.has(literal)) {
    rejectType(`${context} is not a supported exact lowercase value`);
  }
  return literal;
}

function normalizeKaigiCallIdentityFields(record, context, expectedCallId) {
  const callId = requireExactNonEmptyString(record.call_id, `${context}.call_id`);
  const domain = requireExactNonEmptyString(record.domain, `${context}.domain`);
  const callName = requireExactNonEmptyString(record.call_name, `${context}.call_name`);
  if (callId !== `${domain}:${callName}`) {
    rejectType(`${context}.call_id must match domain and call_name`);
  }
  if (expectedCallId !== undefined && callId !== expectedCallId) {
    rejectType(`${context}.call_id must match the requested call id`);
  }
  return { call_id: callId, domain, call_name: callName };
}

function normalizeKaigiCallEventRef(payload, context, expectedCallId) {
  const fields = new Set(["call_id", "domain", "call_name"]);
  const record = requireKaigiResponseObject(payload, fields, fields, context);
  return normalizeKaigiCallIdentityFields(record, context, expectedCallId);
}

function normalizeKaigiCallView(payload, expectedCallId) {
  const context = "kaigi call";
  const record = requireKaigiResponseObject(
    payload,
    KAIGI_CALL_VIEW_REQUIRED_FIELDS,
    KAIGI_CALL_VIEW_FIELDS,
    context,
  );
  const identity = normalizeKaigiCallIdentityFields(record, context, expectedCallId);
  const metadata = ensureRecord(record.metadata, `${context}.metadata`);
  const hasRelayManifest = Object.prototype.hasOwnProperty.call(record, "relay_manifest");
  const relayManifest = hasRelayManifest
    ? ensureRecord(record.relay_manifest, `${context}.relay_manifest`)
    : undefined;
  const privacyMode = requireKaigiEnum(
    record.privacy_mode,
    new Set(["transparent", "private"]),
    `${context}.privacy_mode`,
  );
  const roomPolicy = requireKaigiEnum(
    record.room_policy,
    new Set(["public", "authenticated"]),
    `${context}.room_policy`,
  );
  const status = requireKaigiEnum(
    record.status,
    new Set(["active", "ended"]),
    `${context}.status`,
  );
  const hasHost = Object.prototype.hasOwnProperty.call(record, "host_account_id");
  const hasBilling = Object.prototype.hasOwnProperty.call(record, "billing_account_id");
  const hasParticipantCount = Object.prototype.hasOwnProperty.call(record, "participant_count");
  if (
    (privacyMode === "transparent" && (!hasHost || !hasParticipantCount))
    || (privacyMode === "private" && (hasHost || hasBilling || hasParticipantCount))
  ) {
    rejectType(`${context} authority and participant fields must agree with privacy_mode`);
  }
  const hasEndedAt = Object.prototype.hasOwnProperty.call(record, "ended_at_ms");
  if (hasEndedAt !== (status === "ended")) {
    rejectType(`${context}.ended_at_ms must be present exactly when status is ended`);
  }
  const maxParticipants = Object.prototype.hasOwnProperty.call(record, "max_participants")
    ? normalizeKaigiBoundedUnsignedInteger(
          record.max_participants,
          `${context}.max_participants`,
          0xffff_ffff,
        )
    : undefined;
  if (maxParticipants === 0 || maxParticipants > KAIGI_MAX_PARTICIPANTS_V1) {
    rejectRange(`${context}.max_participants must be between 1 and ${KAIGI_MAX_PARTICIPANTS_V1}`);
  }
  const createdAtMs = normalizeKaigiU64(
    record.created_at_ms,
    "kaigi call.created_at_ms",
  );
  const endedAtMs = hasEndedAt
    ? normalizeKaigiU64(
          record.ended_at_ms,
          "kaigi call.ended_at_ms",
        )
    : undefined;
  if (endedAtMs !== undefined && BigInt(endedAtMs) < BigInt(createdAtMs)) {
    rejectRange(`${context}.ended_at_ms must not precede created_at_ms`);
  }
  return {
    ...identity,
    host_account_id: hasHost
      ? requireExactAccountId(record.host_account_id, `${context}.host_account_id`)
      : undefined,
    billing_account_id: hasBilling
      ? requireExactAccountId(
            record.billing_account_id,
            `${context}.billing_account_id`,
          )
      : undefined,
    title: Object.prototype.hasOwnProperty.call(record, "title")
      ? requireExactString(record.title, `${context}.title`)
      : undefined,
    description: Object.prototype.hasOwnProperty.call(record, "description")
      ? requireExactString(record.description, `${context}.description`)
      : undefined,
    max_participants: maxParticipants,
    gas_rate_per_minute: normalizeKaigiU64(
      record.gas_rate_per_minute,
      `${context}.gas_rate_per_minute`,
    ),
    metadata,
    scheduled_start_ms: Object.prototype.hasOwnProperty.call(record, "scheduled_start_ms")
      ? normalizeKaigiU64(
            record.scheduled_start_ms,
            `${context}.scheduled_start_ms`,
          )
      : undefined,
    privacy_mode: privacyMode,
    room_policy: roomPolicy,
    relay_manifest: relayManifest,
    roster_root_hex: requireKaigiMarkedHash(
      record.roster_root_hex,
      "kaigi call.roster_root_hex",
    ),
    participant_count: hasParticipantCount
      ? normalizeKaigiBoundedUnsignedInteger(
            record.participant_count,
            `${context}.participant_count`,
            0xffff_ffff,
          )
      : undefined,
    commitment_count: normalizeKaigiBoundedUnsignedInteger(
      record.commitment_count,
      "kaigi call.commitment_count",
      0xffff_ffff,
    ),
    nullifier_count: normalizeKaigiBoundedUnsignedInteger(
      record.nullifier_count,
      "kaigi call.nullifier_count",
      0xffff_ffff,
    ),
    usage_commitment_count: normalizeKaigiBoundedUnsignedInteger(
      record.usage_commitment_count,
      "kaigi call.usage_commitment_count",
      0xffff_ffff,
    ),
    status,
    created_at_ms: createdAtMs,
    ended_at_ms: endedAtMs,
    total_duration_ms: normalizeKaigiU64(
      record.total_duration_ms,
      "kaigi call.total_duration_ms",
    ),
    total_billed_gas: normalizeKaigiU64(
      record.total_billed_gas,
      "kaigi call.total_billed_gas",
    ),
    segments_recorded: normalizeKaigiBoundedUnsignedInteger(
      record.segments_recorded,
      "kaigi call.segments_recorded",
      0xffff_ffff,
    ),
  };
}

function normalizeKaigiCallSignal(payload, context, expectedCallId) {
  const record = requireKaigiResponseObject(
    payload,
    KAIGI_CALL_SIGNAL_REQUIRED_FIELDS,
    KAIGI_CALL_SIGNAL_FIELDS,
    context,
  );
  const callId = requireExactNonEmptyString(record.call_id, `${context}.call_id`);
  if (callId !== expectedCallId) {
    rejectType(`${context}.call_id must match the requested call id`);
  }
  if (typeof record.signal_kind !== JS_TYPE_STRING) {
    rejectType(`${context}.signal_kind must be a string`);
  }
  const signalKind = record.signal_kind;
  if (signalKind.length === 0) {
    rejectType(`${context}.signal_kind must not be empty`);
  }
  if (/^\p{White_Space}|\p{White_Space}$/u.test(signalKind)) {
    rejectType(`${context}.signal_kind must not contain surrounding Unicode whitespace`);
  }
  if (/[A-Z]/u.test(signalKind)) {
    rejectType(`${context}.signal_kind must not contain uppercase ASCII characters`);
  }
  const timestampMs = normalizeKaigiU64(record.timestamp_ms, `${context}.timestamp_ms`);
  const createdAtMs = normalizeKaigiU64(record.created_at_ms, `${context}.created_at_ms`);
  if (BigInt(createdAtMs) > BigInt(timestampMs)) {
    rejectRange(`${context}.created_at_ms must not exceed timestamp_ms`);
  }
  const metadata = ensureRecord(record.metadata, `${context}.metadata`);
  if (metadata.schema !== KAIGI_SIGNAL_SCHEMA_V1) {
    rejectType(`${context}.metadata.schema must be ${KAIGI_SIGNAL_SCHEMA_V1}`);
  }
  return {
    entrypoint_hash: requireKaigiMarkedHash(
      record.entrypoint_hash,
      `${context}.entrypoint_hash`,
    ),
    authority: Object.prototype.hasOwnProperty.call(record, "authority")
      ? requireExactAccountId(record.authority, `${context}.authority`)
      : undefined,
    timestamp_ms: timestampMs,
    call_id: callId,
    signal_kind: signalKind,
    host_account_id: Object.prototype.hasOwnProperty.call(record, "host_account_id")
      ? requireExactNonEmptyString(record.host_account_id, `${context}.host_account_id`)
      : undefined,
    participant_account_id: Object.prototype.hasOwnProperty.call(
      record,
      "participant_account_id",
    )
      ? requireExactNonEmptyString(
            record.participant_account_id,
            `${context}.participant_account_id`,
          )
      : undefined,
    created_at_ms: createdAtMs,
    metadata,
  };
}

function normalizeKaigiCallSignalsList(payload, expectedCallId) {
  const context = "kaigi call signals";
  const requiredFields = new Set(["has_more", "items"]);
  const allowedFields = new Set([...requiredFields, "next_cursor"]);
  const record = requireKaigiResponseObject(
    payload,
    requiredFields,
    allowedFields,
    context,
  );
  const rawItems = requireDenseArray(record.items, `${context}.items`);
  if (rawItems.length > KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS) {
    rejectRange(`${context}.items must not exceed ${KAIGI_RELAY_DIAGNOSTIC_MAX_RELAYS} entries`);
  }
  const items = rawItems.map((entry, index) =>
    normalizeKaigiCallSignal(entry, `${context}.items[${index}]`, expectedCallId),
  );
  if (new Set(items.map((item) => item.entrypoint_hash)).size !== items.length) {
    rejectType(`${context}.items must contain unique entrypoint_hash values`);
  }
  if (typeof record.has_more !== "boolean") {
    rejectType(`${context}.has_more must be a boolean`);
  }
  const hasCursor = Object.prototype.hasOwnProperty.call(record, "next_cursor");
  if (record.has_more !== hasCursor) {
    rejectType(`${context}.next_cursor must be present exactly when has_more is true`);
  }
  const nextCursor = hasCursor
    ? normalizeKaigiCallSignalsCursor(
        record.next_cursor,
        `${context}.next_cursor`,
      )
    : undefined;
  return {
    has_more: record.has_more,
    next_cursor: nextCursor,
    items,
  };
}

function normalizeKaigiCallSignalsCursor(value, context) {
  const cursor = requireExactNonEmptyString(value, context);
  if (
    cursor.length > KAIGI_CALL_SIGNALS_CURSOR_MAX_BYTES
    || cursor.length % 4 === 1
    || !/^[A-Za-z0-9_-]+$/u.test(cursor)
  ) {
    rejectType(`${context} must be a canonical bounded base64url value`);
  }
  return cursor;
}

function normalizeKaigiCallEventData(payload, expectedCallId) {
  const context = "kaigi call event";
  const baseRecord = ensureRecord(payload, context);
  const kind = requireExactNonEmptyString(baseRecord.kind, `${context}.kind`);
  if (!KAIGI_CALL_EVENT_KIND_VALUES.has(kind)) {
    rejectType("kaigi call event.kind must be roster_updated or ended");
  }
  const requiredFields = kind === "ended"
    ? new Set(["kind", "call", "status", "ended_at_ms"])
    : new Set(["kind", "call", "privacy_mode", "commitment_count", "nullifier_count"]);
  const allowedFields = kind === "ended"
    ? requiredFields
    : new Set([...requiredFields, "participant_count", "roster_root_hex"]);
  const record = requireKaigiResponseObject(
    baseRecord,
    requiredFields,
    allowedFields,
    context,
  );
  const call = normalizeKaigiCallEventRef(
    record.call,
    `${context}.call`,
    expectedCallId,
  );
  if (kind === "ended") {
    if (record.status !== "ended") {
      rejectType(`${context}.status must be ended`);
    }
    return {
      kind,
      call,
      status: "ended",
      ended_at_ms: normalizeKaigiU64(
        record.ended_at_ms,
        "kaigi call event.ended_at_ms",
      ),
    };
  }
  const privacyMode = requireKaigiEnum(
    record.privacy_mode,
    new Set(["transparent", "private"]),
    `${context}.privacy_mode`,
  );
  const hasParticipantCount = Object.prototype.hasOwnProperty.call(record, "participant_count");
  const hasRosterRoot = Object.prototype.hasOwnProperty.call(record, "roster_root_hex");
  if (
    (privacyMode === "transparent" && (!hasParticipantCount || hasRosterRoot))
    || (privacyMode === "private" && (hasParticipantCount || !hasRosterRoot))
  ) {
    rejectType(`${context} roster fields must agree with privacy_mode`);
  }
  return {
    kind,
    call,
    privacy_mode: privacyMode,
    participant_count: hasParticipantCount
      ? normalizeKaigiBoundedUnsignedInteger(
            record.participant_count,
            `${context}.participant_count`,
            0xffff_ffff,
          )
      : undefined,
    commitment_count: normalizeKaigiBoundedUnsignedInteger(
      record.commitment_count,
      "kaigi call event.commitment_count",
      0xffff_ffff,
    ),
    nullifier_count: normalizeKaigiBoundedUnsignedInteger(
      record.nullifier_count,
      "kaigi call event.nullifier_count",
      0xffff_ffff,
    ),
    roster_root_hex: hasRosterRoot
      ? requireKaigiMarkedHash(
            record.roster_root_hex,
            "kaigi call event.roster_root_hex",
          )
      : undefined,
  };
}

function normalizeKaigiRelayEventData(payload) {
  const context = "kaigi relay event";
  const baseRecord = ensureRecord(payload, context);
  const kind = requireExactNonEmptyString(baseRecord.kind, `${context}.kind`);
  if (!KAIGI_EVENT_KIND_VALUES.has(kind)) {
    rejectType("kaigi relay event.kind must be exact lowercase registration, unregistration, or health");
  }
  const fields = kind === "registration"
    ? new Set(["kind", "domain", "relay_id", "bandwidth_class", "hpke_fingerprint_hex"])
    : kind === "unregistration"
      ? new Set(["kind", "domain", "relay_id"])
      : new Set(["kind", "domain", "relay_id", "status", "reported_at_ms", "call"]);
  const record = requireKaigiResponseObject(baseRecord, fields, fields, context);
  const domain = requireExactNonEmptyString(
    record.domain,
    "kaigi relay event.domain",
  );
  const relayId = requireExactAccountId(
    record.relay_id,
    "kaigi relay event.relay_id",
  );
  if (kind === "registration") {
    return {
      kind,
      domain,
      relay_id: relayId,
      bandwidth_class: normalizeKaigiBandwidthClass(
        record.bandwidth_class,
        "kaigi relay event.bandwidth_class",
      ),
      hpke_fingerprint_hex: requireKaigiMarkedHash(
        record.hpke_fingerprint_hex,
        "kaigi relay event.hpke_fingerprint_hex",
      ),
    };
  }
  if (kind === "unregistration") {
    return {
      kind,
      domain,
      relay_id: relayId,
    };
  }
  const statusValue = requireExactNonEmptyString(
    record.status,
    "kaigi relay event.status",
  );
  if (!KAIGI_HEALTH_STATUS_VALUES.has(statusValue)) {
    rejectType("kaigi relay event.status must be exact lowercase healthy, degraded, or unavailable");
  }
  const callRecord = requireKaigiResponseObject(
    record.call,
    new Set(["domain", "name"]),
    new Set(["domain", "name"]),
    "kaigi relay event.call",
  );
  const callDomain = requireExactNonEmptyString(
    callRecord.domain,
    "kaigi relay event.call.domain",
  );
  const callName = requireExactNonEmptyString(
    callRecord.name,
    "kaigi relay event.call.name",
  );
  if (callDomain !== domain) {
    rejectType("kaigi relay event.call.domain must match event.domain");
  }
  return {
    kind,
    domain,
    relay_id: relayId,
    status: statusValue,
    reported_at_ms: normalizeKaigiU64(
      record.reported_at_ms,
      "kaigi relay event.reported_at_ms",
    ),
    call: {
      domain: callDomain,
      name: callName,
    },
  };
}

function buildKaigiRelayEventParams(options = {}) {
  const normalizedOptions =
    options === undefined
      ? {}
      : requirePlainObjectOption(options, "kaigi relay event options", {
          message: "must be an object",
        });
  const params = {};
  if (normalizedOptions.domain !== undefined && normalizedOptions.domain !== null) {
    params.domain = requireNonEmptyString(
      normalizedOptions.domain,
      "kaigiRelayEvents.domain",
    ).toLowerCase();
  }
  if (normalizedOptions.relay !== undefined && normalizedOptions.relay !== null) {
    params.relay = requireNonEmptyString(normalizedOptions.relay, "kaigiRelayEvents.relay");
  }
  if (normalizedOptions.kind !== undefined && normalizedOptions.kind !== null) {
    const values = Array.isArray(normalizedOptions.kind)
      ? normalizedOptions.kind
      : String(normalizedOptions.kind)
          .split(",")
          .map((entry) => entry.trim())
          .filter((entry) => entry.length > 0);
    const normalized = [];
    for (const entry of values) {
      const token = requireNonEmptyString(entry, "kaigiRelayEvents.kind").toLowerCase();
      if (!KAIGI_EVENT_KIND_VALUES.has(token)) {
        rejectType("kaigiRelayEvents.kind must be registration, unregistration, or health");
      }
      normalized.push(token);
    }
    if (normalized.length > 0) {
      params.kind = normalized.join(",");
    }
  }
  return Object.keys(params).length === 0 ? undefined : params;
}

function buildKaigiCallSignalsQuery(options = {}) {
  const normalizedOptions =
    options === undefined || options === null
      ? undefined
      : requirePlainObjectOption(options, "kaigi call signals options", {
          message: "must be an object",
        });
  if (normalizedOptions) {
    assertSupportedOptionKeys(
      normalizedOptions,
      new Set([
        "afterTimestampMs",
        "after_timestamp_ms",
        "limit",
        "cursor",
        "signal",
        CANONICAL_AUTH_FIELD,
      ]),
      "kaigi call signals options",
    );
  }
  const { signal } = normalizeSignalOption(normalizedOptions, "listKaigiCallSignals");
  const source = normalizedOptions ?? {};
  const params = {};
  const afterTimestampMs =
    source.afterTimestampMs !== undefined
      ? source.afterTimestampMs
      : source.after_timestamp_ms;
  if (afterTimestampMs !== undefined && afterTimestampMs !== null) {
    params.after_timestamp_ms = ToriiClient._normalizeUnsignedInteger(
      afterTimestampMs,
      "kaigiCallSignals.afterTimestampMs",
      { allowZero: true },
    );
  }
  if (source.limit !== undefined && source.limit !== null) {
    params.limit = ToriiClient._normalizeUnsignedInteger(
      source.limit,
      "kaigiCallSignals.limit",
      { allowZero: false },
    );
  }
  if (source.cursor !== undefined && source.cursor !== null) {
    params.cursor = normalizeKaigiCallSignalsCursor(
      source.cursor,
      "kaigiCallSignals.cursor",
    );
  }
  return {
    signal,
    params: Object.keys(params).length === 0 ? undefined : params,
    canonicalAuth: source.canonicalAuth,
  };
}

function buildKaigiCallEventParams(options = {}) {
  const normalizedOptions =
    options === undefined
      ? {}
      : requirePlainObjectOption(options, "kaigi call event options", {
          message: "must be an object",
        });
  const params = {};
  if (normalizedOptions.kind !== undefined && normalizedOptions.kind !== null) {
    const values = Array.isArray(normalizedOptions.kind)
      ? normalizedOptions.kind
      : String(normalizedOptions.kind)
          .split(",")
          .map((entry) => entry.trim())
          .filter((entry) => entry.length > 0);
    const normalized = [];
    for (const entry of values) {
      const token = requireNonEmptyString(entry, "kaigiCallEvents.kind").toLowerCase();
      if (!KAIGI_CALL_EVENT_KIND_VALUES.has(token)) {
        rejectType("kaigiCallEvents.kind must be roster_updated or ended");
      }
      normalized.push(token);
    }
    if (normalized.length > 0) {
      params.kind = normalized.join(",");
    }
  }
  return Object.keys(params).length === 0 ? undefined : params;
}

function buildTriggerListQuery(options = {}) {
  const normalizedOptions =
    options === undefined || options === null
      ? undefined
      : requirePlainObjectOption(options, "trigger list options", {
          message: "must be an object",
        });
  const { signal } = normalizeSignalOption(normalizedOptions ?? undefined, "triggers");
  const params = {};
  const source = normalizedOptions ?? {};
  if (source.namespace !== undefined && source.namespace !== null) {
    params.namespace = requireNonEmptyString(source.namespace, "triggers.namespace");
  }
  if (source.authority !== undefined && source.authority !== null) {
    params.authority = normalizeAccountId(source.authority, "triggers.authority");
  }
  if (source.limit !== undefined && source.limit !== null) {
    params.limit = ToriiClient._normalizeUnsignedInteger(source.limit, "triggers.limit", {
      allowZero: false,
    });
  }
  if (source.offset !== undefined && source.offset !== null) {
    params.offset = ToriiClient._normalizeUnsignedInteger(source.offset, "triggers.offset", {
      allowZero: true,
    });
  }
  return { signal, params: Object.keys(params).length === 0 ? undefined : params };
}

function normalizeSignalOption(options, context) {
  if (options === undefined) {
    return { signal: undefined };
  }
  if (!isPlainObject(options)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} options must be an object`,
      `${context}.options`,
    );
  }
  const { signal } = options;
  if (signal !== undefined && signal !== null && !isAbortSignalLike(signal)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} options.signal must be an AbortSignal`,
      `${context}.options.signal`,
    );
  }
  return { signal: signal ?? undefined };
}

function normalizeSignalOnlyOption(options, context) {
  const { signal } = normalizeSignalOption(options, context);
  if (options !== undefined) {
    const extras = Object.keys(options).filter((key) => key !== "signal");
    if (extras.length > 0) {
      throw createValidationError(
        ValidationErrorCode.INVALID_OBJECT,
        `${context} options contains unsupported fields: ${extras.join(", ")}`,
        `${context}.options`,
      );
    }
  }
  return { signal };
}

async function readBoundedResponseBody(response, maximumBodyBytes, label) {
  if (!Number.isSafeInteger(maximumBodyBytes) || maximumBodyBytes < 0) {
    rejectType(`${label} response byte-size bound is invalid`);
  }

  const rawContentLength = response.headers?.get?.("content-length");
  if (rawContentLength !== null && rawContentLength !== undefined) {
    if (
      typeof rawContentLength !== JS_TYPE_STRING ||
      !/^(?:0|[1-9][0-9]*)$/u.test(rawContentLength)
    ) {
      const error = new TypeError(
        `${label} response Content-Length must be a canonical unsigned decimal integer`,
      );
      await cancelResponseBody(response, error);
      throw error;
    }
    const declaredLength = Number(rawContentLength);
    if (!Number.isSafeInteger(declaredLength) || declaredLength > maximumBodyBytes) {
      const error = new TypeError(
        `${label} response exceeds its ${maximumBodyBytes}-byte size bound`,
      );
      await cancelResponseBody(response, error);
      throw error;
    }
  }

  if (response.body === null || response.body === undefined) {
    return new Uint8Array(0);
  }
  if (typeof response.body.getReader !== JS_TYPE_FUNCTION) {
    const error = new TypeError(
      `${label} response body is not readable as a byte stream`,
    );
    await cancelResponseBody(response, error);
    throw error;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;
  let cancelled = false;
  try {
    // A stream can omit Content-Length or advertise the encoded length while
    // yielding more decoded bytes. The running total is therefore authoritative.
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const result = await reader.read();
      if (!result || typeof result.done !== "boolean") {
        rejectType(`${label} response body returned an invalid stream result`);
      }
      if (result.done) {
        break;
      }
      if (!(result.value instanceof Uint8Array)) {
        rejectType(`${label} response body returned a non-byte chunk`);
      }
      if (result.value.byteLength > maximumBodyBytes - totalBytes) {
        const error = new TypeError(
          `${label} response exceeds its ${maximumBodyBytes}-byte size bound`,
        );
        cancelled = true;
        try {
          await reader.cancel(error);
        } catch {
          // Preserve the deterministic size-bound failure if transport cleanup fails.
        }
        throw error;
      }
      totalBytes += result.value.byteLength;
      chunks.push(result.value);
    }
  } catch (error) {
    if (!cancelled && typeof reader.cancel === JS_TYPE_FUNCTION) {
      cancelled = true;
      try {
        await reader.cancel(error);
      } catch {
        // Preserve the original stream or validation error.
      }
    }
    throw error;
  } finally {
    if (typeof reader.releaseLock === JS_TYPE_FUNCTION) {
      reader.releaseLock();
    }
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function cancelResponseBody(response, reason) {
  const body = response?.body;
  if (!body || body.locked || typeof body.cancel !== JS_TYPE_FUNCTION) {
    return;
  }
  try {
    await body.cancel(reason);
  } catch {
    // A rejected cancellation must not mask the fail-closed validation error.
  }
}

function requirePlainObjectOption(value, context, { message } = {}) {
  if (!isPlainObject(value)) {
    const normalizedPath =
      typeof context === JS_TYPE_STRING ? context.replace(/\s+/g, ".") : context;
    const normalizedMessage = message ?? "must be a plain object";
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} ${normalizedMessage}`,
      normalizedPath,
    );
  }
  return value;
}

function assertSupportedOptionKeys(record, allowedKeys, context) {
  const extras = Object.keys(record).filter((key) => !allowedKeys.has(key));
  if (extras.length > 0) {
    const path = typeof context === JS_TYPE_STRING ? context.replace(/\s+/g, ".") : context;
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context} contains unsupported fields: ${extras.join(", ")}`,
      path,
    );
  }
}

function normalizeIterableListOptions(options, context, allowedKeys = ITERABLE_LIST_OPTION_KEYS) {
  const normalized = ToriiClient._normalizeIterableOptions(options, context, allowedKeys);
  assertSupportedOptionKeys(normalized, allowedKeys, context);
  return normalized;
}

function normalizeIterableQueryOptions(options, context, extraAllowedKeys = []) {
  const allowedKeys = new Set([
    ...ITERABLE_QUERY_OPTION_KEYS,
    ...extraAllowedKeys,
    "fetch_size",
    "count_mode",
    "query_name",
  ]);
  const normalized = ToriiClient._normalizeIterableOptions(options, context, allowedKeys);
  if (normalized.fetch_size !== undefined && normalized.fetchSize === undefined) {
    normalized.fetchSize = normalized.fetch_size;
  }
  if (normalized.count_mode !== undefined && normalized.countMode === undefined) {
    normalized.countMode = normalized.count_mode;
  }
  if (normalized.query_name !== undefined && normalized.queryName === undefined) {
    normalized.queryName = normalized.query_name;
  }
  delete normalized.fetch_size;
  delete normalized.count_mode;
  delete normalized.query_name;
  const resolvedAllowedKeys = new Set([...ITERABLE_QUERY_OPTION_KEYS, ...extraAllowedKeys]);
  assertSupportedOptionKeys(normalized, resolvedAllowedKeys, context);
  return normalized;
}

function normalizeEventStreamOptions(
  options,
  context,
  allowedExtraKeys = [],
  allowLastEventId = true,
) {
  const { signal } = normalizeSignalOption(options, context);
  const normalized = options ?? {};
  const allowedKeys = new Set([
    "signal",
    ...(allowLastEventId ? ["lastEventId"] : []),
    ...allowedExtraKeys,
  ]);
  assertSupportedOptionKeys(normalized, allowedKeys, `${context} options`);
  let lastEventId;
  if (normalized.lastEventId !== undefined) {
    if (normalized.lastEventId === null) {
      rejectType(`${context}.lastEventId must be a non-empty string`);
    }
    lastEventId = requireNonEmptyString(
      normalized.lastEventId,
      `${context}.lastEventId`,
    ).trim();
  }
  return { signal, lastEventId };
}

function isAbortSignalLike(value) {
  if (typeof value !== JS_TYPE_OBJECT || value === null) return false;
  if (hasAbortSignalBrand(value)) return true;
  try {
    return (
      typeof signalIsAborted(value) === "boolean" &&
      ownDataMethod(value, "addEventListener") !== null &&
      ownDataMethod(value, "removeEventListener") !== null
    );
  } catch {
    return false;
  }
}

function normalizeAttachmentMetadataList(payload, context = "attachment list response") {
  if (!Array.isArray(payload)) {
    rejectType(`${context} must be an array`);
  }
  return payload.map((entry, index) =>
    normalizeAttachmentMetadataRecord(entry, `${context}[${index}]`),
  );
}

function normalizeAttachmentUploadPayload(value, context) {
  if (typeof value === JS_TYPE_STRING) {
    return Buffer.from(value, "utf8");
  }
  if (
    Buffer.isBuffer(value) ||
    ArrayBuffer.isView(value) ||
    value instanceof ArrayBuffer ||
    Array.isArray(value)
  ) {
    return toBuffer(value);
  }
  rejectType(`${context} must be a string or binary payload`);
}

function normalizeAttachmentMetadataRecord(value, context) {
  const record = ensureRecord(value, context);
  const id = requireNonEmptyString(record.id, `${context}.id`);
  const contentType = requireNonEmptyString(
    record.content_type,
    `${context}.content_type`,
  );
  const size = ToriiClient._normalizeUnsignedInteger(
    record.size,
    `${context}.size`,
    { allowZero: true },
  );
  const createdMs = ToriiClient._normalizeUnsignedInteger(
    record.created_ms,
    `${context}.created_ms`,
    { allowZero: true },
  );
  const tenant = optionalString(record.tenant, `${context}.tenant`);
  return {
    id,
    contentType,
    size,
    createdMs,
    tenant,
  };
}

const VERIFYING_KEY_LIST_OPTION_KEYS = new Set([
  "signal",
  "backend",
  "status",
  "nameContains",
  "limit",
  "offset",
  "order",
  "idsOnly",
]);
const VERIFYING_KEY_ITERATOR_OPTION_KEYS = new Set([
  ...VERIFYING_KEY_LIST_OPTION_KEYS,
  "pageSize",
  "maxItems",
]);

let verifyingKeyClientPromise;

function loadVerifyingKeyClient() {
  return (verifyingKeyClientPromise ??= import(VERIFYING_KEY_CLIENT_URL).then(
      (module) => {
        if (typeof module.createVerifyingKeyClient !== JS_TYPE_FUNCTION) {
          rejectType("invalid verifying-key module");
        }
        const client = module.createVerifyingKeyClient(
          VERIFYING_KEY_LIST_OPTION_KEYS,
          assertSupportedOptionKeys,
          decodeVerifyingKeyDraftBase64,
          ensureRecord,
          irohaPrehash,
          ToriiClient._normalizeAccountId,
          normalizeRequiredBase64Payload,
          normalizeSignalOption,
          ToriiClient._normalizeUnsignedInteger,
          rejectVerifyingKeyPrivateKeyFields,
          requireExactBoolean,
          requireExactNonEmptyString,
          requireNonEmptyString,
        );
        if (
          !Object.isFrozen(client) ||
          Object.keys(client).join(",") !==
            "backend,detail,draft,id,list,listQuery,name,register,signingContext,update"
        ) {
          rejectType("invalid verifying-key setup: expected frozen helper keys");
        }
        return client;
      },
    ));
}

function rejectVerifyingKeyPrivateKeyFields(record, context) {
  const fields = Object.keys(record).filter((key) =>
    VERIFYING_KEY_PRIVATE_KEY_FIELDS.has(key),
  );
  if (fields.length === 0) {
    return;
  }
  throw createValidationError(
    ValidationErrorCode.INVALID_OBJECT,
    `${context} does not accept private-key fields (${fields.join(", ")}); sign the returned transaction draft locally`,
    `${context}.private_key`,
  );
}

function decodeVerifyingKeyDraftBase64(
  value,
  context,
  { maxBytes = null, exactBytes = null, limitLabel = "payload" } = {},
) {
  if (typeof value !== JS_TYPE_STRING) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} must be exact standard-base64`,
      context,
    );
  }
  if (
    maxBytes !== null &&
    value.length > 4 * Math.ceil(maxBytes / 3)
  ) {
    rejectRange(`${context} exceeds the ${maxBytes}-byte ${limitLabel} limit`);
  }
  if (
    exactBytes !== null &&
    value.length !== 4 * Math.ceil(exactBytes / 3)
  ) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} must decode to exactly ${exactBytes} bytes`,
      context,
    );
  }
  if (!hasExactStandardBase64Shape(value)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} must be exact standard-base64`,
      context,
    );
  }
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const decodedLength = (value.length / 4) * 3 - padding;
  if (maxBytes !== null && decodedLength > maxBytes) {
    rejectRange(`${context} exceeds the ${maxBytes}-byte ${limitLabel} limit`);
  }
  if (exactBytes !== null && decodedLength !== exactBytes) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} must decode to exactly ${exactBytes} bytes`,
      context,
    );
  }
  const decoded = Buffer.from(value, "base64");
  if (
    decoded.length !== decodedLength ||
    decoded.toString("base64") !== value
  ) {
    throw createValidationError(
      ValidationErrorCode.INVALID_STRING,
      `${context} must be exact standard-base64`,
      context,
    );
  }
  return decoded;
}

function normalizeProverReportList(payload, filters, context) {
  if (payload == null) {
    return { kind: "reports", reports: [] };
  }
  if (!Array.isArray(payload)) {
    rejectType(`${context} must be an array`);
  }
  if (payload.length === 0) {
    return { kind: "reports", reports: [] };
  }
  const idsOnlyRequested = isTruthyFilter(filters, "ids_only");
  const messagesOnlyRequested = isTruthyFilter(filters, "messages_only");
  const first = payload[0];
  if (typeof first === JS_TYPE_STRING) {
    if (!idsOnlyRequested) {
      rejectError("Torii returned id-only prover report projection; pass { ids_only: true } to listProverReports to consume this payload");
    }
    payload.forEach((value, index) =>
      requireNonEmptyString(value, `${context}[${index}]`),
    );
    return { kind: "ids", ids: payload.slice() };
  }
  if (
    isPlainObject(first) &&
    Object.keys(first).every((key) => key === "id" || key === "error")
  ) {
    if (!messagesOnlyRequested) {
      rejectError("Torii returned message-only prover report projection; pass { messages_only: true } to listProverReports to consume this payload");
    }
    const messages = payload.map((entry, index) => {
      const record = ensureRecord(entry, `${context}[${index}]`);
      return {
        id: requireNonEmptyString(record.id, `${context}[${index}].id`),
        error:
          record.error === undefined || record.error === null
            ? null
            : requireNonEmptyString(record.error, `${context}[${index}].error`),
      };
    });
    return { kind: "messages", messages };
  }
  return {
    kind: "reports",
    reports: payload.map((entry, index) =>
      normalizeProverReportRecord(entry, `${context}[${index}]`),
    ),
  };
}

function normalizeProverReportRecord(value, context) {
  const record = ensureRecord(value, context);
  const id = requireNonEmptyString(record.id, `${context}.id`);
  const ok = requireBooleanLike(record.ok, `${context}.ok`);
  const error =
    record.error === undefined || record.error === null
      ? null
      : requireNonEmptyString(record.error, `${context}.error`);
  const contentType = requireNonEmptyString(
    record.content_type,
    `${context}.content_type`,
  );
  const size = ToriiClient._normalizeUnsignedInteger(record.size, `${context}.size`, {
    allowZero: true,
  });
  const createdMs = ToriiClient._normalizeUnsignedInteger(
    record.created_ms,
    `${context}.created_ms`,
    { allowZero: true },
  );
  const processedMs = ToriiClient._normalizeUnsignedInteger(
    record.processed_ms,
    `${context}.processed_ms`,
    { allowZero: true },
  );
  const latencyMs = ToriiClient._normalizeUnsignedInteger(
    record.latency_ms ?? 0,
    `${context}.latency_ms`,
    { allowZero: true },
  );
  const zkTags = record.zk1_tags;
  const normalizedTags =
    zkTags === undefined || zkTags === null
      ? null
      : parseStringArray(zkTags, `${context}.zk1_tags`);
  return {
    id,
    ok,
    error,
    content_type: contentType,
    size,
    created_ms: createdMs,
    processed_ms: processedMs,
    latency_ms: latencyMs,
    zk1_tags: normalizedTags,
  };
}

function normalizeSumeragiEvidenceListResponse(payload, limit, offset) {
  const record = ensureRecord(payload, "sumeragi evidence response");
  assertExactSumeragiEvidenceFields(record, "sumeragi evidence response", [
    "total",
    "items",
  ]);
  const rawItems = record.items;
  if (!Array.isArray(rawItems)) {
    rejectType("sumeragi evidence response.items must be an array");
  }
  const items = rawItems.map((item, index) =>
    normalizeSumeragiEvidenceRecord(item, `sumeragi evidence response.items[${index}]`),
  );
  if (items.length > limit) {
    rejectRange(`sumeragi evidence response.items must contain at most ${limit} records`);
  }
  const total = requireSumeragiEvidenceUnsigned(
    record.total,
    "sumeragi evidence response.total",
  );
  const totalInteger = BigInt(total);
  if (totalInteger < BigInt(items.length)) {
    rejectRange("sumeragi evidence response.total must cover the returned items");
  }
  if (
    items.length > 0
    && totalInteger < BigInt(offset) + BigInt(items.length)
  ) {
    rejectRange("sumeragi evidence response.total must cover offset plus returned items");
  }
  return { total, items };
}

function assertExactSumeragiEvidenceFields(record, context, fields) {
  const required = new Set(fields);
  const missing = fields.filter(
    (field) => !Object.prototype.hasOwnProperty.call(record, field),
  );
  const unexpected = Object.keys(record).filter((field) => !required.has(field));
  if (missing.length > 0 || unexpected.length > 0) {
    const details = [];
    if (missing.length > 0) details.push(`missing ${missing.join(", ")}`);
    if (unexpected.length > 0) details.push(`unexpected ${unexpected.join(", ")}`);
    rejectType(`${context} must use the exact server fields (${details.join("; ")})`);
  }
}

function requireSumeragiEvidenceUnsigned(value, context, maximum = MAX_UINT64_BIGINT) {
  let integer;
  if (
    typeof value === JS_TYPE_NUMBER
    && Number.isSafeInteger(value)
    && value >= 0
    && !Object.is(value, -0)
  ) {
    integer = BigInt(value);
  } else if (typeof value === JS_TYPE_BIGINT && value >= 0n) {
    integer = value;
  } else {
    rejectType(`${context} must be an unsigned JSON integer`);
  }
  const maximumInteger = typeof maximum === JS_TYPE_BIGINT ? maximum : BigInt(maximum);
  if (integer > maximumInteger) {
    rejectRange(`${context} must be at most ${maximumInteger}`);
  }
  return integer <= MAX_SAFE_INTEGER_BIGINT ? Number(integer) : integer;
}

function requireSumeragiEvidenceHash(value, context) {
  return requireExactLowerHex32String(value, context);
}

function normalizeSumeragiEvidencePenaltyStatus(value, context) {
  const record = ensureRecord(value, context);
  assertExactSumeragiEvidenceFields(record, context, ["status", "details"]);
  const status = requireExactNonEmptyString(record.status, `${context}.status`);
  if (status === "pending") {
    if (record.details !== null) {
      rejectType(`${context}.details must be null when status is pending`);
    }
    return { status, details: null };
  }
  if (status !== "applied") {
    rejectRange(`${context}.status must be pending or applied`);
  }
  const details = ensureRecord(record.details, `${context}.details`);
  assertExactSumeragiEvidenceFields(details, `${context}.details`, ["height"]);
  return {
    status,
    details: {
      height: requireSumeragiEvidenceUnsigned(
        details.height,
        `${context}.details.height`,
      ),
    },
  };
}

function normalizeSumeragiEvidenceRecord(value, context) {
  const record = ensureRecord(value, context);
  assertExactSumeragiEvidenceFields(record, context, EVIDENCE_RECORD_FIELDS);
  const kind = requireExactNonEmptyString(record.kind, `${context}.kind`);
  if (kind !== EVIDENCE_KIND) {
    rejectRange(`${context}.kind must be ${EVIDENCE_KIND}`);
  }
  const evidenceClass = requireExactNonEmptyString(record.class, `${context}.class`);
  if (!EVIDENCE_CLASS_VALUES.has(evidenceClass)) {
    rejectRange(`${context}.class must be one of ${Array.from(EVIDENCE_CLASS_VALUES).join(", ")}`);
  }
  // Different-view CommitQC conflicts establish a safety violation without attributing signers.
  const permitsUnattributedSafetyViolation =
    evidenceClass === "conflicting_certificates" && record.safety_violation === true;
  if (!Array.isArray(record.offenders) || record.offenders.length > 1024 ||
      (record.offenders.length === 0 && !permitsUnattributedSafetyViolation)) {
    rejectRange(`${context}.offenders must contain between 1 and 1024 entries, or be empty for a conflicting-certificate safety violation`);
  }
  let previousSigner = -1;
  const peers = new Set();
  const offenders = record.offenders.map((value, index) => {
    const offenderContext = `${context}.offenders[${index}]`;
    const offender = ensureRecord(value, offenderContext);
    assertExactSumeragiEvidenceFields(offender, offenderContext, ["signer", "peer_id"]);
    const signer = requireSumeragiEvidenceUnsigned(offender.signer, `${offenderContext}.signer`, 1023);
    if (signer <= previousSigner) {
      rejectRange(`${offenderContext}.signer must increase strictly`);
    }
    const peerId = requireExactNonEmptyString(offender.peer_id, `${offenderContext}.peer_id`);
    // Literal validation does not replace Core's historical signature verification.
    if (!/^ea0130[0-9A-F]{96}$/u.test(peerId)) {
      rejectType(`${offenderContext}.peer_id must be a canonical BLS-normal public key`);
    }
    if (peers.has(peerId)) {
      rejectRange(`${offenderContext}.peer_id must be unique`);
    }
    peers.add(peerId);
    previousSigner = signer;
    return { signer, peer_id: peerId };
  });
  return {
    kind,
    class: evidenceClass,
    instance: requireSumeragiEvidenceHash(record.instance, `${context}.instance`),
    height: requireSumeragiEvidenceUnsigned(record.height, `${context}.height`),
    epoch: requireSumeragiEvidenceUnsigned(record.epoch, `${context}.epoch`),
    context_id: requireSumeragiEvidenceHash(record.context_id, `${context}.context_id`),
    authority_generation: requireSumeragiEvidenceHash(record.authority_generation, `${context}.authority_generation`),
    offenders,
    safety_violation: requireExactBoolean(record.safety_violation, `${context}.safety_violation`),
    native_frame_hash: requireSumeragiEvidenceHash(record.native_frame_hash, `${context}.native_frame_hash`),
    recorded_height: requireSumeragiEvidenceUnsigned(
      record.recorded_height,
      `${context}.recorded_height`,
    ),
    recorded_view: requireSumeragiEvidenceUnsigned(
      record.recorded_view,
      `${context}.recorded_view`,
    ),
    recorded_ms: requireSumeragiEvidenceUnsigned(
      record.recorded_ms,
      `${context}.recorded_ms`,
    ),
    consensus_admitted_height: requireSumeragiEvidenceUnsigned(
      record.consensus_admitted_height,
      `${context}.consensus_admitted_height`,
    ),
    penalty_status: normalizeSumeragiEvidencePenaltyStatus(
      record.penalty_status,
      `${context}.penalty_status`,
    ),
  };
}

function rejectAliasField(record, context, aliasKey, canonicalKey) {
  if (Object.prototype.hasOwnProperty.call(record, aliasKey)) {
    rejectType(`${context}.${aliasKey} is not supported; use ${canonicalKey}`);
  }
}

function normalizeContractActivityListItem(value, context) {
  const record = ensureRecord(value, context);
  rejectAliasField(record, context, "entrypointHash", "entrypoint_hash");
  rejectAliasField(record, context, "resultOk", "result_ok");
  rejectAliasField(record, context, "timestampMs", "timestamp_ms");
  rejectAliasField(record, context, "contractAddress", "contract_address");
  rejectAliasField(record, context, "contractAlias", "contract_alias");
  rejectAliasField(record, context, "contractEntrypoint", "contract_entrypoint");
  rejectAliasField(record, context, "contractPayload", "contract_payload");
  rejectAliasField(record, context, "feePayment", "fee_payment");
  rejectRetiredFeeSelectionFields(record, context);
  const entrypointHash = requireNonEmptyString(
    record.entrypoint_hash,
    `${context}.entrypoint_hash`,
  );
  const resultOk = requireBooleanLike(record.result_ok, `${context}.result_ok`);
  const contractAddress = requireNonEmptyString(
    record.contract_address,
    `${context}.contract_address`,
  );
  let authorityValue = record.authority;
  if (authorityValue !== undefined && authorityValue !== null) {
    authorityValue = requireNonEmptyString(authorityValue, `${context}.authority`);
  }
  let timestampValue = record.timestamp_ms;
  if (timestampValue !== undefined && timestampValue !== null) {
    timestampValue = ToriiClient._normalizeUnsignedInteger(
      timestampValue,
      `${context}.timestamp_ms`,
      { allowZero: true },
    );
  } else {
    timestampValue = undefined;
  }
  const contractAlias =
    record.contract_alias === undefined || record.contract_alias === null
      ? undefined
      : requireNonEmptyString(record.contract_alias, `${context}.contract_alias`);
  const contractEntrypoint =
    record.contract_entrypoint === undefined || record.contract_entrypoint === null
      ? undefined
      : requireNonEmptyString(
          record.contract_entrypoint,
          `${context}.contract_entrypoint`,
        );
  const contractPayload =
    record.contract_payload === undefined
      ? undefined
      : cloneJsonValue(record.contract_payload, `${context}.contract_payload`);
  const feePayment =
    record.fee_payment === undefined || record.fee_payment === null
      ? undefined
      : normalizeFeePaymentIntentValue(record.fee_payment, `${context}.fee_payment`);
  const normalized = {
    ...record,
    entrypoint_hash: entrypointHash,
    result_ok: resultOk,
    contract_address: contractAddress,
  };
  if (authorityValue !== undefined) {
    normalized.authority = authorityValue;
  }
  if (timestampValue !== undefined) {
    normalized.timestamp_ms = timestampValue;
  } else {
    delete normalized.timestamp_ms;
  }
  if (contractAlias !== undefined) {
    normalized.contract_alias = contractAlias;
  }
  if (contractEntrypoint !== undefined) {
    normalized.contract_entrypoint = contractEntrypoint;
  }
  if (contractPayload !== undefined) {
    normalized.contract_payload = contractPayload;
  }
  if (feePayment !== undefined) {
    normalized.fee_payment = feePayment;
  } else {
    delete normalized.fee_payment;
  }
  return normalized;
}

function normalizeContractEventListItem(value, context) {
  const record = ensureRecord(value, context);
  rejectAliasField(record, context, "eventId", "event_id");
  rejectAliasField(record, context, "schemaVersion", "schema_version");
  rejectAliasField(record, context, "timestampMs", "timestamp_ms");
  rejectAliasField(record, context, "txHashHex", "tx_hash_hex");
  rejectAliasField(record, context, "blockHeight", "block_height");
  rejectAliasField(record, context, "blockHashHex", "block_hash_hex");
  rejectAliasField(record, context, "resultOk", "result_ok");
  rejectAliasField(record, context, "contractAddress", "contract_address");
  rejectAliasField(record, context, "contractAlias", "contract_alias");
  rejectAliasField(record, context, "eventKind", "event_kind");
  rejectAliasField(record, context, "assetIds", "asset_ids");
  rejectAliasField(record, context, "numericFields", "numeric_fields");
  rejectAliasField(record, context, "feePayment", "fee_payment");
  rejectRetiredFeeSelectionFields(record, context);
  const eventId = requireNonEmptyString(record.event_id, `${context}.event_id`);
  const schemaVersion = ToriiClient._normalizeUnsignedInteger(
    record.schema_version,
    `${context}.schema_version`,
    { allowZero: false },
  );
  const provenance = requireNonEmptyString(record.provenance, `${context}.provenance`);
  const txHashHex = requireCanonicalTransactionHashString(
    record.tx_hash_hex,
    `${context}.tx_hash_hex`,
  );
  const blockHeight = ToriiClient._normalizeUnsignedInteger(
    record.block_height,
    `${context}.block_height`,
    { allowZero: false },
  );
  const blockHashHex = requireNonEmptyString(
    record.block_hash_hex,
    `${context}.block_hash_hex`,
  );
  const resultOk = requireBooleanLike(record.result_ok, `${context}.result_ok`);
  const contractAddress = requireNonEmptyString(
    record.contract_address,
    `${context}.contract_address`,
  );
  const module = requireNonEmptyString(record.module, `${context}.module`);
  const eventKind = requireNonEmptyString(record.event_kind, `${context}.event_kind`);
  let authorityValue = record.authority;
  if (authorityValue !== undefined && authorityValue !== null) {
    authorityValue = requireNonEmptyString(authorityValue, `${context}.authority`);
  }
  let timestampValue = record.timestamp_ms;
  if (timestampValue !== undefined && timestampValue !== null) {
    timestampValue = ToriiClient._normalizeUnsignedInteger(
      timestampValue,
      `${context}.timestamp_ms`,
      { allowZero: true },
    );
  } else {
    timestampValue = undefined;
  }
  const contractAlias =
    record.contract_alias === undefined || record.contract_alias === null
      ? undefined
      : requireNonEmptyString(record.contract_alias, `${context}.contract_alias`);
  const participants =
    record.participants === undefined
      ? undefined
      : requireStringArray(record.participants, `${context}.participants`);
  const assetIds =
    record.asset_ids === undefined
      ? undefined
      : requireStringArray(record.asset_ids, `${context}.asset_ids`);
  const numericFields =
    record.numeric_fields === undefined
      ? undefined
      : cloneJsonValue(record.numeric_fields, `${context}.numeric_fields`);
  const payload =
    record.payload === undefined
      ? undefined
      : cloneJsonValue(record.payload, `${context}.payload`);
  const feePayment =
    record.fee_payment === undefined || record.fee_payment === null
      ? undefined
      : normalizeFeePaymentIntentValue(record.fee_payment, `${context}.fee_payment`);
  const normalized = {
    ...record,
    event_id: eventId,
    schema_version: schemaVersion,
    provenance,
    tx_hash_hex: txHashHex,
    block_height: blockHeight,
    block_hash_hex: blockHashHex,
    result_ok: resultOk,
    contract_address: contractAddress,
    module,
    event_kind: eventKind,
  };
  if (authorityValue !== undefined) {
    normalized.authority = authorityValue;
  }
  if (timestampValue !== undefined) {
    normalized.timestamp_ms = timestampValue;
  } else {
    delete normalized.timestamp_ms;
  }
  if (contractAlias !== undefined) {
    normalized.contract_alias = contractAlias;
  }
  if (participants !== undefined) {
    normalized.participants = participants;
  }
  if (assetIds !== undefined) {
    normalized.asset_ids = assetIds;
  }
  if (numericFields !== undefined) {
    normalized.numeric_fields = numericFields;
  }
  if (payload !== undefined) {
    normalized.payload = payload;
  }
  if (feePayment !== undefined) {
    normalized.fee_payment = feePayment;
  } else {
    delete normalized.fee_payment;
  }
  return normalized;
}

function normalizeAccountPermissionItem(value, context) {
  const record = ensureRecord(value, context);
  const name = requireNonEmptyString(record.name, `${context}.name`);
  return { ...record, name };
}

function normalizeTriggerUpsertPayload(input) {
  const record = ensureRecord(input, "registerTrigger payload");
  const payload = cloneJsonValue(record, "registerTrigger.payload");
  const id = requireNonEmptyString(
    record.id,
    "registerTrigger.id",
  );
  payload.id = id;
  delete payload.trigger_id;
  delete payload.triggerId;

  const actionValue =
    record.action ??
    record.payload ??
    record.definition ??
    record.trigger ??
    record.triggerDefinition ??
    payload.action;
  if (actionValue === undefined || actionValue === null) {
    rejectType("registerTrigger.action is required");
  }
  if (typeof actionValue === JS_TYPE_STRING) {
    const trimmed = actionValue.trim();
    if (trimmed.length === 0) {
      rejectType("registerTrigger.action must be a non-empty string when provided as base64");
    }
    try {
      const decoded = strictDecodeBase64(trimmed);
      payload.action = Buffer.from(decoded).toString("base64");
    } catch {
      rejectType("registerTrigger.action must be a valid base64 string");
    }
  } else if (!Array.isArray(actionValue) && typeof actionValue === JS_TYPE_OBJECT) {
    payload.action = cloneJsonValue(actionValue, "registerTrigger.action");
  } else {
    rejectType("registerTrigger.action must be an object or base64 string produced by Norito serialization");
  }
  delete payload.payload;
  delete payload.definition;
  delete payload.trigger;
  delete payload.triggerDefinition;

  if (payload.metadata === null || payload.metadata === undefined) {
    delete payload.metadata;
  } else if (
    typeof payload.metadata !== JS_TYPE_OBJECT ||
    Array.isArray(payload.metadata)
  ) {
    rejectType("registerTrigger.metadata must be an object when provided");
  }
  return payload;
}

function normalizeSubscriptionPlanCreateRequest(input) {
  const record = ensureRecord(input, "createSubscriptionPlan request");
  const credentials = normalizeSecretFreeAuthority(record, "createSubscriptionPlan");
  const planId = pickOverride(record, "plan_id", "planId");
  if (planId === undefined || planId === null) {
    rejectType("createSubscriptionPlan.planId is required");
  }
  const planValue = record.plan;
  if (planValue === undefined || planValue === null) {
    rejectType("createSubscriptionPlan.plan is required");
  }
  if (!isPlainObject(planValue)) {
    rejectType("createSubscriptionPlan.plan must be an object");
  }
  return {
    ...credentials,
    plan_id: ToriiClient._requireAssetDefinitionId(planId),
    plan: cloneJsonValue(planValue, "createSubscriptionPlan.plan"),
  };
}

function normalizeSubscriptionCreateRequest(input) {
  const record = ensureRecord(input, "createSubscription request");
  const credentials = normalizeSecretFreeAuthority(record, "createSubscription");
  const subscriptionId = pickOverride(record, "subscription_id", "subscriptionId");
  if (subscriptionId === undefined || subscriptionId === null) {
    rejectType("createSubscription.subscriptionId is required");
  }
  const planId = pickOverride(record, "plan_id", "planId");
  if (planId === undefined || planId === null) {
    rejectType("createSubscription.planId is required");
  }
  const payload = {
    ...credentials,
    subscription_id: requireNonEmptyString(subscriptionId, "createSubscription.subscriptionId"),
    plan_id: ToriiClient._requireAssetDefinitionId(planId),
  };
  const billingTriggerId = pickOverride(record, "billing_trigger_id", "billingTriggerId");
  if (billingTriggerId !== undefined && billingTriggerId !== null) {
    payload.billing_trigger_id = requireNonEmptyString(
      billingTriggerId,
      "createSubscription.billingTriggerId",
    );
  }
  const usageTriggerId = pickOverride(record, "usage_trigger_id", "usageTriggerId");
  if (usageTriggerId !== undefined && usageTriggerId !== null) {
    payload.usage_trigger_id = requireNonEmptyString(
      usageTriggerId,
      "createSubscription.usageTriggerId",
    );
  }
  const firstChargeMs = pickOverride(record, "first_charge_ms", "firstChargeMs");
  if (firstChargeMs !== undefined && firstChargeMs !== null) {
    payload.first_charge_ms = ToriiClient._normalizeUnsignedInteger(
      firstChargeMs,
      "createSubscription.firstChargeMs",
      { allowZero: true },
    );
  }
  const grantUsage = pickOverride(record, "grant_usage_to_provider", "grantUsageToProvider");
  if (grantUsage !== undefined && grantUsage !== null) {
    payload.grant_usage_to_provider = requireBooleanLike(
      grantUsage,
      "createSubscription.grantUsageToProvider",
    );
  }
  return payload;
}

function normalizeSubscriptionActionRequest(input, context) {
  const record = ensureRecord(input, `${context} request`);
  const credentials = normalizeSecretFreeAuthority(record, context);
  const payload = {
    ...credentials,
  };
  const chargeAt = pickOverride(record, "charge_at_ms", "chargeAtMs");
  if (chargeAt !== undefined && chargeAt !== null) {
    if (context !== "resumeSubscription" && context !== "chargeSubscriptionNow") {
      rejectType(`${context}.chargeAtMs is not accepted`);
    }
    payload.charge_at_ms = ToriiClient._normalizeUnsignedInteger(
      chargeAt,
      `${context}.chargeAtMs`,
      { allowZero: true },
    );
  }
  const cancelMode = pickOverride(record, "cancel_mode", "cancelMode");
  if (cancelMode !== undefined && cancelMode !== null) {
    if (context !== "cancelSubscription") {
      rejectType(`${context}.cancelMode is not accepted`);
    }
    const normalized = requireNonEmptyString(cancelMode, `${context}.cancelMode`).toLowerCase();
    if (normalized !== "immediate" && normalized !== "period_end") {
      rejectType(`${context}.cancelMode must be immediate or period_end`);
    }
    payload.cancel_mode = { mode: normalized, value: null };
  } else if (context === "cancelSubscription") {
    rejectType("cancelSubscription.cancelMode is required");
  }
  return payload;
}

function normalizeSubscriptionUsageRequest(input, context) {
  const record = ensureRecord(input, `${context} request`);
  const credentials = normalizeSecretFreeAuthority(record, context);
  const unitKey = pickOverride(record, "unit_key", "unitKey");
  if (unitKey === undefined || unitKey === null) {
    rejectType(`${context}.unitKey is required`);
  }
  const delta = record.delta;
  if (delta === undefined || delta === null) {
    rejectType(`${context}.delta is required`);
  }
  const payload = {
    ...credentials,
    unit_key: requireNonEmptyString(unitKey, `${context}.unitKey`),
    delta: normalizeQuantityInput(delta, `${context}.delta`),
  };
  const usageTriggerId = pickOverride(record, "usage_trigger_id", "usageTriggerId");
  if (usageTriggerId !== undefined && usageTriggerId !== null) {
    payload.usage_trigger_id = requireNonEmptyString(
      usageTriggerId,
      `${context}.usageTriggerId`,
    );
  }
  return payload;
}

function normalizeTriggerRecord(payload, context) {
  const record = ensureRecord(payload, context);
  const id = requireNonEmptyString(record.id, `${context}.id`);
  const action = ensureRecord(record.action ?? {}, `${context}.action`);
  let metadata = {};
  if (record.metadata !== undefined && record.metadata !== null) {
    metadata = ensureRecord(record.metadata, `${context}.metadata`);
  }
  return {
    id,
    action,
    metadata,
    raw: record,
  };
}

function normalizeTriggerListResponse(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const rawItems = record.items ?? [];
  if (!Array.isArray(rawItems)) {
    rejectType(`${context}.items must be an array`);
  }
  const items = rawItems.map((entry, index) =>
    normalizeTriggerRecord(entry, `${context}.items[${index}]`),
  );
  const totalValue =
    record.total === undefined || record.total === null
      ? items.length
      : ToriiClient._normalizeUnsignedInteger(record.total, `${context}.total`, {
          allowZero: true,
        });
  return {
    items,
    total: totalValue,
  };
}

const {
  normalizeSubscriptionActionResponse,
  normalizeSubscriptionCreateResponse,
  normalizeSubscriptionPlanCreateResponse,
  normalizeSubscriptionUsageDraft,
} = createSubscriptionResponseNormalizers({
  cloneJsonValue,
  ensureRecord,
  isPlainObject,
  normalizeAccountId: ToriiClient._normalizeAccountId,
  normalizeAppApiTransactionDraft,
  normalizeAssetDefinitionId: ToriiClient._requireAssetDefinitionId,
  normalizeUnsignedInteger: ToriiClient._normalizeUnsignedInteger,
  requireExactBoolean,
  requireExactLowerEvenHexString,
  requireExactNonEmptyString,
  requireNonEmptyString,
});

function normalizeSubscriptionRecord(value, context) {
  const record = ensureRecord(value, context);
  const subscriptionValue = record.subscription;
  if (subscriptionValue === undefined || subscriptionValue === null) {
    rejectType(`${context}.subscription is required`);
  }
  if (!isPlainObject(subscriptionValue)) {
    rejectType(`${context}.subscription must be an object`);
  }
  let invoiceValue = record.invoice;
  if (invoiceValue !== undefined && invoiceValue !== null && !isPlainObject(invoiceValue)) {
    rejectType(`${context}.invoice must be an object`);
  }
  let planValue = record.plan;
  if (planValue !== undefined && planValue !== null && !isPlainObject(planValue)) {
    rejectType(`${context}.plan must be an object`);
  }
  const normalized = {
    subscription_id: requireNonEmptyString(
      record.subscription_id,
      `${context}.subscription_id`,
    ),
    subscription: cloneJsonValue(subscriptionValue, `${context}.subscription`),
  };
  if (invoiceValue !== undefined) {
    normalized.invoice =
      invoiceValue === null ? null : cloneJsonValue(invoiceValue, `${context}.invoice`);
  }
  if (planValue !== undefined) {
    normalized.plan =
      planValue === null ? null : cloneJsonValue(planValue, `${context}.plan`);
  }
  return normalized;
}

function normalizeSubscriptionGetResponse(payload) {
  const record = ensureRecord(payload, "subscription get response");
  return normalizeSubscriptionRecord(record, "subscription get response");
}

function normalizeConnectSessionResponse(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const sid = normalizeConnectSid(record.sid, `${context}.sid`);
  const networkId = NetworkId.parse(
    requireNonEmptyString(record.network_id, `${context}.network_id`),
  );
  const appPk = requireNonEmptyString(record.app_pk, `${context}.app_pk`);
  const nonce = requireNonEmptyString(record.nonce, `${context}.nonce`);
  if (Buffer.from(appPk, "base64url").length !== 32 || Buffer.from(appPk, "base64url").toString("base64url") !== appPk) {
    rejectError(`${context}.app_pk must be canonical base64url for 32 bytes`);
  }
  if (Buffer.from(nonce, "base64url").length !== 16 || Buffer.from(nonce, "base64url").toString("base64url") !== nonce) {
    rejectError(`${context}.nonce must be canonical base64url for 16 bytes`);
  }
  const walletUri = requireNonEmptyString(
    record.wallet_uri,
    `${context}.wallet_uri`,
  );
  const appUri = requireNonEmptyString(
    record.app_uri,
    `${context}.app_uri`,
  );
  const tokenApp = requireNonEmptyString(
    record.token_app,
    `${context}.token_app`,
  );
  const tokenWallet = requireNonEmptyString(
    record.token_wallet,
    `${context}.token_wallet`,
  );
  const tokenManagement = requireNonEmptyString(
    record.token_management,
    `${context}.token_management`,
  );
  const tokenRelay = requireNonEmptyString(
    record.token_relay,
    `${context}.token_relay`,
  );
  const recognized = new Set([
    "sid",
    "network_id",
    "app_pk",
    "nonce",
    "wallet_uri",
    "app_uri",
    "token_app",
    "token_wallet",
    "token_management",
    "token_relay",
  ]);
  const extra = extractExtraFields(record, recognized);
  return {
    sid,
    network_id: networkId,
    app_pk: appPk,
    nonce,
    wallet_uri: walletUri,
    app_uri: appUri,
    token_app: tokenApp,
    token_wallet: tokenWallet,
    token_management: tokenManagement,
    token_relay: tokenRelay,
    extra,
    raw: record,
  };
}

function normalizeConnectAppRecord(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const normalizedId = requireNonEmptyString(
    record.app_id ?? record.appId,
    `${context}.app_id`,
  );
  const displayName = optionalString(
    record.display_name ?? record.displayName,
    `${context}.display_name`,
  );
  const description = optionalString(
    record.description,
    `${context}.description`,
  );
  const iconUrl = optionalString(
    record.icon_url ?? record.iconUrl,
    `${context}.icon_url`,
  );
  const namespaceSource = record.namespaces ?? [];
  const namespaces = parseStringArray(
    namespaceSource ?? [],
    `${context}.namespaces`,
  );
  const metadataRaw = record.metadata ?? {};
  const policyRaw = record.policy ?? {};
  const metadata = ToriiClient._requirePlainObject(
    metadataRaw,
    `${context}.metadata`,
  );
  const policy = ToriiClient._requirePlainObject(policyRaw, `${context}.policy`);
  const recognized = new Set([
    "app_id",
    "appId",
    "display_name",
    "displayName",
    "description",
    "icon_url",
    "iconUrl",
    "namespaces",
    "metadata",
    "policy",
  ]);
  const extra = extractExtraFields(record, recognized);
  return {
    appId: normalizedId,
    displayName,
    description,
    iconUrl,
    namespaces,
    metadata,
    policy,
    extra,
    raw: record,
  };
}

function normalizeConnectAppRegistryPage(payload) {
  const record = ensureRecord(payload ?? {}, "connect app registry response");
  const rawItems = record.items ?? [];
  if (!Array.isArray(rawItems)) {
    rejectType("connect app registry response.items must be an array");
  }
  const items = rawItems.map((entry, index) =>
    normalizeConnectAppRecord(entry, `connect app registry response.items[${index}]`),
  );
  let total = null;
  if (record.total !== undefined && record.total !== null) {
    total = ToriiClient._normalizeUnsignedInteger(
      record.total,
      "connect app registry response.total",
      { allowZero: true },
    );
  }
  let cursor = record.next_cursor ?? null;
  if (cursor !== null && cursor !== undefined) {
    cursor = requireNonEmptyString(cursor, "connect app registry response.next_cursor");
  } else {
    cursor = null;
  }
  const recognized = new Set(["items", "total", "next_cursor"]);
  const extra = extractExtraFields(record, recognized);
  return {
    items,
    total,
    nextCursor: cursor,
    extra,
    raw: record,
  };
}

function toConnectAppWritePayload(record, context) {
  const normalized = normalizeConnectAppRecord(record, context);
  const payload = {
    app_id: normalized.appId,
    namespaces: [...normalized.namespaces],
    metadata: { ...normalized.metadata },
    policy: { ...normalized.policy },
    ...normalized.extra,
  };
  if (normalized.displayName !== null) {
    payload.display_name = normalized.displayName;
  }
  if (normalized.description !== null) {
    payload.description = normalized.description;
  }
  if (normalized.iconUrl !== null) {
    payload.icon_url = normalized.iconUrl;
  }
  return payload;
}

function normalizeConnectAppPolicyControls(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const policyPayload =
    record.policy && typeof record.policy === JS_TYPE_OBJECT ? record.policy : record;
  const relayEnabled = optionalBoolean(
    policyPayload.relay_enabled ?? policyPayload.relayEnabled,
    `${context}.relay_enabled`,
  );
  const wsMaxSessions = coerceOptionalInt(
    policyPayload.ws_max_sessions ?? policyPayload.wsMaxSessions,
    `${context}.ws_max_sessions`,
  );
  const wsPerIpMaxSessions = coerceOptionalInt(
    policyPayload.ws_per_ip_max_sessions ?? policyPayload.wsPerIpMaxSessions,
    `${context}.ws_per_ip_max_sessions`,
  );
  const wsRatePerIpPerMin = coerceOptionalInt(
    policyPayload.ws_rate_per_ip_per_min ?? policyPayload.wsRatePerIpPerMin,
    `${context}.ws_rate_per_ip_per_min`,
  );
  const sessionTtlMs = coerceOptionalInt(
    policyPayload.session_ttl_ms ?? policyPayload.sessionTtlMs,
    `${context}.session_ttl_ms`,
  );
  const frameMaxBytes = coerceOptionalInt(
    policyPayload.frame_max_bytes ?? policyPayload.frameMaxBytes,
    `${context}.frame_max_bytes`,
  );
  const sessionBufferMaxBytes = coerceOptionalInt(
    policyPayload.session_buffer_max_bytes ?? policyPayload.sessionBufferMaxBytes,
    `${context}.session_buffer_max_bytes`,
  );
  const pingIntervalMs = coerceOptionalInt(
    policyPayload.ping_interval_ms ?? policyPayload.pingIntervalMs,
    `${context}.ping_interval_ms`,
  );
  const pingMissTolerance = coerceOptionalInt(
    policyPayload.ping_miss_tolerance ?? policyPayload.pingMissTolerance,
    `${context}.ping_miss_tolerance`,
  );
  const pingMinIntervalMs = coerceOptionalInt(
    policyPayload.ping_min_interval_ms ?? policyPayload.pingMinIntervalMs,
    `${context}.ping_min_interval_ms`,
  );
  const recognized = new Set([
    "relay_enabled",
    "relayEnabled",
    "ws_max_sessions",
    "wsMaxSessions",
    "ws_per_ip_max_sessions",
    "wsPerIpMaxSessions",
    "ws_rate_per_ip_per_min",
    "wsRatePerIpPerMin",
    "session_ttl_ms",
    "sessionTtlMs",
    "frame_max_bytes",
    "frameMaxBytes",
    "session_buffer_max_bytes",
    "sessionBufferMaxBytes",
    "ping_interval_ms",
    "pingIntervalMs",
    "ping_miss_tolerance",
    "pingMissTolerance",
    "ping_min_interval_ms",
    "pingMinIntervalMs",
  ]);
  const extra = extractExtraFields(policyPayload, recognized);
  return {
    relayEnabled,
    wsMaxSessions,
    wsPerIpMaxSessions,
    wsRatePerIpPerMin,
    sessionTtlMs,
    frameMaxBytes,
    sessionBufferMaxBytes,
    pingIntervalMs,
    pingMissTolerance,
    pingMinIntervalMs,
    extra,
    raw: policyPayload,
  };
}

function toConnectAppPolicyPayload(updates, context) {
  const normalized = normalizeConnectAppPolicyControls(updates, context);
  const payload = { ...normalized.extra };
  if (normalized.relayEnabled !== null) {
    payload.relay_enabled = normalized.relayEnabled;
  }
  if (normalized.wsMaxSessions !== null) {
    payload.ws_max_sessions = normalized.wsMaxSessions;
  }
  if (normalized.wsPerIpMaxSessions !== null) {
    payload.ws_per_ip_max_sessions = normalized.wsPerIpMaxSessions;
  }
  if (normalized.wsRatePerIpPerMin !== null) {
    payload.ws_rate_per_ip_per_min = normalized.wsRatePerIpPerMin;
  }
  if (normalized.sessionTtlMs !== null) {
    payload.session_ttl_ms = normalized.sessionTtlMs;
  }
  if (normalized.frameMaxBytes !== null) {
    payload.frame_max_bytes = normalized.frameMaxBytes;
  }
  if (normalized.sessionBufferMaxBytes !== null) {
    payload.session_buffer_max_bytes = normalized.sessionBufferMaxBytes;
  }
  if (normalized.pingIntervalMs !== null) {
    payload.ping_interval_ms = normalized.pingIntervalMs;
  }
  if (normalized.pingMissTolerance !== null) {
    payload.ping_miss_tolerance = normalized.pingMissTolerance;
  }
  if (normalized.pingMinIntervalMs !== null) {
    payload.ping_min_interval_ms = normalized.pingMinIntervalMs;
  }
  return payload;
}

function normalizeConnectAdmissionManifest(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const manifestRecord = isPlainObject(record.manifest) ? record.manifest : record;
  const rawEntries = manifestRecord.entries ?? [];
  if (!Array.isArray(rawEntries)) {
    rejectType(`${context}.entries must be an array`);
  }
  const entries = rawEntries.map((entry, index) =>
    normalizeConnectAdmissionManifestEntry(entry, `${context}.entries[${index}]`),
  );
  const version = coerceOptionalInt(
    manifestRecord.version,
    `${context}.version`,
  );
  const manifestHash = optionalString(
    manifestRecord.manifest_hash ?? manifestRecord.manifestHash,
    `${context}.manifest_hash`,
  );
  const updatedAt = optionalString(
    manifestRecord.updated_at ?? manifestRecord.updatedAt,
    `${context}.updated_at`,
  );
  const recognized = new Set([
    "entries",
    "version",
    "manifest_hash",
    "manifestHash",
    "updated_at",
    "updatedAt",
  ]);
  const extra = extractExtraFields(manifestRecord, recognized);
  return {
    version,
    entries,
    manifestHash,
    updatedAt,
    extra,
    raw: record,
  };
}

function normalizeConnectAdmissionManifestEntry(payload, context) {
  const record = ensureRecord(payload ?? {}, context);
  const appId = requireNonEmptyString(
    record.app_id ?? record.appId,
    `${context}.app_id`,
  );
  const namespaces = parseStringArray(record.namespaces ?? [], `${context}.namespaces`);
  const metadata = ToriiClient._requirePlainObject(
    record.metadata ?? {},
    `${context}.metadata`,
  );
  const policy = ToriiClient._requirePlainObject(record.policy ?? {}, `${context}.policy`);
  const recognized = new Set([
    "app_id",
    "appId",
    "namespaces",
    "metadata",
    "policy",
  ]);
  const extra = extractExtraFields(record, recognized);
  return {
    appId,
    namespaces,
    metadata,
    policy,
    extra,
    raw: record,
  };
}

function toConnectAdmissionManifestPayload(input, context) {
  const normalized = normalizeConnectAdmissionManifest(input, context);
  const payload = {
    entries: normalized.entries.map((entry) => ({
      app_id: entry.appId,
      namespaces: [...entry.namespaces],
      metadata: { ...entry.metadata },
      policy: { ...entry.policy },
      ...entry.extra,
    })),
    ...normalized.extra,
  };
  if (normalized.version !== null) {
    payload.version = normalized.version;
  }
  if (normalized.manifestHash !== null) {
    payload.manifest_hash = normalized.manifestHash;
  }
  if (normalized.updatedAt !== null) {
    payload.updated_at = normalized.updatedAt;
  }
  return payload;
}

function normalizeConnectStatusSnapshot(payload, context) {
  const record = ensureRecord(payload, context);
  const perIpRaw = Array.isArray(record.per_ip_sessions) ? record.per_ip_sessions : [];
  const perIpSessions = perIpRaw.map((entry, index) =>
    normalizeConnectPerIpSessions(entry, `${context}.per_ip_sessions[${index}]`),
  );
  let policy = null;
  if (record.policy !== undefined && record.policy !== null) {
    policy = normalizeConnectStatusPolicySnapshot(
      record.policy,
      `${context}.policy`,
    );
  }
  return {
    enabled: Boolean(record.enabled),
    sessionsTotal: coerceStatusInt(
      record.sessions_total,
      `${context}.sessions_total`,
    ),
    sessionsActive: coerceStatusInt(
      record.sessions_active,
      `${context}.sessions_active`,
    ),
    perIpSessions,
    bufferedSessions: coerceStatusInt(
      record.buffered_sessions,
      `${context}.buffered_sessions`,
    ),
    totalBufferBytes: coerceStatusInt(
      record.total_buffer_bytes,
      `${context}.total_buffer_bytes`,
    ),
    dedupeSize: coerceStatusInt(record.dedupe_size, `${context}.dedupe_size`),
    policy,
    framesInTotal: coerceStatusInt(
      record.frames_in_total,
      `${context}.frames_in_total`,
    ),
    framesOutTotal: coerceStatusInt(
      record.frames_out_total,
      `${context}.frames_out_total`,
    ),
    ciphertextTotal: coerceStatusInt(
      record.ciphertext_total,
      `${context}.ciphertext_total`,
    ),
    dedupeDropsTotal: coerceStatusInt(
      record.dedupe_drops_total,
      `${context}.dedupe_drops_total`,
    ),
    bufferDropsTotal: coerceStatusInt(
      record.buffer_drops_total,
      `${context}.buffer_drops_total`,
    ),
    plaintextControlDropsTotal: coerceStatusInt(
      record.plaintext_control_drops_total,
      `${context}.plaintext_control_drops_total`,
    ),
    monotonicDropsTotal: coerceStatusInt(
      record.monotonic_drops_total,
      `${context}.monotonic_drops_total`,
    ),
    sequenceViolationClosesTotal: coerceStatusInt(
      record.sequence_violation_closes_total,
      `${context}.sequence_violation_closes_total`,
    ),
    roleDirectionMismatchTotal: coerceStatusInt(
      record.role_direction_mismatch_total,
      `${context}.role_direction_mismatch_total`,
    ),
    pingMissTotal: coerceStatusInt(
      record.ping_miss_total,
      `${context}.ping_miss_total`,
    ),
    p2pRebroadcastsTotal: coerceStatusInt(
      record.p2p_rebroadcasts_total,
      `${context}.p2p_rebroadcasts_total`,
    ),
    p2pRebroadcastSkippedTotal: coerceStatusInt(
      record.p2p_rebroadcast_skipped_total,
      `${context}.p2p_rebroadcast_skipped_total`,
    ),
    p2pAuthFailuresTotal: coerceStatusInt(
      record.p2p_auth_failures_total,
      `${context}.p2p_auth_failures_total`,
    ),
    p2pTtlDropsTotal: coerceStatusInt(
      record.p2p_ttl_drops_total,
      `${context}.p2p_ttl_drops_total`,
    ),
    p2pUnknownSessionDropsTotal: coerceStatusInt(
      record.p2p_unknown_session_drops_total,
      `${context}.p2p_unknown_session_drops_total`,
    ),
    p2pSessionClaimsInTotal: coerceStatusInt(
      record.p2p_session_claims_in_total,
      `${context}.p2p_session_claims_in_total`,
    ),
    p2pSessionClaimsInstalledTotal: coerceStatusInt(
      record.p2p_session_claims_installed_total,
      `${context}.p2p_session_claims_installed_total`,
    ),
    p2pSessionClaimConflictsTotal: coerceStatusInt(
      record.p2p_session_claim_conflicts_total,
      `${context}.p2p_session_claim_conflicts_total`,
    ),
    p2pRoleConsumedTotal: coerceStatusInt(
      record.p2p_role_consumed_total,
      `${context}.p2p_role_consumed_total`,
    ),
    p2pSessionTerminatedTotal: coerceStatusInt(
      record.p2p_session_terminated_total,
      `${context}.p2p_session_terminated_total`,
    ),
  };
}

function normalizeConnectPerIpSessions(payload, context) {
  const record = ensureRecord(payload, context);
  const ip = requireNonEmptyString(
    record.ip,
    `${context}.ip`,
  );
  const sessions = ToriiClient._normalizeUnsignedInteger(
    record.sessions,
    `${context}.sessions`,
    { allowZero: true },
  );
  return { ip, sessions };
}

function normalizeConnectStatusPolicySnapshot(payload, context) {
  const record = ensureRecord(payload, context);
  return {
    wsMaxSessions: ToriiClient._normalizeUnsignedInteger(
      record.ws_max_sessions,
      `${context}.ws_max_sessions`,
      { allowZero: true },
    ),
    wsPerIpMaxSessions: ToriiClient._normalizeUnsignedInteger(
      record.ws_per_ip_max_sessions,
      `${context}.ws_per_ip_max_sessions`,
      { allowZero: true },
    ),
    wsRatePerIpPerMin: ToriiClient._normalizeUnsignedInteger(
      record.ws_rate_per_ip_per_min,
      `${context}.ws_rate_per_ip_per_min`,
      { allowZero: true },
    ),
    sessionTtlMs: ToriiClient._normalizeUnsignedInteger(
      record.session_ttl_ms,
      `${context}.session_ttl_ms`,
      { allowZero: true },
    ),
    frameMaxBytes: ToriiClient._normalizeUnsignedInteger(
      record.frame_max_bytes,
      `${context}.frame_max_bytes`,
      { allowZero: true },
    ),
    sessionBufferMaxBytes: ToriiClient._normalizeUnsignedInteger(
      record.session_buffer_max_bytes,
      `${context}.session_buffer_max_bytes`,
      { allowZero: true },
    ),
    relayEnabled: requireBooleanLike(
      record.relay_enabled,
      `${context}.relay_enabled`,
    ),
    relayStrategy: requireNonEmptyString(
      record.relay_strategy,
      `${context}.relay_strategy`,
    ),
    relayEffectiveStrategy: requireNonEmptyString(
      record.relay_effective_strategy,
      `${context}.relay_effective_strategy`,
    ),
    relayP2pAttached: requireBooleanLike(
      record.relay_p2p_attached,
      `${context}.relay_p2p_attached`,
    ),
    p2pTtlHops: ToriiClient._normalizeUnsignedInteger(
      record.p2p_ttl_hops,
      `${context}.p2p_ttl_hops`,
      { allowZero: true },
    ),
    heartbeatIntervalMs: ToriiClient._normalizeUnsignedInteger(
      record.heartbeat_interval_ms,
      `${context}.heartbeat_interval_ms`,
      { allowZero: true },
    ),
    heartbeatMissTolerance: ToriiClient._normalizeUnsignedInteger(
      record.heartbeat_miss_tolerance,
      `${context}.heartbeat_miss_tolerance`,
      { allowZero: true },
    ),
    heartbeatMinIntervalMs: ToriiClient._normalizeUnsignedInteger(
      record.heartbeat_min_interval_ms,
      `${context}.heartbeat_min_interval_ms`,
      { allowZero: true },
    ),
  };
}

const DEFAULT_SORAFS_ORDERBOOK_EVENTS_WS_PATH = "/v1/sorafs/orderbook/events/ws";
const DEFAULT_CONNECT_WS_PATH = "/v1/connect/ws";

function buildSorafsOrderbookEventsWebSocketUrlInternal(baseUrl, options, context) {
  const resolvedBase = requireNonEmptyString(baseUrl, `${context}.baseUrl`);
  const baseParsed = new URL(resolvedBase);
  const params =
    options === undefined
      ? {}
      : requirePlainObjectOption(options, `${context} options`, {
          message: "must be an object",
        });
  assertSupportedOptionKeys(
    params,
    SORAFS_ORDERBOOK_WEBSOCKET_OPTION_KEYS,
    `${context} options`,
  );
  const endpointPath = params.endpointPath ?? DEFAULT_SORAFS_ORDERBOOK_EVENTS_WS_PATH;
  const baseWithSlash = resolvedBase.endsWith("/") ? resolvedBase : `${resolvedBase}/`;
  const endpoint = isAbsoluteUrl(endpointPath)
    ? new URL(endpointPath)
    : resolveBaseRelativeUrl(baseWithSlash, endpointPath);
  if (endpoint.host !== baseParsed.host) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}: endpointPath host ${endpoint.host} must match baseUrl host ${baseParsed.host}.`,
      `${context}.endpointPath`,
    );
  }
  endpoint.protocol = mapHttpProtocolToWebSocket(endpoint.protocol, context);
  endpoint.search = "";
  const query = buildSorafsOrderbookEventsParams(params, context) ?? {};
  for (const [key, value] of Object.entries(query)) {
    endpoint.searchParams.set(key, String(value));
  }
  return endpoint.toString();
}

function openSorafsOrderbookEventsWebSocketInternal(options, context) {
  const normalizedOptions = requirePlainObjectOption(options, `${context} options`, {
    message: "must be an object",
  });
  assertSupportedOptionKeys(
    normalizedOptions,
    new Set(["baseUrl", ...SORAFS_ORDERBOOK_WEBSOCKET_DIAL_OPTION_KEYS]),
    `${context} options`,
  );
  const { baseUrl, protocols, websocketOptions, WebSocketImpl, ...urlOptions } = normalizedOptions;
  const url = buildSorafsOrderbookEventsWebSocketUrlInternal(baseUrl, urlOptions, context);
  const WebSocketClass = resolveWebSocketImplementation(WebSocketImpl, context);
  const resolvedOptions =
    websocketOptions === undefined || websocketOptions === null ? undefined : { ...websocketOptions };
  if (resolvedOptions !== undefined) {
    if (protocols !== undefined) {
      return new WebSocketClass(url, protocols, resolvedOptions);
    }
    return new WebSocketClass(url, resolvedOptions);
  }
  if (protocols !== undefined) {
    return new WebSocketClass(url, protocols);
  }
  return new WebSocketClass(url);
}

async function* streamWebSocketJsonEvents(socket, options = {}) {
  const context = options.context ?? "streamWebSocketJsonEvents";
  const closeOnReturn = options.closeOnReturn !== false;
  const queue = [];
  let wake = null;
  let closed = false;
  let failure = null;

  const notify = () => {
    if (wake) {
      const resolve = wake;
      wake = null;
      resolve();
    }
  };
  const enqueue = (item) => {
    queue.push(item);
    notify();
  };
  const onMessage = (...args) => {
    enqueue({ type: "message", data: extractWebSocketMessageData(args) });
  };
  const onError = (event) => {
    failure = websocketErrorFromEvent(event, context);
    closed = true;
    notify();
  };
  const onClose = () => {
    closed = true;
    notify();
  };
  const onAbort = () => {
    failure = new Error(`${context}: aborted`);
    closed = true;
    closeWebSocketQuietly(socket);
    notify();
  };
  const removers = [
    addWebSocketListener(socket, "message", onMessage, context),
    addWebSocketListener(socket, "error", onError, context),
    addWebSocketListener(socket, "close", onClose, context),
  ];
  const { signal } = options;
  if (signal) {
    if (signalIsAborted(signal)) {
      onAbort();
    } else {
      addSignalAbortListener(signal, onAbort);
      if (signalIsAborted(signal)) onAbort();
    }
  }

  try {
    for (;;) {
      if (queue.length > 0) {
        const item = queue.shift();
        const text = await decodeWebSocketMessageText(item.data, context);
        yield parseWebSocketJsonEventFrame(text, context);
        continue;
      }
      if (failure) {
        throw failure;
      }
      if (closed) {
        break;
      }
      await new Promise((resolve) => {
        wake = resolve;
      });
    }
  } finally {
    for (const remove of removers) {
      remove();
    }
    if (signal) {
      removeSignalAbortListener(signal, onAbort);
    }
    if (closeOnReturn && !closed) {
      closeWebSocketQuietly(socket);
    }
  }
}

function addWebSocketListener(socket, eventName, listener, context) {
  if (socket && typeof socket.addEventListener === JS_TYPE_FUNCTION) {
    socket.addEventListener(eventName, listener);
    return () => socket.removeEventListener?.(eventName, listener);
  }
  if (socket && typeof socket.on === JS_TYPE_FUNCTION) {
    socket.on(eventName, listener);
    return () => {
      if (typeof socket.off === JS_TYPE_FUNCTION) {
        socket.off(eventName, listener);
      } else if (typeof socket.removeListener === JS_TYPE_FUNCTION) {
        socket.removeListener(eventName, listener);
      }
    };
  }
  rejectError(`${context}: WebSocket implementation must support addEventListener or on`);
}

function extractWebSocketMessageData(args) {
  const first = args[0];
  if (
    args.length === 1 &&
    first &&
    typeof first === JS_TYPE_OBJECT &&
    Object.prototype.hasOwnProperty.call(first, "data")
  ) {
    return first.data;
  }
  return first;
}

async function decodeWebSocketMessageText(data, context) {
  if (typeof data === JS_TYPE_STRING) {
    return data;
  }
  if (data instanceof ArrayBuffer) {
    return new TextDecoder().decode(new Uint8Array(data));
  }
  if (ArrayBuffer.isView(data)) {
    return new TextDecoder().decode(data);
  }
  if (data && typeof data.text === JS_TYPE_FUNCTION) {
    return data.text();
  }
  rejectType(`${context}: WebSocket message must be text or bytes`);
}

function parseWebSocketJsonEventFrame(text, context) {
  let payload;
  try {
    payload = JSON.parse(text);
  } catch (error) {
    rejectError(`${context}: WebSocket frame is not valid JSON: ${error.message}`);
  }
  const record = ensureRecord(payload, `${context} frame`);
  const event =
    record.event === undefined || record.event === null
      ? null
      : requireNonEmptyString(record.event, `${context}.event`);
  return {
    event,
    data: record.data === undefined ? "" : record.data,
    raw: text,
  };
}

function websocketErrorFromEvent(event, context) {
  if (event instanceof Error) {
    return event;
  }
  if (event?.error instanceof Error) {
    return event.error;
  }
  return new Error(`${context}: WebSocket stream failed`);
}

function closeWebSocketQuietly(socket) {
  if (socket && typeof socket.close === JS_TYPE_FUNCTION) {
    try {
      socket.close();
    } catch {
      // Best effort cleanup for caller-owned WebSocket implementations.
    }
  }
}

function buildConnectWebSocketDescriptor(baseUrl, options, context) {
  const resolvedBase = requireNonEmptyString(baseUrl, `${context}.baseUrl`);
  const baseParsed = new URL(resolvedBase);
  const baseHost = baseParsed.host;
  const baseWebSocketProtocol = mapHttpProtocolToWebSocket(baseParsed.protocol, context);
  const baseHasTokenQuery = baseParsed.searchParams.has("token");
  const params =
    options === undefined
      ? {}
      : requirePlainObjectOption(options, `${context} options`, {
          message: "must be an object",
        });
  const normalizedSid = normalizeConnectSid(params.sid, `${context}.sid`);
  const normalizedRole = normalizeConnectRole(params.role, `${context}.role`);
  const token = requireNonEmptyString(params.token, `${context}.token`);
  const endpointPath = params.endpointPath ?? DEFAULT_CONNECT_WS_PATH;
  const baseWithSlash = resolvedBase.endsWith("/") ? resolvedBase : `${resolvedBase}/`;
  const endpoint = isAbsoluteUrl(endpointPath)
    ? new URL(endpointPath)
    : resolveBaseRelativeUrl(baseWithSlash, endpointPath);
  const endpointHost = endpoint.host;
  const endpointProtocol = mapHttpProtocolToWebSocket(endpoint.protocol, context);
  if (endpointHost !== baseHost) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}: endpointPath host ${endpointHost} must match baseUrl host ${baseHost} when credentials are attached.`,
      `${context}.endpointPath`,
    );
  }
  if (endpointProtocol !== baseWebSocketProtocol) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}: endpointPath protocol must match baseUrl protocol (${baseWebSocketProtocol.replace(":", "")}) when credentials are attached.`,
      `${context}.endpointPath`,
    );
  }
  const hadQueryToken = endpoint.searchParams.has("token");
  endpoint.search = "";
  endpoint.protocol = endpointProtocol;
  const allowInsecure =
    params.allowInsecure ??
    (params.config &&
      typeof params.config === JS_TYPE_OBJECT &&
      params.config.allowInsecure) ??
    false;
  requireExactBoolean(allowInsecure, `${context}.allowInsecure`);
  if (!allowInsecure && !isSecureProtocol(endpoint.protocol)) {
    rejectError(`${context}: refusing insecure WebSocket protocol ${endpoint.protocol}; pass allowInsecure: true for local/dev use only.`);
  }
  if (hadQueryToken) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}: query parameter token is forbidden; send the token via Authorization or Sec-WebSocket-Protocol instead.`,
      `${context}.token`,
    );
  }
  if (baseHasTokenQuery) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${context}: baseUrl must not include token query parameters; send the token via Authorization or Sec-WebSocket-Protocol instead.`,
      `${context}.token`,
    );
  }
  endpoint.searchParams.set("sid", normalizedSid);
  endpoint.searchParams.set("role", normalizedRole);
  return {
    url: endpoint.toString(),
    token,
    role: normalizedRole,
    sid: normalizedSid,
    allowInsecure,
  };
}

function buildConnectWebSocketUrlInternal(baseUrl, options, context) {
  return buildConnectWebSocketDescriptor(baseUrl, options, context).url;
}

function openConnectWebSocketInternal(options, context) {
  const normalizedOptions = requirePlainObjectOption(options, `${context} options`, {
    message: "must be an object",
  });
  const { baseUrl, protocols, websocketOptions, WebSocketImpl } = normalizedOptions;
  const { url, token, allowInsecure } = buildConnectWebSocketDescriptor(
    baseUrl,
    normalizedOptions,
    context,
  );
  const parsedBaseUrl = new URL(baseUrl);
  const parsedUrl = new URL(url);
  const pathIsAbsolute = isAbsoluteUrl(normalizedOptions.endpointPath);
  const originMatches =
    parsedUrl.host === parsedBaseUrl.host &&
    parsedUrl.protocol === mapHttpProtocolToWebSocket(parsedBaseUrl.protocol, context);
  emitConnectInsecureTelemetry(
    normalizedOptions.insecureTransportTelemetryHook,
    {
      client: "connect-ws",
      method: "GET",
      url: parsedUrl.toString(),
      baseUrl: parsedBaseUrl.toString(),
      host: parsedUrl.host,
      protocol: parsedUrl.protocol,
      pathIsAbsolute,
      originMatches,
      allowInsecure,
      hasCredentials: Boolean(token),
    },
  );
  const WebSocketClass = resolveWebSocketImplementation(WebSocketImpl, context);
  const supportsHeaders = !isLikelyBrowserWebSocket(WebSocketClass);
  const resolvedOptions =
    websocketOptions === undefined || websocketOptions === null ? {} : { ...websocketOptions };
  const headerContainer =
    resolvedOptions.headers && typeof resolvedOptions.headers === JS_TYPE_OBJECT
      ? { ...resolvedOptions.headers }
      : {};
  if (token && supportsHeaders) {
    if (!hasHeader(headerContainer, "authorization")) {
      headerContainer.Authorization = `Bearer ${token}`;
    }
  }
  const finalProtocols = supportsHeaders
    ? protocols
    : attachProtocolToken(protocols, buildConnectProtocolToken(token), context);
  if (Object.keys(headerContainer).length > 0) {
    resolvedOptions.headers = headerContainer;
  } else if (!websocketOptions) {
    delete resolvedOptions.headers;
  }
  const shouldPassOptions =
    websocketOptions !== undefined || Object.keys(headerContainer).length > 0;
  if (shouldPassOptions) {
    if (finalProtocols !== undefined) {
      return new WebSocketClass(url, finalProtocols, resolvedOptions);
    }
    return new WebSocketClass(url, resolvedOptions);
  }
  if (finalProtocols !== undefined) {
    return new WebSocketClass(url, finalProtocols);
  }
  return new WebSocketClass(url);
}

function emitConnectInsecureTelemetry(hook, event) {
  if (typeof hook !== JS_TYPE_FUNCTION) {
    return;
  }
  if (!event.allowInsecure || !event.hasCredentials || isSecureProtocol(event.protocol)) {
    return;
  }
  try {
    hook({ ...event, timestampMs: Date.now() });
  } catch {
    // No-op: telemetry hooks must never break Connect websockets.
  }
}

function normalizeConnectRole(value, name) {
  const normalized = requireNonEmptyString(value, name).trim().toLowerCase();
  if (normalized === "app" || normalized === "wallet") {
    return normalized;
  }
  rejectType(`${name} must be either "app" or "wallet"`);
}

function mapHttpProtocolToWebSocket(protocol, context) {
  switch (protocol) {
    case "http:":
      return "ws:";
    case "https:":
      return "wss:";
    case "ws:":
    case "wss:":
      return protocol;
    default:
      rejectError(`${context}: unsupported protocol "${protocol}" for Connect WebSocket`);
  }
}

function buildConnectProtocolToken(token) {
  return `iroha-connect.token.v1.${encodeBase64Url(token)}`;
}

function attachProtocolToken(protocols, tokenProtocol, context) {
  if (protocols === undefined || protocols === null) {
    return [tokenProtocol];
  }
  if (typeof protocols === JS_TYPE_STRING) {
    return protocols === tokenProtocol ? protocols : [tokenProtocol, protocols];
  }
  if (Array.isArray(protocols)) {
    if (protocols.includes(tokenProtocol)) {
      return [...protocols];
    }
    return [tokenProtocol, ...protocols];
  }
  throw createValidationError(
    ValidationErrorCode.INVALID_OBJECT,
    `${context}.protocols must be a string or array when header authentication is unavailable`,
    `${context}.protocols`,
  );
}

function encodeBase64Url(value) {
  const raw = Buffer.from(String(value), "utf8").toString("base64");
  return raw.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function resolveWebSocketImplementation(candidate, context) {
  const impl = candidate ?? globalThis.WebSocket;
  if (typeof impl !== JS_TYPE_FUNCTION) {
    rejectError(`${context}: WebSocket implementation is required`);
  }
  return impl;
}

function isLikelyBrowserWebSocket(impl) {
  const browserWebSocket =
    typeof globalThis !== "undefined" &&
    globalThis.window &&
    typeof globalThis.window.WebSocket !== "undefined"
      ? globalThis.window.WebSocket
      : null;
  if (!browserWebSocket) {
    return false;
  }
  return impl === browserWebSocket;
}

function decodeVarintBuffer(buffer, startIndex, context) {
  let value = 0n;
  let shift = 0n;
  let index = startIndex;
  while (index < buffer.length) {
    const byte = BigInt(buffer[index]);
    value |= (byte & 0x7fn) << shift;
    index += 1;
    if ((byte & 0x80n) === 0n) {
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        rejectError(`${context} contains an oversized multihash varint`);
      }
      return { value: Number(value), nextIndex: index };
    }
    shift += 7n;
    if (shift > 63n) {
      rejectError(`${context} contains an invalid multihash varint`);
    }
  }
  rejectError(`${context} contains a truncated multihash varint`);
}

function decodeIdentifierReceiptPublicKey(value, context) {
  const literal = requireNonEmptyString(value, context).trim();
  let prefixedAlgorithm = null;
  let multihashLiteral = literal;
  const separator = literal.indexOf(":");
  if (separator > 0) {
    prefixedAlgorithm = literal.slice(0, separator).trim().toLowerCase();
    multihashLiteral = literal.slice(separator + 1);
  }
  const canonical = canonicalizeMultihashHex(multihashLiteral, context);
  const bytes = Buffer.from(canonical, "hex");
  const functionCode = decodeVarintBuffer(bytes, 0, context);
  const digestLength = decodeVarintBuffer(bytes, functionCode.nextIndex, context);
  const payload = bytes.subarray(digestLength.nextIndex);
  if (payload.length !== digestLength.value) {
    rejectError(`${context} multihash payload length does not match its digest header`);
  }
  const entry = getCurveEntryByPublicKeyMulticodec(functionCode.value);
  if (!entry) {
    rejectError(`${context} uses unsupported multihash code 0x${functionCode.value.toString(16)}`);
  }
  const algorithm = entry.algorithm;
  if (
    prefixedAlgorithm &&
    prefixedAlgorithm !== algorithm &&
    !(prefixedAlgorithm === "mldsa" && algorithm === "ml-dsa")
  ) {
    rejectError(`${context} algorithm prefix does not match the multihash payload`);
  }
  return { algorithm, publicKey: payload };
}

function irohaPrehash(messageBytes) {
  const digest = Buffer.from(blake2b256(messageBytes));
  digest[digest.length - 1] |= 1;
  return digest;
}

function identifierCanonicalU32(value) {
  const buffer = Buffer.allocUnsafe(4);
  buffer.writeUInt32LE(value, 0);
  return buffer;
}

function identifierNormalizeUnsignedBigInt(value, context) {
  if (typeof value === JS_TYPE_BIGINT) {
    if (value < 0n) {
      throw createValidationError(
        ValidationErrorCode.INVALID_NUMERIC,
        `${context} must be a non-negative integer`,
        context,
      );
    }
    return value;
  }
  if (typeof value === JS_TYPE_NUMBER) {
    if (!Number.isInteger(value) || value < 0 || !Number.isSafeInteger(value)) {
      throw createValidationError(
        ValidationErrorCode.INVALID_NUMERIC,
        `${context} must be a non-negative safe integer`,
        context,
      );
    }
    return BigInt(value);
  }
  if (typeof value === JS_TYPE_STRING && /^[0-9]+$/.test(value)) {
    return BigInt(value);
  }
  throw createValidationError(
    ValidationErrorCode.INVALID_NUMERIC,
    `${context} must be a non-negative integer`,
    context,
  );
}

function identifierCanonicalU64(value, context) {
  const bigint = identifierNormalizeUnsignedBigInt(value, context);
  if (bigint > UINT64_MASK) {
    throw createValidationError(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${context} must fit in u64`,
      context,
    );
  }
  const buffer = Buffer.allocUnsafe(8);
  buffer.writeBigUInt64LE(bigint, 0);
  return buffer;
}

function identifierCanonicalCompactLength(value) {
  let remaining = BigInt(value);
  const bytes = [];
  while (remaining >= 0x80n) {
    bytes.push(Number((remaining & 0x7fn) | 0x80n));
    remaining >>= 7n;
  }
  bytes.push(Number(remaining));
  return Buffer.from(bytes);
}

function identifierCanonicalSizedField(payload) {
  const bytes = Buffer.from(payload);
  return Buffer.concat([identifierCanonicalCompactLength(bytes.length), bytes]);
}

function identifierCanonicalString(value, context) {
  return Buffer.concat([
    identifierCanonicalCompactLength(Buffer.byteLength(requireNonEmptyString(value, context))),
    Buffer.from(requireNonEmptyString(value, context), "utf8"),
  ]);
}

function identifierCanonicalExactString(value, context) {
  const literal = requireExactNonEmptyString(value, context);
  return Buffer.concat([
    identifierCanonicalCompactLength(Buffer.byteLength(literal)),
    Buffer.from(literal, "utf8"),
  ]);
}

function identifierCanonicalByteVec(bytes) {
  const payload = Buffer.from(bytes);
  const parts = [identifierCanonicalU64(payload.length, "byteVec.length")];
  for (const byte of payload) {
    parts.push(identifierCanonicalCompactLength(1), Buffer.from([byte]));
  }
  return Buffer.concat(parts);
}

function identifierCanonicalRawByteVec(bytes) {
  const payload = Buffer.from(bytes);
  return Buffer.concat([
    identifierCanonicalU64(payload.length, "rawByteVec.length"),
    payload,
  ]);
}

function identifierCanonicalOptionalU64(value, context) {
  if (value === null || value === undefined) {
    return Buffer.from([0]);
  }
  return Buffer.concat([
    Buffer.from([1]),
    identifierCanonicalSizedField(identifierCanonicalU64(value, context)),
  ]);
}

function identifierPolicyIdPayload(raw) {
  const value = requireIdentifierPolicyId(raw, "payload.policy_id");
  const parts = value.split("#", 2);
  return Buffer.concat([
    identifierCanonicalSizedField(identifierCanonicalString(parts[0], "payload.policy_id.kind")),
    identifierCanonicalSizedField(identifierCanonicalString(parts[1], "payload.policy_id.rule")),
  ]);
}

function identifierProgramIdPayload(raw, field) {
  return identifierCanonicalSizedField(
    identifierCanonicalExactString(raw, field),
  );
}

function identifierBackendTag(raw) {
  const tag = requireExactRamLfeBackend(raw, "payload.execution.backend");
  switch (tag) {
    case "hkdf-sha3-512-prf-v1":
      return 0;
    case "bfv-affine-v1":
      return 1;
    case "bfv-programmed-v1":
      return 2;
    default:
      rejectError(`unsupported RAM-LFE backend: ${raw}`);
  }
}

function identifierVerificationModeTag(raw) {
  const tag = requireExactRamLfeVerificationMode(raw, "payload.execution.verification_mode");
  switch (tag) {
    case "signed":
      return 0;
    case "proof":
      return 1;
    default:
      rejectError(`unsupported RAM-LFE verification mode: ${raw}`);
  }
}

function identifierHashBytes(raw, field) {
  const literal = requireExactNonEmptyString(raw, field);
  let body = literal;
  if (body.toLowerCase().startsWith("hash:")) {
    body = body.slice("hash:".length);
  }
  const suffixIndex = body.indexOf("#");
  if (suffixIndex >= 0) {
    body = body.slice(0, suffixIndex);
  }
  const hex =
    body.startsWith("0x") || body.startsWith("0X")
      ? body.slice(2)
      : body;
  if (hex.length !== 64 || !/^[0-9a-fA-F]{64}$/u.test(hex)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      `${field} must be a 32-byte hex string`,
      field,
    );
  }
  return Buffer.from(hex, "hex");
}

function identifierPrefixedHashBytes(raw, prefix, field) {
  const literal = requireExactNonEmptyString(raw, field);
  const body = literal.toLowerCase().startsWith(prefix) ? literal.slice(prefix.length) : literal;
  return identifierHashBytes(body, field);
}

function identifierOpaqueHashPayload(raw, prefix, field) {
  const hash = identifierPrefixedHashBytes(raw, prefix, field);
  return Buffer.concat([identifierCanonicalCompactLength(hash.length), hash]);
}

function identifierAlgorithmTagForCurveId(curve, context) {
  switch (curveIdToAlgorithm(curve)) {
    case "ed25519":
      return 0;
    case "secp256k1":
      return 1;
    case "bls_normal":
      return 2;
    case "bls_small":
      return 3;
    case "ml-dsa":
      return 4;
    case "gost3410-2012-256-paramset-a":
      return 5;
    case "gost3410-2012-256-paramset-b":
      return 6;
    case "gost3410-2012-256-paramset-c":
      return 7;
    case "gost3410-2012-512-paramset-a":
      return 8;
    case "gost3410-2012-512-paramset-b":
      return 9;
    case "sm2":
      return 10;
    default:
      rejectError(`${context} uses unsupported public-key curve ${curve}`);
  }
}

function identifierCanonicalConstVecU8(bytes) {
  const payload = Buffer.from(bytes);
  const parts = [identifierCanonicalU64(payload.length, "ConstVec<u8>.length")];
  for (const byte of payload) {
    parts.push(identifierCanonicalSizedField(Buffer.from([byte])));
  }
  return Buffer.concat(parts);
}

function identifierPublicKeyPayload(controller, context) {
  ensureCurveIdEnabled(controller.curve, context);
  const publicKey = Buffer.from(normalizeBytes(controller.publicKey));
  validatePublicKeyForCurve(controller.curve, publicKey, context);
  return identifierCanonicalConstVecU8(
    Buffer.concat([
      Buffer.from([identifierAlgorithmTagForCurveId(controller.curve, context)]),
      publicKey,
    ]),
  );
}

function identifierMultisigMemberPayload(member, context) {
  return Buffer.concat([
    identifierCanonicalSizedField(
      identifierPublicKeyPayload(member, `${context}.publicKey`),
    ),
    identifierCanonicalSizedField(identifierCanonicalU16(member.weight, `${context}.weight`)),
  ]);
}

function identifierCanonicalU16(value, context) {
  const integer = Number(identifierNormalizeUnsignedBigInt(value, context));
  if (!Number.isInteger(integer) || integer < 0 || integer > 0xffff) {
    throw createValidationError(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${context} must fit in u16`,
      context,
    );
  }
  const buffer = Buffer.allocUnsafe(2);
  buffer.writeUInt16LE(integer, 0);
  return buffer;
}

function identifierNoritoVec(values, encode, context) {
  const parts = [identifierCanonicalU64(values.length, `${context}.length`)];
  values.forEach((value, index) => {
    parts.push(identifierCanonicalSizedField(encode(value, index)));
  });
  return Buffer.concat(parts);
}

function identifierMultisigPolicyPayload(policy, context) {
  if (!Array.isArray(policy.members) || policy.members.length === 0) {
    rejectError(`${context} multisig policy must contain at least one member`);
  }
  return Buffer.concat([
    identifierCanonicalSizedField(identifierCanonicalU8(policy.version, `${context}.version`)),
    identifierCanonicalSizedField(identifierCanonicalU16(policy.threshold, `${context}.threshold`)),
    identifierCanonicalSizedField(
      identifierNoritoVec(
        policy.members,
        (member, index) => identifierMultisigMemberPayload(member, `${context}.members[${index}]`),
        `${context}.members`,
      ),
    ),
  ]);
}

function identifierCanonicalU8(value, context) {
  const integer = Number(identifierNormalizeUnsignedBigInt(value, context));
  if (!Number.isInteger(integer) || integer < 0 || integer > 0xff) {
    throw createValidationError(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${context} must fit in u8`,
      context,
    );
  }
  return Buffer.from([integer]);
}

function identifierAccountIdPayload(accountId, context) {
  const literal = requireExactAccountId(accountId, context);
  const address = AccountAddress.fromI105(literal);
  const controller = address.controllerInfo();
  if (!controller || typeof controller.tag !== JS_TYPE_NUMBER) {
    rejectError(`${context} could not resolve account controller information`);
  }
  switch (controller.tag) {
    case 0:
      return Buffer.concat([
        identifierCanonicalU32(0),
        identifierCanonicalSizedField(identifierPublicKeyPayload(controller, context)),
      ]);
    case 1:
      return Buffer.concat([
        identifierCanonicalU32(1),
        identifierCanonicalSizedField(identifierMultisigPolicyPayload(controller, context)),
      ]);
    default:
      rejectError(`${context} uses unsupported account controller tag ${controller.tag}`);
  }
}

function identifierExecutionPayload(execution) {
  return Buffer.concat([
    identifierCanonicalSizedField(identifierProgramIdPayload(execution.program_id, "payload.execution.program_id")),
    identifierCanonicalSizedField(identifierHashBytes(execution.program_digest, "payload.execution.program_digest")),
    identifierCanonicalSizedField(identifierCanonicalU32(identifierBackendTag(execution.backend))),
    identifierCanonicalSizedField(identifierCanonicalU32(identifierVerificationModeTag(execution.verification_mode))),
    identifierCanonicalSizedField(identifierHashBytes(execution.input_ciphertext_hash, "payload.execution.input_ciphertext_hash")),
    identifierCanonicalSizedField(identifierHashBytes(execution.output_ciphertext_hash, "payload.execution.output_ciphertext_hash")),
    identifierCanonicalSizedField(identifierHashBytes(execution.parameter_digest, "payload.execution.parameter_digest")),
    identifierCanonicalSizedField(identifierHashBytes(execution.evaluation_key_digest, "payload.execution.evaluation_key_digest")),
    identifierCanonicalSizedField(identifierHashBytes(execution.output_hash, "payload.execution.output_hash")),
    identifierCanonicalSizedField(identifierHashBytes(execution.associated_data_hash, "payload.execution.associated_data_hash")),
    identifierCanonicalSizedField(identifierCanonicalU64(execution.executed_at_ms, "payload.execution.executed_at_ms")),
    identifierCanonicalSizedField(identifierCanonicalOptionalU64(execution.expires_at_ms, "payload.execution.expires_at_ms")),
  ]);
}

function identifierOutputOpeningPayload(openingPayload) {
  return Buffer.concat([
    identifierCanonicalSizedField(
      identifierProgramIdPayload(openingPayload.program_id, "payload.opening.payload.program_id"),
    ),
    identifierCanonicalSizedField(identifierHashBytes(openingPayload.input_ciphertext_hash, "payload.opening.payload.input_ciphertext_hash")),
    identifierCanonicalSizedField(identifierHashBytes(openingPayload.output_ciphertext_hash, "payload.opening.payload.output_ciphertext_hash")),
    identifierCanonicalSizedField(identifierHashBytes(openingPayload.parameter_digest, "payload.opening.payload.parameter_digest")),
    identifierCanonicalSizedField(identifierHashBytes(openingPayload.evaluation_key_digest, "payload.opening.payload.evaluation_key_digest")),
    identifierCanonicalSizedField(identifierHashBytes(openingPayload.opened_output_hash, "payload.opening.payload.opened_output_hash")),
    identifierCanonicalSizedField(identifierCanonicalU64(openingPayload.opened_at_ms, "payload.opening.payload.opened_at_ms")),
    identifierCanonicalSizedField(identifierCanonicalOptionalU64(openingPayload.expires_at_ms, "payload.opening.payload.expires_at_ms")),
  ]);
}

function identifierOutputOpening(opening) {
  return Buffer.concat([
    identifierCanonicalSizedField(identifierOutputOpeningPayload(opening.payload)),
    identifierCanonicalSizedField(
      identifierCanonicalByteVec(Buffer.from(opening.signature, "hex")),
    ),
  ]);
}

function identifierProofBoxPayload(attestation) {
  return Buffer.concat([
    identifierCanonicalSizedField(
      identifierCanonicalString(attestation.proof_backend, "attestation.proof_backend"),
    ),
    identifierCanonicalSizedField(
      identifierCanonicalRawByteVec(
        Buffer.from(
          normalizeRequiredBase64Payload(
            attestation.proof_b64,
            "attestation.proof_b64",
          ),
          "base64",
        ),
      ),
    ),
  ]);
}

function identifierReceiptAttestationPayload(attestation) {
  const normalized = normalizeIdentifierReceiptAttestation(
    attestation,
    "identifier receipt attestation",
  );
  if (normalized.kind === "signed") {
    return Buffer.concat([
      identifierCanonicalU32(0),
      identifierCanonicalSizedField(
        identifierCanonicalByteVec(Buffer.from(normalized.signature, "hex")),
      ),
    ]);
  }
  return Buffer.concat([
    identifierCanonicalU32(1),
    identifierCanonicalSizedField(identifierProofBoxPayload(normalized)),
  ]);
}

function identifierReceiptPayload(payload) {
  return Buffer.concat([
    identifierCanonicalSizedField(identifierPolicyIdPayload(payload.policy_id)),
    identifierCanonicalSizedField(identifierExecutionPayload(payload.execution)),
    identifierCanonicalSizedField(identifierOutputOpening(payload.opening)),
    identifierCanonicalSizedField(identifierOpaqueHashPayload(payload.opaque_id, "opaque:", "payload.opaque_id")),
    identifierCanonicalSizedField(identifierHashBytes(payload.receipt_hash, "payload.receipt_hash")),
    identifierCanonicalSizedField(identifierOpaqueHashPayload(payload.uaid, "uaid:", "payload.uaid")),
    identifierCanonicalSizedField(identifierAccountIdPayload(payload.account_id, "payload.account_id")),
  ]);
}

export function encodeIdentifierResolutionReceiptPayload(payload) {
  return identifierReceiptPayload(
    normalizeIdentifierResolutionPayload(payload, "encodeIdentifierResolutionReceiptPayload.payload"),
  );
}

export function encodeIdentifierResolutionReceiptAttestation(attestation) {
  return identifierReceiptAttestationPayload(attestation);
}

export function getIdentifierBfvPublicParameters(policySummary) {
  const normalizedPolicy = normalizeIdentifierPolicySummary(
    policySummary,
    "getIdentifierBfvPublicParameters.policy",
  );
  if (normalizedPolicy.input_encryption !== "bfv-v1") {
    return null;
  }
  return normalizedPolicy.input_encryption_public_parameters_decoded ?? null;
}

/** The SDK has no secure RAM-LFE input-encryption profile. */
export class RamLfeEncryptionUnavailableError extends Error {
  constructor() {
    super("No secure RAM-LFE input-encryption profile is available.");
    this.name = "RamLfeEncryptionUnavailableError";
    this.code = "ram_lfe_encryption_unavailable";
  }
}

/** Refuse before inspecting policy, plaintext, parameters, or randomness. */
export function encryptIdentifierInputForPolicy(_policySummary, _input) {
  throw new RamLfeEncryptionUnavailableError();
}

export function hashIdentifierEncryptedInput(encryptedInput) {
  const literal = requireExactNonEmptyString(
    encryptedInput,
    "hashIdentifierEncryptedInput.encryptedInput",
  );
  if (!/^(?:[0-9a-f]{2})+$/u.test(literal)) {
    throw createValidationError(
      ValidationErrorCode.INVALID_HEX,
      "hashIdentifierEncryptedInput.encryptedInput must be exact lowercase byte-aligned hex",
      "hashIdentifierEncryptedInput.encryptedInput",
    );
  }
  return irohaHashBytes([Buffer.from(literal, "hex")]).toString("hex");
}

export function buildIdentifierRequestForPolicy(policySummary, options = {}) {
  const normalizedPolicy = normalizeIdentifierPolicySummary(
    policySummary,
    "buildIdentifierRequestForPolicy.policy",
  );
  // TODO: Carry the attestor statement and independent trust pins for phone requests.
  if (
    normalizedPolicy.policy_id.startsWith("phone#") ||
    normalizedPolicy.normalization === "phone_e164" ||
    normalizedPolicy.program_id === "phone_retail"
  ) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      "buildIdentifierRequestForPolicy requires signed canonicality attestation support for phone policies",
      "buildIdentifierRequestForPolicy.policy",
    );
  }
  const record = ensureRecord(options, "buildIdentifierRequestForPolicy options");
  assertSupportedOptionKeys(
    record,
    new Set(["encryptedInput", "outputOpening"]),
    "buildIdentifierRequestForPolicy options",
  );
  if (record.outputOpening === undefined || record.outputOpening === null) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      "buildIdentifierRequestForPolicy options must supply outputOpening",
      "buildIdentifierRequestForPolicy.outputOpening",
    );
  }
  if (normalizedPolicy.input_encryption !== "bfv-v1") {
    rejectError(`buildIdentifierRequestForPolicy: policy ${normalizedPolicy.policy_id} does not publish BFV encrypted-input support`);
  }
  return {
    policyId: normalizedPolicy.policy_id,
    encryptedInput: requireHexString(
      record.encryptedInput,
      "buildIdentifierRequestForPolicy.encryptedInput",
    ),
    outputOpening: normalizeRamLfeOutputOpening(
      record.outputOpening,
      "buildIdentifierRequestForPolicy.outputOpening",
    ),
  };
}

export function verifyIdentifierResolutionReceipt(receipt, policySummary) {
  const normalizedReceipt = normalizeIdentifierResolveResponse(
    receipt,
    "verifyIdentifierResolutionReceipt.receipt",
  );
  const normalizedPolicy = normalizeIdentifierPolicySummary(
    policySummary,
    "verifyIdentifierResolutionReceipt.policy",
  );
  if (normalizedReceipt.payload.policy_id !== normalizedPolicy.policy_id) {
    rejectError(`verifyIdentifierResolutionReceipt: receipt policy ${normalizedReceipt.payload.policy_id} does not match policy ${normalizedPolicy.policy_id}`);
  }
  if (normalizedReceipt.attestation.kind !== "signed") {
    rejectError("verifyIdentifierResolutionReceipt: proof attestations require an external verifier");
  }
  const signedPayload = identifierReceiptPayload(normalizedReceipt.payload);
  const prehash = irohaPrehash(signedPayload);
  const signature = Buffer.from(normalizedReceipt.attestation.signature, "hex");
  const verifyingKey = decodeIdentifierReceiptPublicKey(
    normalizedPolicy.resolver_public_key,
    "verifyIdentifierResolutionReceipt.policy.resolver_public_key",
  );
  switch (verifyingKey.algorithm) {
    case "ed25519":
      return verifyEd25519(prehash, signature, verifyingKey.publicKey);
    case "sm2":
      return verifySm2(
        prehash,
        signature,
        verifyingKey.publicKey,
        SM2_DEFAULT_DISTINGUISHED_ID,
      );
    case "secp256k1":
    case "ml-dsa":
      rejectError(`verifyIdentifierResolutionReceipt: ${verifyingKey.algorithm} verification is not available in the JS SDK without additional native support`);
    default:
      rejectError(`verifyIdentifierResolutionReceipt: unsupported algorithm ${verifyingKey.algorithm}`);
  }
}

export function buildConnectWebSocketUrl(baseUrl, options = {}) {
  return buildConnectWebSocketUrlInternal(
    baseUrl,
    options,
    "buildConnectWebSocketUrl",
  );
}

export function buildSorafsOrderbookEventsWebSocketUrl(baseUrl, options = {}) {
  return buildSorafsOrderbookEventsWebSocketUrlInternal(
    baseUrl,
    options,
    "buildSorafsOrderbookEventsWebSocketUrl",
  );
}

export function openConnectWebSocket(options = {}) {
  const normalizedOptions = requirePlainObjectOption(
    options,
    "openConnectWebSocket options",
    { message: "must be an object" },
  );
  return openConnectWebSocketInternal(normalizedOptions, "openConnectWebSocket");
}

export function openSorafsOrderbookEventsWebSocket(options = {}) {
  return openSorafsOrderbookEventsWebSocketInternal(
    options,
    "openSorafsOrderbookEventsWebSocket",
  );
}
