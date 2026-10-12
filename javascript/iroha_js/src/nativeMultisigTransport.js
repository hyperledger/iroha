import { requireMultisigId } from "./multisigIdentifiers.js";
import { Buffer } from "buffer";
import { sha256 } from "@noble/hashes/sha256";
import { networkIdBytes } from "./networkId.js";

const requests = new WeakMap();
const preparations = new WeakMap();
const responseKeys = ["schema", "requestId", "nonce", "actionId", "requestSha256", "context", "intentSha256", "result"];
const contextKeys = ["networkId", "actorAccountId", "actorPublicKeyHex", "deviceId", "portalOrigin", "operatorBaseUrl", "toriiBaseUrl", "physicalDataspaceId", "laneId"];
const requestKeys = ["stage", "path", "requestBytesBase64", "requestBytesSha256", "proposalId", "instructionsHash", "expiresAtMs"];
const prepareKeys = ["stage", "admissionId", "path", "requestBytesSha256", "prepareBytesSha256", "payloadBase64", "payloadSha256", "signingMessageBase64", "signingMessageSha256", "proposalId", "instructionsHash", "creationTimeMs", "payloadExpiresAtMs", "expiresAtMs", "feePayment"];
const signedKeys = ["stage", "admissionId", "path", "submitBytesBase64", "submitBytesSha256", "signedTransactionBytesBase64", "transactionHashHex", "expiresAtMs"];
const finalityKeys = ["stage", "admissionId", "participationCommitted", "businessExecuted", "cancellationCommitted", "subjectCanceled", "transactionHashHex", "executedTransactionHashHex", "blockHeight", "blockHash"];
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const maximumBytes = 16 * 1024 * 1024;

function record(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new TypeError(`${label} must be a plain record`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value).some(key => typeof key !== "string" || !("value" in descriptors[key])) ||
      (keys && (Reflect.ownKeys(value).length !== keys.length || keys.some(key => !descriptors[key])))) {
    throw new TypeError(`${label} has unexpected fields or accessors`);
  }
  return value;
}

function boundedText(value, maximum, label) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value ||
      value.normalize("NFC") !== value || encoder.encode(value).length > maximum || /[\p{Cc}\p{Cs}]/u.test(value)) {
    throw new TypeError(`${label} must be exact bounded text`);
  }
  return value;
}

function hex(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) throw new TypeError(`${label} must be 32-byte lowercase hex`);
  return value;
}

function uuid(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/u.test(value)) {
    throw new TypeError(`${label} must be a nonnil canonical UUID`);
  }
  return value;
}

function decimal(value, label) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/u.test(value) || BigInt(value) > (1n << 64n) - 1n) {
    throw new TypeError(`${label} must be a canonical u64 decimal string`);
  }
  return value;
}

function safeJson(value, depth = 0) {
  if (depth > 32) throw new TypeError("native transport JSON exceeds nesting bound");
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (encoder.encode(value).length > maximumBytes || /[\p{Cs}]/u.test(value)) throw new TypeError("invalid transport string");
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new TypeError("native transport JSON numbers must be safe integers");
    return value;
  }
  if (Array.isArray(value)) return Object.freeze(value.map(entry => safeJson(entry, depth + 1)));
  record(value, null, "native transport JSON");
  const result = Object.create(null);
  for (const key of Object.keys(value).sort()) result[key] = safeJson(value[key], depth + 1);
  return Object.freeze(result);
}

function canonical(value) { return JSON.stringify(safeJson(value)); }
function digest(bytes) { return Buffer.from(sha256(bytes)).toString("hex"); }
function b64(bytes) { return Buffer.from(bytes).toString("base64"); }
function bytes(value, label, maximum = maximumBytes) {
  if (typeof value !== "string" || value.length > Math.ceil(maximum / 3) * 4) throw new TypeError(`${label} must be bounded canonical base64`);
  const decoded = Uint8Array.from(Buffer.from(value, "base64"));
  if (!decoded.length || decoded.length > maximum || b64(decoded) !== value) throw new TypeError(`${label} must be canonical base64`);
  return decoded;
}
function boundBytes(value, expectedDigest, label, maximum) {
  const decoded = bytes(value, label, maximum);
  if (digest(decoded) !== hex(expectedDigest, `${label} digest`)) throw new TypeError(`${label} digest mismatch`);
  return decoded;
}
function unexpired(value) {
  decimal(value, "expiresAtMs");
  if (BigInt(value) <= BigInt(Date.now())) throw new TypeError("native multisig original expired; a new reviewed action is required");
}
function correlation(value) {
  record(value, ["requestId", "nonce"], "request correlation");
  const requestId = uuid(value.requestId, "requestId");
  const nonce = hex(value.nonce, "nonce");
  if (/^0+$/u.test(nonce)) throw new TypeError("nonce must not be zero");
  return { requestId, nonce };
}
function context(input) {
  record(input, contextKeys, "native multisig context");
  networkIdBytes(input.networkId, "native multisig networkId");
  for (const key of ["actorAccountId", "deviceId"]) boundedText(input[key], 2048, key);
  hex(input.actorPublicKeyHex, "actorPublicKeyHex");
  decimal(input.physicalDataspaceId, "physicalDataspaceId");
  if (!Number.isSafeInteger(input.laneId) || input.laneId < 0 || input.laneId > 0xffffffff) throw new TypeError("laneId must be u32");
  for (const key of ["portalOrigin", "operatorBaseUrl", "toriiBaseUrl"]) {
    const value = boundedText(input[key], 2048, key);
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash ||
        (key === "portalOrigin" && value !== url.origin)) throw new TypeError(`${key} must be an exact service URL`);
  }
  return safeJson({ ...input, networkId: input.networkId.toString() });
}

async function send(state, stage, fields) {
  const call = safeJson(fields);
  const body = canonical(call);
  if (encoder.encode(body).length > maximumBytes) throw new TypeError("native multisig request exceeds limit");
  const identityField = stage === "proposal-finality" ? "lookupId" : "actionId";
  const keys = responseKeys.map(key => key === "actionId" ? identityField : key);
  const schema = stage === "proposal-finality" ? state.contract.proposalFinalitySchema : state.contract[`${stage}Schema`];
  const response = record(await state.transport(Object.freeze({ stage, requestId: call.requestId, body })), keys, "native multisig response");
  if (response.schema !== schema || response.requestId !== call.requestId || response.nonce !== call.nonce ||
      response[identityField] !== state[identityField] || response.requestSha256 !== digest(encoder.encode(body)) ||
      response.intentSha256 !== state.intentSha256 || canonical(response.context) !== canonical(state.context)) {
    throw new TypeError("native multisig response differs from exact request, context, or reviewed intent");
  }
  return response.result;
}

/**
 * Bind a reviewed JSON intent to a native-generated multisig request original.
 * The transport must independently authenticate the service/session and send
 * the exact body under X-Request-Id. This helper has no account or Norito codec
 * and confers no business authority. Persist action originals across retries.
 */
export async function requestNativeMultisigViaTransport(input, transport, contract) {
  record(input, ["requestId", "nonce", "actionId", "context", "intent"], "native multisig input");
  record(contract, ["requestSchema", "prepareSchema", "signedSchema"], "native multisig contract");
  for (const value of Object.values(contract)) boundedText(value, 128, "response schema");
  if (typeof transport !== "function") throw new TypeError("native multisig transport must be a function");
  const state = { actionId: uuid(input.actionId, "actionId"), context: context(input.context),
    intent: safeJson(record(input.intent, null, "reviewed native intent")), contract: safeJson(contract), transport };
  if (!["propose", "approve", "cancel"].includes(state.intent.action)) throw new TypeError("unsupported multisig action");
  state.path = `/v1/multisig/${state.intent.action}`;
  state.intentSha256 = digest(encoder.encode(`${canonical(state.intent)}\n`));
  const result = record(await send(state, "request", { ...correlation({requestId: input.requestId, nonce: input.nonce}),
    actionId: state.actionId, context: state.context, intent: state.intent }), requestKeys, "native multisig request result");
  if (result.stage !== "request" || result.path !== state.path) throw new TypeError("native request stage/path mismatch");
  const requestBytes = boundBytes(result.requestBytesBase64, result.requestBytesSha256, "request bytes");
  const requestBody = safeJson(JSON.parse(decoder.decode(requestBytes)));
  if (canonical(requestBody) !== decoder.decode(requestBytes)) throw new TypeError("native request original is not canonical JSON");
  requireMultisigId(result.proposalId, "proposalId");
  hex(result.instructionsHash, "instructionsHash");
  unexpired(result.expiresAtMs);
  const admitted = safeJson(result);
  requests.set(admitted, { ...state, requestBody, request: admitted });
  return admitted;
}

/** Inspect the exact unsigned Torii response against an admitted request original. */
export async function inspectNativeMultisigPrepareViaTransport(request, input) {
  const state = requests.get(request);
  if (!state) throw new TypeError("native request handle is not admitted");
  record(input, ["requestId", "nonce", "prepareBytes"], "native prepare input");
  if (!(input.prepareBytes instanceof Uint8Array) || !input.prepareBytes.length || input.prepareBytes.length > maximumBytes) throw new TypeError("prepareBytes must be exact response bytes");
  unexpired(request.expiresAtMs);
  const prepareBytes = Uint8Array.from(input.prepareBytes);
  const result = record(await send(state, "prepare", { ...correlation({requestId: input.requestId, nonce: input.nonce}),
    actionId: state.actionId, context: state.context, intent: state.intent,
    requestBytesBase64: request.requestBytesBase64, prepareBytesBase64: b64(prepareBytes) }), prepareKeys, "native prepared result");
  if (result.stage !== "prepared" || result.path !== state.path || result.admissionId !== state.actionId ||
      result.requestBytesSha256 !== request.requestBytesSha256 || result.prepareBytesSha256 !== digest(prepareBytes) ||
      result.proposalId !== request.proposalId || result.instructionsHash !== request.instructionsHash) throw new TypeError("native preparation differs from original request");
  boundBytes(result.payloadBase64, result.payloadSha256, "payload bytes");
  const message = boundBytes(result.signingMessageBase64, result.signingMessageSha256, "signing message", 32);
  if (message.length !== 32) throw new TypeError("native signing message must be 32 bytes");
  decimal(result.creationTimeMs, "creationTimeMs");
  decimal(result.payloadExpiresAtMs, "payloadExpiresAtMs");
  unexpired(result.expiresAtMs);
  if (BigInt(result.creationTimeMs) > BigInt(Date.now()) || BigInt(result.creationTimeMs) >= BigInt(result.payloadExpiresAtMs) ||
      BigInt(result.expiresAtMs) > BigInt(request.expiresAtMs) || BigInt(result.expiresAtMs) > BigInt(result.payloadExpiresAtMs)) throw new TypeError("native preparation changed its fixed lifetime");
  record(result.feePayment, null, "native quoted fees");
  const admitted = safeJson(result);
  preparations.set(admitted, { ...state, prepared: admitted });
  return admitted;
}

/** Bind a client signature to the exact native prepared original before submission. */
export async function inspectNativeMultisigSignedViaTransport(prepared, input) {
  const state = preparations.get(prepared);
  if (!state) throw new TypeError("native prepared handle is not admitted");
  record(input, ["requestId", "nonce", "signature"], "native signed input");
  if (!(input.signature instanceof Uint8Array) || input.signature.length !== 64) throw new TypeError("signature must contain 64 bytes");
  unexpired(prepared.expiresAtMs);
  const creationTime = Number(prepared.creationTimeMs);
  if (!Number.isSafeInteger(creationTime)) throw new TypeError("native creation time cannot be represented exactly in JSON");
  const signedBody = canonical({ ...state.requestBody, creation_time_ms: creationTime, fee_payment: prepared.feePayment,
    public_key_hex: state.context.actorPublicKeyHex, signature_b64: b64(input.signature) });
  const signedBytes = encoder.encode(signedBody);
  const result = record(await send(state, "signed", { ...correlation({requestId: input.requestId, nonce: input.nonce}),
    actionId: state.actionId, context: state.context, admissionId: prepared.admissionId,
    signedRequestBytesBase64: b64(signedBytes) }), signedKeys, "native signed result");
  if (result.stage !== "signed" || result.path !== state.path || result.admissionId !== prepared.admissionId ||
      result.submitBytesBase64 !== b64(signedBytes) || result.expiresAtMs !== prepared.expiresAtMs) throw new TypeError("native signed result changed the exact original");
  boundBytes(result.submitBytesBase64, result.submitBytesSha256, "submit bytes");
  bytes(result.signedTransactionBytesBase64, "signed native transaction");
  hex(result.transactionHashHex, "transactionHashHex");
  unexpired(result.expiresAtMs);
  return safeJson(result);
}

/**
 * Read native-rooted finality for a retained action after signing has expired.
 * Only the action identity/context is sent; the service owns the original signed
 * transaction and independently verifies native evidence against its pinned root.
 * The supplied retained intent and hash constrain the reply; neither grants new
 * signing authority and no new transaction is prepared or submitted.
 */
export async function queryNativeMultisigFinalityViaTransport(input, transport, contract) {
  record(input, ["requestId", "nonce", "actionId", "context", "admissionId", "intent", "transactionHashHex"], "native finality input");
  record(contract, ["finalitySchema"], "native finality contract");
  boundedText(contract.finalitySchema, 128, "finality schema");
  if (typeof transport !== "function") throw new TypeError("native finality transport must be a function");
  const state = {actionId: uuid(input.actionId, "actionId"), context: context(input.context), intent: safeJson(input.intent),
    contract: safeJson(contract), transport};
  if (input.admissionId !== state.actionId || !["propose", "approve", "cancel"].includes(state.intent.action)) throw new TypeError("native finality action/admission mismatch");
  const transactionHashHex = hex(input.transactionHashHex, "retained transaction hash");
  state.intentSha256 = digest(encoder.encode(`${canonical(state.intent)}\n`));
  const result = record(await send(state, "finality", {...correlation({requestId: input.requestId, nonce: input.nonce}),
    actionId: state.actionId, context: state.context, admissionId: input.admissionId}), finalityKeys, "native finality result");
  if (result.stage !== "finality" || result.admissionId !== state.actionId || result.transactionHashHex !== transactionHashHex ||
      [result.participationCommitted, result.businessExecuted, result.cancellationCommitted, result.subjectCanceled].some(value => typeof value !== "boolean") ||
      (result.businessExecuted && (result.cancellationCommitted || result.subjectCanceled || state.intent.targetProposalId != null)) ||
      (result.subjectCanceled && result.cancellationCommitted && state.intent.targetProposalId != null)) throw new TypeError("native finality result differs from retained action");
  if (result.businessExecuted || result.cancellationCommitted) hex(result.executedTransactionHashHex, "executed transaction hash");
  else if (result.executedTransactionHashHex !== null) throw new TypeError("unexecuted action must not advertise execution hash");
  if (result.participationCommitted || result.businessExecuted || result.cancellationCommitted) {
    decimal(result.blockHeight, "finality block height");
    if (result.blockHeight === "0") throw new TypeError("finality block height must be positive");
    hex(result.blockHash, "finality block hash");
  } else if (result.blockHeight !== null || result.blockHash !== null) throw new TypeError("uncommitted action must not advertise finality block");
  return safeJson(result);
}

/** Read independently authorized native proposal execution evidence. The service
 * reconstructs the complete reviewed operation and verifies its native hash and
 * execution against its installed root; no local participation record is needed. */
export async function queryNativeMultisigProposalFinalityViaTransport(input, transport, contract) {
  record(input, ["requestId", "nonce", "lookupId", "context", "intent"], "native proposal finality input");
  record(contract, ["proposalFinalitySchema"], "native proposal finality contract");
  boundedText(contract.proposalFinalitySchema, 128, "proposal finality schema");
  if (typeof transport !== "function") throw new TypeError("native proposal finality transport must be a function");
  const intent = safeJson(record(input.intent, ["multisigAccountId", "proposalId", "instructionsHash", "operation", "targetProposalId", "targetInstructionsHash"], "proposal finality intent"));
  boundedText(intent.multisigAccountId, 2048, "multisigAccountId");
  requireMultisigId(intent.proposalId, "proposalId");
  hex(intent.instructionsHash, "instructionsHash");
  record(intent.operation, null, "complete reviewed operation");
  const cancellation = intent.targetProposalId !== null;
  if (cancellation !== (intent.targetInstructionsHash !== null)) throw new TypeError("cancellation target requires both occurrence and instruction commitment");
  if (cancellation) { hex(intent.targetProposalId, "targetProposalId"); hex(intent.targetInstructionsHash, "targetInstructionsHash"); }
  const state = {lookupId: uuid(input.lookupId, "lookupId"), context: context(input.context), intent,
    intentSha256: digest(encoder.encode(`${canonical(intent)}\n`)), contract: safeJson(contract), transport};
  const result = record(await send(state, "proposal-finality", {...correlation({requestId: input.requestId, nonce: input.nonce}),
    lookupId: state.lookupId, context: state.context, intent}),
  ["stage", "businessExecuted", "cancellationCommitted", "subjectCanceled", "executedTransactionHashHex", "blockHeight", "blockHash"], "native proposal finality result");
  if (result.stage !== "proposal-finality" || typeof result.businessExecuted !== "boolean" || typeof result.cancellationCommitted !== "boolean" || typeof result.subjectCanceled !== "boolean" ||
      (result.businessExecuted && (cancellation || result.cancellationCommitted || result.subjectCanceled)) ||
      (cancellation && result.cancellationCommitted && result.subjectCanceled)) {
    throw new TypeError("native proposal finality differs from exact reviewed operation");
  }
  if (result.businessExecuted || result.cancellationCommitted) {
    hex(result.executedTransactionHashHex, "executed transaction hash");
    decimal(result.blockHeight, "finality block height");
    if (result.blockHeight === "0") throw new TypeError("finality block height must be positive");
    hex(result.blockHash, "finality block hash");
  } else if (result.executedTransactionHashHex !== null || result.blockHeight !== null || result.blockHash !== null) {
    throw new TypeError("unexecuted proposal must not advertise execution evidence");
  }
  return safeJson(result);
}
