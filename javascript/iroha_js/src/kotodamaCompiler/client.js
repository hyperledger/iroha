const propertyDescriptor = Object.getOwnPropertyDescriptor.bind(Object);
const hasOwn = Object.hasOwn.bind(Object);
const applyIntrinsic = Reflect.apply.bind(Reflect);
import { normalizeCompilerResult, validateUnicodeScalarString } from "./normalize.js";

// One error constructor preserves the same class, message and optional cause.
function rejectType(message, options) {
  throw new TypeError(message, options);
}

function rejectCompilerType(message, options) {
  rejectType(`Kotodama compiler ${message}`, options);
}

function compilerError(message) {
  return new Error(`Kotodama compiler ${message}`);
}

function rejectRange(message) {
  throw new RangeError(message);
}

function invoke(callable, receiver, args = []) {
  return applyIntrinsic(callable, receiver, args);
}

// Capture native accessors once; callers never select getters from instances.
function intrinsicGetter(constructor, name) {
  return constructor ? (propertyDescriptor(constructor.prototype, name)?.get ?? null) : null;
}

const COMPILER_RESPONSE_LABEL = "Kotodama compiler response";
const DEFAULT_COMPILE_PATH = "/v1/kotodama/compile";
const DEFAULT_COMPILER_TIMEOUT_MS = 30_000;
const MAX_COMPILER_TIMEOUT_MS = 120_000;
const SOURCE_SET_FIELDS = ["sources", "imports", "packages", "artifacts"];
const COMPILER_REQUEST_OPTION_NAMES = new Set(["sourceName", ...SOURCE_SET_FIELDS, "zk"]);
const COMPILER_CALL_OPTION_NAMES = new Set([
  ...COMPILER_REQUEST_OPTION_NAMES,
  "signal",
  "timeoutMs",
]);
const COMPILER_OPTION_NAMES = new Set([
  "compilerUrl",
  "fetchImpl",
  ...COMPILER_CALL_OPTION_NAMES,
]);
const COMPILER_CLIENT_OPTION_NAMES = new Set(["fetchImpl"]);
const MAX_COMPILER_SOURCE_BYTES = 1024 * 1024;
const MAX_COMPILER_SOURCE_NAME_BYTES = 4096;
const MAX_COMPILER_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_COMPILER_ERROR_BYTES = 64 * 1024;
const MAX_COMPILER_RESPONSE_CHUNKS = 65_536;

const DefaultFetch = globalThis.fetch;
const AbortControllerIntrinsic = globalThis.AbortController;
const abortControllerAbort = AbortControllerIntrinsic?.prototype?.abort ?? null;
const abortControllerSignalGetter = intrinsicGetter(AbortControllerIntrinsic, "signal");
const abortSignalAbortedGetter = intrinsicGetter(globalThis.AbortSignal, "aborted");
const abortSignalReasonGetter = intrinsicGetter(globalThis.AbortSignal, "reason");
const eventTargetAddEventListener = globalThis.EventTarget?.prototype?.addEventListener ?? null;
const eventTargetRemoveEventListener =
  globalThis.EventTarget?.prototype?.removeEventListener ?? null;
const responseOkGetter = intrinsicGetter(globalThis.Response, "ok");
const responseStatusGetter = intrinsicGetter(globalThis.Response, "status");
const responseRedirectedGetter = intrinsicGetter(globalThis.Response, "redirected");
const responseHeadersGetter = intrinsicGetter(globalThis.Response, "headers");
const responseBodyGetter = intrinsicGetter(globalThis.Response, "body");
const headersGet = globalThis.Headers?.prototype?.get ?? null;
const readableStreamGetReader = globalThis.ReadableStream?.prototype?.getReader ?? null;
const readerRead = globalThis.ReadableStreamDefaultReader?.prototype?.read ?? null;
const readerCancel = globalThis.ReadableStreamDefaultReader?.prototype?.cancel ?? null;
const readerReleaseLock =
  globalThis.ReadableStreamDefaultReader?.prototype?.releaseLock ?? null;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const [typedArrayBufferGetter, typedArrayByteOffsetGetter, typedArrayByteLengthGetter, typedArrayTagGetter] =
  ["buffer", "byteOffset", "byteLength", Symbol.toStringTag].map((name) =>
    propertyDescriptor(typedArrayPrototype, name)?.get);
const sharedArrayBufferByteLengthGetter = intrinsicGetter(globalThis.SharedArrayBuffer, "byteLength");
const Uint8ArrayIntrinsic = Uint8Array;
const uint8ArraySet = Uint8Array.prototype.set;
const TextEncoderIntrinsic = TextEncoder;
const textEncoderEncode = TextEncoder.prototype.encode;
const TextDecoderIntrinsic = TextDecoder;
const textDecoderDecode = TextDecoder.prototype.decode;
const setTimeoutIntrinsic = globalThis.setTimeout;
const clearTimeoutIntrinsic = globalThis.clearTimeout;

function isLoopbackHostname(hostname) {
  const normalized = hostname.toLowerCase();
  return (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized === "[::1]" ||
    /^127(?:\.[0-9]{1,3}){3}$/.test(normalized)
  );
}

export function validateCompilerSource(source) {
  if (typeof source !== "string") {
    rejectType("Kotodama source must be a string");
  }
  if (!validateUnicodeScalarString(source)) {
    rejectType("Kotodama source must contain valid Unicode scalar values");
  }
  const sourceBytes = invoke(textEncoderEncode, new TextEncoderIntrinsic(), [
    source,
  ]).length;
  if (sourceBytes > MAX_COMPILER_SOURCE_BYTES) {
    rejectRange(
      `Kotodama source exceeds the ${MAX_COMPILER_SOURCE_BYTES}-byte V1 limit`,
    );
  }
}

function canonicalizeCompilerOptions(options, allowedNames) {
  if (options === undefined) {
    return Object.create(null);
  }
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    rejectCompilerType("options must be an object");
  }
  const prototype = Object.getPrototypeOf(options);
  if (prototype !== Object.prototype && prototype !== null) {
    rejectCompilerType("options must be a plain data object");
  }
  const canonical = Object.create(null);
  for (const name of Reflect.ownKeys(options)) {
    if (typeof name !== "string") {
      rejectCompilerType("options must not contain symbol fields");
    }
    if (!allowedNames.has(name)) {
      rejectType(`unknown Kotodama compiler option '${name}'`);
    }
    const descriptor = propertyDescriptor(options, name);
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !("value" in descriptor)
    ) {
      rejectType(
        `Kotodama compiler option '${name}' must be an enumerable data property`,
      );
    }
    canonical[name] = descriptor.value;
  }
  return canonical;
}

function validateCompilerRequestFields(options) {
  if (hasOwn(options, "sourceName")) {
    if (typeof options.sourceName !== "string" || options.sourceName.length === 0) {
      rejectType("sourceName must be a non-empty string");
    }
    if (!validateUnicodeScalarString(options.sourceName)) {
      rejectType("sourceName must contain valid Unicode scalar values");
    }
    const hasControlCharacter = Array.from(options.sourceName, (character) =>
      character.codePointAt(0),
    ).some((codePoint) => codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f));
    if (hasControlCharacter) {
      rejectType("sourceName must not contain control characters");
    }
    const sourceNameBytes = invoke(
      textEncoderEncode,
      new TextEncoderIntrinsic(),
      [options.sourceName],
    ).length;
    if (sourceNameBytes > MAX_COMPILER_SOURCE_NAME_BYTES) {
      rejectRange(
        `sourceName exceeds the ${MAX_COMPILER_SOURCE_NAME_BYTES}-byte limit`,
      );
    }
  }
  if (hasOwn(options, "zk") && typeof options.zk !== "boolean") {
    rejectType("zk must be a boolean");
  }
  if (SOURCE_SET_FIELDS.some((key) => hasOwn(options, key))) {
    if (options.sourceName === undefined) rejectType("sourceName is required when sources are supplied");
    const names = new Set([canonicalSourcePath(options.sourceName)]);
    if (hasOwn(options, "sources")) options.sources = canonicalSourceFiles(options.sources, names);
    if (hasOwn(options, "artifacts")) options.artifacts = canonicalContractArtifacts(options.artifacts, names);
    if (hasOwn(options, "imports")) options.imports = canonicalSourceImports(options.imports);
    if (hasOwn(options, "packages")) {
      const identities = new Set();
      options.packages = canonicalDataArray(options.packages, "packages").map((value) => {
        const pkg = canonicalizeCompilerOptions(value, new Set(["identity", "modules", "sources", "exports", "imports", "artifacts"]));
        validateGraphIdentifier(pkg.identity, "package identity");
        if (identities.has(pkg.identity)) rejectType("duplicate package identity");
        identities.add(pkg.identity);
        const paths = new Set();
        const modules = canonicalSourceFiles(pkg.modules, paths);
        const sources = canonicalSourceFiles(pkg.sources ?? [], paths);
        const artifacts = canonicalContractArtifacts(pkg.artifacts ?? [], paths);
        const exports = canonicalDataArray(pkg.exports, "exports");
        const exported = new Set();
        for (const name of exports) {
          validateGraphIdentifier(name, "package export");
          if (exported.has(name)) rejectType("duplicate package export");
          exported.add(name);
        }
        return { identity: pkg.identity, modules, sources, artifacts, exports, imports: canonicalSourceImports(pkg.imports ?? []) };
      });
    }
    const count = 1 + (options.sources?.length ?? 0) + (options.artifacts?.length ?? 0) + (options.packages ?? []).reduce((total, pkg) => total + pkg.modules.length + pkg.sources.length + pkg.artifacts.length, 0);
    if (count > 512) rejectRange("a Kotodama source set permits at most 512 files including its root");
  }
  return options;
}

function canonicalDataArray(value, label) {
  if (!Array.isArray(value)) rejectType(`${label} must be an array`);
  if (value.length > 512) rejectRange(`${label} exceeds the 512-item limit`);
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = propertyDescriptor(value, String(index));
    if (!descriptor || !hasOwn(descriptor, "value")) rejectType(`${label} must contain inert data entries`);
    result.push(descriptor.value);
  }
  return result;
}

function validateGraphIdentifier(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || !validateUnicodeScalarString(value) || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    rejectType(`${label} must be a bounded nonempty string`);
  }
}

function canonicalSourceFiles(files, names) {
  return canonicalDataArray(files, "sources").map((source) => {
    const file = canonicalizeCompilerOptions(source, new Set(["sourceName", "source"]));
    if (file.sourceName === undefined) rejectType("each source file requires sourceName");
    validateCompilerRequestFields({ sourceName: file.sourceName });
    validateCompilerSource(file.source);
    const name = canonicalSourcePath(file.sourceName);
    if (names.has(name)) rejectType(`duplicate Kotodama source path '${name}'`);
    names.add(name);
    return { sourceName: name, source: file.source };
  });
}

function canonicalContractArtifacts(artifacts, names) {
  return canonicalDataArray(artifacts, "artifacts").map((value) => {
    const record = canonicalizeCompilerOptions(value, new Set(["sourceName", "artifact"]));
    validateCompilerRequestFields({ sourceName: record.sourceName });
    if (record.sourceName === undefined) rejectType("each compiled artifact requires sourceName");
    const sourceName = canonicalSourcePath(record.sourceName);
    if (!sourceName.endsWith(".to")) rejectType("compiled artifacts require a .to path");
    if (names.has(sourceName)) rejectType("duplicate source or compiled artifact path");
    names.add(sourceName);
    if (!Array.isArray(record.artifact) || record.artifact.length === 0 || record.artifact.length > 16 * 1024 * 1024) rejectType("artifact must be a nonempty bounded byte array");
    const artifact = [];
    for (let index = 0; index < record.artifact.length; index += 1) {
      const descriptor = propertyDescriptor(record.artifact, String(index));
      if (!descriptor || !hasOwn(descriptor, "value") || !Number.isInteger(descriptor.value) || descriptor.value < 0 || descriptor.value > 255) rejectType("artifact must contain inert byte values");
      artifact.push(descriptor.value);
    }
    return { sourceName, artifact };
  });
}

function canonicalSourceImports(imports) {
  const aliases = new Set();
  return canonicalDataArray(imports, "imports").map((value) => {
    const binding = canonicalizeCompilerOptions(value, new Set(["alias", "package"]));
    validateGraphIdentifier(binding.alias, "import alias");
    validateGraphIdentifier(binding.package, "import package");
    if (aliases.has(binding.alias)) rejectType("duplicate import alias");
    aliases.add(binding.alias);
    return { alias: binding.alias, package: binding.package };
  });
}

function canonicalSourcePath(name) {
  if (/^(?:[\\/]|[A-Za-z]:)/u.test(name) || name.includes(":")) {
    rejectType("source paths must be relative to the source-set root");
  }
  const parts = [];
  for (const part of name.replaceAll("\\", "/").split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (parts.length === 0) rejectType("source path escapes the source-set root");
      parts.pop();
    } else {
      if (/^\.+$/u.test(part)) rejectType("source path contains a nonportable component");
      parts.push(part);
    }
  }
  if (parts.length === 0) rejectType("source path must name a file");
  return parts.join("/");
}

function validateCompilerRequestOptions(options) {
  return validateCompilerRequestFields(
    canonicalizeCompilerOptions(options, COMPILER_REQUEST_OPTION_NAMES),
  );
}

function validateAbortSignal(signal) {
  if (abortSignalAbortedGetter === null) {
    rejectCompilerType("options.signal requires AbortSignal support");
  }
  try {
    invoke(abortSignalAbortedGetter, signal);
  } catch {
    rejectCompilerType("options.signal must be an AbortSignal");
  }
}

function validateCompilerTransportFields(options) {
  if (hasOwn(options, "signal")) {
    validateAbortSignal(options.signal);
  }
  if (hasOwn(options, "timeoutMs")) {
    if (
      !Number.isInteger(options.timeoutMs) ||
      options.timeoutMs <= 0 ||
      options.timeoutMs > MAX_COMPILER_TIMEOUT_MS
    ) {
      rejectRange(
        `timeoutMs must be an integer from 1 through ${MAX_COMPILER_TIMEOUT_MS}`,
      );
    }
  }
  return options;
}

function validateCompilerCallOptions(options) {
  return validateCompilerTransportFields(
    validateCompilerRequestFields(
      canonicalizeCompilerOptions(options, COMPILER_CALL_OPTION_NAMES),
    ),
  );
}

export function validateCompilerOptions(options) {
  options = validateCompilerTransportFields(
    validateCompilerRequestFields(
      canonicalizeCompilerOptions(options, COMPILER_OPTION_NAMES),
    ),
  );
  if (
    hasOwn(options, "compilerUrl") &&
    (typeof options.compilerUrl !== "string" || options.compilerUrl.length === 0)
  ) {
    rejectType("compilerUrl must be a non-empty string");
  }
  if (hasOwn(options, "fetchImpl") && typeof options.fetchImpl !== "function") {
    rejectType("fetchImpl must be a function");
  }
  return options;
}

/** Build the exact bounded request shared by the native and service adapters. */
export function buildCompilerRequest(source, options = {}) {
  validateCompilerSource(source);
  options = validateCompilerRequestOptions(options);
  const request = { source, artifacts: options.artifacts ?? [], zk: options.zk ?? false };
  if (options.sourceName !== undefined) {
    request.sourceName = options.sourceName;
  }
  if (SOURCE_SET_FIELDS.some((key) => options[key] !== undefined)) {
    const files = [...(options.sources ?? []), ...(options.packages ?? []).flatMap((pkg) => [...pkg.modules, ...pkg.sources])];
    const artifactBytes = [...(options.artifacts ?? []), ...(options.packages ?? []).flatMap((pkg) => pkg.artifacts)].reduce((total, entry) => total + entry.artifact.length, 0);
    const bytes = [source, ...files.map((file) => file.source)].reduce(
      (total, text) => total + invoke(textEncoderEncode, new TextEncoderIntrinsic(), [text]).length,
      0,
    );
    if (bytes + artifactBytes > 16 * 1024 * 1024) rejectRange("Kotodama source set exceeds the 16777216-byte limit");
    request.sourceName = canonicalSourcePath(request.sourceName);
    for (const key of SOURCE_SET_FIELDS) {
      if (options[key] !== undefined) request[key] = options[key];
    }
  }
  return request;
}

/** Select request policy from an already validated top-level option object. */
export function selectCompilerRequestOptions(options) {
  return selectCompilerFields(options, COMPILER_REQUEST_OPTION_NAMES);
}

/** Select request and transport policy for a remote compiler invocation. */
export function selectCompilerCallOptions(options) {
  return selectCompilerFields(options, COMPILER_CALL_OPTION_NAMES);
}

function selectCompilerFields(options, names) {
  const selected = {};
  for (const name of names) {
    if (hasOwn(options, name)) selected[name] = options[name];
  }
  return selected;
}

function signalIsAborted(signal) {
  return invoke(abortSignalAbortedGetter, signal);
}

function signalAbortReason(signal) {
  if (abortSignalReasonGetter !== null) {
    return invoke(abortSignalReasonGetter, signal);
  }
  const error = compilerError("request was aborted");
  error.name = "AbortError";
  return error;
}

function createCompilerOperation(signal, timeoutMs) {
  if (
    typeof AbortControllerIntrinsic !== "function" ||
    abortControllerAbort === null ||
    abortControllerSignalGetter === null ||
    eventTargetAddEventListener === null ||
    eventTargetRemoveEventListener === null
  ) {
    throw compilerError("service requires AbortController support");
  }

  const controller = new AbortControllerIntrinsic();
  const transportSignal = invoke(abortControllerSignalGetter, controller);
  let cancelled = false;
  let cancellationReason;
  let rejectCancellation;
  const cancellation = new Promise((_, reject) => {
    rejectCancellation = reject;
  });
  // The cancellation may win a synchronous preflight race. Keep the losing
  // promise handled after every operation path has cleaned up.
  cancellation.catch(() => {});

  const cancel = (reason) => {
    if (cancelled) return;
    cancelled = true;
    cancellationReason = reason;
    // Publish the authoritative caller/deadline rejection before notifying
    // transport listeners, which may synchronously reject with another value.
    rejectCancellation(reason);
    try {
      invoke(abortControllerAbort, controller, [reason]);
    } catch {
      // The local rejection remains authoritative if transport abort fails.
    }
  };
  const onCallerAbort = () => cancel(signalAbortReason(signal));

  let callerListenerInstalled = false;
  if (signal !== undefined) {
    if (signalIsAborted(signal)) {
      onCallerAbort();
    } else {
      invoke(eventTargetAddEventListener, signal, [
        "abort",
        onCallerAbort,
        { once: true },
      ]);
      callerListenerInstalled = true;
      // Close the check/listen race without trusting any instance property.
      if (signalIsAborted(signal)) onCallerAbort();
    }
  }

  let timerId;
  if (!cancelled) {
    timerId = invoke(setTimeoutIntrinsic, globalThis, [
      () => {
        const error = compilerError(
          `request timed out after ${timeoutMs}ms`,
        );
        error.name = "TimeoutError";
        cancel(error);
      },
      timeoutMs,
    ]);
  }

  return {
    signal: transportSignal,
    race(promise) {
      return Promise.race([promise, cancellation]).then(
        (value) => {
          if (cancelled) throw cancellationReason;
          return value;
        },
        (error) => {
          if (cancelled) throw cancellationReason;
          throw error;
        },
      );
    },
    throwIfCancelled() {
      if (cancelled) throw cancellationReason;
    },
    isCancelled() {
      return cancelled;
    },
    cancellationReason() {
      return cancellationReason;
    },
    cleanup() {
      if (timerId !== undefined) {
        invoke(clearTimeoutIntrinsic, globalThis, [timerId]);
        timerId = undefined;
      }
      if (callerListenerInstalled) {
        try {
          invoke(eventTargetRemoveEventListener, signal, [
            "abort",
            onCallerAbort,
          ]);
        } catch {
          // Listener removal is cleanup and must not replace the result.
        }
        callerListenerInstalled = false;
      }
    },
  };
}

function responseMetadata(response) {
  if (
    response === null ||
    typeof response !== "object" ||
    responseOkGetter === null ||
    responseStatusGetter === null ||
    responseRedirectedGetter === null ||
    responseHeadersGetter === null ||
    responseBodyGetter === null
  ) {
    rejectCompilerType("fetch returned an invalid Response");
  }
  try {
    const ok = invoke(responseOkGetter, response);
    const status = invoke(responseStatusGetter, response);
    const redirected = invoke(responseRedirectedGetter, response);
    const headers = invoke(responseHeadersGetter, response);
    const body = invoke(responseBodyGetter, response);
    if (
      typeof ok !== "boolean" ||
      !Number.isInteger(status) ||
      status < 100 ||
      status > 599 ||
      typeof redirected !== "boolean"
    ) {
      rejectType("invalid Response metadata");
    }
    return { ok, status, redirected, headers, body };
  } catch (error) {
    rejectCompilerType("fetch returned an invalid Response", {
      cause: error,
    });
  }
}

function headerValue(headers, name, label) {
  if (headersGet === null) {
    rejectType(`${label} does not expose standards-compliant headers`);
  }
  try {
    return invoke(headersGet, headers, [name]);
  } catch (error) {
    rejectType(`${label} does not expose standards-compliant headers`, {
      cause: error,
    });
  }
}

function contentLength(headers, label) {
  const raw = headerValue(headers, "content-length", label);
  if (raw === null || raw === undefined) {
    return null;
  }
  if (!/^(?:0|[1-9][0-9]*)$/.test(raw)) {
    throw new Error(`${label} has an invalid Content-Length header`);
  }
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${label} Content-Length is outside the safe integer range`);
  }
  return parsed;
}

function validateIdentityContentEncoding(headers, label) {
  const encoding = headerValue(headers, "content-encoding", label);
  if (encoding !== null && encoding !== undefined && encoding.toLowerCase() !== "identity") {
    rejectType(
      `${label} Content-Encoding must be absent or exactly identity`,
    );
  }
}

function cancelReaderBestEffort(reader, reason) {
  if (readerCancel === null) return;
  try {
    const cancellation = invoke(readerCancel, reader, [reason]);
    Promise.resolve(cancellation).catch(() => {});
  } catch {
    // Cancellation is cleanup and must not replace the authoritative error.
  }
}

function releaseReaderBestEffort(reader) {
  if (readerReleaseLock === null) return;
  try {
    invoke(readerReleaseLock, reader);
  } catch {
    // Lock release is cleanup and must not replace the authoritative result.
  }
}

function cancelResponseBestEffort(response, reason) {
  try {
    const body = invoke(responseBodyGetter, response);
    if (body === null || readableStreamGetReader === null) return;
    const reader = invoke(readableStreamGetReader, body);
    cancelReaderBestEffort(reader, reason);
    releaseReaderBestEffort(reader);
  } catch {
    // A late or malformed response cannot replace the authoritative result.
  }
}

function snapshotByteChunk(value, label, remainingBytes, limit) {
  let buffer;
  let byteOffset;
  let byteLength;
  try {
    if (invoke(typedArrayTagGetter, value) !== "Uint8Array") {
      rejectType("not Uint8Array");
    }
    buffer = invoke(typedArrayBufferGetter, value);
    byteOffset = invoke(typedArrayByteOffsetGetter, value);
    byteLength = invoke(typedArrayByteLengthGetter, value);
  } catch {
    rejectType(`${label} yielded a non-byte response chunk`);
  }
  if (sharedArrayBufferByteLengthGetter !== null) {
    let isShared = false;
    try {
      invoke(sharedArrayBufferByteLengthGetter, buffer);
      isShared = true;
    } catch {
      // Normal ArrayBuffers fail the SharedArrayBuffer brand check.
    }
    if (isShared) {
      rejectType(`${label} yielded a SharedArrayBuffer-backed chunk`);
    }
  }
  if (byteLength === 0) {
    rejectType(`${label} yielded an empty non-progress response chunk`);
  }
  if (byteLength > remainingBytes) {
    rejectRange(`${label} exceeds the ${limit}-byte response limit`);
  }
  const snapshot = new Uint8ArrayIntrinsic(byteLength);
  try {
    const view = new Uint8ArrayIntrinsic(buffer, byteOffset, byteLength);
    invoke(uint8ArraySet, snapshot, [view]);
  } catch (error) {
    rejectType(`${label} yielded an unstable response chunk`, {
      cause: error,
    });
  }
  return snapshot;
}

async function readBoundedResponseBytes(metadata, limit, label, operation) {
  const declaredLength = contentLength(metadata.headers, label);
  if (declaredLength !== null && declaredLength > limit) {
    rejectRange(`${label} exceeds the ${limit}-byte response limit`);
  }
  if (metadata.body === null) {
    if (declaredLength !== null && declaredLength !== 0) {
      rejectType(
        `${label} body length does not match its Content-Length header`,
      );
    }
    return new Uint8ArrayIntrinsic();
  }
  if (readableStreamGetReader === null || readerRead === null) {
    rejectType(`${label} does not expose a standards-compliant readable body`);
  }

  let reader;
  try {
    reader = invoke(readableStreamGetReader, metadata.body);
  } catch (error) {
    rejectType(
      `${label} does not expose a standards-compliant readable body`,
      { cause: error },
    );
  }
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      operation.throwIfCancelled();
      const read = Promise.resolve().then(() =>
        invoke(readerRead, reader),
      );
      const { done, value } = await operation.race(read);
      if (typeof done !== "boolean") {
        rejectType(`${label} returned an invalid stream read result`);
      }
      if (done) {
        if (value !== undefined) {
          rejectType(`${label} returned data after the stream ended`);
        }
        break;
      }
      if (chunks.length >= MAX_COMPILER_RESPONSE_CHUNKS) {
        rejectRange(`${label} yielded too many fragmented response chunks`);
      }
      const chunk = snapshotByteChunk(value, label, limit - total, limit);
      total += chunk.length;
      if (total > limit) {
        rejectRange(`${label} exceeds the ${limit}-byte response limit`);
      }
      chunks.push(chunk);
    }
  } catch (error) {
    cancelReaderBestEffort(reader, error);
    throw error;
  } finally {
    releaseReaderBestEffort(reader);
  }
  operation.throwIfCancelled();
  if (declaredLength !== null && total !== declaredLength) {
    rejectType(
      `${label} body length does not match its Content-Length header`,
    );
  }
  const bytes = new Uint8ArrayIntrinsic(total);
  let offset = 0;
  for (const chunk of chunks) {
    invoke(uint8ArraySet, bytes, [chunk, offset]);
    offset += chunk.length;
  }
  return bytes;
}

async function readBoundedResponseText(metadata, limit, label, operation) {
  const bytes = await readBoundedResponseBytes(metadata, limit, label, operation);
  try {
    return invoke(
      textDecoderDecode,
      new TextDecoderIntrinsic("utf-8", { fatal: true }),
      [bytes],
    );
  } catch {
    rejectType(`${label} is not valid UTF-8`);
  }
}

async function readCompilerResult(metadata, operation) {
  const text = await readBoundedResponseText(
    metadata,
    MAX_COMPILER_RESPONSE_BYTES,
    COMPILER_RESPONSE_LABEL,
    operation,
  );
  let result;
  try {
    result = JSON.parse(text);
  } catch {
    rejectCompilerType("service returned malformed JSON");
  }
  return normalizeCompilerResult(result);
}

/** Browser/Node client for an explicitly configured canonical Rust compiler service. */
export class KotodamaCompilerClient {
  #baseUrl;

  #fetchImpl;

  constructor(baseUrl, options = {}) {
    if (typeof baseUrl !== "string" || baseUrl.length === 0) {
      rejectCompilerType("baseUrl must be a non-empty string");
    }
    options = canonicalizeCompilerOptions(options, COMPILER_CLIENT_OPTION_NAMES);
    const fetchImpl = hasOwn(options, "fetchImpl")
      ? options.fetchImpl
      : DefaultFetch;
    let parsed;
    try {
      parsed = new URL(baseUrl);
    } catch {
      rejectCompilerType("baseUrl must be an absolute URL");
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      rejectCompilerType("baseUrl must use HTTP or HTTPS");
    }
    if (parsed.protocol === "http:" && !isLoopbackHostname(parsed.hostname)) {
      rejectCompilerType(
        "baseUrl must use HTTPS except for loopback development services",
      );
    }
    if (parsed.username !== "" || parsed.password !== "") {
      rejectCompilerType("baseUrl must not contain credentials");
    }
    if (parsed.search !== "" || parsed.hash !== "") {
      rejectCompilerType("baseUrl must not contain a query or fragment");
    }
    if (typeof fetchImpl !== "function") {
      rejectCompilerType("client requires fetch");
    }
    // Private slots preserve the constructor's validated HTTPS/loopback transport policy.
    this.#baseUrl = parsed.href.replace(/\/$/, "");
    this.#fetchImpl = fetchImpl;
  }

  async compile(source, options = {}) {
    options = validateCompilerCallOptions(options);
    const request = buildCompilerRequest(
      source,
      selectCompilerRequestOptions(options),
    );
    const timeoutMs = options.timeoutMs ?? DEFAULT_COMPILER_TIMEOUT_MS;
    const operation = createCompilerOperation(options.signal, timeoutMs);
    let response;
    try {
      operation.throwIfCancelled();
      const fetchPromise = Promise.resolve().then(() =>
        invoke(this.#fetchImpl, undefined, [
          `${this.#baseUrl}${DEFAULT_COMPILE_PATH}`,
          {
            method: "POST",
            headers: {
              accept: "application/json",
              "content-type": "application/json",
            },
            cache: "no-store",
            credentials: "omit",
            redirect: "error",
            referrerPolicy: "no-referrer",
            signal: operation.signal,
            body: JSON.stringify(request),
          },
        ]),
      );
      // If an injected Fetch ignores abort and resolves after our boundary has
      // rejected, drain/cancel its body without reviving the operation.
      fetchPromise.then(
        (lateResponse) => {
          if (operation.isCancelled()) {
            cancelResponseBestEffort(
              lateResponse,
              operation.cancellationReason(),
            );
          }
        },
        () => {},
      );
      response = await operation.race(fetchPromise);
      operation.throwIfCancelled();
      const metadata = responseMetadata(response);
      try {
        validateIdentityContentEncoding(
          metadata.headers,
          COMPILER_RESPONSE_LABEL,
        );
      } catch (error) {
        cancelResponseBestEffort(response, error);
        throw error;
      }
      if (metadata.redirected) {
        cancelResponseBestEffort(response, "redirected compiler response rejected");
        rejectCompilerType("service redirects are forbidden");
      }
      if (!metadata.ok) {
        const detail = await readBoundedResponseText(
          metadata,
          MAX_COMPILER_ERROR_BYTES,
          ("Kotodama compiler " + "error response"),
          operation,
        );
        const suffix = detail.length === 0 ? "" : `: ${detail}`;
        throw compilerError(
          `service failed (${metadata.status})${suffix}`,
        );
      }
      if (metadata.status !== 200) {
        cancelResponseBestEffort(response, "unexpected compiler success status");
        rejectType(
          `Kotodama compiler service returned unexpected success status ${metadata.status}`,
        );
      }
      if (headerValue(metadata.headers, "content-type", COMPILER_RESPONSE_LABEL) !== "application/json") {
        cancelResponseBestEffort(response, "invalid compiler response media type");
        rejectType(
          "Kotodama compiler response Content-Type must be exactly application/json",
        );
      }
      const result = await readCompilerResult(metadata, operation);
      operation.throwIfCancelled();
      return result;
    } catch (error) {
      if (response !== undefined) {
        cancelResponseBestEffort(response, error);
      }
      throw error;
    } finally {
      operation.cleanup();
    }
  }
}
