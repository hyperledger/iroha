/**
 * Error types shared by every Torii client in this package.
 *
 * `ToriiError` is the single base class: it carries a stable machine-readable
 * `code` and optional structured `details`. HTTP failures are
 * `ToriiHttpError`s built from Torii's `{code, message, details}` error
 * envelope and the `x-iroha-reject-code` header; client-side collection-query
 * problems are `ListQueryError`s whose codes match the server
 * (`invalid_filter`, `invalid_sort`, ...).
 */
import { normalizeIvmFault } from "./ivmFault.js";
import { sortJsonForErrorMessage } from "./toriiClientEncoding.js";

const ERROR_TEXT_MAX_LENGTH = 512;

const LIST_QUERY_ERROR_CODES = Object.freeze({
  filter: "invalid_filter",
  sort: "invalid_sort",
  select: "invalid_select",
  aggregate: "invalid_aggregate",
  limit: "invalid_limit",
  cursor: "invalid_cursor",
  include_total: "invalid_include_total",
});

/** Base class of every error raised for a Torii request or response. */
export class ToriiError extends Error {
  /**
   * @param {string} message
   * @param {{code?: string | null, details?: Record<string, unknown> | null, cause?: unknown}} [options]
   */
  constructor(message, { code = null, details = null, cause } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "ToriiError";
    this.code = code;
    this.details = details && Object.hasOwn(details, "ivm_fault")
      ? {...details, ivm_fault: details.ivm_fault === null ? null : normalizeIvmFault(details.ivm_fault, "Torii error details.ivm_fault")}
      : details;
  }
}

/** The stable error code Torii uses for a list-query control. */
export function listQueryErrorCode(parameter) {
  return LIST_QUERY_ERROR_CODES[parameter] ?? "invalid_query";
}

/**
 * A collection query rejected before it was sent. `code` is the code Torii
 * would return for the same request and `parameter` names the control at
 * fault (`filter`, `sort`, `select`, `aggregate`, `limit`, `cursor`,
 * `include_total`, or `query` for the request as a whole).
 */
export class ListQueryError extends ToriiError {
  constructor(parameter, reason, { cause } = {}) {
    super(`invalid \`${parameter}\`: ${reason}`, {
      code: listQueryErrorCode(parameter),
      details: { field: parameter },
      cause,
    });
    this.name = "ListQueryError";
    this.parameter = parameter;
    this.reason = reason;
  }
}

/**
 * Syntax error in a text filter or sort specification. `reason` is the
 * description without position; `line` and `column` are 1-based (columns count
 * Unicode scalar values) and `offset` is the UTF-8 byte offset of the
 * offending token.
 */
export class FilterSyntaxError extends ListQueryError {
  constructor(parameter, reason, { offset, line, column, multiline }) {
    const position = multiline
      ? `line ${line}, column ${column}`
      : `column ${column}`;
    super(parameter, `${reason} (${position})`);
    this.name = "FilterSyntaxError";
    this.reason = reason;
    this.offset = offset;
    this.line = line;
    this.column = column;
  }
}

/**
 * A server-sent event stream reported a non-replayable gap (`stream_error`)
 * or ended unexpectedly; the consumer must re-read state and resubscribe.
 */
export class ToriiStreamGapError extends ToriiError {
  constructor(message, { code = "stream_gap", droppedMessages = null, replayAvailable = false, payload = null } = {}) {
    super(message, { code, details: payload });
    this.name = "ToriiStreamGapError";
    this.droppedMessages = droppedMessages;
    this.replayAvailable = replayAvailable === true;
    this.payload = payload;
  }
}

/** A non-success HTTP response from Torii. */
export class ToriiHttpError extends ToriiError {
  /**
   * @param {{
   *   status: number,
   *   statusText?: string | null,
   *   expected?: ReadonlyArray<number>,
   *   code?: string | null,
   *   rejectCode?: string | null,
   *   errorMessage?: string | null,
   *   bodyText?: string | null,
   *   bodyJson?: unknown,
   *   details?: Record<string, unknown> | null,
   * }} fields
   */
  constructor({
    status,
    expected,
    statusText,
    code,
    rejectCode,
    errorMessage,
    bodyText,
    bodyJson,
    details,
  }) {
    const expectedLabel =
      Array.isArray(expected) && expected.length > 0
        ? expected.slice().sort((a, b) => a - b).join(", ")
        : "none";
    const statusLabel = statusText ? `${status} ${statusText}` : String(status);
    const detailParts = [];
    if (rejectCode && rejectCode !== code) {
      detailParts.push(`reject=${rejectCode}`);
    }
    if (code) {
      detailParts.push(code);
    }
    if (errorMessage && (!code || errorMessage !== code)) {
      detailParts.push(errorMessage);
    }
    if (detailParts.length === 0 && bodyText) {
      detailParts.push(trimErrorText(bodyText) ?? "");
    }
    const suffix = detailParts.length > 0 ? `: ${detailParts.join(" — ")}` : "";
    super(`Torii responded with HTTP ${statusLabel} (expected ${expectedLabel})${suffix}`, {
      code: code ?? null,
      details: details ?? null,
    });
    this.name = "ToriiHttpError";
    this.status = status;
    this.statusText = statusText ?? null;
    this.expected = Array.isArray(expected) ? [...expected] : [];
    this.rejectCode = rejectCode ?? null;
    this.errorMessage = errorMessage ?? null;
    this.bodyText = bodyText ?? null;
    this.bodyJson = bodyJson ?? null;
  }
}

function trimErrorText(text, maxLength = ERROR_TEXT_MAX_LENGTH) {
  if (typeof text !== "string") return null;
  const trimmed = text.trim();
  if (!trimmed) return null;
  return trimmed.length <= maxLength ? trimmed : `${trimmed.slice(0, maxLength)}...`;
}

function rejectCodeFromDetails(details) {
  if (!details || typeof details !== "object") return null;
  const direct = details.reject_code;
  if (typeof direct === "string" && direct.trim()) return direct.trim();
  const axtCode = details.axt?.code;
  if (typeof axtCode === "string" && axtCode.trim()) return axtCode.trim();
  return null;
}

const MESSAGE_KEYS = Object.freeze([
  "message",
  "error",
  "errors",
  "detail",
  "details",
  "reason",
  "rejection_reason",
  "description",
]);

function messageFromValue(value) {
  if (typeof value === "string") return trimErrorText(value);
  if (Array.isArray(value)) {
    for (const item of value) {
      const nested = messageFromValue(item);
      if (nested) return nested;
    }
    return null;
  }
  if (!value || typeof value !== "object") return null;
  const byKey = new Map();
  for (const [key, entry] of Object.entries(value)) {
    const normalized = key.toLowerCase();
    if (!byKey.has(normalized)) byKey.set(normalized, entry);
  }
  for (const key of MESSAGE_KEYS) {
    if (!byKey.has(key)) continue;
    const nested = messageFromValue(byKey.get(key));
    if (nested) return nested;
  }
  return null;
}

function compactJson(value) {
  if (value === null || value === undefined) return null;
  try {
    return trimErrorText(JSON.stringify(sortJsonForErrorMessage(value)));
  } catch {
    return null;
  }
}

/**
 * Extract the error envelope fields from a Torii error response body.
 *
 * Torii errors are `{"code": "...", "message": "...", "details": {...}}`; the
 * `x-iroha-reject-code` header (or `details.reject_code`) carries the precise
 * admission rejection code and takes precedence as `code` when present.
 *
 * @param {{bodyText?: string | null, bodyJson?: unknown, rejectCodeHeader?: string | null}} input
 * @returns {{code: string | null, rejectCode: string | null, errorMessage: string | null, details: Record<string, unknown> | null}}
 */
export function extractToriiErrorFields({ bodyText = null, bodyJson = null, rejectCodeHeader = null }) {
  const payload = bodyJson && typeof bodyJson === "object" && !Array.isArray(bodyJson)
    ? bodyJson
    : null;
  const details = payload?.details && typeof payload.details === "object" && !Array.isArray(payload.details)
    ? payload.details
    : null;
  const headerRejectCode = typeof rejectCodeHeader === "string" && rejectCodeHeader.trim()
    ? rejectCodeHeader.trim()
    : null;
  const rejectCode = headerRejectCode ?? rejectCodeFromDetails(details);
  let envelopeCode = null;
  if (payload) {
    if (typeof payload.code === "string" && payload.code) {
      envelopeCode = payload.code;
    } else if (typeof payload.reason === "string" && payload.reason) {
      envelopeCode = payload.reason;
    } else if (typeof payload.error === "string" && payload.error.startsWith("ERR_")) {
      envelopeCode = payload.error;
    }
  }
  const textCode = typeof bodyText === "string" ? bodyText.match(/ERR_[A-Z0-9_]+/u)?.[0] ?? null : null;
  const code = rejectCode ?? envelopeCode ?? textCode ?? null;
  const errorMessage =
    messageFromValue(payload ?? bodyJson) ?? compactJson(bodyJson) ?? trimErrorText(bodyText);
  return { code, rejectCode, errorMessage, details };
}

/** Parse a response body as JSON only when it looks like a JSON document. */
export function parseErrorBodyJson(bodyText, contentType) {
  if (typeof bodyText !== "string") return null;
  const trimmed = bodyText.trim();
  if (!trimmed) return null;
  const mediaType = typeof contentType === "string"
    ? contentType.split(";", 1)[0].trim().toLowerCase()
    : "";
  const looksLikeJson = mediaType === "application/json"
    || mediaType.endsWith("+json")
    || trimmed.startsWith("{");
  if (!looksLikeJson) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

/**
 * Build a `ToriiHttpError` from a failed response's status, headers and text.
 *
 * @param {{status: number, statusText?: string | null, expected?: ReadonlyArray<number>, bodyText?: string | null, contentType?: string | null, rejectCodeHeader?: string | null}} input
 * @returns {ToriiHttpError}
 */
export function toriiHttpErrorFromResponseText({
  status,
  statusText = null,
  expected = [],
  bodyText = null,
  contentType = null,
  rejectCodeHeader = null,
}) {
  const text = typeof bodyText === "string" ? bodyText : null;
  const bodyJson = parseErrorBodyJson(text, contentType);
  const fields = extractToriiErrorFields({ bodyText: text, bodyJson, rejectCodeHeader });
  return new ToriiHttpError({
    status,
    statusText,
    expected,
    ...fields,
    bodyText: text === null ? null : text,
    bodyJson,
  });
}
