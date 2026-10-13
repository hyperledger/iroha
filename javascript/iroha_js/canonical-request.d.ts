import type { Buffer } from "buffer";

/** Exact immutable genesis-header hash used as the canonical request domain. */
export class NetworkId {
  private constructor();
  static readonly BYTE_LENGTH: 32;
  static parse(literal: string): NetworkId;
  static fromBytes(value: ArrayBuffer | ArrayBufferView): NetworkId;
  readonly literal: string;
  toBytes(): Uint8Array;
  equals(other: unknown): other is NetworkId;
  toString(): string;
  toJSON(): string;
}

export type CanonicalRequestBytes = Buffer | ArrayBuffer | ArrayBufferView;

/** Maximum UTF-8 bytes in a canonical V1 account identity or alias. */
export const CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1: 36864;
/** Maximum decoded non-empty form pairs in a canonical V1 request. */
export const CANONICAL_REQUEST_MAX_QUERY_PAIRS_V1: 64;
/** Maximum UTF-8 bytes in the raw canonical V1 query. */
export const CANONICAL_REQUEST_MAX_RAW_QUERY_BYTES_V1: 65536;
/** Maximum UTF-8 bytes in the canonical V1 HTTP method token. */
export const CANONICAL_REQUEST_MAX_METHOD_BYTES_V1: 32;
/** Maximum UTF-8 bytes in the canonical V1 percent-encoded path. */
export const CANONICAL_REQUEST_MAX_PATH_BYTES_V1: 65536;
/** Maximum detached-signature bytes accepted by canonical V1 auth. */
export const CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1: 3309;
/** Maximum decoded bytes in a forwarded canonical V1 witness. */
export const CANONICAL_REQUEST_MAX_WITNESS_BYTES_V1: 786432;

export interface CanonicalRequestMessageInput {
  method: string;
  path: string;
  query?: string | URLSearchParams;
  body?: CanonicalRequestBytes | string;
}

export interface CanonicalRequestSignatureMessageInput
  extends CanonicalRequestMessageInput {
  /** Exact genesis-derived network identity included in the signed preimage. */
  networkId: NetworkId;
  /** Non-negative JavaScript safe integer rendered as exact unsigned decimal. */
  timestampMs: number;
  nonce: string;
}

export interface CanonicalRequestHeadersInput
  extends CanonicalRequestMessageInput {
  /** Exact canonical I105 account or structurally bounded ASCII alias header. */
  accountId: string;
  /** Exact genesis-derived network domain for every authenticated route. */
  networkId: NetworkId;
  /** Caller query prepared with WHATWG URL wire encoding before signing. */
  query?: string | URLSearchParams;
  privateKey: CanonicalRequestBytes;
  /** Non-negative JavaScript safe integer rendered as exact unsigned decimal. */
  timestampMs?: number;
  nonce?: string;
}

export interface CanonicalRequestHeaders {
  "X-Iroha-Account": string;
  "X-Iroha-Signature": string;
  "X-Iroha-Timestamp-Ms": string;
  "X-Iroha-Nonce": string;
}

export interface CanonicalJsonRequestSignerInput {
  message: Buffer;
  messageBase64: string;
  networkId: NetworkId;
  method: string;
  path: string;
  query?: string | URLSearchParams;
  body: string;
  /** Non-negative JavaScript safe integer rendered as exact unsigned decimal. */
  timestampMs: number;
  nonce: string;
}

export type CanonicalJsonRequestSignature =
  | Buffer
  | Uint8Array
  | ArrayBuffer
  | ArrayBufferView
  | string;

export interface CanonicalJsonRequestInput {
  /** Exact canonical I105 account or structurally bounded ASCII alias header. */
  accountId: string;
  /** Exact genesis-derived network domain for the signed request. */
  networkId: NetworkId;
  method?: string;
  path: string;
  baseUrl?: string;
  query?: string | URLSearchParams;
  body?: unknown;
  /** Exact pre-serialized JSON original; cannot be combined with body. */
  bodyText?: string;
  headers?:
    | Headers
    | ReadonlyArray<readonly [string, string]>
    | Record<string, string>;
  privateKey?: CanonicalRequestBytes;
  sign?: (
    input: CanonicalJsonRequestSignerInput,
  ) => CanonicalJsonRequestSignature | Promise<CanonicalJsonRequestSignature>;
  /** Non-negative JavaScript safe integer rendered as exact unsigned decimal. */
  timestampMs?: number;
  nonce?: string;
}

export interface CanonicalJsonRequest {
  method: string;
  headers: Record<string, string>;
  body: string;
}

export function canonicalQueryString(
  query?: string | URLSearchParams | null,
): string;

export function canonicalRequestMessage(
  params: CanonicalRequestMessageInput,
): Buffer;

export function canonicalRequestSignatureMessage(
  params: CanonicalRequestSignatureMessageInput,
): Buffer;

export function buildCanonicalRequestHeaders(
  params: CanonicalRequestHeadersInput,
): CanonicalRequestHeaders;

export function buildCanonicalJsonRequest(
  params: CanonicalJsonRequestInput,
): Promise<CanonicalJsonRequest>;
