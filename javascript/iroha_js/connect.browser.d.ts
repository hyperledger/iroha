import type { CanonicalJsonRequestSignerInput } from "./canonical-request.js";
import { NetworkId } from "./index.js";
import type { NativeAccountIdentity } from "./index.js";

export { NetworkId };

/** Wallet policy domain for exact Torii canonical-request message bytes. */
export const TORII_CANONICAL_REQUEST_DOMAIN_TAG: "iroha:torii:canonical-request:v1";

export interface BrowserConnectKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface BrowserConnectBinaryLikeSource {
  readonly length: number;
  [index: number]: number;
}

export type BrowserConnectBinaryLike =
  | Uint8Array
  | ArrayBuffer
  | ArrayBufferView
  | number[]
  | BrowserConnectBinaryLikeSource
  | string;

export interface BrowserConnectSessionPreviewOptions {
  networkId: NetworkId;
  node?: string | null;
  nonce?: BrowserConnectBinaryLike | null;
  appKeyPair?: {
    publicKey: BrowserConnectBinaryLike;
    privateKey: BrowserConnectBinaryLike;
  };
}

export interface BrowserConnectSessionPreview {
  networkId: NetworkId;
  node: string | null;
  sidBytes: Uint8Array;
  sidBase64Url: string;
  nonce: Uint8Array;
  appKeyPair: BrowserConnectKeyPair;
  walletUri: string;
  appUri: string;
  wsUrl: string;
  createdAt: number;
}

export interface BrowserConnectSessionResponse {
  sid: string;
  network_id: string;
  app_pk: string;
  nonce: string;
  wallet_uri: string;
  app_uri: string;
  token_app: string;
  token_wallet: string;
  token_management: string;
  token_relay: string;
  extra?: Record<string, unknown>;
  raw?: Record<string, unknown>;
}

export interface BrowserConnectFetchOptions {
  fetchImpl?: typeof fetch;
}

export interface BrowserConnectManagementOptions extends BrowserConnectFetchOptions {
  tokenManagement?: string;
  token_management?: string;
}

export interface BrowserConnectRegisterOptions extends BrowserConnectFetchOptions {
  node?: string | null;
}

export interface BrowserConnectSocketOptions {
  webSocketImpl?: typeof WebSocket;
  protocols?: string | ReadonlyArray<string>;
  allowInsecure?: boolean;
}

export interface BrowserConnectPermissions {
  methods?: ReadonlyArray<string>;
  events?: ReadonlyArray<string>;
  resources?: ReadonlyArray<string> | null;
}

export interface BrowserConnectAppMeta {
  name: string;
  url?: string | null;
  iconHash?: string | null;
  icon_hash?: string | null;
}

export interface BrowserConnectApproval {
  readonly accountId: string;
  readonly nativeIdentity?: NativeAccountIdentity;
  /** Ed25519 key cryptographically bound to `accountId` by wallet approval. */
  readonly signingPublicKey: Uint8Array;
  /** Ephemeral X25519 key used only for the encrypted Connect transport. */
  readonly walletPublicKey: Uint8Array;
  readonly signature: Uint8Array;
}

export interface BrowserConnectAppSessionOptions extends BrowserConnectSocketOptions {
  baseUrl: string;
  /** Required in browsers; native runtimes can use their local Rust address admission. */
  inspectAccountIdentity?: (accountId: string, options: { signal: AbortSignal }) => Promise<NativeAccountIdentity>;
  preview: BrowserConnectSessionPreview;
  session: Pick<BrowserConnectSessionResponse, "sid" | "token_app" | "token_relay">;
  permissions?: BrowserConnectPermissions | null;
  appMeta?: BrowserConnectAppMeta | null;
}

export interface BrowserConnectAppSession {
  readonly socket: WebSocket;
  readonly approvedAccountId: string | null;
  waitForApproval(): Promise<BrowserConnectApproval>;
  signTransaction(unsignedTxBytes: BrowserConnectBinaryLike): Promise<Uint8Array>;
  /** Requires the corresponding `sign_raw` permission to be granted by the wallet. */
  signRaw(
    domainTag: string,
    bytes: BrowserConnectBinaryLike,
  ): Promise<Uint8Array>;
  close(reason?: string): void;
}

export interface BrowserConnectCanonicalRequestAuth {
  readonly authAccountId: string;
  readonly nativeIdentity?: NativeAccountIdentity;
  readonly sign: (
    input: CanonicalJsonRequestSignerInput,
  ) => Promise<Uint8Array>;
}

export class ConnectApprovalRejectedError extends Error {
  readonly code: number | null;
  readonly codeId: string | null;
  readonly reason: string | null;
}

export class ConnectSessionClosedError extends Error {
  readonly code: number | null;
  readonly reason: string | null;
  readonly retryable: boolean | null;
  readonly who: number | null;
}

export class ConnectSignRequestError extends Error {
  readonly code: string | null;
}

export function toHex(bytes: Uint8Array): string;
export function toBase64Url(bytes: Uint8Array): string;
export function buildConnectWebSocketUrl(
  baseUrl: string,
  sid: string,
  role?: "app" | "wallet",
): string;
export function createConnectSessionPreview(
  options: BrowserConnectSessionPreviewOptions,
): BrowserConnectSessionPreview;
export function registerConnectSession(
  baseUrl: string,
  preview: BrowserConnectSessionPreview,
  options?: BrowserConnectRegisterOptions,
): Promise<BrowserConnectSessionResponse>;
export function deleteConnectSession(
  baseUrl: string,
  sid: string,
  options: BrowserConnectManagementOptions,
): Promise<void>;
export function buildConnectTokenProtocol(token: string): string;
export function resolveConnectLaunchUri(
  role: "app" | "wallet",
  preview?: Pick<BrowserConnectSessionPreview, "walletUri" | "appUri"> | null,
  session?: Pick<BrowserConnectSessionResponse, "wallet_uri" | "app_uri"> | null,
): string;
export function rewriteConnectUriProtocol(uri: string, protocol?: string): string;
export function resolveConnectLaunchUriForProtocol(
  role: "wallet",
  preview?: Pick<BrowserConnectSessionPreview, "walletUri"> | null,
  session?: Pick<BrowserConnectSessionResponse, "wallet_uri"> | null,
  protocol?: string,
): string;
export function resolveConnectLaunchUriForProtocol(
  role: "app",
  preview?: Pick<BrowserConnectSessionPreview, "appUri"> | null,
  session?: Pick<BrowserConnectSessionResponse, "app_uri"> | null,
  protocol?: string,
): string;
export function openConnectWebSocket(
  baseUrl: string,
  sid: string,
  token: string,
  role?: "app" | "wallet",
  options?: BrowserConnectSocketOptions,
): WebSocket;
export function openConnectWebSocket(options: BrowserConnectSocketOptions & {
  baseUrl: string;
  sid: string;
  token: string;
  role?: "app" | "wallet";
}): WebSocket;
export function createConnectAppSession(
  options: BrowserConnectAppSessionOptions,
): BrowserConnectAppSession;
export function createConnectCanonicalRequestAuth(
  session: Pick<BrowserConnectAppSession, "waitForApproval" | "signRaw">,
): Promise<BrowserConnectCanonicalRequestAuth>;
/** Exact current binary transaction-request framing and AEAD overhead. */
export const CONNECT_SIGN_REQUEST_TX_FRAME_OVERHEAD_V1: number;
/** Checks endpoint-reported WebSocket and buffer bounds, not wallet capability or authenticated finality. */
export function validateConnectTransactionTransportStatus(status: unknown, payloadLength: number): Readonly<{ frameBytes: number; frameMaxBytes: number; sessionBufferMaxBytes: number }>;
