import type { NexusTransactionCodec } from "./nexus-app.js";
import type { NetworkId } from "./index.js";

/** Browser-safe structural view of the runtime KotodamaQuantity class. */
export interface BrowserKotodamaQuantity {
  readonly mantissa: bigint;
  readonly scale: number;
  toString(): string;
}

export type BrowserTransactionBytes =
  | Uint8Array
  | ArrayBuffer
  | ArrayBufferView;

export type BrowserTransactionUnsigned = bigint | number | string;

export type BrowserFeeChargeKind = "nexus" | "pipelineGas";

export interface BrowserFeeChargeLimit {
  kind: BrowserFeeChargeKind;
  assetDefinitionId: string;
  /** Positive canonical decimal maximum authorized by the signer. */
  maxAmount: BrowserKotodamaQuantity | bigint | string;
}

export type BrowserFeePayment =
  | {
      payer: "authority";
      chargeLimits: readonly BrowserFeeChargeLimit[];
      gasLimit?: BrowserTransactionUnsigned | null;
    }
  | {
      payer: "sponsor";
      programId: string;
      programRevision: BrowserTransactionUnsigned;
      chargeLimits: readonly BrowserFeeChargeLimit[];
      gasLimit?: BrowserTransactionUnsigned | null;
    };

/** `number` leaves must be safe integers; encode decimals as strings. */
export type BrowserTransactionMetadataValue =
  | null
  | boolean
  | number
  | string
  | readonly BrowserTransactionMetadataValue[]
  | { readonly [key: string]: BrowserTransactionMetadataValue };

export interface BrowserTransferInput {
  networkId: NetworkId;
  chain?: never;
  chainId?: never;
  chain_id?: never;
  authority: string;
  sourceAssetHoldingId?: string;
  sourceAssetId?: string;
  /** Positive canonical decimal, scale <= 28, and value <= 2^511 - 1. */
  quantity: BrowserKotodamaQuantity | bigint | string;
  destinationAccountId: string;
  /** Required signature-bound fee payer, charge maxima, and gas bound. */
  feePayment: BrowserFeePayment;
  metadata?: string | { readonly [key: string]: BrowserTransactionMetadataValue } | null;
  creationTimeMs?: BrowserTransactionUnsigned;
  ttlMs?: BrowserTransactionUnsigned | null;
  nonce?: BrowserTransactionUnsigned | null;
  /** Required caller-selected I105 deployment prefix (u16). */
  networkPrefix: number;
}

export interface BrowserInstructionTransactionInput {
  networkId: NetworkId;
  chain?: never;
  chainId?: never;
  chain_id?: never;
  authority: string;
  instructions: readonly object[];
  /** Required signature-bound fee payer, charge maxima, and gas bound. */
  feePayment: BrowserFeePayment;
  metadata?: string | { readonly [key: string]: BrowserTransactionMetadataValue } | null;
  creationTimeMs?: BrowserTransactionUnsigned;
  ttlMs?: BrowserTransactionUnsigned | null;
  nonce?: BrowserTransactionUnsigned | null;
  /** Required caller-selected I105 deployment prefix (u16). */
  networkPrefix: number;
}

export type BrowserExecutableBatchEntry =
  | {
      kind: "instruction";
      instruction: object;
    }
  | {
      kind: "contractCall";
      contractAddress: string;
      /** Exact marked 32-byte Iroha code hash. */
      expectedCodeHash: BrowserTransactionBytes | string;
      entrypoint: string;
      /** Canonical schema-bound argument-record bytes; maximum 1 MiB. */
      arguments?: BrowserTransactionBytes | null;
    };

export interface BrowserExecutableBatchInput {
  networkId: NetworkId;
  chain?: never;
  chainId?: never;
  chain_id?: never;
  authority: string;
  entries: readonly BrowserExecutableBatchEntry[];
  /** Must include `gasLimit` when any entry is a contract call. */
  feePayment: BrowserFeePayment;
  metadata?: string | { readonly [key: string]: BrowserTransactionMetadataValue } | null;
  creationTimeMs?: BrowserTransactionUnsigned;
  ttlMs?: BrowserTransactionUnsigned | null;
  nonce?: BrowserTransactionUnsigned | null;
  /** Required caller-selected I105 deployment prefix (u16). */
  networkPrefix: number;
}

export interface BrowserTransactionSignable {
  /** Application-pinned exact NetworkId expected in payloadBytes. */
  networkId: NetworkId;
  networkPrefix: number;
  payloadBytes: BrowserTransactionBytes;
  payloadHashHex?: string;
  authority: string;
  signingPublicKey?: BrowserTransactionBytes | string;
  signatureAlgorithm?: "ed25519" | 0;
}

export interface BrowserTransactionSignableConstraints {
  networkId?: NetworkId | null;
  networkPrefix?: number;
  authority?: string | null;
  signingPublicKey?: BrowserTransactionBytes | string | null;
}

export interface ValidatedBrowserTransactionSignable {
  networkId: NetworkId;
  networkPrefix: number;
  payloadBytes: Uint8Array;
  payloadHashHex: string;
  authority: string;
  signingPublicKey: Uint8Array;
  signatureAlgorithm: "ed25519";
}

export interface BrowserTransactionSignatureObject {
  algorithm?: "ed25519" | 0;
  alg?: "ed25519" | 0;
  signature?: BrowserTransactionBytes | string;
  bytes?: BrowserTransactionBytes | string;
  payload?: BrowserTransactionBytes | string;
}

export type BrowserTransactionSignature =
  | BrowserTransactionBytes
  | BrowserTransactionSignatureObject;

export interface BrowserFinalizedSignedTransaction {
  signedTransaction: Uint8Array;
  hash: Uint8Array;
  hashHex: string;
}

export class BrowserTransactionCodecError extends TypeError {
  readonly code: string;
}

export function buildBrowserTransferPayload(input: BrowserTransferInput): Uint8Array;

export function buildBrowserInstructionTransactionPayload(
  input: BrowserInstructionTransactionInput,
): Uint8Array;

export function buildBrowserVerifyingKeyTransactionPayload(
  input: BrowserInstructionTransactionInput,
  operation: "register" | "update",
): Uint8Array;

export function decodeCanonicalVerifyingKeyTransactionPayload(
  payloadBytes: BrowserTransactionBytes,
  constraints: {
    expectedNetworkId: NetworkId;
    expectedAuthority: string;
    networkPrefix: number;
    operation: "register" | "update";
  },
): {
  id: { backend: string; name: string };
  record: Record<string, unknown>;
};

export function buildBrowserExecutableBatchPayload(
  input: BrowserExecutableBatchInput,
): Uint8Array;

export function browserTransactionPayloadHashHex(
  payloadBytes: BrowserTransactionBytes,
  networkPrefix: number,
): string;

export function validateBrowserTransferSignable(
  signable: BrowserTransactionSignable,
  constraints?: BrowserTransactionSignableConstraints,
): Readonly<ValidatedBrowserTransactionSignable>;

export function validateBrowserInstructionTransactionSignable(
  signable: BrowserTransactionSignable,
  constraints?: BrowserTransactionSignableConstraints,
): Readonly<ValidatedBrowserTransactionSignable>;

export function validateBrowserExecutableBatchSignable(
  signable: BrowserTransactionSignable,
  constraints?: BrowserTransactionSignableConstraints,
): Readonly<ValidatedBrowserTransactionSignable>;

export function finalizeBrowserSignedTransaction(
  signable: BrowserTransactionSignable,
  signature: BrowserTransactionSignature,
  signingPublicKey: BrowserTransactionBytes | string,
): BrowserFinalizedSignedTransaction;

export function finalizeBrowserInstructionTransaction(
  signable: BrowserTransactionSignable,
  signature: BrowserTransactionSignature,
  signingPublicKey: BrowserTransactionBytes | string,
): BrowserFinalizedSignedTransaction;

export function finalizeBrowserExecutableBatchTransaction(
  signable: BrowserTransactionSignable,
  signature: BrowserTransactionSignature,
  signingPublicKey: BrowserTransactionBytes | string,
): BrowserFinalizedSignedTransaction;

export function browserSignedTransactionHashHex(
  signedTransaction: BrowserTransactionBytes,
  networkPrefix: number,
): string;

export const browserTransactionCodec: Readonly<NexusTransactionCodec> & Readonly<{
  buildTransferPayload: typeof buildBrowserTransferPayload;
  buildInstructionPayload: typeof buildBrowserInstructionTransactionPayload;
  buildExecutableBatchPayload: typeof buildBrowserExecutableBatchPayload;
  payloadHashHex: typeof browserTransactionPayloadHashHex;
  finalizeSignedTransaction: typeof finalizeBrowserSignedTransaction;
  finalizeInstructionTransaction: typeof finalizeBrowserInstructionTransaction;
  finalizeExecutableBatchTransaction: typeof finalizeBrowserExecutableBatchTransaction;
  validateSignable: typeof validateBrowserTransferSignable;
  validateInstructionSignable: typeof validateBrowserInstructionTransactionSignable;
  validateExecutableBatchSignable: typeof validateBrowserExecutableBatchSignable;
}>;

/** Structural attachment codec only; transaction admission and proof verification are separate. */
export type AttachmentKindV1 = "Proof" | "KeyMaterial";
export type AttachmentRoleV1 = "ActionProof" | "VerifyingKey" | "LanePrivacyProof" | "ExecutionProof";
export type ActionRoleV1 = "ProofEffect" | "ProofVerification" | "Administrative" | "Effect";
export type ActionOperationV1 = { type: "NativeInstruction"; wireId: string } | { type: "TransactionProof" | "IvmProvedExecution" };
export type ActionAuthorityBindingV1 = { type: "TransactionAuthority" } | { type: "ContractSubject" | "Account"; accountId: string };
export type ActionInvocationBindingV1 = { type: "Transaction" } | { type: "Direct"; instructionIndex: number } | { type: "Contract"; rootIndex: number; callPath: number[] };
export interface AttachmentReferenceV1 {
  index: number;
  kind: AttachmentKindV1;
  role: AttachmentRoleV1;
  /** Exact byte count, bounded to 9 MiB. */
  length: number;
  contentHash: Uint8Array;
}
export interface ActionIntentV1 {
  actionIndex: number;
  operation: ActionOperationV1;
  role: ActionRoleV1;
  authority: ActionAuthorityBindingV1;
  invocation: ActionInvocationBindingV1;
  publicInputsDigest: Uint8Array;
  statementDigest: Uint8Array;
  attachments: AttachmentReferenceV1[];
}
export interface SignedAttachmentOccurrenceV1 {
  index: number;
  kind: AttachmentKindV1;
  length: number;
  contentHash: Uint8Array;
  bytes: Uint8Array;
}
export interface SignedAttachmentsV1 {
  actions: ActionIntentV1[];
  occurrences: SignedAttachmentOccurrenceV1[];
}
export const SIGNED_ATTACHMENT_LIMITS_V1: Readonly<{
  maxActions: 16; maxOccurrences: 16; maxOccurrenceBytes: 9437184;
  maxFrameBytes: 9502720; maxCallPath: 32; maxWireIdBytes: 128;
}>;
/** Exact canonical descriptor frame. Does not admit the enclosing transaction or verify a proof. */
export function encodeSignedAttachmentsV1(value: SignedAttachmentsV1): Uint8Array;
/** Structural validation plus independent output bytes. Account validation uses the authenticated SDK native runtime. */
export function decodeSignedAttachmentsV1(encoded: Uint8Array): SignedAttachmentsV1;
/** Padded standard-base64 string value used by canonical Norito JSON. */
export function signedAttachmentsToJsonV1(value: SignedAttachmentsV1): string;
export function signedAttachmentsFromJsonV1(value: string): SignedAttachmentsV1;
/** Statement derived from the supplied ordered intent; does not authenticate the supplied intent or proof. */
export function actionStatementDigestV1(action: ActionIntentV1, orderedIntentDigest: Uint8Array): Uint8Array;
/** Normalized descriptor frame for hashing only. It cannot be decoded as an admitted descriptor. */
export function signedAttachmentsIntentProjectionV1(value: SignedAttachmentsV1): Uint8Array;

/** Structurally complete carrier. This does not establish cryptographic proof validity. */
export interface ProofCarrierV1 {
  backend: string;
  proofBytes: Uint8Array;
  verifyingKey: { backend: string; name: string };
  verifyingKeyCommitment: Uint8Array | null;
  envelopeHash: Uint8Array | null;
  lanePrivacy: { commitmentId: number; leaf: Uint8Array; leafIndex: number; auditPath: Uint8Array[] } | null;
}
/** Complete canonical ProofAttachment, bounded by the signed occurrence limit. */
export declare function encodeProofCarrierV1(value: ProofCarrierV1): Uint8Array;
export declare function decodeProofCarrierV1(encoded: Uint8Array): ProofCarrierV1;
/** Exact proof-free metadata digest. Empty proof bytes are allowed for planning; generated envelope contents are omitted. Does not admit or verify a proof. */
export declare function proofCarrierPublicInputsDigestV1(value: ProofCarrierV1): Uint8Array;
/** Checks actual carrier metadata and statements against a caller-supplied intent.
 * Does not derive/validate transaction context, executable targets, or privacy normalization.
 */
export declare function inspectSignedAttachmentProofBindingsV1(
  descriptor: SignedAttachmentsV1,
  orderedIntentDigest: Uint8Array,
): Array<{ actionIndex: number; attachment: ProofCarrierV1 }>;

/** Canonical context derived and validated by the authenticated Rust payload decoder. */
export interface TransactionAttachmentContextV1 {
  payloadHash: Uint8Array;
  orderedIntentDigest: Uint8Array;
  orderedIntentProjection: Uint8Array;
  attachmentFrame: Uint8Array | null;
  statementDigests: Uint8Array[];
}
/** Validates attachment context against actual payload/network/authority, including Rust privacy normalization.
 * Does not verify proof/signature cryptography or establish runtime/state admission.
 */
export declare function inspectCanonicalTransactionAttachmentContextV1(
  payloadBytes: Uint8Array,
  expected: { networkId: Uint8Array; authority: string },
): TransactionAttachmentContextV1;
