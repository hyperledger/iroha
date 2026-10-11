import type { Buffer } from "buffer";
import type { BrowserFeePayment } from "./transaction-codec.js";
import { OperatorSigningContext } from "./operator-request.js";
import type { RepoAgreementLifecycleFields } from "./repo-agreement.js";
import type { ToriiBlockMerkleCommitment, ToriiBlockMerkleProof, ToriiBlockProofs, ToriiBlockProofTrustedAnchor, ToriiBlockProofVerification } from "./dist/blockProofTypes.js";
import type { BufferEncoding } from "./dist/nodeBufferTypes.js";
import type {
  ToriiBrowserExplorerAssetDefinition,
  ToriiBrowserExplorerBlock,
  ToriiBrowserExplorerInstruction,
  ToriiBrowserExplorerTransaction,
  ToriiBrowserExplorerTransactionDetail,
} from "./dist/toriiBrowserExplorerTypes.js";
export type {
  ToriiBrowserExplorerAssetDefinition,
  ToriiBrowserExplorerBlock,
  ToriiBrowserExplorerInstruction,
  ToriiBrowserExplorerInstructionBox,
  ToriiBrowserExplorerTransaction,
  ToriiBrowserExplorerTransactionDetail,
  ToriiBrowserExplorerTransactionRejection,
} from "./dist/toriiBrowserExplorerTypes.js";
import type { SubscriptionActionResponse, SubscriptionAuthorityActionRequest, SubscriptionCancelActionRequest, SubscriptionChargeActionRequest, SubscriptionCreateRequest, SubscriptionCreateResponse, SubscriptionGetResponse, SubscriptionPlanCreateRequest, SubscriptionPlanCreateResponse, SubscriptionUsageDraft, SubscriptionUsageRequest } from "./dist/subscriptionTypes.js";
import type { SorafsOrderbookSignedTransaction, SorafsOrderbookSubmissionReceipt, SorafsOrderbookTransactionSubmitOptions } from "./dist/sorafsOrderbookSubmission.js";
import { NetworkId } from "./dist/networkId.js";
export { NetworkId, OperatorSigningContext };
export interface TairaTestnetProfile {
  readonly toriiBaseUrl: "https://taira.sora.org";
  readonly chainId: "fc56984b-2be7-431d-840e-21514d1883f0";
  readonly i105Discriminant: 369;
  readonly dsAssetDefinitionId: "7ZepsJTHCVLKsrFFNZGSRGZgvBhv";
  readonly dsAssetAlias: "ds#boi.is";
  readonly dsAssetScale: 2;
  readonly xorAssetDefinitionId: "6TEAJqbb8oEPmLncoNiMRbLEK6tw";
  readonly xorAssetAlias: "xor#universal";
  readonly xorAssetScale: 9;
}
export const TAIRA_TESTNET_PROFILE: Readonly<TairaTestnetProfile>;
export function createTairaLocalSigningContext(
  deployedNetworkId: NetworkId,
): LocalSigningContext;
export * from "./kotodama-compiler.js";
export * from "./transaction-codec.js";
export * from "./smart-contract-deployment.js";
export * from "./bootle-lantern-issuance.js";
export * from "./atomic-private-settlement.js";
export * from "./dist/blockProofTypes.js";
export * from "./dist/toriiBrowserExplorerTypes.js";
export type * from "./dist/subscriptionTypes.js";
export * from "./dist/sorafsOrderbookSubmission.js";

/** One raw contract-state value under a separately trusted accumulated root. */
export interface ContractStateValueInclusionProofV1 {
  readonly version: 1;
  readonly path: string;
  readonly value: ReadonlyArray<number> | Uint8Array;
  readonly leaf_count: number | string;
  readonly steps: ReadonlyArray<{
    readonly bit: number;
    readonly prefix: ReadonlyArray<number> | Uint8Array;
    readonly sibling: string | Uint8Array;
  }>;
}
/** Verify exact key/value membership; the caller authenticates trustedRoot through v2 finality. */
export function verifyContractStateValueInclusionV1(
  proof: ContractStateValueInclusionProofV1,
  expectedPath: string,
  trustedRoot: string | Uint8Array,
): boolean;
/** Decode duplicate-key-free Torii JSON and verify against an authenticated root. */
export function verifyContractStateValueInclusionJsonV1(
  payload: string | Uint8Array,
  expectedPath: string,
  trustedRoot: string | Uint8Array,
): boolean;

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export const CRYPTO_ALGORITHMS: Readonly<{
  ED25519: "ed25519";
  SECP256K1: "secp256k1";
  ML_DSA: "ml-dsa";
  BLS_NORMAL: "bls_normal";
  BLS_SMALL: "bls_small";
  GOST_2012_256_A: "gost3410-2012-256-paramset-a";
  GOST_2012_256_B: "gost3410-2012-256-paramset-b";
  GOST_2012_256_C: "gost3410-2012-256-paramset-c";
  GOST_2012_512_A: "gost3410-2012-512-paramset-a";
  GOST_2012_512_B: "gost3410-2012-512-paramset-b";
  SM2: "sm2";
}>;

export type CryptoAlgorithm =
  (typeof CRYPTO_ALGORITHMS)[keyof typeof CRYPTO_ALGORITHMS];

export type {
  PrivacyCapabilityReadinessV1,
  PrivacyCompiledProfileBindingsV1,
  PrivacyCompiledProfileResultV1,
  PrivacyConsensusLimitsV1,
  PrivacyConsensusPolicyTighteningV1,
  PrivacyConsensusPolicyV1,
  PrivacyEngineIdV1,
  PrivacyEngineTagV1,
  PrivacyExact12DeploymentQualificationV1,
  PrivacyExact12CapabilityAdmissionV1,
  PrivacyExact12CapabilityManifestNodeClientV1,
  PrivacyExact12CapabilityManifestRequestOptions,
  PrivacyExact12CapabilityRowV1,
  PrivacyExact12QualificationRecordV1,
  PrivacyExact12ReleaseManifestV1,
  PrivacyExecutionModeV1,
  PrivacyFixed32BytesV1,
  PrivacyFixed48BytesV1,
  PrivacyOperationSchemaV1,
  PrivacyProofSystemIdV1,
  PrivacyProofSystemTagV1,
  PrivacyProtocolActivationRecordV1,
  PrivacyProtocolIdV1,
  PrivacyProtocolLifecycleV1,
  PrivacyProtocolLimitsV1,
  PrivacyReleaseProtocolBindingV1,
  PrivacyProtocolTagV1,
  PrivacyDeploymentActivationV1,
  PrivacySecurityClaimV1,
  PrivacySecurityModelTagV1,
  PrivacySecurityModelV1,
  PrivacyTaggedUnitV1,
  PrivacyU64V1,
} from "./privacy-capabilities.js";
export interface CryptoKeyPair {
  algorithm: CryptoAlgorithm;
  publicKey: Buffer;
  privateKey: Buffer;
  distid?: string | null;
}

export type RecoveryPhraseWordCount = 12 | 24;

export interface RecoveryPhrase {
  readonly phrase: string;
  readonly words: readonly string[];
  readonly wordCount: RecoveryPhraseWordCount;
}

export interface KeyPair extends CryptoKeyPair {
  algorithm: "ed25519";
}

export interface Sm2KeyPair extends CryptoKeyPair {
  algorithm: "sm2";
  distid: string;
}

export const SM2_PRIVATE_KEY_LENGTH: number;
export const SM2_PUBLIC_KEY_LENGTH: number;
export const SM2_SIGNATURE_LENGTH: number;
export const SM2_DEFAULT_DISTINGUISHED_ID: string;
export const PRIVACY_REQUIRED_BRIDGE_ABI_VERSION: 25;

export interface SignedTransactionResult {
  /** Exact canonical VersionedSignedTransaction V1 bytes. */
  signedTransaction: Buffer;
  hash: Buffer;
}

/** Exact canonical VersionedSignedTransaction V1 submission bytes. */
export type VersionedSignedTransactionV1 =
  | Buffer
  | ArrayBuffer
  | ArrayBufferView;

export const AccountAddressErrorCode: {
  readonly UNSUPPORTED_ALGORITHM: "ERR_UNSUPPORTED_ALGORITHM";
  readonly KEY_PAYLOAD_TOO_LONG: "ERR_KEY_PAYLOAD_TOO_LONG";
  readonly INVALID_HEADER_VERSION: "ERR_INVALID_HEADER_VERSION";
  readonly INVALID_NORM_VERSION: "ERR_INVALID_NORM_VERSION";
  readonly INVALID_I105_DISCRIMINANT: "ERR_INVALID_I105_DISCRIMINANT";
  readonly INVALID_LENGTH: "ERR_INVALID_LENGTH";
  readonly CHECKSUM_MISMATCH: "ERR_CHECKSUM_MISMATCH";
  readonly UNEXPECTED_NETWORK_PREFIX: "ERR_UNEXPECTED_NETWORK_PREFIX";
  readonly UNKNOWN_ADDRESS_CLASS: "ERR_UNKNOWN_ADDRESS_CLASS";
  readonly UNEXPECTED_EXTENSION_FLAG: "ERR_UNEXPECTED_EXTENSION_FLAG";
  readonly UNKNOWN_CONTROLLER_TAG: "ERR_UNKNOWN_CONTROLLER_TAG";
  readonly INVALID_PUBLIC_KEY: "ERR_INVALID_PUBLIC_KEY";
  readonly UNKNOWN_CURVE: "ERR_UNKNOWN_CURVE";
  readonly UNEXPECTED_TRAILING_BYTES: "ERR_UNEXPECTED_TRAILING_BYTES";
  readonly I105_TOO_SHORT: "ERR_I105_TOO_SHORT";
  readonly INVALID_I105_CHAR: "ERR_INVALID_I105_CHAR";
  readonly UNSUPPORTED_ADDRESS_FORMAT: "ERR_UNSUPPORTED_ADDRESS_FORMAT";
  readonly MULTISIG_MEMBER_OVERFLOW: "ERR_MULTISIG_MEMBER_OVERFLOW";
  readonly INVALID_MULTISIG_POLICY: "ERR_INVALID_MULTISIG_POLICY";
};

export class AccountAddressError extends Error {
  readonly code: (typeof AccountAddressErrorCode)[keyof typeof AccountAddressErrorCode];
  readonly details?: Record<string, unknown>;
  readonly cause?: unknown;
}

export const ValidationErrorCode: {
  readonly INVALID_STRING: "ERR_INVALID_STRING";
  readonly INVALID_HEX: "ERR_INVALID_HEX";
  readonly INVALID_MULTIHASH: "ERR_INVALID_MULTIHASH";
  readonly INVALID_ACCOUNT_ID: "ERR_INVALID_ACCOUNT_ID";
  readonly INVALID_ASSET_ID: "ERR_INVALID_ASSET_ID";
  readonly INVALID_ASSET_DEFINITION_ID: "ERR_INVALID_ASSET_DEFINITION_ID";
  readonly INVALID_IBAN: "ERR_INVALID_IBAN";
  readonly INVALID_OBJECT: "ERR_INVALID_OBJECT";
  readonly INVALID_METADATA: "ERR_INVALID_METADATA";
  readonly INVALID_JSON_VALUE: "ERR_INVALID_JSON_VALUE";
  readonly INVALID_NUMERIC: "ERR_INVALID_NUMERIC";
  readonly VALUE_OUT_OF_RANGE: "ERR_VALUE_OUT_OF_RANGE";
};

export class ValidationError extends TypeError {
  readonly code: (typeof ValidationErrorCode)[keyof typeof ValidationErrorCode];
  readonly path: string | null;
  readonly cause?: unknown;
}

export interface AccountAddressDisplay {
  i105: string;
  chainDiscriminant: number;
  i105Warning: string;
}

/** Normalized admitted controller with frozen records and caller-owned key-byte copies. */
export type AccountAddressControllerInfo =
  | {
      readonly tag: 0;
      readonly curve: number;
      readonly publicKey: Uint8Array;
    }
  | {
      readonly tag: 1;
      readonly version: number;
      readonly threshold: number;
      readonly members: ReadonlyArray<{
        readonly curve: number;
        readonly weight: number;
        readonly publicKey: Uint8Array;
      }>;
    };

export class AccountAddress {
  static fromAccount(options: {
    publicKey:
      | Buffer
      | Uint8Array
      | ArrayBuffer
      | ArrayBufferView
      | number[]
      | string;
    algorithm?: CryptoAlgorithm;
  }): AccountAddress;
  static fromCanonicalBytes(
    bytes: Buffer | Uint8Array | ArrayBuffer | ArrayBufferView,
  ): AccountAddress;
  static fromI105(
    encoded: string,
    expectedPrefix?: number | string | bigint,
  ): AccountAddress;
  static fromAccountId(
    accountId: string,
    expectedPrefix?: number | string | bigint,
  ): AccountAddress;
  static parseEncoded(
    input: string,
    expectedPrefix?: number | string | bigint,
  ): { address: AccountAddress; chainDiscriminant?: number };
  /** Return a fresh controller snapshot; mutable key-byte copies never alias the account. */
  controllerInfo(): AccountAddressControllerInfo;
  canonicalBytes(): Uint8Array;
  canonicalHex(): string;
  toI105(prefix?: number | string | bigint): string;
  toString(): string;
  displayFormats(
    chainDiscriminant?: number | string | bigint,
  ): AccountAddressDisplay;
}

export function encodeI105AccountAddress(
  canonicalBytes: Buffer | Uint8Array | ArrayBuffer | ArrayBufferView,
  options?: { chainDiscriminant?: number | string | bigint },
): string;
export function decodeI105AccountAddress(
  encoded: string,
  options?: { expectDiscriminant?: number | string | bigint },
): Uint8Array;

export interface InspectAccountIdOptions {
  chainDiscriminant?: number | string | bigint;
  expectDiscriminant?: number | string | bigint;
}

export interface AccountIdInspection {
  canonicalHex: string;
  i105: { value: string; chainDiscriminant: number };
  i105Warning: string;
}

export function inspectAccountId(
  accountId: string,
  options?: InspectAccountIdOptions,
): AccountIdInspection;

export interface MultisigProposalTtlPreview {
  effectiveTtlMs: number;
  policyCapMs: number;
  expiresAtMs: number;
  wasCapped: boolean;
}

export class MultisigSpec {
  readonly signatories: ReadonlyMap<string, number>;
  readonly quorum: number;
  readonly transactionTtlMs: number;
  previewProposalExpiry(options?: {
    requestedTtlMs?: number | bigint | null;
    nowMs?: number | bigint;
  }): MultisigProposalTtlPreview;
  enforceProposalTtl(options?: {
    requestedTtlMs?: number | bigint | null;
    nowMs?: number | bigint;
  }): MultisigProposalTtlPreview;
  toPayload(): {
    signatories: Record<string, number>;
    quorum: number;
    transaction_ttl_ms: number;
  };
  toJSON(prettyPrinted?: boolean): string;
}

export class MultisigSpecBuilder {
  setQuorum(quorum: number | bigint): this;
  setTransactionTtlMs(ttlMs: number | bigint): this;
  addSignatory(accountId: string, weight: number | bigint): this;
  removeSignatory(accountId: string): this;
  build(): MultisigSpec;
  toJSON(prettyPrinted?: boolean): string;
}

export interface MultisigSpecPayload {
  signatories: Record<string, number>;
  quorum: number;
  transaction_ttl_ms: number;
}

export type MultisigSpecLike = MultisigSpec | MultisigSpecPayload;

export type MultisigTriggerArgsPreset = "lifecycle" | "lookup";

export interface MultisigLifecycleTriggerArgsInput {
  action: string;
  requestId?: string;
  request_id?: string;
  fiId?: string | null;
  fi_id?: string | null;
  toAccountId?: string | null;
  to_account_id?: string | null;
  amountI64?: number | string | bigint | null;
  amount_i64?: number | string | bigint | null;
  requestedByActorId?: JsonValue;
  requested_by_actor_id?: JsonValue;
  createdAtMs?: number | string | bigint | null;
  created_at_ms?: number | string | bigint | null;
  expiresAtMs?: number | string | bigint | null;
  expires_at_ms?: number | string | bigint | null;
}

export interface MultisigLookupTriggerArgsInput {
  requestId?: string;
  request_id?: string;
  requestedByActorId?: JsonValue;
  requested_by_actor_id?: JsonValue;
}

export interface ExecuteTriggerInstructionPayload {
  ExecuteTrigger: {
    trigger: string;
    args: JsonValue | null;
  };
}

export interface MultisigExecuteTriggerOptions {
  trigger: string;
  args?: JsonValue;
  argPreset?: MultisigTriggerArgsPreset;
  preset?: MultisigTriggerArgsPreset;
  argInput?: MultisigLifecycleTriggerArgsInput | MultisigLookupTriggerArgsInput;
  presetInput?:
    | MultisigLifecycleTriggerArgsInput
    | MultisigLookupTriggerArgsInput;
  signerAccountId?: string;
  multisigSpec?: MultisigSpecLike;
  spec?: MultisigSpecLike;
  strictSignerCheck?: boolean;
}

export interface ProposeMultisigExecuteTriggerOptions
  extends MultisigExecuteTriggerOptions {
  accountId: string;
  spec: MultisigSpecLike;
  transactionTtlMs?: number | null;
}

export interface MultisigAccountSelector {
  multisigAccountId?: string;
  multisigAccountAlias?: string;
  multisig_account_id?: string;
  multisig_account_alias?: string;
}

export type MultisigProposalStatus =
  | "COLLECTING_SIGNATURES"
  | "FINALIZED"
  | "CANCELED"
  | "EXPIRED";

export interface MultisigProposalsQueryRequest extends MultisigAccountSelector {
  status?: ReadonlyArray<MultisigProposalStatus>;
  cursor?: string | null;
  limit?: number | string | bigint | null;
}

export interface MultisigProposalsResolveRequest extends MultisigAccountSelector {
  proposalId?: string | null;
  instructionsHash?: string | null;
  proposal_id?: string | null;
  instructions_hash?: string | null;
}

export type MultisigProposeInstructionInput =
  | object
  | string
  | BinaryLike
  | number[];

/**
 * Caller-trusted, off-wire binding for one locally signed transaction draft.
 * The archives must come from a trusted local builder or verified artifact,
 * never from the Torii draft response being checked.
 */
export interface LocalTransactionDraftIntent {
  executableB64: string;
  metadataB64: string;
}

/** Caller-trusted resolved contract and payload evidence for one unsigned call. */
export interface ContractCallDraftIntent extends LocalTransactionDraftIntent {
  contractAddress: string;
  codeHashHex: string;
  payloadDigestHex: string;
}

export interface MultisigProposeRequest extends MultisigAccountSelector {
  signerAccountId: string;
  instructions: MultisigProposeInstructionInput[];
  feePayment: NoritoFeePaymentIntent;
  publicKeyHex?: string | null;
  signatureB64?: string | null;
  creationTimeMs?: number | string | bigint | null;
  validation_fee_assessment?: RetailFeeAssessmentV1;
  memo?: string | null;
  draftIntent?: LocalTransactionDraftIntent;
  draft_intent?: LocalTransactionDraftIntent;
  multisig_account_id?: string;
  multisig_account_alias?: string;
  signer_account_id?: string;
  fee_payment?: NoritoFeePaymentIntent;
  public_key_hex?: string | null;
  signature_b64?: string | null;
  creation_time_ms?: number | string | bigint | null;
}

export interface MultisigProposePayload {
  multisig_account_id?: string;
  multisig_account_alias?: string;
  signer_account_id: string;
  instructions: string[];
  fee_payment: NoritoFeePaymentIntent;
  public_key_hex?: string;
  signature_b64?: string;
  creation_time_ms?: number;
  validation_fee_assessment?: RetailFeeAssessmentV1;
  memo?: string;
}

export interface MultisigContractCallProposeRequest
  extends MultisigAccountSelector {
  signerAccountId: string;
  contractAddress?: never;
  contractAlias: string;
  entrypoint: string;
  payload: Record<string, unknown>;
  feePayment: NoritoFeePaymentIntent;
  publicKeyHex?: string | null;
  signatureB64?: string | null;
  creationTimeMs?: number | string | bigint | null;
  draftIntent?: LocalTransactionDraftIntent;
  draft_intent?: LocalTransactionDraftIntent;
  multisig_account_id?: string;
  multisig_account_alias?: string;
  signer_account_id?: string;
  contract_address?: never;
  contract_alias?: string;
  fee_payment?: NoritoFeePaymentIntent;
  public_key_hex?: string | null;
  signature_b64?: string | null;
  creation_time_ms?: number | string | bigint | null;
}

export interface MultisigContractCallProposePayload {
  multisig_account_id?: string;
  multisig_account_alias?: string;
  signer_account_id: string;
  contract_address?: never;
  contract_alias: string;
  entrypoint: string;
  payload: Record<string, unknown>;
  fee_payment: NoritoFeePaymentIntent;
  public_key_hex?: string;
  signature_b64?: string;
  creation_time_ms?: number;
}

export interface MultisigContractCallApproveRequest
  extends MultisigAccountSelector {
  signerAccountId: string;
  proposalId?: string | null;
  instructionsHash?: string | null;
  feePayment: NoritoFeePaymentIntent;
  publicKeyHex?: string | null;
  signatureB64?: string | null;
  creationTimeMs?: number | string | bigint | null;
  draftIntent?: LocalTransactionDraftIntent;
  draft_intent?: LocalTransactionDraftIntent;
  multisig_account_id?: string;
  multisig_account_alias?: string;
  signer_account_id?: string;
  proposal_id?: string | null;
  instructions_hash?: string | null;
  fee_payment?: NoritoFeePaymentIntent;
  public_key_hex?: string | null;
  signature_b64?: string | null;
  creation_time_ms?: number | string | bigint | null;
  /** Exact current target fields are mandatory; no hash-only contract approval. */
  contract_alias: string;
  entrypoint: string;
  payload: Record<string, unknown>;
}

export interface MultisigContractCallApprovePayload {
  multisig_account_id?: string;
  multisig_account_alias?: string;
  signer_account_id: string;
  proposal_id?: string;
  instructions_hash?: string;
  fee_payment: NoritoFeePaymentIntent;
  public_key_hex?: string;
  signature_b64?: string;
  creation_time_ms?: number;
  /** Exact current target fields are mandatory; no hash-only contract approval. */
  contract_alias: string;
  entrypoint: string;
  payload: Record<string, unknown>;
}

export interface MultisigContractCallResponse {
  ok: boolean;
  resolved_multisig_account_id: string;
  submitted: boolean;
  proposal_id: string | null;
  instructions_hash: string | null;
  tx_hash_hex: string | null;
  executed_tx_hash_hex: string | null;
  creation_time_ms: number | null;
  fee_payment: NoritoFeePaymentIntent;
  transaction_payload_b64: string | null;
  signing_message_b64: string | null;
}

export interface MultisigSpecResponse {
  resolved_multisig_account_id: string;
  spec: JsonValue;
}

export interface MultisigProposalEntry {
  proposal_id: string;
  instructions_hash: string;
  operation_type: string;
  intent: JsonValue | null;
  proposal: JsonValue;
  status: MultisigProposalStatus;
  terminal_at_ms: number | null;
}

export interface MultisigProposalsQueryResponse {
  resolved_multisig_account_id: string;
  proposals: ReadonlyArray<MultisigProposalEntry>;
  next_cursor: string | null;
}

export interface MultisigProposalResolveResponse extends MultisigProposalEntry {
  resolved_multisig_account_id: string;
}

export interface SoradnsGatewayHosts {
  readonly normalizedName: string;
  readonly canonicalLabel: string;
  readonly canonicalHost: string;
  readonly canonicalWildcard: string;
  readonly prettyHost: string;
  readonly hostPatterns: ReadonlyArray<string>;
  matchesHost(host: string): boolean;
}

export interface SoradnsGatewayHostOptions {
  prettySuffix?: string;
}

export function deriveSoradnsGatewayHosts(
  fqdn: string,
  options?: SoradnsGatewayHostOptions,
): SoradnsGatewayHosts;
export function hostPatternsCoverDerivedHosts(
  patterns: Iterable<string>,
  derived: SoradnsGatewayHosts,
): boolean;
export function canonicalGatewaySuffix(): string;
export function canonicalGatewayWildcard(): string;
export function prettyGatewaySuffix(): string;
export function tairaMonPrettyGatewaySuffix(): string;

export interface IsoBridgeAgent {
  bic: string;
  lei?: string;
}

export interface IsoBridgeProxy {
  id: string;
  typeCode?: string;
  typeProprietary?: string;
}

export interface IsoBridgeAccount {
  iban?: string;
  otherId?: string;
  proxy?: IsoBridgeProxy;
}

export interface IsoBridgeParty {
  name: string;
  lei?: string;
  identifier?: string;
  identifierScheme?: string;
}

export interface IsoBridgeAmount {
  currency: string;
  value?: string | number;
  amount?: string | number;
}

export interface DefiOracleAttestationQuery {
  baseUrl?: string;
  toriiUrl?: string;
  domain: number | string;
  subjectId: number | string;
  status?: number | string;
}

export function queryOracleFeeds(
  baseUrl: string,
  options?: Record<string, string | number | boolean | undefined>,
): Promise<JsonValue>;
export function queryOracleFeedHistory(
  baseUrl: string,
  feedId: string,
  options?: Record<string, string | number | boolean | undefined>,
): Promise<JsonValue>;
export function getLatestDefiOracleAttestation(
  query: DefiOracleAttestationQuery,
): Promise<JsonValue>;

export interface BuildPacs008Options {
  messageId: string;
  creationDateTime: string | Date;
  instructionId: string;
  endToEndId?: string;
  transactionId?: string;
  settlementDate?: string | Date;
  amount: IsoBridgeAmount;
  instigatingAgent: IsoBridgeAgent;
  instructedAgent: IsoBridgeAgent;
  debtorAgent?: IsoBridgeAgent;
  creditorAgent?: IsoBridgeAgent;
  debtor?: IsoBridgeParty;
  creditor?: IsoBridgeParty;
  debtorAccount?: IsoBridgeAccount;
  creditorAccount?: IsoBridgeAccount;
  purposeCode?: string;
  remittanceInformation?: string | string[];
  supplementaryData?: Record<string, unknown>;
}

export interface BuildPacs009Options {
  messageId?: string;
  businessMessageId?: string;
  messageDefinitionId?: string;
  creationDateTime: string | Date;
  instructionId: string;
  transactionId?: string;
  settlementDate?: string | Date;
  amount: IsoBridgeAmount;
  instigatingAgent: IsoBridgeAgent;
  instructedAgent: IsoBridgeAgent;
  debtorAgent?: IsoBridgeAgent;
  creditorAgent?: IsoBridgeAgent;
  debtor?: IsoBridgeParty;
  creditor?: IsoBridgeParty;
  debtorAccount?: IsoBridgeAccount;
  creditorAccount?: IsoBridgeAccount;
  purposeCode?: string;
  remittanceInformation?: string | string[];
  supplementaryData?: Record<string, unknown>;
}

export function buildPacs008Message(options: BuildPacs008Options): string;
export function buildPacs009Message(options: BuildPacs009Options): string;
export interface SampleIsoMessageOptions {
  messageSuffix?: string;
  creationDateTime?: string | Date;
  settlementDate?: string | Date;
}
export function buildSamplePacs008Message(
  options?: SampleIsoMessageOptions,
): string;
export function buildSamplePacs009Message(
  options?: SampleIsoMessageOptions,
): string;
export interface CamtReportBalance {
  typeCode?: string;
  amount: IsoBridgeAmount;
  creditDebitIndicator: "CRDT" | "DBIT";
  asOfDateTime?: string | Date;
}
export interface CamtReportEntry {
  amount: IsoBridgeAmount;
  creditDebitIndicator: "CRDT" | "DBIT";
  status?: string;
  bookingDate?: string | Date;
  valueDate?: string | Date;
  reference?: string;
}
export interface CamtReportSummary {
  entryCount?: number;
  sum?: string | number;
  netAmount?: string | number;
  netCreditDebitIndicator?: "CRDT" | "DBIT";
}
export interface BuildCamt052Options {
  messageId: string;
  creationDateTime: string | Date;
  reportId: string;
  pagination?: {
    pageNumber: number;
    lastPage?: boolean;
  };
  sequenceNumber?: number;
  fromDateTime?: string | Date;
  toDateTime?: string | Date;
  account: IsoBridgeAccount;
  accountCurrency?: string;
  balances?: CamtReportBalance[];
  entries?: CamtReportEntry[];
  summary?: CamtReportSummary;
}
export interface BuildCamt056Options {
  assignmentId: string;
  creationDateTime: string | Date;
  cancellationId: string;
  assignerAgent: IsoBridgeAgent;
  assigneeAgent: IsoBridgeAgent;
  debtorAgent: IsoBridgeAgent;
  creditorAgent: IsoBridgeAgent;
  debtor?: IsoBridgeParty;
  debtorAccount?: IsoBridgeAccount;
  creditor?: IsoBridgeParty;
  creditorAccount?: IsoBridgeAccount;
  originalMessageId: string;
  originalMessageNameId: string;
  originalInstructionId?: string;
  originalEndToEndId?: string;
  originalTransactionId?: string;
  originalUetr?: string;
  serviceLevelCode?: string;
  interbankSettlementAmount: IsoBridgeAmount;
  interbankSettlementDate: string | Date;
  caseId?: string;
  caseCreatorName?: string;
}
export type SampleCamtMessageOptions = SampleIsoMessageOptions;
export function buildCamt052Message(options: BuildCamt052Options): string;
export function buildSampleCamt052Message(
  options?: SampleCamtMessageOptions,
): string;
export function buildCamt056Message(options: BuildCamt056Options): string;
export function buildSampleCamt056Message(
  options?: SampleCamtMessageOptions,
): string;

/**
 * Numeric values accepted by non-quantity helpers. Quantity-bearing APIs use
 * {@link QuantityInput} so JavaScript `number` can never lose precision.
 */
export type NumericLike = string | number | bigint;

/** Lossless canonical input accepted by asset and RWA quantity builders. */
export type QuantityInput = KotodamaQuantity | string | bigint;

/**
 * Metadata payload accepted by transaction helpers. Objects are stringified
 * with deterministic key ordering; strings are passed through unchanged.
 */
export type MetadataLike = object | string | null;

/**
 * Inputs accepted where 32-byte hashes are required. Strings may be canonical
 * `hash:…#…` literals or raw hex; binary inputs are converted automatically.
 */
export type HashLike = string | Buffer | ArrayBuffer | ArrayBufferView;

export type BinaryLike =
  | Buffer
  | ArrayBuffer
  | ArrayBufferView
  | ReadonlyArray<number>
  | string;

export type VerifyingKeyIdLike = string | { backend: string; name: string };

/** Exact JSON labels for the two generic OpenVerify engines in Norito order. */
export type OpenVerifyBackendTag = "halo2-ipa-pasta" | "stark";

export interface OpenVerifyEnvelope {
  backend: OpenVerifyBackendTag;
  circuit_id: string;
  vk_hash: BinaryLike;
  public_inputs: BinaryLike;
  proof_bytes: BinaryLike;
  aux?: BinaryLike;
}

export interface ProofAttachmentInput {
  backend: string;
  proof: BinaryLike;
  verifyingKeyRef: { backend: string; name: string };
  verifyingKeyCommitment?: BinaryLike | null;
  envelopeHash?: BinaryLike | null;
  lanePrivacy?: {
    commitmentId: number;
    merkle: {
      leaf: BinaryLike;
      leafIndex: number;
      auditPath: BinaryLike[];
    };
  } | null;
}

/**
 * Canonicalise an account identifier to i105.
 *
 * Accepts only encoded i105 account ids.
 * Domain-suffixed literals (`<id>@domain`) and canonical-hex account literals are rejected.
 */
export function normalizeAccountId(value: string, name?: string): string;
export function ensureCanonicalAccountId(value: string, name?: string): string;
export function normalizeI105AccountId(value: string, name?: string): string;
export type IdentifierNormalization =
  | "exact"
  | "lowercase_trimmed"
  | "phone_e164"
  | "email_address"
  | "account_number";
export function normalizeIdentifierInput(
  value: string,
  normalization: IdentifierNormalization,
  name?: string,
): string;
export function tryNormalizeI105AccountId(
  value: unknown,
  name?: string,
): string | null;
export function normalizeToriiAccountReference(
  value: unknown,
  name?: string,
): string;
export function normalizeAccountAliasFqn(value: string, name?: string): string;
export function tryNormalizeAccountAliasFqn(
  value: unknown,
  name?: string,
): string | null;

/**
 * Canonicalise a public asset identifier to bare Base58 form.
 * Asset aliases (`name#dataspace` / `name#domain.dataspace`) must be resolved first.
 */
export function normalizeAssetId(value: string, name?: string): string;
export function normalizeAssetDefinitionId(
  value: string,
  name?: string,
): string;
export function tryNormalizeAssetDefinitionId(
  value: unknown,
  name?: string,
): string | null;
export function normalizeAssetAliasFqn(value: string, name?: string): string;
export function tryNormalizeAssetAliasFqn(
  value: unknown,
  name?: string,
): string | null;

/**
 * Canonicalise an internal asset-holding identifier in
 * `<base58-asset-definition-id>#<i105-account-id>` form.
 */
export function normalizeAssetHoldingId(value: string, name?: string): string;
export function composeAssetHoldingId(
  assetId: string,
  accountId: string,
  dataspaceId?: string | number | null,
  name?: string,
): string;
export function extractAssetDefinitionId(value: string, name?: string): string;
export function tryExtractAssetDefinitionId(
  value: unknown,
  name?: string,
): string | null;
export function assetReferencesMatch(left: unknown, right: unknown): boolean;

/**
 * Canonicalise an RWA identifier in `<64-hex-hash>$<domain>` form.
 */
export function normalizeRwaId(value: string, name?: string): string;

export function blake2b256(
  data: Buffer | Uint8Array | ArrayBuffer | ArrayBufferView,
  options?: {
    personalization?: Buffer | Uint8Array | ArrayBuffer | ArrayBufferView;
    includeZeroKeyBlock?: boolean;
  },
): Uint8Array;

export const IVM_PROGRAM_HEADER_LENGTH: 49;
export const IVM_ARTIFACT_MAX_BYTES: 4194304;

/** Compute ledger/Core body identity and full-artifact SHA-256 identity. */
export function computeIvmArtifactHashes(
  artifact: Uint8Array | ArrayBuffer | ArrayBufferView,
): {
  codeHashHex: string;
  artifactSha256Hex: string;
};

export interface ConfidentialGasSchedule {
  proofBase: number;
  perPublicInput: number;
  perProofByte: number;
  perNullifier: number;
  perCommitment: number;
}

export function extractConfidentialGasConfig(
  input?: { config?: unknown } | unknown,
): ConfidentialGasSchedule | null;

export interface ContractEventStreamOptions {
  authority?: string;
  contractAddress?: string;
  contractAlias?: string;
  module?: string;
  eventKind?: string;
  participant?: string;
  assetId?: string;
  provenance?: string;
  sinceTimestampMs?: NumericLike;
  untilTimestampMs?: NumericLike;
  resultOk?: boolean;
  signal?: AbortSignal;
}

export interface CanonicalRequestAuth {
  /** Exact canonical I105 account or canonical ASCII account alias. */
  accountId: string;
  privateKey:
    | Buffer
    | Uint8Array
    | ArrayBuffer
    | ArrayBufferView
    | string
    | number[];
}

export interface PermissionedIterableOptions {
  requirePermissions?: boolean;
  canonicalAuth?: CanonicalRequestAuth | null;
}

export type ToriiCountMode = "bounded" | "exact";

export interface ToriiBrowserContractEventStreamOptions {
  authority?: string;
  contractAddress?: string;
  contract_address?: string;
  contractAlias?: string;
  contract_alias?: string;
  module?: string;
  eventKind?: string;
  event_kind?: string;
  participant?: string;
  assetId?: string;
  asset_id?: string;
  provenance?: "emitted" | "derived";
  sinceTimestampMs?: NumericLike;
  since_timestamp_ms?: NumericLike;
  untilTimestampMs?: NumericLike;
  until_timestamp_ms?: NumericLike;
  resultOk?: boolean;
  result_ok?: boolean;
  signal?: AbortSignal;
}

export interface IterableListOptions extends PermissionedIterableOptions {
  limit?: NumericLike;
  offset?: NumericLike;
  filter?: string | Record<string, unknown>;
  sort?: string | ReadonlyArray<{ key: string; order?: "asc" | "desc" }>;
  countMode?: ToriiCountMode;
  count_mode?: ToriiCountMode;
  signal?: AbortSignal;
}

export interface IterableQueryOptions extends IterableListOptions {
  fetch_size?: NumericLike;
  queryName?: string;
  query_name?: string;
  select?: ReadonlyArray<string | Record<string, unknown>>;
}

export interface PaginationIteratorOptions extends IterableListOptions {
  pageSize?: NumericLike;
  maxItems?: NumericLike;
}

export interface ConnectAppListOptions {
  limit?: NumericLike;
  cursor?: string;
  signal?: AbortSignal;
}

export interface ConnectAppIteratorOptions extends ConnectAppListOptions {
  pageSize?: NumericLike;
  maxItems?: NumericLike;
}

export interface RepoLegDto {
  assetDefinitionId: string;
  quantity: string;
  metadata: unknown;
}

export interface RepoGovernanceDto {
  haircutBps: number;
  marginFrequencySecs: number;
}

export interface ToriiRepoAgreement extends RepoAgreementLifecycleFields {
  id: string;
  initiator: string;
  counterparty: string;
  custodian: string | null;
  cashLeg: RepoLegDto;
  collateralLeg: RepoLegDto;
  rateBps: number;
  maturityTimestampMs: number;
  initiatedTimestampMs: number;
  lastMarginCheckTimestampMs: number;
  governance: RepoGovernanceDto;
}

export interface TriggerListOptions {
  namespace?: string;
  authority?: string;
  limit?: NumericLike;
  offset?: NumericLike;
  signal?: AbortSignal;
}

export interface TriggerIteratorOptions extends TriggerListOptions {
  pageSize?: NumericLike;
  maxItems?: NumericLike;
}

export interface TriggerQueryIteratorOptions extends IterableQueryOptions {
  pageSize?: NumericLike;
  maxItems?: NumericLike;
}

export type SubscriptionStatus =
  | "active"
  | "paused"
  | "past_due"
  | "canceled"
  | "suspended";

export interface ToriiIterableListResponse<T = unknown> {
  items: ReadonlyArray<T>;
  total: number;
}

export interface AliasResolutionDto {
  alias: string;
  account_id: string;
  index?: number;
  source?: string;
}

export interface CanonicalRequestOptions {
  signal?: AbortSignal;
  canonicalAuth?: CanonicalRequestAuth;
}

export interface RequiredCanonicalRequestOptions {
  signal?: AbortSignal;
  canonicalAuth: CanonicalRequestAuth;
}

export interface AbortSignalOptions {
  signal?: AbortSignal;
}

export interface AliasLookupByAccountItem {
  alias: string;
  dataspace: string;
  domain: string | null;
  is_primary: boolean;
}

export interface AliasLookupByAccountResponse {
  account_id: string;
  total: number;
  items: ReadonlyArray<AliasLookupByAccountItem>;
}

export interface AliasLookupByAccountOptions extends CanonicalRequestOptions {
  dataspace?: string;
  domain?: string;
}

export interface RetailRecipientLookupRequest {
  accountId?: string;
  account_id?: string;
  aliasFqn?: string;
  alias_fqn?: string;
}

export interface RetailRecipientLookupResponse {
  resolved: boolean;
  account_id: string;
  alias_fqn: string;
  fi_id: "hbl.sbp" | "ubl.sbp";
  full_name?: string;
}

export interface RetailRecipientRouteResponse {
  account_id: string;
  alias_fqn: string;
  fi_id: "hbl.sbp" | "ubl.sbp";
}

export interface FeeSponsorProgramId {
  sponsor: string;
  name: string;
}

export type FeeSponsorProgramLifecycleState =
  | "staged"
  | "paused"
  | "active"
  | "closing"
  | "closed";

export interface FeeSponsorProgram {
  id: FeeSponsorProgramId;
  payout_account: string;
  lifecycle: { state: FeeSponsorProgramLifecycleState; value: null };
  active_revision?: ToriiU64;
  staged_revision?: ToriiU64;
  scheduled_activation?: {
    revision: ToriiU64;
    activate_at_height: ToriiU64;
  };
}

export interface NoritoFeeChargeKind {
  kind: "nexus" | "pipeline_gas";
  value: null;
}

export interface NoritoFeeChargeLimit {
  kind: NoritoFeeChargeKind;
  asset_definition_id: string;
  max_amount: string;
}

export type NoritoFeePaymentIntent =
  | {
      payer: "authority";
      value: {
        charge_limits: ReadonlyArray<NoritoFeeChargeLimit>;
        gas_limit: number | null;
      };
    }
  | {
      payer: "sponsor";
      value: {
        program_id: FeeSponsorProgramId;
        program_revision: number;
        charge_limits: ReadonlyArray<NoritoFeeChargeLimit>;
        gas_limit: number | null;
      };
    };

export type FeeDebitSource =
  | { kind: "account"; value: string }
  | { kind: "sponsor_program"; value: FeeSponsorProgramId };

export interface FeeQuoteResponse {
  intent: NoritoFeePaymentIntent;
  observation: {
    ledger_time_ms: number;
    next_block_height: number;
    route_dataspace_id: number;
  };
  components: ReadonlyArray<{
    kind: NoritoFeeChargeKind;
    asset_definition_id: string;
    max_amount: string;
  }>;
  capacities: ReadonlyArray<{
    asset_definition_id: string;
    vault_balance: string;
    reserve_floor: string;
    block_remaining: string;
    program_epoch_remaining: string;
    beneficiary_epoch_remaining: string;
  }>;
  decision: {
    status: "accepted";
    value:
      | {
          debit_source: { kind: "account"; value: string };
          program_revision: null;
        }
      | {
          debit_source: { kind: "sponsor_program"; value: FeeSponsorProgramId };
          program_revision: number;
        };
  };
}

export type FeeRejectionCode =
  | "invalid_fee_intent"
  | "program_not_found"
  | "revision_not_found"
  | "revision_not_active"
  | "program_not_active"
  | "beneficiary_not_eligible"
  | "operation_not_allowed"
  | "operation_denied"
  | "invalid_gas_limit"
  | "fee_asset_not_covered"
  | "signed_limit_exceeded"
  | "program_transaction_limit_exceeded"
  | "program_block_budget_exhausted"
  | "program_epoch_budget_exhausted"
  | "beneficiary_epoch_budget_exhausted"
  | "vault_insufficient"
  | "authority_payer_insufficient"
  | "relay_capacity_unavailable"
  | "invalid_program_configuration";

export type IdentifierBfvInteger = number | bigint;

export interface IdentifierBfvParameters {
  polynomial_degree: number;
  plaintext_modulus: IdentifierBfvInteger;
  ciphertext_modulus: IdentifierBfvInteger;
  decomposition_base_log: number;
}

export interface IdentifierBfvPublicKey {
  b: ReadonlyArray<IdentifierBfvInteger>;
  a: ReadonlyArray<IdentifierBfvInteger>;
}

export interface IdentifierBfvPublicParameters {
  parameters: IdentifierBfvParameters;
  public_key: IdentifierBfvPublicKey;
  max_input_bytes: number;
  norito_length_encoding?: string;
}

export interface RamLfeProgramProfile {
  /** Canonical hash binding the compiled secret commitment and initializer. */
  initializer_descriptor_hash: string;
  profile_version: number;
  register_count: number;
  memory_lane_count: number;
  ciphertext_mul_per_step: number;
  encrypted_input_mode: "encrypted_envelope_v1";
  min_ciphertext_modulus: IdentifierBfvInteger;
}

export interface RamLfeProofVerifierMetadata {
  proof_backend: string;
  circuit_id: string;
  public_inputs_schema_hash: string;
  verifying_key_bytes_b64: string;
}

/** Current RAM-LFE wire tags; a recognized tag does not imply production encryption support. */
export type RamLfeBackend = "hkdf-sha3-512-prf-v1" | "bfv-affine-v1" | "bfv-programmed-v1";
export type RamLfeVerificationMode = "signed" | "proof";

export interface RamLfeProgramPolicySummary {
  program_id: string;
  owner: string;
  active: boolean;
  resolver_public_key: string;
  output_opening_public_key: string;
  backend: RamLfeBackend;
  verification_mode: RamLfeVerificationMode;
  input_encryption?: string;
  input_encryption_public_parameters?: string;
  input_encryption_public_parameters_decoded?: IdentifierBfvPublicParameters;
  ram_fhe_profile?: RamLfeProgramProfile;
  proof_verifier?: RamLfeProofVerifierMetadata;
  note?: string;
}

export interface RamLfeProgramPolicyListResponse {
  total: number;
  items: ReadonlyArray<RamLfeProgramPolicySummary>;
}

export interface IdentifierPolicySummary {
  policy_id: string;
  program_id: string;
  owner: string;
  active: boolean;
  normalization: string;
  resolver_public_key: string;
  output_opening_public_key: string;
  phone_retail_attestor_public_key?: string;
  backend: RamLfeBackend;
  input_encryption?: string;
  input_encryption_public_parameters?: string;
  input_encryption_public_parameters_decoded?: IdentifierBfvPublicParameters;
  ram_fhe_profile?: RamLfeProgramProfile;
  proof_verifier?: RamLfeProofVerifierMetadata;
  note?: string;
}

export interface IdentifierPolicyListResponse {
  total: number;
  items: ReadonlyArray<IdentifierPolicySummary>;
}

export type IdentifierPolicyClientSummary = Omit<
  IdentifierPolicySummary,
  "program_id" | "output_opening_public_key"
> &
  Partial<
    Pick<IdentifierPolicySummary, "program_id" | "output_opening_public_key">
  >;

export interface RamLfeOutputOpeningPayload {
  program_id: string;
  input_ciphertext_hash: string;
  output_ciphertext_hash: string;
  parameter_digest: string;
  evaluation_key_digest: string;
  opened_output_hash: string;
  opened_at_ms: number;
  expires_at_ms: number | null;
}

export interface RamLfeOutputOpening {
  payload: RamLfeOutputOpeningPayload;
  signature: string;
}

export interface RamLfeExecutionReceiptPayload {
  program_id: string;
  program_digest: string;
  backend: RamLfeBackend;
  verification_mode: RamLfeVerificationMode;
  input_ciphertext_hash: string;
  output_ciphertext_hash: string;
  parameter_digest: string;
  evaluation_key_digest: string;
  output_hash: string;
  associated_data_hash: string;
  executed_at_ms: number;
  expires_at_ms: number | null;
}

export type RamLfeReceiptAttestation =
  | { kind: "signed"; signature: string }
  | { kind: "proof"; proof_backend: string; proof_b64: string };

export interface RamLfeExecutionReceipt {
  payload: RamLfeExecutionReceiptPayload;
  attestation: RamLfeReceiptAttestation;
}

export interface RamLfeExecuteOptions {
  encryptedInput: string;
  signal?: AbortSignal;
  canonicalAuth: CanonicalRequestAuth;
}

export interface RamLfeExecuteResponse {
  program_id: string;
  opaque_hash: string;
  receipt_hash: string;
  output_ciphertext: string;
  output_hash: string;
  associated_data_hash: string;
  executed_at_ms: number;
  expires_at_ms: number | null;
  backend: RamLfeBackend;
  verification_mode: RamLfeVerificationMode;
  receipt: RamLfeExecutionReceipt;
}

export interface IdentifierResolutionRequestOptions {
  policyId: string;
  encryptedInput: string;
  outputOpening: RamLfeOutputOpening;
  signal?: AbortSignal;
  canonicalAuth: CanonicalRequestAuth;
}

export interface IdentifierResolutionReceiptPayload {
  policy_id: string;
  execution: RamLfeExecutionReceiptPayload;
  opening: RamLfeOutputOpening;
  opaque_id: string;
  receipt_hash: string;
  uaid: string;
  account_id: string;
}

export interface IdentifierResolutionReceipt {
  payload: IdentifierResolutionReceiptPayload;
  attestation: RamLfeReceiptAttestation;
}

export interface IdentifierClaimLookupResponse {
  policy_id: string;
  opaque_id: string;
  receipt_hash: string;
  uaid: string;
  account_id: string;
  verified_at_ms: number;
  expires_at_ms: number | null;
}

export interface ToriiAssetDefinitionAliasBinding {
  alias: string;
  status:
    | "permanent"
    | "leased_active"
    | "leased_grace"
    | "expired_pending_cleanup";
  lease_expiry_ms?: number | null;
  grace_until_ms?: number | null;
  bound_at_ms: number;
}

export interface ToriiAccountHistoryItem {
  block_height: number;
  block_index: number;
  movement_index: number;
  id: string;
  source: string;
  type: string;
  timestamp_ms?: number;
  status: string;
  result_ok?: boolean;
  direction: string;
  account_id: string;
  counterparty_account_id?: string;
  asset_id?: string;
  asset_definition_id?: string;
  amount?: string;
  tx_hash?: string;
  operation_id?: string;
  expires_at_ms?: number;
  finalized_at_ms?: number;
  requesting_fi_id?: string;
}

export interface ToriiContractActivityItem {
  block_height: number;
  block_index: number;
  authority?: string;
  timestamp_ms?: number;
  entrypoint_hash: string;
  result_ok: boolean;
  contract_address: string;
  contract_alias?: string;
  contract_entrypoint?: string;
  contract_payload?: JsonValue;
  fee_payment?: NoritoFeePaymentIntent;
}

export interface ToriiContractEventItem {
  block_index: number;
  event_id: string;
  schema_version: number;
  provenance: "emitted" | "derived";
  authority?: string;
  timestamp_ms?: number;
  tx_hash_hex: string;
  block_height: number;
  block_hash_hex: string;
  result_ok: boolean;
  contract_address: string;
  contract_alias?: string;
  module: string;
  event_kind: string;
  participants?: ReadonlyArray<string>;
  asset_ids?: ReadonlyArray<string>;
  numeric_fields?: JsonValue;
  payload?: JsonValue;
  fee_payment?: NoritoFeePaymentIntent;
}

export interface ToriiProverReport {
  id: string;
  ok: boolean;
  error: string | null;
  content_type: string;
  size: number;
  created_ms: number;
  processed_ms: number;
  latency_ms: number;
  zk1_tags: ReadonlyArray<string> | null;
}

export interface ToriiProverReportIdList {
  kind: "ids";
  ids: ReadonlyArray<string>;
}

export interface ToriiProverReportMessageSummary {
  id: string;
  error: string | null;
}

export interface ToriiProverReportMessagesList {
  kind: "messages";
  messages: ReadonlyArray<ToriiProverReportMessageSummary>;
}

export interface ToriiProverReportFilters {
  okOnly?: boolean;
  failedOnly?: boolean;
  errorsOnly?: boolean;
  idsOnly?: boolean;
  messagesOnly?: boolean;
  latest?: boolean;
  contentType?: string;
  hasTag?: string;
  id?: string;
  limit?: NumericLike;
  offset?: NumericLike;
  sinceMs?: NumericLike;
  beforeMs?: NumericLike;
  order?: "asc" | "desc";
}

export interface ToriiProverReportCollection {
  kind: "reports";
  reports: ReadonlyArray<ToriiProverReport>;
}

export type ToriiProverReportListResult =
  | ToriiProverReportCollection
  | ToriiProverReportIdList
  | ToriiProverReportMessagesList;

export interface ToriiAttachmentMetadata {
  id: string;
  contentType: string;
  size: number;
  createdMs: number;
  tenant: string | null;
}

export type ToriiVerifyingKeyStatus = "Proposed" | "Active" | "Withdrawn";

/** Exact verifier-registry labels admitted by the native Rust dispatcher. */
export type ToriiVerifierBackendLabelV1 =
  | "halo2/ipa"
  | "halo2/pasta/kaigi-authorization-v1"
  | "halo2/pasta/kaigi-usage-v1"
  | "halo2/pasta/confidential-transfer-2x2-merkle16-axiom-poseidon-v3"
  | "halo2/pasta/confidential-unshield-full-merkle16-axiom-poseidon-v3"
  | "halo2/pasta/confidential-unshield-change-merkle16-axiom-poseidon-v4"
  | "stark/fri/poseidon-x7-goldilocks-6x64-v1";

/** Canonical low-level proof-engine label stored in a verifier record. */
export type ToriiVerifierEngineLabelV1 = "halo2-ipa-pasta" | "stark";

export interface ToriiVerifyingKeyInline {
  backend: ToriiVerifierBackendLabelV1;
  bytes_b64: string;
}

export interface ToriiVerifyingKeyRecord {
  version: number;
  circuit_id: string;
  owner_manifest_id: string | null;
  namespace: string;
  backend: ToriiVerifierEngineLabelV1;
  curve: string;
  public_inputs_schema_hash: string;
  commitment_hex: string;
  vk_len: number;
  max_proof_bytes: number;
  gas_schedule_id: string | null;
  metadata_uri_cid: string | null;
  vk_bytes_cid: string | null;
  activation_height: number | null;
  withdraw_height: number | null;
  status: ToriiVerifyingKeyStatus;
  inline_key: ToriiVerifyingKeyInline | null;
}

export interface ToriiVerifyingKeyId {
  backend: ToriiVerifierBackendLabelV1;
  name: string;
}

export interface ToriiVerifyingKeyDetail {
  id: ToriiVerifyingKeyId;
  record: ToriiVerifyingKeyRecord;
  record_norito_base64: string;
}

export interface ToriiVerifyingKeyListItem {
  id: ToriiVerifyingKeyId;
  record: ToriiVerifyingKeyRecord | null;
}

export interface ToriiVerifyingKeyListOptions {
  backend?: ToriiVerifierBackendLabelV1;
  status?: ToriiVerifyingKeyStatus;
  nameContains?: string;
  limit?: NumericLike;
  offset?: NumericLike;
  order?: "asc" | "desc";
  idsOnly?: boolean;
  signal?: AbortSignal | null;
}

export interface ToriiVerifyingKeyTransactionDraft {
  readonly submitted: false;
  readonly transaction_payload_b64: string;
  readonly signing_message_b64: string;
}

export interface AppApiTransactionDraft {
  readonly submitted: false;
  readonly transaction_payload_b64: string;
  readonly signing_message_b64: string;
}

export interface ToriiVerifyingKeyRegisterPayload {
  authority: string;
  backend: ToriiVerifierBackendLabelV1;
  name: string;
  version: NumericLike;
  circuit_id: string;
  public_inputs_schema_hash_hex: string;
  gas_schedule_id: string;
  curve?: string;
  max_proof_bytes?: NumericLike;
  metadata_uri_cid?: string;
  vk_bytes_cid?: string;
  activation_height?: NumericLike;
  withdraw_height?: NumericLike;
  commitment_hex?: string;
  vk_bytes?: Buffer | ArrayBuffer | ArrayBufferView | string;
  vk_len?: NumericLike;
  status?: ToriiVerifyingKeyStatus;
}

export interface ToriiVerifyingKeyUpdatePayload {
  authority: string;
  backend: ToriiVerifierBackendLabelV1;
  name: string;
  version: NumericLike;
  circuit_id: string;
  public_inputs_schema_hash_hex: string;
  gas_schedule_id?: string;
  curve?: string;
  max_proof_bytes?: NumericLike;
  metadata_uri_cid?: string;
  vk_bytes_cid?: string;
  activation_height?: NumericLike;
  withdraw_height?: NumericLike;
  commitment_hex?: string;
  vk_bytes?: Buffer | ArrayBuffer | ArrayBufferView | string;
  vk_len?: NumericLike;
  status?: ToriiVerifyingKeyStatus;
}

export interface ToriiPeerRecord {
  address: string;
  public_key_hex: string;
}

export interface ToriiTelemetryPeerInfo {
  url: string;
  connected: boolean;
  telemetryUnsupported: boolean;
  config?: ToriiTelemetryPeerConfig;
  location?: ToriiTelemetryPeerLocation;
  connectedPeers?: ReadonlyArray<string>;
}

export interface ToriiTelemetryPeerConfig {
  publicKey: string;
  queueCapacity?: number;
  networkBlockGossipSize?: number;
  networkBlockGossipPeriodMs?: number;
  networkTxGossipSize?: number;
  networkTxGossipPeriodMs?: number;
}

export interface ToriiTelemetryPeerLocation {
  lat: number;
  lon: number;
  country: string;
  city: string;
}

export interface ToriiExplorerMetricsSnapshot {
  peers: number;
  domains: number;
  accounts: number;
  assets: number;
  transactionsAccepted: number;
  transactionsRejected: number;
  blockHeight: number;
  blockCreatedAt: string | null;
  finalizedBlockHeight: number;
  averageCommitTimeMs: number | null;
  averageBlockTimeMs: number | null;
}

/** Snapshot-bound seek metadata for Explorer chain-history collections. */
/** Seek-pagination metadata for canonical Explorer world collections. */
export interface ToriiExplorerNft {
  id: string;
  ownedBy: string;
  metadata: Record<string, unknown>;
}

export interface ToriiExplorerRwa {
  id: string;
  ownedBy: string;
  quantity: string;
  heldQuantity: string;
  primaryReference: string;
  status: string | null;
  isFrozen: boolean;
  metadata: Record<string, JsonValue>;
  raw: Record<string, JsonValue>;
}

export interface ToriiExplorerBlock {
  hash: string;
  height: number;
  createdAt: string;
  prevBlockHash: string | null;
  transactionsHash: string | null;
  transactionsRejected: number;
  transactionsTotal: number;
}

export interface ToriiExplorerAccountQrSnapshot {
  canonicalId: string;
  literal: string;
  networkPrefix: number;
  errorCorrection: string;
  modules: number;
  qrVersion: number;
  svg: string;
}

export interface ToriiVpnProfile {
  available: boolean;
  relayEndpoint: string;
  supportedExitClasses: ReadonlyArray<string>;
  defaultExitClass: string;
  leaseSecs: number;
  dnsPushIntervalSecs: number;
  meterFamily: string;
  routePushes: ReadonlyArray<string>;
  excludedRoutes: ReadonlyArray<string>;
  dnsServers: ReadonlyArray<string>;
  tunnelAddresses: ReadonlyArray<string>;
  mtuBytes: number;
  displayBillingLabel: string;
  operatorAccountId: string;
  leaseFee: string;
  settlementGraceSecs: number;
  flowLabelBits: number;
  paddingBudgetMs: number;
  relayIdHex: string;
  relayMldsa65PublicKeyHex: string;
  descriptorCommitHex: string;
  tlsServerName: string;
  relayTlsSpkiSha256Hex: string;
  relayCertificateSha256Hex: string;
  directorySnapshotDigestHex: string;
}

export interface ToriiVpnTxInstruction {
  wireId: string;
  payloadHex: string;
}

export interface ToriiVpnQuote {
  quoteId: string;
  leaseIdHex: string;
  /** Canonical 16-byte session ID encoded as 32 lowercase hex characters. */
  sessionIdHex: string;
  paymentReference: string;
  accountId: string;
  exitClass: string;
  relayEndpoint: string;
  leaseSecs: number;
  quoteExpiresAtMs: number;
  feeAssetId: string;
  escrowAccountId: string;
  operatorAccountId: string;
  leaseFee: string;
  routePushes: ReadonlyArray<string>;
  excludedRoutes: ReadonlyArray<string>;
  dnsServers: ReadonlyArray<string>;
  tunnelAddresses: ReadonlyArray<string>;
  mtuBytes: number;
  meterFamily: string;
  flowLabelBits: number;
  paddingBudgetMs: number;
  relayIdHex: string;
  relayMldsa65PublicKeyHex: string;
  descriptorCommitHex: string;
  tlsServerName: string;
  relayTlsSpkiSha256Hex: string;
  relayCertificateSha256Hex: string;
  directorySnapshotDigestHex: string;
  meteringPublicKeyHex: string;
  openLeaseInstruction: ToriiVpnTxInstruction;
}

export interface ToriiVpnSession {
  /** Canonical 16-byte session ID encoded as 32 lowercase hex characters. */
  sessionId: string;
  accountId: string;
  exitClass: string;
  relayEndpoint: string;
  leaseSecs: number;
  expiresAtMs: number;
  connectedAtMs: number;
  meterFamily: string;
  quoteId: string;
  paymentReference: string;
  paymentTxHash: string;
  feeAssetId: string;
  escrowAccountId: string;
  operatorAccountId: string;
  leaseFee: string;
  flowLabelBits: number;
  paddingBudgetMs: number;
  relayIdHex: string;
  relayMldsa65PublicKeyHex: string;
  descriptorCommitHex: string;
  tlsServerName: string;
  relayTlsSpkiSha256Hex: string;
  relayCertificateSha256Hex: string;
  directorySnapshotDigestHex: string;
  routePushes: ReadonlyArray<string>;
  excludedRoutes: ReadonlyArray<string>;
  dnsServers: ReadonlyArray<string>;
  tunnelAddresses: ReadonlyArray<string>;
  mtuBytes: number;
  helperTicketHex: string;
  bytesIn: number;
  bytesOut: number;
  status: string;
}

export interface ToriiVpnReceipt {
  /** Canonical 16-byte session ID encoded as 32 lowercase hex characters. */
  sessionId: string;
  accountId: string;
  exitClass: string;
  relayEndpoint: string;
  meterFamily: string;
  connectedAtMs: number;
  disconnectedAtMs: number;
  durationMs: number;
  bytesIn: number;
  bytesOut: number;
  status:
    | "disconnected"
    | "expired"
    | "replaced"
    | "settlement_pending"
    | "settled";
  receiptSource: string;
  quoteId: string;
  paymentTxHash: string;
  feeAssetId: string;
  escrowAccountId: string;
  operatorAccountId: string;
  leaseFee: string;
  earnedFee: string;
  refundedFee: string;
  leaseIdHex: string;
  settleLeaseInstruction: ToriiVpnTxInstruction | null;
}

export interface ToriiVpnReceiptListResponse {
  items: ReadonlyArray<ToriiVpnReceipt>;
  total: number;
}

export type SnsNameStatus =
  | { status: "Active" }
  | { status: "GracePeriod" }
  | { status: "Redemption" }
  | { status: "Frozen"; reason: string; untilMs: number }
  | { status: "Tombstoned"; reason: string };

export interface SnsNameSelector {
  version: number;
  suffixId: number;
  label: string;
}

export interface SnsNameController {
  controller_type: "Account" | "Multisig" | "ResolverTemplate" | "ExternalLink";
  account_address?: string;
  resolver_template_id?: string;
  payload?: Record<string, unknown>;
}

export interface SnsTokenValue {
  assetId: string;
  amount: string;
}

export interface SnsPricingTier {
  tierId: number;
  labelRegex: string;
  basePrice: SnsTokenValue;
  auctionKind: "VickreyCommitReveal" | "DutchReopen";
  dutchFloor: SnsTokenValue | null;
  minDurationYears: number;
  maxDurationYears: number;
}

export interface SnsReservedLabel {
  normalizedLabel: string;
  assignedTo: string | null;
  releaseAtMs: number | null;
  note: string;
}

export interface SnsFeeSplit {
  treasuryBps: number;
  stewardBps: number;
  referralMaxBps: number;
  escrowBps: number;
}

export interface SnsSuffixPolicy {
  suffixId: number;
  suffix: string;
  steward: string;
  status: "Active" | "Paused" | "Revoked";
  minTermYears: number;
  maxTermYears: number;
  gracePeriodDays: number;
  redemptionPeriodDays: number;
  referralCapBps: number;
  reservedLabels: ReadonlyArray<SnsReservedLabel>;
  paymentAssetId: string;
  pricing: ReadonlyArray<SnsPricingTier>;
  feeSplit: SnsFeeSplit;
  fundSplitterAccount: string;
  policyVersion: number;
  metadata: Record<string, unknown>;
}

export interface SnsNameRecord {
  selector: SnsNameSelector;
  nameHash: string;
  owner: string;
  controllers: ReadonlyArray<SnsNameController>;
  status: SnsNameStatus;
  pricingClass: number;
  registeredAtMs: number;
  expiresAtMs: number;
  graceExpiresAtMs: number;
  redemptionExpiresAtMs: number;
  metadata: Record<string, unknown>;
  auction: SnsAuction | null;
}

export interface SnsAuction {
  kind: "VickreyCommitReveal" | "DutchReopen";
  openedAtMs: number;
  closesAtMs: number;
  floorPrice: SnsTokenValue;
  highestCommitment: string | null;
  settlementTx: unknown;
}

/** `category` of a `/v1/events/sse` payload. */
export type ToriiEventCategory = "Pipeline" | "Data" | "Other";

/** Stable `rejection_code` of a rejected transaction event. */
export type ToriiTransactionRejectionCode =
  | "account_does_not_exist"
  | "limit_check"
  | "validation"
  | "instruction_execution"
  | "ivm_execution"
  | "trigger_execution";

/** Fields shared by every transaction event. */
export interface ToriiPipelineTransactionEventFields {
  readonly category: "Pipeline";
  readonly event: "Transaction";
  /** Transaction hash. */
  readonly hash: string;
  readonly lane_id: number;
  readonly dataspace_id: ToriiU64;
  /** Height of the block that holds the transaction, once there is one. */
  readonly block_height: ToriiU64 | null;
}

/** A transaction status change other than a rejection. */
export interface ToriiPipelineTransactionStatusEvent
  extends ToriiPipelineTransactionEventFields {
  readonly status: "Queued" | "Expired" | "Approved";
}

/** A rejected transaction. */
export interface ToriiPipelineTransactionRejectedEvent
  extends ToriiPipelineTransactionEventFields {
  readonly status: "Rejected";
  readonly rejection_code: ToriiTransactionRejectionCode;
  /** Fixed public text for `rejection_code`. */
  readonly rejection_reason: string;
}

export type ToriiPipelineTransactionEvent =
  | ToriiPipelineTransactionStatusEvent
  | ToriiPipelineTransactionRejectedEvent;

/** A block status change other than a rejection. */
export interface ToriiPipelineBlockStatusEvent {
  readonly category: "Pipeline";
  readonly event: "Block";
  readonly status: "Created" | "Approved" | "Committed" | "Applied";
}

/** A rejected block. */
export interface ToriiPipelineBlockRejectedEvent {
  readonly category: "Pipeline";
  readonly event: "Block";
  readonly status: "Rejected";
  /** The block rejection variant, for example `EmptyBlock`. */
  readonly rejection_code: string;
}

export type ToriiPipelineBlockEvent =
  | ToriiPipelineBlockStatusEvent
  | ToriiPipelineBlockRejectedEvent;

export interface ToriiPipelineWarningEvent {
  readonly category: "Pipeline";
  readonly event: "Warning";
  readonly kind: string;
  readonly details: string;
  /** Height of the block the warning concerns. */
  readonly height: ToriiU64;
}

export interface ToriiPipelineWitnessEvent {
  readonly category: "Pipeline";
  readonly event: "Witness";
  readonly block_hash: string;
  readonly height: ToriiU64;
  readonly view: ToriiU64;
  readonly epoch: ToriiU64;
  readonly read_count: number;
  readonly write_count: number;
}

export type ToriiPipelineEvent =
  | ToriiPipelineTransactionEvent
  | ToriiPipelineBlockEvent
  | ToriiPipelineWarningEvent
  | ToriiPipelineWitnessEvent;

export interface ToriiPipelineTransactionStatusStatus {
  kind: "Queued" | "Approved" | "Committed" | "Applied" | "Rejected" | "Expired";
  block_height?: number;
}

export interface ToriiPipelineTransactionStatus {
  hash: string;
  status: ToriiPipelineTransactionStatusStatus;
  scope: "local" | "global";
  resolved_from: "cache" | "queue" | "state";
}

/** Exact finality returned only after global state has applied the transaction. */
export interface ToriiAppliedTransactionStatus
  extends ToriiPipelineTransactionStatus {
  status: {
    kind: "Applied";
    block_height: number;
  };
  scope: "global";
  resolved_from: "state";
}

export interface ToriiProofEventBase {
  readonly category: "Data";
  readonly backend: string;
  /** Hex-encoded proof hash. */
  readonly proof_hash: string;
  readonly call_hash: string | null;
  readonly envelope_hash: string | null;
  /** `backend::name` of the verifying key. */
  readonly vk_ref: string | null;
  readonly vk_commitment: string | null;
}

export interface ToriiProofVerifiedEvent extends ToriiProofEventBase {
  readonly event: "ProofVerified";
}

export interface ToriiProofRejectedEvent extends ToriiProofEventBase {
  readonly event: "ProofRejected";
}

/** A pruning pass over a backend's proof registry. */
export interface ToriiProofPrunedEvent {
  readonly category: "Data";
  readonly event: "ProofPruned";
  readonly backend: string;
  readonly removed_count: number;
  readonly remaining: ToriiU64;
  readonly cap: ToriiU64;
  readonly grace_blocks: ToriiU64;
  readonly prune_batch: ToriiU64;
  readonly pruned_at_height: ToriiU64;
  /** Account that issued the pruning instruction, or the insert that pruned. */
  readonly pruned_by: string;
  readonly origin: "Insert" | "Manual";
  readonly removed: ReadonlyArray<{ readonly backend: string; readonly proof_hash: string }>;
}

/** Data-event kinds that Torii reports with a diagnostic `summary`. */
export type ToriiDataEventKind =
  | "Peer"
  | "Domain"
  | "Account"
  | "Asset"
  | "AssetDefinition"
  | "Trigger"
  | "Role"
  | "Configuration"
  | "Executor"
  | "VerifyingKey"
  | "RuntimeUpgrade"
  | "SmartContract"
  | "Soradns"
  | "Sorafs"
  | "Musubi"
  | "SpaceDirectory"
  | "Escrow"
  | "Oracle"
  | "Governance"
  | "Social"
  | "Bridge"
  | "GameSession"
  | "Sccp";

/** Any other data event: its kind and a `summary` without a stable format. */
export interface ToriiDataSummaryEvent {
  readonly category: "Data";
  readonly event: ToriiDataEventKind;
  readonly summary: string;
}

export type ToriiDataEvent =
  | ToriiProofVerifiedEvent
  | ToriiProofRejectedEvent
  | ToriiProofPrunedEvent
  | ToriiDataSummaryEvent;

/** A non-data event with a `summary` without a stable format. */
export interface ToriiOtherEvent {
  readonly category: "Other";
  readonly event: "Time" | "ExecuteTrigger" | "TriggerCompleted" | "Other";
  readonly summary: string;
}

/**
 * One `/v1/events/sse` payload, discriminated on `category` and `event`
 * (and on `status` for transactions and blocks). Torii may add `event` kinds;
 * the SDK delivers unrecognized payloads unchanged, so keep a `default`
 * branch when switching over `event`.
 */
export type ToriiEventPayload =
  | ToriiPipelineEvent
  | ToriiDataEvent
  | ToriiOtherEvent;

/** A payload frame of `streamEvents()`; `data` is always a JSON object. */
export interface ToriiEventFrame<T = ToriiEventPayload> {
  /** Payload frames carry no SSE event name. */
  event: null;
  data: T;
  id: string | null;
  retry?: number | null;
  raw: string | null;
}

/**
 * The terminal `event: stream_error` frame that `ToriiClient.streamEvents()`
 * yields before the stream ends (`ToriiBrowserClient` raises
 * `ToriiStreamGapError` instead).
 */
export interface ToriiStreamErrorFrame {
  event: "stream_error";
  data: ToriiContractEventStreamErrorPayload;
  id: string | null;
  retry?: number | null;
  raw: string | null;
}

export interface ToriiSseEvent<T = ToriiEventPayload> {
  event: string | null;
  data: T | string;
  id: string | null;
  retry?: number | null;
  raw: string | null;
}

export interface ToriiContractEventStreamErrorPayload {
  code: string;
  message: string;
  dropped_messages: number | null;
  replay_available: boolean;
}

export interface ToriiWebSocketEvent<T = unknown> {
  event: string | null;
  data: T | string;
  raw: string;
}

/** An effective permission, including grants inherited from assigned roles. */
export interface ToriiAccountPermissionItem {
  name: string;
  payload: JsonValue;
}

export class ConnectRetryPolicy {
  static readonly DEFAULT_BASE_DELAY_MS: number;
  static readonly DEFAULT_MAX_DELAY_MS: number;
  constructor(baseDelayMs?: number, maxDelayMs?: number);
  capMillis(attempt: number): number;
  delayMillis(
    attempt: number,
    seed: Uint8Array | ArrayBuffer | ArrayBufferView | ArrayLike<number>,
  ): number;
}

export type ConnectErrorCategory =
  | "transport"
  | "codec"
  | "authorization"
  | "timeout"
  | "queueOverflow"
  | "internal";

export const ConnectErrorCategory: Readonly<{
  TRANSPORT: "transport";
  CODEC: "codec";
  AUTHORIZATION: "authorization";
  TIMEOUT: "timeout";
  QUEUE_OVERFLOW: "queueOverflow";
  INTERNAL: "internal";
}>;

export interface ConnectErrorTelemetryOptions {
  fatal?: boolean | null;
  httpStatus?: number | null;
  underlying?: string | null;
}

export interface ConnectErrorFromOptions {
  fatal?: boolean | null;
  httpStatus?: number | null;
}

export interface ConnectErrorConvertible {
  toConnectError(): ConnectError;
}

export class ConnectError extends Error implements ConnectErrorConvertible {
  constructor(options?: {
    category?: ConnectErrorCategory;
    code?: string;
    message?: string;
    fatal?: boolean | null;
    httpStatus?: number | null;
    underlying?: string | null;
    cause?: unknown;
  });

  readonly category: ConnectErrorCategory;
  readonly code: string;
  readonly fatal: boolean;
  readonly httpStatus?: number;
  readonly underlying?: string;

  telemetryAttributes(
    options?: ConnectErrorTelemetryOptions,
  ): Record<string, string>;
  toConnectError(): ConnectError;
}

export type ConnectQueueErrorKind = "overflow" | "expired";

export class ConnectQueueError
  extends Error
  implements ConnectErrorConvertible
{
  constructor(
    kind: ConnectQueueErrorKind,
    options?: { limit?: number; ttlMs?: number },
  );

  readonly kind: ConnectQueueErrorKind;
  readonly limit?: number;
  readonly ttlMs?: number;

  static overflow(limit?: number): ConnectQueueError;
  static expired(ttlMs?: number): ConnectQueueError;
  toConnectError(): ConnectError;
}

export type ConnectDirection = "app_to_wallet" | "wallet_to_app";

export const ConnectDirection: Readonly<{
  APP_TO_WALLET: "app_to_wallet";
  WALLET_TO_APP: "wallet_to_app";
}>;

export class ConnectJournalError extends Error {
  constructor(message?: string, options?: { cause?: unknown });
}

export interface ConnectJournalRecordInit {
  direction: ConnectDirection | string;
  sequence: number | bigint | string;
  ciphertext: ArrayLike<number> | ArrayBufferLike;
  payloadHash?: ArrayLike<number> | ArrayBufferLike;
  receivedAtMs?: number;
  expiresAtMs?: number;
}

export class ConnectJournalRecord {
  constructor(init: ConnectJournalRecordInit);
  static fromCiphertext(options: {
    direction: ConnectDirection | string;
    sequence: number | bigint | string;
    ciphertext: ArrayLike<number> | ArrayBufferLike;
    receivedAtMs?: number;
    retentionMs?: number;
  }): ConnectJournalRecord;
  static decode(
    data: ArrayLike<number> | ArrayBufferLike,
    offset?: number,
  ): { record: ConnectJournalRecord; bytesConsumed: number };
  readonly direction: ConnectDirection;
  readonly sequence: bigint;
  readonly ciphertext: Uint8Array;
  readonly payloadHash: Uint8Array;
  readonly receivedAtMs: number;
  readonly expiresAtMs: number;
  readonly payloadLength: number;
  readonly encodedLength: number;
  encode(): Uint8Array;
}

export interface ConnectQueueJournalOptions {
  maxRecordsPerQueue?: number;
  maxBytesPerQueue?: number;
  retentionMs?: number;
  indexedDbName?: string;
  indexedDbVersion?: number;
  storage?: "indexeddb" | "memory";
  indexedDbFactory?: IDBFactory;
}

export interface ConnectQueueJournalAppendOptions {
  ttlMs?: number;
  retentionMs?: number;
  receivedAtMs?: number;
}

export interface ConnectQueueJournalReadOptions {
  nowMs?: number;
}

export class ConnectQueueJournal {
  constructor(
    sessionId: string | ArrayBufferLike | ArrayLike<number>,
    options?: ConnectQueueJournalOptions,
  );
  readonly sessionKey: string;
  append(
    direction: ConnectDirection | string,
    sequence: number | bigint | string,
    ciphertext: ArrayLike<number> | ArrayBufferLike,
    options?: ConnectQueueJournalAppendOptions,
  ): Promise<void>;
  records(
    direction: ConnectDirection | string,
    options?: ConnectQueueJournalReadOptions,
  ): Promise<ConnectJournalRecord[]>;
  popOldest(
    direction: ConnectDirection | string,
    count?: number,
    options?: ConnectQueueJournalReadOptions,
  ): Promise<ConnectJournalRecord[]>;
}

export function connectErrorFrom(
  error: unknown,
  options?: ConnectErrorFromOptions,
): ConnectError;

export interface ToriiClientRetryOptions {
  timeoutMs?: number | null;
  maxRetries?: number | null;
  backoffInitialMs?: number | null;
  backoffMultiplier?: number | null;
  maxBackoffMs?: number | null;
  retryStatuses?: ReadonlyArray<number>;
  retryMethods?: ReadonlyArray<string>;
  defaultHeaders?: Record<string, string>;
  authToken?: string | null;
  apiToken?: string | null;
  retryProfiles?: Record<string, ToriiRetryProfileOptions>;
}

export interface ToriiRetryTelemetryEvent {
  phase: "response" | "network" | "timeout";
  attempt: number;
  nextAttempt: number;
  maxRetries: number;
  method: string;
  url: string;
  status?: number;
  errorName?: string | null;
  errorMessage?: string | null;
  timedOut?: boolean;
  backoffMs?: number;
  timestampMs: number;
  profile?: string;
  durationMs: number;
}

export interface InsecureTransportTelemetryEvent {
  client: string;
  method: string;
  url: string;
  baseUrl: string;
  host: string;
  protocol: string;
  pathIsAbsolute: boolean;
  originMatches: boolean;
  allowInsecure: boolean;
  hasCredentials: boolean;
  hasSensitiveBody?: boolean;
  hasCanonicalAuth?: boolean;
  timestampMs: number;
}

export interface ToriiRetryProfileOptions {
  maxRetries?: number | null;
  backoffInitialMs?: number | null;
  backoffMultiplier?: number | null;
  maxBackoffMs?: number | null;
  retryStatuses?: ReadonlyArray<number>;
  retryMethods?: ReadonlyArray<string>;
}

export interface ToriiResolvedRetryProfile {
  maxRetries: number;
  backoffInitialMs: number;
  backoffMultiplier: number;
  maxBackoffMs: number;
  retryStatuses: Set<number>;
  retryMethods: Set<string>;
}

export interface SorafsReplicationAssignment {
  providerIdHex: string;
  sliceGiB: number;
  lane: string | null;
}

export interface SorafsReplicationSla {
  ingestDeadlineSecs: number;
  minAvailabilityPercentMilli: number;
  minPorSuccessPercentMilli: number;
}

export interface SorafsReplicationMetadataEntry {
  key: string;
  value: string;
}

export interface SorafsReplicationOrder {
  schemaVersion: number;
  orderIdHex: string;
  manifestCidHex: string;
  manifestCidBase64: string;
  manifestDigestHex: string;
  chunkingProfile: string;
  targetReplicas: number;
  assignments: ReadonlyArray<SorafsReplicationAssignment>;
  issuedAtUnix: number;
  deadlineAtUnix: number;
  sla: SorafsReplicationSla;
  metadata: ReadonlyArray<SorafsReplicationMetadataEntry>;
}

export declare const SORAFS_ORDERBOOK_PAYLOAD_KINDS: Readonly<{
  ORDER_REQUEST: "order-request";
  ORDER_CANCEL: "order-cancel";
  TRADE_EVENT: "trade-event";
  SETTLEMENT_CHANNEL: "settlement-channel";
  SETTLEMENT_RECEIPT: "settlement-receipt";
}>;

/** Canonical maximum byte length for a V1 orderbook owner account. */
export declare const ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1: 256;

export type SorafsOrderbookPayloadKind =
  | "order-request"
  | "order-cancel"
  | "trade-event"
  | "settlement-channel"
  | "settlement-receipt";

export type SorafsOrderbookSignablePayloadKind =
  | "order-request"
  | "order-cancel"
  | "settlement-receipt";

export type SorafsOrderbookCancelReason =
  | "owner-requested"
  | "expired"
  | "governance"
  | "replaced";

export type SorafsOrderbookIntegerInput = number | bigint | string;
/** Canonical, non-negative XOR quantity text with at most nine fractional digits. */
export type SorafsOrderbookXorQuantityInput = string;
export type SorafsOrderbookBytesInput = ArrayBufferView | ArrayBuffer | Buffer;

export interface SorafsSignedOrderbookOrderRequestFields {
  orderId?: SorafsOrderbookBytesInput;
  side: SorafsOrderbookSide;
  tier: SorafsOrderbookTier;
  pricePerGib: SorafsOrderbookXorQuantityInput;
  quantityGib: SorafsOrderbookIntegerInput;
  remainingGib?: SorafsOrderbookIntegerInput;
  ownerAccount: SorafsOrderbookBytesInput;
  /** Exact non-zero 32-byte provider identity for asks; omit or pass empty bytes for bids. */
  providerId?: SorafsOrderbookBytesInput;
  expiryUnix: SorafsOrderbookIntegerInput;
  nonce: SorafsOrderbookIntegerInput;
  makerFeeBps: SorafsOrderbookIntegerInput;
  takerFeeBps: SorafsOrderbookIntegerInput;
}

export interface SorafsSignedOrderbookOrderCancelFields {
  orderId: SorafsOrderbookBytesInput;
  ownerAccount: SorafsOrderbookBytesInput;
  reason: SorafsOrderbookCancelReason;
  nonce: SorafsOrderbookIntegerInput;
}

export interface SorafsSignedOrderbookSettlementReceiptFields {
  receiptId: SorafsOrderbookBytesInput;
  channelId: SorafsOrderbookBytesInput;
  tradeId: SorafsOrderbookBytesInput;
  rangeStart: SorafsOrderbookIntegerInput;
  rangeEnd: SorafsOrderbookIntegerInput;
  chunkHash: SorafsOrderbookBytesInput;
  bytesDelivered: SorafsOrderbookIntegerInput;
  xorDebited: SorafsOrderbookXorQuantityInput;
  providerCredit: SorafsOrderbookXorQuantityInput;
  feeAmount: SorafsOrderbookXorQuantityInput;
  issuedAtUnix: SorafsOrderbookIntegerInput;
}

export declare const SORAFS_PDP_PAYLOAD_KINDS: Readonly<{
  COMMITMENT: "commitment";
  CHALLENGE: "challenge";
  PROOF: "proof";
}>;

export declare const SORAFS_FIXTURE_BUNDLE_PAYLOAD_KINDS: Readonly<{
  PROVIDER_ADVERT: "provider-advert";
  PROVIDER_ADMISSION_ENVELOPE: "provider-admission-envelope";
  REPLICATION_ORDER: "replication-order";
  POR_CHALLENGE: "por-challenge";
  POR_PROOF: "por-proof";
  POTR_RECEIPT: "potr-receipt";
  REPAIR_EVIDENCE: "repair-evidence";
  REPAIR_REPORT: "repair-report";
  REPAIR_TASK_RECORD: "repair-task-record";
  REPAIR_SLASH_PROPOSAL: "repair-slash-proposal";
  REPAIR_TASK_EVENT: "repair-task-event";
  ORDERBOOK_ORDER_REQUEST: "orderbook-order-request";
  ORDERBOOK_ORDER_CANCEL: "orderbook-order-cancel";
  ORDERBOOK_TRADE_EVENT: "orderbook-trade-event";
  ORDERBOOK_SETTLEMENT_CHANNEL: "orderbook-settlement-channel";
  ORDERBOOK_SETTLEMENT_RECEIPT: "orderbook-settlement-receipt";
  PDP_COMMITMENT: "pdp-commitment";
  PDP_CHALLENGE: "pdp-challenge";
  PDP_PROOF: "pdp-proof";
}>;

export declare const SORAFS_FIXTURE_BUNDLE_MAX_PAYLOADS_V1: 64;
export declare const SORAFS_GOVERNANCE_DAG_MAX_BLOCKS_V1: 64;
export declare const SORAFS_GOVERNANCE_DAG_CID_BYTES_V1: 32;
export declare const SORAFS_REFERENCE_MAX_INPUT_BYTES_V1: 67108864;
export declare const SORAFS_REFERENCE_MAX_LABEL_BYTES_V1: 1024;

export type SorafsPdpPayloadKind =
  | "commitment"
  | "challenge"
  | "proof";

export type SorafsFixtureBundlePayloadKind =
  | "provider-advert"
  | "provider-admission-envelope"
  | "replication-order"
  | "por-challenge"
  | "por-proof"
  | "potr-receipt"
  | "repair-evidence"
  | "repair-report"
  | "repair-task-record"
  | "repair-slash-proposal"
  | "repair-task-event"
  | "orderbook-order-request"
  | "orderbook-order-cancel"
  | "orderbook-trade-event"
  | "orderbook-settlement-channel"
  | "orderbook-settlement-receipt"
  | "pdp-commitment"
  | "pdp-challenge"
  | "pdp-proof";

export interface SorafsValidationContextField {
  key: string;
  value: string;
}

export interface SorafsValidationInput {
  kind: string;
  path: string;
}

export type SorafsValidationCategory =
  | "validation"
  | "policy"
  | "signature"
  | "norito"
  | "internal";

export interface SorafsValidationOutcomeFields {
  code: string;
  message: string;
  docs_url: "https://docs.iroha.tech/";
  telemetry_tags: ReadonlyArray<string>;
  context: ReadonlyArray<SorafsValidationContextField>;
  inputs: ReadonlyArray<SorafsValidationInput>;
  version: 1;
  generated_at: number;
}

export type SorafsValidationOutcome =
  | (SorafsValidationOutcomeFields & {
      status: "Ok";
      category: "validation";
      action: null;
    })
  | (SorafsValidationOutcomeFields & {
      status: "Error";
      category: SorafsValidationCategory;
      action: string;
    });

export interface SorafsOrderbookValidationOptions {
  label?: string;
  generatedAtUnix?: number | bigint;
}

export interface SorafsAppealFinanceValidationOptions {
  label?: string;
  generatedAtUnix?: number | bigint;
}

export interface SorafsPdpPayloadValidationOptions {
  label?: string;
  generatedAtUnix?: number | bigint;
}

export interface SorafsPdpPairValidationOptions {
  commitmentLabel?: string;
  challengeLabel?: string;
  proofLabel?: string;
  generatedAtUnix?: number | bigint;
}

export type SorafsReferenceBytesInput =
  | ArrayBufferView
  | ArrayBuffer
  | Buffer;

export interface SorafsGovernanceDagBlockInput {
  bytes: SorafsReferenceBytesInput;
  label?: string;
}

export interface SorafsFixtureBundlePayloadInput {
  kind: SorafsFixtureBundlePayloadKind;
  bytes: SorafsReferenceBytesInput;
  label?: string;
}

export interface SorafsFixtureBundleValidationOptions {
  nowUnix?: number | bigint;
  generatedAtUnix?: number | bigint;
}

export interface SorafsGovernanceLogNodeValidationOptions {
  label?: string;
  expectedNodeCid: SorafsReferenceBytesInput;
  generatedAtUnix?: number | bigint;
}

export interface SorafsGovernanceDagBlockValidationOptions {
  label?: string;
  expectedBlockCid?: SorafsReferenceBytesInput;
  generatedAtUnix?: number | bigint;
}

export interface SorafsGovernanceDagHeadValidationOptions {
  headLabel?: string;
  generatedAtUnix?: number | bigint;
}

export function decodeReplicationOrder(
  bytes: ArrayBufferView | ArrayBuffer | Buffer,
): SorafsReplicationOrder;

export function validateOrderbookPayload(
  kind: SorafsOrderbookPayloadKind,
  bytes: ArrayBufferView | ArrayBuffer | Buffer,
  options?: SorafsOrderbookValidationOptions,
): SorafsValidationOutcome;

export function validateAppealFinanceCancelAssetLock(
  bytes: ArrayBufferView | ArrayBuffer | Buffer,
  options?: SorafsAppealFinanceValidationOptions,
): SorafsValidationOutcome;

export function signOrderbookPayload(
  kind: SorafsOrderbookSignablePayloadKind,
  bytes: ArrayBufferView | ArrayBuffer | Buffer,
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
): Buffer;

export function deriveOrderbookOrderId(
  ownerAccount: SorafsOrderbookBytesInput,
  nonce: SorafsOrderbookIntegerInput,
): Buffer;

export function buildSignedOrderbookOrderRequest(
  fields: SorafsSignedOrderbookOrderRequestFields,
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
): Buffer;

export function buildSignedOrderbookOrderCancel(
  fields: SorafsSignedOrderbookOrderCancelFields,
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
): Buffer;

export function buildSignedOrderbookSettlementReceipt(
  fields: SorafsSignedOrderbookSettlementReceiptFields,
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
): Buffer;

export function validatePdpPayload(
  kind: SorafsPdpPayloadKind,
  bytes: ArrayBufferView | ArrayBuffer | Buffer,
  options?: SorafsPdpPayloadValidationOptions,
): SorafsValidationOutcome;

export function validatePdpCommitmentChallenge(
  commitmentBytes: ArrayBufferView | ArrayBuffer | Buffer,
  challengeBytes: ArrayBufferView | ArrayBuffer | Buffer,
  options?: SorafsPdpPairValidationOptions,
): SorafsValidationOutcome;

export function validatePdpChallengeProof(
  challengeBytes: ArrayBufferView | ArrayBuffer | Buffer,
  proofBytes: ArrayBufferView | ArrayBuffer | Buffer,
  options?: SorafsPdpPairValidationOptions,
): SorafsValidationOutcome;

export function validatePdpBundle(
  commitmentBytes: ArrayBufferView | ArrayBuffer | Buffer,
  challengeBytes: ArrayBufferView | ArrayBuffer | Buffer,
  proofBytes: ArrayBufferView | ArrayBuffer | Buffer,
  options?: SorafsPdpPairValidationOptions,
): SorafsValidationOutcome;

export function validateFixtureBundle(
  payloads: ReadonlyArray<SorafsFixtureBundlePayloadInput>,
  options?: SorafsFixtureBundleValidationOptions,
): SorafsValidationOutcome;

export function validateGovernanceLogNode(
  bytes: SorafsReferenceBytesInput,
  options: SorafsGovernanceLogNodeValidationOptions,
): SorafsValidationOutcome;

export function validateGovernanceDagBlock(
  bytes: SorafsReferenceBytesInput,
  options?: SorafsGovernanceDagBlockValidationOptions,
): SorafsValidationOutcome;

export function validateGovernanceDagHeadChain(
  headBytes: SorafsReferenceBytesInput,
  blocks: ReadonlyArray<SorafsGovernanceDagBlockInput>,
  options?: SorafsGovernanceDagHeadValidationOptions,
): SorafsValidationOutcome;

export interface SorafsGatewayProviderSpec {
  name: string;
  providerIdHex: string;
  /** Canonical lowercase Ed25519 public key used to verify the provider stream token. */
  gatewayPublicKeyHex: string;
  baseUrl: string;
  streamTokenB64: string;
  privacyEventsUrl?: string;
}

export interface SorafsLocalProxyNoritoBridgeOptions {
  spoolDir: string;
  extension?: string;
}

export interface SorafsLocalProxyCarBridgeOptions {
  cacheDir: string;
  extension?: string;
  allowZst?: boolean;
}

export interface SorafsLocalProxyKaigiBridgeOptions {
  spoolDir: string;
  extension?: string;
  roomPolicy?: "public" | "authenticated";
}

export interface SorafsLocalProxyOptions {
  bindAddr?: string;
  telemetryLabel?: string;
  guardCacheKeyHex?: string;
  emitBrowserManifest?: boolean;
  proxyMode?: "bridge" | "metadata-only";
  prewarmCircuits?: boolean;
  maxStreamsPerCircuit?: number;
  circuitTtlHintSecs?: number;
  noritoBridge?: SorafsLocalProxyNoritoBridgeOptions;
  carBridge?: SorafsLocalProxyCarBridgeOptions;
  kaigiBridge?: SorafsLocalProxyKaigiBridgeOptions;
}

export interface SorafsGatewayFetchOptions {
  manifestEnvelopeB64?: string;
  manifestCidHex?: string;
  /** Expected cache version advertised by successful gateway responses. */
  cacheVersion?: string;
  clientId?: string;
  telemetryRegion?: string;
  rolloutPhase?: "canary" | "ramp" | "default";
  maxPeers?: number;
  retryBudget?: number;
  transportPolicy?: "soranet-first" | "soranet-strict" | "direct-only";
  anonymityPolicy?: "anon-guard-pq" | "anon-majority-pq" | "anon-strict-pq";
  writeMode?: "read-only" | "upload-pq-only";
  policyOverride?: SorafsGatewayPolicyOverride;
  localProxy?: SorafsLocalProxyOptions;
  scoreboardOutPath?: string;
  scoreboardNowUnixSecs?: number | bigint;
  scoreboardTelemetryLabel?: string;
  scoreboardAllowImplicitMetadata?: boolean;
}

export interface SorafsGatewayPolicyOverride {
  transportPolicy?: "soranet-first" | "soranet-strict" | "direct-only";
  anonymityPolicy?: "anon-guard-pq" | "anon-majority-pq" | "anon-strict-pq";
}

export interface SorafsGatewayCarArchive {
  size: number | bigint;
  payloadDigestHex: string;
  archiveDigestHex: string;
  cidHex: string;
  rootCidsHex: ReadonlyArray<string>;
  verified: boolean;
  porLeafCount: number | bigint;
}

export interface SorafsGatewayCouncilSignature {
  signerHex: string;
  signatureHex: string;
}

export interface SorafsGatewayManifestGovernance {
  councilSignatures: ReadonlyArray<SorafsGatewayCouncilSignature>;
}

export interface SorafsGatewayCarVerification {
  manifestDigestHex: string;
  manifestPayloadDigestHex: string;
  manifestCarDigestHex: string;
  manifestContentLength: number | bigint;
  manifestChunkCount: number | bigint;
  manifestChunkProfileHandle: string;
  manifestGovernance: SorafsGatewayManifestGovernance;
  carArchive: SorafsGatewayCarArchive;
}

export interface SorafsGatewayAnonymityReport {
  policy: string;
  status: string;
  reason: string;
  soranetSelected: number;
  pqSelected: number;
  classicalSelected: number;
  classicalRatio: number;
  pqRatio: number;
  candidateRatio: number;
  deficitRatio: number;
  supplyDelta: number;
  brownout: boolean;
  brownoutEffective: boolean;
  usesClassical: boolean;
}

export interface SorafsGatewayProviderReport {
  provider: string;
  successes: number;
  failures: number;
  disabled: boolean;
}

export interface SorafsGatewayChunkReceipt {
  chunkIndex: number;
  provider: string;
  attempts: number;
  latencyMs: number;
  bytes: number;
}

export type SorafsGatewayProviderMix =
  | "mixed"
  | "direct-only"
  | "gateway-only"
  | "none";

export interface SorafsGatewayScoreboardMetadata {
  providerCount: number;
  gatewayProviderCount: number;
  providerMix: SorafsGatewayProviderMix;
  transportPolicy: string;
  transportPolicyOverride: boolean;
  transportPolicyOverrideLabel: string | null;
  anonymityPolicy: string;
  anonymityPolicyOverride: boolean;
  anonymityPolicyOverrideLabel: string | null;
  writeMode: string;
  writeModeEnforcesPq: boolean;
  maxParallel: number | null;
  maxPeers: number | null;
  retryBudget: number | null;
  providerFailureThreshold: number;
  assumeNowUnix: number;
  telemetrySourceLabel: string | null;
  telemetryRegion: string | null;
  gatewayManifestProvided: boolean;
  gatewayManifestId: string | null;
  gatewayManifestCid: string | null;
  allowImplicitMetadata: boolean;
}

export interface SorafsGatewayScoreboardEntry {
  provider_id: string;
  alias: string | null;
  raw_score: number;
  normalized_weight: number;
  eligibility: string | null;
}

export interface SorafsGatewayFetchResult {
  manifestIdHex: string;
  chunkerHandle: string;
  chunkCount: number;
  assembledBytes: number | bigint;
  payload: Buffer;
  telemetryRegion: string | null;
  anonymity: SorafsGatewayAnonymityReport;
  providerReports: ReadonlyArray<SorafsGatewayProviderReport>;
  chunkReceipts: ReadonlyArray<SorafsGatewayChunkReceipt>;
  localProxyManifest: Record<string, unknown> | null;
  carVerification: SorafsGatewayCarVerification | null;
  metadata: SorafsGatewayScoreboardMetadata;
  scoreboard: ReadonlyArray<SorafsGatewayScoreboardEntry> | null | undefined;
}

export type SorafsGatewayFetchErrorCode =
  | "invalid_plan"
  | "no_providers"
  | "no_healthy_providers"
  | "no_compatible_providers"
  | "no_policy_eligible_providers"
  | "exhausted_retries"
  | "observer_failed"
  | "internal_invariant"
  | "unknown";

export interface SorafsGatewayFetchAttemptFailure {
  kind: "provider" | "invalid_chunk";
  message?: string;
  reason?: Record<string, unknown>;
  policyBlock?: {
    observedStatus: 451;
    code: "gateway_compliance_denied";
    source: "baseline" | "legal_safety_hold";
    catalogDigestHex: string;
  };
}

export interface SorafsGatewayFetchAttemptError {
  providerId: string;
  failure: SorafsGatewayFetchAttemptFailure;
}

export interface SorafsGatewayCapabilityIssue {
  providerId: string;
  reason: string;
  chunkLength?: number;
  maxSpan?: number;
  offset?: number;
  length?: number;
  requiredAlignment?: number;
  burstLimit?: number;
}

export class SorafsGatewayFetchError extends Error {
  readonly kind: string;
  readonly code: SorafsGatewayFetchErrorCode;
  readonly retryable: boolean;
  readonly chunkIndex: number | null;
  readonly attempts: number | null;
  readonly lastError: SorafsGatewayFetchAttemptError | null;
  readonly providers: ReadonlyArray<SorafsGatewayCapabilityIssue> | null;
  readonly observerError: string | null;
  readonly details: Record<string, unknown> | null;
  readonly original: Error | null;
  readonly payload: Record<string, unknown>;
  constructor(payload?: Record<string, unknown>, original?: Error | null);
}

export function sorafsGatewayFetch(
  manifestIdHex: string,
  chunkerHandle: string,
  planJson: string,
  providers: ReadonlyArray<SorafsGatewayProviderSpec>,
  options?: SorafsGatewayFetchOptions,
): SorafsGatewayFetchResult;

export class ToriiDataModelMismatchError extends Error {
  readonly expected: unknown;
  readonly actual: unknown | null;
  readonly cause?: unknown;
  constructor(expected: unknown, actual: unknown, cause?: unknown);
}

export interface IdentifierRequestForPolicyOptions {
  encryptedInput: string;
  outputOpening: RamLfeOutputOpening;
}

export interface IdentifierRequestForPolicy {
  policyId: string;
  encryptedInput: string;
  outputOpening: RamLfeOutputOpening;
}

export function encodeIdentifierResolutionReceiptPayload(payload: unknown): Buffer;
export function encodeIdentifierResolutionReceiptAttestation(
  attestation: unknown,
): Buffer;
export function getIdentifierBfvPublicParameters(
  policySummary: IdentifierPolicyClientSummary,
): Readonly<IdentifierBfvPublicParameters> | null;
/** No secure RAM-LFE input-encryption profile is currently available. */
export class RamLfeEncryptionUnavailableError extends Error {
  readonly code: "ram_lfe_encryption_unavailable";
  constructor();
}
/** Always throws RamLfeEncryptionUnavailableError before inspecting the input. */
export function encryptIdentifierInputForPolicy(
  policySummary: IdentifierPolicyClientSummary,
  input: unknown,
): never;
export function hashIdentifierEncryptedInput(encryptedInput: string): string;
export function buildIdentifierRequestForPolicy(
  policySummary: IdentifierPolicyClientSummary,
  options: IdentifierRequestForPolicyOptions,
): IdentifierRequestForPolicy;
export function verifyIdentifierResolutionReceipt(
  receipt: IdentifierResolutionReceipt,
  policySummary: IdentifierPolicyClientSummary,
): boolean;

type IrohaJsPublicApi = typeof import("./index.js");
type IrohaJsRuntimeNamespace<Keys extends keyof IrohaJsPublicApi> = Readonly<
  Pick<IrohaJsPublicApi, Keys>
>;

type ToriiRuntimeNamespaceExport =
    "IsoMessageTimeoutError"
  | "LocalSigningContext"
  | "OperatorSigningContext"
  | "ToriiClient"
  | "TransactionBatchAdmissionAmbiguousError"
  | "SorafsOrderbookSubmissionAmbiguousError"
  | "ToriiDataModelMismatchError"
  | "ToriiError"
  | "ToriiHttpError"
  | "ToriiStreamGapError"
  | "ListQueryError"
  | "FilterSyntaxError"
  | "AGGREGATE_FUNCTIONS"
  | "CURSOR_MAX_BYTES"
  | "FIELD_PATH_MAX_BYTES"
  | "FILTER_MAX_DEPTH"
  | "FILTER_MAX_MEMBERSHIP_VALUES"
  | "FILTER_MAX_NODES"
  | "FILTER_MAX_TOTAL_MEMBERSHIP_VALUES"
  | "FILTER_TEXT_MAX_BYTES"
  | "LIST_QUERY_MEMBERS"
  | "LIST_QUERY_PARAMETERS"
  | "SELECT_MAX_FIELDS"
  | "SORT_MAX_KEYS"
  | "TORII_COLLECTION_PATHS"
  | "FieldRef"
  | "Filter"
  | "ListQuery"
  | "SortKey"
  | "ToriiCollection"
  | "decodePage"
  | "field"
  | "isDecimalText"
  | "parseSort"
  | "renderFieldPath"
  | "sortToString"
  | "TransactionStatusError"
  | "TransactionTimeoutError"
  | "buildConnectWebSocketUrl"
  | "buildIdentifierRequestForPolicy"
  | "buildSorafsOrderbookEventsWebSocketUrl"
  | "decodePdpCommitmentHeader"
  | "encodeIdentifierResolutionReceiptAttestation"
  | "encodeIdentifierResolutionReceiptPayload"
  | "encryptIdentifierInputForPolicy"
  | "RamLfeEncryptionUnavailableError"
  | "hashIdentifierEncryptedInput"
  | "extractPipelineStatusKind"
  | "getIdentifierBfvPublicParameters"
  | "isStatusQueueStalled"
  | "openConnectWebSocket"
  | "openSorafsOrderbookEventsWebSocket"
  | "statusLivenessElapsedMs"
  | "verifyIdentifierResolutionReceipt";

type NoritoRuntimeNamespaceExport =
  | "encodeRetailFeeQuoteRequestV1"
  | "retailFeePaymentIntentHash"
  | "encodeRetailFeeAssessmentV1"
  | "retailFeeAssessmentMarkerMessage"
  | "decodeRetailFeeAssessmentMarkerMessage"
  | "encodeValidatorStakingPreparationFrameV1"
  | "decodeValidatorStakingPreparationFrameV1"
  | "validateValidatorStakingPreparationV1"
  | "encodeValidatorStakingValueV1"
  | "decodeValidatorStakingValueV1"
  | "CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1"
  | "CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1"
  | "CONFIDENTIAL_MEMO_WIRE_MAGIC_V1"
  | "decodeCancelAssetLockV1"
  | "decodeAccountIdNoritoValue"
  | "encodeAccountIdNoritoValue"
  | "encodeAssetDefinitionIdNoritoValue"
  | "encodeCancelAssetLockV1"
  | "encodeQuantityNoritoValue"
  | "inspectSubscriptionTriggerAction"
  | "noritoDecodeBlockProofs"
  | "noritoDecodeInstruction"
  | "noritoDecodeInstructionBoxArchive"
  | "noritoDecodeConfidentialMemoEnvelopeV1"
  | "noritoDecodeOpenVerifyEnvelope"
  | "noritoDecodePrivacyExact12FixtureBundleBase64V1"
  | "noritoDecodePrivacyExact12FixtureBundleV1"
  | "noritoEncodeInstruction"
  | "noritoEncodeInstructionBoxArchive"
  | "noritoEncodeConfidentialMemoEnvelopeV1"
  | "noritoEncodeContractManifestSignaturePayload"
  | "noritoEncodeFeePaymentIntentArchive"
  | "noritoEncodeMultisigContractCallApproveRequest"
  | "noritoEncodeMultisigContractCallProposeRequest"
  | "noritoEncodeMultisigProposeRequest"
  | "noritoEncodeSorafsBillingAcknowledgementProofV1"
  | "noritoEncodeOpenVerifyEnvelope"
  | "noritoEncodePrivacyExact12FixtureBundleV1"
  | "noritoEncodeTransactionPayloadBatch"
  | "PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1"
  | "PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1"
  | "PRIVACY_EXACT12_PROTOCOL_IDS_V1"
  | "SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1"
  | "SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_SCHEMA_NAME_V1"
  | "validateNoritoFrame"
  | "validateSorafsReplicationOrderPayloadV1"
  | "verifyBlockMerkleProof"
  | "verifyBlockProofs";

type CryptoRuntimeNamespaceExport =
    "CRYPTO_ALGORITHMS"
  | "PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES"
  | "PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1"
  | "PRIVACY_REQUIRED_BRIDGE_ABI_VERSION"
  | "SM2_DEFAULT_DISTINGUISHED_ID"
  | "SM2_PRIVATE_KEY_LENGTH"
  | "SM2_PUBLIC_KEY_LENGTH"
  | "SM2_SIGNATURE_LENGTH"
  | "buildKaigiAuthorizationProofV1"
  | "buildKaigiUsageProofV1"
  | "deriveConfidentialDiversifierV2"
  | "deriveConfidentialKeyset"
  | "deriveConfidentialKeysetFromHex"
  | "deriveConfidentialNoteV2"
  | "deriveConfidentialNullifierV2"
  | "deriveConfidentialOwnerTagV2"
  | "deriveConfidentialReceiveAddressV2"
  | "deriveEd25519SeedFromRecoveryPhrase"
  | "deriveSm2KeyPairFromSeed"
  | "ed25519SeedToRecoveryPhrase"
  | "entropyToRecoveryPhrase"
  | "generateKeyPair"
  | "generateRecoveryPhrase"
  | "generateSm2KeyPair"
  | "isPrivacyNativeAvailable"
  | "loadKeyPair"
  | "loadSm2KeyPair"
  | "normalizeCryptoAlgorithm"
  | "normalizeRecoveryPhrase"
  | "privacyCompiledProfileCatalogV1"
  | "privateKeyMultihash"
  | "publicKeyFromPrivate"
  | "publicKeyMultihash"
  | "recoveryPhraseToEntropy"
  | "sign"
  | "signEd25519"
  | "signSm2"
  | "sm2FixtureFromSeed"
  | "sm2PublicKeyMultihash"
  | "supportedCryptoAlgorithms"
  | "validateRecoveryPhrase"
  | "verify"
  | "verifyEd25519"
  | "verifySm2";

export const Torii: IrohaJsRuntimeNamespace<ToriiRuntimeNamespaceExport>;
export const Norito: IrohaJsRuntimeNamespace<NoritoRuntimeNamespaceExport>;
export const Crypto: IrohaJsRuntimeNamespace<CryptoRuntimeNamespaceExport>;
export interface SoranetPuzzleParamsSnapshot {
  memoryKib: number;
  timeCost: number;
  lanes: number;
}

export interface SoranetTokenConfigSnapshot {
  enabled: boolean;
  suite: string | null;
  relayIdHex: string | null;
  issuerFingerprintHex: string | null;
  maxTtlSecs: number | null;
  minTtlSecs: number | null;
  defaultTtlSecs: number | null;
  clockSkewSecs: number | null;
  revocationIdsHex: ReadonlyArray<string>;
}

export interface SoranetPuzzleConfigSnapshot {
  difficulty: number;
  maxFutureSkewSecs: number;
  minTicketTtlSecs: number;
  ticketTtlSecs: number;
  puzzle: SoranetPuzzleParamsSnapshot;
  token: SoranetTokenConfigSnapshot;
}

export type SoranetPuzzleTicketResponse = {
  credentialB64: string;
  difficulty: number;
  ttlSecs: number;
  expiresAt: number;
} & (
  | {
      credentialKind: "raw";
      signedTicketFingerprintHex: null;
    }
  | {
      credentialKind: "signed";
      signedTicketFingerprintHex: string;
    }
);

export interface SoranetAdmissionTokenResponse {
  tokenB64: string;
  tokenIdHex: string;
  issuedAt: number;
  expiresAt: number;
  ttlSecs: number;
  issuerFingerprintHex: string;
  relayIdHex: string;
}

export interface SoranetPuzzleRequestOptions {
  timeoutMs?: number | null;
  headers?: Record<string, string | null | undefined>;
  signal?: AbortSignal;
}

export interface SoranetPuzzleMintOptions extends SoranetPuzzleRequestOptions {
  ttlSecs?: number | bigint | null;
}

export type SoranetTokenMintOptions = SoranetPuzzleMintOptions;

export interface SoranetPuzzleClientOptions {
  fetchImpl?: typeof fetch;
  defaultHeaders?: Record<string, string>;
  timeoutMs?: number | null;
}

export class SoranetPuzzleError extends Error {
  readonly status: number;
  readonly body: string;
  constructor(status: number, body: string);
}

export class SoranetPuzzleClient {
  constructor(baseUrl: string, options?: SoranetPuzzleClientOptions);
  readonly baseUrl: string;
  getPuzzleConfig(
    options?: SoranetPuzzleRequestOptions,
  ): Promise<SoranetPuzzleConfigSnapshot>;
  mintPuzzleTicket(
    transcriptHashHex: string,
    options?: SoranetPuzzleMintOptions,
  ): Promise<SoranetPuzzleTicketResponse>;
  getTokenConfig(
    options?: SoranetPuzzleRequestOptions,
  ): Promise<SoranetTokenConfigSnapshot>;
  mintAdmissionToken(
    transcriptHashHex: string,
    options?: SoranetTokenMintOptions,
  ): Promise<SoranetAdmissionTokenResponse>;
}

export interface ToriiClientConfigSource extends ToriiClientRetryOptions {
  retryTelemetryHook?: (event: ToriiRetryTelemetryEvent) => void;
  insecureTransportTelemetryHook?: (
    event: InsecureTransportTelemetryEvent,
  ) => void;
  torii?: {
    apiTokens?: ReadonlyArray<string>;
  };
  toriiClient?: ToriiClientRetryOptions;
}

export interface ResolvedToriiClientConfig {
  timeoutMs: number;
  maxRetries: number;
  backoffInitialMs: number;
  backoffMultiplier: number;
  maxBackoffMs: number;
  retryStatuses: Set<number>;
  retryMethods: Set<string>;
  defaultHeaders: Record<string, string>;
  authToken: string | null;
  apiToken: string | null;
  retryProfiles: Record<string, ToriiResolvedRetryProfile>;
  retryTelemetryHook: ((event: ToriiRetryTelemetryEvent) => void) | null;
  insecureTransportTelemetryHook:
    | ((event: InsecureTransportTelemetryEvent) => void)
    | null;
}

export type ToriiHealthStatus = { status: string } & Record<string, unknown>;
/** Immutable NetworkId context required by APIs that return local-signing drafts. */
export class LocalSigningContext {
  constructor(networkId: NetworkId, chainDiscriminant: number);
  readonly networkId: NetworkId; readonly chainDiscriminant: number;
}

export interface ToriiClientOptions extends ToriiClientRetryOptions {
  chain?: never;
  chainId?: never;
  chain_id?: never;
  networkId?: never;
  fetchImpl?: typeof fetch;
  config?: ToriiClientConfigSource;
  localSigningContext?: LocalSigningContext;
  operatorSigningContext?: OperatorSigningContext;
  canonicalRequestAuth?: CanonicalRequestAuth;
  allowInsecure?: boolean;
  retryTelemetryHook?: (event: ToriiRetryTelemetryEvent) => void;
  insecureTransportTelemetryHook?: (
    event: InsecureTransportTelemetryEvent,
  ) => void;
}

/** Polling controls for global, state-authoritative transaction finality. */
export interface TransactionStatusPollOptions {
  signal?: AbortSignal;
  intervalMs?: number;
  timeoutMs?: number | null;
  maxAttempts?: number | null;
  onStatus?: (
    status: string | null,
    payload: ToriiPipelineTransactionStatus | null,
    attempt: number,
  ) => void | Promise<void>;
}

/** Options for a single diagnostic status read; scope defaults to `global`. */
export interface TransactionStatusReadOptions {
  signal?: AbortSignal;
  scope?: "local" | "global";
}

export interface IsoBridgeSignerSnapshot {
  accountId: string;
  privateKey?: string | null;
}

export interface IsoBridgeAliasEntry {
  iban: string;
  accountId: string;
}

export interface IsoBridgeCurrencyBinding {
  currency: string;
  assetDefinition: string;
  maxAmount: string;
}

export interface IsoBridgeConfigSnapshot {
  enabled: boolean;
  dedupeTtlSecs: number;
  defaultProfile: string | null;
  profiles: ReadonlyArray<Record<string, unknown>>;
  storeDir: string | null;
  embeddedSignaturePolicy: string | null;
  signer: IsoBridgeSignerSnapshot | null;
  accountAliases: ReadonlyArray<IsoBridgeAliasEntry>;
  currencyAssets: ReadonlyArray<IsoBridgeCurrencyBinding>;
}

export interface ConnectConfigSnapshot {
  enabled: boolean;
  wsMaxSessions: number;
  wsPerIpMaxSessions: number;
  wsRatePerIpPerMin: number;
  sessionTtlMs: number;
  frameMaxBytes: number;
  sessionBufferMaxBytes: number;
  pingIntervalMs: number;
  pingMissTolerance: number;
  pingMinIntervalMs: number;
  dedupeTtlMs: number;
  dedupeCap: number;
  relayEnabled: boolean;
  relayStrategy: string;
  p2pTtlHops: number;
}

export interface ToriiFeatureConfigSnapshot {
  isoBridge: IsoBridgeConfigSnapshot | null;
  connect: ConnectConfigSnapshot | null;
}

export interface ConnectStatusPolicySnapshot {
  wsMaxSessions: number;
  wsPerIpMaxSessions: number;
  wsRatePerIpPerMin: number;
  sessionTtlMs: number;
  frameMaxBytes: number;
  sessionBufferMaxBytes: number;
  relayEnabled: boolean;
  relayStrategy: string;
  relayEffectiveStrategy: string;
  relayP2pAttached: boolean;
  p2pTtlHops: number;
  heartbeatIntervalMs: number;
  heartbeatMissTolerance: number;
  heartbeatMinIntervalMs: number;
}

export interface ConnectStatusSnapshot {
  enabled: boolean;
  sessionsTotal: number;
  sessionsActive: number;
  perIpSessions: ReadonlyArray<{ ip: string; sessions: number }>;
  bufferedSessions: number;
  totalBufferBytes: number;
  dedupeSize: number;
  policy: ConnectStatusPolicySnapshot | null;
  framesInTotal: number;
  framesOutTotal: number;
  ciphertextTotal: number;
  dedupeDropsTotal: number;
  bufferDropsTotal: number;
  plaintextControlDropsTotal: number;
  monotonicDropsTotal: number;
  sequenceViolationClosesTotal: number;
  roleDirectionMismatchTotal: number;
  pingMissTotal: number;
  p2pRebroadcastsTotal: number;
  p2pRebroadcastSkippedTotal: number;
  p2pAuthFailuresTotal: number;
  p2pTtlDropsTotal: number;
  p2pUnknownSessionDropsTotal: number;
  p2pSessionClaimsInTotal: number;
  p2pSessionClaimsInstalledTotal: number;
  p2pSessionClaimConflictsTotal: number;
  p2pRoleConsumedTotal: number;
  p2pSessionTerminatedTotal: number;
}

export interface ConnectSessionResponse {
  sid: string;
  network_id: NetworkId;
  app_pk: string;
  nonce: string;
  wallet_uri: string;
  app_uri: string;
  token_app: string;
  token_wallet: string;
  token_management: string;
  token_relay: string;
  extra: Record<string, unknown>;
  raw?: Record<string, unknown>;
}

export interface ConnectSidResult {
  sidBytes: Buffer;
  sidBase64Url: string;
  nonce: Buffer;
}

export interface ConnectKeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

export interface ConnectSessionPreviewOptions {
  networkId: NetworkId;
  node?: string | null;
  nonce?: BinaryLike | null;
  appKeyPair?: {
    publicKey: BinaryLike;
    privateKey: BinaryLike;
  };
}

export interface ConnectSessionPreview {
  networkId: NetworkId;
  node: string | null;
  sidBytes: Buffer;
  sidBase64Url: string;
  nonce: Buffer;
  appKeyPair: ConnectKeyPair;
  walletUri: string;
  appUri: string;
}

export function generateConnectSid(options: {
  networkId: NetworkId;
  appPublicKey: BinaryLike;
  nonce?: BinaryLike | null;
}): ConnectSidResult;

export function createConnectSessionPreview(
  options: ConnectSessionPreviewOptions,
): ConnectSessionPreview;

export type ConnectQueueState =
  | "healthy"
  | "throttled"
  | "quarantined"
  | "disabled";

export interface ConnectQueueDirectionStats {
  depth: number;
  bytes: number;
  oldest_sequence: number | null;
  newest_sequence: number | null;
  oldest_timestamp_ms: number | null;
  newest_timestamp_ms: number | null;
}

export interface ConnectQueueSnapshot {
  schema_version: number;
  session_id_base64: string;
  state: ConnectQueueState;
  reason: string | null;
  warning_watermark: number;
  drop_watermark: number;
  last_updated_ms: number;
  app_to_wallet: ConnectQueueDirectionStats;
  wallet_to_app: ConnectQueueDirectionStats;
}

export interface ConnectQueueMetricsSample {
  timestamp_ms?: number;
  state?: ConnectQueueState;
  app_to_wallet_depth?: number;
  wallet_to_app_depth?: number;
  reason?: string | null;
}

export interface ConnectQueueEvidenceFiles {
  app_queue_filename?: string;
  wallet_queue_filename?: string;
  metrics_filename?: string;
}

export interface ConnectQueueEvidenceManifest {
  schema_version: number;
  session_id_base64: string;
  created_at_ms: number;
  snapshot: ConnectQueueSnapshot;
  files: ConnectQueueEvidenceFiles;
}

export interface ConnectQueueEvidenceExportResult {
  manifest: ConnectQueueEvidenceManifest;
  targetDir: string;
}

export interface ConnectQueueRootOptions {
  rootDir?: string;
  connectConfig?:
    | {
        connect?: {
          queue?: {
            root?: string;
            queue_root?: string;
          };
          queue_root?: string;
          queueRoot?: string;
        };
        connect_queue_root?: string;
        connectQueueRoot?: string;
      }
    | string;
  allowEnvOverride?: boolean;
}

export function defaultConnectQueueRoot(
  options?: ConnectQueueRootOptions,
): string;

export function deriveConnectSessionDirectory(
  options: { sid: BinaryLike | string } & ConnectQueueRootOptions,
): string;

export function readConnectQueueSnapshot(
  options: {
    sid?: BinaryLike | string;
    snapshotPath?: string;
    warningWatermark?: number;
    dropWatermark?: number;
  } & ConnectQueueRootOptions,
): Promise<{ snapshot: ConnectQueueSnapshot; statePath: string }>;

export function writeConnectQueueSnapshot(
  snapshot: ConnectQueueSnapshot,
  options?: ConnectQueueRootOptions & { sid?: BinaryLike | string },
): Promise<{ snapshot: ConnectQueueSnapshot; statePath: string }>;

export function updateConnectQueueSnapshot(
  sid: BinaryLike | string,
  updater:
    | Partial<ConnectQueueSnapshot>
    | ((snapshot: ConnectQueueSnapshot) => ConnectQueueSnapshot | void),
  options?: ConnectQueueRootOptions & {
    warningWatermark?: number;
    dropWatermark?: number;
  },
): Promise<ConnectQueueSnapshot>;

export function appendConnectQueueMetric(
  sid: BinaryLike | string,
  sample: ConnectQueueMetricsSample,
  options?: ConnectQueueRootOptions,
): Promise<string>;

export function exportConnectQueueEvidence(
  sid: BinaryLike | string,
  targetDir: string,
  options?: ConnectQueueRootOptions,
): Promise<ConnectQueueEvidenceExportResult>;

export interface BootstrapConnectPreviewOptions
  extends ConnectSessionPreviewOptions {
  register?: boolean;
  sessionOptions?: {
    node?: string | null;
  } | null;
}

export interface BootstrapConnectPreviewResult {
  preview: ConnectSessionPreview;
  session: ConnectSessionResponse | null;
  tokens: {
    wallet: string;
    app: string;
    management: string;
    relay: string;
  } | null;
}

export function bootstrapConnectPreviewSession(
  toriiClient: Pick<ToriiClient, "createConnectSession">,
  options: BootstrapConnectPreviewOptions,
): Promise<BootstrapConnectPreviewResult>;

export interface ConnectAppRecord {
  appId: string;
  displayName: string | null;
  description: string | null;
  iconUrl: string | null;
  namespaces: ReadonlyArray<string>;
  metadata: Record<string, unknown>;
  policy: Record<string, unknown>;
  extra: Record<string, unknown>;
  raw?: Record<string, unknown>;
}

export interface ConnectAppRegistryPage {
  items: ReadonlyArray<ConnectAppRecord>;
  total: number | null;
  nextCursor: string | null;
  extra: Record<string, unknown>;
  raw?: Record<string, unknown>;
}

export interface ConnectAppPolicyControls {
  relayEnabled: boolean | null;
  wsMaxSessions: number | null;
  wsPerIpMaxSessions: number | null;
  wsRatePerIpPerMin: number | null;
  sessionTtlMs: number | null;
  frameMaxBytes: number | null;
  sessionBufferMaxBytes: number | null;
  pingIntervalMs: number | null;
  pingMissTolerance: number | null;
  pingMinIntervalMs: number | null;
  extra: Record<string, unknown>;
  raw?: Record<string, unknown>;
}

export interface ConnectAppUpsertInput {
  appId: string;
  displayName?: string | null;
  description?: string | null;
  iconUrl?: string | null;
  namespaces?: ReadonlyArray<string>;
  metadata?: Record<string, unknown>;
  policy?: Record<string, unknown>;
  extra?: Record<string, unknown>;
}

export interface ConnectAppPolicyUpdate {
  relayEnabled?: boolean | null;
  wsMaxSessions?: number | null;
  wsPerIpMaxSessions?: number | null;
  wsRatePerIpPerMin?: number | null;
  sessionTtlMs?: number | null;
  frameMaxBytes?: number | null;
  sessionBufferMaxBytes?: number | null;
  pingIntervalMs?: number | null;
  pingMissTolerance?: number | null;
  pingMinIntervalMs?: number | null;
  extra?: Record<string, unknown>;
}

export interface ConnectAdmissionManifestEntry {
  appId: string;
  namespaces: ReadonlyArray<string>;
  metadata: Record<string, unknown>;
  policy: Record<string, unknown>;
  extra: Record<string, unknown>;
  raw?: Record<string, unknown>;
}

export interface ConnectAdmissionManifest {
  version: number | null;
  entries: ReadonlyArray<ConnectAdmissionManifestEntry>;
  manifestHash: string | null;
  updatedAt: string | null;
  extra: Record<string, unknown>;
  raw?: Record<string, unknown>;
}

export type ConnectAdmissionManifestInput =
  | ConnectAdmissionManifest
  | {
      manifest?: unknown;
      entries?: ReadonlyArray<Record<string, unknown>>;
      apps?: ReadonlyArray<Record<string, unknown>>;
      version?: number | string | null;
      manifestHash?: string | null;
      manifest_hash?: string | null;
      updatedAt?: string | null;
      updated_at?: string | null;
      [key: string]: unknown;
    };

export type ConnectWebSocketProtocols = string | ReadonlyArray<string>;

export type ConnectWebSocketConstructor<T = unknown> = new (
  url: string,
  protocols?: ConnectWebSocketProtocols,
  options?: unknown,
) => T;

export interface ConnectWebSocketParams {
  sid: string;
  role: "app" | "wallet";
  token: string;
  endpointPath?: string;
  allowInsecure?: boolean;
}

export interface ConnectWebSocketDialOptions<T = unknown>
  extends ConnectWebSocketParams {
  baseUrl: string;
  protocols?: ConnectWebSocketProtocols;
  websocketOptions?: unknown;
  WebSocketImpl?: ConnectWebSocketConstructor<T>;
  insecureTransportTelemetryHook?: (
    event: InsecureTransportTelemetryEvent,
  ) => void;
}

export interface ClientConnectWebSocketOptions<T = unknown>
  extends ConnectWebSocketParams {
  protocols?: ConnectWebSocketProtocols;
  websocketOptions?: unknown;
  WebSocketImpl?: ConnectWebSocketConstructor<T>;
  insecureTransportTelemetryHook?: (
    event: InsecureTransportTelemetryEvent,
  ) => void;
}

/**
 * Exact protocol `u64` decoded from JSON.
 *
 * Values through `Number.MAX_SAFE_INTEGER` remain numbers; larger values are
 * returned as bigint so typed Sumeragi reads never round wire integers.
 */
export type ToriiU64 = number | bigint;

export interface ToriiLaneRuntimeUpgradeHookSnapshot {
  allow: boolean;
  require_metadata: boolean;
  metadata_key?: string | null;
  allowed_ids: string[];
}

export interface ToriiLaneMerkleCommitmentSnapshot {
  root: string;
  max_depth: number;
}

export interface ToriiLanePrivacyCommitmentSnapshot {
  id: number;
  scheme: "merkle";
  merkle: ToriiLaneMerkleCommitmentSnapshot;
}

export interface ToriiLaneGovernanceSnapshot {
  lane_id: number;
  alias: string;
  dataspace_id: number;
  visibility: string;
  storage_profile: string;
  governance?: string | null;
  manifest_required: boolean;
  manifest_ready: boolean;
  manifest_path?: string | null;
  validator_ids: string[];
  quorum?: number | null;
  protected_namespaces: string[];
  runtime_upgrade?: ToriiLaneRuntimeUpgradeHookSnapshot | null;
  privacy_commitments: ToriiLanePrivacyCommitmentSnapshot[];
}

export interface ToriiGovernanceProposalSnapshot {
  proposed: number;
  rejected: number;
  enacted: number;
  superseded: number;
  execution_failed: number;
}

export interface ToriiGovernanceProtectedNamespaceSnapshot {
  total_checks: number;
  allowed: number;
  rejected: number;
}

export interface ToriiGovernanceManifestAdmissionSnapshot {
  total_checks: number;
  allowed: number;
  missing_manifest: number;
  non_validator_authority: number;
  quorum_rejected: number;
  protected_namespace_rejected: number;
  runtime_hook_rejected: number;
}

export interface ToriiGovernanceManifestQuorumSnapshot {
  total_checks: number;
  satisfied: number;
  rejected: number;
}

export interface ToriiGovernanceManifestActivationSnapshot {
  contract_address: string;
  code_hash_hex: string;
  abi_hash_hex?: string | null;
  height: number;
  activated_at_ms: number;
}

export interface ToriiGovernanceStatusSnapshot {
  proposals: ToriiGovernanceProposalSnapshot;
  protected_namespace: ToriiGovernanceProtectedNamespaceSnapshot;
  manifest_admission: ToriiGovernanceManifestAdmissionSnapshot;
  manifest_quorum: ToriiGovernanceManifestQuorumSnapshot;
  recent_manifest_activations: ReadonlyArray<ToriiGovernanceManifestActivationSnapshot>;
  sealed_lanes_total: number;
  sealed_lane_aliases: ReadonlyArray<string>;
}

export type ToriiGovernanceProposalStatus =
  | "Proposed"
  | "Rejected"
  | "Enacted"
  | "Superseded"
  | "ExecutionFailed";

export interface ToriiGovernanceDeployContractProposal {
  proposal_operator: string;
  contract_address: string;
  code_hash: string;
  abi_hash: string;
  abi_version: 1;
  manifest_provenance: ToriiGovernanceManifestProvenance | null;
}

export interface ToriiGovernanceManifestProvenance {
  signer: string;
  signature: string;
}

export interface ToriiGovernanceRuntimeUpgradeSbomDigest {
  algorithm: string;
  digest: string;
}

export interface ToriiGovernanceRuntimeUpgradeManifest {
  name: string;
  description: string;
  abi_version: 1;
  abi_hash: ReadonlyArray<number>;
  added_syscalls: readonly [];
  added_pointer_types: readonly [];
  start_height: number;
  end_height: number;
  sbom_digests: ReadonlyArray<ToriiGovernanceRuntimeUpgradeSbomDigest>;
  slsa_attestation: string;
  provenance: ReadonlyArray<ToriiGovernanceManifestProvenance>;
}

export interface ToriiGovernanceRuntimeUpgradeProposal {
  proposal_operator: string;
  manifest: ToriiGovernanceRuntimeUpgradeManifest;
}

export interface ToriiGovernanceSccpRouteProposal {
  proposal: {
    network_id: string;
    base_revisions: ReadonlyArray<Readonly<Record<string, unknown>>>;
    actions: ReadonlyArray<Readonly<Record<string, unknown>>>;
  };
}

export type ToriiGovernanceValidationFeeChargingMode = Readonly<{
  charging_mode: "RETAIL_MONTHLY_ALLOWANCE";
  value: null;
}>;

export interface ToriiGovernanceValidationFeePayoutBinding {
  contract_address: string;
  code_hash: string;
  entrypoint: "autonomous_validation_fee_tick";
  treasury_account_id: string;
  ds_asset_id: string;
  xor_asset_id: string;
  pool_contract_address: string;
  pool_code_hash: string;
  pool_vault_account_id: string;
  reward_pool_account_id: string;
  reference_feed_id: readonly [string];
  reference_feed_config_version: number;
  reference_provider_accounts: ReadonlyArray<string>;
  max_sbd_per_attempt_minor: number | bigint;
  max_sbd_per_day_minor: number | bigint;
  min_interval_ms: number | bigint;
  max_source_age_ms: number | bigint;
  max_slippage_bps: number;
  validator_lane_id: number;
  min_reward_claim_xor_minor: number | bigint;
}

export interface ToriiGovernanceValidationFeePolicyV1 {
  schema_version: 1;
  network_id: string;
  policy_version: string;
  previous_policy_hash: string | null;
  ds_asset_id: string;
  ds_scale: 2;
  fee: string;
  treasury_account_id: string;
  charging_mode: ToriiGovernanceValidationFeeChargingMode;
  exemption_classes: readonly ["TREASURY_PAYOUT"];
  effective_from_ms: number | bigint;
  notice_published_at_ms: number | bigint;
  retail_schedule: RetailFeeScheduleV1;
  reward_custody: ValidationFeeRewardCustodyV1;
}

export interface ToriiGovernanceValidationFeePolicyProposal {
  proposal_operator: string;
  policy: ToriiGovernanceValidationFeePolicyV1;
}

export interface ToriiGovernanceValidationFeePayoutLifecycleProposal {
  proposal_operator: string;
  payout_binding: ToriiGovernanceValidationFeePayoutBinding;
}

export type ToriiGovernanceMusubiPackageScope = Readonly<
  | { kind: "DataspaceRoot"; value: null }
  | { kind: "Domain"; value: string }
>;

export interface ToriiGovernanceMusubiPackageId {
  home_dataspace: number;
  scope: ToriiGovernanceMusubiPackageScope;
  name: string;
}

export type ToriiGovernanceMusubiPrereleaseIdentifier = Readonly<
  | { kind: "Numeric"; value: number }
  | { kind: "AlphaNumeric"; value: string }
>;

export interface ToriiGovernanceMusubiVersion {
  major: number;
  minor: number;
  patch: number;
  prerelease: ReadonlyArray<ToriiGovernanceMusubiPrereleaseIdentifier>;
}

export interface ToriiGovernanceMusubiReleaseId {
  package: ToriiGovernanceMusubiPackageId;
  version: ToriiGovernanceMusubiVersion;
}

export interface ToriiGovernanceMusubiAliasPricingPolicy {
  revision: number;
  length_1_xor: number;
  length_2_xor: number;
  length_3_xor: number;
  length_4_xor: number;
  length_5_to_32_xor: number;
}

export interface ToriiGovernanceMusubiRegistryPolicy {
  version: 1;
  revision: number;
  mode: Readonly<
    | { kind: "Closed"; value: null }
    | { kind: "Allowlisted"; value: null }
    | { kind: "Open"; value: null }
  >;
  allowlisted_dataspaces: ReadonlyArray<number>;
  alias_pricing: ToriiGovernanceMusubiAliasPricingPolicy;
}

export type ToriiGovernanceMusubiAction = Readonly<
  | {
      kind: "RecoverPackageOwners";
      value: {
        package: ToriiGovernanceMusubiPackageId;
        owners: ReadonlyArray<string>;
        expected_revision: number;
      };
    }
  | {
      kind: "RetargetAlias";
      value: {
        alias: string;
        target: ToriiGovernanceMusubiPackageId;
        expected_revision: number;
      };
    }
  | {
      kind: "TakedownArtifact";
      value: {
        release: ToriiGovernanceMusubiReleaseId;
        reason: string;
        expected_artifact_governance_revision: number;
      };
    }
  | {
      kind: "SetRegistryPolicy";
      value: {
        policy: ToriiGovernanceMusubiRegistryPolicy;
        expected_revision: number;
      };
    }
>;

export type ToriiGovernanceSorafsProviderAction = Readonly<
  | {
      action: "establish";
      value: { provider_id: ReadonlyArray<number>; owner: string };
    }
  | {
      action: "rebind";
      value: {
        provider_id: ReadonlyArray<number>;
        expected_owner: string;
        next_owner: string;
      };
    }
  | {
      action: "remove";
      value: { provider_id: ReadonlyArray<number>; expected_owner: string };
    }
>;

export interface ToriiGovernanceSorafsProviderProposal {
  action: ToriiGovernanceSorafsProviderAction;
}

export type ToriiGovernanceContractLifecycleAction = Readonly<
  | {
      action: "Activate";
      payload: {
        code_hash: string;
        abi_hash: string;
        abi_version: 1;
        manifest_provenance: ToriiGovernanceManifestProvenance | null;
      };
    }
  | {
      action: "Deactivate";
      payload: { expected_code_hash: string; reason: string | null };
    }
  | {
      action: "OfferOwnership";
      payload: { new_owner: string };
    }
  | { action: "CancelOwnershipOffer"; payload: null }
  | { action: "AcceptParliamentOwnership"; payload: null }
  | {
      action: "CompleteEmergencyHoldRetrospective";
      payload: {
        hold_proposal_content_id: ReadonlyArray<number>;
        hold_governance_attempt_id: ReadonlyArray<number>;
        incident_digest: ReadonlyArray<number>;
        retrospective_finding_root: ReadonlyArray<number>;
      };
    }
>;

export interface ToriiGovernanceContractLifecycleProposal {
  proposal_operator: string;
  contract_address: string;
  expected_revision: number;
  action: ToriiGovernanceContractLifecycleAction;
}

export interface ToriiGovernanceContractEmergencyHoldProposal {
  contract_address: string;
  expected_revision: number;
  expected_code_hash: string;
  incident_digest: ReadonlyArray<number>;
  reason: string;
  duration_blocks: number;
}

export interface ToriiGovernanceGlobalDataTriggerPermissionProposal {
  authority: string;
  action: Readonly<{
    action: "grant" | "revoke";
    value: null;
  }>;
}

export interface ToriiGovernanceContractEmergencyHold {
  incident_digest_hex: string;
  proposal_content_id_hex: string;
  governance_attempt_id_hex: string;
  reason: string;
  imposed_at_height: ToriiU64;
  expires_at_height: ToriiU64;
}

export interface ToriiGovernanceContractLifecycle {
  version: 1;
  origin: "direct" | "parliament";
  origin_account: string;
  origin_proposal_content_id_hex: string | null;
  origin_governance_attempt_id_hex: string | null;
  owner: string;
  pending_owner: string | null;
  parliament_delegated: boolean;
  active_code_hash_hex: string | null;
  revision: ToriiU64;
  emergency_hold: ToriiGovernanceContractEmergencyHold | null;
}

export interface ToriiGovernanceContractResponse {
  found: boolean;
  contract_address: string;
  contract_subject_account: string | null;
  dataspace: string | null;
  active: boolean | null;
  lifecycle: ToriiGovernanceContractLifecycle | null;
  emergency_hold_active: boolean | null;
  code_hash_hex: string | null;
  abi_hash_hex: string | null;
  public_entrypoints: string[] | null;
}

export type ToriiGovernanceProposalKind =
  | Readonly<{
      variant: "DeployContract";
      deploy_contract: ToriiGovernanceDeployContractProposal;
    }>
  | Readonly<{
      variant: "RuntimeUpgrade";
      runtime_upgrade: ToriiGovernanceRuntimeUpgradeProposal;
    }>
  | Readonly<{
      variant: "SccpRouteGovernance";
      sccp_route_governance: ToriiGovernanceSccpRouteProposal;
    }>
  | Readonly<{
      variant: "ValidationFeePolicy";
      validation_fee_policy: ToriiGovernanceValidationFeePolicyProposal;
    }>
  | Readonly<{
      variant: "ValidationFeePayoutLifecycle";
      validation_fee_payout_lifecycle: ToriiGovernanceValidationFeePayoutLifecycleProposal;
    }>
  | Readonly<{
      variant: "MusubiRegistryGovernance";
      musubi_registry_governance: ToriiGovernanceMusubiAction;
    }>
  | Readonly<{
      variant: "SorafsProviderGovernance";
      sorafs_provider_governance: ToriiGovernanceSorafsProviderProposal;
    }>
  | Readonly<{
      variant: "ContractLifecycleGovernance";
      contract_lifecycle_governance: ToriiGovernanceContractLifecycleProposal;
    }>
  | Readonly<{
      variant: "ContractEmergencyHold";
      contract_emergency_hold: ToriiGovernanceContractEmergencyHoldProposal;
    }>
  | Readonly<{
      variant: "GlobalDataTriggerPermissionGovernance";
      global_data_trigger_permission_governance: ToriiGovernanceGlobalDataTriggerPermissionProposal;
    }>;

export interface ToriiGovernanceProposalRecord {
  proposer: string;
  created_height: number;
  status: ToriiGovernanceProposalStatus;
  kind: ToriiGovernanceProposalKind;
}

export interface ToriiGovernanceProposalResult {
  found: boolean;
  proposal: ToriiGovernanceProposalRecord | null;
}

/** Lossless unsigned JSON integer; bigint is used above Number.MAX_SAFE_INTEGER. */
export type ToriiGovernanceUnsigned = number | bigint;

export interface ToriiPlainConvictionPolicyV1 {
  asset_definition_id: string;
  asset_scale: number;
  conviction_step_blocks: ToriiGovernanceUnsigned;
  max_conviction: ToriiGovernanceUnsigned;
  approval_threshold_numerator: ToriiGovernanceUnsigned;
  approval_threshold_denominator: ToriiGovernanceUnsigned;
  minimum_turnout: ToriiGovernanceUnsigned;
  minimum_bond: string;
  bond_escrow_account: string;
  slash_receiver_account: string;
}
export interface ToriiPlainVotingDecisionV1 {
  approve: ToriiGovernanceUnsigned;
  reject: ToriiGovernanceUnsigned;
  abstain: ToriiGovernanceUnsigned;
  approved: boolean;
}
export type ToriiGovernanceReferendumRecord = {
  h_start: ToriiGovernanceUnsigned;
  h_end: ToriiGovernanceUnsigned;
} & (
  | { mode: "Zk"; status: "Proposed" | "Open" | "Closed";
      plain_context: { kind: "NotApplicable"; content: null };
      plain_result: { kind: "NotApplicable"; content: null } }
  | { mode: "Plain"; plain_context: { kind: "Conviction"; content: ToriiPlainConvictionPolicyV1 } } & (
      | { status: "Proposed" | "Open"; plain_result: { kind: "Pending"; content: null } }
      | { status: "Closed"; plain_result: { kind: "Decided"; content: ToriiPlainVotingDecisionV1 } }
    )
);
/** Exact wire response after closed-schema, lossless decoding. */
export type ToriiGovernanceReferendumResponse =
  | { found: false }
  | { found: true; referendum: ToriiGovernanceReferendumRecord };
export interface ToriiGovernanceReferendumResult {
  found: boolean;
  referendum: ToriiGovernanceReferendumRecord | null;
}

export interface ToriiGovernanceTally {
  referendum_id: string;
  evaluated_block_height: ToriiGovernanceUnsigned;
  evaluated_block_hash: string;
  approve: ToriiGovernanceUnsigned;
  reject: ToriiGovernanceUnsigned;
  abstain: ToriiGovernanceUnsigned;
}

export interface ToriiGovernanceTallyResult {
  found: boolean;
  referendum_id: string;
  tally: ToriiGovernanceTally | null;
}

/** Exact standalone-election weights at one committed block. */
export interface ToriiElectionTally {
  evaluated_block_height: number | bigint;
  evaluated_block_hash: string;
  finalized: boolean;
  tally: Array<number | bigint>;
}

export interface ToriiGovernanceLockCustody {
  escrowed: boolean;
  asset_definition_id: string;
  bond_escrow_account: string;
  slash_receiver_account: string;
}

export interface ToriiGovernanceLockRecord {
  owner: string;
  amount: string;
  slashed: string;
  expiry_height: ToriiGovernanceUnsigned;
  direction: number;
  duration_blocks: ToriiGovernanceUnsigned;
  custody: ToriiGovernanceLockCustody;
}

export interface ToriiGovernanceLocksResult {
  found: boolean;
  referendum_id: string;
  locks: Record<string, ToriiGovernanceLockRecord>;
}

/** Exact nested Core corpus; the typed convenience method projects its inner map. */
export type ToriiGovernanceLocksResponse =
  | { found: false; referendum_id: string }
  | { found: true; referendum_id: string;
      locks: { locks: Record<string, ToriiGovernanceLockRecord> } };

export interface ToriiGovernanceUnlockStats {
  height_current: number;
  expired_locks_now: number;
  referenda_with_expired: number;
  last_sweep_height: number;
}

export interface ToriiProtectedNamespacesApplyResponse {
  ok: boolean;
  applied: number;
}

export interface ToriiProtectedNamespacesGetResponse {
  found: boolean;
  namespaces: string[];
}

export interface ToriiGovernanceDraftInstruction {
  wire_id: string;
  payload_hex?: string | null;
}

export interface ToriiGovernanceDraftResponse {
  ok: boolean;
  proposal_id: string | null;
  tx_instructions: ReadonlyArray<ToriiGovernanceDraftInstruction>;
  accepted?: boolean;
  reason?: string | null;
}

export interface ToriiGovernanceProposalInstructionDraftV1 {
  wire_id: string;
  payload_hex: string;
}

export interface ToriiGovernanceProposalDraftResponseV1 {
  proposal_id: string;
  tx_instructions: readonly [ToriiGovernanceProposalInstructionDraftV1];
}

export const PARLIAMENT_API_VERSION_V1: 1;
export const PARLIAMENT_ATTEMPT_DRAFT_PATH_V1: "/v1/gov/parliament/attempts/draft";
export const PARLIAMENT_ATTEMPT_READ_PATH_V1: "/v1/gov/parliament/attempts/{governance_attempt_id}";
export const PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_READ_PATH_V1: "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-context";
export const PARLIAMENT_TIMED_OVN_CASTING_PROOF_PATH_V1: "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-proof";
export const PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1: 1;
export const PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_NAME_V1: "iroha.torii.v1.parliament.timed_ovn_casting_proof.request";
export const PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX_V1: "adccf322a5fcf43040e20bea238f55f3";
export const PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_NAME_V1: "iroha.torii.v1.parliament.timed_ovn_casting_proof.response";
export const PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX_V1: "46d29299272433b1299646bee722bd11";
export const PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS_V1: 2;
export const PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT_V1: 8;
export const PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PADDING_BYTES_V1: 0;
export const PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_BYTES_V1: 52;
export const PARLIAMENT_TLE_RELEASE_CONTEXT_READ_PATH_V1: "/v1/gov/parliament/ballots/{ballot_attempt_id}/release-context";
export const PARLIAMENT_TLE_PARTIAL_RELEASE_PATH_V1: "/v1/gov/parliament/ballots/{ballot_attempt_id}/partial-release";
export const PARLIAMENT_TRANSITION_DRAFT_PATH_V1: "/v1/gov/parliament/transitions/draft";
export const PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1: "iroha.governance.parliament.attempt.create.v1";
export const PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1: "iroha.governance.parliament.transition.submit.v1";
export const PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1: 16777216;
export const PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1: 16;
export const PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1: 3624;
export const PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1: 2858;
export const PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1: 32;
export const PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1: 1000;
export const PARLIAMENT_TLE_MAX_COMMITTEE_SIZE_V1: 31;
export const PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1: 4194304;
export const PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_MAX_BYTES_V1: 8388608;

export type ParliamentProposalTagV1 =
  | "DeployContract"
  | "RuntimeUpgrade"
  | "SccpRouteGovernance"
  | "ValidationFeePolicy"
  | "ValidationFeePayoutLifecycle"
  | "MusubiRegistryGovernance"
  | "SorafsProviderGovernance"
  | "ContractLifecycleGovernance"
  | "ContractEmergencyHold"
  | "GlobalDataTriggerPermissionGovernance";

export const PARLIAMENT_PROPOSAL_KINDS_V1: ReadonlyArray<ParliamentProposalTagV1>;

export type ParliamentContractLifecycleActionTagV1 =
  | "Activate"
  | "Deactivate"
  | "OfferOwnership"
  | "CancelOwnershipOffer"
  | "AcceptParliamentOwnership"
  | "CompleteEmergencyHoldRetrospective";

export const PARLIAMENT_CONTRACT_LIFECYCLE_ACTIONS_V1: ReadonlyArray<ParliamentContractLifecycleActionTagV1>;

export type ParliamentPublicTransitionTagV1 =
  | "EscalateRisk"
  | "CompleteQualification"
  | "RegisterSortitionRequest"
  | "ConsumeSortitionPulseBatch"
  | "BeginInvitationAcceptance"
  | "FailBodyElectionNoRoster"
  | "SealBodyRoster"
  | "AdvanceBodyPhase"
  | "RecordAttemptAbsence"
  | "EndorsePublicFinding"
  | "RegisterBallotAttempt"
  | "CloseBallotRegistration"
  | "FreezeBallotSurvivors"
  | "FreezeTimedOvnCorpus"
  | "BeginBallotOpeningBatch"
  | "FailBallotNoResult"
  | "FinalizeOpenedBallot"
  | "RecordInvitationResponse"
  | "RegisterBallotParticipant"
  | "RecordBallotDropout"
  | "FailPublicFindingNoResult"
  | "RegisterInitialSortition";

export interface ParliamentTransitionLayoutV1 {
  readonly noritoIndex: number;
  readonly jsonTag: ParliamentPublicTransitionTagV1;
  readonly jsonPayloadRequired: boolean;
  readonly eventKindIndex: number;
}

export interface ParliamentAutomaticExecutionOutcomeLayoutV1 {
  readonly noritoIndex: number;
  readonly jsonTag: "Enacted" | "Superseded" | "ExecutionFailed";
  readonly jsonPayloadRequired: boolean;
  readonly eventKind: "MarkEnacted" | "MarkSuperseded" | "MarkExecutionFailed";
  readonly eventKindIndex: 17 | 18 | 19;
}

export type ParliamentNoResultKindTagV1 =
  | "PublicFindingQuorumUnreachable"
  | "PublicFindingDeadlineExpired"
  | "BallotRegistrationDeadlineExpired"
  | "BallotSurvivorDeadlineExpired"
  | "BallotCommitmentDeadlineExpired"
  | "BallotReleasePulseUnavailable"
  | "BallotOpeningDeadlineExpired"
  | "SortitionRetriesExhausted"
  | "ConfirmationJuryCapacityUnavailable"
  | "RandomnessRedrawBudgetExhausted";

export interface ParliamentNoResultKindLayoutV1 {
  readonly noritoIndex: number;
  readonly jsonTag: ParliamentNoResultKindTagV1;
}

export type ParliamentBodyNameV1 =
  | "rules-committee"
  | "agenda-council"
  | "interest-panel"
  | "review-panel"
  | "coordination-council"
  | "mpc-committee"
  | "fma-committee"
  | "oversight-committee"
  | "policy-jury"
  | "confirmation-jury";

export const PARLIAMENT_PUBLIC_TRANSITIONS_V1: ReadonlyArray<ParliamentTransitionLayoutV1>;
/** Read/audit-only inventory; these tags are never accepted by the public builder. */
export const PARLIAMENT_AUTOMATIC_EXECUTION_OUTCOMES_V1: ReadonlyArray<ParliamentAutomaticExecutionOutcomeLayoutV1>;
export const PARLIAMENT_NO_RESULT_KINDS_V1: ReadonlyArray<ParliamentNoResultKindLayoutV1>;
/** Canonical presentation order for first-release Parliament bodies. */
export const PARLIAMENT_CANONICAL_BODY_ORDER_V1: ReadonlyArray<ParliamentBodyNameV1>;
export const PARLIAMENT_BODY_STATE_FIELDS_V1: ReadonlyArray<
  | "body"
  | "body_instance_id"
  | "status"
  | "public_finding_opened_at_height"
  | "public_finding_phase_blocks"
  | "public_finding_deadline_height"
  | "no_result_kind"
  | "no_result_height"
  | "timed_ovn_progress"
>;
export const PARLIAMENT_CERTIFICATE_BODY_BINDING_FIELDS_V1: ReadonlyArray<string>;
export const PARLIAMENT_PUBLIC_FINDING_CERTIFICATE_FIELDS_V1: ReadonlyArray<
  "endorsement_root" | "endorsing_assignments" | "endorsements" | "quorum"
>;

export interface ParliamentMusubiPackageIdV1 {
  home_dataspace: number;
  scope: ToriiGovernanceMusubiPackageScope;
  /** Exact Norito JSON tuple encoding of `MusubiPackageNameV1`. */
  name: readonly [string];
}

export interface ParliamentMusubiReleaseIdV1 {
  package: ParliamentMusubiPackageIdV1;
  version: ToriiGovernanceMusubiVersion;
}

export type ParliamentMusubiActionV1 = Readonly<
  | {
      kind: "RecoverPackageOwners";
      value: {
        package: ParliamentMusubiPackageIdV1;
        owners: ReadonlyArray<string>;
        expected_revision: number;
      };
    }
  | {
      kind: "RetargetAlias";
      value: {
        /** Exact Norito JSON tuple encoding of `MusubiAliasNameV1`. */
        alias: readonly [string];
        target: ParliamentMusubiPackageIdV1;
        expected_revision: number;
      };
    }
  | {
      kind: "TakedownArtifact";
      value: {
        release: ParliamentMusubiReleaseIdV1;
        /** Exact Norito JSON tuple encoding of `MusubiReasonV1`. */
        reason: readonly [string];
        expected_artifact_governance_revision: number;
      };
    }
  | {
      kind: "SetRegistryPolicy";
      value: {
        policy: ToriiGovernanceMusubiRegistryPolicy;
        expected_revision: number;
      };
    }
>;

export type ParliamentSorafsProviderActionV1 = Readonly<
  | {
      action: "establish";
      value: {
        /** Exact Norito JSON tuple encoding of `ProviderId`. */
        provider_id: readonly [ReadonlyArray<number>];
        owner: string;
      };
    }
  | {
      action: "rebind";
      value: {
        provider_id: readonly [ReadonlyArray<number>];
        expected_owner: string;
        next_owner: string;
      };
    }
  | {
      action: "remove";
      value: {
        provider_id: readonly [ReadonlyArray<number>];
        expected_owner: string;
      };
    }
>;

export type ParliamentProposalV1 =
  | Readonly<{
      kind: "DeployContract";
      payload: ToriiGovernanceDeployContractProposal;
    }>
  | Readonly<{
      kind: "RuntimeUpgrade";
      payload: ToriiGovernanceRuntimeUpgradeProposal;
    }>
  | Readonly<{
      kind: "SccpRouteGovernance";
      payload: ToriiGovernanceSccpRouteProposal;
    }>
  | Readonly<{
      kind: "ValidationFeePolicy";
      payload: ToriiGovernanceValidationFeePolicyProposal;
    }>
  | Readonly<{
      kind: "ValidationFeePayoutLifecycle";
      payload: ToriiGovernanceValidationFeePayoutLifecycleProposal;
    }>
  | Readonly<{
      kind: "MusubiRegistryGovernance";
      payload: ParliamentMusubiActionV1;
    }>
  | Readonly<{
      kind: "SorafsProviderGovernance";
      payload: { action: ParliamentSorafsProviderActionV1 };
    }>
  | Readonly<{
      kind: "ContractLifecycleGovernance";
      payload: ToriiGovernanceContractLifecycleProposal;
    }>
  | Readonly<{
      kind: "ContractEmergencyHold";
      payload: ToriiGovernanceContractEmergencyHoldProposal;
    }>
  | Readonly<{
      kind: "GlobalDataTriggerPermissionGovernance";
      payload: ToriiGovernanceGlobalDataTriggerPermissionProposal;
    }>;

export type ParliamentLifecycleTransitionV1 =
  | { transition: "CompleteQualification" }
  | { transition: "RegisterInitialSortition" }
  | {
      transition: Exclude<
        ParliamentPublicTransitionTagV1,
        "CompleteQualification" | "RegisterInitialSortition"
      >;
      payload: Record<string, unknown>;
    };

export interface ParliamentAttemptDraftRequestV1 {
  version: 1;
  proposal: ParliamentProposalV1;
  attempt_sequence: number;
}

export interface ParliamentTransitionDraftRequestV1 {
  version: 1;
  governance_attempt_id: string;
  transition: ParliamentLifecycleTransitionV1;
}

export interface ParliamentInstructionDraftV1 {
  wire_id: string;
  payload_hex: string;
}

export interface ParliamentAttemptDraftResponseV1 {
  version: 1;
  proposal_content_id: string;
  governance_attempt_id: string;
  tx_instructions: readonly [ParliamentInstructionDraftV1];
}

export interface ParliamentTransitionDraftResponseV1 {
  version: 1;
  governance_attempt_id: string;
  transition_kind: { kind: ParliamentPublicTransitionTagV1 };
  transition_digest: ReadonlyArray<number>;
  tx_instructions: readonly [ParliamentInstructionDraftV1];
}

export interface ParliamentAttemptReadResponseV1 extends Record<string, unknown> {
  version: 1;
  current_height: number | bigint;
  attempt: Record<string, unknown> & { id: string };
  policy_version: number | bigint;
  required_bodies: ReadonlyArray<{
    body: ParliamentBodyNameV1;
    decision_mode: { mode: "PublicFinding" | "HiddenBindingBallot" };
  }>;
  body_states: ReadonlyArray<ParliamentBodyStateProjectionV1>;
  certificate: (Record<string, unknown> & {
    body_bindings: ReadonlyArray<Record<string, unknown> & { body: ParliamentBodyNameV1 }>;
  }) | null;
  terminal_height: number | bigint | null;
  execution_failure_root: ReadonlyArray<number> | null;
  superseding_head: Record<string, unknown> | null;
  state_payload_hex: string;
}

export interface ParliamentBodyStateProjectionV1 {
  body: string;
  body_instance_id: string | null;
  status: Record<string, unknown> | null;
  public_finding_opened_at_height: number | bigint | null;
  public_finding_phase_blocks: number | bigint | null;
  public_finding_deadline_height: number | bigint | null;
  no_result_kind: { reason: ParliamentNoResultKindTagV1 } | null;
  no_result_height: number | bigint | null;
  timed_ovn_progress: ParliamentTimedOvnProgressProjectionV1 | null;
}

export type ParliamentBallotAttemptStatusTagV1 =
  | "Registration"
  | "SurvivorFreeze"
  | "TimedCommitment"
  | "AwaitingRelease"
  | "Opening"
  | "Finalized"
  | "NoResult"
  | "Superseded";

/** Aggregate-only next-offset projection; contains no ballot or participant evidence. */
export interface ParliamentTimedOvnProgressProjectionV1 {
  ballot_attempt_id: string;
  status: { status: ParliamentBallotAttemptStatusTagV1 };
  frozen_survivor_count: number | null;
  accepted_ballot_prefix_count: number | null;
}

export interface ParliamentTleAdaptiveDealerCommitmentV1 {
  dealer_index: number;
  coefficient_commitments: ReadonlyArray<ReadonlyArray<number>>;
  constant_pok_commitment: ReadonlyArray<number>;
  constant_pok_response: ReadonlyArray<number>;
}

export interface ParliamentTleAdaptivePublicShareV1 {
  index: number;
  participant_hash: ReadonlyArray<number>;
  public_key_share: ReadonlyArray<number>;
}

/** Complete public transcript required for independent adaptive-partial verification. */
export interface ParliamentTleKeySessionPublicStateV1 {
  version: 1;
  key_session_id: string;
  network_id: ReadonlyArray<number>;
  roster_hash: ReadonlyArray<number>;
  committee_size: number;
  threshold: number;
  generator_h: ReadonlyArray<number>;
  generator_v: ReadonlyArray<number>;
  qualified_dealers: ReadonlyArray<number>;
  qualified_dealer_commitments: ReadonlyArray<ParliamentTleAdaptiveDealerCommitmentV1>;
  dkg_event_hash: ReadonlyArray<number>;
  group_public_key: ReadonlyArray<number>;
  public_shares: ReadonlyArray<ParliamentTleAdaptivePublicShareV1>;
  transcript_hash: ReadonlyArray<number>;
}

export interface ParliamentTimedOvnReleaseIdentityProjectionV1 {
  tle_key_session_id: string;
  governance_attempt_id: string;
  body_instance_id: string;
  ballot_attempt_id: string;
  survivor_corpus_root: ReadonlyArray<number>;
  no_recovery_root: ReadonlyArray<number>;
  target_finalized_height: number | bigint;
  parameter_hash: ReadonlyArray<number>;
}

export type ParliamentTimedOvnCastingPhaseV1 =
  | "Registered"
  | "RegistrationClosed"
  | "SurvivorsFrozen";

export interface ParliamentTimedOvnSessionProjectionV1 {
  network_id: ReadonlyArray<number>;
  proposal_content_id: string;
  governance_attempt_id: string;
  body_instance_id: string;
  ballot_attempt_id: string;
  parameter_hash: ReadonlyArray<number>;
  tle_key_session_id: string;
  tle_key_transcript_hash: ReadonlyArray<number>;
  tle_master_public_key: ReadonlyArray<number>;
}

export interface ParliamentTimedOvnCastingContextResponseV1 {
  version: 1;
  current_height: number | bigint;
  phase: ParliamentTimedOvnCastingPhaseV1;
  session: ParliamentTimedOvnSessionProjectionV1;
  registration_opened_at_finalized_height: number | bigint;
  target_finalized_height: number | bigint;
  tle_key_session: ParliamentTleKeySessionPublicStateV1;
  registration_records_hex: ReadonlyArray<string>;
  survivor_participant_hashes: ReadonlyArray<ReadonlyArray<number>> | null;
  release_identity: ParliamentTimedOvnReleaseIdentityProjectionV1 | null;
  archive_norito_base64: string;
}

export interface ParliamentTleReleaseContextResponseV1 {
  version: 1;
  current_height: number | bigint;
  ballot_attempt_id: string;
  governance_attempt_id: string;
  body_instance_id: string;
  status: { status: "Opening" };
  release_height: number | bigint;
  opening_deadline_height: number | bigint;
  tle_key_session: ParliamentTleKeySessionPublicStateV1;
  release_identity: ParliamentTimedOvnReleaseIdentityProjectionV1;
  identity_digest: ReadonlyArray<number>;
  identity_payload_hex: string;
}

export interface ParliamentTlePartialReleaseShareV1 {
  key_session_id: string;
  identity_digest: ReadonlyArray<number>;
  participant_index: number;
  sigma: ReadonlyArray<number>;
  proof_x: ReadonlyArray<number>;
  proof_y: ReadonlyArray<number>;
  z_s: ReadonlyArray<number>;
  z_r: ReadonlyArray<number>;
  z_u: ReadonlyArray<number>;
}

export interface ParliamentAttemptDraftOptionsV1 extends RequiredCanonicalRequestOptions {
  expectedProposalContentId: string;
  expectedGovernanceAttemptId: string;
}

export interface ParliamentTransitionDraftOptionsV1 extends RequiredCanonicalRequestOptions {
  expectedTransitionDigest: BinaryLike;
}

export interface ParliamentTlePartialReleaseOptionsV1 extends RequiredCanonicalRequestOptions {
  expectedKeySessionId: string;
  expectedIdentityDigest: BinaryLike;
  committeeSize: number;
}

export function parliamentAttemptReadPathV1(governanceAttemptId: string): string;
export function parliamentTimedOvnCastingContextReadPathV1(ballotAttemptId: string): string;
export function parliamentTimedOvnCastingProofPathV1(ballotAttemptId: string): string;
export function encodeParliamentTimedOvnCastingProofRequestV1(
  trustedCheckpointHeight: number | bigint,
): Buffer;
export function validateParliamentTimedOvnCastingProofResponseFrameV1(
  value: Buffer | ArrayBuffer | ArrayBufferView,
): Buffer;
export function parliamentTleReleaseContextReadPathV1(ballotAttemptId: string): string;
export function parliamentTlePartialReleasePathV1(ballotAttemptId: string): string;
export function buildParliamentAttemptDraftRequestV1(
  proposal: ParliamentProposalV1,
  attemptSequence: number,
): ParliamentAttemptDraftRequestV1;
export function buildParliamentTransitionDraftRequestV1(
  governanceAttemptId: string,
  transition: ParliamentLifecycleTransitionV1,
): ParliamentTransitionDraftRequestV1;
export function normalizeParliamentAttemptDraftResponseV1(
  value: unknown,
  bindings: {
    expectedProposalContentId: string;
    expectedGovernanceAttemptId: string;
  },
): ParliamentAttemptDraftResponseV1;
export function normalizeParliamentTransitionDraftResponseV1(
  value: unknown,
  bindings: {
    expectedGovernanceAttemptId: string;
    expectedTransitionKind: ParliamentPublicTransitionTagV1;
    expectedTransitionDigest: BinaryLike;
  },
): ParliamentTransitionDraftResponseV1;
export function normalizeParliamentAttemptReadResponseV1(
  value: unknown,
  expectedGovernanceAttemptId: string,
): ParliamentAttemptReadResponseV1;
export function normalizeParliamentTimedOvnCastingContextResponseV1(
  value: unknown,
  expectedBallotAttemptId: string,
): ParliamentTimedOvnCastingContextResponseV1;
export function normalizeParliamentTleReleaseContextResponseV1(
  value: unknown,
  expectedBallotAttemptId: string,
): ParliamentTleReleaseContextResponseV1;
export function normalizeParliamentTlePartialReleaseShareV1(
  value: unknown,
  bindings: {
    expectedKeySessionId: string;
    expectedIdentityDigest: BinaryLike;
    committeeSize: number;
  },
): ParliamentTlePartialReleaseShareV1;

export interface MinistryAgendaProposalDraftRequest {
  proposal: MinistryAgendaProposalV1;
  authority: string;
}

export type MinistryAgendaProposalAction =
  | "add-to-denylist"
  | "remove-from-denylist"
  | "amend-policy";

export type MinistryAgendaProposalTag =
  | "csam"
  | "malware"
  | "fraud"
  | "harassment"
  | "impersonation"
  | "policy-escalation"
  | "terrorism"
  | "spam";

export type MinistryAgendaEvidenceKind =
  | "url"
  | "torii-case"
  | "sorafs-cid"
  | "attachment";

export interface MinistryAgendaProposalSummaryV1 {
  title: string;
  motivation: string;
  expected_impact: string;
}

export interface MinistryAgendaProposalTargetV1 {
  label: string;
  hash_family: string;
  hash_hex: string;
  reason: string;
}

export interface MinistryAgendaEvidenceAttachmentV1 {
  kind: MinistryAgendaEvidenceKind;
  uri: string;
  digest_blake3_hex?: string | null;
  description?: string | null;
}

export interface MinistryAgendaProposalSubmitterV1 {
  name: string;
  contact: string;
  organization?: string | null;
  pgp_fingerprint?: string | null;
}

export interface MinistryAgendaProposalV1 {
  version: 1;
  proposal_id: string;
  submitted_at_unix_ms: number | string | bigint;
  language: string;
  action: MinistryAgendaProposalAction;
  summary: MinistryAgendaProposalSummaryV1;
  tags?: ReadonlyArray<MinistryAgendaProposalTag>;
  targets: ReadonlyArray<MinistryAgendaProposalTargetV1>;
  evidence: ReadonlyArray<MinistryAgendaEvidenceAttachmentV1>;
  submitter: MinistryAgendaProposalSubmitterV1;
  duplicates?: ReadonlyArray<string>;
}

export interface MinistryAgendaProposalDraftResponse {
  ok: boolean;
  agenda_proposal_id: string;
  authority: string;
  tx_instructions: ReadonlyArray<ToriiGovernanceDraftInstruction>;
  signable_transaction_b64: string;
}

export interface MinistryAgendaProposalRecord {
  proposal: MinistryAgendaProposalV1;
  authority: string;
  submitted_tx_hash_hex: string;
  submitted_height: number;
}

export interface MinistryAgendaProposalGetResponse {
  found: boolean;
  record: MinistryAgendaProposalRecord | null;
}

export type ToriiGovernanceBallotDirection = "Aye" | "Nay" | "Abstain";

export interface ToriiGovernanceManifestProvenanceInput {
  signer: string;
  signature: string;
}

export interface ToriiGovernanceDeployContractProposalRequest {
  proposalOperator: string;
  contractAddress?: string;
  contractAlias?: string;
  codeHash: string | BinaryLike;
  abiHash: string | BinaryLike;
  abiVersion?: 1;
  manifestProvenance?: ToriiGovernanceManifestProvenanceInput | null;
}

export interface ToriiGovernancePlainBallotRequest {
  authority: string;
  networkId: NetworkId;
  referendumId: string;
  owner: string;
  amount: QuantityInput;
  durationBlocks: number | string | bigint;
  direction: ToriiGovernanceBallotDirection;
}

export interface ToriiGovernanceZkBallotV1Request {
  authority: string;
  networkId: NetworkId;
  electionId: string;
  backend: string;
  envelope: BinaryLike | string;
  rootHint?: string | BinaryLike | null;
  owner?: string | null;
  amount?: QuantityInput | null;
  durationBlocks?: number | bigint | null;
  direction?: ToriiGovernanceBallotDirection | null;
  nullifier?: string | BinaryLike | null;
}

export interface ToriiGovernanceBallotProof {
  backend: string;
  envelopeBytes: BinaryLike | string;
  rootHint?: string | null;
  owner?: string | null;
  nullifier?: string | null;
  amount?: QuantityInput | null;
  durationBlocks?: number | bigint | null;
  direction?: ToriiGovernanceBallotDirection | null;
}

export interface ToriiGovernanceZkBallotProofRequest {
  authority: string;
  networkId: NetworkId;
  electionId: string;
  ballot: ToriiGovernanceBallotProof;
}

export interface ToriiGovernanceBallotResponse
{
  drafted: true;
  tx_instructions: readonly [ToriiGovernanceProposalInstructionDraftV1];
}

export interface ToriiTriggerUpsertRequest {
  id: string;
  action: JsonValue | string;
  metadata?: JsonValue | null;
}

export interface ToriiTriggerMutationResponse {
  ok: boolean;
  trigger_id: string | null;
  tx_instructions: ReadonlyArray<ToriiGovernanceDraftInstruction>;
  accepted?: boolean;
  message?: string;
}

export interface ToriiTriggerRecord {
  id: string;
  action: JsonValue;
  metadata: JsonValue;
  raw: JsonValue;
}

export interface ToriiTriggerListPage {
  items: ReadonlyArray<ToriiTriggerRecord>;
  total: number;
}

export interface ToriiStatusPayload {
  observed_at_ms: number;
  peers: number;
  queue_size: number;
  queue_queued: number;
  queue_inflight: number;
  last_block_committed_at_ms: number;
  last_non_empty_block_committed_at_ms: number;
  time_since_last_block_ms: number;
  time_since_last_non_empty_block_ms: number;
  commit_time_ms: number;
  txs_approved: number;
  txs_rejected: number;
  view_changes: number;
  governance: ToriiGovernanceStatusSnapshot | null;
  lane_governance: ToriiLaneGovernanceSnapshot[];
  dataspace_catalog: ToriiDataspaceCatalogEntry[];
  lane_governance_sealed_total: number;
  lane_governance_sealed_aliases: ReadonlyArray<string>;
  raw: Record<string, unknown>;
}

export interface ToriiStatusMetrics {
  commit_latency_ms: number;
  queue_size: number;
  queue_queued: number;
  queue_inflight: number;
  queue_delta: number;
  time_since_last_block_ms: number;
  time_since_last_non_empty_block_ms: number;
  tx_approved_delta: number;
  tx_rejected_delta: number;
  view_change_delta: number;
  has_activity: boolean;
}

export interface ToriiDataspaceCatalogEntry {
  lane_id: number;
  lane_alias: string;
  dataspace_id: number;
  alias: string;
  visibility: string;
  storage_profile: string;
  manifest_required: boolean;
  manifest_ready: boolean;
  sealed: boolean;
  manifest_path: string | null;
  protected_namespaces: string[];
}

export interface ToriiStatusSnapshot {
  timestamp: number;
  status: ToriiStatusPayload;
  metrics: ToriiStatusMetrics;
}

/**
 * Typed `GET /v1/pipeline/preflight` body. Every object carries exactly the
 * fields Torii serves; any other field is rejected as protocol drift.
 */
export interface ToriiPipelinePreflight {
  schema_version: number;
  chain_height: number;
  sumeragi: {
    /** Signed-genesis target block time in milliseconds (always positive). */
    block_cadence_ms: number;
  };
  admission: {
    max_signatures: number;
    max_instructions: number;
    max_tx_bytes: number;
    max_decompressed_bytes: number;
    max_metadata_depth: number;
  };
  block: {
    max_transactions: number;
  };
  pipeline: {
    signature_batch_max_ed25519: number;
    signature_batch_max_secp256k1: number;
    signature_batch_max_pqc: number;
    signature_batch_max_bls: number;
    overlay_max_instructions: number;
    ivm_max_cycles_upper_bound: number;
    ivm_admission_cycle_limit: number;
    ivm_max_decoded_instructions: number;
  };
  queue: {
    size: number;
    queued: number;
    inflight: number;
  };
  fees: {
    fee_asset_id: string;
    fee_sink_account_id: string;
    /** Canonical decimal quantity string. */
    base_fee: string;
    /** Canonical decimal quantity string. */
    per_byte_fee: string;
    /** Canonical decimal quantity string. */
    per_instruction_fee: string;
    /** Canonical decimal quantity string. */
    per_gas_unit_fee: string;
    sponsor_vault_custody_account_id: string;
    settlement_mode: "direct" | "lane_relay_burn";
    successful_claim_fee_exempt_authorities: string[];
  };
  raw: Readonly<Record<string, unknown>>;
  /**
   * SDK-derived stall threshold, not a served field:
   * `20 * sumeragi.block_cadence_ms`, saturated at `Number.MAX_SAFE_INTEGER`.
   * Twenty target block cadences cover one crashed leader's view change at
   * the Sumeragi default timings (`specs/sumeragi.md` §8.2 P4, §9.3).
   */
  stallThresholdMs: number;
  /**
   * `isStatusQueueStalled(status, stallThresholdMs)`: queued work exists and
   * no non-empty block was committed for longer than `stallThresholdMs`.
   */
  isStatusStalled(
    status: ToriiStatusPayload | Record<string, unknown>,
  ): boolean;
}

/**
 * Milliseconds since the last committed non-empty block, or since the last
 * block while the peer has not reported a non-empty one.
 */
export function statusLivenessElapsedMs(
  status: ToriiStatusPayload | Record<string, unknown>,
): number;

/**
 * True when `queue_size > 0` and `statusLivenessElapsedMs(status)` exceeds
 * `stallThresholdMs`.
 */
export function isStatusQueueStalled(
  status: ToriiStatusPayload | Record<string, unknown>,
  stallThresholdMs: number | string | bigint,
): boolean;

export interface ToriiNetworkTimeNow {
  timestampMs: number;
  offsetMs: number;
  confidenceMs: number;
}

export interface ToriiNetworkTimePeerSample {
  peer: string;
  lastOffsetMs: number;
  lastRttMs: number;
  count: number;
}

export interface ToriiNetworkTimeRttBucket {
  le: number;
  count: number;
}

export interface ToriiNetworkTimeRttHistogram {
  buckets: ReadonlyArray<ToriiNetworkTimeRttBucket>;
  sumMs: number;
  count: number;
}

export interface ToriiNetworkTimeStatus {
  peers: number;
  samples: ReadonlyArray<ToriiNetworkTimePeerSample>;
  rtt: ToriiNetworkTimeRttHistogram;
  note: string | null;
}

/** Public, account-free V1 bootstrap policy; the default is explicit and unrelated to list order. */
export interface AccountCapabilitiesV1 {
  readonly schema_version: 1;
  readonly network_id: string;
  readonly network_prefix: number;
  readonly allowed_signing: readonly CryptoAlgorithm[];
  readonly default_signing: "ed25519";
}

export interface ToriiNodeCapabilities {
  abiVersion: number;
  dataModelVersion: number;
  crypto: {
    sm: ToriiNodeSmCapabilities;
    curves: ToriiNodeCurveCapabilities;
  };
}

export interface ToriiNodeSmCapabilities {
  enabled: boolean;
  defaultHash: string | null;
  allowedSigning: ReadonlyArray<string>;
  sm2DistIdDefault: string | null;
  opensslPreview: boolean;
  acceleration: ToriiNodeSmAcceleration;
}

export interface ToriiNodeSmAcceleration {
  scalar: boolean;
  neonSm3: boolean;
  neonSm4: boolean;
  policy: string;
}

export interface ToriiNodeCurveCapabilities {
  registryVersion: number;
  allowedCurveIds: ReadonlyArray<number>;
  allowedCurveBitmap: ReadonlyArray<number>;
}

export interface ToriiLoggerConfig {
  level: string;
  filter: string | null;
}

export interface ToriiNetworkConfig {
  blockGossipSize: number;
  blockGossipPeriodMs: number;
  transactionGossipSize: number;
  transactionGossipPeriodMs: number;
}

export interface ToriiQueueConfig {
  capacity: number;
}

export interface ToriiConfigurationSnapshot {
  publicKeyHex: string;
  logger: ToriiLoggerConfig;
  network: ToriiNetworkConfig;
  queue: ToriiQueueConfig | null;
  confidentialGas: ConfidentialGasSchedule | null;
  transport: ToriiConfigurationTransport | null;
}

export interface ToriiRuntimeAbiActiveResponse {
  abiVersion: number;
}

export interface ToriiRuntimeAbiHashResponse {
  policy: string;
  abiHashHex: string;
}

export interface ToriiRuntimeMetrics {
  abiVersion: number;
  upgradeEventsTotal: ToriiRuntimeMetricsCounters;
}

export interface ToriiRuntimeMetricsCounters {
  proposed: number;
  activated: number;
  canceled: number;
}

export interface ToriiConfigurationTransport {
  noritoRpc: ToriiConfigurationTransportNoritoRpc | null;
}

export interface ToriiConfigurationTransportNoritoRpc {
  enabled: boolean;
  stage: string;
  requireMtls: boolean;
  canaryAllowlistSize: number;
}

export interface ToriiRuntimeUpgradeManifestInput {
  name: string;
  description: string;
  abiVersion: number | string | bigint;
  abiHash: string | BinaryLike;
  startHeight: number | string | bigint;
  endHeight: number | string | bigint;
  addedSyscalls?: ReadonlyArray<number | string | bigint>;
  addedPointerTypes?: ReadonlyArray<number | string | bigint>;
}

export interface ToriiRuntimeUpgradeInstruction {
  wire_id: string;
  payload_hex?: string | null;
}

export interface ToriiRuntimeUpgradeTxResponse {
  ok: boolean;
  tx_instructions: ReadonlyArray<ToriiRuntimeUpgradeInstruction>;
}

export interface ToriiRuntimeUpgradeManifest {
  name: string;
  description: string;
  abiVersion: number;
  abiHashHex: string;
  addedSyscalls: ReadonlyArray<number>;
  addedPointerTypes: ReadonlyArray<number>;
  startHeight: number;
  endHeight: number;
}

export type ToriiRuntimeUpgradeStatus =
  | { kind: "Proposed" }
  | { kind: "Canceled" }
  | { kind: "ActivatedAt"; activatedHeight: number };

export interface ToriiRuntimeUpgradeRecord {
  manifest: ToriiRuntimeUpgradeManifest;
  status: ToriiRuntimeUpgradeStatus;
  proposer: string;
  createdHeight: number;
}

export interface ToriiRuntimeUpgradeListItem {
  idHex: string;
  record: ToriiRuntimeUpgradeRecord;
}

export interface ToriiPipelineDagSnapshot {
  fingerprintHex: string;
  keyCount: number;
}

export interface ToriiPipelineTxSnapshot {
  hashHex: string;
  reads: ReadonlyArray<string>;
  writes: ReadonlyArray<string>;
}

export interface ToriiPipelineRecoverySidecar {
  format: string;
  height: number;
  dag: ToriiPipelineDagSnapshot;
  txs: ReadonlyArray<ToriiPipelineTxSnapshot>;
}

export interface ToriiPipelineRecoveryFastpqProof {
  entryHash: string;
  batchIndex: number;
  parameter: string;
  transitionCount: number;
  traceCommitment: string;
  proofDigest: string;
  batchBase64: string | null;
  proofBase64: string | null;
  batchCompact: boolean | null;
  batchReconstructedFromBlock: boolean | null;
  batchReconstructionError: string | null;
  raw: Readonly<Record<string, unknown>>;
}

export interface ToriiPipelineRecoveryFastpqProofs {
  height: number;
  blockHashHex: string;
  proofs: ReadonlyArray<ToriiPipelineRecoveryFastpqProof>;
}

/** Native protocol-1 observation; all nullable keys are mandatory. */
export interface ToriiSumeragiStatus {
  protocol_version: 1;
  config_fingerprint: string;
  beacon_horizon: ToriiSumeragiBeaconHorizon | null;
  instance: string;
  height: ToriiU64;
  view: ToriiU64;
  stage: 0 | 1 | 2;
  leader: string | null;
  proxy_tail: string | null;
  high_qc_view: ToriiU64 | null;
  level: number;
  start_level: number;
  t_retx_ms: ToriiU64;
  committed_height: ToriiU64;
  applied_height: ToriiU64;
  awaiting: boolean;
  signer: string | null;
  unanchored: boolean;
  abstaining: boolean;
  halted: ToriiSumeragiHaltReason | null;
  footprint: ToriiSumeragiFootprint;
}
export interface ToriiSumeragiFootprint {
  votes: ToriiU64;
  timeouts: ToriiU64;
  blocks: ToriiU64;
  exec_entries: ToriiU64;
  wants: ToriiU64;
  pending_apply: ToriiU64;
  sync_entries: ToriiU64;
  sync_bytes: ToriiU64;
  peers: ToriiU64;
  recent_headers: ToriiU64;
  configs: ToriiU64;
  cert_cache: ToriiU64;
  evidence_keys: ToriiU64;
  probe: ToriiU64;
}
export interface ToriiSumeragiBeaconHorizon {
  epoch_length_blocks: ToriiU64;
  next_required_pulse_height: ToriiU64 | null;
  active_session_id: string | null;
  session_covers_next_pulse: boolean;
  local_provider_ready: boolean;
}
export type ToriiSumeragiHaltReason =
  | Readonly<{ reason: "safety_record_corrupt" | "safety_record_inconsistent" | "driver_anomaly"; details: null }>
  | Readonly<{ reason: "safety_violation" | "apply_diverged" | "publication_recovery_required"; details: ToriiU64 }>;
/** Chain parameters pinned into one lane incarnation (Rust `SumeragiParameters`). */
export interface ToriiSumeragiParameters {
  block_cadence_ms: ToriiU64;
  max_clock_drift_ms: ToriiU64;
  key_activation_lead_blocks: ToriiU64;
  key_overlap_grace_blocks: ToriiU64;
  key_expiry_grace_blocks: ToriiU64;
  key_allowed_algorithms: ReadonlyArray<string>;
  payload_retry_interval_ms: ToriiU64;
  exec_budget_ms: ToriiU64;
  apply_budget_ms: ToriiU64;
  max_block_bytes: number;
  epoch_length_blocks: ToriiU64;
  demotion_window: ToriiU64;
}
/** One pinned lane committee member: canonical BLS-normal key and base64 96-byte possession proof. */
export interface ToriiSumeragiLaneMember {
  peer: string;
  pop: string;
}
/** Highest merged lane block; `height` 0 means nothing merged yet. Hashes are uppercase hex. */
export interface ToriiSumeragiLaneFrontier {
  height: ToriiU64;
  block_hash: string;
  result: string;
}
/** Mandatory signed RS16 geometry pinned into one lane incarnation. */
export interface ToriiSumeragiDataAvailabilityLayout {
  encoding: Readonly<{ encoding: "reed_solomon16"; details: null }>;
  chunk_size_bytes: number;
  data_shards: number;
  parity_shards: number;
  max_payload_size_bytes: ToriiU64;
  max_chunk_count: number;
}
/** Committed lifecycle record of one lane incarnation; all nullable keys are mandatory. */
export interface ToriiSumeragiLaneRecord {
  lane: number;
  dataspace: ToriiU64;
  incarnation: string;
  params: ToriiSumeragiParameters;
  da_layout: ToriiSumeragiDataAvailabilityLayout;
  committee: ReadonlyArray<ToriiSumeragiLaneMember>;
  created_at: ToriiU64;
  active_from: ToriiU64;
  closing: ToriiU64 | null;
  anchor_freshness: ToriiU64;
  merged: ToriiSumeragiLaneFrontier;
  merged_at: ToriiU64;
  rescued: ToriiU64;
}
/** One served lane with the node's instance status (`null` while the node runs none). */
export interface ToriiSumeragiLaneStatus {
  record: ToriiSumeragiLaneRecord;
  instance: ToriiSumeragiStatus | null;
}

/** Committed Sumeragi timing parameters and chain height (`GET /v1/sumeragi/params`). */
export interface ToriiSumeragiParamsSnapshot {
  /** Target block cadence in milliseconds; never zero. */
  block_cadence_ms: number;
  /** Maximum tolerated clock drift in milliseconds. */
  max_clock_drift_ms: number;
  /** Committed chain height the snapshot was read at. */
  chain_height: number;
}

export type SumeragiEvidenceKind = "NativeSumeragiEvidence";

export interface SumeragiEvidenceListOptions {
  limit?: NumericLike;
  offset?: NumericLike;
  kind?: SumeragiEvidenceKind;
  signal?: AbortSignal;
}

export interface SumeragiEvidencePendingPenaltyStatus {
  status: "pending";
  details: null;
}

export interface SumeragiEvidenceAppliedPenaltyStatus {
  status: "applied";
  details: { height: ToriiU64 };
}

export type SumeragiEvidencePenaltyStatus =
  | SumeragiEvidencePendingPenaltyStatus
  | SumeragiEvidenceAppliedPenaltyStatus;

export interface SumeragiEvidenceOffender {
  signer: number;
  peer_id: string;
}

export interface SumeragiEvidenceRecord {
  kind: "NativeSumeragiEvidence";
  class: "proposal" | "phase_vote" | "timeout_vote" | "invalid_proposal" | "conflicting_certificates";
  instance: string;
  height: ToriiU64;
  epoch: ToriiU64;
  context_id: string;
  authority_generation: string;
  offenders: ReadonlyArray<SumeragiEvidenceOffender>;
  safety_violation: boolean;
  native_frame_hash: string;
  recorded_height: ToriiU64;
  recorded_view: ToriiU64;
  recorded_ms: ToriiU64;
  consensus_admitted_height: ToriiU64;
  penalty_status: SumeragiEvidencePenaltyStatus;
}

export interface SumeragiEvidenceListResponse {
  total: ToriiU64;
  items: ReadonlyArray<SumeragiEvidenceRecord>;
}

export interface SumeragiEvidenceCountResponse {
  count: ToriiU64;
}

export type KaigiRelayHealthStatus = "healthy" | "degraded" | "unavailable";

export interface KaigiRelaySummary {
  relay_id: string;
  domain: string;
  bandwidth_class: number;
  hpke_fingerprint_hex: string;
  status?: KaigiRelayHealthStatus | null;
  reported_at_ms?: ToriiU64 | null;
}

export interface KaigiRelaySummaryList {
  total: ToriiU64;
  items: ReadonlyArray<KaigiRelaySummary>;
}

export interface KaigiRelayDomainMetrics {
  domain: string;
  registrations_total: ToriiU64;
  manifest_updates_total: ToriiU64;
  failovers_total: ToriiU64;
  health_reports_total: ToriiU64;
}

export interface KaigiRelayDetail {
  relay: KaigiRelaySummary;
  hpke_public_key_b64: string;
  reported_call?: { domain_id: string; call_name: string } | null;
  reported_by?: string | null;
  notes?: string | null;
  metrics?: KaigiRelayDomainMetrics | null;
}

export interface KaigiRelayHealthSnapshot {
  healthy_total: ToriiU64;
  degraded_total: ToriiU64;
  unavailable_total: ToriiU64;
  reports_total: ToriiU64;
  registrations_total: ToriiU64;
  failovers_total: ToriiU64;
  domains: ReadonlyArray<KaigiRelayDomainMetrics>;
}

export interface KaigiRelayEventCallRef {
  domain: string;
  name: string;
}

export interface KaigiRelayRegistrationEvent {
  kind: "registration";
  domain: string;
  relay_id: string;
  bandwidth_class: number;
  hpke_fingerprint_hex: string;
}

export interface KaigiRelayUnregistrationEvent {
  kind: "unregistration";
  domain: string;
  relay_id: string;
}

export interface KaigiRelayHealthEvent {
  kind: "health";
  domain: string;
  relay_id: string;
  status: KaigiRelayHealthStatus;
  reported_at_ms: ToriiU64;
  call: KaigiRelayEventCallRef;
}

export type KaigiRelayEventPayload =
  | KaigiRelayRegistrationEvent
  | KaigiRelayUnregistrationEvent
  | KaigiRelayHealthEvent;

export interface KaigiRelayEventsOptions {
  domain?: string;
  relay?: string;
  kind?: string | ReadonlyArray<string>;
  lastEventId?: string;
  signal?: AbortSignal;
}

export interface KaigiCallEventRef {
  call_id: string;
  domain: string;
  call_name: string;
}

export interface KaigiCallView {
  call_id: string;
  domain: string;
  call_name: string;
  host_account_id?: string | null;
  billing_account_id?: string | null;
  title?: string | null;
  description?: string | null;
  /** Participant limit excluding the host, in 1...4096; omission uses 4096. */
  max_participants?: number | null;
  gas_rate_per_minute: ToriiU64;
  metadata: Record<string, unknown>;
  scheduled_start_ms?: ToriiU64 | null;
  privacy_mode: "transparent" | "private";
  room_policy: "public" | "authenticated";
  relay_manifest?: Record<string, unknown> | null;
  roster_root_hex: string;
  participant_count?: number | null;
  commitment_count: number;
  nullifier_count: number;
  usage_commitment_count: number;
  status: "active" | "ended";
  created_at_ms: ToriiU64;
  ended_at_ms?: ToriiU64 | null;
  total_duration_ms: ToriiU64;
  total_billed_gas: ToriiU64;
  segments_recorded: number;
}

export interface KaigiCallSignalMetadata extends Record<string, unknown> {
  schema: "iroha-demo-kaigi-chain-signal/v1";
}

export interface KaigiCallSignal {
  entrypoint_hash: string;
  authority?: string | null;
  timestamp_ms: ToriiU64;
  call_id: string;
  signal_kind: string;
  host_account_id?: string | null;
  participant_account_id?: string | null;
  created_at_ms: ToriiU64;
  metadata: KaigiCallSignalMetadata;
}

export interface KaigiCallSignalsList {
  has_more: boolean;
  next_cursor?: string;
  items: ReadonlyArray<KaigiCallSignal>;
}

export interface KaigiCallSignalsOptions {
  afterTimestampMs?: NumericLike;
  after_timestamp_ms?: NumericLike;
  limit?: NumericLike;
  cursor?: string;
  signal?: AbortSignal;
  /** Per-call signer; falls back to `ToriiClient`'s `canonicalRequestAuth`. */
  canonicalAuth?: CanonicalRequestAuth;
}

export interface KaigiCallRosterUpdatedEvent {
  kind: "roster_updated";
  call: KaigiCallEventRef;
  privacy_mode: "transparent" | "private";
  participant_count?: number | null;
  commitment_count: number;
  nullifier_count: number;
  roster_root_hex?: string | null;
}

export interface KaigiCallEndedEvent {
  kind: "ended";
  call: KaigiCallEventRef;
  status: "ended";
  ended_at_ms: ToriiU64;
}

export type KaigiCallEventPayload =
  | KaigiCallRosterUpdatedEvent
  | KaigiCallEndedEvent;

export interface KaigiCallEventsOptions {
  kind?: string | ReadonlyArray<string>;
  lastEventId?: string;
  signal?: AbortSignal;
}

type ExclusiveSingleOrMany<
  SingleKey extends PropertyKey,
  SingleValue,
  ManyKey extends PropertyKey,
  ManyValue,
> =
  | ({ [K in SingleKey]: SingleValue } & { [K in ManyKey]?: never })
  | ({ [K in SingleKey]?: never } & { [K in ManyKey]: ManyValue });

type ExclusiveSingleOrManyOptional<
  SingleKey extends PropertyKey,
  SingleValue,
  ManyKey extends PropertyKey,
  ManyValue,
> =
  | ExclusiveSingleOrMany<SingleKey, SingleValue, ManyKey, ManyValue>
  | ({ [K in SingleKey]?: never } & { [K in ManyKey]?: never });

type DomainMintSpec = {
  assetId: string;
  quantity: QuantityInput;
};

type AssetDefinitionMintSpec = {
  accountId?: string;
  assetHoldingId?: string;
  quantity: QuantityInput;
};

type MintTransferSpec = {
  sourceAssetHoldingId?: string;
  quantity: QuantityInput;
  destinationAccountId: string;
};

type AccountTransferSpec = {
  sourceAssetHoldingId: string;
  quantity: QuantityInput;
  destinationAccountId: string;
};

export interface ConfidentialKeyset {
  skSpend: Buffer;
  nk: Buffer;
  ivk: Buffer;
  ovk: Buffer;
  fvk: Buffer;
  skSpendHex: string;
  nkHex: string;
  ivkHex: string;
  ovkHex: string;
  fvkHex: string;
  asHex(): Record<string, string>;
}

export interface ConfidentialReceiveAddressV2 {
  ownerTag: Buffer;
  ownerTagHex: string;
  diversifier: Buffer;
  diversifierHex: string;
}

/** Public outputs of the exact final V1 Kaigi authorization relation. */
export interface KaigiAuthorizationProofV1 {
  readonly commitment: Buffer;
  readonly nullifier: Buffer;
  readonly authorization: Buffer;
  readonly preRosterRoot: Buffer;
  readonly proof: Buffer;
}

export interface KaigiAuthorizationProofOptionsV1 {
  networkId: NetworkId;
  callId: { domainId: string; callName: string };
  hostId: string;
  /** Retained original participant identity, or original host for host actions. */
  subjectId: string;
  participationSequence: bigint;
  action: "hostCreate" | "join" | "leave" | "hostEnd";
  preRosterRoot: Uint8Array;
  /** Mutable canonical nonzero Pasta Fp bytes, consumed and cleared on every call. */
  blinding: Uint8Array;
}

/** Public outputs of the exact final V1 host usage relation. */
export interface KaigiUsageProofV1 {
  readonly hostCommitment: Buffer;
  readonly usageCommitment: Buffer;
  readonly preRosterRoot: Buffer;
  readonly proof: Buffer;
}

export interface KaigiUsageProofOptionsV1 {
  networkId: NetworkId;
  callId: { domainId: string; callName: string };
  /** Retained original host account identity. */
  hostId: string;
  preRosterRoot: Uint8Array;
  /** Exact integer from zero through 2^32 - 1. */
  segmentIndex: number;
  /** Exact positive u64 duration. */
  durationMs: bigint;
  /** Exact unsigned u64 gas charge. */
  billedGas: bigint;
  /** Stored raw canonical host C established by HostCreate. */
  hostCommitment: Uint8Array;
  /** Original host opening; mutable canonical nonzero Fp bytes, consumed and cleared. */
  blinding: Uint8Array;
}

export interface RegisterDomainInput {
  networkId: NetworkId;
  authority: string;
  domainId: string;
  /** Required signature-bound fee payer, maxima, and gas bound. */
  feePayment: BrowserFeePayment;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

/**
 * Parameters for {@link buildTransaction}. The `instructions` array must be
 * non-empty and each entry should be either a builder result or a JSON string
 * produced by `noritoEncodeInstruction`.
 */
export interface TransactionAssemblyInput {
  networkId: NetworkId;
  authority: string;
  instructions: Array<object | string>;
  /** Required signature-bound fee payer, maxima, and gas bound. */
  feePayment: BrowserFeePayment;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export type ExecutableBatchEntry =
  | {
      kind: "instruction";
      instruction: object | string;
    }
  | {
      kind: "contractCall";
      contractAddress: string;
      /** Exact marked 32-byte Iroha code hash. */
      expectedCodeHash: Buffer | ArrayBuffer | ArrayBufferView | string;
      entrypoint: string;
      /** Canonical schema-bound argument-record bytes; maximum 1 MiB. */
      arguments?: Buffer | ArrayBuffer | ArrayBufferView | null;
    };

export interface ExecutableBatchTransactionAssemblyInput {
  networkId: NetworkId;
  authority: string;
  entries: ExecutableBatchEntry[];
  /** Must include `gasLimit` when any entry is a contract call. */
  feePayment: BrowserFeePayment;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export type ExecutableBatchTransactionPayloadDraftInput = Omit<
  ExecutableBatchTransactionAssemblyInput,
  "privateKey" | "privateKeyAlgorithm"
>;

/** Exact unsigned payload whose non-fee fields are fixed before quoting. */
export type TransactionPayloadDraftInput = Omit<
  TransactionAssemblyInput,
  "privateKey" | "privateKeyAlgorithm"
>;

/** Native and JSON projections of one exact unsigned quote draft. */
export interface TransactionPayloadDraftResult {
  payload: Record<string, unknown>;
  payloadJson: string;
  payloadBytes: Buffer;
  payloadHash: Buffer;
}
/** Input for applying a returned quote to the exact draft and signing it. */
export interface QuotedTransactionPayloadSigningInput {
  /** Application-pinned exact NetworkId expected in the quoted payload. */
  networkId: NetworkId;
  payload: Record<string, unknown> | TransactionPayloadDraftResult;
  quotedFeePayment: BrowserFeePayment | Record<string, unknown> | string;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

/** Required signature-bound fee intent shared by all transaction builders. */
export interface FeePaymentRequired {
  feePayment: BrowserFeePayment;
}

export interface IvmProvedTransactionAssemblyInput {
  networkId: NetworkId;
  authority: string;
  proved: object | string;
  attachment: object | string;
  /** Required signature-bound fee payer, maxima, and gas bound. */
  feePayment: BrowserFeePayment;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

/** Exact unsigned proved-IVM payload plus its envelope-only proof attachment. */
export type IvmProvedTransactionPayloadDraftInput = Omit<
  IvmProvedTransactionAssemblyInput,
  "privateKey" | "privateKeyAlgorithm"
>;

export interface IvmProvedTransactionPayloadDraftResult
  extends TransactionPayloadDraftResult {
  attachment: Record<string, unknown>;
  attachmentJson: string;
}
export interface QuotedIvmProvedTransactionPayloadSigningInput {
  /** Application-pinned exact NetworkId expected in the quoted payload. */
  networkId: NetworkId;
  payload: Record<string, unknown> | IvmProvedTransactionPayloadDraftResult;
  attachment?: object | string;
  quotedFeePayment: BrowserFeePayment | Record<string, unknown> | string;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface RegisterMultisigTransactionInput extends FeePaymentRequired {
  networkId: NetworkId;
  authority: string;
  accountId: string;
  spec: MultisigSpecLike;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface MintAssetInput {
  networkId: NetworkId;
  authority: string;
  assetHoldingId: string;
  quantity: QuantityInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface BurnAssetInput {
  networkId: NetworkId;
  authority: string;
  assetHoldingId: string;
  quantity: QuantityInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface MintTriggerInput {
  networkId: NetworkId;
  authority: string;
  triggerId: string;
  repetitions: NumericLike;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface BurnTriggerInput {
  networkId: NetworkId;
  authority: string;
  triggerId: string;
  repetitions: NumericLike;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface TransferAssetInput {
  networkId: NetworkId;
  authority: string;
  sourceAssetHoldingId: string;
  quantity: QuantityInput;
  destinationAccountId: string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface TransferDomainInput {
  networkId: NetworkId;
  authority: string;
  sourceAccountId: string;
  domainId: string;
  destinationAccountId: string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface TransferAssetDefinitionInput {
  networkId: NetworkId;
  authority: string;
  sourceAccountId: string;
  assetDefinitionId: string;
  destinationAccountId: string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface TransferNftInput {
  networkId: NetworkId;
  authority: string;
  sourceAccountId: string;
  nftId: string;
  destinationAccountId: string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface RwaParentRefInput {
  rwa?: string;
  rwaId?: string;
  quantity: QuantityInput;
}

export interface RwaControlPolicyInput {
  controllerAccounts?: ReadonlyArray<string> | null;
  controller_accounts?: ReadonlyArray<string> | null;
  controllerRoles?: ReadonlyArray<string> | null;
  controller_roles?: ReadonlyArray<string> | null;
  freezeEnabled?: boolean | null;
  freeze_enabled?: boolean | null;
  holdEnabled?: boolean | null;
  hold_enabled?: boolean | null;
  forceTransferEnabled?: boolean | null;
  force_transfer_enabled?: boolean | null;
  redeemEnabled?: boolean | null;
  redeem_enabled?: boolean | null;
}

export interface RegisterRwaPayloadInput {
  domain: string;
  quantity: QuantityInput;
  spec?: Record<string, unknown> | null;
  primaryReference?: string;
  primary_reference?: string;
  status?: string | null;
  metadata?: Record<string, JsonValue> | null;
  parents?: ReadonlyArray<RwaParentRefInput> | null;
  controls?: RwaControlPolicyInput | null;
}

export interface MergeRwasPayloadInput {
  parents: ReadonlyArray<RwaParentRefInput>;
  primaryReference?: string;
  primary_reference?: string;
  status?: string | null;
  metadata?: Record<string, JsonValue> | null;
}

export interface RegisterRwaInput {
  networkId: NetworkId;
  authority: string;
  rwa?: RegisterRwaPayloadInput | string;
  rwaJson?: RegisterRwaPayloadInput | string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface TransferRwaInput {
  networkId: NetworkId;
  authority: string;
  sourceAccountId: string;
  rwaId: string;
  quantity: QuantityInput;
  destinationAccountId: string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface MergeRwasInput {
  networkId: NetworkId;
  authority: string;
  merge?: MergeRwasPayloadInput | string;
  mergeJson?: MergeRwasPayloadInput | string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface RedeemRwaInput {
  networkId: NetworkId;
  authority: string;
  rwaId: string;
  quantity: QuantityInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface FreezeRwaInput {
  networkId: NetworkId;
  authority: string;
  rwaId: string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface UnfreezeRwaInput extends FreezeRwaInput {}

export interface HoldRwaInput {
  networkId: NetworkId;
  authority: string;
  rwaId: string;
  quantity: QuantityInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface ReleaseRwaInput extends HoldRwaInput {}

export interface ForceTransferRwaInput {
  networkId: NetworkId;
  authority: string;
  rwaId: string;
  quantity: QuantityInput;
  destinationAccountId: string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface SetRwaControlsInput {
  networkId: NetworkId;
  authority: string;
  rwaId: string;
  controls?: RwaControlPolicyInput | string;
  controlsJson?: RwaControlPolicyInput | string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface SetRwaKeyValueInput {
  networkId: NetworkId;
  authority: string;
  rwaId: string;
  key: string;
  value: JsonValue;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface RemoveRwaKeyValueInput {
  networkId: NetworkId;
  authority: string;
  rwaId: string;
  key: string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

/**
 * Parameters for {@link buildMintAndTransferTransaction}. Provide either
 * `transfer` or `transfers`; when `sourceAssetHoldingId` is omitted on a transfer the
 * helper reuses `mint.assetHoldingId` and enforces that at least one transfer is
 * present.
 */
interface MintAndTransferInputBase {
  networkId: NetworkId;
  authority: string;
  mint: {
    assetHoldingId: string;
    quantity: QuantityInput;
  };
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

type MintAndTransferVariants = ExclusiveSingleOrMany<
  "transfer",
  MintTransferSpec,
  "transfers",
  ReadonlyArray<MintTransferSpec>
>;

export type MintAndTransferInput = MintAndTransferInputBase &
  MintAndTransferVariants;

/**
 * Parameters for {@link buildRegisterDomainAndMintTransaction}. Supply either
 * a single `mint` descriptor or an array of `mints`. When neither is provided
 * the helper will register the domain without minting.
 */
interface RegisterDomainAndMintInputBase {
  networkId: NetworkId;
  authority: string;
  domain: {
    domainId: string;
    logo?: string | null;
    metadata?: object | null;
  };
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

type RegisterDomainMintOptions = ExclusiveSingleOrManyOptional<
  "mint",
  DomainMintSpec,
  "mints",
  ReadonlyArray<DomainMintSpec>
>;

export type RegisterDomainAndMintInput = RegisterDomainAndMintInputBase &
  RegisterDomainMintOptions;

/**
 * Parameters for {@link buildRegisterAccountAndTransferTransaction}. Provide
 * either `transfer` or `transfers`; each transfer must declare a source asset
 * so the helper can enforce explicit provenance.
 */
interface RegisterAccountAndTransferInputBase {
  networkId: NetworkId;
  authority: string;
  account: {
    accountId: string;
    metadata?: object;
  };
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

type RegisterAccountTransferOptions = ExclusiveSingleOrManyOptional<
  "transfer",
  AccountTransferSpec,
  "transfers",
  ReadonlyArray<AccountTransferSpec>
>;

export type RegisterAccountAndTransferInput =
  RegisterAccountAndTransferInputBase & RegisterAccountTransferOptions;

/**
 * Parameters for {@link buildRegisterAssetDefinitionAndMintTransaction}. Supply
 * either `mint` or `mints`. When `assetHoldingId` is omitted the helper derives it as
 * the canonical asset-holding id for `assetDefinitionId + accountId`, and
 * enforces that any provided `assetHoldingId` matches the derived value.
 */
interface RegisterAssetDefinitionAndMintInputBase {
  networkId: NetworkId;
  authority: string;
  assetDefinition: {
    assetDefinitionId: string;
    /** Canonical on-chain Name for the asset definition. */
    name: string;
    /** Immutable ownership intent; null means intentionally unowned global. */
    owningDomain: string | null;
    metadata?: object;
    mintable?: string;
    logo?: string | null;
    spec?: object;
    balanceScopePolicy: string;
  };
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  /** Non-zero lifetime in milliseconds; defaults to the protocol's 100 seconds. */
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

type RegisterAssetDefinitionMintOptions = ExclusiveSingleOrManyOptional<
  "mint",
  AssetDefinitionMintSpec,
  "mints",
  ReadonlyArray<AssetDefinitionMintSpec>
>;

export type RegisterAssetDefinitionAndMintInput =
  RegisterAssetDefinitionAndMintInputBase & RegisterAssetDefinitionMintOptions;

/**
 * Extends {@link RegisterAssetDefinitionAndMintInput} with optional transfer
 * descriptors. Provide either `transfer` or `transfers`; when a transfer omits
 * `sourceAssetHoldingId` the helper reuses the first minted asset destination.
 */
type RegisterAssetDefinitionMintRequired = ExclusiveSingleOrMany<
  "mint",
  AssetDefinitionMintSpec,
  "mints",
  ReadonlyArray<AssetDefinitionMintSpec>
>;

type RegisterAssetDefinitionTransferOptions = ExclusiveSingleOrManyOptional<
  "transfer",
  MintTransferSpec,
  "transfers",
  ReadonlyArray<MintTransferSpec>
>;

export type RegisterAssetDefinitionMintAndTransferInput =
  RegisterAssetDefinitionAndMintInputBase &
    RegisterAssetDefinitionMintRequired &
    RegisterAssetDefinitionTransferOptions;

export type KaigiIdLike =
  | string
  | {
      domain_id?: string;
      domainId?: string;
      call_name?: string;
      callName?: string;
    };

export type KaigiPrivacyModeValue = {
  mode: "Transparent" | "ZkRosterV1";
  state?: null;
};

export type KaigiPrivacyModeInput =
  | string
  | KaigiPrivacyModeValue
  | null
  | undefined;

export interface KaigiRelayHopInput {
  relayId: string;
  hpkePublicKey: ArrayBufferView | ArrayBuffer | Buffer | string;
  weight?: NumericLike;
}

export interface KaigiRelayManifestInput {
  expiryMs: NumericLike;
  hops: ReadonlyArray<KaigiRelayHopInput>;
}

/** Maximum concurrent participants excluding the host in a first-release Kaigi call. */
export declare const KAIGI_MAX_PARTICIPANTS_V1: 4096;

/** Maximum relay hops accepted by the first-release Kaigi manifest. */
export declare const KAIGI_RELAY_MANIFEST_MAX_HOPS_V1: 8;

/** Maximum decoded bytes accepted for a Kaigi HPKE public key. */
export declare const KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1: 4096;

export interface KaigiParticipantCommitmentInput {
  /** Exact canonical Pasta Fp bytes, without a hash marker. */
  commitment: Uint8Array | readonly number[];
}

export interface KaigiParticipantNullifierInput {
  /** Exact canonical Pasta Fp bytes, without a hash marker. */
  digest: Uint8Array | readonly number[];
}

export type KaigiRoomPolicyValue = {
  policy: "Public" | "Authenticated";
  state?: null;
};

export type KaigiRoomPolicyInput =
  | "public"
  | "read-only"
  | "read_only"
  | "open"
  | "authenticated"
  | "auth"
  | "protected"
  | KaigiRoomPolicyValue;

export interface CreateKaigiInput {
  id: KaigiIdLike;
  host: string;
  title?: string | null;
  description?: string | null;
  /** Participant limit excluding the host, in 1...4096; omission uses 4096. */
  maxParticipants?: NumericLike | null;
  gasRatePerMinute?: NumericLike;
  metadata?: object | null;
  scheduledStartMs?: NumericLike | null;
  billingAccount?: string | null;
  privacyMode?: KaigiPrivacyModeInput;
  roomPolicy?: KaigiRoomPolicyInput;
  relayManifest?: KaigiRelayManifestInput | null;
  commitment?: KaigiParticipantCommitmentInput | null;
  nullifier?: KaigiParticipantNullifierInput | null;
  rosterRoot?: ArrayBufferView | ArrayBuffer | Buffer | string | null;
  proof?: ArrayBufferView | ArrayBuffer | Buffer | string | null;
}

export interface JoinKaigiInput {
  callId: KaigiIdLike;
  participant: string;
  commitment?: KaigiParticipantCommitmentInput | null;
  nullifier?: KaigiParticipantNullifierInput | null;
  rosterRoot?: ArrayBufferView | ArrayBuffer | Buffer | string | null;
  proof?: ArrayBufferView | ArrayBuffer | Buffer | string | null;
}

export interface LeaveKaigiInput extends JoinKaigiInput {}

export interface EndKaigiInput {
  callId: KaigiIdLike;
  endedAtMs?: NumericLike | null;
  commitment?: KaigiParticipantCommitmentInput | null;
  nullifier?: KaigiParticipantNullifierInput | null;
  rosterRoot?: ArrayBufferView | ArrayBuffer | Buffer | string | null;
  proof?: ArrayBufferView | ArrayBuffer | Buffer | string | null;
}

export interface RecordKaigiUsageInput {
  callId: KaigiIdLike;
  durationMs: NumericLike;
  billedGas?: NumericLike;
  usageCommitment?: Uint8Array | readonly number[] | null;
  proof?: ArrayBufferView | ArrayBuffer | Buffer | string | null;
}

export interface SetKaigiRelayManifestInput {
  callId: KaigiIdLike;
  relayManifest?: KaigiRelayManifestInput | null;
}

export interface RegisterKaigiRelayInput {
  relayId: string;
  hpkePublicKey: ArrayBufferView | ArrayBuffer | Buffer | string;
  bandwidthClass: NumericLike;
}

export interface UnregisterKaigiRelayInput {
  relayId: string;
}

export type KaigiRelayHealthStatusInput =
  | "Healthy"
  | "Degraded"
  | "Unavailable";

export interface ReportKaigiRelayHealthInput {
  callId: KaigiIdLike;
  relayId: string;
  status: KaigiRelayHealthStatusInput;
  reportedAtMs: NumericLike;
  notes?: string | null;
}

export interface ProposeDeployContractInstructionInput {
  contractAddress: string;
  codeHash: HashLike;
  abiHash: HashLike;
  abiVersion?: 1;
  manifestProvenance?: ToriiGovernanceManifestProvenanceInput | null;
}

export interface CastZkBallotInstructionInput {
  electionId: string;
  proof: ArrayBufferView | ArrayBuffer | Buffer | string;
  publicInputs?: GovernanceZkBallotPublicInputs;
}

export interface GovernanceZkBallotPublicInputs {
  root_hint?: string | null;
  owner?: string | null;
  amount?: QuantityInput | null;
  duration_blocks?: number | string | bigint | null;
  direction?: ToriiGovernanceBallotDirection | null;
  nullifier?: string | null;
}

export interface CastPlainBallotInstructionInput {
  referendumId: string;
  owner: string;
  amount: QuantityInput;
  durationBlocks: NumericLike;
  direction: number | string;
}

/** Choice-free extension of an existing public ballot's bond or lock. */
export interface UpdatePlainConvictionInstructionInput {
  referendumId: string;
  owner: string;
  amount: QuantityInput;
  durationBlocks: NumericLike;
}

export interface RegisterZkAssetInstructionInput {
  assetDefinitionId: string;
  unshieldVerifyingKey?: VerifyingKeyIdLike | null;
}

export interface ScheduleConfidentialPolicyTransitionInstructionInput {
  assetDefinitionId: string;
  newMode: "TransparentOnly" | "ShieldedOnly" | "Convertible" | string;
  effectiveHeight: NumericLike;
  transitionId: HashLike;
  conversionWindow?: NumericLike | null;
}

export interface CancelConfidentialPolicyTransitionInstructionInput {
  assetDefinitionId: string;
  transitionId: HashLike;
}

export interface CreateElectionInstructionInput {
  electionId: string;
  options: NumericLike;
  eligibleRoot: BinaryLike;
  startTs: NumericLike;
  endTs: NumericLike;
  ballotVerifyingKey: VerifyingKeyIdLike;
  tallyVerifyingKey: VerifyingKeyIdLike;
  domainTag?: string;
}

export interface SubmitBallotInstructionInput {
  electionId: string;
  ciphertext: BinaryLike;
  ballotProof: ProofAttachmentInput;
  nullifier: BinaryLike;
}

export interface FinalizeElectionInstructionInput {
  electionId: string;
  /** Exact unsigned 128-bit weights; use bigint or canonical decimal text above JS safe integers. */
  tally: ReadonlyArray<NumericLike>;
  tallyProof: ProofAttachmentInput;
}

export type IsoBridgeStatus = "Pending" | "Accepted" | "Rejected" | "Committed";
export type Pacs002StatusCode =
  | "ACTC"
  | "ACSP"
  | "ACSC"
  | "ACWC"
  | "PDNG"
  | "RJCT";

export interface IsoMessageSubmissionResponseBase {
  message_id: string;
  status: IsoBridgeStatus;
  pacs002_code: Pacs002StatusCode | null;
  transaction_hash: string | null;
  profile_id: string | null;
  message_type: string | null;
  business_service: string | null;
  business_message_id: string | null;
  uetr: string | null;
  payload_hash: string | null;
  reference_snapshot_id: string | null;
  embedded_signature_detected: boolean;
  /** Immutable schema-V3 participant provenance captured at durable admission. */
  originator_participant_id: string | null;
  counterparty_participant_id: string | null;
  admitting_participant_id: string | null;
  admitting_operator_key: string | null;
  /** Original profile and signature policy pinned for every lifecycle message. */
  pinned_profile_id: string | null;
  pinned_signature_policy: string | null;
  status_history: ReadonlyArray<IsoStatusHistoryEntry>;
  hold_reason_code: string | null;
  change_reason_codes: ReadonlyArray<string>;
  rejection_reason_code: string | null;
  ledger_id: string | null;
  source_account_id: string | null;
  source_account_address: string | null;
  target_account_id: string | null;
  target_account_address: string | null;
  asset_definition_id: string | null;
  asset_id: string | null;
  settlement_amount: string | null;
  settlement_currency: string | null;
  settlement_date: string | null;
  settlement_quantity: string | null;
  settlement_movement_type: string | null;
  settlement_payment_type: string | null;
  security_instrument_id: string | null;
  collateral_obligation_id: string | null;
  collateral_original_amount: string | null;
  collateral_original_currency: string | null;
  collateral_original_instrument_id: string | null;
  collateral_substitute_amount: string | null;
  collateral_substitute_currency: string | null;
  collateral_substitute_instrument_id: string | null;
  collateral_effective_date: string | null;
  collateral_substitution_type: string | null;
  collateral_haircut: string | null;
  collateral_reason_code: string | null;
  plan_execution_order: string | null;
  plan_atomicity: string | null;
}

export interface IsoPacs008SubmissionResponse
  extends IsoMessageSubmissionResponseBase {}

export interface IsoPacs009SubmissionResponse
  extends IsoMessageSubmissionResponseBase {}

export interface IsoMessageStatusResponse
  extends IsoMessageSubmissionResponseBase {
  detail: string | null;
  updated_at_ms: number;
}

export interface IsoStatusHistoryEntry {
  status: IsoBridgeStatus;
  pacs002_code: Pacs002StatusCode;
  updated_at_ms: number | null;
  detail: string | null;
  reason_code: string | null;
}

export interface IsoMessagePollEvent {
  attempt: number;
  status: IsoMessageStatusResponse | null;
}

export interface IsoMessageWaitOptions {
  maxAttempts?: number;
  pollIntervalMs?: number;
  signal?: AbortSignal;
  retryProfile?: string;
  resolveOnAcceptedWithoutTransaction?: boolean;
  /**
   * Alias for {@link resolveOnAcceptedWithoutTransaction}.
   */
  resolveOnAccepted?: boolean;
  onPoll?: (event: IsoMessagePollEvent) => void | Promise<void>;
}

export interface SubmitIsoMessageOptions {
  kind?: "pacs.008" | "pacs.009";
  messageKind?: "pacs.008" | "pacs.009";
  contentType?: string;
  profile?: string;
  signal?: AbortSignal;
  retryProfile?: string;
  wait?: IsoMessageWaitOptions;
}

type ContractRequiredAliasPair<
  CamelCase extends string,
  SnakeCase extends string,
  Value,
> =
  | ({ [Key in CamelCase]: Value } & { [Key in SnakeCase]?: Value })
  | ({ [Key in CamelCase]?: Value } & { [Key in SnakeCase]: Value });

// BEGIN GENERATED: kotodama-v1-dynamic-access-policy
export const KOTODAMA_V1_STATE_MAP_KEY_TYPES: readonly [
  "int",
  "decimal",
  "quantity",
  "bool",
  "string",
  "bytes",
  "DataSpaceId",
  "AccountId",
  "AssetDefinitionId",
  "AssetId",
  "NftId",
  "DomainId",
  "Name",
];
export const KOTODAMA_V1_DYNAMIC_ACCESS_BOUND_KINDS: readonly [
  "page",
  "take",
];
export const KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS: 64;

export type ContractStateMapKeyTypeName =
  (typeof KOTODAMA_V1_STATE_MAP_KEY_TYPES)[number];
export type ContractDynamicAccessBoundKind =
  (typeof KOTODAMA_V1_DYNAMIC_ACCESS_BOUND_KINDS)[number];
// END GENERATED: kotodama-v1-dynamic-access-policy

export type ContractDynamicAccessHintInput =
  & ContractRequiredAliasPair<"baseKey", "base_key", string>
  & ContractRequiredAliasPair<
    "keyType",
    "key_type",
    ContractStateMapKeyTypeName
  >
  & ContractRequiredAliasPair<
    "boundKind",
    "bound_kind",
    ContractDynamicAccessBoundKind
  >
  & ContractRequiredAliasPair<"maxKeys", "max_keys", NumericLike>;

export interface ContractAccessSetHintsInput {
  readKeys?: ReadonlyArray<string>;
  writeKeys?: ReadonlyArray<string>;
  dynamicReads?: ReadonlyArray<ContractDynamicAccessHintInput>;
  dynamic_reads?: ReadonlyArray<ContractDynamicAccessHintInput>;
  dynamicWrites?: ReadonlyArray<ContractDynamicAccessHintInput>;
  dynamic_writes?: ReadonlyArray<ContractDynamicAccessHintInput>;
}

export type ContractEntrypointKind =
  | "Kotoage"
  | "View"
  | "Hajimari"
  | "Kaizen";

export interface ContractEntrypointKindRecord {
  kind: ContractEntrypointKind;
  value: null;
}

export type ContractEntrypointValueKindName =
  | "Int"
  | "Decimal"
  | "Quantity"
  | "Bool"
  | "String"
  | "Json"
  | "Name"
  | "AccountId"
  | "AssetDefinitionId"
  | "AssetId"
  | "DomainId"
  | "NftId"
  | "DataSpaceId"
  | "Blob";

export interface ContractEntrypointValueKindRecord {
  kind: ContractEntrypointValueKindName;
  value: null;
}

export interface ContractEntrypointStructTypeNode {
  name: string;
  fields: ReadonlyArray<string>;
}

export interface ContractEntrypointListTypeNode {
  capacity: NumericLike;
}

export type ContractEntrypointValueTypeNode =
  | { kind: "Struct"; value: ContractEntrypointStructTypeNode }
  | { kind: "Tuple"; value: NumericLike }
  | { kind: "Option"; value: null }
  | { kind: "Result"; value: null }
  | { kind: "List"; value: ContractEntrypointListTypeNode }
  | { kind: "Leaf"; value: ContractEntrypointValueKindRecord }
  | { kind: "Unit"; value: null }
  | { kind: "StateCursor"; value: ContractEntrypointValueKindRecord }
  | { kind: "Error"; value: ContractErrorTypeDescriptorRecord };

export interface ContractEntrypointValueType {
  nodes: ReadonlyArray<ContractEntrypointValueTypeNode>;
}

export interface ContractEntrypointArgumentField {
  name: string;
  ty: ContractEntrypointValueType;
}

export interface ContractEntrypointArgumentSchema {
  fields: ReadonlyArray<ContractEntrypointArgumentField>;
}

export type ContractEntrypointParamInput = {
  name: string;
} & ContractRequiredAliasPair<"typeName", "type_name", string>;

export type ContractTriggerRepeats =
  | { Indefinitely: null }
  | { Exactly: NumericLike };

export interface ContractTriggerCallbackInput {
  namespace?: string | null;
  entrypoint: string;
}

export interface ContractTriggerDescriptorInput {
  id: string;
  repeats: ContractTriggerRepeats;
  /** Canonical standard-base64 NRT0 frame for `EventFilterBox`. */
  filter: string;
  authority?: string | null;
  metadata?: Readonly<Record<string, JsonValue>>;
  callback: ContractTriggerCallbackInput;
}

export interface ContractEntrypointInput {
  name: string;
  kind: ContractEntrypointKind | ContractEntrypointKindRecord;
  params?: ReadonlyArray<ContractEntrypointParamInput>;
  argumentSchema?: ContractEntrypointArgumentSchema | null;
  /** Every entrypoint returns a value; Unit uses `()` and a Unit schema. */
  returnType: string;
  returnSchema: ContractEntrypointValueType;
  permission?: string | null;
  readKeys?: ReadonlyArray<string>;
  writeKeys?: ReadonlyArray<string>;
  accessHintsComplete?: boolean | null;
  accessHintsSkipped?: ReadonlyArray<string>;
  triggers?: ReadonlyArray<ContractTriggerDescriptorInput>;
}

export type ContractStateDescriptorInput = {
  name: string;
} & ContractRequiredAliasPair<"typeName", "type_name", string>;

export interface ContractErrorMessage { error_type: string; code: number; message: string; }

export interface ContractErrorVariantDescriptorInput { name: string; code: NumericLike; }
export interface ContractErrorTypeDescriptorInput {
  identity: string;
  variants: ReadonlyArray<ContractErrorVariantDescriptorInput>;
}

export interface ContractKotobaTranslationInput {
  lang: string;
  text: string;
}

export type ContractKotobaEntryInput =
  | {
      msgId: string;
      translations: ReadonlyArray<ContractKotobaTranslationInput>;
    }
  | {
      msg_id: string;
      translations: ReadonlyArray<ContractKotobaTranslationInput>;
    };

export interface ContractManifestProvenanceInput {
  signer: string;
  signature: string;
}

export interface ContractManifestInput {
  seiyakuName?: string | null;
  codeHash?: HashLike | null;
  abiHash?: HashLike | null;
  compilerFingerprint?: string | null;
  featuresBitmap?: NumericLike | null;
  accessSetHints?: ContractAccessSetHintsInput | null;
  entrypoints?: ReadonlyArray<ContractEntrypointInput> | null;
  states?: ReadonlyArray<ContractStateDescriptorInput> | null;
  errorTypes?: ReadonlyArray<ContractErrorTypeDescriptorInput> | null;
  errorMessages?: ReadonlyArray<ContractErrorMessage> | null;
  kotoba?: ReadonlyArray<ContractKotobaEntryInput> | null;
  provenance?: ContractManifestProvenanceInput | null;
}

/**
 * Manifest payload accepted by Torii HTTP contract endpoints. Hash fields must be provided
 * as 32-byte hex strings (optionally prefixed with `0x`); canonical `hash:` literals or
 * binary buffers are rejected at runtime.
 */
export interface ToriiContractManifestInput {
  seiyakuName?: string | null;
  codeHash?: string | null;
  abiHash?: string | null;
  compilerFingerprint?: string | null;
  featuresBitmap?: NumericLike | null;
  accessSetHints?: ContractAccessSetHintsInput | null;
  entrypoints?: ReadonlyArray<ContractEntrypointInput> | null;
  states?: ReadonlyArray<ContractStateDescriptorInput> | null;
  errorTypes?: ReadonlyArray<ContractErrorTypeDescriptorInput> | null;
  errorMessages?: ReadonlyArray<ContractErrorMessage> | null;
  kotoba?: ReadonlyArray<ContractKotobaEntryInput> | null;
  provenance?: ContractManifestProvenanceInput | null;
}

export interface ContractOperationReceipt {
  operation_kind: string;
  status: string;
  transport: string;
  dataspace: string;
  contract_alias: string | null;
  contract_address: string | null;
  code_hash_hex: string | null;
  abi_hash_hex: string | null;
  tx_hash_hex: string | null;
  entrypoint: string | null;
  entrypoint_hash_hex: string | null;
  gas_limit: number | null;
  gas_used: number | null;
  fee_payment: NoritoFeePaymentIntent | null;
  payload_digest_hex: string;
}

export interface SetContractAliasRequest {
  authority: string;
  contractAddress: string;
  contractAlias?: string | null;
  leaseExpiryMs?: number | null;
}

export interface SetContractAliasResponse extends AppApiTransactionDraft {
  contract_alias: string | null;
  contract_address: string;
  dataspace: string;
}

export interface ContractCallRequest {
  authority: string;
  contractAddress?: string;
  contractAlias?: string;
  entrypoint: string;
  payload?: unknown;
  metadata?: Record<string, JsonValue>;
  creationTimeMs?: NumericLike | null;
  creation_time_ms?: NumericLike | null;
  transactionTtlMs?: NumericLike | null;
  transaction_ttl_ms?: NumericLike | null;
  feePayment: NoritoFeePaymentIntent;
  fee_payment?: NoritoFeePaymentIntent;
  draftIntent: ContractCallDraftIntent;
  draft_intent?: ContractCallDraftIntent;
}

export interface ContractCallResponse {
  ok: boolean;
  submitted: boolean;
  dataspace: string;
  contract_address?: string;
  code_hash_hex: string;
  abi_hash_hex: string;
  creation_time_ms: number;
  transaction_ttl_ms: number | null;
  tx_hash_hex: string | null;
  entrypoint_hash_hex: string | null;
  pipeline_status?: ToriiPipelineTransactionStatus | null;
  entrypoint: string | null;
  transaction_payload_b64: string | null;
  signing_message_b64: string | null;
  operation_receipt: ContractOperationReceipt;
}

export interface ContractCallSimulateRequest {
  authority: string;
  contractAddress?: string;
  contract_address?: string;
  contractAlias?: string;
  contract_alias?: string;
  entrypoint?: string | null;
  payload?: JsonValue;
  gasLimit: NumericLike;
  gas_limit?: NumericLike;
}

export interface ContractCallSimulateResponse {
  ok: boolean;
  dataspace: string;
  contract_address: string | null;
  code_hash_hex: string;
  abi_hash_hex: string;
  entrypoint: string;
  normalized_payload: JsonValue | null;
  gas_limit: number;
  gas_used: number;
  queued_instructions: JsonValue[];
  result: JsonValue | null;
  error: string | null;
  vm_diagnostic: JsonValue | null;
}

export interface ContractManifestRecord {
  /** Optional canonical base64 bytes, verified against artifact_id when present. */
  code_bytes?: string;
  network_id: string;
  artifact_id: { dataspace_id: string; code_hash: string };
  manifest: {
    seiyaku_name: string | null;
    /** Lowercase 32-byte hex normalized from Rust's canonical Hash literal. */
    code_hash: string | null;
    /** Lowercase 32-byte hex normalized from Rust's canonical Hash literal. */
    abi_hash: string | null;
    compiler_fingerprint: string | null;
    features_bitmap: number | null;
    access_set_hints:
      | {
          read_keys: ReadonlyArray<string>;
          write_keys: ReadonlyArray<string>;
          dynamic_reads: ReadonlyArray<{
            base_key: string;
            key_type: ContractStateMapKeyTypeName;
            bound_kind: ContractDynamicAccessBoundKind;
            max_keys: number;
          }>;
          dynamic_writes: ReadonlyArray<{
            base_key: string;
            key_type: ContractStateMapKeyTypeName;
            bound_kind: ContractDynamicAccessBoundKind;
            max_keys: number;
          }>;
        }
      | null;
    entrypoints: ReadonlyArray<ContractEntrypointRecord> | null;
    states: ReadonlyArray<ContractStateDescriptorRecord> | null;
    error_types: ReadonlyArray<ContractErrorTypeDescriptorRecord> | null;
    error_messages: ReadonlyArray<ContractErrorMessage> | null;
    kotoba: ReadonlyArray<ContractKotobaEntryRecord> | null;
    provenance: ContractManifestProvenanceInput | null;
  };
  code_hash: string | null;
  abi_hash: string | null;
}

export interface ContractEntrypointParamRecord {
  name: string;
  type_name: string;
}

export interface ContractTriggerDescriptorRecord {
  id: string;
  repeats: { Indefinitely: null } | { Exactly: number };
  filter: string;
  authority: string | null;
  metadata: Readonly<Record<string, JsonValue>>;
  callback: { namespace: string | null; entrypoint: string };
}

export interface ContractEntrypointRecord {
  name: string;
  kind: ContractEntrypointKindRecord;
  params: ReadonlyArray<ContractEntrypointParamRecord>;
  argument_schema: ContractEntrypointArgumentSchema | null;
  return_type: string;
  return_schema: ContractEntrypointValueType;
  permission: string | null;
  read_keys: ReadonlyArray<string>;
  write_keys: ReadonlyArray<string>;
  access_hints_complete: boolean | null;
  access_hints_skipped: ReadonlyArray<string>;
  triggers: ReadonlyArray<ContractTriggerDescriptorRecord>;
}

export interface ContractStateDescriptorRecord {
  name: string;
  type_name: string;
}

export interface ContractErrorVariantDescriptorRecord { name: string; code: number; }
export interface ContractErrorTypeDescriptorRecord {
  identity: string;
  variants: ReadonlyArray<ContractErrorVariantDescriptorRecord>;
}

export interface ContractKotobaEntryRecord {
  msg_id: string;
  translations: ReadonlyArray<ContractKotobaTranslationInput>;
}

export interface ContractCodeBytesRecord {
  network_id: string;
  artifact_id: { dataspace_id: string; code_hash: string };
  code_b64: string;
}

export interface SorafsStorageStateResponse {
  bytes_used: number;
  bytes_capacity: number;
  pin_queue_depth: number;
  fetch_inflight: number;
  fetch_bytes_per_sec: number;
  por_inflight: number;
  por_samples_success_total: number;
  por_samples_failed_total: number;
  fetch_utilisation_bps: number;
  pin_queue_utilisation_bps: number;
  por_utilisation_bps: number;
}

export interface SorafsManifestResponse {
  manifest_id_hex: string;
  manifest_b64: string;
  manifest_digest_hex: string;
  payload_digest_hex: string;
  content_length: number;
  chunk_count: number;
  chunk_profile_handle: string;
  stored_at_unix_secs: number;
}

export interface SorafsPorSubmissionResponse {
  status: string;
}

export interface SorafsPorVerdictResponse {
  status: string;
}

export interface SorafsChunkFetchSpecV1 {
  chunk_index: number;
  offset: number;
  length: number;
  digest_blake3: string;
}

export interface SorafsChunkFetchPlanV1 {
  schema: "sorafs.chunk_fetch_plan.v1";
  payload_digest_blake3_hex: string;
  chunk_fetch_specs: ReadonlyArray<SorafsChunkFetchSpecV1>;
}

export interface DaManifestFetchResponse {
  storage_ticket_hex: string;
  client_blob_id_hex: string;
  blob_hash_hex: string;
  manifest_hash_hex: string;
  manifest_id_hex: string;
  chunk_root_hex: string;
  lane_id: number;
  epoch: number;
  manifest_len: number;
  manifest_b64: string;
  manifest_bytes: Buffer;
  manifest_json: unknown;
  chunk_plan: SorafsChunkFetchPlanV1;
}

export interface DaProofSummaryOptions {
  sampleCount?: number;
  sampleSeed?: number | bigint;
  leafIndexes?: ReadonlyArray<number | bigint>;
}

export interface DaProofRecord {
  origin: string;
  leaf_index: number;
  chunk_index: number;
  segment_index: number;
  leaf_offset: number | bigint;
  leaf_length: number;
  segment_offset: number | bigint;
  segment_length: number;
  chunk_offset: number | bigint;
  chunk_length: number;
  payload_len: number | bigint;
  chunk_digest_hex: string;
  chunk_root_hex: string;
  segment_digest_hex: string;
  leaf_digest_hex: string;
  leaf_bytes_b64: string;
  segment_leaves_hex: ReadonlyArray<string>;
  chunk_segments_hex: ReadonlyArray<string>;
  chunk_count: number | bigint;
  chunk_merkle_path_hex: ReadonlyArray<string>;
  verified: boolean;
}

export interface DaProofSummary {
  blob_hash_hex: string;
  chunk_root_hex: string;
  por_root_hex: string;
  leaf_count: number | bigint;
  segment_count: number | bigint;
  chunk_count: number | bigint;
  sample_count: number;
  sample_seed: number | bigint;
  proof_count: number;
  proofs: ReadonlyArray<DaProofRecord>;
}

export function generateDaProofSummary(
  manifestBytes: BinaryLike,
  payloadBytes: BinaryLike,
  options?: DaProofSummaryOptions,
): DaProofSummary;

export interface DaProofSummaryArtifactRecord {
  origin: string;
  leaf_index: number | string;
  chunk_index: number | string;
  segment_index: number | string;
  leaf_offset: number | string;
  leaf_length: number | string;
  segment_offset: number | string;
  segment_length: number | string;
  chunk_offset: number | string;
  chunk_length: number | string;
  payload_len: number | string;
  chunk_digest: string;
  chunk_root: string;
  segment_digest: string;
  leaf_digest: string;
  leaf_bytes_b64: string;
  segment_leaves: ReadonlyArray<string>;
  chunk_segments: ReadonlyArray<string>;
  chunk_count: number | string;
  chunk_merkle_path: ReadonlyArray<string>;
  verified: boolean;
}

export interface DaProofSummaryArtifact {
  manifest_path: string | null;
  payload_path: string | null;
  blob_hash: string;
  chunk_root: string;
  por_root: string;
  leaf_count: number | string;
  segment_count: number | string;
  chunk_count: number | string;
  sample_count: number | string;
  sample_seed: number | string;
  proof_count: number | string;
  proofs: ReadonlyArray<DaProofSummaryArtifactRecord>;
}

export interface DaProofSummaryArtifactOptions {
  manifestPath?: string | null;
  payloadPath?: string | null;
}

export function buildDaProofSummaryArtifact(
  summary: DaProofSummary,
  options?: DaProofSummaryArtifactOptions,
): DaProofSummaryArtifact;

export interface EmitDaProofSummaryOptions {
  summary?: DaProofSummary;
  manifestBytes?: BinaryLike;
  payloadBytes?: BinaryLike;
  proofOptions?: DaProofSummaryOptions;
  manifestPath?: string | null;
  payloadPath?: string | null;
  outputPath?: string;
  pretty?: number | boolean;
}

export interface EmitDaProofSummaryResult {
  summary: DaProofSummary;
  artifact: DaProofSummaryArtifact;
  outputPath: string | null;
}

export function emitDaProofSummaryArtifact(
  options: EmitDaProofSummaryOptions,
): Promise<EmitDaProofSummaryResult>;

export function deriveDaChunkerHandle(manifestBytes: BinaryLike): string;

export interface DaGatewayFetchRequestBase {
  storageTicketHex?: string;
  manifestBundle?: DaManifestFetchResponse;
  chunkPlan?: SorafsChunkFetchPlanV1;
  planJson?: string;
  chunkerHandle?: string;
  fetchOptions?: SorafsGatewayFetchOptions;
  gatewayOptions?: SorafsGatewayFetchOptions;
  proofSummary?: boolean | DaProofSummaryOptions;
  signal?: AbortSignal;
}

export type DaGatewayFetchRequest =
  | (DaGatewayFetchRequestBase & {
      gatewayProviders: ReadonlyArray<SorafsGatewayProviderSpec>;
      providers?: never;
    })
  | (DaGatewayFetchRequestBase & {
      providers: ReadonlyArray<SorafsGatewayProviderSpec>;
      gatewayProviders?: never;
    });

export interface DaGatewayFetchSession {
  manifest: DaManifestFetchResponse;
  manifestIdHex: string;
  chunkerHandle: string;
  chunkPlan: SorafsChunkFetchPlanV1;
  chunkPlanJson: string;
  gatewayResult: SorafsGatewayFetchResult;
  proofSummary: DaProofSummary | null;
}

export interface DaManifestPersistedPaths {
  manifestPath: string;
  manifestJsonPath: string;
  chunkPlanPath: string;
  label: string;
}

export interface DaIngestMetadataEntry {
  key: string;
  value: ArrayBufferView | ArrayBuffer | Buffer | string;
  visibility?: "Public" | "GovernanceOnly";
  encryption?: {
    cipher?: "None" | "ChaCha20Poly1305";
    keyLabel?: string;
  };
}

export type DaIngestMetadataMapValue =
  | string
  | ArrayBuffer
  | ArrayBufferView
  | Buffer
  | {
      value: ArrayBufferView | ArrayBuffer | Buffer | string;
      visibility?: "Public" | "GovernanceOnly";
      encryption?: {
        cipher?: "None" | "ChaCha20Poly1305";
        keyLabel?: string;
      };
    };

export interface DaIngestRequestInput {
  payload: ArrayBufferView | ArrayBuffer | Buffer | string;
  /** Exact genesis-derived network identity signed into the request. */
  networkId: NetworkId;
  /** Canonical I105 account whose consensus DA quota is charged. */
  owner: string;
  laneId?: number;
  epoch?: number;
  sequence?: number;
  blobClass?:
    | "TaikaiSegment"
    | "NexusLaneSidecar"
    | "GovernanceArtifact"
    | { class: "Custom"; value: number };
  codec?: string;
  chunkSize?: number;
  erasureProfile?: {
    dataShards?: number;
    parityShards?: number;
    rowParityStripes?: number;
    chunkAlignment?: number;
    fecScheme?:
      | "Rs12_10"
      | "RsWin14_10"
      | "Rs18_14"
      | { scheme: "Custom"; value: number };
  };
  retentionPolicy?: {
    hotRetentionSecs?: number;
    coldRetentionSecs?: number;
    requiredReplicas?: number;
    storageClass?: "Hot" | "Warm" | "Cold";
    governanceTag?: string;
  };
  metadata?: Record<string, DaIngestMetadataMapValue> | DaIngestMetadataEntry[];
  compression?: "Identity" | "Gzip" | "Deflate" | "Zstd";
  noritoManifest?: ArrayBufferView | ArrayBuffer | Buffer | string;
  clientBlobId?: ArrayBufferView | ArrayBuffer | Buffer | string;
  signerPublicKey?: string;
  privateKey?: ArrayBufferView | ArrayBuffer | Buffer | string;
  privateKeyHex?: string;
  signatureHex?: string;
  artifactDir?: string;
  noSubmit?: boolean;
  dryRun?: boolean;
}

export interface DaRentQuote {
  base_rent: string;
  protocol_reserve: string;
  provider_reward: string;
  pdp_bonus: string;
  potr_bonus: string;
  egress_credit_per_gib: string;
}

export interface DaStripeLayout {
  total_stripes: number;
  shards_per_stripe: number;
  row_parity_stripes: number;
}

export interface DaIngestReceipt {
  client_blob_id_hex: string;
  client_blob_id_bytes: Buffer;
  lane_id: number;
  epoch: number;
  blob_hash_hex: string;
  blob_hash_bytes: Buffer;
  chunk_root_hex: string;
  chunk_root_bytes: Buffer;
  manifest_hash_hex: string;
  manifest_hash_bytes: Buffer;
  storage_ticket_hex: string;
  storage_ticket_bytes: Buffer;
  stripe_layout: DaStripeLayout;
  pdp_commitment_b64: string | null;
  pdp_commitment_bytes: Buffer | null;
  queued_at_unix: number;
  operator_signature_hex: string;
  rent_quote: DaRentQuote;
}

export interface DaIngestArtifacts {
  clientBlobIdHex: string;
  payloadHashHex: string;
  signerPublicKey: string;
  signatureHex: string;
  signingDigestHex: string;
  payloadLength: number;
}

export interface DaIngestArtifactPaths {
  requestJsonPath: string | null;
  receiptJsonPath: string | null;
  responseHeadersPath: string | null;
}

export interface DaIngestSubmitResponse {
  status: string;
  duplicate: boolean;
  receipt: DaIngestReceipt | null;
  artifacts: DaIngestArtifacts;
  pdpCommitmentHeader: string | null;
  artifactPaths: DaIngestArtifactPaths | null;
}

export interface DaIngestBuildRequestResult {
  request: Record<string, unknown>;
  artifacts: DaIngestArtifacts;
}

export function buildDaIngestRequest(
  options?: DaIngestRequestInput,
): DaIngestBuildRequestResult;

export function computeDaIngestSigningDigest(
  request: Record<string, unknown>,
): Buffer;

export interface SorafsPorStatusOptions {
  manifestHex?: string | null;
  providerHex?: string | null;
  epoch?: NumericLike;
  status?: string;
  limit?: NumericLike;
  maxBytes?: NumericLike;
  cursor?: string | null;
  signal?: AbortSignal;
}

export interface SorafsPorExportOptions {
  startEpoch?: NumericLike;
  endEpoch?: NumericLike;
  limit?: NumericLike;
  maxBytes?: NumericLike;
  cursor?: string | null;
  signal?: AbortSignal;
}

export type SorafsIsoWeekInput = string | { year: number; week: number };

export interface SorafsChunkerHandle {
  profile_id: number;
  namespace: string;
  name: string;
  semver: string;
  multihash_code: number | bigint;
}

export interface SorafsManifestAliasBinding {
  namespace: string;
  name: string;
  /** Exact native standard-base64 proof bytes. */
  proof: string;
}

export type SorafsManifestStatusState = "pending" | "approved" | "retired";

export interface SorafsPinPolicy {
  min_replicas: number;
  storage_class: { type: "Hot" | "Warm" | "Cold"; value: null };
  retention_epoch: number | bigint;
}

export interface SorafsPinFeePayment {
  paid_by: string;
  fee_asset_id: string;
  treasury_account_id: string;
  amount: string;
}

export interface SorafsManifestRecord {
  digest: Uint8Array;
  root_cid: Uint8Array;
  chunker: SorafsChunkerHandle;
  chunk_digest_sha3_256: Uint8Array;
  por_root: Uint8Array;
  content_length: number | bigint;
  policy: SorafsPinPolicy;
  submitted_by: string;
  submitted_epoch: number | bigint;
  approved_epoch: number | bigint | null;
  alias: SorafsManifestAliasBinding | null;
  successor_of?: Uint8Array;
  metadata: Record<string, unknown>;
  status: SorafsPinNativeStatus;
  retirement_reason?: string;
  council_envelope_digest: Uint8Array | null;
  pin_fee_payment?: SorafsPinFeePayment;
}

export interface SorafsPinManifestResponse {
  finalized_cursor: SorafsPinFinalizedCursorV1;
  manifest: SorafsManifestRecord;
}

export interface SorafsPinManifestReadOptions {
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** Positive exact u64; must accompany expectedFinalizedBlockHashHex. */
  expectedFinalizedHeight?: number | bigint;
  /** Exact non-zero lowercase 32-byte hex; must accompany expectedFinalizedHeight. */
  expectedFinalizedBlockHashHex?: string;
}

export interface SorafsPinFinalizedCursorV1 {
  height: number | bigint;
  block_hash: Uint8Array;
}

export interface SorafsPinResourceUsage {
  manifest_count: number | bigint;
  content_bytes: number | bigint;
}

export type SorafsPinNativeStatus =
  | { status: "Pending"; value: null }
  | { status: "Approved"; value: number | bigint }
  | { status: "Retired"; value: number | bigint };

export interface SorafsPinManifestSummaryV1 {
  digest: Uint8Array;
  submitted_by: string;
  submitted_epoch: number | bigint;
  approved_epoch: number | bigint | null;
  content_length: number | bigint;
  retention_epoch: number | bigint;
  status: SorafsPinNativeStatus;
  successor_of: Uint8Array | null;
}

export interface SorafsPinListResponse {
  finalized_cursor: SorafsPinFinalizedCursorV1;
  charged_usage: SorafsPinResourceUsage;
  manifests: ReadonlyArray<SorafsPinManifestSummaryV1>;
  has_more: boolean;
  next_after_digest: Uint8Array | null;
}

export interface SorafsPinListOptions {
  status?: SorafsManifestStatusState;
  limit?: NumericLike;
  maxBytes?: NumericLike;
  afterDigestHex?: string;
  expectedFinalizedHeight?: number | bigint;
  expectedFinalizedBlockHashHex?: string;
  signal?: AbortSignal;
}

export interface SorafsPinIteratorOptions extends SorafsPinListOptions {
  pageSize?: NumericLike;
  maxItems?: NumericLike;
}

export interface RegisterPinManifestAliasInput {
  namespace: string;
  name: string;
  proof: Buffer | ArrayBuffer | ArrayBufferView;
}

export interface RegisterPinManifestInstructionInput {
  manifestPayload: Buffer | ArrayBuffer | ArrayBufferView;
  alias?: RegisterPinManifestAliasInput | null;
  successorOf?: string | Buffer | ArrayBuffer | ArrayBufferView | null;
}

export type RegisterPinManifestTransactionInput = Omit<
  TransactionAssemblyInput,
  "instructions"
> &
  RegisterPinManifestInstructionInput;

export interface SorafsPinRegisterResponse {
  status: "submitted";
  tx_hash_hex: string;
  manifest_digest_hex: string;
}

export type SorafsAliasManifestStatusV1 =
  | { state: "pending" }
  | { state: "approved" | "retired"; epoch: ToriiU64 };

export type SorafsAliasCacheDecisionV1 = "serve" | "hold" | "refuse";
export type SorafsAliasCacheReasonV1 =
  | "RefreshWindow" | "ExpiredTTL" | "HardExpired" | "RotationDue"
  | "GovernanceGrace" | "GovernanceRevoked" | "GovernanceFrozen" | "GovernanceRotated"
  | "ManifestMissing" | "LineageDepthExceeded" | "LineageCycleDetected" | "SuccessorForkResolved"
  | "ApprovedSuccessorPending" | "ApprovedSuccessorGrace" | "ApprovedSuccessor"
  | "MissingTimestamp" | "PendingSuccessor";
export type SorafsAliasLineageAnomalyV1 =
  | "ManifestMissing" | "SuccessorForkResolved" | "LineageDepthExceeded" | "LineageCycleDetected";
export type SorafsAliasStatusLabelV1 =
  | "fresh" | "fresh-rotate" | "refresh" | "refresh-rotate" | "expired" | "hard-expired"
  | "lineage-invalid" | "governance-refused" | "successor-refused"
  | "refresh-successor" | "refresh-governance" | "pending-successor";

export interface SorafsAliasLineageSuccessorV1 {
  digest_hex: string;
  status: SorafsAliasManifestStatusV1;
  approved_epoch: ToriiU64 | null;
  approved_at: string | null;
  status_timestamp_unix: ToriiU64 | null;
}

export interface SorafsAliasLineageV1 {
  successor_of_hex: string | null;
  head_hex: string;
  depth_to_head: number;
  is_head: boolean;
  superseded_by: SorafsAliasLineageSuccessorV1 | null;
  immediate_successor: SorafsAliasLineageSuccessorV1 | null;
  anomalies: ReadonlyArray<SorafsAliasLineageAnomalyV1>;
}

export interface SorafsAliasCacheSuccessorV1 {
  exists: boolean;
  head_hex: string | null;
  approved: boolean;
  approved_at: string | null;
  approved_at_unix: ToriiU64 | null;
  depth_to_head: number;
  anomalies: ReadonlyArray<SorafsAliasLineageAnomalyV1>;
}

export interface SorafsAliasGovernanceFlagsV1 {
  revoked: boolean;
  frozen: boolean;
  rotated: boolean;
}

export interface SorafsAliasCacheGovernanceV1 extends SorafsAliasGovernanceFlagsV1 {
  ref_ids: ReadonlyArray<string>;
  flags: SorafsAliasGovernanceFlagsV1;
  effective_at: string | null;
  effective_at_unix: ToriiU64 | null;
}

export interface SorafsAliasCacheEvaluationV1 {
  decision: SorafsAliasCacheDecisionV1;
  reasons: ReadonlyArray<SorafsAliasCacheReasonV1>;
  ttl_expires_at: string | null;
  ttl_expires_at_unix: ToriiU64;
  serve_until: string | null;
  serve_until_unix: ToriiU64 | null;
  successor: SorafsAliasCacheSuccessorV1;
  governance: SorafsAliasCacheGovernanceV1;
  policy_successor_grace_secs: ToriiU64;
  policy_governance_grace_secs: ToriiU64;
}

/** Committed-state metadata; the SDK projection alone does not verify finality. */
export interface SorafsAliasAttestationV1 {
  block_height: ToriiU64;
  block_hash_hex: string | null;
  chain_id: string;
}

export interface SorafsAliasRecord {
  alias: string;
  namespace: string;
  name: string;
  manifest_digest_hex: string;
  bound_by: string;
  bound_epoch: ToriiU64;
  expiry_epoch: ToriiU64;
  proof_b64: string;
  cache_state: SorafsAliasStatusLabelV1;
  status_label: SorafsAliasStatusLabelV1;
  cache_rotation_due: boolean;
  cache_age_seconds: ToriiU64;
  proof_generated_at_unix: ToriiU64;
  proof_expires_at_unix: ToriiU64;
  proof_expires_in_seconds?: ToriiU64;
  policy_positive_ttl_secs: ToriiU64;
  policy_refresh_window_secs: ToriiU64;
  policy_hard_expiry_secs: ToriiU64;
  policy_rotation_max_age_secs: ToriiU64;
  policy_successor_grace_secs: ToriiU64;
  policy_governance_grace_secs: ToriiU64;
  cache_decision: SorafsAliasCacheDecisionV1;
  cache_reasons: ReadonlyArray<SorafsAliasCacheReasonV1>;
  cache_evaluation: SorafsAliasCacheEvaluationV1;
  lineage: SorafsAliasLineageV1;
}

export interface SorafsAliasListResponse {
  attestation: SorafsAliasAttestationV1;
  total_count: number;
  returned_count: number;
  offset: number;
  limit: number;
  aliases: ReadonlyArray<SorafsAliasRecord>;
}

export interface SorafsAliasListOptions {
  namespace?: string;
  manifestDigestHex?: string;
  limit?: NumericLike;
  offset?: NumericLike;
  signal?: AbortSignal;
  canonicalAuth: CanonicalRequestAuth;
}

export type SorafsReplicationStatus =
  | { state: "pending" }
  | { state: "completed" | "expired" | "cancelled"; epoch: number | bigint };

export interface SorafsReplicationCompletion {
  provider_hex: string;
  completed_by: string;
  completion_epoch: number | bigint;
  assignment_revision: number | bigint;
  completion_authority: {
    provider_owner: string;
    completion_signer: string;
    signer_policy: {
      policy_id_hex: string;
      revision: number | bigint;
      predecessor_digest_hex: string | null;
      policy_digest_hex: string;
    };
  };
  finalized_anchor: { height: number | bigint; block_hash_hex: string };
}

export interface SorafsReplicationOrderProjection {
  version: 1;
  order_id_hex: string;
  manifest_cid_b64: string;
  manifest_digest_hex: string;
  chunking_profile: string;
  target_replicas: number;
  assignments: ReadonlyArray<{ provider_id_hex: string; slice_gib: number | bigint; lane: string | null }>;
  issued_at: number | bigint;
  deadline_at: number | bigint;
  sla: { ingest_deadline_secs: number; min_availability_percent_milli: number; min_por_success_percent_milli: number };
  metadata: ReadonlyArray<{ key: string; value: string }>;
}

export interface SorafsReplicationOrderRecord {
  order_id_hex: string;
  manifest_digest_hex: string;
  issued_by: string;
  issued_epoch: number | bigint;
  deadline_epoch: number | bigint;
  status: SorafsReplicationStatus;
  canonical_order_b64: string;
  assignment_revision: number | bigint;
  order: SorafsReplicationOrderProjection;
  provider_completions: ReadonlyArray<SorafsReplicationCompletion>;
  providers: ReadonlyArray<string>;
}

export interface SorafsReplicationListResponse {
  attestation: { block_height: number | bigint; block_hash_hex: string | null; chain_id: string };
  total_count: number | bigint;
  returned_count: number;
  offset: number;
  limit: number;
  replication_orders: ReadonlyArray<SorafsReplicationOrderRecord>;
}

export interface SorafsReplicationListOptions {
  status?: "pending" | "completed" | "cancelled" | "expired";
  manifestDigestHex?: string;
  limit?: number;
  offset?: number;
  signal?: AbortSignal;
  canonicalAuth: CanonicalRequestAuth;
}

export type SorafsOrderbookSide = "bid" | "ask";
export type SorafsOrderbookTier = "hot" | "warm" | "archive";
export type SorafsOrderbookEventKind =
  | "policy_activated"
  | "order_admitted"
  | "order_cancelled"
  | "trade_matched"
  | "order_expired"
  | "channel_expired"
  | "receipt_recorded";

export interface SorafsOrderbookFinalizedAnchorOptions {
  expectedFinalizedHeight?: NumericLike;
  expectedFinalizedBlockHashHex?: string;
}

export interface SorafsOrderbookReadOptions
  extends SorafsOrderbookFinalizedAnchorOptions {
  limit?: NumericLike;
  afterIdHex?: string;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

export interface SorafsOrderbookEventCursorOptions {
  afterSequence?: NumericLike;
  afterBlockHeight?: NumericLike;
  afterBlockHashHex?: string;
  afterEventIndex?: NumericLike;
}

export interface SorafsOrderbookEventsOptions
  extends SorafsOrderbookFinalizedAnchorOptions,
    SorafsOrderbookEventCursorOptions {
  limit?: NumericLike;
  ifNoneMatch?: string;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

export interface SorafsOrderbookEventStreamOptions
  extends SorafsOrderbookFinalizedAnchorOptions,
    SorafsOrderbookEventCursorOptions {
  limit?: NumericLike;
  signal?: AbortSignal;
}

export interface SorafsOrderbookEventsWebSocketParams
  extends SorafsOrderbookFinalizedAnchorOptions,
    SorafsOrderbookEventCursorOptions {
  limit?: NumericLike;
  endpointPath?: string;
}

export interface SorafsOrderbookEventsWebSocketDialOptions<T = unknown>
  extends SorafsOrderbookEventsWebSocketParams {
  baseUrl: string;
  protocols?: ConnectWebSocketProtocols;
  websocketOptions?: unknown;
  WebSocketImpl?: ConnectWebSocketConstructor<T>;
}

export interface ClientSorafsOrderbookEventsWebSocketOptions<T = unknown>
  extends SorafsOrderbookEventsWebSocketParams {
  protocols?: ConnectWebSocketProtocols;
  websocketOptions?: unknown;
  WebSocketImpl?: ConnectWebSocketConstructor<T>;
}

export interface SorafsOrderbookEventsWebSocketStreamOptions<T = unknown>
  extends ClientSorafsOrderbookEventsWebSocketOptions<T> {
  signal?: AbortSignal;
  closeOnReturn?: boolean;
}

export interface SorafsOrderbookFinalizedCursor {
  height: number;
  block_hash: string;
}

export interface SorafsOrderbookLedgerStatus {
  open_orders: number;
  partially_filled_orders: number;
  filled_orders: number;
  cancelled_orders: number;
  expired_orders: number;
  trades: number;
  settlement_receipts: number;
  settlement_channels: number;
  open_settlement_channels: number;
  book_revision: number;
  next_admission_sequence: number;
  next_trade_sequence: number;
  updated_at_unix: number;
}

export type SorafsOrderbookNativeOrderStatus =
  | "open"
  | "partially_filled"
  | "filled"
  | "cancelled"
  | "expired"
  | Readonly<Record<string, unknown>>;

export interface SorafsOrderbookOrderRecord
  extends Readonly<Record<string, unknown>> {
  order_id: string;
  owner: unknown;
  canonical_order: string;
  admitted_policy_digest: string;
  admitted_at_unix: number;
  admission_sequence: number;
  remaining_gib: number;
  status: SorafsOrderbookNativeOrderStatus;
  updated_at_unix: number;
  canonical_cancel: string | null;
  cancelled_at_unix: number | null;
  cancelled_policy_digest: string | null;
}

export interface SorafsOrderbookTradeRecord
  extends Readonly<Record<string, unknown>> {
  trade_id: string;
  maker_order_id: string;
  taker_order_id: string;
  trade_sequence: number;
  canonical_trade: string;
  channel_id: string;
  book_revision: number;
  recorded_at_unix: number;
}

export type SorafsOrderbookNativeChannelStatus =
  | "open"
  | "closed"
  | "expired"
  | Readonly<Record<string, unknown>>;

export interface SorafsOrderbookSettlementChannelRecord
  extends Readonly<Record<string, unknown>> {
  channel_id: string;
  trade_id: string;
  buyer: unknown;
  provider: unknown;
  provider_id: string;
  settlement_authority: unknown;
  total_bytes: number;
  remaining_bytes: number;
  initial_xor_locked: string;
  remaining_xor_locked: string;
  status: SorafsOrderbookNativeChannelStatus;
  opened_at_unix: number;
  expires_at_unix: number;
  updated_at_unix: number;
}

export interface SorafsOrderbookSettlementReceiptRecord
  extends Readonly<Record<string, unknown>> {
  receipt_id: string;
  channel_id: string;
  trade_id: string;
  canonical_receipt: string;
  admitted_policy_digest: string;
  admitted_at_unix: number;
  recorded_by: unknown;
}

export interface SorafsOrderbookOrderPage {
  finalized_cursor: SorafsOrderbookFinalizedCursor;
  orders: ReadonlyArray<SorafsOrderbookOrderRecord>;
  has_more: boolean;
  next_after_order_id: string | null;
}

export interface SorafsOrderbookTradePage {
  finalized_cursor: SorafsOrderbookFinalizedCursor;
  trades: ReadonlyArray<SorafsOrderbookTradeRecord>;
  has_more: boolean;
  next_after_trade_id: string | null;
}

export interface SorafsOrderbookSettlementChannelPage {
  finalized_cursor: SorafsOrderbookFinalizedCursor;
  channels: ReadonlyArray<SorafsOrderbookSettlementChannelRecord>;
  has_more: boolean;
  next_after_channel_id: string | null;
}

export interface SorafsOrderbookSettlementReceiptPage {
  finalized_cursor: SorafsOrderbookFinalizedCursor;
  receipts: ReadonlyArray<SorafsOrderbookSettlementReceiptRecord>;
  has_more: boolean;
  next_after_receipt_id: string | null;
}

export interface SorafsOrderbookBookResponse {
  source: "finalized_chain";
  status: SorafsOrderbookLedgerStatus;
  orders: SorafsOrderbookOrderPage;
}

export interface SorafsOrderbookTradesResponse {
  source: "finalized_chain";
  trades: SorafsOrderbookTradePage;
}

export interface SorafsOrderbookChannelsResponse {
  source: "finalized_chain";
  channels: SorafsOrderbookSettlementChannelPage;
}

export interface SorafsOrderbookReceiptsResponse {
  source: "finalized_chain";
  receipts: SorafsOrderbookSettlementReceiptPage;
}

export interface SorafsOrderbookLedgerEvent
  extends Readonly<Record<string, unknown>> {
  kind:
    | SorafsOrderbookEventKind
    | Readonly<{ kind: SorafsOrderbookEventKind; detail?: unknown }>;
  order_id: string | null;
  trade_id: string | null;
  channel_id: string | null;
  receipt_id: string | null;
  provider_id: string | null;
  book_revision: number;
  authority: unknown;
  occurred_at_unix_ms: number;
}

export interface SorafsOrderbookFinalizedEventCursor {
  sequence: number;
  block_height: number;
  block_hash: string;
  event_index: number;
}

export interface SorafsOrderbookFinalizedEvent
  extends SorafsOrderbookFinalizedEventCursor {
  event: SorafsOrderbookLedgerEvent;
}

export interface SorafsOrderbookFinalizedEventPage {
  finalized_cursor: SorafsOrderbookFinalizedCursor;
  events: ReadonlyArray<SorafsOrderbookFinalizedEvent>;
  has_more: boolean;
  next_after: SorafsOrderbookFinalizedEventCursor | null;
}

export interface SorafsOrderbookEventsResponse {
  source: "finalized_chain";
  events: SorafsOrderbookFinalizedEventPage;
}

export interface SorafsReputationWitnessHeaders
  extends Record<string, string | undefined> {
  /**
   * Exact canonical Norito witness. Reputation requests carrying a static
   * witness are single-attempt and are never transparently retried.
   */
  "X-Iroha-Witness": string;
  "X-Iroha-Account"?: string;
}

export type SorafsReputationAuthenticationOptions =
  | {
      canonicalAuth: CanonicalRequestAuth;
      headers?: Record<string, string>;
    }
  | {
      canonicalAuth?: never;
      headers: SorafsReputationWitnessHeaders;
    };

export type SorafsReputationCacheOptions =
  SorafsReputationAuthenticationOptions & {
  ifNoneMatch?: string;
  signal?: AbortSignal;
};

export type SorafsReputationEventsOptions =
  SorafsReputationCacheOptions & {
  since?: NumericLike;
  limit?: NumericLike;
};

export type SorafsReputationEventStreamOptions =
  SorafsReputationAuthenticationOptions & {
  since?: NumericLike;
  limit?: NumericLike;
  signal?: AbortSignal;
};

export interface SorafsHedgingBillingAuthOptions {
  canonicalAuth: CanonicalRequestAuth;
  signal?: AbortSignal;
}

export interface SorafsBillingStatementListOptions
  extends SorafsHedgingBillingAuthOptions {
  expectedCheckpointFingerprintHex: string;
  afterStatementIdHex?: string;
  limit: number;
}

export interface SorafsHedgingProjectionOptions
  extends SorafsHedgingBillingAuthOptions {
  expectedCheckpointFingerprintHex: string;
  afterHex?: string;
  limit: number;
}

export type SorafsReputationU64 = number | bigint;

export interface SorafsReputationWeights {
  version: 1;
  por_success_bps: number;
  pdp_success_bps: number;
  potr_success_bps: number;
  latency_bps: number;
  dispute_bps: number;
  token_violation_bps: number;
  repair_breach_bps: number;
}

export interface SorafsReputationProviderMetrics {
  version: 1;
  por_success_bps: number;
  pdp_success_bps: number;
  potr_success_bps: number;
  latency_health_bps: number;
  dispute_rate_bps: number;
  token_violation_rate_bps: number;
  repair_breach_rate_bps: number;
}

export type SorafsReputationDegradationFlagName =
  | "reserve_warning"
  | "reserve_grace"
  | "reserve_delinquent"
  | "reserve_default"
  | "proof_success_below90"
  | "proof_success_below80"
  | "active_dispute"
  | "slashing_event"
  | "low_score";

export interface SorafsReputationDegradationFlag {
  flag: SorafsReputationDegradationFlagName;
  value: null;
}

export interface SorafsReputationProvider {
  provider_id: string;
  score_bps: number;
  degradation_flags: ReadonlyArray<SorafsReputationDegradationFlag>;
  raw_metrics: SorafsReputationProviderMetrics;
  raw_metrics_hash_hex: string;
}

export interface SorafsReputationSnapshotSummary {
  snapshot_id_hex: string;
  generated_at_unix: SorafsReputationU64;
  previous_snapshot_id_hex: string | null;
  merkle_root_hex: string;
  provider_count: number;
  returned_provider_count: number;
  limit: number;
  truncated_providers: boolean;
  alpha_bps: 8500;
  current_score_weight_bps: 7000;
  weights: SorafsReputationWeights;
  providers: ReadonlyArray<SorafsReputationProvider>;
}

export interface SorafsReputationProviderProof {
  provider_id: string;
  leaf_index: number;
  leaf_count: number;
  siblings_hex: ReadonlyArray<string>;
}

export interface SorafsReputationProviderResponse {
  snapshot_id_hex: string;
  generated_at_unix: SorafsReputationU64;
  merkle_root_hex: string;
  provider: SorafsReputationProvider;
  proof: SorafsReputationProviderProof;
}

export interface SorafsReputationWeightsResponse {
  snapshot_id_hex: string;
  generated_at_unix: SorafsReputationU64;
  alpha_bps: 8500;
  current_score_weight_bps: 7000;
  weights: SorafsReputationWeights;
}

export interface SorafsReputationSnapshotEvent {
  version: 1;
  sequence: SorafsReputationU64;
  snapshot_id_hex: string;
  generated_at_unix: SorafsReputationU64;
  merkle_root_hex: string;
  provider_count: number;
  previous_snapshot_id_hex: string | null;
}

export interface SorafsReputationEventsResponse {
  since: SorafsReputationU64 | null;
  limit: number;
  count: number;
  next_since: SorafsReputationU64 | null;
  events: ReadonlyArray<SorafsReputationSnapshotEvent>;
}

export interface SorafsReputationSnapshotSseEvent {
  event: "reputation_snapshot";
  data: SorafsReputationSnapshotEvent;
  id: string;
  retry: null;
  raw: string;
}

export interface SorafsReputationLaggedSseEvent {
  event: "lagged";
  data: SorafsReputationU64;
  id: null;
  retry: null;
  raw: string;
}

export type SorafsReputationSseEvent =
  | SorafsReputationSnapshotSseEvent
  | SorafsReputationLaggedSseEvent;

export interface UaidPortfolioTotals {
  accounts: number;
  positions: number;
}

export interface UaidPortfolioAsset {
  asset_id: string;
  asset_definition_id: string;
  quantity: string;
}

export interface UaidPortfolioAccount {
  account_id: string;
  label: string | null;
  assets: ReadonlyArray<UaidPortfolioAsset>;
}

export interface UaidPortfolioDataspace {
  dataspace_id: number;
  dataspace_alias: string | null;
  accounts: ReadonlyArray<UaidPortfolioAccount>;
}

export interface UaidPortfolioResponse {
  uaid: string;
  totals: UaidPortfolioTotals;
  dataspaces: ReadonlyArray<UaidPortfolioDataspace>;
}

export interface UaidPortfolioQueryOptions {
  assetId?: string;
  signal?: AbortSignal;
}

export interface UaidBindingsDataspace {
  dataspace_id: number;
  dataspace_alias: string | null;
  accounts: ReadonlyArray<string>;
}

export interface UaidBindingsResponse {
  uaid: string;
  dataspaces: ReadonlyArray<UaidBindingsDataspace>;
}

export type UaidManifestStatus = "Pending" | "Active" | "Expired" | "Revoked";

export interface UaidManifestLifecycleRevocation {
  epoch: number;
  reason: string | null;
}

export interface UaidManifestLifecycle {
  activated_epoch: number | null;
  expired_epoch: number | null;
  revocation: UaidManifestLifecycleRevocation | null;
}

export type UaidManifestRole = "Initiator" | "Participant";

export interface UaidManifestScope {
  dataspace?: number;
  program?: string;
  method?: string;
  asset?: string;
  role?: UaidManifestRole;
}

export type UaidManifestAllowanceWindow = "PerSlot" | "PerMinute" | "PerDay";

export interface UaidManifestAllowEffect {
  Allow: {
    window: UaidManifestAllowanceWindow;
    max_amount?: string;
  };
}

export interface UaidManifestDenyEffect {
  Deny: {
    reason?: string;
  };
}

export type UaidManifestEffect =
  | UaidManifestAllowEffect
  | UaidManifestDenyEffect;

export interface UaidManifestEntry {
  scope: UaidManifestScope;
  effect: UaidManifestEffect;
  notes?: string;
}

export interface UaidAssetPermissionManifest {
  version: 1;
  uaid: string;
  dataspace: number;
  issued_ms: number;
  activation_epoch: number;
  expiry_epoch?: number;
  entries: ReadonlyArray<UaidManifestEntry>;
}

export interface UaidManifestRecord {
  dataspace_id: number;
  dataspace_alias: string | null;
  manifest_hash: string;
  status: UaidManifestStatus;
  lifecycle: UaidManifestLifecycle;
  accounts: ReadonlyArray<string>;
  manifest: UaidAssetPermissionManifest;
}

export interface PublishSpaceDirectoryManifestRequest {
  authority: string;
  manifest: UaidAssetPermissionManifest;
  reason?: string;
}

export interface RevokeSpaceDirectoryManifestRequest {
  authority: string;
  uaid: string;
  dataspaceId: number;
  revokedEpoch: number;
  reason?: string;
}

export interface UaidBindingsQueryOptions {
  signal?: AbortSignal;
}

/** Exact dataspace ownership for one immutable compiled artifact. */
export interface ContractArtifactIdInput {
  dataspaceId: SmartContractUnsigned64;
  codeHash: HashLike;
}

export interface RegisterSmartContractCodeInstructionInput {
  artifactId: ContractArtifactIdInput;
  manifest: ContractManifestInput;
}

export interface RegisterSmartContractBytesInstructionInput {
  artifactId: ContractArtifactIdInput;
  code: ArrayBufferView | ArrayBuffer | Buffer | string;
}

export type SmartContractUnsigned64 = number | bigint | string;

export interface UploadSmartContractCodeChunkInstructionInput {
  artifactId: ContractArtifactIdInput;
  totalSize: SmartContractUnsigned64;
  chunkIndex: number;
  chunkCount: number;
  chunk: ArrayBufferView | ArrayBuffer | Buffer | string;
}

export interface FinalizeSmartContractCodeUploadInstructionInput {
  artifactId: ContractArtifactIdInput;
  totalSize: SmartContractUnsigned64;
  chunkCount: number;
}

export interface CancelSmartContractCodeUploadInstructionInput {
  artifactId: ContractArtifactIdInput;
}

export interface CommitContractDeploymentInstructionInput {
  expectedDeployNonce: SmartContractUnsigned64;
  contractAddress: string;
  codeHash: HashLike;
  contractAlias: string;
  leaseExpiryMs?: SmartContractUnsigned64 | null;
  expectedPreviousContractAddress?: string | null;
}

export interface RemoveSmartContractBytesInstructionInput {
  artifactId: ContractArtifactIdInput;
  reason?: string | null;
}

export interface CreateKaigiTransactionInput {
  networkId: NetworkId;
  authority: string;
  call: CreateKaigiInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface JoinKaigiTransactionInput {
  networkId: NetworkId;
  authority: string;
  join: JoinKaigiInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface LeaveKaigiTransactionInput {
  networkId: NetworkId;
  authority: string;
  leave: LeaveKaigiInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface EndKaigiTransactionInput {
  networkId: NetworkId;
  authority: string;
  end: EndKaigiInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface ConfidentialTransferProofInputV2 {
  amount: NumericLike;
  rhoHex: string;
  diversifierHex: string;
  /** Existing leaf position, from 0 through 65535. */
  leafIndex: number;
}

/** Actual consumed notes; the native prover supplies any absent second input. */
export type ConfidentialProofInputsV2 =
  | readonly [ConfidentialTransferProofInputV2]
  | readonly [ConfidentialTransferProofInputV2, ConfidentialTransferProofInputV2];

export interface ConfidentialTransferProofOutputV2 {
  amount: NumericLike;
  rhoHex: string;
  ownerTagHex: string;
}

/** One or two actual output notes for a transfer. */
export type ConfidentialTransferProofOutputsV2 =
  | readonly [ConfidentialTransferProofOutputV2]
  | readonly [ConfidentialTransferProofOutputV2, ConfidentialTransferProofOutputV2];

export interface ConfidentialTransferProofResultV2 {
  nullifiers: ReadonlyArray<Buffer>;
  outputCommitments: ReadonlyArray<Buffer>;
  root: Buffer;
  proof: Buffer;
}

export interface ConfidentialUnshieldProofOutputV3 {
  amount: NumericLike;
  rhoHex: string;
}

export interface RecordKaigiUsageTransactionInput {
  networkId: NetworkId;
  authority: string;
  usage: RecordKaigiUsageInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface SetKaigiRelayManifestTransactionInput {
  networkId: NetworkId;
  authority: string;
  manifest: SetKaigiRelayManifestInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface RegisterKaigiRelayTransactionInput {
  networkId: NetworkId;
  authority: string;
  relay: RegisterKaigiRelayInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface UnregisterKaigiRelayTransactionInput {
  networkId: NetworkId;
  authority: string;
  relayId: string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface ReportKaigiRelayHealthTransactionInput {
  networkId: NetworkId;
  authority: string;
  report: ReportKaigiRelayHealthInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface ProposeDeployContractTransactionInput {
  networkId: NetworkId;
  authority: string;
  proposal: ProposeDeployContractInstructionInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface CastZkBallotTransactionInput {
  networkId: NetworkId;
  authority: string;
  ballot: CastZkBallotInstructionInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface CastPlainBallotTransactionInput {
  networkId: NetworkId;
  authority: string;
  ballot: CastPlainBallotInstructionInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface UpdatePlainConvictionTransactionInput {
  networkId: NetworkId;
  authority: string;
  update: UpdatePlainConvictionInstructionInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface RegisterZkAssetTransactionInput {
  networkId: NetworkId;
  authority: string;
  registration: RegisterZkAssetInstructionInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface ScheduleConfidentialPolicyTransitionTransactionInput {
  networkId: NetworkId;
  authority: string;
  transition: ScheduleConfidentialPolicyTransitionInstructionInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface CancelConfidentialPolicyTransitionTransactionInput {
  networkId: NetworkId;
  authority: string;
  cancellation: CancelConfidentialPolicyTransitionInstructionInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface CreateElectionTransactionInput {
  networkId: NetworkId;
  authority: string;
  election: CreateElectionInstructionInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface SubmitBallotTransactionInput {
  networkId: NetworkId;
  authority: string;
  ballot: SubmitBallotInstructionInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface FinalizeElectionTransactionInput {
  networkId: NetworkId;
  authority: string;
  finalization: FinalizeElectionInstructionInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface RegisterSmartContractCodeTransactionInput {
  artifactId: ContractArtifactIdInput;
  networkId: NetworkId;
  authority: string;
  manifest: ContractManifestInput;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface RegisterSmartContractBytesTransactionInput {
  networkId: NetworkId;
  authority: string;
  artifactId: ContractArtifactIdInput;
  code: ArrayBufferView | ArrayBuffer | Buffer | string;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface RemoveSmartContractBytesTransactionInput {
  networkId: NetworkId;
  authority: string;
  artifactId: ContractArtifactIdInput;
  reason?: string | null;
  metadata?: MetadataLike;
  creationTimeMs?: number | null;
  ttlMs?: number | null;
  nonce?: number | null;
  privateKey: Buffer | ArrayBuffer | ArrayBufferView;
  privateKeyAlgorithm?: CryptoAlgorithm;
}

export interface SubmitTransactionAndWaitOptions
  extends TransactionStatusPollOptions {
  /** Optional assertion; it must equal the hash derived from the signed bytes. */
  hashHex?: string;
}

// ---------------------------------------------------------------------------
// Errors shared by every Torii client
// ---------------------------------------------------------------------------

/** `details` of Torii's `{"code", "message", "details"}` error envelope. */
export interface ToriiErrorDetails {
  /** The request control at fault (`filter`, `sort`, `select`, ...). */
  readonly field?: string;
  /** The data field at fault, when there is one. */
  readonly actual?: string;
  /** The accepted fields, as a comma-separated string. */
  readonly expected?: string;
  /** A suggested fix, such as the closest field name. */
  readonly hint?: string;
  readonly [key: string]: unknown;
}

/** Base class of every error raised for a Torii request or response. */
export declare class ToriiError extends Error {
  constructor(
    message: string,
    options?: {
      code?: string | null;
      details?: ToriiErrorDetails | null;
      cause?: unknown;
    },
  );
  /** Stable machine-readable code such as `invalid_filter`, or `null`. */
  readonly code: string | null;
  /** Structured details from the error envelope, or `null`. */
  readonly details: ToriiErrorDetails | null;
}

/** Collection-query error codes; identical on the client and in Torii responses. */
export type ListQueryErrorCode =
  | "invalid_query"
  | "invalid_filter"
  | "invalid_sort"
  | "invalid_select"
  | "invalid_aggregate"
  | "invalid_limit"
  | "invalid_cursor"
  | "invalid_include_total";

/** The control a collection-query error names; `query` means the request as a whole. */
export type ListQueryParameter =
  | "query"
  | "filter"
  | "sort"
  | "select"
  | "aggregate"
  | "limit"
  | "cursor"
  | "include_total";

/** A collection query rejected before it was sent. */
export declare class ListQueryError extends ToriiError {
  constructor(parameter: ListQueryParameter, reason: string, options?: { cause?: unknown });
  readonly code: ListQueryErrorCode;
  readonly parameter: ListQueryParameter;
  /** The description without the `invalid \`parameter\`:` prefix. */
  readonly reason: string;
}

/** Syntax error in a text filter (`invalid_filter`) or sort specification (`invalid_sort`). */
export declare class FilterSyntaxError extends ListQueryError {
  constructor(
    parameter: "filter" | "sort",
    reason: string,
    position: { offset: number; line: number; column: number; multiline?: boolean },
  );
  /** 1-based line of the offending token. */
  readonly line: number;
  /** 1-based column (in Unicode scalar values) of the offending token. */
  readonly column: number;
  /** UTF-8 byte offset of the offending token. */
  readonly offset: number;
}

/**
 * A non-success HTTP response. `code`, `errorMessage` and `details` come from
 * Torii's `{"code", "message", "details"}` error envelope; `rejectCode` from
 * `x-iroha-reject-code` (which also becomes `code` when present).
 */
export declare class ToriiHttpError extends ToriiError {
  constructor(details: {
    status: number;
    statusText?: string | null;
    expected?: ReadonlyArray<number>;
    code?: string | null;
    rejectCode?: string | null;
    errorMessage?: string | null;
    bodyText?: string | null;
    bodyJson?: unknown;
    details?: ToriiErrorDetails | null;
  });
  readonly status: number;
  readonly statusText: string | null;
  readonly expected: ReadonlyArray<number>;
  readonly rejectCode: string | null;
  /** The envelope `message`, or a compact rendering of the body. */
  readonly errorMessage: string | null;
  readonly bodyText: string | null;
  readonly bodyJson: unknown;
}

/** Terminal non-replayable loss reported by, or inferred for, a live Torii stream. */
export declare class ToriiStreamGapError extends ToriiError {
  constructor(
    message: string,
    options?: {
      code?: string;
      droppedMessages?: number | null;
      replayAvailable?: boolean;
      payload?: ToriiContractEventStreamErrorPayload | null;
    },
  );
  readonly code: string;
  readonly droppedMessages: number | null;
  readonly replayAvailable: boolean;
  readonly payload: ToriiContractEventStreamErrorPayload | null;
}

// ---------------------------------------------------------------------------
// Collection-query language (`specs/torii/collection_queries.md`)
// ---------------------------------------------------------------------------

/** A JSON value as decoded by the SDK; integers beyond 2^53 are `bigint`. */
export type ToriiJsonValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | ToriiJsonValue[]
  | { [key: string]: ToriiJsonValue };
export type ToriiJsonObject = { [key: string]: ToriiJsonValue };

/** An exact decimal such as `KotodamaQuantity` or `KotodamaDecimal`. */
export interface ExactDecimalLike {
  readonly mantissa: bigint;
  readonly scale: number;
}

/**
 * Values accepted as filter literals. Integers that fit `u64`/`i64` become JSON
 * numbers; decimals are exact decimal strings (`"10.5"`) or `ExactDecimalLike`
 * values. Floating-point numbers are rejected. Arrays and objects are allowed
 * only when comparing `metadata.*` fields.
 */
export type FilterLiteralInput =
  | string
  | number
  | bigint
  | boolean
  | null
  | ExactDecimalLike
  | ReadonlyArray<FilterLiteralInput>
  | { readonly [key: string]: FilterLiteralInput };

/** A literal stored in a filter tree. */
export type FilterLiteral =
  | string
  | number
  | bigint
  | boolean
  | null
  | ReadonlyArray<FilterLiteral>
  | { readonly [key: string]: FilterLiteral };

export type FilterOperator =
  | "and"
  | "or"
  | "not"
  | "eq"
  | "ne"
  | "lt"
  | "lte"
  | "gt"
  | "gte"
  | "in"
  | "nin"
  | "exists"
  | "is_null";

/** Canonical JSON form of a filter (`{"op": ..., "args": [...]}`). */
export type FilterJson =
  | { op: "and" | "or"; args: FilterJson[] }
  | { op: "not"; args: [FilterJson] }
  | { op: "eq" | "ne" | "lt" | "lte" | "gt" | "gte"; args: [string, FilterLiteral] }
  | { op: "in" | "nin"; args: [string, FilterLiteral[]] }
  | { op: "exists" | "is_null"; args: [string] };

/**
 * An immutable filter tree. Build one with `field()`, parse the text form with
 * `Filter.parse()` or decode the JSON form with `Filter.fromJSON()`.
 */
export declare class Filter {
  private constructor();
  readonly op: FilterOperator;
  readonly args: ReadonlyArray<Filter | string | FilterLiteral>;
  /** `this and other and ...`, flattening chains of `and`. */
  and(...others: Filter[]): Filter;
  /** `this or other or ...`, flattening chains of `or`. */
  or(...others: Filter[]): Filter;
  /** `not this` */
  not(): Filter;
  /** Canonical JSON form. */
  toJSON(): FilterJson;
  /** Canonical text form, exactly as Torii renders it. */
  toString(): string;
  /** Check depth, node and membership limits. */
  validate(): this;
  static and(first: Filter, ...rest: Filter[]): Filter;
  static or(first: Filter, ...rest: Filter[]): Filter;
  static not(filter: Filter): Filter;
  /** Parse the text form, e.g. `owned_by = "alice" and quantity >= 10.5`. */
  static parse(text: string): Filter;
  /** Decode the JSON form. */
  static fromJSON(value: FilterJson | Record<string, unknown>): Filter;
}

/** A field awaiting an operator; see `field()`. */
export declare class FieldRef {
  constructor(path: string);
  readonly path: string;
  eq(value: FilterLiteralInput): Filter;
  ne(value: FilterLiteralInput): Filter;
  lt(value: FilterLiteralInput): Filter;
  lte(value: FilterLiteralInput): Filter;
  gt(value: FilterLiteralInput): Filter;
  gte(value: FilterLiteralInput): Filter;
  in(values: Iterable<FilterLiteralInput>): Filter;
  notIn(values: Iterable<FilterLiteralInput>): Filter;
  exists(): Filter;
  isNull(): Filter;
  isNotNull(): Filter;
  asc(): SortKey;
  desc(): SortKey;
}

/** Start a predicate or sort key on a dotted field path such as `metadata.tier`. */
export declare function field(path: string): FieldRef;

/** One sort key: `field` sorts ascending, `-field` descending. */
export declare class SortKey {
  constructor(path: string, descending?: boolean);
  readonly field: string;
  readonly descending: boolean;
  readonly order: "asc" | "desc";
  static asc(path: string): SortKey;
  static desc(path: string): SortKey;
  static parse(text: string): SortKey;
  toString(): string;
  toJSON(): string;
}

/** Parse a sort specification such as `-quantity,id`. */
export declare function parseSort(text: string): SortKey[];
/** Render sort keys as `-quantity,id`. */
export declare function sortToString(keys: ReadonlyArray<SortKey>): string;
/** Render a dotted field path with backtick quoting where the grammar needs it. */
export declare function renderFieldPath(path: string): string;
/** Whether `text` is a canonical decimal literal (`-?(0|[1-9][0-9]*)(\.[0-9]+)?`). */
export declare function isDecimalText(text: unknown): boolean;

export const FILTER_MAX_DEPTH: 10;
export const FILTER_MAX_NODES: 1024;
export const FILTER_MAX_MEMBERSHIP_VALUES: 1024;
export const FILTER_MAX_TOTAL_MEMBERSHIP_VALUES: 4096;
export const FIELD_PATH_MAX_BYTES: 256;
export const FILTER_TEXT_MAX_BYTES: 32768;
export const SORT_MAX_KEYS: 8;
export const SELECT_MAX_FIELDS: 64;
export const CURSOR_MAX_BYTES: 4096;
export const LIST_QUERY_MEMBERS: readonly [
  "filter",
  "sort",
  "select",
  "aggregate",
  "limit",
  "cursor",
  "include_total",
];
export const LIST_QUERY_PARAMETERS: readonly [
  "filter",
  "sort",
  "select",
  "limit",
  "cursor",
  "include_total",
];

export type AggregateFunction = "count" | "sum" | "min" | "max" | "avg" | "distinct_count";
export const AGGREGATE_FUNCTIONS: readonly AggregateFunction[];

export interface AggregateMetricInput {
  /** Output column, also usable in `having` and `sort`. */
  alias: string;
  fn: AggregateFunction;
  /** Field consumed by the function (absent for `count`). */
  field?: string;
}

export interface AggregateInput {
  groupBy?: ReadonlyArray<string>;
  metrics: ReadonlyArray<AggregateMetricInput>;
  having?: Filter | string | FilterJson;
}

/** Controls of one collection read. */
export interface ListQueryInput {
  /** A `Filter`, a text filter (sent as-is) or the JSON form. */
  filter?: Filter | string | FilterJson;
  /** `"-quantity,id"`, an array of keys, or `SortKey`s; at most 8 keys. */
  sort?: string | SortKey | ReadonlyArray<string | SortKey>;
  /** Fields per item (at most 64); cannot be combined with `aggregate`. */
  select?: ReadonlyArray<string>;
  /** Grouped metrics instead of items. */
  aggregate?: AggregateInput;
  /** Rows per page; the server default applies when absent. */
  limit?: number | bigint;
  /** The previous page's `nextCursor`. */
  cursor?: string;
  /** Ask for the exact match count (a full scan). */
  includeTotal?: boolean;
}

/** Canonical JSON body of `POST /v1/<collection>/query`. */
export interface ListQueryBody {
  filter?: string | FilterJson;
  sort?: string[];
  select?: string[];
  aggregate?: {
    group_by?: string[];
    metrics: Array<{ alias: string; fn: AggregateFunction; field?: string }>;
    having?: string | FilterJson;
  };
  limit?: number;
  cursor?: string;
  include_total?: true;
}

/** A validated collection query. */
export declare class ListQuery {
  private constructor();
  readonly filter: Filter | string | undefined;
  readonly sort: ReadonlyArray<SortKey>;
  readonly select: ReadonlyArray<string> | undefined;
  readonly aggregate:
    | {
        readonly groupBy: ReadonlyArray<string>;
        readonly metrics: ReadonlyArray<Readonly<AggregateMetricInput>>;
        readonly having: Filter | string | undefined;
      }
    | undefined;
  readonly limit: number | undefined;
  readonly cursor: string | undefined;
  readonly includeTotal: boolean;
  /** Validate a plain query object (an existing `ListQuery` is returned as-is). */
  static from(input?: ListQueryInput | ListQuery): ListQuery;
  /** Decode a `POST /query` body exactly as Torii does. */
  static fromJSON(body: unknown): ListQuery;
  /** Decode percent-decoded `GET` parameters exactly as Torii does. */
  static fromQueryPairs(pairs: Iterable<readonly [string, string]>): ListQuery;
  /** The same query continued after a page's `nextCursor`. */
  withCursor(cursor: string): ListQuery;
  /** Canonical `POST /query` body. */
  toJSON(): ListQueryBody;
  /** `GET` parameters (not yet percent-encoded) in canonical order. */
  toQueryPairs(): Array<[string, string]>;
}

/** One page of a collection read. */
export interface Page<T> {
  /** Items on this page, in the requested order. */
  readonly items: T[];
  /** Pass as `cursor` to continue; `null` on the last page. */
  readonly nextCursor: string | null;
  /**
   * Exact number of matching rows (a `bigint` beyond `Number.MAX_SAFE_INTEGER`);
   * present only when `includeTotal` was requested.
   */
  readonly total?: number | bigint;
}

/** Decode a `{"items", "next_cursor", "total"}` page envelope. */
export declare function decodePage<T = ToriiJsonValue>(value: unknown, context?: string): Page<T>;

export interface CollectionRequestOptions {
  /** Abort the request (and, for `pages()`/`iterate()`, further paging). */
  signal?: AbortSignal;
}

export interface ToriiCollectionRequestOptions extends CollectionRequestOptions {
  /** Sign with these credentials instead of the client's; `null` sends unsigned. */
  canonicalAuth?: CanonicalRequestAuth | null;
}

export interface ToriiBrowserCollectionRequestOptions extends CollectionRequestOptions {
  headers?: Record<string, string>;
}

/** Top-level member of a selected field path (`alias_binding` for `alias_binding.status`). */
export type SelectedMember<P extends string> = P extends `${infer Head}.${string}` ? Head : P;

/**
 * Item shape of a `select` projection: each selected field at its row path,
 * `null` where a row lacks it. Members reached through a nested path (such
 * as `alias_binding` for `alias_binding.status`) are typed `unknown`.
 */
export type SelectedRow<T, K extends string> = {
  readonly [M in SelectedMember<K>]: M extends K
    ? (M extends keyof T ? Exclude<T[M], undefined> : unknown) | null
    : unknown;
};

/**
 * A Torii collection. `list()` fetches one page, `pages()` iterates pages and
 * `iterate()` every item, following `nextCursor` until it is `null`.
 */
export declare class ToriiCollection<
  T,
  O extends CollectionRequestOptions = CollectionRequestOptions,
> {
  constructor(
    path: string,
    execute: (path: string, query: ListQuery, options?: O) => Promise<Page<unknown>>,
    options?: { history?: boolean },
  );
  /** The collection path, e.g. `/v1/assets/definitions`. */
  readonly path: string;
  /** Whether this is a bounded collection with fixed server ordering (see `ToriiHistoryCollection`). */
  readonly history: boolean;
  list<K extends string>(
    query: ListQueryInput & { select: ReadonlyArray<K>; aggregate?: undefined },
    options?: O,
  ): Promise<Page<SelectedRow<T, K>>>;
  list(
    query: ListQueryInput & { aggregate: AggregateInput },
    options?: O,
  ): Promise<Page<ToriiJsonObject>>;
  list(query?: ListQueryInput | ListQuery, options?: O): Promise<Page<T>>;
  pages<K extends string>(
    query: ListQueryInput & { select: ReadonlyArray<K>; aggregate?: undefined },
    options?: O,
  ): AsyncGenerator<Page<SelectedRow<T, K>>, void, undefined>;
  pages(
    query: ListQueryInput & { aggregate: AggregateInput },
    options?: O,
  ): AsyncGenerator<Page<ToriiJsonObject>, void, undefined>;
  pages(query?: ListQueryInput | ListQuery, options?: O): AsyncGenerator<Page<T>, void, undefined>;
  iterate<K extends string>(
    query: ListQueryInput & { select: ReadonlyArray<K>; aggregate?: undefined },
    options?: O,
  ): AsyncGenerator<SelectedRow<T, K>, void, undefined>;
  iterate(
    query: ListQueryInput & { aggregate: AggregateInput },
    options?: O,
  ): AsyncGenerator<ToriiJsonObject, void, undefined>;
  iterate(query?: ListQueryInput | ListQuery, options?: O): AsyncGenerator<T, void, undefined>;
}

/** Controls of a history collection: no `sort`, `includeTotal` or `aggregate`. */
export type HistoryQueryInput = Omit<ListQueryInput, "sort" | "includeTotal" | "aggregate">;

/**
 * A bounded collection with fixed server ordering. Chain history is newest
 * first by block coordinates; Explorer world rows use their collection key.
 * `sort`, `includeTotal` and `aggregate` are rejected. Each page has a bounded scan budget, so a page may hold fewer
 * than `limit` items, even none, together with a `nextCursor`; `pages()` and
 * `iterate()` keep following it until it is `null`.
 */
export interface ToriiHistoryCollection<
  T,
  O extends CollectionRequestOptions = CollectionRequestOptions,
> {
  readonly path: string;
  readonly history: true;
  list<K extends string>(
    query: HistoryQueryInput & { select: ReadonlyArray<K> },
    options?: O,
  ): Promise<Page<SelectedRow<T, K>>>;
  list(query?: HistoryQueryInput | ListQuery, options?: O): Promise<Page<T>>;
  pages<K extends string>(
    query: HistoryQueryInput & { select: ReadonlyArray<K> },
    options?: O,
  ): AsyncGenerator<Page<SelectedRow<T, K>>, void, undefined>;
  pages(query?: HistoryQueryInput | ListQuery, options?: O): AsyncGenerator<Page<T>, void, undefined>;
  iterate<K extends string>(
    query: HistoryQueryInput & { select: ReadonlyArray<K> },
    options?: O,
  ): AsyncGenerator<SelectedRow<T, K>, void, undefined>;
  iterate(query?: HistoryQueryInput | ListQuery, options?: O): AsyncGenerator<T, void, undefined>;
}

/** Paths of the collections that take no path parameter. */
export const TORII_COLLECTION_PATHS: {
  readonly domains: "/v1/domains";
  readonly accounts: "/v1/accounts";
  readonly assetDefinitions: "/v1/assets/definitions";
  readonly nfts: "/v1/nfts";
  readonly rwas: "/v1/rwas";
  readonly repoAgreements: "/v1/repo/agreements";
  readonly transactions: "/v1/transactions";
  readonly subscriptionPlans: "/v1/subscriptions/plans";
  readonly subscriptions: "/v1/subscriptions";
  readonly contractActivity: "/v1/contracts/activity";
  readonly contractEvents: "/v1/contracts/events";
  readonly explorerAccounts: "/v1/explorer/accounts";
  readonly explorerDomains: "/v1/explorer/domains";
  readonly explorerAssetDefinitions: "/v1/explorer/asset-definitions";
  readonly explorerAssets: "/v1/explorer/assets";
  readonly explorerNfts: "/v1/explorer/nfts";
  readonly explorerRwas: "/v1/explorer/rwas";
  readonly explorerBlocks: "/v1/explorer/blocks";
  readonly explorerTransactions: "/v1/explorer/transactions";
  readonly explorerLatestTransactions: "/v1/explorer/transactions/latest";
  readonly explorerInstructions: "/v1/explorer/instructions";
  readonly explorerLatestInstructions: "/v1/explorer/instructions/latest";
};

/**
 * Rows may gain fields, typed `unknown`. Only the fields that identify a row
 * are always present; every other field may be `null` or absent.
 */
export interface ToriiCollectionRowExtras {
  readonly [field: string]: unknown;
}

/** `/v1/domains` row. */
/** Flat subscription-plan row returned by the collection endpoint. */
export interface ToriiSubscriptionPlanRow extends ToriiCollectionRowExtras {
  id: string;
  provider: string;
  billing: JsonValue;
  pricing: JsonValue;
}

/** Flat subscription-state row returned by the collection endpoint. */
export interface ToriiSubscriptionRow extends ToriiCollectionRowExtras {
  id: string;
  owned_by: string;
  status: SubscriptionStatus;
  invoice: JsonValue | null;
  plan: JsonValue | null;
}

export interface ToriiDomainRow extends ToriiCollectionRowExtras {
  readonly id: string;
  readonly owned_by?: string | null;
  readonly logo?: string | null;
  readonly metadata?: ToriiJsonObject | null;
}

/** `/v1/accounts` row. */
export interface ToriiAccountRow extends ToriiCollectionRowExtras {
  readonly id: string;
  readonly label?: string | null;
  readonly uaid?: string | null;
  readonly metadata?: ToriiJsonObject | null;
}

/** `/v1/assets/definitions` row: the complete definition record. */
export interface ToriiAssetDefinitionRow extends ToriiCollectionRowExtras {
  readonly id: string;
  readonly name?: string | null;
  readonly alias?: string | null;
  readonly owned_by?: string | null;
  readonly owning_domain?: string | null;
  readonly mintable?: string | null;
  readonly description?: string | null;
  readonly logo?: string | null;
  readonly spec?: ToriiJsonValue;
  readonly balance_scope_policy?: ToriiJsonValue;
  /** Present when an alias is bound. */
  readonly alias_binding?: ToriiAssetDefinitionAliasBinding | null;
  readonly metadata?: ToriiJsonObject | null;
}

/** `/v1/nfts` row; `metadata` is the NFT content. */
export interface ToriiNftRow extends ToriiCollectionRowExtras {
  readonly id: string;
  readonly owned_by?: string | null;
  readonly metadata?: ToriiJsonObject | null;
}

/** `/v1/rwas` row. Quantities are exact decimal strings. */
export interface ToriiRwaRow extends ToriiCollectionRowExtras {
  readonly id: string;
  readonly owned_by?: string | null;
  readonly primary_reference?: string | null;
  readonly status?: string | null;
  readonly quantity?: string | null;
  readonly is_frozen?: boolean | null;
  readonly metadata?: ToriiJsonObject | null;
}

/** `/v1/accounts/{account_id}/assets` row. */
export interface ToriiAccountAssetRow extends ToriiCollectionRowExtras {
  readonly account_id: string;
  /** Asset definition id. */
  readonly asset: string;
  readonly scope: string;
  /** Exact decimal string. */
  readonly quantity: string;
  readonly asset_name?: string | null;
  readonly asset_alias?: string | null;
}

/** `/v1/assets/{definition_id}/holders` row. */
export interface ToriiAssetHolderRow extends ToriiCollectionRowExtras {
  readonly account_id: string;
  readonly asset: string;
  readonly scope: string;
  /** Exact decimal string. */
  readonly quantity: string;
  readonly asset_alias?: string | null;
}

/**
 * `/v1/transactions` and `/v1/accounts/{account_id}/transactions` row. Rows
 * come newest first by (`block_height`, `block_index`). Filters on the list
 * fields match element-wise: `asset_ids = "..."` and `in` select rows where
 * any element matches; `!=` and `not in` select rows where none does.
 */
export interface ToriiTransactionRow extends ToriiCollectionRowExtras {
  readonly entrypoint_hash: string;
  readonly block_height: ToriiU64;
  /** Position of the transaction within its block. */
  readonly block_index: ToriiU64;
  readonly block_hash?: string | null;
  readonly authority?: string | null;
  readonly timestamp_ms?: ToriiU64 | null;
  readonly entrypoint_kind?: string | null;
  readonly result_ok?: boolean | null;
  readonly asset_ids?: ReadonlyArray<string> | null;
  readonly asset_definition_ids?: ReadonlyArray<string> | null;
  readonly metadata?: ToriiJsonObject | null;
}

/** One leg of a repo agreement row. */
export interface ToriiRepoLegRow extends ToriiCollectionRowExtras {
  readonly asset_definition_id?: string | null;
  /** Exact decimal string. */
  readonly quantity?: string | null;
}

/** `/v1/repo/agreements` row. */
export interface ToriiRepoAgreementRow extends ToriiCollectionRowExtras {
  readonly id: string;
  readonly initiator?: string | null;
  readonly counterparty?: string | null;
  readonly custodian?: string | null;
  readonly status?: string | null;
  readonly cash_source?: string | null;
  readonly cash_leg?: ToriiRepoLegRow | null;
  readonly collateral_leg?: ToriiRepoLegRow | null;
  readonly collateral_custody_asset?: string | null;
  readonly rate_bps?: number | null;
  readonly maturity_timestamp_ms?: ToriiU64 | null;
  readonly initiated_timestamp_ms?: ToriiU64 | null;
  readonly last_margin_check_timestamp_ms?: ToriiU64 | null;
  readonly settlement_timestamp_ms?: ToriiU64 | null;
  readonly governance?: {
    readonly haircut_bps?: number | null;
    readonly margin_frequency_secs?: ToriiU64 | null;
  } | null;
}

/** Event-stream options: `filter` uses the collection-query text grammar over event fields. */
export interface EventStreamOptions {
  filter?: Filter | string | FilterJson;
  signal?: AbortSignal;
}

export declare class TransactionStatusError extends Error {
  constructor(
    hashHex: string,
    status: string | null,
    payload: ToriiPipelineTransactionStatus | null,
  );
  readonly hashHex: string;
  readonly status: string | null;
  readonly payload: ToriiPipelineTransactionStatus | null;
}

export declare class TransactionTimeoutError extends Error {
  constructor(
    message: string,
    hashHex: string,
    attempts: number,
    payload: ToriiPipelineTransactionStatus | null,
  );
  readonly hashHex: string;
  readonly attempts: number;
  readonly payload: ToriiPipelineTransactionStatus | null;
}

export declare class TransactionBatchAdmissionAmbiguousError extends Error {
  constructor(
    message: string,
    expectedCount: number,
    acceptedCount?: number | null,
    cause?: unknown,
  );
  readonly expectedCount: number;
  readonly acceptedCount: number | null;
  readonly ambiguous: true;
  readonly retryable: false;
  readonly cause?: unknown;
}

export declare class IsoMessageTimeoutError extends Error {
  constructor(
    messageId: string,
    attempts: number,
    lastStatus: IsoMessageStatusResponse | null,
  );
  readonly messageId: string;
  readonly attempts: number;
  readonly lastStatus: IsoMessageStatusResponse | null;
}

export declare function extractPipelineStatusKind(
  payload: unknown,
): string | null;
export declare function decodePdpCommitmentHeader(
  headers?:
    | Headers
    | Map<string, string>
    | Record<string, string | undefined | null>
    | null,
): Uint8Array | null;
export declare function buildConnectWebSocketUrl(
  baseUrl: string,
  options: ConnectWebSocketParams,
): string;
export declare function buildSorafsOrderbookEventsWebSocketUrl(
  baseUrl: string,
  options?: SorafsOrderbookEventsWebSocketParams,
): string;

export declare function openConnectWebSocket<T = unknown>(
  options: ConnectWebSocketDialOptions<T>,
): T;
export declare function openSorafsOrderbookEventsWebSocket<T = unknown>(
  options: SorafsOrderbookEventsWebSocketDialOptions<T>,
): T;

export interface InstructionBuilders {
  Mint: {
    Asset: {
      object: string;
      destination: string;
    };
  };
  Burn: {
    Asset: {
      object: string;
      destination: string;
    };
  };
}

export interface ToriiBrowserClientOptions {
  fetchImpl?: typeof fetch;
  /** Caller-selected I105 prefix, required for instruction/signed transaction operations. */
  networkPrefix?: number;
  /** Explicit local-development opt-in for credential headers over HTTP. */
  allowInsecure?: boolean;
  /** Exact genesis-derived network identity required by canonical-auth methods. */
  networkId?: NetworkId;
  /**
   * Immutable default identity for scoped ledger browser GETs, including
   * optional-auth dataspace reads and the global-reader Explorer metrics route.
   * The callback signs the final pathname and wire query for each request.
   */
  canonicalRequestAuth?: ToriiBrowserCanonicalRequestAuth;
  /** Immutable exact-network signer required by operator-only browser reads. */
  operatorSigningContext?: OperatorSigningContext;
  defaultHeaders?: Record<string, string>;
  timeoutMs?: NumericLike;
}

export interface ToriiBrowserRequestOptions {
  signal?: AbortSignal;
  headers?: Record<string, string>;
}

export interface ToriiLedgerHeadersOptions {
  from?: number | string | bigint;
  limit?: number | string | bigint;
  signal?: AbortSignal;
}

export interface ToriiBrowserTransactionStatusOptions {
  signal?: AbortSignal;
  headers?: Record<string, string>;
  scope?: "local" | "global";
}

export interface ToriiBrowserTransactionStatusPollOptions {
  signal?: AbortSignal;
  headers?: Record<string, string>;
  intervalMs?: number;
  timeoutMs?: number;
  maxAttempts?: number;
}

export interface ToriiBrowserSubmitTransactionAndWaitOptions
  extends ToriiBrowserTransactionStatusPollOptions {
  hashHex?: string;
}

export interface ToriiBrowserNodeCapabilities {
  abi_version: number;
  data_model_version: number;
  signed_transaction_schema_hash_hex: string;
  crypto?: Record<string, unknown>;
  query?: Record<string, unknown>;
}

export interface ToriiBrowserContractDeploymentStateRequest {
  authority: string;
  contract_alias: string;
}

export interface ToriiBrowserContractDeploymentStateResponse {
  authority: string;
  contract_alias: string;
  deploy_nonce: string;
  dataspace_alias: string;
  dataspace_id: string;
  previous_contract_address: string | null;
  observed_block_height: string;
  observed_block_hash: string;
  ledger_time_ms: string;
  chain_discriminant: string;
}

export interface CanonicalJsonRequestSignerInput {
  message: Buffer;
  networkId: NetworkId;
  messageBase64: string;
  method: string;
  path: string;
  query?: string | URLSearchParams;
  body: string;
  timestampMs: number;
  nonce: string;
}
export type CanonicalJsonRequestSignature =
  | Buffer
  | Uint8Array
  | ArrayBuffer
  | ArrayBufferView
  | string;

/** Browser-keystore identity used for optional canonical Torii reads. */
export interface ToriiBrowserCanonicalRequestAuth {
  /** Exact canonical I105 account or canonical ASCII account alias. */
  readonly accountId: string;
  /** Sign one freshly constructed exact-network canonical request message. */
  readonly sign: (
    input: CanonicalJsonRequestSignerInput,
  ) => CanonicalJsonRequestSignature | Promise<CanonicalJsonRequestSignature>;
}

export interface ToriiBrowserContractDeploymentStateOptions
  extends ToriiBrowserRequestOptions {
  authAccountId?: string;
  sign?: (
    input: CanonicalJsonRequestSignerInput,
  ) => CanonicalJsonRequestSignature | Promise<CanonicalJsonRequestSignature>;
  timestampMs?: number;
  nonce?: string;
}

export interface ToriiBrowserCanonicalRequestOptions
  extends ToriiBrowserRequestOptions {
  authAccountId: string;
  sign: (
    input: CanonicalJsonRequestSignerInput,
  ) => CanonicalJsonRequestSignature | Promise<CanonicalJsonRequestSignature>;
  timestampMs?: number;
  nonce?: string;
}

export declare class ToriiBrowserClient {
  readonly baseUrl: string;
  readonly networkId: NetworkId | null;
  constructor(baseUrl: string | URL, options?: ToriiBrowserClientOptions);
  /** Domains (`POST /v1/domains/query`). */
  readonly domains: ToriiCollection<ToriiDomainRow, ToriiBrowserCollectionRequestOptions>;
  /** Accounts (`POST /v1/accounts/query`). */
  readonly accounts: ToriiCollection<ToriiAccountRow, ToriiBrowserCollectionRequestOptions>;
  /** Asset definitions (`POST /v1/assets/definitions/query`). */
  readonly assetDefinitions: ToriiCollection<ToriiAssetDefinitionRow, ToriiBrowserCollectionRequestOptions>;
  /** NFTs (`POST /v1/nfts/query`). */
  readonly nfts: ToriiCollection<ToriiNftRow, ToriiBrowserCollectionRequestOptions>;
  /** RWA lots (`POST /v1/rwas/query`). */
  readonly rwas: ToriiCollection<ToriiRwaRow, ToriiBrowserCollectionRequestOptions>;
  /** Repo agreements (`POST /v1/repo/agreements/query`). */
  readonly repoAgreements: ToriiCollection<ToriiRepoAgreementRow, ToriiBrowserCollectionRequestOptions>;
  /** Plans and subscriptions use the same query controls and cursor envelope. */
  readonly subscriptionPlans: ToriiCollection<ToriiSubscriptionPlanRow, ToriiBrowserCollectionRequestOptions>;
  readonly subscriptions: ToriiCollection<ToriiSubscriptionRow, ToriiBrowserCollectionRequestOptions>;
  accountHistory(accountId: string): ToriiHistoryCollection<ToriiAccountHistoryItem, ToriiBrowserCollectionRequestOptions>;
  accountPermissions(accountId: string): ToriiCollection<ToriiAccountPermissionItem, ToriiBrowserCollectionRequestOptions>;
  uaidManifests(uaid: string): ToriiCollection<UaidManifestRecord, ToriiBrowserCollectionRequestOptions>;
  readonly explorerAccounts: ToriiHistoryCollection<ToriiJsonObject, ToriiBrowserCollectionRequestOptions>;
  readonly explorerDomains: ToriiHistoryCollection<ToriiJsonObject, ToriiBrowserCollectionRequestOptions>;
  readonly explorerAssetDefinitions: ToriiHistoryCollection<ToriiJsonObject, ToriiBrowserCollectionRequestOptions>;
  readonly explorerAssets: ToriiHistoryCollection<ToriiJsonObject, ToriiBrowserCollectionRequestOptions>;
  readonly explorerNfts: ToriiHistoryCollection<ToriiJsonObject, ToriiBrowserCollectionRequestOptions>;
  readonly explorerRwas: ToriiHistoryCollection<ToriiJsonObject, ToriiBrowserCollectionRequestOptions>;
  readonly explorerBlocks: ToriiHistoryCollection<ToriiJsonObject, ToriiBrowserCollectionRequestOptions>;
  readonly explorerTransactions: ToriiHistoryCollection<ToriiJsonObject, ToriiBrowserCollectionRequestOptions>;
  readonly explorerLatestTransactions: ToriiHistoryCollection<ToriiJsonObject, ToriiBrowserCollectionRequestOptions>;
  readonly explorerInstructions: ToriiHistoryCollection<ToriiJsonObject, ToriiBrowserCollectionRequestOptions>;
  readonly explorerLatestInstructions: ToriiHistoryCollection<ToriiJsonObject, ToriiBrowserCollectionRequestOptions>;
  readonly contractActivity: ToriiHistoryCollection<ToriiContractActivityItem, ToriiBrowserCollectionRequestOptions>;
  readonly contractEvents: ToriiHistoryCollection<ToriiContractEventItem, ToriiBrowserCollectionRequestOptions>;
  /** Asset balances of one account (`POST /v1/accounts/{account_id}/assets/query`). */
  accountAssets(accountId: string): ToriiCollection<ToriiAccountAssetRow, ToriiBrowserCollectionRequestOptions>;
  /** Holders of one asset definition (`POST /v1/assets/{definition_id}/holders/query`). */
  assetHolders(assetDefinitionId: string): ToriiCollection<ToriiAssetHolderRow, ToriiBrowserCollectionRequestOptions>;
  /** Committed transactions, newest first (`POST /v1/transactions/query`). */
  readonly transactions: ToriiHistoryCollection<ToriiTransactionRow, ToriiBrowserCollectionRequestOptions>;
  /** Transactions of one account, newest first (`POST /v1/accounts/{account_id}/transactions/query`). */
  accountTransactions(accountId: string): ToriiHistoryCollection<ToriiTransactionRow, ToriiBrowserCollectionRequestOptions>;
  submitTransaction(
    signedTransaction: ArrayBufferView | ArrayBuffer | Buffer,
    options?: ToriiBrowserRequestOptions,
  ): Promise<unknown | null>;
  getTransactionStatus(
    hashHex: string,
    options?: ToriiBrowserTransactionStatusOptions,
  ): Promise<ToriiPipelineTransactionStatus | null>;
  waitForTransactionStatus(
    hashHex: string,
    options?: ToriiBrowserTransactionStatusPollOptions,
  ): Promise<ToriiAppliedTransactionStatus>;
  /** Submit and wait; the transaction hash is derived from the signed bytes. */
  submitTransactionAndWait(
    signedTransaction: ArrayBufferView | ArrayBuffer | Buffer,
    options?: ToriiBrowserSubmitTransactionAndWaitOptions,
  ): Promise<ToriiAppliedTransactionStatus>;
  /** Public capability advert (`GET /v1/node/capabilities`); no credentials are sent. */
  getNodeCapabilities(options?: { signal?: AbortSignal }): Promise<ToriiBrowserNodeCapabilities>;
  getAccountCapabilities(options?: { signal?: AbortSignal }): Promise<AccountCapabilitiesV1>;
  getContractDeploymentState(
    request: ToriiBrowserContractDeploymentStateRequest,
    options?: ToriiBrowserContractDeploymentStateOptions,
  ): Promise<ToriiBrowserContractDeploymentStateResponse>;
  resolveContractAlias(
    contractAlias: string,
    options: ToriiBrowserCanonicalRequestOptions,
  ): Promise<unknown>;
  getAccount(
    accountId: string,
    options?: ToriiBrowserRequestOptions,
  ): Promise<unknown>;
  getExplorerAccount(
    accountId: string,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  getExplorerDomain(
    domainId: string,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  getExplorerAsset(
    assetId: string,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  /** List effective direct and role-inherited permissions for an account. */
  streamContractEvents<T = ToriiContractEventItem>(
    options?: ToriiBrowserContractEventStreamOptions,
  ): AsyncGenerator<ToriiSseEvent<T>, void, unknown>;
  /**
   * Stream `/v1/events/sse`; `options.filter` uses the collection-query text
   * grammar over event fields. A `stream_error` event raises `ToriiStreamGapError`.
   */
  streamEvents<T = ToriiEventPayload>(
    options?: EventStreamOptions,
  ): AsyncGenerator<ToriiEventFrame<T>, void, unknown>;
  getAssetDefinition(
    assetDefinitionId: string,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  resolveAlias(
    aliasOrRequest: string | Record<string, unknown>,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  resolveAssetAlias(
    aliasOrRequest: string | Record<string, unknown>,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  getExplorerAssetDefinitionEconometrics(
    assetDefinitionId: string,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  getExplorerAssetDefinitionSnapshot(
    assetDefinitionId: string,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  getExplorerNft(
    nftId: string,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  getExplorerRwa(
    rwaId: string,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  getExplorerBlock(
    identifier: string | number | bigint,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  listLedgerHeaders(options?: ToriiLedgerHeadersOptions): Promise<unknown>;
  getLedgerStateRoot(
    height: number | string | bigint,
    options?: { signal?: AbortSignal },
  ): Promise<unknown>;
  getLedgerStateProof(
    height: number | string | bigint,
    options?: { signal?: AbortSignal },
  ): Promise<unknown>;
  /** Exact canonical result-bearing SignedBlockWire at a finalized height. */
  getLedgerExecutedBlockWire(
    height: number | string | bigint,
    options?: { signal?: AbortSignal },
  ): Promise<Buffer>;
  getLedgerBlockProof(
    height: number | string | bigint,
    entryHash: string,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiBlockProofs>;
  getExplorerMetrics(options?: Record<string, unknown>): Promise<unknown>;
  getExplorerHealth(options?: Record<string, unknown>): Promise<unknown>;
  getExplorerTransaction(
    hash: string,
    options?: Record<string, unknown>,
  ): Promise<ToriiBrowserExplorerTransactionDetail>;
  getExplorerInstruction(
    transactionHash: string,
    index: number,
    options?: Record<string, unknown>,
  ): Promise<ToriiBrowserExplorerInstruction>;
  getExplorerInstructionContractView(
    transactionHash: string,
    index: number,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  getMultisigSpec(
    selector: MultisigAccountSelector,
    options: ToriiBrowserCanonicalRequestOptions,
  ): Promise<MultisigSpecResponse>;
  queryMultisigProposals(
    selector: MultisigProposalsQueryRequest,
    options: ToriiBrowserCanonicalRequestOptions,
  ): Promise<MultisigProposalsQueryResponse>;
  resolveMultisigProposal(
    request: MultisigProposalsResolveRequest,
    options: ToriiBrowserCanonicalRequestOptions,
  ): Promise<MultisigProposalResolveResponse>;
  submitMultisigPropose(
    request: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  submitMultisigContractCallPropose(
    request: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  submitMultisigContractCallApprove(
    request: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  getSumeragiStatus(options?: Record<string, unknown>): Promise<Record<string, unknown>>;
  getSumeragiStatusTyped(options?: { signal?: AbortSignal }): Promise<ToriiSumeragiStatus>;
  getSumeragiLanes(options?: { signal?: AbortSignal }): Promise<ReadonlyArray<ToriiSumeragiLaneStatus>>;
  listKaigiRelays(options?: { signal?: AbortSignal }): Promise<KaigiRelaySummaryList>;
  getKaigiRelay(
    relayId: string,
    options?: { signal?: AbortSignal },
  ): Promise<KaigiRelayDetail | null>;
  getKaigiRelaysHealth(
    options?: { signal?: AbortSignal },
  ): Promise<KaigiRelayHealthSnapshot>;
}

export interface ValidationFeeCheckpointV1 {
  /** Complete canonical native checkpoint selected independently of the response. */
  readonly checkpointNorito: ArrayBuffer | ArrayBufferView;
}

export interface ValidationFeeLedgerBindingV1 {
  readonly schema: "iroha.validation-fee-ledger-binding.v1";
  readonly networkId: NetworkId;
  readonly policyChainGenesisHash: string;
  readonly checkpoint: ValidationFeeCheckpointV1;
}

export interface NormalizedValidationFeeCheckpointV1 {
  /** Returns a copy of the privately retained complete canonical checkpoint bytes. */
  readonly checkpointNorito: Buffer;
}

export interface NormalizedValidationFeeLedgerBindingV1 {
  readonly schema: "iroha.validation-fee-ledger-binding.v1";
  readonly networkId: NetworkId;
  readonly policyChainGenesisHash: string;
  readonly checkpoint: NormalizedValidationFeeCheckpointV1;
}

export interface ValidationFeeVerifiedParliamentProposalV1 {
  readonly proposal_kind:
    | "ValidationFeePolicyV1"
    | "ValidationFeePayoutLifecycleV1";
  readonly proposal_operator: string;
  readonly proposal_id: string;
  readonly payload_hash: string;
  readonly governance_certificate_id: string;
  readonly governance_certificate: Readonly<Record<string, unknown>>;
  readonly certified_at_height: string;
  readonly enacted_at_height: string;
}

export interface ValidationFeeVerifiedCurrentPolicyV1 {
  readonly activePolicyVersion: string;
  readonly activePolicyHash: string;
  readonly feeAssetDefinitionId: string;
  readonly feeScale: 2;
  readonly feeMinorUnits: string;
  readonly chargingMode: "RETAIL_MONTHLY_ALLOWANCE";
  readonly effective_from_ms: number | string | bigint;
  readonly notice_published_at_ms: number | string | bigint;
  readonly retail_schedule: RetailFeeScheduleV1;
  readonly effectiveFromHeight: string;
  readonly parliament: Readonly<ValidationFeeVerifiedParliamentProposalV1>;
  readonly reward_custody: Readonly<ValidationFeeRewardCustodyV1>;
}

export interface ValidationFeeVerifiedPolicyProjectionV1 {
  readonly schema: "iroha.validation_fee.verified_policy_projection.v1";
  readonly version: 1;
  readonly network_id: string;
  readonly policy_chain_genesis_hash: string;
  readonly registry_hash: string;
  readonly head_policy_version: bigint;
  readonly head_policy_hash: string;
  readonly current_policy: Readonly<ValidationFeeVerifiedCurrentPolicyV1> | null;
  readonly conversion_policy: Readonly<ValidationFeeVerifiedConversionPolicyV1> | null;
  readonly trusted_checkpoint_height: bigint;
  readonly trusted_checkpoint_context_id: string;
  readonly evaluated_block_height: bigint;
  readonly evaluated_context_id: string;
  readonly evaluated_block_hash: string;
  readonly observed_ledger_tip_height: bigint;
  readonly more_available: boolean;
}

export interface ValidationFeeVerifiedPageV1 {
  readonly projection: ValidationFeeVerifiedPolicyProjectionV1;
  readonly promotedCheckpoint: NormalizedValidationFeeCheckpointV1;
}

export interface ValidationFeeCurrentPolicyProofPageV1 extends ValidationFeeVerifiedPageV1 {
  readonly proofNorito: Buffer;
}



export interface ValidationFeePolicyProofCatchUpV1
  extends ValidationFeeCurrentPolicyProofPageV1 {
  readonly binding: NormalizedValidationFeeLedgerBindingV1;
  readonly pagesVerified: number;
}

export declare class ToriiClient {
  constructor(baseUrl: string, options?: ToriiClientOptions);
  /** Domains (`POST /v1/domains/query`). */
  readonly domains: ToriiCollection<ToriiDomainRow, ToriiCollectionRequestOptions>;
  /** Accounts (`POST /v1/accounts/query`). */
  readonly accounts: ToriiCollection<ToriiAccountRow, ToriiCollectionRequestOptions>;
  /** Asset definitions (`POST /v1/assets/definitions/query`). */
  readonly assetDefinitions: ToriiCollection<ToriiAssetDefinitionRow, ToriiCollectionRequestOptions>;
  /** NFTs (`POST /v1/nfts/query`). */
  readonly nfts: ToriiCollection<ToriiNftRow, ToriiCollectionRequestOptions>;
  /** RWA lots (`POST /v1/rwas/query`). */
  readonly rwas: ToriiCollection<ToriiRwaRow, ToriiCollectionRequestOptions>;
  /** Repo agreements (`POST /v1/repo/agreements/query`). */
  readonly repoAgreements: ToriiCollection<ToriiRepoAgreementRow, ToriiCollectionRequestOptions>;
  /** Plans and subscriptions use the same query controls and cursor envelope. */
  readonly subscriptionPlans: ToriiCollection<ToriiSubscriptionPlanRow, ToriiCollectionRequestOptions>;
  readonly subscriptions: ToriiCollection<ToriiSubscriptionRow, ToriiCollectionRequestOptions>;
  accountHistory(accountId: string): ToriiHistoryCollection<ToriiAccountHistoryItem, ToriiCollectionRequestOptions>;
  accountPermissions(accountId: string): ToriiCollection<ToriiAccountPermissionItem, ToriiCollectionRequestOptions>;
  uaidManifests(uaid: string): ToriiCollection<UaidManifestRecord, ToriiCollectionRequestOptions>;
  readonly explorerAccounts: ToriiHistoryCollection<ToriiJsonObject, ToriiCollectionRequestOptions>;
  readonly explorerDomains: ToriiHistoryCollection<ToriiJsonObject, ToriiCollectionRequestOptions>;
  readonly explorerAssetDefinitions: ToriiHistoryCollection<ToriiJsonObject, ToriiCollectionRequestOptions>;
  readonly explorerAssets: ToriiHistoryCollection<ToriiJsonObject, ToriiCollectionRequestOptions>;
  readonly explorerNfts: ToriiHistoryCollection<ToriiJsonObject, ToriiCollectionRequestOptions>;
  readonly explorerRwas: ToriiHistoryCollection<ToriiJsonObject, ToriiCollectionRequestOptions>;
  readonly explorerBlocks: ToriiHistoryCollection<ToriiJsonObject, ToriiCollectionRequestOptions>;
  readonly explorerTransactions: ToriiHistoryCollection<ToriiJsonObject, ToriiCollectionRequestOptions>;
  readonly explorerLatestTransactions: ToriiHistoryCollection<ToriiJsonObject, ToriiCollectionRequestOptions>;
  readonly explorerInstructions: ToriiHistoryCollection<ToriiJsonObject, ToriiCollectionRequestOptions>;
  readonly explorerLatestInstructions: ToriiHistoryCollection<ToriiJsonObject, ToriiCollectionRequestOptions>;
  readonly contractActivity: ToriiHistoryCollection<ToriiContractActivityItem, ToriiCollectionRequestOptions>;
  readonly contractEvents: ToriiHistoryCollection<ToriiContractEventItem, ToriiCollectionRequestOptions>;
  /** Asset balances of one account (`POST /v1/accounts/{account_id}/assets/query`). */
  accountAssets(accountId: string): ToriiCollection<ToriiAccountAssetRow, ToriiCollectionRequestOptions>;
  /** Holders of one asset definition (`POST /v1/assets/{definition_id}/holders/query`). */
  assetHolders(assetDefinitionId: string): ToriiCollection<ToriiAssetHolderRow, ToriiCollectionRequestOptions>;
  /** Committed transactions, newest first (`POST /v1/transactions/query`). */
  readonly transactions: ToriiHistoryCollection<ToriiTransactionRow, ToriiCollectionRequestOptions>;
  /** Transactions of one account, newest first (`POST /v1/accounts/{account_id}/transactions/query`). */
  accountTransactions(accountId: string): ToriiHistoryCollection<ToriiTransactionRow, ToriiCollectionRequestOptions>;
  getAccountCapabilities(options?: { signal?: AbortSignal }): Promise<AccountCapabilitiesV1>;
  getExplorerRwaDetail<T = ToriiExplorerRwa>(
    rwaId: string,
    options?: { signal?: AbortSignal },
  ): Promise<T | null>;
  uploadAttachment(
    data: ArrayBufferView | ArrayBuffer | string,
    options: { contentType: string; signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<ToriiAttachmentMetadata>;
  listAttachments(options: {
    signal?: AbortSignal;
    canonicalAuth: CanonicalRequestAuth;
  }): Promise<ReadonlyArray<ToriiAttachmentMetadata>>;
  getAttachment(
    attachmentId: string,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<{ data: Buffer; contentType: string | null }>;
  deleteAttachment(
    attachmentId: string,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<void>;
  listVerifyingKeys(
    options?: ToriiVerifyingKeyListOptions,
  ): Promise<ReadonlyArray<ToriiVerifyingKeyListItem>>;
  iterateVerifyingKeys(
    options?: ToriiVerifyingKeyListOptions & PaginationIteratorOptions,
  ): AsyncGenerator<ToriiVerifyingKeyListItem, void, unknown>;
  getVerifyingKey(
    backend: ToriiVerifierBackendLabelV1,
    name: string,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiVerifyingKeyDetail>;
  registerVerifyingKey(
    payload: ToriiVerifyingKeyRegisterPayload,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiVerifyingKeyTransactionDraft>;
  updateVerifyingKey(
    payload: ToriiVerifyingKeyUpdatePayload,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiVerifyingKeyTransactionDraft>;
  resolveAlias(
    alias: string,
    options?: CanonicalRequestOptions,
  ): Promise<AliasResolutionDto | null>;
  resolveAliasByIndex(
    index: number | string | bigint,
    options?: CanonicalRequestOptions,
  ): Promise<AliasResolutionDto | null>;
  lookupAliasesByAccount(
    accountId: string,
    options?: AliasLookupByAccountOptions,
  ): Promise<AliasLookupByAccountResponse | null>;
  lookupRetailRecipient(
    request: RetailRecipientLookupRequest,
    options?: CanonicalRequestOptions,
  ): Promise<RetailRecipientLookupResponse>;
  routeRetailRecipient(
    accountId: string,
    options?: CanonicalRequestOptions,
  ): Promise<RetailRecipientRouteResponse>;
  findFeeSponsorProgramById(
    programId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<FeeSponsorProgram | null>;
  preparePublicLanePlan(request: StakingPreparationRequestV1, xorAssetDefinitionId: string, options?: { signal?: AbortSignal }): Promise<StakingPreparationV1>;
  quoteFees(
    payload: Record<string, unknown> | TransactionPayloadDraftResult,
    options: RequiredCanonicalRequestOptions,
  ): Promise<FeeQuoteResponse>;
  getValidationFeeCurrentPolicyProofPage(
    binding: ValidationFeeLedgerBindingV1,
    checkpoint: ValidationFeeCheckpointV1 | null,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ValidationFeeCurrentPolicyProofPageV1>;
  catchUpValidationFeeCurrentPolicyProof(
    binding: ValidationFeeLedgerBindingV1,
    options: {
      checkpoint?: ValidationFeeCheckpointV1;
      maxPages?: number;
      signal?: AbortSignal;
      canonicalAuth: CanonicalRequestAuth;
    },
  ): Promise<ValidationFeePolicyProofCatchUpV1>;
  listIdentifierPolicies(options?: {
    signal?: AbortSignal;
  }): Promise<IdentifierPolicyListResponse>;
  resolveIdentifier(
    options: IdentifierResolutionRequestOptions,
  ): Promise<IdentifierResolutionReceipt | null>;
  listRamLfeProgramPolicies(options?: {
    signal?: AbortSignal;
  }): Promise<RamLfeProgramPolicyListResponse>;
  executeRamLfeProgram(
    programId: string,
    options: RamLfeExecuteOptions,
  ): Promise<RamLfeExecuteResponse | null>;
  getIdentifierClaimByReceiptHash(
    receiptHash: string,
    options?: { signal?: AbortSignal },
  ): Promise<IdentifierClaimLookupResponse | null>;
  issueIdentifierClaimReceipt(
    accountId: string,
    options: IdentifierResolutionRequestOptions,
  ): Promise<IdentifierResolutionReceipt | null>;
  verifyRamLfeReceipt(options: {
    receipt: Record<string, unknown>;
    outputHex?: string;
    signal?: AbortSignal;
    canonicalAuth: CanonicalRequestAuth;
  }): Promise<Record<string, unknown>>;
  listSorafsPinManifests(
    options?: SorafsPinListOptions,
  ): Promise<SorafsPinListResponse>;
  iterateSorafsPinManifests(
    options?: SorafsPinIteratorOptions,
  ): AsyncGenerator<SorafsPinManifestSummaryV1, void, unknown>;
  listSorafsAliases(
    options: SorafsAliasListOptions,
  ): Promise<SorafsAliasListResponse>;
  iterateSorafsAliases(
    options: SorafsAliasListOptions & PaginationIteratorOptions,
  ): AsyncGenerator<SorafsAliasRecord, void, unknown>;
  listSorafsReplicationOrders(
    options: SorafsReplicationListOptions,
  ): Promise<SorafsReplicationListResponse>;
  iterateSorafsReplicationOrders(
    options: SorafsReplicationListOptions & PaginationIteratorOptions,
  ): AsyncGenerator<SorafsReplicationOrderRecord, void, unknown>;
  submitSorafsOrderbookOrder(
    signedTransaction: SorafsOrderbookSignedTransaction,
    options: SorafsOrderbookTransactionSubmitOptions,
  ): Promise<SorafsOrderbookSubmissionReceipt>;
  submitSorafsOrderbookCancel(
    signedTransaction: SorafsOrderbookSignedTransaction,
    options: SorafsOrderbookTransactionSubmitOptions,
  ): Promise<SorafsOrderbookSubmissionReceipt>;
  submitSorafsOrderbookReceipt(
    signedTransaction: SorafsOrderbookSignedTransaction,
    options: SorafsOrderbookTransactionSubmitOptions,
  ): Promise<SorafsOrderbookSubmissionReceipt>;
  getSorafsOrderbook(
    options?: SorafsOrderbookReadOptions,
  ): Promise<SorafsOrderbookBookResponse>;
  listSorafsOrderbookTrades(
    options?: SorafsOrderbookReadOptions,
  ): Promise<SorafsOrderbookTradesResponse>;
  listSorafsOrderbookChannels(
    options?: SorafsOrderbookReadOptions,
  ): Promise<SorafsOrderbookChannelsResponse>;
  listSorafsOrderbookReceipts(
    options?: SorafsOrderbookReadOptions,
  ): Promise<SorafsOrderbookReceiptsResponse>;
  listSorafsOrderbookEvents(
    options?: SorafsOrderbookEventsOptions,
  ): Promise<SorafsOrderbookEventsResponse | null>;
  streamSorafsOrderbookEvents(
    options?: SorafsOrderbookEventStreamOptions,
  ): AsyncGenerator<ToriiSseEvent<SorafsOrderbookFinalizedEvent>, void, unknown>;
  buildSorafsOrderbookEventsWebSocketUrl(
    options?: SorafsOrderbookEventsWebSocketParams,
  ): string;
  openSorafsOrderbookEventsWebSocket<T = unknown>(
    options?: ClientSorafsOrderbookEventsWebSocketOptions<T>,
  ): T;
  streamSorafsOrderbookEventsWebSocket<T = unknown>(
    options?: SorafsOrderbookEventsWebSocketStreamOptions<T>,
  ): AsyncGenerator<ToriiWebSocketEvent<SorafsOrderbookFinalizedEvent>, void, unknown>;
  getSorafsReputationLatest(
    options: SorafsReputationCacheOptions,
  ): Promise<SorafsReputationSnapshotSummary | null>;
  getSorafsReputationProvider(
    providerId: string,
    options: SorafsReputationCacheOptions,
  ): Promise<SorafsReputationProviderResponse | null>;
  getSorafsReputationSnapshot(
    snapshotIdHex: string,
    options: SorafsReputationCacheOptions,
  ): Promise<SorafsReputationSnapshotSummary | null>;
  getSorafsReputationWeights(
    options: SorafsReputationCacheOptions,
  ): Promise<SorafsReputationWeightsResponse | null>;
  listSorafsReputationEvents(
    options: SorafsReputationEventsOptions,
  ): Promise<SorafsReputationEventsResponse | null>;
  streamSorafsReputationEvents(
    options: SorafsReputationEventStreamOptions,
  ): AsyncGenerator<SorafsReputationSseEvent, void, unknown>;
  getSorafsBillingStatus(
    options: SorafsHedgingBillingAuthOptions,
  ): Promise<Record<string, unknown>>;
  listSorafsBillingStatements(
    options: SorafsBillingStatementListOptions,
  ): Promise<Record<string, unknown>>;
  getSorafsBillingStatement(
    statementIdHex: string,
    expectedCheckpointFingerprintHex: string,
    options: SorafsHedgingBillingAuthOptions,
  ): Promise<Buffer>;
  acknowledgeSorafsBillingStatement(
    statementIdHex: string,
    expectedCheckpointFingerprintHex: string,
    proof: Readonly<SorafsBillingAcknowledgementProofV1>,
    options: SorafsHedgingBillingAuthOptions,
  ): Promise<Record<string, unknown>>;
  getSorafsBillingReconciliation(
    options: SorafsHedgingBillingAuthOptions,
  ): Promise<Record<string, unknown>>;
  getSorafsHedgingExposure(
    options: SorafsHedgingProjectionOptions,
  ): Promise<Record<string, unknown>>;
  getSorafsHedgingIntents(
    options: SorafsHedgingProjectionOptions,
  ): Promise<Record<string, unknown>>;
  getSorafsPinManifest(
    digestHex: string,
    options?: SorafsPinManifestReadOptions,
  ): Promise<Record<string, unknown> | null>;
  getSorafsPinManifestTyped(
    digestHex: string,
    options?: SorafsPinManifestReadOptions,
  ): Promise<SorafsPinManifestResponse>;
  registerSorafsPinManifest(
    signedTransaction: VersionedSignedTransactionV1,
    options?: { signal?: AbortSignal },
  ): Promise<Record<string, unknown>>;
  registerSorafsPinManifestTyped(
    signedTransaction: VersionedSignedTransactionV1,
    options?: { signal?: AbortSignal },
  ): Promise<SorafsPinRegisterResponse>;
  getSorafsStorageState(options?: {
    signal?: AbortSignal;
  }): Promise<SorafsStorageStateResponse>;
  getSorafsManifest(
    manifestIdHex: string,
    options?: { signal?: AbortSignal },
  ): Promise<SorafsManifestResponse>;
  getDaManifest(
    storageTicketHex: string,
    options?: { signal?: AbortSignal },
  ): Promise<DaManifestFetchResponse>;
  getDaManifestToDir(
    storageTicketHex: string,
    options?: {
      outputDir?: string;
      signal?: AbortSignal;
      label?: string;
    },
  ): Promise<{
    manifest: DaManifestFetchResponse;
    paths: DaManifestPersistedPaths;
    outputDir: string;
  }>;
  submitDaBlob(
    options: DaIngestRequestInput & { signal?: AbortSignal },
  ): Promise<DaIngestSubmitResponse>;
  fetchDaPayloadViaGateway(
    options: DaGatewayFetchRequest,
  ): Promise<DaGatewayFetchSession>;
  proveDaAvailabilityToDir(options: {
    storageTicketHex?: string;
    manifestBundle?: DaManifestFetchResponse;
    gatewayProviders: ReadonlyArray<SorafsGatewayProviderSpec>;
    fetchOptions?: SorafsGatewayFetchOptions;
    proofSummary?: boolean | DaProofSummaryOptions | Record<string, unknown>;
    outputDir?: string;
    chunkerHandle?: string;
    signal?: AbortSignal;
    scoreboardPath?: string;
  }): Promise<{
    manifest: DaManifestFetchResponse;
    manifestPaths: DaManifestPersistedPaths;
    payloadPath: string;
    scoreboardPath: string | null;
    proofSummaryPath: string | null;
    proofSummaryArtifact: DaProofSummaryArtifact | null;
    proofSummary: DaProofSummary | null;
    gatewayResult: SorafsGatewayFetchResult;
    outputDir: string;
  }>;
  recordSorafsPorProof(input: {
    proof?: string | ArrayBuffer | ArrayBufferView | Buffer;
    proofB64?: string;
    signal?: AbortSignal;
  }): Promise<SorafsPorSubmissionResponse>;
  recordSorafsPorVerdict(input: {
    verdict?: string | ArrayBuffer | ArrayBufferView | Buffer;
    verdictB64?: string;
    signal?: AbortSignal;
  }): Promise<SorafsPorVerdictResponse>;
  getSorafsPorStatus(options?: SorafsPorStatusOptions): Promise<Buffer>;
  exportSorafsPorStatus(options?: SorafsPorExportOptions): Promise<Buffer>;
  getSorafsPorWeeklyReport(
    isoWeek: SorafsIsoWeekInput,
    options?: { signal?: AbortSignal },
  ): Promise<Buffer>;
  getUaidPortfolio(
    uaid: string,
    options?: UaidPortfolioQueryOptions,
  ): Promise<UaidPortfolioResponse>;
  getUaidBindings(
    uaid: string,
    options?: UaidBindingsQueryOptions,
  ): Promise<UaidBindingsResponse>;
  publishSpaceDirectoryManifest(
    request: PublishSpaceDirectoryManifestRequest,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<AppApiTransactionDraft>;
  revokeSpaceDirectoryManifest(
    request: RevokeSpaceDirectoryManifestRequest,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<AppApiTransactionDraft>;
  submitTransaction(
    payload: VersionedSignedTransactionV1,
    options?: { signal?: AbortSignal },
  ): Promise<unknown>;
  submitTransactionBatch(
    payloads: ReadonlyArray<VersionedSignedTransactionV1>,
    options?: { signal?: AbortSignal },
  ): Promise<{ acceptedCount: number; route?: unknown; outcomes?: Array<{
    signed_transaction_hash: string; status: number; reject_code: string | null;
  }> }>;
  getTransactionStatus(
    hashHex: string,
    options?: TransactionStatusReadOptions,
  ): Promise<ToriiPipelineTransactionStatus | null>;
  waitForTransactionStatus(
    hashHex: string,
    options?: TransactionStatusPollOptions,
  ): Promise<ToriiAppliedTransactionStatus>;
  /** Submit and wait; the transaction hash is derived from the signed bytes. */
  submitTransactionAndWait(
    payload: VersionedSignedTransactionV1,
    options?: SubmitTransactionAndWaitOptions,
  ): Promise<ToriiAppliedTransactionStatus>;
  getPipelineRecovery(
    height: number | string | bigint,
    options?: AbortSignalOptions,
  ): Promise<Record<string, unknown> | null>;
  getPipelineRecoveryTyped(
    height: number | string | bigint,
    options?: AbortSignalOptions,
  ): Promise<ToriiPipelineRecoverySidecar | null>;
  getPipelinePreflight(options?: AbortSignalOptions): Promise<ToriiPipelinePreflight>;
  getPipelineRecoveryFastpqProofs(
    height: number | string | bigint,
    options?: AbortSignalOptions,
  ): Promise<Record<string, unknown> | null>;
  getPipelineRecoveryFastpqProofsTyped(
    height: number | string | bigint,
    options?: AbortSignalOptions,
  ): Promise<ToriiPipelineRecoveryFastpqProofs | null>;
  /** `GET /health` liveness probe. */
  getHealth(options?: AbortSignalOptions): Promise<ToriiHealthStatus>;
  getConfiguration(): Promise<unknown | null>;
  getConfigurationTyped(): Promise<ToriiConfigurationSnapshot | null>;
  getConfidentialGasSchedule(): Promise<ConfidentialGasSchedule | null>;
  getStatusSnapshot(options?: AbortSignalOptions): Promise<ToriiStatusSnapshot>;
  deploySoracloudAppInfra(request: SoracloudAppInfraRequest, options: RequiredCanonicalRequestOptions): Promise<SoracloudMutationDraftResponseV1>;
  upgradeSoracloudAppInfra(request: SoracloudAppInfraRequest, options: RequiredCanonicalRequestOptions): Promise<SoracloudMutationDraftResponseV1>;
  getSoracloudAppInfraStatus(options: RequiredCanonicalRequestOptions & {
    appName?: string;
    auditLimit?: NumericLike;
  }): Promise<SoracloudAppInfraStatusResponseV1>;
  getSoracloudNamedAppInfraStatus(
    appName: string,
    options: RequiredCanonicalRequestOptions & { auditLimit?: NumericLike },
  ): Promise<SoracloudAppInfraStatusResponseV1>;
  getNetworkTimeNow(options?: {
    signal?: AbortSignal;
  }): Promise<ToriiNetworkTimeNow>;
  getNetworkTimeStatus(options?: {
    signal?: AbortSignal;
  }): Promise<ToriiNetworkTimeStatus>;
  /** Public capability advert (`GET /v1/node/capabilities`); no credentials are sent. */
  getNodeCapabilities(options?: AbortSignalOptions): Promise<ToriiNodeCapabilities>;
  getRuntimeAbiActive(options: RequiredCanonicalRequestOptions): Promise<ToriiRuntimeAbiActiveResponse>;
  getRuntimeAbiHash(options?: {
    signal?: AbortSignal;
  }): Promise<ToriiRuntimeAbiHashResponse>;
  getRuntimeMetrics(options: RequiredCanonicalRequestOptions): Promise<ToriiRuntimeMetrics>;
  listRuntimeUpgrades(options?: {
    signal?: AbortSignal;
  }): Promise<ReadonlyArray<ToriiRuntimeUpgradeListItem>>;
  proposeRuntimeUpgrade(
    manifest: ToriiRuntimeUpgradeManifestInput,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiRuntimeUpgradeTxResponse>;
  activateRuntimeUpgrade(
    idHex: string | BinaryLike,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiRuntimeUpgradeTxResponse>;
  cancelRuntimeUpgrade(
    idHex: string | BinaryLike,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiRuntimeUpgradeTxResponse>;
  listPeers(options?: {
    signal?: AbortSignal;
  }): Promise<Array<Record<string, unknown>>>;
  listPeersTyped(options?: {
    signal?: AbortSignal;
  }): Promise<Array<ToriiPeerRecord>>;
  listTelemetryPeersInfo(options?: {
    signal?: AbortSignal;
  }): Promise<ReadonlyArray<ToriiTelemetryPeerInfo>>;
  getExplorerMetrics(options?: {
    signal?: AbortSignal;
  }): Promise<ToriiExplorerMetricsSnapshot | null>;
  getExplorerAccountQr(
    accountId: string,
    options?: {
      signal?: AbortSignal;
    },
  ): Promise<ToriiExplorerAccountQrSnapshot>;
  getVpnProfile(options?: {
    signal?: AbortSignal;
  }): Promise<ToriiVpnProfile | null>;
  createVpnQuote(
    request: {
      exitClass?: string;
      meteringPublicKeyHex: string;
    },
    options: {
      signal?: AbortSignal;
      canonicalAuth: CanonicalRequestAuth;
    },
  ): Promise<ToriiVpnQuote>;
  createVpnSession(
    request: {
      exitClass?: string;
      quoteId: string;
      paymentTxHash: string;
      meteringPublicKeyHex: string;
    },
    options: {
      signal?: AbortSignal;
      canonicalAuth: CanonicalRequestAuth;
    },
  ): Promise<ToriiVpnSession>;
  getVpnSession(
    /** Canonical 16-byte session ID encoded as hexadecimal text. */
    sessionId: string,
    options: {
      signal?: AbortSignal;
      canonicalAuth: CanonicalRequestAuth;
    },
  ): Promise<ToriiVpnSession | null>;
  submitVpnReceipt(
    request: {
      relayReceiptHex: string;
      clientVoucherHex: string;
      leaseIdHex?: string;
    },
    options: {
      signal?: AbortSignal;
      canonicalAuth: CanonicalRequestAuth;
    },
  ): Promise<ToriiVpnReceipt>;
  listVpnReceipts(options: {
    signal?: AbortSignal;
    canonicalAuth: CanonicalRequestAuth;
  }): Promise<ToriiVpnReceiptListResponse>;
  getSnsPolicy(
    suffixId: number,
    options?: { signal?: AbortSignal },
  ): Promise<SnsSuffixPolicy>;
  getSnsRegistration(
    selector: string,
    options?: { signal?: AbortSignal },
  ): Promise<SnsNameRecord>;
  getGovernanceProposal(
    proposalId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<Record<string, unknown> | null>;
  getGovernanceProposalTyped(
    proposalId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ToriiGovernanceProposalResult>;
  getGovernanceReferendum(
    referendumId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ToriiGovernanceReferendumResponse | null>;
  getGovernanceReferendumTyped(
    referendumId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ToriiGovernanceReferendumResult>;
  getElectionTally(
    electionId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ToriiElectionTally | null>;
  getGovernanceTally(
    referendumId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ToriiGovernanceTally | null>;
  getGovernanceTallyTyped(
    referendumId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ToriiGovernanceTallyResult>;
  getGovernanceLocks(
    referendumId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ToriiGovernanceLocksResponse | null>;
  getGovernanceLocksTyped(
    referendumId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ToriiGovernanceLocksResult>;
  getGovernanceUnlockStats(options: RequiredCanonicalRequestOptions): Promise<Record<string, unknown> | null>;
  getGovernanceUnlockStatsTyped(options: RequiredCanonicalRequestOptions): Promise<ToriiGovernanceUnlockStats>;
  draftParliamentAttemptV1(
    proposal: ParliamentProposalV1,
    attemptSequence: number,
    options: ParliamentAttemptDraftOptionsV1,
  ): Promise<ParliamentAttemptDraftResponseV1>;
  getParliamentAttemptV1(
    governanceAttemptId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ParliamentAttemptReadResponseV1>;
  getParliamentTimedOvnCastingContextV1(
    ballotAttemptId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ParliamentTimedOvnCastingContextResponseV1>;
  getParliamentTimedOvnCastingProofPageV1(
    ballotAttemptId: string,
    trustedCheckpointHeight: number | bigint,
    options: RequiredCanonicalRequestOptions,
  ): Promise<Buffer>;
  getParliamentTleReleaseContextV1(
    ballotAttemptId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ParliamentTleReleaseContextResponseV1>;
  requestParliamentTlePartialReleaseV1(
    ballotAttemptId: string,
    options: ParliamentTlePartialReleaseOptionsV1,
  ): Promise<ParliamentTlePartialReleaseShareV1>;
  draftParliamentTransitionV1(
    governanceAttemptId: string,
    transition: ParliamentLifecycleTransitionV1,
    options: ParliamentTransitionDraftOptionsV1,
  ): Promise<ParliamentTransitionDraftResponseV1>;
  draftMinistryAgendaProposal(
    payload: MinistryAgendaProposalDraftRequest,
    options: RequiredCanonicalRequestOptions,
  ): Promise<MinistryAgendaProposalDraftResponse>;
  getMinistryAgendaProposal(
    proposalId: string,
    options: RequiredCanonicalRequestOptions,
  ): Promise<MinistryAgendaProposalGetResponse>;
  governanceProposeDeployContract(
    payload: ToriiGovernanceDeployContractProposalRequest,
    options: RequiredCanonicalRequestOptions,
  ): Promise<ToriiGovernanceProposalDraftResponseV1>;
  governanceSubmitPlainBallot(
    payload: ToriiGovernancePlainBallotRequest,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<ToriiGovernanceBallotResponse>;
  governanceSubmitZkBallotV1(
    payload: ToriiGovernanceZkBallotV1Request,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<ToriiGovernanceBallotResponse>;
  governanceSubmitZkBallotProofV1(
    payload: ToriiGovernanceZkBallotProofRequest,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<ToriiGovernanceBallotResponse>;
  setProtectedNamespaces(
    namespaces: string | string[],
    options?: { signal?: AbortSignal },
  ): Promise<ToriiProtectedNamespacesApplyResponse>;
  getProtectedNamespaces(options: RequiredCanonicalRequestOptions): Promise<ToriiProtectedNamespacesGetResponse>;
  getSumeragiStatus(options?: {
    signal?: AbortSignal;
  }): Promise<Record<string, unknown>>;
  getSumeragiStatusTyped(options?: {
    signal?: AbortSignal;
  }): Promise<ToriiSumeragiStatus>;
  getSumeragiLanes(options?: {
    signal?: AbortSignal;
  }): Promise<ReadonlyArray<ToriiSumeragiLaneStatus>>;
  getSumeragiBlsKeys(options?: {
    signal?: AbortSignal;
  }): Promise<Record<string, string | null>>;
  getSumeragiParams(options?: {
    signal?: AbortSignal;
  }): Promise<ToriiSumeragiParamsSnapshot>;
  listSumeragiEvidence(
    options?: SumeragiEvidenceListOptions,
  ): Promise<SumeragiEvidenceListResponse>;
  getSumeragiEvidenceCount(): Promise<SumeragiEvidenceCountResponse>;
  /** Prometheus metrics (`GET /metrics`) in the text exposition format. */
  getMetrics(options?: AbortSignalOptions): Promise<string>;
  /** Exact canonical result-bearing SignedBlockWire at a finalized height. */
  getLedgerExecutedBlockWire(
    height: number | string | bigint,
    options?: { signal?: AbortSignal },
  ): Promise<Buffer>;
  getBlock(
    height: number | string | bigint,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiExplorerBlock | null>;
  /**
   * Stream `/v1/events/sse`; `options.filter` uses the collection-query text
   * grammar over event fields. Abort with `options.signal` or by leaving the loop.
   */
  streamEvents<T = ToriiEventPayload>(
    options?: EventStreamOptions,
  ): AsyncGenerator<ToriiEventFrame<T> | ToriiStreamErrorFrame, void, unknown>;
  streamContractEvents<T = ToriiContractEventItem>(
    options?: ContractEventStreamOptions,
  ): AsyncGenerator<ToriiSseEvent<T>, void, unknown>;
  streamSumeragiStatus<T = ToriiSumeragiStatus>(
    options?: Omit<EventStreamOptions, "filter">,
  ): AsyncGenerator<ToriiSseEvent<T>, void, unknown>;
  getKaigiCall(
    callId: string,
    options?: { signal?: AbortSignal },
  ): Promise<KaigiCallView | null>;
  listKaigiCallSignals(
    callId: string,
    options?: KaigiCallSignalsOptions,
  ): Promise<KaigiCallSignalsList>;
  streamKaigiCallEvents(
    callId: string,
    options?: KaigiCallEventsOptions,
  ): AsyncGenerator<ToriiSseEvent<KaigiCallEventPayload>, void, unknown>;
  listKaigiRelays(options?: {
    signal?: AbortSignal;
  }): Promise<KaigiRelaySummaryList>;
  getKaigiRelay(
    relayId: string,
    options?: { signal?: AbortSignal },
  ): Promise<KaigiRelayDetail | null>;
  getKaigiRelaysHealth(options?: {
    signal?: AbortSignal;
  }): Promise<KaigiRelayHealthSnapshot>;
  streamKaigiRelayEvents(
    options?: KaigiRelayEventsOptions,
  ): AsyncGenerator<ToriiSseEvent<KaigiRelayEventPayload>, void, unknown>;
  listProverReports(
    filters?: ToriiProverReportFilters,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiProverReportListResult>;
  iterateProverReports(
    filters?: ToriiProverReportFilters,
    options?: PaginationIteratorOptions & { signal?: AbortSignal },
  ): AsyncGenerator<
    ToriiProverReport | string | ToriiProverReportMessageSummary,
    void,
    unknown
  >;
  getProverReport(
    reportId: string,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiProverReport>;
  deleteProverReport(
    reportId: string,
    options?: { signal?: AbortSignal },
  ): Promise<void>;
  countProverReports(
    filters?: ToriiProverReportFilters,
    options?: { signal?: AbortSignal },
  ): Promise<number>;
  submitIsoPacs008(
    message: ArrayBufferView | ArrayBuffer | Buffer | string,
    options?: {
      contentType?: string;
      profile?: string;
      signal?: AbortSignal;
      retryProfile?: string;
    },
  ): Promise<IsoPacs008SubmissionResponse | null>;
  submitIsoPacs009(
    message: ArrayBufferView | ArrayBuffer | Buffer | string,
    options?: {
      contentType?: string;
      profile?: string;
      signal?: AbortSignal;
      retryProfile?: string;
    },
  ): Promise<IsoPacs009SubmissionResponse | null>;
  submitIsoPacs008AndWait(
    message: ArrayBufferView | ArrayBuffer | Buffer | string,
    options?: {
      contentType?: string;
      profile?: string;
      signal?: AbortSignal;
      retryProfile?: string;
      wait?: IsoMessageWaitOptions;
    },
  ): Promise<IsoMessageStatusResponse>;
  submitIsoPacs009AndWait(
    message: ArrayBufferView | ArrayBuffer | Buffer | string,
    options?: {
      contentType?: string;
      profile?: string;
      signal?: AbortSignal;
      retryProfile?: string;
      wait?: IsoMessageWaitOptions;
    },
  ): Promise<IsoMessageStatusResponse>;
  submitIsoMessage(
    message: BuildPacs008Options | BuildPacs009Options,
    options?: SubmitIsoMessageOptions,
  ): Promise<
    IsoMessageSubmissionResponseBase | IsoMessageStatusResponse | null
  >;
  getIsoMessageStatus(
    messageId: string,
    options?: { signal?: AbortSignal; retryProfile?: string },
  ): Promise<IsoMessageStatusResponse | null>;
  waitForIsoMessageStatus(
    messageId: string,
    options?: IsoMessageWaitOptions,
  ): Promise<IsoMessageStatusResponse>;
  getConnectStatus(): Promise<ConnectStatusSnapshot | null>;
  createConnectSession(input: {
    sid: string;
    networkId: NetworkId;
    appPublicKey: Uint8Array;
    nonce: Uint8Array;
    node?: string | null;
  }): Promise<ConnectSessionResponse>;
  deleteConnectSession(input: {
    sid: string;
    tokenManagement?: string;
    token_management?: string;
  }): Promise<boolean>;
  listConnectApps(
    options?: ConnectAppListOptions,
  ): Promise<ConnectAppRegistryPage>;
  iterateConnectApps(
    options?: ConnectAppIteratorOptions,
  ): AsyncGenerator<ConnectAppRecord, void, unknown>;
  getConnectApp(
    appId: string,
    options?: { signal?: AbortSignal },
  ): Promise<ConnectAppRecord>;
  registerConnectApp(
    record: ConnectAppUpsertInput,
    options?: { signal?: AbortSignal },
  ): Promise<ConnectAppRecord | null>;
  deleteConnectApp(appId: string): Promise<boolean>;
  getConnectAppPolicy(options?: {
    signal?: AbortSignal;
  }): Promise<ConnectAppPolicyControls>;
  updateConnectAppPolicy(
    updates: ConnectAppPolicyUpdate,
    options?: { signal?: AbortSignal },
  ): Promise<ConnectAppPolicyControls>;
  getConnectAdmissionManifest(options?: {
    signal?: AbortSignal;
  }): Promise<ConnectAdmissionManifest>;
  setConnectAdmissionManifest(
    manifest: ConnectAdmissionManifestInput,
    options?: { signal?: AbortSignal },
  ): Promise<ConnectAdmissionManifest>;
  buildConnectWebSocketUrl(options: ConnectWebSocketParams): string;
  openConnectWebSocket<T = unknown>(
    options: ClientConnectWebSocketOptions<T>,
  ): T;
  static buildConnectWebSocketUrl(
    baseUrl: string,
    options: ConnectWebSocketParams,
  ): string;
  setContractAlias(
    request: SetContractAliasRequest,
  ): Promise<SetContractAliasResponse>;
  prepareContractCall(
    request: ContractCallRequest,
    options?: { signal?: AbortSignal; canonicalAuth?: CanonicalRequestAuth },
  ): Promise<ContractCallResponse>;
  simulateContractCall(
    request: ContractCallSimulateRequest,
    options?: { signal?: AbortSignal },
  ): Promise<ContractCallSimulateResponse>;
  proposeMultisig(
    request: MultisigProposeRequest,
    options?: { signal?: AbortSignal },
  ): Promise<MultisigContractCallResponse>;
  proposeMultisigContractCall(
    request: MultisigContractCallProposeRequest,
    options?: { signal?: AbortSignal },
  ): Promise<MultisigContractCallResponse>;
  approveMultisigContractCall(
    request: MultisigContractCallApproveRequest,
    options?: { signal?: AbortSignal },
  ): Promise<MultisigContractCallResponse>;
  getMultisigSpec(
    request: MultisigAccountSelector,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<MultisigSpecResponse>;
  queryMultisigProposals(
    request: MultisigProposalsQueryRequest,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<MultisigProposalsQueryResponse>;
  resolveMultisigProposal(
    request: MultisigProposalsResolveRequest,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<MultisigProposalResolveResponse>;
  getContractManifest(
    artifactId: ContractArtifactIdInput,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<ContractManifestRecord | null>;
  getContractCodeBytes(
    artifactId: ContractArtifactIdInput,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<ContractCodeBytesRecord | null>;
  getGovernanceContract(
    contractAddress: string,
    options: { signal?: AbortSignal; canonicalAuth: CanonicalRequestAuth },
  ): Promise<ToriiGovernanceContractResponse>;
  listTriggers(options?: TriggerListOptions): Promise<ToriiTriggerListPage>;
  iterateTriggers(
    options?: TriggerIteratorOptions,
  ): AsyncGenerator<ToriiTriggerRecord, void, unknown>;
  getTrigger(
    triggerId: string,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiTriggerRecord | null>;
  registerTrigger(
    trigger: ToriiTriggerUpsertRequest,
    options?: { signal?: AbortSignal },
  ): Promise<Record<string, unknown> | null>;
  registerTriggerTyped(
    trigger: ToriiTriggerUpsertRequest,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiTriggerMutationResponse | null>;
  deleteTrigger(
    triggerId: string,
    options?: { signal?: AbortSignal },
  ): Promise<Record<string, unknown> | null>;
  deleteTriggerTyped(
    triggerId: string,
    options?: { signal?: AbortSignal },
  ): Promise<ToriiTriggerMutationResponse | null>;
  queryTriggers(options?: IterableQueryOptions): Promise<ToriiTriggerListPage>;
  iterateTriggersQuery(
    options?: TriggerQueryIteratorOptions,
  ): AsyncGenerator<ToriiTriggerRecord, void, unknown>;
  createSubscriptionPlan(
    request: SubscriptionPlanCreateRequest,
    options: RequiredCanonicalRequestOptions,
  ): Promise<SubscriptionPlanCreateResponse>;
  createSubscription(
    request: SubscriptionCreateRequest,
    options: RequiredCanonicalRequestOptions,
  ): Promise<SubscriptionCreateResponse>;
  getSubscription(
    subscriptionId: string,
    options?: { signal?: AbortSignal },
  ): Promise<SubscriptionGetResponse | null>;
  pauseSubscription(
    subscriptionId: string,
    request: SubscriptionAuthorityActionRequest,
    options: RequiredCanonicalRequestOptions,
  ): Promise<SubscriptionActionResponse>;
  resumeSubscription(
    subscriptionId: string,
    request: SubscriptionChargeActionRequest,
    options: RequiredCanonicalRequestOptions,
  ): Promise<SubscriptionActionResponse>;
  cancelSubscription(
    subscriptionId: string,
    request: SubscriptionCancelActionRequest,
    options: RequiredCanonicalRequestOptions,
  ): Promise<SubscriptionActionResponse>;
  keepSubscription(
    subscriptionId: string,
    request: SubscriptionAuthorityActionRequest,
    options: RequiredCanonicalRequestOptions,
  ): Promise<SubscriptionActionResponse>;
  chargeSubscriptionNow(
    subscriptionId: string,
    request: SubscriptionChargeActionRequest,
    options: RequiredCanonicalRequestOptions,
  ): Promise<SubscriptionActionResponse>;
  recordSubscriptionUsage(
    subscriptionId: string,
    request: SubscriptionUsageRequest,
    options: RequiredCanonicalRequestOptions,
  ): Promise<SubscriptionUsageDraft>;
}

export interface NoritoRpcClientOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number | null;
  defaultHeaders?: Record<string, string>;
  allowInsecure?: boolean;
  authToken?: string | null;
  apiToken?: string | null;
  insecureTransportTelemetryHook?: (
    event: InsecureTransportTelemetryEvent,
  ) => void;
}

export interface NoritoRpcCallOptions {
  timeoutMs?: number;
  headers?: Record<string, string | null | undefined>;
  accept?: string | null;
  method?: string;
  params?: Record<string, string | number | boolean>;
  signal?: AbortSignal;
  allowAbsoluteUrl?: boolean;
  authToken?: string | null;
  apiToken?: string | null;
}

export declare class NoritoRpcClient {
  constructor(baseUrl: string, options?: NoritoRpcClientOptions);
  readonly baseUrl: string;
  call(
    path: string,
    payload: ArrayBufferView | ArrayBuffer | Buffer,
    options?: NoritoRpcCallOptions,
  ): Promise<Uint8Array>;
}

export declare class NoritoRpcError extends Error {
  readonly status: number;
  readonly body: string;
}

export function supportedCryptoAlgorithms(): CryptoAlgorithm[];

export function normalizeCryptoAlgorithm(
  algorithm?: string,
): CryptoAlgorithm;

export function generateKeyPair(options?: {
  seed?: ArrayBufferView | ArrayBuffer | Buffer;
  algorithm?: CryptoAlgorithm;
}): CryptoKeyPair;

export function loadKeyPair(
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
  options?: { algorithm?: CryptoAlgorithm },
): CryptoKeyPair;

export function publicKeyFromPrivate(
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
  options?: { algorithm?: CryptoAlgorithm },
): Buffer;

export function sign(
  message: ArrayBufferView | ArrayBuffer | Buffer | string,
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
  options?: { algorithm?: CryptoAlgorithm },
): Buffer;

export function verify(
  message: ArrayBufferView | ArrayBuffer | Buffer | string,
  signature: ArrayBufferView | ArrayBuffer | Buffer,
  publicKey: ArrayBufferView | ArrayBuffer | Buffer,
  options?: { algorithm?: CryptoAlgorithm },
): boolean;

export function publicKeyMultihash(
  publicKey: ArrayBufferView | ArrayBuffer | Buffer,
  options?: { algorithm?: CryptoAlgorithm },
): string;

export function privateKeyMultihash(
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
  options?: { algorithm?: CryptoAlgorithm },
): string;

export function generateSm2KeyPair(options?: { distid?: string }): Sm2KeyPair;

export function deriveSm2KeyPairFromSeed(
  seed: ArrayBufferView | ArrayBuffer | Buffer | string,
  distid?: string,
): Sm2KeyPair;

export function loadSm2KeyPair(
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
  distid?: string,
): Sm2KeyPair;

export function sm2PublicKeyMultihash(
  publicKey: ArrayBufferView | ArrayBuffer | Buffer,
  distid?: string,
): string;

export function signSm2(
  message: ArrayBufferView | ArrayBuffer | Buffer | string,
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
  distid?: string,
): Buffer;

export function verifySm2(
  message: ArrayBufferView | ArrayBuffer | Buffer | string,
  signature: ArrayBufferView | ArrayBuffer | Buffer,
  publicKey: ArrayBufferView | ArrayBuffer | Buffer,
  distid?: string,
): boolean;

export function buildKaigiAuthorizationProofV1(
  options: KaigiAuthorizationProofOptionsV1,
): KaigiAuthorizationProofV1;

export function buildKaigiUsageProofV1(
  options: KaigiUsageProofOptionsV1,
): KaigiUsageProofV1;

export function signEd25519(
  message: ArrayBufferView | ArrayBuffer | Buffer | string,
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
): Buffer;

export function verifyEd25519(
  message: ArrayBufferView | ArrayBuffer | Buffer | string,
  signature: ArrayBufferView | ArrayBuffer | Buffer,
  publicKey: ArrayBufferView | ArrayBuffer | Buffer,
): boolean;

export function normalizeRecoveryPhrase(phrase: string): RecoveryPhrase;

export function validateRecoveryPhrase(phrase: string): boolean;

export function generateRecoveryPhrase(
  wordCount?: RecoveryPhraseWordCount,
): RecoveryPhrase;

export function entropyToRecoveryPhrase(
  entropy: ArrayBufferView | ArrayBuffer | Buffer,
): RecoveryPhrase;

export function recoveryPhraseToEntropy(phrase: string): Buffer;

export function deriveEd25519SeedFromRecoveryPhrase(phrase: string): Buffer;

export function ed25519SeedToRecoveryPhrase(
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
): RecoveryPhrase;

export * from "./canonical-request.js";

export function deriveConfidentialKeyset(
  spendKey: ArrayBufferView | ArrayBuffer | Buffer,
): ConfidentialKeyset;

export function deriveConfidentialKeysetFromHex(
  spendKeyHex: string,
): ConfidentialKeyset;

export function deriveConfidentialOwnerTagV2(
  spendKey: ArrayBufferView | ArrayBuffer | Buffer,
  options: {
    diversifierHex: string;
  },
): Buffer;

export function deriveConfidentialDiversifierV2(
  seed: ArrayBufferView | ArrayBuffer | Buffer | string,
): {
  diversifier: Buffer;
  diversifierHex: string;
};

export function deriveConfidentialReceiveAddressV2(input: {
  spendKey: ArrayBufferView | ArrayBuffer | Buffer;
  diversifierSeed: ArrayBufferView | ArrayBuffer | Buffer | string;
}): ConfidentialReceiveAddressV2;

export function deriveConfidentialNoteV2(input: {
  assetDefinitionId: string;
  amount: NumericLike;
  rhoHex?: string;
  rho?: ArrayBufferView | ArrayBuffer | Buffer;
  ownerTagHex?: string;
  ownerTag?: ArrayBufferView | ArrayBuffer | Buffer;
}): { commitment: Buffer; commitmentHex: string };

export function deriveConfidentialNullifierV2(input: {
  networkId: NetworkId;
  assetDefinitionId: string;
  spendKey: ArrayBufferView | ArrayBuffer | Buffer;
  rhoHex?: string;
  rho?: ArrayBufferView | ArrayBuffer | Buffer;
}): { nullifier: Buffer; nullifierHex: string };

export const PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES: number;
export const PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1: Readonly<{
  VALID: 0;
  NULL_POINTER: 1;
  EMPTY: 2;
  ARCHIVE_TOO_LARGE: 3;
  DECODE_RESOURCE_LIMIT: 4;
  SCHEMA_MISMATCH: 5;
  NON_CANONICAL: 6;
  MALFORMED_ARCHIVE: 7;
  INVALID_CATALOG: 8;
}>;
export function isPrivacyNativeAvailable(): boolean;
/**
 * Return this native binary's local compiled-profile catalog. This is build
 * metadata only; network readiness requires the native-validated Exact12
 * capability manifest from authenticated Torii state.
 */
export function privacyCompiledProfileCatalogV1(): Buffer;

export interface Sm2Fixture {
  distid: string;
  seedHex: string;
  messageHex: string;
  privateKeyHex: string;
  publicKeySec1Hex: string;
  publicKeyMultihash: string;
  publicKeyPrefixed: string;
  za: string;
  signature: string;
  r: string;
  s: string;
}

export function sm2FixtureFromSeed(
  distid: string,
  seed: ArrayBufferView | ArrayBuffer | Buffer | string,
  message: ArrayBufferView | ArrayBuffer | Buffer | string,
): Sm2Fixture;

/** Exact compact-length AccountId value encoding for typed policy codecs. */
export function encodeAccountIdNoritoValue(
  value: string,
  context?: string,
): Uint8Array;
/** Exact compact-length AccountId value decoding for typed policy codecs. */
export function decodeAccountIdNoritoValue(
  payload: BinaryLike,
  context?: string,
): string;
/** Exact compact-length AssetDefinitionId value encoding for typed policy codecs. */
export function encodeAssetDefinitionIdNoritoValue(
  value: string,
  context?: string,
): Uint8Array;
/** Exact compact-length Quantity value encoding for typed policy codecs. */
export function encodeQuantityNoritoValue(
  value: QuantityInput,
  context?: string,
): Uint8Array;
/** An ordinary owned byte array; Node `Buffer` compatibility aliases are excluded. */
export interface CancelAssetLockV1Archive extends Uint8Array<ArrayBuffer> {
  readonly write?: never;
}

/** Encode the exact schema-bound bare `CancelAssetLock` V1 archive. */
export function encodeCancelAssetLockV1(
  value: Readonly<CancelAssetLockV1>,
): CancelAssetLockV1Archive;
/** Decode an exact schema-bound bare `CancelAssetLock` V1 archive. */
export function decodeCancelAssetLockV1(
  bytes: CancelAssetLockV1Archive,
): CancelAssetLockV1;
/**
 * Encode instruction JSON or an exact native frame (bytes, standard base64 or
 * lowercase 0x hex) using the caller-selected I105 deployment prefix (u16).
 */
export function noritoEncodeInstruction(
  instruction: object | string | ArrayBufferView | ArrayBuffer | Buffer,
  networkPrefix: number,
): Buffer;
export function noritoDecodeBlockProofs(
  bytes: ArrayBufferView | ArrayBuffer | Buffer,
): ToriiBlockProofs;
export function verifyBlockMerkleProof(
  leaf: string | ArrayBufferView | ArrayBuffer | Buffer,
  proof: ToriiBlockMerkleProof,
  commitment: ToriiBlockMerkleCommitment,
): boolean;
/**
 * Perform pure local Merkle consistency checks against a caller-authenticated
 * anchor. This function does not authenticate the anchor or verify finality.
 */
export function verifyBlockProofs(
  proofs: ToriiBlockProofs,
  trustedAnchor: ToriiBlockProofTrustedAnchor,
): ToriiBlockProofVerification;
/** Encode a canonical compact `InstructionBox` archive for a transaction. */
export function noritoEncodeInstructionBoxArchive(
  instruction: object | string | ArrayBufferView | ArrayBuffer | Buffer,
  networkPrefix: number,
): Buffer;
/** Decode one exact canonical compact `InstructionBox` transaction archive. */
export function noritoDecodeInstructionBoxArchive(
  bytes: ArrayBufferView | ArrayBuffer | Buffer,
  networkPrefix: number,
): unknown;
/** Encode the exact current Rust manifest-provenance signing frame. */
export function noritoEncodeContractManifestSignaturePayload(
  manifest: Record<string, unknown>,
): Buffer;
/** Encode one exact compact-length `FeePaymentIntent` archive. */
export function noritoEncodeFeePaymentIntentArchive(
  intent: Readonly<NoritoFeePaymentIntent>,
): Uint8Array;
export function noritoEncodeTransactionPayloadBatch(
  payloads: ReadonlyArray<ArrayBufferView | ArrayBuffer | Buffer>,
): Buffer;
export const SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_SCHEMA_NAME_V1:
  "iroha.torii.v1.sorafs.billing.acknowledgement_proof";
export const SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1: 65536;
export interface SorafsBillingAcknowledgementProofV1 {
  requestNonceHex: string;
  authenticationProof: ArrayBufferView | ArrayBuffer | Buffer;
}
export function noritoEncodeSorafsBillingAcknowledgementProofV1(
  proof: Readonly<SorafsBillingAcknowledgementProofV1>,
): Buffer;
export function noritoEncodeOpenVerifyEnvelope(envelope: OpenVerifyEnvelope): Buffer;
export function noritoDecodeOpenVerifyEnvelope(
  bytes: ArrayBufferView | ArrayBuffer | Buffer | string,
): {
  backend: OpenVerifyBackendTag;
  circuit_id: string;
  vk_hash: number[];
  public_inputs: number[];
  proof_bytes: number[];
  aux: number[];
};
export const PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1:
  "iroha.privacy.exact12-typed-fixture-bundle.v1";
export const PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1: 2097152;
export const PRIVACY_EXACT12_PROTOCOL_IDS_V1: readonly [
  "zk-ace-pq-authorization-v1",
  "anonymous-pgc-k-out-of-n-v1",
  "verange-transparent-range-v1",
  "iroha-zk-ams-v1",
  "vega-existing-credential-zk-v1",
  "iroha-zk-x509-stark-p256-v1",
  "iroha-jindo-polynomial-commitment-v1",
  "iroha-bootle-lantern-anoncred-v1",
  "orchard-halo2-actions-v1",
  "monero-fcmp-plus-plus-v1",
  "iroha-ivm-private-note-stark-v1",
  "pq-masp-stark-v1",
];
export type PrivacyExact12ProtocolIdV1 =
  (typeof PRIVACY_EXACT12_PROTOCOL_IDS_V1)[number];
export interface PrivacyExact12TypedFixtureRowV1 {
  protocolId: PrivacyExact12ProtocolIdV1;
  statementNorito: Uint8Array;
  envelopeNorito: Uint8Array;
  submitProofWireId: "iroha.privacy.submit_proof.v1";
  submitProofInstructionNorito: Uint8Array;
  transactionIntentProjectionNorito: Uint8Array;
  transactionIntentDigest: Uint8Array;
  unsignedTransactionPayloadNorito: Uint8Array;
  signedTransactionVersionedNorito: Uint8Array;
  signedTransactionHash: Uint8Array;
}
export interface PrivacyExact12TypedFixtureRowInputV1 {
  protocolId: PrivacyExact12ProtocolIdV1;
  statementNorito: BinaryLike;
  envelopeNorito: BinaryLike;
  submitProofWireId: "iroha.privacy.submit_proof.v1";
  submitProofInstructionNorito: BinaryLike;
  transactionIntentProjectionNorito: BinaryLike;
  transactionIntentDigest: BinaryLike;
  unsignedTransactionPayloadNorito: BinaryLike;
  signedTransactionVersionedNorito: BinaryLike;
  signedTransactionHash: BinaryLike;
}
export interface PrivacyExact12FixtureBundleV1 {
  version: 1;
  rows: PrivacyExact12TypedFixtureRowV1[];
}
export interface PrivacyExact12FixtureBundleInputV1 {
  version: 1;
  rows: ReadonlyArray<Readonly<PrivacyExact12TypedFixtureRowInputV1>>;
}
/** Decode an exact canonical-standard-base64 checked Exact12 archive. */
export function noritoDecodePrivacyExact12FixtureBundleBase64V1(
  value: string,
): PrivacyExact12FixtureBundleV1;
/** Decode one canonical native-independent Exact12 outer Norito archive. */
export function noritoDecodePrivacyExact12FixtureBundleV1(
  bytes: ArrayBufferView | ArrayBuffer | Buffer,
): PrivacyExact12FixtureBundleV1;
/** Re-encode a complete Exact12 bundle with canonical outer Norito layout. */
export function noritoEncodePrivacyExact12FixtureBundleV1(
  value: Readonly<PrivacyExact12FixtureBundleInputV1>,
): Uint8Array;
export const CONFIDENTIAL_MEMO_WIRE_MAGIC_V1: readonly [
  73,
  82,
  72,
  67,
  77,
  49,
  165,
  90,
];
export const CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1: 8;
export const CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1: 65536;
export type ConfidentialMemoSuiteV1 =
  | "ml-kem-768-xchacha20-poly1305-v1"
  | "ml-kem-1024-xchacha20-poly1305-v1";
export interface ConfidentialMemoRecipientSlotV1Input {
  suite: ConfidentialMemoSuiteV1;
  encapsulation: BinaryLike;
  wrap_nonce: BinaryLike;
  wrapped_memo_key: BinaryLike;
}
export interface ConfidentialMemoRecipientSlotV1 {
  suite: ConfidentialMemoSuiteV1;
  /** Canonical standard-base64 ML-KEM encapsulation. */
  encapsulation: string;
  wrap_nonce: number[];
  wrapped_memo_key: number[];
}
export interface ConfidentialMemoEnvelopeV1Input {
  slots: readonly [
    ConfidentialMemoRecipientSlotV1Input,
    ConfidentialMemoRecipientSlotV1Input,
    ConfidentialMemoRecipientSlotV1Input,
    ConfidentialMemoRecipientSlotV1Input,
    ConfidentialMemoRecipientSlotV1Input,
    ConfidentialMemoRecipientSlotV1Input,
    ConfidentialMemoRecipientSlotV1Input,
    ConfidentialMemoRecipientSlotV1Input,
  ];
  payload_nonce: BinaryLike;
  ciphertext: BinaryLike;
}
export interface ConfidentialMemoEnvelopeV1 {
  slots: [
    ConfidentialMemoRecipientSlotV1,
    ConfidentialMemoRecipientSlotV1,
    ConfidentialMemoRecipientSlotV1,
    ConfidentialMemoRecipientSlotV1,
    ConfidentialMemoRecipientSlotV1,
    ConfidentialMemoRecipientSlotV1,
    ConfidentialMemoRecipientSlotV1,
    ConfidentialMemoRecipientSlotV1,
  ];
  payload_nonce: number[];
  /** Canonical standard-base64 encrypted memo body. */
  ciphertext: string;
}
/** Encode the exact-eight-slot first-release confidential memo bare wire. */
export function noritoEncodeConfidentialMemoEnvelopeV1(
  value: Readonly<ConfidentialMemoEnvelopeV1Input>,
): Uint8Array;
/** Decode one exact canonical confidential memo bare wire. */
export function noritoDecodeConfidentialMemoEnvelopeV1(
  bytes: BinaryLike,
): ConfidentialMemoEnvelopeV1;
export interface NoritoFrameValidationOptions {
  context?: string;
  expectedSchemaHash?: ArrayBufferView | ArrayBuffer | Buffer;
  expectedTypeName?: string;
  expectedPaddingLength?: number;
  requireNonEmptyPayload?: boolean;
}
export interface ValidatedNoritoFrame {
  payload: Buffer;
  schemaHash: Buffer;
  flags: number;
}
/** Validate one canonical, uncompressed Norito v1 frame without decoding its payload. */
export function validateNoritoFrame(
  bytes: ArrayBufferView | ArrayBuffer | Buffer,
  options?: NoritoFrameValidationOptions,
): ValidatedNoritoFrame;
export interface MultisigProposeNoritoRequest {
  multisig_account_id?: string | null;
  multisigAccountId?: string | null;
  multisig_account_alias?: string | null;
  multisigAccountAlias?: string | null;
  signer_account_id?: string;
  signerAccountId?: string;
  public_key_hex?: string | null;
  publicKeyHex?: string | null;
  signature_b64?: string | null;
  signatureB64?: string | null;
  creation_time_ms?: number | string | bigint | null;
  creationTimeMs?: number | string | bigint | null;
  fee_payment?: NoritoFeePaymentIntent;
  feePayment?: NoritoFeePaymentIntent;
  memo?: string | null;
  validation_fee_assessment?: RetailFeeAssessmentV1 | null;
  instructions: Array<object | string | ArrayBufferView | ArrayBuffer | Buffer>;
}
export function noritoEncodeMultisigProposeRequest(
  request: MultisigProposeNoritoRequest,
  networkPrefix: number,
): Buffer;
export function noritoEncodeMultisigContractCallProposeRequest(
  request: MultisigContractCallProposeRequest,
  networkPrefix: number,
): Buffer;
export function noritoEncodeMultisigContractCallApproveRequest(
  request: MultisigContractCallApproveRequest,
  networkPrefix: number,
): Buffer;
export function noritoDecodeInstruction(
  bytes: ArrayBufferView | ArrayBuffer | Buffer,
  networkPrefix: number,
  options?: { parseJson?: boolean },
): JsonValue;
export interface SubscriptionTriggerActionSummary {
  version: 1;
  kind: "billing" | "usage";
  authority: string;
  max_cycles: string;
  charge_at_ms?: number;
  subscription_id?: string;
  trigger_id?: string;
}
export function inspectSubscriptionTriggerAction(
  encodedAction: string,
  networkPrefix: number,
): SubscriptionTriggerActionSummary;

/**
 * Compute the exact native Parliament fingerprint for a validation-fee policy.
 *
 * The policy must use the native snake-case `ValidationFeePolicyV1` JSON
 * contract. Missing, unknown, and retired fields are rejected natively.
 */
export function computeValidationFeePolicyProposalFingerprintV1(
  proposalOperator: string,
  policy: Readonly<Record<string, JsonValue>>,
): string;

/**
 * Compute the exact native Parliament fingerprint for a validation-fee payout lifecycle.
 *
 * Both arguments must use their exact native snake-case JSON contracts.
 * Missing, unknown, legacy, and non-canonical fields are rejected natively.
 */
export function computeValidationFeePayoutLifecycleProposalFingerprintV1(
  proposalOperator: string,
  payoutBinding: Readonly<Record<string, JsonValue>>,
): string;

export interface AxtTouchManifest {
  read: ReadonlyArray<string>;
  write: ReadonlyArray<string>;
}

export interface AxtTouchFragment {
  dsid: number;
  manifest: AxtTouchManifest;
}

export interface AxtTouchSpec {
  dsid: number;
  read: ReadonlyArray<string>;
  write: ReadonlyArray<string>;
}

export interface AxtDescriptorShape {
  dsids: ReadonlyArray<number>;
  touches: ReadonlyArray<AxtTouchSpec>;
}

export interface AxtDescriptorBuild {
  descriptor: AxtDescriptorShape;
  descriptorBytes: Buffer;
  bindingHex: string;
  binding: Buffer;
  touchManifest: ReadonlyArray<AxtTouchFragment>;
  native: true;
}

export function buildTouchManifest(
  read: Iterable<string> | ArrayLike<string>,
  write: Iterable<string> | ArrayLike<string>,
): AxtTouchManifest;

export function buildAxtDescriptor(options: {
  dsids: Iterable<number> | ArrayLike<number>;
  touches?: Iterable<{
    dsid: number;
    read?: Iterable<string> | ArrayLike<string>;
    write?: Iterable<string> | ArrayLike<string>;
  }>;
  touchManifest?: Iterable<{
    dsid: number;
    manifest?: Partial<AxtTouchManifest>;
    read?: Iterable<string> | ArrayLike<string>;
    write?: Iterable<string> | ArrayLike<string>;
  }>;
}): AxtDescriptorBuild;

export function computeAxtBinding(
  descriptorBytes: Buffer | Uint8Array | ArrayBuffer,
): Buffer;

export interface AxtRejectContext {
  reason: string;
  dataspace: number | null;
  lane: number | null;
  snapshot_version: number | null;
  detail: string;
  active_handle_era: number | null;
  next_handle_counter: number | null;
}

export interface AxtHandleRefreshHint {
  dataspace: number | null;
  targetLane: number | null;
  activeHandleEra: number | null;
  nextHandleCounter: number | null;
  reason: string;
  snapshotVersion: number | null;
  detail: string;
}

export function normalizeAxtRejectContext(
  ctx: unknown,
  context?: string,
): AxtRejectContext;

export function buildHandleRefreshRequest(
  ctx: unknown,
  overrides?: Partial<AxtHandleRefreshHint>,
): AxtHandleRefreshHint;

export function hashSignedTransaction(
  signedTransaction: VersionedSignedTransactionV1,
  options?: { encoding?: BufferEncoding | "buffer" },
): string | Buffer;

export function hashSignedTransactionPayload(
  signedTransaction: VersionedSignedTransactionV1,
  options?: { encoding?: BufferEncoding | "buffer" },
): string | Buffer;

export function decodeSignedTransaction(
  signedTransaction: VersionedSignedTransactionV1,
  networkPrefix: number,
): Record<string, unknown>;

export function encodeContractArgumentRecord(
  argumentSchema: Record<string, unknown>,
  payload: Record<string, unknown>,
  networkPrefix: number,
): Buffer;

export function hashInstructionBatch(
  instructions: Array<object | string>,
  networkPrefix: number,
  options?: { encoding?: BufferEncoding | "buffer" },
): string | Buffer;

export function resignSignedTransaction(
  networkId: NetworkId,
  signedTransaction: VersionedSignedTransactionV1,
  privateKey: ArrayBufferView | ArrayBuffer | Buffer,
): Buffer;

/** Convert the ergonomic fee intent into the native signer's exact Norito JSON. */
export function feePaymentIntentToNoritoJson(
  feePayment: BrowserFeePayment,
): string;

export function buildTransaction(
  input: TransactionAssemblyInput,
): SignedTransactionResult;

export function buildExecutableBatchTransaction(
  input: ExecutableBatchTransactionAssemblyInput,
): SignedTransactionResult;

export function buildTransactionPayload(
  input: TransactionPayloadDraftInput,
): TransactionPayloadDraftResult;

export function buildExecutableBatchTransactionPayload(
  input: ExecutableBatchTransactionPayloadDraftInput,
): TransactionPayloadDraftResult;

export function signQuotedTransactionPayload(
  input: QuotedTransactionPayloadSigningInput,
): SignedTransactionResult;

export function quoteAndSignTransaction(
  client: ToriiClient,
  input: TransactionPayloadDraftInput & {
    privateKey: Buffer | ArrayBuffer | ArrayBufferView;
    privateKeyAlgorithm?: CryptoAlgorithm;
  },
  options?: {
    canonicalAuth?: CanonicalRequestAuth;
    signal?: AbortSignal;
  },
): Promise<
  SignedTransactionResult & {
    draft: TransactionPayloadDraftResult;
    quote: FeeQuoteResponse;
  }
>;

export function buildRegisterPinManifestInstruction(
  input: RegisterPinManifestInstructionInput,
): {
  RegisterPinManifest: {
    manifest_payload: string;
    alias: {
      namespace: string;
      name: string;
      proof: string;
    } | null;
    successor_of: ReadonlyArray<number> | null;
  };
};

export function buildRegisterPinManifestTransaction(
  client: ToriiClient,
  input: RegisterPinManifestTransactionInput,
  options?: {
    canonicalAuth?: CanonicalRequestAuth;
    signal?: AbortSignal;
  },
): Promise<
  SignedTransactionResult & {
    draft: TransactionPayloadDraftResult;
    quote: FeeQuoteResponse;
  }
>;

export function buildRegisterDomainTransaction(
  input: RegisterDomainInput,
): SignedTransactionResult;

/**
 * Assemble and sign a transaction whose executable is `Executable::IvmProved`
 * and whose proof attachment list contains the provided attachment.
 */
export function buildIvmProvedTransaction(
  input: IvmProvedTransactionAssemblyInput,
): SignedTransactionResult;
export function buildIvmProvedTransactionPayload(
  input: IvmProvedTransactionPayloadDraftInput,
): IvmProvedTransactionPayloadDraftResult;
export function signQuotedIvmProvedTransactionPayload(
  input: QuotedIvmProvedTransactionPayloadSigningInput,
): SignedTransactionResult;

export const VALIDATION_FEE_CURRENT_POLICY_PROOF_PATH: "/v1/validation-fee/policy/current/proof";
export const VALIDATION_FEE_LEDGER_BINDING_SCHEMA: "iroha.validation-fee-ledger-binding.v1";
export const VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES: 4194304;
export const VALIDATION_FEE_REQUIRED_BRIDGE_ABI_VERSION: 25;
export const VALIDATION_FEE_VERIFIED_POLICY_PROJECTION_SCHEMA: "iroha.validation_fee.verified_policy_projection.v1";

export function normalizeValidationFeeCheckpointV1(
  checkpoint: ValidationFeeCheckpointV1,
): NormalizedValidationFeeCheckpointV1;
export function normalizeValidationFeeLedgerBindingV1(
  binding: ValidationFeeLedgerBindingV1,
): NormalizedValidationFeeLedgerBindingV1;
export function encodeValidationFeeCurrentPolicyProofRequestV1(
  checkpoint: ValidationFeeCheckpointV1,
): Buffer;
export function verifyValidationFeeCurrentPolicyProofV1(
  proofNorito: Buffer | ArrayBuffer | ArrayBufferView,
  binding: ValidationFeeLedgerBindingV1,
  checkpoint: ValidationFeeCheckpointV1,
  networkPrefix: number,
): ValidationFeeVerifiedPageV1;



export function buildMintAssetTransaction(
  input: MintAssetInput & FeePaymentRequired,
): SignedTransactionResult;
/**
 * Build and sign a transaction containing a single `Burn::Asset` instruction.
 * Throws if the quantity is non-positive or the asset identifier is empty.
 */
export function buildBurnAssetTransaction(
  input: BurnAssetInput & FeePaymentRequired,
): SignedTransactionResult;
/**
 * Build and sign a transaction containing a single `Burn::TriggerRepetitions`
 * instruction. Throws when repetitions are not positive integers.
 */
export function buildBurnTriggerTransaction(
  input: BurnTriggerInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildMintTriggerTransaction(
  input: MintTriggerInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildTransferAssetTransaction(
  input: TransferAssetInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildRegisterMultisigTransaction(
  input: RegisterMultisigTransactionInput,
): SignedTransactionResult;
export function buildTransferAssetDefinitionTransaction(
  input: TransferAssetDefinitionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildTransferDomainTransaction(
  input: TransferDomainInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildTransferNftTransaction(
  input: TransferNftInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildRegisterRwaTransaction(
  input: RegisterRwaInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildTransferRwaTransaction(
  input: TransferRwaInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildMergeRwasTransaction(
  input: MergeRwasInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildRedeemRwaTransaction(
  input: RedeemRwaInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildFreezeRwaTransaction(
  input: FreezeRwaInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildUnfreezeRwaTransaction(
  input: UnfreezeRwaInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildHoldRwaTransaction(
  input: HoldRwaInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildReleaseRwaTransaction(
  input: ReleaseRwaInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildForceTransferRwaTransaction(
  input: ForceTransferRwaInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildSetRwaControlsTransaction(
  input: SetRwaControlsInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildSetRwaKeyValueTransaction(
  input: SetRwaKeyValueInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildRemoveRwaKeyValueTransaction(
  input: RemoveRwaKeyValueInput & FeePaymentRequired,
): SignedTransactionResult;
/**
 * Compose a mint followed by one or more transfers. Provide either `transfer`
 * or `transfers`; transfers without an explicit `sourceAssetHoldingId` reuse the mint's
 * destination asset identifier.
 */
export function buildMintAndTransferTransaction(
  input: MintAndTransferInput & FeePaymentRequired,
): SignedTransactionResult;
/**
 * Register a domain and optionally perform follow-up mints in the same
 * transaction. Accepts either a single `mint` or an array of `mints`.
 */
export function buildRegisterDomainAndMintTransaction(
  input: RegisterDomainAndMintInput & FeePaymentRequired,
): SignedTransactionResult;
/**
 * Register an account and enqueue one or more asset transfers. Each transfer
 * must specify its source asset identifier; the helper enforces this at runtime.
 */
export function buildRegisterAccountAndTransferTransaction(
  input: RegisterAccountAndTransferInput & FeePaymentRequired,
): SignedTransactionResult;
/**
 * Register an asset definition and optionally mint initial supply. When both
 * `accountId` and `assetHoldingId` are provided the helper validates that they match
 * the canonical asset-holding id derived from `assetDefinitionId + accountId`.
 */
export function buildRegisterAssetDefinitionAndMintTransaction(
  input: RegisterAssetDefinitionAndMintInput & FeePaymentRequired,
): SignedTransactionResult;
/**
 * Register an asset definition, mint supply, and optionally fan-out transfers.
 * When a transfer omits `sourceAssetHoldingId` the helper reuses the first minted
 * destination identifier.
 */
export function buildRegisterAssetDefinitionMintAndTransferTransaction(
  input: RegisterAssetDefinitionMintAndTransferInput & FeePaymentRequired,
): SignedTransactionResult;

export interface TimeTriggerActionOptions {
  authority: string;
  instructions: ReadonlyArray<object | string>;
  startTimestampMs: number | bigint;
  periodMs?: number | bigint | null;
  repeats?: number | bigint | null;
  metadata?: Record<string, unknown> | string | null;
}

export interface CommitTriggerActionOptions {
  authority: string;
  instructions: ReadonlyArray<object | string>;
  repeats?: number | bigint | null;
  metadata?: Record<string, unknown> | string | null;
}

export function buildTimeTriggerAction(
  options: TimeTriggerActionOptions,
): string;
export function buildPrecommitTriggerAction(
  options: CommitTriggerActionOptions,
): string;

export function buildCreateKaigiTransaction(
  input: CreateKaigiTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildJoinKaigiTransaction(
  input: JoinKaigiTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildLeaveKaigiTransaction(
  input: LeaveKaigiTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildEndKaigiTransaction(
  input: EndKaigiTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildRecordKaigiUsageTransaction(
  input: RecordKaigiUsageTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildSetKaigiRelayManifestTransaction(
  input: SetKaigiRelayManifestTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildRegisterKaigiRelayTransaction(
  input: RegisterKaigiRelayTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildUnregisterKaigiRelayTransaction(
  input: UnregisterKaigiRelayTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildReportKaigiRelayHealthTransaction(
  input: ReportKaigiRelayHealthTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildRegisterSmartContractCodeTransaction(
  input: RegisterSmartContractCodeTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildRegisterSmartContractBytesTransaction(
  input: RegisterSmartContractBytesTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildRemoveSmartContractBytesTransaction(
  input: RemoveSmartContractBytesTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildProposeDeployContractTransaction(
  input: ProposeDeployContractTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildCastZkBallotTransaction(
  input: CastZkBallotTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildCastPlainBallotTransaction(
  input: CastPlainBallotTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildUpdatePlainConvictionTransaction(
  input: UpdatePlainConvictionTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildRegisterZkAssetTransaction(
  input: RegisterZkAssetTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildScheduleConfidentialPolicyTransitionTransaction(
  input: ScheduleConfidentialPolicyTransitionTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildCancelConfidentialPolicyTransitionTransaction(
  input: CancelConfidentialPolicyTransitionTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildCreateElectionTransaction(
  input: CreateElectionTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildSubmitBallotTransaction(
  input: SubmitBallotTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function buildFinalizeElectionTransaction(
  input: FinalizeElectionTransactionInput & FeePaymentRequired,
): SignedTransactionResult;
export function submitSignedTransaction(
  client: ToriiClient,
  signedTransaction: VersionedSignedTransactionV1,
  options?: {
    waitForCommit?: boolean;
    pollIntervalMs?: number;
    timeoutMs?: number;
  } & (
    | { privateKey?: undefined; networkId?: undefined }
    | {
        networkId: NetworkId;
        privateKey: ArrayBufferView | ArrayBuffer | Buffer;
      }
  ),
): Promise<{
  hash: string;
  submission: unknown;
  status?: ToriiAppliedTransactionStatus;
}>;

export const SORAFS_REPLICATION_ORDER_MAX_PAYLOAD_BYTES_V1: 1048576;

export interface IssueReplicationOrderInstruction {
  IssueReplicationOrder: {
    order_id: string;
    order_payload: string;
    issued_epoch: number;
    deadline_epoch: number;
    musubi_archive: string | null;
  };
}

export interface CompleteReplicationOrderInstruction {
  CompleteReplicationOrder: {
    order_id: string;
    provider_id: string;
    completion_epoch: number;
    expected_authority: ProviderIngestCompletionAuthorityV1;
    expected_assignment_revision: number;
    finalized_anchor: ProviderIngestFinalizedAnchorV1;
  };
}

export interface ProviderIngestCompletionSignerPolicyV1 {
  policy_id: string;
  revision: number;
  predecessor_digest: string | null;
  policy_digest: string;
}

export interface ProviderIngestCompletionAuthorityV1 {
  provider_owner: string;
  completion_signer: string;
  signer_policy: ProviderIngestCompletionSignerPolicyV1;
}

export interface ProviderIngestFinalizedAnchorV1 {
  height: number;
  block_hash: string;
}

export interface ExpireReplicationOrderInstruction {
  ExpireReplicationOrder: {
    order_id: string;
    expiration_epoch: number;
  };
}

export interface SorafsReplicationOrderPayloadSummaryV1 {
  orderId: string;
  targetReplicas: number;
  providerIds: string[];
  issuedAt: string;
  deadlineAt: string;
}

/**
 * Validate a canonical, unpadded Norito `ReplicationOrderV1` archive.
 */
export function validateSorafsReplicationOrderPayloadV1(
  payload: BinaryLike,
  expectedOrderId?: string | null,
): SorafsReplicationOrderPayloadSummaryV1;

/**
 * Build a native `IssueReplicationOrder` instruction. IDs are exact non-zero
 * lowercase 64-hex strings and `orderPayload` is canonical standard base64.
 */
export function buildIssueReplicationOrderInstruction(options: {
  orderId: string;
  orderPayload: string;
  issuedEpoch: NumericLike;
  deadlineEpoch: NumericLike;
  musubiArchiveId?: string | null;
}): IssueReplicationOrderInstruction;

/**
 * Build the provider-specific six-field completion instruction. The authority,
 * assignment revision, and finalized anchor are mandatory commit-time
 * compare-and-set inputs.
 */
export function buildCompleteReplicationOrderInstruction(options: {
  orderId: string;
  providerId: string;
  completionEpoch: NumericLike;
  expectedAuthority: {
    providerOwner: string;
    completionSigner: string;
    signerPolicy: {
      policyId: string;
      revision: NumericLike;
      predecessorDigest: string | null;
      policyDigest: string;
    };
  };
  expectedAssignmentRevision: NumericLike;
  finalizedAnchor: {
    height: NumericLike;
    blockHash: string;
  };
}): CompleteReplicationOrderInstruction;

export function buildExpireReplicationOrderInstruction(options: {
  orderId: string;
  expirationEpoch: NumericLike;
}): ExpireReplicationOrderInstruction;

export interface CancelAssetLockInstruction {
  CancelAssetLock: {
    escrow_id: string;
    expected_remaining_amount: string;
  };
}

/** Raw owner-authorized activation guarded by the exact retained lifecycle revision. */
export interface ActivateContractInstanceInstruction {
  ActivateContractInstance: {
    contract_address: string;
    expected_revision: string;
    code_hash: string;
  };
}

/** Raw owner-authorized deactivation guarded by the exact retained lifecycle revision. */
export interface DeactivateContractInstanceInstruction {
  DeactivateContractInstance: {
    contract_address: string;
    expected_revision: string;
    reason: string | null;
  };
}

export interface SetContractParliamentDelegationInstruction {
  SetContractParliamentDelegation: {
    contract_address: string;
    expected_revision: string;
    delegated: boolean;
  };
}

export type ContractLifecycleOwnerV1 =
  | Readonly<{ owner: "Account"; value: string }>
  | Readonly<{ owner: "Parliament"; value: null }>;

export interface OfferContractOwnershipInstruction {
  OfferContractOwnership: {
    contract_address: string;
    expected_revision: string;
    new_owner: ContractLifecycleOwnerV1;
  };
}

export interface AcceptContractOwnershipInstruction {
  AcceptContractOwnership: {
    contract_address: string;
    expected_revision: string;
  };
}

export interface CancelContractOwnershipOfferInstruction {
  CancelContractOwnershipOffer: {
    contract_address: string;
    expected_revision: string;
  };
}

/** Exact two-field value carried by a bare `CancelAssetLock` V1 archive. */
export interface CancelAssetLockV1 {
  readonly escrow_id: string;
  readonly expected_remaining_amount: string;
}

/** Maximum UTF-8 bytes accepted for a CancelAssetLock lock-id preimage. */
export declare const CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1: 4096;

/**
 * Build a native compare-and-cancel asset-lock instruction. `lockId` is
 * exact nonempty text without surrounding whitespace/BOM and at most
 * {@link CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1} UTF-8 bytes. It is
 * deterministically hashed to the ledger `EscrowId`; the precondition must be
 * a positive canonical quantity.
 */
export function buildCancelAssetLockInstruction(options: {
  lockId: string;
  expectedRemainingAmount: QuantityInput;
}): CancelAssetLockInstruction;

export type AssetTransferAvailability = "Enabled" | "Disabled";

/** Maximum UTF-8 bytes accepted for an asset-transfer availability reason. */
export declare const ASSET_TRANSFER_AVAILABILITY_MAX_REASON_BYTES_V1: 512;

export interface SetAssetTransferAvailabilityInstruction {
  SetAssetTransferAvailability: {
    account_id: string;
    asset_definition_id: string;
    expected_revision: string;
    incoming: AssetTransferAvailability;
    outgoing: AssetTransferAvailability;
    reason: string | null;
  };
}

/**
 * Atomically update both transfer directions for one account and asset
 * definition. `expectedRevision` is a compare-and-set precondition, and
 * `reason` is bounded by
 * {@link ASSET_TRANSFER_AVAILABILITY_MAX_REASON_BYTES_V1}.
 */
export function buildSetAssetTransferAvailabilityInstruction(options: {
  accountId: string;
  assetDefinitionId: string;
  expectedRevision: NumericLike;
  incoming: AssetTransferAvailability;
  outgoing: AssetTransferAvailability;
  reason?: string | null;
}): SetAssetTransferAvailabilityInstruction;

export interface SetAssetTransferBlacklistInstruction {
  SetAssetTransferBlacklist: {
    account_id: string;
    asset_definition_id: string;
    blacklisted: boolean;
  };
}

/** Set or clear the outbound-transfer blacklist for one account and asset. */
export function buildSetAssetTransferBlacklistInstruction(options: {
  accountId: string;
  assetDefinitionId: string;
  blacklisted: boolean;
}): SetAssetTransferBlacklistInstruction;

/** Canonical app-API spelling for an outbound transfer-cap window. */
export type AssetTransferControlWindow = "DAY" | "WEEK" | "MONTH";

/** Exact Rust enum spelling carried by a native Norito instruction value. */
export type AssetTransferControlWindowWire = "Day" | "Week" | "Month";

export interface AssetTransferLimitInput {
  window: AssetTransferControlWindow;
  /** Null clears the cap for this window. */
  capAmount: QuantityInput | null;
}

export interface AssetTransferLimit {
  window: AssetTransferControlWindowWire;
  cap_amount: string | null;
}

export interface SetAssetTransferControlInstruction {
  SetAssetTransferControl: {
    account_id: string;
    asset_definition_id: string;
    limits: AssetTransferLimit[];
  };
}

/**
 * Replace outbound transfer caps. Limits are unique and returned in canonical
 * DAY/WEEK/MONTH order; an empty list clears every cap.
 */
export function buildSetAssetTransferControlInstruction(options: {
  accountId: string;
  assetDefinitionId: string;
  limits: readonly AssetTransferLimitInput[];
}): SetAssetTransferControlInstruction;

/**
 * Build a `Mint::Asset` instruction payload with deterministic quantity
 * normalisation.
 */
export function buildMintAssetInstruction({
  assetId,
  quantity,
}: {
  assetId: string;
  quantity: QuantityInput;
}): object;

/**
 * Build a `Burn::Asset` instruction payload mirroring runtime validation in
 * {@link buildBurnAssetTransaction}.
 */
export function buildBurnAssetInstruction({
  assetId,
  quantity,
}: {
  assetId: string;
  quantity: QuantityInput;
}): object;

/**
 * Build a `Mint::TriggerRepetitions` instruction payload. Repetitions must be
 * a positive integer; fractional values throw at runtime.
 */
export function buildMintTriggerRepetitionsInstruction({
  triggerId,
  repetitions,
}: {
  triggerId: string;
  repetitions: NumericLike;
}): object;

/**
 * Build a `Burn::TriggerRepetitions` instruction payload mirroring runtime
 * validation in {@link buildBurnTriggerTransaction}. Repetitions must be a
 * positive integer.
 */
export function buildBurnTriggerRepetitionsInstruction({
  triggerId,
  repetitions,
}: {
  triggerId: string;
  repetitions: NumericLike;
}): object;

export function buildRegisterDomainInstruction({
  domainId,
  logo,
  metadata,
}: {
  domainId: string;
  logo?: string | null;
  metadata?: object | null;
}): object;

export function buildRegisterAccountInstruction({
  accountId,
  metadata,
}: {
  accountId: string;
  metadata?: object | null;
}): object;

export function buildRegisterAssetDefinitionInstruction(options: {
  assetDefinitionId?: string;
  asset_definition_id?: string;
  id?: string;
  name: string;
  description?: string | null;
  alias?: string | null;
  logo?: string | null;
  scale?: NumericLike | null;
  mintable?: string;
  mintOnce?: boolean;
  metadata?: object | null;
  balanceScopePolicy: string;
  balance_scope_policy?: string;
  /** Immutable ownership intent; null means intentionally unowned global. */
  owningDomain: string | null;
}): object;

/** Exact JSON text preserves 64-bit dataspace IDs across the native signing boundary. */
export function buildActivateRetailDailyLimitV1InstructionJson(options: {
  definition: {
    id: string;
    name: string;
    description: string | null;
    alias: string | null;
    spec: { scale: 2 };
    mintable: "Infinitely";
    logo: string | null;
    metadata: Record<string, never>;
    balance_scope_policy: "DataspaceRestricted";
    owning_domain: string;
  };
  policy: {
    asset_definition_id: string;
    physical_dataspace: number | string | bigint;
    revision: number | string | bigint;
    daily_cap: string;
    identity_issuer: string;
    identity_issuer_public_key: string;
    monetary_issuer_account: string;
    reserve_account: string;
    institutional_exceptions: [];
  };
}): string;

/** Wrap an issuer-signed identity attestation without creating signing material. */
export function buildBindRetailIdentityV1InstructionJson(options: {
  attestation: {
    body: {
      domain: "iroha.bpng.retail-identity.v1";
      asset_definition_id: string;
      physical_dataspace: number | string | bigint;
      policy_revision: number | string | bigint;
      account_id: string;
      identity: { digest: ReadonlyArray<number> };
      uniqueness_evidence_digest: ReadonlyArray<number>;
    };
    signature: string;
  };
}): string;

/** Build a typed monetary effect; bank receipt authentication remains external. */
export function buildRetailMonetaryMovementV1InstructionJson(options: {
  assetDefinitionId: string;
  purpose: "mint_to_reserve" | "credit_retail" | "defund_retail" | "burn_reserve";
  retailAccount: string | null;
  amount: string;
  operationDigest: ReadonlyArray<number>;
}): string;

export function buildGrantAccountPermissionInstruction(options: {
  accountId?: string;
  destinationAccountId?: string;
  destination?: string;
  permission?: {
    name: string;
    payload?: JsonValue;
  };
  name?: string;
  payload?: JsonValue;
}): object;

export function buildSetAccountKeyValueInstruction(options: {
  accountId: string;
  key: string;
  value: JsonValue;
}): {
  SetKeyValue: {
    Account: {
      object: string;
      key: string;
      value: JsonValue;
    };
  };
};

export function buildSetAssetDefinitionAliasInstruction(options: {
  assetDefinitionId?: string;
  asset_definition_id?: string;
  alias?: string | null;
  leaseExpiryMs?: NumericLike | null;
  lease_expiry_ms?: NumericLike | null;
}): object;

export function buildExecuteTriggerInstruction(
  trigger: string,
  args?: JsonValue,
): ExecuteTriggerInstructionPayload;
export function buildExecuteTriggerInstruction(options: {
  trigger: string;
  args?: JsonValue;
}): ExecuteTriggerInstructionPayload;
export function buildExecuteTriggerNorito(
  trigger: string | { trigger: string; args?: JsonValue },
  networkPrefix: number,
  args?: JsonValue,
): Buffer;

export function buildMultisigTriggerArgs(
  preset: "lifecycle",
  input: MultisigLifecycleTriggerArgsInput,
): {
  action: string;
  request_id: string;
  fi_id?: string;
  to_account_id?: string;
  amount_i64?: number;
  requested_by_actor_id?: JsonValue;
  created_at_ms?: number;
  expires_at_ms?: number;
};
export function buildMultisigTriggerArgs(
  preset: "lookup",
  input: MultisigLookupTriggerArgsInput,
): {
  request_id: string;
  requested_by_actor_id?: JsonValue;
};

export function isMultisigSignerAuthorized(
  spec: MultisigSpecLike,
  signerAccountId: string,
): boolean;

export function buildMultisigExecuteTriggerInstruction(
  options: MultisigExecuteTriggerOptions,
): ExecuteTriggerInstructionPayload;
export function buildMultisigExecuteTriggerNorito(
  options: MultisigExecuteTriggerOptions,
  networkPrefix: number,
): Buffer;

/**
 * Build a multisig registration instruction payload.
 */
export function buildRegisterMultisigInstruction({
  accountId,
  spec,
}: {
  accountId: string;
  spec: MultisigSpecLike;
}): object;

/**
 * Build a multisig proposal payload while enforcing the policy TTL cap.
 */
export function buildProposeMultisigInstruction({
  accountId,
  instructions,
  spec,
  transactionTtlMs,
}: {
  accountId: string;
  instructions: ReadonlyArray<object>;
  spec: MultisigSpecLike;
  transactionTtlMs?: number | null;
}): object;

export function buildProposeMultisigExecuteTriggerInstruction(
  options: ProposeMultisigExecuteTriggerOptions,
): object;
export function buildProposeMultisigExecuteTriggerNorito(
  options: ProposeMultisigExecuteTriggerOptions,
  networkPrefix: number,
): Buffer;

export function buildMultisigProposeRequest(
  options: MultisigProposeRequest,
): MultisigProposePayload;

export function buildMultisigContractCallProposeRequest(
  options: MultisigContractCallProposeRequest & {
    trigger: string;
    args?: JsonValue;
    argPreset?: MultisigTriggerArgsPreset;
    preset?: MultisigTriggerArgsPreset;
    argInput?:
      | MultisigLifecycleTriggerArgsInput
      | MultisigLookupTriggerArgsInput;
    presetInput?:
      | MultisigLifecycleTriggerArgsInput
      | MultisigLookupTriggerArgsInput;
    multisigSpec?: MultisigSpecLike;
    spec?: MultisigSpecLike;
    strictSignerCheck?: boolean;
  },
): MultisigContractCallProposePayload;

export function buildMultisigContractCallApproveRequest(
  options: MultisigContractCallApproveRequest,
): MultisigContractCallApprovePayload;

export function buildTransferAssetInstruction({
  sourceAssetHoldingId,
  quantity,
  destinationAccountId,
}: {
  sourceAssetHoldingId: string;
  quantity: QuantityInput;
  destinationAccountId: string;
}): object;

export function buildTransferDomainInstruction({
  sourceAccountId,
  domainId,
  destinationAccountId,
}: {
  sourceAccountId: string;
  domainId: string;
  destinationAccountId: string;
}): object;

export function buildTransferAssetDefinitionInstruction({
  sourceAccountId,
  assetDefinitionId,
  destinationAccountId,
}: {
  sourceAccountId: string;
  assetDefinitionId: string;
  destinationAccountId: string;
}): object;

export function buildTransferNftInstruction({
  sourceAccountId,
  nftId,
  destinationAccountId,
}: {
  sourceAccountId: string;
  nftId: string;
  destinationAccountId: string;
}): object;

export function buildRegisterRwaInstruction(
  options:
    | {
        rwa?: RegisterRwaPayloadInput | string;
        rwaJson?: RegisterRwaPayloadInput | string;
      }
    | RegisterRwaPayloadInput,
): object;

export function buildTransferRwaInstruction({
  sourceAccountId,
  rwaId,
  quantity,
  destinationAccountId,
}: {
  sourceAccountId: string;
  rwaId: string;
  quantity: QuantityInput;
  destinationAccountId: string;
}): object;

export function buildMergeRwasInstruction(
  options:
    | {
        merge?: MergeRwasPayloadInput | string;
        mergeJson?: MergeRwasPayloadInput | string;
      }
    | MergeRwasPayloadInput,
): object;

export function buildRedeemRwaInstruction({
  rwaId,
  quantity,
}: {
  rwaId: string;
  quantity: QuantityInput;
}): object;

export function buildFreezeRwaInstruction({ rwaId }: { rwaId: string }): object;

export function buildUnfreezeRwaInstruction({
  rwaId,
}: {
  rwaId: string;
}): object;

export function buildHoldRwaInstruction({
  rwaId,
  quantity,
}: {
  rwaId: string;
  quantity: QuantityInput;
}): object;

export function buildReleaseRwaInstruction({
  rwaId,
  quantity,
}: {
  rwaId: string;
  quantity: QuantityInput;
}): object;

export function buildForceTransferRwaInstruction({
  rwaId,
  quantity,
  destinationAccountId,
}: {
  rwaId: string;
  quantity: QuantityInput;
  destinationAccountId: string;
}): object;

export function buildSetRwaControlsInstruction(options: {
  rwaId: string;
  controls?: RwaControlPolicyInput | string;
  controlsJson?: RwaControlPolicyInput | string;
}): object;

export function buildSetRwaKeyValueInstruction({
  rwaId,
  key,
  value,
}: {
  rwaId: string;
  key: string;
  value: JsonValue;
}): object;

export function buildRemoveRwaKeyValueInstruction({
  rwaId,
  key,
}: {
  rwaId: string;
  key: string;
}): object;

export function buildCreateKaigiInstruction(call: CreateKaigiInput): object;

export function buildJoinKaigiInstruction(join: JoinKaigiInput): object;

export function buildLeaveKaigiInstruction(leave: LeaveKaigiInput): object;

export function buildEndKaigiInstruction(end: EndKaigiInput): object;

export function buildRecordKaigiUsageInstruction(
  usage: RecordKaigiUsageInput,
): object;

export function buildSetKaigiRelayManifestInstruction(
  manifest: SetKaigiRelayManifestInput,
): object;

export function buildRegisterKaigiRelayInstruction(
  relay: RegisterKaigiRelayInput,
): object;

export function buildUnregisterKaigiRelayInstruction(
  input: UnregisterKaigiRelayInput,
): object;

export function buildReportKaigiRelayHealthInstruction(
  report: ReportKaigiRelayHealthInput,
): object;

export function buildProposeDeployContractInstruction(
  input: ProposeDeployContractInstructionInput,
): object;

export function buildCastZkBallotInstruction(
  input: CastZkBallotInstructionInput,
): object;

export function buildCastPlainBallotInstruction(
  input: CastPlainBallotInstructionInput,
): object;
export function buildUpdatePlainConvictionInstruction(
  input: UpdatePlainConvictionInstructionInput,
): object;

export function buildSubmitAgendaProposalInstruction(input: {
  proposal: Record<string, unknown>;
}): object;

export interface ClaimTwitterFollowRewardInstructionInput {
  bindingHash:
    | {
        pepper_id?: string;
        pepperId?: string;
        pepper?: string;
        digest?: string | ArrayBufferView | ArrayBuffer | Buffer;
        hash?: string | ArrayBufferView | ArrayBuffer | Buffer;
        value?: string | ArrayBufferView | ArrayBuffer | Buffer;
      }
    | Record<string, unknown>;
}

export interface SendToTwitterInstructionInput {
  bindingHash:
    | {
        pepper_id?: string;
        pepperId?: string;
        pepper?: string;
        digest?: string | ArrayBufferView | ArrayBuffer | Buffer;
        hash?: string | ArrayBufferView | ArrayBuffer | Buffer;
        value?: string | ArrayBufferView | ArrayBuffer | Buffer;
      }
    | Record<string, unknown>;
  amount: QuantityInput;
}

export interface CancelTwitterEscrowInstructionInput {
  bindingHash:
    | {
        pepper_id?: string;
        pepperId?: string;
        pepper?: string;
        digest?: string | ArrayBufferView | ArrayBuffer | Buffer;
        hash?: string | ArrayBufferView | ArrayBuffer | Buffer;
        value?: string | ArrayBufferView | ArrayBuffer | Buffer;
      }
    | Record<string, unknown>;
}

export function buildClaimTwitterFollowRewardInstruction(
  input: ClaimTwitterFollowRewardInstructionInput,
): object;

export function buildSendToTwitterInstruction(
  input: SendToTwitterInstructionInput,
): object;

export function buildCancelTwitterEscrowInstruction(
  input: CancelTwitterEscrowInstructionInput,
): object;

export function buildRegisterZkAssetInstruction(
  input: RegisterZkAssetInstructionInput,
): object;

export function buildScheduleConfidentialPolicyTransitionInstruction(
  input: ScheduleConfidentialPolicyTransitionInstructionInput,
): object;

export function buildCancelConfidentialPolicyTransitionInstruction(
  input: CancelConfidentialPolicyTransitionInstructionInput,
): object;

export function buildCreateElectionInstruction(
  input: CreateElectionInstructionInput,
): object;

export function buildSubmitBallotInstruction(
  input: SubmitBallotInstructionInput,
): object;

export function buildFinalizeElectionInstruction(
  input: FinalizeElectionInstructionInput,
): object;

export function buildRegisterSmartContractCodeInstruction(
  input: RegisterSmartContractCodeInstructionInput,
): object;

export function buildRegisterSmartContractBytesInstruction(
  input: RegisterSmartContractBytesInstructionInput,
): object;

export function buildUploadSmartContractCodeChunkInstruction(
  input: UploadSmartContractCodeChunkInstructionInput,
): object;

export function buildFinalizeSmartContractCodeUploadInstruction(
  input: FinalizeSmartContractCodeUploadInstructionInput,
): object;

export function buildCancelSmartContractCodeUploadInstruction(
  input: CancelSmartContractCodeUploadInstructionInput,
): object;

export function buildCommitContractDeploymentInstruction(
  input: CommitContractDeploymentInstructionInput,
): object;

export function buildRemoveSmartContractBytesInstruction(
  input: RemoveSmartContractBytesInstructionInput,
): object;

export const DEFAULT_TORII_CLIENT_CONFIG: {
  timeoutMs: number;
  maxRetries: number;
  backoffInitialMs: number;
  backoffMultiplier: number;
  maxBackoffMs: number;
  retryStatuses: ReadonlyArray<number>;
  retryMethods: ReadonlyArray<string>;
  defaultHeaders: Readonly<Record<string, string>>;
  authToken: string | null;
  apiToken: string | null;
  retryTelemetryHook: ((event: ToriiRetryTelemetryEvent) => void) | null;
  insecureTransportTelemetryHook:
    | ((event: InsecureTransportTelemetryEvent) => void)
    | null;
};

export const DEFAULT_RETRY_PROFILE_PIPELINE: ToriiRetryProfileOptions;

export const DEFAULT_RETRY_PROFILE_STREAMING: ToriiRetryProfileOptions;

export function resolveToriiClientConfig(input?: {
  config?: ToriiClientConfigSource;
  env?: Record<string, string | undefined>;
  overrides?: ToriiClientConfigSource;
}): ResolvedToriiClientConfig;

export function extractToriiFeatureConfig(
  input?: {
    config?: Record<string, unknown>;
  } & Record<string, unknown>,
): ToriiFeatureConfigSnapshot;

export type SoracloudStorageClass = "hot" | "warm" | "cold";

export interface SoracloudHfSharedLeaseJoinDraftInput {
  repoId: string;
  /** Full 40-character lowercase Hugging Face commit OID. */
  revision: string;
  serviceName: string;
  apartmentName: string | null;
  storageClass: SoracloudStorageClass;
  leaseTermMs: number | bigint | string;
  leaseAssetDefinitionId: string;
  baseFee: QuantityInput;
}

export interface SoracloudManifestProvenance {
  signer: string;
  signature: string;
}

export interface SoracloudHfSharedLeaseJoinPayload {
  repo_id: string;
  revision: string;
  service_name: string;
  apartment_name: string | null;
  storage_class: SoracloudStorageClass;
  lease_term_ms: number;
  lease_asset_definition_id: string;
  base_fee: string;
}

export interface SoracloudSigningPayload<
  TPayload,
  TSchema extends string,
  TLabel extends string,
> {
  schema: TSchema;
  label: TLabel;
  payload: TPayload;
}

export interface SoracloudHfSharedLeaseJoinDraft {
  payload: SoracloudHfSharedLeaseJoinPayload;
  provenancePayloads: {
    join: SoracloudSigningPayload<
      SoracloudHfSharedLeaseJoinPayload,
      "soracloud.hf.shared_lease_join.provenance.v1",
      "hf_shared_lease_join"
    >;
  };
}

export interface SoracloudHfSharedLeaseJoinRequest {
  payload: SoracloudHfSharedLeaseJoinDraft["payload"];
  provenance: SoracloudManifestProvenance;
}

export interface SoracloudAppInfraRouteInput {
  path: string;
  publicHost: string | null;
  internalUrl: string | null;
}

export interface SoracloudAppInfraLeaseVolumeInput {
  name: string;
  mountPath: string;
  maxTotalBytes: NumericLike;
  temperature: "hot" | "warm" | "cold";
}

export interface SoracloudAppInfraShardInput {
  count: NumericLike;
  shardIdEnv: string;
  shardCountEnv: string;
}

export interface SoracloudAppInfraServiceInput {
  name: string;
  serviceVersion: string;
  serviceManifestHash: string;
  containerManifestHash: string;
  runtime: "Inrou" | "Ivm";
  executionPlane: "HttpService" | "DeterministicService";
  routes: ReadonlyArray<SoracloudAppInfraRouteInput>;
  leaseVolumes: ReadonlyArray<SoracloudAppInfraLeaseVolumeInput>;
  shards: SoracloudAppInfraShardInput | null;
}

export interface SoracloudAppInfraStaticSiteInput {
  publicUrl: string;
  contentCid: string | null;
  manifestDigestHex: string | null;
  mountPath: string;
  apiBasePath: string | null;
}

export interface SoracloudAppInfraDraftInput {
  appName: string;
  appVersion: string;
  publicUrl: string;
  staticSite: SoracloudAppInfraStaticSiteInput | null;
  services: ReadonlyArray<SoracloudAppInfraServiceInput>;
}

export interface SoracloudAppInfraRouteV1 {
  schema_version: 1;
  public_host: string | null;
  path_prefix: string;
  internal_url: string | null;
}

export interface SoracloudAppInfraStaticSiteV1 {
  schema_version: 1;
  public_url: string;
  content_cid: string | null;
  manifest_digest_hex: string | null;
  mount_path: string;
  api_base_path: string | null;
}

export interface SoracloudAppInfraServiceV1 {
  schema_version: 1;
  service_name: string;
  service_version: string;
  service_manifest_hash: string;
  container_manifest_hash: string;
  execution_plane: {
    execution_plane: "HttpService" | "DeterministicService";
    value: null;
  };
  runtime: { runtime: "Inrou" | "Ivm"; value: null };
  routes: SoracloudAppInfraRouteV1[];
  lease_volumes: string[];
  shard: string | null;
}

export interface SoracloudAppInfraPayload {
  schema_version: 1;
  app_name: string;
  app_version: string;
  public_url: string;
  static_site: SoracloudAppInfraStaticSiteV1 | null;
  services: SoracloudAppInfraServiceV1[];
}

export interface SoracloudAppInfraDraft {
  payload: SoracloudAppInfraPayload;
  provenancePayloads: {
    deploy: SoracloudSigningPayload<
      SoracloudAppInfraPayload,
      "soracloud.app.infra.provenance.v1",
      "app_infra_deploy"
    >;
    services: Array<
      SoracloudSigningPayload<
        SoracloudAppInfraServiceV1,
        "soracloud.app.infra.provenance.v1",
        "app_infra_service"
      >
    >;
  };
}

export interface SoracloudAppReportPhaseV1 {
  name:
    | "build"
    | "sync_manifests"
    | "doctor"
    | "publish"
    | "sign"
    | "submit"
    | "status"
    | "verify";
  ok: boolean;
  skipped: boolean;
  diagnostics: string[];
}

export interface SoracloudAppReportServiceV1 {
  service_name: string;
  execution_plane: string;
  runtime: string;
}

export interface SoracloudAppReportV1 {
  schema_version: "soracloud.app.report.v1";
  app_name: string;
  manifest_path: string;
  ok: boolean;
  phases: SoracloudAppReportPhaseV1[];
  app_infra_manifest_hash?: string;
  routes: Array<Record<string, unknown>>;
  services: SoracloudAppReportServiceV1[];
  static_site?: Record<string, unknown>;
  blockers: string[];
  next_action: string;
}

export function buildSoracloudHfSharedLeaseJoinDraft(
  input: SoracloudHfSharedLeaseJoinDraftInput,
): SoracloudHfSharedLeaseJoinDraft;

export function buildSoracloudAppInfraDraft(
  input: SoracloudAppInfraDraftInput,
): SoracloudAppInfraDraft;

export interface SoracloudAppInfraRequest {
  deploy_services: unknown[];
  upgrade_services: unknown[];
  manifest: SoracloudAppInfraDraft["payload"];
  provenance: SoracloudManifestProvenance;
}

export interface SoracloudMutationDraftResponseV1 {
  ok: true;
  authority: string;
  signed_by: string;
  tx_instructions: [SoracloudTxInstruction, ...SoracloudTxInstruction[]];
}

export interface SoracloudAppInfraStateV1 {
  schema_version: 1;
  app_name: string;
  current_app_version: string;
  current_manifest_hash: string;
  revision_count: number;
  deployed_sequence: number;
  updated_sequence: number;
  manifest: SoracloudAppInfraPayload;
}

export interface SoracloudAppInfraAuditEventV1 {
  schema_version: 1;
  sequence: number;
  action: { action: "Deploy" | "Upgrade"; value: null };
  app_name: string;
  from_version: string | null;
  to_version: string;
  app_manifest_hash: string;
  service_count: number;
  signer: string;
}

export interface SoracloudAppInfraStatusResponseV1 {
  schema_version: 1;
  app_count: number;
  audit_event_count: number;
  apps: SoracloudAppInfraStateV1[];
  recent_audit_events: SoracloudAppInfraAuditEventV1[];
}

export function assembleSoracloudAppInfraRequest(
  draft: SoracloudAppInfraDraft,
  provenances: { deploy: SoracloudManifestProvenance },
  options: { deployServices: unknown[]; upgradeServices: unknown[] },
): SoracloudAppInfraRequest;

export function deploySoracloudAppInfraInstruction(
  manifest: Record<string, unknown>,
  provenance: SoracloudManifestProvenance,
): { wire_id: string; payload: Record<string, unknown> };

export function upgradeSoracloudAppInfraInstruction(
  manifest: Record<string, unknown>,
  provenance: SoracloudManifestProvenance,
): { wire_id: string; payload: Record<string, unknown> };

export function assembleSoracloudHfSharedLeaseJoinRequest(
  draft: SoracloudHfSharedLeaseJoinDraft,
  provenances: { join: SoracloudManifestProvenance },
): SoracloudHfSharedLeaseJoinRequest;

export interface SoracloudTxInstruction {
  wire_id: string;
  /** Non-empty lowercase hexadecimal with an even number of digits. */
  payload_hex: string;
}

export interface SoracloudUploadedModelBundleV1 {
  schema_version: 1;
  service_name: string;
  model_id: string;
  weight_version: string;
  family: string;
  modalities: string[];
  plaintext_root: string;
  package_format: {
    package_format: "NormalizedHuggingFaceSafetensorsV1";
    value: null;
  };
  bundle_root: string;
  sorafs_manifest_digest: number[];
  chunk_count: number;
  plaintext_bytes: number;
  ciphertext_bytes: number;
  chunk_manifest_root: string;
  pricing_policy: { storage_price: unknown };
}

export interface SoracloudModelArtifactStatusEntryV1 {
  service_name: string;
  model_name: string;
  artifact_id: string;
  training_job_id: string;
  weight_version: string | null;
  weight_artifact_hash: string;
  dataset_ref: string;
  training_config_hash: string;
  reproducibility_hash: string;
  provenance_attestation_hash: string;
  registered_sequence: number;
  consumed_by_version: string | null;
  chunk_manifest_root: string | null;
}

export interface SoracloudUploadedModelStatusV1 {
  schema_version: 1;
  bundle: SoracloudUploadedModelBundleV1;
  artifact: SoracloudModelArtifactStatusEntryV1 | null;
}

export class NumericV1Error extends Error {
  readonly code: string;
}

export class KotodamaInt {
  constructor(value: bigint | string);
  readonly value: bigint;
  toString(): string;
}

export class KotodamaDecimal {
  constructor(value: string);
  constructor(mantissa: bigint | string, scale: number);
  readonly mantissa: bigint;
  readonly scale: number;
  toString(): string;
}

export class KotodamaQuantity {
  constructor(value: string);
  constructor(mantissa: bigint | string, scale: number);
  readonly mantissa: bigint;
  readonly scale: number;
  toString(): string;
}

export const NumericV1: {
  readonly INT_MIN: bigint;
  readonly INT_MAX: bigint;
  readonly MAX_MANTISSA_BYTES: 64;
  readonly MAX_SCALE: 28;
  // BEGIN GENERATED: kotodama-v1-numeric-policy
  readonly schemas: {
    readonly int: {
      readonly name: "iroha.numeric.IntValueV1";
      readonly hash: string;
      readonly pointerType: 0x0011;
      readonly scaled: false;
    };
    readonly decimal: {
      readonly name: "iroha.numeric.DecimalValueV1";
      readonly hash: string;
      readonly pointerType: 0x0012;
      readonly scaled: true;
    };
    readonly quantity: {
      readonly name: "iroha.numeric.QuantityValueV1";
      readonly hash: string;
      readonly pointerType: 0x0010;
      readonly scaled: true;
    };
  };
  // END GENERATED: kotodama-v1-numeric-policy
  encodeIntFrame(value: KotodamaInt | bigint | string): Uint8Array;
  encodeDecimalFrame(value: KotodamaDecimal | string): Uint8Array;
  encodeQuantityFrame(value: KotodamaQuantity | bigint | string): Uint8Array;
  decodeIntFrame(value: ArrayBuffer | ArrayBufferView): KotodamaInt;
  decodeDecimalFrame(value: ArrayBuffer | ArrayBufferView): KotodamaDecimal;
  decodeQuantityFrame(value: ArrayBuffer | ArrayBufferView): KotodamaQuantity;
  encodeIntEnvelope(value: KotodamaInt | bigint | string): Uint8Array;
  encodeDecimalEnvelope(value: KotodamaDecimal | string): Uint8Array;
  encodeQuantityEnvelope(value: KotodamaQuantity | bigint | string): Uint8Array;
  decodeIntEnvelope(value: ArrayBuffer | ArrayBufferView): KotodamaInt;
  decodeDecimalEnvelope(value: ArrayBuffer | ArrayBufferView): KotodamaDecimal;
  decodeQuantityEnvelope(value: ArrayBuffer | ArrayBufferView): KotodamaQuantity;
  encodeIntJson(value: KotodamaInt | bigint | string): string;
  encodeDecimalJson(value: KotodamaDecimal | string): string;
  encodeQuantityJson(value: KotodamaQuantity | bigint | string): string;
  decodeIntJson(value: string): KotodamaInt;
  decodeDecimalJson(value: string): KotodamaDecimal;
  decodeQuantityJson(value: string): KotodamaQuantity;
};

export * from "./nexus-app.js";
export * from "./transaction-codec.js";
export * from "./smart-contract-deployment.js";

/** Exact independently reviewed target and canonical native argument record. */
export interface CanonicalMultisigContractCallInput {
  multisig_account_id: string;
  contract_address: string;
  contract_alias: string;
  entrypoint: string;
  payload: Record<string, unknown>;
  arguments_hex: string | null;
  code_hash_hex: string;
  /** Positive creation_time_ms of the exact frozen native Propose attempt. */
  creation_time_ms: number;
}
/** Construction only; never evidence of deployment, permission or finality. */
export function buildCanonicalMultisigContractCall(
  input: CanonicalMultisigContractCallInput,
  networkPrefix: number,
): {
  instructions: Array<Record<string, unknown>>;
  instructions_hash: string;
  metadata: Record<string, unknown>;
};

/** Public output of a locally verified confidential proof; ledger admission is separate. */
export interface ConfidentialProof extends ConfidentialTransferProofResultV2 {
  relation: "confidential-transfer" | "confidential-redemption" | "confidential-redemption-with-change";
}

/** Common authenticated tree snapshot and one or two actual private notes. */
export interface ConfidentialSpend {
  treeCommitments: ReadonlyArray<BinaryLike>;
  rootHex: string;
  inputs: ConfidentialProofInputsV2;
}

export class ConfidentialProverError extends Error {
  readonly code: "INVALID_INPUT" | "NATIVE_UNAVAILABLE" | "PROVING_FAILED" | "DISPOSED";
}

/** Local wallet prover with automatic circuit/key selection and native self-verification.
 * Native proof work runs off the JavaScript thread. Owns a key copy until dispose();
 * already queued jobs finish independently. Callers own their original key.
 */
export class ConfidentialProver {
  constructor(options: { networkId: NetworkId; assetDefinitionId: string; spendKey: Uint8Array });
  dispose(): void;
  proveTransfer(request: ConfidentialSpend & { outputs: ConfidentialTransferProofOutputsV2 }): Promise<ConfidentialProof>;
  proveRedemption(request: ConfidentialSpend & { publicAmount: NumericLike; change?: ConfidentialUnshieldProofOutputV3 }): Promise<ConfidentialProof>;
}

/** Compute the fixed-depth local commitment-history root in native Core.
 * Accepts at most 65,536 commitments; the result does not authenticate ledger state.
 */
export function computeConfidentialRoot(options: { commitments: ReadonlyArray<BinaryLike> }): Promise<Buffer>;

/** Native canonical default diversifier used by redemption change. Returns a defensive copy. */
export function defaultConfidentialDiversifier(): Buffer;
/** Construct a later input from retained change and its authenticated leaf index.
 * Does not consume the opening or authenticate membership. Private strings remain caller-owned.
 */
export function confidentialChangeToInput(change: ConfidentialUnshieldProofOutputV3, leafIndex: number): ConfidentialTransferProofInputV2;


export interface RetailFeeScheduleV1 {
  included_payments: number;
  overage_minor: number | bigint;
  maintenance_tiers: Array<{ minimum_average_balance_minor: number | bigint; monthly_fee_minor: number | bigint }>;
}



export interface ValidationFeeRewardCustodyV1 {
  contract_address: string;
  treasury_account_id: string;
  ds_asset_id: string;
  xor_asset_id: string;
  reward_pool_account_id: string;
  validator_lane_id: number;
}



export interface ValidationFeeVerifiedConversionPolicyV1 {
  readonly revision: number | bigint;
  readonly binding: Readonly<ToriiGovernanceValidationFeePayoutBinding>;
  readonly authority: Readonly<ValidationFeeVerifiedParliamentProposalV1>;
  readonly lifecycle_seal_hash: string;
}



/** Canonical wallet intent; counters are supplied exclusively by the ledger. */
export interface RetailFeeQuoteRequestV1 {
  account_id: string;
  asset_definition_id: string;
  transfers: Array<{ destination_account_id: string; amount_minor_units: number | string | bigint }>;
}


/** Canonical assessment DATA; ledger admission binds its exact intent and authenticated state. */
export interface RetailFeeAssessmentV1 {
  account_id: string;
  retail_enrolled: boolean;
  billing_month_start_ms: number | bigint;
  policy_revision: number | bigint;
  payments_used_before: number | bigint;
  qualifying_payments: number | bigint;
  fee_minor: number | bigint;
  state_commitment: string;
  intent_hash: string;
  expires_at_ms: number | bigint;
}


export function encodeRetailFeeQuoteRequestV1(request: RetailFeeQuoteRequestV1): Buffer;


export function retailFeePaymentIntentHash(request: RetailFeeQuoteRequestV1): Uint8Array;


export function encodeRetailFeeAssessmentV1(assessment: RetailFeeAssessmentV1): Buffer;


export function retailFeeAssessmentMarkerMessage(assessment: RetailFeeAssessmentV1): string;



export function decodeRetailFeeAssessmentMarkerMessage(message: string): RetailFeeAssessmentV1;

/** Exact canonical bare staking values. Native execution authenticates all ledger bindings. */
export type StakingUnsignedV1 = bigint | number | string;
export type StakingScopeV1 = { kind: "genesis"; value: null } | { kind: "network"; value: NetworkId };
export type StakingAssetScopeV1 = { kind: "global"; value: null } | { kind: "dataspace"; value: StakingUnsignedV1 };
export interface StakingAssetIdV1 { account: string; definition: string; scope: StakingAssetScopeV1; }
export interface StakingPeerIdV1 { public_key: string; }
export type StakingMonetaryPreconditionV1 =
  | { kind: "registration"; value: { activation_height: StakingUnsignedV1 } }
  | { kind: "bond"; value: { activation_height: StakingUnsignedV1; peer_id: StakingPeerIdV1 } }
  | { kind: "unbond"; value: { activation_height: StakingUnsignedV1; request_hash: string } }
  | { kind: "slash"; value: { activation_height: StakingUnsignedV1; slashable_exposure: string } };
export interface StakingMonetaryPlanV1 {
  network_scope: StakingScopeV1; valid_until_height: StakingUnsignedV1;
  source_asset: StakingAssetIdV1; destination_asset: StakingAssetIdV1;
  amount: string; precondition: StakingMonetaryPreconditionV1;
}
export interface StakingRewardClaimStateV1 { through_epoch: StakingUnsignedV1 | null; }
export interface StakingRewardRecordRefV1 { epoch: StakingUnsignedV1; record_hash: string; }
export interface StakingRewardClaimSourceV1 {
  source_asset: StakingAssetIdV1; destination_asset: StakingAssetIdV1;
  expected_accrued: string | null; payout: string;
}
export interface StakingFeeRewardClaimV1 {
  lifecycle_seal: Uint8Array; beneficiary_id: string; beneficiary_revision: StakingUnsignedV1;
  source_asset: StakingAssetIdV1; destination_asset: StakingAssetIdV1;
  amount: string; expected_claim_sequence: StakingUnsignedV1;
}
export interface StakingRewardClaimPlanV1 {
  network_scope: StakingScopeV1; valid_until_height: StakingUnsignedV1;
  expected_state: StakingRewardClaimStateV1 | null; records: StakingRewardRecordRefV1[];
  sources: StakingRewardClaimSourceV1[]; fee_claim: StakingFeeRewardClaimV1 | null;
}
export interface StakingValidatorKeysV1 { validator: StakingPeerIdV1; eq_proof_public_key: Uint8Array; ep_proof_public_key: Uint8Array; }
export interface StakingAuthorityGenerationV1 {
  version: StakingUnsignedV1; network_id: NetworkId; generation: StakingUnsignedV1; validators: StakingValidatorKeysV1[];
}
export interface StakingEpochAuthorizationV1 {
  version: StakingUnsignedV1; network_id: NetworkId; epoch: StakingUnsignedV1;
  first_height: StakingUnsignedV1; last_height: StakingUnsignedV1; authority_generation: StakingUnsignedV1;
  authority_id: Uint8Array;
  beacon: { kind: "bootstrap"; value: null } | { kind: "installed"; value: { session_id: Uint8Array; transcript_hash: Uint8Array } };
  previous_authorization_id: Uint8Array; transition_id: Uint8Array;
  decision: { kind: "genesis" | "activate" | "retain" | "retain_and_cancel"; value: null };
}
export interface ValidatorStakingValueMapV1 {
  PreparationRequest: StakingPreparationRequestV1; Preparation: StakingPreparationV1;
  MonetaryPlan: StakingMonetaryPlanV1; RewardClaimPlan: StakingRewardClaimPlanV1;
  AuthorityGeneration: StakingAuthorityGenerationV1; EpochAuthorization: StakingEpochAuthorizationV1;
}
/** u64 values decode as bigint; explicit optional fields never default to null. */
export function encodeValidatorStakingValueV1<K extends keyof ValidatorStakingValueMapV1>(name: K, value: ValidatorStakingValueMapV1[K]): Buffer;
export function decodeValidatorStakingValueV1<K extends keyof ValidatorStakingValueMapV1>(name: K, payload: Uint8Array): ValidatorStakingValueMapV1[K];

/** Bounded exact intent; no transaction is signed or submitted. */
export type StakingPreparationOperationV1 =
  | { kind: "registration"; value: { validator: string; peer_id: StakingPeerIdV1; amount: string; candidate: boolean } }
  | { kind: "bond"; value: { validator: string; staker: string; amount: string } }
  | { kind: "finalize_unbond"; value: { validator: string; staker: string; request_id: string } }
  | { kind: "claim_rewards"; value: { recipient: string; upto_epoch: StakingUnsignedV1 | null; max_records: StakingUnsignedV1; accrued_sources: StakingAssetIdV1[] } };
export interface StakingPreparationRequestV1 { lane_id: StakingUnsignedV1; valid_for_blocks: StakingUnsignedV1; operation: StakingPreparationOperationV1; }
export interface StakingPreparationBalanceV1 { asset: StakingAssetIdV1; balance: string; stake_reserved: string; rewards_reserved: string; }
/** Coherent server observation; the reported block identity is not a state proof. */
export interface StakingPreparationV1 {
  request: StakingPreparationRequestV1; network_id: NetworkId; observed_height: StakingUnsignedV1;
  observed_block_hash: string; observed_ledger_time_ms: StakingUnsignedV1; assumed_execution_height: StakingUnsignedV1;
  xor_asset_definition_id: string; plan: { kind: "monetary"; value: StakingMonetaryPlanV1 } | { kind: "claim"; value: StakingRewardClaimPlanV1 };
  balances: StakingPreparationBalanceV1[];
}
export function encodeValidatorStakingPreparationFrameV1<K extends "PreparationRequest" | "Preparation">(name: K, value: ValidatorStakingValueMapV1[K]): Buffer;
export function decodeValidatorStakingPreparationFrameV1<K extends "PreparationRequest" | "Preparation">(name: K, payload: Uint8Array): ValidatorStakingValueMapV1[K];
export function validateValidatorStakingPreparationV1(prepared: StakingPreparationV1, request: StakingPreparationRequestV1, networkId: NetworkId, xorDefinition: string): StakingPreparationV1;
