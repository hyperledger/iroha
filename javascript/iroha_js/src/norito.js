import { contractDeclarationCodecsV1 } from "./noritoContractMetadata.js";
import {
  TEXT_MUST_BE_AN_OBJECT_2,
  TEXT_MUST_CONTAIN,
  TEXT_MUST_BE,
  TEXT_EXCEEDS_THE,
  TEXT_IROHA_DATA_MODEL,
  TEXT_MUST_BE_AN_OBJECT,
  TEXT_USES_UNSUPPORTED,
  TEXT_MUST_CONTAIN_EXACTLY,
  TEXT_MUST_BE_EXACT_STANDARD_BASE64,
  TEXT_MUST_BE_A,
  TEXT_MUST_NOT_CONTAIN,
  COMPACT_LEN_FLAG,
  BufferReader,
  cloneJson,
  normalizeInstructionJsonValue,
  isPublicPlainBallotInstruction,
  exactRegisterDataspaceAssetDefinitionJson,
  parseRegisterDataspaceAssetDefinitionJson,
  validateInstructionObjectNumbers,
  toBuffer,
  encodeStructValue,
  decodeStructFields,
  encodeTupleValue,
  decodeTupleFields,
  encodeOptionValue,
  decodeOptionValue,
  encodeBoolValue,
  decodeBoolValue,
  normalizeFlexibleBytes,
  encodeNameValue,
  decodeNameValue,
  encodeMetadataValue,
  decodeMetadataValue,
  encodeAccountIdValue,
  decodeAccountIdValue,
  encodePublicKeyValue,
  decodePublicKeyValue,
  encodeConstVecU8Value,
  decodeConstVecU8Value,
  encodeEnumTagValue,
  decodeExactStandardBase64,
  assertOnlyObjectKeys,
  encodeU8Value,
  decodeU8Value,
  encodeU16Value,
  decodeU16Value,
  encodeU32Value,
  decodeU32Value,
  encodeNoritoStringValue,
  decodeStringValue,
  encodeNoritoJsonValue,
  readNoritoField,
  encodeNoritoField,
  encodeNoritoVec,
  withNoritoCompactLengths,
  withNoritoLengthFlags,
  decodeNoritoVec,
  schemaHashForTypeName,
  validateNoritoFrame,
  decodeNoritoFrame,
  frameNoritoPayload,
  u32ToLittleEndianBuffer,
  u64ToLittleEndianBuffer,
  normalizeU64Input,
  bigintToSafeNumber,
  encodeUnsignedLeb128,
  decodeUnsignedLeb128,
  assertNonEmptyString,
  assertExactNonEmptyString,
  isPlainObject,
} from "./noritoValueCodecs.js";
import { SORAFS_REPLICATION_ORDER_CHUNKER_HANDLES_V1 } from "./sorafsReplicationProfiles.js";
import { requireNetworkPrefix } from "./networkPrefix.js";
import { createNoritoReplicationOrderValidator } from "./noritoReplicationOrderValidator.js";
import { createNoritoRecordDecoder } from "./noritoRecordDecoder.js";
import { rejectError, rejectRange, rejectType } from "./validationThrow.js";
import { parseStrictLosslessIntegerJson, stringifyStrictLosslessIntegerJson } from "./strictLosslessJson.js";

import { Buffer } from "buffer";
import { BASE58_ALPHABET_TEXT, BASE64_ENCODING, HEX_ENCODING, JS_TYPE_BIGINT, JS_TYPE_FUNCTION, JS_TYPE_OBJECT, JS_TYPE_STRING, UTF8_ENCODING } from "./commonLiterals.js";
import { blake3 } from "@noble/hashes/blake3";

import { blake2b256 } from "./blake2b.js";
import { createBlockProofVerification } from "./blockProofVerification.js";

import { AccountAddress, curveIdFromAlgorithm, ensureCurveIdEnabled, normalizeBytes, validatePublicKeyForCurve } from "./address.js";
import { canonicalizeDomainIdLabel } from "./domainId.js";
import {
  getCurveEntryByPublicKeyMulticodec,
  publicKeyMulticodecForCurveId,
} from "./curveRegistry.js";

import { normalizeAccountId, normalizeAssetId } from "./normalizers.js";
import { normalizeRetailFeeAssessment, rejectUnknownRetailFeeFields } from "./retailFeeAssessment.js";
import {
  defaultNativeRuntime,
  resolveNativeRuntimeBinding,
} from "./nativeRuntime.js";
import {
  createNoritoContractCodecs,
  createNoritoConfidentialMemoCodecs,
} from "./noritoContractCodecs.js";
import {
  createNoritoGovernanceInstructionBoundary,
  parseStrictGovernanceInstructionJson,
} from "./noritoGovernanceBoundary.js";
import { computeHashLiteralCrc } from "./hashLiteralCrc.js";
import { createNoritoStakingCodecs } from "./noritoStakingCodecs.js";
import { createNoritoNftMarketCodecs, NFT_MARKET_INSTRUCTION_NAMES_V1, NFT_MARKET_INSTRUCTION_WIRE_IDS_V1 } from "./noritoNftMarketCodecs.js";
import {createNoritoGameCodecs} from './noritoGameCodecs.js';
import { GAME_INSTRUCTION_NAMES_V1, GAME_INSTRUCTION_WIRE_IDS_V1, gameValueMaximumBytesV1 } from './noritoGameRegistry.js';
import {createNoritoGameInstructionCodecs} from './noritoGameInstructionCodecs.js';
import {createNoritoGameResourceEngine} from './noritoGameResourceEngine.js';
import { KotodamaQuantity, NumericV1 } from "./numericV1.js";
import {
  PRIVACY_EXACT12_TRANSACTION_PAYLOAD_FIELD_NAMES_V1,
  validatePrivacyExact12NetworkBindingsV1,
} from "./privacyExact12Network.js";
import {
  LANE_PRIVACY_MERKLE_MAX_DEPTH,
  PROOF_BOX_MAX_ENCODED_BYTES,
  isPortableVerifyingKeyIdField,
  laneMerkleLeafIndexFitsDepth,
  proofBoxFitsEncodedBudget,
  proofBoxMaxProofBytes,
} from "./proofAttachment.js";

const TEXT_SMART_CONTRACT_CODE = "smart_contract_code::";
const TEXT_MUST_BE_GREATER_THAN_ZERO = " must be greater than zero";

const TEXT_CANCEL_CONFIDENTIAL_POLICY_TRANSITION = "CancelConfidentialPolicyTransition";

const TEXT_ASSET_DEFINITION_ID = "asset_definition_id";
const TEXT_SCHEDULE_CONFIDENTIAL_POLICY_TRANSITION = "ScheduleConfidentialPolicyTransition";

const TEXT_CANONICAL = " canonical ";
const TEXT_EXPECTED_REMAINING_AMOUNT = "expected_remaining_amount";
const TEXT_CARRIES_A_SUBSTITUTED = " carries a substituted ";

const TEXT_TRANSACTION_INTENT_PROJECTION_NORITO_2 = "transactionIntentProjectionNorito";
const TEXT_COMMITMENT = "commitment";

const TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO_3 = "unsignedTransactionPayloadNorito";

const TEXT_EXPIRE_REPLICATION_ORDER_2 = "ExpireReplicationOrder";
const TEXT_SUBMIT_PROOF_INSTRUCTION_NORITO = "submit_proof_instruction_norito";

const TEXT_MUST_NOT_BE = " must not be ";
const TEXT_TRANSACTION_INTENT = "transaction_intent_";
const TEXT_SUBMIT_PROOF_INSTRUCTION_NORITO_2 = "submitProofInstructionNorito";

const TEXT_REGISTER_VERIFYING_KEY = "RegisterVerifyingKey";

const TEXT_MUST_USE_A_NATIVE_HASH_WITH_ITS_MARKER_BIT_SET_2 = " must use a native hash with its marker bit set";
const TEXT_ACCOUNT_ID = "account_id";
const TEXT_SET_ASSET_TRANSFER_BLACKLIST_2 = "SetAssetTransferBlacklist";
const TEXT_REPORT_KAIGI_RELAY_HEALTH = "ReportKaigiRelayHealth";

const TEXT_FINALIZE_ELECTION = "FinalizeElection";
const TEXT_CREATION_TIME_MS = "creation_time_ms";

const TEXT_SET_KAIGI_RELAY_MANIFEST = "SetKaigiRelayManifest";
const TEXT_REGISTER_ZK_ASSET = "RegisterZkAsset";
const TEXT_UPDATE_VERIFYING_KEY = "UpdateVerifyingKey";

const TEXT_COMPLETE_REPLICATION_ORDER_2 = "CompleteReplicationOrder";
const TEXT_CLAIM_TWITTER_FOLLOW_REWARD = "ClaimTwitterFollowReward";

const TEXT_IROHA_DATA_MODEL_ISI = (TEXT_IROHA_DATA_MODEL + "isi::");
const TEXT_IROHA_INSTRUCTION_V1 = "iroha.instruction.v1::";

const TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1 = "PrivacyExact12FixtureBundleV1.";

const TEXT_REPLICATION_ORDER_V1 = "ReplicationOrderV1.";

const TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_DTO = "MultisigContractCallProposeDto.";

const TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1_2 = "PrivacyExact12FixtureBundleV1 ";

const TEXT_MULTISIG_CONTRACT_CALL_APPROVE_DTO = "MultisigContractCallApproveDto.";

const TEXT_NATIVE_GAME_VALUE_EXCEEDS_ITS_COMPILED_PAYLOAD_LIMIT = "native game value exceeds its compiled payload limit";
const TEXT_SORA_FS_BILLING_ACKNOWLEDGEMENT = "SoraFS billing acknowledgement ";
const TEXT_MUST_USE_A_NATIVE_HASH_WITH_ITS_MARKER_BIT_SET = TEXT_MUST_USE_A_NATIVE_HASH_WITH_ITS_MARKER_BIT_SET_2;

const TEXT_ISSUE_REPLICATION_ORDER = "IssueReplicationOrder.";
const TEXT_PAYLOAD_PROOF_AUDIT_PATH_MUST = ".payload.proof.audit_path must ";
const TEXT_MULTISIG_PROPOSE_DTO = "MultisigProposeDtoV1.";

const TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO = ".unsignedTransactionPayloadNorito.";
const TEXT_SIGNED_TRANSACTION_VERSIONED_NORITO = ".signedTransactionVersionedNorito ";

const TEXT_CANCEL_ASSET_LOCK_V1 = "CancelAssetLockV1.";

const TEXT_ENVELOPE_NORITO_CARRIES_A_SUBSTITUTED = (".envelopeNorito" + TEXT_CARRIES_A_SUBSTITUTED);

const TEXT_IS_REQUIRED = " is required";
const TEXT_SIGNED_TRANSACTION_VERSIONED_NORITO_2 = ".signedTransactionVersionedNorito.";
const TEXT_BACKEND = ".backend";

const TEXT_CANCEL_ASSET_LOCK_V1_2 = "CancelAssetLockV1 ";
const TEXT_VALUE_PROGRAM = ".value.program_";

const TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO_DOES_NOT_CONTAIN_THE = ".unsignedTransactionPayloadNorito does not contain the ";

const TEXT_NATIVE_GAME_VALUE_IS_NOT_BYTE_CANONICAL = "native game value is not byte-canonical";

const TEXT_SUBMIT_PROOF_WIRE_ID_MUST_BE = (".submitProofWireId" + TEXT_MUST_BE);
const TEXT_TRANSACTION_INTENT_PROJECTION_NORITO = ("." + TEXT_TRANSACTION_INTENT + "projection_norito");
const TEXT_SUBMIT_PROOF_INSTRUCTION_NORITO_PAYLOAD = ".submitProofInstructionNorito.payload";

const TEXT_CANCEL_ASSET_LOCK = "CancelAssetLock.";
const TEXT_VALUE_CHARGE_LIMITS_MUST = ".value.charge_limits must ";
const TEXT_BLOCK_PROOFS = "BlockProofs.";
const TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO_2 = ".unsigned_transaction_payload_norito";
const TEXT_SIGNED_TRANSACTION = ".signed_transaction_";

// Reuse exact wire names and diagnostic fields throughout this module.

const WIRE_TYPE_CANCEL_ASSET_LOCK = "CancelAssetLock";

const WIRE_FIELD_ASSET_DEFINITION_ID = TEXT_ASSET_DEFINITION_ID;

const WIRE_TYPE_OPEN_VERIFY_ENVELOPE = "OpenVerifyEnvelope";
const WIRE_TYPE_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1 = "PrivacyExact12FixtureBundleV1";

const WIRE_FIELD_EXPECTED_REMAINING_AMOUNT = TEXT_EXPECTED_REMAINING_AMOUNT;

const FIELD_METADATA = "metadata";

const WIRE_FIELD_ORDER_ID = "order_id";

// Norito v1 accepts only fixed-width (0x00) or compact (COMPACT_LEN) per-value prefixes.

const ASSET_DEFINITION_ADDRESS_VERSION = 1;
const BASE58_ALPHABET = BASE58_ALPHABET_TEXT;
const HASH_LITERAL_RE = /^hash:([0-9A-Fa-f]{64})#([0-9A-Fa-f]{4})$/;
const CANONICAL_HASH_LITERAL_RE = /^hash:([0-9A-F]{64})#([0-9A-F]{4})$/;
const MULTIHASH_LITERAL_RE = /^([0-9a-fA-F]+)$/;
const SCHEDULE_CONFIDENTIAL_POLICY_TRANSITION_WIRE_ID =
  ("zk::" + TEXT_SCHEDULE_CONFIDENTIAL_POLICY_TRANSITION);
const CANCEL_CONFIDENTIAL_POLICY_TRANSITION_WIRE_ID =
  ("zk::" + TEXT_CANCEL_CONFIDENTIAL_POLICY_TRANSITION);

const CANCEL_LOCK_REMAINING_CONTEXT = (TEXT_CANCEL_ASSET_LOCK + TEXT_EXPECTED_REMAINING_AMOUNT);
const CANCEL_LOCK_REMAINING_MESSAGE = (TEXT_CANCEL_ASSET_LOCK + "expected_remaining_amount" + TEXT_MUST_BE_GREATER_THAN_ZERO);

const ISSUE_ORDER_ID_CONTEXT = (TEXT_ISSUE_REPLICATION_ORDER + "order_id");

const CANCEL_ASSET_LOCK_WIRE_ID =
  (TEXT_IROHA_INSTRUCTION_V1 + "escrow::CancelAssetLock");
const CANCEL_ASSET_LOCK_INNER_TYPE_NAME =
  `${TEXT_IROHA_DATA_MODEL_ISI}escrow::CancelAssetLock`;
const CANCEL_ASSET_LOCK_V1_SCHEMA_HASH = /* @__PURE__ */ schemaHashForTypeName(
  CANCEL_ASSET_LOCK_INNER_TYPE_NAME,
);
// A transparent 32-byte EscrowId plus one positive signed-512-bit Quantity
// yields an unpadded canonical archive in this exact range. Enforce it before
// CRC work so an oversized attacker-controlled frame cannot make this fixed
// schema perform an unbounded payload scan.
const CANCEL_ASSET_LOCK_V1_MIN_ARCHIVE_BYTES = 85;
const CANCEL_ASSET_LOCK_V1_MAX_ARCHIVE_BYTES = 148;
const SET_ASSET_TRANSFER_AVAILABILITY_WIRE_ID =
  "iroha.asset.transfer.availability.set";
const SET_ASSET_TRANSFER_BLACKLIST_WIRE_ID =
  "iroha.asset.transfer.blacklist.set";
const SET_ASSET_TRANSFER_CONTROL_WIRE_ID =
  "iroha.asset.transfer.control.set";

const ISSUE_REPLICATION_ORDER_WIRE_ID =
  (TEXT_IROHA_INSTRUCTION_V1 + "sorafs::IssueReplicationOrder");
const COMPLETE_REPLICATION_ORDER_WIRE_ID =
  (TEXT_IROHA_INSTRUCTION_V1 + "sorafs::" + TEXT_COMPLETE_REPLICATION_ORDER_2);
const EXPIRE_REPLICATION_ORDER_WIRE_ID =
  (TEXT_IROHA_INSTRUCTION_V1 + "sorafs::" + TEXT_EXPIRE_REPLICATION_ORDER_2);
const REPLICATION_ORDER_V1_SCHEMA_HASH = /* @__PURE__ */ schemaHashForTypeName(
  "sorafs_manifest::capacity::ReplicationOrderV1",
);
const SORAFS_REPLICATION_ORDER_MAX_PAYLOAD_BYTES_V1 = 1024 * 1024;

const MULTISIG_PROPOSE_DTO_SCHEMA_HASH = /* @__PURE__ */ schemaHashForTypeName(
  "iroha_torii::routing::MultisigProposeDtoV1",
);
const MULTISIG_CONTRACT_CALL_PROPOSE_DTO_SCHEMA_HASH = /* @__PURE__ */ schemaHashForTypeName(
  "iroha_torii::routing::MultisigContractCallProposeDto",
);
const MULTISIG_CONTRACT_CALL_APPROVE_DTO_SCHEMA_HASH = /* @__PURE__ */ schemaHashForTypeName(
  "iroha_torii::routing::MultisigContractCallApproveDto",
);
const OPEN_VERIFY_ENVELOPE_SCHEMA_HASH = /* @__PURE__ */ schemaHashForTypeName(
  (TEXT_IROHA_DATA_MODEL + "zk::OpenVerifyEnvelope"),
);

export const PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1 =
  "iroha.privacy.exact12-typed-fixture-bundle.v1";
export const PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1 = 2 * 1024 * 1024;
export const PRIVACY_EXACT12_PROTOCOL_IDS_V1 = /* @__PURE__ */ Object.freeze([
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
]);
/** Exact bare-wire magic for `ConfidentialMemoEnvelopeV1`. */
export const CONFIDENTIAL_MEMO_WIRE_MAGIC_V1 = /* @__PURE__ */ Object.freeze([
  0x49, 0x52, 0x48, 0x43, 0x4d, 0x31, 0xa5, 0x5a,
]);
/** Every confidential memo has exactly eight real-or-padding slots. */
export const CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1 = 8;
/** Maximum authenticated memo ciphertext accepted by the V1 wire. */
export const CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1 = 64 * 1024;
const PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_HASH_V1 = /* @__PURE__ */ schemaHashForTypeName(
  PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1,
);
const PRIVACY_EXACT12_STATEMENT_SCHEMA_HASH_V1 = /* @__PURE__ */ schemaHashForTypeName(
  "iroha.privacy.statement.v1",
);
const PRIVACY_EXACT12_ENVELOPE_SCHEMA_HASH_V1 = /* @__PURE__ */ schemaHashForTypeName(
  "iroha.privacy.proof-envelope.v1",
);
const PRIVACY_EXACT12_SUBMIT_PROOF_SCHEMA_HASH_V1 = /* @__PURE__ */ schemaHashForTypeName(
  `${TEXT_IROHA_DATA_MODEL_ISI}privacy::SubmitPrivacyProofV1`,
);
const PRIVACY_EXACT12_TRANSACTION_PAYLOAD_SCHEMA_HASH_V1 = /* @__PURE__ */ schemaHashForTypeName(
  (TEXT_IROHA_DATA_MODEL + "transaction::signed::model::TransactionPayload"),
);
const PRIVACY_EXACT12_SUBMIT_PROOF_WIRE_ID_V1 =
  "iroha.privacy.submit_proof.v1";
const PRIVACY_EXACT12_INTENT_DIGEST_DOMAIN_V1 = /* @__PURE__ */ Buffer.from(
  "iroha.privacy.transaction-intent-digest.v1",
  "ascii",
);
const PRIVACY_EXACT12_ALIGNED_NESTED_FRAME_PADDING_V1 = 8;
const PRIVACY_EXACT12_TRANSACTION_PAYLOAD_FRAME_PADDING_V1 = 0;
const PRIVACY_EXACT12_ROW_FIELD_NAMES_V1 = /* @__PURE__ */ Object.freeze([
  "protocol_id",
  "statement_norito",
  "envelope_norito",
  "submit_proof_wire_id",
  TEXT_SUBMIT_PROOF_INSTRUCTION_NORITO,
  (TEXT_TRANSACTION_INTENT + "projection_norito"),
  (TEXT_TRANSACTION_INTENT + "digest"),
  "unsigned_transaction_payload_norito",
  "signed_transaction_versioned_norito",
  "signed_transaction_hash",
]);
const PRIVACY_EXACT12_PUBLIC_ROW_FIELD_NAMES_V1 = /* @__PURE__ */ Object.freeze([
  "protocolId",
  "statementNorito",
  "envelopeNorito",
  "submitProofWireId",
  TEXT_SUBMIT_PROOF_INSTRUCTION_NORITO_2,
  TEXT_TRANSACTION_INTENT_PROJECTION_NORITO_2,
  "transactionIntentDigest",
  TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO_3,
  "signedTransactionVersionedNorito",
  "signedTransactionHash",
]);
const PRIVACY_EXACT12_ENVELOPE_FIELD_NAMES_V1 = /* @__PURE__ */ Object.freeze([
  "wire_magic",
  ("catalog_" + TEXT_COMMITMENT),
  "protocol_id",
  "proof_system_id",
  "engine_id",
  "parameter_id",
  "parameter_digest",
  "verifier_digest",
  "statement_schema_digest",
  "engine_manifest_digest",
  "statement_digest",
  "statement",
  "proof",
]);
const PRIVACY_EXACT12_WIRE_MAGIC_V1 = /* @__PURE__ */ Buffer.from("4952485a4b31a55a", "hex");
const PRIVACY_EXACT12_CATALOG_COMMITMENT_V1 = /* @__PURE__ */ Buffer.from(
  "e037f13904a0307c00db15d85cfb406bd79772d20144a949def0f3fda78e342e747f65787cbfbffac94f11c369e2bbff",
  "hex",
);
const PRIVACY_EXACT12_PROOF_ENGINE_TAGS_V1 = /* @__PURE__ */ Object.freeze([
  0, 2, 3, 1, 4, 0, 5, 8, 6, 7, 0, 0,
]);
const TRANSACTION_PAYLOAD_BATCH_SCHEMA_HASH = /* @__PURE__ */ schemaHashForTypeName(
  "alloc::vec::Vec<alloc::vec::Vec<u8>>",
);
export const SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_SCHEMA_NAME_V1 =
  "iroha.torii.v1.sorafs.billing.acknowledgement_proof";
const SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_SCHEMA_HASH_V1 =
  /* @__PURE__ */ schemaHashForTypeName(
    SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_SCHEMA_NAME_V1,
  );
export const SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1 =
  64 * 1024;
const CONTRACT_MANIFEST_SIGNATURE_PAYLOAD_SCHEMA_HASH = Buffer.from(
  "b4bb42540d44c468ed44d5f94c59b007",
  HEX_ENCODING,
);
const BLOCK_PROOFS_TYPE_NAME =
  (TEXT_IROHA_DATA_MODEL + "block::proofs::BlockProofs");
const REGISTER_SMART_CONTRACT_CODE_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "RegisterSmartContractCode");
const REGISTER_SMART_CONTRACT_BYTES_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "RegisterSmartContractBytes");
const DEACTIVATE_CONTRACT_INSTANCE_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "DeactivateContractInstance");
const ACTIVATE_CONTRACT_INSTANCE_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "ActivateContractInstance");
const SET_CONTRACT_PARLIAMENT_DELEGATION_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "SetContractParliamentDelegation");
const OFFER_CONTRACT_OWNERSHIP_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "OfferContractOwnership");
const ACCEPT_CONTRACT_OWNERSHIP_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "AcceptContractOwnership");
const CANCEL_CONTRACT_OWNERSHIP_OFFER_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "CancelContractOwnershipOffer");
const COMMIT_CONTRACT_DEPLOYMENT_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "CommitContractDeployment");
const UPLOAD_SMART_CONTRACT_CODE_CHUNK_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "UploadSmartContractCodeChunk");
const FINALIZE_SMART_CONTRACT_CODE_UPLOAD_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "FinalizeSmartContractCodeUpload");
const CANCEL_SMART_CONTRACT_CODE_UPLOAD_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "CancelSmartContractCodeUpload");
const REMOVE_SMART_CONTRACT_BYTES_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + TEXT_SMART_CONTRACT_CODE + "RemoveSmartContractBytes");
const CREATE_KAIGI_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "kaigi::CreateKaigi");
const JOIN_KAIGI_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "kaigi::JoinKaigi");
const LEAVE_KAIGI_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "kaigi::LeaveKaigi");
const END_KAIGI_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "kaigi::EndKaigi");
const RECORD_KAIGI_USAGE_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "kaigi::RecordKaigiUsage");
const SET_KAIGI_RELAY_MANIFEST_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "kaigi::" + TEXT_SET_KAIGI_RELAY_MANIFEST);
const REGISTER_KAIGI_RELAY_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "kaigi::RegisterKaigiRelay");
const UNREGISTER_KAIGI_RELAY_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "kaigi::UnregisterKaigiRelay");
const REPORT_KAIGI_RELAY_HEALTH_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "kaigi::" + TEXT_REPORT_KAIGI_RELAY_HEALTH);
const PROPOSE_DEPLOY_CONTRACT_WIRE_ID =
  (TEXT_IROHA_INSTRUCTION_V1 + "governance::ProposeDeployContract");
const CAST_ZK_BALLOT_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "governance::CastZkBallot");
const CAST_PLAIN_BALLOT_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "governance::CastPlainBallot");
const UPDATE_PLAIN_CONVICTION_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "governance::UpdatePlainConviction");
const CLAIM_TWITTER_FOLLOW_REWARD_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "social::" + TEXT_CLAIM_TWITTER_FOLLOW_REWARD);
const SEND_TO_TWITTER_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "social::SendToTwitter");
const CANCEL_TWITTER_ESCROW_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "social::CancelTwitterEscrow");
const REGISTER_ZK_ASSET_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "zk::" + TEXT_REGISTER_ZK_ASSET);
const CREATE_ELECTION_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "zk::CreateElection");
const SUBMIT_BALLOT_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "zk::SubmitBallot");
const FINALIZE_ELECTION_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "zk::" + TEXT_FINALIZE_ELECTION);
const REGISTER_VERIFYING_KEY_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "verifying_keys::" + TEXT_REGISTER_VERIFYING_KEY);
const UPDATE_VERIFYING_KEY_WIRE_ID = (TEXT_IROHA_INSTRUCTION_V1 + "verifying_keys::" + TEXT_UPDATE_VERIFYING_KEY);
const REGISTER_DATASPACE_ASSET_DEFINITION_WIRE_ID = "iroha.asset_definition.dataspace.register.v1";
const REGISTER_DATASPACE_ASSET_DEFINITION_JSON_PREFIX = '{"RegisterDataspaceAssetDefinition":';

const RETAIL_INSTRUCTION_NAMES_V1 = Object.freeze([
  "ActivateRetailDailyLimitV1",
  "BindRetailIdentityV1",
  "RetailMonetaryMovementV1",
]);
const RETAIL_INSTRUCTION_WIRE_IDS_V1 = Object.freeze([
  "iroha.asset.retail_day.activate.v1",
  "iroha.asset.retail_day.identity.bind.v1",
  "iroha.asset.retail_day.monetary_movement.v1",
]);
const RETAIL_INSTRUCTION_JSON_PREFIXES_V1 = RETAIL_INSTRUCTION_NAMES_V1.map(
  (name) => `{"${name}":`,
);
const RETAIL_INSTRUCTION_NAME_SET_V1 = new Set(RETAIL_INSTRUCTION_NAMES_V1);

function isRetailInstructionObject(value) {
  return isPlainObject(value) && Object.keys(value).some(
    (name) => RETAIL_INSTRUCTION_NAME_SET_V1.has(name),
  );
}

const INNER_TYPE_NAME_BY_WIRE_ID = Object.freeze({
  ...Object.fromEntries(NFT_MARKET_INSTRUCTION_NAMES_V1.map((name, index) => [NFT_MARKET_INSTRUCTION_WIRE_IDS_V1[index], `${TEXT_IROHA_DATA_MODEL_ISI}nft_market::${name}`])),
  ...Object.fromEntries(GAME_INSTRUCTION_NAMES_V1.map((name, index) => [GAME_INSTRUCTION_WIRE_IDS_V1[index], `${TEXT_IROHA_DATA_MODEL_ISI}game::${name}`])),
  "iroha.mint": `${TEXT_IROHA_DATA_MODEL_ISI}mint_burn::MintBox`,
  "iroha.burn": `${TEXT_IROHA_DATA_MODEL_ISI}mint_burn::BurnBox`,
  "iroha.register": `${TEXT_IROHA_DATA_MODEL_ISI}register::RegisterBox`,
  [REGISTER_DATASPACE_ASSET_DEFINITION_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}register_dataspace_asset_definition::RegisterDataspaceAssetDefinition`,
  "iroha.transfer": `${TEXT_IROHA_DATA_MODEL_ISI}transfer::TransferBox`,
  "iroha.custom": `${TEXT_IROHA_DATA_MODEL_ISI}transparent::CustomInstruction`,
  "iroha.execute_trigger": `${TEXT_IROHA_DATA_MODEL_ISI}transparent::ExecuteTrigger`,
  "iroha.rwa": `${TEXT_IROHA_DATA_MODEL_ISI}rwa::RwaInstructionBox`,
  [CANCEL_ASSET_LOCK_WIRE_ID]: CANCEL_ASSET_LOCK_INNER_TYPE_NAME,
  [SET_ASSET_TRANSFER_AVAILABILITY_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}asset_transfer_control::SetAssetTransferAvailability`,
  [SET_ASSET_TRANSFER_BLACKLIST_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}asset_transfer_control::${TEXT_SET_ASSET_TRANSFER_BLACKLIST_2}`,
  [SET_ASSET_TRANSFER_CONTROL_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}asset_transfer_control::SetAssetTransferControl`,
  [ISSUE_REPLICATION_ORDER_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}sorafs::IssueReplicationOrder`,
  [COMPLETE_REPLICATION_ORDER_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}sorafs::${TEXT_COMPLETE_REPLICATION_ORDER_2}`,
  [EXPIRE_REPLICATION_ORDER_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}sorafs::${TEXT_EXPIRE_REPLICATION_ORDER_2}`,
  [CREATE_KAIGI_WIRE_ID]: `${TEXT_IROHA_DATA_MODEL_ISI}kaigi::CreateKaigi`,
  [JOIN_KAIGI_WIRE_ID]: `${TEXT_IROHA_DATA_MODEL_ISI}kaigi::JoinKaigi`,
  [LEAVE_KAIGI_WIRE_ID]: `${TEXT_IROHA_DATA_MODEL_ISI}kaigi::LeaveKaigi`,
  [END_KAIGI_WIRE_ID]: `${TEXT_IROHA_DATA_MODEL_ISI}kaigi::EndKaigi`,
  [RECORD_KAIGI_USAGE_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}kaigi::RecordKaigiUsage`,
  [SET_KAIGI_RELAY_MANIFEST_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}kaigi::${TEXT_SET_KAIGI_RELAY_MANIFEST}`,
  [REGISTER_KAIGI_RELAY_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}kaigi::RegisterKaigiRelay`,
  [UNREGISTER_KAIGI_RELAY_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}kaigi::UnregisterKaigiRelay`,
  [REPORT_KAIGI_RELAY_HEALTH_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}kaigi::${TEXT_REPORT_KAIGI_RELAY_HEALTH}`,
  [PROPOSE_DEPLOY_CONTRACT_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}governance::ProposeDeployContract`,
  [CAST_ZK_BALLOT_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}governance::CastZkBallot`,
  [CAST_PLAIN_BALLOT_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}governance::CastPlainBallot`,
  [UPDATE_PLAIN_CONVICTION_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}governance::UpdatePlainConviction`,
  [CLAIM_TWITTER_FOLLOW_REWARD_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}social::${TEXT_CLAIM_TWITTER_FOLLOW_REWARD}`,
  [SEND_TO_TWITTER_WIRE_ID]: `${TEXT_IROHA_DATA_MODEL_ISI}social::SendToTwitter`,
  [CANCEL_TWITTER_ESCROW_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}social::CancelTwitterEscrow`,
  [REGISTER_SMART_CONTRACT_CODE_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}RegisterSmartContractCode`,
  [REGISTER_SMART_CONTRACT_BYTES_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}RegisterSmartContractBytes`,
  [DEACTIVATE_CONTRACT_INSTANCE_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}DeactivateContractInstance`,
  [ACTIVATE_CONTRACT_INSTANCE_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}ActivateContractInstance`,
  [SET_CONTRACT_PARLIAMENT_DELEGATION_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}SetContractParliamentDelegation`,
  [OFFER_CONTRACT_OWNERSHIP_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}OfferContractOwnership`,
  [ACCEPT_CONTRACT_OWNERSHIP_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}AcceptContractOwnership`,
  [CANCEL_CONTRACT_OWNERSHIP_OFFER_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}CancelContractOwnershipOffer`,
  [COMMIT_CONTRACT_DEPLOYMENT_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}CommitContractDeployment`,
  [UPLOAD_SMART_CONTRACT_CODE_CHUNK_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}UploadSmartContractCodeChunk`,
  [FINALIZE_SMART_CONTRACT_CODE_UPLOAD_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}FinalizeSmartContractCodeUpload`,
  [CANCEL_SMART_CONTRACT_CODE_UPLOAD_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}CancelSmartContractCodeUpload`,
  [REMOVE_SMART_CONTRACT_BYTES_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}${TEXT_SMART_CONTRACT_CODE}RemoveSmartContractBytes`,
  [REGISTER_ZK_ASSET_WIRE_ID]: `${TEXT_IROHA_DATA_MODEL_ISI}zk::${TEXT_REGISTER_ZK_ASSET}`,
  [SCHEDULE_CONFIDENTIAL_POLICY_TRANSITION_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}zk::${TEXT_SCHEDULE_CONFIDENTIAL_POLICY_TRANSITION}`,
  [CANCEL_CONFIDENTIAL_POLICY_TRANSITION_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}zk::${TEXT_CANCEL_CONFIDENTIAL_POLICY_TRANSITION}`,
  [CREATE_ELECTION_WIRE_ID]: `${TEXT_IROHA_DATA_MODEL_ISI}zk::CreateElection`,
  [SUBMIT_BALLOT_WIRE_ID]: `${TEXT_IROHA_DATA_MODEL_ISI}zk::SubmitBallot`,
  [FINALIZE_ELECTION_WIRE_ID]: `${TEXT_IROHA_DATA_MODEL_ISI}zk::${TEXT_FINALIZE_ELECTION}`,
  [REGISTER_VERIFYING_KEY_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}verifying_keys::${TEXT_REGISTER_VERIFYING_KEY}`,
  [UPDATE_VERIFYING_KEY_WIRE_ID]:
    `${TEXT_IROHA_DATA_MODEL_ISI}verifying_keys::${TEXT_UPDATE_VERIFYING_KEY}`,
  ...Object.fromEntries(RETAIL_INSTRUCTION_NAMES_V1.map((name, index) => [
    RETAIL_INSTRUCTION_WIRE_IDS_V1[index],
    `${TEXT_IROHA_DATA_MODEL_ISI}retail_daily_limit::${name}`,
  ])),
});
const INSTRUCTION_WIRE_SCHEMA_BINDINGS = /* @__PURE__ */ (() => Object.freeze(
  Object.entries(INNER_TYPE_NAME_BY_WIRE_ID).map(
    ([outerWireId, innerTypeName]) =>
      Object.freeze({ outerWireId, innerTypeName }),
  ),
))();

const BASE58_LOOKUP = new Map(
  Array.from(BASE58_ALPHABET, (char, index) => [char, BigInt(index)]),
);

function resolveNative(method, nativeRuntime) {
  const native = resolveNativeRuntimeBinding(nativeRuntime);
  if (typeof native[method] !== JS_TYPE_FUNCTION) {
    rejectError(`Native binding does not expose ${method}`);
  }
  return native;
}

const { isStrictGovernanceInstructionCandidate, validateGovernanceInstructionBoundary } = /* @__PURE__ */ createNoritoGovernanceInstructionBoundary({
    assertExactNonEmptyString,
    assertOnlyObjectKeys,
    decodeExactStandardBase64,
    decodeManifestProvenanceValue: (...args) =>
      decodeManifestProvenanceValue(...args),
    encodeManifestProvenanceValue: (...args) =>
      encodeManifestProvenanceValue(...args),
    isPlainObject,
  });

function parsePublicPlainBallotInstructionJson(json, context) {
  const parsed = JSON.parse(json);
  if (!isPublicPlainBallotInstruction(parsed)) return parsed;
  const exact = parseStrictGovernanceInstructionJson(json, context);
  validateGovernanceInstructionBoundary(exact);
  return exact;
}

const RETIRED_GENERIC_ZK_VARIANTS = Object.freeze([
  ["Shi", "eld"].join(""),
  ["Zk", "Transfer"].join(""),
  ["Un", "shield"].join(""),
]);

function rejectRetiredGenericZkInstruction(instruction) {
  if (!isPlainObject(instruction) || !isPlainObject(instruction.zk)) {
    return;
  }
  for (const variant of RETIRED_GENERIC_ZK_VARIANTS) {
    if (Object.prototype.hasOwnProperty.call(instruction.zk, variant)) {
      rejectType(`zk.${variant} is retired in ABI V1`);
    }
  }
}

function encodeNormalizedInstruction(normalized, networkPrefix, nativeRuntime) {
  rejectRetiredGenericZkInstruction(normalized);
  validateGovernanceInstructionBoundary(normalized);
  const exactJson = exactFinalizeElectionTallyJson(normalized)
    ?? exactPublicPlainBallotJson(normalized)
    ?? exactRegisterDataspaceAssetDefinitionJson(normalized);
  if (exactJson !== null) {
    const native = resolveNative("noritoEncodeInstruction", nativeRuntime);
    return toBuffer(native.noritoEncodeInstruction(exactJson, networkPrefix));
  }
  const retail = isRetailInstructionObject(normalized);
  if (!retail) validateInstructionObjectNumbers(normalized);
  const native = resolveNative("noritoEncodeInstruction", nativeRuntime);
  const json = retail
    ? stringifyStrictLosslessIntegerJson(normalized, "retail instruction")
    : JSON.stringify(normalized);
  return toBuffer(native.noritoEncodeInstruction(json, networkPrefix));
}

/** Serialize one canonical direct public ballot without rounding its u64 duration. */
export function exactPublicPlainBallotJson(instruction) {
  if (!isPublicPlainBallotInstruction(instruction)) return null;
  const canonical = parseStrictGovernanceInstructionJson(
    stringifyStrictLosslessIntegerJson(instruction, "standalone public ballot"),
    "standalone public ballot",
  );
  validateGovernanceInstructionBoundary(canonical);
  const payload = canonical.CastPlainBallot ?? canonical.UpdatePlainConviction;
  if (typeof payload.duration_blocks === "string") {
    payload.duration_blocks = BigInt(payload.duration_blocks);
  }
  return stringifyStrictLosslessIntegerJson(canonical, "standalone public ballot");
}

export function exactFinalizeElectionTallyJson(normalized) {
  const tally = normalized?.zk?.FinalizeElection?.tally;
  if (!Array.isArray(tally) || !tally.some((weight) => typeof weight === "bigint")) {
    return null;
  }
  if (tally.length < 2 || tally.length > 64) {
    rejectRange("FinalizeElection tally must contain 2–64 weights");
  }
  const maxU128 = (1n << 128n) - 1n;
  const exact = tally.map((weight, index) => {
    if (typeof weight === "number") {
      if (!Number.isSafeInteger(weight) || weight < 0) {
        rejectRange(`FinalizeElection tally[${index}] must be a lossless unsigned integer`);
      }
      return BigInt(weight);
    }
    if (typeof weight !== "bigint" || weight < 0n || weight > maxU128) {
      rejectRange(`FinalizeElection tally[${index}] must fit in unsigned 128 bits`);
    }
    return weight;
  });
  const markers = exact.map((_, index) => `__iroha-v1-u128-tally-${index}__`);
  const payload = { ...normalized.zk.FinalizeElection, tally: markers };
  const zk = { ...normalized.zk, FinalizeElection: payload };
  const withMarkers = { ...normalized, zk };
  validateInstructionObjectNumbers(withMarkers);
  const seen = new Uint8Array(markers.length);
  const json = JSON.stringify(withMarkers).replace(
    /"__iroha-v1-u128-tally-(\d+)__"/gu,
    (_token, indexText) => {
      const index = Number(indexText);
      if (!Number.isSafeInteger(index) || index >= exact.length || seen[index] !== 0) {
        rejectType("FinalizeElection tally exact-number marker collision");
      }
      seen[index] = 1;
      return exact[index].toString(10);
    },
  );
  if (seen.some((count) => count !== 1)) {
    rejectType("FinalizeElection tally exact-number marker collision");
  }
  return json;
}

/**
 * Encode instruction JSON, an exact standard-base64 frame, or a lowercase
 * 0x-prefixed hex frame to canonical Norito bytes.
 * @param {object | string | ArrayBufferView | ArrayBuffer | Buffer} instruction
 * @param {number} networkPrefix Caller-selected I105 deployment prefix (u16).
 * @returns {Buffer}
 */
function encodeInstruction(instruction, networkPrefix, nativeRuntime) {
  requireNetworkPrefix(networkPrefix);
  if (isBinaryLike(instruction)) {
    return canonicalInstructionFrame(instruction, networkPrefix, nativeRuntime);
  }
  if (typeof instruction === JS_TYPE_STRING) {
    const trimmed = instruction.trim();
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (error) {
      if (!(error instanceof SyntaxError)) {
        throw error;
      }
      // Encoded frames have explicit representations. A 0x-prefixed hex frame
      // can also be lexically valid base64, so decoder probing is ambiguous.
      let frame;
      if (instruction.startsWith("0x")) {
        if (!/^0x(?:[0-9a-f]{2})+$/u.test(instruction)) {
          rejectType("instruction frame must be exact lowercase 0x-prefixed hex");
        }
        frame = Buffer.from(instruction.slice(2), HEX_ENCODING);
      } else {
        frame = decodeExactStandardBase64(instruction, "instruction frame");
      }
      return canonicalInstructionFrame(frame, networkPrefix, nativeRuntime);
    }
    const exactParsed = isStrictGovernanceInstructionCandidate(parsed)
      ? parseStrictGovernanceInstructionJson(trimmed, "governance instruction")
      : parsed;
    // This view supports local checks only. The owner must see the original
    // JSON tokens, including large integers and duplicate keys, unchanged.
    rejectRetiredGenericZkInstruction(exactParsed);
    validateGovernanceInstructionBoundary(exactParsed);
    const native = resolveNative("noritoEncodeInstruction", nativeRuntime);
    return toBuffer(native.noritoEncodeInstruction(instruction, networkPrefix));
  }
  const normalized = normalizeInstructionJsonValue(cloneJson(instruction));
  return encodeNormalizedInstruction(normalized, networkPrefix, nativeRuntime);
}

function canonicalInstructionFrame(bytes, networkPrefix, nativeRuntime) {
  const frame = toBuffer(bytes);
  const native = resolveNative("noritoDecodeInstruction", nativeRuntime);
  const json = native.noritoDecodeInstruction(frame, networkPrefix);
  const encoder = resolveNative("noritoEncodeInstruction", nativeRuntime);
  const canonical = toBuffer(encoder.noritoEncodeInstruction(json, networkPrefix));
  if (!frame.equals(canonical)) {
    rejectError("instruction frame is not canonical Norito");
  }
  return canonical;
}

export function noritoEncodeInstruction(instruction, networkPrefix) {
  return encodeInstruction(instruction, networkPrefix, defaultNativeRuntime);
}

/**
 * Encode a `/v1/pipeline/transactions/batch` request body.
 *
 * Torii expects a Norito `Vec<Vec<u8>>` where each inner byte vector is one
 * versioned signed transaction payload.
 *
 * @param {ReadonlyArray<ArrayBufferView | ArrayBuffer | Buffer>} payloads
 * @returns {Buffer}
 */
export function noritoEncodeTransactionPayloadBatch(payloads) {
  if (!Array.isArray(payloads)) {
    rejectType(("transaction payload batch" + TEXT_MUST_BE + "an array"));
  }
  if (payloads.length === 0) {
    rejectType(("transaction payload batch" + TEXT_MUST_CONTAIN + "at least one payload"));
  }
  const payload = withNoritoCompactLengths(() =>
    encodeNoritoVec(payloads, (item, index) =>
      encodeByteVecValue(item, `transaction payload batch[${index}]`),
    ),
  );
  return frameNoritoPayload(
    payload,
    TRANSACTION_PAYLOAD_BATCH_SCHEMA_HASH,
    COMPACT_LEN_FLAG,
  );
}

/**
 * Encode the exact shared V1 SoraFS billing acknowledgement proof.
 *
 * The input surface is deliberately closed: nonce bytes, snake-case aliases,
 * hexadecimal proof strings, and additional fields are not accepted.
 *
 * @param {{requestNonceHex: string, authenticationProof: ArrayBufferView | ArrayBuffer | Buffer}} proof
 * @returns {Buffer}
 */
export function noritoEncodeSorafsBillingAcknowledgementProofV1(proof) {
  if (!isPlainObject(proof)) {
    rejectType((TEXT_SORA_FS_BILLING_ACKNOWLEDGEMENT + "proof" + TEXT_MUST_BE_AN_OBJECT_2));
  }
  const keys = Object.keys(proof);
  if (
    keys.length !== 2 ||
    !Object.prototype.hasOwnProperty.call(proof, "requestNonceHex") ||
    !Object.prototype.hasOwnProperty.call(proof, "authenticationProof")
  ) {
    rejectType((TEXT_SORA_FS_BILLING_ACKNOWLEDGEMENT + "proof" + TEXT_MUST_CONTAIN + "exactly requestNonceHex and authenticationProof"));
  }
  const requestNonceHex = proof.requestNonceHex;
  if (
    typeof requestNonceHex !== JS_TYPE_STRING ||
    !/^[0-9a-f]{64}$/u.test(requestNonceHex) ||
    /^0{64}$/u.test(requestNonceHex)
  ) {
    rejectType((TEXT_SORA_FS_BILLING_ACKNOWLEDGEMENT + "requestNonceHex" + TEXT_MUST_BE + "one non-zero lowercase 32-byte hexadecimal digest"));
  }
  const authenticationProof = proof.authenticationProof;
  if (
    !Buffer.isBuffer(authenticationProof) &&
    !ArrayBuffer.isView(authenticationProof) &&
    !(authenticationProof instanceof ArrayBuffer)
  ) {
    rejectType((TEXT_SORA_FS_BILLING_ACKNOWLEDGEMENT + "authenticationProof" + TEXT_MUST_BE + "binary bytes"));
  }
  const proofBytes = Buffer.isBuffer(authenticationProof)
    ? Buffer.from(authenticationProof)
    : ArrayBuffer.isView(authenticationProof)
      ? Buffer.from(
          authenticationProof.buffer,
          authenticationProof.byteOffset,
          authenticationProof.byteLength,
        )
      : Buffer.from(authenticationProof);
  if (
    proofBytes.length === 0 ||
    proofBytes.length >
      SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1
  ) {
    rejectRange(`${TEXT_SORA_FS_BILLING_ACKNOWLEDGEMENT}authenticationProof${TEXT_MUST_CONTAIN}1..=${SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1} bytes`);
  }
  const payload = withNoritoCompactLengths(() =>
    encodeStructValue([
      [
        encodeFixedBytesValue(
          Buffer.from(requestNonceHex, HEX_ENCODING),
          32,
          (TEXT_SORA_FS_BILLING_ACKNOWLEDGEMENT + "requestNonceHex"),
        ),
      ],
      [
        encodeByteVecValue(
          proofBytes,
          (TEXT_SORA_FS_BILLING_ACKNOWLEDGEMENT + "authenticationProof"),
        ),
      ],
    ]),
  );
  return frameNoritoPayload(
    payload,
    SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_SCHEMA_HASH_V1,
    COMPACT_LEN_FLAG,
  );
}

/**
 * Encode the exact current Rust `ContractManifestSignaturePayload` frame.
 *
 * Provenance is deliberately excluded: this is the canonical message signed
 * by `ContractManifest::try_signed` and verified by smart-contract admission.
 *
 * @param {object} manifest
 * @returns {Buffer}
 */
export function noritoEncodeContractManifestSignaturePayload(manifest) {
  const payload = withNoritoCompactLengths(() =>
    encodeContractManifestSignaturePayloadValue(
      manifest,
      "ContractManifestSignaturePayload",
    ),
  );
  return frameNoritoPayload(
    payload,
    CONTRACT_MANIFEST_SIGNATURE_PAYLOAD_SCHEMA_HASH,
    COMPACT_LEN_FLAG,
  );
}

function encodeFeePaymentIntentValue(intent, context) {
  if (!isPlainObject(intent)) {
    rejectType(`${context}${TEXT_MUST_BE_AN_OBJECT}`);
  }
  assertOnlyObjectKeys(intent, ["payer", "value"], context);
  const payer = assertNonEmptyString(intent.payer, `${context}.payer`);
  if (payer !== "authority" && payer !== "sponsor") {
    rejectType(`${context}.payer${TEXT_MUST_BE}authority or sponsor`);
  }
  if (!isPlainObject(intent.value)) {
    rejectType(`${context}.value${TEXT_MUST_BE_AN_OBJECT_2}`);
  }
  const allowedValueFields = ["charge_limits", "gas_limit"];
  if (payer === "sponsor") {
    allowedValueFields.push("program_id", "program_revision");
  }
  assertOnlyObjectKeys(intent.value, allowedValueFields, `${context}.value`);
  if (!Array.isArray(intent.value.charge_limits)) {
    rejectType(`${context}${TEXT_VALUE_CHARGE_LIMITS_MUST}be an array`);
  }
  let previousKind = -1;
  const chargeLimits = encodeNoritoVec(
    Array.from(intent.value.charge_limits, (limit, index) => {
      const itemContext = `${context}.value.charge_limits[${index}]`;
      if (!Object.prototype.hasOwnProperty.call(intent.value.charge_limits, index)) {
        rejectType(`${context}${TEXT_VALUE_CHARGE_LIMITS_MUST}not contain holes`);
      }
      if (!isPlainObject(limit)) {
        rejectType(`${itemContext}${TEXT_MUST_BE_AN_OBJECT}`);
      }
      assertOnlyObjectKeys(
        limit,
        ["kind", WIRE_FIELD_ASSET_DEFINITION_ID, "max_amount"],
        itemContext,
      );
      if (!isPlainObject(limit.kind)) {
        rejectType(`${itemContext}.kind${TEXT_MUST_BE}a tagged unit object`);
      }
      assertOnlyObjectKeys(limit.kind, ["kind", "value"], `${itemContext}.kind`);
      const kind = assertNonEmptyString(limit.kind.kind, `${itemContext}.kind.kind`);
      const kindTag = kind === "nexus" ? 0 : kind === "pipeline_gas" ? 1 : -1;
      if (kindTag < 0 || limit.kind.value !== null) {
        rejectType(`${itemContext}.kind must be the${TEXT_CANONICAL}nexus or pipeline_gas tagged unit`);
      }
      if (kindTag <= previousKind) {
        rejectType(`${context}${TEXT_VALUE_CHARGE_LIMITS_MUST}be unique and ordered nexus before pipeline_gas`);
      }
      previousKind = kindTag;
      const quantity = NumericV1.decodeQuantityJson(limit.max_amount);
      if (quantity.mantissa <= 0n) {
        rejectType(`${itemContext}.max_amount${TEXT_MUST_BE_GREATER_THAN_ZERO}`);
      }
      return encodeStructValue([
        [encodeEnumTagValue(kindTag)],
        [
          encodeAssetDefinitionIdValue(
            limit.asset_definition_id,
            `${itemContext}.${TEXT_ASSET_DEFINITION_ID}`,
          ),
        ],
        [encodeQuantityValue(limit.max_amount, `${itemContext}.max_amount`)],
      ]);
    }),
    (encoded) => encoded,
  );
  const gasLimit = encodeOptionValue(
    intent.value.gas_limit ?? null,
    encodeU64NumberValue,
    `${context}.value.gas_limit`,
  );
  if (intent.value.gas_limit !== undefined && intent.value.gas_limit !== null) {
    const normalizedGas = normalizeU64Input(
      intent.value.gas_limit,
      `${context}.value.gas_limit`,
    );
    if (normalizedGas === 0n) {
      rejectType(`${context}.value.gas_limit${TEXT_MUST_BE}non-zero`);
    }
  }
  if (payer === "authority") {
    return encodeEnumTagValue(0, () =>
      encodeStructValue([[chargeLimits], [gasLimit]]),
    );
  }
  if (!isPlainObject(intent.value.program_id)) {
    rejectType(`${context}${TEXT_VALUE_PROGRAM}id${TEXT_MUST_BE_AN_OBJECT_2}`);
  }
  assertOnlyObjectKeys(
    intent.value.program_id,
    ["sponsor", "name"],
    `${context}${TEXT_VALUE_PROGRAM}id`,
  );
  const name = assertNonEmptyString(
    intent.value.program_id.name,
    `${context}${TEXT_VALUE_PROGRAM}id.name`,
  );
  if (
    name !== intent.value.program_id.name ||
    name.normalize("NFC") !== name ||
    /[\s@#$\/]/u.test(name)
  ) {
    rejectType(`${context}${TEXT_VALUE_PROGRAM}id.name must be a${TEXT_CANONICAL}Iroha Name`);
  }
  const revision = normalizeU64Input(
    intent.value.program_revision,
    `${context}${TEXT_VALUE_PROGRAM}revision`,
  );
  if (revision === 0n) {
    rejectType(`${context}${TEXT_VALUE_PROGRAM}revision${TEXT_MUST_BE}non-zero`);
  }
  const programId = encodeStructValue([
    [
      encodeAccountIdValue(
        intent.value.program_id.sponsor,
        `${context}${TEXT_VALUE_PROGRAM}id.sponsor`,
      ),
    ],
    [encodeNoritoStringValue(name)],
  ]);
  return encodeEnumTagValue(1, () =>
    encodeStructValue([
      [programId],
      [encodeU64Value(revision, `${context}${TEXT_VALUE_PROGRAM}revision`)],
      [chargeLimits],
      [gasLimit],
    ]),
  );
}

/** @internal Encode one exact compact-length `FeePaymentIntent` archive. */
export function noritoEncodeFeePaymentIntentArchive(intent) {
  return withNoritoCompactLengths(() =>
    Uint8Array.from(
      encodeFeePaymentIntentValue(intent, "FeePaymentIntent"),
    ),
  );
}

const INLINE_PRIVATE_KEY_FIELDS = new Set([
  "private_key",
  "privateKey",
  "private_key_hex",
  "privateKeyHex",
  "private_key_bytes",
  "privateKeyBytes",
  "private_key_multihash",
  "privateKeyMultihash",
  "private_key_algorithm",
  "privateKeyAlgorithm",
]);

function rejectInlinePrivateKeyFields(request, context) {
  const fields = Object.keys(request).filter((key) =>
    INLINE_PRIVATE_KEY_FIELDS.has(key),
  );
  if (fields.length !== 0) {
    rejectType(`${context} does not accept private-key fields (${fields.join(", ")}); sign the returned transaction draft locally`);
  }
}

/**
 * Encode a `/v1/multisig/propose` request DTO as a native Norito body.
 *
 * Torii's `NoritoJson<MultisigProposeDtoV1>` extractor accepts this payload with
 * `Content-Type: application/x-norito`. The `instructions` entries are normal
 * InstructionBox values embedded in the DTO, not base64 strings inside JSON.
 *
 * @param {object} request
 * @param {number} networkPrefix Caller-selected I105 deployment prefix (u16).
 * @returns {Buffer}
 */
function encodeMultisigProposeRequest(request, networkPrefix, nativeRuntime) {
  requireNetworkPrefix(networkPrefix);
  if (!isPlainObject(request)) {
    rejectType(("MultisigProposeDtoV1 request" + TEXT_MUST_BE_AN_OBJECT_2));
  }
  if (!Array.isArray(request.instructions)) {
    rejectType((TEXT_MULTISIG_PROPOSE_DTO + "instructions" + TEXT_MUST_BE + "an array"));
  }
  rejectInlinePrivateKeyFields(request, "MultisigProposeDtoV1");
  rejectUnknownRetailFeeFields(request, "MultisigProposeDtoV1");
  if (Object.hasOwn(request, "validation_fee_assessment") && request.validation_fee_assessment === undefined) {
    rejectType("MultisigProposeDtoV1.validation_fee_assessment must be a typed assessment or null");
  }
  for (const [_field, value] of [
    ["signer_account_id", request.signer_account_id ?? request.signerAccountId],
    ["multisig_account_id", request.multisig_account_id ?? request.multisigAccountId],
  ]) {
    if (value !== undefined && value !== null) AccountAddress.parseEncoded(value, networkPrefix);
  }
  const payload = withNoritoCompactLengths(() =>
    encodeStructValue([
      ...encodeMultisigAccountSelectorFields(request, (TEXT_MULTISIG_PROPOSE_DTO + "selector")),
      [
        encodeAccountIdValue(
          request.signer_account_id ?? request.signerAccountId,
          (TEXT_MULTISIG_PROPOSE_DTO + "signer_" + TEXT_ACCOUNT_ID),
        ),
      ],
      [
        encodeOptionValue(
          request.public_key_hex ?? request.publicKeyHex ?? null,
          encodeNoritoStringValue,
          (TEXT_MULTISIG_PROPOSE_DTO + "public_key_hex"),
        ),
      ],
      [
        encodeOptionValue(
          request.signature_b64 ?? request.signatureB64 ?? null,
          encodeExactBase64StringValue,
          (TEXT_MULTISIG_PROPOSE_DTO + "signature_b64"),
        ),
      ],
      [
        encodeOptionValue(
          request.creation_time_ms ?? request.creationTimeMs ?? null,
          encodeU64NumberValue,
          (TEXT_MULTISIG_PROPOSE_DTO + TEXT_CREATION_TIME_MS),
        ),
      ],
      [
        encodeFeePaymentIntentValue(
          request.fee_payment ?? request.feePayment,
          (TEXT_MULTISIG_PROPOSE_DTO + "fee_payment"),
        ),
      ],
      [
        encodeOptionValue(
          request.memo ?? null,
          encodeNoritoStringValue,
          (TEXT_MULTISIG_PROPOSE_DTO + "memo"),
        ),
      ],
      [
        encodeOptionValue(
          request.validation_fee_assessment ?? null,
          encodeRetailFeeAssessmentValue,
          (TEXT_MULTISIG_PROPOSE_DTO + "validation_fee_assessment"),
        ),
      ],
      [
        encodeMultisigInstructions(request.instructions, networkPrefix, nativeRuntime),
      ],
    ]),
  );
  return frameNoritoPayload(payload, MULTISIG_PROPOSE_DTO_SCHEMA_HASH, COMPACT_LEN_FLAG);
}

export function noritoEncodeMultisigProposeRequest(request, networkPrefix) {
  return encodeMultisigProposeRequest(request, networkPrefix, defaultNativeRuntime);
}

// Declared Norito frame identities of the native retail fee types.
const RETAIL_FEE_QUOTE_REQUEST_V1_SCHEMA_HASH = Buffer.from("535a1db30ba036a8f35944ab55678779", HEX_ENCODING);
const RETAIL_FEE_ASSESSMENT_V1_SCHEMA_HASH = Buffer.from("72ca99de9d49cae6dfc07a2a628eb918", HEX_ENCODING);
const RETAIL_FEE_ASSESSMENT_MARKER_PREFIX_V1 = "iroha:retail_fee:assessment:v1:";
const RETAIL_FEE_PAYMENT_INTENT_DOMAIN_V1 = "iroha.retail_fee.payment_intent.v1\0";
const RETAIL_FEE_ASSESSMENT_MARKER_MAX_BYTES_V1 = 4096;
const RETAIL_FEE_MAX_PAYMENT_LEGS_V1 = 1000;
const RETAIL_FEE_ASSESSMENT_FIELDS_V1 = Object.freeze([
  "account_id",
  "retail_enrolled",
  "billing_month_start_ms",
  "policy_revision",
  "payments_used_before",
  "qualifying_payments",
  "fee_minor",
  "state_commitment",
  "intent_hash",
  "expires_at_ms",
]);

function encodeExactRetailFeeAccountIdValue(value, context) {
  if (typeof value !== JS_TYPE_STRING || value.trim() !== value) {
    rejectType(`${context} must be an exact canonical I105 account id`);
  }
  const canonical = normalizeAccountId(value, context);
  if (canonical !== value) {
    rejectType(`${context} must be an exact canonical I105 account id`);
  }
  return encodeAccountIdValue(canonical, context);
}

function encodeRetailFeeQuoteRequestValue(request) {
  const context = "RetailFeeQuoteRequestV1";
  assertExactObjectKeys(request, ["account_id", "asset_definition_id", "transfers"], context);
  if (
    !Array.isArray(request.transfers) ||
    request.transfers.length === 0 ||
    request.transfers.length > RETAIL_FEE_MAX_PAYMENT_LEGS_V1
  ) {
    rejectType(`${context}.transfers requires between 1 and ${RETAIL_FEE_MAX_PAYMENT_LEGS_V1} ordered payment legs`);
  }
  return encodeStructValue([
    [encodeExactRetailFeeAccountIdValue(request.account_id, `${context}.account_id`)],
    [encodeAssetDefinitionIdValue(request.asset_definition_id, `${context}.asset_definition_id`)],
    [encodeNoritoVec(request.transfers, (leg, index) => {
      const label = `${context}.transfers[${index}]`;
      assertExactObjectKeys(leg, ["destination_account_id", "amount_minor_units"], label);
      if (normalizeU64Input(leg.amount_minor_units, `${label}.amount_minor_units`) === 0n) {
        rejectType(`${label}.amount_minor_units must be positive`);
      }
      return encodeStructValue([
        [encodeExactRetailFeeAccountIdValue(leg.destination_account_id, `${label}.destination_account_id`)],
        [encodeU64NumberValue(leg.amount_minor_units, `${label}.amount_minor_units`)],
      ]);
    })],
  ]);
}

function encodeRetailFeeAssessmentValue(value) {
  const assessment = normalizeRetailFeeAssessment(value);
  const context = "RetailFeeAssessmentV1";
  assertExactObjectKeys(assessment, RETAIL_FEE_ASSESSMENT_FIELDS_V1, context);
  // Derived Rust struct [u8; 32] fields are raw fixed bytes, not generic array archives.
  const hash = (name) => encodeFixedBytesValue(
    Buffer.from(assessment[name], HEX_ENCODING), 32, `${context}.${name}`);
  return encodeStructValue([
    [encodeExactRetailFeeAccountIdValue(assessment.account_id, `${context}.account_id`)],
    [encodeBoolValue(assessment.retail_enrolled, `${context}.retail_enrolled`)],
    ...[
      "billing_month_start_ms",
      "policy_revision",
      "payments_used_before",
      "qualifying_payments",
      "fee_minor",
    ].map((name) => [encodeU64NumberValue(assessment[name], `${context}.${name}`)]),
    [hash("state_commitment")],
    [hash("intent_hash")],
    [encodeU64NumberValue(assessment.expires_at_ms, `${context}.expires_at_ms`)],
  ]);
}

/** Encode the native, ordered wallet payment intent without local allowance state. */
export function encodeRetailFeeQuoteRequestV1(request) {
  const payload = withNoritoCompactLengths(() => encodeRetailFeeQuoteRequestValue(request));
  return frameNoritoPayload(
    payload,
    RETAIL_FEE_QUOTE_REQUEST_V1_SCHEMA_HASH,
    COMPACT_LEN_FLAG,
  );
}

/** Hash the exact native payment intent using Iroha's domain and hash marker. */
export function retailFeePaymentIntentHash(request) {
  const bytes = Buffer.concat([
    Buffer.from(RETAIL_FEE_PAYMENT_INTENT_DOMAIN_V1, UTF8_ENCODING),
    encodeRetailFeeQuoteRequestV1(request),
  ]);
  const digest = Uint8Array.from(blake2b256(bytes));
  digest[31] |= 1;
  return digest;
}

/** Encode the complete assessment reviewed by the sender, including an explicit zero fee. */
export function encodeRetailFeeAssessmentV1(assessment) {
  const payload = withNoritoCompactLengths(() => encodeRetailFeeAssessmentValue(assessment));
  return frameNoritoPayload(
    payload,
    RETAIL_FEE_ASSESSMENT_V1_SCHEMA_HASH,
    COMPACT_LEN_FLAG,
  );
}

/** Proposal-bound TRACE marker; the ledger checks this assessment at execution time. */
export function retailFeeAssessmentMarkerMessage(assessment) {
  const encoded = encodeRetailFeeAssessmentV1(assessment);
  if (encoded.length > Math.floor((RETAIL_FEE_ASSESSMENT_MARKER_MAX_BYTES_V1 -
      RETAIL_FEE_ASSESSMENT_MARKER_PREFIX_V1.length) / 2)) {
    rejectType("retail fee assessment marker exceeds size bound");
  }
  return `${RETAIL_FEE_ASSESSMENT_MARKER_PREFIX_V1}${encoded.toString(HEX_ENCODING)}`;
}

/** Decode a proposal marker and require exact canonical re-encoding before review. */
export function decodeRetailFeeAssessmentMarkerMessage(message) {
  const prefix = RETAIL_FEE_ASSESSMENT_MARKER_PREFIX_V1;
  if (
    typeof message !== JS_TYPE_STRING ||
    message.length > RETAIL_FEE_ASSESSMENT_MARKER_MAX_BYTES_V1 ||
    !message.startsWith(prefix) ||
    !/^(?:[0-9a-f]{2})+$/u.test(message.slice(prefix.length))
  ) {
    rejectType("retail fee assessment marker requires canonical lowercase hex");
  }
  const bytes = Buffer.from(message.slice(prefix.length), HEX_ENCODING);
  if (bytes.length > Math.floor((RETAIL_FEE_ASSESSMENT_MARKER_MAX_BYTES_V1 - prefix.length) / 2)) {
    rejectType("retail fee assessment marker exceeds size bound");
  }
  const frame = validateNoritoFrame(bytes, {
    context: "retail fee assessment marker",
    expectedSchemaHash: RETAIL_FEE_ASSESSMENT_V1_SCHEMA_HASH,
  });
  const names = RETAIL_FEE_ASSESSMENT_FIELDS_V1;
  const assessment = withNoritoCompactLengths(() => {
    const fields = decodeStructFields(frame.payload, "RetailFeeAssessmentV1", names);
    const hash = (name) => Buffer.from(
      decodeFixedBytesValue(fields[name], 32, name),
    ).toString(HEX_ENCODING).toUpperCase();
    const result = {
      account_id: decodeAccountIdValue(fields.account_id, "account_id"),
      retail_enrolled: decodeBoolValue(fields.retail_enrolled, "retail_enrolled"),
      state_commitment: hash("state_commitment"),
      intent_hash: hash("intent_hash"),
    };
    for (const name of names.filter((name) => !Object.hasOwn(result, name))) {
      const value = BigInt(decodeU64Value(fields[name], name));
      result[name] = value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
    }
    return Object.fromEntries(names.map((name) => [name, result[name]]));
  });
  if (retailFeeAssessmentMarkerMessage(assessment) !== message) {
    rejectType("retail fee marker is not canonical");
  }
  return assessment;
}

/**
 * Encode a `/v1/contracts/call/multisig/propose` request DTO as a native Norito body.
 *
 * Torii's `NoritoJson<MultisigContractCallProposeDto>` extractor accepts this
 * payload with `Content-Type: application/x-norito`.
 *
 * @param {object} request
 * @param {number} networkPrefix Caller-selected I105 deployment prefix (u16).
 * @returns {Buffer}
 */
export function noritoEncodeMultisigContractCallProposeRequest(request, networkPrefix) {
  requireNetworkPrefix(networkPrefix);
  for (const value of [
    request?.signer_account_id ?? request?.signerAccountId,
    request?.multisig_account_id ?? request?.multisigAccountId,
  ]) {
    if (value !== undefined && value !== null) {
      AccountAddress.parseEncoded(value, networkPrefix);
    }
  }
  if (!isPlainObject(request)) {
    rejectType(("MultisigContractCallProposeDto request" + TEXT_MUST_BE_AN_OBJECT_2));
  }
  rejectInlinePrivateKeyFields(request, "MultisigContractCallProposeDto");
  const contractAlias = request.contract_alias ?? request.contractAlias ?? null;
  if (request.contract_address !== undefined || request.contractAddress !== undefined || contractAlias == null) {
    rejectType("MultisigContractCallProposeDto requires exact contract_alias without contract_address");
  }
  const payloadValue = request.payload;
  if (!isPlainObject(payloadValue)) {
    rejectType("MultisigContractCallProposeDto requires an exact object payload");
  }
  const payload = withNoritoCompactLengths(() =>
    encodeStructValue([
      ...encodeMultisigAccountSelectorFields(
        request,
        (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_DTO + "selector"),
      ),
      [
        encodeAccountIdValue(
          request.signer_account_id ?? request.signerAccountId,
          (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_DTO + "signer_" + TEXT_ACCOUNT_ID),
        ),
      ],
      [
        encodeOptionValue(
          request.public_key_hex ?? request.publicKeyHex ?? null,
          encodeNoritoStringValue,
          (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_DTO + "public_key_hex"),
        ),
      ],
      [
        encodeOptionValue(
          request.signature_b64 ?? request.signatureB64 ?? null,
          encodeExactBase64StringValue,
          (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_DTO + "signature_b64"),
        ),
      ],
      [
        encodeOptionValue(
          request.creation_time_ms ?? request.creationTimeMs ?? null,
          encodeU64NumberValue,
          (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_DTO + TEXT_CREATION_TIME_MS),
        ),
      ],
      [
        encodeNoritoStringValue(assertNonEmptyString(
          contractAlias,
          (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_DTO + "contract_alias"),
        )),
      ],
      [
        encodeNoritoStringValue(
          assertNonEmptyString(
            request.entrypoint,
            (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_DTO + "entrypoint"),
          ),
        ),
      ],
      [encodeNoritoJsonValue(payloadValue)],
      [
        encodeFeePaymentIntentValue(
          request.fee_payment ?? request.feePayment,
          (TEXT_MULTISIG_CONTRACT_CALL_PROPOSE_DTO + "fee_payment"),
        ),
      ],
    ]),
  );
  return frameNoritoPayload(
    payload,
    MULTISIG_CONTRACT_CALL_PROPOSE_DTO_SCHEMA_HASH,
    COMPACT_LEN_FLAG,
  );
}

/**
 * Encode a `/v1/contracts/call/multisig/approve` request DTO as a native Norito body.
 *
 * @param {object} request
 * @param {number} networkPrefix Caller-selected I105 deployment prefix (u16).
 * @returns {Buffer}
 */
export function noritoEncodeMultisigContractCallApproveRequest(request, networkPrefix) {
  requireNetworkPrefix(networkPrefix);
  for (const value of [
    request?.signer_account_id ?? request?.signerAccountId,
    request?.multisig_account_id ?? request?.multisigAccountId,
  ]) {
    if (value !== undefined && value !== null) {
      AccountAddress.parseEncoded(value, networkPrefix);
    }
  }
  if (!isPlainObject(request)) {
    rejectType(("MultisigContractCallApproveDto request" + TEXT_MUST_BE_AN_OBJECT_2));
  }
  rejectInlinePrivateKeyFields(request, "MultisigContractCallApproveDto");
  const proposalId = request.proposal_id ?? request.proposalId ?? null;
  const instructionsHash = request.instructions_hash ?? request.instructionsHash ?? null;
  if (proposalId == null && instructionsHash == null) {
    rejectType("MultisigContractCallApproveDto requires proposal_id or instructions_hash");
  }
  const payload = withNoritoCompactLengths(() =>
    encodeStructValue([
      ...encodeMultisigAccountSelectorFields(
        request,
        (TEXT_MULTISIG_CONTRACT_CALL_APPROVE_DTO + "selector"),
      ),
      [
        encodeAccountIdValue(
          request.signer_account_id ?? request.signerAccountId,
          (TEXT_MULTISIG_CONTRACT_CALL_APPROVE_DTO + "signer_" + TEXT_ACCOUNT_ID),
        ),
      ],
      [
        encodeOptionValue(
          request.public_key_hex ?? request.publicKeyHex ?? null,
          encodeNoritoStringValue,
          (TEXT_MULTISIG_CONTRACT_CALL_APPROVE_DTO + "public_key_hex"),
        ),
      ],
      [
        encodeOptionValue(
          request.signature_b64 ?? request.signatureB64 ?? null,
          encodeExactBase64StringValue,
          (TEXT_MULTISIG_CONTRACT_CALL_APPROVE_DTO + "signature_b64"),
        ),
      ],
      [
        encodeOptionValue(
          request.creation_time_ms ?? request.creationTimeMs ?? null,
          encodeU64NumberValue,
          (TEXT_MULTISIG_CONTRACT_CALL_APPROVE_DTO + TEXT_CREATION_TIME_MS),
        ),
      ],
      [
        encodeFeePaymentIntentValue(
          request.fee_payment ?? request.feePayment,
          (TEXT_MULTISIG_CONTRACT_CALL_APPROVE_DTO + "fee_payment"),
        ),
      ],
      [
        encodeOptionValue(
          proposalId,
          encodeNoritoStringValue,
          (TEXT_MULTISIG_CONTRACT_CALL_APPROVE_DTO + "proposal_id"),
        ),
      ],
      [
        encodeOptionValue(
          instructionsHash,
          encodeNoritoStringValue,
          (TEXT_MULTISIG_CONTRACT_CALL_APPROVE_DTO + "instructions_hash"),
        ),
      ],
      [
        encodeNoritoStringValue(assertNonEmptyString(
          request.contract_alias,
          "MultisigContractCallApproveDto.contract_alias",
        )),
      ],
      [
        encodeNoritoStringValue(assertNonEmptyString(
          request.entrypoint,
          "MultisigContractCallApproveDto.entrypoint",
        )),
      ],
      [encodeNoritoJsonValue(requireExactContractApprovalPayload(request.payload))],
    ]),
  );
  return frameNoritoPayload(
    payload,
    MULTISIG_CONTRACT_CALL_APPROVE_DTO_SCHEMA_HASH,
    COMPACT_LEN_FLAG,
  );
}

function encodeMultisigAccountSelectorFields(request, context) {
  const multisigAccountId = request.multisig_account_id ?? request.multisigAccountId ?? null;
  const multisigAccountAlias =
    request.multisig_account_alias ?? request.multisigAccountAlias ?? null;
  if ((multisigAccountId == null) === (multisigAccountAlias == null)) {
    rejectType(`${context} requires exactly one of multisig_account_id or multisig_account_alias`);
  }
  return [
    [
      encodeOptionValue(
        multisigAccountId,
        encodeAccountIdValue,
        `${context}.multisig_${TEXT_ACCOUNT_ID}`,
      ),
    ],
    [
      encodeOptionValue(
        multisigAccountAlias,
        encodeNoritoStringValue,
        `${context}.multisig_account_alias`,
      ),
    ],
  ];
}

function encodeMultisigInstructions(instructions, networkPrefix, nativeRuntime) {
  // The enclosing DTO owns vector lengths; each element is the exact bare
  // InstructionBox archive supplied by Rust, including its inner frame.
  return encodeNoritoVec(instructions, (instruction) =>
    encodeInstructionBoxArchive(instruction, networkPrefix, nativeRuntime));
}

/**
 * Encode one canonical `InstructionBox` archive for inclusion in a compact
 * transaction payload. The public instruction frame is decoded and rebuilt so
 * both its outer schema and its inner instruction schema are verified before
 * the archive crosses the signing boundary.
 */
function encodeInstructionBoxArchive(instruction, networkPrefix, nativeRuntime) {
  const frame = encodeInstruction(instruction, networkPrefix, nativeRuntime);
  const decoder = resolveNative("noritoDecodeInstruction", nativeRuntime);
  const json = decoder.noritoDecodeInstruction(frame, networkPrefix);
  const encoder = resolveNative("noritoEncodeInstructionBoxArchive", nativeRuntime);
  return toBuffer(encoder.noritoEncodeInstructionBoxArchive(json, networkPrefix));
}

export function noritoEncodeInstructionBoxArchive(instruction, networkPrefix) {
  return encodeInstructionBoxArchive(instruction, networkPrefix, defaultNativeRuntime);
}

/**
 * Decode one exact canonical `InstructionBox` archive embedded in a compact
 * transaction payload.
 *
 * Unlike {@link noritoDecodeInstruction}, this accepts the bare archive used
 * inside `TransactionPayload::instructions`, not a framed public instruction.
 * The decoded value is re-encoded and compared byte-for-byte so alternate
 * length encodings, frame flags, padding, or payload layouts are rejected at
 * signing boundaries.
 *
 * @param {ArrayBufferView | ArrayBuffer | Buffer} bytes
 * @param {number} networkPrefix Caller-selected I105 deployment prefix (u16).
 * @returns {unknown}
 */
export function noritoDecodeInstructionBoxArchive(bytes, networkPrefix) {
  return decodeInstructionBoxArchive(bytes, networkPrefix, defaultNativeRuntime);
}

function decodeInstructionBoxArchive(bytes, networkPrefix, nativeRuntime) {
  requireNetworkPrefix(networkPrefix);
  const native = resolveNative("noritoDecodeInstructionBoxArchive", nativeRuntime);
  const json = native.noritoDecodeInstructionBoxArchive(toBuffer(bytes), networkPrefix);
  const retail = RETAIL_INSTRUCTION_JSON_PREFIXES_V1.some((prefix) => json.startsWith(prefix));
  const directDataspace = json.startsWith(REGISTER_DATASPACE_ASSET_DEFINITION_JSON_PREFIX);
  const decoded = directDataspace
    ? parseRegisterDataspaceAssetDefinitionJson(json, "direct-dataspace instruction archive")
    : retail
      ? parseStrictLosslessIntegerJson(json, "retail instruction archive")
      : parsePublicPlainBallotInstructionJson(json, "standalone public ballot InstructionBox");
  if (directDataspace) {
    exactRegisterDataspaceAssetDefinitionJson(decoded);
  } else if (!retail && !isPublicPlainBallotInstruction(decoded)) {
    validateInstructionObjectNumbers(decoded);
  }
  validateDecodedInstructionProofAttachments(decoded);
  return decoded;
}

/**
 * Decode canonical Norito instruction bytes back to JSON.
 *
 * When `options.parseJson !== false`, the result is the parsed JSON payload.
 * Otherwise the raw JSON string returned by the native binding is emitted.
 *
 * @param {ArrayBufferView | ArrayBuffer | Buffer} bytes
 * @param {number} networkPrefix Caller-selected I105 deployment prefix (u16).
 * @param {{ parseJson?: boolean }} [options]
 * @returns {string | unknown}
 */
function decodeInstruction(bytes, networkPrefix, options, nativeRuntime) {
  requireNetworkPrefix(networkPrefix);
  const buffer = toBuffer(bytes);
  const native = resolveNative("noritoDecodeInstruction", nativeRuntime);
  const json = native.noritoDecodeInstruction(buffer, networkPrefix);
  const retail = RETAIL_INSTRUCTION_JSON_PREFIXES_V1.some((prefix) => json.startsWith(prefix));
  const directDataspace = json.startsWith(REGISTER_DATASPACE_ASSET_DEFINITION_JSON_PREFIX);
  const decoded = directDataspace
    ? parseRegisterDataspaceAssetDefinitionJson(json, "direct-dataspace instruction frame")
    : retail
      ? parseStrictLosslessIntegerJson(json, "retail instruction frame")
      : parsePublicPlainBallotInstructionJson(json, "standalone public ballot instruction");
  validateDecodedInstructionProofAttachments(decoded);
  // Raw mode preserves the owner's exact numeric tokens. Parsed mode must
  // never return a rounded integer or non-finite value to signing callers.
  if (options.parseJson !== false) {
    if (directDataspace) {
      exactRegisterDataspaceAssetDefinitionJson(decoded);
    } else if (!retail && !isPublicPlainBallotInstruction(decoded)) {
      validateInstructionObjectNumbers(decoded);
    }
  }
  return options.parseJson === false ? json : decoded;
}

export function noritoDecodeInstruction(bytes, networkPrefix, options = {}) {
  return decodeInstruction(bytes, networkPrefix, options, defaultNativeRuntime);
}

function validateDecodedInstructionProofAttachments(instruction) {
  rejectRetiredGenericZkInstruction(instruction);
  if (!isPlainObject(instruction) || !isPlainObject(instruction.zk)) {
    return;
  }
  for (const [variant, field] of [
    ["SubmitBallot", "ballot_proof"],
    [TEXT_FINALIZE_ELECTION, "tally_proof"],
  ]) {
    const payload = instruction.zk[variant];
    if (!isPlainObject(payload)) {
      continue;
    }
    if (!Object.prototype.hasOwnProperty.call(payload, field)) {
      rejectType(`zk.${variant}.${field}${TEXT_IS_REQUIRED}`);
    }
    normalizeCanonicalProofAttachmentValue(
      payload[field],
      `zk.${variant}.${field}`,
    );
  }
}

/**
 * Decode and fail closed on one first-release subscription trigger action.
 *
 * The native binding verifies the complete encoded action, including its
 * syscall-only IVM program, repeat policy, filter, retry policy, and metadata.
 * Callers must still bind the returned semantic summary to their reviewed
 * account, subscription, trigger id, and charge time.
 *
 * @param {string} encodedAction
 * @param {number} networkPrefix Caller-selected I105 deployment prefix (u16).
 * @returns {object}
 */
function inspectTriggerAction(encodedAction, networkPrefix, nativeRuntime) {
  requireNetworkPrefix(networkPrefix);
  if (
    typeof encodedAction !== JS_TYPE_STRING ||
    encodedAction.length === 0 ||
    encodedAction.trim() !== encodedAction
  ) {
    rejectType(("inspectSubscriptionTriggerAction encodedAction must be a" + TEXT_CANONICAL + "non-empty string"));
  }
  const native = resolveNative(
    "inspectSubscriptionTriggerAction",
    nativeRuntime,
  );
  const payload = native.inspectSubscriptionTriggerAction(encodedAction, networkPrefix);
  try {
    return JSON.parse(payload);
  } catch (error) {
    rejectError(`native subscription trigger inspection returned invalid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`);
  }
}

export function inspectSubscriptionTriggerAction(encodedAction, networkPrefix) {
  return inspectTriggerAction(encodedAction, networkPrefix, defaultNativeRuntime);
}

/** @internal Source-level test facade; intentionally absent from package exports. */
export function _createNoritoInstructionApi(nativeRuntime) {
  return Object.freeze({
    _instructionWireSchemaBindings: () => INSTRUCTION_WIRE_SCHEMA_BINDINGS,
    _encodeMultisigInstructions: (instructions, networkPrefix) => withNoritoCompactLengths(() =>
      encodeMultisigInstructions(instructions, requireNetworkPrefix(networkPrefix), nativeRuntime)),
    inspectSubscriptionTriggerAction: (encodedAction, networkPrefix) =>
      inspectTriggerAction(encodedAction, networkPrefix, nativeRuntime),
    noritoDecodeInstruction: (bytes, networkPrefix, options = {}) =>
      decodeInstruction(bytes, networkPrefix, options, nativeRuntime),
    noritoDecodeInstructionBoxArchive: (bytes, networkPrefix) =>
      decodeInstructionBoxArchive(bytes, networkPrefix, nativeRuntime),
    noritoEncodeInstruction: (instruction, networkPrefix) =>
      encodeInstruction(instruction, networkPrefix, nativeRuntime),
    noritoEncodeInstructionBoxArchive: (instruction, networkPrefix) =>
      encodeInstructionBoxArchive(instruction, networkPrefix, nativeRuntime),
    noritoEncodeMultisigProposeRequest: (request, networkPrefix) =>
      encodeMultisigProposeRequest(request, networkPrefix, nativeRuntime),
  });
}

function decodeBlockMerkleProofValue(payload, context) {
  const fields = decodeTupleFields(payload, context, ["leaf_index", "audit_path"]);
  return {
    leaf_index: decodeU32Value(fields.leaf_index, `${context}.leaf_index`),
    audit_path: decodeNoritoVec(
      fields.audit_path,
      (entry, index) =>
        decodeOptionValue(
          entry,
          decodeHashValue,
          `${context}.audit_path[${index}]`,
        ),
      `${context}.audit_path`,
    ),
  };
}

function decodeBlockMerkleCommitmentValue(payload, context) {
  const fields = decodeStructFields(payload, context, ["root", "leaf_count"]);
  const leafCount = decodeU64Value(fields.leaf_count, `${context}.leaf_count`);
  if (leafCount === "0") {
    rejectError(`${context}.leaf_count${TEXT_MUST_BE}non-zero`);
  }
  return {
    root: decodeHashValue(fields.root, `${context}.root`),
    leaf_count: leafCount,
  };
}

const BlockReceiptProofValueFields = [
    ["leaf", decodeHashValue, 0],
    ["proof", decodeBlockMerkleProofValue, 0],
  ];

  function decodeBlockReceiptProofValue(payload, context) {
    return decodeRecordFields(payload, context, BlockReceiptProofValueFields);
  }

function decodeTransferSmtWitnessValue(payload, context) {
  const fields = decodeStructFields(payload, context, [
    "root_before",
    "root_after",
    "path_bits",
    "siblings",
  ]);
  return {
    root_before: decodeFixedByteArrayArchiveValue(
      fields.root_before,
      32,
      `${context}.root_before`,
    ).toString(HEX_ENCODING),
    root_after: decodeFixedByteArrayArchiveValue(
      fields.root_after,
      32,
      `${context}.root_after`,
    ).toString(HEX_ENCODING),
    path_bits: decodeNoritoVec(
      fields.path_bits,
      (entry, index) => decodeU8Value(entry, `${context}.path_bits[${index}]`),
      `${context}.path_bits`,
    ),
    siblings: decodeNoritoVec(
      fields.siblings,
      (entry, index) =>
        decodeFixedByteArrayArchiveValue(
          entry,
          32,
          `${context}.siblings[${index}]`,
        ).toString(HEX_ENCODING),
      `${context}.siblings`,
    ),
  };
}

const TransferDeltaTranscriptValueFields = [
    ["from_account", decodeAccountIdValue, 0],
    ["to_account", decodeAccountIdValue, 0],
    ["asset_definition", decodeAssetDefinitionIdValue, 0],
    ["amount", decodeQuantityValue, 0],
    ["from_balance_before", decodeQuantityValue, 0],
    ["from_balance_after", decodeQuantityValue, 0],
    ["to_balance_before", decodeQuantityValue, 0],
    ["to_balance_after", decodeQuantityValue, 0],
    ["from_smt_witness", decodeTransferSmtWitnessValue, 0],
    ["to_smt_witness", decodeTransferSmtWitnessValue, 0],
  ];

  function decodeTransferDeltaTranscriptValue(payload, context) {
    return decodeRecordFields(payload, context, TransferDeltaTranscriptValueFields);
  }

const TransferTranscriptValueFields = [
    ["batch_hash", decodeHashValue, 0],
    ["deltas", decodeTransferDeltaTranscriptValue, 2],
    ["authority_digest", decodeHashValue, 0],
    ["poseidon_preimage_digest", decodeHashValue, 1],
  ];

  function decodeTransferTranscriptValue(payload, context) {
    return decodeRecordFields(payload, context, TransferTranscriptValueFields);
  }

function decodeFastpqTranscriptMap(payload, context) {
  const reader = new BufferReader(payload, context);
  const count = bigintToSafeNumber(reader.readU64LE("count"), `${context}.count`);
  const entries = [];
  let previousKey = null;
  for (let index = 0; index < count; index += 1) {
    const keyPayload = readNoritoField(reader, `key${index}`);
    const valuePayload = readNoritoField(reader, `value${index}`);
    const keyBytes = decodeFixedBytesValue(keyPayload, 32, `${context}.key[${index}]`);
    if (previousKey !== null && Buffer.compare(previousKey, keyBytes) >= 0) {
      rejectError(`${context} keys are not in${TEXT_CANONICAL}strict order`);
    }
    previousKey = keyBytes;
    const key = decodeHashValue(keyPayload, `${context}.key[${index}]`);
    const value = decodeNoritoVec(
      valuePayload,
      (entry, transcriptIndex) =>
        decodeTransferTranscriptValue(
          entry,
          `${context}[${key}][${transcriptIndex}]`,
        ),
      `${context}[${key}]`,
    );
    entries.push([key, value]);
  }
  reader.assertEof();
  return Object.fromEntries(entries);
}

/**
 * Decode the canonical Norito `BlockProofs` response returned by
 * `/v1/ledger/block/{height}/proof/{entry_hash}`.
 *
 * @param {ArrayBufferView | ArrayBuffer | Buffer} bytes
 * @returns {object}
 */
export function noritoDecodeBlockProofs(bytes) {
  const frame = validateNoritoFrame(bytes, {
    context: "BlockProofs",
    expectedTypeName: BLOCK_PROOFS_TYPE_NAME,
    requireNonEmptyPayload: true,
  });
  return withNoritoLengthFlags(frame.flags & COMPACT_LEN_FLAG, () => {
    const fields = decodeStructFields(frame.payload, "BlockProofs", [
      "block_height",
      "block_hash",
      "executed_block_wire_hash",
      "entry_hash",
      ("entry_" + TEXT_COMMITMENT),
      "entry_proof",
      ("result_" + TEXT_COMMITMENT),
      "result_proof",
      "fastpq_transcripts",
    ]);
    const blockHeight = decodeU64Value(fields.block_height, (TEXT_BLOCK_PROOFS + "block_height"));
    if (blockHeight === "0") {
      rejectError((TEXT_BLOCK_PROOFS + "block_height" + TEXT_MUST_BE + "non-zero"));
    }
    const entryCommitment = decodeBlockMerkleCommitmentValue(
      fields.entry_commitment,
      (TEXT_BLOCK_PROOFS + "entry_" + TEXT_COMMITMENT),
    );
    const resultCommitment = decodeBlockMerkleCommitmentValue(
      fields.result_commitment,
      (TEXT_BLOCK_PROOFS + "result_" + TEXT_COMMITMENT),
    );
    if (entryCommitment.leaf_count !== resultCommitment.leaf_count) {
      rejectError("BlockProofs entry/result commitment leaf counts must match");
    }
    return {
      block_height: blockHeight,
      block_hash: decodeHashValue(fields.block_hash, (TEXT_BLOCK_PROOFS + "block_hash")),
      executed_block_wire_hash: decodeHashValue(
        fields.executed_block_wire_hash,
        (TEXT_BLOCK_PROOFS + "executed_block_wire_hash"),
      ),
      entry_hash: decodeHashValue(fields.entry_hash, (TEXT_BLOCK_PROOFS + "entry_hash")),
      entry_commitment: entryCommitment,
      entry_proof: decodeBlockReceiptProofValue(
        fields.entry_proof,
        (TEXT_BLOCK_PROOFS + "entry_proof"),
      ),
      result_commitment: resultCommitment,
      result_proof: decodeBlockReceiptProofValue(
        fields.result_proof,
        (TEXT_BLOCK_PROOFS + "result_proof"),
      ),
      fastpq_transcripts: decodeFastpqTranscriptMap(
        fields.fastpq_transcripts,
        (TEXT_BLOCK_PROOFS + "fastpq_transcripts"),
      ),
    };
  });
}

const { verifyBlockMerkleProof, verifyBlockProofs } =
  createBlockProofVerification(encodeHashLiteralBytes);
export { verifyBlockMerkleProof, verifyBlockProofs };

/**
 * Encode an `iroha_data_model::zk::OpenVerifyEnvelope` as standalone Norito bytes.
 *
 * @param {object} envelope
 * @returns {Buffer}
 */
export function noritoEncodeOpenVerifyEnvelope(envelope) {
  const payload = encodeOpenVerifyEnvelopePayload(envelope, WIRE_TYPE_OPEN_VERIFY_ENVELOPE);
  return frameNoritoPayload(payload, OPEN_VERIFY_ENVELOPE_SCHEMA_HASH, 0);
}

/**
 * Decode standalone Norito bytes for `iroha_data_model::zk::OpenVerifyEnvelope`.
 *
 * @param {ArrayBufferView | ArrayBuffer | Buffer | string} bytes
 * @returns {object}
 */
export function noritoDecodeOpenVerifyEnvelope(bytes) {
  let buffer;
  if (typeof bytes === JS_TYPE_STRING) {
    const trimmed = bytes.trim();
    if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
      buffer = Buffer.from(trimmed, HEX_ENCODING);
    } else {
      buffer = Buffer.from(trimmed, BASE64_ENCODING);
    }
  } else {
    buffer = toBuffer(bytes);
  }
  const frame = decodeNoritoFrame(
    buffer,
    WIRE_TYPE_OPEN_VERIFY_ENVELOPE,
    OPEN_VERIFY_ENVELOPE_SCHEMA_HASH,
  );
  return decodeOpenVerifyEnvelopePayload(
    frame.payload,
    WIRE_TYPE_OPEN_VERIFY_ENVELOPE,
    frame.flags,
  );
}

/**
 * Decode the exact canonical-standard-base64 form of the checked Rust Exact12
 * fixture archive without consulting the native binding.
 *
 * @param {string} value
 * @returns {object}
 */
export function noritoDecodePrivacyExact12FixtureBundleBase64V1(value) {
  const maximumBase64Length =
    Math.ceil(PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1 / 3) * 4;
  if (typeof value !== JS_TYPE_STRING || value.length > maximumBase64Length) {
    rejectRange(`${TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1_2}base64${TEXT_EXCEEDS_THE}${PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1}-byte archive limit`);
  }
  const archive = decodeExactStandardBase64(
    value,
    (TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1_2 + "base64"),
  );
  return noritoDecodePrivacyExact12FixtureBundleV1(archive);
}

/**
 * Decode one canonical outer `PrivacyExact12FixtureBundleV1` archive.
 * Every nested byte-complete field remains byte-exact and is returned as a
 * copied `Uint8Array`.
 *
 * @param {ArrayBufferView | ArrayBuffer | Buffer} bytes
 * @returns {object}
 */
export function noritoDecodePrivacyExact12FixtureBundleV1(bytes) {
  const view = toBuffer(bytes);
  if (view.length === 0) {
    rejectType((TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1_2 + "archive" + TEXT_MUST_NOT_BE + "empty"));
  }
  if (view.length > PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1) {
    rejectRange(`${TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1_2}archive exceeds ${PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1} bytes`);
  }
  const archive = Buffer.from(view);
  const frame = validateNoritoFrame(archive, {
    context: WIRE_TYPE_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1,
    expectedSchemaHash: PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_HASH_V1,
    expectedPaddingLength: 0,
    requireNonEmptyPayload: true,
  });
  if (frame.flags !== COMPACT_LEN_FLAG) {
    rejectError(`${TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1_2}must use${TEXT_CANONICAL}layout flags 0x${COMPACT_LEN_FLAG.toString(16)}`);
  }
  const bundle = withNoritoCompactLengths(() =>
    decodePrivacyExact12FixtureBundlePayloadV1(frame.payload),
  );
  const canonical = encodePrivacyExact12FixtureBundleCanonicalV1(bundle);
  if (!canonical.equals(archive)) {
    rejectError((TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1_2 + "archive is not" + TEXT_CANONICAL + "or contains trailing data"));
  }
  return externalizePrivacyExact12FixtureBundleV1(bundle);
}

/**
 * Encode a fully byte-complete Exact12 bundle using the canonical Rust outer
 * archive layout. Inputs must retain all twelve protocol rows and cross-field
 * bindings.
 *
 * @param {object} value
 * @returns {Uint8Array}
 */
export function noritoEncodePrivacyExact12FixtureBundleV1(value) {
  const bundle = normalizePrivacyExact12FixtureBundleInputV1(value);
  return Uint8Array.from(encodePrivacyExact12FixtureBundleCanonicalV1(bundle));
}

/**
 * Encode the sole first-release confidential memo envelope.
 *
 * The input must use the exact snake-case V1 shape. No version aliases,
 * recipient-count field, empty slots, or legacy X25519 payload are accepted.
 *
 * @param {object} value
 * @returns {Uint8Array}
 */
export function noritoEncodeConfidentialMemoEnvelopeV1(value) {
  return Uint8Array.from(
    confidentialMemoValueCodecs[0](value, "ConfidentialMemoEnvelopeV1"),
  );
}

/**
 * Decode exactly one canonical first-release confidential memo envelope.
 *
 * @param {Uint8Array | Buffer | number[]} bytes
 * @returns {object}
 */
export function noritoDecodeConfidentialMemoEnvelopeV1(bytes) {
  const payload = Buffer.from(
    normalizeFlexibleBytes(bytes, "ConfidentialMemoEnvelopeV1 wire"),
  );
  return confidentialMemoValueCodecs[1](payload, "ConfidentialMemoEnvelopeV1");
}

function decodePrivacyExact12FixtureBundlePayloadV1(payload) {
  const fields = decodeStructFields(payload, WIRE_TYPE_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1, [
    "version",
    "rows",
  ]);
  const version = decodeU32Value(
    fields.version,
    (TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1 + "version"),
  );
  if (version !== 1) {
    rejectRange((TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1 + "version" + TEXT_MUST_BE + "exactly 1"));
  }
  const reader = new BufferReader(
    fields.rows,
    (TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1 + "rows"),
    COMPACT_LEN_FLAG,
  );
  const count = bigintToSafeNumber(
    reader.readU64LE("count"),
    (TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1 + "rows.count"),
  );
  if (count !== PRIVACY_EXACT12_PROTOCOL_IDS_V1.length) {
    rejectRange(`${TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1}rows${TEXT_MUST_CONTAIN}exactly ${PRIVACY_EXACT12_PROTOCOL_IDS_V1.length} rows`);
  }
  const rows = [];
  for (let index = 0; index < count; index += 1) {
    rows.push(
      decodePrivacyExact12FixtureRowV1(
        readNoritoField(reader, `row${index}`),
        index,
      ),
    );
  }
  reader.assertEof();
  return { version, rows };
}

function decodePrivacyExact12FixtureRowV1(payload, rowIndex) {
  const context = `${TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1}rows[${rowIndex}]`;
  const fields = decodeStructFields(
    payload,
    context,
    PRIVACY_EXACT12_ROW_FIELD_NAMES_V1,
  );
  const protocolDiscriminant = decodeU32Value(
    fields.protocol_id,
    `${context}.protocol_id`,
  );
  if (protocolDiscriminant !== rowIndex) {
    const description =
      protocolDiscriminant < PRIVACY_EXACT12_PROTOCOL_IDS_V1.length
        ? `duplicate, substituted, or reordered protocol ${PRIVACY_EXACT12_PROTOCOL_IDS_V1[protocolDiscriminant]}`
        : `unknown protocol discriminant ${protocolDiscriminant}`;
    rejectType(`${context}.protocol_id contains ${description}`);
  }
  const row = {
    protocolId: PRIVACY_EXACT12_PROTOCOL_IDS_V1[rowIndex],
    statementNorito: decodePrivacyExact12NonEmptyByteVectorV1(
      fields.statement_norito,
      `${context}.statement_norito`,
    ),
    envelopeNorito: decodePrivacyExact12NonEmptyByteVectorV1(
      fields.envelope_norito,
      `${context}.envelope_norito`,
    ),
    submitProofWireId: decodeStringValue(
      fields.submit_proof_wire_id,
      `${context}.submit_proof_wire_id`,
    ),
    submitProofInstructionNorito: decodePrivacyExact12NonEmptyByteVectorV1(
      fields.submit_proof_instruction_norito,
      `${context}.${TEXT_SUBMIT_PROOF_INSTRUCTION_NORITO}`,
    ),
    transactionIntentProjectionNorito:
      decodePrivacyExact12NonEmptyByteVectorV1(
        fields.transaction_intent_projection_norito,
        `${context}${TEXT_TRANSACTION_INTENT_PROJECTION_NORITO}`,
      ),
    transactionIntentDigest: decodeFixedBytesValue(
      fields.transaction_intent_digest,
      32,
      `${context}.${TEXT_TRANSACTION_INTENT}digest`,
    ),
    unsignedTransactionPayloadNorito:
      decodePrivacyExact12NonEmptyByteVectorV1(
        fields.unsigned_transaction_payload_norito,
        `${context}${TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO_2}`,
      ),
    signedTransactionVersionedNorito:
      decodePrivacyExact12NonEmptyByteVectorV1(
        fields.signed_transaction_versioned_norito,
        `${context}${TEXT_SIGNED_TRANSACTION}versioned_norito`,
      ),
    signedTransactionHash: decodeFixedBytesValue(
      fields.signed_transaction_hash,
      32,
      `${context}${TEXT_SIGNED_TRANSACTION}hash`,
    ),
  };
  validatePrivacyExact12FixtureRowBindingsV1(row, rowIndex, context);
  return row;
}

function decodePrivacyExact12NonEmptyByteVectorV1(payload, context) {
  const bytes = decodeByteVecValue(
    payload,
    context,
    PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1,
  );
  if (bytes.length === 0) {
    rejectType(`${context}${TEXT_MUST_NOT_BE}empty`);
  }
  return bytes;
}

function validatePrivacyExact12FixtureRowBindingsV1(row, rowIndex, context) {
  return withNoritoCompactLengths(() =>
    validatePrivacyExact12FixtureRowBindingsCompactV1(row, rowIndex, context),
  );
}

function validatePrivacyExact12FixtureRowBindingsCompactV1(
  row,
  rowIndex,
  context,
) {
  if (row.protocolId !== PRIVACY_EXACT12_PROTOCOL_IDS_V1[rowIndex]) {
    rejectType(`${context}.protocolId is unknown, duplicated, or out of order`);
  }
  if (row.submitProofWireId !== PRIVACY_EXACT12_SUBMIT_PROOF_WIRE_ID_V1) {
    rejectType(`${context}${TEXT_SUBMIT_PROOF_WIRE_ID_MUST_BE}exactly ${PRIVACY_EXACT12_SUBMIT_PROOF_WIRE_ID_V1}`);
  }

  const statementFrame = validatePrivacyExact12NestedFrameV1(
    row.statementNorito,
    PRIVACY_EXACT12_STATEMENT_SCHEMA_HASH_V1,
    PRIVACY_EXACT12_ALIGNED_NESTED_FRAME_PADDING_V1,
    `${context}.statementNorito`,
  );
  const statement = decodePrivacyExact12TaggedPayloadV1(
    statementFrame.payload,
    `${context}.statementNorito.payload`,
  );
  if (statement.tag !== rowIndex) {
    rejectType(`${context}.statementNorito${TEXT_CARRIES_A_SUBSTITUTED}protocol`);
  }

  const envelopeFrame = validatePrivacyExact12NestedFrameV1(
    row.envelopeNorito,
    PRIVACY_EXACT12_ENVELOPE_SCHEMA_HASH_V1,
    PRIVACY_EXACT12_ALIGNED_NESTED_FRAME_PADDING_V1,
    `${context}.envelopeNorito`,
  );
  const envelopeFields = withNoritoCompactLengths(() =>
    decodeStructFields(
      envelopeFrame.payload,
      `${context}.envelopeNorito.payload`,
      PRIVACY_EXACT12_ENVELOPE_FIELD_NAMES_V1,
    ),
  );
  assertPrivacyExact12CanonicalStructPayloadV1(
    envelopeFrame.payload,
    envelopeFields,
    PRIVACY_EXACT12_ENVELOPE_FIELD_NAMES_V1,
    `${context}.envelopeNorito.payload`,
  );
  if (!envelopeFields.wire_magic.equals(PRIVACY_EXACT12_WIRE_MAGIC_V1)) {
    rejectType(`${context}.envelopeNorito carries an invalid final V1 wire marker`);
  }
  if (!envelopeFields.catalog_commitment.equals(PRIVACY_EXACT12_CATALOG_COMMITMENT_V1)) {
    rejectType(`${context}${TEXT_ENVELOPE_NORITO_CARRIES_A_SUBSTITUTED}Exact12 catalog ${TEXT_COMMITMENT}`);
  }
  for (const field of ["proof_system_id", "engine_id"]) {
    if (decodeU32Value(envelopeFields[field], `${context}.${field}`) !==
        PRIVACY_EXACT12_PROOF_ENGINE_TAGS_V1[rowIndex]) {
      rejectType(`${context}${TEXT_ENVELOPE_NORITO_CARRIES_A_SUBSTITUTED}${field}`);
    }
  }
  if (
    decodeU32Value(
      envelopeFields.protocol_id,
      `${context}.envelopeNorito.protocol_id`,
    ) !== rowIndex
  ) {
    rejectType(`${context}${TEXT_ENVELOPE_NORITO_CARRIES_A_SUBSTITUTED}protocol`);
  }
  if (!envelopeFields.statement.equals(statementFrame.payload)) {
    rejectType(`${context}.envelopeNorito does not contain statementNorito`);
  }
  const proof = decodePrivacyExact12TaggedPayloadV1(
    envelopeFields.proof,
    `${context}.envelopeNorito.proof`,
  );
  if (proof.tag !== rowIndex) {
    rejectType(`${context}.envelopeNorito proof${TEXT_CARRIES_A_SUBSTITUTED}protocol`);
  }

  const instructionFrame = validatePrivacyExact12NestedFrameV1(
    row.submitProofInstructionNorito,
    PRIVACY_EXACT12_SUBMIT_PROOF_SCHEMA_HASH_V1,
    PRIVACY_EXACT12_ALIGNED_NESTED_FRAME_PADDING_V1,
    `${context}.${TEXT_SUBMIT_PROOF_INSTRUCTION_NORITO_2}`,
  );
  const instructionFields = withNoritoCompactLengths(() =>
    decodeStructFields(
      instructionFrame.payload,
      `${context}${TEXT_SUBMIT_PROOF_INSTRUCTION_NORITO_PAYLOAD}`,
      ["envelope"],
    ),
  );
  assertPrivacyExact12CanonicalStructPayloadV1(
    instructionFrame.payload,
    instructionFields,
    ["envelope"],
    `${context}${TEXT_SUBMIT_PROOF_INSTRUCTION_NORITO_PAYLOAD}`,
  );
  if (!instructionFields.envelope.equals(envelopeFrame.payload)) {
    rejectType(`${context}.submitProofInstructionNorito does not contain envelopeNorito`);
  }

  const projectionFrame = validatePrivacyExact12NestedFrameV1(
    row.transactionIntentProjectionNorito,
    PRIVACY_EXACT12_TRANSACTION_PAYLOAD_SCHEMA_HASH_V1,
    PRIVACY_EXACT12_TRANSACTION_PAYLOAD_FRAME_PADDING_V1,
    `${context}.${TEXT_TRANSACTION_INTENT_PROJECTION_NORITO_2}`,
  );
  const projectionFields = decodePrivacyExact12TransactionPayloadV1(
    projectionFrame.payload,
    `${context}.transactionIntentProjectionNorito.payload`,
  );
  const unsignedFields = decodePrivacyExact12TransactionPayloadV1(
    row.unsignedTransactionPayloadNorito,
    `${context}.${TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO_3}`,
  );
  validatePrivacyExact12NetworkBindingsV1({
    statementTag: statement.tag,
    statementContent: statement.content,
    projectionDomain: projectionFields.domain,
    unsignedDomain: unsignedFields.domain,
    context,
  });
  for (const field of PRIVACY_EXACT12_TRANSACTION_PAYLOAD_FIELD_NAMES_V1) {
    if (field !== "instructions" && !projectionFields[field].equals(unsignedFields[field])) {
      rejectType(`${context}.transaction intent projection changed independent field ${field}`);
    }
  }
  const expectedCreationTime = 1_700_000_000_000n + BigInt(rowIndex);
  if (
    decodeU64Value(
      unsignedFields.creation_time_ms,
      `${context}${TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO}${TEXT_CREATION_TIME_MS}`,
    ) !== expectedCreationTime.toString()
  ) {
    rejectType(`${context}${TEXT_CARRIES_A_SUBSTITUTED}transaction creation time`);
  }
  const nonce = decodeOptionValue(
    unsignedFields.nonce,
    decodeU32Value,
    `${context}${TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO}nonce`,
  );
  if (nonce !== rowIndex + 1) {
    rejectType(`${context}${TEXT_CARRIES_A_SUBSTITUTED}transaction nonce`);
  }
  const attachments = decodeOptionValue(
    unsignedFields.attachments,
    (payload) => payload,
    `${context}${TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO}attachments`,
  );
  if (attachments !== null) {
    rejectType(`${context} must not carry transaction attachments`);
  }

  const instructionOffset = row.unsignedTransactionPayloadNorito.indexOf(
    row.submitProofInstructionNorito,
  );
  if (instructionOffset < 0) {
    rejectType(`${context}${TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO_DOES_NOT_CONTAIN_THE}byte-complete instruction`);
  }
  if (
    row.unsignedTransactionPayloadNorito.indexOf(
      Buffer.from(PRIVACY_EXACT12_SUBMIT_PROOF_WIRE_ID_V1, UTF8_ENCODING),
    ) < 0
  ) {
    rejectType(`${context}${TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO_DOES_NOT_CONTAIN_THE}exact submission wire id`);
  }

  const expectedIntentDigest = Buffer.from(
    blake3(
      Buffer.concat([
        PRIVACY_EXACT12_INTENT_DIGEST_DOMAIN_V1,
        u64ToLittleEndianBuffer(row.transactionIntentProjectionNorito.length),
        row.transactionIntentProjectionNorito,
      ]),
    ),
  );
  if (!expectedIntentDigest.equals(row.transactionIntentDigest)) {
    rejectType(`${context}.transactionIntentDigest does not match its projection`);
  }

  validatePrivacyExact12SignedTransactionV1(row, context);

  const transactionHashPreimage = Buffer.concat([
    u32ToLittleEndianBuffer(0),
    encodeCompactLength(row.unsignedTransactionPayloadNorito.length),
    row.unsignedTransactionPayloadNorito,
  ]);
  const expectedTransactionHash = Buffer.from(blake2b256(transactionHashPreimage));
  expectedTransactionHash[31] |= 1;
  if (!expectedTransactionHash.equals(row.signedTransactionHash)) {
    rejectType(`${context}.signedTransactionHash does not match the unsigned transaction intent`);
  }
}

function validatePrivacyExact12NestedFrameV1(
  bytes,
  schemaHash,
  expectedPaddingLength,
  context,
) {
  const frame = validateNoritoFrame(bytes, {
    context,
    expectedSchemaHash: schemaHash,
    expectedPaddingLength,
    requireNonEmptyPayload: true,
  });
  if (frame.flags !== COMPACT_LEN_FLAG) {
    rejectError(`${context} must use${TEXT_CANONICAL}compact-length layout flags`);
  }
  const canonical = frameNoritoPayload(
    frame.payload,
    schemaHash,
    COMPACT_LEN_FLAG,
    expectedPaddingLength,
  );
  if (!canonical.equals(bytes)) {
    rejectError(`${context} is not a${TEXT_CANONICAL}uncompressed Norito frame`);
  }
  return frame;
}

function decodePrivacyExact12TaggedPayloadV1(payload, context) {
  const reader = new BufferReader(payload, context, COMPACT_LEN_FLAG);
  const tag = reader.readU32LE("tag");
  const content = readNoritoField(reader, "content");
  reader.assertEof();
  const canonical = Buffer.concat([
    u32ToLittleEndianBuffer(tag),
    encodeCompactLength(content.length),
    content,
  ]);
  if (!canonical.equals(payload)) {
    rejectError(`${context} is not a${TEXT_CANONICAL}tagged payload`);
  }
  return { tag, content };
}

function decodePrivacyExact12TransactionPayloadV1(payload, context) {
  const fields = withNoritoCompactLengths(() =>
    decodeStructFields(
      payload,
      context,
      PRIVACY_EXACT12_TRANSACTION_PAYLOAD_FIELD_NAMES_V1,
    ),
  );
  assertPrivacyExact12CanonicalStructPayloadV1(
    payload,
    fields,
    PRIVACY_EXACT12_TRANSACTION_PAYLOAD_FIELD_NAMES_V1,
    context,
  );
  return fields;
}

function assertPrivacyExact12CanonicalStructPayloadV1(
  payload,
  fields,
  fieldNames,
  context,
) {
  const canonical = withNoritoCompactLengths(() =>
    encodeStructValue(fieldNames.map((field) => [fields[field]])),
  );
  if (!canonical.equals(payload)) {
    rejectError(`${context} contains a non-canonical field layout`);
  }
}

function validatePrivacyExact12SignedTransactionV1(row, context) {
  const signed = row.signedTransactionVersionedNorito;
  if (signed[0] !== 1) {
    rejectType(`${context}${TEXT_SIGNED_TRANSACTION_VERSIONED_NORITO}must use version 1`);
  }
  const payload = signed.subarray(1);
  const fields = withNoritoCompactLengths(() =>
    decodeStructFields(
      payload,
      `${context}${TEXT_SIGNED_TRANSACTION_VERSIONED_NORITO_2}payload`,
      ["signature", "payload", "multisig_signatures"],
    ),
  );
  assertPrivacyExact12CanonicalStructPayloadV1(
    payload,
    fields,
    ["signature", "payload", "multisig_signatures"],
    `${context}${TEXT_SIGNED_TRANSACTION_VERSIONED_NORITO_2}payload`,
  );
  if (fields.signature.length === 0) {
    rejectType(`${context}${TEXT_SIGNED_TRANSACTION_VERSIONED_NORITO}has no signature`);
  }
  if (!fields.payload.equals(row.unsignedTransactionPayloadNorito)) {
    rejectType(`${context}${TEXT_SIGNED_TRANSACTION_VERSIONED_NORITO}does not contain the unsigned payload`);
  }
  const multisig = decodeOptionValue(
    fields.multisig_signatures,
    (entry) => entry,
    `${context}${TEXT_SIGNED_TRANSACTION_VERSIONED_NORITO_2}multisig_signatures`,
  );
  if (multisig !== null) {
    rejectType(`${context}${TEXT_SIGNED_TRANSACTION_VERSIONED_NORITO}must not carry multisig signatures`);
  }
}

function normalizePrivacyExact12FixtureBundleInputV1(value) {
  assertExactObjectKeys(value, ["version", "rows"], WIRE_TYPE_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1);
  if (value.version !== 1) {
    rejectType((TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1 + "version" + TEXT_MUST_BE + "exactly 1"));
  }
  if (
    !Array.isArray(value.rows) ||
    value.rows.length !== PRIVACY_EXACT12_PROTOCOL_IDS_V1.length
  ) {
    rejectType(`${TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1}rows${TEXT_MUST_CONTAIN}exactly ${PRIVACY_EXACT12_PROTOCOL_IDS_V1.length} rows`);
  }
  preflightPrivacyExact12FixtureBundleInputV1(value.rows);
  const rows = value.rows.map((row, rowIndex) => {
    const context = `${TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1}rows[${rowIndex}]`;
    const normalized = {
      protocolId: row.protocolId,
      statementNorito: normalizePrivacyExact12InputBytesV1(
        row.statementNorito,
        `${context}.statementNorito`,
      ),
      envelopeNorito: normalizePrivacyExact12InputBytesV1(
        row.envelopeNorito,
        `${context}.envelopeNorito`,
      ),
      submitProofWireId: row.submitProofWireId,
      submitProofInstructionNorito: normalizePrivacyExact12InputBytesV1(
        row.submitProofInstructionNorito,
        `${context}.${TEXT_SUBMIT_PROOF_INSTRUCTION_NORITO_2}`,
      ),
      transactionIntentProjectionNorito: normalizePrivacyExact12InputBytesV1(
        row.transactionIntentProjectionNorito,
        `${context}.${TEXT_TRANSACTION_INTENT_PROJECTION_NORITO_2}`,
      ),
      transactionIntentDigest: normalizePrivacyExact12InputBytesV1(
        row.transactionIntentDigest,
        `${context}.transactionIntentDigest`,
        32,
      ),
      unsignedTransactionPayloadNorito: normalizePrivacyExact12InputBytesV1(
        row.unsignedTransactionPayloadNorito,
        `${context}.${TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO_3}`,
      ),
      signedTransactionVersionedNorito: normalizePrivacyExact12InputBytesV1(
        row.signedTransactionVersionedNorito,
        `${context}.signedTransactionVersionedNorito`,
      ),
      signedTransactionHash: normalizePrivacyExact12InputBytesV1(
        row.signedTransactionHash,
        `${context}.signedTransactionHash`,
        32,
      ),
    };
    if (typeof normalized.submitProofWireId !== JS_TYPE_STRING) {
      rejectType(`${context}${TEXT_SUBMIT_PROOF_WIRE_ID_MUST_BE}a string`);
    }
    validatePrivacyExact12FixtureRowBindingsV1(normalized, rowIndex, context);
    return normalized;
  });
  return { version: 1, rows };
}

function preflightPrivacyExact12FixtureBundleInputV1(rows) {
  let declaredBytes = 0;
  for (let rowIndex = 0; rowIndex < rows.length; rowIndex += 1) {
    const row = rows[rowIndex];
    const context = `${TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1}rows[${rowIndex}]`;
    assertExactObjectKeys(row, PRIVACY_EXACT12_PUBLIC_ROW_FIELD_NAMES_V1, context);
    for (const field of PRIVACY_EXACT12_PUBLIC_ROW_FIELD_NAMES_V1) {
      if (field === "protocolId" || field === "submitProofWireId") {
        continue;
      }
      const length = binaryByteLength(row[field]);
      if (length === null) {
        rejectType(`${context}.${field}${TEXT_MUST_BE}an exact byte sequence`);
      }
      declaredBytes += length;
      if (declaredBytes > PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1) {
        rejectRange(`${TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1_2}fields exceed the ${PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1}-byte archive limit`);
      }
    }
    if (typeof row.submitProofWireId !== JS_TYPE_STRING) {
      rejectType(`${context}${TEXT_SUBMIT_PROOF_WIRE_ID_MUST_BE}a string`);
    }
    declaredBytes += Buffer.byteLength(row.submitProofWireId, UTF8_ENCODING);
    if (declaredBytes > PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1) {
      rejectRange(`${TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1_2}fields exceed the ${PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1}-byte archive limit`);
    }
  }
}

function normalizePrivacyExact12InputBytesV1(value, context, exactLength = null) {
  let bytes;
  if (Buffer.isBuffer(value)) {
    bytes = Buffer.from(value);
  } else if (ArrayBuffer.isView(value)) {
    bytes = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    bytes = Buffer.from(bytes);
  } else if (value instanceof ArrayBuffer) {
    bytes = Buffer.from(value.slice(0));
  } else if (Array.isArray(value)) {
    bytes = Buffer.allocUnsafe(value.length);
    for (let index = 0; index < value.length; index += 1) {
      const byte = value[index];
      if (!Number.isInteger(byte) || byte < 0 || byte > 0xff) {
        rejectType(`${context}[${index}]${TEXT_MUST_BE}an unsigned byte`);
      }
      bytes[index] = byte;
    }
  } else {
    rejectType(`${context}${TEXT_MUST_BE}an exact byte sequence`);
  }
  if (exactLength === null && bytes.length === 0) {
    rejectType(`${context}${TEXT_MUST_NOT_BE}empty`);
  }
  if (exactLength !== null && bytes.length !== exactLength) {
    rejectType(`${context}${TEXT_MUST_CONTAIN_EXACTLY}${exactLength} bytes`);
  }
  return bytes;
}

function encodePrivacyExact12FixtureBundleCanonicalV1(bundle) {
  const payload = withNoritoCompactLengths(() =>
    encodeStructValue([
      [encodeU32Value(bundle.version, (TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1 + "version"))],
      [
        encodeNoritoVec(bundle.rows, (row, rowIndex) =>
          encodePrivacyExact12FixtureRowV1(row, rowIndex),
        ),
      ],
    ]),
  );
  const archive = frameNoritoPayload(
    payload,
    PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_HASH_V1,
    COMPACT_LEN_FLAG,
    0,
  );
  if (archive.length > PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1) {
    rejectRange(`${TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1_2}archive exceeds ${PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1} bytes`);
  }
  return archive;
}

function encodePrivacyExact12FixtureRowV1(row, rowIndex) {
  const context = `${TEXT_PRIVACY_EXACT12_FIXTURE_BUNDLE_V1}rows[${rowIndex}]`;
  return encodeStructValue([
    [encodeU32Value(rowIndex, `${context}.protocol_id`)],
    [encodeByteVecValue(row.statementNorito, `${context}.statement_norito`)],
    [encodeByteVecValue(row.envelopeNorito, `${context}.envelope_norito`)],
    [encodeNoritoStringValue(row.submitProofWireId)],
    [
      encodeByteVecValue(
        row.submitProofInstructionNorito,
        `${context}.${TEXT_SUBMIT_PROOF_INSTRUCTION_NORITO}`,
      ),
    ],
    [
      encodeByteVecValue(
        row.transactionIntentProjectionNorito,
        `${context}${TEXT_TRANSACTION_INTENT_PROJECTION_NORITO}`,
      ),
    ],
    [
      encodeFixedBytesValue(
        row.transactionIntentDigest,
        32,
        `${context}.${TEXT_TRANSACTION_INTENT}digest`,
      ),
    ],
    [
      encodeByteVecValue(
        row.unsignedTransactionPayloadNorito,
        `${context}${TEXT_UNSIGNED_TRANSACTION_PAYLOAD_NORITO_2}`,
      ),
    ],
    [
      encodeByteVecValue(
        row.signedTransactionVersionedNorito,
        `${context}${TEXT_SIGNED_TRANSACTION}versioned_norito`,
      ),
    ],
    [
      encodeFixedBytesValue(
        row.signedTransactionHash,
        32,
        `${context}${TEXT_SIGNED_TRANSACTION}hash`,
      ),
    ],
  ]);
}

function externalizePrivacyExact12FixtureBundleV1(bundle) {
  return {
    version: bundle.version,
    rows: bundle.rows.map((row) => ({
      protocolId: row.protocolId,
      statementNorito: Uint8Array.from(row.statementNorito),
      envelopeNorito: Uint8Array.from(row.envelopeNorito),
      submitProofWireId: row.submitProofWireId,
      submitProofInstructionNorito: Uint8Array.from(
        row.submitProofInstructionNorito,
      ),
      transactionIntentProjectionNorito: Uint8Array.from(
        row.transactionIntentProjectionNorito,
      ),
      transactionIntentDigest: Uint8Array.from(row.transactionIntentDigest),
      unsignedTransactionPayloadNorito: Uint8Array.from(
        row.unsignedTransactionPayloadNorito,
      ),
      signedTransactionVersionedNorito: Uint8Array.from(
        row.signedTransactionVersionedNorito,
      ),
      signedTransactionHash: Uint8Array.from(row.signedTransactionHash),
    })),
  };
}

function isBinaryLike(value) {
  return (
    Buffer.isBuffer(value) ||
    ArrayBuffer.isView(value) ||
    value instanceof ArrayBuffer
  );
}

function assertWellFormedUtf16(value, context) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        rejectType(`${context}${TEXT_MUST_NOT_CONTAIN}unpaired UTF-16 surrogates`);
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      rejectType(`${context}${TEXT_MUST_NOT_CONTAIN}unpaired UTF-16 surrogates`);
    }
  }
}

function normalizeStrictCancelAssetLockV1(value) {
  const prototype =
    value !== null && typeof value === JS_TYPE_OBJECT
      ? Object.getPrototypeOf(value)
      : undefined;
  if (
    prototype !== Object.prototype &&
    prototype !== null
  ) {
    rejectType((TEXT_CANCEL_ASSET_LOCK_V1_2 + "must be a plain object"));
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== 2 ||
    !keys.includes("escrow_id") ||
    !keys.includes(WIRE_FIELD_EXPECTED_REMAINING_AMOUNT)
  ) {
    rejectType((TEXT_CANCEL_ASSET_LOCK_V1_2 + "must contain exactly escrow_id and " + TEXT_EXPECTED_REMAINING_AMOUNT));
  }

  const { escrow_id: escrowId, expected_remaining_amount: expectedRemainingAmount } =
    value;
  if (typeof escrowId !== JS_TYPE_STRING) {
    rejectType((TEXT_CANCEL_ASSET_LOCK_V1 + "escrow_id" + TEXT_MUST_BE + "a string"));
  }
  assertWellFormedUtf16(escrowId, (TEXT_CANCEL_ASSET_LOCK_V1 + "escrow_id"));
  const hashMatch = CANONICAL_HASH_LITERAL_RE.exec(escrowId);
  if (hashMatch === null) {
    rejectType((TEXT_CANCEL_ASSET_LOCK_V1 + "escrow_id must be one" + TEXT_CANONICAL + "uppercase checksummed hash literal"));
  }
  const [, hashBody, checksum] = hashMatch;
  const expectedChecksum = computeHashLiteralCrc("hash", hashBody);
  if (checksum !== expectedChecksum) {
    rejectType(`${TEXT_CANCEL_ASSET_LOCK_V1}escrow_id has invalid checksum; expected ${expectedChecksum}`);
  }
  const hashBytes = Buffer.from(hashBody, HEX_ENCODING);
  if ((hashBytes[hashBytes.length - 1] & 1) === 0) {
    rejectType((TEXT_CANCEL_ASSET_LOCK_V1 + "escrow_id" + TEXT_MUST_USE_A_NATIVE_HASH_WITH_ITS_MARKER_BIT_SET_2));
  }

  if (typeof expectedRemainingAmount !== JS_TYPE_STRING) {
    rejectType((TEXT_CANCEL_ASSET_LOCK_V1 + "expected_remaining_amount must be a" + TEXT_CANONICAL + "quantity string"));
  }
  assertWellFormedUtf16(
    expectedRemainingAmount,
    (TEXT_CANCEL_ASSET_LOCK_V1 + TEXT_EXPECTED_REMAINING_AMOUNT),
  );
  const quantity = NumericV1.decodeQuantityJson(expectedRemainingAmount);
  if (quantity.mantissa <= 0n) {
    rejectRange((TEXT_CANCEL_ASSET_LOCK_V1 + "expected_remaining_amount" + TEXT_MUST_BE_GREATER_THAN_ZERO));
  }

  return {
    escrow_id: escrowId,
    expected_remaining_amount: expectedRemainingAmount,
  };
}

function encodeCancelAssetLockPayload(value) {
  if (!isPlainObject(value)) {
    rejectType(("CancelAssetLock" + TEXT_MUST_BE_AN_OBJECT_2));
  }
  assertOnlyObjectKeys(
    value,
    ["escrow_id", WIRE_FIELD_EXPECTED_REMAINING_AMOUNT],
    WIRE_TYPE_CANCEL_ASSET_LOCK,
  );
  for (const field of ["escrow_id", WIRE_FIELD_EXPECTED_REMAINING_AMOUNT]) {
    if (!Object.prototype.hasOwnProperty.call(value, field)) {
      rejectType(`${TEXT_CANCEL_ASSET_LOCK}${field}${TEXT_IS_REQUIRED}`);
    }
  }
  const expected = parseNumericLiteral(
    value.expected_remaining_amount,
    CANCEL_LOCK_REMAINING_CONTEXT,
  );
  if (expected.mantissa <= 0n) {
    rejectRange(CANCEL_LOCK_REMAINING_MESSAGE);
  }
  const payload = encodeStructValue([
    [
      encodeEscrowIdValue(
        value.escrow_id,
        (TEXT_CANCEL_ASSET_LOCK + "escrow_id"),
      ),
    ],
    [
      encodeQuantityValue(
        value.expected_remaining_amount,
        CANCEL_LOCK_REMAINING_CONTEXT,
      ),
    ],
  ]);
  return payload;
}

function decodeCancelAssetLockInstructionPayload(payload) {
  const fields = decodeStructFields(payload, WIRE_TYPE_CANCEL_ASSET_LOCK, [
    "escrow_id",
    WIRE_FIELD_EXPECTED_REMAINING_AMOUNT,
  ]);
  const expectedRemainingAmount = decodeQuantityValue(
    fields.expected_remaining_amount,
    CANCEL_LOCK_REMAINING_CONTEXT,
  );
  if (
    NumericV1.decodeQuantityJson(expectedRemainingAmount).mantissa <= 0n
  ) {
    rejectRange(CANCEL_LOCK_REMAINING_MESSAGE);
  }
  return {
    CancelAssetLock: {
      escrow_id: decodeEscrowIdValue(
        fields.escrow_id,
        (TEXT_CANCEL_ASSET_LOCK + "escrow_id"),
      ),
      expected_remaining_amount: expectedRemainingAmount,
    },
  };
}

/**
 * Encode the schema-bound bare `CancelAssetLock` V1 archive.
 *
 * The input is the exact two-field wire object. Hash bytes, hex strings,
 * base64 strings, camel-case aliases, and nested compatibility shapes are not
 * accepted for either field.
 *
 * @param {{escrow_id: string, expected_remaining_amount: string}} value
 * @returns {Uint8Array<ArrayBuffer>}
 */
export function encodeCancelAssetLockV1(value) {
  const canonical = normalizeStrictCancelAssetLockV1(value);
  const payload = withNoritoCompactLengths(() =>
    encodeCancelAssetLockPayload(canonical),
  );
  return Uint8Array.from(
    frameNoritoPayload(
      payload,
      CANCEL_ASSET_LOCK_V1_SCHEMA_HASH,
      COMPACT_LEN_FLAG,
    ),
  );
}

function isExactOwnedUint8Array(value) {
  if (
    !(value instanceof Uint8Array) ||
    Buffer.isBuffer(value) ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype
  ) {
    return false;
  }
  try {
    const buffer = value.buffer;
    return (
      Object.getPrototypeOf(buffer) === ArrayBuffer.prototype &&
      value.byteOffset === 0 &&
      value.byteLength === buffer.byteLength
    );
  } catch {
    return false;
  }
}

/**
 * Decode one exact schema-bound bare `CancelAssetLock` V1 archive.
 *
 * Textual hex/base64 aliases, arrays, padding, substituted schemas or flags,
 * and trailing bytes are rejected.
 *
 * The archive must be an ordinary, full-span `Uint8Array` backed by its own
 * `ArrayBuffer`. Buffer, ArrayBuffer, shared, subclass, and partial-view aliases
 * are rejected.
 *
 * @param {Uint8Array<ArrayBuffer>} bytes
 * @returns {{escrow_id: string, expected_remaining_amount: string}}
 */
export function decodeCancelAssetLockV1(bytes) {
  if (!isExactOwnedUint8Array(bytes)) {
    rejectType((TEXT_CANCEL_ASSET_LOCK_V1_2 + "archive" + TEXT_MUST_BE + "an owned, full-span Uint8Array"));
  }
  if (
    bytes.byteLength < CANCEL_ASSET_LOCK_V1_MIN_ARCHIVE_BYTES ||
    bytes.byteLength > CANCEL_ASSET_LOCK_V1_MAX_ARCHIVE_BYTES
  ) {
    rejectRange(`${TEXT_CANCEL_ASSET_LOCK_V1_2}archive${TEXT_MUST_CONTAIN}between ${CANCEL_ASSET_LOCK_V1_MIN_ARCHIVE_BYTES} and ${CANCEL_ASSET_LOCK_V1_MAX_ARCHIVE_BYTES}${TEXT_CANONICAL}bytes`);
  }
  const archive = Buffer.from(bytes.buffer);
  const frame = validateNoritoFrame(archive, {
    context: "CancelAssetLockV1",
    expectedSchemaHash: CANCEL_ASSET_LOCK_V1_SCHEMA_HASH,
    expectedPaddingLength: 0,
    requireNonEmptyPayload: true,
  });
  if (frame.flags !== COMPACT_LEN_FLAG) {
    rejectError((TEXT_CANCEL_ASSET_LOCK_V1_2 + "must use exactly the compact-length Norito flag"));
  }
  const decoded = withNoritoCompactLengths(
    () => decodeCancelAssetLockInstructionPayload(frame.payload).CancelAssetLock,
  );
  const canonical = normalizeStrictCancelAssetLockV1(decoded);
  const reencoded = encodeCancelAssetLockV1(canonical);
  if (!archive.equals(reencoded)) {
    rejectError((TEXT_CANCEL_ASSET_LOCK_V1_2 + "archive is not byte-canonical"));
  }
  return canonical;
}

function encodeFixedBytesValue(value, length, context) {
  const bytes = Buffer.from(normalizeBytes(value));
  if (bytes.length !== length) {
    rejectType(`${context}${TEXT_MUST_CONTAIN_EXACTLY}${length} bytes`);
  }
  return bytes;
}

function decodeFixedBytesValue(payload, length, context) {
  if (payload.length !== length) {
    rejectError(`${context}${TEXT_MUST_CONTAIN_EXACTLY}${length} bytes`);
  }
  return Buffer.from(payload);
}

function encodeFixedByteArrayArchiveValue(value, length, context) {
  const bytes = encodeFixedBytesValue(value, length, context);
  const parts = [];
  for (let index = 0; index < bytes.length; index += 1) {
    parts.push(encodeNoritoField(encodeU8Value(bytes[index], `${context}[${index}]`)));
  }
  return Buffer.concat(parts);
}

function decodeFixedByteArrayArchiveValue(payload, length, context) {
  const reader = new BufferReader(payload, context);
  const out = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) {
    out[index] = decodeU8Value(
      readNoritoField(reader, `item${index}`),
      `${context}[${index}]`,
    );
  }
  reader.assertEof();
  return out;
}

function encodeByteVecValue(value, _context) {
  const bytes = Buffer.from(normalizeFlexibleBytes(value));
  return Buffer.concat([u64ToLittleEndianBuffer(bytes.length), bytes]);
}

function decodeByteVecValue(payload, context, maxLength = null) {
  const reader = new BufferReader(payload, context);
  const length = bigintToSafeNumber(reader.readU64LE("length"), `${context}.length`);
  if (maxLength !== null && length > maxLength) {
    rejectRange(`${context} exceeds its ${maxLength}-byte decoding limit`);
  }
  const bytes = reader.readBytes(length, "payload");
  reader.assertEof();
  return Buffer.from(bytes);
}

function encodeU64NumberValue(value, context) {
  return encodeU64Value(value, context);
}

function decodeU64NumberValue(payload, context) {
  const value = BigInt(decodeU64Value(payload, context));
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString(10);
}

function encodeDomainIdValue(value, context) {
  const literal = assertExactNonEmptyString(value, context);
  if (literal.trim() !== literal) {
    rejectType(`${context}${TEXT_MUST_NOT_CONTAIN}surrounding whitespace`);
  }
  const segments = literal.split(".");
  if (segments.length !== 2 || segments.some((segment) => segment.length === 0)) {
    rejectType(`${context} must use the exact domain.dataspace form`);
  }
  const [name, dataspace] = segments.map((segment) =>
    canonicalizeDomainIdLabel(segment, `${context} label`),
  );
  return encodeStructValue([
    [encodeNameValue(name, `${context}.name`)],
    [encodeNameValue(dataspace, `${context}.dataspace`)],
  ]);
}

function decodeDomainIdValue(payload, context) {
  const fields = decodeStructFields(payload, context, ["name", "dataspace"]);
  return `${decodeNameValue(fields.name, `${context}.name`)}.${decodeNameValue(
    fields.dataspace,
    `${context}.dataspace`,
  )}`;
}

function encodeNftIdValue(value, context) {
  const literal = assertExactNonEmptyString(value, context);
  const separator = literal.indexOf("$");
  if (separator <= 0 || separator === literal.length - 1) {
    rejectError(`${context} must use name$domain`);
  }
  const domain = literal.slice(separator + 1);
  return encodeTupleValue([
    encodeDomainIdValue(
      domain.includes(".") ? domain : `${domain}.universal`,
      `${context}.domain`,
    ),
    encodeNameValue(literal.slice(0, separator), `${context}.name`),
  ]);
}

function decodeNftIdValue(payload, context) {
  const fields = decodeTupleFields(payload, context, ["domain", "name"]);
  return `${decodeNameValue(fields.name, `${context}.name`)}$${decodeDomainIdValue(
    fields.domain,
    `${context}.domain`,
  )}`;
}

function decodeCanonicalReplicationId(value, context) {
  if (typeof value !== JS_TYPE_STRING || !/^[0-9a-f]{64}$/u.test(value)) {
    rejectType(`${context}${TEXT_MUST_CONTAIN_EXACTLY}64 lowercase hexadecimal characters`);
  }
  if (/^0{64}$/u.test(value)) {
    rejectType(`${context}${TEXT_MUST_NOT_BE}the zero identifier`);
  }
  return Buffer.from(value, HEX_ENCODING);
}

function assertExactObjectKeys(value, expectedKeys, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN_OBJECT}`);
  }
  assertOnlyObjectKeys(value, expectedKeys, context);
  const missing = expectedKeys.find(
    (key) => !Object.prototype.hasOwnProperty.call(value, key),
  );
  if (missing !== undefined) {
    rejectType(`${context} is missing field ${missing}`);
  }
}

function decodeNonzeroFixedBytesHex(payload, context) {
  const bytes = decodeFixedBytesValue(payload, 32, context);
  if (bytes.every((byte) => byte === 0)) {
    rejectType(`${context}${TEXT_MUST_NOT_BE}zero`);
  }
  return bytes.toString(HEX_ENCODING);
}

export const validateSorafsReplicationOrderPayloadV1 = /* @__PURE__ */ createNoritoReplicationOrderValidator(
  BASE64_ENCODING,
  FIELD_METADATA,
  HEX_ENCODING,
  ISSUE_ORDER_ID_CONTEXT,
  REPLICATION_ORDER_V1_SCHEMA_HASH,
  SORAFS_REPLICATION_ORDER_CHUNKER_HANDLES_V1,
  SORAFS_REPLICATION_ORDER_MAX_PAYLOAD_BYTES_V1,
  TEXT_CANONICAL,
  TEXT_EXCEEDS_THE,
  TEXT_ISSUE_REPLICATION_ORDER,
  TEXT_MUST_BE,
  TEXT_MUST_BE_GREATER_THAN_ZERO,
  TEXT_MUST_CONTAIN,
  TEXT_MUST_NOT_BE,
  TEXT_REPLICATION_ORDER_V1,
  UTF8_ENCODING,
  WIRE_FIELD_ORDER_ID,
  decodeByteVecValue,
  decodeCanonicalReplicationId,
  decodeFixedBytesValue,
  decodeNonzeroFixedBytesHex,
  decodeNoritoFrame,
  decodeNoritoVec,
  decodeOptionValue,
  decodeStringValue,
  decodeStructFields,
  decodeU16Value,
  decodeU32Value,
  decodeU64Value,
  decodeU8Value,
  frameNoritoPayload,
  normalizeBytes,
  rejectType,
  withNoritoLengthFlags,
);

/** @internal Exact compact-length AccountId value encoding for typed policy codecs. */
export function encodeAccountIdNoritoValue(value, context = "AccountId") {
  return withNoritoCompactLengths(() =>
    Uint8Array.from(encodeAccountIdValue(value, context)),
  );
}

/** @internal Exact compact-length AccountId value decoding for typed policy codecs. */
export function decodeAccountIdNoritoValue(payload, context = "AccountId") {
  const bytes = Buffer.from(normalizeFlexibleBytes(payload, context));
  return withNoritoCompactLengths(() => decodeAccountIdValue(bytes, context));
}

/** @internal Decode and re-encode one exact compact-length AccountId value. */
export function _canonicalAccountIdNoritoValue(payload, context = "AccountId") {
  return encodeAccountIdNoritoValue(decodeAccountIdNoritoValue(payload, context), context);
}

function encodeAssetDefinitionIdValue(value, context) {
  const literal = normalizeAssetId(value, context);
  const payload = decodeBase58(literal, context);
  if (payload.length !== 21) {
    rejectError(`${context} must decode to exactly 21 bytes`);
  }
  if (payload[0] !== ASSET_DEFINITION_ADDRESS_VERSION) {
    rejectError(`${context} version byte ${payload[0]} is not supported`);
  }
  const checksum = payload.subarray(17);
  const expected = assetDefinitionChecksum(payload.subarray(0, 17));
  if (!checksum.equals(expected)) {
    rejectError(`${context} checksum is invalid`);
  }
  return encodeFixedByteArrayArchiveValue(payload.subarray(1, 17), 16, context);
}

/** @internal Exact compact-length AssetDefinitionId value encoding for typed policy codecs. */
export function encodeAssetDefinitionIdNoritoValue(
  value,
  context = "AssetDefinitionId",
) {
  return withNoritoCompactLengths(() =>
    Uint8Array.from(encodeAssetDefinitionIdValue(value, context)),
  );
}

function decodeAssetDefinitionIdValue(payload, context) {
  const bytes = decodeFixedByteArrayArchiveValue(payload, 16, context);
  const payloadBytes = Buffer.concat([
    Buffer.from([ASSET_DEFINITION_ADDRESS_VERSION]),
    bytes,
  ]);
  return encodeBase58(Buffer.concat([payloadBytes, assetDefinitionChecksum(payloadBytes)]));
}

function encodeHashValue(value, context) {
  return encodeHashLiteralBytes(value, context);
}

function decodeHashValue(payload, context) {
  return decodeHashLiteral(payload, context);
}

function encodeEscrowIdValue(value, context) {
  if (typeof value !== JS_TYPE_STRING) {
    rejectType(`${context}${TEXT_MUST_BE_A}canonical checksummed hash literal`);
  }
  const match = HASH_LITERAL_RE.exec(value);
  if (
    match === null ||
    match[1] !== match[1].toUpperCase() ||
    match[2] !== match[2].toUpperCase()
  ) {
    rejectType(`${context} must use${TEXT_CANONICAL}uppercase hash:<hex>#<checksum> syntax`);
  }
  const bytes = encodeHashValue(value, context);
  if ((bytes[bytes.length - 1] & 1) === 0) {
    rejectType(`${context}${TEXT_MUST_USE_A_NATIVE_HASH_WITH_ITS_MARKER_BIT_SET}`);
  }
  return bytes;
}

function decodeEscrowIdValue(payload, context) {
  if (payload.length !== 32 || (payload[payload.length - 1] & 1) === 0) {
    rejectType(`${context}${TEXT_MUST_USE_A_NATIVE_HASH_WITH_ITS_MARKER_BIT_SET}`);
  }
  return decodeHashValue(payload, context);
}

function encodeStringValue(value, context) {
  if (typeof value !== JS_TYPE_STRING) {
    rejectType(`${context}${TEXT_MUST_BE_A}string`);
  }
  return encodeNoritoStringValue(value);
}

function encodeHashLiteralBytes(value, context) {
  let bytes;
  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer || Array.isArray(value)) {
    bytes = encodeFixedBytesValue(value, 32, context);
  } else {
    const literal = assertExactNonEmptyString(value, context);
    const match = HASH_LITERAL_RE.exec(literal);
    if (match) {
      const [, body, checksum] = match;
      const upper = body.toUpperCase();
      const expected = computeHashLiteralCrc("hash", upper);
      if (checksum.toUpperCase() !== expected) {
        rejectError(`${context} has invalid checksum; expected ${expected}`);
      }
      bytes = Buffer.from(upper, HEX_ENCODING);
    } else if (/^[0-9A-Fa-f]{64}$/.test(literal)) {
      bytes = Buffer.from(literal, HEX_ENCODING);
    } else {
      rejectError(`${context}${TEXT_MUST_BE_A}32-byte hash literal or hex string`);
    }
  }
  if ((bytes[bytes.length - 1] & 1) === 0) {
    rejectType(`${context}${TEXT_MUST_USE_A_NATIVE_HASH_WITH_ITS_MARKER_BIT_SET}`);
  }
  return bytes;
}

function decodeHashLiteral(payload, context) {
  const bytes = decodeFixedBytesValue(payload, 32, context);
  if ((bytes[bytes.length - 1] & 1) === 0) {
    rejectType(`${context}${TEXT_MUST_USE_A_NATIVE_HASH_WITH_ITS_MARKER_BIT_SET}`);
  }
  const body = bytes.toString(HEX_ENCODING).toUpperCase();
  return `hash:${body}#${computeHashLiteralCrc("hash", body)}`;
}

function encodeBackendTagValue(value, context) {
  const backend = assertExactNonEmptyString(value, context);
  switch (backend) {
    case "stark":
      return encodeEnumTagValue(1);
    case "native-pipa-r-pasta":
      return encodeEnumTagValue(0);
    default:
      rejectError(`${context} uses unknown or non-canonical backend label ${backend}`);
  }
}

function decodeBackendTagValue(payload, context) {
  const reader = new BufferReader(payload, context);
  const tag = reader.readU32LE("tag");
  reader.assertEof();
  switch (tag) {
    case 0:
      return "native-pipa-r-pasta";
    case 1:
      return "stark";
    default:
      rejectError(`${context}${TEXT_USES_UNSUPPORTED}backend tag ${tag}`);
  }
}

function encodeOpenVerifyEnvelopePayload(value, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN_OBJECT}`);
  }
  assertOnlyObjectKeys(
    value,
    ["backend", "circuit_id", "vk_hash", "public_inputs", "proof_bytes", "aux"],
    context,
  );
  const circuitId = assertExactNonEmptyString(
    value.circuit_id,
    `${context}.circuit_id`,
  );
  if (circuitId.trim() !== circuitId) {
    rejectType(`${context}.circuit_id must not contain surrounding whitespace`);
  }
  return encodeStructValue([
    [encodeBackendTagValue(value.backend, `${context}${TEXT_BACKEND}`)],
    [encodeNoritoStringValue(circuitId)],
    [encodeFixedBytesValue(value.vk_hash, 32, `${context}.vk_hash`)],
    [encodeByteVecValue(value.public_inputs, `${context}.public_inputs`)],
    [encodeByteVecValue(value.proof_bytes, `${context}.proof_bytes`)],
    [encodeByteVecValue(value.aux ?? [], `${context}.aux`)],
  ]);
}

function decodeOpenVerifyEnvelopePayload(payload, context, flags = 0) {
  return withNoritoLengthFlags(flags & COMPACT_LEN_FLAG, () => {
    const fields = decodeStructFields(payload, context, [
      "backend",
      "circuit_id",
      "vk_hash",
      "public_inputs",
      "proof_bytes",
      "aux",
    ]);
    return {
      backend: decodeBackendTagValue(fields.backend, `${context}${TEXT_BACKEND}`),
      circuit_id: decodeStringValue(fields.circuit_id, `${context}.circuit_id`),
      vk_hash: Array.from(decodeFixedBytesValue(fields.vk_hash, 32, `${context}.vk_hash`)),
      public_inputs: Array.from(
        decodeByteVecValue(fields.public_inputs, `${context}.public_inputs`),
      ),
      proof_bytes: Array.from(
        decodeByteVecValue(fields.proof_bytes, `${context}.proof_bytes`),
      ),
      aux: Array.from(decodeByteVecValue(fields.aux, `${context}.aux`)),
    };
  });
}

function normalizeCanonicalProofAttachmentValue(value, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN_OBJECT}`);
  }
  assertOnlyObjectKeys(
    value,
    ["backend", "proof", "vk_ref", ("vk_" + TEXT_COMMITMENT), "envelope_hash", "lane_privacy"],
    context,
  );
  for (const field of ["backend", "proof", "vk_ref"]) {
    if (!Object.prototype.hasOwnProperty.call(value, field)) {
      rejectType(`${context}.${field}${TEXT_IS_REQUIRED}`);
    }
  }
  const backend = assertPortableProofIdField(value.backend, `${context}${TEXT_BACKEND}`);
  const proof = normalizeCanonicalProofBoxValue(value.proof, backend, `${context}.proof`);
  const vkRef = normalizeCanonicalProofVerifyingKeyId(
    value.vk_ref,
    `${context}.vk_ref`,
  );
  if (vkRef.backend !== backend) {
    rejectType(`${context}.vk_ref.backend must match ${context}${TEXT_BACKEND}`);
  }

  const normalized = { backend, proof, vk_ref: vkRef };
  if (value.vk_commitment !== undefined && value.vk_commitment !== null) {
    normalized.vk_commitment = normalizeNonZeroProofDigest(
      value.vk_commitment,
      `${context}.vk_${TEXT_COMMITMENT}`,
    );
  }
  if (value.envelope_hash !== undefined && value.envelope_hash !== null) {
    const envelopeHash = normalizeNonZeroProofDigest(
      value.envelope_hash,
      `${context}.envelope_hash`,
    );
    const expected = Array.from(blake2b256(Buffer.from(proof.bytes)));
    expected[31] |= 1;
    if (!envelopeHash.every((byte, index) => byte === expected[index])) {
      rejectType(`${context}.envelope_hash must match proof bytes`);
    }
    normalized.envelope_hash = envelopeHash;
  }
  if (value.lane_privacy !== undefined && value.lane_privacy !== null) {
    normalized.lane_privacy = normalizeCanonicalLanePrivacyProofValue(
      value.lane_privacy,
      `${context}.lane_privacy`,
    );
  }
  return normalized;
}

function normalizeCanonicalProofBoxValue(value, backend, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN_OBJECT}`);
  }
  assertExactObjectKeys(value, ["backend", "bytes"], context);
  const proofBackend = assertPortableProofIdField(value.backend, `${context}${TEXT_BACKEND}`);
  if (proofBackend !== backend) {
    rejectType(`${context}.backend must match the attachment backend`);
  }
  if (typeof value.bytes === JS_TYPE_STRING) {
    rejectType(`${context}.bytes${TEXT_MUST_BE}an exact non-empty byte sequence`);
  }
  const declaredLength = binaryByteLength(value.bytes);
  if (declaredLength !== null && declaredLength > proofBoxMaxProofBytes(backend)) {
    rejectRange(`${context}${TEXT_EXCEEDS_THE}complete ${PROOF_BOX_MAX_ENCODED_BYTES}-byte ProofBox limit`);
  }
  const bytes = Array.from(normalizeBytes(value.bytes));
  if (bytes.length === 0) {
    rejectType(`${context}.bytes${TEXT_MUST_NOT_BE}empty`);
  }
  if (!proofBoxFitsEncodedBudget(backend, bytes.length)) {
    rejectRange(`${context}${TEXT_EXCEEDS_THE}complete ${PROOF_BOX_MAX_ENCODED_BYTES}-byte ProofBox limit`);
  }
  return { backend: proofBackend, bytes };
}

function normalizeCanonicalProofVerifyingKeyId(value, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN_OBJECT}`);
  }
  assertExactObjectKeys(value, ["backend", "name"], context);
  return {
    backend: assertPortableProofIdField(value.backend, `${context}${TEXT_BACKEND}`),
    name: assertPortableProofIdField(value.name, `${context}.name`),
  };
}

function assertPortableProofIdField(value, context) {
  if (!isPortableVerifyingKeyIdField(value)) {
    rejectType(`${context} must use portable verifier-key registry syntax`);
  }
  return value;
}

function normalizeNonZeroProofDigest(value, context) {
  const bytes = Array.from(encodeFixedBytesValue(value, 32, context));
  if (bytes.every((byte) => byte === 0)) {
    rejectType(`${context}${TEXT_MUST_BE}non-zero`);
  }
  return bytes;
}

function normalizeCanonicalLanePrivacyProofValue(value, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN_OBJECT}`);
  }
  assertExactObjectKeys(value, ["commitment_id", "witness"], context);
  if (
    !Array.isArray(value.commitment_id) ||
    value.commitment_id.length !== 1 ||
    !Number.isInteger(value.commitment_id[0]) ||
    value.commitment_id[0] < 0 ||
    value.commitment_id[0] > 0xffff
  ) {
    rejectRange(`${context}.commitment_id must be an exact one-element u16 tuple`);
  }
  return {
    commitment_id: value.commitment_id,
    witness: normalizeCanonicalLanePrivacyWitnessValue(
      value.witness,
      `${context}.witness`,
    ),
  };
}

function normalizeCanonicalLanePrivacyWitnessValue(value, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN_OBJECT}`);
  }
  assertExactObjectKeys(value, ["kind", "payload"], context);
  if (value.kind !== "merkle") {
    rejectType(`${context}.kind${TEXT_MUST_BE}exactly merkle`);
  }
  if (!isPlainObject(value.payload)) {
    rejectType(`${context}.payload${TEXT_MUST_BE_AN_OBJECT_2}`);
  }
  assertExactObjectKeys(value.payload, ["leaf", "proof"], `${context}.payload`);
  const leaf = Array.from(
    encodeFixedBytesValue(value.payload.leaf, 32, `${context}.payload.leaf`),
  );
  if (!isPlainObject(value.payload.proof)) {
    rejectType(`${context}.payload.proof${TEXT_MUST_BE_AN_OBJECT_2}`);
  }
  assertExactObjectKeys(
    value.payload.proof,
    ["leaf_index", "audit_path"],
    `${context}.payload.proof`,
  );
  const leafIndex = value.payload.proof.leaf_index;
  const auditPath = value.payload.proof.audit_path;
  if (
    !Array.isArray(auditPath) ||
    auditPath.length < 1 ||
    auditPath.length > LANE_PRIVACY_MERKLE_MAX_DEPTH
  ) {
    rejectRange(`${context}${TEXT_PAYLOAD_PROOF_AUDIT_PATH_MUST}contain 1..=${LANE_PRIVACY_MERKLE_MAX_DEPTH} siblings`);
  }
  if (!laneMerkleLeafIndexFitsDepth(leafIndex, auditPath.length)) {
    rejectRange(`${context}.payload.proof.leaf_index is impossible for the Merkle path depth`);
  }
  const canonicalPath = auditPath.map((entry, index) => {
    if (entry === null || entry === undefined) {
      rejectType(`${context}.payload.proof.audit_path[${index}]${TEXT_MUST_CONTAIN}a sibling`);
    }
    const siblingContext = `${context}.payload.proof.audit_path[${index}]`;
    if (typeof entry !== JS_TYPE_STRING) {
      rejectType(`${siblingContext}${TEXT_MUST_BE_A}canonical HashOf literal`);
    }
    const siblingBytes = encodeHashLiteralBytes(entry, siblingContext);
    const canonical = decodeHashLiteral(siblingBytes, siblingContext);
    if (entry !== canonical) {
      rejectType(`${siblingContext}${TEXT_MUST_BE_A}canonical HashOf literal`);
    }
    return canonical;
  });
  return {
    kind: "merkle",
    payload: {
      leaf,
      proof: { leaf_index: leafIndex, audit_path: canonicalPath },
    },
  };
}

function binaryByteLength(value) {
  if (Array.isArray(value) || Buffer.isBuffer(value)) {
    return value.length;
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    return value.byteLength;
  }
  return null;
}

  const decodeRecordFields = /* @__PURE__ */ createNoritoRecordDecoder(
    decodeStructFields, decodeOptionValue, decodeNoritoVec,
  );

const confidentialMemoValueCodecs =
  /* @__PURE__ */ createNoritoConfidentialMemoCodecs(
    BufferReader, decodeUnsignedLeb128, encodeCompactLength, encodeFixedBytesValue,
    encodeU8Value, isPlainObject, normalizeFlexibleBytes,
  );

const [encodeContractManifestSignaturePayloadValue, , , encodeManifestProvenanceValue, decodeManifestProvenanceValue] = /* @__PURE__ */ createNoritoContractCodecs(
  contractDeclarationCodecsV1,
  assertNonEmptyString,
  assertOnlyObjectKeys,
  decodeConstVecU8Value,
  decodeHashValue,
  decodeNoritoVec,
  decodePublicKeyValue,
  decodeStringValue,
  decodeStructFields,
  decodeU32Value,
  decodeU64NumberValue,
  encodeConstVecU8Value,
  encodeHashValue,
  encodeNoritoStringValue,
  encodeNoritoVec,
  encodeOptionValue,
  encodePublicKeyValue,
  encodeStringValue,
  encodeStructValue,
  encodeU32Value,
  encodeU64NumberValue,
  parsePublicKeyLiteral,
  publicKeyLiteralFromParts,
);


const stakingCodecsV1 = /* @__PURE__ */ createNoritoStakingCodecs({
  encodeU32Value, decodeU32Value, encodeBoolValue, decodeBoolValue,
  encodeStructValue, decodeStructFields, encodeNoritoVec, decodeNoritoVec,
  encodeEnumTagValue, encodeOptionValue, decodeOptionValue,
  encodeU16Value, decodeU16Value, encodeU64Value, decodeU64Value,
  encodeFixedBytesValue, decodeFixedBytesValue, encodeEscrowIdValue, decodeEscrowIdValue,
  encodeAccountIdValue, decodeAccountIdValue, encodeAssetDefinitionIdValue, decodeAssetDefinitionIdValue,
  encodePublicKeyValue, decodePublicKeyValue, parsePublicKeyLiteral, publicKeyLiteralFromParts, curveIdFromAlgorithm,
  decodeConstVecU8Value, encodeQuantityValue, decodeQuantityValue,
});
const STAKING_VALUE_NAMES = new Set(["MonetaryPlan", "RewardClaimPlan", "ValidatorGeneration", "EpochAuthorization", "PreparationRequest", "Preparation"]);
/** Encode a canonical staking plan, validator generation or epoch authorization. This does not authenticate state. */
export function encodeValidatorStakingValueV1(name, value) {
  if (!STAKING_VALUE_NAMES.has(name)) throw new TypeError("unknown staking value type");
  return withNoritoCompactLengths(() => stakingCodecsV1.encode(name, value));
}
/** Decode the sole compact layout and reject noncanonical or trailing bytes. */
export function decodeValidatorStakingValueV1(name, payload) {
  if (!STAKING_VALUE_NAMES.has(name)) throw new TypeError("unknown staking value type");
  const bytes = toBuffer(payload);
  return withNoritoCompactLengths(() => {
    const value = stakingCodecsV1.decode(name, bytes);
    if (!stakingCodecsV1.encode(name, value).equals(bytes)) throw new TypeError("staking value is not byte-canonical");
    return value;
  });
}
const STAKING_PREPARATION_FRAMES_V1 = Object.freeze({
  PreparationRequest: ["iroha_data_model::nexus::staking_preparation::PublicLanePreparationRequestV1", 64 * 1024],
  Preparation: ["iroha_data_model::nexus::staking_preparation::PublicLanePreparationV1", 256 * 1024],
});
/** Exact canonical observation frames, never finality or execution proofs. */
export function encodeValidatorStakingPreparationFrameV1(name, value) {
  if (!Object.hasOwn(STAKING_PREPARATION_FRAMES_V1, name)) throw new TypeError("unknown staking preparation frame");
  const [schema, limit] = STAKING_PREPARATION_FRAMES_V1[name];
  const payload = encodeValidatorStakingValueV1(name, value);
  if (payload.length > limit - 40) throw new RangeError("staking preparation frame exceeds its byte bound");
  return frameNoritoPayload(payload, schemaHashForTypeName(schema), COMPACT_LEN_FLAG, 0);
}
/** Reject retired layouts, alternate schemas, trailing bytes and oversized bodies. */
export function decodeValidatorStakingPreparationFrameV1(name, input) {
  if (!Object.hasOwn(STAKING_PREPARATION_FRAMES_V1, name)) throw new TypeError("unknown staking preparation frame");
  const [schema, limit] = STAKING_PREPARATION_FRAMES_V1[name], bytes = toBuffer(input);
  if (bytes.length > limit) throw new RangeError("staking preparation frame exceeds its byte bound");
  const frame = validateNoritoFrame(bytes, { expectedTypeName: schema, expectedPaddingLength: 0, requireNonEmptyPayload: true });
  if (frame.flags !== COMPACT_LEN_FLAG) throw new TypeError("staking preparation requires the canonical compact layout");
  const value = decodeValidatorStakingValueV1(name, frame.payload);
  if (!encodeValidatorStakingPreparationFrameV1(name, value).equals(bytes)) throw new TypeError("staking preparation frame is not byte-canonical");
  return value;
}
/** Check exact request, network, pinned Global XOR, effects and balance-set binding. */
export function validateValidatorStakingPreparationV1(prepared, request, networkId, xorDefinition) {
  return withNoritoCompactLengths(() => stakingCodecsV1.validatePreparation(prepared, request, networkId, xorDefinition));
}
const nftMarketCodecsV1 = /* @__PURE__ */ createNoritoNftMarketCodecs({
  encodeStructValue, decodeStructFields, encodeEscrowIdValue, decodeEscrowIdValue,
  encodeNftIdValue, decodeNftIdValue, encodeAccountIdValue, decodeAccountIdValue,
  encodeAssetDefinitionIdValue, decodeAssetDefinitionIdValue, encodeQuantityValue, decodeQuantityValue,
  encodeMetadataValue, decodeMetadataValue, encodeU16Value, decodeU16Value, encodeU32Value, encodeU64Value, decodeU64Value,
  encodeOptionValue, decodeOptionValue,
});
/** Canonical bounded native NFT offer and metadata value encoding. */
export function noritoEncodeNftMarketValueV1(name, value) {
  return withNoritoLengthFlags(COMPACT_LEN_FLAG, () => {
    const bytes = nftMarketCodecsV1.encode(name, value);
    if (bytes.length > 64 * 1024) throw new RangeError("native NFT value exceeds bound");
    return bytes;
  });
}
/** Exact decode, rejecting trailing bytes, alternate layouts and unknown fields. */
export function noritoDecodeNftMarketValueV1(name, value) {
  const bytes = toBuffer(value);
  if (bytes.length > 64 * 1024) throw new RangeError("native NFT value exceeds bound");
  return withNoritoLengthFlags(COMPACT_LEN_FLAG, () => {
    const decoded = nftMarketCodecsV1.decode(name, bytes);
    if (!nftMarketCodecsV1.encode(name, decoded).equals(bytes)) throw new TypeError("native NFT value is not byte-canonical");
    return decoded;
  });
}
// Resource primitives keep the same compact layout and exact re-encoding checks
// as public values, without importing the complete application value catalog.
const resourceCodecs = /* @__PURE__ */ createNoritoGameResourceEngine({
  encodePrimitive(name, value) {
    if (name !== "u8") return noritoEncodeNftMarketValueV1(name, value);
    return withNoritoLengthFlags(COMPACT_LEN_FLAG, () => {
      const bytes = instructionGameCodecsV1.encode(name, value);
      if (bytes.length > gameValueMaximumBytesV1(name)) {
        throw new RangeError(TEXT_NATIVE_GAME_VALUE_EXCEEDS_ITS_COMPILED_PAYLOAD_LIMIT);
      }
      return bytes;
    });
  },
  decodePrimitive(name, value) {
    if (name !== "u8") return noritoDecodeNftMarketValueV1(name, value);
    const bytes = toBuffer(value);
    if (bytes.length > gameValueMaximumBytesV1(name)) {
      throw new RangeError(TEXT_NATIVE_GAME_VALUE_EXCEEDS_ITS_COMPILED_PAYLOAD_LIMIT);
    }
    return withNoritoLengthFlags(COMPACT_LEN_FLAG, () => {
      const decoded = instructionGameCodecsV1.decode(name, bytes);
      if (!instructionGameCodecsV1.encode(name, decoded).equals(bytes)) {
        throw new TypeError(TEXT_NATIVE_GAME_VALUE_IS_NOT_BYTE_CANONICAL);
      }
      return decoded;
    });
  },
});
/** Encode one exact bounded resource value using the canonical primitive owner. */
export function encodeGameResourceValueV1(name, value) {
  return resourceCodecs.encode(name, value);
}
/** Decode one bounded resource value with byte-canonical re-encoding. */
export function decodeGameResourceValueV1(name, value) {
  return resourceCodecs.decode(name, value);
}
const gamePrimitivesV1 = {
  resourceCodecs,
  encodeNftIdValue, decodeNftIdValue,
  encodeStructValue, decodeStructFields, encodeNoritoVec, decodeNoritoVec,
  encodeEscrowIdValue, decodeEscrowIdValue,
  encodeAssetDefinitionIdValue, decodeAssetDefinitionIdValue,
  encodeQuantityValue, decodeQuantityValue, encodeBoolValue, decodeBoolValue,
  encodeU8Value, encodeU16Value, encodeU32Value, encodeU64Value,
  decodeU8Value, decodeU16Value, decodeU32Value, decodeU64Value,
  encodePublicKeyValue, decodePublicKeyValue, parsePublicKeyLiteral, publicKeyLiteralFromParts,
  encodeConstVecU8Value, decodeConstVecU8Value, encodeByteVecValue, decodeByteVecValue,
  encodeOptionValue, decodeOptionValue, encodeAccountIdValue, decodeAccountIdValue, encodeEnumTagValue,
};
const instructionGameCodecsV1 = /* @__PURE__ */ createNoritoGameInstructionCodecs(gamePrimitivesV1);
const gameCodecsV1 = /* @__PURE__ */ createNoritoGameCodecs(gamePrimitivesV1);

/** Encode one exact native game or compiled adapter value with the consensus bare compact layout. */
export function noritoEncodeGameValueV1(name, value) {
  return withNoritoLengthFlags(COMPACT_LEN_FLAG, () => {
    const bytes = gameCodecsV1.encode(name, value);
    if (bytes.length > gameValueMaximumBytesV1(name)) throw new RangeError(TEXT_NATIVE_GAME_VALUE_EXCEEDS_ITS_COMPILED_PAYLOAD_LIMIT);
    return bytes;
  });
}

/** Decode an exact native game or compiled adapter value and reject noncanonical byte encodings. */
export function noritoDecodeGameValueV1(name, value) {
  const bytes = toBuffer(value);
  if (bytes.length > gameValueMaximumBytesV1(name)) throw new RangeError(TEXT_NATIVE_GAME_VALUE_EXCEEDS_ITS_COMPILED_PAYLOAD_LIMIT);
  return withNoritoLengthFlags(COMPACT_LEN_FLAG, () => {
    const decoded = gameCodecsV1.decode(name, bytes);
    if (!gameCodecsV1.encode(name, decoded).equals(bytes)) throw new TypeError(TEXT_NATIVE_GAME_VALUE_IS_NOT_BYTE_CANONICAL);
    return decoded;
  });
}

function encodeQuantityValue(value, context) {
  const { mantissa, scale } = parseNumericLiteral(value, context);
  const mantissaBytes = bigintToTwosBytes(mantissa);
  const mantissaPayload = Buffer.concat([
    u32ToLittleEndianBuffer(mantissaBytes.length),
    mantissaBytes,
  ]);
  return Buffer.concat([
    encodeNoritoField(mantissaPayload),
    encodeNoritoField(u32ToLittleEndianBuffer(scale)),
  ]);
}

/** @internal Exact compact-length Quantity value encoding for typed policy codecs. */
export function encodeQuantityNoritoValue(value, context = "Quantity") {
  return withNoritoCompactLengths(() =>
    Uint8Array.from(encodeQuantityValue(value, context)),
  );
}

// Low-level wire decoder retained for the NumericV1-backed Quantity payload.
function decodeNumericValue(payload, context) {
  const reader = new BufferReader(payload, context);
  const mantissaPayload = readNoritoField(reader, "mantissa");
  const scalePayload = readNoritoField(reader, "scale");
  reader.assertEof();

  const mantissaReader = new BufferReader(mantissaPayload, `${context}.mantissa`);
  const byteLength = mantissaReader.readU32LE("byteLength");
  if (byteLength > NumericV1.MAX_MANTISSA_BYTES) {
    rejectRange(`${context}.mantissa${TEXT_EXCEEDS_THE}signed 512-bit bound`);
  }
  const bytes = mantissaReader.readBytes(byteLength, "bytes");
  mantissaReader.assertEof();
  if (bytes.length === 1 && bytes[0] === 0) {
    rejectType(`${context}.mantissa uses a noncanonical zero encoding`);
  }
  if (bytes.length > 1) {
    const last = bytes[bytes.length - 1];
    const previous = bytes[bytes.length - 2];
    if ((last === 0 && (previous & 0x80) === 0)
      || (last === 0xff && (previous & 0x80) !== 0)) {
      rejectType(`${context}.mantissa has redundant sign extension`);
    }
  }

  const scaleReader = new BufferReader(scalePayload, `${context}.scale`);
  const scale = scaleReader.readU32LE("value");
  scaleReader.assertEof();
  if (scale > NumericV1.MAX_SCALE) {
    rejectRange(`${context}.scale exceeds ${NumericV1.MAX_SCALE}`);
  }

  const mantissa = twosBytesToBigInt(bytes);
  return NumericV1.decodeQuantityJson(formatNumericLiteral(mantissa, scale)).toString();
}

function decodeQuantityValue(payload, context) {
  const literal = decodeNumericValue(payload, context);
  return NumericV1.decodeQuantityJson(literal).toString();
}

function encodeU64Value(value, context) {
  const bigint = normalizeU64Input(value, context);
  return u64ToLittleEndianBuffer(bigint);
}

function decodeU64Value(payload, context) {
  if (payload.length !== 8) {
    rejectError(`${context}${TEXT_MUST_CONTAIN_EXACTLY}eight bytes`);
  }
  return payload.readBigUInt64LE(0).toString();
}

function encodeExactBase64StringValue(value, context) {
  if (typeof value !== JS_TYPE_STRING) {
    rejectType(`${context}${TEXT_MUST_BE_A}string`);
  }
  if (value.length === 0 || value.trim() !== value || /\s/u.test(value)) {
    rejectType(`${context}${TEXT_MUST_BE_EXACT_STANDARD_BASE64}`);
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(value) || value.length % 4 !== 0) {
    rejectType(`${context}${TEXT_MUST_BE_EXACT_STANDARD_BASE64}`);
  }
  const decoded = Buffer.from(value, BASE64_ENCODING);
  if (decoded.length === 0 || decoded.toString(BASE64_ENCODING) !== value) {
    rejectType(`${context}${TEXT_MUST_BE_EXACT_STANDARD_BASE64}`);
  }
  return encodeNoritoStringValue(value);
}

function parseNumericLiteral(value, context) {
  let quantity;
  if (value instanceof KotodamaQuantity) {
    quantity = new KotodamaQuantity(value.mantissa, value.scale);
  } else if (typeof value === JS_TYPE_STRING) {
    quantity = NumericV1.decodeQuantityJson(value);
  } else if (typeof value === JS_TYPE_BIGINT) {
    quantity = new KotodamaQuantity(value, 0);
  } else {
    rejectType(`${context}${TEXT_MUST_BE_A}KotodamaQuantity,${TEXT_CANONICAL}quantity string, or bigint; JavaScript numbers are rejected`);
  }
  return { mantissa: quantity.mantissa, scale: quantity.scale };
}

function formatNumericLiteral(mantissa, scale) {
  const negative = mantissa < 0n;
  let digits = (negative ? -mantissa : mantissa).toString();
  if (scale === 0) {
    return `${negative ? "-" : ""}${digits}`;
  }
  while (digits.length <= scale) {
    digits = `0${digits}`;
  }
  const split = digits.length - scale;
  return `${negative ? "-" : ""}${digits.slice(0, split)}.${digits.slice(split)}`;
}

function bigintToTwosBytes(value) {
  if (value === 0n) {
    return Buffer.alloc(0);
  }

  if (value > 0n) {
    const bytes = [];
    let remaining = value;
    while (remaining > 0n) {
      bytes.push(Number(remaining & 0xffn));
      remaining >>= 8n;
    }
    if ((bytes[bytes.length - 1] & 0x80) !== 0) {
      bytes.push(0);
    }
    return Buffer.from(bytes);
  }

  let byteLength = 1;
  while (value < -(1n << BigInt(byteLength * 8 - 1))) {
    byteLength += 1;
  }
  let encoded = (1n << BigInt(byteLength * 8)) + value;
  const bytes = [];
  for (let index = 0; index < byteLength; index += 1) {
    bytes.push(Number(encoded & 0xffn));
    encoded >>= 8n;
  }
  while (bytes.length > 1 && bytes[bytes.length - 1] === 0xff && (bytes[bytes.length - 2] & 0x80) !== 0) {
    bytes.pop();
  }
  return Buffer.from(bytes);
}

function twosBytesToBigInt(bytes) {
  if (bytes.length === 0) {
    return 0n;
  }
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index]);
  }
  if ((bytes[bytes.length - 1] & 0x80) !== 0) {
    value -= 1n << BigInt(bytes.length * 8);
  }
  return value;
}

function publicKeyLiteralFromParts(curve, publicKey, context) {
  ensureCurveIdEnabled(curve, context);
  const bytes = Buffer.from(normalizeBytes(publicKey));
  validatePublicKeyForCurve(curve, bytes, context);
  const multicodec = publicKeyMulticodecForCurveId(curve);
  if (multicodec === null) {
    rejectError(`${context}${TEXT_USES_UNSUPPORTED}public-key curve ${curve}`);
  }
  const prefixHex = Buffer.concat([
    encodeUnsignedLeb128(multicodec),
    encodeUnsignedLeb128(bytes.length),
  ]).toString(HEX_ENCODING);
  return `${prefixHex}${bytes.toString(HEX_ENCODING).toUpperCase()}`;
}

function parsePublicKeyLiteral(literal, context) {
  const normalized = assertNonEmptyString(literal, context);
  if (!MULTIHASH_LITERAL_RE.test(normalized) || normalized.length % 2 !== 0) {
    rejectError(`${context}${TEXT_MUST_BE_A}canonical public-key multihash literal`);
  }
  const bytes = Buffer.from(normalized, HEX_ENCODING);
  let offset = 0;
  const [multicodec, multicodecBytes] = decodeUnsignedLeb128(bytes, offset, `${context}.multicodec`);
  offset += multicodecBytes;
  const [payloadLength, payloadLengthBytes] = decodeUnsignedLeb128(bytes, offset, `${context}.length`);
  offset += payloadLengthBytes;
  const remaining = bytes.subarray(offset);
  if (remaining.length !== payloadLength) {
    rejectError(`${context} public-key multihash length header is invalid`);
  }
  const curve = curveIdForMulticodec(multicodec, context);
  const publicKey = remaining;
  ensureCurveIdEnabled(curve, context);
  validatePublicKeyForCurve(curve, publicKey, context);
  return { curve, publicKey: Buffer.from(publicKey) };
}

function curveIdForMulticodec(multicodec, context) {
  const entry = getCurveEntryByPublicKeyMulticodec(multicodec);
  if (!entry) {
    rejectError(`${context}${TEXT_USES_UNSUPPORTED}public-key multicodec ${multicodec}`);
  }
  return entry.id;
}

function encodeCompactLength(length) {
  let remaining = length >>> 0;
  const bytes = [];
  do {
    const chunk = remaining & 0x7f;
    remaining >>>= 7;
    bytes.push(remaining === 0 ? chunk : chunk | 0x80);
  } while (remaining !== 0);
  return Buffer.from(bytes);
}

function assetDefinitionChecksum(payload) {
  return Buffer.from(blake3(payload)).subarray(0, 4);
}

function decodeBase58(value, context) {
  let number = 0n;
  for (const char of value) {
    const digit = BASE58_LOOKUP.get(char);
    if (digit === undefined) {
      rejectError(`${context}${TEXT_MUST_BE}valid Base58`);
    }
    number = number * 58n + digit;
  }

  const bytes = [];
  while (number > 0n) {
    bytes.push(Number(number & 0xffn));
    number >>= 8n;
  }
  bytes.reverse();

  let leadingZeroes = 0;
  for (const char of value) {
    if (char !== "1") {
      break;
    }
    leadingZeroes += 1;
  }

  return Buffer.concat([Buffer.alloc(leadingZeroes), Buffer.from(bytes)]);
}

function encodeBase58(bytes) {
  let number = 0n;
  for (const byte of bytes) {
    number = (number << 8n) | BigInt(byte);
  }

  const encoded = [];
  while (number > 0n) {
    const remainder = Number(number % 58n);
    encoded.push(BASE58_ALPHABET[remainder]);
    number /= 58n;
  }

  for (const byte of bytes) {
    if (byte !== 0) {
      break;
    }
    encoded.push("1");
  }

  return encoded.reverse().join("") || "1";
}

function requireExactContractApprovalPayload(payload) {
  if (!isPlainObject(payload)) {
    throw new TypeError("MultisigContractCallApproveDto.payload must be the exact contract object");
  }
  return payload;
}

export { exactRegisterDataspaceAssetDefinitionJson, validateNoritoFrame } from "./noritoValueCodecs.js";
