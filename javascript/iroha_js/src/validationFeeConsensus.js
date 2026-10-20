import { Buffer } from "node:buffer";
import { requireNetworkPrefix } from "./networkPrefix.js";

import { AccountAddress } from "./address.js";
import {
  defaultNativeRuntime,
  resolveNativeRuntimeBinding,
} from "./nativeRuntime.js";
import { networkIdBytes } from "./networkId.js";
import { ensureCanonicalAccountId } from "./normalizers.js";
import { normalizeParliamentGovernanceCertificateV1 } from "./parliamentApiV1.js";
import { snapshotBoundedBytes as boundedBytes } from "./boundedByteSnapshot.js";
import {
  record, exactKeys, lowerHex32, irohaHash32,
  normalizeValidationFeeCheckpointV1, normalizeValidationFeeLedgerBindingV1,
} from "./validationFeeTrust.js";
export {
  VALIDATION_FEE_LEDGER_BINDING_SCHEMA,
  normalizeValidationFeeCheckpointV1, normalizeValidationFeeLedgerBindingV1,
} from "./validationFeeTrust.js";
import { parseStrictLosslessIntegerJson } from "./strictLosslessJson.js";
import { normalizeValidationFeePayoutBinding, normalizeValidationFeeRewardCustody } from "./governanceProposalV1.js";

export const VALIDATION_FEE_VERIFIED_POLICY_PROJECTION_SCHEMA =
  "iroha.validation_fee.verified_policy_projection.v1";
export const VALIDATION_FEE_CURRENT_POLICY_PROOF_PATH =
  "/v1/validation-fee/policy/current/proof";
export const VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
export const VALIDATION_FEE_REQUIRED_BRIDGE_ABI_VERSION = 31;

const VERIFIED_PAGE_KEYS = Object.freeze(["projectionJson", "promotedCheckpointNorito"]);
const PROJECTION_KEYS = Object.freeze([
  "current_policy",
  "conversion_policy",
  "evaluated_block_hash",
  "evaluated_block_height",
  "evaluated_context_id",
  "head_policy_hash",
  "head_policy_version",
  "more_available",
  "network_id",
  "observed_ledger_tip_height",
  "policy_chain_genesis_hash",
  "registry_hash",
  "schema",
  "trusted_checkpoint_context_id",
  "trusted_checkpoint_height",
  "version",
]);
const CURRENT_POLICY_KEYS = Object.freeze([
  "activePolicyHash",
  "activePolicyVersion",
  "chargingMode",
  "effectiveFromHeight",
  "effective_from_ms",
  "notice_published_at_ms",
  "retail_schedule",
  "feeAssetDefinitionId",
  "feeMinorUnits",
  "feeScale",
  "parliament",
  "reward_custody",
]);
const PARLIAMENT_PROPOSAL_KEYS = Object.freeze([
  "certified_at_height",
  "enacted_at_height",
  "governance_certificate",
  "governance_certificate_id",
  "payload_hash",
  "proposal_id",
  "proposal_kind",
  "proposal_operator",
]);
const CANONICAL_UNSIGNED_DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const MAX_U128 = (1n << 128n) - 1n;

function positiveU64(value, label) {
  let parsed;
  if (typeof value === "bigint") {
    parsed = value;
  } else if (typeof value === "number" && Number.isSafeInteger(value)) {
    parsed = BigInt(value);
  } else if (typeof value === "string" && /^[1-9][0-9]*$/u.test(value)) {
    parsed = BigInt(value);
  } else {
    throw new TypeError(`${label} must be a positive uint64`);
  }
  if (parsed <= 0n || parsed > 0xffff_ffff_ffff_ffffn) {
    throw new TypeError(`${label} must be a positive uint64`);
  }
  return parsed;
}

function canonicalText(value, label) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 4_096 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new TypeError(`${label} must be canonical bounded text`);
  }
  return value;
}

function unsignedDecimalString(value, maximum, label, positive = false) {
  if (
    typeof value !== "string" ||
    value.length > maximum.toString().length ||
    !CANONICAL_UNSIGNED_DECIMAL.test(value)
  ) {
    throw new TypeError(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum || (positive && parsed === 0n)) {
    throw new TypeError(
      `${label} must be a ${positive ? "positive" : "non-negative"} bounded integer`,
    );
  }
  return parsed;
}

function u64String(value, label, positive = false) {
  return unsignedDecimalString(value, MAX_U64, label, positive);
}

function u128String(value, label, positive = false) {
  return unsignedDecimalString(value, MAX_U128, label, positive);
}

function unsignedInteger(value, maximum, label) {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    throw new TypeError(`${label} must be an unsigned integer no greater than ${maximum}`);
  }
  return value;
}

function requireEqual(left, right, label) {
  if (left !== right) {
    throw new TypeError(`${label} must match its verified proposal evidence`);
  }
}

function canonicalAccountId(value, label) {
  const canonical = ensureCanonicalAccountId(value, label);
  if (canonical !== value) {
    throw new TypeError(`${label} must use the exact canonical account literal`);
  }
  AccountAddress.parseEncoded(value);
  return value;
}

function validateParliamentProposal(value, expectedKind, label) {
  const proposal = record(value, label);
  exactKeys(proposal, PARLIAMENT_PROPOSAL_KEYS, label);
  if (proposal.proposal_kind !== expectedKind) {
    throw new TypeError(`${label}.proposal_kind must be ${expectedKind}`);
  }
  const proposalOperator = canonicalAccountId(
    proposal.proposal_operator,
    `${label}.proposal_operator`,
  );
  const proposalId = lowerHex32(proposal.proposal_id, `${label}.proposal_id`);
  const payloadHash = lowerHex32(proposal.payload_hash, `${label}.payload_hash`);
  requireEqual(payloadHash, proposalId, `${label}.payload_hash`);
  lowerHex32(
    proposal.governance_certificate_id,
    `${label}.governance_certificate_id`,
  );
  const certifiedAtHeight = u64String(
    proposal.certified_at_height,
    `${label}.certified_at_height`,
    true,
  );
  const enactedAtHeight = u64String(
    proposal.enacted_at_height,
    `${label}.enacted_at_height`,
    true,
  );
  const certificate = normalizeParliamentGovernanceCertificateV1(
    proposal.governance_certificate,
  );
  if (
    certificate.proposal_content_id !== proposalId ||
    BigInt(certificate.certified_at_height) !== certifiedAtHeight ||
    BigInt(certificate.enact_at_height) !== enactedAtHeight
  ) {
    throw new TypeError(`${label} differs from its retained governance certificate`);
  }
  return { certificate, enactedAtHeight, proposalId, proposalOperator };
}

function validateConversionPolicy(value, currentPolicy, height, label) {
  if (value === null) return;
  const conversion = record(value, label);
  exactKeys(conversion, ["revision", "binding", "authority", "lifecycle_seal_hash"], label);
  positiveU64(conversion.revision, `${label}.revision`);
  const binding = normalizeValidationFeePayoutBinding(conversion.binding, `${label}.binding`);
  const authority = validateParliamentProposal(conversion.authority, "ValidationFeePayoutLifecycleV1", `${label}.authority`);
  irohaHash32(conversion.lifecycle_seal_hash, `${label}.lifecycle_seal_hash`);
  if (authority.enactedAtHeight >= height) throw new TypeError(`${label} is not available at the finalized height`);
  if (currentPolicy !== null) {
    if (authority.proposalId === currentPolicy.parliament.proposal_id) throw new TypeError(`${label} requires a distinct Parliament enactment`);
    for (const [field, value] of Object.entries(currentPolicy.reward_custody)) {
      if (String(binding[field]) !== String(value)) throw new TypeError(`${label} differs from immutable reward custody`);
    }
  }
}

function validateCurrentPolicy(value, label) {
  if (value === null) return;
  const policy = record(value, label);
  exactKeys(policy, CURRENT_POLICY_KEYS, label);
  u64String(policy.activePolicyVersion, `${label}.activePolicyVersion`, true);
  irohaHash32(policy.activePolicyHash, `${label}.activePolicyHash`);
  canonicalText(policy.feeAssetDefinitionId, `${label}.feeAssetDefinitionId`);
  const feeScale = unsignedInteger(policy.feeScale, 255, `${label}.feeScale`);
  const feeMinorUnits = u128String(
    policy.feeMinorUnits,
    `${label}.feeMinorUnits`,
    true,
  );
  if (
    feeScale !== 2 ||
    feeMinorUnits === 0n ||
    policy.chargingMode !== "RETAIL_MONTHLY_ALLOWANCE"
  ) {
    throw new TypeError(`${label} is not an enabled first-release policy`);
  }
  const effectiveFromHeight = u64String(
    policy.effectiveFromHeight,
    `${label}.effectiveFromHeight`,
    true,
  );
  const effectiveMs = positiveU64(policy.effective_from_ms, `${label}.effective_from_ms`);
  const noticeMs = positiveU64(policy.notice_published_at_ms, `${label}.notice_published_at_ms`);
  const local = new Date(Number(effectiveMs + 39_600_000n));
  if (effectiveMs - noticeMs < 2_592_000_000n || !Number.isFinite(local.getTime()) || local.getUTCDate()!==1 || local.getUTCHours()!==0 || local.getUTCMinutes()!==0 || local.getUTCSeconds()!==0 || local.getUTCMilliseconds()!==0) throw new TypeError(`${label} requires 30 days notice and Honiara month activation`);
  const schedule=record(policy.retail_schedule,`${label}.retail_schedule`);
  exactKeys(schedule,["included_payments","overage_minor","maintenance_tiers"],`${label}.retail_schedule`);
  if (unsignedInteger(schedule.included_payments,0xffff_ffff,`${label}.included_payments`)===0) throw new TypeError("monthly payment inclusion must be positive");
  positiveU64(schedule.overage_minor,`${label}.overage_minor`);
  if (!Array.isArray(schedule.maintenance_tiers)||schedule.maintenance_tiers.length===0||schedule.maintenance_tiers.length>32) throw new TypeError("invalid maintenance tiers");
  let previous=-1n,previousFee=0n;
  for(const [index,tier] of schedule.maintenance_tiers.entries()) {
    exactKeys(record(tier,"maintenance tier"),["minimum_average_balance_minor","monthly_fee_minor"],"maintenance tier");
    const threshold=u64String(String(tier.minimum_average_balance_minor),"maintenance threshold");const fee=positiveU64(tier.monthly_fee_minor,"maintenance fee");
    if ((index===0&&threshold!==0n)||threshold<=previous||fee<previousFee) throw new TypeError("invalid maintenance tier order");
    previous=threshold;previousFee=fee;
  }
  const parliament = validateParliamentProposal(policy.parliament, "ValidationFeePolicyV1", `${label}.parliament`);
  const custody = normalizeValidationFeeRewardCustody(policy.reward_custody, `${label}.reward_custody`);
  if (policy.feeAssetDefinitionId !== custody.ds_asset_id || parliament.enactedAtHeight + 1n !== effectiveFromHeight) {
    throw new TypeError(`${label} differs from its Parliament authority or immutable reward custody`);
  }
}

function nativeBinding(nativeRuntime) {
  const native = resolveNativeRuntimeBinding(nativeRuntime);
  if (
    typeof native?.connectNoritoBridgeAbiVersion !== "function" ||
    native.connectNoritoBridgeAbiVersion() !==
      VALIDATION_FEE_REQUIRED_BRIDGE_ABI_VERSION ||
    typeof native?.validationFeeCurrentPolicyProofRequestV1 !== "function" ||
    typeof native?.validationFeeVerifyCurrentPolicyProofV1 !== "function"
  ) {
    throw new Error(
      `native binding lacks the ABI ${VALIDATION_FEE_REQUIRED_BRIDGE_ABI_VERSION} validation-fee consensus proof verifier`,
    );
  }
  return native;
}

/** Encode the exact Norito V1 proof request for `checkpoint`. */
function encodeValidationFeeCurrentPolicyProofRequestV1WithRuntime(
  nativeRuntime,
  checkpoint,
) {
  const normalized = normalizeValidationFeeCheckpointV1(checkpoint);
  const native = nativeBinding(nativeRuntime);
  const encoded = native.validationFeeCurrentPolicyProofRequestV1(
    normalized.checkpointNorito,
  );
  if (!encoded || encoded.length === 0) {
    throw new Error("native validation-fee request encoder returned no bytes");
  }
  return Buffer.from(encoded);
}

function projectionHeight(value, label) {
  return positiveU64(value, label);
}

function freezeProjection(value) {
  const stack = [value];
  let visited = 0;
  while (stack.length > 0) {
    const next = stack.pop();
    if (next === null || typeof next !== "object" || Object.isFrozen(next)) continue;
    visited += 1;
    if (visited > 100_000) {
      throw new TypeError("validation-fee projection exceeds the object bound");
    }
    for (const child of Object.values(next)) stack.push(child);
    Object.freeze(next);
  }
  return value;
}

/**
 * Locally verify one canonical Norito proof page and return its immutable
 * policy projection plus the complete promoted checkpoint from that same native verification.
 */
function verifyValidationFeeCurrentPolicyProofV1WithRuntime(
  nativeRuntime,
  proofNorito,
  bindingValue,
  checkpointValue,
  networkPrefix,
) {
  requireNetworkPrefix(networkPrefix);
  const binding = normalizeValidationFeeLedgerBindingV1(bindingValue);
  const checkpoint = normalizeValidationFeeCheckpointV1(checkpointValue);
  const proof = boundedBytes(proofNorito, "proofNorito", VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES);
  const native = nativeBinding(nativeRuntime);
  const page = record(native.validationFeeVerifyCurrentPolicyProofV1(
    proof,
    Buffer.from(networkIdBytes(binding.networkId, "validation-fee ledger binding.networkId")),
    Buffer.from(binding.policyChainGenesisHash, "hex"),
    checkpoint.checkpointNorito,
    networkPrefix,
  ), "native validation-fee verified page");
  exactKeys(page, VERIFIED_PAGE_KEYS, "native validation-fee verified page");
  const promotedCheckpoint = normalizeValidationFeeCheckpointV1({
    checkpointNorito: page.promotedCheckpointNorito,
  });
  const json = page.projectionJson;
  if (typeof json !== "string" || json.length === 0) {
    throw new Error("native validation-fee verifier returned no projection");
  }
  const projection = record(
    parseStrictLosslessIntegerJson(json, "validation-fee verified projection"),
    "validation-fee verified projection",
  );
  exactKeys(
    projection,
    PROJECTION_KEYS,
    "validation-fee verified projection",
  );
  const projectedTrustedCheckpointHeight = projectionHeight(
    projection.trusted_checkpoint_height,
    "validation-fee projection.trusted_checkpoint_height",
  );
  if (
    projection.schema !== VALIDATION_FEE_VERIFIED_POLICY_PROJECTION_SCHEMA ||
    projection.version !== 1 ||
    projection.network_id !== binding.networkId.toString() ||
    projection.policy_chain_genesis_hash !== binding.policyChainGenesisHash
  ) {
    throw new TypeError(
      "validation-fee verified projection differs from its immutable binding or checkpoint",
    );
  }
  const normalized = {
    ...projection,
    head_policy_version: projectionHeight(
      projection.head_policy_version,
      "validation-fee projection.head_policy_version",
    ),
    trusted_checkpoint_height: projectedTrustedCheckpointHeight,
    evaluated_block_height: projectionHeight(
      projection.evaluated_block_height,
      "validation-fee projection.evaluated_block_height",
    ),
    observed_ledger_tip_height: projectionHeight(
      projection.observed_ledger_tip_height,
      "validation-fee projection.observed_ledger_tip_height",
    ),
  };
  irohaHash32(
    normalized.trusted_checkpoint_context_id,
    "validation-fee projection.trusted_checkpoint_context_id",
  );
  irohaHash32(
    normalized.evaluated_context_id,
    "validation-fee projection.evaluated_context_id",
  );
  irohaHash32(
    normalized.evaluated_block_hash,
    "validation-fee projection.evaluated_block_hash",
  );
  irohaHash32(
    normalized.registry_hash,
    "validation-fee projection.registry_hash",
  );
  irohaHash32(
    normalized.head_policy_hash,
    "validation-fee projection.head_policy_hash",
  );
  if (typeof normalized.more_available !== "boolean") {
    throw new TypeError(
      "validation-fee projection.more_available must be boolean",
    );
  }
  validateCurrentPolicy(
    normalized.current_policy,
    "validation-fee projection.current_policy",
  );
  validateConversionPolicy(
    normalized.conversion_policy,
    normalized.current_policy,
    normalized.evaluated_block_height,
    "validation-fee projection.conversion_policy",
  );
  if (
    normalized.evaluated_block_height < normalized.trusted_checkpoint_height ||
    normalized.observed_ledger_tip_height < normalized.evaluated_block_height ||
    normalized.more_available !== (normalized.evaluated_block_height < normalized.observed_ledger_tip_height) ||
    (normalized.more_available && normalized.evaluated_block_height === normalized.trusted_checkpoint_height)
  ) {
    throw new TypeError("validation-fee checkpoint promotion did not advance consistently");
  }
  return Object.freeze({ projection: freezeProjection(normalized), promotedCheckpoint });
}

/** @internal Create validation-fee consensus codecs for one immutable runtime. */
export function createValidationFeeConsensusApi(nativeRuntime) {
  return Object.freeze({
    encodeValidationFeeCurrentPolicyProofRequestV1: (checkpoint) =>
      encodeValidationFeeCurrentPolicyProofRequestV1WithRuntime(
        nativeRuntime,
        checkpoint,
      ),
    verifyValidationFeeCurrentPolicyProofV1: (
      proofNorito,
      bindingValue,
      checkpointValue,
      networkPrefix,
    ) =>
      verifyValidationFeeCurrentPolicyProofV1WithRuntime(
        nativeRuntime,
        proofNorito,
        bindingValue,
        checkpointValue,
        networkPrefix,
      ),
  });
}

const DEFAULT_VALIDATION_FEE_CONSENSUS_API =
  createValidationFeeConsensusApi(defaultNativeRuntime);

/** Encode the exact Norito V1 proof request for `checkpoint`. */
export function encodeValidationFeeCurrentPolicyProofRequestV1(checkpoint) {
  return DEFAULT_VALIDATION_FEE_CONSENSUS_API
    .encodeValidationFeeCurrentPolicyProofRequestV1(checkpoint);
}

/**
 * Locally verify one canonical Norito proof page and return its immutable
 * policy projection plus the complete promoted checkpoint from that same native verification.
 */
export function verifyValidationFeeCurrentPolicyProofV1(
  proofNorito,
  bindingValue,
  checkpointValue,
  networkPrefix,
) {
  return DEFAULT_VALIDATION_FEE_CONSENSUS_API
    .verifyValidationFeeCurrentPolicyProofV1(
      proofNorito,
      bindingValue,
      checkpointValue,
      networkPrefix,
    );
}
