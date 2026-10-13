//! `Transaction`-related functionality of Iroha.
//!
//! Admission enforces the captured physical Nexus policy independently of the
//! authenticated native execution route. Ordinary policy routes stay frozen at
//! the predecessor state; authenticated genesis uses its in-progress bootstrap state.
//!
//! Types represent various stages of a `Transaction`'s lifecycle. For example, `Transaction` is the
//! start, when a transaction had been received by Torii.
//!
//! This is also where the actual execution of instructions, as well
//! as various forms of validation are performed.
mod authority_admission;
use crate::execution_attempt::{ExecutionAttemptError, ExecutionDeferred};
#[cfg(any(test, feature = "iroha-core-tests"))]
use crate::queue::evaluate_policy_plan_with_nexus_and_world_at_block_height;
use crate::state::network_policy_routes::CapturedNetworkPolicyRoute;

use crate::{
    compliance::{LaneComplianceContext, LaneComplianceEvaluation},
    governance::manifest::{GovernanceRules, LaneManifestRegistryHandle},
    interlane::{LanePrivacyRegistry, verify_lane_privacy_proofs},
    nexus::space_directory::{
        LaneIdentityMetadataError,
        extract_authority_domains as extract_directory_authority_domains,
        extract_lane_identity_metadata as extract_directory_lane_identity_metadata,
    },
    smartcontracts::{code, ivm::cache::IvmCache},
    state::{
        StateBlock, StateReadOnly, StateReadOnlyWithTransactions, StateTransaction, WorldReadOnly,
    },
};
pub(crate) use authority_admission::instructions_allow_multisig_envelope_authority;
pub use authority_admission::{allows_unregistered_authority, executable_self_registers_authority};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use core::{fmt, str::FromStr as _};
use eyre::Result;
use hex;
pub use iroha_data_model::prelude::*;
use iroha_data_model::{
    fraud::types::FraudAssessment,
    isi::error::Mismatch,
    isi::{
        runtime_upgrade::{ActivateRuntimeUpgrade, CancelRuntimeUpgrade, ProposeRuntimeUpgrade},
        smart_contract_code::{
            ActivateContractInstance, CommitContractDeployment, DeactivateContractInstance,
            FinalizeSmartContractCodeUpload, RegisterSmartContractBytes, RegisterSmartContractCode,
            RemoveSmartContractBytes, UploadSmartContractCodeChunk,
        },
    },
    nexus::UniversalAccountId,
    query::error::FindError,
    smart_contract::manifest::{ContractManifest, MANIFEST_METADATA_KEY},
    transaction::signed::{
        SealedTransactionCommitmentPayload, SealedTransactionReveal,
        SignedSealedTransactionCommitment, compute_sealed_transaction_commitment,
    },
    transaction::signed_attachments::{ActionOperationV1, SignedAttachmentErrorV1},
    transaction::{error::TransactionLimitError, signed::TransactionSignatureError},
};
use iroha_logger::{debug, error, warn};
use iroha_macro::FromVariant;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::state_path::StatePath;
use iroha_primitives::time::TimeSource;
use mv::storage::StorageReadOnly;
use std::{
    any::TypeId,
    borrow::Cow,
    collections::BTreeSet,
    sync::{Arc, LazyLock, OnceLock},
    time::{Duration, SystemTime, SystemTimeError},
};
#[cfg(feature = "telemetry")]
type StateTelemetry = crate::telemetry::StateTelemetry;
#[cfg(not(feature = "telemetry"))]
type StateTelemetry = ();
type NexusDataSpaceId = iroha_model_base::topology::DataSpaceId;
type NexusLaneId = iroha_model_base::topology::LaneId;
/// Decode one canonical Norito-framed [`TransactionEntrypoint`] and return its identity.
///
/// The identity is derived from the decoded signed intent rather than the transport frame. This
/// prevents alternate framing, authorization-proof changes, or zero-filled logical tails from
/// creating replay-distinct transaction identifiers.
pub(crate) fn entrypoint_hash_from_framed_bytes(
    framed: &[u8],
) -> Result<HashOf<TransactionEntrypoint>, norito::core::Error> {
    let entrypoint: TransactionEntrypoint = norito::decode_canonical(framed)?;
    Ok(entrypoint.hash())
}
/// Return the exact signed-transaction identity carried by an entrypoint, when one exists.
#[must_use]
pub(crate) fn exact_signed_transaction_hash(
    entrypoint: &TransactionEntrypoint,
) -> Option<HashOf<SignedTransaction>> {
    match entrypoint {
        TransactionEntrypoint::External(signed) => Some(signed.hash()),
        TransactionEntrypoint::SealedReveal(reveal) => Some(reveal.signed_transaction().hash()),
        TransactionEntrypoint::SealedCommitment(_) => None,
    }
}
/// Collect replay identities for fixture comparisons.
/// Production checks the original accepted transaction without allocating this collection.
///
/// A sealed reveal always exposes both its carrier and enclosed signed identity
/// to duplicate/replay validation. This helper does not decide which identities
/// a rejected reveal is authenticated to commit; use
/// [`for_each_canonical_carrier_membership_hash`] at the persistence boundary.
#[cfg(test)]
pub(crate) fn canonical_replay_alias_hashes(
    entrypoints: &[TransactionEntrypoint],
) -> Vec<HashOf<TransactionEntrypoint>> {
    let mut hashes = Vec::with_capacity(entrypoints.len().saturating_mul(2));
    for entrypoint in entrypoints {
        let carrier_hash = entrypoint.hash();
        hashes.push(carrier_hash);
        if let TransactionEntrypoint::SealedReveal(reveal) = entrypoint {
            let execution_hash = reveal.signed_transaction().hash_as_entrypoint();
            if execution_hash != carrier_hash {
                hashes.push(execution_hash);
            }
        }
    }
    hashes
}
/// Collect authenticated carrier identities for fixture comparisons.
/// Production retains the visitor output in its original funded source owner.
///
/// Every entrypoint commits its outer carrier identity. A sealed reveal commits
/// the enclosed signed identity only when it exactly authenticates a pending
/// commitment from the pre-block state at this block's height. Re-reading the
/// pre-block value keeps the classification stable after successful removal,
/// rejected execution rollback, or end-of-block expiry pruning.
#[cfg(test)]
pub(crate) fn canonical_carrier_membership_hashes(
    state_block: &StateBlock<'_>,
    entrypoints: &[TransactionEntrypoint],
) -> Vec<HashOf<TransactionEntrypoint>> {
    let mut hashes = Vec::with_capacity(entrypoints.len().saturating_mul(2));
    for_each_canonical_carrier_membership_hash(state_block, entrypoints, |hash| hashes.push(hash));
    hashes
}
/// Visit the exact canonical carrier identities without allocating an intermediate collection.
///
/// The caller owns any storage needed to retain these hashes. This keeps the
/// ordinary carrier's pre-effect source buffer on its original charged owner.
pub(crate) fn for_each_canonical_carrier_membership_hash(
    state_block: &StateBlock<'_>,
    entrypoints: &[TransactionEntrypoint],
    mut visit: impl FnMut(HashOf<TransactionEntrypoint>),
) {
    for entrypoint in entrypoints {
        let carrier_hash = entrypoint.hash();
        visit(carrier_hash);
        if let Some(execution_hash) = authenticated_signed_replay_alias(state_block, entrypoint) {
            if execution_hash != carrier_hash {
                visit(execution_hash);
            }
        }
    }
}
/// Return the signed replay alias authenticated by the pre-block state, if any.
#[must_use]
pub(crate) fn authenticated_signed_replay_alias(
    state_block: &StateBlock<'_>,
    entrypoint: &TransactionEntrypoint,
) -> Option<HashOf<TransactionEntrypoint>> {
    let TransactionEntrypoint::SealedReveal(reveal) = entrypoint else {
        return None;
    };
    sealed_reveal_authenticated_at_block_start(state_block, reveal)
        .then(|| reveal.signed_transaction().hash_as_entrypoint())
}
/// Signed metadata key selecting restricted quarantine admission.
pub(crate) const QUARANTINE_METADATA_KEY: &str = "quarantine";

/// Only an exact authenticated Norito JSON boolean opts into quarantine.
pub(crate) fn is_quarantine_transaction(tx: &SignedTransaction) -> bool {
    tx.metadata()
        .get(QUARANTINE_METADATA_KEY)
        .and_then(|value| value.clone().try_into_any_norito::<bool>().ok())
        .unwrap_or(false)
}

/// Retain completed rejection gas unless an internal settlement failure forbids it.
pub(crate) fn rejected_transaction_gas_is_accountable(
    gas_used: u64,
    result: &TransactionResultInner,
) -> bool {
    gas_used > 0
        && !matches!(
            result,
            Err(TransactionRejectionReason::Validation(
                ValidationFail::InternalError(_)
            ))
        )
}

/// Project envelope admission failures into the canonical Network rejection type.
pub(crate) fn execution_rejection_from_admission_failure(
    fail: AcceptTransactionFail,
) -> TransactionRejectionReason {
    match fail {
        AcceptTransactionFail::TransactionLimit(err) => TransactionRejectionReason::LimitCheck(err),
        // The committed rejection keeps the class attachment shape failures
        // always had; the typed violation is its deterministic reason text.
        AcceptTransactionFail::SignedAttachments(violation) => {
            TransactionRejectionReason::LimitCheck(TransactionLimitError {
                reason: format!("Signed attachments rejected: {violation}"),
            })
        }
        AcceptTransactionFail::SignatureVerification(sig_fail) => {
            TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::NotPermitted(
                format!("signature verification failed: {}", sig_fail.detail),
            ))
        }
        AcceptTransactionFail::UnexpectedGenesisAccountSignature => {
            TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::NotPermitted(
                "unexpected genesis account signature".to_owned(),
            ))
        }
        AcceptTransactionFail::TransactionDomainMismatch(mismatch) => {
            TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::NotPermitted(
                format!(
                    "transaction domain mismatch: expected {:?} got {:?}",
                    mismatch.expected, mismatch.actual
                ),
            ))
        }
        AcceptTransactionFail::TransactionInTheFuture { .. } => {
            TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::NotPermitted(
                "transaction creation time is in the future".to_owned(),
            ))
        }
        AcceptTransactionFail::TransactionExpired {
            expires_at_ms,
            now_ms,
        } => {
            TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::NotPermitted(
                format!("transaction expired: expires_at_ms={expires_at_ms} now_ms={now_ms}"),
            ))
        }
        AcceptTransactionFail::NetworkTimeUnhealthy { reason } => {
            TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::NotPermitted(
                format!("network time service unhealthy: {reason}"),
            ))
        }
    }
}

/// Project a hash known to identify an external signed transaction into its entrypoint identity.
///
/// `TransactionEntrypoint::External` deliberately preserves the signed transaction's digest.
/// Use only after proving an external signed identity; internal APIs use the entrypoint type.
#[must_use]
pub fn external_entrypoint_hash_from_signed_hash(
    hash: HashOf<SignedTransaction>,
) -> HashOf<TransactionEntrypoint> {
    HashOf::from_untyped_unchecked(Hash::from(hash))
}
/// Stateful admission facts that must be committed only if transaction execution succeeds.
#[derive(Debug, Clone)]
pub(crate) struct StatefulAdmission {
    /// Transaction authority.
    pub(crate) authority: AccountId,
    /// Whether this transaction may run before its authority account is materialized.
    pub(crate) allow_unregistered_authority: bool,
    /// Monotonic sequence value to store after successful execution.
    pub(crate) sequence_to_commit: Option<u64>,
    /// Consensus-owned faucet claim record to persist only after complete execution succeeds.
    pub(crate) faucet_claim_to_commit: Option<(StatePath, Vec<u8>)>,
}

const FAUCET_CLAIM_CONSUMED_STATE_PREFIX_V1: &str = "faucet_claim_consumed_v1/";
const FAUCET_CLAIM_CONSUMED_KEY_DOMAIN_V1: &[u8] = b"iroha.faucet.claim.consumed.key.v1\0";
const FAUCET_CLAIM_EXECUTABLE_SHAPE_ERROR: &str = "faucet claim marker requires exactly one \
    non-zero authority-sourced asset transfer to a different account, optionally preceded by a \
    plain registration of the same destination";

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::tx::FaucetClaimConsumptionRecordV1")]
#[derive(Debug, Clone, norito::codec::Decode, norito::codec::Encode)]
struct FaucetClaimConsumptionRecordV1 {
    marker_version: u64,
    authority: AccountId,
    semantic_hash: [u8; 32],
    first_transaction_hash: HashOf<SignedTransaction>,
}

fn validate_faucet_claim_executable_shape(tx: &SignedTransaction) -> Result<(), ValidationFail> {
    let reject = || ValidationFail::NotPermitted(FAUCET_CLAIM_EXECUTABLE_SHAPE_ERROR.to_owned());
    let Executable::Instructions(instructions) = tx.instructions() else {
        return Err(reject());
    };
    let (registration, transfer) = match instructions.as_ref() {
        [transfer] => (None, transfer),
        [registration, transfer] => (Some(registration), transfer),
        _ => return Err(reject()),
    };
    let Some(TransferBox::Asset(transfer)) = transfer.as_any().downcast_ref::<TransferBox>() else {
        return Err(reject());
    };
    if transfer.source().account() != tx.authority()
        || transfer.destination() == tx.authority()
        || transfer.object().is_zero()
    {
        return Err(reject());
    }
    if let Some(registration) = registration {
        let Some(RegisterBox::Account(registration)) =
            registration.as_any().downcast_ref::<RegisterBox>()
        else {
            return Err(reject());
        };
        let account = registration.object();
        if account.id() != transfer.destination()
            || !account.metadata.is_empty()
            || account.label.is_some()
            || account.uaid.is_some()
            || !account.opaque_ids.is_empty()
        {
            return Err(reject());
        }
    }
    Ok(())
}

/// Parse the signature-bound consensus faucet marker and derive its authority-scoped state key.
pub(crate) fn faucet_claim_consumption_marker(
    tx: &SignedTransaction,
) -> Result<Option<(StatePath, [u8; 32])>, ValidationFail> {
    let Some(version) = tx
        .metadata()
        .get(iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_METADATA_KEY)
    else {
        let prepared_faucet_without_marker = tx
            .metadata()
            .get(iroha_data_model::transaction::PREPARED_OPERATION_METADATA_KEY)
            .and_then(|operation| operation.clone().try_into_any_norito::<String>().ok())
            .is_some_and(|operation| {
                operation == iroha_data_model::transaction::PREPARED_FAUCET_OPERATION
            });
        if prepared_faucet_without_marker {
            return Err(ValidationFail::NotPermitted(
                "prepared faucet operation requires faucet claim marker version metadata"
                    .to_owned(),
            ));
        }
        return Ok(None);
    };
    let version = version.clone().try_into_any_norito::<u64>().map_err(|_| {
        ValidationFail::NotPermitted(
            "faucet claim marker version must be an unsigned integer".to_owned(),
        )
    })?;
    if version != iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_V1 {
        return Err(ValidationFail::NotPermitted(format!(
            "unsupported faucet claim marker version {version}"
        )));
    }
    let operation = tx
        .metadata()
        .get(iroha_data_model::transaction::PREPARED_OPERATION_METADATA_KEY)
        .ok_or_else(|| {
            ValidationFail::NotPermitted(
                "faucet claim marker requires prepared-operation metadata".to_owned(),
            )
        })?
        .clone()
        .try_into_any_norito::<String>()
        .map_err(|_| {
            ValidationFail::NotPermitted(
                "faucet claim prepared-operation metadata must be a string".to_owned(),
            )
        })?;
    if operation != iroha_data_model::transaction::PREPARED_FAUCET_OPERATION {
        return Err(ValidationFail::NotPermitted(
            "faucet claim marker belongs to a non-faucet prepared operation".to_owned(),
        ));
    }
    let semantic_hash = tx
        .metadata()
        .get(iroha_data_model::transaction::PREPARED_SEMANTIC_HASH_METADATA_KEY)
        .ok_or_else(|| {
            ValidationFail::NotPermitted(
                "faucet claim marker requires semantic-hash metadata".to_owned(),
            )
        })?
        .clone()
        .try_into_any_norito::<String>()
        .map_err(|_| {
            ValidationFail::NotPermitted(
                "faucet claim semantic-hash metadata must be a string".to_owned(),
            )
        })?;
    if semantic_hash.len() != Hash::LENGTH * 2
        || !semantic_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ValidationFail::NotPermitted(
            "faucet claim semantic hash must be canonical lowercase hexadecimal".to_owned(),
        ));
    }
    let semantic_hash: [u8; 32] = hex::decode(semantic_hash)
        .map_err(|_| {
            ValidationFail::NotPermitted("faucet claim semantic hash is malformed".to_owned())
        })?
        .try_into()
        .map_err(|_| {
            ValidationFail::NotPermitted("faucet claim semantic hash is malformed".to_owned())
        })?;
    validate_faucet_claim_executable_shape(tx)?;
    let authority = norito::codec::Encode::encode(tx.authority());
    let key_hash = Hash::new_from_chunks(&[
        FAUCET_CLAIM_CONSUMED_KEY_DOMAIN_V1,
        authority.as_slice(),
        semantic_hash.as_slice(),
    ]);
    let path = format!(
        "{FAUCET_CLAIM_CONSUMED_STATE_PREFIX_V1}{}",
        hex::encode(key_hash.as_ref())
    )
    .parse()
    .expect("canonical faucet claim key is a valid state path");
    Ok(Some((path, semantic_hash)))
}

fn staged_faucet_claim_consumption(
    tx: &SignedTransaction,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<Option<(StatePath, Vec<u8>)>, ValidationFail> {
    let Some((path, semantic_hash)) = faucet_claim_consumption_marker(tx)? else {
        return Ok(None);
    };
    if state_transaction
        .world
        .smart_contract_state
        .get(&path)
        .is_some()
    {
        return Err(ValidationFail::NotPermitted(
            "faucet claim was already consumed".to_owned(),
        ));
    }
    let record = FaucetClaimConsumptionRecordV1 {
        marker_version: iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_V1,
        authority: tx.authority().clone(),
        semantic_hash,
        first_transaction_hash: tx.hash(),
    };
    Ok(Some((path, norito::codec::Encode::encode(&record))))
}

/// Commit a previously admitted faucet claim into the same transactional state overlay.
pub(crate) fn commit_faucet_claim_consumption(
    state_transaction: &mut StateTransaction<'_, '_>,
    admission: &StatefulAdmission,
) {
    if let Some((path, record)) = admission.faucet_claim_to_commit.as_ref() {
        state_transaction
            .world
            .smart_contract_state
            .insert(path.clone(), record.clone());
    }
}
#[derive(Debug, Clone, norito::codec::Decode, norito::codec::Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::tx::PendingSealedTransactionCommitment")]
struct PendingSealedTransactionCommitment {
    payload: SealedTransactionCommitmentPayload,
    commit_height: u64,
    commit_index: u64,
}
const SEALED_TRANSACTION_STATE_PREFIX: &str = "sealed_tx_commitment_";
fn sealed_commitment_state_key(commitment: &iroha_crypto::Hash) -> StatePath {
    StatePath::from_str(&format!(
        "{SEALED_TRANSACTION_STATE_PREFIX}{}",
        hex::encode(commitment.as_ref())
    ))
    .expect("sealed transaction commitment key is a valid state path")
}
fn sealed_state_decode_error(error: impl fmt::Display) -> TransactionRejectionReason {
    TransactionRejectionReason::Validation(ValidationFail::InternalError(format!(
        "sealed transaction commitment state decode failed: {error}"
    )))
}
fn sealed_state_encode_error(error: impl fmt::Display) -> TransactionRejectionReason {
    TransactionRejectionReason::Validation(ValidationFail::InternalError(format!(
        "sealed transaction commitment state encode failed: {error}"
    )))
}
fn validate_sealed_reveal_authentication(
    reveal: &SealedTransactionReveal,
    record: &PendingSealedTransactionCommitment,
    height: u64,
) -> Result<(), TransactionRejectionReason> {
    if height < record.payload.reveal_after_height {
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(format!(
                "sealed transaction reveal is too early: height {height}, reveal_after_height {}",
                record.payload.reveal_after_height
            )),
        ));
    }
    if height > record.payload.reveal_deadline_height {
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(format!(
                "sealed transaction reveal deadline {} passed at height {height}",
                record.payload.reveal_deadline_height
            )),
        ));
    }
    let signed = reveal.signed_transaction();
    if signed.network_id() != Some(&record.payload.network_id) {
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(format!(
                "sealed transaction network mismatch: commitment network {} reveal domain {:?}",
                record.payload.network_id,
                signed.domain()
            )),
        ));
    }
    if signed.authority() != &record.payload.authority {
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(
                "sealed transaction reveal authority does not match commitment authority".into(),
            ),
        ));
    }
    let expected = compute_sealed_transaction_commitment(
        &record.payload.network_id,
        signed,
        reveal.salt,
        record.payload.reveal_deadline_height,
    );
    if expected != record.payload.commitment || expected != reveal.commitment {
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(
                "sealed transaction reveal does not match commitment".into(),
            ),
        ));
    }
    Ok(())
}
fn sealed_reveal_authenticated_at_block_start(
    state_block: &StateBlock<'_>,
    reveal: &SealedTransactionReveal,
) -> bool {
    let key = sealed_commitment_state_key(&reveal.commitment);
    let Some(bytes) = state_block
        .world
        .smart_contract_state
        .get_before_block(&key)
    else {
        return false;
    };
    let Ok(record) = norito::decode_from_bytes::<PendingSealedTransactionCommitment>(bytes) else {
        return false;
    };
    validate_sealed_reveal_authentication(reveal, &record, state_block._curr_block.height().get())
        .is_ok()
}
pub(crate) fn validate_sealed_commitment_stateless(
    commitment: &SignedSealedTransactionCommitment,
    expected_network_id: &NetworkId,
    _limits: TransactionParameters,
) -> Result<(), AcceptTransactionFail> {
    let payload = commitment.payload();
    if &payload.network_id != expected_network_id {
        return Err(AcceptTransactionFail::TransactionDomainMismatch(Mismatch {
            expected: TransactionDomain::Network(*expected_network_id),
            actual: TransactionDomain::Network(payload.network_id),
        }));
    }
    if payload.reveal_deadline_height < payload.reveal_after_height {
        return Err(AcceptTransactionFail::TransactionLimit(
            TransactionLimitError {
                reason: "sealed transaction reveal deadline precedes reveal start".into(),
            },
        ));
    }
    commitment.verify_signature().map_err(|err| {
        AcceptTransactionFail::TransactionLimit(TransactionLimitError {
            reason: format!("sealed transaction commitment signature verification failed: {err}"),
        })
    })
}
pub(crate) fn sealed_reveal_execution_key(
    state_block: &StateBlock<'_>,
    reveal: &SealedTransactionReveal,
) -> (u64, iroha_crypto::Hash, u64) {
    let key = sealed_commitment_state_key(&reveal.commitment);
    let Some(bytes) = state_block.world.smart_contract_state.get(&key) else {
        return (u64::MAX, reveal.commitment, u64::MAX);
    };
    let Ok(record) = norito::decode_from_bytes::<PendingSealedTransactionCommitment>(bytes) else {
        return (u64::MAX, reveal.commitment, u64::MAX);
    };
    (record.commit_height, reveal.commitment, record.commit_index)
}
pub(crate) fn prune_expired_sealed_commitments(state_block: &mut StateBlock<'_>) -> usize {
    let height = state_block._curr_block.height().get();
    let expired_keys: Vec<_> = state_block
        .world
        .smart_contract_state
        .iter()
        .filter_map(|(key, bytes)| {
            if !key.as_ref().starts_with(SEALED_TRANSACTION_STATE_PREFIX) {
                return None;
            }
            let record: PendingSealedTransactionCommitment = match norito::decode_from_bytes(bytes)
            {
                Ok(record) => record,
                Err(error) => {
                    warn!(
                        %key,
                        %error,
                        "skipping invalid sealed transaction commitment state during expiry pruning"
                    );
                    return None;
                }
            };
            (height > record.payload.reveal_deadline_height).then(|| key.clone())
        })
        .collect();
    for key in &expired_keys {
        state_block.world.smart_contract_state.remove(key.clone());
    }
    expired_keys.len()
}
macro_rules! metadata_names {
    ($($name:ident => $value:expr),+ $(,)?) => {
        $(
            static $name: LazyLock<iroha_model_base::name::Name> = LazyLock::new(|| {
                iroha_model_base::name::Name::from_str($value)
                    .expect("valid static metadata name")
            });
        )+
    };
}
metadata_names! {
    FRAUD_ASSESSMENT_BAND_NAME => "fraud_assessment_band",
    FRAUD_ASSESSMENT_SCORE_NAME => "fraud_assessment_score_bps",
    FRAUD_ASSESSMENT_TENANT_NAME => "fraud_assessment_tenant",
    FRAUD_ASSESSMENT_LATENCY_NAME => "fraud_assessment_latency_ms",
    FRAUD_ASSESSMENT_ENVELOPE_NAME => "fraud_assessment_envelope",
    FRAUD_ASSESSMENT_DIGEST_NAME => "fraud_assessment_digest",
    CONTRACT_MANIFEST_METADATA_NAME => MANIFEST_METADATA_KEY,
    GOV_CONTRACT_ADDRESS_METADATA_KEY => "gov_contract_address",
    GOV_APPROVERS_METADATA_KEY => "gov_manifest_approvers",
    CONTRACT_ADDRESS_METADATA_KEY => "contract_address",
    HEARTBEAT_METADATA_NAME => "sumeragi_heartbeat",
}
pub(crate) const ED25519_SIGNATURE_LENGTH: usize = 64;
const MULTISIG_DIRECT_SIGN_REJECTION: &str =
    "multisig accounts must use the multisig propose/approve flow; direct signatures are rejected";
const CONTRACT_SUBJECT_DIRECT_SIGN_REJECTION: &str =
    "deployed contract subjects cannot originate signed transactions directly";
/// Prefix used in transaction-limit rejection reasons when the signature cap is exceeded.
pub const SIGNATURE_LIMIT_REASON_PREFIX: &str = "Too many signatures in payload";
#[derive(Clone, Debug)]
enum SignatureCheck {
    Verify,
    PrecheckedSingleEd25519,
    Override(Result<(), SignatureVerificationFail>),
}
#[cfg(feature = "telemetry")]
#[allow(clippy::module_name_repetitions)]
use iroha_model_base::metadata::Metadata as TelemetryMetadata;
#[cfg(feature = "telemetry")]
#[allow(clippy::module_name_repetitions)]
use iroha_model_base::name::Name as TelemetryName;
/// `AcceptedTransaction` — a transaction accepted by Iroha peer.
#[derive(Debug)]
pub struct AcceptedTransaction<'tx> {
    entrypoint: Cow<'tx, TransactionEntrypoint>,
    validation_time: Option<Duration>,
    entrypoint_hash: OnceLock<HashOf<TransactionEntrypoint>>,
    encoded_len: OnceLock<usize>,
    entrypoint_bytes: OnceLock<Arc<Vec<u8>>>,
    signed_bytes: OnceLock<Option<Arc<Vec<u8>>>>,
    payload_hash:
        OnceLock<Option<HashOf<iroha_data_model::transaction::signed::TransactionPayload>>>,
    single_ed25519_key: OnceLock<Option<iroha_crypto::Ed25519ParsedPublicKey>>,
}
impl Clone for AcceptedTransaction<'_> {
    fn clone(&self) -> Self {
        Self {
            // A borrowed accepted source keeps its original owner and lifetime.
            // TODO: replace owned graph copies at their complete physical custody boundary.
            entrypoint: if cfg!(all(test, sumeragi_core_mutation = "HC135")) {
                Cow::Owned(self.entrypoint().clone())
            } else {
                self.entrypoint.clone()
            },
            validation_time: self.validation_time,
            entrypoint_hash: clone_once_lock(&self.entrypoint_hash),
            encoded_len: clone_once_lock(&self.encoded_len),
            entrypoint_bytes: clone_once_lock(&self.entrypoint_bytes),
            signed_bytes: clone_once_lock(&self.signed_bytes),
            payload_hash: clone_once_lock(&self.payload_hash),
            single_ed25519_key: clone_once_lock(&self.single_ed25519_key),
        }
    }
}
impl PartialEq for AcceptedTransaction<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.entrypoint() == other.entrypoint()
    }
}
impl Eq for AcceptedTransaction<'_> {}
fn clone_once_lock<T: Clone>(source: &OnceLock<T>) -> OnceLock<T> {
    let cloned = OnceLock::new();
    if let Some(value) = source.get() {
        let _ = cloned.set(value.clone());
    }
    cloned
}
/// Accepted transaction that has been verified to be absent from the blockchain.
///
/// This wrapper is constructed by checking an [`AcceptedTransaction`] against a state view and
/// guarantees that the transaction hash was not present in the ledger at the time of creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedTransaction<'tx>(AcceptedTransaction<'tx>);
/// Error returned when trying to mark an already committed transaction as pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionAlreadyCommitted;
impl fmt::Display for TransactionAlreadyCommitted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("transaction already committed")
    }
}
impl std::error::Error for TransactionAlreadyCommitted {}
/// Validation identity of the complete signed envelope, including its signature.
/// Canonical entrypoint identity alone cannot authorize signature-check reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct StatelessValidationCacheKey(HashOf<SignedTransaction>);
impl StatelessValidationCacheKey {
    pub(crate) fn new(transaction: &SignedTransaction) -> Self {
        Self(HashOf::new(transaction))
    }
    #[cfg(test)]
    pub(crate) fn for_test(hash: HashOf<SignedTransaction>) -> Self {
        Self(hash)
    }
}
/// Reusable stateless transaction metadata derived once for block validation.
#[derive(Debug, Clone)]
pub(crate) struct PreparedTransactionMetadata {
    /// Canonical signed transaction hash.
    pub(crate) signed_hash: HashOf<SignedTransaction>,
    /// Exact envelope identity used only for reusable stateless validation.
    pub(crate) stateless_cache_key: StatelessValidationCacheKey,
    /// Canonical entrypoint hash used by block Merkle roots.
    pub(crate) entrypoint_hash: HashOf<TransactionEntrypoint>,
    /// Hash of the signed payload, used as the Ed25519 verification message.
    pub(crate) payload_hash: HashOf<iroha_data_model::transaction::signed::TransactionPayload>,
    /// Exact framed Norito length of the signed transaction.
    pub(crate) encoded_len: usize,
    /// Canonical signed transaction bytes when a caller has already materialized them.
    pub(crate) signed_bytes: Option<Arc<Vec<u8>>>,
    /// Canonical external entrypoint bytes derived from the same signed payload.
    pub(crate) entrypoint_bytes: Option<Arc<Vec<u8>>>,
    /// Parsed Ed25519 key when the transaction has a single Ed25519 authority.
    pub(crate) single_ed25519_key: Option<iroha_crypto::Ed25519ParsedPublicKey>,
    /// Parsed transaction metadata nesting depths, in canonical metadata iteration order.
    metadata_depths: Result<Vec<(String, usize)>, TransactionLimitError>,
}
/// Signed transaction decoded from a versioned Torii payload with reusable admission metadata.
///
/// This is public only so Torii can pass the decoded transaction across crate boundaries without
/// redoing stateless preparation. The metadata is derived internally and cannot be supplied by
/// callers.
#[doc(hidden)]
#[derive(Debug)]
pub struct DecodedVersionedSignedTransaction {
    tx: SignedTransaction,
    prepared: PreparedTransactionMetadata,
}
impl<'tx> CheckedTransaction<'tx> {
    /// Attempt to construct a [`CheckedTransaction`] by verifying the transaction hash against the provided state.
    ///
    /// # Errors
    ///
    /// Returns the original transaction and [`TransactionAlreadyCommitted`] when the hash is already present.
    #[allow(clippy::result_large_err)]
    pub fn new(
        tx: AcceptedTransaction<'tx>,
        state: &impl StateReadOnlyWithTransactions,
    ) -> Result<Self, (AcceptedTransaction<'tx>, TransactionAlreadyCommitted)> {
        if tx.has_committed_replay_identity(state) {
            return Err((tx, TransactionAlreadyCommitted));
        }
        Ok(Self(tx))
    }
    /// Construct a checked transaction fixture whose committed-hash validation is owned by the test.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_unchecked(tx: AcceptedTransaction<'tx>) -> Self {
        Self(tx)
    }
    /// Borrow the underlying [`AcceptedTransaction`].
    #[must_use]
    pub fn as_accepted(&self) -> &AcceptedTransaction<'tx> {
        &self.0
    }
    /// Consume the wrapper and return the inner [`AcceptedTransaction`].
    #[must_use]
    pub fn into_accepted(self) -> AcceptedTransaction<'tx> {
        self.0
    }
    /// Check whether the transaction is now recorded in the blockchain.
    #[must_use]
    pub fn is_in_blockchain(&self, state: &impl StateReadOnlyWithTransactions) -> bool {
        self.as_accepted().has_committed_replay_identity(state)
    }
}
impl<'tx> core::ops::Deref for CheckedTransaction<'tx> {
    type Target = AcceptedTransaction<'tx>;
    fn deref(&self) -> &Self::Target {
        self.as_accepted()
    }
}
impl<'tx> AsRef<AcceptedTransaction<'tx>> for CheckedTransaction<'tx> {
    fn as_ref(&self) -> &AcceptedTransaction<'tx> {
        self.as_accepted()
    }
}
impl<'tx> From<CheckedTransaction<'tx>> for AcceptedTransaction<'tx> {
    fn from(value: CheckedTransaction<'tx>) -> Self {
        value.into_accepted()
    }
}
fn json_value_depth(value: &norito::json::Value) -> usize {
    match value {
        norito::json::Value::Array(items) => {
            1 + items.iter().map(json_value_depth).max().unwrap_or(0)
        }
        norito::json::Value::Object(map) => {
            1 + map.values().map(json_value_depth).max().unwrap_or(0)
        }
        _ => 1,
    }
}
fn ensure_metadata_depth(
    metadata: &Metadata,
    max_depth: usize,
) -> Result<(), TransactionLimitError> {
    for (key, depth) in prepare_metadata_depths(metadata)? {
        if depth > max_depth {
            return Err(TransactionLimitError {
                reason: format!("Metadata `{key}` nesting depth {depth} exceeds limit {max_depth}"),
            });
        }
    }
    Ok(())
}
fn prepare_metadata_depths(
    metadata: &Metadata,
) -> Result<Vec<(String, usize)>, TransactionLimitError> {
    let entries = metadata.iter();
    let mut depths = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let parsed =
            norito::json::parse_value(value.get()).map_err(|err| TransactionLimitError {
                reason: format!("Metadata `{key}` is not valid JSON: {err}"),
            })?;
        depths.push((key.to_string(), json_value_depth(&parsed)));
    }
    Ok(depths)
}
fn ensure_metadata_depth_with_prepared(
    metadata: &Metadata,
    max_depth: usize,
    prepared: Option<&PreparedTransactionMetadata>,
) -> Result<(), TransactionLimitError> {
    if let Some(prepared) = prepared {
        let depths = prepared.metadata_depths.as_ref().map_err(Clone::clone)?;
        for (key, depth) in depths {
            if *depth > max_depth {
                return Err(TransactionLimitError {
                    reason: format!(
                        "Metadata `{key}` nesting depth {depth} exceeds limit {max_depth}"
                    ),
                });
            }
        }
        Ok(())
    } else {
        ensure_metadata_depth(metadata, max_depth)
    }
}
/// Verification failed of some signature due to following reason
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureVerificationFail {
    /// Signature which verification has failed
    pub signature: TransactionSignature,
    /// Stable rejection code associated with the failure.
    pub code: SignatureRejectionCode,
    /// Error which happened during verification
    pub detail: String,
}
impl core::fmt::Display for SignatureVerificationFail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Failed to verify signatures ({}): {}",
            self.code.as_str(),
            self.detail,
        )
    }
}
impl std::error::Error for SignatureVerificationFail {}
/// Stable codes describing why signature verification was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureRejectionCode {
    /// Multisig controllers are not supported for transaction signatures yet.
    UnsupportedAuthority,
    /// Signature algorithm is disabled by configuration.
    AlgorithmNotPermitted,
    /// Signature failed to verify against the payload.
    InvalidSignature,
    /// Signature bytes are malformed or incomplete.
    MalformedSignature,
    /// Multisig signature bundle is missing.
    MissingSignatures,
    /// Multisig bundle references a signer outside the policy.
    UnknownSigner,
    /// Multisig bundle does not reach the configured threshold.
    InsufficientWeight,
}
impl SignatureRejectionCode {
    /// Stable machine-readable code string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedAuthority => "PRTRY:TX_UNSUPPORTED_AUTHORITY",
            Self::AlgorithmNotPermitted => "PRTRY:TX_SIGNATURE_ALGO_DENIED",
            Self::InvalidSignature => "PRTRY:TX_SIGNATURE_INVALID",
            Self::MalformedSignature => "PRTRY:TX_SIGNATURE_MALFORMED",
            Self::MissingSignatures => "PRTRY:TX_SIGNATURE_MISSING",
            Self::UnknownSigner => "PRTRY:TX_SIGNATURE_UNKNOWN_SIGNER",
            Self::InsufficientWeight => "PRTRY:TX_SIGNATURE_INSUFFICIENT",
        }
    }
    /// Human-readable summary for logs and envelopes.
    pub const fn summary(self) -> &'static str {
        match self {
            Self::UnsupportedAuthority => "authority type is not supported for transaction signing",
            Self::AlgorithmNotPermitted => "signing algorithm is not permitted by configuration",
            Self::InvalidSignature => "signature verification failed",
            Self::MalformedSignature => "signature or key encoding is malformed",
            Self::MissingSignatures => "multisig signatures are missing",
            Self::UnknownSigner => "multisig contains a signature from an unknown member",
            Self::InsufficientWeight => "multisig signatures do not satisfy the threshold",
        }
    }
}
impl SignatureVerificationFail {
    /// Construct a new failure with the given code and detail string.
    pub fn new(
        signature: TransactionSignature,
        code: SignatureRejectionCode,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            signature,
            code,
            detail: detail.into(),
        }
    }
    /// Accessor for the rejection code.
    pub const fn code(&self) -> SignatureRejectionCode {
        self.code
    }
}
/// Error type for transaction from [`SignedTransaction`] to [`AcceptedTransaction`]
#[derive(Debug, displaydoc::Display, PartialEq, Eq, FromVariant, thiserror::Error)]
pub enum AcceptTransactionFail {
    /// Failure during limits check
    TransactionLimit(#[source] TransactionLimitError),
    /// Signed attachment schema violation: {0}
    SignedAttachments(#[source] SignedAttachmentErrorV1),
    /// Failure during signature verification
    SignatureVerification(#[source] SignatureVerificationFail),
    /// Transaction expired at `{expires_at_ms}` ms since Unix epoch (current time `{now_ms}` ms)
    TransactionExpired {
        /// Millisecond Unix timestamp at which the transaction's TTL elapsed.
        expires_at_ms: u128,
        /// Millisecond Unix timestamp observed during admission.
        now_ms: u128,
    },
    /// Network time service is unhealthy: {reason}
    NetworkTimeUnhealthy {
        /// Health snapshot summary for diagnostics.
        reason: String,
    },
    /// The genesis account can only sign transactions in the genesis block
    UnexpectedGenesisAccountSignature,
    /// Signed transaction domain does not match the admitted domain: {0}
    TransactionDomainMismatch(Mismatch<TransactionDomain>),
    /// Transaction creation time `{creation_time_ms}` ms is in the future (admission time `{now_ms}` ms, maximum drift `{max_clock_drift_ms}` ms)
    TransactionInTheFuture {
        /// Signature-bound transaction creation time in Unix milliseconds.
        creation_time_ms: u128,
        /// Exact network-time snapshot used for this admission decision in Unix milliseconds.
        now_ms: u128,
        /// Configured maximum admitted future drift in milliseconds.
        max_clock_drift_ms: u128,
    },
}
fn duration_since_epoch_with_fallback(result: Result<Duration, SystemTimeError>) -> Duration {
    match result {
        Ok(duration) => duration,
        Err(error) => {
            let skew = error.duration();
            warn!(
                clock_skew_ms = u64::try_from(skew.as_millis()).unwrap_or(u64::MAX),
                "local clock is before the Unix epoch; falling back to Duration::ZERO for admission"
            );
            Duration::ZERO
        }
    }
}
fn current_unix_time() -> Duration {
    unix_time_from_network_status(crate::time::now())
}
fn unix_time_from_network_status(status: crate::time::NetworkTimeStatus) -> Duration {
    duration_since_epoch_with_fallback(status.now.duration_since(SystemTime::UNIX_EPOCH))
}
fn capture_network_admission() -> (Duration, crate::time::NetworkTimeAdmissionSnapshot) {
    let snapshot = crate::time::admission_snapshot();
    (unix_time_from_network_status(snapshot.status), snapshot)
}
impl DecodedVersionedSignedTransaction {
    /// Decode a versioned signed transaction and prepare admission metadata once.
    ///
    /// # Errors
    ///
    /// Returns the same versioning and Norito decode errors as the signed transaction
    /// versioned decoder.
    pub fn decode_versioned(input: &[u8]) -> iroha_version::error::Result<Self> {
        let tx =
            <SignedTransaction as iroha_version::codec::DecodeVersioned>::decode_all_versioned(
                input,
            )?;
        let prepared =
            AcceptedTransaction::prepare_signed_metadata_from_versioned_payload(&tx, input);
        Ok(Self { tx, prepared })
    }
    /// Decode an owned versioned signed transaction and prepare admission metadata once.
    ///
    /// This normalizes adaptive versioned transport payloads to canonical signed
    /// transaction metadata before stateless validation.
    ///
    /// # Errors
    ///
    /// Returns the same versioning and Norito decode errors as the signed transaction
    /// versioned decoder.
    pub fn decode_versioned_owned(input: Vec<u8>) -> iroha_version::error::Result<Self> {
        Self::decode_versioned(input.as_slice())
    }
    /// Borrow the decoded signed transaction.
    #[must_use]
    pub fn signed(&self) -> &SignedTransaction {
        &self.tx
    }
    /// Borrow the decoded authority.
    #[must_use]
    pub fn authority(&self) -> &AccountId {
        self.tx.authority()
    }
    /// Return the prepared canonical transaction hash.
    #[must_use]
    pub fn hash(&self) -> HashOf<SignedTransaction> {
        self.prepared.signed_hash
    }
    /// Return the prepared canonical entrypoint hash.
    #[must_use]
    pub fn hash_as_entrypoint(&self) -> HashOf<TransactionEntrypoint> {
        self.prepared.entrypoint_hash
    }
    /// Return the prepared exact framed signed-transaction length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.prepared.encoded_len
    }
    /// Return the message/signature/public-key tuple used for deterministic Ed25519 batch precheck.
    #[must_use]
    pub fn single_ed25519_precheck_parts(
        &self,
    ) -> Option<(&[u8], &[u8], iroha_crypto::Ed25519ParsedPublicKey)> {
        let public_key = self.prepared.single_ed25519_key?;
        Some((
            self.prepared.payload_hash.as_ref().as_slice(),
            self.tx.signature().payload().payload(),
            public_key,
        ))
    }
    /// Validate and accept the decoded signed transaction using prepared metadata.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`].
    pub fn into_accepted(
        self,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
    ) -> Result<AcceptedTransaction<'static>, AcceptTransactionFail> {
        let (now, nts_snapshot) = capture_network_admission();
        AcceptedTransaction::validate_with_now_and_prepared_metadata(
            &self.tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            now,
            &self.prepared,
        )?;
        enforce_nts_health_for_time_sensitive(&self.tx, nts_snapshot)?;
        Ok(
            AcceptedTransaction::from_external_with_prepared_metadata(self.tx, self.prepared)
                .with_validation_time(now),
        )
    }
    /// Validate and accept the decoded signed transaction after deterministic Ed25519 precheck.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`].
    pub fn into_accepted_after_single_ed25519_precheck(
        self,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
    ) -> Result<AcceptedTransaction<'static>, AcceptTransactionFail> {
        let (now, nts_snapshot) = capture_network_admission();
        AcceptedTransaction::validate_with_now_after_single_ed25519_precheck_and_prepared_metadata(
            &self.tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            now,
            &self.prepared,
        )?;
        enforce_nts_health_for_time_sensitive(&self.tx, nts_snapshot)?;
        Ok(
            AcceptedTransaction::from_external_with_prepared_metadata(self.tx, self.prepared)
                .with_validation_time(now),
        )
    }
}
fn reject_retired_heartbeat_metadata(tx: &SignedTransaction) -> Result<(), TransactionLimitError> {
    if tx.metadata().get(&*HEARTBEAT_METADATA_NAME).is_some() {
        return Err(TransactionLimitError {
            reason:
                "Transaction metadata `sumeragi_heartbeat` is retired in the first-release protocol"
                    .into(),
        });
    }
    Ok(())
}
fn is_time_sensitive_instruction(instruction: &InstructionBox) -> bool {
    let any = instruction.as_any();
    if let Some(iroha_data_model::isi::register::RegisterBox::Trigger(register)) =
        any.downcast_ref::<iroha_data_model::isi::register::RegisterBox>()
    {
        let trigger = &register.object;
        return is_time_sensitive_executable(trigger.action().executable());
    }
    if let Some(register) = any.downcast_ref::<
        iroha_data_model::isi::register::Register<iroha_data_model::trigger::Trigger>,
    >() {
        let trigger = &register.object;
        return is_time_sensitive_executable(trigger.action().executable());
    }
    is_time_sensitive_instruction_type(any.type_id())
}
fn is_time_sensitive_instruction_type(type_id: TypeId) -> bool {
    macro_rules! matches_any_type {
        ($($ty:ty),+ $(,)?) => {
            false $(|| type_id == TypeId::of::<$ty>())+
        };
    }
    matches_any_type!(
        iroha_data_model::isi::private_settlement::ActivatePrivateSettlementPoolV1,
        iroha_data_model::isi::private_settlement::RegisterAtomicPrivateSettlementPrepareV1,
        iroha_data_model::isi::private_settlement::AbortAtomicPrivateSettlementV1,
        iroha_data_model::isi::private_settlement::FinalizeAtomicPrivateSettlementV1,
        iroha_data_model::isi::oracle::RecordTwitterBinding,
        iroha_data_model::isi::social::ClaimTwitterFollowReward,
        iroha_data_model::isi::social::SendToTwitter,
        iroha_data_model::isi::repo::RepoInstructionBox,
        iroha_data_model::isi::settlement::SettlementInstructionBox,
        iroha_data_model::isi::staking::ExitPublicLaneValidator,
        iroha_data_model::isi::staking::SchedulePublicLaneUnbond,
        iroha_data_model::isi::staking::FinalizePublicLaneUnbond,
        iroha_data_model::isi::ExecuteTrigger,
        iroha_data_model::isi::CustomInstruction,
        ProposeRuntimeUpgrade,
        ActivateRuntimeUpgrade,
        CancelRuntimeUpgrade,
        iroha_data_model::isi::governance::ProposeDeployContract,
        iroha_data_model::isi::governance::ProposeContractLifecycleGovernance,
        iroha_data_model::isi::governance::ProposeContractEmergencyHold,
        iroha_data_model::isi::governance::ProposeGlobalDataTriggerPermissionGovernance,
        iroha_data_model::isi::governance::ProposeRuntimeUpgradeProposal,
        iroha_data_model::isi::governance::ProposeSccpRouteGovernance,
        iroha_data_model::isi::governance::ProposeSorafsProviderGovernance,
        iroha_data_model::isi::governance::ProposeValidationFeePolicy,
        iroha_data_model::isi::governance::ProposeValidationFeePayoutLifecycle,
        iroha_data_model::isi::governance::CastZkBallot,
        iroha_data_model::isi::governance::CastPlainBallot,
        iroha_data_model::isi::governance::UpdatePlainConviction,
        iroha_data_model::isi::governance::CreateParliamentGovernanceAttemptV1,
        iroha_data_model::isi::governance::SubmitParliamentLifecycleTransitionV1,
        iroha_data_model::isi::ministry::SubmitAgendaProposal,
    )
}
fn is_time_sensitive_executable(executable: &Executable) -> bool {
    match executable {
        Executable::Instructions(instructions) => {
            instructions.iter().any(is_time_sensitive_instruction)
        }
        Executable::ContractCall(_) => true,
        Executable::Batch(items) => items.iter().any(|item| match item {
            ExecutableBatchItem::Instruction(instruction) => {
                is_time_sensitive_instruction(instruction)
            }
            ExecutableBatchItem::ContractCall(_) => true,
        }),
        Executable::Ivm(_) | Executable::IvmProved(_) => true,
    }
}
fn format_nts_health_reason(status: &crate::time::NetworkTimeStatus) -> String {
    format!(
        "fallback={} samples_used={} peers_seen={} offset_ms={} confidence_ms={} min_samples_ok={} offset_ok={} confidence_ok={}",
        status.fallback,
        status.sample_count,
        status.peer_count,
        status.offset_ms,
        status.confidence_ms,
        status.health.min_samples_ok,
        status.health.offset_ok,
        status.health.confidence_ok
    )
}
fn enforce_time_sensitive_with_nts(
    tx: &SignedTransaction,
    status: crate::time::NetworkTimeStatus,
    mode: iroha_config::parameters::actual::NtsEnforcementMode,
) -> Result<(), AcceptTransactionFail> {
    if status.health.healthy {
        return Ok(());
    }
    match mode {
        iroha_config::parameters::actual::NtsEnforcementMode::Warn => {
            warn!(
                tx_hash = %tx.hash(),
                fallback = status.fallback,
                sample_count = status.sample_count,
                peer_count = status.peer_count,
                offset_ms = status.offset_ms,
                confidence_ms = status.confidence_ms,
                min_samples_ok = status.health.min_samples_ok,
                offset_ok = status.health.offset_ok,
                confidence_ok = status.health.confidence_ok,
                "NTS unhealthy during time-sensitive admission; allowing transaction"
            );
            Ok(())
        }
        iroha_config::parameters::actual::NtsEnforcementMode::Reject => {
            Err(AcceptTransactionFail::NetworkTimeUnhealthy {
                reason: format_nts_health_reason(&status),
            })
        }
    }
}
fn enforce_nts_health_for_time_sensitive(
    tx: &SignedTransaction,
    snapshot: crate::time::NetworkTimeAdmissionSnapshot,
) -> Result<(), AcceptTransactionFail> {
    if !is_time_sensitive_executable(tx.instructions()) {
        return Ok(());
    }
    enforce_time_sensitive_with_nts(tx, snapshot.status, snapshot.enforcement_mode)
}
fn enforce_nts_health_for_entrypoint(
    tx: &TransactionEntrypoint,
    snapshot: crate::time::NetworkTimeAdmissionSnapshot,
) -> Result<(), AcceptTransactionFail> {
    match tx {
        TransactionEntrypoint::External(signed) => {
            enforce_nts_health_for_time_sensitive(signed, snapshot)
        }
        TransactionEntrypoint::SealedReveal(reveal) => {
            enforce_nts_health_for_time_sensitive(reveal.signed_transaction(), snapshot)
        }
        TransactionEntrypoint::SealedCommitment(_) => Ok(()),
    }
}
/// Whether an executor route consumes the attachments of this operation.
///
/// Registration of an instruction wire identifier does not establish support:
/// an attachment-backed action is admitted only when a route verifies its
/// statement and consumes its declared occurrences.
pub(crate) const fn attachment_operation_is_supported(operation: &ActionOperationV1) -> bool {
    match operation {
        // The transaction-level carriers are preverified by the executor.
        ActionOperationV1::TransactionProof | ActionOperationV1::IvmProvedExecution => true,
        // TODO(I.2, I.3): no invocation-scoped attachment handle and no typed
        // native bridge exist yet, so nothing would consume the declared
        // occurrences of a native instruction action. Such a declaration is
        // refused until those routes exist; deleting this refusal alone would
        // admit declarations that are never consumed.
        ActionOperationV1::NativeInstruction(_) => false,
    }
}
/// Refuse the first declared action whose operation has no consuming route.
pub(crate) fn first_unsupported_attachment_operation(
    tx: &SignedTransaction,
) -> Option<SignedAttachmentErrorV1> {
    tx.attachments()?
        .actions()
        .iter()
        .find(|action| !attachment_operation_is_supported(&action.operation))
        .map(|action| SignedAttachmentErrorV1::UnsupportedOperation {
            action_index: action.action_index,
        })
}
/// Validate the ordered intent descriptor and the signed attachment occurrences.
///
/// Type, index, length and hash of every occurrence, the reference–occurrence
/// bijection, the closed operation rules, the invocation bindings, the wrapped
/// proof carriers and the statement bindings are checked by the shared
/// data-model predicate; this node additionally refuses an operation that no
/// executor route consumes.
fn validate_signed_attachments(tx: &SignedTransaction) -> Result<(), AcceptTransactionFail> {
    tx.validate_signed_attachments_v1()?;
    first_unsupported_attachment_operation(tx).map_or(Ok(()), |error| Err(error.into()))
}
impl<'tx> AcceptedTransaction<'tx> {
    fn from_entrypoint(entrypoint: Cow<'tx, TransactionEntrypoint>) -> Self {
        Self {
            entrypoint,
            validation_time: None,
            entrypoint_hash: OnceLock::new(),
            encoded_len: OnceLock::new(),
            entrypoint_bytes: OnceLock::new(),
            signed_bytes: OnceLock::new(),
            payload_hash: OnceLock::new(),
            single_ed25519_key: OnceLock::new(),
        }
    }
    fn with_validation_time(mut self, validation_time: Duration) -> Self {
        self.validation_time = Some(validation_time);
        self
    }
    /// Return the exact clock instant used for ingress envelope validation.
    #[must_use]
    pub(crate) fn validation_time(&self) -> Option<Duration> {
        self.validation_time
    }
    /// Return whether the ledger already commits this carrier or an authenticated replay alias.
    #[must_use]
    pub(crate) fn has_committed_replay_identity(
        &self,
        state: &impl StateReadOnlyWithTransactions,
    ) -> bool {
        state.has_entrypoint(self.hash_as_entrypoint())
            || match self.entrypoint() {
                TransactionEntrypoint::SealedReveal(reveal) => {
                    state.has_entrypoint(reveal.signed_transaction().hash_as_entrypoint())
                }
                TransactionEntrypoint::External(_) | TransactionEntrypoint::SealedCommitment(_) => {
                    false
                }
            }
    }
    fn from_external_with_cached_bytes(
        tx: SignedTransaction,
        signed_bytes: Option<Arc<Vec<u8>>>,
    ) -> Self {
        let canonical_signed_bytes =
            Arc::new(norito::encode_canonical(&tx).expect("encode accepted signed transaction"));
        let signed_bytes = signed_bytes
            .filter(|bytes| bytes.as_slice() == canonical_signed_bytes.as_slice())
            .unwrap_or(canonical_signed_bytes);
        let entrypoint_hash = tx.hash_as_entrypoint();
        let encoded_len = signed_bytes.len();
        let payload_hash = HashOf::new(tx.payload());
        let single_ed25519_key = Self::parsed_single_ed25519_key(&tx);
        let entrypoint = TransactionEntrypoint::External(tx);
        let accepted = Self::from_entrypoint(Cow::Owned(entrypoint));
        let _ = accepted.signed_bytes.set(Some(signed_bytes));
        let _ = accepted.encoded_len.set(encoded_len);
        let _ = accepted.payload_hash.set(Some(payload_hash));
        let _ = accepted.single_ed25519_key.set(single_ed25519_key);
        let _ = accepted.entrypoint_hash.set(entrypoint_hash);
        accepted
    }
    fn from_entrypoint_with_cached_entrypoint_bytes(
        tx: TransactionEntrypoint,
        entrypoint_bytes: Arc<Vec<u8>>,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
    ) -> Self {
        let accepted = Self::from_entrypoint(Cow::Owned(tx));
        let _ = accepted.entrypoint_bytes.set(entrypoint_bytes);
        let _ = accepted.entrypoint_hash.set(entrypoint_hash);
        accepted
    }
    fn from_external_with_hot_cache(tx: SignedTransaction) -> Self {
        Self::from_external_with_cached_bytes(tx, None)
    }
    fn canonical_signed_payload_with_flags(tx: &SignedTransaction) -> (Vec<u8>, u8) {
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        norito::codec::encode_with_header_flags(tx)
    }
    #[cfg(test)]
    fn external_entrypoint_hash_from_signed(
        tx: &SignedTransaction,
    ) -> HashOf<TransactionEntrypoint> {
        tx.hash_as_entrypoint()
    }
    #[cfg(test)]
    fn external_entrypoint_hash_from_signed_frame(
        signed_frame: &[u8],
    ) -> Result<HashOf<TransactionEntrypoint>, norito::core::Error> {
        let transaction: SignedTransaction = norito::decode_canonical(signed_frame)?;
        Ok(transaction.hash_as_entrypoint())
    }
    fn framed_padding_for<T>() -> usize {
        let align = norito::core::archived_payload_align::<T>();
        if align <= 1 {
            return 0;
        }
        let remainder = norito::core::Header::SIZE % align;
        if remainder == 0 { 0 } else { align - remainder }
    }
    fn bare_encoded_len<T: norito::SerializePayload>(value: &T) -> usize {
        norito::codec::Encode::encode(value).len()
    }
    fn framed_encoded_len<T: norito::SerializePayload>(value: &T) -> usize {
        norito::core::Header::SIZE
            .saturating_add(Self::framed_padding_for::<T>())
            .saturating_add(Self::bare_encoded_len(value))
    }
    fn framed_encoded_payload_len<T>(payload_len: usize) -> usize {
        norito::core::Header::SIZE
            .saturating_add(Self::framed_padding_for::<T>())
            .saturating_add(payload_len)
    }
    fn signed_encoded_len(tx: &SignedTransaction) -> usize {
        Self::framed_encoded_len(tx)
    }
    fn entrypoint_encoded_len(tx: &TransactionEntrypoint) -> usize {
        match tx {
            TransactionEntrypoint::External(signed) => Self::signed_encoded_len(signed),
            TransactionEntrypoint::SealedCommitment(entrypoint) => {
                Self::framed_encoded_len(entrypoint)
            }
            TransactionEntrypoint::SealedReveal(entrypoint) => Self::framed_encoded_len(entrypoint),
        }
    }
    fn signed_encoded_len_for_limit(tx: &SignedTransaction) -> u64 {
        u64::try_from(Self::signed_encoded_len(tx)).unwrap_or(u64::MAX)
    }
    fn signed_encoded_len_for_limit_with_prepared(
        tx: &SignedTransaction,
        prepared: Option<&PreparedTransactionMetadata>,
    ) -> u64 {
        prepared.map_or_else(
            || Self::signed_encoded_len_for_limit(tx),
            |metadata| {
                let encoded_len = metadata
                    .signed_bytes
                    .as_ref()
                    .map_or(metadata.encoded_len, |bytes| bytes.len());
                u64::try_from(encoded_len).unwrap_or(u64::MAX)
            },
        )
    }
    fn parsed_single_ed25519_key(
        tx: &SignedTransaction,
    ) -> Option<iroha_crypto::Ed25519ParsedPublicKey> {
        let iroha_data_model::account::AccountController::Single(signatory) =
            tx.authority().controller()
        else {
            return None;
        };
        let Ok((iroha_crypto::Algorithm::Ed25519, public_key)) = signatory.try_to_bytes() else {
            return None;
        };
        if tx.signature().payload().payload().len() != ED25519_SIGNATURE_LENGTH {
            return None;
        }
        iroha_crypto::ed25519_parse_public_key(public_key).ok()
    }
    /// Build reusable stateless metadata for a signed transaction.
    #[must_use]
    pub(crate) fn prepare_signed_metadata(tx: &SignedTransaction) -> PreparedTransactionMetadata {
        let (signed_payload, _signed_payload_flags) = Self::canonical_signed_payload_with_flags(tx);
        let signed_payload_len = signed_payload.len();
        let encoded_len = Self::framed_encoded_payload_len::<SignedTransaction>(signed_payload_len);
        let entrypoint_hash = tx.hash_as_entrypoint();
        Self::prepare_signed_metadata_with_entrypoint_hash_encoded_len_and_caches(
            tx,
            entrypoint_hash,
            encoded_len,
            None,
            None,
        )
    }
    fn prepare_signed_metadata_from_versioned_payload(
        tx: &SignedTransaction,
        versioned_payload: &[u8],
    ) -> PreparedTransactionMetadata {
        let (signed_payload, signed_payload_flags) = Self::canonical_signed_payload_with_flags(tx);
        let signed_payload_len = signed_payload.len();
        let encoded_len = Self::framed_encoded_payload_len::<SignedTransaction>(signed_payload_len);
        let entrypoint_hash = tx.hash_as_entrypoint();
        let signed_bytes = versioned_payload
            .get(1..)
            .filter(|payload| *payload == signed_payload.as_slice())
            .and_then(|payload| {
                norito::core::frame_bare_with_header_flags::<SignedTransaction>(
                    payload,
                    signed_payload_flags,
                )
                .ok()
            })
            .map(Arc::new);
        let entrypoint_bytes = Some(Arc::new(
            norito::encode_canonical(&TransactionEntrypoint::External(tx.clone()))
                .expect("encode canonical external transaction entrypoint"),
        ));
        let encoded_len = signed_bytes
            .as_ref()
            .map_or(encoded_len, |bytes| bytes.len());
        Self::prepare_signed_metadata_with_entrypoint_hash_encoded_len_and_caches(
            tx,
            entrypoint_hash,
            encoded_len,
            signed_bytes,
            entrypoint_bytes,
        )
    }
    fn prepare_signed_metadata_with_entrypoint_hash_encoded_len_and_caches(
        tx: &SignedTransaction,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
        encoded_len: usize,
        signed_bytes: Option<Arc<Vec<u8>>>,
        entrypoint_bytes: Option<Arc<Vec<u8>>>,
    ) -> PreparedTransactionMetadata {
        let signed_hash = HashOf::from_untyped_unchecked(iroha_crypto::Hash::from(entrypoint_hash));
        PreparedTransactionMetadata {
            signed_hash,
            stateless_cache_key: StatelessValidationCacheKey::new(tx),
            entrypoint_hash,
            payload_hash: HashOf::new(tx.payload()),
            encoded_len,
            signed_bytes,
            entrypoint_bytes,
            single_ed25519_key: Self::parsed_single_ed25519_key(tx),
            metadata_depths: prepare_metadata_depths(tx.metadata()),
        }
    }
    fn signed_encoded_len_from_external_entrypoint_frame(
        framed: &[u8],
    ) -> Result<usize, norito::core::Error> {
        const EXTERNAL_ENTRYPOINT_TAG: u32 = 0;
        let view = norito::core::from_bytes_view(framed)?;
        if view.schema() != norito::schema::identity::frame_hash::<TransactionEntrypoint>() {
            return Err(norito::core::Error::SchemaMismatch);
        }
        let payload = view.as_bytes();
        let tag_bytes = payload
            .get(..4)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let tag = u32::from_le_bytes(
            tag_bytes
                .try_into()
                .expect("slice length checked for u32 tag"),
        );
        if tag != EXTERNAL_ENTRYPOINT_TAG {
            return Err(norito::core::Error::Message(
                "gossip entrypoint frame does not contain an external signed transaction".into(),
            ));
        }
        let (signed_payload_len, len_prefix_len) =
            norito::core::read_len_from_slice_with_flags(&payload[4..], view.flags())?;
        let signed_payload_start = 4usize
            .checked_add(len_prefix_len)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let signed_payload_end = signed_payload_start
            .checked_add(signed_payload_len)
            .ok_or(norito::core::Error::LengthMismatch)?;
        if signed_payload_end > payload.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        Ok(Self::framed_encoded_payload_len::<SignedTransaction>(
            signed_payload_len,
        ))
    }
    /// Build stateless metadata for a signed transaction decoded from a canonical gossip frame.
    #[must_use]
    pub(crate) fn prepare_gossip_signed_metadata(
        tx: &SignedTransaction,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
        entrypoint_bytes: Arc<Vec<u8>>,
    ) -> PreparedTransactionMetadata {
        let encoded_len =
            Self::signed_encoded_len_from_external_entrypoint_frame(entrypoint_bytes.as_slice())
                .unwrap_or_else(|_| Self::signed_encoded_len(tx));
        Self::prepare_signed_metadata_with_entrypoint_hash_encoded_len_and_caches(
            tx,
            entrypoint_hash,
            encoded_len,
            None,
            Some(entrypoint_bytes),
        )
    }
    fn from_external_with_prepared_metadata(
        tx: SignedTransaction,
        prepared: PreparedTransactionMetadata,
    ) -> Self {
        let accepted = Self::from_entrypoint(Cow::Owned(TransactionEntrypoint::External(tx)));
        let _ = accepted.encoded_len.set(prepared.encoded_len);
        let _ = accepted.payload_hash.set(Some(prepared.payload_hash));
        let _ = accepted.single_ed25519_key.set(prepared.single_ed25519_key);
        if let Some(signed_bytes) = prepared.signed_bytes {
            let _ = accepted.signed_bytes.set(Some(signed_bytes));
        }
        if let Some(entrypoint_bytes) = prepared.entrypoint_bytes {
            let _ = accepted.entrypoint_bytes.set(entrypoint_bytes);
        }
        let _ = accepted.entrypoint_hash.set(prepared.entrypoint_hash);
        accepted
    }
    fn validate_common(
        tx: &SignedTransaction,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        now: Duration,
    ) -> Result<(), AcceptTransactionFail> {
        let expected_domain = TransactionDomain::Network(*expected_network_id);
        if tx.domain() != &expected_domain {
            return Err(AcceptTransactionFail::TransactionDomainMismatch(Mismatch {
                expected: expected_domain,
                actual: *tx.domain(),
            }));
        }
        Self::validate_common_envelope(tx, max_clock_drift, now)
    }
    fn validate_common_envelope(
        tx: &SignedTransaction,
        max_clock_drift: Duration,
        now: Duration,
    ) -> Result<(), AcceptTransactionFail> {
        if tx.creation_time().saturating_sub(now) > max_clock_drift {
            return Err(AcceptTransactionFail::TransactionInTheFuture {
                creation_time_ms: tx.creation_time().as_millis(),
                now_ms: now.as_millis(),
                max_clock_drift_ms: max_clock_drift.as_millis(),
            });
        }
        tx.payload().validate_fee_payment_intent().map_err(|err| {
            AcceptTransactionFail::SignatureVerification(Self::signature_fail_from_error(
                tx,
                TransactionSignatureError::InvalidFeePaymentIntent(err.to_string()),
            ))
        })?;
        Ok(())
    }
    fn has_single_ed25519_signature(tx: &SignedTransaction) -> bool {
        matches!(
            tx.authority().controller(),
            iroha_data_model::account::AccountController::Single(signatory)
                if signatory
                    .try_to_bytes()
                    .is_ok_and(|(algorithm, _)| algorithm == iroha_crypto::Algorithm::Ed25519)
                    && tx.signature().payload().payload().len() == ED25519_SIGNATURE_LENGTH
        )
    }
    fn verify_signature_for_check(
        tx: &SignedTransaction,
        signature_check: SignatureCheck,
        prepared: Option<&PreparedTransactionMetadata>,
    ) -> Result<(), AcceptTransactionFail> {
        match signature_check {
            SignatureCheck::Override(result) => {
                return result.map_err(AcceptTransactionFail::SignatureVerification);
            }
            SignatureCheck::PrecheckedSingleEd25519 if Self::has_single_ed25519_signature(tx) => {
                return Ok(());
            }
            SignatureCheck::Verify | SignatureCheck::PrecheckedSingleEd25519 => {}
        }
        if let Some(prepared) = prepared
            && let Some(public_key) = prepared.single_ed25519_key
            && Self::has_single_ed25519_signature(tx)
        {
            let message = prepared.payload_hash.as_ref().as_slice();
            let signature = tx.signature().payload().payload();
            let messages = [message];
            let signatures = [signature];
            let public_keys = [public_key];
            return iroha_crypto::ed25519_verify_batch_preparsed_deterministic(
                &messages,
                &signatures,
                &public_keys,
            )
            .map_err(|err| {
                AcceptTransactionFail::SignatureVerification(Self::signature_fail_from_error(
                    tx,
                    TransactionSignatureError::CryptoError(err.to_string()),
                ))
            });
        }
        tx.verify_signature().map_err(|err| {
            AcceptTransactionFail::SignatureVerification(Self::signature_fail_from_error(tx, err))
        })
    }
    fn ensure_signing_allowed(
        tx: &SignedTransaction,
        crypto: &iroha_config::parameters::actual::Crypto,
    ) -> Result<(), AcceptTransactionFail> {
        let signature = tx.signature().clone();
        match tx.authority().controller() {
            iroha_data_model::account::AccountController::Single(signatory) => {
                let algo =
                    Self::signature_public_key_algorithm(&signature, signatory, "signatory")?;
                if !crypto.allowed_signing.contains(&algo) {
                    return Err(AcceptTransactionFail::SignatureVerification(
                        SignatureVerificationFail::new(
                            signature,
                            SignatureRejectionCode::AlgorithmNotPermitted,
                            format!("signing algorithm {algo} is not permitted by configuration"),
                        ),
                    ));
                }
                Ok(())
            }
            iroha_data_model::account::AccountController::Multisig(policy) => {
                for member in policy.members() {
                    let algo = Self::signature_public_key_algorithm(
                        &signature,
                        member.public_key(),
                        "multisig member",
                    )?;
                    if !crypto.allowed_signing.contains(&algo) {
                        return Err(AcceptTransactionFail::SignatureVerification(
                            SignatureVerificationFail::new(
                                signature.clone(),
                                SignatureRejectionCode::AlgorithmNotPermitted,
                                format!(
                                    "multisig member algorithm {algo} is not permitted by configuration"
                                ),
                            ),
                        ));
                    }
                }
                if let Some(bundle) = tx.multisig_signatures() {
                    for entry in &bundle.signatures {
                        let algo = Self::signature_public_key_algorithm(
                            &signature,
                            &entry.signer,
                            "multisig signer",
                        )?;
                        if !crypto.allowed_signing.contains(&algo) {
                            return Err(AcceptTransactionFail::SignatureVerification(
                                SignatureVerificationFail::new(
                                    signature.clone(),
                                    SignatureRejectionCode::AlgorithmNotPermitted,
                                    format!(
                                        "multisig signer {} uses disallowed algorithm {algo}",
                                        entry.signer
                                    ),
                                ),
                            ));
                        }
                    }
                }
                Ok(())
            }
        }
    }
    fn signature_public_key_algorithm(
        signature: &TransactionSignature,
        public_key: &iroha_crypto::PublicKey,
        context: &str,
    ) -> Result<iroha_crypto::Algorithm, AcceptTransactionFail> {
        public_key.try_algorithm().map_err(|err| {
            AcceptTransactionFail::SignatureVerification(SignatureVerificationFail::new(
                signature.clone(),
                SignatureRejectionCode::MalformedSignature,
                format!("{context} public key is malformed: {err}"),
            ))
        })
    }
    fn signature_rejection_code(err: &TransactionSignatureError) -> SignatureRejectionCode {
        match err {
            TransactionSignatureError::UnsupportedMultisigAuthority => {
                SignatureRejectionCode::UnsupportedAuthority
            }
            TransactionSignatureError::AlgorithmNotPermitted(_) => {
                SignatureRejectionCode::AlgorithmNotPermitted
            }
            TransactionSignatureError::AuthorityKeyMismatch
            | TransactionSignatureError::CryptoError(_) => SignatureRejectionCode::InvalidSignature,
            TransactionSignatureError::InvalidFeePaymentIntent(_)
            | TransactionSignatureError::MissingTimeToLive
            | TransactionSignatureError::GenesisDomainNotAllowed
            | TransactionSignatureError::GenesisDomainRequired => {
                SignatureRejectionCode::MalformedSignature
            }
            TransactionSignatureError::UnexpectedMultisigSignatures
            | TransactionSignatureError::NonCanonicalMultisigSignatures => {
                SignatureRejectionCode::MalformedSignature
            }
            TransactionSignatureError::NoSignatures
            | TransactionSignatureError::MissingMultisigSignatures => {
                SignatureRejectionCode::MissingSignatures
            }
            TransactionSignatureError::UnknownMultisigSigner => {
                SignatureRejectionCode::UnknownSigner
            }
            TransactionSignatureError::InsufficientMultisigWeight { .. } => {
                SignatureRejectionCode::InsufficientWeight
            }
        }
    }
    fn signature_fail_from_error(
        tx: &SignedTransaction,
        err: TransactionSignatureError,
    ) -> SignatureVerificationFail {
        SignatureVerificationFail::new(
            tx.signature().clone(),
            Self::signature_rejection_code(&err),
            err.to_string(),
        )
    }
    pub(crate) fn signature_verification_result(
        tx: &SignedTransaction,
    ) -> Result<(), SignatureVerificationFail> {
        tx.verify_signature()
            .map_err(|err| Self::signature_fail_from_error(tx, err))
    }
    fn ensure_signature_limit(
        signature_count: usize,
        limits: &TransactionParameters,
    ) -> Result<(), AcceptTransactionFail> {
        let signature_limit = limits.max_signatures().get();
        let signature_count_u64 = u64::try_from(signature_count).unwrap_or(u64::MAX);
        if signature_count_u64 > signature_limit {
            warn!(
                signature_count,
                signature_limit, "rejecting transaction: signature count exceeds configured limit"
            );
            return Err(AcceptTransactionFail::TransactionLimit(
                TransactionLimitError {
                    reason: format!(
                        "{SIGNATURE_LIMIT_REASON_PREFIX}, max number is {}, but got {}",
                        limits.max_signatures(),
                        signature_count
                    ),
                },
            ));
        }
        Ok(())
    }
    /// Verify that the transaction is not yet committed and wrap it in a [`CheckedTransaction`].
    ///
    /// # Errors
    ///
    /// Returns the original transaction and [`TransactionAlreadyCommitted`] when the hash is already present in the ledger.
    #[allow(clippy::result_large_err)]
    pub fn into_checked(
        self,
        state: &impl StateReadOnlyWithTransactions,
    ) -> Result<CheckedTransaction<'tx>, (AcceptedTransaction<'tx>, TransactionAlreadyCommitted)>
    {
        CheckedTransaction::new(self, state)
    }
    /// Validate a genesis transaction, including its individual authorization proof,
    /// against a caller-provided "now" timestamp.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`]
    pub fn validate_genesis_with_now(
        tx: &SignedTransaction,
        max_clock_drift: Duration,
        genesis_account: &AccountId,
        crypto: &iroha_config::parameters::actual::Crypto,
        now: Duration,
    ) -> Result<(), AcceptTransactionFail> {
        if tx.domain() != &TransactionDomain::Genesis {
            return Err(AcceptTransactionFail::TransactionDomainMismatch(Mismatch {
                expected: TransactionDomain::Genesis,
                actual: *tx.domain(),
            }));
        }
        Self::validate_common_envelope(tx, max_clock_drift, now)?;
        if genesis_account != tx.authority() {
            return Err(AcceptTransactionFail::UnexpectedGenesisAccountSignature);
        }
        Self::ensure_signing_allowed(tx, crypto)?;
        Self::verify_signature_for_check(tx, SignatureCheck::Verify, None)?;
        Ok(())
    }
    /// Like [`Self::accept`], but without wrapping.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`]
    #[allow(clippy::too_many_lines)]
    pub fn validate(
        tx: &SignedTransaction,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
    ) -> Result<(), AcceptTransactionFail> {
        let (now, nts_snapshot) = capture_network_admission();
        Self::validate_with_now(
            tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            now,
        )?;
        enforce_nts_health_for_time_sensitive(tx, nts_snapshot)?;
        Ok(())
    }
    #[allow(clippy::too_many_lines)]
    pub(crate) fn validate_with_now(
        tx: &SignedTransaction,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
        now: Duration,
    ) -> Result<(), AcceptTransactionFail> {
        Self::validate_with_now_and_signature_check(
            tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            now,
            SignatureCheck::Verify,
            None,
        )
    }
    /// Validate a transaction with metadata prepared once by the caller.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`].
    #[allow(clippy::too_many_lines)]
    pub(crate) fn validate_with_now_and_prepared_metadata(
        tx: &SignedTransaction,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
        now: Duration,
        prepared: &PreparedTransactionMetadata,
    ) -> Result<(), AcceptTransactionFail> {
        Self::validate_with_now_and_signature_check(
            tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            now,
            SignatureCheck::Verify,
            Some(prepared),
        )
    }
    /// Validate a transaction with metadata prepared once by the caller and a precomputed signature result.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`].
    #[allow(clippy::too_many_lines)]
    pub(crate) fn validate_with_now_with_signature_result_and_prepared_metadata(
        tx: &SignedTransaction,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
        now: Duration,
        prechecked_signature_result: Option<Result<(), SignatureVerificationFail>>,
        prepared: &PreparedTransactionMetadata,
    ) -> Result<(), AcceptTransactionFail> {
        let signature_check =
            prechecked_signature_result.map_or(SignatureCheck::Verify, SignatureCheck::Override);
        Self::validate_with_now_and_signature_check(
            tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            now,
            signature_check,
            Some(prepared),
        )
    }
    /// Validate a transaction after a successful single-Ed25519 precheck with prepared metadata.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`].
    #[allow(clippy::too_many_lines)]
    pub(crate) fn validate_with_now_after_single_ed25519_precheck_and_prepared_metadata(
        tx: &SignedTransaction,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
        now: Duration,
        prepared: &PreparedTransactionMetadata,
    ) -> Result<(), AcceptTransactionFail> {
        Self::validate_with_now_and_signature_check(
            tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            now,
            SignatureCheck::PrecheckedSingleEd25519,
            Some(prepared),
        )
    }
    #[allow(clippy::too_many_lines)]
    fn validate_with_now_and_signature_check(
        tx: &SignedTransaction,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
        now: Duration,
        signature_check: SignatureCheck,
        prepared: Option<&PreparedTransactionMetadata>,
    ) -> Result<(), AcceptTransactionFail> {
        reject_retired_heartbeat_metadata(tx).map_err(AcceptTransactionFail::TransactionLimit)?;
        Self::validate_common(tx, expected_network_id, max_clock_drift, now)?;
        let ttl = tx.time_to_live().ok_or_else(|| {
            AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                reason: "Transaction `time_to_live_ms` is required and must be signature-bound"
                    .into(),
            })
        })?;
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        let max_ttl_ms = limits.max_time_to_live_ms().get();
        if ttl_ms > max_ttl_ms {
            return Err(AcceptTransactionFail::TransactionLimit(
                TransactionLimitError {
                    reason: format!(
                        "Transaction time-to-live {ttl_ms} ms exceeds the governed limit \
                         {max_ttl_ms} ms"
                    ),
                },
            ));
        }
        let expires_at = tx.creation_time().checked_add(ttl).ok_or_else(|| {
            AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                reason: "Transaction creation time plus time-to-live exceeds the timestamp range"
                    .into(),
            })
        })?;
        if now > expires_at {
            return Err(AcceptTransactionFail::TransactionExpired {
                expires_at_ms: expires_at.as_millis(),
                now_ms: now.as_millis(),
            });
        }
        Self::ensure_signing_allowed(tx, crypto)?;
        Self::verify_signature_for_check(tx, signature_check, prepared)?;
        let signature_count = tx.signature_count();
        Self::ensure_signature_limit(signature_count, &limits)?;
        let tx_encoded_len = Self::signed_encoded_len_for_limit_with_prepared(tx, prepared);
        let max_tx_bytes = limits.max_tx_bytes().get();
        if tx_encoded_len > max_tx_bytes {
            return Err(AcceptTransactionFail::TransactionLimit(
                TransactionLimitError {
                    reason: format!(
                        "Transaction size {tx_encoded_len} bytes exceeds limit {max_tx_bytes} bytes"
                    ),
                },
            ));
        }
        validate_signed_attachments(tx)?;
        let decompressed_len = tx
            .attachments()
            .map_or(0usize, |attachments| attachments.total_occurrence_bytes());
        let decompressed_len = u64::try_from(decompressed_len).unwrap_or(u64::MAX);
        let max_decompressed_bytes = limits.max_decompressed_bytes().get();
        if decompressed_len > max_decompressed_bytes {
            return Err(AcceptTransactionFail::TransactionLimit(
                TransactionLimitError {
                    reason: format!(
                        "Transaction attachments expand to {decompressed_len} bytes which exceeds limit {max_decompressed_bytes} bytes"
                    ),
                },
            ));
        }
        let expires_at_height_meta = tx.expires_at_height().map_err(|err| {
            AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                reason: format!(
                    "Transaction metadata `expires_at_height` must be an unsigned integer: {err}"
                ),
            })
        })?;
        if limits.require_height_ttl && expires_at_height_meta.is_none() {
            return Err(AcceptTransactionFail::TransactionLimit(
                TransactionLimitError {
                    reason: "Transaction metadata `expires_at_height` is required by configuration"
                        .into(),
                },
            ));
        }
        let tx_sequence_meta = tx.tx_sequence().map_err(|err| {
            AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                reason: format!(
                    "Transaction metadata `tx_sequence` must be an unsigned integer: {err}"
                ),
            })
        })?;
        if limits.require_sequence && tx_sequence_meta.is_none() {
            return Err(AcceptTransactionFail::TransactionLimit(
                TransactionLimitError {
                    reason: "Transaction metadata `tx_sequence` is required by configuration"
                        .into(),
                },
            ));
        }
        let max_metadata_depth = usize::from(limits.max_metadata_depth().get());
        ensure_metadata_depth_with_prepared(tx.metadata(), max_metadata_depth, prepared)
            .map_err(AcceptTransactionFail::TransactionLimit)?;
        // Attachment payloads currently carry flat structures; no additional nesting cap required.
        match &tx.instructions() {
            Executable::Instructions(instructions) => {
                if instructions.is_empty() {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: "Transaction must contain at least one instruction".into(),
                        },
                    ));
                }
                let instruction_limit = limits.max_instructions().get();
                let instruction_count = u64::try_from(instructions.len()).unwrap_or(u64::MAX);
                if instruction_count > instruction_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "Too many instructions in payload, max number is {}, but got {}",
                                limits.max_instructions(),
                                instructions.len()
                            ),
                        },
                    ));
                }
            }
            Executable::ContractCall(_) => {
                iroha_data_model::transaction::require_transaction_gas_limit(
                    tx.fee_payment_intent(),
                )
                .map_err(|err| {
                    AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                        reason: err.to_string(),
                    })
                })?;
            }
            Executable::Batch(items) => {
                if items.is_empty() {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: "Transaction executable batch must not be empty".into(),
                        },
                    ));
                }
                let item_limit = limits.max_instructions().get();
                let item_count = u64::try_from(items.len()).unwrap_or(u64::MAX);
                if item_count > item_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "Too many executable batch items, max number is {}, but got {}",
                                limits.max_instructions(),
                                items.len()
                            ),
                        },
                    ));
                }
                if items
                    .iter()
                    .any(|item| matches!(item, ExecutableBatchItem::ContractCall(_)))
                {
                    iroha_data_model::transaction::require_transaction_gas_limit(
                        tx.fee_payment_intent(),
                    )
                    .map_err(|err| {
                        AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                            reason: err.to_string(),
                        })
                    })?;
                }
            }
            Executable::IvmProved(proved) => {
                iroha_data_model::transaction::require_transaction_gas_limit(
                    tx.fee_payment_intent(),
                )
                .map_err(|err| {
                    AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                        reason: err.to_string(),
                    })
                })?;
                let instruction_limit = limits.max_instructions().get();
                let instruction_count = u64::try_from(proved.overlay.len()).unwrap_or(u64::MAX);
                if instruction_count > instruction_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "Too many instructions in proved overlay, max number is {}, but got {}",
                                limits.max_instructions(),
                                proved.overlay.len()
                            ),
                        },
                    ));
                }
                let ivm_bytecode_size_limit = limits.ivm_bytecode_size().get();
                let bytecode_size = u64::try_from(proved.bytecode.size_bytes()).unwrap_or(u64::MAX);
                if bytecode_size > ivm_bytecode_size_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "IVM bytecode size is too large: max {}, got {} \
                                (configured by \"Parameter::SmartContractLimits\")",
                                limits.ivm_bytecode_size(),
                                proved.bytecode.size_bytes()
                            ),
                        },
                    ));
                }
                // Decode the program header to obtain the code section and enforce the global
                // instruction count limit published via `TransactionParameters`.
                let parsed =
                    ivm::ProgramMetadata::parse(proved.bytecode.as_ref()).map_err(|err| {
                        AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                            reason: format!("Failed to parse IVM metadata: {err}"),
                        })
                    })?;
                let code = &proved.bytecode.as_ref()[parsed.code_offset..];
                let decoded_count =
                    ivm::ivm_cache::validate_instruction_stream(code).map_err(|err| {
                        AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                            reason: format!("Failed to decode IVM instructions: {err}"),
                        })
                    })?;
                let decoded_bytes = u64::try_from(code.len()).unwrap_or(u64::MAX);
                if decoded_bytes > ivm_bytecode_size_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "Decoded IVM instruction stream exceeds byte limit {} with {} bytes",
                                limits.ivm_bytecode_size(),
                                decoded_bytes
                            ),
                        },
                    ));
                }
                let decoded_len = u64::try_from(decoded_count).unwrap_or(u64::MAX);
                if decoded_len > instruction_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "Too many IVM instructions in payload, max number is {}, but decoded {}",
                                limits.max_instructions(),
                                decoded_count
                            ),
                        },
                    ));
                }
            }
            Executable::Ivm(smart_contract) => {
                iroha_data_model::transaction::require_transaction_gas_limit(
                    tx.fee_payment_intent(),
                )
                .map_err(|err| {
                    AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                        reason: err.to_string(),
                    })
                })?;
                let ivm_bytecode_size_limit = limits.ivm_bytecode_size().get();
                let bytecode_size = u64::try_from(smart_contract.size_bytes()).unwrap_or(u64::MAX);
                if bytecode_size > ivm_bytecode_size_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "IVM bytecode size is too large: max {}, got {} \
                                (configured by \"Parameter::SmartContractLimits\")",
                                limits.ivm_bytecode_size(),
                                smart_contract.size_bytes()
                            ),
                        },
                    ));
                }
                // Decode the program header to obtain the code section and enforce the global
                // instruction count limit published via `TransactionParameters`.
                let parsed =
                    ivm::ProgramMetadata::parse(smart_contract.as_ref()).map_err(|err| {
                        AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                            reason: format!("Failed to parse IVM metadata: {err}"),
                        })
                    })?;
                let code = &smart_contract.as_ref()[parsed.code_offset..];
                let decoded_count =
                    ivm::ivm_cache::validate_instruction_stream(code).map_err(|err| {
                        AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                            reason: format!("Failed to decode IVM instructions: {err}"),
                        })
                    })?;
                let decoded_bytes = u64::try_from(code.len()).unwrap_or(u64::MAX);
                if decoded_bytes > ivm_bytecode_size_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "Decoded IVM instruction stream exceeds byte limit {} with {} bytes",
                                limits.ivm_bytecode_size(),
                                decoded_bytes
                            ),
                        },
                    ));
                }
                let instruction_limit = limits.max_instructions().get();
                let decoded_len = u64::try_from(decoded_count).unwrap_or(u64::MAX);
                if decoded_len > instruction_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "Too many IVM instructions in payload, max number is {}, but decoded {}",
                                limits.max_instructions(),
                                decoded_count
                            ),
                        },
                    ));
                }
            }
        }
        Ok(())
    }
    /// Create [`Self`] assuming the signed transaction is acceptable.
    pub fn new_unchecked(tx: impl Into<Cow<'tx, SignedTransaction>>) -> Self {
        let entrypoint = match tx.into() {
            Cow::Borrowed(signed) => Cow::Owned(TransactionEntrypoint::External(signed.clone())),
            Cow::Owned(signed) => return Self::from_external_with_hot_cache(signed),
        };
        Self::from_entrypoint(entrypoint)
    }
    /// Create [`Self`] assuming the entrypoint is acceptable.
    pub fn new_unchecked_entrypoint(tx: impl Into<Cow<'tx, TransactionEntrypoint>>) -> Self {
        match tx.into() {
            Cow::Owned(TransactionEntrypoint::External(signed)) => {
                Self::from_external_with_hot_cache(signed)
            }
            entrypoint => Self::from_entrypoint(entrypoint),
        }
    }
    /// Borrow the underlying entrypoint.
    #[must_use]
    pub fn entrypoint(&self) -> &TransactionEntrypoint {
        self.entrypoint.as_ref()
    }
    /// Consume the accepted transaction and return its wrapped entrypoint.
    #[must_use]
    pub fn into_entrypoint(self) -> TransactionEntrypoint {
        self.entrypoint.into_owned()
    }
    /// Borrow the wrapped signed transaction when present.
    #[must_use]
    pub fn external(&self) -> Option<&SignedTransaction> {
        match self.entrypoint() {
            TransactionEntrypoint::External(entrypoint) => Some(entrypoint),
            TransactionEntrypoint::SealedReveal(entrypoint) => {
                Some(entrypoint.signed_transaction())
            }
            TransactionEntrypoint::SealedCommitment(_) => None,
        }
    }
    /// Return the canonical hash of the complete wrapped entrypoint.
    ///
    /// Sealed carriers keep their outer identity. Signed work inside a reveal has a
    /// separate execution-call identity and must not substitute for this hash.
    #[must_use]
    pub fn hash_as_entrypoint(&self) -> HashOf<TransactionEntrypoint> {
        *self
            .entrypoint_hash
            .get_or_init(|| self.entrypoint().hash())
    }
    /// Return the framed size of the signed transaction or sealed variant for admission limits.
    /// The canonical entrypoint frame includes its enum envelope; queue retention accounts
    /// for those complete bytes through `entrypoint_bytes`.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        *self
            .encoded_len
            .get_or_init(|| Self::entrypoint_encoded_len(self.entrypoint()))
    }
    /// Return cached canonical signed-transaction bytes for queue gossip when this is external.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn signed_bytes(&self) -> Option<Arc<Vec<u8>>> {
        self.signed_bytes
            .get_or_init(|| {
                self.external().map(|signed| {
                    Arc::new(norito::to_bytes(signed).expect("encode signed transaction"))
                })
            })
            .as_ref()
            .map(Arc::clone)
    }
    /// Return cached canonical transaction-entrypoint bytes for queue gossip.
    #[must_use]
    pub(crate) fn entrypoint_bytes(&self) -> Arc<Vec<u8>> {
        Arc::clone(self.entrypoint_bytes.get_or_init(|| {
            Arc::new(
                norito::encode_canonical(self.entrypoint())
                    .expect("encode canonical transaction entrypoint"),
            )
        }))
    }
    /// Return cached payload hash when this is an external transaction.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn payload_hash(
        &self,
    ) -> Option<HashOf<iroha_data_model::transaction::signed::TransactionPayload>> {
        *self
            .payload_hash
            .get_or_init(|| self.external().map(|signed| HashOf::new(signed.payload())))
    }
    /// Return cached parsed Ed25519 key for single-key Ed25519 authorities.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn single_ed25519_key(&self) -> Option<iroha_crypto::Ed25519ParsedPublicKey> {
        *self
            .single_ed25519_key
            .get_or_init(|| self.external().and_then(Self::parsed_single_ed25519_key))
    }
    /// Return prepared metadata for an external transaction.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn prepared_metadata(&self) -> Option<PreparedTransactionMetadata> {
        let TransactionEntrypoint::External(signed) = self.entrypoint() else {
            return None;
        };
        let payload_hash = *self
            .payload_hash
            .get_or_init(|| self.external().map(|signed| HashOf::new(signed.payload())))
            .as_ref()?;
        let single_ed25519_key = *self
            .single_ed25519_key
            .get_or_init(|| self.external().and_then(Self::parsed_single_ed25519_key));
        Some(PreparedTransactionMetadata {
            signed_hash: signed.hash(),
            stateless_cache_key: StatelessValidationCacheKey::new(signed),
            entrypoint_hash: self.hash_as_entrypoint(),
            payload_hash,
            encoded_len: self.encoded_len(),
            signed_bytes: self.signed_bytes(),
            entrypoint_bytes: Some(self.entrypoint_bytes()),
            single_ed25519_key,
            metadata_depths: prepare_metadata_depths(self.metadata()?),
        })
    }
    /// Return signed cache metadata only for an original External fixture.
    #[cfg(test)]
    pub(crate) fn stateless_cache_metadata(&self) -> Option<PreparedTransactionMetadata> {
        let TransactionEntrypoint::External(signed) = self.entrypoint() else {
            return None;
        };
        let payload_hash = *self
            .payload_hash
            .get_or_init(|| Some(HashOf::new(signed.payload())))
            .as_ref()?;
        let single_ed25519_key = *self
            .single_ed25519_key
            .get_or_init(|| Self::parsed_single_ed25519_key(signed));
        Some(PreparedTransactionMetadata {
            signed_hash: signed.hash(),
            stateless_cache_key: StatelessValidationCacheKey::new(signed),
            entrypoint_hash: self.hash_as_entrypoint(),
            payload_hash,
            encoded_len: self.encoded_len(),
            signed_bytes: None,
            entrypoint_bytes: None,
            single_ed25519_key,
            metadata_depths: prepare_metadata_depths(self.metadata()?),
        })
    }
    /// Borrow the transaction authority account identifier when present.
    #[must_use]
    pub fn authority_opt(&self) -> Option<&AccountId> {
        self.entrypoint().authority_opt()
    }
    /// Borrow the transaction authority account identifier.
    #[must_use]
    pub fn authority(&self) -> &AccountId {
        self.entrypoint().authority()
    }
    /// Entry-point metadata when present.
    #[must_use]
    pub fn metadata(&self) -> Option<&Metadata> {
        self.entrypoint().metadata()
    }
    /// Creation timestamp for queue expiry and projections.
    #[must_use]
    pub fn creation_time(&self) -> Duration {
        match self.entrypoint() {
            TransactionEntrypoint::External(entrypoint) => entrypoint.creation_time(),
            TransactionEntrypoint::SealedCommitment(_) => Duration::ZERO,
            TransactionEntrypoint::SealedReveal(entrypoint) => {
                entrypoint.signed_transaction().creation_time()
            }
        }
    }
    /// Entry-point TTL when one exists.
    #[must_use]
    pub fn time_to_live(&self) -> Option<Duration> {
        self.external().and_then(SignedTransaction::time_to_live)
    }
    /// Borrow a source after the same explicit-time envelope/signature admission.
    /// The applying owner separately authenticates any historical time authority.
    pub(crate) fn accept_borrowed_entrypoint_at_time(
        tx: &'tx TransactionEntrypoint,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
        validation_time: Duration,
    ) -> Result<Self, AcceptTransactionFail> {
        AcceptedTransaction::<'static>::validate_entrypoint_with_now(
            tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            validation_time,
        )?;
        Ok(Self::from_entrypoint(Cow::Borrowed(tx)).with_validation_time(validation_time))
    }
}
impl AcceptedTransaction<'static> {
    fn validate_entrypoint_with_now(
        tx: &TransactionEntrypoint,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
        now: Duration,
    ) -> Result<(), AcceptTransactionFail> {
        match tx {
            TransactionEntrypoint::External(signed) => {
                Self::validate_with_now(
                    signed,
                    expected_network_id,
                    max_clock_drift,
                    limits,
                    crypto,
                    now,
                )?;
            }
            TransactionEntrypoint::SealedCommitment(commitment) => {
                validate_sealed_commitment_stateless(commitment, expected_network_id, limits)?;
            }
            TransactionEntrypoint::SealedReveal(reveal) => {
                let signed = reveal.signed_transaction();
                Self::validate_with_now(
                    signed,
                    expected_network_id,
                    max_clock_drift,
                    limits,
                    crypto,
                    now,
                )?;
            }
        }
        Ok(())
    }
    /// Accept genesis transaction. Transition from [`SignedTransaction`] to [`AcceptedTransaction`].
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`]
    pub fn accept_genesis(
        tx: SignedTransaction,
        max_clock_drift: Duration,
        genesis_account: &AccountId,
        crypto: &iroha_config::parameters::actual::Crypto,
    ) -> Result<Self, AcceptTransactionFail> {
        let now = current_unix_time();
        Self::validate_genesis_with_now(&tx, max_clock_drift, genesis_account, crypto, now)?;
        Ok(Self::from_external_with_hot_cache(tx).with_validation_time(now))
    }
    /// Accept transaction. Transition from [`SignedTransaction`] to [`AcceptedTransaction`].
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`]
    pub fn accept(
        tx: SignedTransaction,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
    ) -> Result<Self, AcceptTransactionFail> {
        let (now, nts_snapshot) = capture_network_admission();
        Self::validate_with_now(
            &tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            now,
        )?;
        enforce_nts_health_for_time_sensitive(&tx, nts_snapshot)?;
        Ok(Self::from_external_with_hot_cache(tx).with_validation_time(now))
    }
    /// Accept transaction using caller-provided canonical signed-transaction bytes.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`].
    #[cfg(test)]
    pub(crate) fn accept_with_canonical_signed_bytes(
        tx: SignedTransaction,
        signed_bytes: Arc<Vec<u8>>,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
    ) -> Result<Self, AcceptTransactionFail> {
        let (now, nts_snapshot) = capture_network_admission();
        Self::validate_with_now(
            &tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            now,
        )?;
        enforce_nts_health_for_time_sensitive(&tx, nts_snapshot)?;
        Ok(Self::from_external_with_cached_bytes(tx, Some(signed_bytes)).with_validation_time(now))
    }
    /// Accept transaction using a caller-provided [`TimeSource`] for envelope checks.
    ///
    /// Time-sensitive instruction policy is still evaluated from one live NTS
    /// snapshot; the caller-provided clock is intentionally used only for the
    /// creation-time and TTL checks.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`]
    pub fn accept_with_time_source(
        tx: SignedTransaction,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
        time_source: &TimeSource,
    ) -> Result<Self, AcceptTransactionFail> {
        let now = time_source.get_unix_time();
        Self::validate_with_now(
            &tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            now,
        )?;
        enforce_nts_health_for_time_sensitive(&tx, crate::time::admission_snapshot())?;
        Ok(Self::from_external_with_hot_cache(tx).with_validation_time(now))
    }
    /// Accept any directly submitted transaction entrypoint.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`].
    pub fn accept_entrypoint(
        tx: TransactionEntrypoint,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
    ) -> Result<Self, AcceptTransactionFail> {
        let (now, nts_snapshot) = capture_network_admission();
        Self::validate_entrypoint_with_now(
            &tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            now,
        )?;
        enforce_nts_health_for_entrypoint(&tx, nts_snapshot)?;
        Ok(match tx {
            TransactionEntrypoint::External(signed) => Self::from_external_with_hot_cache(signed),
            other => Self::from_entrypoint(Cow::Owned(other)),
        }
        .with_validation_time(now))
    }
    /// Admit a test-chain or queue fixture at one explicit validation instant.
    ///
    /// Fixtures run the same chain, signature, crypto-policy, clock, and limit checks as
    /// ingress with their own clock. Live NTS health is not part of this fixture operation;
    /// production ingress captures and enforces its actual NTS admission snapshot.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`].
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn accept_entrypoint_at_time(
        tx: TransactionEntrypoint,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
        validation_time: Duration,
    ) -> Result<Self, AcceptTransactionFail> {
        Self::validate_entrypoint_with_now(
            &tx,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            validation_time,
        )?;
        Ok(match tx {
            TransactionEntrypoint::External(signed) => Self::from_external_with_hot_cache(signed),
            other => Self::from_entrypoint(Cow::Owned(other)),
        }
        .with_validation_time(validation_time))
    }
    /// Accept an already-decoded gossip entrypoint and seed its canonical entrypoint frame bytes.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`].
    pub(crate) fn accept_gossip_entrypoint_with_payload(
        tx: TransactionEntrypoint,
        entrypoint_bytes: Arc<Vec<u8>>,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
    ) -> Result<Self, AcceptTransactionFail> {
        Self::accept_gossip_entrypoint_with_payload_and_prepared_metadata(
            tx,
            entrypoint_bytes,
            entrypoint_hash,
            expected_network_id,
            max_clock_drift,
            limits,
            crypto,
            None,
            false,
        )
    }
    /// Accept an already-decoded gossip entrypoint using caller-prepared metadata.
    ///
    /// This path lets gossip admission reuse deterministic single-Ed25519 batch
    /// verification while still running every non-signature admission check.
    ///
    /// # Errors
    ///
    /// See [`AcceptTransactionFail`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn accept_gossip_entrypoint_with_payload_and_prepared_metadata(
        tx: TransactionEntrypoint,
        entrypoint_bytes: Arc<Vec<u8>>,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
        expected_network_id: &NetworkId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
        prepared: Option<&PreparedTransactionMetadata>,
        single_ed25519_prechecked: bool,
    ) -> Result<Self, AcceptTransactionFail> {
        let (now, nts_snapshot) = capture_network_admission();
        match &tx {
            TransactionEntrypoint::External(signed) => {
                if let Some(prepared) = prepared {
                    if single_ed25519_prechecked {
                        Self::validate_with_now_after_single_ed25519_precheck_and_prepared_metadata(
                            signed,
                            expected_network_id,
                            max_clock_drift,
                            limits,
                            crypto,
                            now,
                            prepared,
                        )?;
                    } else {
                        Self::validate_with_now_and_prepared_metadata(
                            signed,
                            expected_network_id,
                            max_clock_drift,
                            limits,
                            crypto,
                            now,
                            prepared,
                        )?;
                    }
                } else {
                    Self::validate_entrypoint_with_now(
                        &tx,
                        expected_network_id,
                        max_clock_drift,
                        limits,
                        crypto,
                        now,
                    )?;
                }
            }
            _ => {
                Self::validate_entrypoint_with_now(
                    &tx,
                    expected_network_id,
                    max_clock_drift,
                    limits,
                    crypto,
                    now,
                )?;
            }
        }
        enforce_nts_health_for_entrypoint(&tx, nts_snapshot)?;
        let accepted = Self::from_entrypoint_with_cached_entrypoint_bytes(
            tx,
            entrypoint_bytes,
            entrypoint_hash,
        );
        if let Some(prepared) = prepared {
            let _ = accepted.encoded_len.set(prepared.encoded_len);
            let _ = accepted.payload_hash.set(Some(prepared.payload_hash));
            let _ = accepted.single_ed25519_key.set(prepared.single_ed25519_key);
            if let Some(signed_bytes) = prepared.signed_bytes.as_ref() {
                let _ = accepted.signed_bytes.set(Some(Arc::clone(signed_bytes)));
            }
            if let Some(entrypoint_bytes) = prepared.entrypoint_bytes.as_ref() {
                let _ = accepted.entrypoint_bytes.set(Arc::clone(entrypoint_bytes));
            }
            let _ = accepted.entrypoint_hash.set(prepared.entrypoint_hash);
        }
        Ok(accepted.with_validation_time(now))
    }
}
impl StateBlock<'_> {
    /// Carry bounded confidential work from one live overlay into block totals.
    pub(crate) fn account_confidential_work_v1(
        &mut self,
        operations: u32,
        verify_calls: u32,
        proof_bytes: u64,
        confidential_gas: u64,
    ) {
        self.zk_confidential_ops_in_block =
            self.zk_confidential_ops_in_block.saturating_add(operations);
        self.zk_verify_calls_in_block = self.zk_verify_calls_in_block.saturating_add(verify_calls);
        self.zk_proof_bytes_in_block = self.zk_proof_bytes_in_block.saturating_add(proof_bytes);
        self.confidential_gas_used_in_block = self
            .confidential_gas_used_in_block
            .saturating_add(confidential_gas);
    }
    /// Stage the original prevalidated penalties without choosing an apply owner.
    pub(crate) fn stage_rejected_governance_ballot_penalties_v1(
        penalty_tx: &mut StateTransaction<'_, '_>,
        penalties: &[crate::state::DeferredGovernanceBallotPenaltyV1],
    ) -> Result<(), TransactionRejectionReason> {
        for penalty in penalties {
            crate::smartcontracts::isi::world::isi::apply_deferred_governance_ballot_penalty_v1(
                penalty, penalty_tx,
            )
            .map_err(|error| {
                TransactionRejectionReason::Validation(ValidationFail::InternalError(format!(
                    "failed to commit deferred governance ballot penalty: {error}"
                )))
            })?;
        }
        Ok(())
    }
    /// Validate stateful admission rules that must hold before transaction execution.
    ///
    /// This helper intentionally does not execute instructions or apply state. Callers must only
    /// commit the returned sequence after the transaction itself succeeds.
    /// Physical policy uses the captured source capability independently of the native execution
    /// route. Only an authenticated genesis input may omit runtime fraud-assessment metadata.
    pub(crate) fn validate_stateful_admission(
        tx: &SignedTransaction,
        state_transaction: &mut StateTransaction<'_, '_>,
        routing_decision: crate::queue::RoutingDecision,
        policy_route: CapturedNetworkPolicyRoute,
        genesis: Option<&crate::block::AuthenticatedGenesisTransaction>,
    ) -> Result<StatefulAdmission, TransactionRejectionReason> {
        if let Some(genesis) = genesis {
            genesis
                .validate(tx, state_transaction)
                .map_err(reject_not_permitted)?;
        }
        let authority = tx.authority().clone();
        if code::is_historical_contract_subject(&state_transaction.world, &authority) {
            warn!(
                authority = %authority,
                "deployed contract subjects cannot sign transactions directly"
            );
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(CONTRACT_SUBJECT_DIRECT_SIGN_REJECTION.into()),
            ));
        }
        let authority_exists = state_transaction.world.accounts.get(&authority).is_some();
        let allow_unregistered_authority =
            !authority_exists && allows_unregistered_authority(tx.instructions(), &authority);
        // Multisig propose/approve envelopes may use an unmaterialized authority because
        // authorization is derived from multisig membership rather than account storage. All
        // other transactions must originate from an existing account.
        if !authority_exists && !allow_unregistered_authority {
            return Err(TransactionRejectionReason::AccountDoesNotExist(
                FindError::Account(authority.clone()),
            ));
        }
        if let Executable::Instructions(instructions) = tx.instructions()
            && instructions.is_empty()
        {
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(
                    "Transaction must contain at least one instruction".to_owned(),
                ),
            ));
        }
        let (require_height_ttl, require_sequence) = {
            let params = state_transaction.world.parameters();
            (
                params.transaction.require_height_ttl,
                params.transaction.require_sequence,
            )
        };
        let expires_at_height = tx.expires_at_height().map_err(|err| {
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(format!(
                "Transaction metadata `expires_at_height` must be an unsigned integer: {err}"
            )))
        })?;
        let tx_sequence_value = tx.tx_sequence().map_err(|err| {
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(format!(
                "Transaction metadata `tx_sequence` must be an unsigned integer: {err}"
            )))
        })?;
        if require_height_ttl && expires_at_height.is_none() {
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(
                    "Transaction metadata `expires_at_height` is required by configuration".into(),
                ),
            ));
        }
        if let Some(expiry) = expires_at_height {
            let current_height = state_transaction.block_height();
            if current_height >= expiry {
                return Err(TransactionRejectionReason::Validation(
                    ValidationFail::NotPermitted(format!(
                        "Transaction expired at height {expiry}; current height is {current_height}"
                    )),
                ));
            }
        }
        let mut sequence_to_commit = None;
        if let Some(seq) = tx_sequence_value {
            let previous = state_transaction
                .world
                .tx_sequences
                .get(&authority)
                .copied();
            if let Some(prev) = previous {
                if seq <= prev {
                    if require_sequence {
                        return Err(TransactionRejectionReason::Validation(
                            ValidationFail::NotPermitted(format!(
                                "Transaction sequence {seq} for {authority} must exceed previous {prev}"
                            )),
                        ));
                    }
                } else {
                    sequence_to_commit = Some(seq);
                }
            } else {
                sequence_to_commit = Some(seq);
            }
        } else if require_sequence {
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(
                    "Transaction metadata `tx_sequence` is required by configuration".into(),
                ),
            ));
        }
        #[cfg(feature = "telemetry")]
        let telemetry_handle: Option<&StateTelemetry> = Some(state_transaction.telemetry);
        #[cfg(not(feature = "telemetry"))]
        let telemetry_handle: Option<&StateTelemetry> = None;
        if let Ok(account) = state_transaction.world.account(&authority) {
            let has_multisig_state = state_transaction
                .world
                .smart_contract_state
                .get(&crate::smartcontracts::isi::multisig::multisig_account_state_key(&authority))
                .is_some();
            let has_multisig_metadata = account
                .metadata()
                .get(&crate::smartcontracts::isi::multisig::spec_key())
                .is_some();
            let has_multisig_controller = authority.multisig_policy().is_some();
            let allows_multisig_envelope_authority = match tx.instructions() {
                Executable::Instructions(instructions) => {
                    instructions_allow_multisig_envelope_authority(instructions)
                }
                Executable::ContractCall(_)
                | Executable::Batch(_)
                | Executable::IvmProved(_)
                | Executable::Ivm(_) => false,
            };
            if (has_multisig_state || has_multisig_metadata || has_multisig_controller)
                && !allows_multisig_envelope_authority
            {
                warn!(
                    authority = %authority,
                    "multisig accounts cannot sign transactions directly"
                );
                #[cfg(feature = "telemetry")]
                if let Some(telemetry) = telemetry_handle {
                    crate::telemetry::record_social_rejection(telemetry, "multisig_direct_sign");
                }
                return Err(TransactionRejectionReason::Validation(
                    ValidationFail::NotPermitted(MULTISIG_DIRECT_SIGN_REJECTION.into()),
                ));
            }
        }
        let physical = policy_route
            .for_signed(tx, state_transaction, routing_decision)
            .map_err(|error| match error {
                ExecutionAttemptError::Rejected(error) => error,
                ExecutionAttemptError::Deferred(reason) => TransactionRejectionReason::Validation(
                    state_transaction.defer_execution(reason),
                ),
            })?
            .decision();
        state_transaction.current_lane_id = Some(routing_decision.lane_id);
        state_transaction.current_dataspace_id = Some(routing_decision.dataspace_id);
        state_transaction.world.current_dataspace_id = Some(routing_decision.dataspace_id);
        crate::executor::reject_committed_direct_payment(state_transaction, tx).map_err(
            |error| {
                TransactionRejectionReason::Validation(
                    state_transaction.attempt_error_to_validation_fail(error),
                )
            },
        )?;
        crate::executor::validate_transaction_fee_admission(state_transaction, tx)
            .map_err(TransactionRejectionReason::Validation)?;
        if let Err(error) =
            crate::validation_fee::enforce_validation_fee_admission(tx, state_transaction)
        {
            return Err(match error {
                crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    TransactionRejectionReason::Validation(
                        state_transaction.defer_execution(reason),
                    )
                }
            });
        }
        let lane_assignment = LaneAssignment {
            lane_id: physical.lane_id,
            dataspace_id: physical.dataspace_id,
            dataspace_catalog: &state_transaction.nexus.dataspace_catalog,
        };
        enforce_lane_policies(tx, state_transaction, &lane_assignment)?;
        if genesis.is_none() {
            enforce_fraud_policy(
                &state_transaction.fraud_monitoring,
                tx.metadata(),
                telemetry_handle,
                &lane_assignment,
            )?;
        }
        let faucet_claim_to_commit = staged_faucet_claim_consumption(tx, state_transaction)
            .map_err(TransactionRejectionReason::Validation)?;
        Ok(StatefulAdmission {
            authority,
            allow_unregistered_authority,
            sequence_to_commit,
            faucet_claim_to_commit,
        })
    }
    /// Execute admission, business logic and callbacks in the caller's overlay.
    ///
    /// The caller owns rollback, rejection penalties/fees and the output fit check
    /// before applying any successful business changes. This method never applies
    /// the overlay. Returns the trigger sequence, a deterministic rejection, or a
    /// non-serializable local refusal before any completed-output settlement.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub(crate) fn execute_accepted_transaction_in_overlay(
        tx: AcceptedTransaction<'_>,
        state_transaction: &mut StateTransaction<'_, '_>,
        ivm_cache: &mut IvmCache,
        routing_decision: crate::queue::RoutingDecision,
        policy_route: CapturedNetworkPolicyRoute,
        genesis: Option<&crate::block::AuthenticatedGenesisTransaction>,
    ) -> Result<DataTriggerSequence, ExecutionAttemptError<TransactionRejectionReason>> {
        state_transaction.genesis_execution_scope = None;
        state_transaction
            .ensure_execution_ready()
            .map_err(ExecutionAttemptError::Deferred)?;
        if genesis.is_some() && !matches!(tx.entrypoint(), TransactionEntrypoint::External(_)) {
            return Err(
                reject_not_permitted("genesis admission requires an external input").into(),
            );
        }
        let signed = match tx.entrypoint() {
            TransactionEntrypoint::SealedCommitment(commitment) => {
                return Self::validate_sealed_transaction_commitment(commitment, state_transaction)
                    .map_err(ExecutionAttemptError::Rejected);
            }
            TransactionEntrypoint::SealedReveal(reveal) => {
                return Self::validate_sealed_transaction_reveal(
                    reveal,
                    state_transaction,
                    ivm_cache,
                    routing_decision,
                    policy_route,
                );
            }
            TransactionEntrypoint::External(signed) => signed,
        };
        let admission = Self::validate_stateful_admission(
            signed,
            state_transaction,
            routing_decision,
            policy_route,
            genesis,
        )?;
        state_transaction.genesis_execution_scope =
            policy_route.genesis_execution_scope(signed, state_transaction, genesis)?;
        let authority = admission.authority.clone();
        let allow_unregistered_authority = admission.allow_unregistered_authority;
        match signed.instructions() {
            Executable::ContractCall(call) => {
                if crate::executor::transaction_gas_limit(signed).is_none() {
                    return Err(TransactionRejectionReason::Validation(
                        ValidationFail::NotPermitted(
                            "missing gas limit in fee payment intent".to_owned(),
                        ),
                    )
                    .into());
                }
                code::ensure_contract_execution_allowed(
                    &state_transaction.world,
                    &call.contract_address,
                    state_transaction.block_height(),
                )
                .map_err(|reason| {
                    TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason))
                })?;
                let record =
                    code::fetch_bound_contract_record(state_transaction, &call.contract_address)
                        .map_err(|error| {
                            error.map_rejection(TransactionRejectionReason::Validation)
                        })?
                        .ok_or_else(|| {
                            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                                format!(
                                    "contract instance `{}` not found in WSV",
                                    call.contract_address
                                ),
                            ))
                        })?;
                crate::executor::ensure_contract_invocation_code_hash(call, record.code_hash)
                    .map_err(TransactionRejectionReason::Validation)?;
                let contract_address = Some(call.contract_address.clone());
                Self::validate_ivm(
                    authority.clone(),
                    state_transaction,
                    IvmBytecode::from_compiled(record.code_bytes),
                    None,
                    contract_address,
                    ivm_cache,
                )?;
            }
            Executable::Ivm(bytes) => {
                if crate::executor::transaction_gas_limit(signed).is_none() {
                    return Err(TransactionRejectionReason::Validation(
                        ValidationFail::NotPermitted(
                            "missing gas limit in fee payment intent".to_owned(),
                        ),
                    )
                    .into());
                }
                Self::validate_ivm(
                    authority.clone(),
                    state_transaction,
                    bytes.clone(),
                    Some(signed.metadata()),
                    None,
                    ivm_cache,
                )?;
            }
            _ => {}
        }
        debug!(tx=%tx.hash_as_entrypoint(), "Validating transaction");
        Self::validate_transaction_with_runtime_executor(
            signed.clone(),
            state_transaction,
            ivm_cache,
        )?;
        let trigger_sequence = if allow_unregistered_authority {
            debug!(
                authority = %authority,
                "transaction authority is not materialized; skipping data trigger dispatch"
            );
            DataTriggerSequence::default()
        } else {
            debug!("Transaction validated successfully; processing data triggers");
            let trigger_result = state_transaction.execute_data_triggers_dfs(&authority);
            state_transaction
                .ensure_execution_ready()
                .map_err(ExecutionAttemptError::Deferred)?;
            let trigger_sequence = trigger_result?;
            debug!("Data triggers executed successfully");
            trigger_sequence
        };
        crate::retail_fee::finalize(state_transaction)?;
        if genesis.is_none() {
            // All instructions and callbacks have completed in this disposable overlay.
            // Authenticated genesis is checked once after its complete signed batch.
            crate::resource_coherence::validate_final_policy(
                &state_transaction.world,
                state_transaction.block_height(),
            )
            .map_err(crate::resource_coherence::PolicyCoherenceError::into_transaction_rejection)?;
        }
        if let Some(seq) = admission.sequence_to_commit {
            state_transaction
                .world
                .tx_sequences
                .insert(authority.clone(), seq);
        }
        commit_faucet_claim_consumption(state_transaction, &admission);
        Ok(trigger_sequence)
    }
    fn validate_sealed_transaction_commitment(
        commitment: &SignedSealedTransactionCommitment,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> TransactionResultInner {
        validate_sealed_commitment_stateless(
            commitment,
            &state_transaction.network_id,
            state_transaction.world.parameters().transaction(),
        )
        .map_err(|err| match err {
            AcceptTransactionFail::TransactionDomainMismatch(mismatch) => {
                TransactionRejectionReason::Validation(ValidationFail::NotPermitted(format!(
                    "transaction domain mismatch: expected {:?} got {:?}",
                    mismatch.expected, mismatch.actual
                )))
            }
            AcceptTransactionFail::TransactionLimit(limit) => {
                TransactionRejectionReason::LimitCheck(limit)
            }
            other => TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                other.to_string(),
            )),
        })?;
        let payload = commitment.payload();
        let height = state_transaction._curr_block.height().get();
        if payload.reveal_after_height <= height {
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(format!(
                    "sealed transaction reveal_after_height {} must be greater than commit height {height}",
                    payload.reveal_after_height
                )),
            ));
        }
        let key = sealed_commitment_state_key(&payload.commitment);
        if state_transaction
            .world
            .smart_contract_state
            .get(&key)
            .is_some()
        {
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted("sealed transaction commitment already exists".into()),
            ));
        }
        let record = PendingSealedTransactionCommitment {
            payload: payload.clone(),
            commit_height: height,
            commit_index: state_transaction.current_entrypoint_index.unwrap_or(0),
        };
        let bytes = norito::to_bytes(&record).map_err(sealed_state_encode_error)?;
        state_transaction
            .world
            .smart_contract_state
            .insert(key, bytes);
        Ok(DataTriggerSequence::default())
    }
    fn validate_sealed_transaction_reveal(
        reveal: &SealedTransactionReveal,
        state_transaction: &mut StateTransaction<'_, '_>,
        ivm_cache: &mut IvmCache,
        routing_decision: crate::queue::RoutingDecision,
        policy_route: CapturedNetworkPolicyRoute,
    ) -> Result<DataTriggerSequence, ExecutionAttemptError<TransactionRejectionReason>> {
        let key = sealed_commitment_state_key(&reveal.commitment);
        let Some(bytes) = state_transaction.world.smart_contract_state.get(&key) else {
            return Err(
                TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                    "sealed transaction commitment is not pending".into(),
                ))
                .into(),
            );
        };
        let record: PendingSealedTransactionCommitment =
            norito::decode_from_bytes(bytes).map_err(sealed_state_decode_error)?;
        let height = state_transaction._curr_block.height().get();
        validate_sealed_reveal_authentication(reveal, &record, height)?;
        let signed = reveal.signed_transaction();
        state_transaction.world.smart_contract_state.remove(key);
        let accepted = AcceptedTransaction::new_unchecked(Cow::Borrowed(signed));
        // The outer entrypoint's route was authenticated before the reveal was opened. Preserve it
        // for the inner signed transaction so policy drift cannot replace the committed lane.
        Self::execute_accepted_transaction_in_overlay(
            accepted,
            state_transaction,
            ivm_cache,
            routing_decision,
            policy_route,
            None,
        )
    }
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    fn validate_ivm(
        authority: AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
        contract: IvmBytecode,
        transaction_metadata: Option<&Metadata>,
        deploy_target: Option<iroha_data_model::smart_contract::ContractAddress>,
        ivm_cache: &mut IvmCache,
    ) -> Result<(), ExecutionAttemptError<TransactionRejectionReason>> {
        // Parse and cache metadata + derived hashes.
        let bytes = contract.as_ref();
        let summary = ivm_cache.summarize_executable(bytes).map_err(|error| {
            let error = match ExecutionDeferred::try_from_vm_error(error) {
                Ok(owner) => return ExecutionAttemptError::Deferred(owner),
                Err(error) => error,
            };
            let failure = match error {
                ivm::VMError::UnknownSyscall(number) => ValidationFail::NotPermitted(format!(
                    "unknown syscall number 0x{number:02x} for abi_version 1"
                )),
                error => ValidationFail::IvmAdmission(
                    crate::smartcontracts::ivm::admission_reason_from_vm_error(error),
                ),
            };
            ExecutionAttemptError::Rejected(TransactionRejectionReason::Validation(failure))
        })?;
        let is_contract = matches!(
            &summary,
            crate::smartcontracts::ivm::cache::ExecutableProgramSummary::Contract(_)
        );
        if !is_contract {
            if let Some(metadata) = transaction_metadata {
                crate::smartcontracts::ivm::validate_generic_execution_metadata(metadata)
                    .map_err(TransactionRejectionReason::Validation)?;
            }
        }
        let manifest_metadata = transaction_metadata
            .and_then(|metadata| metadata.get(&*CONTRACT_MANIFEST_METADATA_NAME))
            .map(|json| json.clone().try_into_any_norito::<ContractManifest>())
            .transpose()
            .map_err(|_| {
                TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                    iroha_data_model::executor::IvmAdmissionError::ManifestMalformed,
                ))
            })?;
        let metadata_deploy_target = transaction_metadata
            .and_then(|metadata| metadata.get(&*GOV_CONTRACT_ADDRESS_METADATA_KEY))
            .map(|json| {
                json.clone()
                    .try_into_any_norito::<String>()
                    .map_err(|_| ())
                    .and_then(|raw| raw.parse().map_err(|_| ()))
            })
            .transpose()
            .map_err(|()| {
                TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                    "invalid gov_contract_address metadata".to_owned(),
                ))
            })?;
        let deploy_target = deploy_target.or(metadata_deploy_target);
        let meta = summary.metadata().clone();
        let offset = summary.code_offset();
        // Use the domain-separated full-artifact hash and canonical ABI hash.
        let code_hash = summary.code_hash();
        let artifact_id =
            crate::executor::root_scope::captured_artifact_id(state_transaction, code_hash)
                .map_err(TransactionRejectionReason::Validation)?;
        let abi_hash = summary.abi_hash();
        crate::pipeline::overlay::validate_header_policy(&meta).map_err(|error| {
            TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(error))
        })?;
        // Runtime upgrade admission: if there is an activated runtime upgrade record for this ABI
        // version, require that the computed ABI hash matches the active manifest.
        //
        // This is redundant under the v1-only policy (all valid manifests must match ABI v1),
        // but guards against tampered WSV and keeps admission deterministic across nodes.
        {
            let current_height = state_transaction._curr_block.height().get();
            if let Some(expected) = crate::smartcontracts::ivm::active_runtime_abi_hash(
                &state_transaction.world,
                current_height,
            )
            .map_err(|error| {
                TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(error))
            })? {
                if expected != abi_hash {
                    return Err(TransactionRejectionReason::Validation(
                        ValidationFail::IvmAdmission(
                            iroha_data_model::executor::IvmAdmissionError::ManifestAbiHashMismatch(
                                iroha_data_model::executor::ManifestAbiHashMismatchInfo {
                                    expected,
                                    actual: abi_hash,
                                },
                            ),
                        ),
                    )
                    .into());
                }
            }
        }
        // Fuel (`max_cycles`) must be explicitly provided and bounded by both
        // governance and the local deterministic execution ceiling.
        let upper_bound = state_transaction.pipeline.ivm_max_cycles_upper_bound;
        let params = state_transaction.world.parameters.get();
        crate::smartcontracts::ivm::validate_cycle_limits(
            &meta,
            upper_bound,
            params.smart_contract().fuel(),
        )
        .map_err(|error| {
            TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(error))
        })?;
        let code = &bytes[offset..];
        let decoded = if code.is_empty() {
            None
        } else {
            Some(
                ivm::ivm_cache::IvmCache::decode_stream_with_memory_budget(
                    code,
                    &state_transaction.execution_budget(),
                )
                .map_err(|err| {
                    let err = match ExecutionDeferred::try_from_vm_error(err) {
                        Ok(owner) => return ExecutionAttemptError::Deferred(owner),
                        Err(error) => error,
                    };
                    ExecutionAttemptError::Rejected(TransactionRejectionReason::Validation(
                        ValidationFail::IvmAdmission(
                            iroha_data_model::executor::IvmAdmissionError::BytecodeDecodingFailed(
                                err.to_string(),
                            ),
                        ),
                    ))
                })?,
            )
        };
        let inst_cap = state_transaction.pipeline.ivm_max_decoded_instructions;
        let bytes_cap = state_transaction.pipeline.ivm_max_decoded_bytes;
        if let Some(decoded) = decoded.as_ref() {
            if inst_cap != 0 {
                let decoded_instr = u64::try_from(decoded.len()).unwrap_or(u64::MAX);
                if decoded_instr > inst_cap {
                    return Err(TransactionRejectionReason::Validation(
                        ValidationFail::IvmAdmission(
                            iroha_data_model::executor::IvmAdmissionError::DecodedInstructionCountExceeded(
                                iroha_data_model::executor::DecodedInstructionLimitInfo {
                                    decoded_instructions: decoded_instr,
                                    limit: inst_cap,
                                },
                            ),
                        ),
                    ).into());
                }
            }
            if bytes_cap != 0 {
                let decoded_bytes = u64::try_from(code.len()).unwrap_or(u64::MAX);
                if decoded_bytes > bytes_cap {
                    return Err(TransactionRejectionReason::Validation(
                        ValidationFail::IvmAdmission(
                            iroha_data_model::executor::IvmAdmissionError::DecodedCodeSizeExceeded(
                                iroha_data_model::executor::DecodedCodeSizeLimitInfo {
                                    decoded_bytes,
                                    limit: bytes_cap,
                                },
                            ),
                        ),
                    )
                    .into());
                }
            }
        }
        // Admission guard: reject bytecode that invokes syscalls outside the ABI surface.
        if let Some(decoded) = decoded.as_ref() {
            debug_assert_eq!(meta.abi_version, 1, "only ABI v1 is supported");
            let policy = ivm::SyscallPolicy::AbiV1;
            for op in decoded.iter() {
                let opcode = ivm::instruction::wide::opcode(op.inst);
                let number = if opcode == ivm::instruction::wide::system::SCALL {
                    // SCALL immediate is an unsigned byte; reinterpret negative imm8 as its
                    // 8-bit two's complement value to mirror VM execution semantics.
                    Some(u32::from(
                        ivm::instruction::wide::imm8(op.inst).to_ne_bytes()[0],
                    ))
                } else if opcode == ivm::instruction::wide::system::SYSTEM {
                    Some(ivm::encoding::wide::decode_syscallx(op.inst))
                } else {
                    None
                };
                if let Some(number) = number
                    && !ivm::syscalls::is_syscall_allowed(policy, number)
                {
                    return Err(TransactionRejectionReason::Validation(
                        ValidationFail::NotPermitted(format!(
                            "unknown syscall number 0x{number:02x} for abi_version {}",
                            meta.abi_version
                        )),
                    )
                    .into());
                }
            }
        }
        // Validate every supplied or stored manifest as a complete V1
        // consensus binding. A present manifest may not omit either hash.
        let validate_manifest =
            |manifest: &ContractManifest| -> Result<(), TransactionRejectionReason> {
                crate::smartcontracts::ivm::validate_manifest_hashes(manifest, code_hash, abi_hash)
                    .map_err(|error| {
                        TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(error))
                    })
            };
        if is_contract {
            if let Some(manifest) = manifest_metadata.as_ref() {
                validate_manifest(manifest)?;
            }
            if let Some(manifest) = state_transaction.world.contract_manifests.get(&artifact_id) {
                validate_manifest(manifest)?;
            }
        } else if manifest_metadata.is_some()
            || state_transaction
                .world
                .contract_manifests
                .get(&artifact_id)
                .is_some()
            || deploy_target.is_some()
        {
            return Err(
                TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                    iroha_data_model::executor::IvmAdmissionError::ManifestMalformed,
                ))
                .into(),
            );
        }
        // Protected namespaces admission (governance gating)
        if let Some(contract_address) = deploy_target {
            let protected = crate::smartcontracts::code::protected_contract_namespaces(
                state_transaction.world.parameters.get(),
            )
            .map_err(|error| {
                TransactionRejectionReason::Validation(ValidationFail::InternalError(format!(
                    "invalid protected-contract namespace policy: {error}"
                )))
            })?
            .unwrap_or_default();
            if !protected.is_empty() {
                // Require an enacted proposal matching the governed contract address and hashes.
                let want_code = hex::encode(<[u8; 32]>::from(code_hash));
                let want_abi = hex::encode(<[u8; 32]>::from(abi_hash));
                let mut ok = false;
                for (_pid, rec) in state_transaction.world.governance_proposals.iter() {
                    let Some(payload) = rec.as_deploy_contract() else {
                        continue;
                    };
                    if payload.contract_address == contract_address
                        && payload.code_hash.to_hex() == want_code
                        && payload.abi_hash.to_hex() == want_abi
                        && matches!(rec.status, crate::state::GovernanceProposalStatus::Enacted)
                    {
                        ok = true;
                        break;
                    }
                }
                if !ok {
                    #[cfg(feature = "telemetry")]
                    state_transaction
                        .telemetry
                        .record_protected_namespace_enforcement("rejected");
                    return Err(TransactionRejectionReason::Validation(
                        ValidationFail::NotPermitted(
                            "deployment into governed contract address requires enacted governance proposal"
                                .to_owned(),
                        ),
                    ).into());
                }
                #[cfg(feature = "telemetry")]
                state_transaction
                    .telemetry
                    .record_protected_namespace_enforcement("allowed");
            }
        }
        let _ = authority; // reserved for future context-dependent checks
        Ok(())
    }
    /// Validate transaction with runtime executors.
    ///
    /// Note: transaction instructions will be executed on the given `state_transaction`.
    fn validate_transaction_with_runtime_executor(
        tx: SignedTransaction,
        state_transaction: &mut StateTransaction<'_, '_>,
        ivm_cache: &mut IvmCache,
    ) -> Result<(), ExecutionAttemptError<TransactionRejectionReason>> {
        let authority = tx.authority().clone();
        state_transaction
            .world
            .executor
            .clone()
            .execute_transaction(state_transaction, &authority, tx, ivm_cache)
            .map_err(|error| {
                error.map_rejection(|error| {
                    if let ValidationFail::InternalError(msg) = &error {
                        error!(
                            error = msg,
                            "Internal error occurred during transaction validation, \
                         is Runtime Executor correct?"
                        )
                    }
                    error.into()
                })
            })
    }
}
#[cfg(feature = "telemetry")]
static FRAUD_ASSESSMENT_TENANT_KEY: LazyLock<TelemetryName> = LazyLock::new(|| {
    TelemetryName::from_str("fraud_assessment_tenant").expect("static tenant metadata key")
});
#[cfg(feature = "telemetry")]
static FRAUD_ASSESSMENT_SCORE_KEY: LazyLock<TelemetryName> = LazyLock::new(|| {
    TelemetryName::from_str("fraud_assessment_score_bps").expect("static score metadata key")
});
#[cfg(feature = "telemetry")]
static FRAUD_ASSESSMENT_LATENCY_KEY: LazyLock<TelemetryName> = LazyLock::new(|| {
    TelemetryName::from_str("fraud_assessment_latency_ms").expect("static latency metadata key")
});
#[cfg(feature = "telemetry")]
static FRAUD_ASSESSMENT_DISPOSITION_KEY: LazyLock<TelemetryName> = LazyLock::new(|| {
    TelemetryName::from_str("fraud_assessment_disposition")
        .expect("static disposition metadata key")
});
#[cfg(feature = "telemetry")]
#[derive(Clone, Copy)]
enum FraudDisposition {
    Fraud,
    Clean,
}
/// Dataspace routing details needed when enforcing the fraud policy.
pub(crate) struct LaneAssignment<'cfg> {
    /// Lane identifier selected by routing policy.
    pub(crate) lane_id: NexusLaneId,
    /// Dataspace identifier associated with the lane.
    pub(crate) dataspace_id: NexusDataSpaceId,
    /// Catalog used to resolve dataspace metadata.
    pub(crate) dataspace_catalog: &'cfg DataSpaceCatalog,
}
impl LaneAssignment<'_> {
    fn dataspace_label(&self) -> String {
        dataspace_label_from_catalog(self.dataspace_catalog, self.dataspace_id)
    }
}
fn dataspace_label_from_catalog(catalog: &DataSpaceCatalog, id: NexusDataSpaceId) -> String {
    catalog
        .entries()
        .iter()
        .find(|entry| entry.id == id)
        .map_or_else(|| id.as_u64().to_string(), |entry| entry.alias.clone())
}
fn reject_not_permitted(reason: impl Into<String>) -> TransactionRejectionReason {
    TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason.into()))
}
fn reject_lane_policy(alias: &str, reason: impl Into<String>) -> TransactionRejectionReason {
    reject_not_permitted(format!("lane {alias}: {}", reason.into()))
}
fn collect_lane_privacy_proofs(
    tx: &SignedTransaction,
) -> Vec<iroha_data_model::nexus::LanePrivacyProof> {
    // Admission has validated every wrapped carrier. A transaction that
    // bypassed it and holds a malformed carrier contributes no witness, so the
    // lane policy that requires one refuses it.
    tx.lane_privacy_proofs_v1().unwrap_or_default()
}
fn enforce_manifest_quorum(
    alias: &str,
    rules: &GovernanceRules,
    tx: &SignedTransaction,
) -> Result<(), TransactionRejectionReason> {
    if let Executable::Instructions(instructions) = tx.instructions()
        && instructions_allow_multisig_envelope_authority(instructions)
    {
        return Ok(());
    }
    let Some(quorum) = rules.quorum else {
        return Ok(());
    };
    if quorum <= 1 {
        return Ok(());
    }
    if rules.validators.is_empty() {
        return Ok(());
    }
    let approvals = collect_manifest_approvals(alias, tx)?;
    let validators = canonical_manifest_validators(alias, rules)?;
    let approved = approvals
        .iter()
        .filter(|account| validators.contains(*account))
        .count();
    let required = usize::try_from(quorum).unwrap_or(usize::MAX);
    if approved < required {
        return Err(reject_lane_policy(
            alias,
            format!(
                "lane manifest quorum requires {quorum} validator approvals but {approved} were provided"
            ),
        ));
    }
    Ok(())
}
fn collect_manifest_approvals(
    alias: &str,
    tx: &SignedTransaction,
) -> Result<BTreeSet<String>, TransactionRejectionReason> {
    let mut approvals = BTreeSet::new();
    let authority = tx.authority();
    let authority_i105 = authority.canonical_i105().map_err(|err| {
        reject_lane_policy(
            alias,
            format!("failed to encode authority `{authority}` as i105: {err}"),
        )
    })?;
    approvals.insert(authority_i105);
    let metadata = tx.metadata();
    let Some(raw) = metadata.get(&*GOV_APPROVERS_METADATA_KEY) else {
        return Ok(approvals);
    };
    let entries = raw.try_into_any_norito::<Vec<String>>().map_err(|_| {
        reject_lane_policy(
            alias,
            "`gov_manifest_approvers` metadata must be an array of account identifiers",
        )
    })?;
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            return Err(reject_lane_policy(
                alias,
                "`gov_manifest_approvers` metadata entries must not be blank",
            ));
        }
        let canonical = AccountId::canonicalize(trimmed).map_err(|err| {
            reject_lane_policy(
                alias,
                format!("invalid account id `{trimmed}` in `gov_manifest_approvers`: {err}"),
            )
        })?;
        if !approvals.insert(canonical) {
            return Err(reject_lane_policy(
                alias,
                "`gov_manifest_approvers` metadata must not duplicate approvers",
            ));
        }
    }
    Ok(approvals)
}
fn canonical_manifest_validators(
    alias: &str,
    rules: &GovernanceRules,
) -> Result<BTreeSet<String>, TransactionRejectionReason> {
    let mut validators = BTreeSet::new();
    for validator in &rules.validators {
        let i105 = validator.canonical_i105().map_err(|err| {
            reject_lane_policy(
                alias,
                format!("failed to encode validator `{validator}` as i105: {err}"),
            )
        })?;
        if !validators.insert(i105) {
            return Err(reject_lane_policy(
                alias,
                "lane manifest validator set contains duplicate validators",
            ));
        }
    }
    Ok(validators)
}
fn tx_contains_runtime_upgrade_instruction(tx: &SignedTransaction) -> bool {
    let contains_runtime_upgrade = |instruction: &InstructionBox| {
        instruction
            .as_any()
            .downcast_ref::<ProposeRuntimeUpgrade>()
            .is_some()
            || instruction
                .as_any()
                .downcast_ref::<ActivateRuntimeUpgrade>()
                .is_some()
            || instruction
                .as_any()
                .downcast_ref::<CancelRuntimeUpgrade>()
                .is_some()
    };
    match tx.instructions() {
        Executable::Instructions(instructions) => instructions.iter().any(contains_runtime_upgrade),
        Executable::Batch(items) => items.iter().any(|item| match item {
            ExecutableBatchItem::Instruction(instruction) => contains_runtime_upgrade(instruction),
            ExecutableBatchItem::ContractCall(_) => false,
        }),
        Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => false,
    }
}
fn tx_touches_manifest_protected_namespace_surface(tx: &SignedTransaction) -> bool {
    let metadata = tx.metadata();
    let has_governance_contract_address =
        metadata.get(&*GOV_CONTRACT_ADDRESS_METADATA_KEY).is_some();
    let has_contract_address_hint = metadata.get(&*CONTRACT_ADDRESS_METADATA_KEY).is_some();
    let mut contract_targets_seen = false;
    let mut register_code_seen = false;
    let inspect_instruction = |instruction: &InstructionBox| {
        let is_contract_target = instruction
            .as_any()
            .downcast_ref::<ActivateContractInstance>()
            .is_some()
            || instruction
                .as_any()
                .downcast_ref::<CommitContractDeployment>()
                .is_some()
            || instruction
                .as_any()
                .downcast_ref::<DeactivateContractInstance>()
                .is_some();
        let is_code_registration = if is_contract_target {
            false
        } else {
            let any = instruction.as_any();
            any.is::<RegisterSmartContractCode>()
                || any.is::<RegisterSmartContractBytes>()
                || any.is::<UploadSmartContractCodeChunk>()
                || any.is::<FinalizeSmartContractCodeUpload>()
                || any.is::<RemoveSmartContractBytes>()
        };
        (is_contract_target, is_code_registration)
    };
    match tx.instructions() {
        Executable::Instructions(instructions) => {
            for instruction in instructions {
                let (target, registration) = inspect_instruction(instruction);
                contract_targets_seen |= target;
                register_code_seen |= registration;
            }
        }
        Executable::ContractCall(_) => {
            contract_targets_seen = true;
        }
        Executable::Batch(items) => {
            for item in items {
                match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        let (target, registration) = inspect_instruction(instruction);
                        contract_targets_seen |= target;
                        register_code_seen |= registration;
                    }
                    ExecutableBatchItem::ContractCall(_) => contract_targets_seen = true,
                }
            }
        }
        Executable::Ivm(_) | Executable::IvmProved(_) => {}
    }
    let ivm_with_contract_metadata = matches!(tx.instructions(), Executable::Ivm(_))
        && (has_governance_contract_address || has_contract_address_hint);
    register_code_seen || contract_targets_seen || ivm_with_contract_metadata
}
fn tx_requires_manifest_validator_gating(rules: &GovernanceRules, tx: &SignedTransaction) -> bool {
    tx_contains_runtime_upgrade_instruction(tx)
        || (!rules.protected_namespaces.is_empty()
            && tx_touches_manifest_protected_namespace_surface(tx))
}
#[allow(clippy::too_many_lines)]
fn enforce_manifest_protected_namespaces(
    alias: &str,
    rules: &GovernanceRules,
    tx: &SignedTransaction,
    world: &impl WorldReadOnly,
) -> Result<(), TransactionRejectionReason> {
    if rules.protected_namespaces.is_empty() {
        return Ok(());
    }
    let metadata = tx.metadata();
    let metadata_governance_contract_address = metadata
        .get(&*GOV_CONTRACT_ADDRESS_METADATA_KEY)
        .map(|value| {
            let raw = value.try_into_any_norito::<String>().map_err(|_| {
                reject_lane_policy(
                    alias,
                    "`gov_contract_address` metadata must be a string value",
                )
            })?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(reject_lane_policy(
                    alias,
                    "`gov_contract_address` metadata must not be blank",
                ));
            }
            trimmed.parse::<iroha_data_model::smart_contract::ContractAddress>().map_err(|err| {
                reject_lane_policy(
                    alias,
                    format!(
                        "`gov_contract_address` metadata `{trimmed}` is not a valid ContractAddress: {err}"
                    ),
                )
            })
        })
        .transpose()?;
    let metadata_contract_address_hint = metadata
        .get(&*CONTRACT_ADDRESS_METADATA_KEY)
        .map(|value| {
            let raw = value.try_into_any_norito::<String>().map_err(|_| {
                reject_lane_policy(alias, "`contract_address` metadata must be a string value")
            })?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(reject_lane_policy(
                    alias,
                    "`contract_address` metadata must not be blank",
                ));
            }
            trimmed.parse::<iroha_data_model::smart_contract::ContractAddress>().map_err(|err| {
                reject_lane_policy(
                    alias,
                    format!(
                        "`contract_address` metadata `{trimmed}` is not a valid ContractAddress: {err}"
                    ),
                )
            })
        })
        .transpose()?;
    let mut contract_targets = BTreeSet::new();
    let mut register_code_seen = false;
    let mut commit_deployment_count = 0_usize;
    let mut activate_seen = false;
    let mut deactivate_seen = false;
    match tx.instructions() {
        Executable::Instructions(instructions) => {
            for instruction in instructions {
                if let Some(commit) = instruction
                    .as_any()
                    .downcast_ref::<CommitContractDeployment>()
                {
                    commit_deployment_count += 1;
                    contract_targets.insert(commit.contract_address().clone());
                } else if let Some(activate) = instruction
                    .as_any()
                    .downcast_ref::<ActivateContractInstance>()
                {
                    activate_seen = true;
                    contract_targets.insert(activate.contract_address().clone());
                } else if let Some(deactivate) = instruction
                    .as_any()
                    .downcast_ref::<DeactivateContractInstance>()
                {
                    deactivate_seen = true;
                    contract_targets.insert(deactivate.contract_address().clone());
                } else {
                    let modifies_contract_code = {
                        let any = instruction.as_any();
                        any.is::<RegisterSmartContractCode>()
                            || any.is::<RegisterSmartContractBytes>()
                            || any.is::<UploadSmartContractCodeChunk>()
                            || any.is::<FinalizeSmartContractCodeUpload>()
                            || any.is::<RemoveSmartContractBytes>()
                    };
                    if modifies_contract_code {
                        register_code_seen = true;
                    }
                }
            }
        }
        Executable::ContractCall(call) => {
            contract_targets.insert(call.contract_address.clone());
        }
        Executable::Batch(items) => {
            for item in items {
                match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        if let Some(commit) = instruction
                            .as_any()
                            .downcast_ref::<CommitContractDeployment>()
                        {
                            commit_deployment_count += 1;
                            contract_targets.insert(commit.contract_address().clone());
                        } else if let Some(activate) = instruction
                            .as_any()
                            .downcast_ref::<ActivateContractInstance>()
                        {
                            activate_seen = true;
                            contract_targets.insert(activate.contract_address().clone());
                        } else if let Some(deactivate) = instruction
                            .as_any()
                            .downcast_ref::<DeactivateContractInstance>(
                        ) {
                            deactivate_seen = true;
                            contract_targets.insert(deactivate.contract_address().clone());
                        } else {
                            let any = instruction.as_any();
                            if any.is::<RegisterSmartContractCode>()
                                || any.is::<RegisterSmartContractBytes>()
                                || any.is::<UploadSmartContractCodeChunk>()
                                || any.is::<FinalizeSmartContractCodeUpload>()
                                || any.is::<RemoveSmartContractBytes>()
                            {
                                register_code_seen = true;
                            }
                        }
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        contract_targets.insert(call.contract_address.clone());
                    }
                }
            }
        }
        Executable::Ivm(_) | Executable::IvmProved(_) => {}
    }
    if commit_deployment_count > 1
        || (commit_deployment_count == 1 && (activate_seen || deactivate_seen))
        || (activate_seen && deactivate_seen)
    {
        return Err(reject_lane_policy(
            alias,
            "protected contract rotations must use exactly one `CommitContractDeployment` instruction and no legacy activate/deactivate pair",
        ));
    }
    if let Some(contract_address) = metadata_governance_contract_address.clone() {
        contract_targets.insert(contract_address);
    }
    let ivm_with_contract_metadata = matches!(tx.instructions(), Executable::Ivm(_))
        && (metadata_governance_contract_address.is_some()
            || metadata_contract_address_hint.is_some());
    let contract_instr_seen =
        register_code_seen || !contract_targets.is_empty() || ivm_with_contract_metadata;
    let explicit_contract_instruction_seen =
        register_code_seen || commit_deployment_count > 0 || activate_seen || deactivate_seen;
    let has_directly_addressed_call = match tx.instructions() {
        Executable::ContractCall(_) => true,
        Executable::Batch(items) => items
            .iter()
            .any(|item| matches!(item, ExecutableBatchItem::ContractCall(_))),
        Executable::Instructions(_) | Executable::Ivm(_) | Executable::IvmProved(_) => false,
    };
    if contract_instr_seen
        && metadata_governance_contract_address.is_none()
        && (!has_directly_addressed_call || explicit_contract_instruction_seen)
    {
        return Err(reject_lane_policy(
            alias,
            "transactions with contract operations must set `gov_contract_address` metadata when lane governance protects namespaces",
        ));
    }
    if let (Some(hint), Some(meta)) = (
        metadata_contract_address_hint.as_ref(),
        metadata_governance_contract_address.as_ref(),
    ) {
        if hint != meta {
            return Err(reject_lane_policy(
                alias,
                "`contract_address` metadata must match `gov_contract_address` for protected operations",
            ));
        }
    }
    if let Some(meta_contract_address) = metadata_governance_contract_address.as_ref()
        && !contract_targets.is_empty()
        && contract_targets
            .iter()
            .any(|contract_address| contract_address != meta_contract_address)
    {
        return Err(reject_lane_policy(
            alias,
            "`gov_contract_address` metadata does not match contract addresses referenced by contract instructions",
        ));
    }
    let _ = world;
    Ok(())
}
fn enforce_runtime_upgrade_hook(
    alias: &str,
    rules: &GovernanceRules,
    tx: &SignedTransaction,
) -> Result<bool, TransactionRejectionReason> {
    let contains_runtime_upgrade = contains_runtime_upgrade_instruction(tx);
    if !contains_runtime_upgrade {
        return Ok(false);
    }
    let Some(hook) = rules.hooks.runtime_upgrade.as_ref() else {
        return Ok(true);
    };
    if !hook.allow {
        return Err(reject_lane_policy(
            alias,
            "runtime upgrade hook prohibits runtime upgrade instructions".to_string(),
        ));
    }
    if hook.require_metadata || hook.allowed_ids.is_some() {
        let Some(key) = hook.metadata_key.as_ref() else {
            return Err(reject_lane_policy(
                alias,
                "runtime upgrade hook missing metadata_key despite requiring metadata".to_string(),
            ));
        };
        let metadata = tx.metadata();
        let Some(raw_value) = metadata.get(key) else {
            return Err(reject_lane_policy(
                alias,
                format!("runtime upgrade hook requires metadata `{}`", key.as_ref()),
            ));
        };
        let value = raw_value.try_into_any_norito::<String>().map_err(|_| {
            reject_lane_policy(
                alias,
                format!(
                    "runtime upgrade metadata `{}` must be a string",
                    key.as_ref()
                ),
            )
        })?;
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(reject_lane_policy(
                alias,
                format!(
                    "runtime upgrade metadata `{}` must not be blank",
                    key.as_ref()
                ),
            ));
        }
        if let Some(ids) = hook.allowed_ids.as_ref()
            && !ids.contains(trimmed)
        {
            return Err(reject_lane_policy(
                alias,
                format!(
                    "runtime upgrade metadata `{}` value `{trimmed}` not permitted by lane manifest",
                    key.as_ref()
                ),
            ));
        }
    }
    Ok(contains_runtime_upgrade)
}
fn contains_runtime_upgrade_instruction(tx: &SignedTransaction) -> bool {
    tx_contains_runtime_upgrade_instruction(tx)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeUpgradeModuleKind {
    Parliament,
    LocalAdmins,
}
fn resolve_runtime_upgrade_module_kind(
    module_name: Option<&str>,
    catalog: &iroha_config::parameters::actual::GovernanceCatalog,
) -> Option<RuntimeUpgradeModuleKind> {
    let configured = module_name.or(catalog.default_module.as_deref())?;
    let module_type = catalog
        .modules
        .get(configured)
        .and_then(|module| module.module_type.as_deref())
        .unwrap_or(configured);
    let normalized = module_type.trim().to_ascii_lowercase().replace('-', "_");
    if normalized.contains("parliament") {
        Some(RuntimeUpgradeModuleKind::Parliament)
    } else {
        Some(RuntimeUpgradeModuleKind::LocalAdmins)
    }
}
fn enforce_runtime_upgrade_dataspace_policy(
    alias: &str,
    dataspace_id: NexusDataSpaceId,
    module_name: Option<&str>,
    catalog: &iroha_config::parameters::actual::GovernanceCatalog,
) -> Result<(), TransactionRejectionReason> {
    let Some(module_kind) = resolve_runtime_upgrade_module_kind(module_name, catalog) else {
        return Err(reject_lane_policy(
            alias,
            "runtime upgrade policy requires a governance module".to_string(),
        ));
    };
    if dataspace_id == NexusDataSpaceId::UNIVERSAL
        && !matches!(module_kind, RuntimeUpgradeModuleKind::Parliament)
    {
        return Err(reject_lane_policy(
            alias,
            "runtime upgrades in universal dataspace require a parliament governance module"
                .to_string(),
        ));
    }
    Ok(())
}
fn extract_lane_identity_metadata(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    dataspace_id: NexusDataSpaceId,
    lane_alias: &str,
) -> Result<(Option<UniversalAccountId>, Vec<String>), TransactionRejectionReason> {
    extract_directory_lane_identity_metadata(world, authority, dataspace_id).map_err(
        |err| match err {
            LaneIdentityMetadataError::MissingDataspaceBinding { uaid, dataspace } => {
                reject_lane_policy(
                    lane_alias,
                    format!(
                        "UAID {uaid} is not bound to dataspace {}",
                        dataspace.as_u64()
                    ),
                )
            }
            LaneIdentityMetadataError::InactiveManifest { uaid, dataspace } => reject_lane_policy(
                lane_alias,
                format!(
                    "UAID {uaid} manifest for dataspace {} is not active",
                    dataspace.as_u64()
                ),
            ),
        },
    )
}
fn extract_lane_authority_domains(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    lane_alias: &str,
    now_ms: u64,
) -> Result<Vec<iroha_model_base::domain::DomainId>, TransactionRejectionReason> {
    extract_directory_authority_domains(world, authority, now_ms).map_err(|err| {
        reject_lane_policy(
            lane_alias,
            format!("authority alias domain resolution failed: {err}"),
        )
    })
}
fn publishes_only_space_directory_manifests(tx: &SignedTransaction) -> bool {
    let is_publish = |instruction: &InstructionBox| {
        instruction
            .as_any()
            .downcast_ref::<iroha_data_model::isi::space_directory::PublishSpaceDirectoryManifest>()
            .is_some()
    };
    match tx.instructions() {
        Executable::Instructions(instructions) if !instructions.is_empty() => {
            instructions.iter().all(is_publish)
        }
        Executable::Batch(items) if !items.is_empty() => items.iter().all(|item| match item {
            ExecutableBatchItem::Instruction(instruction) => is_publish(instruction),
            ExecutableBatchItem::ContractCall(_) => false,
        }),
        _ => false,
    }
}
fn enforce_lane_policies(
    tx: &SignedTransaction,
    state_transaction: &StateTransaction<'_, '_>,
    lane_assignment: &LaneAssignment<'_>,
) -> Result<(), TransactionRejectionReason> {
    let lane_id = lane_assignment.lane_id;
    let dataspace_id = lane_assignment.dataspace_id;
    let manifest_registry: &LaneManifestRegistryHandle = &state_transaction.lane_manifests;
    if let Err(err) = manifest_registry.ensure_lane_ready(lane_id) {
        return Err(reject_not_permitted(err.message()));
    }
    let manifest_status = manifest_registry.status(lane_id).cloned();
    let lane_alias = manifest_status.as_ref().map_or_else(
        || format!("lane-{}", lane_id.as_u32()),
        |status| status.alias.clone(),
    );
    let allows_multisig_envelope_authority = match tx.instructions() {
        Executable::Instructions(instructions) => {
            instructions_allow_multisig_envelope_authority(instructions)
        }
        Executable::ContractCall(_)
        | Executable::Batch(_)
        | Executable::IvmProved(_)
        | Executable::Ivm(_) => false,
    };
    let eligible_lanes = crate::state::nexus_manifest_authority_eligible_lanes_at_height(
        lane_id,
        dataspace_id,
        &state_transaction.nexus,
        state_transaction.block_height(),
    );
    if !eligible_lanes.contains(&lane_id) {
        return Err(reject_lane_policy(
            &lane_alias,
            "lane is not active in the routed dataspace at the current block height".to_string(),
        ));
    }
    // Validators, account-to-peer bindings, and quorum are dataspace authority. Hooks and
    // protected namespaces remain sourced from the exact target-lane rules below.
    let dataspace_authority_rules = manifest_registry
        .dataspace_authority_rules_for_lanes(lane_id, dataspace_id, &eligible_lanes)
        .map_err(|err| reject_not_permitted(err.message()))?;
    let mut runtime_upgrade_present = false;
    if let Some(status) = manifest_status.as_ref() {
        if let Some(rules) = status.rules() {
            let governance_manifest = status.governance.is_some();
            let governance_sensitive =
                governance_manifest && tx_requires_manifest_validator_gating(rules, tx);
            if governance_sensitive {
                let manifest_validators = dataspace_authority_rules
                    .map(|rules| canonical_manifest_validators(&lane_alias, rules))
                    .transpose()?;
                if let Some(validators) = manifest_validators.as_ref()
                    && !allows_multisig_envelope_authority
                {
                    let authority = tx.authority();
                    let authority_i105 = authority.canonical_i105().map_err(|err| {
                        reject_lane_policy(
                            &lane_alias,
                            format!("failed to encode authority `{authority}` as i105: {err}"),
                        )
                    })?;
                    if !validators.contains(&authority_i105) {
                        return Err(reject_lane_policy(
                            &lane_alias,
                            "authority not part of lane validator set".to_string(),
                        ));
                    }
                }
                if !allows_multisig_envelope_authority
                    && let Some(authority_rules) = dataspace_authority_rules
                    && authority_rules.quorum.unwrap_or(0).saturating_sub(1) > 0
                {
                    enforce_manifest_quorum(&lane_alias, authority_rules, tx)?;
                }
            }
            if governance_manifest {
                enforce_manifest_protected_namespaces(
                    &lane_alias,
                    rules,
                    tx,
                    &state_transaction.world,
                )?;
                runtime_upgrade_present = enforce_runtime_upgrade_hook(&lane_alias, rules, tx)?;
            }
        }
    }
    if !runtime_upgrade_present {
        runtime_upgrade_present = contains_runtime_upgrade_instruction(tx);
    }
    if runtime_upgrade_present {
        let module_name = manifest_status
            .as_ref()
            .and_then(|status| status.governance.as_deref());
        enforce_runtime_upgrade_dataspace_policy(
            &lane_alias,
            dataspace_id,
            module_name,
            &state_transaction.nexus.governance,
        )?;
    }
    // The manifest snapshot is the consensus input. Rebuild the privacy
    // projection here so an old or locally corrupted cache cannot choose a
    // different proof-verification or compliance result on another peer.
    let lane_privacy_registry = LanePrivacyRegistry::from_manifest_registry(manifest_registry);
    let privacy_proofs = collect_lane_privacy_proofs(tx);
    let verified_privacy_commitments = if privacy_proofs.is_empty() {
        BTreeSet::new()
    } else {
        verify_lane_privacy_proofs(&lane_privacy_registry, lane_id, &privacy_proofs).map_err(
            |err| reject_lane_policy(&lane_alias, format!("lane privacy proof rejected: {err}")),
        )?
    };
    let lane_privacy_registry = if lane_privacy_registry.is_empty() {
        None
    } else {
        Some(Arc::new(lane_privacy_registry))
    };
    let publishes_space_directory_manifest = publishes_only_space_directory_manifests(tx);
    let lane_identity = if publishes_space_directory_manifest {
        (None, Vec::new())
    } else {
        extract_lane_identity_metadata(
            &state_transaction.world,
            tx.authority(),
            dataspace_id,
            &lane_alias,
        )?
    };
    if !publishes_space_directory_manifest
        && let Some(engine) = state_transaction.lane_compliance.as_ref()
    {
        let (uaid_value, capability_tags) = lane_identity;
        let authority_domains = extract_lane_authority_domains(
            &state_transaction.world,
            tx.authority(),
            &lane_alias,
            state_transaction.block_unix_timestamp_ms(),
        )?;
        let ctx = LaneComplianceContext {
            lane_id,
            dataspace_id,
            authority: tx.authority(),
            authority_domains: authority_domains.as_slice(),
            uaid: uaid_value.as_ref(),
            capability_tags: capability_tags.as_slice(),
            lane_privacy_registry,
            verified_privacy_commitments: &verified_privacy_commitments,
        };
        let evaluation = engine.evaluate(&ctx);
        match evaluation {
            LaneComplianceEvaluation::NotConfigured => {
                if !engine.audit_only() {
                    return Err(reject_lane_policy(
                        &lane_alias,
                        "no exact lane compliance policy is configured".to_string(),
                    ));
                }
            }
            LaneComplianceEvaluation::Allowed(record) => {
                record.log(engine.audit_only());
            }
            LaneComplianceEvaluation::Denied(record) => {
                record.log(engine.audit_only());
                if !engine.audit_only() {
                    let reason = record
                        .reason
                        .clone()
                        .unwrap_or_else(|| "lane compliance policy denied".to_string());
                    return Err(reject_lane_policy(&lane_alias, reason));
                }
            }
        }
    }
    Ok(())
}
#[cfg(feature = "telemetry")]
fn tenant_label_from(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        "unknown"
    } else {
        trimmed
    }
}
#[cfg(feature = "telemetry")]
struct FraudTelemetryContext<'a> {
    telemetry: &'a StateTelemetry,
    lane_id: NexusLaneId,
    dataspace_label: String,
    tenant: String,
    score_bps: Option<u16>,
    latency_ms: Option<u64>,
    disposition: Option<FraudDisposition>,
}
#[cfg(feature = "telemetry")]
impl<'a> FraudTelemetryContext<'a> {
    fn prepare(
        telemetry: Option<&'a StateTelemetry>,
        routing: &LaneAssignment<'_>,
        metadata: &TelemetryMetadata,
    ) -> Option<Self> {
        let telemetry = telemetry?;
        if !telemetry.is_enabled() {
            return None;
        }
        Some(Self::new(telemetry, routing, metadata))
    }
    #[allow(clippy::too_many_lines)]
    fn new(
        telemetry: &'a StateTelemetry,
        routing: &LaneAssignment<'_>,
        metadata: &TelemetryMetadata,
    ) -> Self {
        let dataspace_label = routing.dataspace_label();
        let lane_id = routing.lane_id;
        let tenant = metadata
            .get(FRAUD_ASSESSMENT_TENANT_KEY.as_ref())
            .map_or_else(
                || "unknown".to_string(),
                |value| {
                    value.try_into_any_norito::<String>().map_or_else(
                        |_| {
                            telemetry.record_fraud_invalid_metadata(
                                lane_id,
                                dataspace_label.as_str(),
                                "unknown",
                                "tenant",
                            );
                            "unknown".to_string()
                        },
                        |raw| {
                            let trimmed = raw.trim();
                            if trimmed.is_empty() {
                                telemetry.record_fraud_invalid_metadata(
                                    lane_id,
                                    dataspace_label.as_str(),
                                    "unknown",
                                    "tenant",
                                );
                                "unknown".to_string()
                            } else if trimmed.len() != raw.len() {
                                trimmed.to_owned()
                            } else {
                                raw
                            }
                        },
                    )
                },
            );
        let tenant_label = tenant_label_from(&tenant);
        let latency_ms: Option<u64> = metadata
            .get(FRAUD_ASSESSMENT_LATENCY_KEY.as_ref())
            .and_then(|value| {
                value.try_into_any_norito::<u64>().map_or_else(
                    |_| {
                        telemetry.record_fraud_invalid_metadata(
                            lane_id,
                            dataspace_label.as_str(),
                            tenant_label,
                            "latency_ms",
                        );
                        None
                    },
                    Some,
                )
            });
        let score_bps: Option<u16> =
            metadata
                .get(FRAUD_ASSESSMENT_SCORE_KEY.as_ref())
                .and_then(|value| {
                    value.try_into_any_norito::<u64>().map_or_else(
                        |_| {
                            telemetry.record_fraud_invalid_metadata(
                                lane_id,
                                dataspace_label.as_str(),
                                tenant_label,
                                "score_bps",
                            );
                            None
                        },
                        |raw| {
                            u16::try_from(raw).map_or_else(
                                |_| {
                                    telemetry.record_fraud_invalid_metadata(
                                        lane_id,
                                        dataspace_label.as_str(),
                                        tenant_label,
                                        "score_bps",
                                    );
                                    None
                                },
                                Some,
                            )
                        },
                    )
                });
        let disposition = metadata
            .get(FRAUD_ASSESSMENT_DISPOSITION_KEY.as_ref())
            .and_then(|value| {
                value.try_into_any_norito::<String>().map_or_else(
                    |_| {
                        telemetry.record_fraud_invalid_metadata(
                            lane_id,
                            dataspace_label.as_str(),
                            tenant_label,
                            "disposition",
                        );
                        None
                    },
                    |raw| {
                        FraudDisposition::from_metadata(&raw).unwrap_or_else(|()| {
                            telemetry.record_fraud_invalid_metadata(
                                lane_id,
                                dataspace_label.as_str(),
                                tenant_label,
                                "disposition",
                            );
                            None
                        })
                    },
                )
            });
        Self {
            telemetry,
            lane_id,
            dataspace_label,
            tenant,
            score_bps,
            latency_ms,
            disposition,
        }
    }
    fn tenant_label(&self) -> &str {
        tenant_label_from(&self.tenant)
    }
    fn dataspace_label(&self) -> &str {
        self.dataspace_label.as_str()
    }
    fn record_missing(&self, cause: &'static str) {
        self.telemetry.record_fraud_missing_assessment(
            self.lane_id,
            self.dataspace_label(),
            self.tenant_label(),
            cause,
        );
    }
    fn record_invalid(&self, field: &'static str) {
        self.telemetry.record_fraud_invalid_metadata(
            self.lane_id,
            self.dataspace_label(),
            self.tenant_label(),
            field,
        );
    }
    fn record_assessment(&self, band: iroha_data_model::fraud::FraudRiskBandV1) {
        self.telemetry.record_fraud_assessment(
            self.lane_id,
            self.dataspace_label(),
            self.tenant_label(),
            band.as_str(),
            self.score_bps,
            self.latency_ms,
        );
        if let Some(direction) = self.outcome_mismatch_direction(band) {
            self.telemetry.record_fraud_outcome_mismatch(
                self.lane_id,
                self.dataspace_label(),
                self.tenant_label(),
                direction,
            );
        }
    }
    fn record_attestation(&self, engine_id: &str, status: &'static str) {
        self.telemetry.record_fraud_attestation(
            self.lane_id,
            self.dataspace_label(),
            self.tenant_label(),
            engine_id,
            status,
        );
    }
    fn outcome_mismatch_direction(
        &self,
        band: iroha_data_model::fraud::FraudRiskBandV1,
    ) -> Option<&'static str> {
        let band_level = match band {
            iroha_data_model::fraud::FraudRiskBandV1::Low => 0,
            iroha_data_model::fraud::FraudRiskBandV1::Medium => 1,
            iroha_data_model::fraud::FraudRiskBandV1::High => 2,
            iroha_data_model::fraud::FraudRiskBandV1::Critical => 3,
        };
        match self.disposition {
            Some(FraudDisposition::Fraud) if band_level < 2 => Some("missed_fraud"),
            Some(FraudDisposition::Clean) if band_level >= 2 => Some("false_positive"),
            _ => None,
        }
    }
}
#[cfg(feature = "telemetry")]
impl FraudDisposition {
    fn from_metadata(raw: &str) -> Result<Option<Self>, ()> {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(());
        }
        match normalized.as_str() {
            "confirmed_fraud" | "chargeback" | "fraud" | "loss" | "write_off" => {
                Ok(Some(Self::Fraud))
            }
            "approved" | "cleared" | "authorized" | "settled" | "false_positive" | "refunded" => {
                Ok(Some(Self::Clean))
            }
            "declined" | "manual_review" | "review" | "pending" | "blocked" => Ok(None),
            _ => Err(()),
        }
    }
}
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
#[allow(clippy::too_many_lines)]
/// Enforce the configured fraud monitoring policy against the transaction metadata.
pub(crate) fn enforce_fraud_policy(
    config: &iroha_config::parameters::actual::FraudMonitoring,
    metadata: &iroha_model_base::metadata::Metadata,
    telemetry: Option<&StateTelemetry>,
    routing: &LaneAssignment<'_>,
) -> Result<(), TransactionRejectionReason> {
    let config = &config.policy;
    if !config.enabled {
        return Ok(());
    }
    let lane_id = routing.lane_id;
    let dataspace_id = routing.dataspace_id;
    let dataspace_label = routing.dataspace_label();
    #[cfg(feature = "telemetry")]
    let fraud_ctx = FraudTelemetryContext::prepare(telemetry, routing, metadata);
    let Some(required) = config.required_minimum_band else {
        if config.enabled {
            warn!(
                "Fraud monitoring enabled but required_minimum_band not set; skipping enforcement"
            );
        }
        return Ok(());
    };
    let Some(value) = metadata.get(FRAUD_ASSESSMENT_BAND_NAME.as_ref()) else {
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            let cause = if !config.missing_assessment_permitted {
                "missing"
            } else {
                "permitted"
            };
            ctx.record_missing(cause);
        }
        if !config.missing_assessment_permitted {
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(
                    "fraud monitoring requires an attached assessment".into(),
                ),
            ));
        }
        warn!(
            missing_assessment_permitted = config.missing_assessment_permitted,
            lane = ?lane_id,
            dataspace = ?dataspace_id,
            dataspace_label = %dataspace_label,
            "Transaction missing fraud assessment; permitted by committed policy"
        );
        return Ok(());
    };
    let band_str = if let Ok(s) = value.try_into_any_norito::<String>() {
        s
    } else {
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            ctx.record_invalid("band_type");
        }
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted("fraud assessment band must be a string".into()),
        ));
    };
    let band = if let Ok(band) = band_str.parse::<iroha_data_model::fraud::FraudRiskBandV1>() {
        band
    } else {
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            ctx.record_invalid("band_value");
        }
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(format!("fraud assessment band '{band_str}' is invalid")),
        ));
    };
    let tenant_value = if let Some(value) = metadata.get(FRAUD_ASSESSMENT_TENANT_NAME.as_ref()) {
        value
    } else {
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            ctx.record_invalid("tenant");
        }
        warn!(
            lane = ?lane_id,
            dataspace = ?dataspace_id,
            dataspace_label = %dataspace_label,
            "fraud assessment missing tenant metadata"
        );
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(
                "fraud monitoring requires metadata field 'fraud_assessment_tenant'".into(),
            ),
        ));
    };
    let tenant_raw = tenant_value.try_into_any_norito::<String>().map_err(|_| {
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            ctx.record_invalid("tenant");
        }
        TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
            "fraud assessment tenant must be a string".into(),
        ))
    })?;
    if tenant_raw.trim().is_empty() {
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            ctx.record_invalid("tenant");
        }
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted("fraud assessment tenant must not be empty".into()),
        ));
    }
    let tenant = tenant_raw;
    if let Some(latency_value) = metadata.get(FRAUD_ASSESSMENT_LATENCY_NAME.as_ref())
        && latency_value
            .try_into_any_norito::<u64>()
            .map(|_| ())
            .is_err()
    {
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            ctx.record_invalid("latency_ms");
        }
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(
                "fraud assessment latency must be an unsigned integer".into(),
            ),
        ));
    }
    let score_value = if let Some(value) = metadata.get(FRAUD_ASSESSMENT_SCORE_NAME.as_ref()) {
        value
    } else {
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            ctx.record_invalid("score_bps");
        }
        warn!(
            lane = ?lane_id,
            dataspace = ?dataspace_id,
            dataspace_label = %dataspace_label,
            "fraud assessment missing score_bps metadata"
        );
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(
                "fraud monitoring requires metadata field 'fraud_assessment_score_bps'".into(),
            ),
        ));
    };
    let score_raw = score_value.try_into_any_norito::<u64>().map_err(|_| {
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            ctx.record_invalid("score_bps");
        }
        TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
            "fraud assessment score must be an integer basis-point value".into(),
        ))
    })?;
    let score_bps = u16::try_from(score_raw).map_err(|_| {
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            ctx.record_invalid("score_bps");
        }
        TransactionRejectionReason::Validation(ValidationFail::NotPermitted(format!(
            "fraud assessment score {score_raw} exceeds supported range (0-10000 basis points)"
        )))
    })?;
    if score_bps > 10_000 {
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            ctx.record_invalid("score_bps");
        }
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(format!(
                "fraud assessment score {score_bps} exceeds supported range (0-10000 basis points)"
            )),
        ));
    }
    let expected_band = expected_band_from_score(score_bps);
    if expected_band != band {
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            ctx.record_invalid("band");
        }
        warn!(
            lane = ?lane_id,
            dataspace = ?dataspace_id,
            dataspace_label = %dataspace_label,
            actual = %band,
            expected = %expected_band,
            score_bps,
            "fraud assessment band does not match reported score"
        );
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(format!(
                "fraud assessment band {band} inconsistent with score {score_bps} bps (expected {expected_band})"
            )),
        ));
    }
    #[cfg(feature = "telemetry")]
    if let Some(ctx) = fraud_ctx.as_ref() {
        ctx.record_assessment(band);
    }
    if band < required {
        return Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(format!(
                "fraud assessment band {band} below required minimum {required}"
            )),
        ));
    }
    if !config.attesters.is_empty() {
        let tenant_label = {
            let trimmed = tenant.trim();
            if trimmed.is_empty() {
                "unknown"
            } else {
                trimmed
            }
        };
        let Some(envelope_value) = metadata.get(FRAUD_ASSESSMENT_ENVELOPE_NAME.as_ref()) else {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_invalid("attestation_envelope");
                ctx.record_attestation("unknown", "missing_envelope");
            }
            warn!(
                lane = ?lane_id,
                dataspace = ?dataspace_id,
                dataspace_label = %dataspace_label,
                tenant = %tenant_label,
                "fraud assessment missing attestation envelope metadata"
            );
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(
                    "fraud monitoring requires metadata field 'fraud_assessment_envelope'".into(),
                ),
            ));
        };
        let envelope_raw = envelope_value
            .try_into_any_norito::<String>()
            .map_err(|_| {
                #[cfg(feature = "telemetry")]
                if let Some(ctx) = fraud_ctx.as_ref() {
                    ctx.record_invalid("attestation_envelope");
                    ctx.record_attestation("unknown", "envelope_type");
                }
                TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                    "fraud assessment envelope must be a base64 string".into(),
                ))
            })?;
        let envelope_trimmed = envelope_raw.trim();
        if envelope_trimmed.is_empty() {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_invalid("attestation_envelope");
                ctx.record_attestation("unknown", "missing_envelope");
            }
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted("fraud assessment envelope must not be blank".into()),
            ));
        }
        let envelope_bytes = BASE64_STANDARD
            .decode(envelope_trimmed.as_bytes())
            .map_err(|err| {
                #[cfg(feature = "telemetry")]
                if let Some(ctx) = fraud_ctx.as_ref() {
                    ctx.record_invalid("attestation_envelope");
                    ctx.record_attestation("unknown", "envelope_decode");
                }
                warn!(
                    lane = ?lane_id,
                    dataspace = ?dataspace_id,
                    dataspace_label = %dataspace_label,
                    tenant = %tenant_label,
                    error = %err,
                    "fraud assessment envelope failed base64 decoding"
                );
                TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                    "fraud assessment envelope must be base64-encoded".into(),
                ))
            })?;
        let mut cursor = envelope_bytes.as_slice();
        let assessment: FraudAssessment =
            norito::codec::Decode::decode(&mut cursor).map_err(|err| {
                #[cfg(feature = "telemetry")]
                if let Some(ctx) = fraud_ctx.as_ref() {
                    ctx.record_invalid("attestation_envelope");
                    ctx.record_attestation("unknown", "envelope_decode");
                }
                warn!(
                    lane = ?lane_id,
                    dataspace = ?dataspace_id,
                    dataspace_label = %dataspace_label,
                    tenant = %tenant_label,
                    error = %err,
                    "fraud assessment envelope failed Norito decode"
                );
                TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                    "fraud assessment envelope could not be decoded".into(),
                ))
            })?;
        if !cursor.is_empty() {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_invalid("attestation_envelope");
                ctx.record_attestation("unknown", "envelope_decode");
            }
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(
                    "fraud assessment envelope contains trailing bytes".into(),
                ),
            ));
        }
        let signature_bytes = assessment.signature.as_ref().ok_or_else(|| {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_invalid("attestation_signature");
                ctx.record_attestation("unknown", "unsigned");
            }
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                "fraud assessment envelope missing signature".into(),
            ))
        })?;
        let engine_id = assessment.engine_id.trim();
        let attester = config.attester(engine_id).ok_or_else(|| {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_attestation(engine_id, "unknown_engine");
            }
            warn!(
                lane = ?lane_id,
                dataspace = ?dataspace_id,
                dataspace_label = %dataspace_label,
                tenant = %tenant_label,
                engine = %assessment.engine_id,
                "fraud assessment engine id not registered for attestation"
            );
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(format!(
                "fraud assessment engine id '{}' is not registered with this host",
                assessment.engine_id
            )))
        })?;
        let attester_label = attester.engine_label();
        let mut unsigned = assessment.clone();
        unsigned.signature = None;
        let attester_algorithm = attester.public_key.try_algorithm().map_err(|_| {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_invalid("attestation_signature");
                ctx.record_attestation(attester_label, "public_key");
            }
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                "fraud assessment attester public key is malformed".into(),
            ))
        })?;
        if attester_algorithm == iroha_crypto::Algorithm::Ed25519
            && signature_bytes.len() != ED25519_SIGNATURE_LENGTH
        {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_invalid("attestation_signature");
                ctx.record_attestation(attester_label, "signature_parse");
            }
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted("fraud assessment signature must be 64 bytes".into()),
            ));
        }
        let signature_parse_rejection = |err: String| {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_invalid("attestation_signature");
                ctx.record_attestation(attester_label, "signature_parse");
            }
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(format!(
                "fraud assessment signature is malformed: {err}"
            )))
        };
        let signature = match attester_algorithm {
            iroha_crypto::Algorithm::Ed25519 => {
                iroha_crypto::ed25519_parse_signature(signature_bytes)
                    .map_err(|err| signature_parse_rejection(err.to_string()))?
            }
            iroha_crypto::Algorithm::MlDsa => {
                iroha_crypto::mldsa65_parse_signature(signature_bytes)
                    .map_err(|err| signature_parse_rejection(err.to_string()))?
            }
            _ => iroha_crypto::Signature::try_from_bytes(signature_bytes).map_err(|err| {
                #[cfg(feature = "telemetry")]
                if let Some(ctx) = fraud_ctx.as_ref() {
                    ctx.record_invalid("attestation_signature");
                    ctx.record_attestation(attester_label, "signature_parse");
                }
                TransactionRejectionReason::Validation(ValidationFail::NotPermitted(format!(
                    "fraud assessment signature is malformed: {err}"
                )))
            })?,
        };
        let typed = iroha_crypto::SignatureOf::<FraudAssessment>::from_signature(signature);
        typed.verify(&attester.public_key, &unsigned).map_err(|_| {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_attestation(attester_label, "signature_verify");
            }
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                "fraud assessment signature failed verification".into(),
            ))
        })?;
        if assessment.risk_score_bps != score_bps {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_attestation(attester_label, "score_mismatch");
            }
            warn!(
                lane = ?lane_id,
                dataspace = ?dataspace_id,
                dataspace_label = %dataspace_label,
                tenant = %tenant_label,
                engine = %assessment.engine_id,
                observed = assessment.risk_score_bps,
                metadata = score_bps,
                "fraud assessment risk_score_bps mismatch with metadata"
            );
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(
                    "fraud assessment score does not match attested envelope".into(),
                ),
            ));
        }
        let unsigned_bytes = norito::codec::Encode::encode(&unsigned);
        let digest_bytes: [u8; 32] = iroha_crypto::Hash::new(&unsigned_bytes).into();
        let expected_digest = hex::encode_upper(digest_bytes);
        let Some(digest_value) = metadata.get(FRAUD_ASSESSMENT_DIGEST_NAME.as_ref()) else {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_invalid("attestation_digest");
                ctx.record_attestation(attester_label, "digest_missing");
            }
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(
                    "fraud monitoring requires metadata field 'fraud_assessment_digest'".into(),
                ),
            ));
        };
        let digest_str = digest_value.try_into_any_norito::<String>().map_err(|_| {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_invalid("attestation_digest");
                ctx.record_attestation(attester_label, "digest_type");
            }
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                "fraud assessment digest must be a hex string".into(),
            ))
        })?;
        let digest_trimmed = digest_str.trim();
        if digest_trimmed.len() != expected_digest.len()
            || !digest_trimmed.eq_ignore_ascii_case(&expected_digest)
        {
            #[cfg(feature = "telemetry")]
            if let Some(ctx) = fraud_ctx.as_ref() {
                ctx.record_attestation(attester_label, "digest_mismatch");
            }
            warn!(
                lane = ?lane_id,
                dataspace = ?dataspace_id,
                dataspace_label = %dataspace_label,
                tenant = %tenant_label,
                engine = %assessment.engine_id,
                expected = %expected_digest,
                provided = %digest_trimmed,
                "fraud assessment digest mismatch"
            );
            return Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(
                    "fraud assessment digest does not match attested payload".into(),
                ),
            ));
        }
        #[cfg(feature = "telemetry")]
        if let Some(ctx) = fraud_ctx.as_ref() {
            ctx.record_attestation(attester_label, "verified");
        }
    }
    Ok(())
}
fn expected_band_from_score(score_bps: u16) -> iroha_data_model::fraud::FraudRiskBandV1 {
    use iroha_data_model::fraud::FraudRiskBandV1;
    if score_bps > 1_000 {
        match score_bps {
            ..=2_499 => FraudRiskBandV1::Low,
            2_500..=5_499 => FraudRiskBandV1::Medium,
            5_500..=7_499 => FraudRiskBandV1::High,
            _ => FraudRiskBandV1::Critical,
        }
    } else {
        match score_bps {
            ..=249 => FraudRiskBandV1::Low,
            250..=549 => FraudRiskBandV1::Medium,
            550..=749 => FraudRiskBandV1::High,
            _ => FraudRiskBandV1::Critical,
        }
    }
}
// Transaction-local fixture: exercises the production admission/executor in a bounded
// component overlay. It owns rollback and never creates a Network output or proof.
/// Execute one transaction in an isolated bounded component overlay, with rollback.
///
/// This uses current stateful admission and execution. It does not construct a Network
/// output, account rejected output work, or authenticate a block or finality proof.
///
/// # Errors
/// Returns the transaction's deterministic rejection and discards its changes.
///
/// # Panics
/// Panics if the fixture has no single route, cannot fund its component owner, or defers locally.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub fn execute_component_transaction_for_testing(
    block: &mut StateBlock<'_>,
    accepted: AcceptedTransaction<'_>,
    cache: &mut IvmCache,
    context: Option<(u64, crate::queue::RoutingDecision)>,
) -> Result<DataTriggerSequence, TransactionRejectionReason> {
    use crate::state::StateReadOnly as _;
    let (index, route) = context.unwrap_or_else(|| {
        let plan = evaluate_policy_plan_with_nexus_and_world_at_block_height(
            block.nexus(),
            &accepted,
            block.world(),
            0,
            block._curr_block.height().get(),
        )
        .expect("component route resolves");
        let crate::queue::RoutingPlan::Single(leg) = plan else {
            panic!("component fixture requires a single route")
        };
        (0, leg.route)
    });
    let call_hash = Hash::from(accepted.entrypoint().execution_call_hash());
    let mut overlay = block.transaction_for_fastpq_testing(call_hash);
    overlay.current_entrypoint_index = Some(index);
    overlay.current_network_entrypoint_hash = Some(accepted.hash_as_entrypoint());
    overlay.current_tx_hash = accepted.external().map(|signed| signed.hash());
    overlay.current_lane_id = Some(route.lane_id);
    overlay.current_dataspace_id = Some(route.dataspace_id);
    overlay.world.current_dataspace_id = Some(route.dataspace_id);
    let policy_route = CapturedNetworkPolicyRoute::for_component(&accepted, &overlay, route)
        .expect("completed original physical policy capture");
    match StateBlock::execute_accepted_transaction_in_overlay(
        accepted,
        &mut overlay,
        cache,
        route,
        policy_route,
        None,
    ) {
        Ok(sequence) => {
            overlay.apply();
            Ok(sequence)
        }
        Err(ExecutionAttemptError::Rejected(reason)) => Err(reason),
        Err(ExecutionAttemptError::Deferred(reason)) => {
            panic!("component locally deferred: {reason:?}")
        }
    }
}

#[cfg(test)]
/// Tests for transaction acceptance and validation.
pub mod tests {
    use super::*;
    use crate::{
        block::{BlockBuilder, CommittedBlock, ValidBlock},
        compliance::LaneComplianceEngine,
        governance::manifest::{
            GovernanceRules, LaneManifestRegistry, LaneManifestStatus, RuntimeUpgradeHook,
        },
        kura::Kura,
        nexus::space_directory::{
            SpaceDirectoryManifestRecord, SpaceDirectoryManifestSet, UaidDataspaceBindings,
        },
        query::store::LiveQueryStore,
        smartcontracts::{Execute, ivm::cache::IvmCache},
        state::{State, StateBlock, StateReadOnly, World},
    };
    use core::panic;
    use iroha_crypto::{
        Algorithm, Hash, KeyPair, MerkleProof,
        privacy::{LaneCommitmentId, LanePrivacyCommitment, MerkleCommitment},
    };
    use iroha_data_model::{
        account::{Account, AccountId, MultisigMember, MultisigPolicy},
        block::{BlockHeader, SignedBlock},
        domain::Domain,
        events::{
            EventBox,
            data::{
                self,
                prelude::{AssetChanged, AssetEvent, AssetTransferred, DomainEvent},
            },
            trigger_completed::{TriggerCompletedEvent, TriggerCompletedOutcome},
        },
        isi::{InstructionBox, Log, governance::ProposeRuntimeUpgradeProposal},
        nexus::{
            AUTOSCALE_META_CREATED_HEIGHT, AUTOSCALE_META_MANAGED, AssetPermissionManifest,
            AuditControls, DataSpaceCatalog, JurisdictionSet, LaneCompliancePolicy,
            LaneCompliancePolicyId, LaneComplianceRule, LaneConfig, LanePrivacyMerkleWitness,
            LanePrivacyProof, LanePrivacyWitness, LaneStorageProfile, LaneVisibility,
            ManifestVersion, ParticipantSelector,
        },
        permission::Permissions,
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
        role::{Role, RoleId},
        runtime::RuntimeUpgradeManifest,
        smart_contract::ContractArtifactId,
        transaction::{TransactionBuilder, executable::ContractInvocation},
    };
    use iroha_executor_data_model::isi::multisig::{
        DEFAULT_MULTISIG_TTL_MS, MultisigApprove, MultisigRegister, MultisigSpec,
    };
    use iroha_genesis::GENESIS_DOMAIN_ID;
    use iroha_logger::Level;
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;

    use iroha_model_base::topology::DataSpaceId;
    use iroha_model_base::{
        topology::DataSpaceId as TestDataSpaceId, topology::LaneId as TestLaneId,
    };
    use iroha_primitives::{
        const_vec::ConstVec,
        json::Json,
        numeric::{Numeric, Quantity},
        time::TimeSource,
    };
    use iroha_schema::Ident;
    use iroha_test_samples::gen_account_in;
    use nonzero_ext::nonzero;
    use std::sync::LazyLock; // for Name::from_str in tests
    use std::{
        borrow::Cow,
        collections::{BTreeMap, BTreeSet},
        num::{NonZeroU16, NonZeroU32, NonZeroU64},
        path::PathBuf,
        str::FromStr,
        sync::Arc,
    };

    fn checked_signature_of<T: norito::codec::Encode>(
        private_key: &PrivateKey,
        payload: &T,
    ) -> SignatureOf<T> {
        SignatureOf::try_new(private_key, payload).expect("test fixture signing should succeed")
    }
    fn checked_fixture_keypair(seed: Vec<u8>, algorithm: Algorithm) -> KeyPair {
        KeyPair::try_from_seed(seed, algorithm).expect("test fixture key derivation should succeed")
    }
    fn checked_random_tx_keypair() -> KeyPair {
        KeyPair::try_random().expect("transaction fixture key generation should succeed")
    }
    fn checked_random_tx_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm)
            .expect("transaction fixture key generation should succeed")
    }
    fn test_network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0x15; Hash::LENGTH]),
        ))
    }
    #[test]
    fn tx_fixture_key_generation_preserves_algorithms() {
        assert_eq!(
            checked_random_tx_keypair().public_key().algorithm(),
            Algorithm::default()
        );
        for algorithm in [Algorithm::Ed25519, Algorithm::Secp256k1] {
            assert_eq!(
                checked_random_tx_keypair_with_algorithm(algorithm)
                    .public_key()
                    .algorithm(),
                algorithm
            );
        }
    }
    fn single_lane_assignment(catalog: &DataSpaceCatalog) -> super::LaneAssignment<'_> {
        super::LaneAssignment {
            lane_id: TestLaneId::SINGLE,
            dataspace_id: TestDataSpaceId::UNIVERSAL,
            dataspace_catalog: catalog,
        }
    }
    fn new_account_in_domain(
        account_id: &AccountId,
        _domain_id: &DomainId,
    ) -> iroha_data_model::account::NewAccount {
        Account::new(account_id.clone())
    }
    fn world_with_authority(domain: &str) -> (World, AccountId, KeyPair) {
        let (authority_id, key_pair) = gen_account_in(domain);
        let domain_id = DomainId::try_new(domain, "universal").expect("domain id");
        let domain = Domain::new(domain_id.clone()).build(&authority_id);
        let account = new_account_in_domain(&authority_id, &domain_id).build(&authority_id);
        (World::with([domain], [account], []), authority_id, key_pair)
    }
    fn original_component_successor_header(state: &State) -> BlockHeader {
        let view = state.view();
        let parent = view
            .latest_block()
            .expect("completed original State read")
            .expect("original applied signed genesis or successor");
        BlockHeader::new(
            NonZeroU64::new(u64::try_from(view.height()).expect("height fits") + 1)
                .expect("actual successor height"),
            Some(parent.hash()),
            None,
            u64::try_from(parent.header().creation_time().as_millis()).expect("time fits") + 1,
            0,
        )
    }
    #[test]
    fn transaction_component_fixture_retains_signed_genesis_and_exact_successor() {
        let (world, _, _) = world_with_authority("wonderland");
        let state = State::new(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        assert!(
            crate::sumeragi::lanes::routing::committed_root_scope(state.view().world()).is_none()
        );
        let chain = crate::block::tests::component_chain(state);
        let header = original_component_successor_header(chain.state());
        assert_eq!(chain.state().committed_height(), 1);
        assert_eq!(header.height().get(), 2);
        assert_eq!(header.prev_block_hash(), Some(chain.genesis().hash()));
        assert_eq!(
            header.creation_time(),
            chain.genesis().header().creation_time() + Duration::from_millis(1)
        );
        assert!(
            crate::sumeragi::lanes::routing::committed_root_scope(chain.state().view().world())
                .is_some()
        );
    }
    fn configure_active_same_dataspace_lanes(state: &State, lane_count: NonZeroU32) {
        let lanes = (1..lane_count.get())
            .map(|index| LaneConfig {
                id: TestLaneId::new(index),
                alias: format!("lane-{index}"),
                dataspace_id: TestDataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                ..LaneConfig::default()
            })
            .collect();
        state
            .apply_lane_lifecycle(&iroha_data_model::nexus::LaneLifecyclePlan {
                additions: lanes,
                retire: Vec::new(),
            })
            .expect("install same-dataspace lanes through their lifecycle");
    }

    fn configure_active_autoscale_sibling(state: &mut State) {
        let mut elastic_lane = LaneConfig {
            id: TestLaneId::new(1),
            alias: "elastic-lane-1".to_owned(),
            dataspace_id: TestDataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            ..LaneConfig::default()
        };
        elastic_lane
            .metadata
            .insert(AUTOSCALE_META_MANAGED.to_owned(), "true".to_owned());
        elastic_lane
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.to_owned(), "1".to_owned());
        crate::state::attach_synthetic_autoscale_committee_for_test(&mut elastic_lane);

        let mut nexus = state.nexus_snapshot();
        nexus.autoscale.enabled = true;
        nexus.autoscale.min_lane_id = nonzero!(1_u32);
        nexus.autoscale.max_lane_id_exclusive = nonzero!(2_u32);
        state
            .set_nexus_from_config(nexus)
            .expect("enable pre-genesis autoscale policy");
        state
            .apply_autoscale_lane_lifecycle_for_tests(&iroha_data_model::nexus::LaneLifecyclePlan {
                additions: vec![elastic_lane],
                retire: Vec::new(),
            })
            .expect("install the authenticated elastic sibling");
    }

    fn lane_manifest_status(
        lane: TestLaneId,
        governance: Option<&str>,
        rules: GovernanceRules,
    ) -> LaneManifestStatus {
        LaneManifestStatus {
            lane,
            alias: format!("lane-{}", lane.as_u32()),
            dataspace: TestDataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: governance.map(str::to_owned),
            manifest_path: Some(PathBuf::from(format!(
                "/tmp/lane-{}.manifest.json",
                lane.as_u32()
            ))),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        }
    }

    fn runtime_upgrade_rules(allow: bool) -> GovernanceRules {
        let mut rules = GovernanceRules::default();
        rules.hooks.runtime_upgrade = Some(RuntimeUpgradeHook {
            allow,
            require_metadata: false,
            metadata_key: None,
            allowed_ids: None,
        });
        rules
    }

    fn runtime_upgrade_transaction(authority: AccountId, keypair: &KeyPair) -> SignedTransaction {
        TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([
            iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade {
                manifest_bytes: vec![0x01],
            },
        ])
        .sign(keypair.private_key())
    }

    fn assert_not_permitted_contains(
        result: Result<(), TransactionRejectionReason>,
        expected: &str,
    ) {
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message))) => {
                assert!(
                    message.contains(expected),
                    "expected rejection containing `{expected}`, got `{message}`"
                );
            }
            other => panic!("expected NotPermitted rejection, got {other:?}"),
        }
    }
    fn world_with_uaid_account(
        uaid: UniversalAccountId,
        dataspace: TestDataSpaceId,
        with_manifest: bool,
        manifest_active: bool,
    ) -> (World, AccountId) {
        let (authority, _) = gen_account_in("wonderland");
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain = Domain::new(domain_id.clone()).build(&authority);
        let account = new_account_in_domain(&authority, &domain_id)
            .with_uaid(Some(uaid))
            .build(&authority);
        let mut world = World::with([domain], [account], []);
        if with_manifest {
            let manifest = AssetPermissionManifest {
                version: ManifestVersion::default(),
                uaid,
                dataspace,
                issued_ms: 1,
                activation_epoch: 1,
                expiry_epoch: None,
                entries: Vec::new(),
            };
            let mut record = SpaceDirectoryManifestRecord::new(manifest);
            record.lifecycle.mark_activated(1);
            if !manifest_active {
                record.lifecycle.mark_expired(2);
            }
            let mut set = SpaceDirectoryManifestSet::default();
            set.upsert(record);
            world.space_directory_manifests.insert(uaid, set);
            if manifest_active {
                let mut bindings = UaidDataspaceBindings::default();
                bindings.bind_account(dataspace, authority.clone());
                world.uaid_dataspaces.insert(uaid, bindings);
            }
        }
        (world, authority)
    }
    #[test]
    fn lane_identity_rejects_uaid_without_dataspace_binding() {
        let uaid = UniversalAccountId::from_hash(Hash::new(b"tx::uaid-no-manifest"));
        let dataspace = TestDataSpaceId::new(7);
        let (world, authority) = world_with_uaid_account(uaid, dataspace, false, true);
        let world_view = world.view();
        let err =
            super::extract_lane_identity_metadata(&world_view, &authority, dataspace, "lane-x")
                .expect_err("UAID routing must require a dataspace binding");
        match err {
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg)) => {
                assert!(
                    msg.contains("not bound to dataspace"),
                    "expected missing binding rejection message, got {msg}"
                );
            }
            other => panic!("expected NotPermitted rejection, got {other:?}"),
        }
    }
    #[test]
    fn lane_policy_allows_space_directory_manifest_publish_before_uaid_binding_exists() {
        let chain: ChainId = "space-directory-publish".parse().unwrap();
        let uaid = UniversalAccountId::from_hash(Hash::new(b"tx::publish-manifest"));
        let dataspace = TestDataSpaceId::new(10);
        let (authority, keypair) = gen_account_in("wonderland");
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain = Domain::new(domain_id.clone()).build(&authority);
        let account = new_account_in_domain(&authority, &domain_id)
            .with_uaid(Some(uaid))
            .build(&authority);
        let world = World::with([domain], [account], []);
        let state = State::new_with_chain(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain.clone(),
        );
        let policy = LaneCompliancePolicy {
            id: LaneCompliancePolicyId::new(Hash::prehashed([0xBC; 32])),
            version: 1,
            lane_id: TestLaneId::SINGLE,
            dataspace_id: dataspace,
            jurisdiction: JurisdictionSet::default(),
            deny: vec![LaneComplianceRule {
                selector: ParticipantSelector {
                    account: Some(authority.clone()),
                    ..ParticipantSelector::default()
                },
                reason_code: Some("unbound uaid".to_string()),
                jurisdiction_override: JurisdictionSet::default(),
            }],
            allow: Vec::new(),
            transfer_limits: Vec::new(),
            audit_controls: AuditControls::default(),
            metadata: Metadata::default(),
        };
        let engine = LaneComplianceEngine::from_policies(vec![policy], false).expect("engine");
        state.install_lane_compliance_engine(Some(Arc::new(engine)));
        let manifest = AssetPermissionManifest {
            version: ManifestVersion::default(),
            uaid,
            dataspace,
            issued_ms: 1,
            activation_epoch: 0,
            expiry_epoch: None,
            entries: Vec::new(),
        };
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([PublishSpaceDirectoryManifest { manifest }])
        .sign(keypair.private_key());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let stx = block.transaction();
        let assignment = super::LaneAssignment {
            lane_id: TestLaneId::SINGLE,
            dataspace_id: TestDataSpaceId::UNIVERSAL,
            dataspace_catalog: &stx.nexus.dataspace_catalog,
        };
        super::enforce_lane_policies(&tx, &stx, &assignment)
            .expect("manifest publication creates the UAID dataspace binding");
    }
    #[test]
    fn lane_identity_rejects_inactive_target_manifest() {
        let uaid = UniversalAccountId::from_hash(Hash::new(b"tx::uaid-inactive-manifest"));
        let dataspace = TestDataSpaceId::new(9);
        let (world, authority) = world_with_uaid_account(uaid, dataspace, true, false);
        let world_view = world.view();
        let err =
            super::extract_lane_identity_metadata(&world_view, &authority, dataspace, "lane-x")
                .expect_err("inactive target manifest must be rejected");
        match err {
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg)) => {
                assert!(
                    msg.contains("not active"),
                    "expected inactive-manifest rejection message, got {msg}"
                );
            }
            other => panic!("expected NotPermitted rejection, got {other:?}"),
        }
    }
    #[test]
    fn dataspace_label_helper_uses_alias_and_fallback() {
        use iroha_data_model::nexus::DataSpaceMetadata;
        let catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: TestDataSpaceId::new(7),
                alias: "alpha".to_string(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("valid catalog");
        let label = super::dataspace_label_from_catalog(&catalog, TestDataSpaceId::new(7));
        assert_eq!(label, "alpha");
        let fallback = super::dataspace_label_from_catalog(&catalog, TestDataSpaceId::new(9));
        assert_eq!(fallback, "9");
    }
    #[test]
    fn duration_since_epoch_with_ok_result_passes_through() {
        let expected = Duration::from_secs(42);
        let actual = super::duration_since_epoch_with_fallback(Ok(expected));
        assert_eq!(actual, expected);
    }
    #[test]
    fn duration_since_epoch_with_err_falls_back_to_zero() {
        let skew_error = SystemTime::UNIX_EPOCH
            .duration_since(SystemTime::UNIX_EPOCH + Duration::from_secs(5))
            .unwrap_err();
        let actual = super::duration_since_epoch_with_fallback(Err(skew_error));
        assert_eq!(actual, Duration::ZERO);
    }
    #[test]
    fn admission_time_uses_the_network_time_snapshot() {
        let expected = Duration::from_secs(42);
        let status = crate::time::NetworkTimeStatus {
            now: SystemTime::UNIX_EPOCH + expected,
            offset_ms: 10,
            confidence_ms: 1,
            sample_count: 3,
            peer_count: 3,
            fallback: false,
            health: crate::time::NtsHealth {
                min_samples_ok: true,
                offset_ok: true,
                confidence_ok: true,
                healthy: true,
            },
        };
        assert_eq!(super::unix_time_from_network_status(status), expected);
    }
    #[test]
    fn future_transaction_rejection_retains_the_exact_admission_clock_boundary() {
        let (_handle, source) = TimeSource::new_mock(Duration::from_millis(12_000));
        let tx = TransactionBuilder::new_genesis_with_time_source(
            GENESIS_ACCOUNT.id.clone(),
            &source,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::DEBUG, "future clock boundary".to_owned())])
        .sign(&GENESIS_ACCOUNT.key);
        let drift = Duration::from_millis(1_000);
        AcceptedTransaction::validate_common_envelope(&tx, drift, Duration::from_millis(11_000))
            .expect("exact maximum future drift remains accepted");
        let error = AcceptedTransaction::validate_common_envelope(
            &tx,
            drift,
            Duration::from_millis(10_999),
        )
        .expect_err("one millisecond beyond the configured drift is rejected");
        assert_eq!(
            error,
            super::AcceptTransactionFail::TransactionInTheFuture {
                creation_time_ms: 12_000,
                now_ms: 10_999,
                max_clock_drift_ms: 1_000,
            }
        );
        let rendered = error.to_string();
        for value in ["12000", "10999", "1000"] {
            assert!(rendered.contains(value), "{rendered}");
        }
        AcceptedTransaction::validate_common_envelope(&tx, drift, Duration::from_millis(12_001))
            .expect("a transaction created before the admission snapshot is not future-dated");
    }
    #[test]
    fn validate_genesis_with_now_uses_supplied_timestamp() {
        let far_future = Duration::from_secs(10_000_000_000);
        let (_handle, time_source) = TimeSource::new_mock(far_future);
        let tx = TransactionBuilder::new_genesis_with_time_source(
            GENESIS_ACCOUNT.id.clone(),
            &time_source,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::DEBUG,
            "genesis timestamp check".to_string(),
        )])
        .sign(&GENESIS_ACCOUNT.key);
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        AcceptedTransaction::validate_genesis_with_now(
            &tx,
            Duration::from_secs(1),
            &GENESIS_ACCOUNT.id,
            &crypto_cfg,
            far_future,
        )
        .expect("genesis validation should use provided timestamp");
    }
    #[test]
    fn accepted_genesis_records_its_validation_time() {
        let now = super::current_unix_time();
        let (_handle, time_source) = TimeSource::new_mock(now);
        let tx = TransactionBuilder::new_genesis_with_time_source(
            GENESIS_ACCOUNT.id.clone(),
            &time_source,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::DEBUG,
            "genesis validation timestamp".to_string(),
        )])
        .sign(&GENESIS_ACCOUNT.key);
        let accepted = AcceptedTransaction::accept_genesis(
            tx,
            Duration::from_secs(60),
            &GENESIS_ACCOUNT.id,
            &iroha_config::parameters::actual::Crypto::default(),
        )
        .expect("genesis transaction should be accepted");
        assert!(accepted.validation_time().is_some());
    }
    #[test]
    fn validate_genesis_with_now_rejects_invalid_transaction_signature() {
        let now = Duration::from_secs(10_000);
        let (_handle, time_source) = TimeSource::new_mock(now);
        let mut tx = TransactionBuilder::new_genesis_with_time_source(
            GENESIS_ACCOUNT.id.clone(),
            &time_source,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::DEBUG,
            "genesis signature check".to_string(),
        )])
        .sign(&GENESIS_ACCOUNT.key);
        let unrelated = checked_random_tx_keypair_with_algorithm(Algorithm::Ed25519);
        tx.set_signature(TransactionSignature(checked_signature_of(
            unrelated.private_key(),
            tx.payload(),
        )));
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        assert!(matches!(
            AcceptedTransaction::validate_genesis_with_now(
                &tx,
                Duration::from_secs(1),
                &GENESIS_ACCOUNT.id,
                &crypto_cfg,
                now,
            ),
            Err(AcceptTransactionFail::SignatureVerification(_))
        ));
    }
    #[test]
    fn runtime_and_genesis_transaction_domains_are_disjoint() {
        let now = Duration::from_secs(10_000);
        let (_handle, time_source) = TimeSource::new_mock(now);
        let network_id = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xA5; Hash::LENGTH])),
        );
        let fee_payment =
            || iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None);
        let runtime = TransactionBuilder::new_with_time_source(
            network_id,
            GENESIS_ACCOUNT.id.clone(),
            &time_source,
            fee_payment(),
        )
        .with_instructions([Log::new(Level::DEBUG, "runtime domain".to_string())])
        .sign(&GENESIS_ACCOUNT.key);
        let genesis = TransactionBuilder::new_genesis_with_time_source(
            GENESIS_ACCOUNT.id.clone(),
            &time_source,
            fee_payment(),
        )
        .with_instructions([Log::new(Level::DEBUG, "genesis domain".to_string())])
        .sign(&GENESIS_ACCOUNT.key);
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        assert!(matches!(
            AcceptedTransaction::validate_genesis_with_now(
                &runtime,
                Duration::from_secs(1),
                &GENESIS_ACCOUNT.id,
                &crypto_cfg,
                now,
            ),
            Err(AcceptTransactionFail::TransactionDomainMismatch(Mismatch {
                expected: TransactionDomain::Genesis,
                actual: TransactionDomain::Network(actual),
            })) if actual == network_id
        ));
        assert!(matches!(
            AcceptedTransaction::validate_with_now(
                &genesis,
                &network_id,
                Duration::from_secs(1),
                TransactionParameters::default(),
                &crypto_cfg,
                now,
            ),
            Err(AcceptTransactionFail::TransactionDomainMismatch(Mismatch {
                expected: TransactionDomain::Network(expected),
                actual: TransactionDomain::Genesis,
            })) if expected == network_id
        ));
    }
    #[test]
    fn signature_limit_allows_count_at_cap() {
        let default_limits = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            nonzero!(3_u64),
            nonzero!(16_u64),
            nonzero!(2048_u64),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        );
        super::AcceptedTransaction::ensure_signature_limit(3, &limits)
            .expect("signature count at cap should be accepted");
    }
    #[test]
    fn signature_limit_rejects_counts_above_cap() {
        let default_limits = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            nonzero!(3_u64),
            nonzero!(16_u64),
            nonzero!(2048_u64),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        );
        let err = super::AcceptedTransaction::ensure_signature_limit(4, &limits)
            .expect_err("signature count above cap must be rejected");
        match err {
            super::AcceptTransactionFail::TransactionLimit(fail) => {
                assert!(
                    fail.reason.contains("Too many signatures"),
                    "error message should explain the signature cap: {:?}",
                    fail.reason
                );
            }
            other => panic!("expected TransactionLimit failure, got {other:?}"),
        }
    }
    mod signature_rejection_tests {
        //! Verifies stable rejection-code classification for malformed
        //! signature bundles and transaction-domain metadata.
        //!
        //! Kept isolated from the transaction implementation's production code.
        use super::*;
        include!("tx/signature_rejection_tests.rs");
    }
    #[test]
    fn multisig_authority_rejected_with_stable_code() {
        let (authority, keypair) = gen_account_in("wonderland");
        let mut builder = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder = builder.with_instructions([Log::new(Level::INFO, "multisig".into())]);
        let tx = builder.sign(keypair.private_key());
        let member = MultisigMember::new(keypair.public_key().clone(), 1).expect("member is valid");
        let policy = MultisigPolicy::new(1, vec![member]).expect("policy is valid");
        let multisig_authority = AccountId::new_multisig(policy);
        let tx = tx.with_authority(multisig_authority);
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        match AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        ) {
            Err(AcceptTransactionFail::SignatureVerification(fail)) => {
                assert_eq!(
                    fail.code(),
                    SignatureRejectionCode::MissingSignatures,
                    "expected multisig missing-signatures code"
                );
                assert_eq!(
                    fail.detail,
                    "missing multisig signatures for multisig authority"
                );
            }
            other => panic!("expected SignatureVerification failure, got {other:?}"),
        }
    }
    #[test]
    fn multisig_authority_accepts_mixed_curves_with_quorum() {
        let member_ed = checked_random_tx_keypair_with_algorithm(Algorithm::Ed25519);
        let member_secp = checked_random_tx_keypair_with_algorithm(Algorithm::Secp256k1);
        let members = vec![
            MultisigMember::new(member_ed.public_key().clone(), 1).expect("member ed"),
            MultisigMember::new(member_secp.public_key().clone(), 1).expect("member secp"),
        ];
        let policy = MultisigPolicy::new(2, members).expect("policy");
        let authority = AccountId::new_multisig(policy.clone());
        let mut builder = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder = builder.with_instructions([Log::new(Level::INFO, "multisig ok".into())]);
        let tx = builder.sign_multisig([member_ed.private_key(), member_secp.private_key()]);
        let limits = TransactionParameters::default();
        let mut crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        if !crypto_cfg.allowed_signing.contains(&Algorithm::Secp256k1) {
            crypto_cfg.allowed_signing.push(Algorithm::Secp256k1);
        }
        crypto_cfg.allowed_signing.sort();
        crypto_cfg.allowed_signing.dedup();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("multisig with quorum should be accepted");
    }
    #[test]
    fn multisig_authority_rejects_unknown_signer() {
        let member_key = checked_random_tx_keypair();
        let member =
            MultisigMember::new(member_key.public_key().clone(), 2).expect("member is valid");
        let policy = MultisigPolicy::new(2, vec![member]).expect("policy is valid");
        let rogue = checked_random_tx_keypair();
        // A canonical bundle and matching primary signature reach membership validation.
        let tx = TransactionBuilder::new(
            test_network_id(),
            AccountId::new_multisig(policy),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "multisig".into())])
        .sign_multisig([rogue.private_key()]);
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        match AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        ) {
            Err(AcceptTransactionFail::SignatureVerification(fail)) => {
                assert_eq!(fail.code(), SignatureRejectionCode::UnknownSigner);
            }
            other => panic!("expected UnknownSigner rejection, got {other:?}"),
        }
    }
    #[test]
    fn multisig_authority_rejects_insufficient_weight_bundle() {
        let signer = checked_random_tx_keypair();
        let other = checked_random_tx_keypair();
        let members = vec![
            MultisigMember::new(signer.public_key().clone(), 1).expect("member"),
            MultisigMember::new(other.public_key().clone(), 1).expect("member"),
        ];
        let policy = MultisigPolicy::new(2, members).expect("policy");
        let authority = AccountId::new_multisig(policy);
        let mut builder = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder = builder
            .with_instructions([Log::new(Level::INFO, "insufficient multisig weight".into())]);
        let tx = builder.sign_multisig([signer.private_key()]);
        let limits = TransactionParameters::default();
        let mut crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        if !crypto_cfg.allowed_signing.contains(&Algorithm::Ed25519) {
            crypto_cfg.allowed_signing.push(Algorithm::Ed25519);
        }
        crypto_cfg.allowed_signing.sort();
        crypto_cfg.allowed_signing.dedup();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        match AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        ) {
            Err(AcceptTransactionFail::SignatureVerification(fail)) => {
                assert_eq!(fail.code(), SignatureRejectionCode::InsufficientWeight);
            }
            other => panic!("expected InsufficientWeight rejection, got {other:?}"),
        }
    }
    #[test]
    fn multisig_account_direct_signing_rejected_in_validation() {
        use iroha_model_base::domain::DomainId;
        let chain: ChainId = "multisig-direct".parse().unwrap();
        let domain_id: DomainId = DomainId::try_new("multisig", "universal").unwrap();
        let signer1 = checked_random_tx_keypair();
        let signer2 = checked_random_tx_keypair();
        let signer1_id = AccountId::new(signer1.public_key().clone());
        let signer2_id = AccountId::new(signer2.public_key().clone());
        let spec = MultisigSpec {
            signatories: BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            quorum: NonZeroU16::new(2).expect("nonzero quorum"),
            transaction_ttl_ms: NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS)
                .expect("nonzero multisig ttl"),
        };
        let multisig_key = checked_random_tx_keypair();
        let multisig_id = AccountId::new(multisig_key.public_key().clone());
        let mut multisig_metadata = Metadata::default();
        multisig_metadata.insert(
            crate::smartcontracts::isi::multisig::spec_key(),
            Json::new(spec),
        );
        let domain = Domain::new(domain_id.clone()).build(&signer1_id);
        let accounts = [
            new_account_in_domain(&signer1_id, &domain_id).build(&signer1_id),
            new_account_in_domain(&signer2_id, &domain_id).build(&signer2_id),
            new_account_in_domain(&multisig_id, &domain_id)
                .with_metadata(multisig_metadata)
                .build(&multisig_id),
        ];
        let world = World::with([domain], accounts, []);
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
        config.chain_id = chain;
        let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
            .expect("apply original signed four-validator genesis");
        let tx = TransactionBuilder::new(
            chain.network_id(),
            multisig_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "direct multisig signer bypass".into(),
        )])
        .sign(multisig_key.private_key());
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        let _accepted = AcceptedTransaction::accept_with_time_source(
            tx.clone(),
            &chain.network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("admission must accept the signature shape");
        chain.commit(vec![tx]);
        let committed = chain.committed(2);
        let result = committed
            .block()
            .network_output_at(0)
            .expect("original transaction has an authenticated execution row")
            .1
            .result
            .0
            .clone();
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason))) => {
                assert!(
                    reason.contains("multisig"),
                    "unexpected reject reason: {reason}"
                );
            }
            other => panic!("expected multisig direct-sign reject, got {other:?}"),
        }
    }
    #[test]
    fn deactivated_contract_subject_remains_in_the_non_signing_index() {
        use iroha_data_model::{
            isi::smart_contract_code::DeactivateContractInstance, smart_contract::ContractAddress,
        };
        use iroha_model_base::domain::DomainId;
        let chain: ChainId = "contract-subject-direct-sign".parse().unwrap();
        let domain_id: DomainId = DomainId::try_new("contracts", "universal").unwrap();
        let deployer_keypair = checked_random_tx_keypair();
        let deployer = AccountId::new(deployer_keypair.public_key().clone());
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &deployer,
            1,
            iroha_model_base::topology::DataSpaceId::new(0),
        )
        .expect("derive contract address");
        let contract_subject = contract_address.subject_id();
        let domain = Domain::new(domain_id.clone()).build(&deployer);
        let deployer_account = new_account_in_domain(&deployer, &domain_id).build(&deployer);
        let mut world = World::with([domain], [deployer_account], []);
        let contract_code_hash = iroha_crypto::Hash::new(b"contract-code");
        let lifecycle_permission: Permission =
            iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode
                .into();
        world
            .account_permissions
            .insert(deployer.clone(), Permissions::from([lifecycle_permission]));
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, query_handle, chain.clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut state_tx = block.transaction();
        state_tx
            .world
            .bind_inactive_contract_subject_for_testing(contract_address.clone(), deployer.clone());
        state_tx
            .world
            .contract_subject_bindings
            .get_mut(&contract_address)
            .expect("seed retained lifecycle")
            .lifecycle
            .active_code_hash = Some(contract_code_hash);
        state_tx
            .world
            .contract_subject_bindings
            .get_mut(&contract_address)
            .unwrap()
            .lifecycle
            .retained_code_hash = Some(contract_code_hash);
        state_tx
            .world
            .contract_instances
            .insert(contract_address.clone(), contract_code_hash);
        DeactivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 1,
            reason: Some("retired for signer-history regression".to_owned()),
        }
        .execute(&deployer, &mut state_tx)
        .expect("deactivate contract instance");
        let retained_binding = state_tx
            .world
            .contract_subject_bindings
            .get(&contract_address)
            .expect("deactivation must retain typed subject history");
        assert_eq!(retained_binding.subject, contract_subject);
        state_tx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit contract deactivation");
        assert!(
            code::is_historical_contract_subject(state.view().world(), &contract_subject),
            "deactivation must retain the canonical subject in the admission-denial index"
        );
    }
    #[test]
    fn multisig_signatory_role_does_not_block_direct_signing() {
        use iroha_model_base::domain::DomainId;
        let chain: ChainId = "multisig-role-only".parse().unwrap();
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let (authority_id, keypair) = gen_account_in("wonderland");
        let domain = Domain::new(domain_id.clone()).build(&authority_id);
        let account = new_account_in_domain(&authority_id, &domain_id).build(&authority_id);
        let mut world = World::with([domain], [account], []);
        let role_id: RoleId = format!(
            "MULTISIG_SIGNATORY/{}/{}",
            domain_id,
            authority_id.expect_single_signatory()
        )
        .parse()
        .expect("static multisig role must parse");
        let role = Role {
            id: role_id.clone(),
            permissions: Permissions::new(),
            permission_epochs: BTreeMap::new(),
        };
        world.roles.insert(role_id.clone(), role);
        world.account_roles.insert(
            crate::role::RoleIdWithOwner::new(authority_id.clone(), role_id),
            (),
        );
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
        config.chain_id = chain;
        let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
            .expect("apply original signed four-validator genesis");
        let tx = TransactionBuilder::new(
            chain.network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "multisig direct sign role fallback".into(),
        )])
        .sign(keypair.private_key());
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        let _accepted = AcceptedTransaction::accept_with_time_source(
            tx.clone(),
            &chain.network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("admission must accept the signature shape");
        chain.commit(vec![tx]);
        let committed = chain.committed(2);
        let result = committed
            .block()
            .network_output_at(0)
            .expect("original transaction has an authenticated execution row")
            .1
            .result
            .0
            .clone();
        assert!(
            result.is_ok(),
            "single-key signatories with multisig roles should keep ordinary direct-signing rights: {result:?}"
        );
    }
    #[test]
    fn multisig_signatory_role_can_submit_multisig_propose_envelope() {
        use iroha_executor_data_model::isi::multisig::MultisigPropose;
        use iroha_model_base::domain::DomainId;
        let chain: ChainId = "multisig-propose-role-allowed".parse().unwrap();
        let home_domain: DomainId = DomainId::try_new("banka", "universal").unwrap();
        let target_domain: DomainId = DomainId::try_new("centralbank", "universal").unwrap();
        let signer1 = checked_random_tx_keypair();
        let signer2 = checked_random_tx_keypair();
        let signer1_id = AccountId::new(signer1.public_key().clone());
        let signer2_id = AccountId::new(signer2.public_key().clone());
        let retail_key = checked_random_tx_keypair();
        let retail_id = AccountId::new(retail_key.public_key().clone());
        let spec = MultisigSpec {
            signatories: BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            quorum: NonZeroU16::new(2).expect("nonzero quorum"),
            transaction_ttl_ms: NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS)
                .expect("nonzero multisig ttl"),
        };
        let multisig_id = AccountId::new_multisig(
            MultisigPolicy::new(
                2,
                vec![
                    MultisigMember::new(signer1.public_key().clone(), 1).expect("signer1 member"),
                    MultisigMember::new(signer2.public_key().clone(), 1).expect("signer2 member"),
                ],
            )
            .expect("multisig policy"),
        );
        let home = Domain::new(home_domain.clone()).build(&signer1_id);
        let target = Domain::new(target_domain.clone()).build(&signer1_id);
        let signer1_account = new_account_in_domain(&signer1_id, &home_domain).build(&signer1_id);
        let signer2_account = new_account_in_domain(&signer2_id, &home_domain).build(&signer2_id);
        let world = World::with([home, target], [signer1_account, signer2_account], []);
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
        config.chain_id = chain;
        config.genesis_key = signer1.clone();
        config
            .genesis_instructions
            .push(InstructionBox::from(MultisigRegister::with_account(
                AccountId::new(checked_random_tx_keypair().public_key().clone()),
                home_domain.clone(),
                spec,
            )));
        let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
            .expect("register canonical multisig through the original signed genesis");
        let registration = Register::account(new_account_in_domain(&retail_id, &target_domain));
        let tx = TransactionBuilder::new(
            chain.network_id(),
            signer1_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(MultisigPropose::new(multisig_id,
iroha_executor_data_model::isi::multisig::MultisigProposalNonce::new([0x61;32]).unwrap(),
vec![registration.into()],
None))])
        .sign(signer1.private_key());
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        let _accepted = AcceptedTransaction::accept_with_time_source(
            tx.clone(),
            &chain.network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("admission must accept the signature shape");
        chain.commit(vec![tx]);
        let committed = chain.committed(2);
        let result = committed
            .block()
            .network_output_at(0)
            .expect("signed multisig envelope has a certified execution result")
            .1
            .result
            .0
            .clone();
        assert!(
            result.is_ok(),
            "multisig propose envelope should bypass direct-sign rejection for signatory roles: {result:?}"
        );
    }
    #[test]
    fn lane_validator_gating_allows_multisig_propose_envelope_from_live_signer() {
        use iroha_executor_data_model::isi::multisig::MultisigPropose;
        use iroha_model_base::domain::DomainId;
        let chain: ChainId = "multisig-propose-lane-validator-bypass".parse().unwrap();
        let home_domain: DomainId = DomainId::try_new("banka", "universal").unwrap();
        let target_domain: DomainId = DomainId::try_new("centralbank", "universal").unwrap();
        let signer1 = checked_random_tx_keypair();
        let signer2 = checked_random_tx_keypair();
        let validator = checked_random_tx_keypair();
        let signer1_id = AccountId::new(signer1.public_key().clone());
        let signer2_id = AccountId::new(signer2.public_key().clone());
        let validator_id = AccountId::new(validator.public_key().clone());
        let retail_key = checked_random_tx_keypair();
        let retail_id = AccountId::new(retail_key.public_key().clone());
        let spec = MultisigSpec {
            signatories: BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            quorum: NonZeroU16::new(2).expect("nonzero quorum"),
            transaction_ttl_ms: NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS)
                .expect("nonzero multisig ttl"),
        };
        let multisig_id = AccountId::new_multisig(
            MultisigPolicy::new(
                2,
                vec![
                    MultisigMember::new(signer1.public_key().clone(), 1).expect("signer1 member"),
                    MultisigMember::new(signer2.public_key().clone(), 1).expect("signer2 member"),
                ],
            )
            .expect("multisig policy"),
        );
        let home = Domain::new(home_domain.clone()).build(&signer1_id);
        let target = Domain::new(target_domain.clone()).build(&signer1_id);
        let signer1_account = new_account_in_domain(&signer1_id, &home_domain).build(&signer1_id);
        let signer2_account = new_account_in_domain(&signer2_id, &home_domain).build(&signer2_id);
        let validator_account =
            new_account_in_domain(&validator_id, &home_domain).build(&validator_id);
        let world = World::with(
            [home, target],
            [signer1_account, signer2_account, validator_account],
            [],
        );
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 0);
        config.chain_id = chain;
        config
            .genesis_instructions
            .push(InstructionBox::from(MultisigRegister::with_account(
                AccountId::new(checked_random_tx_keypair().public_key().clone()),
                home_domain.clone(),
                spec,
            )));
        let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
            .expect("register canonical multisig through the original signed genesis source");
        let state = chain.state();
        let mut statuses = BTreeMap::new();
        statuses.insert(
            TestLaneId::SINGLE,
            LaneManifestStatus {
                lane: TestLaneId::SINGLE,
                alias: "centralbank".to_string(),
                dataspace: TestDataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: Some("parliament".to_string()),
                manifest_path: Some(std::path::PathBuf::from("/tmp/centralbank.manifest.json")),
                governance_rules: Some(GovernanceRules {
                    validators: vec![validator_id.clone()],
                    ..GovernanceRules::default()
                }),
                privacy_commitments: Vec::new(),
            },
        );
        let registry = std::sync::Arc::new(LaneManifestRegistry::from_statuses(statuses));
        let policy_manifests = Arc::clone(&registry);
        let registration = Register::account(new_account_in_domain(&retail_id, &target_domain));
        let tx = TransactionBuilder::new(
            chain.network_id(),
            signer1_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(MultisigPropose::new(multisig_id,
iroha_executor_data_model::isi::multisig::MultisigProposalNonce::new([0x61;32]).unwrap(),
vec![registration.into()],
None))])
        .sign(signer1.private_key());
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        let accepted = AcceptedTransaction::accept_with_time_source(
            tx,
            &chain.network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("admission must accept the signature shape");
        let header = original_component_successor_header(state);
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        let mut ivm_cache = IvmCache::new();
        let result =
            execute_component_transaction_for_testing(&mut block, accepted, &mut ivm_cache, None);
        assert!(
            result.is_ok(),
            "lane validator gating should not reject multisig propose envelopes from live signers: {result:?}"
        );
    }
    #[test]
    fn lane_validator_gating_ignores_non_governance_transactions() {
        let chain: ChainId = "lane-validator-gating-plain-transfer".parse().unwrap();
        let (authority, authority_keypair) = gen_account_in("wonderland");
        let (validator_a, _) = gen_account_in("wonderland");
        let (validator_b, _) = gen_account_in("wonderland");
        let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain = Domain::new(domain_id.clone()).build(&authority);
        let authority_account = new_account_in_domain(&authority, &domain_id).build(&authority);
        let validator_a_account =
            new_account_in_domain(&validator_a, &domain_id).build(&validator_a);
        let second_validator_registration =
            new_account_in_domain(&validator_b, &domain_id).build(&validator_b);
        let world = World::with(
            [domain],
            [
                authority_account,
                validator_a_account,
                second_validator_registration,
            ],
            [],
        );
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, query_handle, chain.clone());
        let chain = crate::block::tests::component_chain(state);
        let state = chain.state();
        let mut statuses = BTreeMap::new();
        statuses.insert(
            TestLaneId::SINGLE,
            LaneManifestStatus {
                lane: TestLaneId::SINGLE,
                alias: "paynet".to_string(),
                dataspace: TestDataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: Some("parliament".to_string()),
                manifest_path: Some(std::path::PathBuf::from("/tmp/paynet.manifest.json")),
                governance_rules: Some(GovernanceRules {
                    validators: vec![validator_a.clone(), validator_b.clone()],
                    quorum: Some(2),
                    ..GovernanceRules::default()
                }),
                privacy_commitments: Vec::new(),
            },
        );
        let registry = std::sync::Arc::new(LaneManifestRegistry::from_statuses(statuses));
        let policy_manifests = Arc::clone(&registry);
        let tx = TransactionBuilder::new(
            chain.network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "retail transfer".into())])
        .sign(authority_keypair.private_key());
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        let accepted = AcceptedTransaction::accept_with_time_source(
            tx,
            &chain.network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("admission should accept transaction shape");
        let header = original_component_successor_header(state);
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        let mut ivm_cache = IvmCache::new();
        let result =
            execute_component_transaction_for_testing(&mut block, accepted, &mut ivm_cache, None);
        assert!(
            result.is_ok(),
            "lane validator gating should ignore plain transactions that do not touch governance surfaces: {result:?}"
        );
    }
    #[test]
    fn native_execution_lane_collision_cannot_bypass_the_physical_policy_hook() {
        let (world, authority, keypair) = world_with_authority("wonderland");
        let state = State::new(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_active_same_dataspace_lanes(&state, nonzero!(2_u32));
        let statuses = BTreeMap::from([
            (
                TestLaneId::SINGLE,
                lane_manifest_status(
                    TestLaneId::SINGLE,
                    Some("parliament"),
                    runtime_upgrade_rules(false),
                ),
            ),
            (
                TestLaneId::new(1),
                lane_manifest_status(
                    TestLaneId::new(1),
                    Some("parliament"),
                    runtime_upgrade_rules(true),
                ),
            ),
        ]);
        let mut metadata = Metadata::default();
        metadata.insert("expires_at_height".parse().unwrap(), Json::new(5_u64));
        metadata.insert("tx_sequence".parse().unwrap(), Json::new(1_u64));
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(metadata)
        .with_instructions([
            iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade {
                manifest_bytes: vec![0x01],
            },
        ])
        .sign(keypair.private_key());
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        block.lane_manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        let mut overlay = block.transaction();
        let native =
            crate::queue::RoutingDecision::new(TestLaneId::new(1), TestDataSpaceId::UNIVERSAL);
        let accepted = AcceptedTransaction::new_unchecked(Cow::Borrowed(&tx));
        let policy_route = CapturedNetworkPolicyRoute::for_component(&accepted, &overlay, native)
            .expect("completed original physical policy capture");
        assert_not_permitted_contains(
            StateBlock::validate_stateful_admission(&tx, &mut overlay, native, policy_route, None)
                .map(|_| ()),
            "runtime upgrade hook prohibits runtime upgrade instructions",
        );
        assert_eq!(overlay.current_lane_id, Some(native.lane_id));
        assert_eq!(overlay.current_dataspace_id, Some(native.dataspace_id));
        assert!(overlay.world.runtime_upgrades.iter().next().is_none());
    }

    #[test]
    fn native_execution_dataspace_mismatch_refuses_before_application_policy() {
        let (world, authority, keypair) = world_with_authority("wonderland");
        let state = State::new(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut metadata = Metadata::default();
        metadata.insert("expires_at_height".parse().unwrap(), Json::new(5_u64));
        metadata.insert("tx_sequence".parse().unwrap(), Json::new(1_u64));
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(metadata)
        .with_instructions([Log::new(Level::INFO, "mismatched scope".into())])
        .sign(keypair.private_key());
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut overlay = block.transaction();
        let native =
            crate::queue::RoutingDecision::new(TestLaneId::new(1), TestDataSpaceId::new(7));
        let accepted = AcceptedTransaction::new_unchecked(Cow::Borrowed(&tx));
        let policy_route = CapturedNetworkPolicyRoute::for_component(&accepted, &overlay, native)
            .expect("completed original physical policy capture");
        assert_not_permitted_contains(
            StateBlock::validate_stateful_admission(&tx, &mut overlay, native, policy_route, None)
                .map(|_| ()),
            "physical policy dataspace differs from authenticated native source",
        );
        assert_eq!(overlay.current_lane_id, None);
        assert_eq!(overlay.current_dataspace_id, None);
    }

    #[test]
    fn lane_validator_gating_inherits_same_dataspace_manifest_authority() {
        let chain: ChainId = "same-dataspace-lane-validator-gating".parse().unwrap();
        let (world, authority, keypair) = world_with_authority("wonderland");
        let (validator, _) = gen_account_in("wonderland");
        let state = State::new_with_chain(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain,
        );
        configure_active_same_dataspace_lanes(&state, nonzero!(2_u32));

        let authority_rules = GovernanceRules {
            validators: vec![validator],
            quorum: Some(1),
            ..GovernanceRules::default()
        };
        let statuses = BTreeMap::from([
            (
                TestLaneId::SINGLE,
                lane_manifest_status(TestLaneId::SINGLE, None, authority_rules),
            ),
            (
                TestLaneId::new(1),
                lane_manifest_status(
                    TestLaneId::new(1),
                    Some("parliament"),
                    runtime_upgrade_rules(true),
                ),
            ),
        ]);
        let policy_manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));

        let tx = runtime_upgrade_transaction(authority, &keypair);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        let stx = block.transaction();
        let assignment = super::LaneAssignment {
            lane_id: TestLaneId::new(1),
            dataspace_id: TestDataSpaceId::UNIVERSAL,
            dataspace_catalog: &stx.nexus.dataspace_catalog,
        };

        assert_not_permitted_contains(
            super::enforce_lane_policies(&tx, &stx, &assignment),
            "authority not part of lane validator set",
        );
    }

    #[test]
    fn lane_validator_gating_inherits_same_dataspace_manifest_quorum() {
        let chain: ChainId = "same-dataspace-lane-validator-quorum".parse().unwrap();
        let (world, authority, keypair) = world_with_authority("wonderland");
        let (secondary_validator, _) = gen_account_in("wonderland");
        let state = State::new_with_chain(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain,
        );
        configure_active_same_dataspace_lanes(&state, nonzero!(2_u32));

        let authority_rules = GovernanceRules {
            validators: vec![authority.clone(), secondary_validator],
            quorum: Some(2),
            ..GovernanceRules::default()
        };
        let statuses = BTreeMap::from([
            (
                TestLaneId::SINGLE,
                lane_manifest_status(TestLaneId::SINGLE, None, authority_rules),
            ),
            (
                TestLaneId::new(1),
                lane_manifest_status(
                    TestLaneId::new(1),
                    Some("parliament"),
                    runtime_upgrade_rules(true),
                ),
            ),
        ]);
        let policy_manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));

        let tx = runtime_upgrade_transaction(authority, &keypair);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        let stx = block.transaction();
        let assignment = super::LaneAssignment {
            lane_id: TestLaneId::new(1),
            dataspace_id: TestDataSpaceId::UNIVERSAL,
            dataspace_catalog: &stx.nexus.dataspace_catalog,
        };

        assert_not_permitted_contains(
            super::enforce_lane_policies(&tx, &stx, &assignment),
            "lane manifest quorum requires 2 validator approvals",
        );
    }

    #[test]
    fn lane_validator_gating_keeps_hooks_and_protected_namespaces_lane_local() {
        let chain: ChainId = "same-dataspace-lane-local-hook".parse().unwrap();
        let (world, authority, keypair) = world_with_authority("wonderland");
        let state = State::new_with_chain(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain,
        );
        configure_active_same_dataspace_lanes(&state, nonzero!(2_u32));

        let mut authority_rules = runtime_upgrade_rules(true);
        authority_rules.validators = vec![authority.clone()];
        authority_rules.quorum = Some(1);
        authority_rules
            .protected_namespaces
            .insert(Name::from_str("apps").expect("protected namespace"));
        let statuses = BTreeMap::from([
            (
                TestLaneId::SINGLE,
                lane_manifest_status(TestLaneId::SINGLE, None, authority_rules),
            ),
            (
                TestLaneId::new(1),
                lane_manifest_status(
                    TestLaneId::new(1),
                    Some("parliament"),
                    runtime_upgrade_rules(false),
                ),
            ),
        ]);
        let policy_manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));

        let tx = runtime_upgrade_transaction(authority.clone(), &keypair);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        let stx = block.transaction();
        let assignment = super::LaneAssignment {
            lane_id: TestLaneId::new(1),
            dataspace_id: TestDataSpaceId::UNIVERSAL,
            dataspace_catalog: &stx.nexus.dataspace_catalog,
        };

        assert_not_permitted_contains(
            super::enforce_lane_policies(&tx, &stx, &assignment),
            "runtime upgrade hook prohibits runtime upgrade instructions",
        );

        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &test_network_id(),
            &authority,
            0,
            TestDataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let contract_tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([ActivateContractInstance {
            contract_address,
            expected_revision: 1,
            code_hash: Hash::prehashed([0_u8; 32]),
        }])
        .sign(keypair.private_key());
        let result = super::enforce_lane_policies(&contract_tx, &stx, &assignment);
        assert!(
            result.is_ok(),
            "a sibling lane's protected namespaces must not gate target-lane policy: {result:?}"
        );
    }

    #[test]
    fn lane_validator_gating_separates_static_and_autoscale_manifest_authority() {
        let chain: ChainId = "static-autoscale-manifest-authority".parse().unwrap();
        let (world, static_validator, static_keypair) = world_with_authority("wonderland");
        let (elastic_validator, elastic_keypair) = gen_account_in("wonderland");
        let mut state = State::new_with_chain(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain,
        );
        configure_active_autoscale_sibling(&mut state);

        let mut static_rules = runtime_upgrade_rules(false);
        static_rules.validators = vec![static_validator.clone()];
        let mut elastic_rules = runtime_upgrade_rules(false);
        elastic_rules.validators = vec![elastic_validator.clone()];
        let statuses = BTreeMap::from([
            (
                TestLaneId::SINGLE,
                lane_manifest_status(TestLaneId::SINGLE, Some("parliament"), static_rules),
            ),
            (
                TestLaneId::new(1),
                lane_manifest_status(TestLaneId::new(1), Some("parliament"), elastic_rules),
            ),
        ]);
        let policy_manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));

        let static_tx = runtime_upgrade_transaction(static_validator, &static_keypair);
        let elastic_tx = runtime_upgrade_transaction(elastic_validator, &elastic_keypair);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        let stx = block.transaction();
        let static_assignment = single_lane_assignment(&stx.nexus.dataspace_catalog);
        let elastic_assignment = super::LaneAssignment {
            lane_id: TestLaneId::new(1),
            dataspace_id: TestDataSpaceId::UNIVERSAL,
            dataspace_catalog: &stx.nexus.dataspace_catalog,
        };

        for (tx, assignment) in [
            (&static_tx, &static_assignment),
            (&elastic_tx, &elastic_assignment),
        ] {
            assert_not_permitted_contains(
                super::enforce_lane_policies(tx, &stx, assignment),
                "runtime upgrade hook prohibits runtime upgrade instructions",
            );
        }
    }

    #[test]
    fn lane_validator_gating_rejects_conflicting_same_dataspace_authority() {
        let chain: ChainId = "same-dataspace-lane-validator-conflict".parse().unwrap();
        let (world, authority, keypair) = world_with_authority("wonderland");
        let (conflicting_validator, _) = gen_account_in("wonderland");
        let state = State::new_with_chain(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain,
        );
        configure_active_same_dataspace_lanes(&state, nonzero!(3_u32));

        let first_authority = GovernanceRules {
            validators: vec![authority.clone()],
            quorum: Some(1),
            ..GovernanceRules::default()
        };
        let conflicting_authority = GovernanceRules {
            validators: vec![conflicting_validator],
            quorum: Some(1),
            ..GovernanceRules::default()
        };
        let statuses = BTreeMap::from([
            (
                TestLaneId::SINGLE,
                lane_manifest_status(TestLaneId::SINGLE, None, first_authority),
            ),
            (
                TestLaneId::new(1),
                lane_manifest_status(
                    TestLaneId::new(1),
                    Some("parliament"),
                    runtime_upgrade_rules(true),
                ),
            ),
            (
                TestLaneId::new(2),
                lane_manifest_status(TestLaneId::new(2), None, conflicting_authority),
            ),
        ]);
        let policy_manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));

        let tx = runtime_upgrade_transaction(authority, &keypair);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        let stx = block.transaction();
        let assignment = super::LaneAssignment {
            lane_id: TestLaneId::new(1),
            dataspace_id: TestDataSpaceId::UNIVERSAL,
            dataspace_catalog: &stx.nexus.dataspace_catalog,
        };

        assert_not_permitted_contains(
            super::enforce_lane_policies(&tx, &stx, &assignment),
            "conflicting manifest validator pools",
        );
    }

    #[test]
    fn lane_validator_gating_rejects_missing_active_authority_source_manifest() {
        let chain: ChainId = "same-dataspace-missing-authority-manifest".parse().unwrap();
        let (world, authority, keypair) = world_with_authority("wonderland");
        let state = State::new_with_chain(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain,
        );
        configure_active_same_dataspace_lanes(&state, nonzero!(2_u32));

        let mut missing_source = lane_manifest_status(
            TestLaneId::SINGLE,
            Some("parliament"),
            GovernanceRules::default(),
        );
        missing_source.manifest_path = None;
        missing_source.governance_rules = None;
        let statuses = BTreeMap::from([
            (TestLaneId::SINGLE, missing_source),
            (
                TestLaneId::new(1),
                lane_manifest_status(
                    TestLaneId::new(1),
                    Some("parliament"),
                    runtime_upgrade_rules(true),
                ),
            ),
        ]);
        let policy_manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));

        let tx = runtime_upgrade_transaction(authority, &keypair);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        let stx = block.transaction();
        let assignment = super::LaneAssignment {
            lane_id: TestLaneId::new(1),
            dataspace_id: TestDataSpaceId::UNIVERSAL,
            dataspace_catalog: &stx.nexus.dataspace_catalog,
        };

        assert_not_permitted_contains(
            super::enforce_lane_policies(&tx, &stx, &assignment),
            "no manifest was loaded",
        );
    }

    #[test]
    fn lane_validator_gating_preserves_exact_lane_authority_when_nexus_is_disabled() {
        let chain: ChainId = "disabled-nexus-lane-validator-gating".parse().unwrap();
        let (world, authority, keypair) = world_with_authority("wonderland");
        let (validator, _) = gen_account_in("wonderland");
        let state = State::new_with_chain(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain,
        );

        let mut rules = runtime_upgrade_rules(true);
        rules.validators = vec![validator];
        rules.quorum = Some(1);
        let statuses = BTreeMap::from([(
            TestLaneId::SINGLE,
            lane_manifest_status(TestLaneId::SINGLE, Some("parliament"), rules),
        )]);
        let policy_manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));

        let tx = runtime_upgrade_transaction(authority, &keypair);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        let stx = block.transaction();
        let assignment = single_lane_assignment(&stx.nexus.dataspace_catalog);

        assert_not_permitted_contains(
            super::enforce_lane_policies(&tx, &stx, &assignment),
            "authority not part of lane validator set",
        );
    }

    #[test]
    fn missing_authority_rejected_for_non_multisig_transaction() {
        let chain: ChainId = "missing-authority-regular".parse().unwrap();
        let (authority, keypair) = gen_account_in("wonderland");
        let world = World::new();
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
        config.chain_id = chain;
        let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
            .expect("apply original signed four-validator genesis");
        let tx = TransactionBuilder::new(
            chain.network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "regular".into())])
        .sign(keypair.private_key());
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        let _accepted = AcceptedTransaction::accept_with_time_source(
            tx.clone(),
            &chain.network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("admission should accept transaction shape");
        chain.commit(vec![tx]);
        let committed = chain.committed(2);
        let result = committed
            .block()
            .network_output_at(0)
            .expect("original transaction has an authenticated execution row")
            .1
            .result
            .0
            .clone();
        match result {
            Err(TransactionRejectionReason::AccountDoesNotExist(FindError::Account(id))) => {
                assert_eq!(id, authority, "unexpected missing-account id");
            }
            other => panic!("expected AccountDoesNotExist rejection, got {other:?}"),
        }
    }
    #[test]
    fn unregistered_authority_predicates_require_exact_first_self_registration() {
        let (authority, _) = gen_account_in("wonderland");
        let (other, _) = gen_account_in("wonderland");
        let exact = Executable::Instructions(
            vec![
                InstructionBox::from(Register::account(Account::new(authority.clone()))),
                InstructionBox::from(Log::new(Level::INFO, "after registration".into())),
            ]
            .into(),
        );
        assert!(executable_self_registers_authority(&exact, &authority));
        assert!(allows_unregistered_authority(&exact, &authority));
        let registers_other = Executable::Instructions(
            vec![InstructionBox::from(Register::account(Account::new(other)))].into(),
        );
        assert!(!executable_self_registers_authority(
            &registers_other,
            &authority
        ));
        assert!(!allows_unregistered_authority(&registers_other, &authority));
        let registration_is_not_first = Executable::Instructions(
            vec![
                InstructionBox::from(Log::new(Level::INFO, "before registration".into())),
                InstructionBox::from(Register::account(Account::new(authority.clone()))),
            ]
            .into(),
        );
        assert!(!executable_self_registers_authority(
            &registration_is_not_first,
            &authority
        ));
        assert!(!allows_unregistered_authority(
            &registration_is_not_first,
            &authority
        ));
        assert!(!allows_unregistered_authority(
            &Executable::Instructions(Vec::<InstructionBox>::new().into()),
            &authority,
        ));
    }
    #[test]
    fn missing_authority_self_register_allows_transaction() {
        let chain: ChainId = "missing-authority-self-register".parse().unwrap();
        let (authority, keypair) = gen_account_in("wonderland");
        let world = World::new();
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
        config.chain_id = chain;
        let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
            .expect("apply original signed four-validator genesis");
        let tx = TransactionBuilder::new(
            chain.network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([
            InstructionBox::from(Register::account(Account::new(authority.clone()))),
            InstructionBox::from(Log::new(Level::INFO, "self-register".into())),
        ])
        .sign(keypair.private_key());
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        let _accepted = AcceptedTransaction::accept_with_time_source(
            tx.clone(),
            &chain.network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("admission should accept transaction shape");
        chain.commit(vec![tx]);
        let committed = chain.committed(2);
        let result = committed
            .block()
            .network_output_at(0)
            .expect("original transaction has an authenticated execution row")
            .1
            .result
            .0
            .clone();
        assert!(result.is_ok(), "self-register flow should pass: {result:?}");
        assert!(
            chain
                .state()
                .view()
                .world()
                .accounts()
                .get(&authority)
                .is_some(),
            "authority account should be created by the first transaction"
        );
    }
    #[test]
    fn existing_authority_self_register_rejects_repetition_without_mutation() {
        let chain: ChainId = "existing-authority-self-register".parse().unwrap();
        let (authority, keypair) = gen_account_in("wonderland");
        let existing = Account::new(authority.clone()).build(&authority);
        let world = World::with([], [existing], []);
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
        config.chain_id = chain;
        let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
            .expect("apply original signed four-validator genesis");
        let tx = TransactionBuilder::new(
            chain.network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([
            InstructionBox::from(Register::account(Account::new(authority.clone()))),
            InstructionBox::from(Log::new(Level::INFO, "self-register-again".into())),
        ])
        .sign(keypair.private_key());
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        let _accepted = AcceptedTransaction::accept_with_time_source(
            tx.clone(),
            &chain.network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("admission should accept transaction shape");
        let account_before = chain
            .state()
            .view()
            .world()
            .accounts()
            .get(&authority)
            .cloned();
        chain.commit(vec![tx]);
        let committed = chain.committed(2);
        let result = committed
            .block()
            .network_output_at(0)
            .expect("original transaction has an authenticated execution row")
            .1
            .result
            .0
            .clone();
        assert!(
            matches!(&result,
                Err(TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                    iroha_data_model::isi::error::InstructionExecutionError::Repetition(error)
                ))) if error.instruction == iroha_data_model::isi::InstructionType::Register
                    && error.id == IdBox::AccountId(authority.clone())
            ),
            "duplicate self-register must reject its exact existing identity: {result:?}"
        );
        assert_eq!(
            chain
                .state()
                .view()
                .world()
                .accounts()
                .get(&authority)
                .cloned(),
            account_before
        );
    }
    #[test]
    fn missing_authority_multisig_approve_reaches_instruction_validation() {
        let chain: ChainId = "missing-authority-multisig-approve".parse().unwrap();
        let (missing_authority, keypair) = gen_account_in("wonderland");
        let multisig_account = AccountId::new(checked_random_tx_keypair().public_key().clone());
        let instructions_hash = HashOf::new(&Vec::<InstructionBox>::new());
        let world = World::new();
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
        config.chain_id = chain;
        let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
            .expect("apply original signed four-validator genesis");
        let tx = TransactionBuilder::new(
            chain.network_id(),
            missing_authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([MultisigApprove::new(multisig_account.clone(),
iroha_executor_data_model::isi::multisig::MultisigProposalId::derive(&chain.network_id(), &multisig_account.clone(), &iroha_executor_data_model::isi::multisig::MultisigProposalNonce::new([0x61;32]).unwrap()),
instructions_hash)])
        .sign(keypair.private_key());
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        let _accepted = AcceptedTransaction::accept_with_time_source(
            tx.clone(),
            &chain.network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("admission should accept transaction shape");
        chain.commit(vec![tx]);
        let committed = chain.committed(2);
        let result = committed
            .block()
            .network_output_at(0)
            .expect("original transaction has an authenticated execution row")
            .1
            .result
            .0
            .clone();
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                iroha_data_model::isi::error::InstructionExecutionError::Find(FindError::Account(
                    _,
                )),
            ))) => {}
            other => panic!("expected instruction-level account lookup failure, got {other:?}"),
        }
    }
    #[test]
    fn single_authority_rejects_disallowed_algorithm() {
        let keypair = checked_random_tx_keypair_with_algorithm(Algorithm::Secp256k1);
        let authority = AccountId::new(keypair.public_key().clone());
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "single disallowed algorithm".into())])
        .sign(keypair.private_key());
        let limits = TransactionParameters::default();
        let mut crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        crypto_cfg
            .allowed_signing
            .retain(|algo| *algo == Algorithm::Ed25519);
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        match AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        ) {
            Err(AcceptTransactionFail::SignatureVerification(fail)) => {
                assert_eq!(fail.code(), SignatureRejectionCode::AlgorithmNotPermitted);
            }
            other => panic!("expected AlgorithmNotPermitted rejection, got {other:?}"),
        }
    }
    #[test]
    fn multisig_authority_rejects_disallowed_algorithm() {
        let member = checked_random_tx_keypair_with_algorithm(Algorithm::Secp256k1);
        let members = vec![MultisigMember::new(member.public_key().clone(), 1).expect("member")];
        let policy = MultisigPolicy::new(1, members).expect("policy");
        let authority = AccountId::new_multisig(policy);
        let mut builder = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder = builder.with_instructions([Log::new(
            Level::INFO,
            "multisig disallowed algorithm".into(),
        )]);
        let tx = builder.sign_multisig(vec![member.private_key()]);
        let limits = TransactionParameters::default();
        let mut crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        crypto_cfg
            .allowed_signing
            .retain(|algo| *algo == Algorithm::Ed25519);
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        match AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        ) {
            Err(AcceptTransactionFail::SignatureVerification(fail)) => {
                assert_eq!(fail.code(), SignatureRejectionCode::AlgorithmNotPermitted);
            }
            other => panic!("expected AlgorithmNotPermitted rejection, got {other:?}"),
        }
    }
    #[test]
    fn multisig_authority_rejects_insufficient_weight() {
        let member_a = checked_random_tx_keypair();
        let member_b = checked_random_tx_keypair();
        let members = vec![
            MultisigMember::new(member_a.public_key().clone(), 1).expect("member a"),
            MultisigMember::new(member_b.public_key().clone(), 1).expect("member b"),
        ];
        let policy = MultisigPolicy::new(2, members).expect("policy");
        let authority = AccountId::new_multisig(policy);
        let mut builder = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder = builder
            .with_instructions([Log::new(Level::INFO, "multisig insufficient weight".into())]);
        let tx = builder.sign_multisig(vec![member_a.private_key()]);
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        match AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        ) {
            Err(AcceptTransactionFail::SignatureVerification(fail)) => {
                assert_eq!(fail.code(), SignatureRejectionCode::InsufficientWeight);
            }
            other => panic!("expected InsufficientWeight rejection, got {other:?}"),
        }
    }
    #[test]
    fn multisig_signature_limit_counts_bundle_entries() {
        let signers = std::array::from_fn::<_, 3, _>(|_| checked_random_tx_keypair());
        let members = signers
            .iter()
            .map(|signer| MultisigMember::new(signer.public_key().clone(), 1).expect("member"))
            .collect();
        let policy = MultisigPolicy::new(1, members).expect("policy");
        let authority = AccountId::new_multisig(policy);
        // Three distinct, correctly ordered signatures reach the two-signature limit.
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "multisig too many signatures".into())])
        .sign_multisig(signers.iter().map(KeyPair::private_key));
        let defaults = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            nonzero!(2_u64),
            defaults.max_instructions(),
            defaults.ivm_bytecode_size(),
            defaults.max_tx_bytes(),
            defaults.max_decompressed_bytes(),
            defaults.max_metadata_depth(),
        );
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let (_clock_handle, time_source) = TimeSource::new_mock(tx.creation_time());
        match AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            &time_source,
        ) {
            Err(AcceptTransactionFail::TransactionLimit(fail)) => {
                assert!(
                    fail.reason.contains("Too many signatures"),
                    "expected signature limit failure, got {:?}",
                    fail.reason
                );
            }
            other => panic!("expected signature limit rejection, got {other:?}"),
        }
    }
    #[test]
    fn accepted_transaction_into_checked_allows_pending() {
        let (authority, keypair) = gen_account_in("wonderland");
        let instruction = Log::new(Level::INFO, "noop".into());
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction])
        .sign(keypair.private_key());
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(signed));
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let state = State::new_for_testing(World::default(), kura, query);
        let view = state.view();
        let checked = accepted
            .clone()
            .into_checked(&view)
            .expect("transaction should not be committed");
        assert_eq!(checked.hash_as_entrypoint(), accepted.hash_as_entrypoint());
    }
    #[test]
    fn accepted_transaction_into_entrypoint_consumes_wrapped_entrypoint() {
        let (authority, keypair) = gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "into-entrypoint".into())])
        .sign(keypair.private_key());
        let expected = TransactionEntrypoint::External(signed.clone());
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(signed));
        assert_eq!(accepted.into_entrypoint(), expected);
    }
    #[test]
    fn accepted_transaction_into_checked_detects_committed() {
        let (authority, keypair) = gen_account_in("wonderland");
        let instruction = Log::new(Level::INFO, "commit".into());
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction])
        .sign(keypair.private_key());
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(signed.clone()));
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let state = State::new_for_testing(World::default(), kura, query);
        let entrypoint_hash = accepted.hash_as_entrypoint();
        let generation = state.state_view_generation();
        let checked = accepted
            .clone()
            .into_checked(&state.view())
            .expect("the replay identity is initially pending");

        // Exercise committed replay membership through its storage owner. Whole
        // carrier publication also requires the exact finalized block hash.
        let mut membership = state.transactions.block();
        membership.insert_block_with_single_tx(entrypoint_hash, nonzero!(1_usize));
        assert!(
            !checked.is_in_blockchain(&state.view()),
            "staging replay membership must not expose it to committed readers"
        );
        membership.commit().expect("commit replay membership");
        assert!(checked.is_in_blockchain(&state.view()));
        assert_eq!(
            state.committed_entrypoint_height(&entrypoint_hash),
            Some(nonzero!(1_usize))
        );
        assert_eq!(state.committed_height(), 0);
        assert_eq!(state.latest_block_hash_fast(), None);
        assert_eq!(
            state.state_view_generation(),
            generation,
            "the focused membership fixture does not publish World"
        );
        let view = state.view();
        let result = accepted.into_checked(&view);
        assert!(matches!(result, Err((_, TransactionAlreadyCommitted))));
    }
    #[test]
    fn checked_sealed_reveal_rejects_only_a_committed_replay_alias() {
        let (authority, keypair) = gen_account_in("sealed-queue-replay-alias");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "sealed queue alias".into())])
        .sign(keypair.private_key());
        let deadline = 9;
        let first_salt = [0x41; 32];
        let second_salt = [0x42; 32];
        let first = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            compute_sealed_transaction_commitment(
                &test_network_id(),
                &signed,
                first_salt,
                deadline,
            ),
            signed.clone(),
            first_salt,
        ));
        let second = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            compute_sealed_transaction_commitment(
                &test_network_id(),
                &signed,
                second_salt,
                deadline,
            ),
            signed.clone(),
            second_salt,
        ));
        let accepted = AcceptedTransaction::new_unchecked_entrypoint(Cow::Owned(second.clone()));
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut first_membership = state.transactions.block();
        first_membership.insert_block_with_single_tx(first.hash(), nonzero!(1_usize));
        first_membership
            .commit()
            .expect("commit outer-only reveal identity");

        let pending_checked = accepted
            .clone()
            .into_checked(&state.view())
            .expect("a different carrier remains pending while the signed alias is uncommitted");
        assert!(!pending_checked.is_in_blockchain(&state.view()));

        let mut second_membership = state.transactions.block();
        second_membership
            .insert_block_with_single_tx(signed.hash_as_entrypoint(), nonzero!(2_usize));
        second_membership
            .commit()
            .expect("commit authenticated signed replay alias");

        assert!(pending_checked.is_in_blockchain(&state.view()));
        assert!(matches!(
            accepted.into_checked(&state.view()),
            Err((_, TransactionAlreadyCommitted))
        ));
    }
    #[test]
    fn accepted_transaction_caches_hashes_and_encoded_length() {
        let (authority, keypair) = gen_account_in("wonderland");
        let instruction = Log::new(Level::INFO, "cache".into());
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction])
        .sign(keypair.private_key());
        let expected_len = norito::to_bytes(&signed)
            .expect("signed transaction encodes")
            .len();
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(signed.clone()));
        assert_eq!(
            Hash::from(accepted.hash_as_entrypoint()),
            Hash::from(signed.hash())
        );
        assert_eq!(accepted.hash_as_entrypoint(), signed.hash_as_entrypoint());
        assert_eq!(
            external_entrypoint_hash_from_signed_hash(signed.hash()),
            signed.hash_as_entrypoint(),
            "an explicitly external signed identity must project to its canonical entrypoint identity"
        );
        assert_eq!(accepted.encoded_len(), expected_len);
        let signed_bytes = accepted
            .signed_bytes()
            .expect("external transaction should cache signed bytes");
        assert_eq!(signed_bytes.as_slice(), norito::to_bytes(&signed).unwrap());
        assert_eq!(accepted.payload_hash(), Some(HashOf::new(signed.payload())));
        assert!(accepted.single_ed25519_key().is_some());
        let prepared = accepted
            .prepared_metadata()
            .expect("external transaction has prepared metadata");
        assert_eq!(prepared.signed_hash, signed.hash());
        assert_eq!(prepared.entrypoint_hash, signed.hash_as_entrypoint());
        assert_eq!(prepared.encoded_len, expected_len);
        assert!(
            prepared
                .signed_bytes
                .as_ref()
                .is_some_and(|bytes| Arc::ptr_eq(bytes, &signed_bytes))
        );
        assert_eq!(accepted.clone().encoded_len(), expected_len);
        let cloned_bytes = accepted
            .clone()
            .signed_bytes()
            .expect("clone should preserve signed bytes");
        assert!(Arc::ptr_eq(&signed_bytes, &cloned_bytes));
    }
    #[test]
    fn single_ed25519_fast_path_requires_ed25519_key_and_signature_shape() {
        let (authority, keypair) = gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "ed25519-fast-path".into())])
        .sign(keypair.private_key());
        assert!(AcceptedTransaction::has_single_ed25519_signature(&signed));
        assert!(AcceptedTransaction::parsed_single_ed25519_key(&signed).is_some());
        let secp_keypair = checked_random_tx_keypair_with_algorithm(Algorithm::Secp256k1);
        let secp_authority = AccountId::new(secp_keypair.public_key().clone());
        let secp_signed = TransactionBuilder::new(
            test_network_id(),
            secp_authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "secp256k1-fast-path".into())])
        .sign(secp_keypair.private_key());
        assert!(!AcceptedTransaction::has_single_ed25519_signature(
            &secp_signed
        ));
        assert!(AcceptedTransaction::parsed_single_ed25519_key(&secp_signed).is_none());
        let mut short_signature_tx = signed.clone();
        let short_signature = iroha_crypto::Signature::from_bytes(&[0_u8; 1]);
        short_signature_tx.set_signature(TransactionSignature(
            iroha_crypto::SignatureOf::from_signature(short_signature),
        ));
        assert!(!AcceptedTransaction::has_single_ed25519_signature(
            &short_signature_tx
        ));
        assert!(AcceptedTransaction::parsed_single_ed25519_key(&short_signature_tx).is_none());
    }
    #[test]
    fn borrowed_external_entrypoint_hash_matches_canonical_hash() {
        let (authority, keypair) = gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "borrowed-hash".into())])
        .sign(keypair.private_key());
        assert_eq!(
            AcceptedTransaction::external_entrypoint_hash_from_signed(&signed),
            signed.hash_as_entrypoint()
        );
    }
    #[test]
    fn signed_frame_entrypoint_hash_matches_canonical_hash() {
        let (authority, keypair) = gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "signed-frame-hash".into())])
        .sign(keypair.private_key());
        let signed_bytes =
            norito::encode_canonical(&signed).expect("signed transaction encodes canonically");
        assert_eq!(
            AcceptedTransaction::external_entrypoint_hash_from_signed_frame(&signed_bytes)
                .expect("signed frame hashes"),
            signed.hash_as_entrypoint()
        );
        let mut corrupted = signed_bytes.clone();
        let payload_start = norito::core::Header::SIZE
            + AcceptedTransaction::framed_padding_for::<SignedTransaction>();
        corrupted[payload_start] ^= 0x01;
        assert!(matches!(
            AcceptedTransaction::external_entrypoint_hash_from_signed_frame(&corrupted),
            Err(norito::core::Error::ChecksumMismatch)
        ));
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&signed).expect("encode alternate-layout signed transaction")
        };
        assert_ne!(alternate, signed_bytes);
        norito::decode_from_bytes::<SignedTransaction>(&alternate)
            .expect("ordinary Norito accepts its advertised layout");
        assert!(matches!(
            AcceptedTransaction::external_entrypoint_hash_from_signed_frame(&alternate),
            Err(norito::core::Error::NonCanonicalEncoding)
        ));
    }
    #[test]
    fn prepared_governance_transaction_hash_matches_canonical_entrypoint_hash() {
        let (authority, keypair) = gen_account_in("wonderland");
        let manifest = RuntimeUpgradeManifest {
            name: "runtime.upgrade.hash.test".into(),
            description: "runtime upgrade hash fixture".into(),
            abi_version: 1,
            abi_hash: [7; 32],
            added_syscalls: Vec::new(),
            added_pointer_types: Vec::new(),
            start_height: 42,
            end_height: 84,
            sbom_digests: Vec::new(),
            slsa_attestation: Vec::new(),
            provenance: Vec::new(),
        };
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([ProposeRuntimeUpgradeProposal { manifest }])
        .sign(keypair.private_key());
        let prepared = AcceptedTransaction::prepare_signed_metadata(&signed);
        assert_eq!(prepared.entrypoint_hash, signed.hash_as_entrypoint());
        assert_eq!(prepared.signed_hash, signed.hash());
    }
    #[test]
    fn accept_with_canonical_signed_bytes_reuses_payload_cache() {
        let (authority, keypair) = gen_account_in("wonderland");
        // This test exercises live ingress, so creation must use its network clock.
        let time_source = TimeSource::new_fixed(super::current_unix_time());
        let signed = TransactionBuilder::new_with_time_source(
            test_network_id(),
            authority,
            &time_source,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "canonical-cache".into())])
        .sign(keypair.private_key());
        let (signed_payload, signed_payload_flags) =
            AcceptedTransaction::canonical_signed_payload_with_flags(&signed);
        let signed_bytes = Arc::new(
            norito::core::frame_bare_with_header_flags::<SignedTransaction>(
                &signed_payload,
                signed_payload_flags,
            )
            .expect("signed transaction encodes"),
        );
        let expected_entrypoint_bytes = Arc::new(
            norito::encode_canonical(&TransactionEntrypoint::External(signed.clone()))
                .expect("external entrypoint encodes canonically"),
        );
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let accepted = AcceptedTransaction::accept_with_canonical_signed_bytes(
            signed,
            Arc::clone(&signed_bytes),
            &test_network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
        )
        .expect("accepted transaction");
        let cached = accepted.signed_bytes().expect("canonical bytes cached");
        assert!(Arc::ptr_eq(&cached, &signed_bytes));
        assert_eq!(
            accepted.entrypoint_bytes().as_slice(),
            expected_entrypoint_bytes.as_slice()
        );
    }
    #[test]
    fn decoded_versioned_signed_transaction_prepares_exact_length_from_payload() {
        let (authority, keypair) = gen_account_in("wonderland");
        // This test exercises live ingress, so creation must use its network clock.
        let time_source = TimeSource::new_fixed(super::current_unix_time());
        let signed = TransactionBuilder::new_with_time_source(
            test_network_id(),
            authority,
            &time_source,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "versioned-cache".into())])
        .sign(keypair.private_key());
        let expected_len = norito::to_bytes(&signed)
            .expect("signed transaction encodes")
            .len();
        let expected_entrypoint_bytes =
            norito::encode_canonical(&TransactionEntrypoint::External(signed.clone()))
                .expect("entrypoint transaction encodes canonically");
        let versioned =
            <SignedTransaction as iroha_version::codec::EncodeVersioned>::encode_versioned(&signed);
        let decoded = DecodedVersionedSignedTransaction::decode_versioned(&versioned)
            .expect("versioned signed transaction decodes");
        assert_eq!(decoded.hash(), signed.hash());
        assert_eq!(decoded.hash_as_entrypoint(), signed.hash_as_entrypoint());
        assert_eq!(decoded.encoded_len(), expected_len);
        assert_eq!(decoded.prepared.encoded_len, expected_len);
        assert_eq!(
            decoded
                .prepared
                .signed_bytes
                .as_ref()
                .expect("canonical signed bytes are seeded from ingress")
                .as_slice(),
            norito::encode_canonical(&signed).unwrap().as_slice()
        );
        assert_eq!(
            decoded
                .prepared
                .entrypoint_bytes
                .as_ref()
                .expect("canonical entrypoint bytes are seeded from ingress")
                .as_slice(),
            expected_entrypoint_bytes.as_slice()
        );
        assert_eq!(decoded.prepared.payload_hash, HashOf::new(signed.payload()));
        assert!(decoded.prepared.single_ed25519_key.is_some());
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let accepted = decoded
            .into_accepted(&test_network_id(), Duration::ZERO, limits, &crypto_cfg)
            .expect("decoded transaction accepts");
        assert_eq!(
            Hash::from(accepted.hash_as_entrypoint()),
            Hash::from(signed.hash())
        );
        assert_eq!(accepted.hash_as_entrypoint(), signed.hash_as_entrypoint());
        assert_eq!(accepted.encoded_len(), expected_len);
        assert_eq!(
            accepted.entrypoint_bytes().as_slice(),
            expected_entrypoint_bytes.as_slice()
        );
        assert_eq!(accepted.payload_hash(), Some(HashOf::new(signed.payload())));
        assert!(accepted.single_ed25519_key().is_some());
    }
    #[test]
    fn decoded_versioned_signed_transaction_preserves_exact_confidential_payload_metadata() {
        let (authority, keypair) = gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(
            iroha_data_model::isi::zk::VerifyProof::new(ProofAttachment::new_ref(
                "halo2/ipa".into(),
                ProofBox::new("halo2/ipa".into(), vec![8; 192]),
                VerifyingKeyId::new("halo2/ipa", "adaptive-zk-proof"),
            )),
        )])
        .sign(keypair.private_key());
        let actual_payload_len = norito::codec::Encode::encode(&signed).len();
        assert_eq!(
            norito::core::SerializePayload::encoded_len_exact(&signed),
            Some(actual_payload_len),
            "the first-release confidential transaction layout must advertise its exact payload length"
        );
        let canonical_len = norito::to_bytes(&signed)
            .expect("signed transaction encodes")
            .len();
        let versioned =
            <SignedTransaction as iroha_version::codec::EncodeVersioned>::encode_versioned(&signed);
        assert_eq!(versioned.len().saturating_sub(1), actual_payload_len);
        assert_eq!(
            AcceptedTransaction::signed_encoded_len(&signed),
            canonical_len
        );
        let decoded = DecodedVersionedSignedTransaction::decode_versioned(&versioned)
            .expect("versioned signed transaction decodes");
        assert_eq!(decoded.signed(), &signed);
        assert_eq!(
            AcceptedTransaction::external_entrypoint_hash_from_signed(&signed),
            signed.hash_as_entrypoint()
        );
        assert_eq!(decoded.hash(), signed.hash());
        assert_eq!(decoded.hash_as_entrypoint(), signed.hash_as_entrypoint());
        assert_eq!(decoded.encoded_len(), canonical_len);
        assert_eq!(decoded.prepared.encoded_len, canonical_len);
        assert!(
            decoded.prepared.signed_bytes.is_some(),
            "canonical confidential ingress payload should seed signed bytes"
        );
        assert!(
            decoded.prepared.entrypoint_bytes.is_some(),
            "canonical confidential ingress payload should seed entrypoint bytes"
        );
    }
    #[test]
    fn decoded_versioned_signed_transaction_owned_supports_ed25519_prechecked_accept() {
        let (authority, keypair) = gen_account_in("wonderland");
        // This test exercises live ingress, so creation must use its network clock.
        let time_source = TimeSource::new_fixed(super::current_unix_time());
        let signed = TransactionBuilder::new_with_time_source(
            test_network_id(),
            authority,
            &time_source,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "versioned-owned-precheck".into())])
        .sign(keypair.private_key());
        let expected_len = norito::to_bytes(&signed)
            .expect("signed transaction encodes")
            .len();
        let versioned =
            <SignedTransaction as iroha_version::codec::EncodeVersioned>::encode_versioned(&signed);
        let decoded = DecodedVersionedSignedTransaction::decode_versioned_owned(versioned)
            .expect("owned versioned signed transaction decodes");
        let (message, signature, _public_key) = decoded
            .single_ed25519_precheck_parts()
            .expect("single Ed25519 transaction exposes precheck parts");
        assert_eq!(message, HashOf::new(signed.payload()).as_ref().as_slice());
        assert_eq!(signature, signed.signature().payload().payload());
        assert_eq!(decoded.encoded_len(), expected_len);
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let accepted = decoded
            .into_accepted_after_single_ed25519_precheck(
                &test_network_id(),
                Duration::ZERO,
                limits,
                &crypto_cfg,
            )
            .expect("prechecked decoded transaction accepts");
        assert_eq!(
            Hash::from(accepted.hash_as_entrypoint()),
            Hash::from(signed.hash())
        );
        assert_eq!(accepted.encoded_len(), expected_len);
    }
    #[test]
    fn every_prechecked_signature_path_rejects_invalid_fee_intent() {
        let (authority, keypair) = gen_account_in("wonderland");
        let mut metadata = Metadata::default();
        metadata.insert(
            "fee_sponsor".parse().expect("valid metadata key"),
            Json::new("retired".to_owned()),
        );
        let builder = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "invalid fee intent".into())])
        .with_metadata(metadata);
        let signature = Signature::try_new(keypair.private_key(), &builder.payload_hash_bytes())
            .expect("fixture signature");
        let signed = builder.build_with_signature(signature);
        let prepared = AcceptedTransaction::prepare_signed_metadata(&signed);
        let crypto = iroha_config::parameters::actual::Crypto::default();
        let now = signed.creation_time();
        let assert_rejected = |result: Result<(), AcceptTransactionFail>, path: &str| {
            let error = result.expect_err(path);
            match error {
                AcceptTransactionFail::SignatureVerification(failure) => {
                    assert_eq!(failure.code(), SignatureRejectionCode::MalformedSignature);
                    assert!(
                        failure.detail.contains("fee_sponsor"),
                        "{path} returned an unrelated rejection: {failure}"
                    );
                }
                other => panic!("{path} returned an unrelated rejection: {other:?}"),
            }
        };
        assert_rejected(
            AcceptedTransaction::validate_with_now_with_signature_result_and_prepared_metadata(
                &signed,
                &test_network_id(),
                Duration::ZERO,
                TransactionParameters::default(),
                &crypto,
                now,
                Some(Ok(())),
                &prepared,
            ),
            "batch signature override",
        );
        assert_rejected(
            AcceptedTransaction::validate_with_now_after_single_ed25519_precheck_and_prepared_metadata(
                &signed,
                &test_network_id(),
                Duration::ZERO,
                TransactionParameters::default(),
                &crypto,
                now,
                &prepared,
            ),
            "single Ed25519 precheck",
        );
        assert_rejected(
            AcceptedTransaction::validate_with_now_and_prepared_metadata(
                &signed,
                &test_network_id(),
                Duration::ZERO,
                TransactionParameters::default(),
                &crypto,
                now,
                &prepared,
            ),
            "prepared deterministic verification",
        );
    }
    #[test]
    fn decoded_versioned_signed_transaction_rejects_malformed_payloads() {
        let (authority, keypair) = gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "versioned-reject".into())])
        .sign(keypair.private_key());
        let mut versioned =
            <SignedTransaction as iroha_version::codec::EncodeVersioned>::encode_versioned(&signed);
        assert!(DecodedVersionedSignedTransaction::decode_versioned(&[]).is_err());
        let mut unsupported = versioned.clone();
        unsupported[0] = 0x7f;
        assert!(DecodedVersionedSignedTransaction::decode_versioned(&unsupported).is_err());
        versioned.push(0);
        assert!(DecodedVersionedSignedTransaction::decode_versioned(&versioned).is_err());
    }
    fn accepted_hash_carriers() -> [TransactionEntrypoint; 3] {
        let (authority, keypair) = gen_account_in("wonderland");
        let mut builder = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "original carrier identity".into())]);
        builder.set_creation_time(Duration::from_millis(1_000));
        let signed = builder.sign(keypair.private_key());
        let salt = [0x59; 32];
        let deadline = 9;
        let commitment_hash =
            compute_sealed_transaction_commitment(&test_network_id(), &signed, salt, deadline);
        let commitment = SignedSealedTransactionCommitment::sign(
            SealedTransactionCommitmentPayload::new(
                test_network_id(),
                authority,
                commitment_hash,
                2,
                deadline,
                None,
            ),
            keypair.private_key(),
        );
        [
            TransactionEntrypoint::External(signed.clone()),
            TransactionEntrypoint::SealedCommitment(commitment),
            TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
                commitment_hash,
                signed,
                salt,
            )),
        ]
    }

    #[test]
    fn accepted_and_checked_hashes_preserve_each_original_complete_carrier() {
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        for entrypoint in accepted_hash_carriers() {
            let expected = entrypoint.hash();
            let bytes = Arc::new(norito::encode_canonical(&entrypoint).unwrap());
            let borrowed =
                AcceptedTransaction::new_unchecked_entrypoint(Cow::Borrowed(&entrypoint));
            assert!(std::ptr::eq(borrowed.entrypoint(), &raw const entrypoint));
            assert_eq!(borrowed.hash_as_entrypoint(), expected);
            let admitted = AcceptedTransaction::accept_entrypoint_at_time(
                entrypoint.clone(),
                &test_network_id(),
                Duration::ZERO,
                TransactionParameters::default(),
                &iroha_config::parameters::actual::Crypto::default(),
                Duration::from_millis(1_000),
            )
            .expect("each original carrier passes its actual signature and network checks");
            assert_eq!(admitted.hash_as_entrypoint(), expected);
            assert_eq!(admitted.entrypoint(), &entrypoint);
            let cached = AcceptedTransaction::from_entrypoint_with_cached_entrypoint_bytes(
                admitted.into_entrypoint(),
                Arc::clone(&bytes),
                expected,
            );
            assert_eq!(cached.hash_as_entrypoint(), expected);
            assert!(Arc::ptr_eq(&cached.entrypoint_bytes(), &bytes));
            let checked = cached
                .clone()
                .into_checked(&state.view())
                .expect("the blank ledger contains none of these original carriers");
            assert_eq!(checked.hash_as_entrypoint(), expected);
            assert!(Arc::ptr_eq(&checked.entrypoint_bytes(), &bytes));
            assert_eq!(checked.into_accepted().into_entrypoint(), entrypoint);
            assert_eq!(cached.entrypoint_bytes().as_slice(), bytes.as_slice());
            if let TransactionEntrypoint::SealedReveal(reveal) = &entrypoint {
                assert_ne!(expected, reveal.signed_transaction().hash_as_entrypoint());
                assert_eq!(
                    entrypoint.execution_call_hash(),
                    reveal.signed_transaction().hash_as_entrypoint()
                );
            }
        }
    }

    #[test]
    fn accepted_signed_metadata_requires_an_original_external_carrier() {
        for entrypoint in accepted_hash_carriers() {
            let accepted =
                AcceptedTransaction::new_unchecked_entrypoint(Cow::Owned(entrypoint.clone()));
            let frame = accepted.entrypoint_bytes();
            let identity = accepted.hash_as_entrypoint();
            let prepared = accepted.prepared_metadata();
            let cache = accepted.stateless_cache_metadata();
            match &entrypoint {
                TransactionEntrypoint::External(signed) => {
                    let prepared = prepared.expect("the original External has signed metadata");
                    let cache = cache.expect("the original External has signed cache metadata");
                    for metadata in [&prepared, &cache] {
                        assert_eq!(metadata.signed_hash, signed.hash());
                        assert_eq!(metadata.entrypoint_hash, signed.hash_as_entrypoint());
                        assert_eq!(
                            metadata.stateless_cache_key,
                            StatelessValidationCacheKey::new(signed)
                        );
                        assert_eq!(metadata.payload_hash, HashOf::new(signed.payload()));
                        assert_eq!(
                            metadata.encoded_len,
                            norito::encode_canonical(signed).unwrap().len()
                        );
                    }
                    assert!(Arc::ptr_eq(
                        prepared.entrypoint_bytes.as_ref().unwrap(),
                        &frame
                    ));
                    assert!(Arc::ptr_eq(
                        prepared.signed_bytes.as_ref().unwrap(),
                        &accepted.signed_bytes().unwrap()
                    ));
                    assert!(cache.entrypoint_bytes.is_none());
                    assert!(cache.signed_bytes.is_none());
                }
                TransactionEntrypoint::SealedCommitment(_)
                | TransactionEntrypoint::SealedReveal(_) => {
                    assert!(
                        prepared.is_none(),
                        "sealed carrier metadata must not be labeled as an External signed frame"
                    );
                    assert!(cache.is_none());
                    assert!(accepted.signed_bytes.get().is_none());
                    assert!(accepted.payload_hash.get().is_none());
                    assert!(accepted.single_ed25519_key.get().is_none());
                    if let TransactionEntrypoint::SealedReveal(reveal) = &entrypoint {
                        assert_eq!(accepted.external(), Some(reveal.signed_transaction()));
                        assert_ne!(identity, reveal.signed_transaction().hash_as_entrypoint());
                    }
                }
            }
            assert_eq!(accepted.entrypoint(), &entrypoint);
            assert_eq!(accepted.hash_as_entrypoint(), identity);
            assert!(Arc::ptr_eq(&accepted.entrypoint_bytes(), &frame));
            assert_eq!(
                frame.as_slice(),
                norito::encode_canonical(&entrypoint).unwrap()
            );
        }
    }

    #[test]
    fn accepted_transaction_entrypoint_encoded_lengths_match_norito_frames() {
        let (authority, keypair) = gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "entrypoint-len".into())])
        .sign(keypair.private_key());
        let signed_expected_len = norito::encode_canonical(&signed)
            .expect("signed transaction encodes")
            .len();
        assert_eq!(
            AcceptedTransaction::framed_encoded_len(&signed),
            signed_expected_len
        );
        assert_eq!(
            AcceptedTransaction::new_unchecked(Cow::Owned(signed.clone())).encoded_len(),
            signed_expected_len
        );
        assert_eq!(
            AcceptedTransaction::new_unchecked_entrypoint(Cow::Owned(
                TransactionEntrypoint::External(signed.clone())
            ))
            .encoded_len(),
            signed_expected_len
        );
        let salt = [0x46; 32];
        let deadline = 9;
        let commitment_hash =
            compute_sealed_transaction_commitment(&test_network_id(), &signed, salt, deadline);
        let commitment = SignedSealedTransactionCommitment::sign(
            SealedTransactionCommitmentPayload::new(
                test_network_id(),
                authority,
                commitment_hash,
                2,
                deadline,
                None,
            ),
            keypair.private_key(),
        );
        commitment
            .verify_signature()
            .expect("real commitment signature");
        let reveal = SealedTransactionReveal::new(commitment_hash, signed.clone(), salt);
        let cases = [
            (
                TransactionEntrypoint::SealedCommitment(commitment.clone()),
                AcceptedTransaction::bare_encoded_len(&commitment),
                AcceptedTransaction::framed_encoded_len(&commitment),
            ),
            (
                TransactionEntrypoint::SealedReveal(reveal.clone()),
                AcceptedTransaction::bare_encoded_len(&reveal),
                AcceptedTransaction::framed_encoded_len(&reveal),
            ),
        ];
        for (entrypoint, payload_len, accounted_len) in cases {
            let frame = norito::encode_canonical(&entrypoint).expect("sealed Network frame");
            assert_eq!(
                norito::decode_canonical::<TransactionEntrypoint>(&frame)
                    .expect("current sealed entrypoint roundtrip"),
                entrypoint,
            );
            assert_eq!(
                AcceptedTransaction::framed_encoded_len(&entrypoint),
                frame.len()
            );
            let view = norito::core::from_bytes_view(&frame).expect("sealed frame envelope");
            let (child_len, prefix_len) =
                norito::core::read_len_from_slice_with_flags(&view.as_bytes()[4..], view.flags())
                    .expect("sealed variant field length");
            assert_eq!(4 + prefix_len + child_len, view.as_bytes().len());
            assert_eq!(payload_len, child_len);
            let accepted =
                AcceptedTransaction::new_unchecked_entrypoint(Cow::Borrowed(&entrypoint));
            assert_eq!(accepted.encoded_len(), accounted_len);
            assert_eq!(accepted.hash_as_entrypoint(), entrypoint.hash());
            let authenticated = AcceptedTransaction::accept_entrypoint_at_time(
                entrypoint.clone(),
                &test_network_id(),
                Duration::ZERO,
                TransactionParameters::default(),
                &iroha_config::parameters::actual::Crypto::default(),
                signed.creation_time(),
            )
            .expect("the supported sealed source passes real stateless admission");
            assert_eq!(authenticated.encoded_len(), accounted_len);
            assert_eq!(authenticated.hash_as_entrypoint(), entrypoint.hash());
            assert_eq!(
                authenticated.validation_time(),
                Some(signed.creation_time())
            );
        }
    }
    #[test]
    fn signed_encoded_len_matches_norito_for_optional_metadata_shapes() {
        let (authority, keypair) = gen_account_in("wonderland");
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("signed-len-tag").expect("name"),
            Json::from("cached"),
        );
        let mut builder = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "signed-len".into())])
        .with_metadata(metadata);
        builder.set_nonce(NonZeroU32::new(7).expect("nonce"));
        builder.set_ttl(Duration::from_millis(5_000));
        let signed = builder.sign(keypair.private_key());
        let expected_len = norito::to_bytes(&signed)
            .expect("signed transaction encodes")
            .len();
        assert!(
            norito::SerializePayload::encoded_len_exact(&signed).is_some(),
            "representative signed transaction should have an exact encoded length"
        );
        assert_eq!(
            AcceptedTransaction::signed_encoded_len(&signed),
            expected_len
        );
        let prepared = AcceptedTransaction::prepare_signed_metadata(&signed);
        assert_eq!(prepared.encoded_len, expected_len);
    }
    #[test]
    fn prepared_metadata_depth_matches_direct_depth_check() {
        let (authority, keypair) = gen_account_in("wonderland");
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("depth").expect("name"),
            Json::from_str_norito("[[[1]]]").expect("valid nested json"),
        );
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "prepared-depth".into())])
        .with_metadata(metadata)
        .sign(keypair.private_key());
        let prepared = AcceptedTransaction::prepare_signed_metadata(&signed);
        ensure_metadata_depth_with_prepared(signed.metadata(), 4, Some(&prepared))
            .expect("prepared metadata depth should accept equal max depth");
        assert_eq!(
            ensure_metadata_depth_with_prepared(signed.metadata(), 3, Some(&prepared))
                .expect_err("prepared metadata depth should reject too deep metadata"),
            ensure_metadata_depth(signed.metadata(), 3)
                .expect_err("direct metadata depth should reject too deep metadata")
        );
    }
    #[test]
    fn gossip_signed_metadata_matches_canonical_preparation() {
        let (authority, keypair) = gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "gossip-metadata".into())])
        .sign(keypair.private_key());
        let entrypoint = TransactionEntrypoint::External(signed.clone());
        let entrypoint_bytes =
            norito::encode_canonical(&entrypoint).expect("entrypoint transaction encodes");
        let expected = AcceptedTransaction::prepare_signed_metadata(&signed);
        let actual = AcceptedTransaction::prepare_gossip_signed_metadata(
            &signed,
            entrypoint.hash(),
            Arc::new(entrypoint_bytes.clone()),
        );
        assert_eq!(actual.signed_hash, expected.signed_hash);
        assert_eq!(actual.entrypoint_hash, expected.entrypoint_hash);
        assert_eq!(actual.payload_hash, expected.payload_hash);
        assert_eq!(actual.encoded_len, expected.encoded_len);
        assert!(actual.signed_bytes.is_none());
        assert_eq!(
            actual
                .entrypoint_bytes
                .as_ref()
                .expect("gossip metadata keeps canonical entrypoint bytes")
                .as_slice(),
            entrypoint_bytes.as_slice()
        );
        assert_eq!(
            actual.single_ed25519_key.is_some(),
            expected.single_ed25519_key.is_some()
        );
    }
    #[test]
    fn signed_length_from_entrypoint_frame_checks_owner_tag_and_bounds() {
        let (authority, keypair) = gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "external frame length".into())])
        .sign(keypair.private_key());
        let signed_frame = norito::encode_canonical(&signed).expect("signed frame");
        let frame = norito::encode_canonical(&TransactionEntrypoint::External(signed.clone()))
            .expect("external entrypoint frame");
        let length = AcceptedTransaction::signed_encoded_len_from_external_entrypoint_frame;
        assert_eq!(
            length(&frame).expect("exact external frame length"),
            signed_frame.len()
        );
        assert!(matches!(
            length(&signed_frame),
            Err(norito::Error::SchemaMismatch)
        ));
        assert!(length(&frame[..norito::core::Header::SIZE - 1]).is_err());
        assert!(length(&frame[..frame.len() - 1]).is_err());
        let view = norito::core::from_bytes_view(&frame).expect("valid external frame envelope");
        let payload = view.as_bytes();
        let truncated_child = norito::core::frame_bare_with_header_flags::<TransactionEntrypoint>(
            &payload[..payload.len() - 1],
            view.flags(),
        )
        .expect("frame truncated child with valid current-owner envelope and checksum");
        norito::core::from_bytes_view(&truncated_child)
            .expect("truncated child still has a valid frame envelope");
        assert!(matches!(
            length(&truncated_child),
            Err(norito::Error::LengthMismatch)
        ));
        let salt = [0x47; 32];
        let commitment_hash =
            compute_sealed_transaction_commitment(&test_network_id(), &signed, salt, 9);
        let reveal = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            commitment_hash,
            signed,
            salt,
        ));
        let reveal_frame = norito::encode_canonical(&reveal).expect("current non-external frame");
        assert!(matches!(
            length(&reveal_frame),
            Err(norito::Error::Message(message))
                if message == "gossip entrypoint frame does not contain an external signed transaction"
        ));
    }
    #[test]
    fn retired_time_entrypoint_frame_is_rejected_before_identity_or_admission() {
        // Negative bytes only: internal invocations have no Network ingress type.
        #[derive(norito::Encode, norito::NoritoSchema)]
        #[norito_schema(name = "iroha_data_model::trigger::time::TimeTriggerEntrypoint")]
        struct RetiredTimeEntrypoint {
            id: TriggerId,
            instructions: ExecutionStep,
            authority: AccountId,
        }
        #[derive(norito::Encode, norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_data_model::transaction::signed::model::TransactionEntrypoint"
        )]
        enum RetiredNetworkTime {
            #[codec(index = 3)]
            Time(RetiredTimeEntrypoint),
        }
        let (authority, _) = gen_account_in("retired-time-network-frame");
        let frame = norito::encode_canonical(&RetiredNetworkTime::Time(RetiredTimeEntrypoint {
            id: "retired-time-network-frame".parse().expect("trigger id"),
            instructions: ExecutionStep(ConstVec::from(Vec::<InstructionBox>::new())),
            authority,
        }))
        .expect("encode retired fixture bytes");
        norito::core::from_bytes_view(&frame).expect("valid envelope and current owner identity");
        assert!(norito::decode_canonical::<TransactionEntrypoint>(&frame).is_err());
        assert!(entrypoint_hash_from_framed_bytes(&frame).is_err());
        assert!(matches!(
            AcceptedTransaction::signed_encoded_len_from_external_entrypoint_frame(&frame),
            Err(norito::Error::Message(message))
                if message == "gossip entrypoint frame does not contain an external signed transaction"
        ));
    }
    #[test]
    fn signed_encoded_len_for_limit_uses_cached_canonical_bytes() {
        let (authority, keypair) = gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "signed-len-cache".into())])
        .sign(keypair.private_key());
        let signed_bytes = Arc::new(norito::to_bytes(&signed).expect("signed transaction encodes"));
        let mut prepared = AcceptedTransaction::prepare_signed_metadata(&signed);
        prepared.encoded_len = usize::MAX;
        prepared.signed_bytes = Some(Arc::clone(&signed_bytes));
        assert_eq!(
            AcceptedTransaction::signed_encoded_len_for_limit_with_prepared(
                &signed,
                Some(&prepared)
            ),
            u64::try_from(signed_bytes.len()).expect("length fits in u64")
        );
    }
    #[test]
    fn fraud_policy_allows_when_disabled() {
        let cfg = iroha_config::parameters::actual::FraudMonitoring::default();
        let metadata = Metadata::default();
        let catalog = DataSpaceCatalog::default();
        let assignment = single_lane_assignment(&catalog);
        assert!(super::enforce_fraud_policy(&cfg, &metadata, None, &assignment).is_ok());
    }
    #[test]
    fn fraud_policy_rejects_missing_assessment() {
        let cfg = iroha_config::parameters::actual::FraudMonitoring {
            policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
                enabled: true,
                required_minimum_band: Some(iroha_data_model::fraud::FraudRiskBandV1::High),
                ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
            },
            ..Default::default()
        };
        let metadata = iroha_model_base::metadata::Metadata::default();
        let catalog = DataSpaceCatalog::default();
        let assignment = single_lane_assignment(&catalog);
        let result = super::enforce_fraud_policy(&cfg, &metadata, None, &assignment);
        assert!(matches!(
            result,
            Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(_)
            ))
        ));
    }
    #[test]
    fn accept_with_time_source_uses_mock_clock() {
        let (authority, keypair) = gen_account_in("wonderland");
        let (handle, time_source) = TimeSource::new_mock(Duration::from_secs(5));
        let mut builder = TransactionBuilder::new_with_time_source(
            test_network_id(),
            authority.clone(),
            &time_source,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "ttl ok".to_owned())])
        .with_metadata(Metadata::default());
        builder.set_ttl(Duration::from_secs(10));
        let signed = builder.sign(keypair.private_key());
        let default_limits = TransactionParameters::default();
        let tx_limits = TransactionParameters::with_max_signatures(
            nonzero!(1_u64),
            nonzero!(16_u64),
            nonzero!(2048_u64),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        );
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        handle.advance(Duration::from_secs(1));
        let accepted = AcceptedTransaction::accept_with_time_source(
            signed.clone(),
            &test_network_id(),
            Duration::from_secs(0),
            tx_limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("transaction should be accepted with mock clock");
        assert_eq!(accepted.validation_time(), Some(Duration::from_secs(6)));
        handle.set(Duration::from_secs(15));
        let accepted = AcceptedTransaction::accept_with_time_source(
            signed.clone(),
            &test_network_id(),
            Duration::ZERO,
            tx_limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("the exact signed TTL boundary remains valid");
        assert_eq!(accepted.validation_time(), Some(Duration::from_secs(15)));
        handle.advance(Duration::from_millis(1));
        let err = AcceptedTransaction::accept_with_time_source(
            signed.clone(),
            &test_network_id(),
            Duration::ZERO,
            tx_limits,
            &crypto_cfg,
            &time_source,
        )
        .expect_err("one millisecond past the signed TTL must expire");
        assert_eq!(
            err,
            AcceptTransactionFail::TransactionExpired {
                expires_at_ms: 15_000,
                now_ms: 15_001,
            }
        );
        let err = AcceptedTransaction::accept(
            signed,
            &test_network_id(),
            Duration::from_secs(0),
            tx_limits,
            &crypto_cfg,
        )
        .expect_err("network admission clock should see TTL expired relative to mock timestamp");
        assert!(matches!(
            err,
            AcceptTransactionFail::TransactionExpired { .. }
        ));
    }
    #[test]
    fn stateless_admission_rejects_missing_signature_bound_ttl() {
        let (authority, keypair) = gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "required ttl".to_owned())])
        .sign(keypair.private_key());
        let encoded = norito::json::to_json(&signed).expect("serialize transaction");
        let ttl_field = format!(
            "\"time_to_live_ms\":{}",
            iroha_data_model::transaction::DEFAULT_TRANSACTION_TIME_TO_LIVE.as_millis()
        );
        assert!(
            encoded.contains(&ttl_field),
            "fixture must carry the builder's signature-bound TTL: {encoded}"
        );
        let malformed_json = encoded.replacen(&ttl_field, "\"time_to_live_ms\":null", 1);
        let malformed: SignedTransaction =
            norito::json::from_str(&malformed_json).expect("decode malformed wire fixture");
        let error = AcceptedTransaction::validate_with_now(
            &malformed,
            &test_network_id(),
            Duration::ZERO,
            TransactionParameters::default(),
            &iroha_config::parameters::actual::Crypto::default(),
            malformed.creation_time(),
        )
        .expect_err("missing TTL must never be stateless-valid");
        match error {
            AcceptTransactionFail::TransactionLimit(limit) => assert!(
                limit.reason.contains("time_to_live_ms") && limit.reason.contains("required"),
                "unexpected missing-TTL reason: {limit:?}"
            ),
            other => panic!("expected TransactionLimit for missing TTL, got {other:?}"),
        }
    }
    #[test]
    fn stateless_admission_enforces_governed_maximum_ttl() {
        let (authority, keypair) = gen_account_in("wonderland");
        let mut builder = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "bounded ttl".to_owned())]);
        builder.set_ttl(Duration::from_millis(5_001));
        let signed = builder.sign(keypair.private_key());
        let limits = TransactionParameters::default().with_max_time_to_live_ms(nonzero!(5_000_u64));
        let error = AcceptedTransaction::validate_with_now(
            &signed,
            &test_network_id(),
            Duration::ZERO,
            limits,
            &iroha_config::parameters::actual::Crypto::default(),
            signed.creation_time(),
        )
        .expect_err("TTL above the governed maximum must be rejected");
        match error {
            AcceptTransactionFail::TransactionLimit(limit) => assert!(
                limit.reason.contains("5001") && limit.reason.contains("5000"),
                "unexpected maximum-TTL reason: {limit:?}"
            ),
            other => panic!("expected TransactionLimit for excessive TTL, got {other:?}"),
        }
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn time_sensitive_instruction_detects_governance_and_non_sensitive() {
        let (authority, _keypair) = gen_account_in("wonderland");
        let (counterparty, _keypair) = gen_account_in("wonderland");
        let parliament_attempt =
            iroha_data_model::isi::governance::CreateParliamentGovernanceAttemptV1 {
                proposal: iroha_data_model::governance::types::ProposalKind::DeployContract(
                    iroha_data_model::governance::types::DeployContractProposal {
                        proposal_operator: authority.clone(),
                        contract_address: ContractAddress::derive(
                            &test_network_id(),
                            &authority,
                            1,
                            DataSpaceId::UNIVERSAL,
                        )
                        .expect("contract address"),
                        code_hash: iroha_data_model::governance::types::ContractCodeHash::new(
                            [1; 32],
                        ),
                        abi_hash: iroha_data_model::governance::types::ContractAbiHash::new(
                            [2; 32],
                        ),
                        abi_version: 1.into(),
                        manifest_provenance: None,
                    },
                ),
                attempt_sequence: 0,
            };
        let parliament_attempt_box = InstructionBox::from(parliament_attempt);
        assert!(super::is_time_sensitive_instruction(
            &parliament_attempt_box
        ));
        let standalone_ballot = iroha_data_model::isi::governance::CastPlainBallot {
            referendum_id: "standalone-ref-1".into(),
            owner: authority.clone(),
            amount: 1_u64.into(),
            duration_blocks: 1,
            direction: 0,
        };
        assert!(super::is_time_sensitive_instruction(&InstructionBox::from(
            standalone_ballot
        )));
        let agreement_id: iroha_data_model::repo::RepoAgreementId =
            "repo-1".parse().expect("repo id");
        let cash_leg = iroha_data_model::repo::RepoCashLeg {
            asset_definition_id: iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "usd".parse().unwrap(),
            ),
            quantity: 1u32.into(),
        };
        let collateral_leg = iroha_data_model::repo::RepoCollateralLeg::new(
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "bond".parse().unwrap(),
            ),
            1u32,
        );
        let governance = iroha_data_model::repo::RepoGovernance::with_defaults(100, 3600);
        let repo = iroha_data_model::isi::repo::RepoIsi::new(
            agreement_id.clone(),
            counterparty.clone(),
            authority.clone(),
            None,
            cash_leg.clone(),
            collateral_leg.clone(),
            250,
            1_700_000_000_000,
            governance,
        );
        assert!(super::is_time_sensitive_instruction(&InstructionBox::from(
            repo
        )));
        let reverse = iroha_data_model::isi::repo::ReverseRepoIsi::new(agreement_id.clone());
        assert!(super::is_time_sensitive_instruction(&InstructionBox::from(
            reverse
        )));
        let margin_call = iroha_data_model::isi::repo::RepoMarginCallIsi::new(agreement_id.clone());
        assert!(super::is_time_sensitive_instruction(&InstructionBox::from(
            margin_call
        )));
        let exit = iroha_data_model::isi::staking::ExitPublicLaneValidator {
            lane_id: TestLaneId::SINGLE,
            validator: counterparty.clone(),
            release_at_ms: 1_700_000_000_000,
        };
        assert!(super::is_time_sensitive_instruction(&InstructionBox::from(
            exit
        )));
        let request_id = iroha_crypto::Hash::new("unbond");
        let unbond = iroha_data_model::isi::staking::SchedulePublicLaneUnbond {
            lane_id: TestLaneId::SINGLE,
            validator: counterparty.clone(),
            staker: counterparty.clone(),
            request_id,
            amount: 1u32.into(),
            release_at_ms: 1_700_000_000_000,
        };
        assert!(super::is_time_sensitive_instruction(&InstructionBox::from(
            unbond
        )));
        let pending_unbond = iroha_data_model::nexus::PublicLaneUnbonding {
            request_id,
            amount: Quantity::one(),
            release_at_ms: 1_700_000_000_000,
            slashable_through_height: 1,
            liability_release_height: 2,
        };
        let stake_asset = cash_leg.asset_definition_id.clone();
        let finalize = iroha_data_model::isi::staking::FinalizePublicLaneUnbond {
            lane_id: TestLaneId::SINGLE,
            validator: counterparty.clone(),
            staker: counterparty.clone(),
            request_id,
            monetary_plan: iroha_data_model::nexus::PublicLaneMonetaryPlanV1 {
                network_scope: iroha_data_model::nexus::PublicLaneMonetaryScopeV1::Network(
                    test_network_id(),
                ),
                valid_until_height: 2,
                source_asset: AssetId::of(stake_asset.clone(), authority.clone()),
                destination_asset: AssetId::of(stake_asset, counterparty.clone()),
                amount: pending_unbond.amount.clone(),
                precondition: iroha_data_model::nexus::PublicLaneMonetaryPreconditionV1::Unbond(
                    iroha_data_model::nexus::PublicLaneMonetaryUnbondV1 {
                        activation_height: 1,
                        request_hash: iroha_data_model::nexus::public_lane_unbonding_commitment(
                            &pending_unbond,
                        )
                        .unwrap(),
                    },
                ),
            },
        };
        assert!(super::is_time_sensitive_instruction(&InstructionBox::from(
            finalize
        )));
        let settlement_id: iroha_data_model::isi::settlement::SettlementId =
            iroha_data_model::isi::SettlementId::new(
                authority.clone(),
                "settlement-1".parse().expect("settlement reference"),
            );
        let dvp = iroha_data_model::isi::settlement::DvpIsi::new(
            settlement_id.clone(),
            iroha_data_model::isi::settlement::SettlementLeg::new(
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "bond".parse().unwrap(),
                ),
                1u32,
                counterparty.clone(),
                authority.clone(),
            ),
            iroha_data_model::isi::settlement::SettlementLeg::new(
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "usd".parse().unwrap(),
                ),
                1u32,
                authority.clone(),
                counterparty.clone(),
            ),
            iroha_data_model::isi::settlement::SettlementPlan::default(),
        );
        assert!(super::is_time_sensitive_instruction(&InstructionBox::from(
            dvp
        )));
        let pvp = iroha_data_model::isi::settlement::PvpIsi::new(
            settlement_id,
            iroha_data_model::isi::settlement::SettlementLeg::new(
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "eur".parse().unwrap(),
                ),
                1u32,
                counterparty.clone(),
                authority.clone(),
            ),
            iroha_data_model::isi::settlement::SettlementLeg::new(
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "usd".parse().unwrap(),
                ),
                1u32,
                authority.clone(),
                counterparty.clone(),
            ),
            iroha_data_model::isi::settlement::SettlementPlan::default(),
        );
        assert!(super::is_time_sensitive_instruction(&InstructionBox::from(
            pvp
        )));
        let trigger_id: iroha_data_model::trigger::TriggerId =
            "nts-trigger".parse().expect("trigger id");
        let execute_trigger = iroha_data_model::isi::ExecuteTrigger::new(trigger_id);
        assert!(super::is_time_sensitive_instruction(&InstructionBox::from(
            execute_trigger
        )));
        let log_box = InstructionBox::from(Log::new(Level::INFO, "ok".into()));
        assert!(!super::is_time_sensitive_instruction(&log_box));
    }
    #[test]
    fn time_sensitive_instruction_detects_trigger_registration() {
        let (authority, _keypair) = gen_account_in("wonderland");
        let trigger_id: iroha_data_model::trigger::TriggerId =
            "nts-trigger-reg".parse().expect("trigger id");
        let exec_trigger_id: iroha_data_model::trigger::TriggerId =
            "nts-trigger-exec".parse().expect("trigger id");
        let action = iroha_data_model::trigger::action::Action::new(
            vec![InstructionBox::from(
                iroha_data_model::isi::ExecuteTrigger::new(exec_trigger_id),
            )],
            iroha_data_model::trigger::action::Repeats::Indefinitely,
            authority.clone(),
            iroha_data_model::events::EventFilterBox::ExecuteTrigger(
                iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter::new(),
            ),
        )
        .expect("trigger action fixture satisfies validation invariants");
        let trigger = iroha_data_model::trigger::Trigger::new(trigger_id, action);
        let register = iroha_data_model::isi::register::Register::trigger(trigger);
        let boxed = InstructionBox::from(register);
        assert!(super::is_time_sensitive_instruction(&boxed));
    }
    #[test]
    fn time_sensitive_instruction_marks_custom_instruction() {
        let custom = iroha_data_model::isi::CustomInstruction::new(Json::new("payload"));
        let boxed = InstructionBox::from(custom);
        assert!(super::is_time_sensitive_instruction(&boxed));
    }
    #[test]
    fn time_sensitive_type_table_covers_settlement_and_governance_operations() {
        let classified = [
            TypeId::of::<iroha_data_model::isi::private_settlement::ActivatePrivateSettlementPoolV1>(
            ),
            TypeId::of::<
                iroha_data_model::isi::private_settlement::RegisterAtomicPrivateSettlementPrepareV1,
            >(),
            TypeId::of::<iroha_data_model::isi::private_settlement::AbortAtomicPrivateSettlementV1>(
            ),
            TypeId::of::<
                iroha_data_model::isi::private_settlement::FinalizeAtomicPrivateSettlementV1,
            >(),
            TypeId::of::<ProposeRuntimeUpgrade>(),
            TypeId::of::<ActivateRuntimeUpgrade>(),
            TypeId::of::<CancelRuntimeUpgrade>(),
            TypeId::of::<iroha_data_model::isi::governance::ProposeRuntimeUpgradeProposal>(),
            TypeId::of::<iroha_data_model::isi::governance::ProposeSorafsProviderGovernance>(),
            TypeId::of::<
                iroha_data_model::isi::governance::ProposeGlobalDataTriggerPermissionGovernance,
            >(),
            TypeId::of::<iroha_data_model::isi::governance::ProposeValidationFeePolicy>(),
            TypeId::of::<iroha_data_model::isi::governance::ProposeValidationFeePayoutLifecycle>(),
        ];
        for type_id in classified {
            assert!(super::is_time_sensitive_instruction_type(type_id));
        }
        assert!(!super::is_time_sensitive_instruction_type(
            TypeId::of::<Log>()
        ));
    }
    #[test]
    fn time_sensitive_executable_detects_sensitive_and_safe() {
        let (authority, _keypair) = gen_account_in("wonderland");
        let attempt = iroha_data_model::isi::governance::CreateParliamentGovernanceAttemptV1 {
            proposal: iroha_data_model::governance::types::ProposalKind::DeployContract(
                iroha_data_model::governance::types::DeployContractProposal {
                    proposal_operator: authority.clone(),
                    contract_address: ContractAddress::derive(
                        &test_network_id(),
                        &authority,
                        2,
                        DataSpaceId::UNIVERSAL,
                    )
                    .expect("contract address"),
                    code_hash: iroha_data_model::governance::types::ContractCodeHash::new([3; 32]),
                    abi_hash: iroha_data_model::governance::types::ContractAbiHash::new([4; 32]),
                    abi_version: 1.into(),
                    manifest_provenance: None,
                },
            ),
            attempt_sequence: 0,
        };
        let sensitive = Executable::from(vec![InstructionBox::from(attempt)]);
        assert!(super::is_time_sensitive_executable(&sensitive));
        let safe = Executable::from(vec![InstructionBox::from(Log::new(
            Level::INFO,
            "ok".into(),
        ))]);
        assert!(!super::is_time_sensitive_executable(&safe));
        let ivm = Executable::Ivm(
            iroha_data_model::transaction::executable::IvmBytecode::from_compiled(vec![0xCA]),
        );
        assert!(super::is_time_sensitive_executable(&ivm));
        let proved = Executable::IvmProved(iroha_data_model::transaction::IvmProved {
            bytecode: iroha_data_model::transaction::executable::IvmBytecode::from_compiled(vec![
                0xCA,
            ]),
            overlay: Vec::<InstructionBox>::new().into(),
            events_commitment: Hash::new(b"events"),
            gas_policy_commitment: Hash::new(b"gas"),
        });
        assert!(
            super::is_time_sensitive_executable(&proved),
            "proved bytecode remains time-sensitive even with an empty overlay"
        );
        let runtime_upgrade = ProposeRuntimeUpgradeProposal {
            manifest: RuntimeUpgradeManifest {
                name: "runtime.upgrade.nts.test".into(),
                description: "NTS time-sensitive governance fixture".into(),
                abi_version: 1,
                abi_hash: [7; 32],
                added_syscalls: Vec::new(),
                added_pointer_types: Vec::new(),
                start_height: 42,
                end_height: 84,
                sbom_digests: Vec::new(),
                slsa_attestation: Vec::new(),
                provenance: Vec::new(),
            },
        };
        assert!(super::is_time_sensitive_instruction(&InstructionBox::from(
            runtime_upgrade
        )));
    }
    #[test]
    fn nts_enforcement_rejects_time_sensitive_when_unhealthy() {
        let (authority, keypair) = gen_account_in("wonderland");
        let attempt = iroha_data_model::isi::governance::CreateParliamentGovernanceAttemptV1 {
            proposal: iroha_data_model::governance::types::ProposalKind::DeployContract(
                iroha_data_model::governance::types::DeployContractProposal {
                    proposal_operator: authority.clone(),
                    contract_address: ContractAddress::derive(
                        &test_network_id(),
                        &authority,
                        3,
                        DataSpaceId::UNIVERSAL,
                    )
                    .expect("contract address"),
                    code_hash: iroha_data_model::governance::types::ContractCodeHash::new([5; 32]),
                    abi_hash: iroha_data_model::governance::types::ContractAbiHash::new([6; 32]),
                    abi_version: 1.into(),
                    manifest_provenance: None,
                },
            ),
            attempt_sequence: 0,
        };
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([attempt])
        .sign(keypair.private_key());
        let status = crate::time::NetworkTimeStatus {
            now: std::time::SystemTime::UNIX_EPOCH,
            offset_ms: 0,
            confidence_ms: 0,
            sample_count: 0,
            peer_count: 0,
            fallback: true,
            health: crate::time::NtsHealth {
                min_samples_ok: false,
                offset_ok: true,
                confidence_ok: true,
                healthy: false,
            },
        };
        let err = super::enforce_time_sensitive_with_nts(
            &tx,
            status,
            iroha_config::parameters::actual::NtsEnforcementMode::Reject,
        )
        .expect_err("unhealthy NTS should reject in reject mode");
        match err {
            AcceptTransactionFail::NetworkTimeUnhealthy { reason } => {
                assert!(reason.contains("fallback=true"));
                assert!(reason.contains("samples_used=0"));
            }
            other => panic!("expected NetworkTimeUnhealthy, got {other:?}"),
        }
        assert!(
            super::enforce_time_sensitive_with_nts(
                &tx,
                status,
                iroha_config::parameters::actual::NtsEnforcementMode::Warn,
            )
            .is_ok()
        );
    }
    #[test]
    fn nts_enforcement_rejects_low_level_runtime_upgrade_when_unhealthy() {
        let (authority, keypair) = gen_account_in("wonderland");
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([ProposeRuntimeUpgrade {
            manifest_bytes: vec![0xCA, 0xFE],
        }])
        .sign(keypair.private_key());
        let snapshot = crate::time::NetworkTimeAdmissionSnapshot {
            status: crate::time::NetworkTimeStatus {
                now: SystemTime::UNIX_EPOCH,
                offset_ms: 0,
                confidence_ms: 0,
                sample_count: 0,
                peer_count: 0,
                fallback: true,
                health: crate::time::NtsHealth {
                    min_samples_ok: false,
                    offset_ok: true,
                    confidence_ok: true,
                    healthy: false,
                },
            },
            enforcement_mode: iroha_config::parameters::actual::NtsEnforcementMode::Reject,
        };
        assert!(matches!(
            super::enforce_nts_health_for_time_sensitive(&tx, snapshot),
            Err(AcceptTransactionFail::NetworkTimeUnhealthy { .. })
        ));
    }
    #[test]
    fn nts_enforcement_skips_non_sensitive_transactions() {
        let (authority, keypair) = gen_account_in("wonderland");
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "ok".into())])
        .sign(keypair.private_key());
        assert!(
            super::enforce_nts_health_for_time_sensitive(&tx, crate::time::admission_snapshot(),)
                .is_ok()
        );
    }
    #[test]
    fn durable_replay_validation_does_not_reapply_live_nts_policy() {
        let (authority, keypair) = gen_account_in("wonderland");
        let trigger_id: iroha_data_model::trigger::TriggerId =
            "nts-replay-trigger".parse().expect("trigger id");
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([iroha_data_model::isi::ExecuteTrigger::new(trigger_id)])
        .sign(keypair.private_key());
        let validation_time = tx.creation_time();
        let reject_snapshot = crate::time::NetworkTimeAdmissionSnapshot {
            status: crate::time::NetworkTimeStatus {
                now: SystemTime::UNIX_EPOCH + validation_time,
                offset_ms: 0,
                confidence_ms: 0,
                sample_count: 0,
                peer_count: 0,
                fallback: true,
                health: crate::time::NtsHealth {
                    min_samples_ok: false,
                    offset_ok: true,
                    confidence_ok: true,
                    healthy: false,
                },
            },
            enforcement_mode: iroha_config::parameters::actual::NtsEnforcementMode::Reject,
        };
        assert!(matches!(
            super::enforce_nts_health_for_time_sensitive(&tx, reject_snapshot),
            Err(AcceptTransactionFail::NetworkTimeUnhealthy { .. })
        ));

        AcceptedTransaction::accept_entrypoint_at_time(
            TransactionEntrypoint::External(tx),
            &test_network_id(),
            Duration::ZERO,
            TransactionParameters::default(),
            &iroha_config::parameters::actual::Crypto::default(),
            validation_time,
        )
        .expect("durable replay must use the persisted admission instant without live NTS gating");
    }
    #[test]
    fn fraud_policy_rejects_insufficient_band() {
        use iroha_primitives::json::Json;
        let cfg = iroha_config::parameters::actual::FraudMonitoring {
            policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
                enabled: true,
                required_minimum_band: Some(iroha_data_model::fraud::FraudRiskBandV1::High),
                ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
            },
            ..Default::default()
        };
        let mut metadata = Metadata::default();
        let band_key = Name::from_str("fraud_assessment_band").expect("static name");
        metadata.insert(band_key, Json::new("medium"));
        let score_key = Name::from_str("fraud_assessment_score_bps").expect("static name");
        metadata.insert(score_key, Json::new(450_u64));
        let tenant_key = Name::from_str("fraud_assessment_tenant").expect("static name");
        metadata.insert(tenant_key, Json::new("tenant-eu"));
        let latency_key = Name::from_str("fraud_assessment_latency_ms").expect("static name");
        metadata.insert(latency_key, Json::new(120_u64));
        let catalog = DataSpaceCatalog::default();
        let assignment = single_lane_assignment(&catalog);
        let result = super::enforce_fraud_policy(&cfg, &metadata, None, &assignment);
        assert!(matches!(
            result,
            Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(_)
            ))
        ));
    }
    #[test]
    fn fraud_policy_accepts_sufficient_band() {
        use iroha_primitives::json::Json;
        let cfg = iroha_config::parameters::actual::FraudMonitoring {
            policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
                enabled: true,
                required_minimum_band: Some(iroha_data_model::fraud::FraudRiskBandV1::Medium),
                ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
            },
            ..Default::default()
        };
        let mut metadata = Metadata::default();
        let band_key = Name::from_str("fraud_assessment_band").expect("static name");
        metadata.insert(band_key, Json::new("high"));
        let score_key = Name::from_str("fraud_assessment_score_bps").expect("static name");
        metadata.insert(score_key, Json::new(650_u64));
        let tenant_key = Name::from_str("fraud_assessment_tenant").expect("static name");
        metadata.insert(tenant_key, Json::new("tenant-eu"));
        let latency_key = Name::from_str("fraud_assessment_latency_ms").expect("static name");
        metadata.insert(latency_key, Json::new(95_u64));
        let catalog = DataSpaceCatalog::default();
        let assignment = single_lane_assignment(&catalog);
        assert!(super::enforce_fraud_policy(&cfg, &metadata, None, &assignment).is_ok());
    }
    #[test]
    fn fraud_policy_rejects_inconsistent_band() {
        use iroha_primitives::json::Json;
        let cfg = iroha_config::parameters::actual::FraudMonitoring {
            policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
                enabled: true,
                required_minimum_band: Some(iroha_data_model::fraud::FraudRiskBandV1::Low),
                ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
            },
            ..Default::default()
        };
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("fraud_assessment_band").expect("static name"),
            Json::new("low"),
        );
        metadata.insert(
            Name::from_str("fraud_assessment_score_bps").expect("static name"),
            Json::new(8_000_u64),
        );
        metadata.insert(
            Name::from_str("fraud_assessment_tenant").expect("static name"),
            Json::new("tenant-eu"),
        );
        metadata.insert(
            Name::from_str("fraud_assessment_latency_ms").expect("static name"),
            Json::new(110_u64),
        );
        let catalog = DataSpaceCatalog::default();
        let assignment = single_lane_assignment(&catalog);
        let result = super::enforce_fraud_policy(&cfg, &metadata, None, &assignment)
            .expect_err("inconsistent band must be rejected");
        match result {
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason)) => {
                assert!(
                    reason.contains("inconsistent"),
                    "unexpected error message: {reason}"
                );
            }
            other => panic!("expected Validation::NotPermitted, got {other:?}"),
        }
    }
    fn fraud_metadata_with_assessment(assessment: &FraudAssessment) -> Metadata {
        use iroha_primitives::json::Json;
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("fraud_assessment_band").expect("static name"),
            Json::new("high"),
        );
        metadata.insert(
            Name::from_str("fraud_assessment_score_bps").expect("static name"),
            Json::new(u64::from(assessment.risk_score_bps)),
        );
        metadata.insert(
            Name::from_str("fraud_assessment_tenant").expect("static name"),
            Json::new("tenant-eu"),
        );
        metadata.insert(
            Name::from_str("fraud_assessment_latency_ms").expect("static name"),
            Json::new(95_u64),
        );
        let mut unsigned = assessment.clone();
        unsigned.signature = None;
        let unsigned_bytes = norito::codec::Encode::encode(&unsigned);
        let digest_bytes: [u8; 32] = iroha_crypto::Hash::new(&unsigned_bytes).into();
        metadata.insert(
            Name::from_str("fraud_assessment_digest").expect("static name"),
            Json::new(hex::encode_upper(digest_bytes)),
        );
        metadata.insert(
            Name::from_str("fraud_assessment_envelope").expect("static name"),
            Json::new(BASE64_STANDARD.encode(norito::codec::Encode::encode(assessment))),
        );
        metadata
    }
    #[test]
    fn fraud_policy_attester_signature_precheck_uses_checked_public_key_algorithm() {
        let attester =
            checked_fixture_keypair(b"fraud-attester-ed25519".to_vec(), Algorithm::Ed25519);
        let assessment = FraudAssessment::new(
            Vec::new(),
            iroha_data_model::fraud::types::FraudAssessmentParts {
                query_id: [0xFA; 32],
                engine_id: "risk-engine-eu".to_owned(),
                risk_score_bps: 650,
                confidence_bps: 9_000,
                decision: iroha_data_model::fraud::types::AssessmentDecision::Allow,
                generated_at_ms: 1,
                signature: Some(vec![0xAA, 0xBB, 0xCC]),
            },
        );
        let metadata = fraud_metadata_with_assessment(&assessment);
        let cfg = iroha_config::parameters::actual::FraudMonitoring {
            policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
                enabled: true,
                required_minimum_band: Some(iroha_data_model::fraud::FraudRiskBandV1::Medium),
                attesters: vec![iroha_data_model::fraud::FraudAdmissionAttesterV1 {
                    engine_id: "risk-engine-eu".to_owned(),
                    public_key: attester.public_key().clone(),
                }],
                ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
            },
            ..Default::default()
        };
        let catalog = DataSpaceCatalog::default();
        let assignment = single_lane_assignment(&catalog);
        let err = super::enforce_fraud_policy(&cfg, &metadata, None, &assignment)
            .expect_err("short Ed25519 attestation signature must be rejected");
        match err {
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason)) => {
                assert!(
                    reason.contains("64 bytes"),
                    "unexpected rejection reason: {reason}"
                );
            }
            other => panic!("expected Validation::NotPermitted, got {other:?}"),
        }
    }
    #[test]
    fn fraud_policy_rejects_all_zero_attestation_signature_before_backend() {
        let attester =
            checked_fixture_keypair(b"fraud-attester-ed25519".to_vec(), Algorithm::Ed25519);
        let assessment = FraudAssessment::new(
            Vec::new(),
            iroha_data_model::fraud::types::FraudAssessmentParts {
                query_id: [0xFA; 32],
                engine_id: "risk-engine-eu".to_owned(),
                risk_score_bps: 650,
                confidence_bps: 9_000,
                decision: iroha_data_model::fraud::types::AssessmentDecision::Allow,
                generated_at_ms: 1,
                signature: Some(vec![0_u8; ED25519_SIGNATURE_LENGTH]),
            },
        );
        let metadata = fraud_metadata_with_assessment(&assessment);
        let cfg = iroha_config::parameters::actual::FraudMonitoring {
            policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
                enabled: true,
                required_minimum_band: Some(iroha_data_model::fraud::FraudRiskBandV1::Medium),
                attesters: vec![iroha_data_model::fraud::FraudAdmissionAttesterV1 {
                    engine_id: "risk-engine-eu".to_owned(),
                    public_key: attester.public_key().clone(),
                }],
                ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
            },
            ..Default::default()
        };
        let catalog = DataSpaceCatalog::default();
        let assignment = single_lane_assignment(&catalog);
        let err = super::enforce_fraud_policy(&cfg, &metadata, None, &assignment)
            .expect_err("all-zero Ed25519 attestation signature must be rejected");
        match err {
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason)) => {
                assert!(
                    reason.contains("fraud assessment signature is malformed:")
                        && reason.contains("signature payload must not be empty or all zero"),
                    "unexpected rejection reason: {reason}"
                );
            }
            other => panic!("expected Validation::NotPermitted, got {other:?}"),
        }
    }
    #[test]
    fn fraud_policy_rejects_malformed_ed25519_attestation_signature_r_before_backend() {
        const SMALL_ORDER_R: [u8; 32] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        const NONCANONICAL_R: [u8; 32] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let attester =
            checked_fixture_keypair(b"fraud-attester-ed25519".to_vec(), Algorithm::Ed25519);
        let unsigned = FraudAssessment::new(
            Vec::new(),
            iroha_data_model::fraud::types::FraudAssessmentParts {
                query_id: [0xFA; 32],
                engine_id: "risk-engine-eu".to_owned(),
                risk_score_bps: 650,
                confidence_bps: 9_000,
                decision: iroha_data_model::fraud::types::AssessmentDecision::Allow,
                generated_at_ms: 1,
                signature: None,
            },
        );
        let valid_signature = checked_signature_of(attester.private_key(), &unsigned);
        let cfg = iroha_config::parameters::actual::FraudMonitoring {
            policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
                enabled: true,
                required_minimum_band: Some(iroha_data_model::fraud::FraudRiskBandV1::Medium),
                attesters: vec![iroha_data_model::fraud::FraudAdmissionAttesterV1 {
                    engine_id: "risk-engine-eu".to_owned(),
                    public_key: attester.public_key().clone(),
                }],
                ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
            },
            ..Default::default()
        };
        let catalog = DataSpaceCatalog::default();
        let assignment = single_lane_assignment(&catalog);
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_R),
            ("noncanonical", NONCANONICAL_R),
        ] {
            let mut signature_bytes = valid_signature.payload().to_vec();
            signature_bytes[..replacement_r.len()].copy_from_slice(&replacement_r);
            let mut assessment = unsigned.clone();
            assessment.signature = Some(signature_bytes);
            let metadata = fraud_metadata_with_assessment(&assessment);
            let err = super::enforce_fraud_policy(&cfg, &metadata, None, &assignment)
                .expect_err("malformed Ed25519 attestation signature R must be rejected");
            match err {
                TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason)) => {
                    assert!(
                        reason.contains("signature is malformed"),
                        "{label} R produced unexpected rejection reason: {reason}"
                    );
                }
                other => panic!("expected Validation::NotPermitted for {label} R, got {other:?}"),
            }
        }
    }
    #[test]
    fn fraud_policy_rejects_malformed_mldsa_attestation_signature_lengths_before_backend() {
        let attester = checked_fixture_keypair(b"fraud-attester-mldsa".to_vec(), Algorithm::MlDsa);
        let unsigned = FraudAssessment::new(
            Vec::new(),
            iroha_data_model::fraud::types::FraudAssessmentParts {
                query_id: [0xFB; 32],
                engine_id: "risk-engine-eu".to_owned(),
                risk_score_bps: 650,
                confidence_bps: 9_000,
                decision: iroha_data_model::fraud::types::AssessmentDecision::Allow,
                generated_at_ms: 1,
                signature: None,
            },
        );
        let valid_signature = checked_signature_of(attester.private_key(), &unsigned);
        let cfg = iroha_config::parameters::actual::FraudMonitoring {
            policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
                enabled: true,
                required_minimum_band: Some(iroha_data_model::fraud::FraudRiskBandV1::Medium),
                attesters: vec![iroha_data_model::fraud::FraudAdmissionAttesterV1 {
                    engine_id: "risk-engine-eu".to_owned(),
                    public_key: attester.public_key().clone(),
                }],
                ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
            },
            ..Default::default()
        };
        let catalog = DataSpaceCatalog::default();
        let assignment = single_lane_assignment(&catalog);
        for label in ["short", "overlong"] {
            let mut signature_bytes = valid_signature.payload().to_vec();
            match label {
                "short" => {
                    signature_bytes
                        .pop()
                        .expect("ML-DSA fraud attestation signature is non-empty");
                }
                "overlong" => signature_bytes.push(0xA5),
                _ => unreachable!("covered labels"),
            }
            let mut assessment = unsigned.clone();
            assessment.signature = Some(signature_bytes);
            let metadata = fraud_metadata_with_assessment(&assessment);
            let err = super::enforce_fraud_policy(&cfg, &metadata, None, &assignment)
                .expect_err("malformed ML-DSA attestation signature length must be rejected");
            match err {
                TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason)) => {
                    assert!(
                        reason.contains("signature is malformed"),
                        "{label} ML-DSA signature length produced unexpected rejection reason: {reason}"
                    );
                }
                other => {
                    panic!(
                        "expected Validation::NotPermitted for {label} ML-DSA length, got {other:?}"
                    )
                }
            }
        }
    }
    #[test]
    fn tx_rejected_when_pipeline_gas_charge_limit_is_required_but_missing() {
        use iroha_data_model::transaction::{Executable, TransactionBuilder};
        // Minimal state with one domain/account as authority
        let (world, authority_id, kp) = world_with_authority("domain");
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query_handle = crate::query::store::LiveQueryStore::start_test();
        let chain: ChainId = "chain".parse().unwrap();
        let state = State::new_with_chain(world, kura, query_handle, chain.clone());
        // Commit the pipeline gas allowlist in the original signed genesis.
        let gas = iroha_config::parameters::actual::Gas {
            accepted_assets: vec![
                AssetDefinitionId::derive_from_components(
                    DomainId::try_new("domain", "universal").unwrap(),
                    "xor".parse().unwrap(),
                )
                .canonical_address(),
            ],
            ..Default::default()
        };
        let chain = crate::block::tests::component_chain_with_genesis_parameters(
            state,
            crate::pipeline_gas_policy::parameters_for_testing(gas).into(),
        );
        let state = chain.state();
        // Bind an executable gas limit but omit the required PipelineGas charge limit.
        let program = minimal_ivm_program_with_max_cycles(1, 1_000);
        let tx = TransactionBuilder::new(
            chain.network_id(),
            authority_id.clone(),
            fee_payment_with_gas_limit(TEST_GAS_LIMIT),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
        .sign(kp.private_key());
        // Height one is the fee-exempt genesis bootstrap boundary. Exercise
        // ordinary admission so the signed PipelineGas limit is mandatory.
        let header = original_component_successor_header(state);
        assert_eq!(header.height().get(), 2);
        assert_eq!(header.prev_block_hash(), Some(chain.genesis().hash()));
        let mut block = state.block(header);
        let fragments = block.committed_fragment_count();
        let mut ivm_cache = IvmCache::new();
        let accepted = super::AcceptedTransaction::new_unchecked(Cow::Owned(tx));
        let res =
            execute_component_transaction_for_testing(&mut block, accepted, &mut ivm_cache, None);
        assert!(
            matches!(&res,
                Err(TransactionRejectionReason::Validation(
                    ValidationFail::NotPermitted(message)
                )) if message == "signed fee intent is missing PipelineGas charge limit"
            ),
            "ordinary signed admission must reject the missing pipeline gas limit: {res:?}"
        );
        assert_eq!(block.committed_fragment_count(), fragments);
    }
    #[test]
    fn signature_limit_rejects_above_bound() {
        let default_limits = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            nonzero!(1_u64),
            nonzero!(4096_u64),
            nonzero!(4096_u64),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        );
        let err = AcceptedTransaction::ensure_signature_limit(2, &limits)
            .expect_err("limit should reject excessive signatures");
        assert!(matches!(err, AcceptTransactionFail::TransactionLimit(_)));
    }
    #[test]
    fn signature_limit_allows_at_bound() {
        let default_limits = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            nonzero!(2_u64),
            nonzero!(4096_u64),
            nonzero!(4096_u64),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        );
        assert!(AcceptedTransaction::ensure_signature_limit(2, &limits).is_ok());
    }
    const IVM_METADATA_HEADER_LEN: usize = ivm::HEADER_SIZE;
    const LITERAL_SECTION_MAGIC: [u8; 4] = *b"LTLB";
    /// Build a minimal valid IVM program: header (1.1, vector=4, `max_cycles=0`, abi=1) + HALT.
    fn minimal_ivm_program(abi_version: u8) -> Vec<u8> {
        let mut code = Vec::new();
        code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let mut program = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 4,
            max_cycles: 1_000,
            abi_version,
        }
        .encode();
        program.extend_from_slice(&code);
        program
    }
    /// Build a minimal self-describing view returning one initialized Unit table word.
    fn minimal_ivm_contract_program() -> Vec<u8> {
        let mut program = ivm::ProgramMetadata {
            max_cycles: 1_000,
            ..ivm::ProgramMetadata::default()
        }
        .encode();
        let interface = ivm::EmbeddedContractInterfaceV1 {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            callables: vec![crate::ivm_test_support::unit_callable(0)],
            seiyaku_name: "TxManifestFixture".to_owned(),
            compiler_fingerprint: "iroha-core-tx-tests".to_owned(),
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
            features_bitmap: 0,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
                name: "inspect".to_owned(),
                kind: iroha_data_model::smart_contract::manifest::EntryPointKind::View,
                params: Vec::new(),
                argument_schema: None,
                return_type: Some("()".to_owned()),
                return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                    nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
                }),
                authorization: iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
                read_keys: Vec::new(),
                write_keys: Vec::new(),
                access_hints_complete: Some(true),
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
                entry_pc: 0,
            }],
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        };
        program.extend_from_slice(&interface.encode_section());
        program.extend_from_slice(&crate::ivm_test_support::unit_return());
        program
    }
    /// Build a minimal program and override `max_cycles` in the header.
    fn minimal_ivm_program_with_max_cycles(abi_version: u8, max_cycles: u64) -> Vec<u8> {
        let mut prog = minimal_ivm_program(abi_version);
        // Overwrite bytes [8..16] with the desired max_cycles value
        prog[8..16].copy_from_slice(&max_cycles.to_le_bytes());
        prog
    }
    #[track_caller]
    fn minimal_ivm_program_with_instruction_count(
        abi_version: u8,
        max_cycles: u64,
        instruction_count: usize,
    ) -> Vec<u8> {
        assert!(instruction_count > 0, "instruction_count must be non-zero");
        assert!(max_cycles > 0, "max_cycles must be non-zero");
        let mut code = Vec::with_capacity(instruction_count * core::mem::size_of::<u32>());
        for _ in 0..instruction_count {
            code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        }
        let mut program = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 4,
            max_cycles,
            abi_version,
        }
        .encode();
        program.extend_from_slice(&code);
        program
    }
    /// Build a minimal program and insert a literal-section padding block so the artifact
    /// reaches `total_len` bytes.
    fn minimal_ivm_program_with_literal_padding(abi_version: u8, total_len: usize) -> Vec<u8> {
        assert!(
            total_len >= IVM_METADATA_HEADER_LEN + 4 + 16,
            "literal padding requires at least one opcode and metadata block"
        );
        let mut program = minimal_ivm_program(abi_version);
        let mut code = program.split_off(IVM_METADATA_HEADER_LEN);
        debug_assert_eq!(
            code.len(),
            4,
            "minimal program should contain a single opcode"
        );
        let pad_len = total_len
            .checked_sub(IVM_METADATA_HEADER_LEN + code.len())
            .expect("total_len smaller than header + code");
        assert!(
            pad_len >= 16,
            "literal table header consumes 16 bytes; remaining pad must fit that"
        );
        let data_and_pad = pad_len - 16;
        let literal_data_len = data_and_pad
            .checked_sub(data_and_pad % 4)
            .expect("literal padding underflow");
        let post_pad = data_and_pad - literal_data_len;
        assert!(
            post_pad == (4 - (literal_data_len % 4)) % 4,
            "requested total_len cannot be represented by a valid literal section"
        );
        let literal_data_len_u32 = u32::try_from(literal_data_len)
            .expect("literal data length exceeds literal section encoding");
        let post_pad_u32 =
            u32::try_from(post_pad).expect("pad length exceeds literal section encoding");
        let mut padded = program;
        padded.extend_from_slice(&LITERAL_SECTION_MAGIC);
        padded.extend_from_slice(&0u32.to_le_bytes()); // literal count
        padded.extend_from_slice(&post_pad_u32.to_le_bytes());
        padded.extend_from_slice(&literal_data_len_u32.to_le_bytes());
        padded.resize(padded.len() + literal_data_len + post_pad, 0);
        padded.append(&mut code);
        assert_eq!(
            padded.len(),
            total_len,
            "padding must reach exact target length"
        );
        padded
    }
    /// Build a minimal program that issues a single syscall followed by HALT.
    fn minimal_ivm_program_with_syscall(abi_version: u8, syscall: u8) -> Vec<u8> {
        let mut code = Vec::new();
        code.extend_from_slice(
            &ivm::encoding::wide::encode_sys(ivm::instruction::wide::system::SCALL, syscall)
                .to_le_bytes(),
        );
        code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let mut program = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 4,
            max_cycles: 1_000,
            abi_version,
        }
        .encode();
        program.extend_from_slice(&code);
        program
    }
    /// Build a minimal program that issues a single extended syscall followed by HALT.
    fn minimal_ivm_program_with_syscallx(abi_version: u8, syscall: u32) -> Vec<u8> {
        let mut code = Vec::new();
        code.extend_from_slice(&ivm::encoding::wide::encode_syscallx(syscall).to_le_bytes());
        code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let mut program = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 4,
            max_cycles: 1_000,
            abi_version,
        }
        .encode();
        program.extend_from_slice(&code);
        program
    }
    const TEST_GAS_LIMIT: u64 = 1_000_000;
    fn fee_payment_with_gas_limit(limit: u64) -> FeePaymentIntent {
        FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(limit))
    }
    struct IvmAdmissionFixture {
        state: State,
        authority_id: AccountId,
        keypair: KeyPair,
    }
    impl IvmAdmissionFixture {
        fn new() -> Self {
            let (world, authority_id, keypair) = world_with_authority("wonderland");
            let mut parameters = world.parameters.block();
            parameters
                .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                    iroha_data_model::block::consensus::SumeragiRootScope::Global,
                ))
                .expect("valid fixture parameters");
            parameters.commit();
            let state = State::new_with_chain(
                world,
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
                "chain".parse().expect("chain id"),
            );
            Self {
                state,
                authority_id,
                keypair,
            }
        }
        fn validate_program(self, program: Vec<u8>) -> Result<(), TransactionRejectionReason> {
            self.validate_program_with(program, None, |_| {})
        }
        fn validate_program_with(
            self,
            program: Vec<u8>,
            metadata: Option<Metadata>,
            prepare_block: impl FnOnce(&mut StateBlock<'_>),
        ) -> Result<(), TransactionRejectionReason> {
            // Admission limits belong to signed chain policy. Preserve local cache settings,
            // but commit the requested validity limits through real genesis before execution.
            let policy =
                crate::pipeline_validity_policy::policy_of(self.state.installed_pipeline());
            let chain = crate::block::tests::component_chain_with_genesis_parameters(
                self.state,
                vec![iroha_data_model::parameter::Parameter::Custom(
                    policy.clone().into_custom_parameter(),
                )],
            );
            let state = chain.state();
            let header = original_component_successor_header(state);
            let mut block = state.block(header);
            assert_eq!(
                crate::pipeline_validity_policy::policy_of(block.pipeline()),
                policy
            );
            prepare_block(&mut block);
            let builder = TransactionBuilder::new(
                chain.network_id(),
                self.authority_id.clone(),
                fee_payment_with_gas_limit(TEST_GAS_LIMIT),
            );
            let builder = match metadata {
                Some(metadata) => builder.with_metadata(metadata),
                None => builder,
            };
            let transaction = builder
                .with_executable(iroha_data_model::transaction::Executable::Ivm(
                    IvmBytecode::from_compiled(program),
                ))
                .sign(self.keypair.private_key());
            let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(transaction));
            let mut ivm_cache = IvmCache::new();
            execute_component_transaction_for_testing(&mut block, accepted, &mut ivm_cache, None)
                .map(|_| ())
        }
    }
    #[test]
    fn validate_ivm_header_accepts_supported_versions() {
        let result = IvmAdmissionFixture::new().validate_program(minimal_ivm_program(1));
        assert!(result.is_ok(), "valid header should pass: {result:?}");
    }
    #[test]
    fn validate_ivm_header_rejects_unknown_abi() {
        let result = IvmAdmissionFixture::new().validate_program(minimal_ivm_program(3));
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::UnsupportedAbiVersion(3),
            ))) => {}
            other => panic!("Expected UnsupportedAbiVersion(3) error, got {other:?}"),
        }
    }
    #[test]
    fn validate_ivm_header_rejects_abi_zero() {
        // abi_version=0 must be rejected in v1-only release
        let result = IvmAdmissionFixture::new().validate_program(minimal_ivm_program(0));
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::UnsupportedAbiVersion(0),
            ))) => {}
            other => panic!("Expected UnsupportedAbiVersion(0) error, got {other:?}"),
        }
    }
    #[test]
    fn validate_generic_ivm_rejects_reserved_manifest_metadata_before_decode() {
        let mut metadata = Metadata::default();
        metadata.insert(
            (*CONTRACT_MANIFEST_METADATA_NAME).clone(),
            Json::from("not-a-contract-manifest"),
        );
        let result = IvmAdmissionFixture::new().validate_program_with(
            minimal_ivm_program(1),
            Some(metadata),
            |_| {},
        );
        assert!(matches!(
            result,
            Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                message
            ))) if message.contains("reserved `contract_manifest`")
        ));
    }
    #[test]
    fn validate_ivm_rejects_stale_authenticated_cntr_abi_hash() {
        let (artifact, _) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                "seiyaku StaleAbi { view fn inspect() authorize(anyone) -> int { return 1; } }",
            )
            .expect("compile self-describing contract");
        let parsed = ivm::ProgramMetadata::parse(&artifact).expect("parse compiled contract");
        let mut interface = parsed
            .contract_interface
            .expect("compiled contract carries CNTR");
        let original_section_len = interface.encode_section().len();
        let expected = interface.abi_hash;
        interface.abi_hash[0] ^= 0x80;
        let actual = interface.abi_hash;
        let mut stale = parsed.metadata.encode();
        stale.extend_from_slice(&interface.encode_section());
        stale.extend_from_slice(
            artifact
                .get(parsed.header_len + original_section_len..)
                .expect("post-CNTR artifact suffix is in bounds"),
        );
        let result = IvmAdmissionFixture::new().validate_program(stale);
        assert!(matches!(
            result,
            Err(TransactionRejectionReason::Validation(
                ValidationFail::IvmAdmission(
                    iroha_data_model::executor::IvmAdmissionError::ArtifactAbiHashMismatch(info)
                )
            )) if info.expected == iroha_crypto::Hash::prehashed(expected)
                && info.actual == iroha_crypto::Hash::prehashed(actual)
        ));
    }
    #[test]
    fn validate_ivm_manifest_metadata_conflict_rejected_even_if_state_matches() {
        use iroha_data_model::{
            smart_contract::manifest::ContractManifest,
            transaction::{Executable, TransactionBuilder},
        };
        use nonzero_ext::nonzero;
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let fixture = IvmAdmissionFixture::new();
        // Seed block 1 with a correct manifest for the program.
        let header1 = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block1 = fixture.state.block(header1);
        let mut tx1 = block1.transaction();
        // Seed synthetic Global scope in this component World/height overlay;
        // the fixture does not authenticate committed genesis or Network finality.
        tx1.world
            .parameters
            .get_mut()
            .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                iroha_data_model::block::consensus::SumeragiRootScope::Global,
            ))
            .expect("valid fixture parameters");
        let prog = minimal_ivm_contract_program();
        let code_hash = ivm::contract_code_hash(&prog);
        let abi_hash = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
        tx1.world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            ContractManifest {
                events: Vec::new(),
                enum_types: Vec::new(),
                permissions: Vec::new(),
                seiyaku_name: None,
                code_hash: Some(code_hash),
                abi_hash: Some(iroha_crypto::Hash::prehashed(abi_hash)),
                compiler_fingerprint: None,
                features_bitmap: None,
                access_set_hints: None,
                entrypoints: None,
                states: None,
                kotoba: None,
                error_messages: None,
                error_types: None,
                provenance: None,
            }
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &fixture.keypair,
            )
            .expect("sign bounded fixture manifest"),
        );
        tx1.apply();
        let _ = block1.commit_world_overlay_for_testing();
        // Block 2: metadata manifest advertises the wrong abi_hash; admission must reject even
        // though the stored manifest matches.
        let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block2 = fixture.state.block(header2);
        assert_eq!(
            crate::sumeragi::lanes::routing::committed_root_scope(&block2.world),
            Some(iroha_data_model::block::consensus::SumeragiRootScope::Global),
        );
        let mut wrong_abi = abi_hash;
        wrong_abi[0] ^= 0x55;
        let manifest = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: Some(iroha_crypto::Hash::prehashed(wrong_abi)),
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            entrypoints: None,
            states: None,
            kotoba: None,
            error_messages: None,
            error_types: None,
            provenance: None,
        }
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &fixture.keypair,
        )
        .expect("sign bounded fixture manifest");
        let mut md = Metadata::default();
        md.insert(
            "contract_manifest".parse::<Name>().unwrap(),
            Json::new(manifest),
        );
        let tx = TransactionBuilder::new(
            test_network_id(),
            fixture.authority_id.clone(),
            fee_payment_with_gas_limit(TEST_GAS_LIMIT),
        )
        .with_metadata(md)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(fixture.keypair.private_key());
        let mut ivm_cache = IvmCache::new();
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
        let result =
            execute_component_transaction_for_testing(&mut block2, accepted, &mut ivm_cache, None);
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::ManifestAbiHashMismatch(info),
            ))) => {
                assert_eq!(info.expected, iroha_crypto::Hash::prehashed(wrong_abi));
                assert_eq!(info.actual, iroha_crypto::Hash::prehashed(abi_hash));
            }
            other => panic!(
                "Expected ManifestAbiHashMismatch from metadata manifest conflict, got {other:?}"
            ),
        }
    }
    #[test]
    fn validate_ivm_manifest_abi_and_code_hash_match() {
        use iroha_data_model::smart_contract::manifest::ContractManifest;
        use nonzero_ext::nonzero;
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let fixture = IvmAdmissionFixture::new();
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block = fixture.state.block(header);
        let mut state_tx = block.transaction();
        state_tx.current_dataspace_id = Some(TestDataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(TestDataSpaceId::UNIVERSAL);
        // Build minimal program with abi_version=1 (current baseline)
        let prog = minimal_ivm_contract_program();
        // Compute the canonical full-artifact contract hash.
        let code_hash = ivm::contract_code_hash(&prog);
        // Compute abi hash for the policy
        let abi_hash = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
        // Attach manifest in metadata
        let manifest = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: Some(iroha_crypto::Hash::prehashed(abi_hash)),
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            entrypoints: None,
            states: None,
            kotoba: None,
            error_messages: None,
            error_types: None,
            provenance: None,
        }
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &fixture.keypair,
        )
        .expect("sign bounded fixture manifest");
        let mut md = Metadata::default();
        md.insert(
            "contract_manifest".parse::<Name>().unwrap(),
            Json::new(manifest),
        );
        let mut ivm_cache = IvmCache::new();
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let result = StateBlock::validate_ivm(
            fixture.authority_id.clone(),
            &mut state_tx,
            IvmBytecode::from_compiled(prog),
            Some(&md),
            None,
            &mut ivm_cache,
        );
        assert!(result.is_ok(), "valid manifest should pass: {result:?}");
    }
    #[test]
    fn validate_ivm_manifest_rejects_mismatched_hashes() {
        use iroha_data_model::smart_contract::manifest::ContractManifest;
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let fixture = IvmAdmissionFixture::new();
        let prog = minimal_ivm_contract_program();
        // Compute real code hash; then corrupt expected
        let code_hash = ivm::contract_code_hash(&prog);
        // Compute abi hash then flip
        let mut wrong_abi = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
        wrong_abi[0] ^= 0xAA;
        let manifest = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: Some(iroha_crypto::Hash::prehashed(wrong_abi)),
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            entrypoints: None,
            states: None,
            kotoba: None,
            error_messages: None,
            error_types: None,
            provenance: None,
        }
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &fixture.keypair,
        )
        .expect("sign bounded fixture manifest");
        let mut md = Metadata::default();
        md.insert(
            "contract_manifest".parse::<Name>().unwrap(),
            Json::new(manifest),
        );
        let result = fixture.validate_program_with(prog, Some(md), |_| {});
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::ManifestAbiHashMismatch(..),
            ))) => {}
            other => panic!(
                "Expected ManifestAbiHashMismatch structured error for mismatched manifest, got {other:?}"
            ),
        }
    }
    #[test]
    fn validate_ivm_manifest_rejects_mismatched_code_hash() {
        use iroha_data_model::smart_contract::manifest::ContractManifest;
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let fixture = IvmAdmissionFixture::new();
        let prog = minimal_ivm_contract_program();
        let mut wrong_bytes = [0u8; 32];
        wrong_bytes[0] = 0xFF;
        wrong_bytes[31] = 1; // set LSB as per Hash invariant
        let wrong_code_hash = iroha_crypto::Hash::prehashed(wrong_bytes);
        let abi_hash = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
        let manifest = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(wrong_code_hash),
            abi_hash: Some(iroha_crypto::Hash::prehashed(abi_hash)),
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            entrypoints: None,
            states: None,
            kotoba: None,
            error_messages: None,
            error_types: None,
            provenance: None,
        }
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &fixture.keypair,
        )
        .expect("sign bounded fixture manifest");
        let mut md = Metadata::default();
        md.insert(
            "contract_manifest".parse::<Name>().unwrap(),
            Json::new(manifest),
        );
        let result = fixture.validate_program_with(prog, Some(md), |_| {});
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::ManifestCodeHashMismatch(..),
            ))) => {}
            other => panic!(
                "Expected ManifestCodeHashMismatch structured error for mismatched manifest, got {other:?}"
            ),
        }
    }
    #[test]
    fn validate_ivm_manifest_state_conflict_rejected_even_if_metadata_matches() {
        use iroha_data_model::{
            smart_contract::manifest::ContractManifest,
            transaction::{Executable, TransactionBuilder},
        };
        use nonzero_ext::nonzero;
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let fixture = IvmAdmissionFixture::new();
        // Seed block 1 with a manifest that has the right code_hash but wrong abi_hash.
        let header1 = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block1 = fixture.state.block(header1);
        let mut tx1 = block1.transaction();
        // Seed synthetic Global scope in this component World/height overlay;
        // the fixture does not authenticate committed genesis or Network finality.
        tx1.world
            .parameters
            .get_mut()
            .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                iroha_data_model::block::consensus::SumeragiRootScope::Global,
            ))
            .expect("valid fixture parameters");
        let prog = minimal_ivm_contract_program();
        let code_hash = ivm::contract_code_hash(&prog);
        let abi_hash = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
        let mut wrong_abi = abi_hash;
        wrong_abi[0] ^= 0x5A;
        tx1.world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            ContractManifest {
                events: Vec::new(),
                enum_types: Vec::new(),
                permissions: Vec::new(),
                seiyaku_name: None,
                code_hash: Some(code_hash),
                abi_hash: Some(iroha_crypto::Hash::prehashed(wrong_abi)),
                compiler_fingerprint: None,
                features_bitmap: None,
                access_set_hints: None,
                entrypoints: None,
                states: None,
                kotoba: None,
                error_messages: None,
                error_types: None,
                provenance: None,
            }
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &fixture.keypair,
            )
            .expect("sign bounded fixture manifest"),
        );
        tx1.apply();
        let _ = block1.commit_world_overlay_for_testing();
        // Block 2: attach a correct manifest in metadata; validation should still reject
        // because the stored manifest ABI hash mismatches the computed one.
        let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block2 = fixture.state.block(header2);
        assert_eq!(
            crate::sumeragi::lanes::routing::committed_root_scope(&block2.world),
            Some(iroha_data_model::block::consensus::SumeragiRootScope::Global),
        );
        let manifest = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: Some(iroha_crypto::Hash::prehashed(abi_hash)),
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            entrypoints: None,
            states: None,
            kotoba: None,
            error_messages: None,
            error_types: None,
            provenance: None,
        }
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &fixture.keypair,
        )
        .expect("sign bounded fixture manifest");
        let mut md = Metadata::default();
        md.insert(
            "contract_manifest".parse::<Name>().unwrap(),
            Json::new(manifest),
        );
        let tx = TransactionBuilder::new(
            test_network_id(),
            fixture.authority_id.clone(),
            fee_payment_with_gas_limit(TEST_GAS_LIMIT),
        )
        .with_metadata(md)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(fixture.keypair.private_key());
        let mut ivm_cache = IvmCache::new();
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
        let result =
            execute_component_transaction_for_testing(&mut block2, accepted, &mut ivm_cache, None);
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::ManifestAbiHashMismatch(info),
            ))) => {
                assert_eq!(info.expected, iroha_crypto::Hash::prehashed(wrong_abi));
                assert_eq!(info.actual, iroha_crypto::Hash::prehashed(abi_hash));
            }
            other => panic!(
                "Expected ManifestAbiHashMismatch structured error despite metadata manifest, got {other:?}"
            ),
        }
    }
    #[test]
    fn validate_ivm_max_cycles_structured_error() {
        // Program with max_cycles above default config bound; expect structured error
        let result = IvmAdmissionFixture::new()
            .validate_program(minimal_ivm_program_with_max_cycles(1, 9_999_999));
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::MaxCyclesExceedsUpperBound(..),
            ))) => {}
            other => panic!("Expected MaxCyclesExceedsUpperBound structured error, got {other:?}"),
        }
    }
    #[test]
    fn validate_ivm_missing_max_cycles_rejected() {
        let result =
            IvmAdmissionFixture::new().validate_program(minimal_ivm_program_with_max_cycles(1, 0));
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::MissingMaxCycles,
            ))) => {}
            other => panic!("Expected MissingMaxCycles error, got {other:?}"),
        }
    }
    #[test]
    fn validate_ivm_max_cycles_exceeds_fuel_rejected() {
        let mut fixture = IvmAdmissionFixture::new();
        // Commit an upper bound above the fuel limit so the fuel check triggers first.
        let mut pipeline = fixture.state.installed_pipeline().clone();
        let fuel_limit = fixture
            .state
            .world
            .parameters
            .view()
            .smart_contract()
            .fuel()
            .get();
        pipeline.ivm_max_cycles_upper_bound =
            std::num::NonZeroU64::new(fuel_limit + 10).expect("fuel limit plus ten is non-zero");
        fixture.state.set_pipeline(pipeline);
        let result =
            fixture.validate_program(minimal_ivm_program_with_max_cycles(1, fuel_limit + 1));
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::MaxCyclesExceedsFuel(info),
            ))) => {
                assert_eq!(info.fuel_limit, fuel_limit);
                assert_eq!(info.max_cycles, fuel_limit + 1);
            }
            other => panic!("Expected MaxCyclesExceedsFuel error, got {other:?}"),
        }
    }
    /// The committed fuel is inclusive: a cycle ceiling equal to it passes admission, and
    /// the next value is the first one refused (the test above).
    #[test]
    fn validate_ivm_max_cycles_equal_to_fuel_is_admitted() {
        let mut fixture = IvmAdmissionFixture::new();
        let mut pipeline = fixture.state.installed_pipeline().clone();
        let fuel_limit = fixture
            .state
            .world
            .parameters
            .view()
            .smart_contract()
            .fuel()
            .get();
        // Commit a ceiling above the fuel so only the fuel comparison decides.
        pipeline.ivm_max_cycles_upper_bound =
            std::num::NonZeroU64::new(fuel_limit + 10).expect("fuel limit plus ten is non-zero");
        fixture.state.set_pipeline(pipeline);
        let result = fixture.validate_program(minimal_ivm_program_with_max_cycles(1, fuel_limit));
        assert!(
            result.is_ok(),
            "a cycle ceiling equal to the fuel is admitted: {result:?}"
        );
    }
    #[test]
    fn validate_ivm_instruction_limit_enforced() {
        let mut fixture = IvmAdmissionFixture::new();
        let mut pipeline = fixture.state.installed_pipeline().clone();
        pipeline.ivm_max_decoded_instructions = 2;
        pipeline.ivm_max_decoded_bytes =
            iroha_config::parameters::defaults::pipeline::IVM_MAX_DECODED_BYTES;
        fixture.state.set_pipeline(pipeline);
        let result =
            fixture.validate_program(minimal_ivm_program_with_instruction_count(1, 1_000, 4));
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::DecodedInstructionCountExceeded(
                    info,
                ),
            ))) => {
                assert_eq!(info.limit, 2);
                assert_eq!(info.decoded_instructions, 4);
            }
            other => panic!("Expected DecodedInstructionCountExceeded error, got {other:?}"),
        }
    }
    #[test]
    fn validate_ivm_cache_retention_limit_does_not_change_admission() {
        let baseline = ivm::ivm_cache::cache_limits();
        let _cache_limits = ivm::ivm_cache::CacheLimitsGuard::new(baseline);
        let mut fixture = IvmAdmissionFixture::new();
        let mut pipeline = fixture.state.installed_pipeline().clone();
        pipeline.ivm_cache_max_decoded_ops = 1;
        pipeline.ivm_max_decoded_instructions = 4;
        pipeline.ivm_max_decoded_bytes =
            iroha_config::parameters::defaults::pipeline::IVM_MAX_DECODED_BYTES;
        fixture.state.set_pipeline(pipeline);

        let result =
            fixture.validate_program(minimal_ivm_program_with_instruction_count(1, 1_000, 4));
        assert!(
            result.is_ok(),
            "a process-local cache retention ceiling must not reject valid bytecode: {result:?}"
        );
    }
    #[test]
    fn validate_ivm_decoded_byte_limit_enforced() {
        let mut fixture = IvmAdmissionFixture::new();
        let mut pipeline = fixture.state.installed_pipeline().clone();
        pipeline.ivm_max_decoded_instructions = 0;
        pipeline.ivm_max_decoded_bytes = 8; // allow only two 4-byte instructions
        fixture.state.set_pipeline(pipeline);
        let result =
            fixture.validate_program(minimal_ivm_program_with_instruction_count(1, 1_000, 4));
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::DecodedCodeSizeExceeded(info),
            ))) => {
                assert_eq!(info.limit, 8);
                assert_eq!(info.decoded_bytes, 16);
            }
            other => panic!("Expected DecodedCodeSizeExceeded error, got {other:?}"),
        }
    }
    #[test]
    fn validate_ivm_manifest_lookup_in_state() {
        use iroha_data_model::smart_contract::manifest::ContractManifest;
        use nonzero_ext::nonzero;
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let fixture = IvmAdmissionFixture::new();
        // Seed block 1: insert a manifest into WSV directly via state tx
        let header1 = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block1 = fixture.state.block(header1);
        let mut tx1 = block1.transaction();
        // Seed synthetic Global scope in this component World/height overlay;
        // the fixture does not authenticate committed genesis or Network finality.
        tx1.world
            .parameters
            .get_mut()
            .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                iroha_data_model::block::consensus::SumeragiRootScope::Global,
            ))
            .expect("valid fixture parameters");
        // Build a minimal program to compute its code_hash/abi_hash
        let prog = minimal_ivm_contract_program();
        let code_hash = ivm::contract_code_hash(&prog);
        let abi_hash = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
        let manifest = ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: Some(iroha_crypto::Hash::prehashed(abi_hash)),
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            entrypoints: None,
            states: None,
            kotoba: None,
            error_messages: None,
            error_types: None,
            provenance: None,
        }
        .try_signed(
            manifest_signing.context(),
            manifest_signing.max_frame_bytes(),
            &fixture.keypair,
        )
        .expect("sign bounded fixture manifest");
        tx1.world.contract_manifests.insert(
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest.clone(),
        );
        tx1.apply();
        let _ = block1.commit_world_overlay_for_testing();
        // Block 2: submit the IVM program; validation should find the manifest in WSV and accept
        let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block2 = fixture.state.block(header2);
        assert_eq!(
            crate::sumeragi::lanes::routing::committed_root_scope(&block2.world),
            Some(iroha_data_model::block::consensus::SumeragiRootScope::Global),
        );
        let mut state_tx = block2.transaction();
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        assert_eq!(
            crate::executor::root_scope::captured_artifact_id(&mut state_tx, code_hash)
                .expect("fixture captures the exact committed artifact dataspace"),
            iroha_data_model::smart_contract::ContractArtifactId::new(
                DataSpaceId::UNIVERSAL,
                code_hash,
            ),
        );
        let mut ivm_cache = IvmCache::new();
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let result = StateBlock::validate_ivm(
            fixture.authority_id.clone(),
            &mut state_tx,
            IvmBytecode::from_compiled(prog),
            None,
            None,
            &mut ivm_cache,
        );
        assert!(
            result.is_ok(),
            "lookup manifest should allow validation: {result:?}"
        );
    }
    #[test]
    fn validate_ivm_unknown_syscall_rejected_at_admission() {
        let syscall = (0u8..=u8::MAX)
            .find(|number| {
                !ivm::syscalls::is_syscall_allowed(ivm::SyscallPolicy::AbiV1, u32::from(*number))
            })
            .expect("ABI v1 should leave at least one u8 syscall number unmapped");
        // Program issues an unmapped SCALL then HALT; admission should reject before the VM runs.
        let result = IvmAdmissionFixture::new()
            .validate_program(minimal_ivm_program_with_syscall(1, syscall));
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg))) => {
                let expected = format!("unknown syscall number 0x{syscall:02x}");
                assert!(
                    msg.contains(&expected) && msg.contains("abi_version 1"),
                    "expected UnknownSyscall rejection to surface via NotPermitted, got {msg}"
                );
            }
            other => panic!("Expected UnknownSyscall rejection, got {other:?}"),
        }
    }
    #[test]
    fn validate_ivm_unknown_scallx_rejected_at_admission() {
        let syscall = 0x02_0000;
        assert!(!ivm::syscalls::is_syscall_allowed(
            ivm::SyscallPolicy::AbiV1,
            syscall
        ));
        let result = IvmAdmissionFixture::new()
            .validate_program(minimal_ivm_program_with_syscallx(1, syscall));
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg))) => {
                let expected = format!("unknown syscall number 0x{syscall:02x}");
                assert!(
                    msg.contains(&expected) && msg.contains("abi_version 1"),
                    "expected UnknownSyscall rejection to surface via NotPermitted, got {msg}"
                );
            }
            other => panic!("Expected UnknownSyscall rejection, got {other:?}"),
        }
    }
    #[test]
    fn invalid_signature_is_rejected() {
        use iroha_data_model::prelude::*;
        use std::time::Duration;
        let (authority_id, keypair) = gen_account_in("wonderland");
        let instruction = SetKeyValue::account(authority_id.clone(), "k".parse().unwrap(), "v");
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction])
        .sign(keypair.private_key());
        let mut invalid_tx = tx.clone();
        let mut signature_payload = invalid_tx.signature().payload().payload().to_vec();
        assert!(
            !signature_payload.is_empty(),
            "transaction signature payload should never be empty"
        );
        let flip_index = signature_payload.len() - 1;
        signature_payload[flip_index] ^= 0xFF;
        let forged_signature = iroha_crypto::Signature::try_from_bytes(&signature_payload)
            .expect("tampered transaction signature remains structurally admissible");
        invalid_tx.set_signature(TransactionSignature(
            iroha_crypto::SignatureOf::from_signature(forged_signature),
        ));
        assert_ne!(invalid_tx.signature(), tx.signature());
        let default_limits = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            NonZeroU64::new(1).unwrap(),
            NonZeroU64::new(10).unwrap(),
            NonZeroU64::new(1024).unwrap(),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        );
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        match AcceptedTransaction::validate_with_now(
            &invalid_tx,
            &test_network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            invalid_tx.creation_time(),
        ) {
            Err(AcceptTransactionFail::SignatureVerification(fail)) => {
                assert_eq!(fail.signature, invalid_tx.signature().clone());
            }
            other => panic!("Expected signature verification error, got {other:?}"),
        }
    }
    #[test]
    fn ivm_bytecode_oversize_is_rejected_at_admission() {
        use iroha_data_model::transaction::{Executable, TransactionBuilder};
        use std::time::Duration;
        // Build a valid signed transaction with an oversized IVM bytecode blob
        let (authority_id, kp) = gen_account_in("wonderland");
        // Limit bytecode size to 1024 bytes for this test
        let default_limits = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            NonZeroU64::new(1).unwrap(),
            NonZeroU64::new(10).unwrap(),
            NonZeroU64::new(1024).unwrap(),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        );
        // Create a blob twice the allowed size (2 KiB) — content need not be a valid IVM header
        let oversize_blob = vec![0u8; 2048];
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id.clone(),
            fee_payment_with_gas_limit(TEST_GAS_LIMIT),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(oversize_blob)))
        .sign(kp.private_key());
        // Admission must reject with a TransactionLimit error
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        match AcceptedTransaction::validate_with_now(
            &tx,
            &test_network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            tx.creation_time(),
        ) {
            Err(AcceptTransactionFail::TransactionLimit(_)) => {}
            other => {
                panic!("Expected TransactionLimit error for oversize IVM bytecode, got {other:?}")
            }
        }
    }
    #[test]
    fn ivm_bytecode_at_limit_is_accepted_at_admission() {
        use iroha_data_model::transaction::{Executable, TransactionBuilder};
        use std::time::Duration;
        const BYTECODE_LIMIT: u64 = 1021;
        let (authority_id, kp) = gen_account_in("wonderland");
        // Use an exact bytecode-size limit that can be represented by the 17-byte
        // IVM metadata header plus a valid literal-prefix alignment.
        let default_limits = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            NonZeroU64::new(1).unwrap(),
            NonZeroU64::new(10).unwrap(),
            NonZeroU64::new(BYTECODE_LIMIT).unwrap(),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        );
        // Create a blob exactly at the allowed bytecode size.
        let at_limit_blob = minimal_ivm_program_with_literal_padding(
            1,
            usize::try_from(BYTECODE_LIMIT).expect("fixture value fits usize"),
        );
        assert_eq!(
            at_limit_blob.len(),
            usize::try_from(BYTECODE_LIMIT).expect("fixture value fits usize")
        );
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id.clone(),
            fee_payment_with_gas_limit(TEST_GAS_LIMIT),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(at_limit_blob)))
        .sign(kp.private_key());
        // Admission should accept this transaction
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        match AcceptedTransaction::validate_with_now(
            &tx,
            &test_network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            tx.creation_time(),
        ) {
            Ok(()) => {}
            other => panic!("Expected Ok for at-limit IVM bytecode, got {other:?}"),
        }
    }
    #[test]
    fn ivm_missing_gas_bound_rejected_at_admission() {
        use iroha_data_model::transaction::{Executable, TransactionBuilder};
        use std::time::Duration;
        let (authority_id, kp) = gen_account_in("wonderland");
        let prog = minimal_ivm_program_with_max_cycles(1, 1_000);
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(kp.private_key());
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let limits = TransactionParameters::default();
        let err = AcceptedTransaction::validate_with_now(
            &tx,
            &test_network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            tx.creation_time(),
        )
        .expect_err("missing gas limit in fee payment intent should be rejected");
        match err {
            AcceptTransactionFail::TransactionLimit(limit) => {
                assert!(
                    limit
                        .reason
                        .contains("missing gas limit in fee payment intent"),
                    "unexpected reason: {}",
                    limit.reason
                );
            }
            other => panic!("Expected TransactionLimit failure, got {other:?}"),
        }
    }
    #[test]
    fn legacy_gas_limit_metadata_is_rejected_before_admission() {
        use iroha_data_model::transaction::{Executable, TransactionBuilder};
        let (authority_id, kp) = gen_account_in("wonderland");
        let prog = minimal_ivm_program_with_max_cycles(1, 1_000);
        let mut metadata = Metadata::default();
        metadata.insert("gas_limit".parse().unwrap(), Json::new(0_u64));
        let error = TransactionBuilder::new(
            test_network_id(),
            authority_id,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(metadata)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .try_sign(kp.private_key())
        .expect_err("retired gas-limit metadata must fail before admission");
        assert!(
            error
                .to_string()
                .contains("legacy transaction metadata key `gas_limit`"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn ivm_proved_missing_gas_bound_rejected_at_admission() {
        use iroha_data_model::transaction::{Executable, IvmProved, TransactionBuilder};
        use std::time::Duration;
        let (authority_id, kp) = gen_account_in("wonderland");
        let prog = minimal_ivm_program_with_max_cycles(1, 1_000);
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::IvmProved(IvmProved {
            bytecode: IvmBytecode::from_compiled(prog),
            overlay: Vec::<InstructionBox>::new().into(),
            events_commitment: Hash::new(b"events"),
            gas_policy_commitment: Hash::new(b"gas"),
        }))
        .sign(kp.private_key());
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let limits = TransactionParameters::default();
        let err = AcceptedTransaction::validate_with_now(
            &tx,
            &test_network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            tx.creation_time(),
        )
        .expect_err("missing gas limit in fee payment intent should be rejected");
        match err {
            AcceptTransactionFail::TransactionLimit(limit) => {
                assert!(
                    limit
                        .reason
                        .contains("missing gas limit in fee payment intent"),
                    "unexpected reason: {}",
                    limit.reason
                );
            }
            other => panic!("Expected TransactionLimit failure, got {other:?}"),
        }
    }
    #[test]
    fn contract_call_missing_gas_bound_rejected_at_admission() {
        use iroha_data_model::transaction::{
            Executable, TransactionBuilder, executable::ContractInvocation,
        };
        use std::time::Duration;
        let (authority_id, kp) = gen_account_in("wonderland");
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::ContractCall(ContractInvocation {
            contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                .parse()
                .expect("contract address"),
            expected_code_hash: Hash::new(b"admission-contract-code"),
            entrypoint: "call".to_owned(),
            arguments: None,
        }))
        .sign(kp.private_key());
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let limits = TransactionParameters::default();
        let err = AcceptedTransaction::validate_with_now(
            &tx,
            &test_network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            tx.creation_time(),
        )
        .expect_err("missing gas limit in fee payment intent should be rejected");
        match err {
            AcceptTransactionFail::TransactionLimit(limit) => {
                assert!(
                    limit
                        .reason
                        .contains("missing gas limit in fee payment intent"),
                    "unexpected reason: {}",
                    limit.reason
                );
            }
            other => panic!("Expected TransactionLimit failure, got {other:?}"),
        }
    }
    #[test]
    fn mixed_batch_missing_gas_bound_rejected_at_admission() {
        let (authority_id, kp) = gen_account_in("wonderland");
        let call = ContractInvocation {
            contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                .parse()
                .expect("contract address"),
            expected_code_hash: Hash::new(b"batch-admission-contract-code"),
            entrypoint: "call".to_owned(),
            arguments: None,
        };
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(InstructionBox::from(Log::new(
                    Level::INFO,
                    "before call".to_owned(),
                ))),
                ExecutableBatchItem::ContractCall(call),
            ]
            .into(),
        ))
        .sign(kp.private_key());
        let err = AcceptedTransaction::validate_with_now(
            &tx,
            &test_network_id(),
            Duration::ZERO,
            TransactionParameters::default(),
            &iroha_config::parameters::actual::Crypto::default(),
            tx.creation_time(),
        )
        .expect_err("mixed batch without a signed gas limit must be rejected");
        assert!(matches!(
            err,
            AcceptTransactionFail::TransactionLimit(ref limit)
                if limit.reason.contains("missing gas limit in fee payment intent")
        ));
    }
    #[test]
    fn empty_executable_batch_rejected_at_admission() {
        let (authority_id, kp) = gen_account_in("wonderland");
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Batch(ConstVec::new_empty()))
        .sign(kp.private_key());
        let err = AcceptedTransaction::validate_with_now(
            &tx,
            &test_network_id(),
            Duration::ZERO,
            TransactionParameters::default(),
            &iroha_config::parameters::actual::Crypto::default(),
            tx.creation_time(),
        )
        .expect_err("empty executable batch must be rejected");
        assert!(matches!(
            err,
            AcceptTransactionFail::TransactionLimit(ref limit)
                if limit.reason.contains("must not be empty")
        ));
    }
    #[test]
    fn transaction_size_limit_enforced() {
        use std::time::Duration;
        let (authority_id, kp) = gen_account_in("wonderland");
        let mut metadata = Metadata::default();
        metadata.insert(
            "blob".parse().expect("metadata key"),
            Json::new("x".repeat(1024)),
        );
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "sized".to_string())])
        .with_metadata(metadata)
        .sign(kp.private_key());
        let limits = TransactionParameters::with_max_signatures(
            NonZeroU64::new(1).unwrap(),
            NonZeroU64::new(10).unwrap(),
            NonZeroU64::new(4096).unwrap(),
            NonZeroU64::new(256).unwrap(),
            NonZeroU64::new(4096).unwrap(),
            NonZeroU16::new(8).unwrap(),
        );
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let err = AcceptedTransaction::validate_with_now(
            &tx,
            &test_network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            tx.creation_time(),
        )
        .expect_err("transaction exceeding max_tx_bytes must be rejected");
        match err {
            AcceptTransactionFail::TransactionLimit(limit) => {
                assert!(
                    limit.reason.contains("Transaction size"),
                    "expected max_tx_bytes rejection, got {limit:?}"
                );
            }
            other => panic!("expected TransactionLimit failure, got {other:?}"),
        }
    }
    /// Wrap proof attachments as transaction-level carriers without checking them.
    fn unvalidated_proof_carriers(
        attachments: &[ProofAttachment],
    ) -> iroha_data_model::transaction::SignedAttachmentsV1 {
        use iroha_data_model::transaction::signed_attachments::PlannedActionV1;
        let mut plan = iroha_data_model::transaction::SignedAttachmentPlanV1::new();
        for attachment in attachments {
            plan.push_action(
                PlannedActionV1::transaction_proof_unvalidated(attachment)
                    .expect("canonical wrapper"),
            );
        }
        plan.declare()
    }
    fn carrier_attachment(name: &str, proof: Vec<u8>) -> ProofAttachment {
        ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), proof),
            VerifyingKeyId::new("halo2/ipa", name),
        )
    }
    /// A proof attachment whose canonical wrapper frame has exactly `target` bytes.
    fn carrier_attachment_with_frame_len(target: usize) -> ProofAttachment {
        let mut proof_len = target / 2;
        loop {
            let attachment = carrier_attachment("vk_ceiling", vec![0x5a; proof_len]);
            let actual = norito::encode_canonical(&attachment)
                .expect("canonical wrapper")
                .len();
            if actual == target {
                return attachment;
            }
            proof_len = proof_len + target - actual;
        }
    }
    fn admit(
        tx: &SignedTransaction,
        limits: TransactionParameters,
    ) -> Result<(), AcceptTransactionFail> {
        AcceptedTransaction::validate_with_now(
            tx,
            &test_network_id(),
            std::time::Duration::from_secs(0),
            limits,
            &iroha_config::parameters::actual::Crypto::default(),
            tx.creation_time(),
        )
    }
    #[test]
    fn signed_attachment_schema_violations_are_rejected_at_admission() {
        use iroha_data_model::transaction::signed_attachments::{
            ActionAuthorityBindingV1, ActionIntentV1, ActionInvocationBindingV1,
            ActionPublicInputsDigestV1, ActionRoleV1, AttachmentKindV1, AttachmentRoleV1,
            PlannedActionV1, PlannedAttachmentV1, SignedAttachmentOccurrenceV1,
            SignedAttachmentPlanV1, SignedAttachmentsV1,
        };
        let (authority_id, kp) = gen_account_in("wonderland");
        let limits = TransactionParameters::default();
        let builder = || {
            TransactionBuilder::new(
                test_network_id(),
                authority_id.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "attachments".to_owned())])
        };
        let valid = builder()
            .with_proof_attachments([
                carrier_attachment("vk_a", vec![1, 2, 3]),
                carrier_attachment("vk_b", vec![4, 5, 6, 7]),
            ])
            .expect("two carriers")
            .sign(kp.private_key());
        admit(&valid, limits).expect("valid carriers are admitted");

        // Sign a payload exactly as given: nothing is rebound or repaired.
        let sign = |payload: TransactionPayload| {
            TransactionBuilder::from_payload(payload)
                .expect("ordinary payload")
                .sign(kp.private_key())
        };
        let tampered =
            |change: &dyn Fn(&mut Vec<ActionIntentV1>, &mut Vec<SignedAttachmentOccurrenceV1>)| {
                let mut payload = valid.payload().clone();
                let (mut actions, mut occurrences) = payload
                    .attachments
                    .take()
                    .expect("attachments")
                    .into_parts();
                change(&mut actions, &mut occurrences);
                payload.attachments = Some(SignedAttachmentsV1::from_parts_unvalidated(
                    actions,
                    occurrences,
                ));
                sign(payload)
            };
        let rejection = |tx: &SignedTransaction| match admit(tx, limits) {
            Err(AcceptTransactionFail::SignedAttachments(error)) => error,
            other => panic!("expected a signed attachment rejection, got {other:?}"),
        };

        // Reorder.
        assert_eq!(
            rejection(&tampered(&|actions, _| actions.swap(0, 1))),
            SignedAttachmentErrorV1::ActionOutOfOrder {
                position: 0,
                action_index: 1
            }
        );
        assert_eq!(
            rejection(&tampered(&|_, occurrences| occurrences.swap(0, 1))),
            SignedAttachmentErrorV1::OccurrenceOutOfOrder {
                position: 0,
                index: 1
            }
        );
        // Substitute: another wrapped proof in a declared slot.
        let substitute = norito::encode_canonical(&carrier_attachment("vk_c", vec![9, 9, 9]))
            .expect("canonical wrapper");
        assert_eq!(
            rejection(&tampered(&|_, occurrences| {
                occurrences[0] = SignedAttachmentOccurrenceV1::new(
                    0,
                    AttachmentKindV1::Proof,
                    substitute.clone(),
                );
            })),
            SignedAttachmentErrorV1::ReferenceHashMismatch {
                action_index: 0,
                index: 0
            }
        );
        // Bytes changed under an unchanged occurrence header.
        assert_eq!(
            rejection(&tampered(&|_, occurrences| occurrences[1].bytes[60] ^= 1)),
            SignedAttachmentErrorV1::OccurrenceHashMismatch { index: 1 }
        );
        assert_eq!(
            rejection(&tampered(&|_, occurrences| occurrences[1].bytes.push(0))),
            SignedAttachmentErrorV1::OccurrenceLengthMismatch {
                index: 1,
                declared: u64::try_from(valid.attachments().unwrap().occurrences()[1].bytes.len())
                    .unwrap(),
                actual: valid.attachments().unwrap().occurrences()[1].bytes.len() + 1
            }
        );
        // Omit.
        assert_eq!(
            rejection(&tampered(&|_, occurrences| {
                occurrences.pop();
            })),
            SignedAttachmentErrorV1::MissingOccurrence {
                action_index: 1,
                index: 1
            }
        );
        // Duplicate.
        assert_eq!(
            rejection(&tampered(&|actions, _| {
                let first = actions[0].attachments[0];
                actions[1].attachments[0] = first;
            })),
            SignedAttachmentErrorV1::DuplicateReference {
                action_index: 1,
                index: 0
            }
        );
        let duplicated = builder()
            .with_signed_attachments(unvalidated_proof_carriers(&[
                carrier_attachment("vk_a", vec![1, 2, 3]),
                carrier_attachment("vk_a", vec![1, 2, 3]),
            ]))
            .sign(kp.private_key());
        assert_eq!(
            rejection(&duplicated),
            SignedAttachmentErrorV1::DuplicateProofContent {
                first: 0,
                second: 1
            }
        );
        // Unused declaration.
        assert_eq!(
            rejection(&tampered(&|_, occurrences| {
                occurrences.push(SignedAttachmentOccurrenceV1::new(
                    2,
                    AttachmentKindV1::Proof,
                    vec![0xEE; 8],
                ));
            })),
            SignedAttachmentErrorV1::UnreferencedOccurrence { index: 2 }
        );
        // Another declared type and role.
        assert_eq!(
            rejection(&tampered(&|actions, _| {
                actions[0].attachments[0].kind = AttachmentKindV1::KeyMaterial;
            })),
            SignedAttachmentErrorV1::ReferenceKindMismatch {
                action_index: 0,
                index: 0
            }
        );
        assert_eq!(
            rejection(&tampered(&|actions, _| {
                actions[0].attachments[0].role = AttachmentRoleV1::VerifyingKey;
            })),
            SignedAttachmentErrorV1::ReferenceRoleMismatch {
                action_index: 0,
                index: 0
            }
        );

        // Replay of a signed descriptor: the same actions and occurrences under
        // another nonce carry statement digests of another ordered intent.
        let mut lifted = valid.payload().clone();
        lifted.nonce = std::num::NonZeroU32::new(77);
        let expected = lifted
            .action_statement_digests_v1()
            .expect("statement digests")[0];
        assert_eq!(
            rejection(&sign(lifted)),
            SignedAttachmentErrorV1::StatementBindingMismatch {
                action_index: 0,
                expected,
                actual: valid.attachments().unwrap().actions()[0].statement_digest,
            }
        );

        // A native instruction action is well formed and bound, but no route
        // consumes its attachments yet.
        let log_wire_id = iroha_data_model::isi::instruction_wire_id(&InstructionBox::from(
            Log::new(Level::INFO, "attachments".to_owned()),
        ))
        .expect("Log is registered")
        .to_owned();
        let mut plan = SignedAttachmentPlanV1::new();
        plan.push_action(PlannedActionV1 {
            operation: ActionOperationV1::NativeInstruction(log_wire_id),
            role: ActionRoleV1::ProofEffect,
            authority: ActionAuthorityBindingV1::TransactionAuthority,
            invocation: ActionInvocationBindingV1::Direct {
                instruction_index: 0,
            },
            public_inputs_digest: ActionPublicInputsDigestV1::new([0x5a; 32]),
            attachments: vec![PlannedAttachmentV1 {
                kind: AttachmentKindV1::Proof,
                role: AttachmentRoleV1::ActionProof,
                bytes: vec![0xAA; 48],
            }],
        });
        let native = builder()
            .with_attachment_plan(plan)
            .expect("schema-valid native action")
            .sign(kp.private_key());
        native
            .validate_signed_attachments_v1()
            .expect("the shared predicate accepts the declaration");
        assert_eq!(
            rejection(&native),
            SignedAttachmentErrorV1::UnsupportedOperation { action_index: 0 }
        );
        assert!(super::attachment_operation_is_supported(
            &ActionOperationV1::TransactionProof
        ));
        assert!(super::attachment_operation_is_supported(
            &ActionOperationV1::IvmProvedExecution
        ));
        assert_eq!(super::first_unsupported_attachment_operation(&valid), None);
    }
    #[test]
    fn ceiling_sized_attachment_is_admitted_and_one_byte_over_is_rejected() {
        use iroha_data_model::transaction::signed_attachments::SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1;
        let (authority_id, kp) = gen_account_in("wonderland");
        let signed_with = |attachment: &ProofAttachment| {
            TransactionBuilder::new(
                test_network_id(),
                authority_id.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "ceiling".to_owned())])
            .with_signed_attachments(unvalidated_proof_carriers(std::slice::from_ref(attachment)))
            .sign(kp.private_key())
        };
        // The committed defaults: a 10 MiB transaction and 10 MiB of attachment bytes.
        let defaults = TransactionParameters::default();

        let at_ceiling = signed_with(&carrier_attachment_with_frame_len(
            SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1,
        ));
        let occurrence_bytes = at_ceiling
            .attachments()
            .expect("attachments")
            .total_occurrence_bytes();
        assert_eq!(occurrence_bytes, SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1);
        let framed_len = norito::encode_canonical(&at_ceiling)
            .expect("canonical frame")
            .len();
        assert!(
            u64::try_from(framed_len).unwrap() <= defaults.max_tx_bytes().get(),
            "a ceiling-sized occurrence must fit the transaction cap"
        );
        admit(&at_ceiling, defaults).expect("a ceiling-sized occurrence is admitted");

        let one_over = signed_with(&carrier_attachment_with_frame_len(
            SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1 + 1,
        ));
        assert_eq!(
            admit(&one_over, defaults),
            Err(AcceptTransactionFail::SignedAttachments(
                SignedAttachmentErrorV1::OccurrenceTooLarge {
                    index: 0,
                    actual: SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1 + 1,
                    maximum: SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1,
                }
            ))
        );

        // The complete framed transaction is measured against the committed cap.
        let limits_with = |max_tx_bytes: usize, max_decompressed_bytes: usize| {
            TransactionParameters::with_max_signatures(
                defaults.max_signatures(),
                defaults.max_instructions(),
                defaults.ivm_bytecode_size(),
                NonZeroU64::new(u64::try_from(max_tx_bytes).unwrap()).unwrap(),
                NonZeroU64::new(u64::try_from(max_decompressed_bytes).unwrap()).unwrap(),
                defaults.max_metadata_depth(),
            )
        };
        admit(&at_ceiling, limits_with(framed_len, occurrence_bytes))
            .expect("exactly the transaction cap and exactly the attachment byte budget");
        match admit(&at_ceiling, limits_with(framed_len - 1, occurrence_bytes)) {
            Err(AcceptTransactionFail::TransactionLimit(limit)) => {
                assert!(limit.reason.contains("Transaction size"), "{limit:?}");
            }
            other => panic!("expected the transaction cap to refuse, got {other:?}"),
        }
        match admit(&at_ceiling, limits_with(framed_len, occurrence_bytes - 1)) {
            Err(AcceptTransactionFail::TransactionLimit(limit)) => {
                assert!(limit.reason.contains("attachments expand"), "{limit:?}");
            }
            other => panic!("expected the attachment byte budget to refuse, got {other:?}"),
        }
    }
    #[test]
    fn ceiling_sized_raw_native_proof_passes_every_size_check_and_lacks_only_a_route() {
        use iroha_data_model::transaction::signed_attachments::{
            ActionAuthorityBindingV1, ActionInvocationBindingV1, ActionPublicInputsDigestV1,
            ActionRoleV1, AttachmentKindV1, AttachmentRoleV1, PlannedActionV1, PlannedAttachmentV1,
            SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1, SignedAttachmentPlanV1,
        };
        let (authority_id, kp) = gen_account_in("wonderland");
        let defaults = TransactionParameters::default();
        let log = || Log::new(Level::INFO, "ceiling".to_owned());
        let log_wire_id = iroha_data_model::isi::instruction_wire_id(&InstructionBox::from(log()))
            .expect("Log is registered")
            .to_owned();
        // One native action whose single occurrence is a raw proof of exactly
        // the 9,437,184-byte proof ceiling: no wrapper counts toward it.
        let mut plan = SignedAttachmentPlanV1::new();
        plan.push_action(PlannedActionV1 {
            operation: ActionOperationV1::NativeInstruction(log_wire_id),
            role: ActionRoleV1::ProofEffect,
            authority: ActionAuthorityBindingV1::TransactionAuthority,
            invocation: ActionInvocationBindingV1::Direct {
                instruction_index: 0,
            },
            public_inputs_digest: ActionPublicInputsDigestV1::new([0x5a; 32]),
            attachments: vec![PlannedAttachmentV1 {
                kind: AttachmentKindV1::Proof,
                role: AttachmentRoleV1::ActionProof,
                bytes: vec![0x5a; SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1],
            }],
        });
        let raw_ceiling = TransactionBuilder::new(
            test_network_id(),
            authority_id,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([log()])
        .with_attachment_plan(plan)
        .expect("a ceiling-sized raw proof is schema-valid")
        .sign(kp.private_key());
        assert_eq!(
            raw_ceiling
                .attachments()
                .expect("attachments")
                .total_occurrence_bytes(),
            9_437_184
        );
        let framed_len = norito::encode_canonical(&raw_ceiling)
            .expect("canonical frame")
            .len();
        assert!(
            u64::try_from(framed_len).unwrap() <= defaults.max_tx_bytes().get(),
            "a ceiling-sized raw proof must fit the 10 MiB transaction cap"
        );
        raw_ceiling
            .validate_signed_attachments_v1()
            .expect("the shared predicate accepts the ceiling-sized declaration");
        // The transaction cap and the schema admit it. The node refuses it only
        // because no executor route consumes a native instruction action yet
        // (`attachment_operation_is_supported`, TODO(I.2, I.3)).
        assert_eq!(
            admit(&raw_ceiling, defaults),
            Err(AcceptTransactionFail::SignedAttachments(
                SignedAttachmentErrorV1::UnsupportedOperation { action_index: 0 }
            ))
        );
    }
    #[test]
    fn attachments_decompressed_limit_enforced() {
        use std::time::Duration;
        let (authority_id, kp) = gen_account_in("wonderland");
        let proof = ProofBox::new("halo2/ipa".into(), vec![0u8; 192]);
        let vk_id = VerifyingKeyId::new("halo2/ipa", "vk_limit");
        let attachment = ProofAttachment::new_ref("halo2/ipa".into(), proof, vk_id);
        let attachments = vec![attachment];
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "proof".to_string())])
        .with_proof_attachments(attachments)
        .expect("valid proof carriers")
        .sign(kp.private_key());
        let limits = TransactionParameters::with_max_signatures(
            NonZeroU64::new(1).unwrap(),
            NonZeroU64::new(10).unwrap(),
            NonZeroU64::new(4096).unwrap(),
            NonZeroU64::new(1_048_576).unwrap(),
            NonZeroU64::new(128).unwrap(),
            NonZeroU16::new(8).unwrap(),
        );
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let err = AcceptedTransaction::validate_with_now(
            &tx,
            &test_network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            tx.creation_time(),
        )
        .expect_err("attachments exceeding max_decompressed_bytes must be rejected");
        match err {
            AcceptTransactionFail::TransactionLimit(limit) => {
                assert!(
                    limit.reason.contains("attachments expand"),
                    "expected max_decompressed_bytes rejection, got {limit:?}"
                );
            }
            other => panic!("expected TransactionLimit failure, got {other:?}"),
        }
    }
    #[test]
    fn malformed_proof_attachments_rejected_at_transaction_admission() {
        use std::time::Duration;
        let (authority_id, kp) = gen_account_in("wonderland");
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let limits = TransactionParameters::default();
        let mut zero_vk_commitment = ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("halo2/ipa", "vk_admission"),
        );
        zero_vk_commitment.vk_commitment = Some([0u8; 32]);
        let mut zero_envelope_hash = ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("halo2/ipa", "vk_admission"),
        );
        zero_envelope_hash.envelope_hash = Some([0u8; 32]);
        let mut forged_envelope_hash = ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("halo2/ipa", "vk_admission"),
        );
        let mut forged_hash: [u8; 32] =
            iroha_crypto::Hash::new(&forged_envelope_hash.proof.bytes).into();
        forged_hash[0] ^= 0x80;
        forged_envelope_hash.envelope_hash = Some(forged_hash);
        assert!(matches!(
            TransactionBuilder::new(
                test_network_id(),
                authority_id.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_proof_attachments(Vec::new()),
            Err(SignedAttachmentErrorV1::NoActions)
        ));
        let cases = [
            (
                "proof-backend-mismatch",
                vec![ProofAttachment::new_ref(
                    "halo2/ipa".into(),
                    ProofBox::new("stark/fri".into(), vec![1, 2, 3]),
                    VerifyingKeyId::new("halo2/ipa", "vk_admission"),
                )],
                "proof.backend",
            ),
            (
                "nonportable-vk-ref-name",
                vec![ProofAttachment::new_ref(
                    "halo2/ipa".into(),
                    ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
                    VerifyingKeyId::new("halo2/ipa", "VkAdmission"),
                )],
                "vk_ref",
            ),
            (
                "empty-proof-bytes",
                vec![ProofAttachment::new_ref(
                    "halo2/ipa".into(),
                    ProofBox::new("halo2/ipa".into(), Vec::new()),
                    VerifyingKeyId::new("halo2/ipa", "vk_admission"),
                )],
                "proof.bytes",
            ),
            (
                "zero-vk-commitment",
                vec![zero_vk_commitment],
                "vk_commitment",
            ),
            (
                "zero-envelope-hash",
                vec![zero_envelope_hash],
                "envelope_hash",
            ),
            (
                "forged-envelope-hash",
                vec![forged_envelope_hash],
                "envelope_hash",
            ),
        ];
        for (label, attachments, expected_reason) in cases {
            let tx = TransactionBuilder::new(
                test_network_id(),
                authority_id.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, format!("proof-{label}"))])
            .with_signed_attachments(unvalidated_proof_carriers(&attachments))
            .sign(kp.private_key());
            let err = AcceptedTransaction::validate_with_now(
                &tx,
                &test_network_id(),
                Duration::from_secs(0),
                limits,
                &crypto_cfg,
                tx.creation_time(),
            )
            .expect_err("malformed proof attachment must be rejected at admission");
            match err {
                AcceptTransactionFail::SignedAttachments(
                    SignedAttachmentErrorV1::MalformedProofCarrier { index: 0, reason },
                ) => {
                    assert!(
                        reason.contains(expected_reason),
                        "case {label}: expected reason to contain {expected_reason}, got {reason}"
                    );
                }
                other => {
                    panic!("case {label}: expected a malformed proof carrier, got {other:?}")
                }
            }
        }
    }
    #[test]
    fn accept_transaction_requires_expires_at_height_when_configured() {
        use iroha_data_model::isi::Log;
        use iroha_logger::Level;
        use std::time::Duration;
        let (authority_id, kp) = gen_account_in("wonderland");
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "ttl".into())])
        .sign(kp.private_key());
        let default_limits = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            default_limits.max_signatures(),
            default_limits.max_instructions(),
            default_limits.ivm_bytecode_size(),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        )
        .with_ingress_enforcement(true, false);
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let time_source = TimeSource::new_fixed(tx.creation_time());
        let err = AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect_err("transactions must provide expires_at_height when required");
        match err {
            AcceptTransactionFail::TransactionLimit(limit) => {
                assert!(
                    limit.reason.contains("expires_at_height"),
                    "expected expires_at_height failure, got {limit:?}"
                );
            }
            other => panic!("expected TransactionLimit failure, got {other:?}"),
        }
    }
    #[test]
    fn accept_transaction_requires_tx_sequence_when_configured() {
        use iroha_data_model::isi::Log;
        use iroha_logger::Level;
        use std::time::Duration;
        let (authority_id, kp) = gen_account_in("wonderland");
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "seq".into())])
        .sign(kp.private_key());
        let default_limits = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            default_limits.max_signatures(),
            default_limits.max_instructions(),
            default_limits.ivm_bytecode_size(),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        )
        .with_ingress_enforcement(false, true);
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let time_source = TimeSource::new_fixed(tx.creation_time());
        let err = AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect_err("transactions must provide tx_sequence when required");
        match err {
            AcceptTransactionFail::TransactionLimit(limit) => {
                assert!(
                    limit.reason.contains("tx_sequence"),
                    "expected tx_sequence failure, got {limit:?}"
                );
            }
            other => panic!("expected TransactionLimit failure, got {other:?}"),
        }
    }
    #[test]
    fn signature_verification_result_reports_invalid_signature() {
        use std::time::Duration;
        let (authority_id, kp) = gen_account_in("wonderland");
        let (other_id, _other_kp) = gen_account_in("underland");
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "sig".into())])
        .sign(kp.private_key());
        let tampered = tx.with_authority(other_id);
        let err =
            AcceptedTransaction::signature_verification_result(&tampered).expect_err("must fail");
        assert_eq!(err.code, SignatureRejectionCode::InvalidSignature);
        let now = tampered.creation_time();
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let result = AcceptedTransaction::validate_with_now(
            &tampered,
            &test_network_id(),
            Duration::ZERO,
            limits,
            &crypto_cfg,
            now,
        );
        assert!(matches!(
            result,
            Err(AcceptTransactionFail::SignatureVerification(err))
                if err.code == SignatureRejectionCode::InvalidSignature
        ));
    }
    #[test]
    fn retired_heartbeat_string_marker_is_rejected() {
        use std::time::Duration;
        let signer = checked_random_tx_keypair_with_algorithm(Algorithm::Ed25519);
        let (_handle, time_source) = TimeSource::new_mock(Duration::from_millis(1));
        let authority = AccountId::new(signer.public_key().clone());
        let mut metadata = Metadata::default();
        metadata.insert(HEARTBEAT_METADATA_NAME.clone(), Json::new("true"));
        let tx = TransactionBuilder::new_with_time_source(
            test_network_id(),
            authority,
            &time_source,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(metadata)
        .sign(signer.private_key());
        let tx_params = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let error = AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::ZERO,
            tx_params,
            &crypto_cfg,
            &time_source,
        )
        .expect_err("retired string heartbeat marker must be rejected");
        assert!(matches!(
            error,
            AcceptTransactionFail::TransactionLimit(limit)
                if limit.reason.contains("sumeragi_heartbeat")
                    && limit.reason.contains("retired")
        ));
    }
    #[test]
    fn retired_heartbeat_false_marker_is_rejected() {
        use std::time::Duration;
        let signer = checked_random_tx_keypair_with_algorithm(Algorithm::Ed25519);
        let (_handle, time_source) = TimeSource::new_mock(Duration::from_millis(1));
        let authority = AccountId::new(signer.public_key().clone());
        let mut metadata = Metadata::default();
        metadata.insert(HEARTBEAT_METADATA_NAME.clone(), Json::new(false));
        let tx = TransactionBuilder::new_with_time_source(
            test_network_id(),
            authority,
            &time_source,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(metadata)
        .sign(signer.private_key());
        let tx_params = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let err = AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::ZERO,
            tx_params,
            &crypto_cfg,
            &time_source,
        )
        .expect_err("false heartbeat marker should be rejected");
        match err {
            AcceptTransactionFail::TransactionLimit(limit) => {
                assert!(
                    limit.reason.contains("sumeragi_heartbeat"),
                    "expected heartbeat marker rejection, got {limit:?}"
                );
            }
            other => panic!("expected TransactionLimit failure, got {other:?}"),
        }
    }
    #[test]
    fn retired_heartbeat_arbitrary_marker_is_rejected() {
        use std::time::Duration;
        let signer = checked_random_tx_keypair_with_algorithm(Algorithm::Ed25519);
        let (_handle, time_source) = TimeSource::new_mock(Duration::from_millis(1));
        let authority = AccountId::new(signer.public_key().clone());
        let mut metadata = Metadata::default();
        metadata.insert(HEARTBEAT_METADATA_NAME.clone(), Json::new("nope"));
        let tx = TransactionBuilder::new_with_time_source(
            test_network_id(),
            authority,
            &time_source,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(metadata)
        .sign(signer.private_key());
        let tx_params = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let err = AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::ZERO,
            tx_params,
            &crypto_cfg,
            &time_source,
        )
        .expect_err("invalid heartbeat marker should be rejected");
        match err {
            AcceptTransactionFail::TransactionLimit(limit) => {
                assert!(
                    limit.reason.contains("sumeragi_heartbeat"),
                    "expected heartbeat marker rejection, got {limit:?}"
                );
            }
            other => panic!("expected TransactionLimit failure, got {other:?}"),
        }
    }
    #[test]
    fn retired_heartbeat_marker_rejects_non_empty_transactions() {
        use iroha_data_model::isi::Log;
        use iroha_logger::Level;
        use std::time::Duration;
        let (authority_id, kp) = gen_account_in("wonderland");
        let mut metadata = Metadata::default();
        metadata.insert(HEARTBEAT_METADATA_NAME.clone(), Json::new(true));
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "noop".into())])
        .with_metadata(metadata)
        .sign(kp.private_key());
        let limits = TransactionParameters::default();
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let time_source = TimeSource::new_fixed(tx.creation_time());
        let err = AcceptedTransaction::accept_with_time_source(
            tx,
            &test_network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect_err("retired heartbeat marker must reject a non-empty transaction");
        match err {
            AcceptTransactionFail::TransactionLimit(limit) => {
                assert!(
                    limit.reason.contains("sumeragi_heartbeat") && limit.reason.contains("retired"),
                    "expected heartbeat rejection, got {limit:?}"
                );
            }
            other => panic!("expected retired heartbeat rejection, got {other:?}"),
        }
    }
    include!("tx_height_expiry_inline_tests.rs");
    #[test]
    fn sequence_not_increasing_is_rejected_by_state() {
        use iroha_data_model::{isi::Log, transaction::TransactionBuilder};
        use iroha_logger::Level;
        use iroha_model_base::metadata::Metadata;
        use iroha_primitives::json::Json;
        use std::time::Duration;
        let (mut world, authority_id, kp) = world_with_authority("wonderland");
        world.tx_sequences.insert(authority_id.clone(), 5);

        let chain: ChainId = "seq-check-chain".parse().unwrap();
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
        config.chain_id = chain;
        config
            .genesis_parameters
            .push(iroha_data_model::parameter::Parameter::Transaction(
                iroha_data_model::parameter::system::TransactionParameter::RequireSequence(true),
            ));
        let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
            .expect("apply signed genesis with sequence enforcement");
        assert!(
            chain
                .state()
                .view()
                .world()
                .parameters()
                .transaction()
                .require_sequence,
            "the original signed genesis must retain the requested sequence policy"
        );
        assert_eq!(
            chain.state().view().world().tx_sequences.get(&authority_id),
            Some(&5),
            "original signed genesis must retain the independently seeded previous sequence"
        );
        let mut metadata = Metadata::default();
        metadata.insert(
            iroha_model_base::name::Name::from_str("tx_sequence").unwrap(),
            Json::from(5_u64),
        );
        let tx = TransactionBuilder::new(
            chain.network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "seq".into())])
        .with_metadata(metadata)
        .sign(kp.private_key());
        let default_limits = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            default_limits.max_signatures(),
            default_limits.max_instructions(),
            default_limits.ivm_bytecode_size(),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        )
        .with_ingress_enforcement(false, true);
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let time_source = TimeSource::new_fixed(tx.creation_time());
        let _accepted = AcceptedTransaction::accept_with_time_source(
            tx.clone(),
            &chain.network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("stateless sequence checks should pass when metadata present");
        chain.commit(vec![tx]);
        let committed = chain.committed(2);
        let result = committed
            .block()
            .network_output_at(0)
            .expect("original transaction has a certified execution result")
            .1
            .result
            .0
            .clone();
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg))) => {
                assert!(
                    msg.contains("sequence"),
                    "expected sequence rejection, got {msg}"
                );
            }
            other => panic!(
                "expected Validation::NotPermitted for non-increasing sequence, got {other:?}"
            ),
        }
        assert_eq!(
            chain.state().view().world().tx_sequences.get(&authority_id),
            Some(&5),
            "a rejected signed transaction must not advance the committed sequence"
        );
    }
    #[test]
    fn sequence_increasing_is_accepted_by_state() {
        use iroha_data_model::{isi::Log, transaction::TransactionBuilder};
        use iroha_logger::Level;
        use iroha_model_base::metadata::Metadata;
        use iroha_primitives::json::Json;
        use std::time::Duration;
        let (mut world, authority_id, kp) = world_with_authority("wonderland");
        world.tx_sequences.insert(authority_id.clone(), 5);

        let chain: ChainId = "seq-accept-chain".parse().unwrap();
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
        config.chain_id = chain;
        config
            .genesis_parameters
            .push(iroha_data_model::parameter::Parameter::Transaction(
                iroha_data_model::parameter::system::TransactionParameter::RequireSequence(true),
            ));
        let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
            .expect("apply signed genesis with sequence enforcement");
        assert!(
            chain
                .state()
                .view()
                .world()
                .parameters()
                .transaction()
                .require_sequence,
            "the original signed genesis must retain the requested sequence policy"
        );
        assert_eq!(
            chain.state().view().world().tx_sequences.get(&authority_id),
            Some(&5),
            "original signed genesis must retain the independently seeded previous sequence"
        );
        let mut metadata = Metadata::default();
        metadata.insert(
            iroha_model_base::name::Name::from_str("tx_sequence").unwrap(),
            Json::from(6_u64),
        );
        let tx = TransactionBuilder::new(
            chain.network_id(),
            authority_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "seq".into())])
        .with_metadata(metadata)
        .sign(kp.private_key());
        let default_limits = TransactionParameters::default();
        let limits = TransactionParameters::with_max_signatures(
            default_limits.max_signatures(),
            default_limits.max_instructions(),
            default_limits.ivm_bytecode_size(),
            default_limits.max_tx_bytes(),
            default_limits.max_decompressed_bytes(),
            default_limits.max_metadata_depth(),
        )
        .with_ingress_enforcement(false, true);
        let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
        let time_source = TimeSource::new_fixed(tx.creation_time());
        let _accepted = AcceptedTransaction::accept_with_time_source(
            tx.clone(),
            &chain.network_id(),
            Duration::from_secs(0),
            limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("stateless sequence checks should pass when metadata present");
        chain.commit(vec![tx]);
        let committed = chain.committed(2);
        let result = committed
            .block()
            .network_output_at(0)
            .expect("original transaction has a certified execution result")
            .1
            .result
            .0
            .clone();
        result.expect("sequence should be accepted");
        let updated = chain
            .state()
            .view()
            .world()
            .tx_sequences
            .get(&authority_id)
            .copied()
            .expect("sequence entry must exist");
        assert_eq!(updated, 6);
    }
    #[test]
    fn custom_parameter_cannot_disable_committed_ivm_cycle_ceiling() {
        use iroha_data_model::parameter::{
            Parameter,
            custom::{CustomParameter, CustomParameterId},
        };
        use iroha_model_base::name::Name;
        use iroha_primitives::json::Json;
        let mut fixture = IvmAdmissionFixture::new();
        let mut pipeline = fixture.state.installed_pipeline().clone();
        pipeline.ivm_max_cycles_upper_bound =
            std::num::NonZeroU64::new(1_000).expect("test ceiling is non-zero");
        fixture.state.set_pipeline(pipeline);
        // A custom parameter with the retired name must not disable or override
        // the actual committed pipeline policy frozen for this block.
        let id = CustomParameterId::new(Name::from_str("max_ivm_cycles_upper_bound").unwrap());
        let custom = CustomParameter::new(id, Json::new(0_u64));
        // Build program with max_cycles = 2000
        let result = fixture.validate_program_with(
            minimal_ivm_program_with_max_cycles(1, 2_000),
            None,
            |block| {
                block
                    .world
                    .parameters
                    .get_mut()
                    .set_parameter(Parameter::Custom(custom))
                    .expect("valid fixture parameters");
            },
        );
        match result {
            Err(TransactionRejectionReason::Validation(ValidationFail::IvmAdmission(
                iroha_data_model::executor::IvmAdmissionError::MaxCyclesExceedsUpperBound(info),
            ))) => {
                assert_eq!(info.max_cycles, 2_000);
                assert_eq!(info.upper_bound, 1_000);
            }
            other => panic!("committed cycle ceiling must reject the program, got {other:?}"),
        }
    }
    #[test]
    fn committed_ivm_cycle_ceiling_accepts_within_bound_despite_custom_parameter() {
        use iroha_data_model::{
            parameter::{
                Parameter,
                custom::{CustomParameter, CustomParameterId},
            },
            transaction::{Executable, TransactionBuilder},
        };
        use iroha_model_base::name::Name;
        use iroha_primitives::json::Json;
        let (world, authority_id, kp) = world_with_authority("wonderland");
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query_handle = crate::query::store::LiveQueryStore::start_test();
        let mut state = State::new(world, kura, query_handle);
        let mut pipeline = state.installed_pipeline().clone();
        pipeline.ivm_max_cycles_upper_bound =
            std::num::NonZeroU64::new(4_000).expect("test ceiling is non-zero");
        let policy = crate::pipeline_validity_policy::policy_of(&pipeline);
        state.set_pipeline(pipeline);
        let chain = crate::block::tests::component_chain_with_genesis_parameters(
            state,
            vec![Parameter::Custom(policy.into_custom_parameter())],
        );
        let state = chain.state();
        let header = original_component_successor_header(state);
        let mut block = state.block(header);
        // The retired custom parameter cannot lower the committed ceiling.
        let id = CustomParameterId::new(Name::from_str("max_ivm_cycles_upper_bound").unwrap());
        let custom = CustomParameter::new(id, Json::new(1_u64));
        block
            .world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(custom))
            .expect("valid fixture parameters");
        // Build program with max_cycles = 2000, below the bound
        let prog = minimal_ivm_program_with_max_cycles(1, 2_000);
        let tx = TransactionBuilder::new(
            chain.network_id(),
            authority_id.clone(),
            fee_payment_with_gas_limit(TEST_GAS_LIMIT),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(prog)))
        .sign(kp.private_key());
        let mut ivm_cache = IvmCache::new();
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
        let result =
            execute_component_transaction_for_testing(&mut block, accepted, &mut ivm_cache, None);
        assert!(result.is_ok(), "max_cycles within bound should pass");
    }
    mod time_trigger {
        use super::*;
        /// # Scenario
        ///
        /// 1. Transaction: Alice sends a large donation to Bob.
        /// 2. Data trigger: Bob forwards the donation to Carol.
        /// 3. Time trigger: Carol attempts to send the donation to Dave; this should fail if step 2 did not occur.
        /// 4. Data trigger: Dave forwards the donation to Eve.
        #[tokio::test]
        async fn fires_after_external_transactions() {
            let mut sandbox = Sandbox::default()
                .with_data_trigger_transfer("bob", 50, "carol")
                .with_time_trigger_transfer("carol", 50, "dave")
                .with_data_trigger_transfer("dave", 50, "eve");
            sandbox.request_transfer("alice", 50, "bob");
            let mut block = sandbox.block();
            block.assert_balances([
                ("alice", 60),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 10),
            ]);
            let (events, _) = block.apply();
            assert_events(&events, "time_trigger/fires_after_external_transactions");
            block.assert_balances([
                ("alice", 10),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 60),
            ]);
        }
    }
    mod data_trigger {
        use super::*;
        /// # Scenario
        ///
        /// 1. Transaction: Alice sends a large donation to Bob.
        /// 2. Data trigger: Bob forwards the donation to Carol.
        /// 3. Transaction: Carol attempts to send the donation to Dave; this should fail if step 2 did not occur.
        #[tokio::test]
        async fn fires_for_each_transaction() {
            let mut sandbox = Sandbox::default().with_data_trigger_transfer("bob", 50, "carol");
            sandbox.request_transfer("alice", 50, "bob");
            sandbox.request_transfer("carol", 50, "dave");
            let mut block = sandbox.block();
            block.assert_balances([("alice", 60), ("bob", 10), ("carol", 10), ("dave", 10)]);
            let (events, _committed_block) = block.apply();
            assert_events(&events, "data_trigger/fires_for_each_transaction");
            block.assert_balances([("alice", 10), ("bob", 10), ("carol", 10), ("dave", 60)]);
        }
        /// # Scenario
        ///
        /// 1. Transaction: Alice sends the asset to Bob in two separate packages, emitting two events.
        /// 2. Data trigger: Bob forwards each package to Carol; it fires once per matching instruction,
        ///    even when the events are emitted within the same transaction.
        #[tokio::test]
        async fn fires_for_each_matching_instruction() {
            let mut sandbox = Sandbox::default().with_data_trigger_transfer("bob", 10, "carol");
            sandbox.request_transfers_batched::<2>("alice", 10, "bob");
            let mut block = sandbox.block();
            block.assert_balances([("alice", 60), ("bob", 10), ("carol", 10)]);
            let (events, _committed_block) = block.apply();
            assert_events(&events, "data_trigger/fires_for_each_matching_instruction");
            block.assert_balances([("alice", 40), ("bob", 10), ("carol", 30)]);
        }
        /// # Scenario
        ///
        /// 1. Transaction: Alice sends a large donation to Bob.
        /// 2. Data triggers: Bob forwards the donation to Carol, Carol forwards it to Dave, and Dave forwards it back to Bob.
        /// 3. Data trigger: Bob forwards the donation to Eve; this should fail if step 2 has not completed.
        #[tokio::test]
        async fn chains_in_depth_first_order() {
            let mut sandbox = Sandbox::default()
                // Carol receives it before Eve because triggers matching the same event are processed in lexicographical order of their IDs.
                .with_data_trigger_transfer_once("bob", 50, "carol")
                // Sibling trigger waits for depth-first resolution.
                .with_data_trigger_transfer_once("bob", 50, "eve")
                .with_data_trigger_transfer("carol", 50, "dave")
                .with_data_trigger_transfer("dave", 50, "bob");
            sandbox.request_transfer("alice", 50, "bob");
            let mut block = sandbox.block();
            block.assert_balances([
                ("alice", 60),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 10),
            ]);
            let (events, _committed_block) = block.apply();
            assert_events(&events, "data_trigger/chains_in_depth_first_order");
            block.assert_balances([
                ("alice", 10),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 60),
            ]);
        }
        /// # Scenario
        ///
        /// 1. Transaction: Alice sends 50 units to Bob.
        /// 2. Data triggers: each branch (Bob -> Carol -> Dave -> Eve) runs independently to a max depth of 3, forwarding 1 unit per step.
        fn depth_three_branch_sandbox(
            profile: Option<iroha_data_model::parameter::FastpqSourcePolicyV1>,
        ) -> Sandbox {
            Sandbox::with_genesis_fastpq_source_policy(profile)
                .with_max_execution_depth(3)
                // Branches: Bob -> Carol
                .with_data_trigger_transfer_labeled("bob", 1, "carol", 0)
                .with_data_trigger_transfer_labeled("bob", 1, "carol", 1)
                .with_data_trigger_transfer_labeled("bob", 1, "carol", 2)
                .with_data_trigger_transfer_labeled("bob", 1, "carol", 3)
                .with_data_trigger_transfer_labeled("bob", 1, "carol", 4)
                .with_data_trigger_transfer_labeled("bob", 1, "carol", 5)
                .with_data_trigger_transfer_labeled("bob", 1, "carol", 6)
                // Common path: Carol -> Dave -> Eve
                .with_data_trigger_transfer("carol", 1, "dave")
                .with_data_trigger_transfer("dave", 1, "eve")
        }
        #[tokio::test]
        async fn each_branch_is_assigned_depth() {
            // This depth corpus contains one external transfer and 7 * 3 callbacks.
            // Give that exact finite corpus its own signed genesis source profile.
            // Production bootstrap ceilings and all source byte ceilings stay unchanged.
            let parameters = iroha_data_model::parameter::system::Parameters::default();
            let previous = parameters.block().fastpq_source();
            let mut intrinsic = previous.intrinsic;
            intrinsic.max_transcripts = 1 + 7 * 3;
            intrinsic.max_deltas = intrinsic.max_transcripts;
            let profile = iroha_data_model::parameter::FastpqSourcePolicyV1::from_sizing(
                parameters.block().execution_output(),
                intrinsic,
                previous.mandatory,
                iroha_data_model::parameter::FastpqSourcePolicyV1::BOOTSTRAP_NETWORK_INPUTS,
            )
            .expect("exact 22-transfer depth corpus has a coherent finite source policy");
            let mut sandbox = depth_three_branch_sandbox(Some(profile));
            assert_eq!(
                sandbox
                    .state
                    .view()
                    .world()
                    .parameters()
                    .block()
                    .fastpq_source(),
                profile
            );
            sandbox.request_transfer("alice", 50, "bob");
            let mut block = sandbox.block();
            block.assert_balances([
                ("alice", 60),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 10),
            ]);
            let (events, committed_block) = block.apply();
            let results = committed_block
                .as_ref()
                .output_results()
                .collect::<Vec<_>>();
            assert!(
                results.iter().all(|result| result.is_ok()),
                "each independent depth-three branch must complete under its original configured bound: {results:?}"
            );
            assert_events(&events, "data_trigger/each_branch_is_assigned_depth");
            block.assert_balances([
                ("alice", 10),
                ("bob", 53),
                ("carol", 10),
                ("dave", 10),
                ("eve", 17),
            ]);
        }
        #[tokio::test]
        async fn depth_three_branch_corpus_retains_the_bootstrap_source_limit() {
            let mut sandbox = depth_three_branch_sandbox(None);
            let profile = sandbox
                .state
                .view()
                .world()
                .parameters()
                .block()
                .fastpq_source();
            assert_eq!(
                profile,
                iroha_data_model::parameter::FastpqSourcePolicyV1::bootstrap()
            );
            sandbox.request_transfer("alice", 50, "bob");
            let mut block = sandbox.block();
            let (events, committed) = block.apply();
            let results = committed.as_ref().output_results().collect::<Vec<_>>();
            assert_eq!(results.len(), 1);
            assert!(
                matches!(results[0].as_ref(),
                    Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message)))
                        if message == crate::fastpq::source_reservation::admission::SOURCE_INTRINSIC_REJECTION
                ),
                "the original finite source limit must refuse the entire 22-transfer corpus: {results:?}"
            );
            assert!(
                events
                    .iter()
                    .all(|event| !matches!(event, EventBox::Data(_)))
            );
            block.assert_balances([
                ("alice", 60),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 10),
            ]);
        }
        /// All or none of the initial transaction and subsequent data triggers should take effect.
        #[tokio::test]
        async fn atomically_chains_from_transaction() {
            let sandbox = || {
                let mut res = Sandbox::default();
                res.request_transfer("alice", 50, "bob");
                res
            };
            aborts_on_execution_error(sandbox(), "txn");
            aborts_on_exceeding_depth(sandbox(), "txn");
            commits_on_depleting_lives(sandbox(), "txn");
            commits_on_regular_success(sandbox(), "txn");
        }
        /// All or none of the initial time trigger and subsequent data triggers should take effect.
        #[tokio::test]
        async fn atomically_chains_from_time_trigger() {
            let sandbox = || Sandbox::default().with_time_trigger_transfer("alice", 50, "bob");
            aborts_on_execution_error(sandbox(), "time");
            aborts_on_exceeding_depth(sandbox(), "time");
            commits_on_depleting_lives(sandbox(), "time");
            commits_on_regular_success(sandbox(), "time");
        }
        /// Negative transfer amounts cannot cross the nominal quantity boundary.
        #[test]
        fn negative_transfer_amount_cannot_be_constructed() {
            let negative = Numeric::try_new(-1_i128, 0).expect("negative numeric amount");
            assert!(Quantity::try_from_numeric(negative).is_err());
        }
        /// Data trigger chains must roll back when a transfer uses a zero amount.
        #[tokio::test]
        async fn atomically_aborts_on_zero_amount_from_transaction() {
            let sandbox = || {
                let mut res = Sandbox::default();
                res.request_transfer("alice", 50, "bob");
                res
            };
            aborts_on_zero_amount(sandbox(), "txn");
        }
        /// Zero transfer amounts should abort chains initiated by time triggers as well.
        #[tokio::test]
        async fn atomically_aborts_on_zero_amount_from_time_trigger() {
            let sandbox = || Sandbox::default().with_time_trigger_transfer("alice", 50, "bob");
            aborts_on_zero_amount(sandbox(), "time");
        }
        fn aborts_on_execution_error(sandbox: Sandbox, snapshot_suffix: &str) {
            let mut sandbox = sandbox
                .with_data_trigger_transfer("bob", 10, "carol")
                .with_data_trigger_transfer("bob", 10, "dave")
                // This trigger execution fails.
                .with_data_trigger_transfer("dave", 500, "eve");
            let mut block = sandbox.block();
            block.assert_balances([
                ("alice", 60),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 10),
            ]);
            let (events, _committed_block) = block.apply();
            let data_events = events
                .iter()
                .filter(|event| matches!(event, EventBox::Data(_)))
                .count();
            assert_eq!(
                data_events, 0,
                "failing data trigger must not emit persisted data events"
            );
            assert_events(
                &events,
                format!("data_trigger/aborts_on_execution_error-{snapshot_suffix}"),
            );
            // Everything should be rolled back.
            block.assert_balances([
                ("alice", 60),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 10),
            ]);
        }
        fn aborts_on_zero_amount(sandbox: Sandbox, snapshot_suffix: &str) {
            let mut sandbox = sandbox
                .with_data_trigger_transfer("bob", 10, "carol")
                .with_data_trigger_transfer("bob", 10, "dave")
                .with_data_trigger_transfer_quantity("dave", Quantity::zero(), "eve");
            let mut block = sandbox.block();
            block.assert_balances([
                ("alice", 60),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 10),
            ]);
            let (events, _committed_block) = block.apply();
            let data_events = events
                .iter()
                .filter(|event| matches!(event, EventBox::Data(_)))
                .count();
            assert_eq!(
                data_events, 0,
                "failing data trigger must not emit persisted data events"
            );
            assert_events(
                &events,
                format!("data_trigger/aborts_on_zero_amount-{snapshot_suffix}"),
            );
            block.assert_balances([
                ("alice", 60),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 10),
            ]);
        }
        fn aborts_on_exceeding_depth(sandbox: Sandbox, snapshot_suffix: &str) {
            let mut sandbox = sandbox
                .with_max_execution_depth(2)
                .with_data_trigger_transfer("bob", 50, "carol")
                .with_data_trigger_transfer("carol", 50, "dave")
                // The execution sequence exceeds the depth limit.
                .with_data_trigger_transfer("dave", 50, "eve");
            let mut block = sandbox.block();
            block.assert_balances([
                ("alice", 60),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 10),
            ]);
            let (events, _committed_block) = block.apply();
            assert_events(
                &events,
                format!("data_trigger/aborts_on_exceeding_depth-{snapshot_suffix}"),
            );
            // Everything should be rolled back.
            block.assert_balances([
                ("alice", 60),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 10),
            ]);
        }
        fn commits_on_depleting_lives(sandbox: Sandbox, snapshot_suffix: &str) {
            let mut sandbox = sandbox
                .with_data_trigger_transfer("bob", 50, "carol")
                // This trigger depletes after an execution.
                .with_data_trigger_transfer_once("carol", 50, "bob");
            let mut block = sandbox.block();
            block.assert_balances([("alice", 60), ("bob", 10), ("carol", 10)]);
            let (events, _committed_block) = block.apply();
            assert_events(
                &events,
                format!("data_trigger/commits_on_depleting_lives-{snapshot_suffix}"),
            );
            // The execution sequence should take effect.
            block.assert_balances([("alice", 10), ("bob", 10), ("carol", 60)]);
        }
        fn commits_on_regular_success(sandbox: Sandbox, snapshot_suffix: &str) {
            let mut sandbox = sandbox
                .with_max_execution_depth(3)
                .with_data_trigger_transfer("bob", 50, "carol")
                .with_data_trigger_transfer("carol", 50, "dave")
                .with_data_trigger_transfer("dave", 50, "eve");
            let mut block = sandbox.block();
            block.assert_balances([
                ("alice", 60),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 10),
            ]);
            let (events, _committed_block) = block.apply();
            assert_events(
                &events,
                format!("data_trigger/commits_on_regular_success-{snapshot_suffix}"),
            );
            // The execution sequence should take effect.
            block.assert_balances([
                ("alice", 10),
                ("bob", 10),
                ("carol", 10),
                ("dave", 10),
                ("eve", 60),
            ]);
        }
    }
    include!("tx/empty_instruction_test.rs");
    #[test]
    fn lane_privacy_proofs_collected_from_attachments() {
        let (authority, keypair) = gen_account_in("wonderland");
        let backend = Ident::from_str("halo2/ipa").expect("ident");
        let proof1 = LanePrivacyProof {
            commitment_id: LaneCommitmentId::new(1),
            witness: LanePrivacyWitness::Merkle(LanePrivacyMerkleWitness {
                leaf: [0x11; 32],
                proof: MerkleProof::from_audit_path_bytes(0, vec![[0x33; 32]]),
            }),
        };
        let proof2 = LanePrivacyProof {
            commitment_id: LaneCommitmentId::new(2),
            witness: LanePrivacyWitness::Merkle(LanePrivacyMerkleWitness {
                leaf: [0x22; 32],
                proof: MerkleProof::from_audit_path_bytes(0, vec![[0x44; 32]]),
            }),
        };
        let mut attachment1 = ProofAttachment::new_ref(
            backend.clone(),
            ProofBox::new(backend.clone(), vec![0xAA]),
            VerifyingKeyId::new(backend.clone(), "vk_lane_1"),
        );
        attachment1.lane_privacy = Some(proof1.clone());
        let mut attachment2 = ProofAttachment::new_ref(
            backend.clone(),
            ProofBox::new(backend.clone(), vec![0xCC]),
            VerifyingKeyId::new(backend, "vk_lane_2"),
        );
        attachment2.lane_privacy = Some(proof2.clone());
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "noop".into())])
        .with_proof_attachments(vec![attachment1, attachment2])
        .expect("valid proof carriers")
        .sign(keypair.private_key());
        let collected_proofs = super::collect_lane_privacy_proofs(&tx);
        let ids: BTreeSet<_> = collected_proofs
            .iter()
            .map(|proof| proof.commitment_id())
            .collect();
        assert_eq!(collected_proofs.len(), 2);
        assert!(ids.contains(&LaneCommitmentId::new(1)));
        assert!(ids.contains(&LaneCommitmentId::new(2)));
    }
    #[test]
    fn state_manifest_quorum_requires_approvers() {
        let primary_keypair = checked_fixture_keypair(vec![0x11; 32], Algorithm::Ed25519);
        let secondary_keypair = checked_fixture_keypair(vec![0x22; 32], Algorithm::Ed25519);
        let primary_id = AccountId::new(primary_keypair.public_key().clone());
        let secondary_id = AccountId::new(secondary_keypair.public_key().clone());
        let rules = GovernanceRules {
            validators: vec![primary_id.clone(), secondary_id.clone()],
            quorum: Some(2),
            ..GovernanceRules::default()
        };
        let lane_alias = "gov";
        let tx = TransactionBuilder::new(
            test_network_id(),
            primary_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "noop".into())])
        .sign(primary_keypair.private_key());
        match enforce_manifest_quorum(lane_alias, &rules, &tx) {
            Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg))) => {
                assert!(
                    msg.contains("quorum"),
                    "expected quorum rejection, got {msg}"
                );
            }
            other => panic!("expected quorum rejection, got {other:?}"),
        }
        let mut metadata = Metadata::default();
        metadata.insert(
            (*super::GOV_APPROVERS_METADATA_KEY).clone(),
            Json::new(vec![secondary_id.to_string()]),
        );
        let tx = TransactionBuilder::new(
            test_network_id(),
            primary_id,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "noop".into())])
        .with_metadata(metadata)
        .sign(primary_keypair.private_key());
        let result = enforce_manifest_quorum(lane_alias, &rules, &tx);
        assert!(result.is_ok(), "quorum satisfied should pass: {result:?}");
    }
    #[test]
    fn state_manifest_quorum_rejects_duplicate_validators() {
        let primary_keypair = checked_fixture_keypair(vec![0x11; 32], Algorithm::Ed25519);
        let primary_id = AccountId::new(primary_keypair.public_key().clone());
        let rules = GovernanceRules {
            validators: vec![primary_id.clone(), primary_id],
            ..GovernanceRules::default()
        };
        match super::canonical_manifest_validators("gov", &rules) {
            Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg))) => {
                assert!(
                    msg.contains("duplicate validators"),
                    "expected duplicate validator rejection, got {msg}"
                );
            }
            other => panic!("expected duplicate validator rejection, got {other:?}"),
        }
    }
    #[test]
    fn state_manifest_quorum_rejects_duplicate_approvers() {
        let primary_keypair = checked_fixture_keypair(vec![0x11; 32], Algorithm::Ed25519);
        let secondary_keypair = checked_fixture_keypair(vec![0x22; 32], Algorithm::Ed25519);
        let primary_id = AccountId::new(primary_keypair.public_key().clone());
        let secondary_id = AccountId::new(secondary_keypair.public_key().clone());
        let rules = GovernanceRules {
            validators: vec![primary_id.clone(), secondary_id.clone()],
            quorum: Some(2),
            ..GovernanceRules::default()
        };
        let mut metadata = Metadata::default();
        metadata.insert(
            (*super::GOV_APPROVERS_METADATA_KEY).clone(),
            Json::new(vec![secondary_id.to_string(), secondary_id.to_string()]),
        );
        let tx = TransactionBuilder::new(
            test_network_id(),
            primary_id,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "noop".into())])
        .with_metadata(metadata)
        .sign(primary_keypair.private_key());
        match enforce_manifest_quorum("gov", &rules, &tx) {
            Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg))) => {
                assert!(
                    msg.contains("duplicate approvers"),
                    "expected duplicate approver rejection, got {msg}"
                );
            }
            other => panic!("expected duplicate approver rejection, got {other:?}"),
        }
    }
    #[test]
    fn manifest_protected_namespaces_require_metadata() {
        let (authority, keypair) = gen_account_in("wonderland");
        let mut rules = GovernanceRules::default();
        rules
            .protected_namespaces
            .insert(Name::from_str("apps").expect("namespace"));
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let instruction = iroha_data_model::isi::smart_contract_code::ActivateContractInstance {
            contract_address,
            expected_revision: 1,
            code_hash: Hash::prehashed([0_u8; 32]),
        };
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction])
        .sign(keypair.private_key());
        let world = World::default();
        let world_view = world.view();
        let err = super::enforce_manifest_protected_namespaces("lane-0", &rules, &tx, &world_view)
            .expect_err("missing governance metadata should reject");
        match err {
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg)) => {
                assert!(
                    msg.contains("gov_contract_address"),
                    "expected gov_contract_address rejection, got {msg}"
                );
            }
            other => panic!("expected NotPermitted rejection, got {other:?}"),
        }
    }
    #[test]
    fn manifest_protected_rotation_requires_atomic_commit_instruction() {
        let (authority, keypair) = gen_account_in("wonderland");
        let mut rules = GovernanceRules::default();
        rules
            .protected_namespaces
            .insert(Name::from_str("apps").expect("namespace"));
        let old_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("old contract address");
        let new_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            1,
            DataSpaceId::UNIVERSAL,
        )
        .expect("new contract address");
        let code_hash = Hash::new(b"atomic protected rotation");
        let mut metadata = Metadata::default();
        metadata.insert(
            (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(new_address.to_string()),
        );
        let commit = CommitContractDeployment {
            expected_deploy_nonce: 1,
            contract_address: new_address.clone(),
            code_hash,
            contract_alias: "payments::universal".parse().expect("contract alias"),
            lease_expiry_ms: None,
            expected_previous_contract_address: Some(old_address.clone()),
        };
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([commit])
        .with_metadata(metadata.clone())
        .sign(keypair.private_key());
        let world = World::default();
        let world_view = world.view();
        super::enforce_manifest_protected_namespaces("lane-0", &rules, &tx, &world_view)
            .expect("single atomic deployment commit should pass protected address validation");
        let legacy = vec![
            InstructionBox::from(DeactivateContractInstance {
                contract_address: old_address,
                expected_revision: 1,
                reason: Some("legacy rotation".to_owned()),
            }),
            InstructionBox::from(ActivateContractInstance {
                contract_address: new_address,
                expected_revision: 1,
                code_hash,
            }),
        ];
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(legacy)
        .with_metadata(metadata)
        .sign(keypair.private_key());
        let error =
            super::enforce_manifest_protected_namespaces("lane-0", &rules, &tx, &world_view)
                .expect_err("legacy multi-instruction rotation must be rejected");
        match error {
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message)) => {
                assert!(
                    message.contains("CommitContractDeployment"),
                    "unexpected protected rotation rejection: {message}"
                );
            }
            other => panic!("expected NotPermitted rejection, got {other:?}"),
        }
    }
    #[test]
    fn state_block_manifest_protects_native_contract_upload_lifecycle() {
        let chain: ChainId = "lane-native-upload-protected-ns".parse().unwrap();
        let (mut world, authority, keypair) = world_with_authority("wonderland");
        let lifecycle_permission: Permission =
            iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode
                .into();
        world
            .account_permissions
            .insert(authority.clone(), Permissions::from([lifecycle_permission]));
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, query_handle, chain.clone());
        let chain = crate::block::tests::component_chain(state);
        let state = chain.state();
        let mut protected_namespaces = BTreeSet::new();
        protected_namespaces.insert(Name::from_str("apps").expect("protected namespace"));
        let rules = GovernanceRules {
            validators: vec![authority.clone()],
            protected_namespaces,
            ..GovernanceRules::default()
        };
        let mut statuses = BTreeMap::new();
        statuses.insert(
            TestLaneId::SINGLE,
            LaneManifestStatus {
                lane: TestLaneId::SINGLE,
                alias: "apps".to_owned(),
                dataspace: TestDataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: Some("parliament".to_owned()),
                manifest_path: Some(PathBuf::from("/tmp/apps.manifest.json")),
                governance_rules: Some(rules),
                privacy_commitments: Vec::new(),
            },
        );
        let policy_manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &chain.network_id(),
            &authority,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let mut governance_metadata = Metadata::default();
        governance_metadata.insert(
            (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(contract_address.to_string()),
        );
        let header = original_component_successor_header(state);
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        macro_rules! validate_instruction {
            ($instruction:expr, $metadata:expr) => {{
                let tx = TransactionBuilder::new(
                    chain.network_id(),
                    authority.clone(),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .with_instructions([$instruction])
                .with_metadata($metadata)
                .sign(keypair.private_key());
                let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
                let mut ivm_cache = IvmCache::new();
                execute_component_transaction_for_testing(
                    &mut block,
                    accepted,
                    &mut ivm_cache,
                    None,
                )
            }};
        }
        let (code, _) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                "seiyaku NativeUploadGovernance { view fn inspect() authorize(anyone) -> int { return 1; } }",
            )
            .expect("compile self-describing contract fixture");
        assert!(
            code.len()
                <= iroha_data_model::isi::smart_contract_code::SMART_CONTRACT_CODE_CHUNK_BYTES,
            "governance fixture must fit the declared one-chunk upload"
        );
        let code_hash = ivm::contract_code_hash(&code);
        let total_size = u64::try_from(code.len()).expect("contract fixture size fits u64");
        let descriptor = crate::state::SmartContractCodeUploadDescriptor {
            total_size,
            chunk_count: 1,
        };
        let artifact_id = iroha_data_model::smart_contract::ContractArtifactId::new(
            DataSpaceId::UNIVERSAL,
            code_hash,
        );
        let missing_upload_metadata = validate_instruction!(
            UploadSmartContractCodeChunk {
                artifact_id,
                total_size,
                chunk_index: 0,
                chunk_count: 1,
                chunk: code.clone(),
            },
            Metadata::default()
        );
        assert!(matches!(
            missing_upload_metadata,
            Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(message)
            )) if message.contains("gov_contract_address")
        ));
        assert_eq!(
            block
                .world
                .contract_code_upload_progress(&authority, &artifact_id),
            None,
            "rejected upload must not create resumable staging"
        );
        let accepted_upload = validate_instruction!(
            UploadSmartContractCodeChunk {
                artifact_id,
                total_size,
                chunk_index: 0,
                chunk_count: 1,
                chunk: code.clone(),
            },
            governance_metadata.clone()
        );
        assert!(
            accepted_upload.is_ok(),
            "explicit code-management permission with required governance context should admit upload: {accepted_upload:?}"
        );
        assert_eq!(
            block
                .world
                .contract_code_upload_progress(&authority, &artifact_id),
            Some(crate::state::SmartContractCodeUploadProgress {
                descriptor,
                received_chunks: 1,
            })
        );
        let missing_finalize_metadata = validate_instruction!(
            FinalizeSmartContractCodeUpload {
                artifact_id,
                total_size,
                chunk_count: 1,
            },
            Metadata::default()
        );
        assert!(matches!(
            missing_finalize_metadata,
            Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(message)
            )) if message.contains("gov_contract_address")
        ));
        assert_eq!(
            block
                .world
                .contract_code_upload_progress(&authority, &artifact_id),
            Some(crate::state::SmartContractCodeUploadProgress {
                descriptor,
                received_chunks: 1,
            }),
            "rejected finalization must preserve resumable staging"
        );
        assert!(block.world.contract_code().get(&artifact_id).is_none());
        let accepted_finalize = validate_instruction!(
            FinalizeSmartContractCodeUpload {
                artifact_id,
                total_size,
                chunk_count: 1,
            },
            governance_metadata.clone()
        );
        assert!(
            accepted_finalize.is_ok(),
            "explicit code-management permission with required governance context should admit finalization: {accepted_finalize:?}"
        );
        assert_eq!(
            block
                .world
                .contract_code()
                .get(&artifact_id)
                .map(Vec::as_slice),
            Some(code.as_slice())
        );
        assert_eq!(
            block
                .world
                .contract_code_upload_progress(&authority, &artifact_id),
            None,
            "successful finalization must clear staging"
        );
        let cancelled_artifact_id = iroha_data_model::smart_contract::ContractArtifactId::new(
            DataSpaceId::UNIVERSAL,
            Hash::new(b"owner-scoped cleanup"),
        );
        let accepted_cancel_stage = validate_instruction!(
            UploadSmartContractCodeChunk {
                artifact_id: cancelled_artifact_id,
                total_size: 1,
                chunk_index: 0,
                chunk_count: 1,
                chunk: vec![0xCA],
            },
            governance_metadata.clone()
        );
        assert!(
            accepted_cancel_stage.is_ok(),
            "cleanup fixture upload should be staged: {accepted_cancel_stage:?}"
        );
        let accepted_cancel = validate_instruction!(
            iroha_data_model::isi::smart_contract_code::CancelSmartContractCodeUpload {
                artifact_id: cancelled_artifact_id,
            },
            Metadata::default()
        );
        assert!(
            accepted_cancel.is_ok(),
            "owner cleanup must remain outside protected deployment governance: {accepted_cancel:?}"
        );
        assert_eq!(
            block
                .world
                .contract_code_upload_progress(&authority, &cancelled_artifact_id),
            None
        );
        // Registered owners may create their own artifacts without a management grant.
        // Protected deployment still needs the original governance metadata; global
        // artifact removal independently requires the exact management permission.
        block.world.account_permissions.remove(authority.clone());
        let owner_upload_without_management = validate_instruction!(
            UploadSmartContractCodeChunk {
                artifact_id: cancelled_artifact_id,
                total_size: 1,
                chunk_index: 0,
                chunk_count: 1,
                chunk: vec![0xCA],
            },
            governance_metadata.clone()
        );
        assert!(
            owner_upload_without_management.is_ok(),
            "ordinary owner-scoped staging requires governance context, not global management: {owner_upload_without_management:?}"
        );
        assert_eq!(
            block
                .world
                .contract_code_upload_progress(&authority, &cancelled_artifact_id),
            Some(crate::state::SmartContractCodeUploadProgress {
                descriptor: crate::state::SmartContractCodeUploadDescriptor {
                    total_size: 1,
                    chunk_count: 1,
                },
                received_chunks: 1,
            })
        );
        validate_instruction!(
            iroha_data_model::isi::smart_contract_code::CancelSmartContractCodeUpload {
                artifact_id: cancelled_artifact_id,
            },
            Metadata::default()
        )
        .expect("ordinary owner may still cancel its own staging");
        let missing_management_permission = validate_instruction!(
            iroha_data_model::isi::smart_contract_code::RemoveSmartContractBytes {
                artifact_id,
                reason: None,
            },
            governance_metadata
        );
        assert!(
            matches!(&missing_management_permission,
                Err(TransactionRejectionReason::Validation(
                    ValidationFail::InstructionFailed(
                        iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(message)
                    )
                )) if message.as_ref() == "not permitted: CanManageSmartContractCode"
            ),
            "global removal must retain its explicit management gate: {missing_management_permission:?}"
        );
        assert_eq!(
            block
                .world
                .contract_code_upload_progress(&authority, &cancelled_artifact_id),
            None
        );
        assert_eq!(
            block
                .world
                .contract_code()
                .get(&artifact_id)
                .map(Vec::as_slice),
            Some(code.as_slice())
        );
    }
    #[test]
    fn generic_ivm_cannot_hide_contract_admin_syscalls_from_governance() {
        use iroha_data_model::transaction::{Executable, executable::IvmBytecode};
        let chain: ChainId = "generic-ivm-contract-admin-governance".parse().unwrap();
        let (mut world, authority, keypair) = world_with_authority("wonderland");
        let (second_validator, _) = gen_account_in("wonderland");
        let lifecycle_permission: Permission =
            iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode
                .into();
        world
            .account_permissions
            .insert(authority.clone(), Permissions::from([lifecycle_permission]));
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, query_handle, chain.clone());
        let mut protected_namespaces = BTreeSet::new();
        protected_namespaces.insert(Name::from_str("apps").expect("protected namespace"));
        let rules = GovernanceRules {
            validators: vec![authority.clone(), second_validator],
            quorum: Some(2),
            protected_namespaces,
            ..GovernanceRules::default()
        };
        let mut statuses = BTreeMap::new();
        statuses.insert(
            TestLaneId::SINGLE,
            LaneManifestStatus {
                lane: TestLaneId::SINGLE,
                alias: "apps".to_owned(),
                dataspace: TestDataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: Some("parliament".to_owned()),
                manifest_path: Some(PathBuf::from("/tmp/apps.manifest.json")),
                governance_rules: Some(rules),
                privacy_commitments: Vec::new(),
            },
        );
        let policy_manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        for syscall in [
            ivm::syscalls::SYSCALL_REGISTER_SMART_CONTRACT_BYTES,
            ivm::syscalls::SYSCALL_ACTIVATE_CONTRACT_INSTANCE,
        ] {
            let syscall_u8 = u8::try_from(syscall).expect("contract-admin syscall fits SCALL");
            let program = minimal_ivm_program_with_syscall(1, syscall_u8);
            let tx = TransactionBuilder::new(
                test_network_id(),
                authority.clone(),
                fee_payment_with_gas_limit(TEST_GAS_LIMIT),
            )
            .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
            .sign(keypair.private_key());
            let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
            let mut ivm_cache = IvmCache::new();
            let result = execute_component_transaction_for_testing(
                &mut block,
                accepted,
                &mut ivm_cache,
                None,
            );
            assert!(matches!(
                result,
                Err(TransactionRejectionReason::Validation(
                    ValidationFail::IvmAdmission(
                        iroha_data_model::executor::IvmAdmissionError::GenericSyscallNotAllowed(
                            rejected
                        )
                    )
                )) if rejected == syscall
            ));
            assert!(
                block.world.contract_code().iter().next().is_none(),
                "rejected generic syscall must not register contract bytes"
            );
            assert!(
                block.world.contract_instances().iter().next().is_none(),
                "rejected generic syscall must not activate a contract instance"
            );
        }
    }
    #[test]
    fn runtime_upgrade_hook_requires_metadata() {
        let (authority, keypair) = gen_account_in("wonderland");
        let mut rules = GovernanceRules::default();
        rules.hooks.runtime_upgrade = Some(RuntimeUpgradeHook {
            allow: true,
            require_metadata: true,
            metadata_key: Some(Name::from_str("upgrade_id").expect("key")),
            allowed_ids: Some(BTreeSet::from(["v1".to_string()])),
        });
        let instruction = iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade {
            manifest_bytes: vec![0x01, 0x02],
        };
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction.clone()])
        .sign(keypair.private_key());
        let err = super::enforce_runtime_upgrade_hook("lane-0", &rules, &tx)
            .expect_err("missing metadata should reject");
        match err {
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg)) => {
                assert!(
                    msg.contains("requires metadata"),
                    "expected metadata rejection, got {msg}"
                );
            }
            other => panic!("expected NotPermitted rejection, got {other:?}"),
        }
        let mut metadata = Metadata::default();
        metadata.insert(Name::from_str("upgrade_id").expect("key"), Json::new("v1"));
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction])
        .with_metadata(metadata)
        .sign(keypair.private_key());
        let ok = super::enforce_runtime_upgrade_hook("lane-0", &rules, &tx)
            .expect("runtime upgrade hook should allow");
        assert!(ok, "runtime upgrade hook should be applied");
    }
    #[test]
    fn state_enforces_lane_compliance_engine() {
        let chain: ChainId = "lane-compliance".parse().unwrap();
        let (world, authority, keypair) = world_with_authority("wonderland");
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, query_handle, chain.clone());
        let policy = LaneCompliancePolicy {
            id: LaneCompliancePolicyId::new(Hash::prehashed([0xAA; 32])),
            version: 1,
            lane_id: TestLaneId::SINGLE,
            dataspace_id: TestDataSpaceId::UNIVERSAL,
            jurisdiction: JurisdictionSet::default(),
            deny: vec![LaneComplianceRule {
                selector: ParticipantSelector {
                    account: Some(authority.clone()),
                    ..ParticipantSelector::default()
                },
                reason_code: Some("denied account".to_string()),
                jurisdiction_override: JurisdictionSet::default(),
            }],
            allow: Vec::new(),
            transfer_limits: Vec::new(),
            audit_controls: AuditControls::default(),
            metadata: Metadata::default(),
        };
        let engine = LaneComplianceEngine::from_policies(vec![policy], false).expect("engine");
        state.install_lane_compliance_engine(Some(Arc::new(engine)));
        assert!(
            state.lane_compliance_engine().is_some(),
            "lane compliance engine should be installed"
        );
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "noop".into())])
        .sign(keypair.private_key());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let stx = block.transaction();
        let assignment = super::LaneAssignment {
            lane_id: TestLaneId::SINGLE,
            dataspace_id: TestDataSpaceId::UNIVERSAL,
            dataspace_catalog: &stx.nexus.dataspace_catalog,
        };
        let err = super::enforce_lane_policies(&tx, &stx, &assignment)
            .expect_err("compliance denial should reject");
        match err {
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg)) => {
                assert!(
                    msg.contains("denied account") || msg.contains("lane compliance"),
                    "expected compliance rejection, got {msg}"
                );
            }
            other => panic!("expected compliance rejection, got {other:?}"),
        }
    }
    #[test]
    fn non_governed_manifest_validators_do_not_gate_state_policy_for_ivm_contract_metadata() {
        use iroha_data_model::transaction::{Executable, executable::IvmBytecode};
        let chain: ChainId = "non-governed-manifest-ivm-contract".parse().unwrap();
        let (world, authority, keypair) = world_with_authority("wonderland");
        let (validator, _) = gen_account_in("wonderland");
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new_with_chain(world, kura, query_handle, chain.clone());
        let mut rules = GovernanceRules {
            validators: vec![validator],
            quorum: Some(1),
            ..GovernanceRules::default()
        };
        rules
            .protected_namespaces
            .insert(Name::from_str("is").expect("namespace"));
        let mut statuses = BTreeMap::new();
        statuses.insert(
            TestLaneId::SINGLE,
            LaneManifestStatus {
                lane: TestLaneId::SINGLE,
                alias: "is".to_string(),
                dataspace: TestDataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: None,
                manifest_path: Some(PathBuf::from("/tmp/is.manifest.json")),
                governance_rules: Some(rules),
                privacy_commitments: Vec::new(),
            },
        );
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        let policy_manifests = Arc::clone(&manifests);
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            TestDataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let mut metadata = Metadata::default();
        metadata.insert(
            (*super::CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(contract_address.to_string()),
        );
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(metadata)
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(vec![0xCA])))
        .sign(keypair.private_key());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        let stx = block.transaction();
        let assignment = single_lane_assignment(&stx.nexus.dataspace_catalog);
        let result = super::enforce_lane_policies(&tx, &stx, &assignment);
        assert!(
            result.is_ok(),
            "non-governed manifest validators must not reject contract metadata: {result:?}"
        );
    }
    #[test]
    fn validate_transaction_without_context_uses_live_autoscale_route() {
        use iroha_crypto::bls_normal_pop_prove;
        use iroha_data_model::{
            IntoKeyValue,
            consensus::{ConsensusKeyRecord, ConsensusKeyStatus},
            isi::consensus_keys::RegisterConsensusKey,
            transaction::{Executable, executable::IvmBytecode},
        };
        use iroha_executor_data_model::permission::governance::CanManageConsensusKeys;
        use iroha_model_base::peer::PeerId;
        let chain: ChainId = "tx-live-autoscale-route".parse().unwrap();
        let (world, authority, keypair) = world_with_authority("wonderland");
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let mut state = State::new_with_chain(world, kura, query_handle, chain.clone());
        let mut elastic_lane = {
            let mut elastic_lane = LaneConfig {
                id: TestLaneId::new(1),
                alias: "elastic-lane-1".to_string(),
                dataspace_id: TestDataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                ..LaneConfig::default()
            };
            elastic_lane
                .metadata
                .insert(AUTOSCALE_META_MANAGED.to_string(), "true".to_string());
            elastic_lane
                .metadata
                .insert(AUTOSCALE_META_CREATED_HEIGHT.to_string(), "1".to_string());
            let mut nexus = state.nexus_snapshot();
            nexus.autoscale.enabled = true;
            nexus.autoscale.min_lane_id = nonzero!(1_u32);
            nexus.autoscale.max_lane_id_exclusive = nonzero!(8_u32);
            state
                .set_nexus_from_config(nexus)
                .expect("enable pre-genesis autoscale policy");
            elastic_lane
        };
        // The signed genesis configures only the original base geometry. Install
        // the managed lane through its actual runtime lifecycle after genesis;
        // an effective managed lane is never fresh-start configured authority.
        let nexus = state.nexus_snapshot();
        let crypto = state.crypto();
        let zk = state.zk_snapshot();
        let pipeline = state.installed_pipeline().clone();
        let fraud_monitoring = state.fraud_monitoring.clone();
        let governance = state.gov.clone();
        #[cfg(feature = "telemetry")]
        let telemetry = state.telemetry.clone();
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(state.world, 0);
        config.chain_id = chain;
        config.pipeline = pipeline;
        config.nexus = Some(nexus.clone());
        config.zk = Some(zk);
        config.crypto = Some(crypto.as_ref().clone());
        config.fraud_monitoring = fraud_monitoring;
        config.governance = Some(governance);
        // The exact four global genesis peers also own participant-lane Committee
        // custody. These signed registrations run the ordinary permission and PoP checks.
        let mut validators = (0xC1_u8..=0xC4)
            .map(|seed| {
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                    .expect("genuine participant-lane BLS custody")
            })
            .collect::<Vec<_>>();
        validators.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        let peers = validators
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>();
        assert_eq!(peers.len(), 4);
        crate::state::attach_autoscale_committee_for_test(&mut elastic_lane, &validators);
        let pinned = crate::state::autoscale_lane_pinned_committee_with_pops(&elastic_lane)
            .expect("canonical pin of the exact original four holders");
        assert_eq!(
            pinned
                .iter()
                .map(|(peer, _)| peer.clone())
                .collect::<Vec<_>>(),
            peers,
        );
        for ((peer, pop), holder) in pinned.iter().zip(&validators) {
            assert_eq!(peer.public_key(), holder.public_key());
            assert_eq!(pop, &bls_normal_pop_prove(holder.private_key()).unwrap());
            assert!(iroha_crypto::bls_normal_pop_verify(peer.public_key(), pop).is_ok());
        }
        for key in &validators {
            let id = AccountId::new(key.public_key().clone());
            let (id, account) = Account::new(id.clone()).build(&id).into_key_value();
            config.world.accounts.insert(id, account);
        }
        config.world.account_permissions_mut_for_testing().insert(
            AccountId::new(config.genesis_key.public_key().clone()),
            BTreeSet::from([CanManageConsensusKeys.into()]),
        );
        config.validator_keys = Some(validators.clone());
        config.genesis_instructions = validators
            .iter()
            .map(|key| {
                let id = crate::state::derive_committee_key_id(key.public_key());
                RegisterConsensusKey {
                    id: id.clone(),
                    record: ConsensusKeyRecord {
                        id,
                        public_key: key.public_key().clone(),
                        pop: Some(
                            bls_normal_pop_prove(key.private_key())
                                .expect("checked same-key participant-lane proof of possession"),
                        ),
                        activation_height: 1,
                        expiry_height: None,
                        replaces: None,
                        status: ConsensusKeyStatus::Active,
                    },
                }
                .into()
            })
            .collect();
        let bindings = validators
            .iter()
            .map(
                |key| crate::governance::manifest::ManifestValidatorBinding {
                    validator: AccountId::new(key.public_key().clone()),
                    peer_id: PeerId::new(key.public_key().clone()),
                    torii_url: None,
                },
            )
            .collect();
        config.lane_manifests = Some(Arc::new(
            crate::governance::manifest::test_support::validator_registry(
                &nexus.lane_catalog,
                &nexus.governance,
                BTreeMap::from([(TestLaneId::SINGLE, bindings)]),
            ),
        ));
        let mut prepared = crate::sumeragi::test_chain::CertifiedTestChain::prepare(config)
            .expect("derive signed routing fixture genesis with materialized base authority");
        #[cfg(feature = "telemetry")]
        {
            Arc::get_mut(&mut prepared.state)
                .expect("unpublished original routing State")
                .telemetry = telemetry;
        }
        let chain = crate::sumeragi::test_chain::CertifiedTestChain::from_prepared(prepared)
            .expect("original four-peer genesis executes checked Committee registrations");
        let state = chain.state();
        {
            let view = state.view();
            for peer in &peers {
                for lane in [TestLaneId::SINGLE, TestLaneId::new(1)] {
                    assert_eq!(
                        crate::state::peer_consensus_key_gate_for_lane(view.world(), peer, 1, lane,),
                        crate::state::ConsensusKeyGate::Live,
                        "the same genuine peer must own both exact lane key roles"
                    );
                }
            }
        }
        assert_eq!(
            state.nexus_snapshot().configured_lane_catalog.lanes(),
            &[LaneConfig::default()]
        );
        state
            .apply_autoscale_lane_lifecycle_for_tests(&iroha_data_model::nexus::LaneLifecyclePlan {
                additions: vec![elastic_lane],
                retire: Vec::new(),
            })
            .expect("install the authenticated elastic lane after original genesis");
        assert!(
            state
                .nexus_snapshot()
                .lane_catalog
                .lanes()
                .iter()
                .any(|lane| lane.id == TestLaneId::new(1) && lane.claims_autoscale_managed())
        );
        let next_header = original_component_successor_header(state);
        let committee = state
            .resolve_lane_committee_at_height(
                crate::state::LaneAuthorityRoute::new(
                    TestLaneId::new(1),
                    TestDataSpaceId::UNIVERSAL,
                ),
                next_header.height().get(),
            )
            .expect("actual lifecycle pins the original four live Committee peers");
        assert_eq!(committee.validators(), peers.as_slice());
        assert_eq!(committee.fault_tolerance(), 1);
        let mut statuses = BTreeMap::new();
        statuses.insert(
            TestLaneId::SINGLE,
            LaneManifestStatus {
                lane: TestLaneId::SINGLE,
                alias: "base-lane".to_string(),
                dataspace: TestDataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: Some("base-governance".to_string()),
                manifest_path: None,
                governance_rules: None,
                privacy_commitments: Vec::new(),
            },
        );
        statuses.insert(
            TestLaneId::new(1),
            LaneManifestStatus {
                lane: TestLaneId::new(1),
                alias: "elastic-lane-1".to_string(),
                dataspace: TestDataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: None,
                manifest_path: None,
                governance_rules: None,
                privacy_commitments: Vec::new(),
            },
        );
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        let policy_manifests = Arc::clone(&manifests);
        let mut selected = None;
        for attempt in 0_u64..256 {
            let mut metadata = Metadata::default();
            metadata.insert(
                Name::from_str("route_attempt").expect("static metadata key"),
                Json::new(attempt),
            );
            let tx = TransactionBuilder::new(
                chain.network_id(),
                authority.clone(),
                fee_payment_with_gas_limit(TEST_GAS_LIMIT),
            )
            .with_metadata(metadata)
            .with_executable(Executable::Ivm(IvmBytecode::from_compiled(
                minimal_ivm_program(1),
            )))
            .sign(keypair.private_key());
            let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx.clone()));
            let (catalog_only, live_plan) = {
                let view = state.view();
                let ledger_time_ms =
                    u64::try_from(next_header.creation_time().as_millis()).expect("time fits");
                let catalog_only = crate::queue::evaluate_policy_with_catalog_and_world_at(
                    &view.nexus.routing_policy,
                    &view.nexus.lane_catalog,
                    &view.nexus.dataspace_catalog,
                    &accepted,
                    view.world(),
                    ledger_time_ms,
                )
                .expect("catalog-only route resolves");
                let live_plan =
                    crate::queue::evaluate_policy_plan_with_nexus_and_world_at_block_height(
                        &view.nexus,
                        &accepted,
                        view.world(),
                        ledger_time_ms,
                        next_header.height().get(),
                    )
                    .expect("live autoscale route resolves");
                (catalog_only, live_plan)
            };
            if catalog_only.lane_id == TestLaneId::SINGLE
                && live_plan.coordinator_route().lane_id == TestLaneId::new(1)
            {
                selected = Some(tx);
                break;
            }
        }
        let tx = selected.expect("fixture should find a tx routed to elastic lane");
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
        let header = next_header;
        let mut block = state.block(header);
        block.lane_manifests = Arc::clone(&policy_manifests);
        let mut ivm_cache = IvmCache::new();
        let result =
            execute_component_transaction_for_testing(&mut block, accepted, &mut ivm_cache, None);
        result.expect("live autoscale-routed transaction should bypass blocked base lane");
    }
    fn state_with_guarded_base_and_open_elastic_lane(
        chain: &ChainId,
        world: World,
    ) -> (State, Arc<LaneManifestRegistry>) {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let mut state = State::new_with_chain(world, kura, query_handle, chain.clone());
        let elastic_lane_id = TestLaneId::new(1);
        let mut elastic_lane = LaneConfig {
            id: elastic_lane_id,
            alias: "elastic-lane-1".to_string(),
            dataspace_id: TestDataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            ..LaneConfig::default()
        };
        elastic_lane
            .metadata
            .insert(AUTOSCALE_META_MANAGED.to_string(), "true".to_string());
        elastic_lane
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.to_string(), "1".to_string());
        crate::state::attach_synthetic_autoscale_committee_for_test(&mut elastic_lane);
        {
            let mut nexus = state.nexus_snapshot();
            nexus.autoscale.enabled = true;
            nexus.autoscale.min_lane_id = nonzero!(1_u32);
            nexus.autoscale.max_lane_id_exclusive = nonzero!(8_u32);
            state
                .set_nexus_from_config(nexus)
                .expect("enable pre-genesis autoscale policy");
            state
                .apply_autoscale_lane_lifecycle_for_tests(
                    &iroha_data_model::nexus::LaneLifecyclePlan {
                        additions: vec![elastic_lane],
                        retire: Vec::new(),
                    },
                )
                .expect("install the authenticated elastic lane");
        }
        let mut statuses = BTreeMap::new();
        statuses.insert(
            TestLaneId::SINGLE,
            LaneManifestStatus {
                lane: TestLaneId::SINGLE,
                alias: "base-lane".to_string(),
                dataspace: TestDataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: Some("base-governance".to_string()),
                manifest_path: None,
                governance_rules: None,
                privacy_commitments: Vec::new(),
            },
        );
        statuses.insert(
            elastic_lane_id,
            LaneManifestStatus {
                lane: elastic_lane_id,
                alias: "elastic-lane-1".to_string(),
                dataspace: TestDataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: None,
                manifest_path: None,
                governance_rules: None,
                privacy_commitments: Vec::new(),
            },
        );
        // The deliberately unavailable base manifest belongs only to the component overlay;
        // canonical State retains the materialized source established by lane lifecycle.
        (
            state,
            Arc::new(LaneManifestRegistry::from_statuses(statuses)),
        )
    }
    #[test]
    fn sealed_reveal_preserves_authenticated_routing_context() {
        use iroha_data_model::transaction::{
            Executable, TransactionBuilder, executable::IvmBytecode,
        };
        let chain: ChainId = "sealed-reveal-authenticated-route".parse().unwrap();
        let (world, authority, keypair) = world_with_authority("wonderland");
        let (state, policy_manifests) =
            state_with_guarded_base_and_open_elastic_lane(&chain, world);
        let signed = (0_u64..256)
            .find_map(|attempt| {
                let mut metadata = Metadata::default();
                metadata.insert(
                    Name::from_str("sealed_route_attempt").expect("static metadata key"),
                    Json::new(attempt),
                );
                let signed = TransactionBuilder::new(
                    *state.network_id_ref(),
                    authority.clone(),
                    fee_payment_with_gas_limit(TEST_GAS_LIMIT),
                )
                .with_metadata(metadata)
                .with_executable(Executable::Ivm(IvmBytecode::from_compiled(
                    minimal_ivm_program(1),
                )))
                .sign(keypair.private_key());
                let accepted = AcceptedTransaction::new_unchecked(Cow::Borrowed(&signed));
                let plan = {
                    let view = state.view();
                    evaluate_policy_plan_with_nexus_and_world_at_block_height(
                        &view.nexus,
                        &accepted,
                        view.world(),
                        0,
                        1,
                    )
                    .expect("fresh sealed-reveal route resolves")
                };
                (plan.coordinator_route().lane_id == TestLaneId::new(1)).then_some(signed)
            })
            .expect("fixture finds a transaction freshly routed to the open elastic lane");
        let salt = [0xA5; 32];
        let reveal_deadline_height = 2;
        let commitment = compute_sealed_transaction_commitment(
            state.network_id_ref(),
            &signed,
            salt,
            reveal_deadline_height,
        );
        let record = PendingSealedTransactionCommitment {
            payload: SealedTransactionCommitmentPayload {
                network_id: *state.network_id_ref(),
                authority: authority.clone(),
                commitment,
                reveal_after_height: 1,
                reveal_deadline_height,
                nonce: None,
            },
            commit_height: 0,
            commit_index: 0,
        };
        {
            let mut world = state.world.block();
            world.smart_contract_state.insert(
                sealed_commitment_state_key(&commitment),
                norito::to_bytes(&record).expect("encode pending sealed commitment"),
            );
            world.commit();
        }
        let reveal = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            commitment,
            signed.clone(),
            salt,
        ));
        let explicit_route =
            crate::queue::RoutingDecision::new(TestLaneId::SINGLE, TestDataSpaceId::UNIVERSAL);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        block.lane_manifests = policy_manifests;
        let mut ivm_cache = IvmCache::new();
        // Capture the governed physical route in this explicit component scope, then
        // reopen elastic routing. Both outer and inner execution must keep that capability.
        let execute = |block: &mut StateBlock<'_>,
                       accepted: AcceptedTransaction<'_>,
                       index,
                       cache: &mut IvmCache| {
            let mut overlay = block.transaction_for_fastpq_testing(Hash::from(
                accepted.entrypoint().execution_call_hash(),
            ));
            overlay.current_entrypoint_index = Some(index);
            overlay.current_network_entrypoint_hash = Some(accepted.hash_as_entrypoint());
            overlay.current_tx_hash = accepted.external().map(SignedTransaction::hash);
            overlay.current_lane_id = Some(explicit_route.lane_id);
            overlay.current_dataspace_id = Some(explicit_route.dataspace_id);
            overlay.world.current_dataspace_id = Some(explicit_route.dataspace_id);
            overlay.nexus.autoscale.enabled = false;
            let captured =
                CapturedNetworkPolicyRoute::for_component(&accepted, &overlay, explicit_route)
                    .expect("completed original physical policy capture");
            overlay.nexus.autoscale.enabled = true;
            StateBlock::execute_accepted_transaction_in_overlay(
                accepted,
                &mut overlay,
                cache,
                explicit_route,
                captured,
                None,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
        };
        let external_result = execute(
            &mut block,
            AcceptedTransaction::new_unchecked(Cow::Owned(signed)),
            0,
            &mut ivm_cache,
        );
        let reveal_result = execute(
            &mut block,
            AcceptedTransaction::new_unchecked_entrypoint(Cow::Owned(reveal)),
            1,
            &mut ivm_cache,
        );
        assert!(matches!(
            &external_result,
            Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(_)
            ))
        ));
        assert_eq!(
            reveal_result, external_result,
            "sealed reveal must preserve the captured physical policy instead of re-deriving the open elastic route"
        );
        assert!(
            block
                .world
                .smart_contract_state
                .get(&sealed_commitment_state_key(&commitment))
                .is_some(),
            "a rejected reveal must roll back pending-commitment removal"
        );
    }
    #[test]
    fn sealed_reveal_replay_validation_checks_carrier_and_signed_alias() {
        let (authority, keypair) = gen_account_in("sealed-replay-identities");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "sealed replay identity".to_owned())])
        .sign(keypair.private_key());
        let salt = [0x5A; 32];
        let deadline = 9;
        let commitment =
            compute_sealed_transaction_commitment(&test_network_id(), &signed, salt, deadline);
        let reveal = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            commitment,
            signed.clone(),
            salt,
        ));

        let identities = canonical_replay_alias_hashes(core::slice::from_ref(&reveal));

        assert_eq!(identities.len(), 2);
        assert!(identities.contains(&reveal.hash()));
        assert!(identities.contains(&signed.hash_as_entrypoint()));
    }
    #[test]
    fn sealed_reveal_membership_requires_exact_preblock_authentication() {
        let (authority, keypair) = gen_account_in("sealed-membership-authentication");
        let signed = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "sealed membership".to_owned())])
        .sign(keypair.private_key());
        let salt = [0x31; 32];
        let wrong_salt = [0x32; 32];
        let deadline = 9;
        let commitment =
            compute_sealed_transaction_commitment(&test_network_id(), &signed, salt, deadline);
        let exact = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            commitment,
            signed.clone(),
            salt,
        ));
        let wrong = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            commitment,
            signed.clone(),
            wrong_salt,
        ));
        let missing = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            Hash::new(b"missing sealed commitment"),
            signed.clone(),
            salt,
        ));
        let record = PendingSealedTransactionCommitment {
            payload: SealedTransactionCommitmentPayload {
                network_id: test_network_id(),
                authority,
                commitment,
                reveal_after_height: 2,
                reveal_deadline_height: deadline,
                nonce: None,
            },
            commit_height: 1,
            commit_index: 0,
        };
        let frame = norito::encode_canonical(&record).expect("current pending commitment frame");
        assert_eq!(
            <PendingSealedTransactionCommitment as norito::NoritoSchema>::nominal_name(),
            "iroha_core::tx::PendingSealedTransactionCommitment",
        );
        assert_eq!(
            <PendingSealedTransactionCommitment as norito::NoritoSchema>::frame_name(),
            "iroha_core::tx::PendingSealedTransactionCommitment",
        );
        assert_eq!(
            frame[6..22],
            norito::schema::identity::frame_hash::<PendingSealedTransactionCommitment>()
        );
        let decoded = norito::decode_canonical::<PendingSealedTransactionCommitment>(&frame)
            .expect("current pending commitment roundtrip");
        assert_eq!(decoded.payload, record.payload);
        assert_eq!(
            (decoded.commit_height, decoded.commit_index),
            (record.commit_height, record.commit_index)
        );
        assert_eq!(
            norito::encode_canonical(&decoded).expect("re-encode commitment"),
            frame
        );
        let mut wrong_owner = frame.clone();
        wrong_owner[6..22]
            .copy_from_slice(&norito::schema::identity::frame_hash::<TransactionEntrypoint>());
        assert!(matches!(
            norito::decode_canonical::<PendingSealedTransactionCommitment>(&wrong_owner),
            Err(norito::Error::SchemaMismatch)
        ));
        assert!(
            norito::decode_canonical::<PendingSealedTransactionCommitment>(
                &frame[..frame.len() - 1]
            )
            .is_err()
        );
        let mut trailing = frame;
        trailing.push(0);
        assert!(norito::decode_canonical::<PendingSealedTransactionCommitment>(&trailing).is_err());
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        {
            let mut world = state.world.block();
            world.smart_contract_state.insert(
                sealed_commitment_state_key(&commitment),
                norito::to_bytes(&record).expect("encode pending sealed commitment"),
            );
            world.commit();
        }

        let early_block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let early =
            canonical_carrier_membership_hashes(&early_block, core::slice::from_ref(&exact));
        assert_eq!(early, vec![exact.hash()]);
        drop(early_block);

        let open_block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
        let missing_identities =
            canonical_carrier_membership_hashes(&open_block, core::slice::from_ref(&missing));
        assert_eq!(missing_identities, vec![missing.hash()]);
        let wrong_identities =
            canonical_carrier_membership_hashes(&open_block, core::slice::from_ref(&wrong));
        assert_eq!(wrong_identities, vec![wrong.hash()]);
        let exact_identities =
            canonical_carrier_membership_hashes(&open_block, core::slice::from_ref(&exact));
        let mut visited = Vec::new();
        for_each_canonical_carrier_membership_hash(
            &open_block,
            core::slice::from_ref(&exact),
            |hash| visited.push(hash),
        );
        assert_eq!(visited, exact_identities);
        assert_eq!(exact_identities.len(), 2);
        let alias_bytes = std::alloc::Layout::array::<HashOf<TransactionEntrypoint>>(2)
            .unwrap()
            .size();
        let alias_budget = iroha_allocation::AllocationBudget::new(alias_bytes);
        let mut paid_aliases = iroha_allocation::ChargedBuffer::new(2, &alias_budget)
            .expect("exact two-identity backing admits at its capacity boundary");
        for_each_canonical_carrier_membership_hash(
            &open_block,
            core::slice::from_ref(&exact),
            |hash| {
                paid_aliases.append(std::slice::from_ref(&hash)).unwrap();
            },
        );
        assert_eq!(paid_aliases.as_slice(), exact_identities);
        assert_eq!(alias_budget.reserved_bytes(), alias_bytes);
        drop(paid_aliases);
        assert_eq!(alias_budget.reserved_bytes(), 0);
        assert!(exact_identities.contains(&exact.hash()));
        assert!(exact_identities.contains(&signed.hash_as_entrypoint()));
        drop(open_block);

        let late_block = state.block(BlockHeader::new(nonzero!(10_u64), None, None, 0, 0));
        let late = canonical_carrier_membership_hashes(&late_block, core::slice::from_ref(&exact));
        assert_eq!(late, vec![exact.hash()]);
    }
    #[test]
    fn rejected_confidential_work_consumes_the_next_overlay_block_budget() {
        let mut state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut zk = state.installed_zk().clone();
        zk.max_confidential_ops_per_block = 1;
        zk.max_verify_calls_per_block = 1;
        zk.max_verify_calls_per_tx = 2;
        zk.max_proof_bytes_block = 64;
        zk.max_proof_size_bytes = 64;
        state
            .set_zk(zk)
            .expect("empty state accepts focused confidential limits");
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut rejected = block.transaction();
        rejected
            .register_confidential_proof(8)
            .expect("first attempted proof fits the block budget");
        let work = (
            rejected.zk_confidential_ops_in_tx,
            rejected.zk_verify_calls_in_tx,
            rejected.zk_proof_bytes_in_tx,
            rejected.confidential_gas_used_in_tx,
        );
        drop(rejected);
        block.account_confidential_work_v1(work.0, work.1, work.2, work.3);

        let mut next = block.transaction();
        let error = next
            .register_confidential_proof(8)
            .expect_err("a rejected proof must still exhaust the one-call block budget");
        assert!(
            matches!(&error,
                iroha_data_model::isi::error::InstructionExecutionError::InvalidParameter(
                    iroha_data_model::isi::error::InvalidParameterError::SmartContract(reason)
                ) if reason == "confidential verify calls per block exceeded"
            ),
            "the next overlay must reject at the block verify-call quota: {error:?}"
        );
    }
    #[test]
    fn zero_block_gas_limit_remains_unlimited_in_transaction_executor() {
        let chain: ChainId = "zero-block-gas-unlimited".parse().expect("chain id");
        let (world, authority, keypair) = world_with_authority("wonderland");
        let state = State::new_with_chain(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain,
        );
        let chain = crate::block::tests::component_chain(state);
        let state = chain.state();
        let signed = TransactionBuilder::new(
            *state.network_id_ref(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "unlimited block gas".to_owned())])
        .sign(keypair.private_key());
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(signed));
        let header = original_component_successor_header(state);
        let mut block = state.block(header);
        block.gas_limit_per_block = 0;
        let mut cache = IvmCache::new();

        let mut overlay = block.transaction_for_fastpq_testing(Hash::from(
            accepted.entrypoint().execution_call_hash(),
        ));
        let route =
            crate::queue::RoutingDecision::new(TestLaneId::SINGLE, TestDataSpaceId::UNIVERSAL);
        let policy_route = CapturedNetworkPolicyRoute::for_component(&accepted, &overlay, route)
            .expect("completed original physical policy capture");
        let result = StateBlock::execute_accepted_transaction_in_overlay(
            accepted,
            &mut overlay,
            &mut cache,
            route,
            policy_route,
            None,
        );
        result.expect("zero block gas limit must mean unlimited");
        assert!(overlay.last_tx_gas_used > 0);
    }
    fn faucet_marker_metadata(semantic_hash: &str) -> Metadata {
        let mut metadata = Metadata::default();
        metadata.insert(
            iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_METADATA_KEY
                .parse()
                .expect("marker version metadata key"),
            Json::new(iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_V1),
        );
        metadata.insert(
            iroha_data_model::transaction::PREPARED_OPERATION_METADATA_KEY
                .parse()
                .expect("operation metadata key"),
            Json::new(iroha_data_model::transaction::PREPARED_FAUCET_OPERATION.to_owned()),
        );
        metadata.insert(
            iroha_data_model::transaction::PREPARED_SEMANTIC_HASH_METADATA_KEY
                .parse()
                .expect("semantic hash metadata key"),
            Json::new(semantic_hash.to_owned()),
        );
        metadata
    }

    fn marked_test_transaction(
        network_id: iroha_data_model::NetworkId,
        authority: AccountId,
        keypair: &KeyPair,
        semantic_hash: &str,
        instructions: impl IntoIterator<Item = InstructionBox>,
    ) -> SignedTransaction {
        TransactionBuilder::new(
            network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(faucet_marker_metadata(semantic_hash))
        .with_instructions(instructions)
        .sign(keypair.private_key())
    }

    fn faucet_test_asset_definition(
        owner: &AccountId,
    ) -> (Domain, AssetDefinitionId, AssetDefinition) {
        let domain_id = DomainId::try_new("faucet", "universal").expect("faucet test domain");
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "claim_coin".parse().expect("faucet test asset name"),
        );
        let domain = Domain::new(domain_id).build(owner);
        let definition = AssetDefinition::new(
            definition_id.clone(),
            "Faucet claim coin".to_owned(),
            NumericSpec::integer(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(owner);
        (domain, definition_id, definition)
    }

    fn faucet_test_transfer(
        definition: &AssetDefinitionId,
        source: &AccountId,
        destination: &AccountId,
        amount: u32,
    ) -> InstructionBox {
        Transfer::asset_quantity(
            AssetId::new(definition.clone(), source.clone()),
            amount,
            destination.clone(),
        )
        .into()
    }

    #[test]
    fn faucet_claim_marker_is_authority_scoped_and_consumed_once() {
        let chain: ChainId = "faucet-claim-consumed-once".parse().expect("chain id");
        let (faucet, faucet_keypair) = gen_account_in("faucet");
        let (other, other_keypair) = gen_account_in("other-faucet");
        let (recipient, _) = gen_account_in("faucet-recipient");
        let (domain, definition_id, definition) = faucet_test_asset_definition(&faucet);
        let original_chain = || {
            let world = World::with_assets(
                [domain.clone()],
                [
                    Account::new(faucet.clone()).build(&faucet),
                    Account::new(other.clone()).build(&other),
                    Account::new(recipient.clone()).build(&recipient),
                ],
                [definition.clone()],
                [
                    Asset::new(AssetId::new(definition_id.clone(), faucet.clone()), 10_u32),
                    Asset::new(AssetId::new(definition_id.clone(), other.clone()), 10_u32),
                ],
                [],
            );
            let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 0);
            config.chain_id = chain.clone();
            crate::sumeragi::test_chain::CertifiedTestChain::start(config)
                .expect("same original signed faucet genesis")
        };
        let mut chain = original_chain();
        let semantic_hash = "ab".repeat(Hash::LENGTH);
        let first = marked_test_transaction(
            chain.network_id(),
            faucet.clone(),
            &faucet_keypair,
            &semantic_hash,
            [faucet_test_transfer(&definition_id, &faucet, &recipient, 1)],
        );
        let marker_path = faucet_claim_consumption_marker(&first)
            .expect("valid marker")
            .expect("marker present")
            .0;
        let first_hash = first.hash();
        chain.commit(vec![first]);
        let committed = chain.committed(2);
        let first_result = committed
            .block()
            .network_output_at(0)
            .expect("actual certified original faucet output")
            .1
            .result
            .0
            .clone();
        first_result.expect("first authority-scoped claim succeeds");
        assert!(
            chain
                .state()
                .view()
                .world()
                .smart_contract_state
                .get(&marker_path)
                .is_some(),
            "successful execution persists its claim marker"
        );
        let state = chain.state();
        assert!(
            state
                .view()
                .world()
                .smart_contract_state
                .get(&marker_path)
                .is_some(),
            "claim marker must survive the transaction overlay commit"
        );
        let snapshot =
            norito::json::to_value(state.as_ref()).expect("serialize marker-bearing state");
        assert!(matches!(
            crate::state::deserialize::KuraSeed {
                execution_budget: iroha_allocation::AllocationBudget::new(
                    iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
                ),
                lane_manifests: state.lane_manifests.read().clone(),
                kura: Kura::blank_kura_for_testing(),
                query_handle: LiveQueryStore::start_test(),
                #[cfg(feature = "telemetry")]
                telemetry: crate::telemetry::StateTelemetry::default(),
            }
            .into_state_from_json(snapshot),
            Err(crate::state::deserialize::StateRestoreError::NativeExecutionReplayRequired)
        ));
        let mut replay = original_chain();
        assert_eq!(replay.network_id(), chain.network_id());
        replay
            .replay_from(&chain)
            .expect("restore only the original certified faucet prefix");
        let restarted = replay.state();
        assert!(
            restarted
                .view()
                .world()
                .smart_contract_state
                .get(&marker_path)
                .is_some(),
            "claim marker must survive original native replay"
        );
        let replay_header = original_component_successor_header(restarted);
        let mut ivm_cache = IvmCache::new();
        let mut replay_block = restarted.block(replay_header);

        let duplicate = marked_test_transaction(
            chain.network_id(),
            faucet.clone(),
            &faucet_keypair,
            &semantic_hash,
            [faucet_test_transfer(&definition_id, &faucet, &recipient, 2)],
        );
        assert_ne!(duplicate.hash(), first_hash);
        let duplicate_result = execute_component_transaction_for_testing(
            &mut replay_block,
            AcceptedTransaction::new_unchecked(Cow::Owned(duplicate)),
            &mut ivm_cache,
            None,
        );
        assert!(
            matches!(
                &duplicate_result,
                Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                    message
                ))) if message == "faucet claim was already consumed"
            ),
            "same authority and semantic claim must fail deterministically: {duplicate_result:?}"
        );

        let other_tx = marked_test_transaction(
            chain.network_id(),
            other.clone(),
            &other_keypair,
            &semantic_hash,
            [faucet_test_transfer(&definition_id, &other, &recipient, 1)],
        );
        let other_path = faucet_claim_consumption_marker(&other_tx)
            .expect("valid other marker")
            .expect("other marker present")
            .0;
        assert_ne!(marker_path, other_path);
        let other_result = execute_component_transaction_for_testing(
            &mut replay_block,
            AcceptedTransaction::new_unchecked(Cow::Owned(other_tx)),
            &mut ivm_cache,
            None,
        );
        other_result.expect("another authority cannot be pre-consumed");
    }

    #[test]
    fn failed_faucet_transaction_does_not_burn_claim_marker() {
        let chain: ChainId = "failed-faucet-claim-rolls-back".parse().expect("chain id");
        let (faucet, faucet_keypair) = gen_account_in("faucet");
        let (recipient, _) = gen_account_in("faucet-recipient");
        let (domain, definition_id, definition) = faucet_test_asset_definition(&faucet);
        let world = World::with_assets(
            [domain],
            [
                Account::new(faucet.clone()).build(&faucet),
                Account::new(recipient.clone()).build(&recipient),
            ],
            [definition],
            [Asset::new(
                AssetId::new(definition_id.clone(), faucet.clone()),
                10_u32,
            )],
            [],
        );
        let state = State::new_with_chain(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain,
        );
        let chain = crate::block::tests::component_chain(state);
        let state = chain.state();
        let semantic_hash = "cd".repeat(Hash::LENGTH);
        let failing = marked_test_transaction(
            chain.network_id(),
            faucet.clone(),
            &faucet_keypair,
            &semantic_hash,
            [faucet_test_transfer(
                &definition_id,
                &faucet,
                &recipient,
                11,
            )],
        );
        let marker_path = faucet_claim_consumption_marker(&failing)
            .expect("valid marker")
            .expect("marker present")
            .0;
        let header = original_component_successor_header(state);
        let mut block = state.block(header);
        let mut ivm_cache = IvmCache::new();
        let failure = execute_component_transaction_for_testing(
            &mut block,
            AcceptedTransaction::new_unchecked(Cow::Owned(failing)),
            &mut ivm_cache,
            None,
        );
        assert!(failure.is_err(), "overdrawn faucet transfer must fail");
        assert!(
            block.world.smart_contract_state.get(&marker_path).is_none(),
            "failed execution must drop its staged marker"
        );

        let retry = marked_test_transaction(
            chain.network_id(),
            faucet.clone(),
            &faucet_keypair,
            &semantic_hash,
            [faucet_test_transfer(&definition_id, &faucet, &recipient, 1)],
        );
        let retry_result = execute_component_transaction_for_testing(
            &mut block,
            AcceptedTransaction::new_unchecked(Cow::Owned(retry)),
            &mut ivm_cache,
            None,
        );
        retry_result.expect("corrected transaction consumes the unburned claim");
        assert!(block.world.smart_contract_state.get(&marker_path).is_some());
    }

    #[test]
    fn faucet_claim_marker_requires_exact_executable_shape() {
        let (authority, keypair) = gen_account_in("faucet");
        let (foreign_source, _) = gen_account_in("foreign-source");
        let (destination, _) = gen_account_in("destination");
        let (other_destination, _) = gen_account_in("other-destination");
        let (_, definition_id, _) = faucet_test_asset_definition(&authority);
        let semantic_hash = "ef".repeat(Hash::LENGTH);
        let transfer = || faucet_test_transfer(&definition_id, &authority, &destination, 1);
        let registration =
            || InstructionBox::from(Register::account(Account::new(destination.clone())));

        let without_registration = marked_test_transaction(
            test_network_id(),
            authority.clone(),
            &keypair,
            &semantic_hash,
            [transfer()],
        );
        assert!(
            faucet_claim_consumption_marker(&without_registration)
                .expect("one direct faucet transfer is valid")
                .is_some()
        );
        let with_registration = marked_test_transaction(
            test_network_id(),
            authority.clone(),
            &keypair,
            &semantic_hash,
            [registration(), transfer()],
        );
        assert!(
            faucet_claim_consumption_marker(&with_registration)
                .expect("plain destination registration and transfer are valid")
                .is_some()
        );

        let mut annotated_metadata = Metadata::default();
        annotated_metadata.insert(
            "annotation".parse().expect("annotation metadata key"),
            Json::new("not a plain registration".to_owned()),
        );
        let annotated_registration = InstructionBox::from(Register::account(
            Account::new(destination.clone()).with_metadata(annotated_metadata),
        ));
        let identified_registration = InstructionBox::from(Register::account(
            Account::new(destination.clone()).with_uaid(Some(
                iroha_data_model::nexus::UniversalAccountId::from_hash(Hash::new(
                    b"decorated-faucet-registration",
                )),
            )),
        ));
        let cases = [
            (
                "log-only",
                vec![Log::new(Level::INFO, "not a faucet transfer".to_owned()).into()],
            ),
            (
                "non-asset transfer",
                vec![
                    Transfer::asset_definition(
                        authority.clone(),
                        definition_id.clone(),
                        destination.clone(),
                    )
                    .into(),
                ],
            ),
            (
                "zero asset transfer",
                vec![faucet_test_transfer(
                    &definition_id,
                    &authority,
                    &destination,
                    0,
                )],
            ),
            (
                "foreign-source asset transfer",
                vec![faucet_test_transfer(
                    &definition_id,
                    &foreign_source,
                    &destination,
                    1,
                )],
            ),
            (
                "authority self-transfer",
                vec![faucet_test_transfer(
                    &definition_id,
                    &authority,
                    &authority,
                    1,
                )],
            ),
            ("register-only", vec![registration()]),
            (
                "registration destination mismatch",
                vec![
                    Register::account(Account::new(other_destination.clone())).into(),
                    transfer(),
                ],
            ),
            (
                "annotated registration",
                vec![annotated_registration, transfer()],
            ),
            (
                "identified registration",
                vec![identified_registration, transfer()],
            ),
            (
                "registration after transfer",
                vec![transfer(), registration()],
            ),
            (
                "duplicate registration",
                vec![registration(), registration(), transfer()],
            ),
            (
                "extra instruction",
                vec![
                    transfer(),
                    Log::new(Level::INFO, "extra side effect".to_owned()).into(),
                ],
            ),
        ];
        for (case, instructions) in cases {
            let tx = marked_test_transaction(
                test_network_id(),
                authority.clone(),
                &keypair,
                &semantic_hash,
                instructions,
            );
            assert!(
                matches!(
                    faucet_claim_consumption_marker(&tx),
                    Err(ValidationFail::NotPermitted(message))
                        if message == FAUCET_CLAIM_EXECUTABLE_SHAPE_ERROR
                ),
                "{case} must not allocate a consensus faucet marker"
            );
        }

        let indirect = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(faucet_marker_metadata(&semantic_hash))
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(Vec::new())))
        .sign(keypair.private_key());
        assert!(matches!(
            faucet_claim_consumption_marker(&indirect),
            Err(ValidationFail::NotPermitted(message))
                if message == FAUCET_CLAIM_EXECUTABLE_SHAPE_ERROR
        ));
    }

    #[test]
    fn faucet_claim_marker_metadata_fails_closed() {
        let (authority, keypair) = gen_account_in("faucet");
        let mut malformed = faucet_marker_metadata(&"AB".repeat(Hash::LENGTH));
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(core::mem::take(&mut malformed))
        .with_instructions([Log::new(Level::INFO, "malformed marker".to_owned())])
        .sign(keypair.private_key());
        assert!(matches!(
            faucet_claim_consumption_marker(&tx),
            Err(ValidationFail::NotPermitted(message))
                if message.contains("canonical lowercase hexadecimal")
        ));
    }

    #[test]
    fn prepared_faucet_operation_requires_claim_marker() {
        let (authority, keypair) = gen_account_in("faucet");
        let mut metadata = Metadata::default();
        metadata.insert(
            iroha_data_model::transaction::PREPARED_OPERATION_METADATA_KEY
                .parse()
                .expect("operation metadata key"),
            Json::new(iroha_data_model::transaction::PREPARED_FAUCET_OPERATION.to_owned()),
        );
        metadata.insert(
            iroha_data_model::transaction::PREPARED_SEMANTIC_HASH_METADATA_KEY
                .parse()
                .expect("semantic hash metadata key"),
            Json::new("ab".repeat(Hash::LENGTH)),
        );
        let tx = TransactionBuilder::new(
            test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(metadata)
        .with_instructions([Log::new(Level::INFO, "unmarked faucet claim".to_owned())])
        .sign(keypair.private_key());

        assert!(matches!(
            faucet_claim_consumption_marker(&tx),
            Err(ValidationFail::NotPermitted(message))
                if message
                    == "prepared faucet operation requires faucet claim marker version metadata"
        ));
    }

    include!("tx/lane_manifest_privacy_registry_test.rs");
    /// Lightweight end-to-end harness for exercising transaction, trigger, and block flow in tests.
    pub struct Sandbox {
        /// In-memory state under test.
        pub state: State,
        /// Buffered transactions that will be packed into the next block.
        pub transactions: Vec<SignedTransaction>,
    }
    /// Handle returned by [`Sandbox::block`] for asserting and committing a prepared block.
    pub struct SandboxBlock<'state> {
        /// View into the mutable world state for this block.
        pub state: Box<StateBlock<'state>>,
        /// The signed block prepared from queued transactions.
        pub block: Option<SignedBlock>,
        /// Original recorder acquired before the first block effect.
        recording: Option<crate::exec_witness::ExecWitnessGuard>,
    }
    /// Short names of pre-created test accounts used by the sandbox.
    pub const ACCOUNTS_STR: [&str; 5] = ["alice", "bob", "carol", "dave", "eve"];
    /// Initial balances for the sandbox asset, keyed by account short name.
    pub static INIT_BALANCE: LazyLock<AccountBalance> =
        LazyLock::new(|| ACCOUNTS_STR.into_iter().zip([60, 10, 10, 10, 10]).collect());
    /// Default maximum smart contract execution depth used by the sandbox.
    pub const INIT_EXECUTION_DEPTH: u8 = u8::MAX;
    /// Mapping from account short name to its numeric asset balance.
    pub type AccountBalance = std::collections::BTreeMap<&'static str, u64>;
    /// Mapping from account short name to its credentials (ID and key).
    pub type AccountMap = std::collections::BTreeMap<&'static str, Credential>;
    /// Mapping from account identifier to its short alias.
    pub type AccountAliasMap = std::collections::BTreeMap<AccountId, &'static str>;
    /// Domain used for all sandbox entities.
    pub const DOMAIN_STR: &str = "wonderland";
    /// Asset definition name used by the sandbox.
    pub const ASSET_STR: &str = "rose";
    /// Pre-parsed domain identifier for the sandbox domain.
    pub static DOMAIN: LazyLock<DomainId> =
        LazyLock::new(|| DomainId::try_new(DOMAIN_STR, "universal").unwrap());
    /// Pre-parsed asset definition identifier for the sandbox asset.
    pub static ASSET: LazyLock<AssetDefinitionId> = LazyLock::new(|| {
        AssetDefinitionId::derive_from_components(
            DOMAIN.clone(),
            ASSET_STR.parse().expect("sandbox asset name is valid"),
        )
    });
    const SANDBOX_ACCOUNT_KEYS: [(&str, &str, &str); 5] = [
        (
            "alice",
            "ed0120FF365BDAA7CB998DBE6505CA8911C8C85C9ADBBF3A9CD4DF4FFAE5A09723590F",
            "5309423ca944339f556bdbaa648e6f962ca680c7a07ca4bfdaeb92c2e84c0631",
        ),
        (
            "bob",
            "ed01200B25F5244DCFA449F1A00758C1652F3BD912FE5ADF3244B084D84BC11548C640",
            "79a36c14bca68bd098e2968d03fa0ec1dc44f863aeb2cf775892352696f27943",
        ),
        (
            "carol",
            "ed0120D3E0032F42620A333DC05AF7B72C5D5613286505AD6590356046FA23C3231EDD",
            "64942ccc247311f9265ef5144962da8a462e788174d7a3d586fbd31633a6d7ef",
        ),
        (
            "dave",
            "ed01206AA7B199B45261F2A9C71B7644F9346EF5B1A8DCD59F90B0C6B954DD5DF320DC",
            "608673cd53310dbec45a8cca4716968712d1b4986b4dc7294d75028bcf7ac34e",
        ),
        (
            "eve",
            "ed012040C2A4B02CCAD1EFEBDF9BDB77AACCECC8A7BDEA2C6E543719FDD3B6DD21DA74",
            "bc4ff9e3d5cc415426f864c513f974ccd5ab2f86cda19fc20c4e1fec86585fa1",
        ),
    ];
    /// Pre-derived credentials for sandbox accounts (IDs and private keys).
    pub static ACCOUNT: LazyLock<AccountMap> = LazyLock::new(|| {
        SANDBOX_ACCOUNT_KEYS
            .iter()
            .map(|(name, public, private_hex)| {
                let signatory: iroha_crypto::PublicKey = public.parse().unwrap();
                let id = AccountId::new(signatory);
                let key = iroha_crypto::PrivateKey::from_hex(
                    iroha_crypto::Algorithm::Ed25519,
                    private_hex,
                )
                .unwrap();
                (*name, Credential { id, key })
            })
            .collect()
    });
    /// Reverse lookup from account identifier to its sandbox alias.
    pub static ACCOUNT_ALIAS_BY_ID: LazyLock<AccountAliasMap> = LazyLock::new(|| {
        ACCOUNT
            .iter()
            .map(|(alias, cred)| (cred.id.clone(), *alias))
            .collect()
    });
    include!("tx/sandbox_state_tests.rs");
}
#[cfg(test)]
include!("tx/numeric_to_u64_tests.rs");
