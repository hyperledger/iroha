//! Modeling block transitions.
//!
//! Operations on blocks:
//!
//! 1. Static analysis of the block. This is a _fallible_ operation
//! 2. Execute transactions and time triggers infallibly, recording transaction errors in the block.
//! 3. Voting
//! 4. Pre-commit signatures check
//! 5. Apply & commit
//!
//! Operations 1 + 2 form a process we call _validation_.
//!
//! Block lifecycle stages:
//!
//! 1. A node-created [`NewBlock`] is assumed valid and needs no static validation before [`ValidBlock`].
//! 2. Block is received/deserialized from disk (as [`SignedBlock`]). Such blocks require static
//!    validation before execution to transition to [`ValidBlock`].
//! 3. [`ValidBlock`] pairs with [`crate::state::StateBlock`] containing applied state changes and
//!    transaction errors.
//! 4. Block is committed ([`CommittedBlock`]). Created from [`ValidBlock`] once the consensus core
//!    has certified it; the canonical SignedBlockWire retains the exact native certificate.
//!
//! ### Scenario: a block ordered by the Sumeragi core
//!
//! Flow: the leader builds the payload with [`BlockBuilder`] (`sumeragi::payload`); every node
//! executes the ordered payload with [`ValidBlock::validate_sumeragi_block`] against its
//! committed parent and commits it with [`ValidBlock::commit_unchecked`] after the core's
//! `CommitBlock` (`sumeragi::executor`).
//!
//! ### Scenario: genesis (init or receive)
//!
//! Flow: authenticate the signed genesis handshake mode, call
//! [`ValidBlock::validate_signed_genesis`], then [`ValidBlock::commit`].
//!
//! ### Scenario: plain block execution
//!
//! Flow: Having [`SignedBlock`], [`ValidBlock::validate_unchecked`] (infallible),
//! [`ValidBlock::commit_unchecked`] (infallible)

use core::fmt;
use iroha_crypto::{Hash, HashOf, KeyPair, MerkleTree, PublicKey};
#[cfg(test)]
use iroha_data_model::block::consensus::ValidatorIndex;
use iroha_data_model::{
    NetworkId,
    account::{AccountController, AccountId, rekey::AccountAlias},
    asset::{AssetDefinitionAlias, AssetDefinitionId},
    block::*,
    confidential::ConfidentialFeatureDigest,
    consensus::{ConsensusKeyRole, NposConsensusEffects},
    da::{
        commitment::{DaCommitmentBundle, DaProofPolicyBundle},
        pin_intent::DaPinIntentBundle,
    },
    events::prelude::*,
    nexus::{AxtPolicyEntry, AxtProofEnvelope, AxtRejectReason, DataSpaceCatalog, ProofBlob},
    transaction::{SignedTransaction, TransactionEntrypoint, error::TransactionLimitError},
};
#[cfg(test)]
use iroha_data_model::{
    asset::AssetId,
    isi::InstructionBox,
    nexus::LaneConfig,
    transaction::{Executable, error::TransactionRejectionReason, signed::TransactionResultInner},
};
#[cfg(feature = "bls")]
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
#[cfg(test)]
use iroha_primitives::numeric::Quantity;
#[cfg(test)]
use iroha_primitives::small::SmallVec;
use mv::storage::StorageReadOnly;
#[cfg(test)]
use norito::codec::Encode;
#[cfg(feature = "bls")]
use norito::json::Value as JsonValue;
#[cfg(test)]
use std::hint::black_box;
#[cfg(feature = "bls")]
use std::sync::LazyLock;
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
    str::FromStr,
    time::Duration,
};

fn ensure_confidential_features_match(
    expected: Option<ConfidentialFeatureDigest>,
    actual: Option<ConfidentialFeatureDigest>,
) -> Result<(), BlockValidationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(BlockValidationError::ConfidentialFeaturesMismatch { expected, actual })
    }
}
fn validate_external_entrypoint_count(
    actual: usize,
    configured_max: NonZeroU64,
) -> Result<(), BlockValidationError> {
    let max = usize::try_from(configured_max.get()).unwrap_or(usize::MAX);
    if actual > max {
        Err(BlockValidationError::TooManyTransactions { actual, max })
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod external_entrypoint_count_tests {
    use super::*;
    #[test]
    fn configured_block_limit_is_enforced_before_expensive_validation() {
        let max = NonZeroU64::new(1).expect("one is non-zero");
        assert!(validate_external_entrypoint_count(1, max).is_ok());
        assert!(matches!(
            validate_external_entrypoint_count(2, max),
            Err(BlockValidationError::TooManyTransactions { actual: 2, max: 1 })
        ));
    }
}
#[cfg(feature = "bls")]
fn bls_pop_from_metadata(
    metadata: &Metadata,
    key: &iroha_model_base::name::Name,
) -> Option<Vec<u8>> {
    let json = metadata.get(key)?;
    let val: JsonValue = norito::json::from_str(json.get()).ok()?;
    match val {
        JsonValue::String(s) => hex::decode(s).ok(),
        _ => None,
    }
}
#[cfg(feature = "bls")]
fn bls_small_pop_from_metadata(
    metadata: &Metadata,
    key: &iroha_model_base::name::Name,
) -> Option<Vec<u8>> {
    bls_pop_from_metadata(metadata, key)
}
#[cfg(test)]
fn checked_keypair() -> KeyPair {
    KeyPair::try_random().expect("block fixture key generation should succeed")
}
#[cfg(test)]
fn deterministic_test_network_id(seed: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([seed; Hash::LENGTH]),
    ))
}
#[cfg(test)]
fn checked_keypair_with_algorithm(algorithm: iroha_crypto::Algorithm) -> KeyPair {
    KeyPair::try_random_with_algorithm(algorithm)
        .expect("block fixture key generation for requested algorithm should succeed")
}
#[cfg(test)]
mod checked_keypair_tests {
    #[test]
    fn checked_keypair_helpers_preserve_requested_algorithms() {
        assert_eq!(
            super::checked_keypair().algorithm(),
            iroha_crypto::Algorithm::default()
        );
        for algorithm in [
            iroha_crypto::Algorithm::Ed25519,
            iroha_crypto::Algorithm::BlsNormal,
        ] {
            assert_eq!(
                super::checked_keypair_with_algorithm(algorithm).algorithm(),
                algorithm
            );
        }
    }
}
#[cfg(test)]
/// Preserve stable overlay rejection labels for scheduler regression tests.
fn map_overlay_error(
    err: &crate::pipeline::overlay::OverlayBuildError,
) -> TransactionRejectionReason {
    match err {
        crate::pipeline::overlay::OverlayBuildError::HeaderPolicy(e) => {
            TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::IvmAdmission(
                e.clone(),
            ))
        }
        crate::pipeline::overlay::OverlayBuildError::AxtReject(ctx) => {
            TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::AxtReject(
                ctx.clone(),
            ))
        }
        crate::pipeline::overlay::OverlayBuildError::InvalidAxtPolicySnapshot(error) => {
            TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::InternalError(
                format!("invalid AXT policy snapshot: {error}"),
            ))
        }
        crate::pipeline::overlay::OverlayBuildError::AmxBudgetViolation(violation) => {
            let message = crate::pipeline::overlay::amx_timeout_message(violation);
            TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::NotPermitted(
                format!(
                    "{message} code={}",
                    iroha_data_model::errors::CanonicalErrorKind::AMX_TIMEOUT_CODE
                ),
            ))
        }
        crate::pipeline::overlay::OverlayBuildError::IvmRun(ivm::VMError::AmxBudgetExceeded {
            dataspace,
            stage,
            elapsed_ms,
            budget_ms,
        }) => TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::NotPermitted(format!(
                "{} code={}",
                crate::pipeline::overlay::amx_timeout_message(
                    &crate::smartcontracts::ivm::host::AmxBudgetViolation {
                        dataspace: *dataspace,
                        stage: *stage,
                        elapsed_ms: u32::try_from((*elapsed_ms).min(u64::from(u32::MAX)))
                            .expect("elapsed_ms clamped to u32::MAX"),
                        budget_ms: u32::try_from((*budget_ms).min(u64::from(u32::MAX)))
                            .expect("budget_ms clamped to u32::MAX"),
                    }
                ),
                iroha_data_model::errors::CanonicalErrorKind::AMX_TIMEOUT_CODE
            )),
        ),
        other => TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::NotPermitted(other.to_string()),
        ),
    }
}
#[cfg(test)]
/// Reference VM-overlay classification retained for scheduler regression tests.
#[must_use]
const fn uses_live_vm_overlay_scheduler(executable: &Executable) -> bool {
    matches!(
        executable,
        Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_)
    )
}
#[cfg(test)]
/// Reference live-batch classification retained for scheduler regression tests.
#[must_use]
fn uses_live_batch_scheduler(executable: &Executable) -> bool {
    matches!(executable, Executable::Batch(_))
        || matches!(
            crate::state::standalone_governance_ballot_instruction_v1(executable),
            Ok(Some(_)) | Err(_)
        )
}
#[cfg(test)]
mod overlay_error_tests {
    use super::*;
    use iroha_data_model::{
        ValidationFail,
        nexus::{AxtPolicySnapshotValidationError, AxtRejectContext, AxtRejectReason},
        transaction::{ExecutableBatchItem, IvmBytecode, IvmProved},
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    #[test]
    fn map_overlay_error_preserves_axt_context() {
        let ctx = AxtRejectContext {
            reason: AxtRejectReason::Manifest,
            dataspace: Some(DataSpaceId::new(7)),
            lane: Some(LaneId::new(3)),
            snapshot_version: Some(42),
            detail: "manifest mismatch".to_string(),
            active_handle_era: None,
            next_handle_counter: None,
        };
        let mapped = map_overlay_error(&crate::pipeline::overlay::OverlayBuildError::AxtReject(
            ctx.clone(),
        ));
        match mapped {
            TransactionRejectionReason::Validation(ValidationFail::AxtReject(seen)) => {
                assert_eq!(seen.reason, ctx.reason);
                assert_eq!(seen.dataspace, ctx.dataspace);
                assert_eq!(seen.lane, ctx.lane);
                assert_eq!(seen.snapshot_version, ctx.snapshot_version);
                assert!(seen.detail.contains("manifest"));
            }
            other => panic!("unexpected mapping: {other:?}"),
        }
    }
    #[test]
    fn map_overlay_error_classifies_invalid_axt_snapshot_as_internal() {
        let mapped = map_overlay_error(
            &crate::pipeline::overlay::OverlayBuildError::InvalidAxtPolicySnapshot(
                AxtPolicySnapshotValidationError::VersionMismatch {
                    expected: 7,
                    actual: 8,
                },
            ),
        );
        assert!(matches!(
            mapped,
            TransactionRejectionReason::Validation(ValidationFail::InternalError(message))
                if message == "invalid AXT policy snapshot: policy snapshot version mismatch: expected 7, found 8"
        ));
    }
    #[test]
    fn ivm_proved_uses_live_overlay_scheduler_path() {
        let proved = Executable::IvmProved(IvmProved {
            bytecode: IvmBytecode::from_compiled(Vec::new()),
            overlay: Vec::<InstructionBox>::new().into(),
            events_commitment: Hash::new(b"events"),
            gas_policy_commitment: Hash::new(b"gas-policy"),
        });
        assert!(uses_live_vm_overlay_scheduler(&proved));
        let instructions = Executable::Instructions(Vec::<InstructionBox>::new().into());
        assert!(!uses_live_vm_overlay_scheduler(&instructions));
    }
    #[test]
    fn mixed_batch_uses_live_scheduler_barrier_path() {
        let batch = Executable::Batch(
            vec![ExecutableBatchItem::Instruction(InstructionBox::from(
                iroha_data_model::isi::Log::new(
                    iroha_data_model::level::Level::INFO,
                    "live batch".to_owned(),
                ),
            ))]
            .into(),
        );
        assert!(uses_live_batch_scheduler(&batch));
        let instructions = Executable::Instructions(Vec::<InstructionBox>::new().into());
        assert!(!uses_live_batch_scheduler(&instructions));
    }
    #[test]
    fn governance_ballot_requires_an_exact_standalone_direct_entrypoint() {
        let ballot = InstructionBox::from(iroha_data_model::isi::governance::CastZkBallot {
            election_id: "referendum.v1".to_owned(),
            proof_b64: "AA==".to_owned(),
            public_inputs_json: "{}".to_owned(),
        });
        let instructions = Executable::Instructions(vec![ballot.clone()].into());
        assert!(uses_live_batch_scheduler(&instructions));
        assert_eq!(
            crate::state::standalone_governance_ballot_instruction_v1(&instructions),
            Ok(Some(ballot.clone()))
        );

        let singleton_batch =
            Executable::Batch(vec![ExecutableBatchItem::Instruction(ballot.clone())].into());
        assert_eq!(
            crate::state::standalone_governance_ballot_instruction_v1(&singleton_batch),
            Ok(Some(ballot.clone()))
        );

        let mixed = Executable::Instructions(
            vec![
                ballot,
                InstructionBox::from(iroha_data_model::isi::Log::new(
                    iroha_data_model::level::Level::INFO,
                    "must not follow a ballot".to_owned(),
                )),
            ]
            .into(),
        );
        assert!(uses_live_batch_scheduler(&mixed));
        assert!(crate::state::standalone_governance_ballot_instruction_v1(&mixed).is_err());
    }
}
const EMPTY_CONFIDENTIAL_FEATURE_DIGEST: ConfidentialFeatureDigest =
    iroha_data_model::confidential::DEFAULT_CONFIDENTIAL_FEATURE_DIGEST;
pub(crate) use self::event::WithEvents;
pub use self::{chained::Chained, commit::CommittedBlock, new::NewBlock, valid::ValidBlock};

/// Reserve exact control for a standalone structural block fixture.
/// Production and original-execution tests must reserve from their actual State pool.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub fn reserve_block_for_tests() -> ReservedSharedSignedBlock {
    let budget =
        iroha_allocation::AllocationBudget::new(SharedSignedBlock::allocation_layout().size());
    SharedSignedBlock::reserve(&budget).expect("finite standalone block fixture control")
}
use crate::da::{
    DaCommitmentValidationError, DaPinIntentValidationError, DaShardCursorError,
    receipts::DaReceiptCursorError,
};
#[cfg(test)]
use crate::{
    kura::{PipelineDagSnapshot, PipelineRecoverySidecar, PipelineTxSnapshot},
    pipeline::{overlay::TxOverlay, smallset::sort_dedup_u32_in_place},
    state::StateBlock,
};
use crate::{
    prelude::*,
    queue::routing_plan_from_execution_context,
    state::{
        State, StatelessValidationContext, WorldReadOnly, compute_confidential_feature_digest,
    },
    sumeragi::network_topology::Topology,
    tx::{AcceptTransactionFail, SignatureRejectionCode, SignatureVerificationFail},
};
use std::sync::Arc;
use thiserror::Error;
type CommittedBlockEval = Result<CommittedBlock, (Box<ValidBlock>, Box<BlockValidationError>)>;
type WithCommittedBlockEvents = WithEvents<CommittedBlockEval>;
struct PreparedBlockTransaction {
    metadata: crate::tx::PreparedTransactionMetadata,
}
#[cfg(test)]
#[derive(Clone)]
struct AccessIds {
    reads: SmallVec<[u32; 8]>,
    writes: SmallVec<[u32; 8]>,
}
#[cfg(test)]
const GLOBAL_WILDCARD_KEY: &str = "*";
#[cfg(test)]
const STATE_KEY_PREFIX: &str = "state:";
#[cfg(test)]
const STATE_WILDCARD_SUFFIX: &str = "[*]";
#[cfg(test)]
fn state_wildcard_base(key: &str) -> Option<&str> {
    let rest = key.strip_prefix(STATE_KEY_PREFIX)?;
    if rest == "*" {
        return Some("*");
    }
    rest.strip_suffix(STATE_WILDCARD_SUFFIX)
}
#[cfg(test)]
fn state_map_entry_base(key: &str) -> Option<&str> {
    let rest = key.strip_prefix(STATE_KEY_PREFIX)?;
    let (base, _) = rest.split_once('/')?;
    if base.is_empty() {
        return None;
    }
    Some(base)
}
#[cfg(test)]
fn state_wildcard_key(base: &str) -> String {
    if base == "*" {
        format!("{STATE_KEY_PREFIX}*")
    } else {
        format!("{STATE_KEY_PREFIX}{base}{STATE_WILDCARD_SUFFIX}")
    }
}
#[cfg(test)]
#[allow(clippy::explicit_iter_loop)]
fn intern_access(access: &[crate::pipeline::access::AccessSet]) -> (usize, Vec<AccessIds>) {
    use std::collections::{BTreeMap, BTreeSet};
    let mut wildcard_bases: BTreeSet<String> = BTreeSet::new();
    let mut global_present = false;
    for aset in access.iter() {
        for key in aset.read_keys.iter().chain(aset.write_keys.iter()) {
            if key == GLOBAL_WILDCARD_KEY {
                global_present = true;
            }
            if let Some(base) = state_wildcard_base(key) {
                wildcard_bases.insert(base.to_string());
            }
        }
    }
    let mut wildcard_keys: BTreeMap<String, String> = BTreeMap::new();
    for base in &wildcard_bases {
        wildcard_keys.insert(base.clone(), state_wildcard_key(base));
    }
    let mut map: BTreeMap<&str, u32> = BTreeMap::new();
    // Assign stable IDs by iterating lexicographically over all keys
    for aset in access.iter() {
        for k in aset.read_keys.iter() {
            map.entry(k.as_str()).or_insert(u32::MAX);
        }
        for k in aset.write_keys.iter() {
            map.entry(k.as_str()).or_insert(u32::MAX);
        }
    }
    for k in wildcard_keys.values() {
        map.entry(k.as_str()).or_insert(u32::MAX);
    }
    if global_present {
        map.entry(GLOBAL_WILDCARD_KEY).or_insert(u32::MAX);
    }
    let mut next: u32 = 0;
    for value in map.values_mut() {
        *value = next;
        next = next.saturating_add(1);
    }
    let key_count = next as usize;
    let mut out: Vec<AccessIds> = Vec::with_capacity(access.len());
    for aset in access.iter() {
        let mut reads: SmallVec<[u32; 8]> = SmallVec::new();
        let mut writes: SmallVec<[u32; 8]> = SmallVec::new();
        let has_global = aset.read_keys.contains(GLOBAL_WILDCARD_KEY)
            || aset.write_keys.contains(GLOBAL_WILDCARD_KEY);
        let add_state_wildcard = |key: &str, reads: &mut SmallVec<[u32; 8]>| {
            if let Some(base) = state_map_entry_base(key) {
                if let Some(wildcard_key) = wildcard_keys.get(base) {
                    reads.push(*map.get(wildcard_key.as_str()).expect("key interned"));
                }
            }
            if wildcard_bases.contains("*") && key.starts_with(STATE_KEY_PREFIX) {
                if state_wildcard_base(key) == Some("*") {
                    return;
                }
                if let Some(wildcard_key) = wildcard_keys.get("*") {
                    reads.push(*map.get(wildcard_key.as_str()).expect("key interned"));
                }
            }
        };
        for key in aset.read_keys.iter() {
            if state_wildcard_base(key).is_some() {
                writes.push(*map.get(key.as_str()).expect("all keys interned"));
            } else {
                reads.push(*map.get(key.as_str()).expect("all keys interned"));
            }
            add_state_wildcard(key, &mut reads);
        }
        for key in aset.write_keys.iter() {
            writes.push(*map.get(key.as_str()).expect("all keys interned"));
            add_state_wildcard(key, &mut reads);
        }
        if has_global {
            writes.push(*map.get(GLOBAL_WILDCARD_KEY).expect("all keys interned"));
        } else if global_present {
            reads.push(*map.get(GLOBAL_WILDCARD_KEY).expect("all keys interned"));
        }
        let len_reads = sort_dedup_u32_in_place(reads.0.as_mut_slice());
        reads.0.truncate(len_reads);
        let len_writes = sort_dedup_u32_in_place(writes.0.as_mut_slice());
        writes.0.truncate(len_writes);
        out.push(AccessIds { reads, writes });
    }
    (key_count, out)
}
#[cfg(test)]
fn expected_pipeline_dag_fingerprint(
    height: u64,
    block_hash: HashOf<BlockHeader>,
    call_hashes: &[HashOf<TransactionEntrypoint>],
    sidecar: &PipelineRecoverySidecar,
) -> Option<[u8; 32]> {
    if sidecar.height != height {
        iroha_logger::debug!(
            height,
            sidecar_height = sidecar.height,
            "pipeline sidecar height mismatch; ignoring expected DAG fingerprint"
        );
        return None;
    }
    if sidecar.block_hash != block_hash {
        iroha_logger::debug!(
            height,
            expected = %block_hash,
            actual = %sidecar.block_hash,
            "pipeline sidecar block hash mismatch; ignoring expected DAG fingerprint"
        );
        return None;
    }
    let matches_block = sidecar.txs.len() == call_hashes.len()
        && sidecar
            .txs
            .iter()
            .zip(call_hashes.iter())
            .all(|(tx, hash)| tx.hash == *hash);
    if !matches_block {
        iroha_logger::debug!(
            height,
            sidecar_txs = sidecar.txs.len(),
            block_txs = call_hashes.len(),
            "pipeline sidecar does not match block transactions; ignoring expected DAG fingerprint"
        );
        return None;
    }
    Some(sidecar.dag.fingerprint)
}
pub(crate) fn parse_account_literal_with_world(
    world: &impl WorldReadOnly,
    dataspace_catalog: &DataSpaceCatalog,
    input: &str,
    now_ms: u64,
) -> Result<Option<AccountId>, crate::sns::SnsError> {
    use iroha_data_model::account::address::{AccountAddress, AccountAddressError};

    let literal = input.trim();
    if literal.is_empty() {
        return Ok(None);
    }
    // Use the typed address boundary so a local allocation refusal cannot become alias absence.
    let prefix = iroha_data_model::account::address::chain_discriminant();
    if !literal.contains('@') {
        let parsed =
            AccountAddress::from_i105_for_discriminant(literal, Some(prefix)).and_then(|address| {
                if address.to_i105_for_discriminant(prefix)? != literal {
                    return Err(AccountAddressError::UnsupportedAddressFormat);
                }
                address.to_account_id()
            });
        match parsed {
            Ok(account_id) => return Ok(Some(account_id)),
            Err(error) if error.is_decode_resource_limit() => {
                if cfg!(all(test, sumeragi_core_mutation = "HC37")) {
                    return Ok(None);
                }
                return Err(crate::sns::SnsError::Deferred(
                    ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into(),
                ));
            }
            Err(_) => {}
        }
    }
    let Ok(alias) = AccountAlias::from_literal(literal, dataspace_catalog) else {
        return Ok(None);
    };
    resolve_account_alias_in_world(world, dataspace_catalog, &alias, now_ms)
}
pub(crate) fn resolve_account_alias_in_world(
    world: &impl WorldReadOnly,
    dataspace_catalog: &DataSpaceCatalog,
    alias: &AccountAlias,
    now_ms: u64,
) -> Result<Option<AccountId>, crate::sns::SnsError> {
    crate::sns::resolve_active_account_alias(world, dataspace_catalog, alias, now_ms)
}
pub(crate) fn parse_asset_definition_literal_with_world(
    world: &impl WorldReadOnly,
    input: &str,
    now_ms: u64,
) -> Option<AssetDefinitionId> {
    let literal = input.trim();
    if literal.is_empty() {
        return None;
    }
    AssetDefinitionId::parse_address_literal(literal)
        .ok()
        .or_else(|| {
            AssetDefinitionAlias::from_str(literal)
                .ok()
                .and_then(|alias| world.asset_definition_id_by_alias_at(&alias, now_ms))
        })
}
/// Resolve an exact fee selector against the network's committed XOR identity.
/// Chains without NPoS use the canonical default identity, never an arbitrary
/// locally configured token. Staking itself additionally requires signed NPoS.
pub(crate) fn resolve_network_xor_asset_definition(
    world: &impl WorldReadOnly,
    input: &str,
    now_ms: u64,
) -> Result<Option<AssetDefinitionId>, crate::execution_attempt::ExecutionDeferred> {
    use iroha_data_model::parameter::system::SumeragiNposParameters;

    if input.trim() != input
        || (input != "xor#universal" && AssetDefinitionId::parse_address_literal(input).is_err())
    {
        return Ok(None);
    }
    let Some(asset) = parse_asset_definition_literal_with_world(world, input, now_ms) else {
        return Ok(None);
    };
    let parameter_id = SumeragiNposParameters::parameter_id();
    let pin = match world.parameters().custom().get(&parameter_id) {
        Some(custom) => {
            if custom.id() != &parameter_id {
                return Ok(None);
            }
            let params =
                match norito::json::from_str::<SumeragiNposParameters>(custom.payload().get()) {
                    Ok(params) => params,
                    Err(error) => {
                        match crate::execution_attempt::json_decode_attempt_error(error, |_| ()) {
                            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                                if cfg!(all(test, sumeragi_core_mutation = "HC37")) {
                                    return Ok(None);
                                }
                                return Err(reason);
                            }
                            crate::execution_attempt::ExecutionAttemptError::Rejected(()) => {
                                return Ok(None);
                            }
                        }
                    }
                };
            if params.validate().is_err() {
                return Ok(None);
            }
            params.xor_asset_definition_id
        }
        None => {
            let Ok(default) = AssetDefinitionId::parse_address_literal(
                &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
            ) else {
                return Ok(None);
            };
            default
        }
    };
    Ok((asset == pin).then_some(asset))
}
#[cfg(test)]
#[test]
fn network_xor_resolver_requires_exact_committed_identity() {
    use iroha_data_model::parameter::{Parameter, system::SumeragiNposParameters};
    let world = crate::state::World::new();
    let canonical = iroha_config::parameters::defaults::nexus::fees::fee_asset_id();
    let other = AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::try_new("test", "universal").expect("test domain"),
        "currency".parse().expect("name"),
    );
    assert!(
        resolve_network_xor_asset_definition(&world.view(), &canonical, 0)
            .expect("completed pin read")
            .is_some()
    );
    assert!(
        resolve_network_xor_asset_definition(&world.view(), &other.to_string(), 0)
            .expect("completed pin read")
            .is_none()
    );
    let mut parameters = world.parameters.block();
    parameters
        .get_mut()
        .set_parameter(Parameter::Custom(
            SumeragiNposParameters {
                xor_asset_definition_id: other.clone(),
                ..Default::default()
            }
            .into_custom_parameter(),
        ))
        .expect("valid fixture parameters");
    parameters.commit();
    assert_eq!(
        resolve_network_xor_asset_definition(&world.view(), &other.to_string(), 0)
            .expect("completed pin read"),
        Some(other)
    );
    assert!(
        resolve_network_xor_asset_definition(&world.view(), &canonical, 0)
            .expect("completed pin read")
            .is_none()
    );
    assert!(
        resolve_network_xor_asset_definition(&world.view(), &format!(" {canonical}"), 0)
            .expect("completed pin read")
            .is_none()
    );
}
#[cfg(test)]
#[test]
fn original_canonical_account_refusal_does_not_fall_through_to_alias_absence() {
    let world = crate::state::World::default();
    let account = iroha_test_samples::ALICE_ID.clone();
    let literal = account.to_string();
    let read = || {
        parse_account_literal_with_world(
            &world.view(),
            world.view().dataspace_catalog(),
            &literal,
            0,
        )
    };
    assert_eq!(read().unwrap(), Some(account.clone()));
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
        read,
    );
    assert!(
        matches!(refused, Err(crate::sns::SnsError::Deferred(ref reason))
        if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
        "{refused:?}"
    );
    assert_eq!(read().unwrap(), Some(account));
    assert_eq!(
        parse_account_literal_with_world(
            &world.view(),
            world.view().dataspace_catalog(),
            "not-an-account",
            0
        )
        .unwrap(),
        None
    );
}
#[cfg(test)]
fn parse_account_from_access_key(
    world: &impl WorldReadOnly,
    dataspace_catalog: &DataSpaceCatalog,
    key: &str,
    now_ms: u64,
) -> Result<Option<AccountId>, crate::sns::SnsError> {
    if let Some(rest) = key.strip_prefix("account:") {
        parse_account_literal_with_world(world, dataspace_catalog, rest, now_ms)
    } else if let Some(rest) = key.strip_prefix("account.detail:") {
        let Some((account_raw, _)) = rest.split_once(':') else {
            return Ok(None);
        };
        parse_account_literal_with_world(world, dataspace_catalog, account_raw, now_ms)
    } else {
        Ok(None)
    }
}
#[cfg(test)]
fn warm_overlay_chunk(overlay: &TxOverlay, chunk_size: usize) -> usize {
    let chunk = chunk_size.max(1);
    let mut warmed = 0usize;
    for instr in overlay.instructions().take(chunk) {
        let _ = black_box(instr.id());
        warmed = warmed.saturating_add(1);
    }
    warmed
}
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PrefetchStats {
    account_loaded: bool,
    tx_sequence_loaded: bool,
    permissions_touched: usize,
    roles_touched: usize,
}
#[cfg(test)]
fn prefetch_account_stores(state_block: &StateBlock<'_>, account_id: &AccountId) -> PrefetchStats {
    let mut stats = PrefetchStats::default();
    if let Some(account) = state_block.world.accounts.get(account_id) {
        let _ = black_box(account);
        stats.account_loaded = true;
    }
    if let Some(seq) = state_block.world.tx_sequences.get(account_id) {
        let _ = black_box(seq);
        stats.tx_sequence_loaded = true;
    }
    if let Some(perms) = state_block.world.account_permissions.get(account_id) {
        for perm in perms {
            let _ = black_box(perm);
            stats.permissions_touched = stats.permissions_touched.saturating_add(1);
        }
    }
    for (role, ()) in state_block.world.account_roles.iter() {
        if role.account == *account_id {
            let _ = black_box(role);
            stats.roles_touched = stats.roles_touched.saturating_add(1);
        }
    }
    stats
}
#[cfg(test)]
mod prefetch_tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        role::RoleIdWithOwner,
        state::{State, World},
    };
    use iroha_data_model::{
        Registrable,
        account::{Account, AccountAlias, AccountAliasDomain, AccountDetails, AccountValue},
        block::BlockHeader,
        domain::Domain,
        isi::{InstructionBox, Log},
        nexus::{DataSpaceCatalog, DataSpaceMetadata},
        role::RoleId,
    };
    use iroha_logger::Level;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_test_samples::ALICE_ID;
    use nonzero_ext::nonzero;
    #[test]
    fn parse_account_key_variants() {
        let alice = (*ALICE_ID).clone();
        let world = World::new();
        let world_view = world.view();
        let detail_key = format!("account.detail:{alice}:quota");
        let expected = alice.clone();
        assert_eq!(
            (parse_account_from_access_key(
                &world_view,
                &DataSpaceCatalog::default(),
                &format!("account:{alice}"),
                0,
            ))
            .as_ref()
            .expect("the operation must complete successfully"),
            &(Some(expected.clone()))
        );
        assert_eq!(
            (parse_account_from_access_key(
                &world_view,
                &DataSpaceCatalog::default(),
                &detail_key,
                0,
            ))
            .as_ref()
            .expect("the operation must complete successfully"),
            &(Some(expected.clone()))
        );
        assert_eq!(expected.subject_id(), alice.subject_id());
        assert!(
            parse_account_from_access_key(
                &world_view,
                &DataSpaceCatalog::default(),
                "asset:coin#wonderland",
                0,
            )
            .expect("valid access-key account state")
            .is_none()
        );
    }
    #[test]
    fn parse_account_literal_rejects_i105_with_domain_suffix() {
        let alice = (*ALICE_ID).clone();
        let wonderland: DomainId =
            DomainId::try_new("wonderland", "universal").expect("wonderland domain");
        let domain = Domain::new(wonderland.clone()).build(&alice);
        let account = Account::new(alice.clone()).build(&alice);
        let world = World::with([domain], [account], []);
        let world_view = world.view();
        let i105 = alice.canonical_i105().expect("i105 encoding");
        let literal = format!("{i105}@{wonderland}");
        assert_eq!(
            (parse_account_literal_with_world(
                &world_view,
                &DataSpaceCatalog::default(),
                &literal,
                0,
            ))
            .as_ref()
            .expect("the operation must complete successfully"),
            &(None)
        );
    }
    #[test]
    fn parse_account_literal_accepts_encoded_without_selector_registry() {
        let alice = (*ALICE_ID).clone();
        let wonderland: DomainId =
            DomainId::try_new("wonderland", "universal").expect("wonderland domain");
        let domain = Domain::new(wonderland.clone()).build(&alice);
        let account = Account::new(alice.clone()).build(&alice);
        let world = World::with([domain], [account], []);
        let world_view = world.view();
        let i105 = alice.canonical_i105().expect("i105 encoding");
        assert_eq!((parse_account_literal_with_world(&world_view, &DataSpaceCatalog::default(), &i105, 0,)).as_ref().expect("the operation must complete successfully"),
&(Some(alice)));
    }
    #[test]
    fn parse_account_literal_accepts_canonical_i105_without_domain_materialization() {
        let account = (*ALICE_ID).clone();
        let alpha: DomainId = DomainId::try_new("alpha", "universal").expect("alpha domain");
        let world = World::with(
            [Domain::new(alpha).build(&account)],
            [Account::new(account.clone()).build(&account)],
            [],
        );
        let world_view = world.view();
        let encoded = account
            .canonical_i105()
            .expect("canonical I105 account literal");
        assert_eq!(
            (parse_account_literal_with_world(
                &world_view,
                &DataSpaceCatalog::default(),
                &encoded,
                0,
            ))
            .as_ref()
            .expect("the operation must complete successfully"),
            &(Some(account)),
            "canonical I105 account ids must remain valid without domain-linked account materialization"
        );
    }
    #[test]
    fn parse_account_literal_resolves_on_chain_alias_literals() {
        let domain_id: DomainId = DomainId::try_new("ivm", "universal").expect("domain");
        let account_id = (*ALICE_ID).clone();
        let alias = AccountAlias::new(
            Name::from_str("gas").expect("alias name"),
            Some(AccountAliasDomain::new(domain_id.name().clone())),
            DataSpaceId::UNIVERSAL,
        );
        let mut world = World::with(
            [Domain::new(domain_id.clone()).build(&account_id)],
            [Account::new(account_id.clone()).build(&account_id)],
            [],
        );
        let selector = crate::sns::selector_for_account_alias(&alias, &DataSpaceCatalog::default())
            .expect("SNS selector");
        let address = iroha_data_model::account::AccountAddress::from_account_id(&account_id)
            .expect("account address");
        let lease = iroha_data_model::sns::NameRecordV1::new(
            selector.clone(),
            account_id.clone(),
            vec![iroha_data_model::sns::NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            iroha_model_base::metadata::Metadata::default(),
        );
        world.smart_contract_state_mut_for_testing().insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&lease),
        );
        world
            .account_aliases
            .insert(alias.clone(), account_id.clone());
        world.replace_account_rekey_record_for_testing(
            iroha_data_model::account::rekey::AccountRekeyRecord::new(alias, account_id.clone()),
        );
        let world_view = world.view();
        assert_eq!(
            (parse_account_literal_with_world(
                &world_view,
                &DataSpaceCatalog::default(),
                "gas@ivm.universal",
                0,
            ))
            .as_ref()
            .expect("the operation must complete successfully"),
            &(Some(account_id)),
            "account selectors must resolve active on-chain aliases to canonical account ids"
        );
    }
    #[test]
    fn parse_account_literal_resolves_aliases_in_non_default_dataspaces() {
        let account_id = (*ALICE_ID).clone();
        let alias = AccountAlias::domainless(
            Name::from_str("treasury").expect("alias name"),
            DataSpaceId::new(7),
        );
        let catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: DataSpaceId::new(7),
                alias: "retail".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("dataspace catalog");
        let mut world = World::with(
            [],
            [Account::new(account_id.clone()).build(&account_id)],
            [],
        );
        let selector =
            crate::sns::selector_for_account_alias(&alias, &catalog).expect("SNS selector");
        let address = iroha_data_model::account::AccountAddress::from_account_id(&account_id)
            .expect("account address");
        let lease = iroha_data_model::sns::NameRecordV1::new(
            selector.clone(),
            account_id.clone(),
            vec![iroha_data_model::sns::NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            iroha_model_base::metadata::Metadata::default(),
        );
        world.smart_contract_state_mut_for_testing().insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&lease),
        );
        world
            .account_aliases
            .insert(alias.clone(), account_id.clone());
        world.replace_account_rekey_record_for_testing(
            iroha_data_model::account::rekey::AccountRekeyRecord::new(alias, account_id.clone()),
        );
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let mut state = State::new_for_testing(world, kura, query);
        state.set_dataspace_catalog_for_testing(catalog);
        let state_view = state.view();
        let world_view = state_view.world();
        assert_eq!(
            (parse_account_literal_with_world(
                world_view,
                &state_view.nexus.dataspace_catalog,
                "treasury@retail",
                0,
            ))
            .as_ref()
            .expect("the operation must complete successfully"),
            &(Some(account_id.clone())),
            "account selectors must resolve aliases in non-default dataspaces"
        );
    }
    #[test]
    fn warm_overlay_chunk_respectschunk_size() {
        let instrs = vec![
            InstructionBox::from(Log::new(Level::INFO, "a".to_owned())),
            InstructionBox::from(Log::new(Level::INFO, "b".to_owned())),
            InstructionBox::from(Log::new(Level::INFO, "c".to_owned())),
        ];
        let overlay = TxOverlay::from_instructions(instrs);
        assert_eq!(warm_overlay_chunk(&overlay, 2), 2);
        assert_eq!(warm_overlay_chunk(&overlay, 10), 3);
    }
    #[test]
    fn prefetch_account_reports_hits() {
        let alice = (*ALICE_ID).clone();
        let mut world = World::new();
        world
            .accounts
            .insert(alice.clone(), AccountValue::new(AccountDetails::default()));
        world.tx_sequences.insert(alice.clone(), 7);
        let role_id = RoleId {
            name: Name::from_str("auditor").expect("valid name"),
        };
        world
            .account_roles
            .insert(RoleIdWithOwner::new(alice.clone(), role_id), ());
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new_for_testing(world, kura, query_handle);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let state_block = state.block(header);
        let prefetch_stats = prefetch_account_stores(&state_block, &alice);
        assert!(prefetch_stats.account_loaded);
        assert!(prefetch_stats.tx_sequence_loaded);
        assert_eq!(prefetch_stats.roles_touched, 1);
        // No permissions were inserted above.
        assert_eq!(prefetch_stats.permissions_touched, 0);
    }
}
#[cfg(test)]
mod pipeline_recovery_tests {
    use super::*;
    #[test]
    fn expected_pipeline_dag_fingerprint_requires_matching_block_hash() {
        let height = 1;
        let block_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x11; 32]));
        let other_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x22; 32]));
        let call_hash =
            HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::prehashed([0x33; 32]));
        let dag = PipelineDagSnapshot {
            fingerprint: [0x44; 32],
            key_count: 1,
        };
        let txs = vec![PipelineTxSnapshot::compact(call_hash, 0, 0)];
        let sidecar_mismatch = PipelineRecoverySidecar::new(height, other_hash, dag, txs.clone());
        assert!(
            expected_pipeline_dag_fingerprint(height, block_hash, &[call_hash], &sidecar_mismatch)
                .is_none(),
            "sidecars anchored to a different block hash should be ignored"
        );
        let sidecar_match = PipelineRecoverySidecar::new(height, block_hash, dag, txs);
        assert_eq!(
            expected_pipeline_dag_fingerprint(height, block_hash, &[call_hash], &sidecar_match),
            Some(dag.fingerprint),
            "matching v1 sidecars should provide expected fingerprint"
        );
    }
}
#[cfg(test)]
#[derive(Debug)]
struct DisjointSet {
    parent: Vec<usize>,
    rank: Vec<u8>,
}
#[cfg(test)]
impl DisjointSet {
    fn new(size: usize) -> Self {
        Self {
            parent: (0..size).collect(),
            rank: vec![0; size],
        }
    }
    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            let root = self.find(self.parent[x]);
            self.parent[x] = root;
        }
        self.parent[x]
    }
    fn union(&mut self, a: usize, b: usize) {
        let mut ra = self.find(a);
        let mut rb = self.find(b);
        if ra == rb {
            return;
        }
        if self.rank[ra] < self.rank[rb] {
            core::mem::swap(&mut ra, &mut rb);
        }
        self.parent[rb] = ra;
        if self.rank[ra] == self.rank[rb] {
            self.rank[ra] = self.rank[ra].saturating_add(1);
        }
    }
}
#[cfg(test)]
fn component_iteration_order(
    components: &[Vec<usize>],
    call_hashes: &[iroha_crypto::HashOf<
        iroha_data_model::transaction::signed::TransactionEntrypoint,
    >],
) -> Vec<usize> {
    use core::cmp::Ordering;
    let mut indices: Vec<usize> = (0..components.len()).collect();
    let mut keys: Vec<
        Option<(
            iroha_crypto::HashOf<iroha_data_model::transaction::signed::TransactionEntrypoint>,
            usize,
        )>,
    > = Vec::with_capacity(indices.len());
    for component in components {
        let key = component
            .iter()
            .copied()
            .map(|idx| (call_hashes[idx], idx))
            .min_by(std::cmp::Ord::cmp);
        keys.push(key);
    }
    indices.sort_unstable_by(|&a, &b| match (&keys[a], &keys[b]) {
        (Some(ka), Some(kb)) => ka.cmp(kb),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    });
    indices
}
#[cfg(test)]
fn schedule_components_ready_heap(
    components: &[Vec<usize>],
    row_offsets: &[usize],
    cols: &[usize],
    call_hashes: &[iroha_crypto::HashOf<
        iroha_data_model::transaction::signed::TransactionEntrypoint,
    >],
) -> Option<Vec<usize>> {
    use std::{cmp::Reverse, collections::BinaryHeap};
    let n = call_hashes.len();
    debug_assert_eq!(
        row_offsets.len(),
        n.saturating_add(1),
        "CSR row offsets must track all vertices"
    );
    if n == 0 {
        return Some(Vec::new());
    }
    let mut order = Vec::with_capacity(n);
    let mut in_component = vec![false; n];
    let mut local_indeg = vec![0usize; n];
    let mut heap: BinaryHeap<
        Reverse<(
            iroha_crypto::HashOf<iroha_data_model::transaction::signed::TransactionEntrypoint>,
            usize,
        )>,
    > = BinaryHeap::with_capacity(n);
    let ordered_components = component_iteration_order(components, call_hashes);
    for &component_idx in &ordered_components {
        let component = &components[component_idx];
        if component.is_empty() {
            continue;
        }
        for &idx in component {
            in_component[idx] = true;
            local_indeg[idx] = 0;
        }
        for &idx in component {
            let start = row_offsets[idx];
            let end = row_offsets[idx + 1];
            for &child in &cols[start..end] {
                debug_assert!(child < n, "CSR edge index out of bounds");
                if !in_component[child] {
                    return None;
                }
                local_indeg[child] = local_indeg[child].saturating_add(1);
            }
        }
        heap.clear();
        for &idx in component {
            if local_indeg[idx] == 0 {
                heap.push(Reverse((call_hashes[idx], idx)));
            }
        }
        let prior_len = order.len();
        while let Some(Reverse((_hash, node))) = heap.pop() {
            order.push(node);
            let start = row_offsets[node];
            let end = row_offsets[node + 1];
            for &child in &cols[start..end] {
                if in_component[child] {
                    let deg = local_indeg[child].saturating_sub(1);
                    local_indeg[child] = deg;
                    if deg == 0 {
                        heap.push(Reverse((call_hashes[child], child)));
                    }
                } else {
                    return None;
                }
            }
        }
        if order.len() - prior_len != component.len() {
            return None;
        }
        for &idx in component {
            in_component[idx] = false;
            local_indeg[idx] = 0;
        }
    }
    Some(order)
}
#[cfg(test)]
fn schedule_components_wave(
    components: &[Vec<usize>],
    row_offsets: &[usize],
    cols: &[usize],
    call_hashes: &[iroha_crypto::HashOf<
        iroha_data_model::transaction::signed::TransactionEntrypoint,
    >],
) -> Option<Vec<usize>> {
    let n = call_hashes.len();
    debug_assert_eq!(
        row_offsets.len(),
        n.saturating_add(1),
        "CSR row offsets must track all vertices"
    );
    if n == 0 {
        return Some(Vec::new());
    }
    let mut order = Vec::with_capacity(n);
    let mut in_component = vec![false; n];
    let mut local_indeg = vec![0usize; n];
    let mut ready_frontier: Vec<usize> = Vec::new();
    let mut current_layer: Vec<usize> = Vec::new();
    let ordered_components = component_iteration_order(components, call_hashes);
    for &component_idx in &ordered_components {
        let component = &components[component_idx];
        if component.is_empty() {
            continue;
        }
        for &idx in component {
            in_component[idx] = true;
            local_indeg[idx] = 0;
        }
        for &idx in component {
            let start = row_offsets[idx];
            let end = row_offsets[idx + 1];
            for &child in &cols[start..end] {
                debug_assert!(child < n, "CSR edge index out of bounds");
                if !in_component[child] {
                    return None;
                }
                local_indeg[child] = local_indeg[child].saturating_add(1);
            }
        }
        ready_frontier.clear();
        for &idx in component {
            if local_indeg[idx] == 0 {
                ready_frontier.push(idx);
            }
        }
        let prior_len = order.len();
        while !ready_frontier.is_empty() {
            ready_frontier.sort_unstable_by(|&a, &b| {
                call_hashes[a].cmp(&call_hashes[b]).then_with(|| a.cmp(&b))
            });
            current_layer.clear();
            current_layer.extend(ready_frontier.iter().copied());
            ready_frontier.clear();
            for &node in &current_layer {
                order.push(node);
                let start = row_offsets[node];
                let end = row_offsets[node + 1];
                for &child in &cols[start..end] {
                    if in_component[child] {
                        let deg = local_indeg[child].saturating_sub(1);
                        local_indeg[child] = deg;
                        if deg == 0 {
                            ready_frontier.push(child);
                        }
                    } else {
                        return None;
                    }
                }
            }
        }
        if order.len() - prior_len != component.len() {
            return None;
        }
        for &idx in component {
            in_component[idx] = false;
            local_indeg[idx] = 0;
        }
    }
    Some(order)
}
#[cfg(test)]
fn conflict_free_component_layers(
    components: &[Vec<usize>],
    row_offsets: &[usize],
    cols: &[usize],
    call_hashes: &[iroha_crypto::HashOf<
        iroha_data_model::transaction::signed::TransactionEntrypoint,
    >],
) -> Option<Vec<Vec<usize>>> {
    let n = call_hashes.len();
    debug_assert_eq!(
        row_offsets.len(),
        n.saturating_add(1),
        "CSR row offsets must track all vertices"
    );
    if n == 0 {
        return Some(Vec::new());
    }
    let mut in_component = vec![false; n];
    let mut local_indeg = vec![0usize; n];
    let mut ready_frontier: Vec<usize> = Vec::new();
    let mut current_layer: Vec<usize> = Vec::new();
    let mut per_comp_layers: Vec<Vec<Vec<usize>>> = Vec::with_capacity(components.len());
    let mut max_depth = 0usize;
    let ordered_components = component_iteration_order(components, call_hashes);
    for &component_idx in &ordered_components {
        let component = &components[component_idx];
        if component.is_empty() {
            per_comp_layers.push(Vec::new());
            continue;
        }
        for &idx in component {
            debug_assert!(idx < n, "component vertex index out of bounds");
            in_component[idx] = true;
            local_indeg[idx] = 0;
        }
        for &idx in component {
            let start = row_offsets[idx];
            let end = row_offsets[idx + 1];
            for &child in &cols[start..end] {
                debug_assert!(child < n, "CSR edge index out of bounds");
                if !in_component[child] {
                    return None;
                }
                local_indeg[child] = local_indeg[child].saturating_add(1);
            }
        }
        ready_frontier.clear();
        for &idx in component {
            if local_indeg[idx] == 0 {
                ready_frontier.push(idx);
            }
        }
        let mut seen = 0usize;
        let mut comp_layers: Vec<Vec<usize>> = Vec::new();
        while !ready_frontier.is_empty() {
            ready_frontier.sort_unstable_by(|&a, &b| {
                call_hashes[a].cmp(&call_hashes[b]).then_with(|| a.cmp(&b))
            });
            current_layer.clear();
            current_layer.extend(ready_frontier.iter().copied());
            ready_frontier.clear();
            let mut wave = Vec::with_capacity(current_layer.len());
            for &node in &current_layer {
                seen = seen.saturating_add(1);
                wave.push(node);
                let start = row_offsets[node];
                let end = row_offsets[node + 1];
                for &child in &cols[start..end] {
                    if !in_component[child] {
                        return None;
                    }
                    let deg = local_indeg[child].saturating_sub(1);
                    local_indeg[child] = deg;
                    if deg == 0 {
                        ready_frontier.push(child);
                    }
                }
            }
            comp_layers.push(wave);
        }
        if seen != component.len() {
            return None;
        }
        max_depth = max_depth.max(comp_layers.len());
        per_comp_layers.push(comp_layers);
        for &idx in component {
            in_component[idx] = false;
            local_indeg[idx] = 0;
        }
    }
    let mut layers: Vec<Vec<usize>> = Vec::with_capacity(max_depth);
    for depth in 0..max_depth {
        let mut wave: Vec<usize> = Vec::new();
        for comp_layers in &per_comp_layers {
            if let Some(layer) = comp_layers.get(depth) {
                wave.extend_from_slice(layer);
            }
        }
        if !wave.is_empty() {
            wave.sort_unstable_by(|&a, &b| {
                call_hashes[a].cmp(&call_hashes[b]).then_with(|| a.cmp(&b))
            });
            layers.push(wave);
        }
    }
    Some(layers)
}
#[cfg(test)]
fn schedule_ready_heap_global(
    row_offsets: &[usize],
    cols: &[usize],
    indeg: &[usize],
    call_hashes: &[iroha_crypto::HashOf<
        iroha_data_model::transaction::signed::TransactionEntrypoint,
    >],
) -> Vec<usize> {
    use std::{cmp::Reverse, collections::BinaryHeap};
    let n = indeg.len();
    debug_assert_eq!(
        row_offsets.len(),
        n.saturating_add(1),
        "CSR row offsets must track all vertices"
    );
    let mut indeg_s = indeg.to_vec();
    let mut heap: BinaryHeap<
        Reverse<(
            iroha_crypto::HashOf<iroha_data_model::transaction::signed::TransactionEntrypoint>,
            usize,
        )>,
    > = BinaryHeap::with_capacity(n);
    for i in 0..n {
        if indeg_s[i] == 0 {
            heap.push(Reverse((call_hashes[i], i)));
        }
    }
    let mut order = Vec::with_capacity(n);
    while let Some(Reverse((_hash, node))) = heap.pop() {
        order.push(node);
        let start = row_offsets[node];
        let end = row_offsets[node + 1];
        for &child in &cols[start..end] {
            indeg_s[child] = indeg_s[child].saturating_sub(1);
            if indeg_s[child] == 0 {
                heap.push(Reverse((call_hashes[child], child)));
            }
        }
    }
    order
}
#[cfg(test)]
fn schedule_wave_global(
    row_offsets: &[usize],
    cols: &[usize],
    indeg: &[usize],
    call_hashes: &[iroha_crypto::HashOf<
        iroha_data_model::transaction::signed::TransactionEntrypoint,
    >],
) -> Vec<usize> {
    let n = indeg.len();
    debug_assert_eq!(
        row_offsets.len(),
        n.saturating_add(1),
        "CSR row offsets must track all vertices"
    );
    let mut indeg_s = indeg.to_vec();
    let mut ready_frontier: Vec<usize> = Vec::with_capacity(n);
    for (i, indegree) in indeg_s.iter().enumerate() {
        if *indegree == 0 {
            ready_frontier.push(i);
        }
    }
    let mut order = Vec::with_capacity(n);
    let mut current_layer: Vec<usize> = Vec::new();
    while !ready_frontier.is_empty() {
        ready_frontier
            .sort_unstable_by(|&a, &b| call_hashes[a].cmp(&call_hashes[b]).then_with(|| a.cmp(&b)));
        current_layer.clear();
        current_layer.extend(ready_frontier.iter().copied());
        ready_frontier.clear();
        for &node in &current_layer {
            order.push(node);
            let start = row_offsets[node];
            let end = row_offsets[node + 1];
            for &child in &cols[start..end] {
                indeg_s[child] = indeg_s[child].saturating_sub(1);
                if indeg_s[child] == 0 {
                    ready_frontier.push(child);
                }
            }
        }
    }
    order
}
#[cfg(test)]
impl Clone for DisjointSet {
    fn clone(&self) -> Self {
        Self {
            parent: self.parent.clone(),
            rank: self.rank.clone(),
        }
    }
}
/// Structured context for AXT envelope validation failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AxtEnvelopeValidationDetails {
    /// Human-readable message describing the failure.
    pub message: String,
    /// Categorised reason label for the rejection.
    pub reason: AxtRejectReason,
    /// Policy snapshot version active during validation, when block results were present.
    pub snapshot_version: Option<u64>,
    /// Dataspace associated with the rejection (if known).
    pub dataspace: Option<DataSpaceId>,
    /// Lane associated with the rejection (if known).
    pub lane: Option<LaneId>,
    /// Exact active handle era for refresh guidance.
    pub active_handle_era: Option<u64>,
    /// Exact next handle counter for refresh guidance.
    pub next_handle_counter: Option<u64>,
}
impl fmt::Display for AxtEnvelopeValidationDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (reason={}, lane={:?}, dsid={:?}",
            self.message,
            self.reason.label(),
            self.lane,
            self.dataspace
        )?;
        if let Some(snapshot_version) = self.snapshot_version {
            write!(f, ", snapshot_version={snapshot_version}")?;
        }
        if let Some(hint) = self.active_handle_era {
            write!(f, ", active_handle_era={hint}")?;
        }
        if let Some(hint) = self.next_handle_counter {
            write!(f, ", next_handle_counter={hint}")?;
        }
        write!(f, ")")
    }
}
impl From<crate::state::StateBlockStartError<BlockValidationError>> for BlockValidationError {
    fn from(error: crate::state::StateBlockStartError<Self>) -> Self {
        match error {
            crate::state::StateBlockStartError::Storage(error) => {
                Self::StateStorageAdmission(error)
            }
            crate::state::StateBlockStartError::History(error) => Self::BlockHashAdmission(error),
            crate::state::StateBlockStartError::Membership(error) => {
                Self::MembershipAdmission(error)
            }
            crate::state::StateBlockStartError::ExecutionDeferred(error) => {
                Self::ExecutionDeferred(error)
            }
            crate::state::StateBlockStartError::GovernanceDueUnavailable(error) => {
                Self::GovernanceDueUnavailable(error)
            }
            crate::state::StateBlockStartError::Stage(error) => error,
            crate::state::StateBlockStartError::Policy(error) => {
                Self::ExecutionContextInvalid(error)
            }
        }
    }
}
/// Errors occurred on block validation
#[derive(Debug, displaydoc::Display, Error)]
pub enum BlockValidationError {
    /// Native source publication changed; reacquire and authenticate before retrying ({authenticated_generation} -> {observed_generation})
    NativeSourceChanged {
        /// State generation authenticated by the original acquisition.
        authenticated_generation: u64,
        /// State generation observed before the unfinished attempt returned.
        observed_generation: u64,
    },
    /// Original native parent history is unavailable or contradicts its retained source: {0}
    NativeHistory(crate::sumeragi::certified_chain::ChainReadError),
    /// Local State view could not be captured before candidate validation: {0}
    StateView(#[source] crate::state::StateViewError),
    /// Local World storage admission failed before State execution: {0}
    StateStorageAdmission(crate::state::StateStorageAdmissionError),
    /// Local evidence or stake-index penalty preparation failed: {0}
    EvidencePreparation(crate::state::EvidencePreparationError),
    /// Local execution did not complete: {0}
    ExecutionDeferred(crate::execution_attempt::ExecutionDeferred),
    /// The shared Parliament due-work dependency is unavailable: {0}
    GovernanceDueUnavailable(crate::smartcontracts::isi::sccp::keepalive::DueWorkUnavailable),
    /// Local hash-history admission failed before State execution: {0}
    BlockHashAdmission(crate::state::BlockHashAdmissionError),
    /// Local membership-history admission failed before State execution: {0}
    MembershipAdmission(crate::state::MembershipAdmissionError),
    /// Block has committed transactions
    HasCommittedTransactions,
    /// Block contained no committed overlays
    EmptyBlock,
    /// Block contains duplicate transactions
    DuplicateTransactions,
    /// Block contains too many external entrypoints. Actual: {actual}, maximum: {max}
    TooManyTransactions {
        /// Number of externally supplied entrypoints in the block.
        actual: usize,
        /// Consensus maximum active for this block.
        max: usize,
    },
    /// Mismatch between the actual and expected hashes of the previous block. Expected: {expected:?}, actual: {actual:?}
    PrevBlockHashMismatch {
        /// Expected value
        expected: Option<HashOf<BlockHeader>>,
        /// Actual value
        actual: Option<HashOf<BlockHeader>>,
    },
    /// Mismatch between the actual and expected height of the previous block. Expected: {expected}, actual: {actual}
    PrevBlockHeightMismatch {
        /// Expected value
        expected: usize,
        /// Actual value
        actual: usize,
    },
    /// The merkle root does not match the computed one.
    MerkleRootMismatch,
    /// Execution context invalid: {0}
    ExecutionContextInvalid(String),
    /// Local lane storage failed before candidate validation: {0}
    LaneStorage(#[source] std::io::Error),
    /// Local storage observation requires recovery before candidate validation: {reason}
    LocalStorageRecoveryRequired {
        /// Diagnostic from the failed local observation, never rejection authority.
        reason: String,
    },
    /// Committed fragment count mismatch. Expected: {expected}, actual: {actual}
    CommittedFragmentCountMismatch {
        /// Count recomputed while executing the block.
        expected: u64,
        /// Count advertised in the received block result.
        actual: u64,
    },
    /// Cannot accept a transaction
    TransactionAccept(#[from] AcceptTransactionFail),
    /// Mismatch between the actual and expected topology. Expected: {expected:?}, actual: {actual:?}
    TopologyMismatch {
        /// Expected value
        expected: Vec<PeerId>,
        /// Actual value
        actual: Vec<PeerId>,
    },
    /// Error during block signatures check
    SignatureVerification(#[from] SignatureVerificationError),
    /// Invalid genesis block: {0}
    InvalidGenesis(#[from] InvalidGenesisError),
    /// Signed genesis policy mismatch: execution {expected_execution} != {actual_execution}, Nexus {expected_nexus} != {actual_nexus}
    GenesisPolicyMismatch {
        /// Execution policy committed by the signed genesis body.
        expected_execution: Hash,
        /// Execution policy actually used by this original genesis execution.
        actual_execution: Hash,
        /// Nexus/AMX policy committed by the signed genesis body.
        expected_nexus: Hash,
        /// Nexus/AMX context derived from the original staged genesis effects.
        actual_nexus: Hash,
    },
    /// Block's creation time is earlier than that of the previous block
    BlockInThePast,
    /// Block's creation time is later than the current node local time
    BlockInTheFuture,
    /// Sumeragi block creation time is below its required floor. Minimum: {minimum_ms} ms, actual: {actual_ms} ms
    BlockTimeBeforeRequiredFloor {
        /// Deterministic minimum derived from the parent, cadence, and authenticated inputs.
        minimum_ms: u64,
        /// Timestamp committed by the proposed block.
        actual_ms: u64,
    },
    /// Sumeragi logical block time exceeded the canonical u64-millisecond range
    BlockTimeOverflow,
    /// Sumeragi finality authority does not bind this block and execution: {0}
    FinalityAuthorityInvalid(String),
    /// Some transaction in the block is created after the block itself
    TransactionInTheFuture,
    /// Block confidential feature digest mismatch. Expected: {expected:?}, actual: {actual:?}
    ConfidentialFeaturesMismatch {
        /// Digest expected by the local node.
        expected: Option<ConfidentialFeatureDigest>,
        /// Digest committed in the incoming block.
        actual: Option<ConfidentialFeatureDigest>,
    },
    /// Proof policy hash mismatch. Expected: {expected:?}, actual: {actual:?}
    ProofPolicyHashMismatch {
        /// Hash derived from the local lane catalog.
        expected: HashOf<DaProofPolicyBundle>,
        /// Hash embedded in the incoming header.
        actual: Option<HashOf<DaProofPolicyBundle>>,
    },
    /// DA proof-policy sidecar hash does not match the signed header. Expected: {expected:?}, actual: {actual:?}
    DaProofPolicySidecarHashMismatch {
        /// Hash derived from the embedded policy sidecar.
        expected: Option<HashOf<DaProofPolicyBundle>>,
        /// Hash embedded in the incoming header.
        actual: Option<HashOf<DaProofPolicyBundle>>,
    },
    /// DA proof-policy sidecar differs from the active policy snapshot.
    DaProofPolicyBundleMismatch,
    /// DA commitment hash mismatch. Expected: {expected:?}, actual: {actual:?}
    DaCommitmentHashMismatch {
        /// Hash derived from the embedded DA commitment bundle.
        expected: Option<HashOf<DaCommitmentBundle>>,
        /// Hash embedded in the incoming header.
        actual: Option<HashOf<DaCommitmentBundle>>,
    },
    /// An empty DA commitment sidecar must be represented as `None`.
    NonCanonicalEmptyDaCommitmentBundle,
    /// DA pin-intent hash mismatch. Expected: {expected:?}, actual: {actual:?}
    DaPinIntentHashMismatch {
        /// Hash derived from the embedded DA pin-intent bundle.
        expected: Option<HashOf<DaPinIntentBundle>>,
        /// Hash embedded in the incoming header.
        actual: Option<HashOf<DaPinIntentBundle>>,
    },
    /// An empty DA pin-intent sidecar must be represented as `None`.
    NonCanonicalEmptyDaPinIntentBundle,
    /// DA commitment bundle failed validation: {0}
    DaCommitmentBundle(#[from] DaCommitmentValidationError),
    /// DA pin-intent bundle failed validation: {0}
    DaPinIntentBundle(#[from] DaPinIntentValidationError),
    /// DA index hydration failed before block validation: {0}
    DaIndexHydration(String),
    /// DA receipt cursor gate failed: {0}
    DaReceiptCursor(#[from] DaReceiptCursorError),
    /// DA shard cursor gate failed: {0}
    DaShardCursor(#[from] DaShardCursorError),
    /// AXT envelope export contained invalid or inconsistent fragments: {0}
    AxtEnvelopeValidationFailed(AxtEnvelopeValidationDetails),
    /// NPoS consensus effects are invalid: {0}
    NposEffectsInvalid(String),
}
impl BlockValidationError {
    /// Keep local autoscale observations out of deterministic block rejection.
    #[cfg(test)]
    pub(crate) fn from_autoscale_lifecycle_error(error: crate::state::LaneLifecycleError) -> Self {
        use crate::state::LaneLifecycleError;
        let error = match error {
            LaneLifecycleError::NposPolicy(
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason),
            ) => return Self::ExecutionDeferred(reason),
            completed => completed,
        };
        let reason = format!("failed to evaluate Nexus autoscale: {error}");
        match error {
            LaneLifecycleError::DrainObservation(_)
            | LaneLifecycleError::Storage(_)
            | LaneLifecycleError::GeometryStorage(_)
            | LaneLifecycleError::PublicationBusy { .. } => {
                Self::LocalStorageRecoveryRequired { reason }
            }
            _ => Self::ExecutionContextInvalid(reason),
        }
    }

    /// Preserve local observation provenance at the certified merge staging boundary.
    #[cfg(test)]
    pub(crate) fn from_certified_merge_stage_error(
        error: crate::state::MergeLedgerCommitError,
    ) -> Self {
        use crate::state::MergeLedgerCommitError;
        match error {
            MergeLedgerCommitError::StateView(error) => Self::StateView(error),
            MergeLedgerCommitError::StateStorageAdmission(error) => {
                Self::StateStorageAdmission(error)
            }
            MergeLedgerCommitError::ExecutionDeferred(reason) => Self::ExecutionDeferred(reason),
            MergeLedgerCommitError::BlockHashAdmission(error) => Self::BlockHashAdmission(error),
            MergeLedgerCommitError::MembershipAdmission(error) => Self::MembershipAdmission(error),
            MergeLedgerCommitError::NativeControlValidation(error) => *error,
            local @ (MergeLedgerCommitError::NativeResourceAdmission(_)
            | MergeLedgerCommitError::ExecutionObservationChanged
            | MergeLedgerCommitError::ExecutionRecorderConflict(_)
            | MergeLedgerCommitError::Persistence(_)
            | MergeLedgerCommitError::LocalDrainObservation(_)) => {
                Self::LocalStorageRecoveryRequired {
                    reason: format!("certified merge entry could not be staged: {local}"),
                }
            }
            other => Self::ExecutionContextInvalid(format!(
                "certified merge entry could not be staged: {other}"
            )),
        }
    }

    /// Keep local resource refusal outside the deterministic NPoS verdict channel.
    pub(crate) fn from_npos_application_error(error: eyre::Report, stage: &str) -> Self {
        if let Some(local) = error.downcast_ref::<crate::state::StateAdmissionError>() {
            match local {
                crate::state::StateAdmissionError::Storage(error) => {
                    Self::StateStorageAdmission(error.clone())
                }
                crate::state::StateAdmissionError::History(error) => {
                    Self::BlockHashAdmission(error.clone())
                }
                crate::state::StateAdmissionError::Membership(error) => {
                    Self::MembershipAdmission(error.clone())
                }
            }
        } else if let Some(local) = error.downcast_ref::<crate::state::StateStorageAdmissionError>()
        {
            Self::StateStorageAdmission(local.clone())
        } else if let Some(local) = error.downcast_ref::<crate::state::EvidencePreparationError>() {
            Self::EvidencePreparation(local.clone())
        } else {
            use crate::execution_attempt::ExecutionAttemptError;
            let error = match error.downcast::<ExecutionAttemptError<String>>() {
                Ok(ExecutionAttemptError::Deferred(original)) => {
                    return Self::ExecutionDeferred(original);
                }
                Ok(ExecutionAttemptError::Rejected(completed)) => {
                    return Self::NposEffectsInvalid(format!("{stage}: {completed}"));
                }
                Err(error) => error,
            };
            let error = match error.downcast::<ExecutionAttemptError<iroha_data_model::isi::error::InstructionExecutionError>>() {
                Ok(ExecutionAttemptError::Deferred(original)) => return Self::ExecutionDeferred(original),
                Ok(ExecutionAttemptError::Rejected(completed)) => return Self::NposEffectsInvalid(format!("{stage}: {completed}")),
                Err(error) => error,
            };
            match error.downcast::<crate::sumeragi::evidence::EvidenceAdmissionError>() {
                Ok(crate::sumeragi::evidence::EvidenceAdmissionError::Policy(
                    ExecutionAttemptError::Deferred(original),
                )) => Self::ExecutionDeferred(original),
                Ok(completed) => Self::NposEffectsInvalid(format!("{stage}: {completed}")),
                Err(error) => Self::NposEffectsInvalid(format!("{stage}: {error}")),
            }
        }
    }
}
/// Preserve the original local storage failure across native lane expansion.
impl From<crate::sumeragi::lanes::merge::MergeError> for BlockValidationError {
    fn from(error: crate::sumeragi::lanes::merge::MergeError) -> Self {
        use crate::sumeragi::lanes::merge::MergeError;
        match error {
            MergeError::SourceChanged {
                authenticated_generation,
                observed_generation,
            } => Self::NativeSourceChanged {
                authenticated_generation,
                observed_generation,
            },
            MergeError::StateView(error) => Self::StateView(error),
            MergeError::RoutingDeferred(reason) | MergeError::ResourceDeferred(reason) => {
                Self::ExecutionDeferred(reason)
            }
            MergeError::Storage(crate::execution_attempt::ExecutionAttemptError::Deferred(
                local,
            )) => Self::ExecutionDeferred(local),
            MergeError::Storage(crate::execution_attempt::ExecutionAttemptError::Rejected(
                source,
            )) => Self::LaneStorage(source),
            MergeError::Pending(reason) => Self::LocalStorageRecoveryRequired { reason },
            MergeError::Invalid(reason) => Self::ExecutionContextInvalid(reason),
        }
    }
}

#[cfg(test)]
#[path = "block/lane_storage_error_tests.rs"]
mod lane_storage_error_tests;

/// Preserve an unfinished history read before projecting only completed schedule failures.
impl From<crate::execution_attempt::ExecutionAttemptError<crate::sumeragi::schedule::ScheduleError>>
    for BlockValidationError
{
    fn from(
        error: crate::execution_attempt::ExecutionAttemptError<
            crate::sumeragi::schedule::ScheduleError,
        >,
    ) -> Self {
        match error {
            crate::execution_attempt::ExecutionAttemptError::Deferred(local) => {
                Self::ExecutionDeferred(local)
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => Self::from(error),
        }
    }
}

/// Preserve the original epoch-allocation refusal before any diagnostic formatting.
impl From<crate::sumeragi::schedule::ScheduleError> for BlockValidationError {
    fn from(error: crate::sumeragi::schedule::ScheduleError) -> Self {
        use crate::sumeragi::schedule::ScheduleError;
        match error {
            ScheduleError::CommittedSource(source) => Self::LocalStorageRecoveryRequired {
                reason: source.to_string(),
            },
            ScheduleError::Admission(refusal) => Self::ExecutionDeferred(refusal.into()),
            ScheduleError::Allocator { .. } => {
                Self::ExecutionDeferred(ivm::error::ExecutionDeferral::AllocationUnavailable.into())
            }
            deterministic => Self::ExecutionContextInvalid(deterministic.to_string()),
        }
    }
}

#[cfg(test)]
#[test]
fn epoch_schedule_capacity_preserves_original_local_release() {
    use crate::sumeragi::schedule::ScheduleError;
    let budget = iroha_allocation::AllocationBudget::new(8);
    let occupied = budget.try_reserve_bytes(8).expect("occupy original pool");
    let refusal = budget
        .try_reserve_bytes(1)
        .expect_err("local capacity refusal");
    let error = BlockValidationError::from(ScheduleError::Admission(refusal.clone()));
    assert_eq!(event::map_block_err_to_reason(&error), None);
    let BlockValidationError::ExecutionDeferred(owner) = error else {
        panic!("local epoch capacity cannot reject a block");
    };
    assert_eq!(owner.allocation_refusal(), Some(&refusal));
    assert!(matches!(
        owner.allocation_refusal(),
        Some(iroha_allocation::AllocationRefusal::Capacity { .. })
    ));
    drop(occupied);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[cfg(test)]
#[test]
fn epoch_schedule_allocator_refusal_and_invalid_context_stay_distinct() {
    use crate::sumeragi::schedule::ScheduleError;

    let source = crate::sumeragi::certified_chain::ChainReadError::NotInView { height: 2 };
    let local = BlockValidationError::from(
        crate::sumeragi::schedule::ScheduleError::CommittedSource(source.into()),
    );
    assert!(matches!(
        local,
        BlockValidationError::LocalStorageRecoveryRequired { .. }
    ));
    assert_eq!(event::map_block_err_to_reason(&local), None);

    let error = BlockValidationError::from(ScheduleError::Allocator {
        requested_bytes: 64,
    });
    assert_eq!(event::map_block_err_to_reason(&error), None);
    let BlockValidationError::ExecutionDeferred(owner) = error else {
        panic!("physical allocator refusal cannot reject a block");
    };
    assert_eq!(
        owner.reason(),
        ivm::error::ExecutionDeferral::AllocationUnavailable
    );
    assert!(owner.allocation_refusal().is_none());
    let error = BlockValidationError::from(ScheduleError::Epoch("wrong authority".into()));
    assert!(matches!(
        error,
        BlockValidationError::ExecutionContextInvalid(_)
    ));
    assert!(event::map_block_err_to_reason(&error).is_some());
}

impl From<crate::state::DaIndexHydrationError> for BlockValidationError {
    fn from(error: crate::state::DaIndexHydrationError) -> Self {
        // These errors arise while replaying already committed local history,
        // including its cursors. Preserve that context so block validation does
        // not mistake local reconstruction failure for a malformed candidate.
        match error {
            crate::state::DaIndexHydrationError::Deferred(original) => {
                Self::ExecutionDeferred(original)
            }
            error => Self::DaIndexHydration(error.to_string()),
        }
    }
}
#[cfg(test)]
#[test]
fn native_resource_refusal_is_a_local_certified_merge_staging_error() {
    let error = BlockValidationError::from_certified_merge_stage_error(
        crate::state::MergeLedgerCommitError::NativeResourceAdmission(
            iroha_allocation::AllocationRefusal::DemandOverflow,
        ),
    );
    assert!(matches!(
        error,
        BlockValidationError::LocalStorageRecoveryRequired { .. }
    ));
}
#[cfg(test)]
#[test]
fn native_execution_observation_and_recorder_conflicts_require_local_recovery() {
    for error in [
        crate::state::MergeLedgerCommitError::ExecutionObservationChanged,
        crate::state::MergeLedgerCommitError::ExecutionRecorderConflict(
            "recorder is already owned".to_owned(),
        ),
    ] {
        let classified = BlockValidationError::from_certified_merge_stage_error(error);
        assert!(matches!(
            &classified,
            BlockValidationError::LocalStorageRecoveryRequired { .. }
        ));
        assert!(event::map_block_err_to_reason(&classified).is_none());
    }
}
/// Error during signature verification
#[derive(Debug, displaydoc::Display, Clone, Copy, PartialEq, Eq, Error)]
pub enum SignatureVerificationError {
    /// The block doesn't have enough valid signatures to be committed (`{votes_count}` out of `{min_votes_for_commit}`)
    NotEnoughSignatures {
        /// Current number of signatures
        votes_count: usize,
        /// Minimal required number of signatures
        min_votes_for_commit: usize,
    },
    /// Multiple signatures were provided for the same signer index (`{signer}`)
    DuplicateSignature {
        /// Signer index that appeared more than once
        signer: usize,
    },
    /// Block signatory doesn't correspond to any in topology
    UnknownSignatory,
    /// Block signature doesn't correspond to block payload
    UnknownSignature,
    /// Missing proof-of-possession for validator consensus key
    MissingPop,
    /// The block doesn't have proxy tail signature
    ProxyTailMissing,
    /// The block doesn't have leader signature
    LeaderMissing,
    /// Block signer does not have an active consensus key for this height/role
    InactiveConsensusKey,
    /// Miscellaneous
    Other,
}
#[path = "block/genesis_output_rejection.rs"]
mod genesis_output_rejection;
pub use genesis_output_rejection::GenesisOutputRejection;

/// Errors occurred on genesis block validation
#[derive(Debug, Clone, displaydoc::Display, PartialEq, Eq, Error)]
pub enum InvalidGenesisError {
    /// Genesis block must be signed with genesis private key and not signed by any peer
    InvalidSignature,
    /// Every genesis transaction must carry a valid authorization proof for the genesis account
    InvalidTransactionSignature,
    /// Genesis authority must use a single-key account controller
    GenesisAuthorityNotSingleKey,
    /// Genesis transaction must be authorized by genesis account
    UnexpectedAuthority,
    /// Genesis block must carry deterministic execution results
    MissingResults,
    /// Genesis Network output count {actual} does not match input count {expected}
    NetworkOutputCountMismatch {
        /// Number of complete genesis Network inputs.
        expected: usize,
        /// Number of attached Network output rows.
        actual: usize,
    },
    /// Genesis execution output rejected: {0}
    RejectedOutput(#[source] GenesisOutputRejection),
    /// Genesis proposal commitments do not match their complete source payload
    ProposalCommitmentMismatch,
    /// Genesis typed outputs have malformed source ownership, phase or metadata
    OutputStructureMismatch,
    /// Genesis output Merkle cache does not match the complete typed execution outputs
    OutputMerkleCacheMismatch,
    /// Genesis transaction must contain instructions
    NotInstructions,
    /// Genesis block must have 1 to 16 transactions (executor upgrade, parameters, ordinary instructions, IVM trigger registrations, initial topology)
    BadTransactionsAmount,
    /// Genesis block header must start the chain (height 1, no previous hash)
    InvalidHeader,
    /// Genesis Merkle root does not match the committed transactions
    MerkleRootMismatch,
    /// Genesis output count exceeds the canonical `u64` range
    GenesisOutputCountOverflow,
    /// Genesis committed fragment count {actual:?} is below the successful-output lower bound {minimum}
    CommittedFragmentCountBelowOutputCount {
        /// Minimum number of committed fragments implied by successful genesis outputs.
        minimum: u64,
        /// Fragment count advertised by the attached block result, if present.
        actual: Option<u64>,
    },
    /// A genesis transaction does not carry the explicit genesis-only domain.
    TransactionDomainMismatch,
    /// Genesis DA commitment hash does not match embedded bundle
    DaCommitmentMismatch,
    /// Genesis DA proof-policy hash does not match a valid embedded policy bundle
    DaProofPolicyMismatch,
    /// Genesis DA pin intent hash does not match embedded bundle
    DaPinIntentMismatch,
}
/// Authenticate a genesis proposal's original signed inputs and payload commitments.
///
/// This validates the configured genesis authority, the sole index-zero block
/// signature, and every original transaction's domain, authority and signature.
/// It does not execute instructions, require outputs, or grant execution authority.
///
/// # Errors
///
/// Returns [`InvalidGenesisError`] for an invalid original header, signature,
/// transaction, or payload commitment, even when the proposal has no outputs yet.
pub fn check_genesis_block_intents(
    block: &SignedBlock,
    genesis_account: &iroha_data_model::account::AccountId,
) -> Result<(), InvalidGenesisError> {
    authenticate_genesis_block_intents(block, genesis_account)?;
    block
        .validate_proposal_commitments()
        .map_err(|_| InvalidGenesisError::ProposalCommitmentMismatch)
}

/// Validate the structural correctness of a genesis block before submitting it to the pipeline.
///
/// # Errors
///
/// Returns [`InvalidGenesisError`] when the block violates any of the required genesis invariants,
/// such as signature mismatch, invalid authorities, or malformed transactions.
#[allow(clippy::too_many_lines)]
pub fn check_genesis_block(
    block: &SignedBlock,
    genesis_account: &iroha_data_model::account::AccountId,
) -> Result<(), InvalidGenesisError> {
    authenticate_genesis_block_intents(block, genesis_account)?;
    check_genesis_execution_results(block)
}
/// Authenticate the immutable genesis intent before any bootstrap instruction executes.
///
/// Consensus proposals deliberately omit deterministic execution results. The configured
/// genesis key must therefore authenticate the height-one header and its ordered transaction
/// intents independently of whether those results have already been attached.
#[derive(Debug)]
pub(crate) struct AuthenticatedGenesisOutputSource {
    header: BlockHeader,
    account: AccountId,
}

impl AuthenticatedGenesisOutputSource {
    /// Recheck the exact immutable source authenticated against the configured genesis key.
    pub(crate) fn account_for(&self, block: &SignedBlock) -> Result<&AccountId, String> {
        block.validate_proposal_commitments()?;
        if block.header() != self.header {
            return Err("genesis execution capability belongs to another proposal".into());
        }
        Ok(&self.account)
    }

    /// Bind bootstrap admission to one original input of the authenticated proposal.
    pub(crate) fn transaction_for(
        &self,
        block: &SignedBlock,
        index: usize,
    ) -> Result<AuthenticatedGenesisTransaction, String> {
        self.account_for(block)?;
        let input = block
            .network_entrypoint_at(index)
            .ok_or("authenticated genesis transaction is absent")?;
        let TransactionEntrypoint::External(transaction) = input else {
            return Err("authenticated genesis transaction is not external".into());
        };
        if transaction.authority() != &self.account {
            return Err("authenticated genesis transaction has another authority".into());
        }
        transaction.verify_signature().map_err(|error| {
            format!("authenticated genesis transaction signature changed: {error}")
        })?;
        Ok(AuthenticatedGenesisTransaction {
            header: self.header,
            entrypoint_hash: input.hash(),
            signed_hash: HashOf::new(transaction),
            index: u64::try_from(index).map_err(|_| "genesis input index exceeds u64")?,
        })
    }
}

/// Admission authority for one signed input of the configured, authenticated genesis.
///
/// A height-one header or component overlay cannot construct this capability. It only
/// exempts the exact bootstrap input from runtime fraud-assessment metadata, which
/// canonical genesis transactions cannot carry.
pub(crate) struct AuthenticatedGenesisTransaction {
    header: BlockHeader,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
    signed_hash: HashOf<SignedTransaction>,
    index: u64,
}

impl AuthenticatedGenesisTransaction {
    /// Recheck the original source and empty committed history at stateful admission.
    pub(crate) fn validate(
        &self,
        transaction: &SignedTransaction,
        state: &crate::state::StateTransaction<'_, '_>,
    ) -> Result<(), String> {
        if state._curr_block != self.header
            || !state.block_hashes.is_empty()
            || transaction.hash_as_entrypoint() != self.entrypoint_hash
            || HashOf::new(transaction) != self.signed_hash
            || state.current_network_entrypoint_hash != Some(self.entrypoint_hash)
            || state.current_entrypoint_index != Some(self.index)
        {
            return Err(
                "genesis admission does not belong to this original bootstrap input".into(),
            );
        }
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn authenticate_genesis_block_intents(
    block: &SignedBlock,
    genesis_account: &iroha_data_model::account::AccountId,
) -> Result<AuthenticatedGenesisOutputSource, InvalidGenesisError> {
    const MAX_GENESIS_TRANSACTIONS: usize = 16;
    let signatures = block.signatures().collect::<Vec<_>>();
    let [signature] = signatures.as_slice() else {
        return Err(InvalidGenesisError::InvalidSignature);
    };
    if signature.index() != 0 {
        return Err(InvalidGenesisError::InvalidSignature);
    }
    let genesis_signatory = genesis_account
        .try_signatory()
        .ok_or(InvalidGenesisError::GenesisAuthorityNotSingleKey)?;
    signature
        .signature()
        .verify_hash(genesis_signatory, block.hash())
        .map_err(|_| InvalidGenesisError::InvalidSignature)?;
    if block.header().height().get() != 1 || block.header().prev_block_hash().is_some() {
        return Err(InvalidGenesisError::InvalidHeader);
    }
    let transactions: Vec<_> = block.external_transactions().collect();
    let external_entrypoints: Vec<_> = block.external_entrypoints_cloned().collect();
    if transactions.is_empty() || transactions.len() > MAX_GENESIS_TRANSACTIONS {
        return Err(InvalidGenesisError::BadTransactionsAmount);
    }
    if external_entrypoints.len() != transactions.len()
        || external_entrypoints.iter().any(|entrypoint| {
            !matches!(
                entrypoint,
                iroha_data_model::transaction::TransactionEntrypoint::External(_)
            )
        })
    {
        return Err(InvalidGenesisError::BadTransactionsAmount);
    }
    let expected_merkle_root = block
        .external_entrypoints_cloned()
        .map(|entrypoint| entrypoint.hash())
        .collect::<MerkleTree<_>>()
        .root();
    if block.header().merkle_root() != expected_merkle_root {
        return Err(InvalidGenesisError::MerkleRootMismatch);
    }
    match (
        block.header().da_proof_policies_hash(),
        block.da_proof_policies(),
    ) {
        (Some(hash), Some(bundle))
            if hash == HashOf::new(bundle)
                && crate::da::validate_committed_proof_policy_bundle(bundle).is_ok() => {}
        _ => return Err(InvalidGenesisError::DaProofPolicyMismatch),
    }
    match (block.header().da_commitments_hash(), block.da_commitments()) {
        (None, None) => {}
        (Some(hash), Some(bundle)) => {
            if bundle.merkle_commitment() != Some(hash) {
                return Err(InvalidGenesisError::DaCommitmentMismatch);
            }
        }
        _ => return Err(InvalidGenesisError::DaCommitmentMismatch),
    }
    match (block.header().da_pin_intents_hash(), block.da_pin_intents()) {
        (None, None) => {}
        (Some(hash), Some(bundle)) => {
            let expected = bundle.merkle_commitment();
            if expected != Some(hash) {
                return Err(InvalidGenesisError::DaPinIntentMismatch);
            }
        }
        _ => return Err(InvalidGenesisError::DaPinIntentMismatch),
    }
    for transaction in transactions {
        if transaction.domain() != &iroha_data_model::transaction::TransactionDomain::Genesis {
            return Err(InvalidGenesisError::TransactionDomainMismatch);
        }
        if transaction.authority() != genesis_account {
            return Err(InvalidGenesisError::UnexpectedAuthority);
        }
        transaction
            .verify_signature()
            .map_err(|_| InvalidGenesisError::InvalidTransactionSignature)?;
        let iroha_data_model::transaction::Executable::Instructions(_isi) =
            transaction.instructions()
        else {
            return Err(InvalidGenesisError::NotInstructions);
        };
    }
    Ok(AuthenticatedGenesisOutputSource {
        header: block.header(),
        account: genesis_account.clone(),
    })
}
fn check_genesis_execution_results(block: &SignedBlock) -> Result<(), InvalidGenesisError> {
    use iroha_data_model::block::execution_output::ExecutionOutputV1;

    if !block.has_results() {
        return Err(InvalidGenesisError::MissingResults);
    }
    block
        .validate_proposal_commitments()
        .map_err(|_| InvalidGenesisError::ProposalCommitmentMismatch)?;
    let input_count = block.network_entrypoint_count();
    let outputs = block.execution_outputs();
    let network_count = outputs
        .iter()
        .filter(|output| matches!(output, ExecutionOutputV1::Network(_)))
        .count();
    if network_count != input_count {
        return Err(InvalidGenesisError::NetworkOutputCountMismatch {
            expected: input_count,
            actual: network_count,
        });
    }
    // Internal invocations have their own output positions. The complete shape
    // validator checks each Network.input_index, phase and invocation owner.
    block
        .validate_execution_result_structure()
        .map_err(|_| InvalidGenesisError::OutputStructureMismatch)?;
    block
        .validate_output_merkle_cache()
        .map_err(|_| InvalidGenesisError::OutputMerkleCacheMismatch)?;
    if let Some(rejection) = GenesisOutputRejection::first(outputs) {
        return Err(InvalidGenesisError::RejectedOutput(rejection));
    }
    // Every successful root invocation applies at least one fragment; retained
    // protocol fragments can make the actual count larger than the output count.
    let minimum_committed_fragment_count = u64::try_from(outputs.len())
        .map_err(|_| InvalidGenesisError::GenesisOutputCountOverflow)?;
    let actual_committed_fragment_count = block.committed_fragment_count();
    if !matches!(
        actual_committed_fragment_count,
        Some(actual) if actual >= minimum_committed_fragment_count
    ) {
        return Err(
            InvalidGenesisError::CommittedFragmentCountBelowOutputCount {
                minimum: minimum_committed_fragment_count,
                actual: actual_committed_fragment_count,
            },
        );
    }
    Ok(())
}
/// Canonical millisecond time strictly after every timed execution input.
/// Admission controls are not execution inputs and do not advance this clock.
pub(crate) fn creation_time_after_inputs<I, T>(minimum: Duration, inputs: I) -> Option<Duration>
where
    I: IntoIterator<Item = T>,
    T: core::borrow::Borrow<TransactionEntrypoint>,
{
    let mut milliseconds = u64::try_from(minimum.as_millis()).ok()?;
    for input in inputs {
        if let Some(created) = input.borrow().creation_time_ms() {
            milliseconds = milliseconds.max(created.checked_add(1)?);
        }
    }
    Some(Duration::from_millis(milliseconds))
}

#[cfg(test)]
mod input_clock_tests {
    use super::*;
    use iroha_data_model::transaction::{
        TransactionBuilder,
        signed::{
            SealedTransactionCommitmentPayload, SealedTransactionReveal,
            SignedSealedTransactionCommitment, compute_sealed_transaction_commitment,
        },
    };

    fn timed_input(milliseconds: u64) -> (SignedTransaction, KeyPair) {
        let key = KeyPair::from_seed(vec![0x91; 32], iroha_crypto::Algorithm::Ed25519);
        let mut builder = TransactionBuilder::new(
            crate::unit_test_support::synthetic_network_id("input-clock"),
            AccountId::new(key.public_key().clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(milliseconds));
        (
            builder
                .with_instructions(Vec::<InstructionBox>::new())
                .sign(key.private_key()),
            key,
        )
    }

    #[test]
    fn input_clock_covers_external_and_sealed_inputs_without_timing_commitments() {
        let (transaction, key) = timed_input(10_000);
        let network_id = *transaction.network_id().unwrap();
        let commitment =
            compute_sealed_transaction_commitment(&network_id, &transaction, [0x92; 32], 100);
        let external = TransactionEntrypoint::External(transaction.clone());
        let reveal = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            commitment,
            transaction.clone(),
            [0x92; 32],
        ));
        let sealed =
            TransactionEntrypoint::SealedCommitment(SignedSealedTransactionCommitment::sign(
                SealedTransactionCommitmentPayload {
                    network_id,
                    authority: transaction.authority().clone(),
                    commitment,
                    reveal_after_height: 1,
                    reveal_deadline_height: 100,
                    nonce: None,
                },
                key.private_key(),
            ));
        for input in [&external, &reveal] {
            assert_eq!(
                creation_time_after_inputs(Duration::from_millis(1), [input]),
                Some(Duration::from_millis(10_001))
            );
        }
        assert_eq!(
            creation_time_after_inputs(Duration::from_millis(1), [&sealed]),
            Some(Duration::from_millis(1))
        );
        assert_eq!(
            creation_time_after_inputs(
                Duration::from_millis(20_000),
                [&external, &reveal, &sealed]
            ),
            Some(Duration::from_millis(20_000))
        );
    }

    #[test]
    fn input_clock_rejects_unrepresentable_input_successor_and_baseline() {
        let (transaction, _) = timed_input(u64::MAX);
        assert!(
            creation_time_after_inputs(
                Duration::ZERO,
                [&TransactionEntrypoint::External(transaction)]
            )
            .is_none()
        );
        assert!(
            creation_time_after_inputs(
                Duration::from_millis(u64::MAX) + Duration::from_millis(1),
                std::iter::empty::<&TransactionEntrypoint>()
            )
            .is_none()
        );
        assert_eq!(
            creation_time_after_inputs(
                Duration::from_millis(u64::MAX),
                std::iter::empty::<&TransactionEntrypoint>(),
            ),
            Some(Duration::from_millis(u64::MAX))
        );
    }
}

/// Builder for blocks
#[derive(Debug, Clone)]
pub struct BlockBuilder<B>(B);
#[cfg(any(test, feature = "iroha-core-tests"))]
fn default_test_execution_context(
    transactions: &[AcceptedTransaction<'static>],
) -> BlockExecutionContextBundle {
    BlockExecutionContextBundle::new(
        transactions
            .iter()
            .map(|transaction| {
                ExternalExecutionContext::new(
                    transaction.hash_as_entrypoint(),
                    LaneId::SINGLE,
                    DataSpaceId::UNIVERSAL,
                )
            })
            .collect(),
    )
}

mod pending {
    use super::*;
    use iroha_primitives::time::TimeSource;
    use nonzero_ext::nonzero;
    /// First stage in the life-cycle of a [`Block`].
    /// In the beginning the block is assumed to be verified and to contain only accepted transactions.
    /// Additionally the block must retain events emitted during the execution of on-chain logic during
    /// the previous round, which might then be processed by the trigger system.
    #[derive(Debug, Clone)]
    pub struct Pending {
        /// Collection of transactions which have been accepted.
        transactions: Vec<AcceptedTransaction<'static>>,
        time_source: TimeSource,
    }
    impl BlockBuilder<Pending> {
        const TIME_PADDING: Duration = Duration::from_millis(1);
        /// Create [`Self`] while preserving the caller's transaction order.
        #[inline]
        pub fn new(transactions: Vec<AcceptedTransaction<'static>>) -> Self {
            Self::new_with_time_source(transactions, TimeSource::new_system())
        }
        /// Create with a provided [`TimeSource`] while preserving transaction order.
        pub fn new_with_time_source(
            transactions: Vec<AcceptedTransaction<'static>>,
            time_source: TimeSource,
        ) -> Self {
            // Empty blocks can be built for tests, but validation rejects them unless they carry
            // entrypoints (external transactions or time triggers) or deterministic artifacts
            // such as DA bundles; consensus should not emit them.
            Self(Pending {
                transactions,
                time_source,
            })
        }
        fn make_header(
            &self,
            prev_block: Option<&SignedBlock>,
            view_change_index: u64,
        ) -> BlockHeader {
            let prev_block_time =
                prev_block.map_or(Duration::ZERO, |block| block.header().creation_time());
            let latest_txn_time = self
                .0
                .transactions
                .iter()
                .map(crate::tx::AcceptedTransaction::creation_time)
                .max()
                // No transactions present; validation still rejects empty payloads.
                .unwrap_or(Duration::ZERO);
            let now = self.0.time_source.get_unix_time();
            // NOTE: Lower time bound must always be upheld for a valid block
            // If the clock has drifted too far this block will be rejected
            let creation_time = [
                now,
                latest_txn_time.saturating_add(Self::TIME_PADDING),
                prev_block_time.saturating_add(Self::TIME_PADDING),
            ]
            .into_iter()
            .max()
            .unwrap();
            let height = prev_block.map(|block| block.header().height()).map_or_else(
                || nonzero!(1_u64),
                |height| {
                    height
                        .checked_add(1)
                        .expect("INTERNAL BUG: Blockchain height exceeds usize::MAX")
                },
            );
            let prev_block_hash = prev_block.map(SignedBlock::hash);
            let merkle_root = self
                .0
                .transactions
                .iter()
                .map(crate::tx::AcceptedTransaction::hash_as_entrypoint)
                .collect::<MerkleTree<_>>()
                .root();
            let creation_time_ms = creation_time.as_millis().try_into().unwrap_or(u64::MAX);
            BlockHeader::new(
                height,
                prev_block_hash,
                merkle_root,
                creation_time_ms,
                view_change_index,
            )
        }
        /// Chain the block with existing blockchain.
        ///
        /// Upon executing this method current timestamp is stored in the block header.
        pub fn chain(
            self,
            view_change_index: u64,
            latest_block: Option<&SignedBlock>,
        ) -> BlockBuilder<Chained> {
            let mut header = self.make_header(latest_block, view_change_index);
            if header.confidential_features().is_none() {
                header.set_confidential_features(Some(EMPTY_CONFIDENTIAL_FEATURE_DIGEST));
            }
            BlockBuilder(Chained {
                header,
                transactions: self.0.transactions,
                da_commitments: None,
                da_proof_policies: None,
                da_pin_intents: None,
                npos_consensus_effects: None,
                global_beacon_pulse: None,
                execution_context: None,
            })
        }
        /// Chain the block to a known parent hash when the parent body is unavailable.
        pub fn chain_with_parent_hash(
            self,
            view_change_index: u64,
            parent_height: u64,
            parent_hash: HashOf<BlockHeader>,
        ) -> BlockBuilder<Chained> {
            let mut header = self.make_header(None, view_change_index);
            header.set_height(
                core::num::NonZeroU64::new(parent_height.saturating_add(1))
                    .expect("parent height plus one is non-zero"),
            );
            header.set_prev_block_hash(Some(parent_hash));
            if header.confidential_features().is_none() {
                header.set_confidential_features(Some(EMPTY_CONFIDENTIAL_FEATURE_DIGEST));
            }
            BlockBuilder(Chained {
                header,
                transactions: self.0.transactions,
                da_commitments: None,
                da_proof_policies: None,
                da_pin_intents: None,
                npos_consensus_effects: None,
                global_beacon_pulse: None,
                execution_context: None,
            })
        }
    }
}
mod chained {
    use super::*;
    use iroha_crypto::SignatureOf;
    use new::NewBlock;
    /// When a `Pending` block is chained with the blockchain it becomes [`Chained`] block.
    #[derive(Debug, Clone)]
    pub struct Chained {
        pub(super) header: BlockHeader,
        pub(super) transactions: Vec<AcceptedTransaction<'static>>,
        pub(super) da_commitments: Option<DaCommitmentBundle>,
        pub(super) da_proof_policies: Option<DaProofPolicyBundle>,
        pub(super) da_pin_intents: Option<DaPinIntentBundle>,
        pub(super) npos_consensus_effects: Option<NposConsensusEffects>,
        pub(super) global_beacon_pulse:
            Option<iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1>,
        pub(super) execution_context: Option<BlockExecutionContextBundle>,
    }
    impl BlockBuilder<Chained> {
        /// Creation time that will be embedded in the block header.
        #[inline]
        #[must_use]
        pub fn creation_time(&self) -> Duration {
            self.0.header.creation_time()
        }
        /// Derive the clock from the exact retained transaction inputs.
        pub(crate) fn with_network_input_time_floor(mut self, minimum: Duration) -> Option<Self> {
            let inputs = self
                .0
                .transactions
                .iter()
                .map(AcceptedTransaction::entrypoint);
            let time = creation_time_after_inputs(minimum, inputs)?;
            self.0.header.creation_time_ms = u64::try_from(time.as_millis()).ok()?;
            Some(self)
        }
        /// Attach a DA commitment bundle and update the header hash accordingly.
        #[must_use]
        pub fn with_da_commitments(mut self, commitments: Option<DaCommitmentBundle>) -> Self {
            let hash = commitments
                .as_ref()
                .and_then(DaCommitmentBundle::merkle_commitment);
            self.0.header.set_da_commitments_hash(hash);
            self.0.da_commitments = commitments;
            self
        }
        /// Attach a DA proof policy bundle and update the header hash accordingly.
        #[must_use]
        pub fn with_da_proof_policies(mut self, policies: Option<DaProofPolicyBundle>) -> Self {
            let hash = policies.as_ref().map(HashOf::new);
            self.0.header.set_da_proof_policies_hash(hash);
            self.0.da_proof_policies = policies;
            self
        }
        /// Attach a DA pin intent bundle and update the header hash accordingly.
        #[must_use]
        pub fn with_da_pin_intents(mut self, intents: Option<DaPinIntentBundle>) -> Self {
            let hash = intents
                .as_ref()
                .and_then(DaPinIntentBundle::merkle_commitment);
            self.0.header.set_da_pin_intents_hash(hash);
            self.0.da_pin_intents = intents;
            self
        }
        /// Attach deterministic `NPoS` effects and update the header hash accordingly.
        #[must_use]
        pub fn with_npos_consensus_effects(
            mut self,
            effects: Option<NposConsensusEffects>,
        ) -> Self {
            let effects = effects.filter(|bundle| !bundle.is_empty());
            let hash = effects.as_ref().map(HashOf::new);
            self.0.header.set_npos_effects_hash(hash);
            self.0.npos_consensus_effects = effects;
            self
        }
        /// Attach the current threshold pulse; it never substitutes transaction work.
        #[must_use]
        pub fn with_global_beacon_pulse(
            mut self,
            pulse: Option<iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1>,
        ) -> Self {
            self.0
                .header
                .set_global_beacon_pulse_hash(pulse.as_ref().map(HashOf::new));
            self.0.global_beacon_pulse = pulse;
            self
        }
        /// Attach durable execution context and update the header hash accordingly.
        #[must_use]
        pub fn with_execution_context(
            mut self,
            context: Option<BlockExecutionContextBundle>,
        ) -> Self {
            let context = context.filter(|bundle| !bundle.is_empty());
            let hash = context.as_ref().map(HashOf::new);
            self.0.header.set_execution_context_hash(hash);
            self.0.execution_context = context;
            self
        }
        /// Attach the confidential feature digest that this block commits to.
        #[must_use]
        pub fn with_confidential_features(
            mut self,
            digest: Option<ConfidentialFeatureDigest>,
        ) -> Self {
            self.0.header.set_confidential_features(digest);
            self
        }
        fn into_new_block(self, signature: BlockSignature) -> NewBlock {
            NewBlock {
                signature,
                header: self.0.header,
                transactions: self.0.transactions,
                da_commitments: self.0.da_commitments,
                da_proof_policies: self.0.da_proof_policies,
                da_pin_intents: self.0.da_pin_intents,
                npos_consensus_effects: self.0.npos_consensus_effects,
                global_beacon_pulse: self.0.global_beacon_pulse,
                execution_context: self.0.execution_context,
            }
        }
        /// Fallibly sign this block and get [`NewBlock`] using the provided validator index.
        ///
        /// # Errors
        ///
        /// Returns [`iroha_crypto::Error::Signing`] when the signing backend
        /// rejects the private key or block-header payload.
        pub fn try_sign_with_index(
            self,
            private_key: &PrivateKey,
            signatory_idx: u64,
        ) -> Result<WithEvents<NewBlock>, iroha_crypto::Error> {
            let mut builder = self;
            if builder.0.da_proof_policies.is_none()
                && builder.0.header.da_proof_policies_hash().is_none()
            {
                let default_policies = crate::da::proof_policy_bundle(
                    &iroha_config::parameters::actual::LaneConfig::default(),
                );
                builder = builder.with_da_proof_policies(Some(default_policies));
            }
            #[cfg(any(test, feature = "iroha-core-tests"))]
            if builder.0.execution_context.is_none() && !builder.0.transactions.is_empty() {
                let context = default_test_execution_context(&builder.0.transactions);
                builder = builder.with_execution_context(Some(context));
            }
            let signature = BlockSignature::new(
                signatory_idx,
                SignatureOf::try_from_hash(private_key, builder.0.header.hash())?,
            );
            Ok(WithEvents::new(builder.into_new_block(signature)))
        }
        /// Finish this block without a block signature (`specs/sumeragi.md` §3.2): the
        /// canonical resultless proposal a Sumeragi leader proposes, which its certified core
        /// header authenticates without depending on a local signing key.
        #[must_use]
        pub fn into_unsigned_proposal(self) -> SignedBlock {
            let mut builder = self;
            if builder.0.da_proof_policies.is_none()
                && builder.0.header.da_proof_policies_hash().is_none()
            {
                let default_policies = crate::da::proof_policy_bundle(
                    &iroha_config::parameters::actual::LaneConfig::default(),
                );
                builder = builder.with_da_proof_policies(Some(default_policies));
            }
            let Chained {
                header,
                transactions,
                da_commitments,
                da_proof_policies,
                da_pin_intents,
                npos_consensus_effects,
                global_beacon_pulse,
                execution_context,
            } = builder.0;
            SignedBlock::unsigned_with_payload(BlockPayload {
                header,
                external_entrypoints: transactions
                    .into_iter()
                    .map(AcceptedTransaction::into_entrypoint)
                    .collect(),
                execution_context,
                da_commitments,
                da_proof_policies,
                da_pin_intents,
                npos_consensus_effects,
                global_beacon_pulse,
            })
        }
        /// Sign this block and get [`NewBlock`] using the provided validator index.
        pub fn sign_with_index(
            self,
            private_key: &PrivateKey,
            signatory_idx: u64,
        ) -> WithEvents<NewBlock> {
            self.try_sign_with_index(private_key, signatory_idx)
                .expect("block signing should succeed for a valid private key and header hash")
        }
        /// Fallibly sign this block and get [`NewBlock`] using validator index 0.
        ///
        /// # Errors
        ///
        /// Returns [`iroha_crypto::Error::Signing`] when the signing backend
        /// rejects the private key or block-header payload.
        pub fn try_sign(
            self,
            private_key: &PrivateKey,
        ) -> Result<WithEvents<NewBlock>, iroha_crypto::Error> {
            self.try_sign_with_index(private_key, 0)
        }
        /// Sign this block and get [`NewBlock`] using validator index 0.
        pub fn sign(self, private_key: &PrivateKey) -> WithEvents<NewBlock> {
            self.try_sign(private_key)
                .expect("block signing should succeed for a valid private key and header hash")
        }
    }
}
mod new {
    use super::*;
    #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
    use crate::state::StateBlock;
    /// First stage in the life-cycle of a block.
    ///
    /// Transactions in this block are not categorized.
    #[derive(Debug, Clone)]
    pub struct NewBlock {
        pub(super) signature: BlockSignature,
        pub(super) header: BlockHeader,
        pub(super) transactions: Vec<AcceptedTransaction<'static>>,
        pub(super) da_commitments: Option<DaCommitmentBundle>,
        pub(super) da_proof_policies: Option<DaProofPolicyBundle>,
        pub(super) da_pin_intents: Option<DaPinIntentBundle>,
        pub(super) npos_consensus_effects: Option<NposConsensusEffects>,
        pub(super) global_beacon_pulse:
            Option<iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1>,
        pub(super) execution_context: Option<BlockExecutionContextBundle>,
    }
    impl NewBlock {
        /// Transition to [`ValidBlock`]. Skips static checks and only applies state changes.
        #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
        pub fn validate_and_record_transactions(
            self,
            state_block: &mut StateBlock<'_>,
            recorder: crate::exec_witness::ExecWitnessGuard,
        ) -> WithEvents<ValidBlock> {
            // Future pipeline overlap: the scheduler can pre-validate on a snapshot pinned at
            // height N-1 while proposing block N. For now we keep the simple path to preserve
            // deterministic behaviour; see specs/new_pipeline.md for the staged rollout.
            ValidBlock::validate_unchecked(self.into(), state_block, recorder)
        }
        /// Block signature
        pub fn signature(&self) -> &BlockSignature {
            &self.signature
        }
        /// Block header
        pub fn header(&self) -> BlockHeader {
            self.header
        }
        /// Block transactions
        pub fn transactions(&self) -> &[AcceptedTransaction<'_>] {
            &self.transactions
        }
        /// DA commitments embedded in this block, if any.
        pub fn da_commitments(&self) -> Option<&DaCommitmentBundle> {
            self.da_commitments.as_ref()
        }
        /// DA proof policies embedded in this block, if any.
        pub fn da_proof_policies(&self) -> Option<&DaProofPolicyBundle> {
            self.da_proof_policies.as_ref()
        }
        /// DA pin intents embedded in this block, if any.
        pub fn da_pin_intents(&self) -> Option<&DaPinIntentBundle> {
            self.da_pin_intents.as_ref()
        }
        /// `NPoS` consensus effects embedded in this block, if any.
        pub fn npos_consensus_effects(&self) -> Option<&NposConsensusEffects> {
            self.npos_consensus_effects.as_ref()
        }
    }
    impl From<NewBlock> for SignedBlock {
        fn from(block: NewBlock) -> Self {
            let mut external_entrypoints = Vec::with_capacity(block.transactions.len());
            for accepted in block.transactions {
                external_entrypoints.push(accepted.into_entrypoint());
            }
            SignedBlock::presigned_with_payload(
                block.signature,
                BlockPayload {
                    header: block.header,
                    external_entrypoints,
                    execution_context: block.execution_context,
                    da_commitments: block.da_commitments,
                    da_proof_policies: block.da_proof_policies,
                    da_pin_intents: block.da_pin_intents,
                    npos_consensus_effects: block.npos_consensus_effects,
                    global_beacon_pulse: block.global_beacon_pulse,
                },
            )
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{block::BlockBuilder, tx::AcceptedTransaction};
        use iroha_data_model::{isi::Log, transaction::TransactionBuilder};
        use iroha_logger::Level;
        use iroha_primitives::time::TimeSource;
        use iroha_test_samples::gen_account_in;
        use std::{borrow::Cow, time::Duration};
        #[test]
        fn into_signed_block_preserves_external_transactions_without_legacy_cache() {
            let network_id = deterministic_test_network_id(0x01);
            let (authority, keypair) = gen_account_in("wonderland");
            let tx1 = TransactionBuilder::new(
                network_id,
                authority.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "first".to_owned())])
            .sign(keypair.private_key());
            let tx2 = TransactionBuilder::new(
                network_id,
                authority,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "second".to_owned())])
            .sign(keypair.private_key());
            let mut submitted = vec![tx1, tx2];
            submitted.sort_by_key(|tx| core::cmp::Reverse(tx.hash_as_entrypoint()));
            assert!(submitted[0].hash_as_entrypoint() > submitted[1].hash_as_entrypoint());
            let expected = submitted.clone();
            let accepted = submitted
                .into_iter()
                .map(|tx| AcceptedTransaction::new_unchecked(Cow::Owned(tx)))
                .collect();
            let (_handle, time_source) = TimeSource::new_mock(Duration::from_secs(1));
            let builder = BlockBuilder::new_with_time_source(accepted, time_source);
            let block_signer = crate::block::checked_keypair();
            let new_block = builder
                .chain(0, None)
                .sign(block_signer.private_key())
                .unpack(|_| {});
            let signed_block: SignedBlock = new_block.into();
            assert_eq!(
                signed_block.external_transactions().collect::<Vec<_>>(),
                expected.iter().collect::<Vec<_>>(),
                "block construction must not replace FIFO order with grindable hash priority"
            );
        }
        #[test]
        fn block_builder_sign_with_index_sets_signature_index() {
            let (authority, keypair) = gen_account_in("wonderland");
            let tx = TransactionBuilder::new(
                deterministic_test_network_id(0x02),
                authority,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "signed".to_owned())])
            .sign(keypair.private_key());
            let accepted = vec![AcceptedTransaction::new_unchecked(Cow::Owned(tx))];
            let builder = BlockBuilder::new(accepted);
            let signer = crate::block::checked_keypair();
            let signatory_idx = 7_u64;
            let new_block = builder
                .chain(0, None)
                .sign_with_index(signer.private_key(), signatory_idx)
                .unpack(|_| {});
            assert_eq!(new_block.signature().index(), signatory_idx);
        }
        #[test]
        fn block_builder_try_sign_with_index_sets_verifiable_signature() {
            let (authority, keypair) = gen_account_in("wonderland");
            let tx = TransactionBuilder::new(
                deterministic_test_network_id(0x03),
                authority,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "try-signed".to_owned())])
            .sign(keypair.private_key());
            let accepted = vec![AcceptedTransaction::new_unchecked(Cow::Owned(tx))];
            let builder = BlockBuilder::new(accepted);
            let signer = crate::block::checked_keypair();
            let signatory_idx = 11_u64;
            let new_block = builder
                .chain(0, None)
                .try_sign_with_index(signer.private_key(), signatory_idx)
                .expect("fallible block signing succeeds")
                .unpack(|_| {});
            assert_eq!(new_block.signature().index(), signatory_idx);
            new_block
                .signature()
                .signature()
                .verify_hash(signer.public_key(), new_block.header().hash())
                .expect("fallibly signed block signature verifies");
        }
    }
}
pub(crate) mod valid {
    #[cfg(test)]
    #[path = "admission_batching.rs"]
    mod admission_batching_tests;
    #[cfg(test)]
    use super::event::{map_block_err_to_reason, map_sig_err_to_reason};
    use super::{event::emit_block_rejection, *};
    use crate::state::{StateBlock, storage_transactions::TransactionsReadOnly};
    use crate::sumeragi::network_topology::Role;
    use commit::CommittedBlock;
    use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};
    use iroha_data_model::events::pipeline::PipelineEventBox;
    use iroha_data_model::nexus::AxtPolicySnapshot;
    #[cfg(test)]
    use iroha_model_base::chain::ChainId;
    use iroha_primitives::time::TimeSource;
    use std::{num::NonZeroUsize, time::Instant};
    /// Block that was validated and accepted.
    #[derive(Debug, Clone)]
    pub struct ValidBlock {
        block: SignedBlock,
        signatures_verified: bool,
    }
    /// Timing breakdown for block validation stages.
    #[derive(Debug, Clone, Copy, Default)]
    #[allow(clippy::struct_field_names)]
    pub struct ValidationTimings {
        /// Elapsed milliseconds for stateless checks.
        pub(crate) stateless_ms: u64,
        /// Elapsed milliseconds spent in state-dependent stateless checks.
        pub(crate) stateless_state_dependent_ms: u64,
        /// Elapsed milliseconds spent in snapshot-based stateless checks.
        pub(crate) stateless_snapshot_ms: u64,
        /// Elapsed milliseconds for execution/stateful checks.
        pub(crate) execution_ms: u64,
        /// Elapsed milliseconds spent ensuring DA indexes are hydrated.
        pub(crate) execution_da_indexes_ms: u64,
        /// Elapsed milliseconds spent creating the state block.
        pub(crate) execution_state_block_ms: u64,
        /// Elapsed milliseconds spent executing transactions.
        pub(crate) execution_tx_ms: u64,
        /// Elapsed milliseconds spent applying overlays and finalizing results.
        pub(crate) execution_tx_apply_ms: u64,
        /// Elapsed milliseconds spent in the sequential apply path (when parallel apply is off).
        pub(crate) execution_tx_apply_sequential_ms: u64,
        /// Elapsed milliseconds spent validating AXT envelopes.
        pub(crate) execution_axt_ms: u64,
        /// Elapsed milliseconds spent validating DA shard cursors.
        pub(crate) execution_da_cursor_ms: u64,
        /// Elapsed milliseconds spent checking genesis transaction invariants.
        pub(crate) execution_genesis_clean_ms: u64,
        /// Total elapsed milliseconds for validation.
        pub(crate) total_ms: u64,
    }
    type Error = (Box<SignedBlock>, Box<BlockValidationError>);
    #[cfg(feature = "telemetry")]
    type MetricsRef<'a> = Option<&'a crate::telemetry::StateTelemetry>;
    #[cfg(not(feature = "telemetry"))]
    type MetricsRef<'a> = ();
    #[derive(Debug)]
    struct StaticValidationData {
        expected_block_height: usize,
        max_clock_drift: Duration,
        tx_params: iroha_data_model::parameter::TransactionParameters,
        crypto_cfg: Arc<iroha_config::parameters::actual::Crypto>,
        pipeline_cfg: iroha_config::parameters::actual::Pipeline,
        pipeline_parallelism: crate::state::PipelineParallelism,
        aggregate_lane: LaneId,
    }
    #[derive(Debug, PartialEq, Eq)]
    enum ConsensusValidationProfile {
        /// A block ordered by the Sumeragi core (`specs/sumeragi.md` §4): the certified
        /// core header binds the nonempty payload, so block signatures are not checked;
        /// block time is canonical from the parent and
        /// the cadence; nothing depends on a separate height context.
        Sumeragi {
            block_cadence: Duration,
            consensus_mode: iroha_data_model::parameter::system::ConsensusMode,
            root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
            supplied_pulse:
                Option<iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1>,
            /// The block's lane step input (`specs/sumeragi_lanes.md` §4.3).
            lanes: crate::sumeragi::lanes::merge::LaneStepInput,
            expected_pulse_context:
                iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1,
            source_generation: u64,
        },
        /// The sole signed genesis path; installs the native consensus schedule and lane step.
        SumeragiGenesis {
            consensus_mode: iroha_data_model::parameter::system::ConsensusMode,
            root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
        },
    }
    impl ConsensusValidationProfile {
        /// The genesis height when the block advances the Sumeragi schedule
        /// (`specs/sumeragi.md` §10).
        const fn sumeragi_schedule(&self) -> Option<u64> {
            match self {
                Self::Sumeragi { .. } | Self::SumeragiGenesis { .. } => {
                    Some(crate::sumeragi::startup::GENESIS_HEIGHT)
                }
            }
        }
        /// Lane lifecycle input committed by this global block.
        fn take_sumeragi_lanes(&mut self) -> Option<crate::sumeragi::lanes::merge::LaneStepInput> {
            match self {
                Self::Sumeragi { lanes, .. } => Some(std::mem::take(lanes)),
                Self::SumeragiGenesis { .. } => {
                    Some(crate::sumeragi::lanes::merge::LaneStepInput::default())
                }
            }
        }
        /// The exact transported native control witness, never a local aggregator lookup.
        const fn sumeragi_pulse(
            &self,
        ) -> Option<iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1> {
            match self {
                Self::Sumeragi { supplied_pulse, .. } => *supplied_pulse,
                _ => None,
            }
        }
        /// The authenticated native header source, absent only for signed genesis.
        const fn sumeragi_pulse_context(
            &self,
        ) -> Option<iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1> {
            match self {
                Self::Sumeragi {
                    expected_pulse_context,
                    ..
                } => Some(*expected_pulse_context),
                _ => None,
            }
        }
        const fn source_generation(&self) -> Option<u64> {
            match self {
                Self::Sumeragi {
                    source_generation, ..
                } => Some(*source_generation),
                _ => None,
            }
        }

        const fn enforce_local_wall_clock(&self) -> bool {
            matches!(self, Self::SumeragiGenesis { .. })
        }
        const fn block_cadence(&self) -> Option<Duration> {
            match self {
                Self::Sumeragi { block_cadence, .. } => Some(*block_cadence),
                _ => None,
            }
        }

        fn sccp_height_source(
            &self,
        ) -> crate::smartcontracts::isi::sccp::height::SccpHeightSourceV1 {
            use crate::smartcontracts::isi::sccp::height::SccpHeightSourceV1;
            self.sumeragi_schedule()
                .map_or(SccpHeightSourceV1::Unauthenticated, |genesis_height| {
                    SccpHeightSourceV1::SumeragiSchedule {
                        genesis_height,
                        mode: self.authoritative_consensus_mode(),
                        root_scope: match self {
                            Self::Sumeragi { root_scope, .. }
                            | Self::SumeragiGenesis { root_scope, .. } => *root_scope,
                        },
                    }
                })
        }

        const fn authoritative_consensus_mode(
            &self,
        ) -> iroha_data_model::parameter::system::ConsensusMode {
            match self {
                Self::Sumeragi { consensus_mode, .. }
                | Self::SumeragiGenesis { consensus_mode, .. } => *consensus_mode,
            }
        }
    }
    #[cfg(all(test, feature = "app_api"))]
    std::thread_local! {
        static AXT_FASTPQ_PROOF_VERIFICATION_COUNT: std::cell::Cell<usize> =
            const { std::cell::Cell::new(0) };
    }
    #[cfg(all(test, feature = "app_api"))]
    pub(super) fn reset_axt_fastpq_proof_verification_count() {
        AXT_FASTPQ_PROOF_VERIFICATION_COUNT.with(|count| count.set(0));
    }
    #[cfg(all(test, feature = "app_api"))]
    pub(super) fn axt_fastpq_proof_verification_count() -> usize {
        AXT_FASTPQ_PROOF_VERIFICATION_COUNT.with(std::cell::Cell::get)
    }
    pub(super) fn map_axt_fastpq_error(
        error: fastpq_prover::Error,
        context: &str,
        snapshot_version: u64,
        dataspace: DataSpaceId,
        lane: LaneId,
    ) -> BlockValidationError {
        if matches!(
            error,
            fastpq_prover::Error::LocalAllocationUnavailable { .. }
        ) {
            return BlockValidationError::ExecutionDeferred(
                ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
            );
        }
        BlockValidationError::AxtEnvelopeValidationFailed(AxtEnvelopeValidationDetails {
            message: format!("{context}: {error}"),
            reason: AxtRejectReason::Proof,
            snapshot_version: Some(snapshot_version),
            dataspace: Some(dataspace),
            lane: Some(lane),
            active_handle_era: None,
            next_handle_counter: None,
        })
    }
    #[allow(clippy::too_many_lines)]
    pub fn validate_axt_envelopes<'block>(
        block: &'block SignedBlock,
        state_block: &StateBlock<'_>,
    ) -> Result<(), BlockValidationError> {
        let advertised_snapshot = block.axt_policy_snapshot().cloned().ok_or_else(|| {
            BlockValidationError::AxtEnvelopeValidationFailed(AxtEnvelopeValidationDetails {
                message: "block result is missing its required AXT policy snapshot".to_owned(),
                reason: AxtRejectReason::MissingPolicy,
                snapshot_version: None,
                dataspace: None,
                lane: None,
                active_handle_era: None,
                next_handle_counter: None,
            })
        })?;
        let advertised_transitioned_dataspaces =
            block.axt_transitioned_dataspaces().ok_or_else(|| {
                BlockValidationError::AxtEnvelopeValidationFailed(AxtEnvelopeValidationDetails {
                    message: "block result is missing its required AXT transition set".to_owned(),
                    reason: AxtRejectReason::PolicyDenied,
                    snapshot_version: Some(advertised_snapshot.version),
                    dataspace: None,
                    lane: None,
                    active_handle_era: None,
                    next_handle_counter: None,
                })
            })?;
        let snapshot_version = advertised_snapshot.version;
        let make_axt_error_with =
            |reason: AxtRejectReason,
             message: &str,
             dataspace: Option<DataSpaceId>,
             lane: Option<LaneId>,
             active_handle_era: Option<u64>,
             next_handle_counter: Option<u64>| {
                BlockValidationError::AxtEnvelopeValidationFailed(AxtEnvelopeValidationDetails {
                    message: message.to_owned(),
                    reason,
                    snapshot_version: Some(snapshot_version),
                    dataspace,
                    lane,
                    active_handle_era,
                    next_handle_counter,
                })
            };
        advertised_snapshot.validate().map_err(|error| {
            make_axt_error_with(
                AxtRejectReason::PolicyDenied,
                &format!("invalid AXT policy snapshot: {error}"),
                None,
                None,
                None,
                None,
            )
        })?;
        let block_start = state_block.axt_block_start_snapshot();
        let snapshot = block_start.policy_snapshot();
        snapshot.validate().map_err(|error| {
            make_axt_error_with(
                AxtRejectReason::PolicyDenied,
                &format!("invalid block-start AXT policy snapshot: {error}"),
                None,
                None,
                None,
                None,
            )
        })?;
        let axt_timing = state_block.nexus.axt;
        let policies: BTreeMap<_, _> = snapshot
            .entries
            .iter()
            .map(|binding| (binding.dsid, binding.policy))
            .collect();
        let advertised_policies: BTreeMap<_, _> = advertised_snapshot
            .entries
            .iter()
            .map(|binding| (binding.dsid, binding.policy))
            .collect();
        let next_sub_nonces: BTreeMap<DataSpaceId, u64> = policies
            .iter()
            .map(|(dsid, policy)| (*dsid, policy.next_handle_counter))
            .collect();
        if let Some(envelopes) = block.axt_envelopes() {
            struct VerifiedProof<'block> {
                proof: &'block ProofBlob,
                dsid: DataSpaceId,
                facts: ivm::axt::AxtProofUseFacts,
            }
            type VerifiedProofBuckets = BTreeMap<(Option<u64>, Hash), Vec<usize>>;

            if let Some(envelope) = envelopes
                .iter()
                .find(|envelope| !envelope.spends.is_empty())
            {
                return Err(make_axt_error_with(
                    AxtRejectReason::Proof,
                    crate::fastpq::AXT_UNANCHORED_REMOTE_SPEND_REJECTION,
                    Some(envelope.spends[0].draft.intent.asset_dsid),
                    Some(envelope.lane),
                    None,
                    None,
                ));
            }
            let validate_proof_expiry = |proof: &ProofBlob,
                                         dsid: DataSpaceId,
                                         policy: &AxtPolicyEntry,
                                         policy_slot: u64,
                                         min_expiry_slot: Option<u64>|
             -> Result<(), BlockValidationError> {
                if let Some(expiry_slot) = proof.expiry_slot {
                    if expiry_slot == 0 {
                        return Err(make_axt_error_with(
                            AxtRejectReason::Proof,
                            "proof expiry slot is zero",
                            Some(dsid),
                            Some(policy.target_lane),
                            None,
                            None,
                        ));
                    }
                    let expiry_deadline = ivm::axt::expiry_slot_with_skew(
                        expiry_slot,
                        axt_timing.slot_length_ms,
                        axt_timing.max_clock_skew_ms,
                        None,
                    );
                    if policy_slot > 0 && policy_slot > expiry_deadline {
                        return Err(make_axt_error_with(
                            AxtRejectReason::Expiry,
                            "proof expired relative to policy slot",
                            Some(dsid),
                            Some(policy.target_lane),
                            None,
                            None,
                        ));
                    }
                    if let Some(min_expiry) = min_expiry_slot {
                        if min_expiry > expiry_slot {
                            return Err(make_axt_error_with(
                                AxtRejectReason::Expiry,
                                "proof expires before handle",
                                Some(dsid),
                                Some(policy.target_lane),
                                None,
                                None,
                            ));
                        }
                    }
                }
                Ok(())
            };
            // Digest buckets make repeated exact-value lookups independent of the
            // number and size of unrelated proofs. The full-value equality check
            // inside a matching bucket keeps hash collisions fail-safe, while
            // references avoid copying proof payloads owned by the block.
            let mut verified_proofs = Vec::<VerifiedProof<'block>>::new();
            let mut verified_proof_buckets = VerifiedProofBuckets::new();
            let validate_proof = |verified_proofs: &mut Vec<VerifiedProof<'block>>,
                                  verified_proof_buckets: &mut VerifiedProofBuckets,
                                  proof: &'block ProofBlob,
                                  dsid: DataSpaceId,
                                  policy: &AxtPolicyEntry,
                                  policy_slot: u64,
                                  min_expiry_slot: Option<u64>|
             -> Result<usize, BlockValidationError> {
                if crate::fastpq::axt_proof_payload_exceeds_decode_limit(&proof.payload) {
                    return Err(make_axt_error_with(
                        AxtRejectReason::Proof,
                        &format!(
                            "proof payload exceeds the {}-byte decode limit",
                            fastpq_prover::MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES,
                        ),
                        Some(dsid),
                        Some(policy.target_lane),
                        None,
                        None,
                    ));
                }
                let cache_key = (proof.expiry_slot, Hash::new(&proof.payload));
                let cached_index = verified_proof_buckets.get(&cache_key).and_then(|bucket| {
                    bucket
                        .iter()
                        .copied()
                        .find(|index| verified_proofs[*index].proof == proof)
                });
                if let Some(index) = cached_index {
                    if verified_proofs[index].dsid != dsid {
                        return Err(make_axt_error_with(
                            AxtRejectReason::Manifest,
                            "one exact FASTPQ proof cannot be relabelled for another dataspace",
                            Some(dsid),
                            Some(policy.target_lane),
                            None,
                            None,
                        ));
                    }
                    validate_proof_expiry(proof, dsid, policy, policy_slot, min_expiry_slot)?;
                    return Ok(index);
                }
                if proof.payload.is_empty() {
                    return Err(make_axt_error_with(
                        AxtRejectReason::Proof,
                        "empty proof payload",
                        Some(dsid),
                        Some(policy.target_lane),
                        None,
                        None,
                    ));
                }
                if policy.manifest_root.iter().all(|byte| *byte == 0) {
                    return Err(make_axt_error_with(
                        AxtRejectReason::Manifest,
                        "policy manifest root is zeroed",
                        Some(dsid),
                        Some(policy.target_lane),
                        None,
                        None,
                    ));
                }
                let envelope =
                    ivm::codec::decode_canonical_norito::<AxtProofEnvelope>(&proof.payload)
                        .map_err(|err| {
                            make_axt_error_with(
                                AxtRejectReason::Proof,
                                &format!("proof payload is not an AXT proof envelope: {err}"),
                                Some(dsid),
                                Some(policy.target_lane),
                                None,
                                None,
                            )
                        })?;
                if envelope.dsid != dsid || envelope.manifest_root != policy.manifest_root {
                    return Err(make_axt_error_with(
                        AxtRejectReason::Manifest,
                        "proof does not match policy manifest root",
                        Some(dsid),
                        Some(policy.target_lane),
                        None,
                        None,
                    ));
                }
                let binding = envelope.fastpq_binding.as_ref().ok_or_else(|| {
                    make_axt_error_with(
                        AxtRejectReason::Proof,
                        "FASTPQ proof envelope is missing fastpq_binding",
                        Some(dsid),
                        Some(policy.target_lane),
                        None,
                        None,
                    )
                })?;
                fastpq_prover::validate_axt_transfer_claim_binding(binding).map_err(|err| {
                    map_axt_fastpq_error(
                        err,
                        "generic AXT proof admission requires a witnessed transfer claim",
                        snapshot_version,
                        dsid,
                        policy.target_lane,
                    )
                })?;
                validate_proof_expiry(proof, dsid, policy, policy_slot, min_expiry_slot)?;
                #[cfg(all(test, feature = "app_api"))]
                AXT_FASTPQ_PROOF_VERIFICATION_COUNT
                    .with(|count| count.set(count.get().saturating_add(1)));
                fastpq_prover::verify_axt_proof_envelope_with_outer_metadata(
                    &envelope,
                    proof.expiry_slot,
                )
                .map_err(|err| {
                    map_axt_fastpq_error(
                        err,
                        "FASTPQ verification failed",
                        snapshot_version,
                        dsid,
                        policy.target_lane,
                    )
                })?;
                let index = verified_proofs.len();
                verified_proofs.push(VerifiedProof {
                    proof,
                    dsid,
                    facts: ivm::axt::AxtProofUseFacts::from_verified_envelope(envelope),
                });
                verified_proof_buckets
                    .entry(cache_key)
                    .or_default()
                    .push(index);
                Ok(index)
            };
            let make_env_error =
                |lane: LaneId,
                 reason: AxtRejectReason,
                 message: &str,
                 dsid: Option<DataSpaceId>,
                 active_handle_era: Option<u64>,
                 next_handle_counter: Option<u64>| {
                    make_axt_error_with(
                        reason,
                        message,
                        dsid,
                        Some(lane),
                        active_handle_era,
                        next_handle_counter,
                    )
                };
            for envelope in envelopes {
                let envelope_lane = envelope.lane;
                let expected_commit_height = block.header().height().get();
                if envelope.commit_height != expected_commit_height {
                    return Err(make_env_error(
                        envelope_lane,
                        AxtRejectReason::Descriptor,
                        &format!(
                            "envelope commit height {} does not match block height {expected_commit_height}",
                            envelope.commit_height
                        ),
                        None,
                        None,
                        None,
                    ));
                }
                if let Err(err) = iroha_data_model::nexus::validate_descriptor(&envelope.descriptor)
                {
                    return Err(make_env_error(
                        envelope_lane,
                        AxtRejectReason::Descriptor,
                        &format!("invalid descriptor: {err}"),
                        None,
                        None,
                        None,
                    ));
                }
                let expected_binding = envelope.descriptor.binding().map_err(|err| {
                    make_env_error(
                        envelope_lane,
                        AxtRejectReason::Descriptor,
                        &format!("failed to compute descriptor binding: {err}"),
                        None,
                        None,
                        None,
                    )
                })?;
                if expected_binding != envelope.binding {
                    return Err(make_env_error(
                        envelope_lane,
                        AxtRejectReason::Descriptor,
                        "descriptor binding does not match envelope binding",
                        None,
                        None,
                        None,
                    ));
                }
                let expected_dsids: BTreeSet<_> =
                    envelope.descriptor.dsids.iter().copied().collect();
                let mut touch_specs: BTreeMap<DataSpaceId, &iroha_data_model::nexus::AxtTouchSpec> =
                    BTreeMap::new();
                for spec in &envelope.descriptor.touches {
                    touch_specs.insert(spec.dsid, spec);
                }
                if envelope
                    .touches
                    .windows(2)
                    .any(|pair| pair[0].dsid >= pair[1].dsid)
                {
                    return Err(make_env_error(
                        envelope_lane,
                        AxtRejectReason::Descriptor,
                        "touch fragments are not strictly ordered by dataspace",
                        None,
                        None,
                        None,
                    ));
                }
                let mut touch_dsids: BTreeSet<DataSpaceId> = BTreeSet::new();
                for touch in &envelope.touches {
                    if ivm::axt::validate_model_touch_manifest(&touch.manifest).is_err() {
                        return Err(make_env_error(
                            envelope_lane,
                            AxtRejectReason::Descriptor,
                            "touch manifest paths are not canonical",
                            Some(touch.dsid),
                            None,
                            None,
                        ));
                    }
                    if !expected_dsids.contains(&touch.dsid) {
                        return Err(make_env_error(
                            envelope_lane,
                            AxtRejectReason::Descriptor,
                            "touch references undeclared dataspace",
                            Some(touch.dsid),
                            None,
                            None,
                        ));
                    }
                    if !touch_dsids.insert(touch.dsid) {
                        return Err(make_env_error(
                            envelope_lane,
                            AxtRejectReason::Descriptor,
                            "duplicate touch manifest for dataspace",
                            Some(touch.dsid),
                            None,
                            None,
                        ));
                    }
                    if let Some(spec) = touch_specs.get(&touch.dsid) {
                        if (!spec.read.is_empty() || !spec.write.is_empty())
                            && touch.manifest.read.is_empty()
                            && touch.manifest.write.is_empty()
                        {
                            return Err(make_env_error(
                                envelope_lane,
                                AxtRejectReason::Descriptor,
                                "missing touch manifest for dataspace",
                                Some(touch.dsid),
                                None,
                                None,
                            ));
                        }
                        if !touch
                            .manifest
                            .read
                            .iter()
                            .all(|entry| spec.read.iter().any(|prefix| entry.starts_with(prefix)))
                        {
                            return Err(make_env_error(
                                envelope_lane,
                                AxtRejectReason::Descriptor,
                                "touch manifest read entry outside descriptor",
                                Some(touch.dsid),
                                None,
                                None,
                            ));
                        }
                        if !touch
                            .manifest
                            .write
                            .iter()
                            .all(|entry| spec.write.iter().any(|prefix| entry.starts_with(prefix)))
                        {
                            return Err(make_env_error(
                                envelope_lane,
                                AxtRejectReason::Descriptor,
                                "touch manifest write entry outside descriptor",
                                Some(touch.dsid),
                                None,
                                None,
                            ));
                        }
                    } else if !touch.manifest.read.is_empty() || !touch.manifest.write.is_empty() {
                        return Err(make_env_error(
                            envelope_lane,
                            AxtRejectReason::Descriptor,
                            "touch manifest provided without descriptor spec",
                            Some(touch.dsid),
                            None,
                            None,
                        ));
                    }
                }
                for spec in &envelope.descriptor.touches {
                    if (!spec.read.is_empty() || !spec.write.is_empty())
                        && !touch_dsids.contains(&spec.dsid)
                    {
                        return Err(make_env_error(
                            envelope_lane,
                            AxtRejectReason::Descriptor,
                            "missing touch manifest for dataspace",
                            Some(spec.dsid),
                            None,
                            None,
                        ));
                    }
                }
                let mut proofs_by_ds: BTreeMap<DataSpaceId, (&ProofBlob, usize)> = BTreeMap::new();
                if envelope
                    .proofs
                    .windows(2)
                    .any(|pair| pair[0].dsid >= pair[1].dsid)
                {
                    return Err(make_env_error(
                        envelope_lane,
                        AxtRejectReason::Proof,
                        "proof fragments are not strictly ordered by dataspace",
                        None,
                        None,
                        None,
                    ));
                }
                for proof in &envelope.proofs {
                    if !expected_dsids.contains(&proof.dsid) {
                        return Err(make_axt_error_with(
                            AxtRejectReason::Descriptor,
                            "proof references undeclared dataspace",
                            Some(proof.dsid),
                            Some(envelope_lane),
                            None,
                            None,
                        ));
                    }
                    let policy = policies.get(&proof.dsid).ok_or_else(|| {
                        make_axt_error_with(
                            AxtRejectReason::MissingPolicy,
                            "no policy for dataspace",
                            Some(proof.dsid),
                            Some(envelope_lane),
                            None,
                            None,
                        )
                    })?;
                    let proof_index = validate_proof(
                        &mut verified_proofs,
                        &mut verified_proof_buckets,
                        &proof.proof,
                        proof.dsid,
                        policy,
                        policy.current_slot,
                        None,
                    )?;
                    if proofs_by_ds
                        .insert(proof.dsid, (&proof.proof, proof_index))
                        .is_some()
                    {
                        return Err(make_axt_error_with(
                            AxtRejectReason::Proof,
                            "duplicate proof for dataspace",
                            Some(proof.dsid),
                            Some(envelope_lane),
                            None,
                            None,
                        ));
                    }
                }
                // No signed spend may consume a claim until finalized source
                // execution can be authenticated by State.
                let consumed_by_proof = proofs_by_ds
                    .iter()
                    .map(|(dsid, (_, proof_index))| (*proof_index, (*dsid, Vec::new())))
                    .collect::<BTreeMap<usize, (DataSpaceId, Vec<[u8; 32]>)>>();
                let dataspace_proofs_present: BTreeSet<DataSpaceId> =
                    proofs_by_ds.keys().copied().collect();
                for dsid in &expected_dsids {
                    if !dataspace_proofs_present.contains(dsid) {
                        return Err(make_env_error(
                            envelope_lane,
                            AxtRejectReason::Proof,
                            "proof missing for dataspace",
                            Some(*dsid),
                            None,
                            None,
                        ));
                    }
                }
                for (proof_index, (dsid, consumed)) in consumed_by_proof {
                    verified_proofs[proof_index]
                        .facts
                        .validate_remote_spend_consumption(&consumed)
                        .map_err(|_| {
                            make_env_error(
                                envelope_lane,
                                AxtRejectReason::Proof,
                                "FASTPQ remote-spend claims were not consumed exactly once",
                                Some(dsid),
                                None,
                                None,
                            )
                        })?;
                }
            }
            // Proofs with remote-spend commitments cannot be consumed while
            // anchored source execution admission is unavailable.
            for verified in &verified_proofs {
                verified
                    .facts
                    .validate_remote_spend_consumption(&[])
                    .map_err(|_| {
                        make_axt_error_with(
                            AxtRejectReason::Proof,
                            "FASTPQ remote-spend claims require anchored admission",
                            Some(verified.dsid),
                            None,
                            None,
                            None,
                        )
                    })?;
            }
        }
        let ratchet_dataspaces: BTreeSet<_> = advertised_policies
            .keys()
            .chain(policies.keys())
            .chain(advertised_transitioned_dataspaces.iter())
            .copied()
            .collect();
        for dsid in ratchet_dataspaces {
            let advertised_policy = advertised_policies.get(&dsid);
            let previous_policy = policies.get(&dsid);
            let counter_before_block = state_block.axt_handle_counter_at_block_start(dsid);
            let reconstructed_next = next_sub_nonces
                .get(&dsid)
                .copied()
                .or_else(|| {
                    counter_before_block.map(iroha_data_model::nexus::AxtHandleCounterRecord::next)
                })
                .unwrap_or(0);
            let candidate_policy = state_block.world.axt_policies.get(&dsid);
            let error_lane = advertised_policy
                .or(candidate_policy)
                .or(previous_policy)
                .map(|policy| policy.target_lane);
            let minimum_generation = crate::state::axt_policy_generation_minimum(
                &state_block.world,
                dsid,
                candidate_policy,
            );
            let base_generation = counter_before_block
                .map(iroha_data_model::nexus::AxtHandleCounterRecord::authorization_generation)
                .or_else(|| previous_policy.map(|policy| policy.active_handle_era))
                .unwrap_or(minimum_generation);
            let current_counter = if reconstructed_next == 0 {
                None
            } else {
                Some(
                    iroha_data_model::nexus::AxtHandleCounterRecord::try_from_parts(
                        reconstructed_next,
                        base_generation,
                    )
                    .map_err(|_| {
                        make_axt_error_with(
                            AxtRejectReason::SubNonce,
                            "invalid reconstructed AXT permanent counter",
                            Some(dsid),
                            error_lane,
                            Some(base_generation),
                            Some(reconstructed_next),
                        )
                    })?,
                )
            };
            let authorization_identity_changed = advertised_transitioned_dataspaces.contains(&dsid)
                || block_start.authorization_identity_changed(
                    &state_block.world,
                    &state_block.lane_incarnations,
                    dsid,
                    candidate_policy,
                );
            let reconstructed = crate::state::axt_counter_after_block_boundary(
                previous_policy,
                candidate_policy,
                minimum_generation,
                authorization_identity_changed,
                counter_before_block.copied(),
                current_counter,
            )
            .map_err(|_| {
                make_axt_error_with(
                    AxtRejectReason::SubNonce,
                    "AXT permanent counter is exhausted during policy revocation",
                    Some(dsid),
                    error_lane,
                    Some(base_generation),
                    Some(reconstructed_next),
                )
            })?;
            let expected_next = reconstructed
                .as_ref()
                .map_or(0, iroha_data_model::nexus::AxtHandleCounterRecord::next);
            let expected_generation = reconstructed.as_ref().map_or(
                0,
                iroha_data_model::nexus::AxtHandleCounterRecord::authorization_generation,
            );
            if let Some(advertised_policy) = advertised_policy {
                if expected_next != advertised_policy.next_handle_counter
                    || expected_generation != advertised_policy.active_handle_era
                {
                    return Err(make_axt_error_with(
                        AxtRejectReason::SubNonce,
                        "authenticated AXT execution does not equal the committed permanent authorization-generation ratchet",
                        Some(dsid),
                        Some(advertised_policy.target_lane),
                        Some(expected_generation),
                        Some(expected_next),
                    ));
                }
            }
            match (
                state_block.world.axt_handle_counters.get(&dsid),
                reconstructed.as_ref(),
            ) {
                (Some(final_ratchet), Some(expected))
                    if final_ratchet.next() == expected_next
                        && final_ratchet.authorization_generation() == expected_generation
                        && final_ratchet == expected => {}
                (None, None) => {}
                _ => {
                    return Err(make_axt_error_with(
                        AxtRejectReason::SubNonce,
                        "authenticated AXT execution does not equal the committed authorization-generation ratchet",
                        Some(dsid),
                        error_lane,
                        Some(expected_generation),
                        Some(expected_next),
                    ));
                }
            }
        }
        Ok(())
    }
    /// Counts of signatures attached to a block.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SignatureTally {
        /// Total signatures present on the block (all roles).
        pub present: usize,
        /// Deduplicated signatures from commit-eligible roles (leader, validators, set-B, proxy tail).
        pub counted: usize,
        /// Signatures contributed by set-B validators (role `SetBValidator`).
        pub set_b_signatures: usize,
    }
    /// Build a signature tally for the given block under the provided topology.
    pub fn commit_signature_tally(block: &SignedBlock, topology: &Topology) -> SignatureTally {
        let mut counted = BTreeSet::new();
        let commit_roles: &[Role] = &[
            Role::Leader,
            Role::ProxyTail,
            Role::ValidatingPeer,
            Role::SetBValidator,
        ];
        for signature in topology.filter_signatures_by_roles(commit_roles, block.signatures()) {
            if let Ok(idx) = usize::try_from(signature.index()) {
                counted.insert(idx);
            }
        }
        let set_b_signatures = topology
            .filter_signatures_by_roles(&[Role::SetBValidator], block.signatures())
            .count();
        SignatureTally {
            present: block.signatures().count(),
            counted: counted.len(),
            set_b_signatures,
        }
    }
    /// Original committed cut admitted before the constructor acquires execution writers.
    struct PristineNativeSource<'state> {
        state: &'state State,
        generation: u64,
        header: BlockHeader,
        staking: crate::sumeragi::evidence::PreparedStakingEffects<'state>,
    }
    include!("block/native_header_source.rs");
    include!("block/native_genesis_policy.rs");
    #[cfg(test)]
    #[path = "native_header_source_tests.rs"]
    mod native_header_source_tests;

    include!("block/post_execution_tail.rs");

    impl ValidBlock {
        #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
        fn new_unverified(block: SignedBlock) -> Self {
            Self {
                block,
                signatures_verified: false,
            }
        }
        #[cfg(test)]
        pub(crate) fn new_unverified_for_tests(block: SignedBlock) -> Self {
            Self::new_unverified(block)
        }
        fn new_signatures_verified(block: SignedBlock) -> Self {
            Self {
                block,
                signatures_verified: true,
            }
        }
        #[cfg(test)]
        pub(crate) fn committed_from_replay_signed_block(block: SignedBlock) -> CommittedBlock {
            Self::new_signatures_verified(block)
                .commit_unchecked(crate::block::reserve_block_for_tests())
                .unpack(|_| {})
        }
        #[cfg(test)]
        fn mark_signatures_verified(&mut self) {
            self.signatures_verified = true;
        }
        fn clear_signatures_verified(&mut self) {
            self.signatures_verified = false;
        }
        fn validate_advertised_axt_post_state(
            advertised: Option<&AxtPolicySnapshot>,
            computed: &AxtPolicySnapshot,
        ) -> Result<(), BlockValidationError> {
            let Some(advertised) = advertised else {
                return Ok(());
            };
            if advertised == computed {
                return Ok(());
            }
            Err(BlockValidationError::AxtEnvelopeValidationFailed(
                AxtEnvelopeValidationDetails {
                    message: "advertised AXT post-state policy snapshot does not match deterministic execution"
                        .to_owned(),
                    reason: AxtRejectReason::PolicyDenied,
                    snapshot_version: Some(advertised.version),
                    dataspace: None,
                    lane: None,
                    active_handle_era: None,
                    next_handle_counter: None,
                },
            ))
        }
        fn validate_advertised_axt_transitions(
            advertised: Option<&BTreeSet<DataSpaceId>>,
            computed: &BTreeSet<DataSpaceId>,
            snapshot_version: u64,
        ) -> Result<(), BlockValidationError> {
            let Some(advertised) = advertised else {
                return Ok(());
            };
            if advertised == computed {
                return Ok(());
            }
            Err(BlockValidationError::AxtEnvelopeValidationFailed(
                AxtEnvelopeValidationDetails {
                    message: "advertised AXT transition set does not match deterministic execution"
                        .to_owned(),
                    reason: AxtRejectReason::PolicyDenied,
                    snapshot_version: Some(snapshot_version),
                    dataspace: None,
                    lane: None,
                    active_handle_era: None,
                    next_handle_counter: None,
                },
            ))
        }
        #[cfg(test)]
        fn signatures_verified_for_tests(&self) -> bool {
            self.signatures_verified
        }
        fn verify_unique_signers(block: &SignedBlock) -> Result<(), SignatureVerificationError> {
            let mut seen = BTreeSet::new();
            for signature in block.signatures() {
                let signer = usize::try_from(signature.index())
                    .map_err(|_| SignatureVerificationError::UnknownSignatory)?;
                if !seen.insert(signer) {
                    return Err(SignatureVerificationError::DuplicateSignature { signer });
                }
            }
            Ok(())
        }
        fn is_bls_normal_public_key(public_key: &PublicKey) -> bool {
            crate::crypto_util::is_bls_normal_public_key(public_key)
        }
        fn verify_leader_signature(
            block: &SignedBlock,
            topology: &Topology,
        ) -> Result<(), SignatureVerificationError> {
            use SignatureVerificationError::{LeaderMissing, UnknownSignature};
            // Enforce BLS-normal for leader
            if !Self::is_bls_normal_public_key(topology.leader().public_key()) {
                return Err(LeaderMissing);
            }
            let Some(signature) = topology
                .filter_signatures_by_roles(&[Role::Leader], block.signatures())
                .next()
            else {
                return Err(LeaderMissing);
            };
            signature
                .signature()
                .verify_hash(topology.leader().public_key(), block.hash())
                .map_err(|_err| UnknownSignature)?;
            Ok(())
        }
        fn verify_validator_signatures(
            block: &SignedBlock,
            topology: &Topology,
        ) -> Result<(), SignatureVerificationError> {
            // Enforce BLS-normal for validator roles in Set A + Set B (including proxy tail).
            let valid_roles: &[Role] =
                &[Role::ValidatingPeer, Role::SetBValidator, Role::ProxyTail];
            topology
                .filter_signatures_by_roles(valid_roles, block.signatures())
                .try_for_each(|signature| {
                    use SignatureVerificationError::{UnknownSignatory, UnknownSignature};
                    let signatory =
                        usize::try_from(signature.index()).map_err(|_err| UnknownSignatory)?;
                    let signatory: &PeerId =
                        topology.as_ref().get(signatory).ok_or(UnknownSignatory)?;
                    if !Self::is_bls_normal_public_key(signatory.public_key()) {
                        return Err(UnknownSignature);
                    }
                    signature
                        .signature()
                        .verify_hash(signatory.public_key(), block.hash())
                        .map_err(|_err| UnknownSignature)?;
                    Ok(())
                })?;
            Ok(())
        }
        fn verify_no_undefined_signatures(
            block: &SignedBlock,
            topology: &Topology,
        ) -> Result<(), SignatureVerificationError> {
            if topology
                .filter_signatures_by_roles(&[Role::Undefined], block.signatures())
                .next()
                .is_some()
            {
                return Err(SignatureVerificationError::UnknownSignatory);
            }
            Ok(())
        }
        #[cfg(test)]
        fn verify_signer_set(
            topology: &Topology,
            signers: &BTreeSet<ValidatorIndex>,
            allow_quorum_bypass: bool,
        ) -> Result<(), SignatureVerificationError> {
            let roster_len = topology.as_ref().len();
            if roster_len <= 1 {
                return Ok(());
            }
            let min_votes_for_commit = topology.min_votes_for_commit();
            let mut seen = BTreeSet::new();
            for signer in signers {
                let signer = usize::try_from(*signer)
                    .map_err(|_| SignatureVerificationError::UnknownSignatory)?;
                if signer >= roster_len {
                    return Err(SignatureVerificationError::UnknownSignatory);
                }
                if !seen.insert(signer) {
                    return Err(SignatureVerificationError::DuplicateSignature { signer });
                }
            }
            let votes_count = signers.len();
            if votes_count < min_votes_for_commit && !allow_quorum_bypass {
                return Err(SignatureVerificationError::NotEnoughSignatures {
                    votes_count,
                    min_votes_for_commit,
                });
            }
            Ok(())
        }
        /// Verify every signature present on the block against the provided topology.
        ///
        /// This only checks signatures that exist on the block; it does not require a particular
        /// role to be present and accepts partial signature sets as long as each entry is valid.
        fn verify_signatures_against_topology(
            block: &SignedBlock,
            topology: &Topology,
        ) -> Result<(), SignatureVerificationError> {
            let hash = block.hash();
            for signature in block.signatures() {
                let signatory = usize::try_from(signature.index())
                    .map_err(|_| SignatureVerificationError::UnknownSignatory)?;
                let peer = topology
                    .as_ref()
                    .get(signatory)
                    .ok_or(SignatureVerificationError::UnknownSignatory)?;
                let role = topology.role(peer);
                match role {
                    Role::Leader | Role::ValidatingPeer | Role::ProxyTail | Role::SetBValidator => {
                        if !Self::is_bls_normal_public_key(peer.public_key()) {
                            return Err(SignatureVerificationError::UnknownSignature);
                        }
                        signature
                            .signature()
                            .verify_hash(peer.public_key(), hash)
                            .map_err(|_| SignatureVerificationError::UnknownSignature)?;
                    }
                    Role::Undefined => return Err(SignatureVerificationError::UnknownSignatory),
                }
            }
            Ok(())
        }
        #[cfg(test)]
        fn verify_signatures_against_topology_with_pops(
            block: &SignedBlock,
            topology: &Topology,
            pops: &BTreeMap<PublicKey, Vec<u8>>,
        ) -> Result<(), SignatureVerificationError> {
            let hash = block.hash();
            let mut bls_normal_signatures: Vec<&[u8]> = Vec::new();
            let mut bls_normal_public_keys: Vec<&PublicKey> = Vec::new();
            let mut bls_normal_pops: Vec<&[u8]> = Vec::new();
            for signature in block.signatures() {
                let signatory = usize::try_from(signature.index())
                    .map_err(|_| SignatureVerificationError::UnknownSignatory)?;
                let peer = topology
                    .as_ref()
                    .get(signatory)
                    .ok_or(SignatureVerificationError::UnknownSignatory)?;
                let role = topology.role(peer);
                match role {
                    Role::Leader | Role::ValidatingPeer | Role::ProxyTail | Role::SetBValidator => {
                        if !Self::is_bls_normal_public_key(peer.public_key()) {
                            return Err(SignatureVerificationError::UnknownSignature);
                        }
                        let pop = pops
                            .get(peer.public_key())
                            .ok_or(SignatureVerificationError::MissingPop)?;
                        let signature_payload = signature.signature().payload();
                        iroha_crypto::Signature::try_from_bytes(signature_payload)
                            .map_err(|_| SignatureVerificationError::UnknownSignature)?;
                        bls_normal_signatures.push(signature_payload);
                        bls_normal_public_keys.push(peer.public_key());
                        bls_normal_pops.push(pop.as_slice());
                    }
                    Role::Undefined => return Err(SignatureVerificationError::UnknownSignatory),
                }
            }
            if !bls_normal_signatures.is_empty() {
                iroha_crypto::bls_normal_verify_aggregate_same_message_fast(
                    hash.as_ref(),
                    &bls_normal_signatures,
                    &bls_normal_public_keys,
                    &bls_normal_pops,
                )
                .map_err(|_| SignatureVerificationError::UnknownSignature)?;
            }
            Ok(())
        }
        /// Validate the signature set for the block against the provided topology and key registry.
        ///
        /// Unlike [`Self::is_commit`], this accepts partial signature sets and only enforces that
        /// each present signature is unique, maps to a known validator role, and uses a live
        /// consensus key.
        #[cfg(test)]
        pub(crate) fn validate_signatures_subset_world(
            block: &SignedBlock,
            topology: &Topology,
            world: &impl WorldReadOnly,
        ) -> Result<(), SignatureVerificationError> {
            if block.header().is_genesis() {
                return Ok(());
            }
            Self::validate_signatures_subset_world_exact(block, topology, world)
        }
        /// Verify the exact stored signature indices and payloads, including at genesis.
        ///
        /// Certificate-bound replay uses this after authenticating the canonical block wire;
        /// signer-index recovery would change the certified payload and is therefore forbidden.
        #[cfg(test)]
        pub(crate) fn validate_signatures_subset_world_exact(
            block: &SignedBlock,
            topology: &Topology,
            world: &impl WorldReadOnly,
        ) -> Result<(), SignatureVerificationError> {
            Self::verify_unique_signers(block)?;
            let params = world.parameters();
            let sumeragi = params.sumeragi();
            let height = block.header().height().get();
            if world.consensus_keys().is_empty() {
                Self::verify_signatures_against_topology(block, topology)?;
                return Self::enforce_consensus_key_lifecycle_world(block, topology, world);
            }
            let pops = Self::collect_validator_pops(
                world,
                height,
                sumeragi.key_overlap_grace_blocks,
                sumeragi.key_expiry_grace_blocks,
            )?;
            Self::verify_signatures_against_topology_with_pops(block, topology, &pops)?;
            Self::enforce_consensus_key_lifecycle_world(block, topology, world)
        }

        #[cfg(test)]
        pub(crate) fn validate_signatures_subset(
            block: &SignedBlock,
            topology: &Topology,
            state: &impl StateReadOnly,
        ) -> Result<(), SignatureVerificationError> {
            Self::validate_signatures_subset_world(block, topology, state.world())
        }
        #[cfg(test)]
        fn collect_validator_pops(
            world: &impl WorldReadOnly,
            height: u64,
            overlap_grace_blocks: u64,
            expiry_grace_blocks: u64,
        ) -> Result<BTreeMap<PublicKey, Vec<u8>>, SignatureVerificationError> {
            let mut pops: BTreeMap<PublicKey, Vec<u8>> = BTreeMap::new();
            for (id, record) in world.consensus_keys().iter() {
                if id.role != ConsensusKeyRole::Validator {
                    continue;
                }
                if !record.is_live_at(height, overlap_grace_blocks, expiry_grace_blocks) {
                    continue;
                }
                if Self::is_bls_normal_public_key(&record.public_key) {
                    let Some(pop) = record.pop.as_ref() else {
                        return Err(SignatureVerificationError::MissingPop);
                    };
                    if let Some(existing) = pops.get(&record.public_key) {
                        if existing.as_slice() != pop.as_slice() {
                            return Err(SignatureVerificationError::Other);
                        }
                        continue;
                    }
                    pops.insert(record.public_key.clone(), pop.clone());
                }
            }
            Ok(pops)
        }
        pub(crate) fn enforce_consensus_key_lifecycle_world(
            block: &SignedBlock,
            topology: &Topology,
            world: &impl WorldReadOnly,
        ) -> Result<(), SignatureVerificationError> {
            if block.header().is_genesis() {
                return Ok(());
            }
            // Skip enforcement until consensus keys are explicitly registered. Once any
            // registry entries exist, validators must present a live key for signing.
            if world.consensus_keys().is_empty() {
                return Ok(());
            }
            let params = world.parameters();
            let sumeragi = params.sumeragi();
            let overlap = sumeragi.key_overlap_grace_blocks;
            let expiry_grace = sumeragi.key_expiry_grace_blocks;
            let height = block.header().height().get();
            for signature in topology.filter_signatures_by_roles(
                &[
                    Role::ValidatingPeer,
                    Role::SetBValidator,
                    Role::Leader,
                    Role::ProxyTail,
                ],
                block.signatures(),
            ) {
                let signatory = usize::try_from(signature.index())
                    .map_err(|_| SignatureVerificationError::UnknownSignatory)?;
                let signatory = topology
                    .as_ref()
                    .get(signatory)
                    .ok_or(SignatureVerificationError::UnknownSignatory)?;
                let pk = signatory.public_key();
                let pk_label = pk.to_string();
                let mut found_index_record = false;
                let mut live = world
                    .consensus_keys_by_pk()
                    .get(&pk_label)
                    .is_some_and(|ids| {
                        ids.iter().any(|id| {
                            world.consensus_keys().get(id).is_some_and(|rec| {
                                found_index_record = true;
                                rec.id.role == ConsensusKeyRole::Validator
                                    && rec.is_live_at(height, overlap, expiry_grace)
                            })
                        })
                    });
                if !live && !found_index_record {
                    // Fallback when the pk index is stale or missing for this peer.
                    live = world.consensus_keys().iter().any(|(id, rec)| {
                        id.role == ConsensusKeyRole::Validator
                            && rec.public_key == *pk
                            && rec.is_live_at(height, overlap, expiry_grace)
                    });
                }
                if !live {
                    return Err(SignatureVerificationError::InactiveConsensusKey);
                }
            }
            Ok(())
        }
        pub(crate) fn enforce_consensus_key_lifecycle(
            block: &SignedBlock,
            topology: &Topology,
            state: &impl StateReadOnly,
        ) -> Result<(), SignatureVerificationError> {
            Self::enforce_consensus_key_lifecycle_world(block, topology, state.world())
        }
        fn ensure_genesis_transactions_clean(
            block: &SignedBlock,
            genesis_account: &AccountId,
        ) -> Result<(), BlockValidationError> {
            if block.header().is_genesis() {
                if !block.has_results() {
                    iroha_logger::error!(
                        "Invalid genesis block rejected during validation: execution results missing"
                    );
                    return Err(BlockValidationError::InvalidGenesis(
                        InvalidGenesisError::MissingResults,
                    ));
                }
                if let Err(err) = check_genesis_block(block, genesis_account) {
                    iroha_logger::error!(
                        error = %err,
                        "Invalid genesis block rejected during validation"
                    );
                    return Err(BlockValidationError::InvalidGenesis(err));
                }
            }
            Ok(())
        }

        /// Begin an ordinary component execution before its first block effects.
        ///
        /// The returned original recorder must be consumed by `validate_unchecked`.
        /// This fixture does not authenticate consensus controls or finality.
        ///
        /// # Errors
        /// Refuses unavailable recording or failed block-start effects.
        #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
        pub fn start_component_execution<'state>(
            block: &SignedBlock,
            state: &'state State,
        ) -> Result<
            (
                Box<StateBlock<'state>>,
                crate::exec_witness::ExecWitnessGuard,
            ),
            BlockValidationError,
        > {
            state
                .block_with_recorded_pristine_carrier_stage(
                    block,
                    |_| Ok::<(), BlockValidationError>(()),
                    Self::execution_context_error,
                )
                .map_err(BlockValidationError::from)
        }

        /// Execute the signed genesis through the sole native consensus path without publishing.
        /// The staged state includes the authenticated schedule, the actual global lane step,
        /// and the same complete execution witness used by startup and result certification.
        /// The original state stays boxed across validation and event delivery to bound stack use.
        ///
        /// The mode must come from the canonical signed genesis handshake metadata. It is threaded
        /// explicitly because the pre-execution world cannot yet contain genesis parameters.
        #[allow(clippy::too_many_arguments)]
        pub fn validate_signed_genesis<'state>(
            block: SignedBlock,
            topology: &Topology,
            genesis_account: &AccountId,
            time_source: &TimeSource,
            state: &'state State,
            consensus_mode: iroha_data_model::parameter::system::ConsensusMode,
            root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
        ) -> WithEvents<Result<(ValidBlock, Box<StateBlock<'state>>), Error>> {
            if !block.header().is_genesis() {
                return WithEvents::new(Err((
                    Box::new(block),
                    Box::new(BlockValidationError::InvalidGenesis(
                        InvalidGenesisError::InvalidHeader,
                    )),
                )));
            }
            Self::validate_with_profile(
                block,
                topology,
                genesis_account,
                time_source,
                state,
                false,
                None,
                false,
                ConsensusValidationProfile::SumeragiGenesis {
                    consensus_mode,
                    root_scope,
                },
                false,
                None,
                None,
                None,
            )
        }
        /// Execute the exact original nonempty proposal bound by its native consensus header.
        /// The source is verified before certified lane merges expand its execution inputs.
        /// Transaction validation, deterministic execution and original State generation checks
        /// remain mandatory; the native consensus certificate owns block authentication.
        /// AMX legs and parent services borrow only the original Worker's completed owners.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn validate_sumeragi_block<'state>(
            block: SignedBlock,
            topology: &Topology,
            genesis_account: &AccountId,
            block_cadence: Duration,
            consensus_mode: iroha_data_model::parameter::system::ConsensusMode,
            root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
            expansion: crate::sumeragi::lanes::merge::Expansion<'state>,
            native_header: &iroha_sumeragi::message::BlockHeader,
            native_payload: &[u8],
            state: &'state State,
            amx_legs: Option<&mut crate::sumeragi::amx::NativeAmxLegPreparations>,
            parent_service: Option<&crate::sumeragi::certified_chain::ParentServicePreparation>,
        ) -> WithEvents<Result<(ValidBlock, Box<StateBlock<'state>>), Error>> {
            if let Err(error) = expansion.validate_publication(state) {
                return WithEvents::new(Err((
                    Box::new(block),
                    Box::new(BlockValidationError::from(error)),
                )));
            }
            let source =
                match Self::native_header_source(&block, state, native_header, native_payload) {
                    Ok(source) => source,
                    Err(error) => return WithEvents::new(Err((Box::new(block), Box::new(error)))),
                };
            // Completed AMX legs retain canonical byte custody only. The fresh native
            // source and pristine StateBlock authenticate current authority on every attempt.
            if !block.has_consensus_work() {
                let header = source.header();
                return WithEvents::new(Err((
                    Box::new(block),
                    Box::new(BlockValidationError::EmptyBlock),
                )))
                .with_authenticated_rejection(
                    header,
                    source.state(),
                    source.generation(),
                );
            }
            let (block, lanes) = match expansion.apply(block, source.state(), source.generation()) {
                Ok(expanded) => expanded,
                Err((block, error)) => {
                    return WithEvents::new(Err((
                        Box::new(block),
                        Box::new(BlockValidationError::from(error)),
                    )));
                }
            };
            let (_, time_source) = TimeSource::new_mock(block.header().creation_time());
            let authenticated_header = source.header();
            Self::validate_with_profile(
                block,
                topology,
                genesis_account,
                &time_source,
                state,
                false,
                None,
                true,
                ConsensusValidationProfile::Sumeragi {
                    block_cadence,
                    consensus_mode,
                    root_scope,
                    supplied_pulse: source.pulse,
                    lanes,
                    expected_pulse_context: source.expected_context,
                    source_generation: source.generation,
                },
                true,
                None,
                amx_legs,
                parent_service,
            )
            .with_authenticated_rejection(
                authenticated_header,
                state,
                source.generation,
            )
        }

        fn state_block_for_execution<'state>(
            block: &SignedBlock,
            state: &'state State,
            source: PristineNativeSource<'state>,
            profile: &ConsensusValidationProfile,
        ) -> Result<
            (
                Box<StateBlock<'state>>,
                crate::exec_witness::ExecWitnessGuard,
            ),
            BlockValidationError,
        > {
            crate::exec_witness::ensure_exec_witness_capture_available()
                .map_err(Self::execution_context_error)?;
            Self::validate_sumeragi_consensus_effects(block)?;
            state
                .block_with_recorded_pristine_carrier_stage(
                    block,
                    |overlay| {
                        overlay
                            .validate_native_pristine_control_owner(
                                source.state,
                                source.generation,
                                &source.header,
                            )
                            .map_err(Self::execution_context_error)?;
                        if let Some(genesis_height) = profile.sumeragi_schedule() {
                            overlay
                                .request_sumeragi_schedule(
                                    genesis_height,
                                    block,
                                    profile.sumeragi_pulse(),
                                    profile.sumeragi_pulse_context(),
                                )
                                .map_err(BlockValidationError::from)?;
                        }
                        source
                            .staking
                            .apply(overlay, block, source.state, source.generation)
                            .map_err(|error| {
                                BlockValidationError::from_npos_application_error(
                                    error,
                                    "native pristine staking application",
                                )
                            })?;
                        Ok(())
                    },
                    Self::execution_context_error,
                )
                .map_err(BlockValidationError::from)
        }

        fn validate_staged_execution_controls(
            block: &SignedBlock,
        ) -> Result<(), BlockValidationError> {
            Self::checked_execution_context_header(block)?;

            Ok(())
        }

        #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
        fn validate_with_profile<'state>(
            mut block: SignedBlock,
            topology: &Topology,
            genesis_account: &AccountId,
            time_source: &TimeSource,
            state: &'state State,
            soft_fork: bool,
            timings: Option<&mut ValidationTimings>,
            skip_block_signatures: bool,
            mut validation_profile: ConsensusValidationProfile,
            allow_empty_block: bool,
            mut send_events: Option<&mut dyn FnMut(PipelineEventBox)>,
            amx_legs: Option<&mut crate::sumeragi::amx::NativeAmxLegPreparations>,
            parent_service: Option<&crate::sumeragi::certified_chain::ParentServicePreparation>,
        ) -> WithEvents<Result<(ValidBlock, Box<StateBlock<'state>>), Error>> {
            let total_start = Instant::now();
            let stateless_start = Instant::now();
            let to_ms = |duration: Duration| -> u64 {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            };
            let mut timings = timings;
            let mut emit_rejection = |block: &SignedBlock, error: &BlockValidationError| {
                if let Some(send_events) = send_events.as_deref_mut() {
                    emit_block_rejection(block.header(), error, send_events);
                }
            };
            let record_timings =
                |timings: &mut Option<&mut ValidationTimings>,
                 stateless_elapsed: Duration,
                 execution_start: Option<Instant>| {
                    if let Some(timings) = timings.as_deref_mut() {
                        timings.stateless_ms = to_ms(stateless_elapsed);
                        timings.execution_ms =
                            execution_start.map_or(0, |start| to_ms(start.elapsed()));
                        timings.total_ms = to_ms(total_start.elapsed());
                    }
                };

            let static_state_start = Instant::now();
            let static_data = {
                let view = state.query_view();
                match Self::validate_static_state_dependent(
                    &block,
                    topology,
                    genesis_account,
                    &view,
                    state.pipeline_parallelism(),
                    soft_fork,
                    time_source,
                    skip_block_signatures,
                    &validation_profile,
                ) {
                    Ok(data) => {
                        if let Some(timings) = timings.as_deref_mut() {
                            timings.stateless_state_dependent_ms =
                                to_ms(static_state_start.elapsed());
                        }
                        data
                    }
                    Err(error) => {
                        let stateless_elapsed = stateless_start.elapsed();
                        if let Some(timings) = timings.as_deref_mut() {
                            timings.stateless_state_dependent_ms =
                                to_ms(static_state_start.elapsed());
                        }
                        record_timings(&mut timings, stateless_elapsed, None);
                        emit_rejection(&block, &error);
                        return WithEvents::new(Err((Box::new(block), Box::new(error))));
                    }
                }
            };
            let prepared_txs = Self::prepare_external_transactions(&block);
            let (committed_heights, committed_carrier_heights) = {
                let transactions_view = state.transactions.view();
                (
                    Self::committed_heights_for_prepared_transactions(
                        &prepared_txs,
                        &transactions_view,
                    ),
                    Self::committed_heights_for_entrypoint_carriers(&block, &transactions_view),
                )
            };
            let cache_cap = static_data.pipeline_cfg.stateless_cache_cap;
            let cache_enabled = cache_cap > 0 && !block.header().is_genesis();
            let max_clock_drift_ms = static_data.max_clock_drift.as_millis();
            let cache_context = if cache_enabled {
                Some(StatelessValidationContext::new(
                    *state.network_id_ref(),
                    u64::try_from(max_clock_drift_ms).unwrap_or(u64::MAX),
                    static_data.tx_params,
                    static_data.crypto_cfg.allowed_signing.clone(),
                ))
            } else {
                None
            };
            #[cfg(feature = "telemetry")]
            let metrics = Some(&state.telemetry);
            #[cfg(not(feature = "telemetry"))]
            let metrics = ();
            let static_snapshot_start = Instant::now();
            if let Err(error) = Self::validate_static_with_snapshot(
                &block,
                state.network_id_ref(),
                genesis_account,
                &static_data,
                &committed_heights,
                &committed_carrier_heights,
                &prepared_txs,
                metrics,
            ) {
                let stateless_elapsed = stateless_start.elapsed();
                if let Some(timings) = timings.as_deref_mut() {
                    timings.stateless_snapshot_ms = to_ms(static_snapshot_start.elapsed());
                }
                record_timings(&mut timings, stateless_elapsed, None);
                emit_rejection(&block, &error);
                return WithEvents::new(Err((Box::new(block), Box::new(error))));
            }
            let consensus_effects =
                Self::validate_sumeragi_consensus_effects(&block).and_then(|()| {
                    let generation = validation_profile
                        .source_generation()
                        .unwrap_or_else(|| state.state_view_generation());
                    let staking = crate::sumeragi::evidence::prepare(state, &block, generation)?;
                    Ok(PristineNativeSource {
                        state,
                        generation,
                        header: block.header(),
                        staking,
                    })
                });
            let penalty_index = match consensus_effects {
                Ok(index) => index,
                Err(error) => {
                    let stateless_elapsed = stateless_start.elapsed();
                    record_timings(&mut timings, stateless_elapsed, None);
                    emit_rejection(&block, &error);
                    return WithEvents::new(Err((Box::new(block), Box::new(error))));
                }
            };
            if let Some(context) = cache_context {
                let mut cache = state.stateless_validation_cache().lock();
                cache.set_cap(cache_cap);
                cache.ensure_context(context);
                for (tx, prepared) in Self::collect_external_signed_transactions(&block)
                    .into_iter()
                    .zip(prepared_txs.iter())
                {
                    let expires_at_ms = tx
                        .time_to_live()
                        .and_then(|ttl| tx.creation_time().checked_add(ttl))
                        .map(|expires_at| expires_at.as_millis());
                    let not_before_ms = tx
                        .creation_time()
                        .as_millis()
                        .saturating_sub(max_clock_drift_ms);
                    cache.insert_ok(
                        prepared.metadata.stateless_cache_key,
                        expires_at_ms,
                        not_before_ms,
                    );
                }
            }
            if let Some(timings) = timings.as_deref_mut() {
                timings.stateless_snapshot_ms = to_ms(static_snapshot_start.elapsed());
            }
            let stateless_elapsed = stateless_start.elapsed();
            let execution_start = Instant::now();
            // Release block writer before creating new one
            let da_indexes_start = Instant::now();
            if let Err(error) = state.ensure_da_indexes_hydrated() {
                if let Some(timings) = timings.as_deref_mut() {
                    timings.execution_da_indexes_ms = to_ms(da_indexes_start.elapsed());
                }
                record_timings(&mut timings, stateless_elapsed, Some(execution_start));
                let error = BlockValidationError::from(error);
                emit_rejection(&block, &error);
                return WithEvents::new(Err((Box::new(block), Box::new(error))));
            }
            if let Some(timings) = timings.as_deref_mut() {
                timings.execution_da_indexes_ms = to_ms(da_indexes_start.elapsed());
            }
            let state_block_start = Instant::now();
            let (mut state_block, exec_witness_guard) = match Self::state_block_for_execution(
                &block,
                state,
                penalty_index,
                &validation_profile,
            ) {
                Ok((mut overlay, guard)) => {
                    if let Some(lanes) = validation_profile.take_sumeragi_lanes() {
                        overlay.request_sumeragi_lanes(lanes);
                    }
                    (overlay, guard)
                }
                Err(error) => {
                    record_timings(&mut timings, stateless_elapsed, Some(execution_start));
                    emit_rejection(&block, &error);
                    return WithEvents::new(Err((Box::new(block), Box::new(error))));
                }
            };
            if let Some(timings) = timings.as_deref_mut() {
                timings.execution_state_block_ms = to_ms(state_block_start.elapsed());
            }
            // `validate_static_with_snapshot` above verified (batched and in parallel)
            // the signature of every Network input of this exact block and rejects
            // the block on any failure, so its execution need not verify them again.
            if !block.header().is_genesis() {
                state_block.mark_network_signatures_prechecked();
            }
            if let Err(error) = Self::validate_staged_execution_controls(&block) {
                drop(state_block);
                record_timings(&mut timings, stateless_elapsed, Some(execution_start));
                emit_rejection(&block, &error);
                return WithEvents::new(Err((Box::new(block), Box::new(error))));
            }
            let tx_start = Instant::now();
            let genesis = if block.header().is_genesis() {
                match authenticate_genesis_block_intents(&block, genesis_account) {
                    Ok(genesis) => Some(genesis),
                    Err(error) => {
                        let error = BlockValidationError::from(error);
                        drop(state_block);
                        record_timings(&mut timings, stateless_elapsed, Some(execution_start));
                        emit_rejection(&block, &error);
                        return WithEvents::new(Err((Box::new(block), Box::new(error))));
                    }
                }
            } else {
                None
            };
            if let Err(error) = Self::execute_and_record_canonical_outputs_in_context(
                &mut block,
                &mut state_block,
                timings.as_deref_mut(),
                genesis.as_ref(),
                validation_profile.sccp_height_source(),
                amx_legs,
                parent_service,
            ) {
                drop(state_block);
                record_timings(&mut timings, stateless_elapsed, Some(execution_start));
                emit_rejection(&block, &error);
                return WithEvents::new(Err((Box::new(block), Box::new(error))));
            }
            if let Some(timings) = timings.as_deref_mut() {
                timings.execution_tx_ms = to_ms(tx_start.elapsed());
            }
            let axt_start = Instant::now();
            if let Err(error) = validate_axt_envelopes(&block, &state_block) {
                drop(state_block);
                if let Some(timings) = timings.as_deref_mut() {
                    timings.execution_axt_ms = to_ms(axt_start.elapsed());
                }
                record_timings(&mut timings, stateless_elapsed, Some(execution_start));
                emit_rejection(&block, &error);
                return WithEvents::new(Err((Box::new(block), Box::new(error))));
            }
            if let Some(timings) = timings.as_deref_mut() {
                timings.execution_axt_ms = to_ms(axt_start.elapsed());
            }
            let da_cursor_start = Instant::now();
            if let Err(error) = state_block.validate_da_shard_cursors(&block) {
                drop(state_block);
                if let Some(timings) = timings.as_deref_mut() {
                    timings.execution_da_cursor_ms = to_ms(da_cursor_start.elapsed());
                }
                record_timings(&mut timings, stateless_elapsed, Some(execution_start));
                emit_rejection(&block, &error);
                return WithEvents::new(Err((Box::new(block), Box::new(error))));
            }
            if let Some(timings) = timings.as_deref_mut() {
                timings.execution_da_cursor_ms = to_ms(da_cursor_start.elapsed());
            }
            if let Err(error) = state_block
                .capture_exec_witness_attempt()
                .map_err(Self::execution_capture_attempt_error)
            {
                drop(state_block);
                record_timings(&mut timings, stateless_elapsed, Some(execution_start));
                emit_rejection(&block, &error);
                return WithEvents::new(Err((Box::new(block), Box::new(error))));
            }
            drop(exec_witness_guard);
            if block.is_empty() && !allow_empty_block {
                let error = BlockValidationError::EmptyBlock;
                drop(state_block);
                record_timings(&mut timings, stateless_elapsed, Some(execution_start));
                emit_rejection(&block, &error);
                return WithEvents::new(Err((Box::new(block), Box::new(error))));
            }
            let genesis_clean_start = Instant::now();
            if let Err(error) = Self::ensure_genesis_transactions_clean(&block, genesis_account) {
                drop(state_block);
                if let Some(timings) = timings.as_deref_mut() {
                    timings.execution_genesis_clean_ms = to_ms(genesis_clean_start.elapsed());
                }
                record_timings(&mut timings, stateless_elapsed, Some(execution_start));
                emit_rejection(&block, &error);
                return WithEvents::new(Err((Box::new(block), Box::new(error))));
            }
            if let Some(timings) = timings.as_deref_mut() {
                timings.execution_genesis_clean_ms = to_ms(genesis_clean_start.elapsed());
            }
            record_timings(&mut timings, stateless_elapsed, Some(execution_start));
            WithEvents::new(Ok((
                ValidBlock::new_signatures_verified(block),
                state_block,
            )))
        }

        /// All static checks that require a state snapshot.
        fn block_time_floor(
            block: &SignedBlock,
            prev_block: &SignedBlock,
            block_cadence: Duration,
        ) -> Result<Duration, BlockValidationError> {
            Self::block_time_floor_from_parent_time(
                block,
                prev_block.header().creation_time(),
                block_cadence,
            )
        }
        /// Minimum permitted creation time over a parent created at `parent_creation_time`:
        /// at least one cadence later, at the certified lane floor and strictly after every
        /// timed native input. A proposer may authenticate a later time (§4.5).
        ///
        /// # Errors
        /// The time overflows.
        pub(crate) fn sumeragi_block_time_floor(
            block: &SignedBlock,
            parent_creation_time: Duration,
            block_cadence: Duration,
        ) -> Result<Duration, BlockValidationError> {
            Self::block_time_floor_from_parent_time(block, parent_creation_time, block_cadence)
        }
        fn block_time_floor_from_parent_time(
            block: &SignedBlock,
            parent_creation_time: Duration,
            block_cadence: Duration,
        ) -> Result<Duration, BlockValidationError> {
            let minimum = parent_creation_time
                .checked_add(block_cadence)
                .ok_or(BlockValidationError::BlockTimeOverflow)?;
            // Merged lane transactions do not set the time: the merge section's floor does
            // (`specs/sumeragi_lanes.md` §4.2), so the original proposal fixes this floor.
            let floor = Duration::from_millis(
                block
                    .lane_merge()
                    .map_or(0, |section| section.time_floor_ms),
            );
            let external = block.external_entrypoints_slice();
            let own = &external[..external.len() - block.merged_entrypoint_count()];
            let natives = block.network_entrypoints().skip(external.len());
            creation_time_after_inputs(minimum.max(floor), own.iter().chain(natives))
                .ok_or(BlockValidationError::BlockTimeOverflow)
        }
        #[allow(
            clippy::too_many_arguments,
            clippy::too_many_lines,
            clippy::explicit_iter_loop,
            clippy::collapsible_else_if
        )]
        fn validate_static_state_dependent(
            block: &SignedBlock,
            topology: &Topology,
            genesis_account: &AccountId,
            state: &impl StateReadOnly,
            pipeline_parallelism: &crate::state::PipelineParallelism,
            soft_fork: bool,
            time_source: &TimeSource,
            skip_block_signatures: bool,
            validation_profile: &ConsensusValidationProfile,
        ) -> Result<StaticValidationData, BlockValidationError> {
            let state_height = state.block_hashes().len();
            let expected_block_height = if soft_fork {
                state_height
            } else {
                state_height
                    .checked_add(1)
                    .expect("INTERNAL BUG: Block height exceeds usize::MAX")
            };
            let actual_height = block
                .header()
                .height()
                .get()
                .try_into()
                .expect("INTERNAL BUG: Block height exceeds usize::MAX");
            if expected_block_height != actual_height {
                let state_latest_hash = state.block_hashes().iter().nth_back(0).copied();
                let state_prev_hash = state.block_hashes().iter().nth_back(1).copied();
                iroha_logger::warn!(
                    expected_height = expected_block_height,
                    actual_height,
                    state_height,
                    block_prev_hash = ?block.header().prev_block_hash(),
                    block_hash = ?block.hash(),
                    state_latest_hash = ?state_latest_hash,
                    state_prev_hash = ?state_prev_hash,
                    "prev block height mismatch during static validation"
                );
                return Err(BlockValidationError::PrevBlockHeightMismatch {
                    expected: expected_block_height,
                    actual: actual_height,
                });
            }
            let params = state.world().parameters();
            // Merged lane entrypoints are bounded by the lane merge rules
            // (`specs/sumeragi_lanes.md` §4.3); the cap applies to the block's own.
            validate_external_entrypoint_count(
                block
                    .external_entrypoint_count()
                    .saturating_sub(block.merged_entrypoint_count()),
                params.block().max_transactions(),
            )?;
            let max_clock_drift = params.sumeragi().max_clock_drift();
            let tx_params = params.transaction();
            if validation_profile.enforce_local_wall_clock() {
                let now = time_source.now();
                let block_creation_time = block.header().creation_time();
                if block_creation_time.saturating_sub(now) > max_clock_drift {
                    return Err(BlockValidationError::BlockInTheFuture);
                }
            }
            let expected_prev_block_hash = if soft_fork {
                state.block_hashes().iter().nth_back(1).copied()
            } else {
                state.block_hashes().iter().nth_back(0).copied()
            };
            let actual_prev_block_hash = block.header().prev_block_hash();
            if expected_prev_block_hash != actual_prev_block_hash {
                return Err(BlockValidationError::PrevBlockHashMismatch {
                    expected: expected_prev_block_hash,
                    actual: actual_prev_block_hash,
                });
            }
            if block.header().is_genesis() {
                // A consensus proposal is canonically resultless. Authenticate the configured
                // genesis root and every intent it commits before any genesis-only instruction
                // is allowed to execute against the bootstrap state.
                authenticate_genesis_block_intents(block, genesis_account)?;
            }
            Self::validate_sumeragi_consensus_effects(block)?;
            Self::validate_da_sidecar_hashes(block)?;
            Self::validate_da_pin_intent_bundle(block, state)?;
            Self::validate_execution_context_with_state(
                block,
                topology,
                state,
                validation_profile,
            )?;
            let block_height = block.header().height().get();
            let nexus = state.nexus();
            let expected_policy_bundle =
                crate::da::active_proof_policy_bundle_at_height(nexus, block_height);
            let expected_policy_hash = HashOf::new(&expected_policy_bundle);
            if block.header().da_proof_policies_hash() != Some(expected_policy_hash) {
                return Err(BlockValidationError::ProofPolicyHashMismatch {
                    expected: expected_policy_hash,
                    actual: block.header().da_proof_policies_hash(),
                });
            }
            if block.da_proof_policies() != Some(&expected_policy_bundle) {
                return Err(BlockValidationError::DaProofPolicyBundleMismatch);
            }
            let computed_digest =
                compute_confidential_feature_digest(state.world(), state.zk(), block_height);
            let expected_digest = if computed_digest.is_empty() {
                None
            } else {
                Some(computed_digest)
            };
            let actual_digest = block.header().confidential_features();
            ensure_confidential_features_match(expected_digest, actual_digest)?;
            if block.header().is_genesis() {
                if block.has_results() {
                    check_genesis_execution_results(block)?;
                }
            } else {
                let prev_block = if soft_fork {
                    state.prev_block()
                } else {
                    state.latest_block()
                }
                .map_err(|error| {
                    BlockValidationError::ExecutionDeferred(match error {
                        crate::execution_attempt::ExecutionAttemptError::Deferred(original) => {
                            original
                        }
                        crate::execution_attempt::ExecutionAttemptError::Rejected(_) => {
                            ivm::error::ExecutionDeferral::CanonicalHistoryUnavailable.into()
                        }
                    })
                })?;
                if let Some(prev_block) = prev_block {
                    let prev_block_time = prev_block.header().creation_time();
                    if let Some(block_cadence) = validation_profile.block_cadence() {
                        let minimum = Self::block_time_floor(block, &prev_block, block_cadence)?;
                        let actual = block.header().creation_time();
                        if actual < minimum
                            || cfg!(all(test, sumeragi_core_mutation = "HC329"))
                                && actual != minimum
                        {
                            return Err(BlockValidationError::BlockTimeBeforeRequiredFloor {
                                minimum_ms: u64::try_from(minimum.as_millis())
                                    .map_err(|_| BlockValidationError::BlockTimeOverflow)?,
                                actual_ms: u64::try_from(actual.as_millis())
                                    .map_err(|_| BlockValidationError::BlockTimeOverflow)?,
                            });
                        }
                    }
                    if block.header().creation_time() <= prev_block_time {
                        return Err(BlockValidationError::BlockInThePast);
                    }
                } else {
                    return Err(BlockValidationError::PrevBlockHashMismatch {
                        expected: expected_prev_block_hash,
                        actual: actual_prev_block_hash,
                    });
                }
                if !skip_block_signatures {
                    Self::verify_leader_signature(block, topology)?;
                    // Enforce BLS-normal for validator signatures (Set A + Set B).
                    Self::verify_validator_signatures(block, topology)?;
                    Self::verify_no_undefined_signatures(block, topology)?;
                    Self::verify_unique_signers(block)?;
                    Self::enforce_consensus_key_lifecycle(block, topology, state)?;
                }
            }
            let crypto_cfg = state.crypto();
            let pipeline_cfg = state.pipeline().clone();
            let aggregate_lane = nexus.routing_policy.default_lane;
            Ok(StaticValidationData {
                expected_block_height,
                max_clock_drift,
                tx_params,
                crypto_cfg,
                pipeline_cfg,
                pipeline_parallelism: pipeline_parallelism.clone(),
                aggregate_lane,
            })
        }
        fn npos_effects_error(message: impl Into<String>) -> BlockValidationError {
            BlockValidationError::NposEffectsInvalid(message.into())
        }

        fn validate_da_sidecar_hashes(block: &SignedBlock) -> Result<(), BlockValidationError> {
            let expected_policies = block.da_proof_policies().map(HashOf::new);
            let actual_policies = block.header().da_proof_policies_hash();
            if expected_policies.is_none() || actual_policies != expected_policies {
                return Err(BlockValidationError::DaProofPolicySidecarHashMismatch {
                    expected: expected_policies,
                    actual: actual_policies,
                });
            }
            if block
                .da_commitments()
                .is_some_and(DaCommitmentBundle::is_empty)
            {
                return Err(BlockValidationError::NonCanonicalEmptyDaCommitmentBundle);
            }
            let expected_commitments = block
                .da_commitments()
                .and_then(DaCommitmentBundle::merkle_commitment);
            let actual_commitments = block.header().da_commitments_hash();
            if actual_commitments != expected_commitments {
                return Err(BlockValidationError::DaCommitmentHashMismatch {
                    expected: expected_commitments,
                    actual: actual_commitments,
                });
            }
            if block
                .da_pin_intents()
                .is_some_and(DaPinIntentBundle::is_empty)
            {
                return Err(BlockValidationError::NonCanonicalEmptyDaPinIntentBundle);
            }
            let expected_pin_intents = block
                .da_pin_intents()
                .and_then(DaPinIntentBundle::merkle_commitment);
            let actual_pin_intents = block.header().da_pin_intents_hash();
            if actual_pin_intents != expected_pin_intents {
                return Err(BlockValidationError::DaPinIntentHashMismatch {
                    expected: expected_pin_intents,
                    actual: actual_pin_intents,
                });
            }
            Ok(())
        }
        fn validate_da_pin_intent_bundle(
            block: &SignedBlock,
            state: &impl StateReadOnly,
        ) -> Result<(), BlockValidationError> {
            let Some(bundle) = block.da_pin_intents() else {
                return Ok(());
            };
            let world = state.world();
            crate::da::validate_pin_intent_bundle_against_nexus_at_height(
                bundle,
                state.nexus(),
                block.header().height().get(),
                |account| world.accounts().get(account).is_some(),
            )?;
            crate::da::validate_pin_intent_authorizations(
                bundle,
                *state.network_id(),
                |account| {
                    world
                        .accounts()
                        .get(account)
                        .map(|_| account.controller().clone())
                },
            )?;
            let admission_policy = world
                .parameters()
                .custom()
                .get(&iroha_data_model::da::ingest::DaIngestAdmissionPolicyV1::parameter_id())
                .map(|custom| {
                    iroha_data_model::da::ingest::DaIngestAdmissionPolicyV1::from_custom_parameter(
                        custom,
                    )
                    .map_err(|error| {
                        BlockValidationError::DaPinIntentBundle(
                            DaPinIntentValidationError::InvalidAdmissionPolicy {
                                reason: error.to_string(),
                            },
                        )
                    })?
                    .ok_or_else(|| {
                        BlockValidationError::DaPinIntentBundle(
                            DaPinIntentValidationError::InvalidAdmissionPolicy {
                                reason: "reserved parameter changed identity".to_owned(),
                            },
                        )
                    })
                })
                .transpose()?;
            crate::da::validate_pin_intent_admission_policy(
                bundle,
                admission_policy.as_ref(),
                |lane_id| state.lane_incarnation_at_height(lane_id, block.header().height().get()),
            )?;
            crate::da::quota::prepare_ingest_quota_writes(
                world.smart_contract_state(),
                bundle,
                block.header().height().get(),
                &state.nexus().da,
            )?;
            for intent in &bundle.intents {
                if world
                    .da_pin_intents_by_lane_epoch()
                    .get(&(intent.lane_id, intent.epoch, intent.sequence))
                    .is_some()
                {
                    return Err(BlockValidationError::DaPinIntentBundle(
                        DaPinIntentValidationError::DuplicateIntent {
                            lane: intent.lane_id,
                            epoch: intent.epoch,
                            sequence: intent.sequence,
                        },
                    ));
                }
                if world
                    .da_pin_intents_by_manifest()
                    .get(&intent.manifest_hash)
                    .is_some()
                {
                    return Err(BlockValidationError::DaPinIntentBundle(
                        DaPinIntentValidationError::DuplicateManifest {
                            lane: intent.lane_id,
                            epoch: intent.epoch,
                            sequence: intent.sequence,
                        },
                    ));
                }
                if world
                    .da_pin_intents_by_ticket()
                    .get(&intent.storage_ticket)
                    .is_some()
                {
                    return Err(BlockValidationError::DaPinIntentBundle(
                        DaPinIntentValidationError::DuplicateStorageTicket {
                            lane: intent.lane_id,
                            epoch: intent.epoch,
                            sequence: intent.sequence,
                        },
                    ));
                }
            }
            Ok(())
        }

        /// Native control belongs to the authenticated header; the payload has no second
        /// pulse owner. ScheduleStep validates and applies that witness exactly once.
        fn validate_sumeragi_consensus_effects(
            block: &SignedBlock,
        ) -> Result<(), BlockValidationError> {
            if block.header().npos_effects_hash() != block.npos_consensus_effects().map(HashOf::new)
                || block
                    .npos_consensus_effects()
                    .is_some_and(NposConsensusEffects::is_empty)
            {
                return Err(Self::npos_effects_error(
                    "native staking effects require one nonempty exactly header-bound bundle",
                ));
            }
            if block.global_beacon_pulse().is_some()
                || block.header().global_beacon_pulse_hash().is_some()
            {
                return Err(Self::npos_effects_error(
                    "native payload rejects a second beacon pulse owner",
                ));
            }
            Ok(())
        }

        fn execution_capture_attempt_error(
            error: crate::state::WitnessCaptureError,
        ) -> BlockValidationError {
            match error {
                crate::state::WitnessCaptureError::Rejected(error) => {
                    Self::execution_context_error(error)
                }
                crate::state::WitnessCaptureError::Deferred(reason) => {
                    BlockValidationError::ExecutionDeferred(reason)
                }
                crate::state::WitnessCaptureError::StorageAdmission(error) => {
                    BlockValidationError::StateStorageAdmission(error)
                }
            }
        }
        fn amx_deadline_error(
            error: iroha_data_model::sumeragi_amx::AmxError,
        ) -> BlockValidationError {
            match crate::sumeragi::amx::classified_decode_refusal(&error) {
                Some(original) if !cfg!(all(test, sumeragi_core_mutation = "HC162")) => {
                    BlockValidationError::StateStorageAdmission(
                        crate::state::StateStorageAdmissionError::AmxDecode(original),
                    )
                }
                _ => Self::execution_context_error(error.to_string()),
            }
        }
        fn execution_context_error(message: impl Into<String>) -> BlockValidationError {
            BlockValidationError::ExecutionContextInvalid(message.into())
        }
        fn checked_execution_context_header(
            block: &SignedBlock,
        ) -> Result<Option<&BlockExecutionContextBundle>, BlockValidationError> {
            match (
                block.header().execution_context_hash(),
                block.execution_context(),
            ) {
                (None, None) => Ok(None),
                (Some(_), None) => Err(Self::execution_context_error(
                    "header references execution context but payload is missing",
                )),
                (None, Some(_)) => Err(Self::execution_context_error(
                    "payload includes execution context but header hash is absent",
                )),
                (Some(expected), Some(bundle)) => {
                    if !bundle.has_current_version() {
                        return Err(Self::execution_context_error(format!(
                            "unsupported block execution-context bundle version {}",
                            bundle.version
                        )));
                    }
                    let actual = HashOf::new(bundle);
                    if actual != expected {
                        return Err(Self::execution_context_error(
                            "execution context hash mismatch",
                        ));
                    }
                    Ok(Some(bundle))
                }
            }
        }

        fn validate_execution_context_alignment(
            block: &SignedBlock,
            bundle: &BlockExecutionContextBundle,
        ) -> Result<(), BlockValidationError> {
            let expected_len = block.external_entrypoint_count();
            if bundle.external.len() != expected_len {
                return Err(Self::execution_context_error(format!(
                    "execution context length mismatch: expected {expected_len}, got {}",
                    bundle.external.len()
                )));
            }
            for (idx, (entrypoint, context)) in block
                .external_entrypoints_cloned()
                .zip(bundle.external.iter())
                .enumerate()
            {
                let expected = entrypoint.hash();
                if context.entrypoint_hash != expected {
                    return Err(Self::execution_context_error(format!(
                        "execution context entrypoint hash mismatch at index {idx}"
                    )));
                }
            }
            Ok(())
        }

        fn validate_execution_context_with_state(
            block: &SignedBlock,
            _topology: &Topology,
            state: &impl StateReadOnly,
            _profile: &ConsensusValidationProfile,
        ) -> Result<(), BlockValidationError> {
            let bundle = Self::checked_execution_context_header(block)?;
            let Some(bundle) = bundle else {
                return if !block.header().is_genesis() && block.external_entrypoint_count() != 0 {
                    Err(Self::execution_context_error(
                        "missing execution context for external inputs",
                    ))
                } else {
                    Ok(())
                };
            };
            Self::validate_execution_context_alignment(block, bundle)?;
            if block.header().is_genesis() {
                return Ok(());
            }
            let routing = crate::sumeragi::lanes::routing::RoutingSnapshot::of(state)
                .map_err(BlockValidationError::ExecutionDeferred)?;
            let inputs = routing.inputs(state.world());
            for (index, (entrypoint, context)) in block
                .external_entrypoints_slice()
                .iter()
                .zip(&bundle.external)
                .enumerate()
            {
                let plan = routing_plan_from_execution_context(context)
                    .map_err(|error| Self::execution_context_error(error.clone()))?;
                let accepted = crate::tx::AcceptedTransaction::new_unchecked_entrypoint(
                    Cow::Borrowed(entrypoint),
                );
                let expected = inputs
                    .execution_route(&accepted, block.header().height().get())
                    .map_err(BlockValidationError::ExecutionDeferred)?
                    .ok_or_else(|| {
                        Self::execution_context_error(
                            "committed native execution route is unavailable",
                        )
                    })?;
                if matches!(plan, crate::queue::RoutingPlan::NativeAmx(_))
                    || plan.coordinator_route() != expected
                {
                    return Err(Self::execution_context_error(format!(
                        "input {index} differs from its native committed execution route"
                    )));
                }
            }
            Ok(())
        }

        fn committed_heights_for_prepared_transactions(
            prepared_txs: &[PreparedBlockTransaction],
            transactions: &impl TransactionsReadOnly,
        ) -> Vec<Option<NonZeroUsize>> {
            prepared_txs
                .iter()
                .map(|prepared| transactions.get(&prepared.metadata.entrypoint_hash))
                .collect()
        }
        fn committed_heights_for_entrypoint_carriers(
            block: &SignedBlock,
            transactions: &impl TransactionsReadOnly,
        ) -> Vec<Option<NonZeroUsize>> {
            block
                .external_entrypoints_slice()
                .iter()
                .map(|entrypoint| transactions.get(&entrypoint.hash()))
                .collect()
        }
        /// Reject a block that carries more fee-exempt SCCP transactions than the per-block
        /// caps allow (`specs/sccp.md` §4.19). Eligibility is a pure function of the entry
        /// points and the committed parent World, and the caps are the parent's parameters,
        /// exactly what the proposer's queue selection counts
        /// (`Queue::bounded_pending_snapshot`), so a block its proposer built always passes.
        /// Execution exempts with the same predicate against the same World, so every exempt
        /// transaction is counted. Without SCCP nothing is capped.
        fn validate_sccp_exempt_cap(
            block: &SignedBlock,
            state_block: &StateBlock<'_>,
        ) -> Result<(), BlockValidationError> {
            use crate::smartcontracts::isi::sccp::eligibility::EligibilityRead as _;
            use crate::smartcontracts::isi::sccp::keepalive;
            let parent =
                crate::smartcontracts::isi::sccp::eligibility::BlockParent(&state_block.world);
            let mut keepalives = 0usize;
            for entrypoint in block.network_entrypoints() {
                let signed = match entrypoint {
                    TransactionEntrypoint::External(signed) => signed,
                    TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
                    TransactionEntrypoint::SealedCommitment(_) => continue,
                };
                let count = keepalive::count(signed.instructions());
                keepalives = keepalives.saturating_add(count);
                keepalive::check_count(keepalives).map_err(Self::execution_context_error)?;
                if count != 0 && !keepalive::valid_shape(signed.payload()) {
                    return Err(Self::execution_context_error(
                        "invalid standalone Keepalive shape",
                    ));
                }
            }
            if keepalives != 0 {
                let time_ms = u64::try_from(block.header().creation_time().as_millis())
                    .map_err(|_| Self::execution_context_error("Keepalive block time overflow"))?;
                match keepalive::due_from(&parent, block.header().height().get(), time_ms) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(Self::execution_context_error("KeepaliveNotDue"));
                    }
                    Err(error) => {
                        return Err(BlockValidationError::GovernanceDueUnavailable(error));
                    }
                }
            }
            if parent.parameters().is_none() {
                return Ok(());
            }
            let committed_time_ms =
                crate::smartcontracts::isi::sccp::hold::committed_time_ms(state_block)
                    .map_err(|error| Self::execution_context_error(error.to_string()))?;
            Self::validate_sccp_exempt_cap_against(block, &parent, committed_time_ms)
        }
        /// Check the per-block SCCP exemption caps of `block` against the `parent` World.
        fn validate_sccp_exempt_cap_against(
            block: &SignedBlock,
            parent: &(impl crate::smartcontracts::isi::sccp::eligibility::EligibilityRead + ?Sized),
            committed_time_ms: Option<u64>,
        ) -> Result<(), BlockValidationError> {
            use crate::smartcontracts::isi::sccp::admission;
            if parent.parameters().is_none() {
                return Ok(());
            }
            let classes = block
                .network_entrypoints()
                .filter_map(|entrypoint| {
                    admission::exempt_class_of_entrypoint_from(
                        parent,
                        entrypoint,
                        committed_time_ms,
                    )
                })
                .collect::<Vec<_>>();
            let mut budget =
                admission::SccpExemptBlockBudgetV1::from_parameters(parent.parameters());
            if classes.iter().all(|class| budget.admit(Some(*class))) {
                Ok(())
            } else {
                Err(Self::execution_context_error(format!(
                    "block carries {} fee-exempt SCCP transactions beyond the per-block caps",
                    classes.len()
                )))
            }
        }
        fn signed_transaction_from_entrypoint(
            entrypoint: &TransactionEntrypoint,
        ) -> Option<&SignedTransaction> {
            match entrypoint {
                TransactionEntrypoint::External(tx) => Some(tx),
                TransactionEntrypoint::SealedReveal(reveal) => Some(reveal.signed_transaction()),
                TransactionEntrypoint::SealedCommitment(_) => None,
            }
        }
        fn collect_external_signed_transactions(block: &SignedBlock) -> Vec<&SignedTransaction> {
            block
                .external_entrypoints_slice()
                .iter()
                .filter_map(Self::signed_transaction_from_entrypoint)
                .collect()
        }
        /// Prepare metadata once for each signed external entrypoint in canonical order.
        fn prepare_external_transactions(block: &SignedBlock) -> Vec<PreparedBlockTransaction> {
            Self::collect_external_signed_transactions(block)
                .into_iter()
                .map(|tx| PreparedBlockTransaction {
                    metadata: crate::tx::AcceptedTransaction::prepare_signed_metadata(tx),
                })
                .collect()
        }
        #[cfg(feature = "bls")]
        #[allow(clippy::too_many_lines)]
        fn precheck_bls_transaction_signatures(
            signed_txs: &[&SignedTransaction],
            prepared_txs: &[PreparedBlockTransaction],
            cap: usize,
            prechecked_signature_results: &mut [Option<Result<(), SignatureVerificationFail>>],
            metrics: MetricsRef<'_>,
            lane_id: LaneId,
        ) {
            #[derive(Clone)]
            struct BlsItem {
                idx: usize,
                pk: iroha_crypto::PublicKey,
                pk_bytes: Vec<u8>,
                pop: Option<Vec<u8>>,
                msg: [u8; 32],
                sig: Vec<u8>,
            }
            static BLS_POP_KEY: LazyLock<iroha_model_base::name::Name> =
                LazyLock::new(|| "bls_pop".parse().expect("valid metadata key"));
            static BLS_POP_SMALL_KEY: LazyLock<iroha_model_base::name::Name> =
                LazyLock::new(|| "bls_pop_small".parse().expect("valid metadata key"));
            let mut all_normal_have_pop = true;
            let mut all_small_have_pop = true;
            let mut items_normal: Vec<BlsItem> = Vec::new();
            let mut items_small: Vec<BlsItem> = Vec::new();
            for (idx, (tx, prepared)) in signed_txs.iter().zip(prepared_txs.iter()).enumerate() {
                let AccountController::Single(signatory) = tx.authority().controller() else {
                    continue;
                };
                let Ok((algorithm, pk_bytes)) = signatory.try_to_bytes() else {
                    continue;
                };
                let small = match algorithm {
                    iroha_crypto::Algorithm::BlsNormal => false,
                    iroha_crypto::Algorithm::BlsSmall => true,
                    _ => continue,
                };
                let h = prepared.metadata.payload_hash;
                let mut msg = [0_u8; 32];
                msg.copy_from_slice(h.as_ref());
                let sig = tx.signature().payload().payload().to_vec();
                let mut pop = None;
                if small {
                    if let Some(pop_bytes) =
                        bls_small_pop_from_metadata(tx.metadata(), &BLS_POP_SMALL_KEY)
                    {
                        if iroha_crypto::bls_small_pop_verify(signatory, &pop_bytes).is_ok() {
                            pop = Some(pop_bytes);
                        } else {
                            all_small_have_pop = false;
                        }
                    } else {
                        all_small_have_pop = false;
                    }
                } else if let Some(pop_bytes) = bls_pop_from_metadata(tx.metadata(), &BLS_POP_KEY) {
                    if iroha_crypto::bls_normal_pop_verify(signatory, &pop_bytes).is_ok() {
                        pop = Some(pop_bytes);
                    } else {
                        all_normal_have_pop = false;
                    }
                } else {
                    all_normal_have_pop = false;
                }
                let item = BlsItem {
                    idx,
                    pk: signatory.clone(),
                    pk_bytes: pk_bytes.to_vec(),
                    pop,
                    msg,
                    sig,
                };
                if small {
                    items_small.push(item);
                } else {
                    items_normal.push(item);
                }
            }
            #[cfg(feature = "telemetry")]
            let mut same_msg_agg = 0_u64;
            #[cfg(feature = "telemetry")]
            let mut multi_msg_agg = 0_u64;
            #[cfg(feature = "telemetry")]
            let mut deterministic = 0_u64;
            #[cfg(feature = "telemetry")]
            let record_result = |same_message: bool, success: bool| {
                if let Some(metrics) = metrics {
                    metrics.inc_pipeline_sig_bls_result(lane_id, same_message, success);
                }
            };
            let mut verify_set = |items: &[BlsItem], small: bool| {
                if items.is_empty() {
                    return;
                }
                let mut groups: BTreeMap<[u8; 32], Vec<&BlsItem>> = BTreeMap::new();
                for item in items {
                    groups.entry(item.msg).or_default().push(item);
                }
                let mut singletons: Vec<&BlsItem> = Vec::new();
                for group in groups.values() {
                    if group.len() == 1 {
                        singletons.push(group[0]);
                        continue;
                    }
                    let Some(pops) = group
                        .iter()
                        .map(|item| item.pop.as_deref())
                        .collect::<Option<Vec<_>>>()
                    else {
                        return;
                    };
                    let msg = group[0].msg.as_slice();
                    let sigs: Vec<&[u8]> = group.iter().map(|item| item.sig.as_slice()).collect();
                    let pks: Vec<&iroha_crypto::PublicKey> =
                        group.iter().map(|item| &item.pk).collect();
                    let ok = if small {
                        iroha_crypto::bls_small_verify_aggregate_same_message(
                            msg, &sigs, &pks, &pops,
                        )
                        .is_ok()
                    } else {
                        iroha_crypto::bls_normal_verify_aggregate_same_message(
                            msg, &sigs, &pks, &pops,
                        )
                        .is_ok()
                    };
                    #[cfg(feature = "telemetry")]
                    {
                        same_msg_agg = same_msg_agg.saturating_add(1);
                        record_result(true, ok);
                    }
                    if ok {
                        for item in group {
                            prechecked_signature_results[item.idx] = Some(Ok(()));
                        }
                    } else {
                        for item in group {
                            prechecked_signature_results[item.idx] = Some(
                                crate::tx::AcceptedTransaction::signature_verification_result(
                                    signed_txs[item.idx],
                                ),
                            );
                        }
                    }
                }
                if !singletons.is_empty() {
                    let msgs: Vec<&[u8]> =
                        singletons.iter().map(|item| item.msg.as_slice()).collect();
                    let sigs: Vec<&[u8]> =
                        singletons.iter().map(|item| item.sig.as_slice()).collect();
                    let pks: Vec<&[u8]> = singletons
                        .iter()
                        .map(|item| item.pk_bytes.as_slice())
                        .collect();
                    let ok = if small {
                        iroha_crypto::bls_small_verify_aggregate_multi_message(&msgs, &sigs, &pks)
                            .is_ok()
                    } else {
                        iroha_crypto::bls_normal_verify_aggregate_multi_message(&msgs, &sigs, &pks)
                            .is_ok()
                    };
                    #[cfg(feature = "telemetry")]
                    {
                        multi_msg_agg = multi_msg_agg.saturating_add(1);
                        record_result(false, ok);
                    }
                    if ok {
                        for item in singletons {
                            prechecked_signature_results[item.idx] = Some(Ok(()));
                        }
                    } else {
                        for item in singletons {
                            prechecked_signature_results[item.idx] = Some(
                                crate::tx::AcceptedTransaction::signature_verification_result(
                                    signed_txs[item.idx],
                                ),
                            );
                        }
                    }
                }
            };
            if cap > 0 {
                if all_normal_have_pop {
                    for chunk in items_normal.chunks(cap) {
                        verify_set(chunk, false);
                    }
                } else {
                    #[cfg(feature = "telemetry")]
                    {
                        deterministic = deterministic
                            .saturating_add(u64::try_from(items_normal.len()).unwrap_or(u64::MAX));
                    }
                }
                if all_small_have_pop {
                    for chunk in items_small.chunks(cap) {
                        verify_set(chunk, true);
                    }
                } else {
                    #[cfg(feature = "telemetry")]
                    {
                        deterministic = deterministic
                            .saturating_add(u64::try_from(items_small.len()).unwrap_or(u64::MAX));
                    }
                }
            } else {
                #[cfg(feature = "telemetry")]
                {
                    let item_count = items_normal.len().saturating_add(items_small.len());
                    deterministic =
                        deterministic.saturating_add(u64::try_from(item_count).unwrap_or(u64::MAX));
                }
            }
            #[cfg(feature = "telemetry")]
            if let Some(metrics) = metrics {
                metrics.set_pipeline_sig_bls_counts(same_msg_agg, multi_msg_agg, deterministic);
            }
            #[cfg(not(feature = "telemetry"))]
            let _ = (metrics, lane_id);
        }
        /// Static checks that do not require holding a state view.
        #[allow(
            clippy::too_many_arguments,
            clippy::too_many_lines,
            clippy::explicit_iter_loop,
            clippy::collapsible_else_if,
            clippy::items_after_statements,
            clippy::option_if_let_else,
            clippy::manual_flatten
        )]
        fn validate_static_with_snapshot(
            block: &SignedBlock,
            network_id: &NetworkId,
            genesis_account: &AccountId,
            static_data: &StaticValidationData,
            committed_heights: &[Option<NonZeroUsize>],
            committed_carrier_heights: &[Option<NonZeroUsize>],
            prepared_txs: &[PreparedBlockTransaction],
            metrics: MetricsRef<'_>,
        ) -> Result<(), BlockValidationError> {
            use rayon::prelude::*;
            let _ = static_data.aggregate_lane;
            #[cfg(not(feature = "bls"))]
            let _ = metrics;
            // Rayon workers must use the caller's configured account address profile.
            let account_discriminant = chain_discriminant();
            #[cfg(test)]
            let account_profile_observer = tests::account_profile_validation_observer();
            let max_clock_drift = static_data.max_clock_drift;
            let tx_params = static_data.tx_params;
            let expected_block_height = static_data.expected_block_height;
            let pipeline_cfg = &static_data.pipeline_cfg;
            let crypto_cfg = &static_data.crypto_cfg;
            let block_creation_time = block.header().creation_time();
            debug_assert_eq!(
                committed_heights.len(),
                prepared_txs.len(),
                "committed-height snapshot must align with block transaction list",
            );
            if committed_heights.len() != prepared_txs.len() {
                return Err(BlockValidationError::MerkleRootMismatch);
            }
            if committed_carrier_heights.len() != block.external_entrypoint_count() {
                return Err(BlockValidationError::MerkleRootMismatch);
            }
            if committed_carrier_heights.iter().any(|committed_height| {
                committed_height
                    .as_ref()
                    .is_some_and(|height| height.get() < expected_block_height)
            }) {
                return Err(BlockValidationError::HasCommittedTransactions);
            }
            let signed_txs = Self::collect_external_signed_transactions(block);
            debug_assert_eq!(
                signed_txs.len(),
                prepared_txs.len(),
                "prepared metadata must align with signed block transactions",
            );
            if signed_txs.len() != prepared_txs.len() {
                return Err(BlockValidationError::MerkleRootMismatch);
            }
            let is_genesis_block = block.header().is_genesis();
            let mut prechecked_signature_results: Vec<
                Option<Result<(), SignatureVerificationFail>>,
            > = vec![None; prepared_txs.len()];
            // Genesis authenticates the ordered transaction intents once through the
            // genesis-authority block signature. Per-transaction proof bytes are not
            // an additional admission boundary.
            #[cfg(feature = "bls")]
            if !is_genesis_block {
                Self::precheck_bls_transaction_signatures(
                    &signed_txs,
                    prepared_txs,
                    pipeline_cfg.signature_batch_max_bls,
                    &mut prechecked_signature_results,
                    metrics,
                    static_data.aggregate_lane,
                );
            }
            let mut seen_hashes: BTreeSet<HashOf<SignedTransaction>> = BTreeSet::new();
            let mut seen_sealed_commitments = BTreeSet::new();
            for ((tx, prepared), committed_height) in signed_txs
                .iter()
                .copied()
                .zip(prepared_txs.iter())
                .zip(committed_heights.iter())
            {
                let tx_hash = prepared.metadata.signed_hash;
                // In case of soft-fork transaction is check if it was added at the same height as candidate block.
                if committed_height
                    .as_ref()
                    .is_some_and(|height| height.get() < expected_block_height)
                {
                    return Err(BlockValidationError::HasCommittedTransactions);
                }
                if !seen_hashes.insert(tx_hash) {
                    iroha_logger::error!(
                        %tx_hash,
                        height = %block.header().height(),
                        "duplicate transaction detected during block validation"
                    );
                    return Err(BlockValidationError::DuplicateTransactions);
                }
                if tx.creation_time() >= block_creation_time {
                    return Err(BlockValidationError::TransactionInTheFuture);
                }
            }
            let mut entrypoint_hashes = Vec::with_capacity(block.external_entrypoint_count());
            let mut prepared_signed_idx = 0usize;
            for entrypoint in block.external_entrypoints_slice() {
                match entrypoint {
                    TransactionEntrypoint::External(_) => {
                        let prepared = prepared_txs
                            .get(prepared_signed_idx)
                            .ok_or(BlockValidationError::MerkleRootMismatch)?;
                        entrypoint_hashes.push(prepared.metadata.entrypoint_hash);
                        prepared_signed_idx = prepared_signed_idx.saturating_add(1);
                    }
                    TransactionEntrypoint::SealedReveal(_) => {
                        let _prepared = prepared_txs
                            .get(prepared_signed_idx)
                            .ok_or(BlockValidationError::MerkleRootMismatch)?;
                        entrypoint_hashes.push(entrypoint.hash());
                        prepared_signed_idx = prepared_signed_idx.saturating_add(1);
                    }
                    TransactionEntrypoint::SealedCommitment(commitment) => {
                        crate::tx::validate_sealed_commitment_stateless(
                            commitment, network_id, tx_params,
                        )
                        .map_err(BlockValidationError::TransactionAccept)?;
                        if commitment.payload().reveal_after_height
                            <= u64::try_from(expected_block_height).unwrap_or(u64::MAX)
                        {
                            return Err(BlockValidationError::TransactionAccept(
                                AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                                    reason: "sealed transaction reveal_after_height must be greater than commit height".into(),
                                }),
                            ));
                        }
                        if !seen_sealed_commitments.insert(*commitment.commitment()) {
                            return Err(BlockValidationError::DuplicateTransactions);
                        }
                        entrypoint_hashes.push(entrypoint.hash());
                    }
                }
            }
            debug_assert_eq!(
                prepared_signed_idx,
                prepared_txs.len(),
                "signed entrypoint preparation must align with external entries",
            );
            let mut ed25519_prechecked = vec![false; prepared_txs.len()];
            let ed25519_batch_cap = pipeline_cfg.signature_batch_max_ed25519;
            if !is_genesis_block && ed25519_batch_cap > 0 {
                struct Ed25519BatchItem {
                    idx: usize,
                }
                fn verify_ed25519_batch_slices<'a>(
                    messages: &[&'a [u8]],
                    signatures: &[&'a [u8]],
                    public_keys: &[iroha_crypto::Ed25519ParsedPublicKey],
                    scratch: &mut iroha_crypto::Ed25519BatchScratch<'a>,
                ) -> Result<(), iroha_crypto::Error> {
                    iroha_crypto::ed25519_verify_batch_preparsed_deterministic_with_scratch(
                        messages,
                        signatures,
                        public_keys,
                        scratch,
                    )
                }
                let mut items = Vec::with_capacity(prepared_txs.len());
                let mut messages = Vec::with_capacity(prepared_txs.len());
                let mut signatures = Vec::with_capacity(prepared_txs.len());
                let mut public_keys = Vec::with_capacity(prepared_txs.len());
                let mut scratch = iroha_crypto::Ed25519BatchScratch::default();
                for (idx, (tx, prepared)) in signed_txs
                    .iter()
                    .copied()
                    .zip(prepared_txs.iter())
                    .enumerate()
                {
                    let signature = tx.signature().payload().payload();
                    if ed25519_prechecked[idx] {
                        continue;
                    }
                    if signature.len() != crate::tx::ED25519_SIGNATURE_LENGTH {
                        continue;
                    }
                    let Some(public_key) = prepared.metadata.single_ed25519_key else {
                        continue;
                    };
                    items.push(Ed25519BatchItem { idx });
                    messages.push(prepared.metadata.payload_hash.as_ref().as_slice());
                    signatures.push(signature);
                    public_keys.push(public_key);
                }
                let signature_error = |tx: &SignedTransaction, detail: String| {
                    BlockValidationError::TransactionAccept(
                        AcceptTransactionFail::SignatureVerification(
                            SignatureVerificationFail::new(
                                tx.signature().clone(),
                                SignatureRejectionCode::InvalidSignature,
                                detail,
                            ),
                        ),
                    )
                };
                for range_start in (0..items.len()).step_by(ed25519_batch_cap) {
                    let range_end = range_start
                        .saturating_add(ed25519_batch_cap)
                        .min(items.len());
                    let messages = &messages[range_start..range_end];
                    let signatures = &signatures[range_start..range_end];
                    let public_keys = &public_keys[range_start..range_end];
                    if let Err(err) =
                        verify_ed25519_batch_slices(messages, signatures, public_keys, &mut scratch)
                    {
                        if let Some((relative_idx, detail)) =
                            iroha_crypto::ed25519_first_bad_preparsed_deterministic_with_scratch(
                                messages,
                                signatures,
                                public_keys,
                                &mut scratch,
                            )
                        {
                            let idx = items[range_start + relative_idx].idx;
                            return Err(signature_error(signed_txs[idx], detail));
                        }
                        let idx = items.get(range_start).map_or(0, |item| item.idx);
                        return Err(signature_error(signed_txs[idx], err.to_string()));
                    }
                    for item in &items[range_start..range_end] {
                        ed25519_prechecked[item.idx] = true;
                    }
                }
            }
            let isolate_observations = crate::status::replay_observations_are_isolated();
            let validate_tx = |(idx, (tx, prepared)): (
                usize,
                (&SignedTransaction, &PreparedBlockTransaction),
            )|
             -> Option<BlockValidationError> {
                let _observations =
                    isolate_observations.then(crate::status::isolate_replay_observations);
                #[cfg(test)]
                let inherited_account_profile = chain_discriminant();
                let _profile = ChainDiscriminantGuard::enter(account_discriminant);
                #[cfg(test)]
                if let Some(observer) = account_profile_observer.as_ref() {
                    observer.observe(idx, inherited_account_profile, chain_discriminant());
                }
                let prechecked_signature_result = prechecked_signature_results
                    .get(idx)
                    .and_then(|result| result.clone());
                let validation_time = block_creation_time;
                if is_genesis_block {
                    if let Some(Err(fail)) = prechecked_signature_result {
                        return Some(BlockValidationError::TransactionAccept(
                            AcceptTransactionFail::SignatureVerification(fail),
                        ));
                    }
                    return AcceptedTransaction::validate_genesis_with_now(
                        tx,
                        max_clock_drift,
                        genesis_account,
                        crypto_cfg.as_ref(),
                        block_creation_time,
                    )
                    .err()
                    .map(BlockValidationError::TransactionAccept);
                }
                let stateless = if let Some(prechecked_signature_result) =
                    prechecked_signature_result
                {
                    AcceptedTransaction::validate_with_now_with_signature_result_and_prepared_metadata(
                            tx,
                            network_id,
                            max_clock_drift,
                            tx_params,
                            crypto_cfg.as_ref(),
                            validation_time,
                            Some(prechecked_signature_result),
                            &prepared.metadata,
                        )
                } else if ed25519_prechecked[idx] {
                    AcceptedTransaction::validate_with_now_after_single_ed25519_precheck_and_prepared_metadata(
                            tx,
                            network_id,
                            max_clock_drift,
                            tx_params,
                            crypto_cfg.as_ref(),
                            validation_time,
                            &prepared.metadata,
                        )
                } else {
                    AcceptedTransaction::validate_with_now_and_prepared_metadata(
                        tx,
                        network_id,
                        max_clock_drift,
                        tx_params,
                        crypto_cfg.as_ref(),
                        validation_time,
                        &prepared.metadata,
                    )
                };
                stateless.err().map(BlockValidationError::TransactionAccept)
            };
            let static_pool = static_data.pipeline_parallelism.pool();
            let use_parallel = static_pool.is_some() && prepared_txs.len() > 1;
            let tx_errors: Vec<Option<BlockValidationError>> = if use_parallel {
                static_pool
                    .as_ref()
                    .expect("parallel validation requires a configured pipeline pool")
                    .install(|| {
                        signed_txs
                            .par_iter()
                            .copied()
                            .zip(prepared_txs.par_iter())
                            .enumerate()
                            .map(validate_tx)
                            .collect()
                    })
            } else {
                signed_txs
                    .iter()
                    .copied()
                    .zip(prepared_txs.iter())
                    .enumerate()
                    .map(validate_tx)
                    .collect()
            };
            for maybe_err in tx_errors {
                if let Some(err) = maybe_err {
                    return Err(err);
                }
            }
            let expected_merkle_root = if let Some(pool) = static_pool.as_ref() {
                pool.install(|| {
                    let merkle_tree: MerkleTree<TransactionEntrypoint> =
                        MerkleTree::from_typed_leaves_parallel(entrypoint_hashes);
                    merkle_tree.root()
                })
            } else {
                let merkle_tree: MerkleTree<TransactionEntrypoint> =
                    entrypoint_hashes.into_iter().collect();
                merkle_tree.root()
            };
            let actual_merkle_root = block.header().merkle_root();
            if expected_merkle_root != actual_merkle_root {
                return Err(BlockValidationError::MerkleRootMismatch);
            }
            Ok(())
        }

        fn validated_committed_fragment_count(
            state_block: &StateBlock<'_>,
            advertised_committed_fragments: Option<u64>,
        ) -> Result<u64, BlockValidationError> {
            let ordinary = u64::try_from(state_block.committed_fragment_count()).map_err(|_| {
                Self::execution_context_error(
                    "ordinary committed fragment count exceeds the canonical u64 range",
                )
            })?;
            let expected = ordinary;
            if let Some(actual) = advertised_committed_fragments
                && actual != expected
            {
                return Err(BlockValidationError::CommittedFragmentCountMismatch {
                    expected,
                    actual,
                });
            }
            Ok(expected)
        }
        /// Execute a component fixture without a consensus height context.
        #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
        fn execute_and_record_canonical_outputs(
            block: &mut SignedBlock,
            state_block: &mut StateBlock<'_>,
            timings: Option<&mut ValidationTimings>,
            genesis: Option<&AuthenticatedGenesisOutputSource>,
        ) -> Result<(), BlockValidationError> {
            Self::execute_and_record_canonical_outputs_in_context(
                block,
                state_block,
                timings,
                genesis,
                crate::smartcontracts::isi::sccp::height::SccpHeightSourceV1::Unauthenticated,
                None,
                None,
            )
        }
        /// Execute and seal ordinary outputs. `sccp_height` names the authenticated consensus
        /// inputs of the block's height that the SCCP post-execution hook consumes
        /// (`specs/sccp.md` §4.3.2); `Unauthenticated` is reserved for component fixtures.
        /// Production genesis uses its independently authenticated native schedule.
        fn execute_and_record_canonical_outputs_in_context(
            block: &mut SignedBlock,
            state_block: &mut StateBlock<'_>,
            timings: Option<&mut ValidationTimings>,
            genesis: Option<&AuthenticatedGenesisOutputSource>,
            sccp_height: crate::smartcontracts::isi::sccp::height::SccpHeightSourceV1,
            amx_legs: Option<&mut crate::sumeragi::amx::NativeAmxLegPreparations>,
            parent_service_preparation: Option<
                &crate::sumeragi::certified_chain::ParentServicePreparation,
            >,
        ) -> Result<(), BlockValidationError> {
            let start = Instant::now();
            // Full input/control authority is checked by the caller. The State
            // owner rechecks proposal/source bindings and owns every actual phase.
            block
                .validate_proposal_commitments()
                .map_err(Self::execution_context_error)?;
            // Authenticate the common offered parent proof before any overlay mutation.
            // Original source loss and decoder refusal remain local retry outcomes.
            let parent_service = if block.header().height().get() <= 2 {
                if block
                    .npos_consensus_effects()
                    .and_then(|effects| effects.parent_service_commit_qc.as_ref())
                    .is_some()
                {
                    return Err(Self::execution_context_error(
                        "genesis has no native parent service proof",
                    ));
                }
                None
            } else if let Some(prepared) = parent_service_preparation {
                prepared
                    .authenticate(&*state_block, block)
                    .map_err(|error| match error {
                        crate::sumeragi::certified_chain::ParentServiceError::Invalid(reason) => {
                            Self::execution_context_error(reason)
                        }
                        crate::sumeragi::certified_chain::ParentServiceError::NativeSource(
                            error,
                        ) => BlockValidationError::NativeHistory(error),
                        crate::sumeragi::certified_chain::ParentServiceError::Source(error) => {
                            BlockValidationError::LocalStorageRecoveryRequired {
                                reason: error.to_string(),
                            }
                        }
                        crate::sumeragi::certified_chain::ParentServiceError::Deferred(reason) => {
                            BlockValidationError::ExecutionDeferred(reason)
                        }
                    })?
            } else {
                let reader =
                    crate::sumeragi::certified_chain::CertifiedChain::new_for_parent_service(
                        &*state_block,
                    )
                    .map_err(|error| match error {
                        crate::sumeragi::certified_chain::ParentServiceError::Deferred(reason) => {
                            BlockValidationError::ExecutionDeferred(reason)
                        }
                        error => BlockValidationError::LocalStorageRecoveryRequired {
                            reason: error.to_string(),
                        },
                    })?;
                reader
                    .authenticate_parent_service(block, |_, _| Ok(()))
                    .map_err(|error| match error {
                        crate::sumeragi::certified_chain::ParentServiceError::Invalid(reason) => {
                            Self::execution_context_error(reason)
                        }
                        crate::sumeragi::certified_chain::ParentServiceError::NativeSource(
                            error,
                        ) => BlockValidationError::NativeHistory(error),
                        crate::sumeragi::certified_chain::ParentServiceError::Source(error) => {
                            BlockValidationError::LocalStorageRecoveryRequired {
                                reason: error.to_string(),
                            }
                        }
                        crate::sumeragi::certified_chain::ParentServiceError::Deferred(reason) => {
                            BlockValidationError::ExecutionDeferred(reason)
                        }
                    })?
            };
            Self::validate_sccp_exempt_cap(block, state_block)?;
            let advertised_fragments = block.committed_fragment_count();
            let advertised_policy = block.axt_policy_snapshot().cloned();
            let advertised_transitions = block.axt_transitioned_dataspaces().cloned();
            if block.has_results() {
                block
                    .validate_output_merkle_cache()
                    .map_err(|error| Self::execution_context_error(error.to_string()))?;
                let policy = advertised_policy.as_ref().ok_or_else(|| {
                    BlockValidationError::AxtEnvelopeValidationFailed(
                        AxtEnvelopeValidationDetails {
                            message: "block result is missing its AXT post-state policy snapshot"
                                .to_owned(),
                            reason: AxtRejectReason::MissingPolicy,
                            snapshot_version: None,
                            dataspace: None,
                            lane: None,
                            active_handle_era: None,
                            next_handle_counter: None,
                        },
                    )
                })?;
                policy.validate().map_err(|error| {
                    BlockValidationError::AxtEnvelopeValidationFailed(
                        AxtEnvelopeValidationDetails {
                            message: format!("invalid AXT policy snapshot: {error}"),
                            reason: AxtRejectReason::PolicyDenied,
                            snapshot_version: Some(policy.version),
                            dataspace: None,
                            lane: None,
                            active_handle_era: None,
                            next_handle_counter: None,
                        },
                    )
                })?;
            }
            let expired =
                crate::smartcontracts::isi::sorafs::expire_pin_manifests_at_consensus_time(
                    state_block,
                )
                .map_err(|error| match error {
                    crate::smartcontracts::isi::sorafs::PinExpiryMaintenanceError::Storage(
                        error,
                    ) => BlockValidationError::StateStorageAdmission(error),
                    crate::smartcontracts::isi::sorafs::PinExpiryMaintenanceError::Instruction(
                        error,
                    ) => Self::execution_context_error(format!(
                        "SoraFS pin expiry maintenance failed: {error}"
                    )),
                })?;
            if expired != 0 {
                iroha_logger::debug!(
                    count = expired,
                    "retired SoraFS pins at the block consensus timestamp"
                );
            }
            // Materialize bounded native fee state before admitting customer outputs.
            // Missing parent finality defers the block; it never fabricates service.
            crate::validation_fee_rewards::process_finalized_service(
                state_block,
                block,
                parent_service.as_ref(),
            )
            .map_err(|error| match error {
                crate::state::ExecutionOutputAttemptError::Storage(error) => {
                    BlockValidationError::StateStorageAdmission(error)
                }
                crate::state::ExecutionOutputAttemptError::Deferred(reason) => {
                    BlockValidationError::ExecutionDeferred(reason)
                }
                crate::state::ExecutionOutputAttemptError::Owner(reason) => {
                    Self::execution_context_error(reason)
                }
            })?;
            crate::validation_fee::policy_history::process(state_block).map_err(
                |error| match error {
                    crate::state::ExecutionOutputAttemptError::Storage(error) => {
                        BlockValidationError::StateStorageAdmission(error)
                    }
                    crate::state::ExecutionOutputAttemptError::Deferred(reason) => {
                        BlockValidationError::ExecutionDeferred(reason)
                    }
                    crate::state::ExecutionOutputAttemptError::Owner(reason) => {
                        Self::execution_context_error(reason)
                    }
                },
            )?;
            crate::validation_fee_rewards::process_reward_entitlements(state_block).map_err(
                |error| match error {
                    crate::state::ExecutionOutputAttemptError::Storage(error) => {
                        BlockValidationError::StateStorageAdmission(error)
                    }
                    crate::state::ExecutionOutputAttemptError::Deferred(reason) => {
                        BlockValidationError::ExecutionDeferred(reason)
                    }
                    crate::state::ExecutionOutputAttemptError::Owner(reason) => {
                        Self::execution_context_error(reason)
                    }
                },
            )?;
            // Reserve evidence space for mandatory historical reward progress
            // before the optional idle-wallet batch. The sweep's own budget
            // check rolls its batch back when the remaining corpus is full.
            crate::retail_fee::process_idle_accounts(state_block).map_err(
                |attempt| match attempt {
                    crate::execution_attempt::ExecutionAttemptError::Deferred(original) => {
                        BlockValidationError::ExecutionDeferred(original)
                    }
                    crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                        BlockValidationError::StateStorageAdmission(error)
                    }
                },
            )?;
            let finalize = |state: &mut StateBlock<'_>,
                            source: &SignedBlock,
                            routes: &[crate::queue::RoutingDecision]| {
                // The Sumeragi schedule is World state: advance it before the seal fixes the
                // block's World delta.
                state
                    .advance_requested_sumeragi_schedule()
                    .map_err(|error| match error {
                        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                            BlockValidationError::ExecutionDeferred(reason)
                        }
                        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                            BlockValidationError::from(error)
                        }
                    })?;
                // TODO: Retire these test-only observations after the real finite-pool
                // finalizer fixture records the cumulative demand at this boundary.
                #[cfg(test)]
                eprintln!(
                    "native lane finalizer before: height={}, reserved={}, limit={}, peak={}, samples={}",
                    source.header().height().get(),
                    state
                        .pipeline_ivm_prepared_cache
                        .execution_budget()
                        .reserved_bytes(),
                    state
                        .pipeline_ivm_prepared_cache
                        .execution_budget()
                        .limit_bytes(),
                    state
                        .pipeline_ivm_prepared_cache
                        .execution_budget()
                        .peak_reserved_bytes(),
                    state.world.sumeragi_lanes().samples.len(),
                );
                let lane_outcome = state.advance_requested_sumeragi_lanes();
                #[cfg(test)]
                eprintln!(
                    "native lane finalizer after: height={}, reserved={}, limit={}, peak={}, samples={}, outcome={lane_outcome:?}",
                    source.header().height().get(),
                    state
                        .pipeline_ivm_prepared_cache
                        .execution_budget()
                        .reserved_bytes(),
                    state
                        .pipeline_ivm_prepared_cache
                        .execution_budget()
                        .limit_bytes(),
                    state
                        .pipeline_ivm_prepared_cache
                        .execution_budget()
                        .peak_reserved_bytes(),
                    state.world.sumeragi_lanes().samples.len(),
                );
                // A local lane refusal must return the original proposal from validation,
                // before any successful seal transfers it to the executor's one-shot takes.
                if !cfg!(all(test, sumeragi_core_mutation = "HC133")) {
                    lane_outcome.map_err(|error| match error {
                        crate::sumeragi::lanes::step::LaneStepError::Deferred(original) => {
                            BlockValidationError::ExecutionDeferred(
                                original.at_native_lane_finalizer(),
                            )
                        }
                        completed => Self::execution_context_error(completed.to_string()),
                    })?;
                }
                // AMX deadline decisions (`specs/sumeragi.md` §11.5) are World writes too.
                state
                    .advance_sumeragi_amx()
                    .map_err(Self::amx_deadline_error)?;
                Self::validate_native_genesis_policy(source, state)?;
                Self::finalize_owned_execution_metadata(
                    source,
                    state,
                    routes,
                    advertised_fragments,
                    advertised_policy.as_ref(),
                    advertised_transitions.as_ref(),
                    sccp_height,
                )
            };
            // The applying constructor already owns the recorder over pristine
            // controls and start effects. A late reset would erase that prefix.
            state_block
                .require_original_execution_recorder()
                .map_err(Self::execution_context_error)?;
            let result = state_block
                .execute_and_seal_ordinary_outputs_with_amx(block, genesis, finalize, amx_legs);
            result.map_err(|error| match error {
                crate::state::ExecutionOutputSealError::Storage(error) => {
                    BlockValidationError::StateStorageAdmission(error)
                }
                crate::state::ExecutionOutputSealError::Owner(reason) => {
                    Self::execution_context_error(reason)
                }
                crate::state::ExecutionOutputSealError::Deferred(reason) => {
                    BlockValidationError::ExecutionDeferred(reason)
                }
                crate::state::ExecutionOutputSealError::RejectedGenesis(rejection) => {
                    BlockValidationError::InvalidGenesis(InvalidGenesisError::RejectedOutput(
                        rejection,
                    ))
                }
                crate::state::ExecutionOutputSealError::Finalizer(error) => error,
            })?;
            state_block
                .verify_execution_output_seal(block)
                .map_err(Self::execution_context_error)?;
            if let Some(timings) = timings {
                let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                timings.execution_tx_apply_ms = elapsed;
                timings.execution_tx_apply_sequential_ms = elapsed;
            }
            Ok(())
        }
        /// Execute an ordinary component fixture whose input admission is supplied by its test.
        ///
        /// The recorder must originate from the same State's recording-aware constructor
        /// before any block effects. This component adapter does not authorize finality.
        #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
        pub fn validate_unchecked(
            block: SignedBlock,
            state_block: &mut StateBlock<'_>,
            recorder: crate::exec_witness::ExecWitnessGuard,
        ) -> WithEvents<ValidBlock> {
            Self::validate_recorded_unchecked(block, state_block, recorder)
        }

        /// Execute a fixture with the original recorder already acquired by its
        /// writer-first applying constructor. This consumes that same guard.
        #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
        pub(crate) fn validate_recorded_unchecked(
            mut block: SignedBlock,
            state_block: &mut StateBlock<'_>,
            exec_witness_guard: crate::exec_witness::ExecWitnessGuard,
        ) -> WithEvents<ValidBlock> {
            Self::execute_recorded_component_outputs(&mut block, state_block, &exec_witness_guard)
                .expect(
                    "unchecked component execution must preserve its original source and witness",
                );
            drop(exec_witness_guard);
            WithEvents::new(ValidBlock::new_unverified(block))
        }

        /// Execute component outputs while retaining the recorder acquired before block effects.
        /// This never creates recording authority or grants consensus/publication authority.
        /// The producer rechecks the exact original carrier owned by `state_block`.
        ///
        /// # Errors
        /// Refuses changed sources, execution controls, output ownership or witness capture.
        #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
        pub(crate) fn execute_recorded_component_outputs(
            block: &mut SignedBlock,
            state_block: &mut StateBlock<'_>,
            _recorder: &crate::exec_witness::ExecWitnessGuard,
        ) -> Result<(), BlockValidationError> {
            Self::validate_staged_execution_controls(block)?;
            Self::execute_and_record_canonical_outputs(block, state_block, None, None)?;
            validate_axt_envelopes(block, state_block)?;
            state_block
                .capture_exec_witness_attempt()
                .map_err(Self::execution_capture_attempt_error)
        }
        #[cfg(any(test, feature = "iroha-core-tests"))]
        /// Add additional signature for [`Self`]
        ///
        /// # Errors
        ///
        /// If given signature doesn't match block hash
        pub fn add_signature(
            &mut self,
            signature: BlockSignature,
            topology: &Topology,
        ) -> Result<(), SignatureVerificationError> {
            use SignatureVerificationError::{Other, UnknownSignatory, UnknownSignature};
            let signatory = usize::try_from(signature.index()).map_err(|_err| UnknownSignatory)?;
            let signatory = topology.as_ref().get(signatory).ok_or(UnknownSignatory)?;
            if matches!(topology.role(signatory), Role::Leader | Role::Undefined) {
                return Err(UnknownSignatory);
            }
            signature
                .signature()
                .verify_hash(signatory.public_key(), self.as_ref().hash())
                .map_err(|_err| UnknownSignature)?;
            self.block.add_signature(signature).map_err(|_err| Other)?;
            self.clear_signatures_verified();
            Ok(())
        }
        /// Replace block's signatures. Returns previous block signatures
        ///
        /// # Errors
        ///
        /// - Replacement signatures don't contain the leader signature
        /// - Replacement signatures contain unknown signatories
        /// - Replacement signatures contain incorrect signatures
        /// - Replacement signatures contain duplicate signatures
        pub fn replace_signatures(
            &mut self,
            signatures: iroha_data_model::block::BlockSignatures,
            topology: &Topology,
        ) -> WithEvents<Result<iroha_data_model::block::BlockSignatures, SignatureVerificationError>>
        {
            let mut seen = BTreeSet::new();
            for signature in &signatures {
                let signer = match usize::try_from(signature.index()) {
                    Ok(idx) => idx,
                    Err(_) => {
                        return WithEvents::new(Err(SignatureVerificationError::UnknownSignatory));
                    }
                };
                if !seen.insert(signer) {
                    return WithEvents::new(Err(SignatureVerificationError::DuplicateSignature {
                        signer,
                    }));
                }
            }
            let was_verified = self.signatures_verified;
            let Ok(prev_signatures) = self.block.replace_signatures(signatures) else {
                return WithEvents::new(Err(SignatureVerificationError::Other));
            };
            self.clear_signatures_verified();
            let result = if let Err(err) = Self::is_commit(self.as_ref(), topology) {
                self.block
                    .replace_signatures(prev_signatures)
                    .expect("INTERNAL BUG: invalid signatures in block");
                self.signatures_verified = was_verified;
                Err(err)
            } else {
                Ok(prev_signatures)
            };
            WithEvents::new(result)
        }
        /// Transition block to [`CommittedBlock`].
        ///
        /// # Errors
        ///
        /// - Block is missing the leader signature
        /// - Block doesn't have enough valid signatures
        pub fn commit(
            self,
            topology: &Topology,
            shell: ReservedSharedSignedBlock,
        ) -> WithCommittedBlockEvents {
            WithEvents::new(
                match Self::is_commit_internal(self.as_ref(), topology, self.signatures_verified) {
                    Err(err) => Err((Box::new(self), Box::new(err.into()))),
                    Ok(()) => Ok(CommittedBlock::from_execution(self, shell)),
                },
            )
        }

        #[cfg(test)]
        /// Commit using a prevalidated signer set (e.g., from a QC).
        ///
        /// The block signatures are still verified to guard against forged aggregates; `signers`
        /// must match a quorum of signatures present on the block.
        pub fn commit_with_signers(
            self,
            topology: &Topology,
            signers: &BTreeSet<ValidatorIndex>,
            allow_quorum_bypass: bool,
            shell: ReservedSharedSignedBlock,
        ) -> WithCommittedBlockEvents {
            let validation = (|| -> Result<(), SignatureVerificationError> {
                // Ensure the QC-reported signer set matches the expected quorum shape.
                Self::verify_signer_set(topology, signers, allow_quorum_bypass)?;
                // Block signatures can be a trimmed subset when the QC carries the quorum.
                // Validate all present signatures against the topology and ensure they
                // don't contradict the QC signer set.
                if !self.signatures_verified {
                    Self::verify_unique_signers(self.as_ref())?;
                    Self::verify_signatures_against_topology(self.as_ref(), topology)?;
                }
                Ok(())
            })();
            WithEvents::new(match validation {
                Err(err) => Err((Box::new(self), Box::new(err.into()))),
                Ok(()) => Ok(CommittedBlock::from_execution(self, shell)),
            })
        }
        /// Like [`Self::commit`], but without block signature checks.
        ///
        /// Useful e.g. for Explorer, which assumes all blocks from Iroha are valid, and
        /// only executes them to produce state changes.
        pub fn commit_unchecked(
            self,
            shell: ReservedSharedSignedBlock,
        ) -> WithEvents<CommittedBlock> {
            WithEvents::new(CommittedBlock::from_execution(self, shell))
        }

        /// Attach the independently checked finality artifact before freezing this original.
        /// This grants no finality or allocation authority and never copies the block graph.
        pub(crate) fn with_commit_certificate(mut self, certificate: CommitCertificate) -> Self {
            self.block.set_commit_certificate(Some(certificate));
            self
        }
        /// Check if block satisfy requirements to be committed
        ///
        /// # Errors
        ///
        /// - Block is missing the leader signature
        /// - Block doesn't have enough signatures for quorum
        pub(crate) fn is_commit(
            block: &SignedBlock,
            topology: &Topology,
        ) -> Result<(), SignatureVerificationError> {
            Self::is_commit_internal(block, topology, false)
        }
        fn is_commit_internal(
            block: &SignedBlock,
            topology: &Topology,
            signatures_verified: bool,
        ) -> Result<(), SignatureVerificationError> {
            if !block.header().is_genesis() {
                if !signatures_verified {
                    Self::verify_unique_signers(block)?;
                    Self::verify_leader_signature(block, topology)?;
                    Self::verify_signatures_against_topology(block, topology)?;
                }
                let SignatureTally {
                    present: present_signatures,
                    counted: votes_count,
                    set_b_signatures,
                } = commit_signature_tally(block, topology);
                iroha_logger::info!(
                    signatures_present = present_signatures,
                    votes = votes_count,
                    set_b_signatures,
                    min_votes = topology.min_votes_for_commit(),
                    topo_len = topology.as_ref().len(),
                    block_hash = %block.hash(),
                    "verifying block commit quorum"
                );
                if votes_count < topology.min_votes_for_commit() {
                    return Err(SignatureVerificationError::NotEnoughSignatures {
                        votes_count,
                        min_votes_for_commit: topology.min_votes_for_commit(),
                    });
                }
            }
            Ok(())
        }
        /// Fallibly add additional signatures for [`Self`].
        ///
        /// # Errors
        ///
        /// Returns [`iroha_crypto::Error::Signing`] when the configured signing
        /// backend rejects the private-key material or finalized block header hash.
        pub fn try_sign(
            &mut self,
            key_pair: &KeyPair,
            topology: &Topology,
        ) -> Result<(), iroha_crypto::Error> {
            let signatory_idx = topology
                .position(key_pair.public_key())
                .expect("INTERNAL BUG: Node is not in topology");
            self.block.try_sign(key_pair.private_key(), signatory_idx)?;
            self.clear_signatures_verified();
            Ok(())
        }
        /// Add additional signatures for [`Self`].
        pub fn sign(&mut self, key_pair: &KeyPair, topology: &Topology) {
            self.try_sign(key_pair, topology)
                .expect("signing should succeed for a valid validator key and block header");
        }
        #[cfg(test)]
        pub(crate) fn new_dummy(leader_private_key: &PrivateKey) -> Self {
            Self::new_dummy_and_modify_header(leader_private_key, |_| {})
        }
        #[cfg(test)]
        pub(crate) fn new_dummy_and_modify_header(
            leader_private_key: &PrivateKey,
            f: impl FnOnce(&mut BlockHeader),
        ) -> Self {
            let merkle_root = MerkleTree::<TransactionEntrypoint>::default().root();
            let mut header =
                BlockHeader::new(nonzero_ext::nonzero!(2_u64), None, merkle_root, 0, 0);
            f(&mut header);
            if header.confidential_features().is_none() {
                header.set_confidential_features(Some(EMPTY_CONFIDENTIAL_FEATURE_DIGEST));
            }
            let builder = BlockBuilder(Chained {
                header,
                transactions: Vec::new(),
                da_commitments: None,
                da_proof_policies: None,
                da_pin_intents: None,
                npos_consensus_effects: None,
                global_beacon_pulse: None,
                execution_context: None,
            });
            let default_policies = crate::da::proof_policy_bundle(
                &iroha_config::parameters::actual::LaneConfig::default(),
            );
            let mut unverified_block: SignedBlock = builder
                .with_da_proof_policies(Some(default_policies))
                .sign(leader_private_key)
                .unpack(|_| {})
                .into();
            unverified_block
                .set_execution_outputs(
                    Vec::new(),
                    0,
                    std::collections::BTreeMap::default(),
                    Vec::new(),
                    iroha_data_model::nexus::AxtPolicySnapshot::default(),
                    std::collections::BTreeSet::default(),
                    &crate::execution_output_test_support::structural_output_limits(),
                )
                .expect("empty structural block has complete execution metadata");
            // Keep the exact payload whose commitments were signed above.
            // The transaction-only constructor would discard the DA policy body.
            Self::new_unverified(unverified_block)
        }
    }
    impl From<ValidBlock> for SignedBlock {
        fn from(source: ValidBlock) -> Self {
            source.block
        }
    }
    impl AsRef<SignedBlock> for ValidBlock {
        fn as_ref(&self) -> &SignedBlock {
            &self.block
        }
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    impl AsMut<SignedBlock> for ValidBlock {
        fn as_mut(&mut self) -> &mut SignedBlock {
            &mut self.block
        }
    }
    #[test]
    fn dummy_block_populates_proof_policy_hash() {
        let kp = crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal);
        let block = ValidBlock::new_dummy(kp.private_key());
        assert!(block.as_ref().header().da_proof_policies_hash().is_some());
        let block = block.as_ref();
        let policy = block
            .da_proof_policies()
            .expect("dummy retains its signed policy body");
        assert_eq!(
            block.header().da_proof_policies_hash(),
            Some(HashOf::new(policy))
        );
        block
            .validate_proposal_commitments()
            .expect("dummy proposal commitments match its actual payload");
        block
            .validate_output_merkle_cache()
            .expect("dummy outputs retain complete empty execution metadata");
        assert_eq!(block.committed_fragment_count(), Some(0));
        assert!(block.axt_policy_snapshot().is_some());
        assert!(
            block
                .axt_transitioned_dataspaces()
                .is_some_and(BTreeSet::is_empty)
        );
        block
            .signatures()
            .next()
            .unwrap()
            .signature()
            .verify_hash(kp.public_key(), block.hash())
            .expect("dummy signature authenticates the complete retained proposal");
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            kura::Kura,
            query::store::LiveQueryStore,
            soracloud_runtime::{
                SoracloudApartmentExecutionRequest, SoracloudApartmentExecutionResult,
                SoracloudDeterministicStateMutation, SoracloudLocalReadRequest,
                SoracloudLocalReadResponse, SoracloudOrderedMailboxExecutionRequest,
                SoracloudOrderedMailboxExecutionResult, SoracloudRuntime,
                SoracloudRuntimeExecutionError, SoracloudRuntimeExecutionErrorKind,
                SoracloudRuntimeReadHandle, SoracloudRuntimeSnapshot,
            },
            state::{State, World},
            sumeragi::network_topology::{Topology, test_topology_with_keys},
            tx::AcceptedTransaction,
        };
        use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, PrivateKey, Signature, SignatureOf};
        use iroha_data_model::{
            Registrable,
            block::error::BlockRejectionReason as Reason,
            consensus::{ConsensusKeyId, ConsensusKeyRecord, ConsensusKeyRole, ConsensusKeyStatus},
            da::{
                commitment::{
                    DaCommitmentBundle, DaCommitmentRecord, DaProofScheme, RetentionClass,
                },
                pin_intent::{DaPinIntent, DaPinIntentBundle},
                types::{BlobDigest, StorageTicketId},
            },
            isi::{InstructionBox, Log, error::Mismatch},
            nexus::{AxtPolicyBinding, AxtPolicyEntry, AxtPolicySnapshot, LaneCatalog, LaneConfig},
            parameter::Parameter,
            prelude::{Account, Domain, Register},
            soracloud::{
                SORA_STATE_BINDING_VERSION_V1, SoraCapabilityPolicyV1,
                SoraCertifiedResponsePolicyV1, SoraContainerManifestRefV1, SoraContainerManifestV1,
                SoraContainerRuntimeV1, SoraDeploymentBundleV1, SoraLifecycleHooksV1,
                SoraMailboxContractV1, SoraNetworkPolicyV1, SoraResourceLimitsV1,
                SoraRolloutPolicyV1, SoraRuntimeReceiptV1, SoraServiceDeploymentStateV1,
                SoraServiceHandlerClassV1, SoraServiceHandlerV1, SoraServiceHealthStatusV1,
                SoraServiceMailboxMessageV1, SoraServiceManifestV1, SoraServiceRuntimeStateV1,
                SoraStateBindingV1, SoraStateEncryptionV1, SoraStateMutabilityV1,
                SoraStateMutationOperationV1,
            },
            sorafs::pin_registry::ManifestDigest,
            transaction::{SignedTransaction, TransactionBuilder, error::TransactionLimitError},
        };
        use iroha_logger::Level;
        use iroha_model_base::domain::DomainId;
        use iroha_model_base::metadata::Metadata;
        use iroha_model_base::name::Name;
        use iroha_model_base::peer::PeerId;
        use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
        use iroha_primitives::time::TimeSource;
        use iroha_schema::Ident;
        use iroha_test_samples::{ALICE_ID, gen_account_in};

        use mv::storage::StorageReadOnly;
        use nonzero_ext::nonzero;
        use std::{
            borrow::Cow,
            collections::{BTreeMap, BTreeSet},
            num::{NonZeroU16, NonZeroU32, NonZeroU64},
            path::PathBuf,
            str::FromStr,
            sync::Arc,
            time::Duration,
        };
        include!("block/parallel_account_profile_tests.rs");
        mod native_validation_tests {
            include!("block/native_validation_tests.rs");
        }
        include!("block/post_execution_tail_tests.rs");
        include!("block/sccp_call_site_tests.rs");
        #[test]
        fn amx_deadline_finalizer_preserves_exact_local_refusal_without_rejection() {
            use iroha_data_model::sumeragi_amx::AmxError;

            for original in [
                norito::core::classify_decode_attempt(|| {
                    Err::<(), _>(norito::Error::AllocationFailed { bytes: 57 })
                })
                .unwrap_err(),
                norito::with_decode_limits_scope(
                    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 73, 64),
                    || {
                        norito::core::classify_decode_attempt(|| {
                            norito::core::reserve_decode_allocation(99)
                        })
                    },
                )
                .unwrap_err(),
            ] {
                let expected = original.local_refusal().unwrap();
                let mapped = ValidBlock::amx_deadline_error(AmxError::Resource(original));
                assert!(matches!(
                    &mapped,
                    BlockValidationError::StateStorageAdmission(
                        crate::state::StateStorageAdmissionError::AmxDecode(retained)
                    ) if *retained == expected
                ));
                assert_eq!(
                    map_block_err_to_reason(&mapped),
                    None,
                    "unfinished local deadline output cannot emit a protocol rejection"
                );
            }
            for semantic in [
                AmxError::Encoding("invalid canonical decision".into()),
                AmxError::Record("malformed decision"),
            ] {
                let expected = semantic.to_string();
                let mapped = ValidBlock::amx_deadline_error(semantic);
                assert!(matches!(
                    &mapped,
                    BlockValidationError::ExecutionContextInvalid(retained) if *retained == expected
                ));
                assert_eq!(
                    map_block_err_to_reason(&mapped),
                    Some(Reason::TransactionValidationFailed)
                );
            }
        }

        fn checked_block_signature(
            private_key: &PrivateKey,
            block_hash: HashOf<BlockHeader>,
        ) -> SignatureOf<BlockHeader> {
            SignatureOf::try_from_hash(private_key, block_hash)
                .expect("test block signing should succeed")
        }
        fn checked_seeded_keypair(seed: &[u8], algorithm: Algorithm) -> KeyPair {
            KeyPair::try_from_seed(seed.to_vec(), algorithm)
                .expect("test block seeded keypair should be valid")
        }
        fn checked_da_ack_signature(byte: u8) -> Signature {
            Signature::try_from_bytes(&[byte; 64])
                .expect("checked core block DA acknowledgement signature fixture")
        }
        fn axt_post_snapshot(sub_nonce: u64) -> AxtPolicySnapshot {
            let entries = vec![AxtPolicyBinding {
                dsid: DataSpaceId::new(7),
                policy: AxtPolicyEntry {
                    manifest_root: [0xA7; 32],
                    target_lane: LaneId::new(2),
                    active_handle_era: 3,
                    next_handle_counter: sub_nonce,
                    current_slot: 11,
                },
            }];
            AxtPolicySnapshot {
                version: AxtPolicySnapshot::compute_version(&entries),
                entries,
            }
        }
        #[test]
        fn advertised_axt_post_state_must_equal_deterministic_execution() {
            let computed = axt_post_snapshot(4);
            let forged = axt_post_snapshot(400);
            ValidBlock::validate_advertised_axt_post_state(None, &computed)
                .expect("locally produced blocks have no advertised pre-result snapshot");
            ValidBlock::validate_advertised_axt_post_state(Some(&computed), &computed)
                .expect("the exact deterministic post-state is accepted");
            assert!(matches!(
                ValidBlock::validate_advertised_axt_post_state(Some(&forged), &computed),
                Err(BlockValidationError::AxtEnvelopeValidationFailed(details))
                    if details.reason == AxtRejectReason::PolicyDenied
            ));
        }
        fn raw_block_with_da_sidecars(
            da_commitments: Option<DaCommitmentBundle>,
            da_pin_intents: Option<DaPinIntentBundle>,
        ) -> SignedBlock {
            let signer = crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal);
            let policies = iroha_data_model::da::commitment::DaProofPolicyBundle::new(Vec::new());
            let mut header = BlockHeader::new(nonzero!(2_u64), None, None, 1, 0);
            header.set_da_proof_policies_hash(Some(HashOf::new(&policies)));
            let signature = BlockSignature::new(
                0,
                checked_block_signature(signer.private_key(), header.hash()),
            );
            let mut block = SignedBlock::presigned_with_payload(
                signature,
                BlockPayload {
                    header,
                    external_entrypoints: Vec::new(),
                    execution_context: None,
                    da_commitments: None,
                    da_proof_policies: Some(policies),
                    da_pin_intents: None,
                    npos_consensus_effects: None,
                    global_beacon_pulse: None,
                },
            );
            block.replace_da_sidecars_for_testing(da_commitments, da_pin_intents);
            block
        }
        #[test]
        fn da_sidecar_validation_rejects_noncanonical_empty_bundles() {
            let commitments = raw_block_with_da_sidecars(Some(DaCommitmentBundle::default()), None);
            assert!(matches!(
                ValidBlock::validate_da_sidecar_hashes(&commitments),
                Err(BlockValidationError::NonCanonicalEmptyDaCommitmentBundle)
            ));
            let pin_intents = raw_block_with_da_sidecars(None, Some(DaPinIntentBundle::default()));
            assert!(matches!(
                ValidBlock::validate_da_sidecar_hashes(&pin_intents),
                Err(BlockValidationError::NonCanonicalEmptyDaPinIntentBundle)
            ));
        }
        fn state_confidential_features_at_height(
            state: &State,
            height: u64,
        ) -> Option<ConfidentialFeatureDigest> {
            let view = state.query_view();
            let digest = compute_confidential_feature_digest(view.world(), view.zk(), height);
            (!digest.is_empty()).then_some(digest)
        }
        fn with_current_state_da_sidecars(
            mut builder: BlockBuilder<Chained>,
            state: &State,
        ) -> BlockBuilder<Chained> {
            let height = builder.0.header.height().get();
            if builder.0.execution_context.is_none() && !builder.0.transactions.is_empty() {
                let context = default_test_execution_context(&builder.0.transactions);
                builder = builder.with_execution_context(Some(context));
            }
            let nexus = state.nexus_snapshot();
            let proof_policies = crate::da::active_proof_policy_bundle_at_height(&nexus, height);
            builder
                .with_da_proof_policies(Some(proof_policies))
                .with_confidential_features(state_confidential_features_at_height(state, height))
        }
        fn with_current_state_confidential_features(
            mut block: SignedBlock,
            state: &State,
            signers: &[(u64, &PrivateKey)],
        ) -> SignedBlock {
            let mut header = block.header();
            header.set_confidential_features(state_confidential_features_at_height(
                state,
                header.height().get(),
            ));
            block.replace_header_for_testing(header);
            let block_hash = block.hash();
            let signatures = iroha_data_model::block::BlockSignatures::try_from_iter(
                signers.iter().map(|(index, private_key)| {
                    BlockSignature::new(*index, checked_block_signature(private_key, block_hash))
                }),
            )
            .expect("at most 31 block signatures");
            block
                .replace_signatures(signatures)
                .expect("replace signatures after refreshing confidential test sidecar");
            block
        }
        fn install_test_lane_manifests_for_keypairs(state: &State, keypairs: &[KeyPair]) {
            let validators = keypairs
                .iter()
                .map(|keypair| AccountId::new(keypair.public_key().clone()))
                .collect::<Vec<_>>();
            let validator_bindings = validators
                .iter()
                .map(
                    |validator| crate::governance::manifest::ManifestValidatorBinding {
                        validator: validator.clone(),
                        peer_id: PeerId::from(
                            validator
                                .try_signatory()
                                .expect("manifest test validators must be single-signatory")
                                .clone(),
                        ),
                        torii_url: None,
                    },
                )
                .collect::<Vec<_>>();
            let nexus = state.nexus_snapshot();
            let bindings_by_lane = nexus
                .lane_catalog
                .lanes()
                .iter()
                .map(|lane| (lane.id, validator_bindings.clone()))
                .collect();
            state.install_lane_manifests_for_testing(&Arc::new(
                crate::governance::manifest::test_support::validator_registry(
                    &nexus.lane_catalog,
                    &nexus.governance,
                    bindings_by_lane,
                ),
            ));
        }
        fn insert_consensus_key(
            world: &mut World,
            name: &str,
            keypair: &KeyPair,
            activation_height: u64,
            expiry_height: Option<u64>,
            status: ConsensusKeyStatus,
        ) -> ConsensusKeyId {
            let peer_id = PeerId::from(keypair.public_key().clone());
            let mut peers = world.peers.block();
            let _ = peers.get_mut().push(peer_id);
            peers.commit();
            let id = ConsensusKeyId::new(
                ConsensusKeyRole::Validator,
                Ident::from_str(name).expect("consensus key name parses"),
            );
            let pop = match keypair
                .public_key()
                .try_algorithm()
                .expect("fixture public key must be valid")
            {
                Algorithm::BlsNormal => Some(
                    iroha_crypto::bls_normal_pop_prove(keypair.private_key())
                        .expect("pop for consensus key"),
                ),
                Algorithm::BlsSmall => Some(
                    iroha_crypto::bls_small_pop_prove(keypair.private_key())
                        .expect("pop for consensus key"),
                ),
                _ => None,
            };
            let record = ConsensusKeyRecord {
                id: id.clone(),
                public_key: keypair.public_key().clone(),
                pop,
                activation_height,
                expiry_height,
                replaces: None,
                status,
            };
            world.consensus_keys.insert(id.clone(), record.clone());
            let pk_label = record.public_key.to_string();
            world
                .consensus_keys_by_pk
                .insert(pk_label, vec![id.clone()]);
            id
        }
        #[cfg(feature = "bls")]
        #[test]
        fn bls_normal_public_key_check_uses_checked_algorithm_access() {
            let bls_key = checked_seeded_keypair(b"checked-bls-key", Algorithm::BlsNormal);
            let ed25519_key = checked_seeded_keypair(b"checked-ed25519-key", Algorithm::Ed25519);
            assert!(ValidBlock::is_bls_normal_public_key(bls_key.public_key()));
            assert!(!ValidBlock::is_bls_normal_public_key(
                ed25519_key.public_key()
            ));
        }
        include!("block/soracloud_validation_tests.rs");
        /// Build an ordinary successor from original genesis before removing its routing context.
        fn signed_contextless_routing_fixture(
            label: &str,
            workers: usize,
        ) -> (crate::sumeragi::test_chain::CertifiedTestChain, SignedBlock) {
            use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};

            let (authority, signer) = gen_account_in(label);
            let account = Account::new(authority.clone()).build(&authority);
            let mut key_pairs = (0..4)
                .map(|_| crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal))
                .collect::<Vec<_>>();
            key_pairs.sort_by_key(|key| PeerId::new(key.public_key().clone()));
            let mut config = TestChainConfig::new(World::with([], [account], []), 0);
            config.chain_id = label
                .parse()
                .expect("canonical routing fixture chain label");
            config.pipeline.workers = workers;
            config.validator_keys = Some(key_pairs.clone());
            let chain =
                CertifiedTestChain::start(config).expect("original routing fixture genesis");
            let state = chain.state();
            let (_, time_source) = TimeSource::new_mock(Duration::from_millis(1));
            let transaction = TransactionBuilder::new_with_time_source(
                chain.network_id(),
                authority,
                &time_source,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, format!("{label}-0"))])
            .sign(signer.private_key());
            let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(transaction));
            let previous = state
                .view()
                .latest_block()
                .expect("original block read attempt")
                .expect("original genesis parent");
            let builder = BlockBuilder::new_with_time_source(vec![accepted], time_source)
                .chain(0, Some(&previous));
            let block = with_current_state_da_sidecars(builder, state)
                .sign(key_pairs[0].private_key())
                .unpack(|_| {});
            (chain, block.into())
        }
        fn assert_contextless_unknown_default_route_is_pristine(
            state: &State,
            block: &mut SignedBlock,
            unknown_dataspace: DataSpaceId,
        ) {
            let entrypoint_hash = block
                .external_entrypoints_cloned()
                .next()
                .expect("routing failure fixture has one entrypoint")
                .hash();
            let (mut state_block, _state_block_recorder) =
                crate::block::ValidBlock::start_component_execution(&block.clone().into(), state)
                    .expect("original writer-first component execution");
            assert!(
                state_block
                    .nexus
                    .dataspace_catalog
                    .by_id(unknown_dataspace)
                    .is_none()
            );
            state_block.nexus.routing_policy.default_dataspace = unknown_dataspace;
            assert_eq!(
                state_block.transactions.get(&entrypoint_hash),
                None,
                "routing failure fixture starts without a transaction-index row"
            );
            let error = ValidBlock::execute_and_record_canonical_outputs(
                block,
                &mut state_block,
                None,
                None,
            )
            .expect_err(
                "a missing authenticated route must refuse the source before policy routing",
            );
            assert!(
                matches!(&error, BlockValidationError::ExecutionContextInvalid(reason)
                if reason == "Network source has an invalid execution context"),
                "contextless source must fail before routing or execution: {error:?}"
            );
            assert_eq!(
                state_block.transactions.get(&entrypoint_hash),
                None,
                "failed routing must not stage a transaction-index row"
            );
            assert!(
                !block.has_results(),
                "failed routing must not attach transaction results or routed metadata"
            );
            assert!(
                block.execution_context().is_none(),
                "contextless routing must not fabricate a lane-0/dataspace-0 context"
            );
            assert!(
                !block.has_results(),
                "failed routing must not attach unauthenticated execution outputs"
            );
        }
        #[test]
        fn contextless_parallel_validation_fails_before_routing_metadata_or_index_mutation() {
            let (chain, mut block) =
                signed_contextless_routing_fixture("contextless-parallel-routing-failure", 2);
            let state = chain.state();
            let unknown_dataspace = DataSpaceId::new(4_242);
            block.set_execution_context(None);

            assert_contextless_unknown_default_route_is_pristine(
                state,
                &mut block,
                unknown_dataspace,
            );
        }
        #[test]
        fn contextless_sealed_source_fails_before_routing_metadata_or_index_mutation() {
            let (chain, mut block) =
                signed_contextless_routing_fixture("contextless-sequential-routing-failure", 1);
            let state = chain.state();
            let unknown_dataspace = DataSpaceId::new(4_243);
            let signed = block
                .external_transactions()
                .next()
                .expect("signed fixture source")
                .clone();
            let reveal = iroha_data_model::transaction::signed::SealedTransactionReveal::new(
                Hash::new(b"unresolved sealed routing source"),
                signed,
                [0; 32],
            );
            block.set_external_entrypoints(vec![TransactionEntrypoint::SealedReveal(reveal)]);
            block.set_execution_context(None);
            assert!(
                matches!(
                    block.network_entrypoint_at(0),
                    Some(TransactionEntrypoint::SealedReveal(_))
                ),
                "a sealed Network source must pass through the same frozen routing gate"
            );

            assert_contextless_unknown_default_route_is_pristine(
                state,
                &mut block,
                unknown_dataspace,
            );
        }
        fn future_created_autoscale_nexus(
            state: &State,
            lane_id: LaneId,
            created_height: u64,
        ) -> iroha_config::parameters::actual::Nexus {
            let mut elastic_lane = LaneConfig {
                id: lane_id,
                alias: format!("elastic-lane-{}", lane_id.as_u32()),
                ..LaneConfig::default()
            };
            elastic_lane
                .metadata
                .insert("autoscale.managed".to_owned(), "true".to_owned());
            elastic_lane.metadata.insert(
                "autoscale.created_height".to_owned(),
                created_height.to_string(),
            );
            crate::state::attach_synthetic_autoscale_committee_for_test(&mut elastic_lane);
            let lane_catalog =
                LaneCatalog::new(nonzero!(2_u32), vec![LaneConfig::default(), elastic_lane])
                    .expect("future-created autoscale lane catalog");
            let mut nexus = state.nexus_snapshot();
            nexus.autoscale.enabled = true;
            nexus.autoscale.min_lane_id = nonzero!(1_u32);
            nexus.autoscale.max_lane_id_exclusive = nonzero!(3_u32);
            nexus.lane_config =
                iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog);
            nexus.lane_catalog = lane_catalog;
            nexus
        }
        #[test]
        fn signature_verification_ok() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(7)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let block_hash = block.as_ref().hash();
            key_pairs
                .iter()
                .enumerate()
                // Include only peers in validator set
                .take(topology.min_votes_for_commit())
                // Skip leader since already singed
                .skip(1)
                .filter(|(i, _)| *i != 4) // Skip proxy tail
                .map(|(i, key_pair)| {
                    BlockSignature::new(
                        i as u64,
                        checked_block_signature(key_pair.private_key(), block_hash),
                    )
                })
                .try_for_each(|signature| block.add_signature(signature, &topology))
                .expect("Failed to add signatures");
            block.sign(&key_pairs[4], &topology);
            let _ = block
                .commit(&topology, crate::block::reserve_block_for_tests())
                .unpack(|_| {})
                .unwrap();
        }
        #[test]
        fn signature_verification_consensus_not_required_ok() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(1)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let block = ValidBlock::new_dummy(key_pairs[0].private_key());
            assert!(
                block
                    .commit(&topology, crate::block::reserve_block_for_tests())
                    .unpack(|_| {})
                    .is_ok()
            );
        }
        /// Check requirement of having at least $2f + 1$ signatures in $3f + 1$ network
        #[test]
        fn signature_verification_not_enough_signatures() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(7)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            block.sign(&key_pairs[4], &topology);
            let err = block
                .commit(&topology, crate::block::reserve_block_for_tests())
                .unpack(|_| {})
                .unwrap_err()
                .1;
            let BlockValidationError::SignatureVerification(actual) = err.as_ref() else {
                panic!("unexpected validation failure: {err:?}");
            };
            assert_eq!(
                actual,
                &SignatureVerificationError::NotEnoughSignatures {
                    votes_count: 2,
                    min_votes_for_commit: topology.min_votes_for_commit(),
                }
            );
        }
        #[test]
        fn four_node_quorum_rejects_two_commit_signers() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(4)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            assert_eq!(topology.min_votes_for_commit(), 3);
            // Leader is signed by constructor; add only the proxy tail.
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            block.sign(&key_pairs[2], &topology);
            let tally = commit_signature_tally(block.as_ref(), &topology);
            assert_eq!(tally.counted, 2);
            assert_eq!(tally.present, 2);
            let err = block
                .commit(&topology, crate::block::reserve_block_for_tests())
                .unpack(|_| {})
                .unwrap_err()
                .1;
            let BlockValidationError::SignatureVerification(actual) = err.as_ref() else {
                panic!("unexpected validation failure: {err:?}");
            };
            assert_eq!(
                actual,
                &SignatureVerificationError::NotEnoughSignatures {
                    votes_count: 2,
                    min_votes_for_commit: 3
                }
            );
        }
        #[test]
        fn four_node_quorum_accepts_three_commit_signers() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(4)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            assert_eq!(topology.min_votes_for_commit(), 3);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            block.sign(&key_pairs[1], &topology); // validator
            block.sign(&key_pairs[2], &topology); // proxy tail
            let tally = commit_signature_tally(block.as_ref(), &topology);
            assert_eq!(tally.counted, 3);
            assert_eq!(tally.present, 3);
            assert_eq!(tally.set_b_signatures, 0);
            assert!(
                block
                    .commit(&topology, crate::block::reserve_block_for_tests())
                    .unpack(|_| {})
                    .is_ok()
            );
        }
        #[cfg(feature = "bls")]
        #[test]
        fn commit_with_signers_accepts_full_roster_quorum() {
            // Six-node topology (min_votes_for_commit = 5). Provide a quorum that excludes the
            // leader (0) but still spans the full roster beyond the first commit set.
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(6)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            assert_eq!(topology.min_votes_for_commit(), 5);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            // Populate the block with commit-role signatures so the QC signer set can omit the
            // leader while still carrying the full commit quorum.
            block.sign(&key_pairs[1], &topology);
            block.sign(&key_pairs[2], &topology);
            block.sign(&key_pairs[3], &topology);
            block.sign(&key_pairs[4], &topology);
            block.sign(&key_pairs[5], &topology);
            let signers: BTreeSet<_> = [1_u32, 2_u32, 3_u32, 4_u32, 5_u32].into_iter().collect();
            let result = block
                .commit_with_signers(
                    &topology,
                    &signers,
                    false,
                    crate::block::reserve_block_for_tests(),
                )
                .unpack(|_| {});
            assert!(
                result.is_ok(),
                "quorum signers outside the first commit set should still be accepted: {result:?}"
            );
        }
        #[test]
        fn duplicate_signatures_rejected() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(2)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let block_hash = block.as_ref().hash();
            let mut signatures = BTreeSet::new();
            signatures.insert(BlockSignature::new(
                0,
                checked_block_signature(key_pairs[0].private_key(), block_hash),
            ));
            signatures.insert(BlockSignature::new(
                1,
                checked_block_signature(key_pairs[1].private_key(), block_hash),
            ));
            // Duplicate index with a different signature payload.
            let spoofing_key = crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal);
            signatures.insert(BlockSignature::new(
                1,
                checked_block_signature(spoofing_key.private_key(), block_hash),
            ));
            let err = block
                .replace_signatures(
                    iroha_data_model::block::BlockSignatures::try_from_iter(signatures)
                        .expect("at most 31 block signatures"),
                    &topology,
                )
                .unpack(|_| {})
                .unwrap_err();
            assert_eq!(
                err,
                SignatureVerificationError::DuplicateSignature { signer: 1 }
            );
            // Original signature set should remain intact after the failed replacement.
            assert_eq!(
                block.as_ref().signatures().count(),
                1,
                "failed replacement must roll back"
            );
        }
        #[test]
        fn proxy_tail_signature_mismatch_rejected() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(2)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let block_hash = block.as_ref().hash();
            let mut signatures = BTreeSet::new();
            signatures.insert(BlockSignature::new(
                0,
                checked_block_signature(key_pairs[0].private_key(), block_hash),
            ));
            // Proxy tail index signed with the wrong key.
            let wrong = crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal);
            signatures.insert(BlockSignature::new(
                1,
                checked_block_signature(wrong.private_key(), block_hash),
            ));
            let err = block
                .replace_signatures(
                    iroha_data_model::block::BlockSignatures::try_from_iter(signatures)
                        .expect("at most 31 block signatures"),
                    &topology,
                )
                .unpack(|_| {})
                .unwrap_err();
            assert_eq!(err, SignatureVerificationError::UnknownSignature);
            // Original leader-only signature remains after rollback.
            assert_eq!(block.as_ref().signatures().count(), 1);
        }
        #[test]
        fn leader_signature_mismatch_rejected() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(3)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let block_hash = block.as_ref().hash();
            let mut signatures = BTreeSet::new();
            // Leader slot signed with validator key instead of the leader's.
            signatures.insert(BlockSignature::new(
                0,
                checked_block_signature(key_pairs[1].private_key(), block_hash),
            ));
            signatures.insert(BlockSignature::new(
                1,
                checked_block_signature(key_pairs[1].private_key(), block_hash),
            ));
            signatures.insert(BlockSignature::new(
                2,
                checked_block_signature(key_pairs[2].private_key(), block_hash),
            ));
            let err = block
                .replace_signatures(
                    iroha_data_model::block::BlockSignatures::try_from_iter(signatures)
                        .expect("at most 31 block signatures"),
                    &topology,
                )
                .unpack(|_| {})
                .unwrap_err();
            assert_eq!(err, SignatureVerificationError::UnknownSignature);
            assert_eq!(block.as_ref().signatures().count(), 1);
        }
        #[test]
        fn set_b_signatures_contribute_to_quorum() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(4)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            // Leader signature is included by constructor
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            block.sign(&key_pairs[1], &topology); // validator
            block.sign(&key_pairs[3], &topology); // set B
            assert!(
                block
                    .commit(&topology, crate::block::reserve_block_for_tests())
                    .unpack(|_| {})
                    .is_ok(),
                "set B signatures should count toward quorum without requiring proxy tail"
            );
        }
        #[test]
        fn set_b_signature_mismatch_rejected() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(5)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let block_hash = block.as_ref().hash();
            // Set B signature forged with the wrong key should invalidate the block.
            let bogus_set_b = crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal);
            let mut signatures = BTreeSet::new();
            signatures.insert(BlockSignature::new(
                0,
                checked_block_signature(key_pairs[0].private_key(), block_hash),
            ));
            signatures.insert(BlockSignature::new(
                1,
                checked_block_signature(key_pairs[1].private_key(), block_hash),
            ));
            signatures.insert(BlockSignature::new(
                2,
                checked_block_signature(key_pairs[2].private_key(), block_hash),
            ));
            signatures.insert(BlockSignature::new(
                3,
                checked_block_signature(bogus_set_b.private_key(), block_hash),
            ));
            let err = block
                .replace_signatures(
                    iroha_data_model::block::BlockSignatures::try_from_iter(signatures)
                        .expect("at most 31 block signatures"),
                    &topology,
                )
                .unpack(|_| {})
                .unwrap_err();
            assert_eq!(err, SignatureVerificationError::UnknownSignature);
            // Replacement should fail and leave the original leader-only signature set.
            assert_eq!(block.as_ref().signatures().count(), 1);
        }
        #[test]
        fn commit_signature_tally_tracks_present_and_counted_roles() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(4)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let block_hash = block.as_ref().hash();
            // Proxy tail signature should count toward quorum.
            block
                .add_signature(
                    BlockSignature::new(
                        2,
                        checked_block_signature(key_pairs[2].private_key(), block_hash),
                    ),
                    &topology,
                )
                .expect("proxy tail signature");
            // Set B signature counts toward quorum.
            block.sign(&key_pairs[3], &topology);
            let tally = commit_signature_tally(block.as_ref(), &topology);
            assert_eq!(tally.present, 3);
            assert_eq!(tally.counted, 3);
            assert_eq!(tally.set_b_signatures, 1);
        }
        #[test]
        fn add_signature_rejects_leader_slot_without_panicking() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(3)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let block_hash = block.as_ref().hash();
            let leader_signature = BlockSignature::new(
                0,
                checked_block_signature(key_pairs[0].private_key(), block_hash),
            );
            assert_eq!(
                block.add_signature(leader_signature, &topology),
                Err(SignatureVerificationError::UnknownSignatory)
            );
        }
        #[test]
        fn replace_signatures_rolls_back_on_failure() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(3)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let block_hash = block.as_ref().hash();
            // Start from a valid quorum.
            block
                .add_signature(
                    BlockSignature::new(
                        1,
                        checked_block_signature(key_pairs[1].private_key(), block_hash),
                    ),
                    &topology,
                )
                .expect("validator signature");
            block.sign(&key_pairs[2], &topology);
            assert!(
                block
                    .clone()
                    .commit(&topology, crate::block::reserve_block_for_tests())
                    .unpack(|_| {})
                    .is_ok()
            );
            let original = block.as_ref().signatures().cloned().collect::<Vec<_>>();
            // Replacement below quorum should fail and restore the original set.
            let mut replacement = BTreeSet::new();
            replacement.insert(BlockSignature::new(
                0,
                checked_block_signature(key_pairs[0].private_key(), block_hash),
            ));
            replacement.insert(BlockSignature::new(
                1,
                checked_block_signature(key_pairs[1].private_key(), block_hash),
            ));
            let err = block
                .replace_signatures(
                    iroha_data_model::block::BlockSignatures::try_from_iter(replacement)
                        .expect("at most 31 block signatures"),
                    &topology,
                )
                .unpack(|_| {})
                .unwrap_err();
            assert_eq!(
                err,
                SignatureVerificationError::NotEnoughSignatures {
                    votes_count: 2,
                    min_votes_for_commit: 3
                }
            );
            let restored: Vec<_> = block.as_ref().signatures().cloned().collect();
            assert_eq!(restored, original);
        }
        #[test]
        fn consensus_key_lifecycle_requires_proxy_tail_entry() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(3)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut block =
                ValidBlock::new_dummy_and_modify_header(key_pairs[0].private_key(), |header| {
                    header.set_height(nonzero!(5_u64));
                });
            block.sign(&key_pairs[1], &topology);
            block.sign(&key_pairs[2], &topology);
            let mut world = World::new();
            insert_consensus_key(
                &mut world,
                "leader",
                &key_pairs[0],
                1,
                None,
                ConsensusKeyStatus::Active,
            );
            insert_consensus_key(
                &mut world,
                "validator",
                &key_pairs[1],
                1,
                None,
                ConsensusKeyStatus::Active,
            );
            let kura = Kura::blank_kura_for_testing();
            let query = LiveQueryStore::start_test();
            let state = State::new_for_testing(world, kura, query);
            let view = state.view();
            let err = ValidBlock::enforce_consensus_key_lifecycle(block.as_ref(), &topology, &view)
                .expect_err("missing proxy tail consensus key should be rejected");
            assert_eq!(err, SignatureVerificationError::InactiveConsensusKey);
        }
        #[test]
        fn validate_signatures_subset_rejects_missing_pop() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(2)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let mut world = World::new();
            let id = ConsensusKeyId::new(
                ConsensusKeyRole::Validator,
                Ident::from_str("leader").expect("consensus key name parses"),
            );
            let record = ConsensusKeyRecord {
                id: id.clone(),
                public_key: key_pairs[0].public_key().clone(),
                pop: None,
                activation_height: 1,
                expiry_height: None,
                replaces: None,
                status: ConsensusKeyStatus::Active,
            };
            world.consensus_keys.insert(id.clone(), record.clone());
            world
                .consensus_keys_by_pk
                .insert(record.public_key.to_string(), vec![id.clone()]);
            let kura = Kura::blank_kura_for_testing();
            let query = LiveQueryStore::start_test();
            let state = State::new_for_testing(world, kura, query);
            let view = state.view();
            let err = ValidBlock::validate_signatures_subset(block.as_ref(), &topology, &view)
                .expect_err("missing pop should be rejected");
            assert_eq!(err, SignatureVerificationError::MissingPop);
        }
        #[test]
        fn validate_signatures_subset_rejects_all_zero_signature_material_before_aggregate() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(2)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            block
                .block
                .replace_signatures(
                    iroha_data_model::block::BlockSignatures::try_from_iter([BlockSignature::new(
                        0,
                        SignatureOf::from_signature(iroha_crypto::Signature::from_bytes(
                            &[0_u8; 96],
                        )),
                    )])
                    .expect("at most 31 block signatures"),
                )
                .expect("replace block signature fixture");
            let mut world = World::new();
            insert_consensus_key(
                &mut world,
                "leader",
                &key_pairs[0],
                0,
                None,
                ConsensusKeyStatus::Active,
            );
            let kura = Kura::blank_kura_for_testing();
            let query = LiveQueryStore::start_test();
            let state = State::new_for_testing(world, kura, query);
            let view = state.view();
            let err = ValidBlock::validate_signatures_subset(block.as_ref(), &topology, &view)
                .expect_err("all-zero block signature payload must reject before aggregation");
            assert_eq!(err, SignatureVerificationError::UnknownSignature);
        }
        #[test]
        fn validate_signatures_subset_accepts_without_consensus_registry() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(2)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let kura = Kura::blank_kura_for_testing();
            let query = LiveQueryStore::start_test();
            let state = State::new_for_testing(World::new(), kura, query);
            let view = state.view();
            ValidBlock::validate_signatures_subset(block.as_ref(), &topology, &view)
                .expect("empty consensus key registry should use direct signature checks");
        }
        #[test]
        fn consensus_key_lifecycle_honours_grace_windows() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(3)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut params = iroha_data_model::parameter::Parameters::default();
            params.sumeragi.key_overlap_grace_blocks = 2;
            params.sumeragi.key_expiry_grace_blocks = 1;
            let mut world = World::new();
            world.parameters = mv::cell::Cell::new(
                crate::state::StateParameters::try_from(params).expect("valid fixture parameters"),
            );
            insert_consensus_key(
                &mut world,
                "leader",
                &key_pairs[0],
                2,
                Some(5),
                ConsensusKeyStatus::Active,
            );
            insert_consensus_key(
                &mut world,
                "validator",
                &key_pairs[1],
                2,
                Some(5),
                ConsensusKeyStatus::Active,
            );
            insert_consensus_key(
                &mut world,
                "proxy",
                &key_pairs[2],
                2,
                Some(5),
                ConsensusKeyStatus::Retiring,
            );
            let kura = Kura::blank_kura_for_testing();
            let query = LiveQueryStore::start_test();
            let state = State::new_for_testing(world, kura, query);
            let view = state.view();
            let mut within_grace =
                ValidBlock::new_dummy_and_modify_header(key_pairs[0].private_key(), |header| {
                    header.set_height(nonzero!(6_u64));
                });
            within_grace.sign(&key_pairs[1], &topology);
            within_grace.sign(&key_pairs[2], &topology);
            assert!(
                ValidBlock::enforce_consensus_key_lifecycle(
                    within_grace.as_ref(),
                    &topology,
                    &view
                )
                .is_ok()
            );
            let mut beyond_grace =
                ValidBlock::new_dummy_and_modify_header(key_pairs[0].private_key(), |header| {
                    header.set_height(nonzero!(7_u64));
                });
            beyond_grace.sign(&key_pairs[1], &topology);
            beyond_grace.sign(&key_pairs[2], &topology);
            let err = ValidBlock::enforce_consensus_key_lifecycle(
                beyond_grace.as_ref(),
                &topology,
                &view,
            )
            .expect_err("expired consensus keys should be rejected after grace");
            assert_eq!(err, SignatureVerificationError::InactiveConsensusKey);
        }
        #[test]
        fn consensus_key_lifecycle_falls_back_for_stale_pk_index() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(3)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut world = World::new();
            insert_consensus_key(
                &mut world,
                "leader-active",
                &key_pairs[0],
                1,
                None,
                ConsensusKeyStatus::Active,
            );
            insert_consensus_key(
                &mut world,
                "validator",
                &key_pairs[1],
                1,
                None,
                ConsensusKeyStatus::Active,
            );
            insert_consensus_key(
                &mut world,
                "proxy",
                &key_pairs[2],
                1,
                None,
                ConsensusKeyStatus::Active,
            );
            // Simulate a stale pk → id index entry that omits the active record.
            let stale_id = ConsensusKeyId::new(
                ConsensusKeyRole::Validator,
                Ident::from_str("stale").expect("ident parses"),
            );
            world
                .consensus_keys_by_pk
                .insert(key_pairs[0].public_key().to_string(), vec![stale_id]);
            // Active record remains available after inserting stale index entry.
            let kura = Kura::blank_kura_for_testing();
            let query = LiveQueryStore::start_test();
            let state = State::new_for_testing(world, kura, query);
            let view = state.view();
            let mut block =
                ValidBlock::new_dummy_and_modify_header(key_pairs[0].private_key(), |header| {
                    header.set_height(nonzero!(3_u64));
                });
            block.sign(&key_pairs[1], &topology);
            block.sign(&key_pairs[2], &topology);
            assert!(
                ValidBlock::enforce_consensus_key_lifecycle(block.as_ref(), &topology, &view)
                    .is_ok()
            );
        }
        #[test]
        fn validation_profiles_always_carry_an_explicit_consensus_mode() {
            use iroha_data_model::block::consensus::ConsensusMode;
            // World/Parameters defaults do not authenticate a consensus mode.
            assert!(
                World::new()
                    .view()
                    .sumeragi_npos_parameters()
                    .expect("original policy decoder completes")
                    .is_none()
            );
            assert_eq!(
                ConsensusValidationProfile::SumeragiGenesis {
                    consensus_mode: ConsensusMode::Npos,
                    root_scope: iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture::new().root_scope(),
                }
                .authoritative_consensus_mode(),
                ConsensusMode::Npos,
                "an explicitly authenticated NPoS mode must not be downgraded",
            );
        }
        #[test]
        fn validate_da_sidecars_rejects_missing_policy_body_under_signed_hash() {
            let signer = crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal);
            let mut block: SignedBlock = BlockBuilder::new(Vec::new())
                .chain(0, None)
                .sign(signer.private_key())
                .unpack(|_| {})
                .into();
            let signed_header = block.header();
            assert!(block.da_proof_policies().is_some());
            block.set_da_proof_policies(None);
            block.replace_header_for_testing(signed_header);
            assert!(matches!(
                ValidBlock::validate_da_sidecar_hashes(&block),
                Err(BlockValidationError::DaProofPolicySidecarHashMismatch {
                    expected: None,
                    actual: Some(_),
                })
            ));
        }
        #[test]
        fn validate_da_sidecars_rejects_policy_body_substitution() {
            let signer = crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal);
            let mut block: SignedBlock = BlockBuilder::new(Vec::new())
                .chain(0, None)
                .sign(signer.private_key())
                .unpack(|_| {})
                .into();
            let signed_header = block.header();
            let original = block
                .da_proof_policies()
                .expect("builder must attach default policies");
            let mut changed_policies = original.policies().to_vec();
            changed_policies[0].alias.push_str("-substituted");
            let substituted = DaProofPolicyBundle::from_untrusted_parts(
                original.version(),
                original.policy_hash(),
                changed_policies,
            );
            block.set_da_proof_policies(Some(substituted));
            block.replace_header_for_testing(signed_header);
            assert!(matches!(
                ValidBlock::validate_da_sidecar_hashes(&block),
                Err(BlockValidationError::DaProofPolicySidecarHashMismatch {
                    expected: Some(_),
                    actual: Some(_),
                })
            ));
        }
        #[test]
        fn canonical_output_execution_releases_the_original_recorder_between_attempts() {
            let (alice_id, alice_keypair) = gen_account_in("wonderland");
            let domain_id: DomainId =
                DomainId::try_new("wonderland", "universal").expect("valid domain");
            let account = Account::new(alice_id.clone()).build(&alice_id);
            let domain = Domain::new(domain_id).build(&alice_id);
            let world = World::with([domain], [account], []);
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(world, kura, query_handle);
            let native_chain = crate::block::tests::component_chain(state);
            let state = native_chain.state();
            let (max_clock_drift, tx_limits) = {
                let state_view = state.world.view();
                let params = state_view.parameters();
                (params.sumeragi().max_clock_drift(), params.transaction())
            };
            let tx = TransactionBuilder::new(
                state.network_id,
                alice_id,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "test".to_string())])
            .sign(alice_keypair.private_key());
            let crypto_cfg = state.crypto();
            let (_clock, time_source) = TimeSource::new_mock(tx.creation_time());
            let tx = AcceptedTransaction::accept_with_time_source(
                tx,
                &state.network_id,
                max_clock_drift,
                tx_limits,
                crypto_cfg.as_ref(),
                &time_source,
            )
            .expect("valid tx");
            let new_block = BlockBuilder::new(vec![tx.clone()])
                .chain(
                    0,
                    state
                        .view()
                        .latest_block()
                        .expect("original block read attempt")
                        .as_deref(),
                )
                .sign(alice_keypair.private_key())
                .unpack(|_| {});
            let mut first_block: SignedBlock = new_block.clone().into();
            let (mut state_block, state_block_recorder) =
                crate::block::ValidBlock::start_component_execution(
                    &first_block.clone().into(),
                    state,
                )
                .expect("original writer-first component execution");
            ValidBlock::execute_and_record_canonical_outputs(
                &mut first_block,
                &mut state_block,
                None,
                None,
            )
            .expect("first original execution should attach transaction results");
            let first_results: Vec<_> = first_block
                .output_results()
                .map(|result| result.as_ref().is_ok())
                .collect();
            drop(state_block);
            drop(state_block_recorder);
            let mut second_block: SignedBlock = new_block.into();
            let (mut state_block, state_block_recorder) =
                crate::block::ValidBlock::start_component_execution(
                    &second_block.clone().into(),
                    state,
                )
                .expect("original writer-first component execution");
            ValidBlock::execute_and_record_canonical_outputs(
                &mut second_block,
                &mut state_block,
                None,
                None,
            )
            .expect("a new original recorder should attach transaction results");
            let second_results: Vec<_> = second_block
                .output_results()
                .map(|result| result.as_ref().is_ok())
                .collect();
            assert_eq!(first_results, vec![true]);
            assert_eq!(first_results, second_results);
            drop(state_block);
            drop(state_block_recorder);
            assert_eq!(
                state.view().height(),
                usize::try_from(native_chain.height()).expect("fixture value fits usize")
            );
        }
        #[test]
        fn maps_signature_verification_errors() {
            assert_eq!(
                map_sig_err_to_reason(&SignatureVerificationError::NotEnoughSignatures {
                    votes_count: 1,
                    min_votes_for_commit: 2
                }),
                Reason::InsufficientBlockSignatures
            );
            assert_eq!(
                map_sig_err_to_reason(&SignatureVerificationError::UnknownSignatory),
                Reason::UnknownBlockSignatory
            );
            assert_eq!(
                map_sig_err_to_reason(&SignatureVerificationError::DuplicateSignature {
                    signer: 0
                }),
                Reason::InvalidBlockSignature
            );
            assert_eq!(
                map_sig_err_to_reason(&SignatureVerificationError::UnknownSignature),
                Reason::InvalidBlockSignature
            );
            assert_eq!(
                map_sig_err_to_reason(&SignatureVerificationError::MissingPop),
                Reason::InvalidBlockSignature
            );
            assert_eq!(
                map_sig_err_to_reason(&SignatureVerificationError::ProxyTailMissing),
                Reason::ProxyTailSignatureMissing
            );
            assert_eq!(
                map_sig_err_to_reason(&SignatureVerificationError::LeaderMissing),
                Reason::LeaderSignatureMissing
            );
            assert_eq!(
                map_sig_err_to_reason(&SignatureVerificationError::Other),
                Reason::OtherSignatureError
            );
        }
        /// Check quorum requirement when proxy tail is missing.
        #[test]
        fn signature_verification_rejects_insufficient_quorum_without_proxy_tail() {
            let key_pairs = core::iter::repeat_with(|| {
                crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal)
            })
            .take(7)
            .collect::<Vec<_>>();
            let topology = test_topology_with_keys(&key_pairs);
            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let block_hash = block.as_ref().hash();
            key_pairs
                .iter()
                .enumerate()
                // Include only peers in validator set
                .take(topology.min_votes_for_commit())
                // Skip leader since already singed
                .skip(1)
                .filter(|(i, _)| *i != 4) // Skip proxy tail
                .map(|(i, key_pair)| {
                    BlockSignature::new(
                        i as u64,
                        checked_block_signature(key_pair.private_key(), block_hash),
                    )
                })
                .try_for_each(|signature| block.add_signature(signature, &topology))
                .expect("Failed to add signatures");
            let err = block
                .commit(&topology, crate::block::reserve_block_for_tests())
                .unpack(|_| {})
                .unwrap_err()
                .1;
            let BlockValidationError::SignatureVerification(actual) = err.as_ref() else {
                panic!("unexpected validation failure: {err:?}");
            };
            assert_eq!(
                actual,
                &SignatureVerificationError::NotEnoughSignatures {
                    votes_count: topology.min_votes_for_commit() - 1,
                    min_votes_for_commit: topology.min_votes_for_commit(),
                }
            );
        }
        #[test]
        fn maps_block_validation_errors() {
            for reason in [
                ivm::error::ExecutionDeferral::AllocationUnavailable,
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity,
                ivm::error::ExecutionDeferral::VerifierArtifactsUnavailable,
                ivm::error::ExecutionDeferral::LocalInvariantViolation,
            ] {
                assert_eq!(
                    map_block_err_to_reason(&BlockValidationError::ExecutionDeferred(
                        reason.into()
                    )),
                    None
                );
            }
            assert_eq!(
                map_block_err_to_reason(&BlockValidationError::MerkleRootMismatch),
                Some(Reason::MerkleRootMismatch)
            );
            assert_eq!(
                map_block_err_to_reason(&BlockValidationError::EmptyBlock),
                Some(Reason::EmptyBlock)
            );
            assert_eq!(
                map_block_err_to_reason(&BlockValidationError::DuplicateTransactions),
                Some(Reason::TransactionValidationFailed)
            );
            assert_eq!(
                map_block_err_to_reason(&BlockValidationError::TooManyTransactions {
                    actual: 2,
                    max: 1
                }),
                Some(Reason::TransactionValidationFailed)
            );
            assert_eq!(
                map_block_err_to_reason(&BlockValidationError::SignatureVerification(
                    SignatureVerificationError::LeaderMissing
                )),
                Some(Reason::LeaderSignatureMissing)
            );
            let network_id = |seed| {
                NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
                    Hash::prehashed([seed; Hash::LENGTH]),
                ))
            };
            let chain_mismatch = BlockValidationError::TransactionAccept(
                AcceptTransactionFail::TransactionDomainMismatch(Mismatch {
                    expected: iroha_data_model::transaction::TransactionDomain::Network(
                        network_id(0xA1),
                    ),
                    actual: iroha_data_model::transaction::TransactionDomain::Network(network_id(
                        0xB2,
                    )),
                }),
            );
            assert_eq!(
                map_block_err_to_reason(&chain_mismatch),
                Some(Reason::TransactionValidationFailed)
            );
            let tx_limit = BlockValidationError::TransactionAccept(
                AcceptTransactionFail::TransactionLimit(TransactionLimitError {
                    reason: "too big".into(),
                }),
            );
            assert_eq!(
                map_block_err_to_reason(&tx_limit),
                Some(Reason::TransactionValidationFailed)
            );
            assert_eq!(
                map_block_err_to_reason(&BlockValidationError::InvalidGenesis(
                    InvalidGenesisError::RejectedOutput(GenesisOutputRejection {
                        output_index: 0,
                        reason: Box::new(TransactionRejectionReason::Validation(
                            iroha_data_model::ValidationFail::NotPermitted(
                                "rejected genesis mapping fixture".into()
                            ),
                        )),
                    })
                )),
                Some(Reason::InvalidGenesis)
            );
            assert_eq!(
                map_block_err_to_reason(&BlockValidationError::ConfidentialFeaturesMismatch {
                    expected: None,
                    actual: None
                }),
                Some(Reason::ConfidentialFeatureDigestMismatch)
            );
            let policy_err = BlockValidationError::ProofPolicyHashMismatch {
                expected: HashOf::from_untyped_unchecked(Hash::prehashed([1; Hash::LENGTH])),
                actual: None,
            };
            assert_eq!(
                map_block_err_to_reason(&policy_err),
                Some(Reason::DaProofPolicyMismatch)
            );
            assert_eq!(
                map_block_err_to_reason(&BlockValidationError::FinalityAuthorityInvalid(
                    "certificate does not bind the canonical execution".to_owned(),
                )),
                Some(Reason::ConsensusBlockRejection)
            );
        }
        #[test]
        fn maps_transaction_future_error() {
            let err = BlockValidationError::TransactionInTheFuture;
            assert_eq!(
                map_block_err_to_reason(&err),
                Some(Reason::TransactionInTheFuture)
            );
        }
        #[test]
        fn transaction_signature_validation_has_no_bypass_terms() {
            let needles = [
                ["signature", "_", "override"].concat(),
                ["signature", "_", "overrides"].concat(),
                ["skip", "_tx", "_signature", "_validation"].concat(),
                ["trust", "_replay", "_tx", "_signatures"].concat(),
                ["cached", "_stateless", "_ok"].concat(),
            ];
            let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
            let mut pending = vec![src.clone()];
            let mut hits = Vec::new();
            while let Some(path) = pending.pop() {
                let metadata = std::fs::metadata(&path).expect("source path metadata");
                if metadata.is_dir() {
                    for entry in std::fs::read_dir(&path).expect("source directory readable") {
                        pending.push(entry.expect("source directory entry").path());
                    }
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("Rust source readable");
                for needle in &needles {
                    if source.contains(needle) {
                        let relative = path.strip_prefix(&src).unwrap_or(&path);
                        hits.push(format!("{} contains {needle}", relative.display()));
                    }
                }
            }
            assert!(
                hits.is_empty(),
                "forbidden source terms:\n{}",
                hits.join("\n")
            );
        }
        // Direct fragment preserves canonical genesis validation test paths and source order.
        include!("block/canonical_genesis_validation_tests.rs");
        #[test]
        fn check_genesis_block_rejects_parent_hash() {
            use iroha_data_model::prelude::*;
            use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
            let genesis_account = SAMPLE_GENESIS_ACCOUNT_ID.clone();
            let tx = TransactionBuilder::new_genesis(
                genesis_account.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "genesis".to_owned())])
            .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
            let mut block = SignedBlock::genesis(
                vec![tx],
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
                None,
                None,
            );
            let mut header = block.header();
            header.set_prev_block_hash(Some(HashOf::from_untyped_unchecked(Hash::new(
                b"not-a-genesis-parent",
            ))));
            block.replace_header_for_testing(header);
            let signature = BlockSignature::new(
                0,
                checked_block_signature(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(), block.hash()),
            );
            block
                .replace_signatures(
                    iroha_data_model::block::BlockSignatures::try_from_iter([signature])
                        .expect("at most 31 block signatures"),
                )
                .expect("replace signature after changing test header");
            assert_eq!(
                check_genesis_block(&block, &genesis_account),
                Err(InvalidGenesisError::InvalidHeader)
            );
        }
        #[test]
        fn resultless_genesis_proposal_is_authenticated_before_execution() {
            use iroha_data_model::prelude::*;
            use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
            let genesis_account = SAMPLE_GENESIS_ACCOUNT_ID.clone();
            let transaction = TransactionBuilder::new_genesis(
                genesis_account.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "genesis".to_owned())])
            .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
            let block = SignedBlock::genesis(
                vec![transaction],
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
                None,
                None,
            );
            let proposal = block
                .canonical_resultless_proposal()
                .expect("valid fixture proposal projection");
            assert!(proposal.is_resultless_proposal());
            authenticate_genesis_block_intents(&proposal, &genesis_account)
                .expect("the configured genesis key must authenticate a resultless proposal");
            let mut noncanonical_index = proposal.clone();
            noncanonical_index
                .replace_signatures(
                    iroha_data_model::block::BlockSignatures::try_from_iter([BlockSignature::new(
                        1,
                        checked_block_signature(
                            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
                            noncanonical_index.hash(),
                        ),
                    )])
                    .expect("at most 31 block signatures"),
                )
                .expect("replace the proposal signature index for the adversarial fixture");
            assert_eq!(
                authenticate_genesis_block_intents(&noncanonical_index, &genesis_account)
                    .unwrap_err(),
                InvalidGenesisError::InvalidSignature
            );
            let unrelated = crate::block::checked_keypair();
            let mut forged = proposal;
            let forged_hash = forged.hash();
            forged
                .replace_signatures(
                    iroha_data_model::block::BlockSignatures::try_from_iter([BlockSignature::new(
                        0,
                        checked_block_signature(unrelated.private_key(), forged_hash),
                    )])
                    .expect("at most 31 block signatures"),
                )
                .expect("replace the proposal signature for the adversarial fixture");
            assert_eq!(
                authenticate_genesis_block_intents(&forged, &genesis_account).unwrap_err(),
                InvalidGenesisError::InvalidSignature
            );
        }
        #[test]
        fn genesis_block_signature_does_not_replace_transaction_signature() {
            use iroha_data_model::prelude::*;
            let genesis_keypair = crate::block::checked_keypair();
            let unrelated = crate::block::checked_keypair();
            let genesis_account = AccountId::new(genesis_keypair.public_key().clone());
            let mut transaction = TransactionBuilder::new_genesis(
                genesis_account.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "genesis".to_owned())])
            .sign(genesis_keypair.private_key());
            transaction.set_signature(iroha_data_model::transaction::TransactionSignature(
                SignatureOf::try_new(unrelated.private_key(), transaction.payload())
                    .expect("unrelated key can sign the adversarial fixture payload"),
            ));
            let block =
                SignedBlock::genesis(vec![transaction], genesis_keypair.private_key(), None, None);
            assert_eq!(
                check_genesis_block(&block, &genesis_account),
                Err(InvalidGenesisError::InvalidTransactionSignature)
            );
        }
        include!("block/genesis_validation_regression_tests.rs");
        #[test]
        fn signed_genesis_validation_is_storage_side_effect_free() {
            use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
            use iroha_data_model::parameter::{Parameter, system::SumeragiParameter};
            let mut config = TestChainConfig::new(World::new(), 1_000);
            config.genesis_parameters = vec![
                Parameter::Sumeragi(SumeragiParameter::MaxClockDriftMs(100)),
                Parameter::Sumeragi(SumeragiParameter::MaxClockDriftMs(333)),
            ];
            let prepared = CertifiedTestChain::prepare(config)
                .expect("ordered parameters are bound into original signed genesis");
            let genesis = prepared.genesis.block().clone();
            let account = genesis
                .external_transactions()
                .next()
                .unwrap()
                .authority()
                .clone();
            let topology = Topology::new(
                prepared
                    .validator_keys
                    .iter()
                    .map(|key| PeerId::new(key.public_key().clone())),
            );
            let (valid, overlay) = {
                let selected_genesis = genesis.clone();
                let selected_scope =
                    crate::sumeragi::epoch::authenticated_genesis(&selected_genesis)
                        .expect("signed fixture root scope")
                        .into_parts()
                        .1;
                ValidBlock::validate_signed_genesis(
                    selected_genesis,
                    &topology,
                    &account,
                    &TimeSource::new_system(),
                    &prepared.state,
                    iroha_data_model::parameter::system::ConsensusMode::Permissioned,
                    selected_scope,
                )
            }
            .unpack(|_| {})
            .expect("ordered original signed genesis executes in a disposable overlay");
            assert_eq!(
                overlay.world.parameters().sumeragi().max_clock_drift(),
                Duration::from_millis(333),
                "the last ordered genesis parameter wins in actual execution",
            );
            assert!(valid.as_ref().output_results().all(|result| result.is_ok()));
            assert_eq!(
                valid
                    .as_ref()
                    .canonical_resultless_proposal()
                    .expect("valid fixture proposal projection"),
                genesis
            );
            drop((valid, overlay));
            assert_eq!(prepared.state.view().height(), 0);
            assert_eq!(prepared.kura.blocks_count(), 0);
            assert_eq!(
                prepared.kura.pipeline_sidecar_queue_len_for_testing(),
                0,
                "disposable signed-genesis validation must not publish pipeline recovery metadata"
            );
        }
    }
    #[cfg(test)]
    #[path = "genesis_rejection_tests.rs"]
    mod genesis_rejection_tests;
    #[test]
    fn insufficient_commit_quorum_maps_to_a_rejection_reason() {
        let keypairs = (0..4)
            .map(|_| checked_keypair_with_algorithm(Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        let topology = Topology::new(
            keypairs
                .iter()
                .map(|key| PeerId::new(key.public_key().clone())),
        );
        let signed: SignedBlock = ValidBlock::new_dummy(keypairs[0].private_key()).into();
        let error = ValidBlock::is_commit(&signed, &topology)
            .expect_err("one valid BLS leader signature cannot satisfy the four-validator quorum");
        assert!(matches!(
            map_sig_err_to_reason(&error),
            iroha_data_model::block::error::BlockRejectionReason::InsufficientBlockSignatures
        ));
    }
}
mod commit {
    use super::*;
    /// Executed block lifecycle wrapper. Native consensus authentication is held by the
    /// original canonical carrier and `sumeragi::certified_chain::CommittedBlock`.
    #[derive(Debug, Clone)]
    pub struct CommittedBlock {
        block: SharedSignedBlock,
    }
    impl CommittedBlock {
        pub(super) fn from_execution(block: ValidBlock, shell: ReservedSharedSignedBlock) -> Self {
            Self {
                block: shell.initialize(block.into()),
            }
        }

        /// Borrow the immutable original graph shared with staging and durable storage.
        pub fn shared(&self) -> &SharedSignedBlock {
            &self.block
        }

        /// Transfer this original shared reference without extracting or cloning its graph.
        pub fn into_shared(self) -> SharedSignedBlock {
            self.block
        }
    }
    impl AsRef<SignedBlock> for CommittedBlock {
        fn as_ref(&self) -> &SignedBlock {
            self.block.as_ref()
        }
    }
    #[cfg(all(test, feature = "app_api"))]
    mod axt_validation_tests {
        include!("block/axt_anchored_spend_admission_tests.rs");
    }
}
mod event {
    use super::*;
    use crate::state::StateBlock;
    use new::NewBlock;

    pub trait EventProducer {
        fn produce_events(&self) -> impl Iterator<Item = PipelineEventBox>;
    }
    #[derive(Debug)]
    #[must_use]
    pub struct WithEvents<B>(B, Option<PipelineEventBox>);
    impl<B> WithEvents<B> {
        pub(super) fn new(source: B) -> Self {
            Self(source, None)
        }
    }
    impl<B: EventProducer, U> WithEvents<Result<B, (U, Box<BlockValidationError>)>> {
        pub fn unpack<F: FnMut(PipelineEventBox)>(
            self,
            f: F,
        ) -> Result<B, (U, Box<BlockValidationError>)> {
            match self.0 {
                Ok(ok) => Ok(WithEvents::new(ok).unpack(f)),
                Err(err) => Err(WithEvents::new(err).unpack(f)),
            }
        }
    }
    impl<'state, B: EventProducer, U>
        WithEvents<Result<(B, Box<StateBlock<'state>>), (U, Box<BlockValidationError>)>>
    {
        /// Retain a deterministic rejection only after its original native source was checked.
        /// The caller still owns publication; local resource refusals produce no event.
        #[expect(
            clippy::large_types_passed_by_value,
            reason = "the header is transferred into the authenticated rejection event"
        )]
        pub(super) fn with_authenticated_rejection(
            mut self,
            header: BlockHeader,
            state: &crate::state::State,
            generation: u64,
        ) -> Self {
            if let Err((_, error)) = &mut self.0 {
                // A pre-existing local failure owns its exact refusal or terminal custody.
                // A concurrent publication cannot replace that owner or authorize rejection.
                if !cfg!(all(test, sumeragi_core_mutation = "HC99"))
                    && map_block_err_to_reason(error).is_none()
                {
                    return self;
                }
                let observed_generation = state.state_view_generation();
                if !crate::state::is_stable_state_view_generation(generation, observed_generation) {
                    **error = BlockValidationError::NativeSourceChanged {
                        authenticated_generation: generation,
                        observed_generation,
                    };
                } else {
                    emit_block_rejection(header, error, |event| self.1 = Some(event));
                }
            }
            self
        }
        pub fn unpack<F: FnMut(PipelineEventBox)>(
            self,
            mut f: F,
        ) -> Result<(B, Box<StateBlock<'state>>), (U, Box<BlockValidationError>)> {
            self.1.into_iter().for_each(&mut f);
            match self.0 {
                Ok((ok, state)) => Ok((WithEvents::new(ok).unpack(f), state)),
                Err(err) => Err(WithEvents::new(err).unpack(f)),
            }
        }
    }
    impl WithEvents<Result<iroha_data_model::block::BlockSignatures, SignatureVerificationError>> {
        pub fn unpack<F: FnMut(PipelineEventBox)>(
            self,
            f: F,
        ) -> Result<iroha_data_model::block::BlockSignatures, SignatureVerificationError> {
            match self.0 {
                Ok(ok) => Ok(ok),
                Err(err) => Err(WithEvents::new(err).unpack(f)),
            }
        }
    }
    impl<B: EventProducer> WithEvents<B> {
        pub fn unpack<F: FnMut(PipelineEventBox)>(self, f: F) -> B {
            self.0.produce_events().for_each(f);
            self.0
        }
    }
    impl<B, E: EventProducer> WithEvents<(B, E)> {
        pub(crate) fn unpack<F: FnMut(PipelineEventBox)>(self, f: F) -> (B, E) {
            self.0.1.produce_events().for_each(f);
            self.0
        }
    }
    impl EventProducer for NewBlock {
        fn produce_events(&self) -> impl Iterator<Item = PipelineEventBox> {
            let block_event = BlockEvent {
                header: self.header,
                status: BlockStatus::Created,
            };
            core::iter::once(block_event.into())
        }
    }
    impl EventProducer for ValidBlock {
        fn produce_events(&self) -> impl Iterator<Item = PipelineEventBox> {
            let block = self.as_ref();
            let block_height = block.header().height();
            let is_genesis = block.header().is_genesis();
            // Validate the complete body before exposing any status. A missing
            // or malformed output must never default to Approved.
            let valid_outputs = match block.validate_output_merkle_cache() {
                Ok(()) => true,
                Err(error) => {
                    iroha_logger::error!(
                        block_height = block_height.get(),
                        %error,
                        "validated block event source has invalid execution outputs"
                    );
                    false
                }
            };
            let committed_routes = block
                .execution_context()
                .map(|bundle| bundle.external.as_slice());
            let tx_events = block.network_entrypoints().enumerate().filter_map(
                move |(idx, entrypoint)| {
                    if !valid_outputs {
                        return None;
                    }
                    let entrypoint_hash = entrypoint.hash();
                    let tx = match entrypoint {
                        TransactionEntrypoint::External(tx) => tx,
                        TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
                        TransactionEntrypoint::SealedCommitment(_) => return None,
                    };
                    let input_index = u32::try_from(idx).ok()?;
                    let (_, output) = block.network_output_at(input_index)?;
                    let Some(context) = committed_routes.and_then(|routes| routes.get(idx)) else {
                        if !is_genesis {
                            iroha_logger::error!(
                                block_height = block_height.get(),
                                entrypoint_index = idx,
                                %entrypoint_hash,
                                "validated block transaction event is missing its committed execution route"
                            );
                        }
                        return None;
                    };
                    if context.entrypoint_hash != entrypoint_hash {
                        iroha_logger::error!(
                            block_height = block_height.get(),
                            entrypoint_index = idx,
                            %entrypoint_hash,
                            committed_entrypoint_hash = %context.entrypoint_hash,
                            "validated block transaction event route is bound to a different entrypoint"
                        );
                        return None;
                    }
                    let status = match output.result.as_ref() {
                        Ok(_) => TransactionStatus::Approved,
                        Err(error) => TransactionStatus::Rejected(Box::new(error.clone())),
                    };
                    Some(TransactionEvent {
                        hash: tx.hash(),
                        block_height: Some(block_height),
                        lane_id: context.lane_id,
                        dataspace_id: context.dataspace_id,
                        status,
                    })
                },
            );
            let block_event = valid_outputs.then(|| BlockEvent {
                header: block.header(),
                status: BlockStatus::Approved,
            });
            tx_events
                .map(PipelineEventBox::from)
                .chain(block_event.into_iter().map(Into::into))
        }
    }
    impl EventProducer for CommittedBlock {
        fn produce_events(&self) -> impl Iterator<Item = PipelineEventBox> {
            let block_event = core::iter::once(BlockEvent {
                header: self.as_ref().header(),
                status: BlockStatus::Committed,
            });
            block_event.map(Into::into)
        }
    }
    pub(super) fn map_sig_err_to_reason(
        err: &SignatureVerificationError,
    ) -> iroha_data_model::block::error::BlockRejectionReason {
        use iroha_data_model::block::error::BlockRejectionReason as Reason;
        match err {
            SignatureVerificationError::NotEnoughSignatures { .. } => {
                Reason::InsufficientBlockSignatures
            }
            SignatureVerificationError::DuplicateSignature { .. }
            | SignatureVerificationError::UnknownSignature
            | SignatureVerificationError::MissingPop => Reason::InvalidBlockSignature,
            SignatureVerificationError::UnknownSignatory => Reason::UnknownBlockSignatory,
            SignatureVerificationError::InactiveConsensusKey => Reason::InactiveConsensusKey,
            SignatureVerificationError::ProxyTailMissing => Reason::ProxyTailSignatureMissing,
            SignatureVerificationError::LeaderMissing => Reason::LeaderSignatureMissing,
            SignatureVerificationError::Other => Reason::OtherSignatureError,
        }
    }
    pub(super) fn map_block_err_to_reason(
        err: &BlockValidationError,
    ) -> Option<iroha_data_model::block::error::BlockRejectionReason> {
        use iroha_data_model::block::error::BlockRejectionReason as Reason;
        Some(match err {
            BlockValidationError::NativeSourceChanged { .. }
            | BlockValidationError::NativeHistory(_)
            | BlockValidationError::DaIndexHydration(_)
            | BlockValidationError::LocalStorageRecoveryRequired { .. }
            | BlockValidationError::StateView(_)
            | BlockValidationError::LaneStorage(_)
            | BlockValidationError::StateStorageAdmission(_)
            | BlockValidationError::EvidencePreparation(_)
            | BlockValidationError::ExecutionDeferred(_)
            | BlockValidationError::GovernanceDueUnavailable(_)
            | BlockValidationError::BlockHashAdmission(_)
            | BlockValidationError::MembershipAdmission(_) => return None,
            BlockValidationError::HasCommittedTransactions => Reason::ContainsCommittedTransactions,
            BlockValidationError::EmptyBlock => Reason::EmptyBlock,
            BlockValidationError::DuplicateTransactions
            | BlockValidationError::TooManyTransactions { .. } => {
                Reason::TransactionValidationFailed
            }
            BlockValidationError::ExecutionContextInvalid(_)
            | BlockValidationError::CommittedFragmentCountMismatch { .. } => {
                Reason::TransactionValidationFailed
            }
            BlockValidationError::PrevBlockHashMismatch { .. } => Reason::PrevBlockHashMismatch,
            BlockValidationError::PrevBlockHeightMismatch { .. } => Reason::PrevBlockHeightMismatch,
            BlockValidationError::MerkleRootMismatch => Reason::MerkleRootMismatch,
            BlockValidationError::TransactionAccept(fail) => match fail {
                AcceptTransactionFail::TransactionLimit(_)
                | AcceptTransactionFail::SignedAttachments(_)
                | AcceptTransactionFail::SignatureVerification(_)
                | AcceptTransactionFail::UnexpectedGenesisAccountSignature
                | AcceptTransactionFail::TransactionDomainMismatch(_)
                | AcceptTransactionFail::TransactionInTheFuture { .. }
                | AcceptTransactionFail::TransactionExpired { .. }
                | AcceptTransactionFail::NetworkTimeUnhealthy { .. } => {
                    Reason::TransactionValidationFailed
                }
            },
            BlockValidationError::TopologyMismatch { .. } => Reason::TopologyMismatch,
            BlockValidationError::SignatureVerification(e) => map_sig_err_to_reason(e),
            BlockValidationError::InvalidGenesis(_)
            | BlockValidationError::GenesisPolicyMismatch { .. } => Reason::InvalidGenesis,
            BlockValidationError::BlockInThePast
            | BlockValidationError::BlockTimeBeforeRequiredFloor { .. } => Reason::BlockInThePast,
            BlockValidationError::BlockInTheFuture => Reason::BlockInTheFuture,
            BlockValidationError::BlockTimeOverflow => Reason::BlockInTheFuture,
            BlockValidationError::FinalityAuthorityInvalid(_) => Reason::ConsensusBlockRejection,
            BlockValidationError::TransactionInTheFuture => Reason::TransactionInTheFuture,
            BlockValidationError::ConfidentialFeaturesMismatch { .. } => {
                Reason::ConfidentialFeatureDigestMismatch
            }
            BlockValidationError::ProofPolicyHashMismatch { .. }
            | BlockValidationError::DaProofPolicySidecarHashMismatch { .. }
            | BlockValidationError::DaProofPolicyBundleMismatch => Reason::DaProofPolicyMismatch,
            BlockValidationError::DaCommitmentHashMismatch { .. }
            | BlockValidationError::NonCanonicalEmptyDaCommitmentBundle
            | BlockValidationError::DaPinIntentHashMismatch { .. }
            | BlockValidationError::NonCanonicalEmptyDaPinIntentBundle => {
                Reason::DaShardCursorViolation
            }
            BlockValidationError::DaCommitmentBundle(
                crate::da::DaCommitmentValidationError::ProofPolicy(_),
            ) => Reason::DaProofPolicyMismatch,
            BlockValidationError::DaCommitmentBundle(_) => Reason::DaShardCursorViolation,
            BlockValidationError::DaPinIntentBundle(_) => Reason::DaShardCursorViolation,
            BlockValidationError::DaReceiptCursor(_) => Reason::DaShardCursorViolation,
            BlockValidationError::DaShardCursor(_) => Reason::DaShardCursorViolation,
            BlockValidationError::AxtEnvelopeValidationFailed(_) => {
                Reason::TransactionValidationFailed
            }
            BlockValidationError::NposEffectsInvalid(_) => Reason::NposEffectsMismatch,
        })
    }
    /// Emit a rejection only when validation produced a deterministic reason.
    #[expect(
        clippy::large_types_passed_by_value,
        reason = "the header is transferred into the emitted block event"
    )]
    pub(super) fn emit_block_rejection(
        header: BlockHeader,
        error: &BlockValidationError,
        mut send_events: impl FnMut(PipelineEventBox),
    ) {
        if let Some(reason) = map_block_err_to_reason(error) {
            send_events(PipelineEventBox::from(BlockEvent {
                header,
                status: BlockStatus::Rejected(reason),
            }));
        }
    }
    impl EventProducer for BlockValidationError {
        fn produce_events(&self) -> impl Iterator<Item = PipelineEventBox> {
            // Rejection events require a block header to construct `BlockEvent`.
            // These are emitted by consensus callers at sites where the offending
            // header and authenticated validation context are available.
            core::iter::empty()
        }
    }
    impl<T: EventProducer + ?Sized> EventProducer for Box<T> {
        fn produce_events(&self) -> impl Iterator<Item = PipelineEventBox> {
            (**self).produce_events()
        }
    }
    impl EventProducer for SignatureVerificationError {
        fn produce_events(&self) -> impl Iterator<Item = PipelineEventBox> {
            // Similar to `BlockValidationError`: emission is performed by the
            // caller at the site where the header is available.
            core::iter::empty()
        }
    }
    #[cfg(test)]
    mod tests {
        include!("block/output_event_tests.rs");
    }
}
#[cfg(all(test, feature = "simd"))]
mod simd_parent_dedup {
    const LANES: usize = 8;

    pub(super) fn dedup_sorted_slice(slice: &mut [usize]) -> Option<usize> {
        if slice.len() <= 1 {
            return Some(slice.len());
        }
        let mut write = 1usize;
        let mut prev = slice[0];
        let mut idx = 1usize;
        while idx + LANES <= slice.len() {
            // Snapshot each fixed-width chunk before compacting into the same
            // slice. This keeps the kernel safe, deterministic, and suitable
            // for stable-Rust auto-vectorization without aliasing unread data.
            let mut chunk = [0usize; LANES];
            chunk.copy_from_slice(&slice[idx..idx + LANES]);
            for value in chunk {
                if value != prev {
                    slice[write] = value;
                    write += 1;
                    prev = value;
                }
            }
            idx += LANES;
        }
        while idx < slice.len() {
            let value = slice[idx];
            if value != prev {
                slice[write] = value;
                write += 1;
                prev = value;
            }
            idx += 1;
        }
        Some(write)
    }

    #[cfg(test)]
    mod tests {
        use super::dedup_sorted_slice;

        #[test]
        fn fixed_width_dedup_handles_chunk_boundaries() {
            let mut values = [1, 1, 2, 3, 3, 3, 4, 5, 5, 6, 7, 7, 8, 9, 9, 10, 10];
            let len = dedup_sorted_slice(&mut values).expect("fixed-width path is available");
            assert_eq!(&values[..len], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        }
    }
}
#[cfg(test)]
/// Build a conflict graph from access sets using an incremental O(n + E) algorithm.
/// Returns adjacency list and indegree vector.
#[allow(clippy::disallowed_types)]
fn build_conflict_graph(
    access: &[crate::pipeline::access::AccessSet],
) -> (
    Vec<iroha_primitives::small::SmallVec<[usize; 8]>>,
    Vec<usize>,
) {
    use iroha_primitives::small::SmallVec;
    // Intern keys once per block to operate on compact integer IDs while
    // preserving deterministic ordering across peers.
    let (key_count, access_ids) = intern_access(access);
    let n = access.len();
    let mut adj: Vec<SmallVec<[usize; 8]>> = vec![SmallVec::new(); n];
    let mut indeg = vec![0usize; n];
    // Track the most recent writer per interned key and readers awaiting a write.
    let mut last_writer: Vec<Option<usize>> = vec![None; key_count];
    let mut open_readers: Vec<SmallVec<[usize; 4]>> = (0..key_count)
        .map(|_| SmallVec::<[usize; 4]>::new())
        .collect();
    // Component partitioning via disjoint-set prepass is handled before scheduling.
    for (idx, aset) in access_ids.iter().enumerate() {
        // Collect parents in a small vec; sort+dedup to avoid the log factor of BTreeSet
        let mut parents: SmallVec<[usize; 8]> = SmallVec::new();
        // Read dependencies: last writer of each read key must precede this read
        for &key in aset.reads.iter() {
            let key_idx = key as usize;
            if let Some(writer) = last_writer[key_idx] {
                parents.push(writer);
            }
            open_readers[key_idx].push(idx);
        }
        // Write dependencies: last writer must precede; all open readers must precede
        for &key in aset.writes.iter() {
            let key_idx = key as usize;
            if let Some(writer) = last_writer[key_idx] {
                parents.push(writer);
            }
            let readers = &mut open_readers[key_idx];
            for &reader in readers.iter() {
                parents.push(reader);
            }
            readers.clear();
            last_writer[key_idx] = Some(idx);
        }
        if !parents.is_empty() {
            // Deterministic dedup without extra allocations
            parents.sort_unstable();
            let mut write = 0usize;
            let mut last: Option<usize> = None;
            for i in 0..parents.len() {
                let v = parents[i];
                if Some(v) != last {
                    parents[write] = v;
                    write += 1;
                    last = Some(v);
                }
            }
            while parents.len() > write {
                let _ = parents.remove(parents.len() - 1);
            }
            for p in parents {
                adj[p].push(idx);
                indeg[idx] += 1;
            }
        }
    }
    (adj, indeg)
}
#[cfg(test)]
mod dag_tests {
    use super::build_conflict_graph;
    use crate::pipeline::access::AccessSet;
    fn rw(reads: &[&str], writes: &[&str]) -> AccessSet {
        let mut s = AccessSet::new();
        for k in reads {
            s.add_read((*k).to_string());
        }
        for k in writes {
            s.add_write((*k).to_string());
        }
        s
    }
    #[test]
    fn ww_conflict_edge() {
        let a = rw(&[], &["k"]);
        let b = rw(&[], &["k"]);
        let (adj, indeg) = build_conflict_graph(&[a, b]);
        assert_eq!(indeg, vec![0, 1]);
        assert_eq!(&adj[0][..], &[1]);
        assert!(adj[1].is_empty());
    }
    #[test]
    fn state_map_wildcard_conflicts_with_map_entries() {
        let a = rw(&[], &["state:Foo/1"]);
        let b = rw(&[], &["state:Foo/2"]);
        let c = rw(&[], &["state:Foo[*]"]);
        let (adj, indeg) = build_conflict_graph(&[a, b, c]);
        assert_eq!(indeg, vec![0, 0, 2]);
        assert_eq!(&adj[0][..], &[2]);
        assert_eq!(&adj[1][..], &[2]);
        assert!(adj[2].is_empty());
    }
    #[test]
    fn exact_state_map_keys_only_conflict_when_canonical_keys_match() {
        let first = rw(&[], &["state:Foo/01"]);
        let distinct = rw(&[], &["state:Foo/02"]);
        let repeated = rw(&[], &["state:Foo/01"]);
        let (adj, indeg) = build_conflict_graph(&[first, distinct, repeated]);
        assert_eq!(indeg, vec![0, 0, 1]);
        assert_eq!(&adj[0][..], &[2]);
        assert!(adj[1].is_empty());
        assert!(adj[2].is_empty());
    }
    #[test]
    fn global_wildcard_conflicts_with_all() {
        let a = rw(&[], &["k1"]);
        let b = rw(&[], &["*"]);
        let c = rw(&[], &["k2"]);
        let (adj, indeg) = build_conflict_graph(&[a, b, c]);
        assert_eq!(indeg, vec![0, 1, 1]);
        assert_eq!(&adj[0][..], &[1]);
        assert_eq!(&adj[1][..], &[2]);
        assert!(adj[2].is_empty());
    }
    #[test]
    fn state_global_wildcard_conflicts_with_state_entries() {
        let a = rw(&[], &["state:Foo/1"]);
        let b = rw(&[], &["state:*"]);
        let c = rw(&[], &["state:Foo/2"]);
        let (adj, indeg) = build_conflict_graph(&[a, b, c]);
        assert_eq!(indeg, vec![0, 1, 1]);
        assert_eq!(&adj[0][..], &[1]);
        assert_eq!(&adj[1][..], &[2]);
        assert!(adj[2].is_empty());
    }
    #[test]
    fn wr_conflict_edge() {
        let a = rw(&[], &["k"]);
        let b = rw(&["k"], &[]);
        let (adj, indeg) = build_conflict_graph(&[a, b]);
        assert_eq!(indeg, vec![0, 1]);
        assert_eq!(&adj[0][..], &[1]);
        assert!(adj[1].is_empty());
    }
    #[test]
    fn rw_conflict_edge() {
        let a = rw(&["k"], &[]);
        let b = rw(&[], &["k"]);
        let (adj, indeg) = build_conflict_graph(&[a, b]);
        assert_eq!(indeg, vec![0, 1]);
        assert_eq!(&adj[0][..], &[1]);
        assert!(adj[1].is_empty());
    }
    #[test]
    fn dedup_edges_for_multiple_keys() {
        let a = rw(&[], &["x", "y"]);
        let b = rw(&["x", "y"], &[]);
        let (adj, indeg) = build_conflict_graph(&[a, b]);
        assert_eq!(indeg, vec![0, 1]);
        assert_eq!(&adj[0][..], &[1]); // only one edge despite two overlapping keys
    }
    #[test]
    fn disjoint_transactions_remain_independent() {
        let a = rw(&["alpha"], &[]);
        let b = rw(&[], &["beta"]);
        let c = rw(&["gamma"], &[]);
        let (adj, indeg) = build_conflict_graph(&[a, b, c]);
        assert_eq!(indeg, vec![0, 0, 0]);
        assert!(adj.iter().all(|neighbors| neighbors.is_empty()));
    }
    #[test]
    fn chain_reads_and_writes() {
        // 0: R(A); 1: W(A); 2: R(A); 3: W(A)
        let a0 = rw(&["A"], &[]);
        let a1 = rw(&[], &["A"]);
        let a2 = rw(&["A"], &[]);
        let a3 = rw(&[], &["A"]);
        let (adj, indeg) = build_conflict_graph(&[a0, a1, a2, a3]);
        assert_eq!(indeg, vec![0, 1, 1, 2]);
        assert_eq!(&adj[0][..], &[1]);
        assert_eq!(&adj[1][..], &[2, 3]);
        assert_eq!(&adj[2][..], &[3]);
        assert!(adj[3].is_empty());
    }
}
#[cfg(test)]
mod dsu_tests {
    use super::{DisjointSet, intern_access};
    use crate::pipeline::access::AccessSet;
    use iroha_primitives::small::SmallVec;
    fn ids(reads: &[&str], writes: &[&str]) -> AccessSet {
        let mut s = AccessSet::new();
        for k in reads {
            s.add_read((*k).to_string());
        }
        for k in writes {
            s.add_write((*k).to_string());
        }
        s
    }
    #[test]
    fn dsu_partitions_independent_components() {
        // Two independent components: {0,1} share key "A"; {2,3} share key "B".
        let a0 = ids(&["A"], &[]);
        let a1 = ids(&[], &["A"]);
        let b0 = ids(&["B"], &[]);
        let b1 = ids(&[], &["B"]);
        let access = [a0, a1, b0, b1];
        let (key_count, access_ids) = intern_access(&access);
        let mut dsu = DisjointSet::new(access_ids.len());
        {
            let mut last_writer: Vec<Option<usize>> = vec![None; key_count];
            let mut open_readers: Vec<SmallVec<[usize; 4]>> = vec![SmallVec::new(); key_count];
            for (idx, aset) in access_ids.iter().enumerate() {
                for &k in aset.reads.iter() {
                    if let Some(w) = last_writer[k as usize] {
                        dsu.union(idx, w);
                    }
                    open_readers[k as usize].push(idx);
                }
                for &k in aset.writes.iter() {
                    if let Some(w) = last_writer[k as usize] {
                        dsu.union(idx, w);
                    }
                    if let Some(readers) = {
                        if open_readers[k as usize].is_empty() {
                            None
                        } else {
                            Some(std::mem::take(&mut open_readers[k as usize]))
                        }
                    } {
                        for r in readers {
                            dsu.union(idx, r);
                        }
                    }
                    last_writer[k as usize] = Some(idx);
                }
            }
        }
        let mut roots: Vec<usize> = Vec::new();
        let mut dsu_copy = dsu.clone();
        for i in 0..4 {
            roots.push(dsu_copy.find(i));
        }
        // Expect two distinct roots among four items
        let mut uniq = roots.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), 2);
    }
}
include!("block/scheduler_variant_tests.rs");
/// Block validation tests and signed Native AMX fixtures shared within Core.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        block::event::map_sig_err_to_reason,
        kura::Kura,
        query::store::LiveQueryStore,
        smartcontracts::{Execute, isi::triggers::set::SetReadOnly},
        state::{State, World},
        tx::AcceptedTransaction,
    };
    use core::time::Duration;
    use iroha_crypto::{Hash, HashOf, KeyPair};
    use iroha_data_model::{
        errors::AmxStage,
        events::pipeline::{BlockEventFilter, TransactionEventFilter},
        prelude::*,
        smart_contract::ContractArtifactId,
        transaction::{
            ExecutableBatchItem,
            signed::{
                SealedTransactionCommitmentPayload, SealedTransactionReveal,
                SignedSealedTransactionCommitment, SignedTransaction,
                compute_sealed_transaction_commitment,
            },
        },
    };
    use iroha_genesis::GENESIS_DOMAIN_ID;
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::{name::Name, state_path::StatePath};
    use iroha_primitives::json::Json;
    use iroha_primitives::time::TimeSource;
    use iroha_test_samples::gen_account_in;
    use nonzero_ext::nonzero;
    use std::{borrow::Cow, num::NonZeroU64};
    include!("block/native_amx_and_dag_tests.rs");
    fn accept_transaction_at_mock_time(
        transaction: SignedTransaction,
        network: &NetworkId,
        max_clock_drift: Duration,
        limits: iroha_data_model::parameter::TransactionParameters,
        crypto: &iroha_config::parameters::actual::Crypto,
        now: Duration,
    ) -> Result<AcceptedTransaction<'static>, crate::tx::AcceptTransactionFail> {
        AcceptedTransaction::accept_with_time_source(
            transaction,
            network,
            max_clock_drift,
            limits,
            crypto,
            &TimeSource::new_fixed(now),
        )
    }
    fn encode_fixture_int_map_key(value: i128) -> Vec<u8> {
        use ivm_abi::state_value::{
            StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1,
            StateValueSchemaV1, state_value_schema_hash_v1,
        };
        let schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Int)],
        };
        let envelope =
            ivm_abi::numeric_tlv::encode_int(&iroha_primitives::bigint::BigInt::from_i128(value))
                .unwrap();
        norito::encode_canonical(&StateValueRecordV1 {
            schema_hash: state_value_schema_hash_v1(&norito::encode_canonical(&schema).unwrap()),
            atoms: vec![StateValueAtomV1::Pointer(envelope)],
        })
        .unwrap()
    }
    /// Decode the current schema-bound durable `int` record, including its pointer envelope.
    fn decode_stored_state_int(stored: &[u8]) -> i128 {
        use ivm::state_value::{
            StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1,
            StateValueSchemaV1, state_value_schema_hash_v1,
        };
        let schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Int)],
        };
        let record: StateValueRecordV1 =
            norito::decode_from_bytes(stored).expect("canonical persisted StateMap record");
        assert_eq!(
            record.schema_hash,
            state_value_schema_hash_v1(&norito::to_bytes(&schema).unwrap())
        );
        assert!(schema.validate_atoms(&record.atoms));
        let [StateValueAtomV1::Pointer(envelope)] = record.atoms.as_slice() else {
            panic!("StateMap int record must contain exactly one pointer atom");
        };
        ivm::numeric_tlv::decode_int_bytes(envelope)
            .expect("canonical persisted StateMap integer")
            .to_string()
            .parse()
            .expect("fixture integer fits i128")
    }

    fn configured_component_state(
        world: World,
        chain_id: ChainId,
        nexus: iroha_config::parameters::actual::Nexus,
    ) -> State {
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                nexus
                    .fees
                    .clone()
                    .into_custom_parameter()
                    .expect("explicit fixture fee policy"),
            ))
            .expect("valid fixture fee policy");
        parameters.commit();
        let (mut state, _) = State::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
            world,
            nexus.clone(),
            LiveQueryStore::start_test(),
            chain_id,
            deterministic_test_network_id(0x0B),
        );
        state
            .set_nexus_from_config(nexus)
            .expect("original fixture Nexus fee policy");
        state
    }

    pub(crate) fn component_chain(state: State) -> crate::sumeragi::test_chain::CertifiedTestChain {
        component_chain_with_genesis_parameters(state, Vec::new())
    }

    pub(crate) fn component_chain_with_genesis_parameters(
        state: State,
        genesis_parameters: Vec<iroha_data_model::parameter::Parameter>,
    ) -> crate::sumeragi::test_chain::CertifiedTestChain {
        assert_eq!(
            state.committed_height(),
            0,
            "component source must be pristine"
        );
        assert_eq!(
            state.kura().blocks_count(),
            0,
            "component source cannot replace history"
        );
        let nexus = state.nexus_snapshot();
        let crypto = state.crypto();
        let zk = state.zk_snapshot();
        let chain_id = state.chain_id_ref().clone();
        let pipeline = state.installed_pipeline().clone();
        let fraud = state.fraud_monitoring.clone();
        let governance = state.gov.clone();
        #[cfg(feature = "telemetry")]
        let telemetry = state.telemetry.clone();
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(state.world, 0);
        config.genesis_parameters = genesis_parameters;
        config.chain_id = chain_id;
        config.pipeline = pipeline;
        config.nexus = Some(nexus);
        config.zk = Some(zk);
        config.crypto = Some(crypto.as_ref().clone());
        config.fraud_monitoring = fraud;
        config.governance = Some(governance);
        let mut prepared = crate::sumeragi::test_chain::CertifiedTestChain::prepare(config)
            .expect("derive signed component genesis policies");
        #[cfg(feature = "telemetry")]
        {
            Arc::get_mut(&mut prepared.state)
                .expect("unpublished State owner")
                .telemetry = telemetry;
        }
        crate::sumeragi::test_chain::CertifiedTestChain::from_prepared(prepared)
            .expect("original component World executes under its signed genesis policies")
    }
    fn state_with_transaction_policy(
        chain_id: &ChainId,
        authority: &AccountId,
        require_height_ttl: bool,
        require_sequence: bool,
    ) -> State {
        let domain_id = DomainId::try_new("wonderland", "universal").expect("valid domain");
        let domain = Domain::new(domain_id).build(authority);
        let account = Account::new(authority.clone()).build(authority);
        let mut world = World::with([domain], [account], []);
        let mut params = iroha_data_model::parameter::system::Parameters::default();
        params.transaction = params
            .transaction
            .with_ingress_enforcement(require_height_ttl, require_sequence);
        world.parameters = mv::cell::Cell::new(
            crate::state::StateParameters::try_from(params).expect("valid fixture parameters"),
        );
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        State::new_with_chain_and_network_id_for_testing(
            world,
            kura,
            query_handle,
            chain_id.clone(),
            deterministic_test_network_id(0x0B),
        )
    }
    #[test]
    fn rejected_prepared_overlay_carries_confidential_work_into_block_budget() {
        let chain_id = ChainId::from("rejected-overlay-confidential-budget");
        let (authority, keypair) = gen_account_in("wonderland");
        let mut state = state_with_transaction_policy(&chain_id, &authority, false, false);
        // Generic proof verification requires an explicitly installed executor.
        // This deterministic policy admits the instruction; Core still enforces
        // its production circuit registry, proof-work budgets, and registered VK.
        let verdict = norito::codec::Encode::encode(&Ok::<(), ValidationFail>(()));
        let executor_program = crate::executor::build_program_from_encoded_result(&verdict);
        let executor = crate::executor::LoadedExecutor::load(
            iroha_data_model::executor::Executor::new(IvmBytecode::from_compiled(executor_program)),
        )
        .expect("load proof-verification executor policy");
        state.world.executor =
            mv::cell::Cell::new(crate::executor::Executor::UserProvided(executor));
        let mut pipeline = state.installed_pipeline().clone();
        pipeline.parallel_overlay = true;
        pipeline.workers = 2;
        state.set_pipeline(pipeline);
        let mut zk = state.installed_zk().clone();
        zk.max_confidential_ops_per_block = 1;
        zk.max_verify_calls_per_block = 1;
        zk.max_verify_calls_per_tx = 2;
        zk.max_proof_bytes_block = 1_000_000;
        zk.max_proof_size_bytes = 1_000_000;
        state
            .set_zk(zk)
            .expect("empty state accepts focused confidential limits");

        let native_chain = crate::block::tests::component_chain(state);
        let state = native_chain.state();
        let fixture = crate::zk::test_utils::native_framing_fixture_envelope(
            crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
            [0_u8; 32],
        );
        let proof = fixture.proof_box("pipa-r/pasta");
        let proof_bytes = u64::try_from(proof.bytes.len()).expect("proof length fits u64");
        let instruction: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(
            iroha_data_model::proof::ProofAttachment::new_ref(
                "pipa-r/pasta".into(),
                proof,
                iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "missing-overlay-vk"),
            ),
        )
        .into();
        let expected_confidential_gas =
            crate::gas::confidential_gas_cost(&instruction, &crate::gas::DEFAULT_ZK_GAS)
                .expect("completed fixture gas quote");
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction])
        .sign(keypair.private_key());
        let block = BlockBuilder::new(vec![AcceptedTransaction::new_unchecked(Cow::Owned(
            transaction,
        ))])
        .chain(
            0,
            state
                .view()
                .latest_block()
                .expect("original block read attempt")
                .as_deref(),
        )
        .sign(keypair.private_key())
        .unpack(|_| {});
        let (mut state_block, state_block_recorder) =
            crate::block::ValidBlock::start_component_execution(&block.clone().into(), state)
                .expect("original writer-first component execution");

        let valid = block
            .validate_and_record_transactions(&mut state_block, state_block_recorder)
            .unpack(|_| {});
        let results = valid
            .as_ref()
            .network_entrypoints()
            .enumerate()
            .map(|(index, entrypoint)| {
                let (output_index, output) = valid
                    .as_ref()
                    .network_output_at(
                        u32::try_from(index).expect("fixture Network index fits u32"),
                    )
                    .expect("every queried input has its explicit Network output");
                assert_eq!(usize::try_from(output_index).unwrap(), index);
                (index, entrypoint, &output.result)
            })
            .map(|(_, _, result)| result.0.clone())
            .collect::<Vec<_>>();
        assert!(
            matches!(
                results.as_slice(),
                [Err(TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                    iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(message)
                )))] if message.as_ref() == "proof must reference a registered verifying key reference; inline verifying keys are not supported"
            ),
            "missing verifying key must reject after attempting its proof: {results:?}"
        );
        assert_eq!(state_block.zk_confidential_ops_in_block, 1);
        assert_eq!(state_block.zk_verify_calls_in_block, 1);
        assert_eq!(state_block.zk_proof_bytes_in_block, proof_bytes);
        assert_eq!(
            state_block.confidential_gas_used_in_block,
            expected_confidential_gas
        );

        let mut next = state_block.transaction();
        let error = next
            .register_confidential_proof(1)
            .expect_err("the rejected overlay must exhaust the one-operation block budget");
        assert!(
            matches!(
                error,
                iroha_data_model::isi::error::InstructionExecutionError::InvalidParameter(
                    iroha_data_model::isi::error::InvalidParameterError::SmartContract(message)
                ) if message == "confidential verify calls per block exceeded"
            ),
            "the next proof must fail the exact exhausted block verification quota"
        );
    }
    #[test]
    fn ordinary_prepared_overlay_block_cap_prevents_post_cap_execution() {
        for parallel_apply in [false, true] {
            let chain_id =
                ChainId::try_from(format!("ordinary-overlay-parent-gas-{parallel_apply}"))
                    .expect("canonical test chain id");
            let (authority, keypair) = gen_account_in("wonderland");
            let mut state = state_with_transaction_policy(&chain_id, &authority, false, false);
            let mut pipeline = state.installed_pipeline().clone();
            pipeline.parallel_apply = parallel_apply;
            pipeline.parallel_overlay = true;
            pipeline.workers = 2;
            state.set_pipeline(pipeline);
            let native_chain = crate::block::tests::component_chain(state);
            let state = native_chain.state();
            let instruction =
                InstructionBox::from(Log::new(Level::INFO, "meter ordinary overlay".into()));
            let expected_gas = crate::gas::meter_instructions(
                core::slice::from_ref(&instruction),
                &crate::gas::DEFAULT_ZK_GAS,
            )
            .expect("completed fixture gas quote");
            assert!(expected_gas > 0, "the fixture must consume gas");
            let accepted = [0_u64, 1_u64, 2_u64]
                .into_iter()
                .map(|creation_time_ms| {
                    let mut builder = TransactionBuilder::new(
                        state.network_id,
                        authority.clone(),
                        iroha_data_model::transaction::FeePaymentIntent::authority(
                            Vec::new(),
                            None,
                        ),
                    );
                    builder.set_creation_time(Duration::from_millis(creation_time_ms));
                    let transaction = builder
                        .with_instructions([instruction.clone()])
                        .sign(keypair.private_key());
                    AcceptedTransaction::new_unchecked(Cow::Owned(transaction))
                })
                .collect::<Vec<_>>();
            let _previous = previous_block_at_height(1);
            let previous = state
                .view()
                .latest_block()
                .expect("original block read attempt")
                .expect("original genesis");
            let (_clock, time_source) = TimeSource::new_mock(Duration::from_millis(10));
            let block = BlockBuilder::new_with_time_source(accepted, time_source)
                .chain(1, Some(&previous))
                .sign(keypair.private_key())
                .unpack(|_| {});
            let (mut state_block, state_block_recorder) =
                crate::block::ValidBlock::start_component_execution(&block.clone().into(), state)
                    .expect("original writer-first component execution");
            state_block.gas_limit_per_block = expected_gas;

            let valid = block
                .validate_and_record_transactions(&mut state_block, state_block_recorder)
                .unpack(|_| {});
            let results = valid
                .as_ref()
                .network_entrypoints()
                .enumerate()
                .map(|(index, entrypoint)| {
                    let (output_index, output) = valid
                        .as_ref()
                        .network_output_at(
                            u32::try_from(index).expect("fixture Network index fits u32"),
                        )
                        .expect("every queried input has its explicit Network output");
                    assert_eq!(usize::try_from(output_index).unwrap(), index);
                    (index, entrypoint, &output.result)
                })
                .map(|(_, _, result)| result.0.clone())
                .collect::<Vec<_>>();
            assert_eq!(
                results.iter().filter(|result| result.is_ok()).count(),
                1,
                "exactly one overlay must fit with parallel_apply={parallel_apply}: {results:?}"
            );
            assert_eq!(
                results
                    .iter()
                    .filter(|result| matches!(
                        result,
                        Err(TransactionRejectionReason::Validation(
                            ValidationFail::NotPermitted(message)
                        )) if message.contains("block gas limit exceeded")
                    ))
                    .count(),
                2,
                "every overlay after the cap must fail before execution with parallel_apply={parallel_apply}: {results:?}"
            );
            assert_eq!(
                state_block.gas_used_in_block, expected_gas,
                "the rejected overlay must fail its base-gas reservation before executing work"
            );
        }
    }
    #[test]
    fn rejected_prepared_overlay_accounts_full_gas_exactly_once() {
        let chain_id = ChainId::from("rejected-overlay-exact-gas");
        let (authority, keypair) = gen_account_in("wonderland");
        let (missing_account, _) = gen_account_in("missing");
        let mut state = state_with_transaction_policy(&chain_id, &authority, false, false);
        let mut pipeline = state.installed_pipeline().clone();
        pipeline.parallel_overlay = true;
        pipeline.workers = 2;
        state.set_pipeline(pipeline);
        let native_chain = crate::block::tests::component_chain(state);
        let state = native_chain.state();
        let instruction = InstructionBox::from(SetKeyValue::account(
            missing_account,
            "rejected_overlay_marker".parse().expect("metadata key"),
            Json::new("must roll back"),
        ));
        let expected_gas = crate::gas::meter_instructions(
            core::slice::from_ref(&instruction),
            &crate::gas::DEFAULT_ZK_GAS,
        )
        .expect("completed fixture gas quote");
        assert!(expected_gas > 0, "the fixture must consume gas");
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction])
        .sign(keypair.private_key());
        let _previous = previous_block_at_height(1);
        let previous = state
            .view()
            .latest_block()
            .expect("original block read attempt")
            .expect("original genesis");
        let block = BlockBuilder::new(vec![AcceptedTransaction::new_unchecked(Cow::Owned(
            transaction,
        ))])
        .chain(1, Some(&previous))
        .sign(keypair.private_key())
        .unpack(|_| {});
        let (mut state_block, state_block_recorder) =
            crate::block::ValidBlock::start_component_execution(&block.clone().into(), state)
                .expect("original writer-first component execution");
        state_block.gas_limit_per_block = expected_gas.saturating_mul(4);

        let valid = block
            .validate_and_record_transactions(&mut state_block, state_block_recorder)
            .unpack(|_| {});
        let results = valid
            .as_ref()
            .network_entrypoints()
            .enumerate()
            .map(|(index, entrypoint)| {
                let (output_index, output) = valid
                    .as_ref()
                    .network_output_at(
                        u32::try_from(index).expect("fixture Network index fits u32"),
                    )
                    .expect("every queried input has its explicit Network output");
                assert_eq!(usize::try_from(output_index).unwrap(), index);
                (index, entrypoint, &output.result)
            })
            .map(|(_, _, result)| result.0.clone())
            .collect::<Vec<_>>();
        assert!(matches!(results.as_slice(), [Err(_)]), "{results:?}");
        assert_eq!(state_block.gas_used_in_block, expected_gas);
    }
    fn add_pipeline_metadata_trigger(
        world: &mut World,
        authority: &AccountId,
        trigger_id: &str,
        key: Name,
        filter: PipelineEventFilterBox,
    ) {
        let mut action = crate::smartcontracts::triggers::specialized::SpecializedAction::new(
            vec![InstructionBox::from(SetKeyValue::account(
                authority.clone(),
                key,
                Json::new("ok"),
            ))],
            Repeats::Exactly(1),
            authority.clone(),
            filter,
        )
        .expect("test pipeline-trigger action satisfies its authority invariant");
        // These component actions become active after original genesis. They cannot
        // consume their one-shot invocation during genesis execution itself.
        action.metadata.insert(
            crate::smartcontracts::isi::triggers::TRIGGER_REGISTERED_BLOCK_HEIGHT_METADATA_KEY
                .parse()
                .expect("valid trigger lifecycle metadata key"),
            Json::from(1_u64),
        );
        let mut trigger_block = world.triggers.block();
        let mut trigger_transaction = trigger_block.transaction();
        trigger_transaction
            .add_pipeline_trigger(
                crate::smartcontracts::triggers::specialized::SpecializedTrigger::new(
                    trigger_id.parse().expect("trigger id"),
                    action,
                ),
            )
            .expect("add pipeline trigger");
        trigger_transaction.apply();
        trigger_block.commit();
    }
    pub(super) fn previous_block_at_height(height: u64) -> SignedBlock {
        let leader = crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal);
        let (_leader_public, leader_private) = leader.into_parts();
        let latest_valid = ValidBlock::new_dummy_and_modify_header(&leader_private, |header| {
            header.set_height(NonZeroU64::new(height).expect("non-zero height"));
        });
        latest_valid.into()
    }
    fn validation_error_message(block: &SignedBlock) -> String {
        block
            .output_results()
            .enumerate()
            .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
            .map(|(_, err)| format!("{err:?}"))
            .expect("block must contain a transaction error")
    }
    pub(super) fn sealed_set_key_entrypoints(
        network_id: NetworkId,
        authority: &AccountId,
        keypair: &KeyPair,
        reveal_after_height: u64,
        reveal_deadline_height: u64,
        metadata_key: Name,
    ) -> (TransactionEntrypoint, TransactionEntrypoint) {
        let mut builder = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::ZERO);
        let signed = builder
            .with_instructions([SetKeyValue::account(
                authority.clone(),
                metadata_key,
                Json::new("revealed"),
            )])
            .sign(keypair.private_key());
        sealed_entrypoints_from_signed(
            network_id,
            authority,
            keypair,
            reveal_after_height,
            reveal_deadline_height,
            signed,
        )
    }
    fn sealed_entrypoints_from_signed(
        network_id: NetworkId,
        authority: &AccountId,
        keypair: &KeyPair,
        reveal_after_height: u64,
        reveal_deadline_height: u64,
        signed: SignedTransaction,
    ) -> (TransactionEntrypoint, TransactionEntrypoint) {
        let salt = [0x5A; 32];
        let commitment = compute_sealed_transaction_commitment(
            &network_id,
            &signed,
            salt,
            reveal_deadline_height,
        );
        let payload = SealedTransactionCommitmentPayload::new(
            network_id,
            authority.clone(),
            commitment,
            reveal_after_height,
            reveal_deadline_height,
            None,
        );
        let signed_commitment =
            SignedSealedTransactionCommitment::sign(payload, keypair.private_key());
        let reveal = SealedTransactionReveal::new(commitment, signed, salt);
        (
            TransactionEntrypoint::SealedCommitment(signed_commitment),
            TransactionEntrypoint::SealedReveal(reveal),
        )
    }
    #[test]
    fn block_validation_external_only_records_entrypoint_hash_without_fallback() {
        let chain_id = ChainId::from("external-only-borrowed-validation");
        let (authority, keypair) = gen_account_in("wonderland");
        let state = state_with_transaction_policy(&chain_id, &authority, false, false);
        let native_chain = crate::block::tests::component_chain(state);
        let state = native_chain.state();
        let signed = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "external-only".to_owned())])
        .sign(keypair.private_key());
        let entrypoint_hash = TransactionEntrypoint::External(signed.clone()).hash();
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(signed));
        let block = BlockBuilder::new(vec![accepted])
            .chain(
                0,
                state
                    .view()
                    .latest_block()
                    .expect("original block read attempt")
                    .as_deref(),
            )
            .sign(keypair.private_key())
            .unpack(|_| {});
        let (mut state_block, state_block_recorder) =
            crate::block::ValidBlock::start_component_execution(&block.clone().into(), state)
                .expect("original writer-first component execution");
        let valid_block = block
            .validate_and_record_transactions(&mut state_block, state_block_recorder)
            .unpack(|_| {});
        let results: Vec<_> = valid_block
            .as_ref()
            .network_entrypoints()
            .enumerate()
            .map(|(index, entrypoint)| {
                let (output_index, output) = valid_block
                    .as_ref()
                    .network_output_at(
                        u32::try_from(index).expect("fixture Network index fits u32"),
                    )
                    .expect("every queried input has its explicit Network output");
                assert_eq!(usize::try_from(output_index).unwrap(), index);
                (index, entrypoint, &output.result)
            })
            .collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1.hash(), entrypoint_hash);
        assert!(
            results[0].2.0.is_ok(),
            "external-only transaction must execute successfully: {:?}",
            results[0].2
        );
    }
    #[test]
    fn external_executables_keep_one_canonical_network_source() {
        let network_id = deterministic_test_network_id(0x0C);
        let (authority, keypair) = gen_account_in("wonderland");
        let make_block = |tx: SignedTransaction| {
            BlockBuilder::new(vec![AcceptedTransaction::new_unchecked(Cow::Owned(tx))])
                .chain(0, None)
                .sign(keypair.private_key())
                .unpack(|_| {})
                .into()
        };
        let instructions_tx = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "plain".to_owned())])
        .sign(keypair.private_key());
        let instructions_block: SignedBlock = make_block(instructions_tx);
        assert!(
            matches!(
                instructions_block.network_entrypoint_at(0),
                Some(TransactionEntrypoint::External(_))
            ) && instructions_block.network_entrypoint_count() == 1,
            "plain Instructions retain their actual signed Network input"
        );
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &network_id,
            &authority,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let contract_tx = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::ContractCall(
            iroha_data_model::transaction::executable::ContractInvocation {
                contract_address,
                expected_code_hash: Hash::new(b"overlay-routing-contract-code"),
                entrypoint: "increment".to_owned(),
                arguments: None,
            },
        ))
        .sign(keypair.private_key());
        let contract_block: SignedBlock = make_block(contract_tx);
        assert!(
            matches!(
                contract_block.network_entrypoint_at(0),
                Some(TransactionEntrypoint::External(_))
            ) && contract_block.network_entrypoint_count() == 1,
            "ContractCall retains its actual signed Network input"
        );
        let ivm_tx = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(vec![0x01])))
        .sign(keypair.private_key());
        let ivm_block: SignedBlock = make_block(ivm_tx);
        assert!(
            matches!(
                ivm_block.network_entrypoint_at(0),
                Some(TransactionEntrypoint::External(_))
            ) && ivm_block.network_entrypoint_count() == 1,
            "raw IVM retains its actual signed Network input"
        );
        let proved_tx = TransactionBuilder::new(
            network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::IvmProved(IvmProved {
            bytecode: IvmBytecode::from_compiled(vec![0x01, 0x02, 0x03]),
            overlay: Vec::<InstructionBox>::new().into(),
            events_commitment: Hash::new(b"events"),
            gas_policy_commitment: Hash::new(b"gas"),
        }))
        .sign(keypair.private_key());
        let proved_block: SignedBlock = make_block(proved_tx);
        assert!(
            matches!(
                proved_block.network_entrypoint_at(0),
                Some(TransactionEntrypoint::External(_))
            ) && proved_block.network_entrypoint_count() == 1,
            "IvmProved retains its actual signed Network input; execution still verifies the proof"
        );
    }
    #[test]
    fn block_overlay_rejects_protected_contract_call_without_persisting_state() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let chain_id = ChainId::from("protected-contract-overlay");
        let (authority, keypair) = gen_account_in("wonderland");
        let domain =
            Domain::new(DomainId::try_new("wonderland", "universal").expect("valid domain"))
                .build(&authority);
        let account = Account::new(authority.clone()).build(&authority);
        let mut world = World::with([domain], [account], []);
        let source = r"
seiyaku GuardedOverlay { permission CanWriteGuardedOverlay;
  state StateMap<int, int> Values;

  kotoage fn write(int value) authorize(CanWriteGuardedOverlay) {
    Values[0] = value;
  }
}
";
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(source)
            .expect("compile protected overlay contract");
        let interface = ivm::ProgramMetadata::parse(&program)
            .expect("parse protected contract")
            .contract_interface
            .expect("compiled contract interface");
        let code_hash = ivm::contract_code_hash(&program);
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        let artifact_id = ContractArtifactId::for_address(&contract_address, code_hash)
            .expect("contract address retains its exact artifact dataspace");
        world.contract_code.insert(artifact_id, program);
        world.contract_manifests.insert(
            artifact_id,
            manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &keypair,
                )
                .expect("sign bounded fixture manifest"),
        );
        world
            .contract_instances
            .insert(contract_address.clone(), code_hash);
        let contract_subject = contract_address.subject_id();
        world.accounts.insert(
            contract_subject.clone(),
            iroha_data_model::account::AccountValue::new(
                iroha_data_model::account::AccountDetails::default(),
            ),
        );
        world.contract_subject_bindings.insert(
            contract_address.clone(),
            crate::smartcontracts::code::ContractSubjectBinding::new_direct(
                &contract_address,
                authority.clone(),
            )
            .with_active_code_hash(code_hash),
        );
        world
            .contract_subject_addresses
            .insert(contract_subject, contract_address.clone());
        let state = State::new_with_chain_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain_id.clone(),
        );
        let native_chain = crate::block::tests::component_chain(state);
        let state = native_chain.state();
        let payload = Json::new(norito::json!({ "value": "9" }));
        let schema = interface
            .entrypoints
            .iter()
            .find(|descriptor| descriptor.name == "write")
            .and_then(|descriptor| descriptor.argument_schema.as_ref());
        let arguments = crate::executor::encode_contract_argument_record(schema, Some(&payload))
            .expect("encode guarded arguments")
            .map(iroha_data_model::transaction::executable::ContractArgumentRecord::try_new)
            .transpose()
            .expect("bounded guarded arguments");
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(
                Vec::new(),
                core::num::NonZeroU64::new(100_000),
            ),
        )
        .with_executable(Executable::ContractCall(
            iroha_data_model::transaction::executable::ContractInvocation {
                contract_address,
                expected_code_hash: code_hash,
                entrypoint: "write".to_owned(),
                arguments,
            },
        ))
        .sign(keypair.private_key());
        let block = BlockBuilder::new(vec![AcceptedTransaction::new_unchecked(Cow::Owned(
            transaction,
        ))])
        .chain(
            0,
            state
                .view()
                .latest_block()
                .expect("original block read attempt")
                .as_deref(),
        )
        .sign(keypair.private_key())
        .unpack(|_| {});
        let (mut state_block, state_block_recorder) =
            crate::block::ValidBlock::start_component_execution(&block.clone().into(), state)
                .expect("original writer-first component execution");
        let initial_smart_contract_state = state_block
            .world
            .smart_contract_state
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        let valid = block
            .validate_and_record_transactions(&mut state_block, state_block_recorder)
            .unpack(|_| {});
        let results = valid
            .as_ref()
            .network_entrypoints()
            .enumerate()
            .map(|(index, entrypoint)| {
                let (output_index, output) = valid
                    .as_ref()
                    .network_output_at(
                        u32::try_from(index).expect("fixture Network index fits u32"),
                    )
                    .expect("every queried input has its explicit Network output");
                assert_eq!(usize::try_from(output_index).unwrap(), index);
                (index, entrypoint, &output.result)
            })
            .map(|(_, _, result)| result.0.clone())
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);
        assert!(
            results[0].as_ref().is_err_and(|error| matches!(
                error,
                TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message))
                    if message.contains("CanWriteGuardedOverlay")
            )),
            "protected overlay call must be rejected with its stable permission name: {results:?}"
        );
        let final_smart_contract_state = state_block
            .world
            .smart_contract_state
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            final_smart_contract_state, initial_smart_contract_state,
            "a denied overlay must not persist any contract state"
        );
    }
    #[test]
    fn block_validation_reprepares_stale_contract_state_read_modify_write() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let chain_id = ChainId::from("durable-state-read-validation");
        let (alice, alice_keypair) = gen_account_in("wonderland");
        let (bob, bob_keypair) = gen_account_in("wonderland");
        let domain_id = DomainId::try_new("wonderland", "universal").expect("valid domain");
        let domain = Domain::new(domain_id).build(&alice);
        let alice_account = Account::new(alice.clone()).build(&alice);
        let bob_account = Account::new(bob.clone()).build(&alice);
        let mut world = World::with([domain], [alice_account, bob_account], []);
        let source = r"
seiyaku DynamicAccessCounter { permission CanWriteCounters;
  state StateMap<int, int> Counters;

  fn bump_hidden(int key, int delta) {
    let current = Counters.get(key).unwrap_or(0);
    Counters[key] = current + delta;
  }

  kotoage fn bump_direct(int key, int delta) authorize(CanWriteCounters) {
    let current = Counters.get(key).unwrap_or(0);
    Counters[key] = current + delta;
  }

  kotoage fn bump_via_helper(int key, int delta) authorize(CanWriteCounters) {
    bump_hidden(key: key, delta: delta);
  }
}
";
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(source)
            .expect("compile dynamic StateMap counter");
        let contract_interface = ivm::ProgramMetadata::parse(&program)
            .expect("parse compiled contract")
            .contract_interface
            .expect("compiled contract interface");
        let code_hash = ivm::contract_code_hash(&program);
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &alice,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        // Contract-local declarations require the exact instance and permission grant.
        for authority in [&alice, &bob] {
            let mut permissions = iroha_data_model::permission::Permissions::new();
            assert!(permissions.insert(
                iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                    contract: contract_address.clone(),
                    permission: "CanWriteCounters".parse().expect("declared contract permission"),
                }
                .into(),
            ));
            world
                .account_permissions_mut_for_testing()
                .insert(authority.clone(), permissions);
        }
        let artifact_id = ContractArtifactId::for_address(&contract_address, code_hash)
            .expect("contract address retains its exact artifact dataspace");
        world.contract_code.insert(artifact_id, program);
        world.contract_manifests.insert(
            artifact_id,
            manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &alice_keypair,
                )
                .expect("sign bounded fixture manifest"),
        );
        world
            .contract_instances
            .insert(contract_address.clone(), code_hash);
        let contract_subject = contract_address.subject_id();
        world.accounts.insert(
            contract_subject.clone(),
            iroha_data_model::account::AccountValue::new(
                iroha_data_model::account::AccountDetails::default(),
            ),
        );
        world.contract_subject_bindings.insert(
            contract_address.clone(),
            crate::smartcontracts::code::ContractSubjectBinding::new_direct(
                &contract_address,
                alice.clone(),
            )
            .with_active_code_hash(code_hash),
        );
        world
            .contract_subject_addresses
            .insert(contract_subject, contract_address.clone());
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let mut state = State::new_with_chain_for_testing(world, kura, query, chain_id.clone());
        let mut pipeline = state.installed_pipeline().clone();
        pipeline.dynamic_prepass = true;
        pipeline.parallel_overlay = true;
        pipeline.parallel_apply = true;
        pipeline.workers = 2;
        state.set_pipeline(pipeline);
        let native_chain = component_chain(state);
        let state = native_chain.state();
        let make_call = |authority: AccountId, keypair: &KeyPair, entrypoint: &str, delta: i64| {
            let payload = Json::new(norito::json!({
                "key": "7",
                "delta": (delta.to_string()),
            }));
            let schema = contract_interface
                .entrypoints
                .iter()
                .find(|descriptor| descriptor.name == entrypoint)
                .and_then(|descriptor| descriptor.argument_schema.as_ref());
            let arguments =
                crate::executor::encode_contract_argument_record(schema, Some(&payload))
                    .expect("encode contract arguments")
                    .map(iroha_data_model::transaction::executable::ContractArgumentRecord::try_new)
                    .transpose()
                    .expect("bounded contract arguments");
            TransactionBuilder::new(
                state.network_id,
                authority,
                iroha_data_model::transaction::FeePaymentIntent::authority(
                    Vec::new(),
                    core::num::NonZeroU64::new(1_000_000),
                ),
            )
            .with_executable(Executable::ContractCall(
                iroha_data_model::transaction::executable::ContractInvocation {
                    contract_address: contract_address.clone(),
                    expected_code_hash: code_hash,
                    entrypoint: entrypoint.to_owned(),
                    arguments,
                },
            ))
            .sign(keypair.private_key())
        };
        let direct = make_call(alice.clone(), &alice_keypair, "bump_direct", 3);
        let helper = make_call(bob, &bob_keypair, "bump_via_helper", 5);
        let accepted = [direct, helper]
            .into_iter()
            .map(|tx| AcceptedTransaction::new_unchecked(Cow::Owned(tx)))
            .collect();
        let block = BlockBuilder::new(accepted)
            .chain(
                0,
                state
                    .view()
                    .latest_block()
                    .expect("original block read attempt")
                    .as_deref(),
            )
            .sign(alice_keypair.private_key())
            .unpack(|_| {});
        let (mut state_block, state_block_recorder) =
            crate::block::ValidBlock::start_component_execution(&block.clone().into(), state)
                .expect("original writer-first component execution");
        let valid = block
            .validate_and_record_transactions(&mut state_block, state_block_recorder)
            .unpack(|_| {});
        let results = valid
            .as_ref()
            .network_entrypoints()
            .enumerate()
            .map(|(index, entrypoint)| {
                let (output_index, output) = valid
                    .as_ref()
                    .network_output_at(
                        u32::try_from(index).expect("fixture Network index fits u32"),
                    )
                    .expect("every queried input has its explicit Network output");
                assert_eq!(usize::try_from(output_index).unwrap(), index);
                (index, entrypoint, &output.result)
            })
            .map(|(_, _, result)| result.0.clone())
            .collect::<Vec<_>>();
        assert!(
            results.iter().all(Result::is_ok),
            "both co-batched contract calls must succeed: {results:?}"
        );
        let encoded_key = encode_fixture_int_map_key(7);
        let logical_path = format!("Counters/{}", hex::encode(encoded_key));
        let scope_id = contract_address.to_string();
        let scope_digest = hex::encode(Hash::new(scope_id.as_bytes()).as_ref());
        let scoped_path: StatePath = format!("sc/{scope_digest}/{logical_path}")
            .parse()
            .expect("valid scoped StateMap path");
        let stored = state_block
            .world
            .smart_contract_state
            .get(&scoped_path)
            .expect("counter state must be persisted");
        let counter = decode_stored_state_int(stored);
        assert_eq!(
            counter, 8,
            "the second overlay must be recomputed from the first call's committed value"
        );
    }
    #[test]
    fn block_validation_serializes_a_dynamic_target_that_changes_during_reprepare() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let chain_id = ChainId::from("dynamic-target-live-reprepare");
        let (alice, alice_keypair) = gen_account_in("wonderland");
        let (bob, bob_keypair) = gen_account_in("wonderland");
        let (charlie, charlie_keypair) = gen_account_in("wonderland");
        let (dave, dave_keypair) = gen_account_in("wonderland");
        let domain_id = DomainId::try_new("wonderland", "universal").expect("valid domain");
        let domain = Domain::new(domain_id).build(&alice);
        let accounts = [
            Account::new(alice.clone()).build(&alice),
            Account::new(bob.clone()).build(&alice),
            Account::new(charlie.clone()).build(&alice),
            Account::new(dave.clone()).build(&alice),
        ];
        let mut world = World::with([domain], accounts, []);
        let source = r"
seiyaku DynamicTarget { permission CanWriteCounters;
  error enum DynamicTargetError {
    SelectorClosed = 1,
  }

  state StateMap<int, int> Selector;
  state StateMap<int, int> Counters;

  kotoage fn choose(int key) authorize(CanWriteCounters) {
    Selector[0] = key;
  }

  kotoage fn set_selected(int value) authorize(CanWriteCounters) {
    let key = Selector.get(0).unwrap_or(1);
    Counters[key] = value;
  }

  kotoage fn set_direct(int key, int value) authorize(CanWriteCounters) {
    Counters[key] = value;
  }

  kotoage fn guarded_set(int value) authorize(CanWriteCounters) {
    require(Selector.get(0).unwrap_or(0) == 2, DynamicTargetError::SelectorClosed);
    Counters[3] = value;
  }
}
";
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(source)
            .expect("compile dynamic-target contract");
        let contract_interface = ivm::ProgramMetadata::parse(&program)
            .expect("parse compiled contract")
            .contract_interface
            .expect("compiled contract interface");
        let code_hash = ivm::contract_code_hash(&program);
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &alice,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        // Contract-local declarations require the exact instance and permission grant.
        for authority in [&alice, &bob, &charlie, &dave] {
            let mut permissions = iroha_data_model::permission::Permissions::new();
            assert!(permissions.insert(
                iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                    contract: contract_address.clone(),
                    permission: "CanWriteCounters".parse().expect("declared contract permission"),
                }
                .into(),
            ));
            world
                .account_permissions_mut_for_testing()
                .insert(authority.clone(), permissions);
        }
        let artifact_id = ContractArtifactId::for_address(&contract_address, code_hash)
            .expect("contract address retains its exact artifact dataspace");
        world.contract_code.insert(artifact_id, program);
        world.contract_manifests.insert(
            artifact_id,
            manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &alice_keypair,
                )
                .expect("sign bounded fixture manifest"),
        );
        world
            .contract_instances
            .insert(contract_address.clone(), code_hash);
        let contract_subject = contract_address.subject_id();
        world.accounts.insert(
            contract_subject.clone(),
            iroha_data_model::account::AccountValue::new(
                iroha_data_model::account::AccountDetails::default(),
            ),
        );
        world.contract_subject_bindings.insert(
            contract_address.clone(),
            crate::smartcontracts::code::ContractSubjectBinding::new_direct(
                &contract_address,
                alice.clone(),
            )
            .with_active_code_hash(code_hash),
        );
        world
            .contract_subject_addresses
            .insert(contract_subject, contract_address.clone());
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let mut state = State::new_with_chain_for_testing(world, kura, query, chain_id.clone());
        let mut pipeline = state.installed_pipeline().clone();
        pipeline.dynamic_prepass = true;
        pipeline.parallel_overlay = true;
        pipeline.parallel_apply = true;
        pipeline.workers = 4;
        state.set_pipeline(pipeline);
        let native_chain = crate::block::tests::component_chain(state);
        let state = native_chain.state();
        let make_call = |authority: AccountId,
                         keypair: &KeyPair,
                         entrypoint: &str,
                         payload: Json,
                         fixture_nonce: u64| {
            let mut metadata = Metadata::default();
            metadata.insert(
                "dynamic_target_fixture_nonce"
                    .parse()
                    .expect("fixture nonce name"),
                Json::new(fixture_nonce),
            );
            let schema = contract_interface
                .entrypoints
                .iter()
                .find(|descriptor| descriptor.name == entrypoint)
                .and_then(|descriptor| descriptor.argument_schema.as_ref());
            let arguments =
                crate::executor::encode_contract_argument_record(schema, Some(&payload))
                    .expect("encode contract arguments")
                    .map(iroha_data_model::transaction::executable::ContractArgumentRecord::try_new)
                    .transpose()
                    .expect("bounded contract arguments");
            TransactionBuilder::new(
                state.network_id,
                authority,
                iroha_data_model::transaction::FeePaymentIntent::authority(
                    Vec::new(),
                    core::num::NonZeroU64::new(1_000_000),
                ),
            )
            .with_metadata(metadata)
            .with_executable(Executable::ContractCall(
                iroha_data_model::transaction::executable::ContractInvocation {
                    contract_address: contract_address.clone(),
                    expected_code_hash: code_hash,
                    entrypoint: entrypoint.to_owned(),
                    arguments,
                },
            ))
            .sign(keypair.private_key())
        };
        let choose = (0_u64..)
            .find_map(|nonce| {
                let tx = make_call(
                    alice.clone(),
                    &alice_keypair,
                    "choose",
                    Json::new(norito::json!({ "key": "2" })),
                    nonce,
                );
                (tx.hash_as_entrypoint().as_ref()[0] < 0x10).then_some(tx)
            })
            .expect("find selector update in the first canonical hash band");
        let selected = (0_u64..)
            .find_map(|nonce| {
                let tx = make_call(
                    bob.clone(),
                    &bob_keypair,
                    "set_selected",
                    Json::new(norito::json!({ "value": "5" })),
                    nonce,
                );
                (0x40..0x50)
                    .contains(&tx.hash_as_entrypoint().as_ref()[0])
                    .then_some(tx)
            })
            .expect("find selected write in the second canonical hash band");
        let direct = (0_u64..)
            .find_map(|nonce| {
                let tx = make_call(
                    charlie.clone(),
                    &charlie_keypair,
                    "set_direct",
                    Json::new(norito::json!({ "key": "2", "value": "7" })),
                    nonce,
                );
                (0x80..0x90)
                    .contains(&tx.hash_as_entrypoint().as_ref()[0])
                    .then_some(tx)
            })
            .expect("find direct write in the third canonical hash band");
        let guarded = (0_u64..)
            .find_map(|nonce| {
                let tx = make_call(
                    dave.clone(),
                    &dave_keypair,
                    "guarded_set",
                    Json::new(norito::json!({ "value": "11" })),
                    nonce,
                );
                (tx.hash_as_entrypoint().as_ref()[0] >= 0xF0).then_some(tx)
            })
            .expect("find guarded write in the final canonical hash band");
        let accepted = [choose, selected, direct, guarded]
            .into_iter()
            .map(|tx| AcceptedTransaction::new_unchecked(Cow::Owned(tx)))
            .collect();
        let block = BlockBuilder::new(accepted)
            .chain(
                0,
                state
                    .view()
                    .latest_block()
                    .expect("original block read attempt")
                    .as_deref(),
            )
            .sign(alice_keypair.private_key())
            .unpack(|_| {});
        let (mut state_block, state_block_recorder) =
            crate::block::ValidBlock::start_component_execution(&block.clone().into(), state)
                .expect("original writer-first component execution");
        let valid = block
            .validate_and_record_transactions(&mut state_block, state_block_recorder)
            .unpack(|_| {});
        let results = valid
            .as_ref()
            .network_entrypoints()
            .enumerate()
            .map(|(index, entrypoint)| {
                let (output_index, output) = valid
                    .as_ref()
                    .network_output_at(
                        u32::try_from(index).expect("fixture Network index fits u32"),
                    )
                    .expect("every queried input has its explicit Network output");
                assert_eq!(usize::try_from(output_index).unwrap(), index);
                (index, entrypoint, &output.result)
            })
            .map(|(_, _, result)| result.0.clone())
            .collect::<Vec<_>>();
        assert!(
            results.iter().all(Result::is_ok),
            "all dynamic-target calls must succeed: {results:?}"
        );
        let encoded_key = encode_fixture_int_map_key(2);
        let logical_path = format!("Counters/{}", hex::encode(encoded_key));
        let scope_digest = hex::encode(Hash::new(contract_address.to_string().as_bytes()).as_ref());
        let scoped_path: StatePath = format!("sc/{scope_digest}/{logical_path}")
            .parse()
            .expect("valid scoped StateMap path");
        let stored = state_block
            .world
            .smart_contract_state
            .get(&scoped_path)
            .expect("selected counter must be persisted");
        let counter = decode_stored_state_int(stored);
        assert_eq!(
            counter, 7,
            "a key selected during live re-execution must retain source-order conflict semantics"
        );
        let guarded_key = encode_fixture_int_map_key(3);
        let guarded_path: StatePath =
            format!("sc/{scope_digest}/Counters/{}", hex::encode(guarded_key))
                .parse()
                .expect("valid guarded StateMap path");
        let guarded_stored = state_block
            .world
            .smart_contract_state
            .get(&guarded_path)
            .expect("an initially failing VM overlay must be retried against live state");
        let guarded_value = decode_stored_state_int(guarded_stored);
        assert_eq!(guarded_value, 11);
    }
    #[test]
    fn block_validation_sealed_commitment_and_time_keep_distinct_canonical_sources() {
        use crate::state::{StateReadOnlyWithTransactions, TransactionsReadOnly};
        use iroha_data_model::{
            events::time::{ExecutionTime, TimeEvent, TimeEventFilter, TimeInterval},
            fastpq::{FastpqSourceExecutionKindV1, FastpqSourceRouteV1},
            trigger::{
                Trigger,
                action::{Action, Repeats},
            },
        };

        let chain_id = ChainId::from("non-external-sequential-fallback");
        let (authority, keypair) = gen_account_in("wonderland");
        let state = state_with_transaction_policy(&chain_id, &authority, false, false);
        let time_trigger_id: iroha_data_model::trigger::TriggerId =
            "non_external_sequential_heartbeat"
                .parse()
                .expect("trigger id");
        let mut trigger_metadata = Metadata::default();
        trigger_metadata.insert(
            "__registered_block_height"
                .parse()
                .expect("registered-height key"),
            Json::new(1_u64),
        );
        trigger_metadata.insert(
            "__registered_at_ms".parse().expect("registered-time key"),
            Json::new(0_u64),
        );
        let time_trigger = Trigger::new(
            time_trigger_id.clone(),
            Action::new(
                vec![InstructionBox::from(Log::new(
                    Level::INFO,
                    "sequential heartbeat".to_owned(),
                ))],
                Repeats::Exactly(1),
                authority.clone(),
                TimeEventFilter::new(ExecutionTime::PreCommit),
            )
            .expect("time-trigger action")
            .with_metadata(trigger_metadata),
        );
        {
            let mut triggers_block = state.world.triggers.block();
            let mut triggers_transaction = triggers_block.transaction();
            triggers_transaction
                .add_time_trigger(time_trigger.try_into().expect("specialized time trigger"))
                .expect("add time trigger");
            triggers_transaction.apply();
            triggers_block.commit();
        }
        let mut native_chain = component_chain(state);
        let state = Arc::clone(native_chain.state());
        let parent = state
            .view()
            .latest_block()
            .expect("original block read attempt")
            .expect("original signed genesis");
        let metadata_key = Name::from_str("sequential_fallback_marker").expect("metadata key");
        let (commitment_entrypoint, _reveal_entrypoint) =
            sealed_set_key_entrypoints(state.network_id, &authority, &keypair, 3, 4, metadata_key);
        let commitment_entrypoint_hash = commitment_entrypoint.hash();
        let commitment_call_hash = Hash::from(commitment_entrypoint.execution_call_hash());
        let block = native_chain.proposal_entrypoints(vec![commitment_entrypoint]);
        let time_event = TimeEvent {
            interval: TimeInterval::new(
                parent.header().creation_time(),
                block
                    .header()
                    .creation_time()
                    .saturating_sub(parent.header().creation_time()),
            ),
        };
        let expected_invocation = iroha_data_model::block::execution_output::TimeInvocationV1 {
            schedule_index: 0,
            event: time_event,
            trigger:
                crate::smartcontracts::isi::triggers::set::invocation_identity::time_trigger_use_v1(
                    &state.world.triggers.view(),
                    &time_trigger_id,
                    block.header().height().get(),
                )
                .expect("bind actual stored Time action before execution"),
        };
        let expected_time_call_hash = expected_invocation
            .execution_call_hash(block.header().hash())
            .unwrap();
        let mut pending = native_chain
            .begin_proposal(block, iroha_sumeragi::types::ControlWitness::default())
            .expect("original sealed and Time sources execute together");
        let time_non_network_hash = pending
            .inspect(move |execution| {
                let valid_block = execution.block;
                let state_block = execution.state;
                let results: Vec<_> = valid_block
                    .as_ref()
                    .network_entrypoints()
                    .enumerate()
                    .map(|(index, entrypoint)| {
                        let (output_index, output) = valid_block
                            .as_ref()
                            .network_output_at(
                                u32::try_from(index).expect("fixture Network index fits u32"),
                            )
                            .expect("every queried input has its explicit Network output");
                        assert_eq!(usize::try_from(output_index).unwrap(), index);
                        (index, entrypoint, &output.result)
                    })
                    .collect();
                assert_eq!(results.len(), 1);
                assert_eq!(valid_block.as_ref().execution_outputs().len(), 2);
                assert_eq!(results[0].1.hash(), commitment_entrypoint_hash);
                assert!(
                    results[0].2.0.is_ok(),
                    "non-external entrypoint fallback must preserve execution: {:?}",
                    results[0].2
                );
                let time_output = &valid_block.as_ref().execution_outputs()[1];
                let iroha_data_model::block::execution_output::ExecutionOutputV1::Time(time) =
                    time_output
                else {
                    panic!("actual Time invocation follows the single Network output");
                };
                assert_eq!(time.invocation, expected_invocation);
                assert!(
                    time.result.is_ok(),
                    "actual Time output must succeed: {:?}",
                    time.result
                );
                let time_output_hash = HashOf::new(time_output);
                let time_non_network_hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(
                    Hash::from(time_output_hash),
                );
                assert_eq!(
                    state_block.transactions.get(&commitment_entrypoint_hash),
                    None,
                    "unpublished execution does not enter canonical replay history"
                );
                assert_eq!(
                    state_block.transactions.get(&time_non_network_hash),
                    None,
                    "an internal output hash is not a signed canonical replay carrier"
                );
                let source_inventory = state_block
                    .fastpq_source_inventory()
                    .expect("valid finalized source inventory")
                    .expect("execution retains its complete source inventory");
                let canonical_entrypoints = valid_block
                    .as_ref()
                    .external_entrypoints_cloned()
                    .collect::<Vec<_>>();
                let expected_tx_set_hash: [u8; 32] =
                    iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(
                        canonical_entrypoints.iter(),
                    )
                    .expect("canonical sequential transaction set")
                    .into();
                assert_eq!(source_inventory.tx_set_hash(), expected_tx_set_hash);
                assert_eq!(source_inventory.entries().len(), 2);
                assert_eq!(
                    source_inventory.entries()[0].entry_hash,
                    commitment_call_hash
                );
                let time_source = &source_inventory.entries()[1];
                assert_eq!(time_source.entry_hash, expected_time_call_hash);
                assert_ne!(time_source.entry_hash, Hash::from(time_output_hash));
                assert_eq!(
                    time_source.execution_kind,
                    FastpqSourceExecutionKindV1::ExecutionCall
                );
                assert_eq!(time_source.route, FastpqSourceRouteV1::Unrouted);
                assert_eq!(time_source.dataspace_id, DataSpaceId::UNIVERSAL);
                time_non_network_hash
            })
            .expect("inspect the original sealed and Time execution");
        pending
            .publish(crate::sumeragi::test_chain::Signers::Quorum)
            .expect("publish the exact certified source execution");
        drop(pending);
        let view = state.view();
        assert_eq!(
            view.transactions().get(&commitment_entrypoint_hash),
            Some(nonzero!(2_usize))
        );
        assert_eq!(
            view.transactions().get(&time_non_network_hash),
            None,
            "internal Time output never becomes a signed replay carrier"
        );
    }
    #[test]
    fn block_validation_sealed_only_entrypoint_executes_only_block_pipeline_trigger() {
        let chain_id = ChainId::from("sealed-only-pipeline-triggers");
        let network_id = deterministic_test_network_id(0x0E);
        let (authority, keypair) = gen_account_in("wonderland");
        let domain_id = DomainId::try_new("wonderland", "universal").expect("valid domain");
        let domain = Domain::new(domain_id).build(&authority);
        let account = Account::new(authority.clone()).build(&authority);
        let mut world = World::with([domain], [account], []);
        let block_key = Name::from_str("sealed_only_block_pipeline_trigger").expect("metadata key");
        let wrong_block_height_key =
            Name::from_str("sealed_only_wrong_height_block_pipeline_trigger")
                .expect("metadata key");
        let tx_key = Name::from_str("sealed_only_tx_pipeline_trigger").expect("metadata key");
        let any_tx_key =
            Name::from_str("sealed_only_any_tx_pipeline_trigger").expect("metadata key");
        let dummy_signed = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "dummy".to_owned())])
        .sign(keypair.private_key());
        add_pipeline_metadata_trigger(
            &mut world,
            &authority,
            "sealed_only_block_approved",
            block_key.clone(),
            PipelineEventFilterBox::from(BlockEventFilter::new().for_status(BlockStatus::Approved)),
        );
        add_pipeline_metadata_trigger(
            &mut world,
            &authority,
            "sealed_only_wrong_height_block_approved",
            wrong_block_height_key.clone(),
            PipelineEventFilterBox::from(
                BlockEventFilter::new()
                    .for_height(nonzero!(9999_u64))
                    .for_status(BlockStatus::Approved),
            ),
        );
        add_pipeline_metadata_trigger(
            &mut world,
            &authority,
            "sealed_only_dummy_tx_approved",
            tx_key.clone(),
            PipelineEventFilterBox::from(
                TransactionEventFilter::new()
                    .for_hash(dummy_signed.hash())
                    .for_status(TransactionStatus::Approved),
            ),
        );
        add_pipeline_metadata_trigger(
            &mut world,
            &authority,
            "sealed_only_any_tx_approved",
            any_tx_key.clone(),
            PipelineEventFilterBox::from(
                TransactionEventFilter::new().for_status(TransactionStatus::Approved),
            ),
        );
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new_with_chain_and_network_id_for_testing(
            world,
            kura,
            query_handle,
            chain_id.clone(),
            network_id,
        );
        let native_chain = component_chain(state);
        let state = native_chain.state();
        let metadata_key = Name::from_str("sealed_only_commitment_marker").expect("metadata key");
        let (commitment_entrypoint, _reveal_entrypoint) =
            sealed_set_key_entrypoints(state.network_id, &authority, &keypair, 3, 4, metadata_key);
        let accepted_commitment =
            AcceptedTransaction::new_unchecked_entrypoint(Cow::Owned(commitment_entrypoint));
        let block = BlockBuilder::new(vec![accepted_commitment])
            .chain(
                0,
                state
                    .view()
                    .latest_block()
                    .expect("original block read attempt")
                    .as_deref(),
            )
            .sign(keypair.private_key())
            .unpack(|_| {});
        assert_ne!(block.header().height(), nonzero!(9999_u64));
        let (mut state_block, state_block_recorder) =
            crate::block::ValidBlock::start_component_execution(&block.clone().into(), state)
                .expect("original writer-first component execution");
        let valid_block = block
            .validate_and_record_transactions(&mut state_block, state_block_recorder)
            .unpack(|_| {});
        assert!(
            valid_block
                .as_ref()
                .network_entrypoints()
                .enumerate()
                .map(|(index, entrypoint)| {
                    let (output_index, output) = valid_block
                        .as_ref()
                        .network_output_at(
                            u32::try_from(index).expect("fixture Network index fits u32"),
                        )
                        .expect("every queried input has its explicit Network output");
                    assert_eq!(usize::try_from(output_index).unwrap(), index);
                    (index, entrypoint, &output.result)
                })
                .all(|(_, _, result)| result.0.is_ok()),
            "sealed-only block should validate successfully"
        );
        let (block_value, wrong_block_height_value, tx_value, any_tx_value) = state_block
            .world
            .map_account(&authority, |account| {
                (
                    account.value().metadata().get(&block_key).cloned(),
                    account
                        .value()
                        .metadata()
                        .get(&wrong_block_height_key)
                        .cloned(),
                    account.value().metadata().get(&tx_key).cloned(),
                    account.value().metadata().get(&any_tx_key).cloned(),
                )
            })
            .expect("authority account exists");
        assert_eq!(block_value, Some(Json::new("ok")));
        assert_eq!(
            wrong_block_height_value, None,
            "approved block trigger must not match a different block height"
        );
        assert_eq!(
            tx_value, None,
            "sealed-only entrypoints must not synthesize transaction pipeline events for arbitrary hashes"
        );
        assert_eq!(
            any_tx_value, None,
            "sealed-only entrypoints must not synthesize broad transaction pipeline events"
        );
    }
    include!("block/sequential_rejected_pipeline_trigger_tests.rs");
    #[test]
    fn block_pipeline_executes_sealed_reveal_and_records_entrypoint_hash() {
        let chain_id = ChainId::from("sealed-block-pipeline");
        let (authority, keypair) = gen_account_in("wonderland");
        let (fee_sink, _) = gen_account_in("wonderland");
        let domain = DomainId::try_new("wonderland", "universal").unwrap();
        let fee_asset = AssetDefinitionId::parse_address_literal(
            &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
        )
        .expect("canonical network XOR identity");
        let world = World::with(
            [Domain::new(domain).build(&authority)],
            [Account::new(authority.clone()).build(&authority)],
            [],
        );
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.fees.fee_asset_id = fee_asset.clone();
        nexus.fees.fee_sink_account_id = fee_sink.clone();
        nexus.fees.base_fee = Quantity::zero();
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_instruction_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        let state = configured_component_state(world, chain_id, nexus);
        {
            let mut genesis = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
            let mut transaction = genesis.transaction();
            Register::account(Account::new(fee_sink.clone()))
                .execute(&authority, &mut transaction)
                .unwrap();
            Register::asset_definition(AssetDefinition::numeric(
                fee_asset.clone(),
                "sealed fee",
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            ))
            .execute(&authority, &mut transaction)
            .unwrap();
            Mint::asset_quantity(1_u32, AssetId::new(fee_asset.clone(), authority.clone()))
                .execute(&authority, &mut transaction)
                .unwrap();
            transaction.apply();
            genesis.commit_world_overlay_for_testing().unwrap();
        }
        let mut native_chain = component_chain(state);
        let state = Arc::clone(native_chain.state());
        let metadata_key = Name::from_str("sealed_reveal_executed").expect("metadata key");
        let mut builder = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(
                vec![iroha_data_model::transaction::FeeChargeLimit::new(
                    iroha_data_model::transaction::FeeChargeKind::Nexus,
                    fee_asset,
                    Quantity::from(1_u32),
                )],
                None,
            ),
        );
        builder.set_creation_time(Duration::ZERO);
        let signed = builder
            .with_instructions([SetKeyValue::account(
                authority.clone(),
                metadata_key.clone(),
                Json::new("revealed"),
            )])
            .sign(keypair.private_key());
        let (commitment_entrypoint, reveal_entrypoint) =
            sealed_entrypoints_from_signed(state.network_id, &authority, &keypair, 3, 4, signed);
        let commitment_entrypoint_hash = commitment_entrypoint.hash();
        let reveal_entrypoint_hash = reveal_entrypoint.hash();
        let initial_smart_contract_state_len = state.world.view().smart_contract_state.len();
        let commitment = native_chain.commit_entrypoints(vec![commitment_entrypoint]);
        let commitment_block = commitment.block();
        assert_eq!(
            commitment_block
                .network_entrypoints()
                .next()
                .unwrap()
                .hash(),
            commitment_entrypoint_hash
        );
        assert!(
            commitment_block
                .network_output_at(0)
                .unwrap()
                .1
                .result
                .is_ok(),
            "sealed commitment executes"
        );
        assert_eq!(
            state.world.view().smart_contract_state.len(),
            initial_smart_contract_state_len + 1,
            "the actual committed block retains one pending commitment"
        );
        let reveal = native_chain.commit_entrypoints(vec![reveal_entrypoint]);
        assert_eq!(
            reveal.block().network_entrypoints().next().unwrap().hash(),
            reveal_entrypoint_hash
        );
        assert!(
            reveal
                .block()
                .network_output_at(0)
                .unwrap()
                .1
                .result
                .is_ok(),
            "sealed reveal executes the signed inner transaction: {:?}",
            reveal.block().network_output_at(0).unwrap().1.result
        );
        assert_eq!(
            state.world.view().smart_contract_state.len(),
            initial_smart_contract_state_len,
            "successful reveal consumes the pending commitment exactly once"
        );
        let view = state.view();
        let metadata_value = view
            .world()
            .map_account(&authority, |account| {
                account.value().metadata().get(&metadata_key).cloned()
            })
            .unwrap();
        assert_eq!(metadata_value, Some(Json::new("revealed")));
    }
    #[test]
    fn block_pipeline_finalizes_sealed_reveal_batch_receipts_on_outer_result_once() {
        use iroha_data_model::sumeragi_lanes::{
            SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy, SumeragiLaneRoute,
        };

        let (authority, keypair) = gen_account_in("wonderland");
        let (destination, _destination_keypair) = gen_account_in("wonderland");
        let sealed_dataspace = DataSpaceId::new(7);
        let sealed_dataspace_alias = "sealed-dataspace-7";
        let domain_id = DomainId::try_new("wonderland", sealed_dataspace_alias).expect("domain id");
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "sealed_coin".parse().expect("asset name"),
        );
        let source_asset_id = AssetId::with_scope(
            asset_definition_id.clone(),
            authority.clone(),
            iroha_data_model::asset::AssetBalanceScope::Dataspace(sealed_dataspace),
        );
        let destination_asset_id = AssetId::with_scope(
            asset_definition_id.clone(),
            destination.clone(),
            iroha_data_model::asset::AssetBalanceScope::Dataspace(sealed_dataspace),
        );
        let world = World::with_assets(
            [Domain::new(domain_id.clone()).build(&authority)],
            [
                Account::new(authority.clone()).build(&authority),
                Account::new(destination.clone()).build(&destination),
            ],
            [AssetDefinition::numeric(
                asset_definition_id.clone(),
                "sealed batch coin".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
                Some(domain_id.clone()),
            )
            .build(&authority)],
            [Asset::new(source_asset_id.clone(), Quantity::from(10_u32))],
            [],
        );
        let sealed_lane = LaneId::new(1);
        let lane_catalog = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: sealed_lane,
                    dataspace_id: sealed_dataspace,
                    alias: "sealed-dataspace".to_owned(),
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("sealed test lane catalog");
        let dataspace_catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata {
                id: DataSpaceId::UNIVERSAL,
                alias: "universal".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
            DataSpaceMetadata {
                id: sealed_dataspace,
                alias: sealed_dataspace_alias.to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("sealed test dataspace catalog");
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.lane_catalog = lane_catalog;
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        nexus.dataspace_catalog = dataspace_catalog;
        nexus.routing_policy.default_lane = LaneId::SINGLE;
        nexus.routing_policy.default_dataspace = DataSpaceId::UNIVERSAL;
        nexus.fees.base_fee = Quantity::zero();
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_instruction_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        // Lane zero remains global/universal; the signed native policy authorizes DS7 separately.
        let state = State::new_with_pre_genesis_nexus_for_testing(
            world,
            nexus,
            LiveQueryStore::start_test(),
        );
        assert_eq!(
            state
                .world
                .view()
                .asset_definition_domains()
                .get(&asset_definition_id),
            Some(&domain_id),
            "the fixture asset must be authoritative on the sealed execution dataspace"
        );

        let lane_policy = SumeragiLanePolicy {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            anchor_freshness: 64,
            max_merge_blocks: 16,
            stall_window: 1_000,
            lane_params: iroha_data_model::parameter::system::SumeragiParameters::default(),
            fixed: vec![SumeragiFixedLane {
                lane: sealed_lane,
                dataspace: sealed_dataspace,
                committee: crate::sumeragi::test_chain::fixture_validators()
                    .into_iter()
                    .map(|(peer, pop)| SumeragiLaneMember { peer, pop })
                    .collect(),
            }],
            routes: vec![SumeragiLaneRoute {
                lane: sealed_lane,
                account: Some(authority.to_string()),
                instruction: None,
            }],
            autoscale: None,
        };
        let mut native_chain = component_chain_with_genesis_parameters(
            state,
            vec![iroha_data_model::parameter::Parameter::Custom(
                lane_policy.into_custom_parameter(),
            )],
        );
        native_chain.commit(Vec::new());
        native_chain.commit(Vec::new());
        let state = Arc::clone(native_chain.state());
        let reveal_height = native_chain.height() + 2;
        let reveal_deadline = reveal_height + 1;
        let mut transaction_builder = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        transaction_builder.set_creation_time(Duration::ZERO);
        let signed = transaction_builder
            .with_instructions([TransferAssetBatch::independent(vec![
                TransferAssetBatchEntry::with_leg_id(
                    "sealed-batch-leg",
                    authority.clone(),
                    destination.clone(),
                    asset_definition_id,
                    3_u32,
                ),
            ])])
            .sign(keypair.private_key());
        let inner_call_hash = signed.hash_as_entrypoint();
        let salt = [0x5B; 32];
        let commitment = compute_sealed_transaction_commitment(
            &state.network_id,
            &signed,
            salt,
            reveal_deadline,
        );
        let commitment_entrypoint =
            TransactionEntrypoint::SealedCommitment(SignedSealedTransactionCommitment::sign(
                SealedTransactionCommitmentPayload::new(
                    state.network_id,
                    authority,
                    commitment,
                    reveal_height,
                    reveal_deadline,
                    None,
                ),
                keypair.private_key(),
            ));
        let reveal_entrypoint = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            commitment, signed, salt,
        ));
        let outer_reveal_hash = reveal_entrypoint.hash();

        let committed = native_chain.commit_entrypoints(vec![commitment_entrypoint]);
        assert!(
            committed
                .block()
                .network_output_at(0)
                .unwrap()
                .1
                .result
                .is_ok(),
            "the original sealed commitment finalizes"
        );
        let accepted_reveal =
            AcceptedTransaction::new_unchecked_entrypoint(Cow::Owned(reveal_entrypoint.clone()));
        let (_reveal_clock, reveal_time_source) =
            TimeSource::new_mock(Duration::from_millis(reveal_height));
        let reveal_plan = {
            let view = state.view();
            crate::queue::evaluate_policy_plan_with_nexus_and_world_at_block_height(
                &view.nexus,
                &accepted_reveal,
                view.world(),
                u64::try_from(reveal_time_source.get_unix_time().as_millis()).unwrap_or(u64::MAX),
                reveal_height,
            )
            .expect("sealed batch route resolves from the installed Nexus catalog")
        };
        assert_eq!(
            reveal_plan.coordinator_route(),
            crate::queue::RoutingDecision::new(sealed_lane, sealed_dataspace),
            "the production router must select the authoritative sealed dataspace"
        );
        let proposal = native_chain.proposal_entrypoints(vec![reveal_entrypoint]);
        assert_eq!(
            proposal.execution_context().unwrap().external[0],
            crate::queue::execution_context_for_routing_plan(outer_reveal_hash, &reveal_plan)
        );
        let mut pending = native_chain
            .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
            .expect("the original sealed batch executes through native output ownership");
        let source_for_inspection = source_asset_id.clone();
        let destination_for_inspection = destination_asset_id.clone();
        pending
            .inspect(move |execution| {
                let valid_reveal = execution.block;
                let reveal_state_block = execution.state;
                let source_asset_id = source_for_inspection;
                let destination_asset_id = destination_for_inspection;
                let (_, result_entrypoint, result) = valid_reveal
                    .as_ref()
                    .network_entrypoints()
                    .enumerate()
                    .map(|(index, entrypoint)| {
                        let (output_index, output) = valid_reveal
                            .as_ref()
                            .network_output_at(
                                u32::try_from(index).expect("fixture Network index fits u32"),
                            )
                            .expect("every queried input has its explicit Network output");
                        assert_eq!(usize::try_from(output_index).unwrap(), index);
                        (index, entrypoint, &output.result)
                    })
                    .next()
                    .expect("one sealed reveal result");
                assert_eq!(result_entrypoint.hash(), outer_reveal_hash);
                assert!(
                    result.0.is_ok(),
                    "the sealed native batch must execute successfully: {result:?}"
                );
                let outcomes = result.batch_transfer_outcomes();
                assert_eq!(outcomes.len(), 1);
                assert_eq!(outcomes[0].leg_index, 0);
                assert_eq!(outcomes[0].leg_id, "sealed-batch-leg");
                assert!(
                    matches!(outcomes[0].status, AssetBatchTransferLegStatus::Applied),
                    "the sealed batch leg must apply: {:?}",
                    outcomes[0]
                );
                assert_eq!(
                    valid_reveal
                        .as_ref()
                        .batch_transfer_outcomes_for(&outer_reveal_hash),
                    outcomes,
                    "the canonical outer entrypoint must query the inner execution receipts"
                );
                assert!(
                    valid_reveal
                        .as_ref()
                        .batch_transfer_outcomes_for(&inner_call_hash)
                        .is_empty(),
                    "committed receipt lookup remains keyed by the canonical outer entrypoint"
                );
                let inner_call_hash = Hash::from(inner_call_hash);
                let outer_reveal_hash = Hash::from(outer_reveal_hash);
                assert_eq!(
                    valid_reveal
                        .as_ref()
                        .fastpq_transcripts()
                        .keys()
                        .copied()
                        .collect::<Vec<_>>(),
                    vec![inner_call_hash],
                    "sealed FASTPQ evidence must retain the inner signed execution identity"
                );
                let witness = execution.witness;
                assert_eq!(witness.fastpq_transcripts.len(), 1);
                assert_eq!(witness.fastpq_transcripts[0].entry_hash, inner_call_hash);
                let fastpq_context = reveal_state_block
                    .take_fastpq_witness_context()
                    .expect("sealed numeric transfer captures FASTPQ context");
                assert_eq!(
                    fastpq_context.entry_dataspaces.get(&inner_call_hash),
                    Some(&crate::fastpq::dataspace_id_bytes(sealed_dataspace))
                );
                assert!(
                    !fastpq_context
                        .entry_dataspaces
                        .contains_key(&outer_reveal_hash),
                    "the outer reveal envelope must not replace the signed execution-call identity"
                );
                let ordered_entrypoints = valid_reveal
                    .as_ref()
                    .external_entrypoints_cloned()
                    .collect::<Vec<_>>();
                let expected_tx_set_hash: [u8; 32] =
                    iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(
                        ordered_entrypoints.iter(),
                    )
                    .expect("canonical sealed-reveal transaction set")
                    .into();
                assert_eq!(fastpq_context.tx_set_hash, Some(expected_tx_set_hash));
                assert_eq!(
                    reveal_state_block
                        .fastpq_source_inventory()
                        .expect("valid finalized reveal inventory")
                        .expect("reveal execution retains source ownership")
                        .tx_set_hash(),
                    expected_tx_set_hash,
                );
                assert_eq!(
                    reveal_state_block
                        .world
                        .asset(&source_asset_id)
                        .expect("source balance exists")
                        .value()
                        .clone()
                        .into_inner(),
                    Quantity::from(7_u32)
                );
                assert_eq!(
                    reveal_state_block
                        .world
                        .asset(&destination_asset_id)
                        .expect("destination balance exists")
                        .value()
                        .clone()
                        .into_inner(),
                    Quantity::from(3_u32)
                );
            })
            .expect("inspect the exact original Worker execution");
        pending
            .publish(crate::sumeragi::test_chain::Signers::Quorum)
            .expect("publish the same original sealed batch execution");
        drop(pending);
        assert_eq!(
            state
                .world
                .view()
                .asset(&source_asset_id)
                .expect("committed source balance exists")
                .value()
                .clone()
                .into_inner(),
            Quantity::from(7_u32)
        );
        assert_eq!(
            state
                .world
                .view()
                .asset(&destination_asset_id)
                .expect("committed destination balance exists")
                .value()
                .clone()
                .into_inner(),
            Quantity::from(3_u32)
        );
    }
    #[test]
    fn prune_expired_sealed_commitments_removes_pending_state_after_deadline() {
        let chain_id = ChainId::from("sealed-prune-pipeline");
        let (authority, keypair) = gen_account_in("wonderland");
        let state = state_with_transaction_policy(&chain_id, &authority, false, false);
        let mut native_chain = component_chain(state);
        let state = Arc::clone(native_chain.state());
        let metadata_key = Name::from_str("sealed_prune_marker").expect("metadata key");
        let (commitment_entrypoint, _reveal_entrypoint) =
            sealed_set_key_entrypoints(state.network_id, &authority, &keypair, 3, 3, metadata_key);
        let initial_smart_contract_state_len = state.world.view().smart_contract_state.len();
        let committed = native_chain.commit_entrypoints(vec![commitment_entrypoint]);
        assert!(
            committed
                .block()
                .network_output_at(0)
                .unwrap()
                .1
                .result
                .is_ok()
        );
        assert_eq!(
            state.world.view().smart_contract_state.len(),
            initial_smart_contract_state_len + 1
        );
        native_chain.commit(Vec::new());
        assert_eq!(native_chain.height(), 3);
        let prune_header = BlockHeader::new(nonzero!(4_u64), None, None, 3, 0);
        let mut prune_state_block = state.block(prune_header);
        assert_eq!(
            prune_state_block.world.smart_contract_state.len(),
            initial_smart_contract_state_len + 1,
            "pending commitment should still be visible before pruning"
        );
        let pruned = crate::tx::prune_expired_sealed_commitments(&mut prune_state_block);
        assert_eq!(pruned, 1);
        assert_eq!(
            prune_state_block.world.smart_contract_state.len(),
            initial_smart_contract_state_len,
            "expired sealed commitment should be removed after its deadline"
        );
    }
    #[test]
    fn block_pipeline_rejects_expired_height_ttl() {
        let chain_id = ChainId::from("block-height-ttl-check");
        let (authority, keypair) = gen_account_in("wonderland");
        let state = state_with_transaction_policy(&chain_id, &authority, true, false);
        let native_chain = crate::block::tests::component_chain(state);
        let state = native_chain.state();
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("expires_at_height").expect("metadata key"),
            Json::from(2_u64),
        );
        let mut builder = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::ZERO);
        let tx = builder
            .with_instructions([Log::new(Level::INFO, "expired".to_owned())])
            .with_metadata(metadata)
            .sign(keypair.private_key());
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
        let (_handle, time_source) = TimeSource::new_mock(Duration::from_millis(10));
        let _previous = previous_block_at_height(1);
        let previous = state
            .view()
            .latest_block()
            .expect("original block read attempt")
            .expect("original genesis");
        let unverified_block = BlockBuilder::new_with_time_source(vec![accepted], time_source)
            .chain(0, Some(&previous))
            .sign(keypair.private_key())
            .unpack(|_| {});
        let (mut state_block, state_block_recorder) =
            crate::block::ValidBlock::start_component_execution(
                &unverified_block.clone().into(),
                state,
            )
            .expect("original writer-first component execution");
        let valid_block = unverified_block
            .validate_and_record_transactions(&mut state_block, state_block_recorder)
            .unpack(|_| {});
        let error = validation_error_message(valid_block.as_ref());
        assert!(error.contains("expired"), "unexpected rejection: {error}");
    }
    #[test]
    fn block_pipeline_rejects_non_increasing_tx_sequence() {
        let chain_id = ChainId::from("block-sequence-check");
        let (authority, keypair) = gen_account_in("wonderland");
        let state = state_with_transaction_policy(&chain_id, &authority, false, true);
        {
            let mut world = state.world.block();
            world.tx_sequences.insert(authority.clone(), 5);
            world.commit();
        }
        let native_chain = component_chain_with_genesis_parameters(
            state,
            vec![iroha_data_model::parameter::Parameter::Transaction(
                iroha_data_model::parameter::system::TransactionParameter::RequireSequence(true),
            )],
        );
        let state = native_chain.state();
        assert!(
            state
                .view()
                .world()
                .parameters()
                .transaction()
                .require_sequence,
            "the original signed genesis must retain the requested sequence policy"
        );
        assert_eq!(
            state.view().world().tx_sequences.get(&authority),
            Some(&5),
            "original signed genesis must retain the independently seeded previous sequence"
        );
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("tx_sequence").expect("metadata key"),
            Json::from(5_u64),
        );
        let mut builder = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::ZERO);
        let tx = builder
            .with_instructions([Log::new(Level::INFO, "sequence".to_owned())])
            .with_metadata(metadata)
            .sign(keypair.private_key());
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
        let (_handle, time_source) = TimeSource::new_mock(Duration::from_millis(10));
        let _previous = previous_block_at_height(1);
        let previous = state
            .view()
            .latest_block()
            .expect("original block read attempt")
            .expect("original genesis");
        let unverified_block = BlockBuilder::new_with_time_source(vec![accepted], time_source)
            .chain(0, Some(&previous))
            .sign(keypair.private_key())
            .unpack(|_| {});
        let (mut state_block, state_block_recorder) =
            crate::block::ValidBlock::start_component_execution(
                &unverified_block.clone().into(),
                state,
            )
            .expect("original writer-first component execution");
        let valid_block = unverified_block
            .validate_and_record_transactions(&mut state_block, state_block_recorder)
            .unpack(|_| {});
        let error = validation_error_message(valid_block.as_ref());
        assert!(error.contains("sequence"), "unexpected rejection: {error}");
    }
    #[tokio::test]
    async fn should_reject_due_to_repetition() {
        // Predefined world state
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("Valid");
        let account = Account::new(alice_id.clone()).build(&alice_id);
        let domain = Domain::new(domain_id.clone()).build(&alice_id);
        let world = World::with([domain], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(world, kura, query_handle);
        let native_chain = crate::block::tests::component_chain(state);
        let state = native_chain.state();
        let (max_clock_drift, tx_limits) = {
            let state_view = state.world.view();
            let params = state_view.parameters();
            (params.sumeragi().max_clock_drift(), params.transaction())
        };
        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
            "xor".parse().expect("asset name"),
        );
        // Make two distinct signed transactions that attempt the same state
        // transition. Exact duplicate signed hashes are rejected by the block
        // execution-context boundary before instruction evaluation.
        let make_transaction = |creation_time_ms| {
            let mut builder = TransactionBuilder::new(
                state.network_id,
                alice_id.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            );
            builder.set_creation_time(Duration::from_millis(creation_time_ms));
            builder
                .with_instructions([Register::asset_definition(AssetDefinition::numeric(
                    asset_definition_id.clone(),
                    "xor",
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    Some(domain_id.clone()),
                ))])
                .sign(alice_keypair.private_key())
        };
        let first_tx = make_transaction(0);
        let second_tx = make_transaction(1);
        let (_clock, time_source) = TimeSource::new_mock(Duration::from_millis(10));
        let crypto_cfg = state.crypto();
        let first_tx = AcceptedTransaction::accept_with_time_source(
            first_tx,
            &state.network_id,
            max_clock_drift,
            tx_limits,
            crypto_cfg.as_ref(),
            &time_source,
        )
        .expect("Valid");
        let second_tx = AcceptedTransaction::accept_with_time_source(
            second_tx,
            &state.network_id,
            max_clock_drift,
            tx_limits,
            crypto_cfg.as_ref(),
            &time_source,
        )
        .expect("Valid");
        // Creating a block of two semantically repetitive transactions and validating it
        let transactions = vec![first_tx, second_tx];
        let unverified_block = BlockBuilder::new_with_time_source(transactions, time_source)
            .chain(
                0,
                state
                    .view()
                    .latest_block()
                    .expect("original block read attempt")
                    .as_deref(),
            )
            .sign(alice_keypair.private_key())
            .unpack(|_| {});
        let (mut state_block, state_block_recorder) =
            crate::block::ValidBlock::start_component_execution(
                &unverified_block.clone().into(),
                state,
            )
            .expect("original writer-first component execution");
        let valid_block = unverified_block
            .validate_and_record_transactions(&mut state_block, state_block_recorder)
            .unpack(|_| {});
        // The 1st transaction should be confirmed and the 2nd rejected
        assert_eq!(
            valid_block
                .as_ref()
                .output_results()
                .enumerate()
                .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
                .unwrap()
                .0,
            1
        );
    }
    include!("block/tx_order_validation_revalidation_test.rs");
    #[tokio::test]
    async fn failed_transactions_revert() {
        // Predefined world state
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("Valid");
        let account = Account::new(alice_id.clone()).build(&alice_id);
        let domain = Domain::new(domain_id).build(&alice_id);
        let (created_account_id, _) = gen_account_in("wonderland");
        let world = World::with([domain], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(world, kura, query_handle);
        let native_chain = crate::block::tests::component_chain(state);
        let state = native_chain.state();
        let (max_clock_drift, tx_limits) = {
            let state_view = state.world.view();
            let params = state_view.parameters();
            (params.sumeragi().max_clock_drift(), params.transaction())
        };
        let create_account = Register::account(Account::new(created_account_id));
        let asset_definition_id =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "coin".parse().unwrap(),
            );
        let create_asset = Register::asset_definition(AssetDefinition::numeric(
            asset_definition_id,
            "coin",
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(DomainId::try_new("wonderland", "universal").unwrap()),
        ));
        let (missing_account_id, _) = gen_account_in("wonderland");
        let fail_isi = Unregister::account(missing_account_id);
        let tx_fail = TransactionBuilder::new(
            state.network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions::<InstructionBox>([create_account.clone().into(), fail_isi.into()])
        .sign(alice_keypair.private_key());
        let crypto_cfg = state.crypto();
        let (_clock, time_source) = TimeSource::new_mock(tx_fail.creation_time());
        let tx_fail = AcceptedTransaction::accept_with_time_source(
            tx_fail,
            &state.network_id,
            max_clock_drift,
            tx_limits,
            crypto_cfg.as_ref(),
            &time_source,
        )
        .expect("Valid");
        let tx_accept = TransactionBuilder::new(
            state.network_id,
            alice_id,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions::<InstructionBox>([create_account.into(), create_asset.into()])
        .sign(alice_keypair.private_key());
        let (_clock, time_source) = TimeSource::new_mock(tx_accept.creation_time());
        let tx_accept = AcceptedTransaction::accept_with_time_source(
            tx_accept,
            &state.network_id,
            max_clock_drift,
            tx_limits,
            crypto_cfg.as_ref(),
            &time_source,
        )
        .expect("Valid");
        let fail_hash = tx_fail.hash_as_entrypoint();
        let accept_hash = tx_accept.hash_as_entrypoint();
        // Creating a block of where first transaction must fail and second one fully executed
        let transactions = vec![tx_fail, tx_accept];
        let unverified_block = BlockBuilder::new(transactions)
            .chain(
                0,
                state
                    .view()
                    .latest_block()
                    .expect("original block read attempt")
                    .as_deref(),
            )
            .sign(alice_keypair.private_key())
            .unpack(|_| {});
        let (mut state_block, state_block_recorder) =
            crate::block::ValidBlock::start_component_execution(
                &unverified_block.clone().into(),
                state,
            )
            .expect("original writer-first component execution");
        let valid_block = unverified_block
            .validate_and_record_transactions(&mut state_block, state_block_recorder)
            .unpack(|_| {});
        let block_ref = valid_block.as_ref();
        let outcomes: Vec<_> = block_ref
            .network_entrypoints()
            .enumerate()
            .map(|(index, input)| {
                let (output_index, row) = block_ref
                    .network_output_at(u32::try_from(index).unwrap())
                    .expect("exact Network source output");
                assert_eq!(usize::try_from(output_index).unwrap(), index);
                (input.hash(), &row.result)
            })
            .collect();
        let lookup = |target: &_, msg: &str| {
            outcomes
                .iter()
                .find(|(hash, _)| hash == target)
                .unwrap_or_else(|| panic!("missing result for {msg}"))
                .1
                .as_ref()
        };
        let fail_result = lookup(&fail_hash, "fail tx");
        assert!(fail_result.is_err(), "Failing tx must be rejected");
        let accept_result = lookup(&accept_hash, "accept tx");
        assert!(
            accept_result.is_ok(),
            "Second tx must succeed, got {accept_result:?}"
        );
    }
    include!("block/rejected_live_batch_fee_tests.rs");
    include!("block/fee_admission_tests.rs");
    include!("block/public_contract_creation_fee_tests.rs");
    include!("block/bootstrap_and_genesis_tests.rs");
    #[test]
    fn sumeragi_parameters_are_accessible() {
        let params = iroha_data_model::parameter::Parameters::default();
        let _ = params.sumeragi().max_clock_drift();
    }
    #[test]
    fn signature_error_maps_inactive_consensus_key_reason() {
        assert_eq!(
            map_sig_err_to_reason(&SignatureVerificationError::InactiveConsensusKey),
            error::BlockRejectionReason::InactiveConsensusKey
        );
    }
}
#[cfg(test)]
#[path = "block/commit_signature_tally_tests.rs"]
mod commit_signature_tally_tests;
#[cfg(test)]
fn committed_teu_by_lane_from_routes(
    routes: impl IntoIterator<Item = impl core::borrow::Borrow<crate::queue::RoutingDecision>>,
    teus: impl IntoIterator<Item = u64>,
) -> BTreeMap<LaneId, u64> {
    routes
        .into_iter()
        .zip(teus)
        .fold(BTreeMap::new(), |mut committed, (route, teu)| {
            let route = route.borrow();
            committed
                .entry(route.lane_id)
                .and_modify(|total| *total = total.saturating_add(teu))
                .or_insert(teu);
            committed
        })
}
#[cfg(test)]
mod committed_teu_tests {
    use super::committed_teu_by_lane_from_routes;
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    #[test]
    fn committed_teu_attribution_uses_supplied_routes_not_cached_hints() {
        let stale_hint_lane = LaneId::new(99);
        let fresh_lane = LaneId::new(1);
        let routes = [
            crate::queue::RoutingDecision::new(fresh_lane, DataSpaceId::UNIVERSAL),
            crate::queue::RoutingDecision::new(fresh_lane, DataSpaceId::UNIVERSAL),
            crate::queue::RoutingDecision::new(LaneId::new(2), DataSpaceId::UNIVERSAL),
        ];
        let committed = committed_teu_by_lane_from_routes(routes.iter(), [7, 11, 5]);
        assert_eq!(committed.get(&fresh_lane), Some(&18));
        assert_eq!(committed.get(&LaneId::new(2)), Some(&5));
        assert_eq!(
            committed.get(&stale_hint_lane),
            None,
            "committed telemetry must be derived from validated block routes"
        );
    }
    #[test]
    fn committed_teu_attribution_saturates_instead_of_wrapping() {
        let lane = LaneId::new(7);
        let routes = [
            crate::queue::RoutingDecision::new(lane, DataSpaceId::UNIVERSAL),
            crate::queue::RoutingDecision::new(lane, DataSpaceId::UNIVERSAL),
        ];
        let committed = committed_teu_by_lane_from_routes(routes.iter(), [u64::MAX, 1]);
        assert_eq!(committed.get(&lane), Some(&u64::MAX));
    }
}
