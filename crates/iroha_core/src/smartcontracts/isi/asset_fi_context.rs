//! Native FI observations asserted at one exact instruction execution cut.
//! No assertion writes approval, relationship, usage, balances or receipt state.
use super::*;
use crate::{
    execution_attempt::{ExecutionAttemptError, canonical_decode_attempt_error},
    smartcontracts::code,
    state::{asset_fi, asset_uid},
};
use iroha_data_model::{
    asset::{
        AssetBalancePolicy,
        fi_context::{
            AssetFiContextSnapshotV1, AssetFiContextTargetV1, AssetFiControllerBindingV1,
            asset_fi_context_snapshot_hash_v1, asset_fi_transfer_receipt_hash_v1,
        },
        fi_link::{AssetFiLinkAttestationV1, AssetFiLinkV1, AssetFiTransferReceiptV1, AssetFiV1},
        uid::{AssetUidBindingV1, AssetUidPolicyV1},
    },
    isi::asset_fi_context::{AssertAssetFiContextV1, AssertAssetFiTransferReceiptV1},
    nexus::AxtAssetIncarnationV1,
};
use iroha_model_base::state_path::StatePath;
type Attempt<T> = Result<T, ExecutionAttemptError<Error>>;
fn reject(message: &str) -> Error {
    asset_fi::reject(message)
}

fn canonical<T>(operation: impl FnOnce() -> Result<T, norito::core::Error>) -> Attempt<T> {
    norito::core::classify_decode_attempt(operation).map_err(|error| {
        canonical_decode_attempt_error(error, |_| reject("invalid canonical native FI observation"))
    })
}
fn read<T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>>(
    world: &impl WorldReadOnly,
    key: &StatePath,
    remaining: &mut usize,
) -> Attempt<Option<T>> {
    let Some(bytes) = world.smart_contract_state().get(key) else {
        return Ok(None);
    };
    // Borrow and count the whole frame before any owned decode. Remaining is
    // cumulative across all selected rows; a later row cannot reset its allowance.
    *remaining = remaining
        .checked_sub(bytes.len())
        .ok_or_else(|| reject("FI assertion retained frames exceed the frozen byte ceiling"))?;
    canonical(|| norito::decode_canonical(bytes)).map(Some)
}
fn bounded_frame<T: norito::NoritoSerialize>(value: &T, ceiling: usize) -> Attempt<()> {
    if canonical(|| norito::canonical_frame_len(value))? > ceiling {
        return Err(reject("FI assertion typed frame exceeds the frozen byte ceiling").into());
    }
    Ok(())
}
fn within_limits<T>(
    tx: &StateTransaction<'_, '_>,
    operation: impl FnOnce(usize) -> Attempt<T>,
) -> Attempt<T> {
    let ceiling = asset_fi::assertion_encoding_ceiling(tx)?;
    let elements = ceiling
        .checked_mul(8)
        .ok_or_else(|| reject("FI assertion ceiling overflows"))?;
    // This existing cumulative codec owner bounds retained graph and scratch
    // requests. It is not physical whole-World reservation or a work/gas policy.
    let limits = norito::DecodeLimits::new(elements, ceiling, elements, ceiling, 64);
    norito::core::with_decode_limits_scope(limits, || operation(ceiling))
}
fn account_copy(account: &AccountId) -> Attempt<AccountId> {
    canonical(|| account.try_clone_for_admission())
}
fn floor(
    tx: &StateTransaction<'_, '_>,
    challenge: &[u8; 32],
    request: &[u8; 32],
    height: u64,
    hash: &[u8; 32],
) -> Result<(), Error> {
    let index = usize::try_from(height)
        .ok()
        .and_then(|height| height.checked_sub(1))
        .ok_or_else(|| reject("FI assertion requires a retained nonzero checkpoint floor"))?;
    if *challenge == [0; 32]
        || *request == [0; 32]
        || *hash == [0; 32]
        || tx.block_height() <= height
        || tx.block_hashes().get(index).map(|value| *value.as_ref()) != Some(*hash)
    {
        return Err(reject(
            "FI assertion challenge, request digest or checkpoint floor is invalid",
        ));
    }
    Ok(())
}
fn authorize(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    account: &AccountId,
    authority: &AccountId,
    historical: bool,
) -> Result<(), Error> {
    if world.accounts().get(authority).is_none() || world.accounts().get(account).is_none() {
        return Err(reject("FI assertion requires registered exact accounts"));
    }
    let definition = world.asset_definitions().get(definition).ok_or_else(||reject("FI assertion asset is unavailable"))?;
    if definition.balance_scope_policy() != AssetBalancePolicy::Global
        || (definition.owned_by() != authority && !(historical && account == authority))
    {
        return Err(reject(
            "FI assertion requires its exact authorized Global asset context",
        ));
    }
    Ok(())
}

/// Borrowed target selectors; no reconstructed historical owner link.
pub(crate) struct TargetSelection<'a> {
    pub(crate) asset_definition_id: &'a AssetDefinitionId,
    pub(crate) account_id: &'a AccountId,
    pub(crate) fi_account_id: &'a AccountId,
    pub(crate) reference_digest: &'a [u8; 32],
    controller: Option<&'a iroha_data_model::smart_contract::ContractAddress>,
    controller_from_current_link: bool,
}
/// Select only terms actually present in the descriptive target.
pub(crate) fn target_selection(
    target: &AssetFiContextTargetV1,
) -> Result<TargetSelection<'_>, Error> {
    match target {
        AssetFiContextTargetV1::LinkApproval(value) => {
            if value.expected_policy_revision == 0 {
                return Err(reject("FI target policy revision must be positive"));
            }
            asset_fi::validate_link_shape(&value.link)?;
            Ok(TargetSelection {
                asset_definition_id: &value.link.asset_definition_id,
                account_id: &value.link.account_id,
                fi_account_id: &value.link.fi_account_id,
                reference_digest: &value.link.reference_digest,
                controller: value.link.controller.as_ref(),
                controller_from_current_link: false,
            })
        }
        AssetFiContextTargetV1::Transfer {
            instruction,
            fi_account_id,
            reference_digest,
            expected_fi_revision,
            expected_attestation_revision,
        } => {
            if instruction.expected_link_revision == 0
                || instruction.expected_policy_revision == 0
                || instruction.amount.is_zero()
                || *reference_digest == [0; 32]
                || *expected_fi_revision == 0
                || *expected_attestation_revision == 0
                || instruction.account_id == *fi_account_id
            {
                return Err(reject(
                    "FI transfer target has invalid retained consent terms",
                ));
            }
            Ok(TargetSelection {
                asset_definition_id: &instruction.asset_definition_id,
                account_id: &instruction.account_id,
                fi_account_id,
                reference_digest,
                controller: None,
                controller_from_current_link: true,
            })
        }
    }
}

/// Native selection and invariants shared with a future admitted context query.
/// This is an instruction helper, not an authorized or bounded public query API.
pub(crate) fn current_snapshot(
    tx: &StateTransaction<'_, '_>,
    target: &AssetFiContextTargetV1,
    expected_incarnation: &AxtAssetIncarnationV1,
    expected_uid: &[u8; 32],
) -> Attempt<AssetFiContextSnapshotV1> {
    within_limits(tx, |ceiling| {
        current_snapshot_bounded(tx, target, expected_incarnation, expected_uid, ceiling)
    })
}
/// Selected rows owned by the caller's existing instruction or query admission.
pub(crate) struct ContextRows {
    pub(crate) binding: Option<AssetUidBindingV1>,
    pub(crate) policy: Option<AssetUidPolicyV1>,
    pub(crate) fi: Option<AssetFiV1>,
    pub(crate) attestation: Option<AssetFiLinkAttestationV1>,
    pub(crate) link: Option<AssetFiLinkV1>,
}

/// Shared selection semantics; transfer observes the actual current link only.
pub(crate) fn selected_controller<'a>(
    selected: &'a TargetSelection<'a>,
    rows: &'a ContextRows,
) -> Option<&'a iroha_data_model::smart_contract::ContractAddress> {
    if selected.controller_from_current_link {
        rows.link.as_ref().and_then(|link| link.controller.as_ref())
    } else {
        selected.controller
    }
}

/// Shared native context invariants and field assembly. It performs no World reads.
/// Account copies use the caller's active codec owner; this grants no query authority.
pub(crate) fn snapshot_from_rows(
    target: &AssetFiContextTargetV1,
    expected_incarnation: &AxtAssetIncarnationV1,
    expected_uid: &[u8; 32],
    actual_incarnation: Option<AxtAssetIncarnationV1>,
    rows: ContextRows,
    controller: Option<AssetFiControllerBindingV1>,
) -> Attempt<AssetFiContextSnapshotV1> {
    let selected = target_selection(target)?;
    let definition = selected.asset_definition_id;
    let account = selected.account_id;
    expected_incarnation
        .validate()
        .map_err(|_| reject("invalid expected FI asset incarnation"))?;
    let incarnation = actual_incarnation
        .ok_or_else(|| reject("FI context has no exact live asset incarnation"))?;
    if &incarnation != expected_incarnation
        || incarnation.validate().is_err()
        || *expected_uid == [0; 32]
    {
        return Err(reject(
            "FI current context incarnation or UID differs from the requested context",
        )
        .into());
    }
    if let Some(value) = &rows.binding {
        if value.asset_definition_id != *definition
            || value.account_id != *account
            || value.uid != *expected_uid
        {
            return Err(reject("FI context UID binding differs from its exact selector").into());
        }
        if rows
            .policy
            .as_ref()
            .is_none_or(|policy| !policy.accounts.contains(account))
        {
            return Err(reject("FI bound wallet has no exact UID policy membership").into());
        }
    }
    if let Some(value) = &rows.policy {
        value.validate_shape().map_err(reject)?;
        if value.asset_definition_id != *definition
            || value.uid != *expected_uid
            || (rows.binding.is_none() && value.accounts.contains(account))
        {
            return Err(reject("FI context UID policy differs from native membership").into());
        }
    }
    if rows.fi.as_ref().is_some_and(|value| {
        value.asset_definition_id != *definition
            || value.fi_account_id != *selected.fi_account_id
            || value.revision == 0
    }) {
        return Err(reject("FI context eligibility differs from its exact selector").into());
    }
    if rows.attestation.as_ref().is_some_and(|value| {
        value.asset_definition_id != *definition
            || value.account_id != *account
            || value.fi_account_id != *selected.fi_account_id
            || value.reference_digest != *selected.reference_digest
            || value.revision == 0
    }) {
        return Err(reject("FI context attestation differs from its exact selector").into());
    }
    if let Some(value) = &rows.link {
        asset_fi::validate_link_shape(value)?;
        if value.asset_definition_id != *definition || value.account_id != *account {
            return Err(reject("FI context owner link differs from its exact selector").into());
        }
    }
    Ok(AssetFiContextSnapshotV1 {
        asset_definition_id: definition.clone(),
        asset_incarnation: incarnation,
        account_id: account_copy(account)?,
        uid: *expected_uid,
        fi_account_id: account_copy(selected.fi_account_id)?,
        reference_digest: *selected.reference_digest,
        binding: rows.binding,
        policy: rows.policy,
        fi: rows.fi,
        attestation: rows.attestation,
        link: rows.link,
        controller,
    })
}

fn current_snapshot_bounded(
    tx: &StateTransaction<'_, '_>,
    target: &AssetFiContextTargetV1,
    expected_incarnation: &AxtAssetIncarnationV1,
    expected_uid: &[u8; 32],
    ceiling: usize,
) -> Attempt<AssetFiContextSnapshotV1> {
    bounded_frame(target, ceiling)?;
    let selected = target_selection(target)?;
    let definition = selected.asset_definition_id;
    let account = selected.account_id;
    let world = tx.world();
    let mut remaining = ceiling;
    let rows = ContextRows {
        binding: read(
            world,
            &asset_uid::binding_key(definition, account),
            &mut remaining,
        )?,
        policy: read(
            world,
            &asset_uid::policy_key(definition, expected_uid),
            &mut remaining,
        )?,
        fi: read(
            world,
            &asset_fi::fi_key(definition, selected.fi_account_id),
            &mut remaining,
        )?,
        attestation: read(
            world,
            &asset_fi::attestation_key(
                definition,
                account,
                selected.fi_account_id,
                selected.reference_digest,
            ),
            &mut remaining,
        )?,
        link: read(
            world,
            &asset_fi::link_key(definition, account),
            &mut remaining,
        )?,
    };
    let controller = if let Some(address) = selected_controller(&selected, &rows) {
        if let Some(binding) = world.contract_subject_bindings().get(address) {
            let size = canonical(|| norito::canonical_frame_len(binding))?;
            remaining = remaining.checked_sub(size).ok_or_else(|| {
                reject("FI assertion controller exceeds cumulative frozen byte ceiling")
            })?;
        }
        let parameters = world.parameters();
        if let Some(metadata) = parameters
            .custom()
            .get(&iroha_data_model::parameter::system::consensus_metadata::handshake_meta_id())
        {
            let size = metadata.payload().get().as_str().len();
            remaining.checked_sub(size).ok_or_else(|| {
                reject("FI assertion root metadata exceeds cumulative frozen byte ceiling")
            })?;
        }
        let subject = match code::try_borrow_active_contract_subject_for_observation(
            world,
            address,
            tx.block_height(),
            |_| Ok::<(), core::convert::Infallible>(()),
        ) {
            Ok(subject) => subject,
            Err(code::ContractObservationAttemptError::Native(
                ExecutionAttemptError::Rejected(_),
            )) => None,
            Err(code::ContractObservationAttemptError::Native(
                ExecutionAttemptError::Deferred(original),
            )) => return Err(ExecutionAttemptError::Deferred(original)),
            Err(code::ContractObservationAttemptError::Admission(never)) => match never {},
        };
        subject
            .map(|subject| {
                Ok::<_, ExecutionAttemptError<Error>>(AssetFiControllerBindingV1 {
                    address: canonical(|| address.try_clone_for_admission())?,
                    subject: account_copy(subject)?,
                })
            })
            .transpose()?
    } else {
        None
    };
    snapshot_from_rows(
        target,
        expected_incarnation,
        expected_uid,
        world.axt_asset_incarnations().get(definition).copied(),
        rows,
        controller,
    )
}
fn current(
    value: &AssertAssetFiContextV1,
    authority: &AccountId,
    tx: &StateTransaction<'_, '_>,
) -> Attempt<()> {
    let selected = target_selection(&value.target)?;
    authorize(
        tx.world(),
        selected.asset_definition_id,
        selected.account_id,
        authority,
        false,
    )?;
    floor(
        tx,
        &value.challenge,
        &value.request_sha256,
        value.minimum_height,
        &value.minimum_block_hash,
    )?;
    let ceiling = asset_fi::assertion_encoding_ceiling(tx)?;
    let snapshot = current_snapshot_bounded(
        tx,
        &value.target,
        &value.expected_incarnation,
        &value.expected_uid,
        ceiling,
    )?;
    bounded_frame(&snapshot, ceiling)?;
    if canonical(|| asset_fi_context_snapshot_hash_v1(&snapshot))? != value.expected_context_hash {
        return Err(reject("FI current context hash assertion failed").into());
    }
    Ok(())
}
fn historical(
    value: &AssertAssetFiTransferReceiptV1,
    authority: &AccountId,
    tx: &StateTransaction<'_, '_>,
) -> Attempt<()> {
    authorize(
        tx.world(),
        &value.asset_definition_id,
        &value.account_id,
        authority,
        true,
    )?;
    floor(
        tx,
        &value.challenge,
        &value.request_sha256,
        value.minimum_height,
        &value.minimum_block_hash,
    )?;
    value
        .expected_incarnation
        .validate()
        .map_err(|_| reject("invalid historical FI incarnation"))?;
    bounded_frame(&value.account_id, asset_fi::assertion_encoding_ceiling(tx)?)?;
    let key = asset_fi::receipt::key(
        &value.asset_definition_id,
        &value.account_id,
        &value.execution_call_hash,
        value.transcript_index,
    );
    let mut remaining = asset_fi::assertion_encoding_ceiling(tx)?;
    let original: AssetFiTransferReceiptV1 = read(tx.world(), &key, &mut remaining)?
        .ok_or_else(|| reject("FI historical assertion requires its exact retained receipt"))?;
    // Protected native capture owns record construction. The assertion still checks
    // immutable field relationships plus the complete public canonical commitment.
    asset_fi::receipt::validate_fields(&original)?;
    bounded_frame(&original, asset_fi::assertion_encoding_ceiling(tx)?)?;
    if original.instruction.asset_definition_id != value.asset_definition_id
        || original.instruction.account_id != value.account_id
        || original.execution_call_hash != value.execution_call_hash
        || original.transcript_index != value.transcript_index
        || original.asset_incarnation != value.expected_incarnation
        || &original.network != tx.network_id()
        || canonical(|| asset_fi_transfer_receipt_hash_v1(&original))?
            != value.expected_receipt_hash
    {
        return Err(reject("FI historical receipt hash or occurrence assertion failed").into());
    }
    Ok(())
}
impl Execute for AssertAssetFiContextV1 {
    fn execute(
        self,
        authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        within_limits(tx, |_| current(&self, authority, tx))
            .map_err(|error| tx.attempt_error_to_instruction_error(error))
    }
}
impl Execute for AssertAssetFiTransferReceiptV1 {
    fn execute(
        self,
        authority: &AccountId,
        tx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        within_limits(tx, |_| historical(&self, authority, tx))
            .map_err(|error| tx.attempt_error_to_instruction_error(error))
    }
}

#[cfg(test)]
mod bounds_tests {
    use super::*;
    #[test]
    fn fi_assertion_retained_rows_accept_exact_bound_and_refuse_cumulative_overrun_before_decode() {
        let (_, state) = crate::state::asset_fi::FiLinkReaderFixture::new();
        let header = iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::new(1).unwrap(),
            None,
            None,
            1_000,
            0,
        );
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let key: StatePath = "fi_assertion_bounds/test".parse().unwrap();
        let bytes = norito::encode_canonical(&17_u64).unwrap();
        let exact = bytes.len();
        tx.world
            .smart_contract_state
            .insert(key.clone(), bytes.clone());
        let before = tx.pending_transfer_transcript_count_for_testing();
        let mut remaining = exact;
        assert_eq!(
            read::<u64>(tx.world(), &key, &mut remaining).unwrap(),
            Some(17)
        );
        assert_eq!(remaining, 0);
        assert!(read::<u64>(tx.world(), &key, &mut remaining).is_err());
        let mut one_under = exact - 1;
        assert!(read::<u64>(tx.world(), &key, &mut one_under).is_err());
        assert_eq!(one_under, exact - 1);
        let mut two_rows = exact * 2;
        assert!(read::<u64>(tx.world(), &key, &mut two_rows).is_ok());
        assert!(read::<u64>(tx.world(), &key, &mut two_rows).is_ok());
        assert_eq!(two_rows, 0);
        assert!(bounded_frame(&17_u64, exact).is_ok());
        assert!(bounded_frame(&17_u64, exact - 1).is_err());
        // Invalid bytes wider than the retained allowance refuse before decoding.
        tx.world
            .smart_contract_state
            .insert(key.clone(), vec![0; exact + 1]);
        let mut remaining = exact;
        let error = read::<u64>(tx.world(), &key, &mut remaining).unwrap_err();
        assert!(matches!(error, ExecutionAttemptError::Rejected(_)));
        assert_eq!(remaining, exact);
        assert_eq!(tx.pending_transfer_transcript_count_for_testing(), before);
        assert_eq!(
            tx.world().smart_contract_state().get(&key).unwrap(),
            &vec![0; exact + 1]
        );
    }
}

impl crate::smartcontracts::ValidQuery for iroha_data_model::query::asset_fi_context::FindAssetFiContextV1 {
    fn execute(self, _filter: iroha_data_model::query::dsl::CompoundPredicate<AssetFiContextSnapshotV1>,
        _state: &impl crate::state::StateReadOnly)
        -> Result<impl Iterator<Item = AssetFiContextSnapshotV1>, iroha_data_model::query::error::QueryExecutionFail>
    {
        Err::<core::iter::Empty<AssetFiContextSnapshotV1>, _>(iroha_data_model::query::error::QueryExecutionFail::Conversion(
            "FI context requires bounded ordinary native query admission".into()))
    }
}
