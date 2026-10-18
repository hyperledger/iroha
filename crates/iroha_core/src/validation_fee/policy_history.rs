//! Bounded hot fee-policy suffixes backed by original certified registry custody.

use super::{ValidationFeePolicyRegistryV1, validated_policy_registry_in_world};
use crate::{
    execution_attempt::ExecutionAttemptError,
    state::{ExecutionOutputAttemptError, StateBlock, StateReadOnly, StateTransaction},
};
use iroha_data_model::parameter::Parameter;
use mv::storage::StorageReadOnly;

type Attempt<T> = Result<T, ExecutionAttemptError<String>>;

/// Authenticate a checkpoint from its original committed fee corpus on restoration.
/// Finality authenticates that source snapshot; recursively opening every older snapshot would
/// turn a bounded restart check into lifetime work and is neither necessary nor permitted.
pub(crate) fn validate_retained_history(
    state: &impl StateReadOnly,
    registry: &ValidationFeePolicyRegistryV1,
    restored_height: u64,
) -> Attempt<()> {
    let Some(history) = &registry.history else {
        return Ok(());
    };
    if history.archived_at_height >= restored_height {
        return Err("fee history checkpoint does not precede restored state"
            .to_owned()
            .into());
    }
    let corpus =
        crate::query::native_receipts::committed_fee_evidence(state, history.archived_at_height)?;
    let source = corpus
        .registry()
        .ok_or("original fee history registry is absent")?;
    registry
        .validate_history_source(history.archived_at_height, source)
        .map_err(|error| error.to_string())?;
    if history.retired_policy_version != 0 {
        let block = state
            .latest_block()
            .map_err(|error| error.map_rejection(|error| error.to_string()))?
            .ok_or("compacted policy restoration requires the committed ledger timestamp")?;
        let now = u64::try_from(block.header().creation_time().as_millis())
            .map_err(|_| "restored fee-policy time overflow")?;
        let frontier = crate::retail_fee::oldest_unsettled_policy_month(state.world(), now)?;
        if registry
            .registered_policies
            .first()
            .is_none_or(|entry| entry.policy.effective_from_ms > frontier)
        {
            return Err("compacted fee policy crosses an unsettled wallet frontier"
                .to_owned()
                .into());
        }
    }
    Ok(())
}

/// Retain exact policy provenance for receipts already produced in this block as well as
/// unsettled wallets. The delta journal is bounded by the current block, never ledger history.
fn pricing_frontier(stx: &StateTransaction<'_, '_>) -> Attempt<u64> {
    let mut frontier = crate::retail_fee::oldest_unsettled_policy_month(
        &stx.world,
        stx.block_unix_timestamp_ms(),
    )?;
    for key in stx
        .world
        .smart_contract_state
        .changed_keys_in_block()
        .filter(|key| key.as_ref().starts_with("retail_fee_receipts_v1/"))
    {
        let Some(bytes) = stx.world.smart_contract_state.get(key) else {
            continue;
        };
        let receipt: iroha_data_model::validation_fee::RetailFeeReceiptV1 =
            norito::decode_canonical(bytes).map_err(|error| {
                crate::execution_attempt::norito_decode_attempt_error(error, |error| {
                    error.to_string()
                })
            })?;
        frontier = frontier.min(receipt.billing_month_start_ms);
    }
    Ok(frontier)
}

/// Retire already superseded entries only after the exact source has original committed custody.
/// Every still-unsettled retail month and the parent service binding remain in the hot suffix.
fn compact(stx: &mut StateTransaction<'_, '_>) -> Attempt<bool> {
    let height = stx
        .block_height()
        .checked_sub(1)
        .ok_or("fee history height underflow")?;
    if height < 2 {
        return Ok(false);
    }
    let Some(registry) = validated_policy_registry_in_world(&stx.world)
        .map_err(|error| error.map_rejection(|error| error.to_string()))?
    else {
        return Ok(false);
    };
    let frontier = pricing_frontier(stx)?;
    let Some(next) = registry
        .compacted_suffix(height, frontier, height)
        .map_err(|error| error.to_string())?
    else {
        return Ok(false);
    };
    let corpus = crate::query::native_receipts::committed_fee_evidence(stx, height)?;
    let Some(original) = corpus.registry() else {
        return Ok(false);
    };
    // A same-block enactment has no archived post-state yet. Preserve the whole source until
    // the following block instead of substituting an earlier registry or a mutable World copy.
    if original != &registry {
        return Ok(false);
    }
    next.validate_history_source(height, original)
        .map_err(|error| error.to_string())?;
    let next = next.into_custom_parameter().map_err(|error| {
        crate::execution_attempt::norito_decode_attempt_error(error, |error| error.to_string())
    })?;
    stx.world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(next))
        .map_err(|error| {
            crate::execution_attempt::norito_decode_attempt_error(error, |error| error.to_string())
        })?;
    Ok(true)
}

/// Run one atomic native compaction pass with constant archive count and a bounded hot registry.
pub(crate) fn process(block: &mut StateBlock<'_>) -> Result<(), ExecutionOutputAttemptError> {
    let mut stx = block.try_transaction()?;
    let result = compact(&mut stx);
    stx.require_storage_admission()?;
    stx.ensure_execution_ready()
        .map_err(ExecutionOutputAttemptError::Deferred)?;
    let changed = result.map_err(|error| match error {
        ExecutionAttemptError::Deferred(reason) => ExecutionOutputAttemptError::Deferred(reason),
        ExecutionAttemptError::Rejected(error) => ExecutionOutputAttemptError::Owner(error),
    })?;
    if changed {
        stx.apply();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumeragi::test_chain::CertifiedTestChain;
    use crate::validation_fee::tests::{
        install_policy_registry_fixture, payout_registry_entry,
        signed_payout_lifecycle_registry_fixture,
    };
    use ivm::error::ExecutionDeferral;

    const NOW: u64 = 1_735_650_000_000;

    fn archived_revision_fixture() -> CertifiedTestChain {
        let (mut chain, mut binding) = signed_payout_lifecycle_registry_fixture();
        while chain.height() < 20 {
            chain.commit_at((chain.height() + 1) * 1_000, Vec::new());
        }
        let mut registry = crate::validation_fee::tests::policy_registry(&[], &[binding.clone()]);
        binding.min_reward_claim_xor_minor += 1;
        registry
            .payout_policies
            .entries
            .push(payout_registry_entry(&binding, 2, 20));
        chain.setup_world_at(NOW, |stx| install_policy_registry_fixture(&registry, stx));
        // Its explicit component prestate first gains actual original certified custody.
        chain.commit_at(NOW + 1, Vec::new());
        let observed = validated_policy_registry_in_world(&chain.state().view().world)
            .unwrap()
            .unwrap();
        assert_eq!(observed, registry);
        chain
    }

    #[test]
    fn current_block_settlement_receipt_keeps_original_pricing_provenance() {
        use iroha_data_model::{
            IntoKeyValue,
            asset::{Asset, AssetId},
            validation_fee::{RetailFeeAccountStateV1, honiara_month_bounds},
        };
        use iroha_primitives::numeric::Quantity;
        let opened = 1_793_451_600_000;
        let (old_month, current_month) = honiara_month_bounds(opened).unwrap();
        let now = current_month + 1_000;
        crate::retail_fee_tests::fixture(now, |stx, policy| {
            let owner = iroha_data_model::account::AccountId::new(
                iroha_crypto::KeyPair::from_seed(vec![3; 32], iroha_crypto::Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            );
            let asset = AssetId::new(policy.ds_asset_id.clone(), owner.clone());
            let (_, balance) = Asset::new(asset.clone(), Quantity::from(100_u32)).into_key_value();
            stx.world.assets.insert(asset.clone(), balance);
            let record = RetailFeeAccountStateV1::enroll(owner, opened, 10_000).unwrap();
            crate::retail_fee::write_account(&mut stx.world, &record).unwrap();
            assert_eq!(pricing_frontier(stx).unwrap(), old_month);
            crate::retail_fee::settle_balance(&mut stx.world, &asset).unwrap();
            assert_eq!(
                crate::retail_fee::oldest_unsettled_policy_month(&stx.world, now).unwrap(),
                current_month
            );
            assert_eq!(
                pricing_frontier(stx).unwrap(),
                old_month,
                "the new receipt must still open its original pricing in this block's corpus"
            );
            let receipt = stx
                .world
                .smart_contract_state
                .changed_keys_in_block()
                .find(|key| key.as_ref().starts_with("retail_fee_receipts_v1/"))
                .unwrap()
                .clone();
            stx.world
                .smart_contract_state
                .insert(receipt, vec![1, 2, 3]);
            assert!(pricing_frontier(stx).is_err());
        });
    }

    #[test]
    fn original_registry_compaction_is_atomic_and_missing_or_corrupt_custody_defers() {
        let chain = archived_revision_fixture();
        let height = chain.height();
        let path = chain
            .kura()
            .store_root()
            .join("native-contexts")
            .join(format!(
                "{height:020}-{}.nrt",
                hex::encode(chain.committed(height).block_hash().as_ref()),
            ));
        let original = std::fs::read(&path).unwrap();
        let registry = validated_policy_registry_in_world(&chain.state().view().world)
            .unwrap()
            .unwrap();
        let proposal = chain.proposal(Some(NOW + 2), Vec::new());
        let state = std::sync::Arc::clone(chain.state());
        let mut block = state.block(proposal.header());
        {
            let mut stx = block.transaction();
            assert!(compact(&mut stx).unwrap());
            let next = validated_policy_registry_in_world(&stx.world)
                .unwrap()
                .unwrap();
            assert_eq!(next.payout_policies.entries.len(), 1);
            next.validate_history_source(height, &registry).unwrap();
            // A later instruction failure drops this exact transaction, including checkpoint.
        }
        assert_eq!(
            validated_policy_registry_in_world(&block.world)
                .unwrap()
                .unwrap(),
            registry
        );
        let hidden = path.with_extension("policy-history-original");
        std::fs::rename(&path, &hidden).unwrap();
        let missing = {
            let mut stx = block.transaction();
            compact(&mut stx)
        };
        std::fs::rename(&hidden, &path).unwrap();
        assert!(
            matches!(missing, Err(ExecutionAttemptError::Deferred(reason))
            if reason.reason() == ExecutionDeferral::CanonicalHistoryUnavailable)
        );
        std::fs::write(&path, b"tampered policy history archive").unwrap();
        let corrupt = {
            let mut stx = block.transaction();
            compact(&mut stx)
        };
        std::fs::write(&path, original).unwrap();
        assert!(
            matches!(corrupt, Err(ExecutionAttemptError::Deferred(reason))
            if reason.reason() == ExecutionDeferral::CanonicalHistoryUnavailable)
        );
        assert_eq!(
            validated_policy_registry_in_world(&block.world)
                .unwrap()
                .unwrap(),
            registry
        );
        let mut stx = block.transaction();
        assert!(
            compact(&mut stx).unwrap(),
            "restoring exact original custody permits retry"
        );
    }

    #[test]
    fn compaction_process_preserves_original_decoder_refusal_and_atomic_retry() {
        let chain = archived_revision_fixture();
        let height = chain.height();
        let original_state = crate::snapshot::canonical_state_snapshot_hash(chain.state()).unwrap();
        let registry = validated_policy_registry_in_world(&chain.state().view().world)
            .unwrap()
            .unwrap();
        let proposal = chain.proposal(Some(NOW + 2), Vec::new());
        let state = std::sync::Arc::clone(chain.state());
        let mut block = state.block(proposal.header());
        let parameters = block.world.parameters.get().clone();
        let fragments = block.committed_fragment_count();
        let original = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            0,
            usize::MAX,
        ));
        let refused = original.with(|| process(&mut block));
        let Err(ExecutionOutputAttemptError::Deferred(refused)) = refused else {
            panic!("compaction must preserve the original local registry decoder refusal");
        };
        assert_eq!(refused.reason(), ExecutionDeferral::ActiveMemoryCapacity);
        let observed = refused
            .decode_refusal()
            .expect("original registry decoder cause")
            .clone();
        assert_eq!(
            observed.kind(),
            norito::core::DecodeLocalRefusalKind::EnclosingLimit
        );
        assert!(matches!(
            observed.resource_error(),
            norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 }
                if attempted > 0
        ));
        assert!(refused.allocation_refusal().is_none());
        assert!(refused.verification_refusal().is_none());
        assert!(refused.phase().is_none());
        let returned =
            crate::execution_attempt::ExecutionDeferred::try_from_vm_error(refused.into_vm_error())
                .expect("consuming VM roundtrip retains the original registry decoder cause");
        assert_eq!(returned.decode_refusal(), Some(&observed));
        assert_eq!(original.consumed_allocated_bytes(), 0);
        assert!(!norito::core::decode_limits_active());
        assert_eq!(*block.world.parameters.get(), parameters);
        assert_eq!(block.committed_fragment_count(), fragments);

        // The actual certified source and the fixture's existing execution budget
        // remain unchanged. Retrying after the refused attempt publishes one suffix.
        process(&mut block).unwrap();
        let next = validated_policy_registry_in_world(&block.world)
            .unwrap()
            .unwrap();
        assert_eq!(
            next.payout_policies.entries,
            registry.payout_policies.entries[1..]
        );
        assert_eq!(next.registered_policies, registry.registered_policies);
        assert_eq!(next.history.as_ref().unwrap().archived_at_height, height);
        next.validate_history_source(height, &registry).unwrap();
        assert_eq!(block.committed_fragment_count(), fragments + 1);
        drop(block);
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(chain.state()).unwrap(),
            original_state,
            "dropping the enclosing unpublished block must also roll back its successful compaction"
        );
    }

    #[test]
    fn certified_maintenance_compacts_registry_and_restart_replays_exact_original_history() {
        let mut chain = archived_revision_fixture();
        let source_height = chain.height();
        chain.commit_at(NOW + 2, Vec::new());
        let registry = validated_policy_registry_in_world(&chain.state().view().world)
            .unwrap()
            .unwrap();
        assert_eq!(registry.payout_policies.entries.len(), 1);
        assert_eq!(
            registry.history.as_ref().unwrap().archived_at_height,
            source_height
        );
        assert_eq!(
            registry.history.as_ref().unwrap().retired_payout_revision,
            1
        );
        validate_retained_history(&chain.state().view(), &registry, chain.height()).unwrap();
        assert!(
            matches!(
                validate_retained_history(&chain.state().view(), &registry, source_height),
                Err(ExecutionAttemptError::Rejected(_))
            ),
            "the archive checkpoint must strictly precede restored state"
        );
        let original = crate::query::native_receipts::committed_fee_evidence(
            &chain.state().view(),
            source_height,
        )
        .unwrap();
        assert_eq!(
            original.registry().unwrap().payout_policies.entries.len(),
            2
        );
        let current = crate::query::native_receipts::committed_fee_evidence(
            &chain.state().view(),
            chain.height(),
        )
        .unwrap();
        assert_eq!(current.registry(), Some(&registry));
        let mut substituted = registry.clone();
        substituted.history.as_mut().unwrap().registry_hash[0] ^= 1;
        assert!(matches!(
            validate_retained_history(&chain.state().view(), &substituted, chain.height()),
            Err(ExecutionAttemptError::Rejected(_))
        ));
        let mut restarted = archived_revision_fixture();
        restarted.replay_from(&chain).unwrap();
        let expected = crate::snapshot::canonical_state_snapshot_hash(chain.state()).unwrap();
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(restarted.state()).unwrap(),
            expected
        );
        restarted.replay_from(&chain).unwrap();
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(restarted.state()).unwrap(),
            expected
        );
        validate_retained_history(&restarted.state().view(), &registry, restarted.height())
            .unwrap();
    }
}
