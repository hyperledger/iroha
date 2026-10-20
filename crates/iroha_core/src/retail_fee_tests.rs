//! Native boundary, receipt and signed-assessment integration tests.
use super::retail_fee::*;
use crate::{smartcontracts::Execute, state::StateTransaction};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{prelude::*, validation_fee::*};
use iroha_model_base::{domain::DomainId, metadata::Metadata, state_path::StatePath};
use mv::storage::StorageReadOnly;

const START: u64 = 1_793_451_600_000;

#[test]
fn native_conversion_exemption_consumes_only_the_exact_leg_before_customer_pricing() {
    for now in [START - 1, START] {
        fixture(now, |stx, policy| {
            let source = AssetId::new(
                policy.ds_asset_id.clone(),
                policy.treasury_account_id.clone(),
            );
            let destination = account(3);
            let amount = Quantity::from(10_u32);
            stx.world.retail_fee_exempt_payments.push((
                source.clone(),
                destination.clone(),
                amount.clone(),
            ));
            let changed_legs = [
                (
                    AssetId::new(policy.ds_asset_id.clone(), account(4)),
                    destination.clone(),
                    amount.clone(),
                ),
                (
                    AssetId::new(
                        policy.reward_custody.xor_asset_id.clone(),
                        source.account().clone(),
                    ),
                    destination.clone(),
                    amount.clone(),
                ),
                (source.clone(), account(4), amount.clone()),
                (source.clone(), destination.clone(), Quantity::from(11_u32)),
            ];
            for (changed_source, changed_destination, changed_amount) in changed_legs {
                let _ = record_payment(stx, &changed_source, &changed_destination, &changed_amount);
                assert_eq!(stx.world.retail_fee_exempt_payments.len(), 1);
                assert!(
                    finalize(stx).is_err(),
                    "a mismatched leg cannot consume the exemption"
                );
            }
            record_payment(stx, &source, &destination, &amount).unwrap();
            assert!(stx.world.retail_fee_exempt_payments.is_empty());
            finalize(stx).unwrap();
            if now == START {
                assert!(
                    record_payment(stx, &source, &destination, &amount).is_err(),
                    "the consumed exemption cannot authorize a second retail payment"
                );
            }
        });
    }
}

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    )
}
pub(crate) fn fixture(
    now: u64,
    test: impl FnOnce(&mut StateTransaction<'_, '_>, ValidationFeePolicyV1),
) {
    crate::validation_fee::tests::with_validation_fee_payout_invocation_at_time(
        200_000,
        now,
        Hash::new(b"retail-native-test"),
        |stx, deployer, code, code_hash| {
            let policy = install_retail_policy_fixture(stx, deployer, code, code_hash);
            assert_eq!(stx.tx_call_hash, Some(Hash::new(b"retail-native-test")));
            // The finite invocation owner was retained before borrowing State.
            test(stx, policy);
        },
    );
}
pub(crate) fn fixture_block(
    now: u64,
    test: impl FnOnce(&mut crate::state::StateBlock<'_>, ValidationFeePolicyV1),
) {
    crate::validation_fee::tests::with_validation_fee_payout_block_at_time(
        200_000,
        now,
        |block, deployer, code, code_hash| {
            let mut setup = block.transaction();
            let policy = install_retail_policy_fixture(&mut setup, deployer, code, code_hash);
            setup.apply();
            test(block, policy);
        },
    );
}
fn install_retail_policy_fixture(
    stx: &mut StateTransaction<'_, '_>,
    deployer: &AccountId,
    code: &[u8],
    code_hash: Hash,
) -> ValidationFeePolicyV1 {
    let asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("fees", "paynet").unwrap(),
        "fee_token".parse().unwrap(),
    );
    let mut bound = crate::validation_fee::tests::activate_bound_payout_runtime(
        stx,
        deployer,
        code,
        code_hash,
        91,
        asset.clone(),
        "retail_test_conversion",
    );
    let pool = crate::validation_fee::tests::activate_bound_payout_runtime(
        stx,
        deployer,
        code,
        code_hash,
        92,
        asset.clone(),
        "retail_test_pool",
    );
    bound.binding.pool_vault_account_id = pool.binding.treasury_account_id;
    bound.binding.pool_contract_address = pool.binding.contract_address;
    bound.binding.pool_code_hash = pool.binding.code_hash;
    let policy = ValidationFeePolicyV1 {
        schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
        network_id: stx.network_id,
        policy_version: 1,
        previous_policy_hash: None,
        ds_asset_id: asset,
        ds_scale: 2,
        fee: "0.10".parse().unwrap(),
        treasury_account_id: bound.binding.treasury_account_id.clone(),
        charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,

        retail_schedule: RetailFeeScheduleV1::default(),
        effective_from_ms: START,
        notice_published_at_ms: START - RETAIL_FEE_NOTICE_MS,
        exemption_classes: vec![VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS.into()],
        reward_custody: bound.binding.custody(),
    };
    let registry = crate::validation_fee::tests::policy_registry(
        std::slice::from_ref(&policy),
        &[bound.binding],
    );
    registry.validate().unwrap();
    crate::validation_fee::tests::install_policy_registry_fixture(&registry, stx);
    policy
}

fn seed(
    stx: &mut StateTransaction<'_, '_>,
    policy: &ValidationFeePolicyV1,
    owner: &AccountId,
    value: u64,
    used: u64,
    opened: u64,
) {
    let id = AssetId::new(policy.ds_asset_id.clone(), owner.clone());
    let mut record = RetailFeeAccountStateV1::enroll(owner.clone(), opened, value).unwrap();
    record.payments_used = used;
    crate::retail_fee::write_account(&mut stx.world, &record).unwrap();
    **stx
        .world
        .asset_or_insert_exact(&id, Quantity::zero())
        .unwrap() = format!("{}.{:02}", value / 100, value % 100)
        .parse()
        .unwrap();
}
fn request(
    policy: &ValidationFeePolicyV1,
    owner: &AccountId,
    count: usize,
) -> RetailFeeQuoteRequestV1 {
    RetailFeeQuoteRequestV1 {
        account_id: owner.clone(),
        asset_definition_id: policy.ds_asset_id.clone(),
        transfers: (0..count)
            .map(|_| RetailFeePaymentLegV1 {
                destination_account_id: account(4),
                amount_minor_units: 100,
            })
            .collect(),
    }
}
fn reviewed(
    stx: &mut StateTransaction<'_, '_>,
    req: &RetailFeeQuoteRequestV1,
    tag: u8,
) -> RetailFeeAssessmentV1 {
    let assessment = quote(
        &stx.world,
        stx.block_height(),
        stx.block_unix_timestamp_ms(),
        req,
    )
    .unwrap();
    stx.world.retail_fee_assessment = Some(assessment.clone());
    stx.world.retail_fee_source_transaction_hash = Some(*Hash::new([tag]).as_ref());
    assessment
}
fn pay(stx: &mut StateTransaction<'_, '_>, req: &RetailFeeQuoteRequestV1) {
    for leg in &req.transfers {
        Transfer::asset_quantity(
            AssetId::new(req.asset_definition_id.clone(), req.account_id.clone()),
            Quantity::from(1_u32),
            leg.destination_account_id.clone(),
        )
        .execute(&req.account_id, stx)
        .unwrap();
    }
}
#[test]
fn applied_three_leg_batch_crosses_allowance_once_and_records_funded_receipt() {
    fixture(START + 1000, |stx, policy| {
        let owner = account(3);
        seed(stx, &policy, &owner, 1000, 49, START);
        let req = request(&policy, &owner, 3);
        let assessment = reviewed(stx, &req, 1);
        assert_eq!(assessment.fee_minor, 20);
        let entries = req
            .transfers
            .iter()
            .enumerate()
            .map(|(index, leg)| {
                iroha_data_model::isi::transfer::TransferAssetBatchEntry::with_leg_id(
                    format!("payment-{index}"),
                    owner.clone(),
                    leg.destination_account_id.clone(),
                    policy.ds_asset_id.clone(),
                    Quantity::from(1_u32),
                )
            })
            .collect();
        TransferAssetBatch::new(entries)
            .execute(&owner, stx)
            .unwrap();
        finalize(stx).unwrap();
        let status = account_state(&stx.world, &owner).unwrap().unwrap();
        assert_eq!((status.balance_minor, status.payments_used), (680, 52));
        let receipt = receipts(&stx.world, &owner, None, 10).unwrap();
        assert_eq!(receipt.len(), 1);
        assert_eq!(
            (receipt[0].collected_minor, receipt[0].payment_count),
            (20, 3)
        );
        assert_eq!(
            stx.world
                .assets
                .get(&AssetId::new(
                    policy.ds_asset_id,
                    policy.treasury_account_id
                ))
                .unwrap()
                .as_ref(),
            &"0.20".parse::<Quantity>().unwrap()
        );
    });
}
#[test]
fn included_payments_have_zero_receipts_without_treasury_balance_entries() {
    fixture(START + 1000, |stx, policy| {
        let owner = account(3);
        seed(stx, &policy, &owner, 1000, 0, START);
        let req = request(&policy, &owner, 1);
        assert_eq!(reviewed(stx, &req, 2).fee_minor, 0);
        pay(stx, &req);
        finalize(stx).unwrap();
        assert!(
            stx.world
                .assets
                .get(&AssetId::new(
                    policy.ds_asset_id,
                    policy.treasury_account_id
                ))
                .is_none()
        );
        assert_eq!(
            receipts(&stx.world, &owner, None, 10).unwrap()[0].collected_minor,
            0
        );
    });
}
#[test]
fn direct_unquoted_and_stale_free_payments_cannot_silently_charge() {
    fixture_block(START + 1000, |block, policy| {
        let owner = account(3);
        let mut setup = block.transaction();
        seed(&mut setup, &policy, &owner, 1000, 49, START);
        setup.apply();
        let req = request(&policy, &owner, 1);
        let transfer = Transfer::asset_quantity(
            AssetId::new(policy.ds_asset_id.clone(), owner.clone()),
            Quantity::from(1_u32),
            account(4),
        );
        let mut unquoted =
            block.transaction_for_fastpq_testing(Hash::new(b"retail-unquoted-refusal"));
        assert!(transfer.clone().execute(&owner, &mut unquoted).is_err());
        assert_eq!(
            unquoted
                .world
                .assets
                .get(&AssetId::new(policy.ds_asset_id.clone(), owner.clone()))
                .unwrap()
                .as_ref(),
            &Quantity::from(10_u32)
        );
        assert!(unquoted.retail_fee_transcripts_for_test().is_empty());
        drop(unquoted);
        let mut accepted =
            block.transaction_for_fastpq_testing(Hash::new(b"retail-reviewed-payment"));
        assert_eq!(
            account_state(&accepted.world, &owner)
                .unwrap()
                .unwrap()
                .payments_used,
            49,
            "unquoted refusal rolled back the original account"
        );
        let old = reviewed(&mut accepted, &req, 3);
        assert_eq!(old.fee_minor, 0);
        pay(&mut accepted, &req);
        finalize(&mut accepted).unwrap();
        accepted.apply();
        let mut stale = block.transaction_for_fastpq_testing(Hash::new(b"retail-stale-payment"));
        stale.world.retail_fee_assessment = Some(old);
        stale.world.retail_fee_source_transaction_hash = Some(*Hash::new([4]).as_ref());
        pay(&mut stale, &req);
        assert!(finalize(&mut stale).is_err());
        drop(stale);
        let check = block.transaction();
        assert_eq!(
            account_state(&check.world, &owner)
                .unwrap()
                .unwrap()
                .payments_used,
            50
        );
    });
}
#[test]
fn later_credit_materializes_old_shortfall_before_credit_and_keeps_receipt() {
    fixture(START + 30 * 86_400_000, |stx, policy| {
        let owner = account(3);
        seed(stx, &policy, &owner, 30, 50, START);
        let id = AssetId::new(policy.ds_asset_id.clone(), owner.clone());
        assert_eq!(
            projected_balance(&stx.world, &id, stx.block_unix_timestamp_ms()).unwrap(),
            Some(Quantity::zero())
        );
        Mint::asset_quantity(Quantity::from(10_u32), id)
            .execute(&owner, stx)
            .unwrap();
        finalize(stx).unwrap();
        let status = account_state(&stx.world, &owner).unwrap().unwrap();
        assert_eq!((status.balance_minor, status.payments_used), (1000, 0));
        let receipt = receipts(&stx.world, &owner, None, 10).unwrap();
        assert_eq!(
            (receipt[0].collected_minor, receipt[0].waived_minor),
            (30, 70)
        );
    });
}
#[test]
fn native_recovery_preserves_allowance_and_retires_old_identity() {
    fixture(START + 1000, |stx, policy| {
        let old = account(3);
        let new = account(6);
        seed(stx, &policy, &old, 1000, 49, START);
        prepare_rekey(stx, &old, &new).unwrap();
        finish_rekey(stx, &old, &new).unwrap();
        assert_eq!(
            account_state(&stx.world, &new)
                .unwrap()
                .unwrap()
                .payments_used,
            49
        );
        assert!(account_state(&stx.world, &old).unwrap().is_none());
        assert!(ensure_not_rekeyed(&stx.world, &old).is_err());
        assert!(prepare_rekey(stx, &new, &old).is_err());
    });
}

#[test]
fn maintenance_delta_precedes_principal_and_overage_follows_it() {
    fixture(START + 30 * 86_400_000, |stx, policy| {
        let owner = account(3);
        seed(stx, &policy, &owner, 1000, 50, START);
        let req = request(&policy, &owner, 1);
        assert_eq!(reviewed(stx, &req, 19).fee_minor, 0);
        pay(stx, &req);
        finalize(stx).unwrap();
        let deltas: Vec<_> = stx
            .retail_fee_transcripts_for_test()
            .iter()
            .flat_map(|t| &t.deltas)
            .collect();
        assert_eq!(deltas.len(), 2);
        assert_eq!(deltas[0].to_account, policy.treasury_account_id);
        assert_eq!(deltas[0].from_balance_before, Quantity::from(10_u32));
        assert_eq!(deltas[0].from_balance_after, Quantity::from(9_u32));
        assert_eq!(deltas[1].from_balance_before, deltas[0].from_balance_after);
        assert_eq!(deltas[1].from_balance_after, Quantity::from(8_u32));
    });
    fixture(START + 1000, |stx, policy| {
        let owner = account(3);
        seed(stx, &policy, &owner, 1000, 50, START);
        let req = request(&policy, &owner, 1);
        assert_eq!(reviewed(stx, &req, 20).fee_minor, 10);
        pay(stx, &req);
        finalize(stx).unwrap();
        let deltas: Vec<_> = stx
            .retail_fee_transcripts_for_test()
            .iter()
            .flat_map(|t| &t.deltas)
            .collect();
        assert_eq!(deltas.len(), 2);
        assert_eq!(deltas[1].to_account, policy.treasury_account_id);
        assert_eq!(deltas[1].from_balance_before, deltas[0].from_balance_after);
        assert_eq!(
            deltas[1].from_balance_after,
            "8.90".parse::<Quantity>().unwrap()
        );
    });
}
#[test]
fn deferred_and_immediate_boundary_collection_have_identical_native_effects() {
    let boundary = START + 30 * 86_400_000;
    let now = boundary + 14 * 86_400_000;
    let mut outcomes = Vec::new();
    for eager in [false, true] {
        fixture(now, |stx, policy| {
            let owner = account(3);
            seed(stx, &policy, &owner, 1000, 50, START);
            if eager {
                stx.world.retail_fee_now_ms = boundary;
                settle_balance(
                    &mut stx.world,
                    &AssetId::new(policy.ds_asset_id.clone(), owner.clone()),
                )
                .unwrap();
                stx.flush_retail_fee_transfer_transcripts().unwrap();
                stx.world.retail_fee_now_ms = now;
            }
            let req = request(&policy, &owner, 1);
            reviewed(stx, &req, 21);
            pay(stx, &req);
            finalize(stx).unwrap();
            outcomes.push((
                account_state(&stx.world, &owner).unwrap(),
                receipts(&stx.world, &owner, None, 10).unwrap(),
                stx.retail_fee_transcripts_for_test().to_vec(),
            ));
        });
    }
    assert_eq!(outcomes[0], outcomes[1]);
}
#[test]
fn independent_governed_payment_batch_is_rejected_before_principal() {
    fixture(START + 1000, |stx, policy| {
        let owner = account(3);
        seed(stx, &policy, &owner, 1000, 49, START);
        let req = request(&policy, &owner, 1);
        reviewed(stx, &req, 22);
        let batch = TransferAssetBatch::independent(vec![
            iroha_data_model::isi::transfer::TransferAssetBatchEntry::new(
                owner.clone(),
                account(4),
                policy.ds_asset_id,
                Quantity::from(1_u32),
            ),
        ]);
        assert!(batch.execute(&owner, stx).is_err());
        assert_eq!(
            account_state(&stx.world, &owner)
                .unwrap()
                .unwrap()
                .balance_minor,
            1000
        );
        assert!(stx.retail_fee_transcripts_for_test().is_empty());
    });
}
#[test]
fn enrollment_requires_the_wallet_primary_alias_issuer_domain() {
    use iroha_data_model::account::{AccountAlias, AccountAliasDomain};
    use iroha_executor_data_model::permission::account::CanRegisterAccount;
    fixture(START + 1000, |stx, _policy| {
        let issuer = account(5);
        let wallet = account(3);
        let alias = AccountAlias::new_in_dataspace(
            "retail".parse().unwrap(),
            Some(AccountAliasDomain::new("contracts".parse().unwrap())),
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        );
        stx.world
            .account_mut(&wallet)
            .unwrap()
            .set_label(Some(alias));
        let wrong: Permission = CanRegisterAccount {
            domain: DomainId::try_new("fees", "paynet").unwrap(),
        }
        .into();
        Grant::account_permission(wrong, issuer.clone())
            .execute(&issuer, stx)
            .unwrap();
        assert!(enroll(stx, &issuer, &wallet).is_err());
        assert!(!is_account_issuer_for_primary_alias(&stx.world, &issuer, &wallet).unwrap());
        assert!(!is_account_issuer_for_primary_alias(&stx.world, &account(4), &wallet).unwrap());
        let scoped: Permission = CanRegisterAccount {
            domain: DomainId::try_new("contracts", "universal").unwrap(),
        }
        .into();
        Grant::account_permission(scoped, issuer.clone())
            .execute(&issuer, stx)
            .unwrap();
        assert!(is_account_issuer_for_primary_alias(&stx.world, &issuer, &wallet).unwrap());
        assert!(
            account_state(&stx.world, &wallet).unwrap().is_none(),
            "read authorization never enrolls or mutates a wallet"
        );
        enroll(stx, &issuer, &wallet).unwrap();
        assert!(enroll(stx, &wallet, &wallet).is_err());
        assert_eq!(
            account_state(&stx.world, &wallet)
                .unwrap()
                .unwrap()
                .payments_used,
            0
        );
    });
}

#[test]
fn idle_maintenance_transcript_uses_immutable_receipt_protocol_identity() {
    crate::validation_fee::tests::with_validation_fee_payout_protocol_at_time(
        200_000,
        START + 30 * 86_400_000,
        |stx, deployer, code, code_hash| {
            // Reuse the same activated runtime and policy installation under the explicit
            // mandatory component owner rather than grant that owner to ordinary fixtures.
            let policy = install_retail_policy_fixture(stx, deployer, code, code_hash);
            let owner = account(3);
            seed(stx, &policy, &owner, 30, 0, START);
            assert!(stx.tx_call_hash.is_none());
            settle_balance(
                &mut stx.world,
                &AssetId::new(policy.ds_asset_id, owner.clone()),
            )
            .unwrap();
            finalize(stx).unwrap();
            let receipt = receipts(&stx.world, &owner, None, 10).unwrap().remove(0);
            let hash = Hash::prehashed(receipt.receipt_id);
            assert_eq!(stx.retail_fee_transcripts_for_test()[0].batch_hash, hash);
            assert!(stx.retail_fee_source_kind_for_test(&hash));
            assert_eq!((receipt.collected_minor, receipt.waived_minor), (30, 70));
        },
    );
}

#[test]
fn receipt_chain_is_contiguous_and_recovery_preserves_its_original_wallet() {
    fixture(START + 1000, |stx, policy| {
        let owner = account(3);
        let recovered = account(6);
        seed(stx, &policy, &owner, 1000, 0, START);
        let req = request(&policy, &owner, 1);
        reviewed(stx, &req, 61);
        pay(stx, &req);
        finalize(stx).unwrap();
        let first = receipt_sequence(&stx.world, &owner, 0, 10)
            .unwrap()
            .remove(0);
        assert_eq!(first.sequence, 1);
        assert_eq!(first.wallet_id, owner);
        assert_eq!(first.previous_receipt_hash, None);
        let first_hash = retail_fee_receipt_chain_hash_v1(&first).unwrap();
        let head = receipt_head(&stx.world, &owner).unwrap().unwrap();
        assert_eq!(head.last_receipt_hash, Some(first_hash));
        prepare_rekey(stx, &owner, &recovered).unwrap();
        finish_rekey(stx, &owner, &recovered).unwrap();
        let recovered_head = receipt_head(&stx.world, &recovered).unwrap().unwrap();
        assert_eq!(recovered_head.wallet_id, owner);
        assert_eq!(recovered_head.current_account_id, recovered);
        assert_eq!(recovered_head.sequence, head.sequence);
        assert_eq!(recovered_head.last_receipt_hash, head.last_receipt_hash);
        // The private producer links a subsequent receipt to the unchanged original wallet.
        let mut second = first.clone();
        second.account_id = recovered.clone();
        second.source_transaction_hash = Some([62; 32]);
        second.receipt_id = retail_fee_receipt_id_v1(
            &recovered,
            second.kind,
            second.billing_month_start_ms,
            second.source_transaction_hash,
            None,
        )
        .unwrap();
        store_receipt(&mut stx.world, &mut second).unwrap();
        assert_eq!(second.sequence, 2);
        assert_eq!(second.wallet_id, owner);
        assert_eq!(second.previous_receipt_hash, Some(first_hash));
        assert!(store_receipt(&mut stx.world, &mut second).is_err());
        let rows = receipt_sequence(&stx.world, &owner, 0, 10).unwrap();
        assert_eq!(rows, vec![first, second]);
        let latest = receipt_head(&stx.world, &recovered).unwrap().unwrap();
        let frontier = iroha_data_model::fee_evidence::RetailFeeReceiptCursorV1 {
            wallet_id: owner.clone(),
            next_sequence: latest.sequence,
            next_receipt_hash: latest.last_receipt_hash,
        };
        let page = receipt_page(&stx.world, &frontier, 1).unwrap();
        assert_eq!(page.receipts.len(), 1);
        let next = page.verify(&frontier).unwrap();
        assert_eq!(
            (next.next_sequence, next.next_receipt_hash),
            (1, Some(first_hash))
        );
        let last = receipt_page(&stx.world, &next, 1)
            .unwrap()
            .verify(&next)
            .unwrap();
        assert_eq!((last.next_sequence, last.next_receipt_hash), (0, None));
        assert!(receipt_page(&stx.world, &frontier, 0).is_err());
        assert!(receipt_page(&stx.world, &frontier, 101).is_err());
        assert_eq!(
            receipt_head(&stx.world, &recovered)
                .unwrap()
                .unwrap()
                .sequence,
            2
        );
        assert!(is_reserved_state_key(
            &retail_fee_receipt_head_state_key_v1(&owner).unwrap()
        ));
        assert!(is_reserved_state_key(&receipt_sequence_key(&owner, 2)));
    });
}

#[test]
fn account_closure_defers_maintenance_and_preserves_current_month_usage() {
    fixture(START + 15 * 86_400_000, |stx, policy| {
        let owner = account(3);
        seed(stx, &policy, &owner, 5_000_000, 49, START);
        close_account(stx, &owner).unwrap();
        let retained = account_state(&stx.world, &owner).unwrap().unwrap();
        assert_eq!(retained.payments_used, 49);
        assert_eq!(retained.active_time_ms, 15 * 86_400_000);
        assert!(retained.closed_at_ms.is_some());
        assert!(receipts(&stx.world, &owner, None, 10).unwrap().is_empty());
        assert!(stx.retail_fee_transcripts_for_test().is_empty());
        assert!(stx.world.retail_fee_pending_credits.is_empty());
        // Account removal is the same overlay's following lifecycle operation.
        stx.world.accounts.remove(owner.clone());
        stx.world
            .assets
            .remove(AssetId::new(policy.ds_asset_id.clone(), owner.clone()));
        stx.world.retail_fee_now_ms = START + 30 * 86_400_000;
        settle_balance(
            &mut stx.world,
            &AssetId::new(policy.ds_asset_id.clone(), owner.clone()),
        )
        .unwrap();
        finalize(stx).unwrap();
        let receipt = receipts(&stx.world, &owner, None, 10).unwrap().remove(0);
        assert_eq!(
            (
                receipt.scheduled_minor,
                receipt.collected_minor,
                receipt.waived_minor
            ),
            (500, 0, 500)
        );
        assert!(
            stx.world
                .assets
                .get(&AssetId::new(policy.ds_asset_id, owner))
                .is_none()
        );
        assert!(stx.retail_fee_transcripts_for_test().is_empty());
    });
}

#[test]
fn finalized_parent_quote_remains_usable_in_later_block_within_original_expiry() {
    let now = START + 30_000;
    for used in [0, 50] {
        fixture(now, |stx, policy| {
            let owner = account(3);
            seed(stx, &policy, &owner, 1000, used, START);
            let req = request(&policy, &owner, 1);
            let parent = quote(&stx.world, stx.block_height() - 1, now - 20_000, &req).unwrap();
            let later = quote(&stx.world, stx.block_height(), now, &req).unwrap();
            assert_eq!(parent.state_commitment, later.state_commitment);
            assert_eq!(parent.fee_minor, if used == 0 { 0 } else { 10 });
            assert!(parent.expires_at_ms < later.expires_at_ms);
            let mut metadata = Metadata::default();
            metadata.insert(
                RETAIL_FEE_ASSESSMENT_METADATA_KEY.parse().unwrap(),
                Json::new(parent.clone()),
            );
            let signing = KeyPair::try_from_seed(vec![3; 32], Algorithm::Ed25519).unwrap();
            let signed = TransactionBuilder::new(
                stx.network_id,
                owner.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Transfer::asset_quantity(
                AssetId::new(policy.ds_asset_id.clone(), owner.clone()),
                Quantity::from(1_u32),
                account(4),
            )])
            .with_metadata(metadata)
            .sign(signing.private_key());
            admit(&signed, stx).unwrap();
            pay(stx, &req);
            finalize(stx).unwrap();
            let receipt = receipts(&stx.world, &owner, None, 10).unwrap().remove(0);
            assert_eq!(receipt.assessment, Some(parent.clone()));
            assert_eq!(receipt.collected_minor, parent.fee_minor);
            let current = account_state(&stx.world, &owner).unwrap().unwrap();
            assert_eq!(current.payments_used, used + 1);
            assert_eq!(current.balance_minor, 900 - parent.fee_minor);
        });
    }
}

fn assessment_marker(assessment: &RetailFeeAssessmentV1) -> Log {
    Log::new(
        Level::TRACE,
        format!(
            "{ASSESSMENT_MARKER_PREFIX}{}",
            hex::encode(norito::to_bytes(assessment).unwrap())
        ),
    )
}

#[test]
fn deferred_assessment_rejects_duplicate_and_noncanonical_markers_without_binding() {
    fixture(START + 1000, |stx, policy| {
        let owner = account(3);
        seed(stx, &policy, &owner, 1000, 0, START);
        let req = request(&policy, &owner, 1);
        let assessment = quote(&stx.world, stx.block_height(), START + 1000, &req).unwrap();
        let marker = assessment_marker(&assessment);
        let mut different = assessment.clone();
        different.fee_minor += 1;
        for second in [marker.clone(), assessment_marker(&different)] {
            assert!(admit_deferred(&[marker.clone().into(), second.into()], stx).is_err());
            assert!(stx.world.retail_fee_assessment.is_none());
            assert!(!stx.world.retail_fee_assessment_marker_pending);
        }

        let encoded = marker.msg.strip_prefix(ASSESSMENT_MARKER_PREFIX).unwrap();
        let noncompact = {
            let _flags = norito::core::DecodeFlagsGuard::enter(0);
            norito::to_bytes(&assessment).unwrap()
        };
        assert_eq!(
            norito::decode_from_bytes::<RetailFeeAssessmentV1>(&noncompact).unwrap(),
            assessment
        );
        assert_ne!(hex::encode(&noncompact), encoded);
        for invalid in [
            encoded.to_uppercase(),
            format!(" {encoded}"),
            format!("{encoded} "),
            format!("0x{encoded}"),
            encoded[1..].to_owned(),
            format!("{encoded}00"),
            hex::encode(noncompact),
            "00".repeat(4097),
            String::new(),
        ] {
            let log = Log::new(Level::TRACE, format!("{ASSESSMENT_MARKER_PREFIX}{invalid}"));
            assert!(admit_deferred(&[log.into()], stx).is_err());
            assert!(stx.world.retail_fee_assessment.is_none());
        }
        assert!(admit_deferred(&[Log::new(Level::INFO, marker.msg.clone()).into()], stx).is_err());
        admit_deferred(&[marker.into()], stx).unwrap();
        assert_eq!(stx.world.retail_fee_assessment, Some(assessment));
    });
}

#[test]
fn assessment_metadata_and_deferred_scopes_cannot_bind_the_same_assessment_twice() {
    for metadata_first in [true, false] {
        fixture(START + 1000, |stx, policy| {
            let owner = account(3);
            seed(stx, &policy, &owner, 1000, 0, START);
            let req = request(&policy, &owner, 1);
            let assessment = quote(&stx.world, stx.block_height(), START + 1000, &req).unwrap();
            let marker = assessment_marker(&assessment);
            let mut metadata = Metadata::default();
            metadata.insert(
                RETAIL_FEE_ASSESSMENT_METADATA_KEY.parse().unwrap(),
                Json::new(assessment.clone()),
            );
            let signing = KeyPair::try_from_seed(vec![3; 32], Algorithm::Ed25519).unwrap();
            let signed = TransactionBuilder::new(
                stx.network_id,
                owner,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "ordinary log".into())])
            .with_metadata(metadata)
            .sign(signing.private_key());
            if metadata_first {
                admit(&signed, stx).unwrap();
                assert!(marker.clone().execute(signed.authority(), stx).is_err());
                assert!(admit_deferred(&[marker.clone().into()], stx).is_err());
                assert!(admit(&signed, stx).is_err());
            } else {
                admit_deferred(&[marker.clone().into()], stx).unwrap();
                assert!(
                    admit_deferred(&[], stx).is_ok(),
                    "marker-free nested relay must remain valid"
                );
                assert!(
                    admit_deferred(&[marker.clone().into()], stx).is_err(),
                    "nested or sibling duplicate must reject"
                );
                assert!(admit(&signed, stx).is_err());
            }
            assert_eq!(stx.world.retail_fee_assessment, Some(assessment));
        });
    }
}

#[test]
fn deferred_marker_is_consumed_once_and_preserves_atomic_free_and_paid_payments() {
    for used in [0, 50] {
        fixture(START + 1000, |stx, policy| {
            let owner = account(3);
            seed(stx, &policy, &owner, 1000, used, START);
            let req = request(&policy, &owner, 1);
            let assessment = quote(&stx.world, stx.block_height(), START + 1000, &req).unwrap();
            let marker = assessment_marker(&assessment);
            // A direct or contract-emitted log cannot establish the assessment.
            assert!(marker.clone().execute(&owner, stx).is_err());
            assert!(stx.world.retail_fee_assessment.is_none());
            admit_deferred(&[], stx).unwrap();
            let instructions = vec![marker.clone().into()];
            admit_deferred(&instructions, stx).unwrap();
            assert!(
                marker.clone().execute(&owner, stx).is_err(),
                "not inside authenticated deferred execution"
            );
            stx.multisig_deferred_execution_stack.push((
                owner.clone(),
                iroha_executor_data_model::isi::multisig::MultisigProposalId::derive(
                    &stx.network_id,
                    &owner,
                    &iroha_executor_data_model::isi::multisig::MultisigProposalNonce::new(
                        [0x61; 32],
                    )
                    .unwrap(),
                ),
            ));
            admit_deferred(&[], stx).unwrap();
            stx.world.retail_fee_source_transaction_hash =
                Some(*Hash::new([u8::try_from(used).expect("fixture value fits u8")]).as_ref());
            pay(stx, &req);
            assert!(
                finalize(stx).is_err(),
                "unconsumed preauthorized marker must not finalize"
            );
            assert!(receipts(&stx.world, &owner, None, 10).unwrap().is_empty());
            marker.clone().execute(&owner, stx).unwrap();
            assert!(!stx.world.retail_fee_assessment_marker_pending);
            assert!(
                admit_deferred(&instructions, stx).is_err(),
                "consumption cannot reauthorize a nested duplicate"
            );
            assert!(
                marker.execute(&owner, stx).is_err(),
                "contract-emitted duplicate cannot consume another authorization"
            );
            stx.multisig_deferred_execution_stack.pop();
            finalize(stx).unwrap();
            let receipt = receipts(&stx.world, &owner, None, 10).unwrap().remove(0);
            assert_eq!(receipt.assessment, Some(assessment.clone()));
            assert_eq!(receipt.collected_minor, if used == 0 { 0 } else { 10 });
            let current = account_state(&stx.world, &owner).unwrap().unwrap();
            assert_eq!(current.payments_used, used + 1);
            assert_eq!(current.balance_minor, 900 - assessment.fee_minor);
        });
    }
}

#[test]
fn direct_assessment_markers_reject_with_or_without_metadata_in_instructions_and_batches() {
    use iroha_data_model::transaction::{Executable, ExecutableBatchItem, FeePaymentIntent};
    fixture(START + 1000, |stx, policy| {
        let owner = account(3);
        seed(stx, &policy, &owner, 1000, 0, START);
        let req = request(&policy, &owner, 1);
        let assessment = quote(&stx.world, stx.block_height(), START + 1000, &req).unwrap();
        let marker = assessment_marker(&assessment);
        let signing = KeyPair::try_from_seed(vec![3; 32], Algorithm::Ed25519).unwrap();
        for with_metadata in [false, true] {
            for executable in [
                Executable::Instructions(vec![marker.clone().into()].into()),
                Executable::Batch(
                    vec![ExecutableBatchItem::Instruction(marker.clone().into())].into(),
                ),
            ] {
                let mut metadata = Metadata::default();
                if with_metadata {
                    metadata.insert(
                        RETAIL_FEE_ASSESSMENT_METADATA_KEY.parse().unwrap(),
                        Json::new(assessment.clone()),
                    );
                }
                let signed = TransactionBuilder::new(
                    stx.network_id,
                    owner.clone(),
                    FeePaymentIntent::authority(Vec::new(), None),
                )
                .with_executable(executable)
                .with_metadata(metadata)
                .sign(signing.private_key());
                assert!(admit(&signed, stx).is_err());
                assert!(stx.world.retail_fee_assessment.is_none());
                assert!(!stx.world.retail_fee_assessment_marker_pending);
            }
        }
    });
}

#[test]
fn freeze_transitions_preserve_boundary_availability_and_permanent_waivers() {
    use crate::smartcontracts::isi::asset::isi::update_control_record;
    use iroha_data_model::asset::{AssetTransferAvailability, AssetTransferControlRecord};
    let boundary = START + 30 * 86_400_000;
    for initially_frozen in [false, true] {
        fixture(boundary + 1_000, |stx, policy| {
            let owner = account(3);
            seed(stx, &policy, &owner, 1000, 0, START);
            let mut control = AssetTransferControlRecord::new(policy.ds_asset_id.clone());
            if initially_frozen {
                stx.world.retail_fee_now_ms = START;
                control.outgoing_availability = AssetTransferAvailability::Disabled;
                update_control_record(stx, &owner, control.clone()).unwrap();
                stx.world.retail_fee_now_ms = boundary + 1_000;
            }
            control.outgoing_availability = if initially_frozen {
                AssetTransferAvailability::Enabled
            } else {
                AssetTransferAvailability::Disabled
            };
            update_control_record(stx, &owner, control).unwrap();
            finalize(stx).unwrap();
            let collected = if initially_frozen { 0 } else { 100 };
            let receipt = receipts(&stx.world, &owner, None, 10).unwrap();
            assert_eq!(receipt.len(), 1);
            assert_eq!(receipt[0].collected_minor, collected);
            assert_eq!(receipt[0].waived_minor, 100 - collected);
            let id = AssetId::new(policy.ds_asset_id.clone(), owner.clone());
            Mint::asset_quantity(Quantity::from(10_u32), id)
                .execute(&owner, stx)
                .unwrap();
            finalize(stx).unwrap();
            assert_eq!(
                account_state(&stx.world, &owner)
                    .unwrap()
                    .unwrap()
                    .balance_minor,
                2000 - collected
            );
            assert_eq!(receipts(&stx.world, &owner, None, 10).unwrap().len(), 1);
        });
    }
}

#[test]
fn multi_year_dormancy_rejects_before_mutation_and_bounded_sweeps_preserve_waivers() {
    let mut now = START;
    for _ in 0..36 {
        now = honiara_month_bounds(now).unwrap().1;
    }
    fixture(now + 1000, |stx, policy| {
        let owner = account(3);
        seed(stx, &policy, &owner, 30, 49, START);
        let original = account_state(&stx.world, &owner).unwrap().unwrap();
        let mut candidate = original.clone();
        assert_eq!(
            candidate
                .settle_until(now, true, |_| Ok((1, policy.retail_schedule.clone())))
                .unwrap_err(),
            RETAIL_FEE_CATCH_UP_REQUIRED
        );
        assert_eq!(candidate, original);
        let id = AssetId::new(policy.ds_asset_id.clone(), owner.clone());
        let deposit = Mint::asset_quantity(Quantity::from(10_u32), id.clone());
        assert!(
            deposit
                .clone()
                .execute(&owner, stx)
                .unwrap_err()
                .to_string()
                .contains(RETAIL_FEE_CATCH_UP_REQUIRED)
        );
        assert_eq!(
            account_state(&stx.world, &owner).unwrap().unwrap(),
            original
        );
        assert!(receipts(&stx.world, &owner, None, 100).unwrap().is_empty());
        assert_eq!(
            **stx.world.assets.get(&id).unwrap(),
            "0.30".parse::<Quantity>().unwrap()
        );
        for pass in 1..=3 {
            let record = account_state(&stx.world, &owner).unwrap().unwrap();
            settle_idle_account(stx, &policy, record).unwrap();
            finalize(stx).unwrap();
            assert!(
                stx.world.assets.get(&id).is_none(),
                "depleted fee sources use canonical absent balances"
            );
            assert!(
                stx.world
                    .asset_definition_nonzero_holders
                    .get(&(policy.ds_asset_id.clone(), owner.clone()))
                    .is_none()
            );
            assert_eq!(
                receipts(&stx.world, &owner, None, 100).unwrap().len(),
                pass * 12
            );
        }
        deposit.execute(&owner, stx).unwrap();
        finalize(stx).unwrap();
        assert_eq!(
            account_state(&stx.world, &owner)
                .unwrap()
                .unwrap()
                .balance_minor,
            1000
        );
        let history = receipts(&stx.world, &owner, None, 100).unwrap();
        assert_eq!(history.len(), 36);
        assert_eq!(
            stx.world
                .smart_contract_state
                .iter()
                .filter(|(key, _)| key.as_ref().starts_with("retail_fee_v1/"))
                .count(),
            1,
            "idle-account index never scans historical receipt rows"
        );
        assert_eq!(history.iter().map(|r| r.collected_minor).sum::<u64>(), 30);
        assert_eq!(history.iter().map(|r| r.waived_minor).sum::<u64>(), 3570);
    });
}
#[test]
fn empty_idle_sweep_retains_original_fragment_count_and_dirty_sibling() {
    let state = crate::state::State::new_for_testing(
        crate::state::World::default(),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    let mut block = state.block(iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::MIN,
        None,
        None,
        0,
        0,
    ));
    let fragments = block.committed_fragment_count();
    process_idle_accounts(&mut block).unwrap();
    assert_eq!(block.committed_fragment_count(), fragments);

    let key: StatePath = "retail_idle_original_sibling_TESTDATA".parse().unwrap();
    {
        let mut sibling = block.transaction();
        sibling
            .world
            .smart_contract_state
            .insert(key.clone(), vec![23]);
        sibling.apply();
    }
    assert_eq!(block.committed_fragment_count(), fragments + 1);
    assert_eq!(block.world.smart_contract_state.touched_entries().len(), 1);
    process_idle_accounts(&mut block).unwrap();
    assert_eq!(block.committed_fragment_count(), fragments + 1);
    assert_eq!(block.world.smart_contract_state.get(&key), Some(&vec![23]));
    assert_eq!(block.world.smart_contract_state.touched_entries().len(), 1);
    drop(block);
    assert!(
        state
            .view()
            .world()
            .smart_contract_state
            .get(&key)
            .is_none()
    );
}

#[test]
fn idle_cursor_local_decode_refusal_returns_before_child_drop_and_retries_original_state() {
    let state = crate::state::State::new_for_testing(
        crate::state::World::default(),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    let cursor_key: StatePath = "retail_fee_control_v1/sweep_cursor".parse().unwrap();
    let original_cursor: StatePath = "retail_fee_v1/original_cursor".parse().unwrap();
    let bytes = norito::to_bytes(&original_cursor).unwrap();
    let header =
        iroha_data_model::block::BlockHeader::new(std::num::NonZeroU64::MIN, None, None, 0, 0);
    let mut block = state.block(header);
    block
        .world
        .smart_contract_state
        .insert(cursor_key.clone(), bytes.clone());
    let fragments = block.committed_fragment_count();
    // StatePath is nominal text: deny its actual field bytes, not sequence elements.
    let refused = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, usize::MAX),
        || process_idle_accounts(&mut block),
    )
    .unwrap_err();
    let crate::execution_attempt::ExecutionAttemptError::Deferred(original) = refused else {
        panic!("cursor decoding must not become successful optional sweep completion");
    };
    assert_eq!(
        original.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    let observation = original
        .decode_refusal()
        .expect("original captured cursor scope")
        .clone();
    assert!(original.allocation_refusal().is_none());
    let block_error = crate::block::BlockValidationError::ExecutionDeferred(original);
    let crate::block::BlockValidationError::ExecutionDeferred(returned) = block_error else {
        unreachable!()
    };
    assert_eq!(returned.decode_refusal(), Some(&observation));
    assert_eq!(block.committed_fragment_count(), fragments);
    assert_eq!(
        block.world.smart_contract_state.get(&cursor_key),
        Some(&bytes)
    );
    process_idle_accounts(&mut block)
        .expect("same cursor and parent retry after enclosing scope retires");
    assert_eq!(block.committed_fragment_count(), fragments);
    assert_eq!(
        block.world.smart_contract_state.get(&cursor_key),
        Some(&bytes)
    );
    drop(block);
    assert!(
        state
            .view()
            .world()
            .smart_contract_state
            .get(&cursor_key)
            .is_none(),
        "disposable block-local state never became durable"
    );
}

#[test]
fn original_idle_sweep_admits_exact_native_receipts_before_carrier_execution() {
    fixture_block(START + 30 * 86_400_000, |block, policy| {
        let owner = account(3);
        {
            let mut setup = block.transaction();
            seed(&mut setup, &policy, &owner, 1_000, 0, START);
            setup.apply();
        }
        let (ordinary, mandatory) = block.fastpq_source_usage_for_testing();
        let native_before = block.native_maintenance_usage_for_testing();
        let fragments = block.committed_fragment_count();
        process_idle_accounts(block).unwrap();
        let rows = receipts(&block.world, &owner, None, 10).unwrap();
        assert_eq!(
            rows.len(),
            1,
            "original idle sweep must admit its own receipt purpose"
        );
        let receipt = &rows[0];
        assert_eq!((receipt.collected_minor, receipt.waived_minor), (100, 0));
        assert_eq!(receipt.kind, RetailFeeReceiptKindV1::Maintenance);
        assert_eq!(receipt.source_transaction_hash, None);
        assert_eq!(
            account_state(&block.world, &owner)
                .unwrap()
                .unwrap()
                .balance_minor,
            900
        );
        assert_eq!(
            block.fastpq_source_usage_for_testing(),
            (ordinary, mandatory)
        );
        let native = block.native_maintenance_usage_for_testing();
        assert_eq!(native.executed_entries, native_before.executed_entries + 1);
        assert_eq!(native.transcripts, native_before.transcripts + 1);
        assert_eq!(native.deltas, native_before.deltas + 1);
        assert!(native.input_transcript_bytes > native_before.input_transcript_bytes);
        assert!(native.total_statement_bytes > native_before.total_statement_bytes);
        assert_eq!(block.committed_fragment_count(), fragments + 1);
        // A second original sweep cannot debit the same receipt or poison a later sibling.
        process_idle_accounts(block).unwrap();
        assert_eq!(receipts(&block.world, &owner, None, 10).unwrap(), rows);
        assert_eq!(block.native_maintenance_usage_for_testing(), native);
        let marker: StatePath = "retail_native_carrier_sibling_TESTDATA".parse().unwrap();
        let mut sibling = block.transaction();
        sibling
            .world
            .smart_contract_state
            .insert(marker.clone(), vec![31]);
        sibling.apply();
        assert_eq!(
            block.world.smart_contract_state.get(&marker),
            Some(&vec![31])
        );
    });
}

pub(crate) fn with_original_due_idle_wallet(
    test: impl FnOnce(&mut crate::state::StateBlock<'_>, ValidationFeePolicyV1, AccountId),
) {
    fixture_block(START + 30 * 86_400_000, |block, policy| {
        let owner = account(3);
        let mut setup = block.transaction();
        seed(&mut setup, &policy, &owner, 1_000, 0, START);
        setup.apply();
        test(block, policy, owner);
    });
}

#[test]
fn original_idle_sweep_keeps_bounded_month_prefix_and_fair_native_share() {
    let mut now = START;
    for _ in 0..24 {
        now = honiara_month_bounds(now).unwrap().1;
    }
    fixture_block(now + 1_000, |block, policy| {
        let owners: Vec<_> = (2..=9).map(account).collect();
        let mut setup = block.transaction();
        for owner in &owners {
            seed(&mut setup, &policy, owner, 10_000, 0, START);
        }
        setup.apply();
        let ordinary = block.fastpq_source_usage_for_testing();
        process_idle_accounts(block).unwrap();
        let mut count = 0;
        let mut visited = Vec::new();
        for owner in &owners {
            let rows = receipts(&block.world, owner, None, 100).unwrap();
            assert!(rows.len() <= 12, "original per-wallet twelve-month bound");
            if !rows.is_empty() {
                visited.push((
                    format!(
                        "retail_fee_v1/{}",
                        hex::encode(Hash::new(owner.to_string().as_bytes()).as_ref())
                    )
                    .parse::<StatePath>()
                    .unwrap(),
                    rows.len(),
                ));
            }
            count += rows.len();
            let record = account_state(&block.world, owner).unwrap().unwrap();
            assert_eq!(
                record.balance_minor,
                10_000 - u64::try_from(rows.len()).unwrap() * 100
            );
            assert!(
                record.billing_month_start_ms < now,
                "unsettled months never fast-forward"
            );
            assert!(
                rows.iter()
                    .all(|receipt| receipt.collected_minor == 100 && receipt.waived_minor == 0)
            );
        }
        assert_eq!(
            count, 32,
            "original native pool must admit a fair exact retail prefix"
        );
        visited.sort();
        assert_eq!(
            visited.iter().map(|(_, count)| *count).collect::<Vec<_>>(),
            vec![12, 12, 8]
        );
        let cursor: StatePath = norito::decode_from_bytes(
            block
                .world
                .smart_contract_state
                .get(
                    &"retail_fee_control_v1/sweep_cursor"
                        .parse::<StatePath>()
                        .unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            cursor,
            visited.last().unwrap().0,
            "cursor advances only through settled wallets"
        );
        let native = block.native_maintenance_usage_for_testing();
        assert_eq!(native.executed_entries, 32);
        assert_eq!((native.transcripts, native.deltas), (32, 32));
        assert_eq!(block.fastpq_source_usage_for_testing(), ordinary);
        let fragments = block.committed_fragment_count();
        process_idle_accounts(block).unwrap();
        assert_eq!(block.native_maintenance_usage_for_testing(), native);
        assert_eq!(block.committed_fragment_count(), fragments);
        assert_eq!(
            block.world.smart_contract_state.get(
                &"retail_fee_control_v1/sweep_cursor"
                    .parse::<StatePath>()
                    .unwrap()
            ),
            Some(&norito::to_bytes(&cursor).unwrap())
        );
    });
}

#[test]
fn original_one_entry_native_policy_alternates_retail_and_sns_admission() {
    let mut now = START;
    for _ in 0..3 {
        now = honiara_month_bounds(now).unwrap().1;
    }
    for height in [200_000, 200_001] {
        crate::validation_fee::tests::with_retail_native_capacity_block(
            height,
            now + 1_000,
            1,
            |block, deployer, code, hash| {
                let mut setup = block.transaction();
                let policy = install_retail_policy_fixture(&mut setup, deployer, code, hash);
                let owner = account(3);
                seed(&mut setup, &policy, &owner, 1_000, 0, START);
                setup.apply();
                process_idle_accounts(block).unwrap();
                let rows = receipts(&block.world, &owner, None, 10).unwrap();
                let expected = usize::from(height.is_multiple_of(2));
                assert_eq!(
                    rows.len(),
                    expected,
                    "one finite native slot alternates by height"
                );
                let native = block.native_maintenance_usage_for_testing();
                assert_eq!(native.executed_entries, u64::try_from(expected).unwrap());
                assert_eq!(
                    account_state(&block.world, &owner)
                        .unwrap()
                        .unwrap()
                        .balance_minor,
                    1_000 - u64::try_from(expected).unwrap() * 100
                );
                assert!(
                    account_state(&block.world, &owner)
                        .unwrap()
                        .unwrap()
                        .billing_month_end_ms
                        <= now + 1_000,
                    "next uncollected month is retained even with a one-entry policy"
                );
                process_idle_accounts(block).unwrap();
                assert_eq!(receipts(&block.world, &owner, None, 10).unwrap(), rows);
                assert_eq!(block.native_maintenance_usage_for_testing(), native);
            },
        );
    }
}

#[test]
fn original_idle_waived_receipts_keep_exact_history_without_native_entries() {
    let mut now = START;
    for _ in 0..36 {
        now = honiara_month_bounds(now).unwrap().1;
    }
    fixture_block(now, |block, policy| {
        let owner = account(3);
        let mut setup = block.transaction();
        seed(&mut setup, &policy, &owner, 0, 0, START);
        setup.apply();
        process_idle_accounts(block).unwrap();
        let rows = receipts(&block.world, &owner, None, 100).unwrap();
        assert_eq!(rows.len(), 12);
        assert!(
            rows.iter()
                .all(|row| row.collected_minor == 0 && row.waived_minor == 100)
        );
        assert_eq!(
            block.native_maintenance_usage_for_testing(),
            crate::fastpq::source_reservation::SourceUsage::ZERO
        );
        let record = account_state(&block.world, &owner).unwrap().unwrap();
        assert_eq!(record.balance_minor, 0);
        assert!(record.billing_month_start_ms < now);
        // The receipt page is ordered by hash; the wallet journal owns chronology.
        let sequence = receipt_sequence(&block.world, &owner, 0, 100).unwrap();
        assert_eq!(sequence.len(), rows.len());
        let mut page = sequence.clone();
        page.sort_by_key(|receipt| receipt.receipt_id);
        assert_eq!(page, rows);
        let mut boundary = honiara_month_bounds(START).unwrap().0;
        for (index, receipt) in sequence.iter().enumerate() {
            assert_eq!(receipt.sequence, u64::try_from(index).unwrap() + 1);
            assert_eq!(receipt.billing_month_start_ms, boundary);
            boundary = honiara_month_bounds(boundary).unwrap().1;
            assert_eq!(receipt.effective_at_ms, Some(boundary));
        }
        assert_eq!(record.billing_month_start_ms, boundary);
        assert_eq!(
            record.billing_month_start_ms,
            sequence.last().unwrap().effective_at_ms.unwrap()
        );
    });
}

fn seed_due_native_renewals(
    transaction: &mut StateTransaction<'_, '_>,
    now: u64,
    count: usize,
) -> Vec<(
    StatePath,
    iroha_data_model::alias_setup::AliasAutoRenewStateV1,
)> {
    use iroha_data_model::{
        alias_setup::{
            AliasAutoRenewConfigV1, AliasAutoRenewStateV1, AliasTargetV1, ResolvedDomainV1,
        },
        sns::{DOMAIN_NAME_SUFFIX_ID, NameControllerV1, NameRecordV1},
    };
    let owner = account(13);
    let collector = account(14);
    let mut policy = crate::sns::policy_by_id(&transaction.world, DOMAIN_NAME_SUFFIX_ID)
        .unwrap()
        .unwrap();
    let asset = iroha_data_model::sns::pricing::payment_asset_definition_id(&policy).unwrap();
    policy.fund_splitter_account = collector;
    transaction.world.smart_contract_state.insert(
        crate::sns::policy_storage_key(DOMAIN_NAME_SUFFIX_ID),
        norito::codec::Encode::encode(&policy),
    );
    assert_eq!(
        crate::sns::policy_by_id(&transaction.world, DOMAIN_NAME_SUFFIX_ID)
            .expect("fixture uses the production SNS policy codec"),
        Some(policy.clone()),
        "SNS fixtures use the actual fixed-v1 bare policy storage owner"
    );
    **transaction
        .world
        .asset_or_insert_exact(
            &AssetId::new(asset.clone(), owner.clone()),
            Quantity::zero(),
        )
        .unwrap() = Quantity::from(1_000_u32);
    let mut rows = Vec::new();
    for index in 0..count {
        let domain = DomainId::try_new(format!("nativerenew{index}"), "universal").unwrap();
        transaction
            .world
            .domains
            .insert(domain.clone(), Domain::new(domain.clone()).build(&owner));
        let selector = crate::sns::selector_for_domain(&domain).unwrap();
        let expiry = now + 86_400_000;
        let record = NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![NameControllerV1::account(
                &AccountAddress::from_account_id(&owner).unwrap(),
            )],
            0,
            now - 86_400_000,
            expiry,
            expiry + 30 * 86_400_000,
            expiry + 90 * 86_400_000,
            Metadata::default(),
        );
        transaction.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
        assert_eq!(
            crate::sns::record_by_selector(&transaction.world, &selector)
                .expect("fixture uses the production SNS record codec"),
            Some(record.clone())
        );
        assert_eq!(
            crate::sns::get_name_record_by_selector(&transaction.world, &selector, now).unwrap(),
            record,
            "SNS fixtures must be readable by the original renewal record owner"
        );
        let target = AliasTargetV1::Domain(ResolvedDomainV1::new(
            domain,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        ));
        let renewal = AliasAutoRenewStateV1::new(
            target,
            owner.clone(),
            1,
            Some(AliasAutoRenewConfigV1 {
                term_years: 1,
                policy_version: policy.policy_version,
                payment_asset: asset.clone(),
                max_amount: Quantity::one(),
                renew_before_expiry_ms: 86_400_000,
                retry_backoff_ms: 100,
                max_failures: 3,
            }),
        );
        let key = crate::sns::alias_auto_renew_storage_key(&renewal.target).unwrap();
        crate::sns::persist_alias_auto_renew_state(transaction, &renewal).unwrap();
        rows.push((key, renewal));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

#[test]
fn original_time_sns_sweep_uses_only_capacity_left_by_exact_retail_prefix() {
    use iroha_data_model::block::{BlockHeader, builder::BlockBuilder};
    let mut now = START;
    for _ in 0..24 {
        now = honiara_month_bounds(now).unwrap().1;
    }
    now += 1_000;
    // The fixture's Parliament fee and payout policies must already be active.
    // Preserve both height parities when the native pool has only one entry.
    for (total, height, retail_count, sns_count) in [
        (64_u32, 200_000, 32_usize, 32_usize),
        (1, 200_000, 1, 0),
        (1, 200_001, 0, 1),
    ] {
        crate::validation_fee::tests::with_retail_native_capacity_state(
            total,
            |state, deployer, code, hash| {
                let header = BlockHeader::new(
                    std::num::NonZeroU64::new(height).unwrap(),
                    state.view().latest_block_hash(),
                    None,
                    now,
                    0,
                );
                let source = BlockBuilder::new(header)
                    .build_with_signature(0, iroha_test_samples::ALICE_KEYPAIR.private_key());
                let (mut block, _recording) =
                    crate::block::ValidBlock::start_component_execution(&source, state).unwrap();
                let policy;
                let renewal_rows;
                {
                    let mut setup = block.transaction();
                    policy = install_retail_policy_fixture(&mut setup, deployer, code, hash);
                    assert_eq!(
                        policy_at(&setup.world, height, now).unwrap(),
                        Some(policy.clone()),
                        "retail collection starts after the exact fee-policy activation"
                    );
                    let payout =
                        crate::validation_fee::active_payout_binding_at_height(&setup, height)
                            .unwrap()
                            .expect("retail collection requires its finalized payout policy");
                    assert_eq!(payout.custody(), policy.reward_custody);
                    for owner in (2..=9).map(account) {
                        seed(&mut setup, &policy, &owner, 10_000, 0, START);
                    }
                    renewal_rows = seed_due_native_renewals(
                        &mut setup,
                        now,
                        usize::try_from(total).unwrap() + 1,
                    );
                    setup.apply();
                }
                assert_eq!(
                    block
                        .native_maintenance_usage_for_testing()
                        .executed_entries,
                    0
                );
                process_idle_accounts(&mut block).unwrap();
                assert_eq!(
                    block
                        .native_maintenance_usage_for_testing()
                        .executed_entries,
                    u64::try_from(retail_count).unwrap()
                );
                let retail_receipts: usize = (2..=9)
                    .map(account)
                    .map(|owner| receipts(&block.world, &owner, None, 100).unwrap().len())
                    .sum();
                assert_eq!(retail_receipts, retail_count);
                let cursor_key: StatePath = "sns/auto_renew_cursor/v1".parse().unwrap();
                let cursor_before = block.world.smart_contract_state.get(&cursor_key).cloned();
                let witness_before =
                    crate::exec_witness::snapshot_exec_witness().fastpq_transcripts;
                block.reserve_ordinary_execution_outputs(&source).unwrap();
                block.execute_ordinary_output_plan(&source, None).unwrap();
                for (index, (_, original)) in renewal_rows.iter().enumerate() {
                    let current =
                        crate::sns::alias_auto_renew_state(&block.world, &original.target)
                            .unwrap()
                            .unwrap();
                    if index < sns_count {
                        assert_eq!(current.revision, original.revision + 1);
                        assert_eq!(current.failure_count, 0);
                        assert_eq!(current.next_retry_at_ms, None);
                        assert_eq!(current.suspended_reason, None);
                    } else {
                        assert_eq!(
                            current, *original,
                            "native capacity deferral must preserve the exact unselected renewal"
                        );
                    }
                }
                assert_eq!(
                    block
                        .native_maintenance_usage_for_testing()
                        .executed_entries,
                    u64::from(total)
                );
                let witness_after = crate::exec_witness::snapshot_exec_witness().fastpq_transcripts;
                assert_eq!(witness_after.len(), retail_count + sns_count);
                if sns_count == 0 {
                    assert_eq!(
                        block.world.smart_contract_state.get(&cursor_key),
                        cursor_before.as_ref()
                    );
                    assert_eq!(
                        witness_after, witness_before,
                        "zero SNS capacity cannot publish a renewal witness"
                    );
                } else {
                    assert_eq!(
                        crate::sns::alias_auto_renew_cursor_for_testing(&block.world)
                            .unwrap()
                            .as_ref(),
                        Some(&renewal_rows[sns_count - 1].0)
                    );
                }
                let sns_asset = iroha_data_model::sns::pricing::payment_asset_definition_id(
                    &crate::sns::policy_by_id(
                        &block.world,
                        iroha_data_model::sns::DOMAIN_NAME_SUFFIX_ID,
                    )
                    .unwrap()
                    .unwrap(),
                )
                .unwrap();
                let remaining_minor = 100_000 - u64::try_from(sns_count).unwrap() * 50;
                assert_eq!(
                    block
                        .world
                        .assets
                        .get(&AssetId::new(sns_asset, account(13)))
                        .unwrap()
                        .as_ref(),
                    &format!("{}.{:02}", remaining_minor / 100, remaining_minor % 100)
                        .parse::<Quantity>()
                        .unwrap()
                );
            },
        );
    }
}

fn privacy_fee_test_owner() -> crate::privacy_state::PrivacyPublicReserveOwnerV1 {
    use iroha_data_model::privacy::*;
    crate::privacy_state::PrivacyPublicReserveOwnerV1::Orchard {
        namespace: PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
            PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
                pool_id: PrivacyPoolIdV1::new([0xD1; 32]),
            }),
        ),
        bootstrap_digest: PrivacyOrchardPoolBootstrapDigestV1::new([0xD2; 32]),
    }
}

#[test]
fn enrolled_privacy_reserve_maintenance_preserves_backing_and_ordinary_fee_collection() {
    use crate::privacy_state::{PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1};
    for protected in [false, true] {
        fixture(START + 30 * 86_400_000, |stx, policy| {
            let wallet = account(3);
            seed(stx, &policy, &wallet, 1000, 0, START);
            let id = AssetId::new(policy.ds_asset_id.clone(), wallet.clone());
            let owner = privacy_fee_test_owner();
            let key =
                PrivacyCommitmentKeyV1::public_reserve_custody(owner.protocol_id(), &id).unwrap();
            if protected {
                stx.world.privacy_commitments.insert(
                    key.clone(),
                    PrivacyStateItemRecordV1::PublicReserveCustody {
                        reserve_asset_id: id.clone(),
                        owner,
                        funded_allowance: Quantity::from(10_u32),
                    },
                );
            }
            let original_custody = stx.world.privacy_commitments.get(&key).cloned();
            let expected = Quantity::from(if protected { 10_u32 } else { 9_u32 });
            assert_eq!(
                projected_balance(&stx.world, &id, START + 30 * 86_400_000).unwrap(),
                Some(expected.clone())
            );
            settle_balance(&mut stx.world, &id).unwrap();
            finalize(stx).unwrap();
            assert_eq!(stx.world.assets.get(&id).unwrap().as_ref(), &expected);
            assert_eq!(
                stx.world.privacy_commitments.get(&key),
                original_custody.as_ref()
            );
            let receipt = receipts(&stx.world, &wallet, None, 10).unwrap().remove(0);
            assert_eq!(receipt.collected_minor, if protected { 0 } else { 100 });
            assert_eq!(
                stx.retail_fee_transcripts_for_test().len(),
                usize::from(!protected)
            );
        });
    }
}

#[test]
fn malformed_exact_reserve_custody_refuses_fees_but_unrelated_rows_do_not() {
    use crate::privacy_state::{PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1};
    fixture(START + 30 * 86_400_000, |stx, policy| {
        let wallet = account(3);
        seed(stx, &policy, &wallet, 1000, 0, START);
        let id = AssetId::new(policy.ds_asset_id.clone(), wallet.clone());
        let owner = privacy_fee_test_owner();
        let key = PrivacyCommitmentKeyV1::public_reserve_custody(owner.protocol_id(), &id).unwrap();
        let wrong = AssetId::new(policy.ds_asset_id.clone(), account(4));
        let malformed =
            PrivacyStateItemRecordV1::public_reserve_custody(wrong.clone(), owner).unwrap();
        stx.world
            .privacy_commitments
            .insert(key.clone(), malformed.clone());
        let before = stx
            .world
            .smart_contract_state
            .iter()
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert!(matches!(
            projected_balance(&stx.world, &id, START + 30 * 86_400_000),
            Err(crate::execution_attempt::ExecutionAttemptError::Rejected(_))
        ));
        assert!(settle_balance(&mut stx.world, &id).is_err());
        assert_eq!(
            stx.world
                .smart_contract_state
                .iter()
                .map(|(path, bytes)| (path.clone(), bytes.clone()))
                .collect::<std::collections::BTreeMap<_, _>>(),
            before
        );
        assert_eq!(
            stx.world.assets.get(&id).unwrap().as_ref(),
            &Quantity::from(10_u32)
        );
        assert_eq!(stx.world.privacy_commitments.get(&key), Some(&malformed));
        assert!(stx.retail_fee_transcripts_for_test().is_empty());
        stx.world.privacy_commitments.remove(key);
        // Malformed under another exact identity: no global scan or fee exemption.
        let unrelated_key =
            PrivacyCommitmentKeyV1::public_reserve_custody(owner.protocol_id(), &wrong).unwrap();
        stx.world.privacy_commitments.insert(
            unrelated_key,
            PrivacyStateItemRecordV1::public_reserve_custody(id.clone(), owner).unwrap(),
        );
        settle_balance(&mut stx.world, &id).unwrap();
        assert_eq!(
            stx.world.assets.get(&id).unwrap().as_ref(),
            &Quantity::from(9_u32)
        );
    });
}

#[test]
fn payment_fee_rechecks_reserve_custody_installed_after_principal() {
    use crate::privacy_state::{PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1};
    for malformed in [false, true] {
        fixture(START + 1000, |stx, policy| {
            let wallet = account(3);
            seed(stx, &policy, &wallet, 1000, 50, START);
            let req = request(&policy, &wallet, 1);
            let assessment = reviewed(stx, &req, 0xD3);
            assert_eq!(assessment.fee_minor, 10);
            pay(stx, &req);
            // This accessor includes the already executed principal occurrence.
            // A refused fee must preserve it exactly and queue no collection.
            let principal_transcripts = stx.retail_fee_transcripts_for_test().to_vec();
            assert_eq!(principal_transcripts.len(), 1);
            assert_eq!(principal_transcripts[0].deltas.len(), 1);
            assert_eq!(principal_transcripts[0].deltas[0].from_account, wallet);
            assert_eq!(principal_transcripts[0].deltas[0].to_account, account(4));
            assert_eq!(
                principal_transcripts[0].deltas[0].amount,
                Quantity::from(1_u32)
            );
            assert!(stx.world.retail_fee_pending_transcripts.is_empty());
            let id = AssetId::new(policy.ds_asset_id.clone(), wallet.clone());
            assert_eq!(
                stx.world.assets.get(&id).unwrap().as_ref(),
                &Quantity::from(9_u32)
            );
            let owner = privacy_fee_test_owner();
            let key =
                PrivacyCommitmentKeyV1::public_reserve_custody(owner.protocol_id(), &id).unwrap();
            let bound_id = if malformed {
                AssetId::new(policy.ds_asset_id.clone(), account(4))
            } else {
                id.clone()
            };
            let custody =
                PrivacyStateItemRecordV1::public_reserve_custody(bound_id, owner).unwrap();
            stx.world
                .privacy_commitments
                .insert(key.clone(), custody.clone());
            let treasury = AssetId::new(
                policy.ds_asset_id.clone(),
                policy.treasury_account_id.clone(),
            );
            let treasury_before = stx.world.assets.get(&treasury).cloned();
            let before = stx
                .world
                .smart_contract_state
                .iter()
                .map(|(path, bytes)| (path.clone(), bytes.clone()))
                .collect::<std::collections::BTreeMap<_, _>>();
            let error = finalize(stx)
                .expect_err("late custody must reject the complete payment, never waive its fee");
            let TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message)) =
                error
            else {
                panic!("late custody must preserve its original typed refusal: {error:?}");
            };
            if malformed {
                assert_eq!(
                    message,
                    format!("public-reserve custody digest collision or owner mismatch for {id}")
                );
            } else {
                assert_eq!(
                    message,
                    "payment fee cannot debit governed privacy reserve custody"
                );
            }
            assert_eq!(
                stx.world.assets.get(&id).unwrap().as_ref(),
                &Quantity::from(9_u32)
            );
            assert_eq!(stx.world.assets.get(&treasury), treasury_before.as_ref());
            assert_eq!(stx.world.privacy_commitments.get(&key), Some(&custody));
            assert_eq!(
                stx.world
                    .smart_contract_state
                    .iter()
                    .map(|(path, bytes)| (path.clone(), bytes.clone()))
                    .collect::<std::collections::BTreeMap<_, _>>(),
                before
            );
            assert_eq!(stx.retail_fee_transcripts_for_test(), principal_transcripts);
            assert!(stx.world.retail_fee_pending_transcripts.is_empty());
            // This failed disposable transaction is intentionally never applied.
        });
    }
}

#[test]
fn native_idle_sweep_preserves_enrolled_privacy_reserve_and_fee_evidence() {
    use crate::privacy_state::{PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1};
    fixture_block(START + 30 * 86_400_000, |block, policy| {
        let wallet = account(3);
        let id = AssetId::new(policy.ds_asset_id.clone(), wallet.clone());
        let owner = privacy_fee_test_owner();
        let key = PrivacyCommitmentKeyV1::public_reserve_custody(owner.protocol_id(), &id).unwrap();
        let custody = PrivacyStateItemRecordV1::PublicReserveCustody {
            reserve_asset_id: id.clone(),
            owner,
            funded_allowance: Quantity::from(10_u32),
        };
        {
            let mut setup = block.transaction();
            seed(&mut setup, &policy, &wallet, 1000, 0, START);
            setup
                .world
                .privacy_commitments
                .insert(key.clone(), custody.clone());
            setup.apply();
        }
        let native_before = block.native_maintenance_usage_for_testing();
        process_idle_accounts(block).unwrap();
        let rows = receipts(&block.world, &wallet, None, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].collected_minor, rows[0].waived_minor), (0, 100));
        assert_eq!(
            block.world.assets.get(&id).unwrap().as_ref(),
            &Quantity::from(10_u32)
        );
        assert_eq!(block.world.privacy_commitments.get(&key), Some(&custody));
        assert_eq!(
            account_state(&block.world, &wallet)
                .unwrap()
                .unwrap()
                .balance_minor,
            1000
        );
        assert_eq!(block.native_maintenance_usage_for_testing(), native_before);
        process_idle_accounts(block).unwrap();
        assert_eq!(receipts(&block.world, &wallet, None, 10).unwrap(), rows);
        assert_eq!(block.native_maintenance_usage_for_testing(), native_before);
    });
}
