// Focused first-release privacy public-reserve custody guards.
use crate::privacy_state::PrivacyPublicReserveOwnerV1;
use crate::smartcontracts::isi::asset::isi::{
    execute_verified_privacy_pool_public_balance_transfer,
    execute_verified_privacy_public_balance_transfer,
};
use iroha_data_model::privacy::{PrivacyStatementDigestV1, PrivacyValueBalanceDirectionV1};

fn seed_test_orchard_public_reserve(
    state_transaction: &mut StateTransaction<'_, '_>,
    reserve_asset_id: &AssetId,
) -> PrivacyPublicReserveOwnerV1 {
    use iroha_data_model::privacy::{
        PrivacyNamespaceScopeV1, PrivacyNamespaceV1, PrivacyOrchardPoolBootstrapDigestV1,
        PrivacyPoolIdV1, PrivacyPoolNamespaceV1, PrivacyProtocolIdV1,
    };

    let owner = PrivacyPublicReserveOwnerV1::Orchard {
        namespace: PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
            PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
                pool_id: PrivacyPoolIdV1::new([0xD1; 32]),
            }),
        ),
        bootstrap_digest: PrivacyOrchardPoolBootstrapDigestV1::new([0xD2; 32]),
    };
    state_transaction.world.privacy_commitments.insert(
        crate::privacy_state::PrivacyCommitmentKeyV1::public_reserve_custody(
            owner.protocol_id(),
            reserve_asset_id,
        )
        .expect("reserve custody key"),
        crate::privacy_state::PrivacyStateItemRecordV1::public_reserve_custody(
            reserve_asset_id.clone(),
            owner,
        )
        .expect("reserve custody row"),
    );
    owner
}

#[test]
fn privacy_public_reserve_refuses_owner_delegate_general_bridge_and_burn() {
    let (state, definition_id, reserve_asset_id) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(definition_id.clone(), BOB_ID.clone());
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    block.admit_fastpq_source_for_testing(Hash::prehashed([0xD1; Hash::LENGTH]));
    let mut transaction = block.transaction();
    seed_test_call_hash(&mut transaction, 0xD1);
    seed_test_orchard_public_reserve(&mut transaction, &reserve_asset_id);
    transaction.world.add_account_permission(
        &BOB_ID,
        Permission::from(
            iroha_executor_data_model::permission::asset::CanTransferAsset {
                asset: reserve_asset_id.clone(),
            },
        ),
    );
    let original_events = transaction.world.internal_event_buf.len();
    for authority in [ALICE_ID.clone(), BOB_ID.clone()] {
        let error = execute_user_numeric_asset_transfer(
            &mut transaction,
            &authority,
            reserve_asset_id.clone(),
            BOB_ID.clone(),
            Quantity::one(),
        )
        .expect_err("reserve owner and exact delegate cannot use ordinary transfer");
        assert!(
            error.to_string().contains("exact verified pool bridge"),
            "unexpected reserve-transfer error for {authority}: {error}"
        );
    }
    let error = execute_verified_privacy_public_balance_transfer(
        &mut transaction,
        &BOB_ID,
        PrivacyStatementDigestV1::new([0xD3; 32]),
        &definition_id,
        iroha_data_model::asset::AssetBalanceScope::Global,
        &ALICE_ID,
        &BOB_ID,
        Quantity::one(),
    )
    .expect_err("the general ZK-ACE bridge cannot debit a typed pool reserve");
    assert!(error.to_string().contains("exact verified pool bridge"));
    let error = Burn::asset_quantity(1_u32, reserve_asset_id.clone())
        .execute(&ALICE_ID, &mut transaction)
        .expect_err("reserve owner cannot burn pool backing");
    assert!(error.to_string().contains("cannot be burned"));
    assert_eq!(
        asset_balance_or_zero(&transaction, &reserve_asset_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &destination_asset_id),
        Quantity::zero()
    );
    assert_eq!(transaction.world.internal_event_buf.len(), original_events);
    let (unregistered, _) = iroha_test_samples::gen_account_in("wonderland");
    assert!(transaction.world.accounts.get(&unregistered).is_none());
    let error = execute_user_numeric_asset_transfer(
        &mut transaction,
        &ALICE_ID,
        reserve_asset_id.clone(),
        unregistered.clone(),
        Quantity::one(),
    )
    .expect_err("reserve debit must reject before implicit recipient admission");
    assert!(error.to_string().contains("exact verified pool bridge"));
    assert!(
        transaction.world.accounts.get(&unregistered).is_none(),
        "failed reserve debit must not create the proposed receiving account"
    );
}
#[test]
fn privacy_reserve_rejection_is_leg_local_in_independent_batch() {
    let (state, definition_id, reserve_asset_id) = build_asset_transfer_control_test_state(10);
    let bob_asset_id = AssetId::new(definition_id.clone(), BOB_ID.clone());
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    block.admit_fastpq_source_for_testing(Hash::prehashed([0xD7; Hash::LENGTH]));
    let mut transaction = block.transaction();
    seed_test_call_hash(&mut transaction, 0xD7);
    seed_test_orchard_public_reserve(&mut transaction, &reserve_asset_id);
    Mint::asset_quantity(3_u32, bob_asset_id.clone())
        .execute(&ALICE_ID, &mut transaction)
        .expect("fund independent sibling source");
    transaction.world.add_account_permission(
        &BOB_ID,
        Permission::from(
            iroha_executor_data_model::permission::asset::CanTransferAsset {
                asset: reserve_asset_id.clone(),
            },
        ),
    );
    TransferAssetBatch::independent(vec![
        TransferAssetBatchEntry::with_leg_id(
            "protected-reserve",
            ALICE_ID.clone(),
            BOB_ID.clone(),
            definition_id.clone(),
            1_u32,
        ),
        TransferAssetBatchEntry::with_leg_id(
            "ordinary-sibling",
            BOB_ID.clone(),
            ALICE_ID.clone(),
            definition_id,
            2_u32,
        ),
    ])
    .execute(&BOB_ID, &mut transaction)
    .expect("independent batch records the denied reserve leg and applies its sibling");
    assert_eq!(
        asset_balance_or_zero(&transaction, &reserve_asset_id),
        Quantity::from(12_u32),
        "reserve has only the accepted sibling's incoming units"
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &bob_asset_id),
        Quantity::one(),
        "rejected reserve leg did not credit its destination"
    );
}
#[test]
fn privacy_pool_bridge_requires_exact_owner_and_direction_before_reserve_debit() {
    let (state, definition_id, reserve_asset_id) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(definition_id.clone(), BOB_ID.clone());
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    block.admit_fastpq_source_for_testing(Hash::prehashed([0xD4; Hash::LENGTH]));
    let mut transaction = block.transaction();
    seed_test_call_hash(&mut transaction, 0xD4);
    execute_user_numeric_asset_transfer(
        &mut transaction,
        &ALICE_ID,
        reserve_asset_id.clone(),
        BOB_ID.clone(),
        Quantity::from(10_u32),
    )
    .unwrap();
    let owner = seed_test_orchard_public_reserve(&mut transaction, &reserve_asset_id);
    execute_verified_privacy_pool_public_balance_transfer(
        &mut transaction,
        &BOB_ID,
        PrivacyStatementDigestV1::new([0xEE; 32]),
        owner,
        &definition_id,
        iroha_data_model::asset::AssetBalanceScope::Global,
        &ALICE_ID,
        PrivacyValueBalanceDirectionV1::IntoPool,
        Quantity::from(10_u32),
    )
    .unwrap();
    let forged_owner = match owner {
        PrivacyPublicReserveOwnerV1::Orchard { namespace, .. } => {
            PrivacyPublicReserveOwnerV1::Orchard {
                namespace,
                bootstrap_digest:
                    iroha_data_model::privacy::PrivacyOrchardPoolBootstrapDigestV1::new([0xD5; 32]),
            }
        }
        _ => unreachable!("test seeds Orchard owner"),
    };
    let digest = PrivacyStatementDigestV1::new([0xD6; 32]);
    let scope = iroha_data_model::asset::AssetBalanceScope::Global;
    let error = execute_verified_privacy_pool_public_balance_transfer(
        &mut transaction,
        &BOB_ID,
        digest,
        forged_owner,
        &definition_id,
        scope,
        &ALICE_ID,
        PrivacyValueBalanceDirectionV1::OutOfPool,
        Quantity::one(),
    )
    .expect_err("forged bootstrap cannot use the reserve bridge");
    assert!(
        error
            .to_string()
            .contains("does not match governed reserve custody")
    );
    let error = execute_verified_privacy_pool_public_balance_transfer(
        &mut transaction,
        &BOB_ID,
        digest,
        owner,
        &definition_id,
        scope,
        &ALICE_ID,
        PrivacyValueBalanceDirectionV1::Balanced,
        Quantity::one(),
    )
    .expect_err("balanced effect has no public debit");
    assert!(error.to_string().contains("no public-reserve transfer"));
    assert_eq!(
        asset_balance_or_zero(&transaction, &reserve_asset_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &destination_asset_id),
        Quantity::zero()
    );
    execute_verified_privacy_pool_public_balance_transfer(
        &mut transaction,
        &BOB_ID,
        digest,
        owner,
        &definition_id,
        scope,
        &ALICE_ID,
        PrivacyValueBalanceDirectionV1::OutOfPool,
        Quantity::one(),
    )
    .expect("the exact typed post-verification pool bridge may debit its reserve");
    assert_eq!(
        asset_balance_or_zero(&transaction, &reserve_asset_id),
        Quantity::from(9_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &destination_asset_id),
        Quantity::one()
    );
}
