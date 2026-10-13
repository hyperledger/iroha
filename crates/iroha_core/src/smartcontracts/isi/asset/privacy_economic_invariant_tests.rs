// Verifier-fault mutation tests for the public legs of private pools
// (specs/zk_economic_invariants.json, ZK delivery plan task F.3).
//
// A proof verifier that accepts every proof hands the ledger an arbitrary
// "verified" public leg. The harness below builds exactly such a leg and
// applies it through the post-verification entry points the proof handler
// uses. Each test therefore shows what the ledger still refuses, and what
// stays exposed, when verification succeeds wrongly. The harness is compiled
// for tests only: no node path, configuration value or feature reaches it.
//
// What these tests do not show: that a proof relation is sound, or that value
// hidden inside a pool is conserved. A reserve balance bounds what can leave a
// pool; it does not prove what is inside it.
use super::*;
use crate::privacy_state::{
    PrivacyCommitmentKeyV1, PrivacyPublicReserveOwnerV1, PrivacyStateItemRecordV1,
};
use crate::smartcontracts::isi::asset::isi::{
    execute_verified_privacy_pool_public_balance_transfer,
    execute_verified_privacy_public_balance_transfer,
};
use iroha_data_model::asset::AssetBalanceScope;
use iroha_data_model::privacy::{
    PrivacyNamespaceScopeV1, PrivacyNamespaceV1, PrivacyOrchardPoolBootstrapDigestV1,
    PrivacyPoolIdV1, PrivacyPoolNamespaceV1, PrivacyPoolProgramNamespaceV1, PrivacyProgramIdV1,
    PrivacyProofManagedPoolBootstrapDigestV1, PrivacyProtocolIdV1, PrivacyStatementDigestV1,
    PrivacyValueBalanceDirectionV1,
};

/// Public leg of a pool effect exactly as a verifier that accepts every proof returns it.
struct FaultyVerifierPoolEffect<'a> {
    owner: PrivacyPublicReserveOwnerV1,
    definition: &'a AssetDefinitionId,
    scope: AssetBalanceScope,
    reserve_account: &'a AccountId,
    direction: PrivacyValueBalanceDirectionV1,
    amount: u32,
    statement: u8,
}

/// Apply a wrongly verified pool effect through the post-verification bridge.
///
/// This is the call the proof handler makes after `verify_privacy_envelope_v1`
/// returned success; no proof is checked here, which is the fault under test.
fn apply_faulty_verifier_pool_effect(
    transaction: &mut StateTransaction<'_, '_>,
    submitter: &AccountId,
    effect: &FaultyVerifierPoolEffect<'_>,
) -> Result<(), iroha_data_model::isi::error::InstructionExecutionError> {
    execute_verified_privacy_pool_public_balance_transfer(
        transaction,
        submitter,
        PrivacyStatementDigestV1::new([effect.statement; 32]),
        effect.owner,
        effect.definition,
        effect.scope,
        effect.reserve_account,
        effect.direction,
        Quantity::from(effect.amount),
    )
}

fn economic_orchard_owner(pool: u8) -> PrivacyPublicReserveOwnerV1 {
    PrivacyPublicReserveOwnerV1::Orchard {
        namespace: PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
            PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
                pool_id: PrivacyPoolIdV1::new([pool; 32]),
            }),
        ),
        bootstrap_digest: PrivacyOrchardPoolBootstrapDigestV1::new([pool ^ 0x0F; 32]),
    }
}

fn economic_private_ivm_owner(pool: u8) -> PrivacyPublicReserveOwnerV1 {
    PrivacyPublicReserveOwnerV1::PrivateIvm {
        namespace: PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            PrivacyNamespaceScopeV1::PoolProgram(PrivacyPoolProgramNamespaceV1 {
                pool_id: PrivacyPoolIdV1::new([pool; 32]),
                program_id: PrivacyProgramIdV1::new([pool ^ 0xF0; 32]),
            }),
        ),
        bootstrap_digest: PrivacyProofManagedPoolBootstrapDigestV1::new([pool ^ 0x0F; 32]),
    }
}

fn economic_seed_reserve_custody(
    transaction: &mut StateTransaction<'_, '_>,
    reserve_asset_id: &AssetId,
    owner: PrivacyPublicReserveOwnerV1,
) {
    transaction.world.privacy_commitments.insert(
        PrivacyCommitmentKeyV1::public_reserve_custody(owner.protocol_id(), reserve_asset_id)
            .expect("reserve custody key"),
        PrivacyStateItemRecordV1::public_reserve_custody(reserve_asset_id.clone(), owner)
            .expect("reserve custody row"),
    );
}

/// Sum of every transparent balance of `definition`, read from the balances themselves.
fn economic_transparent_units(
    transaction: &StateTransaction<'_, '_>,
    definition: &AssetDefinitionId,
    holders: &[&AccountId],
) -> Quantity {
    holders.iter().fold(Quantity::zero(), |total, holder| {
        total
            .checked_add(&asset_balance_or_zero(
                transaction,
                &AssetId::new(definition.clone(), (*holder).clone()),
            ))
            .expect("fixture balances fit one quantity")
    })
}

/// A wrongly verified withdrawal of one unit from the named reserve.
fn economic_withdrawal_of_one<'a>(
    owner: PrivacyPublicReserveOwnerV1,
    definition: &'a AssetDefinitionId,
    scope: AssetBalanceScope,
    reserve_account: &'a AccountId,
    statement: u8,
) -> FaultyVerifierPoolEffect<'a> {
    FaultyVerifierPoolEffect {
        owner,
        definition,
        scope,
        reserve_account,
        direction: PrivacyValueBalanceDirectionV1::OutOfPool,
        amount: 1,
        statement,
    }
}

fn economic_owners() -> [PrivacyPublicReserveOwnerV1; 2] {
    [
        economic_orchard_owner(0xA1),
        economic_private_ivm_owner(0xA2),
    ]
}

#[test]
fn faulty_verifier_pool_withdrawal_is_bounded_by_the_reserve_balance() {
    for (index, owner) in economic_owners().into_iter().enumerate() {
        let seed = 0xB0 + u8::try_from(index).expect("two owners");
        let (state, definition, reserve_asset_id) = build_asset_transfer_control_test_state(10);
        let attacker_asset_id = AssetId::new(definition.clone(), BOB_ID.clone());
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut transaction =
            block.transaction_for_fastpq_testing(Hash::prehashed([seed; Hash::LENGTH]));
        economic_seed_reserve_custody(&mut transaction, &reserve_asset_id, owner);
        let holders = [&*ALICE_ID, &*BOB_ID];
        let supply = economic_transparent_units(&transaction, &definition, &holders);
        let withdrawal = |amount: u32, statement: u8| FaultyVerifierPoolEffect {
            owner,
            definition: &definition,
            scope: AssetBalanceScope::Global,
            reserve_account: &ALICE_ID,
            direction: PrivacyValueBalanceDirectionV1::OutOfPool,
            amount,
            statement,
        };

        // An inflated hidden balance cannot withdraw more than the reserve holds.
        apply_faulty_verifier_pool_effect(&mut transaction, &BOB_ID, &withdrawal(11, 1))
            .expect_err("a withdrawal above the reserve balance must be refused");
        assert_eq!(
            asset_balance_or_zero(&transaction, &reserve_asset_id),
            Quantity::from(10_u32),
            "{owner:?}: a refused withdrawal left the reserve unchanged"
        );
        assert_eq!(
            asset_balance_or_zero(&transaction, &attacker_asset_id),
            Quantity::zero(),
            "{owner:?}: a refused withdrawal credited nothing"
        );

        // The remaining exposure is the whole reserve of this one pool: the ledger pays it out.
        apply_faulty_verifier_pool_effect(&mut transaction, &BOB_ID, &withdrawal(10, 2))
            .expect("the ledger cannot tell a wrongly verified withdrawal within the reserve");
        assert_eq!(
            asset_balance_or_zero(&transaction, &reserve_asset_id),
            Quantity::zero(),
            "{owner:?}: the reserve was debited by exactly the withdrawn amount"
        );
        assert_eq!(
            asset_balance_or_zero(&transaction, &attacker_asset_id),
            Quantity::from(10_u32),
            "{owner:?}: the credit equals the reserve debit"
        );

        // An empty reserve pays nothing further and is never driven below zero.
        apply_faulty_verifier_pool_effect(&mut transaction, &BOB_ID, &withdrawal(1, 3))
            .expect_err("an empty reserve cannot be overdrawn");
        assert_eq!(
            asset_balance_or_zero(&transaction, &attacker_asset_id),
            Quantity::from(10_u32)
        );
        assert_eq!(
            economic_transparent_units(&transaction, &definition, &holders),
            supply,
            "{owner:?}: wrongly verified withdrawals moved existing units and minted none"
        );
    }
}

#[test]
fn faulty_verifier_pool_effect_cannot_reach_another_pool_asset_scope_or_account() {
    let (state, definition, reserve_asset_id) = build_asset_transfer_control_test_state(10);
    let bob_asset_id = AssetId::new(definition.clone(), BOB_ID.clone());
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut transaction =
        block.transaction_for_fastpq_testing(Hash::prehashed([0xB4; Hash::LENGTH]));
    // ALICE's balance backs one Orchard pool. BOB holds ordinary units that back no pool.
    let governed = economic_orchard_owner(0xA1);
    economic_seed_reserve_custody(&mut transaction, &reserve_asset_id, governed);
    Mint::asset_quantity(4_u32, bob_asset_id.clone())
        .execute(&ALICE_ID, &mut transaction)
        .expect("fund an ordinary account");
    let other_definition = wonderland_asset_definition_id("tulip");
    let global = AssetBalanceScope::Global;
    let custody_mismatch = "does not match governed reserve custody";

    // Another pool of the same protocol, and a pool of another protocol, own no part of this reserve.
    for (statement, foreign) in [
        (1_u8, economic_orchard_owner(0xA3)),
        (2_u8, economic_private_ivm_owner(0xA1)),
    ] {
        let error = apply_faulty_verifier_pool_effect(
            &mut transaction,
            &BOB_ID,
            &economic_withdrawal_of_one(foreign, &definition, global, &ALICE_ID, statement),
        )
        .expect_err("a foreign pool cannot debit this reserve");
        assert!(
            error.to_string().contains(custody_mismatch),
            "unexpected foreign-pool rejection: {error}"
        );
    }
    // The governed owner cannot name another asset, another balance scope or an ordinary account.
    let error = apply_faulty_verifier_pool_effect(
        &mut transaction,
        &BOB_ID,
        &economic_withdrawal_of_one(governed, &other_definition, global, &ALICE_ID, 3),
    )
    .expect_err("another asset definition is not this pool's reserve");
    assert!(error.to_string().contains(custody_mismatch), "{error}");
    let error = apply_faulty_verifier_pool_effect(
        &mut transaction,
        &BOB_ID,
        &economic_withdrawal_of_one(
            governed,
            &definition,
            AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
            &ALICE_ID,
            4,
        ),
    )
    .expect_err("another balance scope is not this pool's reserve");
    assert!(error.to_string().contains(custody_mismatch), "{error}");
    let error = apply_faulty_verifier_pool_effect(
        &mut transaction,
        &ALICE_ID,
        &economic_withdrawal_of_one(governed, &definition, global, &BOB_ID, 5),
    )
    .expect_err("an ordinary account's balance is not a pool reserve");
    assert!(error.to_string().contains(custody_mismatch), "{error}");

    assert_eq!(
        asset_balance_or_zero(&transaction, &reserve_asset_id),
        Quantity::from(10_u32),
        "every refused effect left the governed reserve unchanged"
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &bob_asset_id),
        Quantity::from(4_u32),
        "every refused effect left the ordinary balance unchanged"
    );
}

#[test]
fn faulty_verifier_pool_deposit_moves_existing_units_and_never_mints() {
    for (index, owner) in economic_owners().into_iter().enumerate() {
        let seed = 0xB8 + u8::try_from(index).expect("two owners");
        let (state, definition, reserve_asset_id) = build_asset_transfer_control_test_state(10);
        let depositor_asset_id = AssetId::new(definition.clone(), BOB_ID.clone());
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut transaction =
            block.transaction_for_fastpq_testing(Hash::prehashed([seed; Hash::LENGTH]));
        economic_seed_reserve_custody(&mut transaction, &reserve_asset_id, owner);
        Mint::asset_quantity(3_u32, depositor_asset_id.clone())
            .execute(&ALICE_ID, &mut transaction)
            .expect("fund the depositor");
        let holders = [&*ALICE_ID, &*BOB_ID];
        let supply = economic_transparent_units(&transaction, &definition, &holders);
        let deposit = |amount: u32, statement: u8| FaultyVerifierPoolEffect {
            owner,
            definition: &definition,
            scope: AssetBalanceScope::Global,
            reserve_account: &ALICE_ID,
            direction: PrivacyValueBalanceDirectionV1::IntoPool,
            amount,
            statement,
        };

        // A deposit the depositor cannot fund creates no reserve units.
        apply_faulty_verifier_pool_effect(&mut transaction, &BOB_ID, &deposit(4, 1))
            .expect_err("a deposit above the depositor's balance must be refused");
        assert_eq!(
            asset_balance_or_zero(&transaction, &reserve_asset_id),
            Quantity::from(10_u32)
        );
        assert_eq!(
            asset_balance_or_zero(&transaction, &depositor_asset_id),
            Quantity::from(3_u32)
        );

        // A funded deposit debits the depositor by exactly what the reserve gains.
        apply_faulty_verifier_pool_effect(&mut transaction, &BOB_ID, &deposit(3, 2))
            .expect("a funded deposit moves existing units into the reserve");
        assert_eq!(
            asset_balance_or_zero(&transaction, &reserve_asset_id),
            Quantity::from(13_u32)
        );
        assert_eq!(
            asset_balance_or_zero(&transaction, &depositor_asset_id),
            Quantity::zero()
        );
        assert_eq!(
            economic_transparent_units(&transaction, &definition, &holders),
            supply,
            "{owner:?}: a wrongly verified deposit moved existing units and minted none"
        );

        // A balanced effect has no public leg at all.
        let balanced = FaultyVerifierPoolEffect {
            direction: PrivacyValueBalanceDirectionV1::Balanced,
            ..deposit(1, 3)
        };
        let error = apply_faulty_verifier_pool_effect(&mut transaction, &BOB_ID, &balanced)
            .expect_err("a balanced effect moves no public value");
        assert!(
            error.to_string().contains("no public-reserve transfer"),
            "unexpected balanced-effect rejection: {error}"
        );
    }
}

#[test]
fn faulty_verifier_general_bridge_moves_only_existing_source_units() {
    let (state, definition, source_asset_id) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(definition.clone(), BOB_ID.clone());
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut transaction =
        block.transaction_for_fastpq_testing(Hash::prehashed([0xBC; Hash::LENGTH]));
    let holders = [&*ALICE_ID, &*BOB_ID];
    let supply = economic_transparent_units(&transaction, &definition, &holders);
    // The transparent leg of a ZK-ACE authorization, as a verifier that accepts every proof
    // would return it: ALICE never signed, the proof alone names her as the source.
    let mut bridge = |amount: u32, statement: u8, destination: &AccountId| {
        execute_verified_privacy_public_balance_transfer(
            &mut transaction,
            &BOB_ID,
            PrivacyStatementDigestV1::new([statement; 32]),
            &definition,
            AssetBalanceScope::Global,
            &ALICE_ID,
            destination,
            Quantity::from(amount),
        )
    };

    bridge(11, 1, &BOB_ID).expect_err("the bridge cannot move more than the source holds");
    let error = bridge(1, 2, &ALICE_ID).expect_err("source and destination must differ");
    assert!(
        error
            .to_string()
            .contains("source and destination must differ"),
        "unexpected self-transfer rejection: {error}"
    );
    // The remaining exposure is the named source's whole balance of the policy asset.
    bridge(10, 3, &BOB_ID).expect("the ledger cannot tell a wrongly verified authorization");
    bridge(1, 4, &BOB_ID).expect_err("an emptied source cannot be overdrawn");
    assert_eq!(
        asset_balance_or_zero(&transaction, &source_asset_id),
        Quantity::zero()
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &destination_asset_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        economic_transparent_units(&transaction, &definition, &holders),
        supply,
        "a wrongly verified authorization moved existing units and minted none"
    );
}

#[test]
fn dropped_transaction_discards_a_faulty_pool_withdrawal() {
    let (state, definition, reserve_asset_id) = build_asset_transfer_control_test_state(10);
    let attacker_asset_id = AssetId::new(definition.clone(), BOB_ID.clone());
    let owner = economic_orchard_owner(0xA1);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    block.admit_fastpq_source_for_testing(Hash::prehashed([0xBE; Hash::LENGTH]));
    {
        let mut custody = block.transaction();
        economic_seed_reserve_custody(&mut custody, &reserve_asset_id, owner);
        custody.apply();
    }
    {
        let mut transaction = block.transaction();
        seed_test_call_hash(&mut transaction, 0xBE);
        apply_faulty_verifier_pool_effect(
            &mut transaction,
            &BOB_ID,
            &FaultyVerifierPoolEffect {
                owner,
                definition: &definition,
                scope: AssetBalanceScope::Global,
                reserve_account: &ALICE_ID,
                direction: PrivacyValueBalanceDirectionV1::OutOfPool,
                amount: 6,
                statement: 1,
            },
        )
        .expect("the withdrawal is staged inside this transaction");
        assert_eq!(
            asset_balance_or_zero(&transaction, &reserve_asset_id),
            Quantity::from(4_u32)
        );
        // A later instruction of the same transaction fails; the transaction is not applied.
    }
    let transaction = block.transaction();
    assert_eq!(
        asset_balance_or_zero(&transaction, &reserve_asset_id),
        Quantity::from(10_u32),
        "a transaction that is not applied leaves the reserve whole"
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &attacker_asset_id),
        Quantity::zero(),
        "a transaction that is not applied credits nothing"
    );
}

// TODO: the checks that follow a verifier call inline have no verifier-fault test: the Orchard,
// FCMP++, Anonymous PGC and ZK-ACE apply arms of the proof handler and the PGC bootstrap handler
// still need an apply entry point that takes the verified effect, which is a production
// change of their owner. Recorded in specs/zk_economic_invariants.json as
// D-HARNESS-NO-SEAM-AFTER-VERIFIER (P.3, P.1). The fee-sponsor capacity and lease
// boundary is covered separately in world_fee_sponsor_ledger_effect_tests.rs; its
// genuine proof integration and original codec-refusal propagation remain separate.
