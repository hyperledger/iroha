//! State-backed atomic settlement execution and reference-retention controls.

#[path = "boi_clearing_tests.rs"]
mod boi_clearing_tests;

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::query::error::FindError;
use iroha_data_model::{
    escrow::{
        AssetEscrowKind, AssetEscrowStatus, ConditionalEscrowCondition,
        ConditionalEscrowOracleCondition, ConditionalEscrowPredicate, ConditionalEscrowValue,
        EscrowId,
    },
    isi::{
        AtomicSettlementEscrow, AtomicSettlementEscrows, AtomicSettlementMovement,
        AtomicSettlementMovements, SettleAtomic, SettlementDetails,
        escrow::{AttestEscrowCondition, ExpireConditionalEscrow, OpenConditionalEscrow},
    },
};
use std::num::NonZeroU64;

/// Measure the component corpus through the real bounded canonical frame sizer.
/// Fixed context hashes affect bytes but not lengths; no source authority is emitted.
fn atomic_fixture_source_usage(
    movements: &[AtomicSettlementMovement],
) -> crate::fastpq::FastpqSourceTranscriptUsage {
    use iroha_data_model::fastpq::{
        TransferDeltaTranscript, TransferSmtWitness, TransferTranscript,
    };
    let entry = Hash::new(b"atomic-fixture-carrier");
    let mut transcript = TransferTranscript {
        batch_hash: entry,
        authority_digest: Hash::new(b"atomic-fixture-authority-length"),
        poseidon_preimage_digest: None,
        deltas: movements
            .iter()
            .enumerate()
            .map(|(index, movement)| TransferDeltaTranscript {
                from_account: movement.source.account().clone(),
                to_account: movement.recipient.clone(),
                asset_definition: movement.source.definition().clone(),
                amount: movement.quantity.clone(),
                from_balance_before: Quantity::from(10_u32),
                from_balance_after: Quantity::from(9_u32),
                to_balance_before: Quantity::from(u64::try_from(index).unwrap()),
                to_balance_after: Quantity::from(u64::try_from(index + 1).unwrap()),
                from_smt_witness: TransferSmtWitness::default(),
                to_smt_witness: TransferSmtWitness::default(),
            })
            .collect(),
    };
    if let [delta] = transcript.deltas.as_slice() {
        transcript.poseidon_preimage_digest =
            Some(crate::fastpq::poseidon_preimage_digest(delta, &entry));
    }
    crate::fastpq::source_prefix_lengths::entry::measure_fastpq_source_entry_frame_usage(
        entry,
        [&transcript],
        crate::fastpq::FastpqSourceStatementBuildLimits {
            max_executed_entries: 1,
            max_transcripts: 1,
            max_deltas: 255,
            max_input_transcript_bytes: 1024 * 1024,
            max_statement_bytes: 1024 * 1024,
            max_total_statement_bytes: 1024 * 1024,
        },
    )
    .expect("finite original component corpus frame")
}

fn atomic_state(count: usize) -> (State, Vec<AtomicSettlementMovement>, AssetDefinitionId) {
    atomic_state_in_scope(count, AssetBalanceScope::Global, AssetBalancePolicy::Global)
}
fn atomic_state_in_scope(
    count: usize,
    scope: AssetBalanceScope,
    policy: AssetBalancePolicy,
) -> (State, Vec<AtomicSettlementMovement>, AssetDefinitionId) {
    atomic_state_in_scope_with_source_delta_limit(
        count,
        scope,
        policy,
        u32::try_from(count)
            .expect("bounded movement count")
            .max(16),
        Quantity::from(10_u32),
    )
}
fn atomic_state_in_scope_with_source_delta_limit(
    count: usize,
    scope: AssetBalanceScope,
    policy: AssetBalancePolicy,
    max_deltas: u32,
    source_balance: Quantity,
) -> (State, Vec<AtomicSettlementMovement>, AssetDefinitionId) {
    let domain_id = DomainId::try_new("atomic", "universal").expect("domain");
    let definition =
        AssetDefinitionId::derive_from_components(domain_id.clone(), "cash".parse().expect("name"));
    let mut accounts = vec![Account::new(CARPENTER_ID.clone()).build(&CARPENTER_ID)];
    let mut assets = Vec::new();
    let mut movements = Vec::new();
    for index in 0..count {
        let mut seed = vec![0xA5; 32];
        seed[..2].copy_from_slice(
            &u16::try_from(index)
                .expect("fixture value fits u16")
                .to_le_bytes(),
        );
        let owner = AccountId::new(
            KeyPair::try_from_seed(seed, Algorithm::Ed25519)
                .expect("fixture key")
                .public_key()
                .clone(),
        );
        accounts.push(Account::new(owner.clone()).build(&CARPENTER_ID));
        let source = AssetId::with_scope(definition.clone(), owner, scope);
        assets.push(Asset::new(source.clone(), source_balance.clone()));
        movements.push(AtomicSettlementMovement {
            source,
            recipient: CARPENTER_ID.clone(),
            quantity: Quantity::one(),
        });
    }
    movements.sort_by(|a, b| (&a.source, &a.recipient).cmp(&(&b.source, &b.recipient)));
    let world = World::with_assets(
        [Domain::new(domain_id.clone()).build(&CARPENTER_ID)],
        accounts,
        [AssetDefinition::numeric(
            definition.clone(),
            "cash".to_owned(),
            policy,
            (policy == AssetBalancePolicy::DataspaceRestricted).then_some(domain_id),
        )
        .build(&CARPENTER_ID)],
        assets,
        [],
    );
    // The 255-payment corpus exceeds the sixteen-delta bootstrap profile.
    // Install its finite complete-frame bound before State freezes the source
    // quota. This component policy grants no Network or publication authority.
    {
        use iroha_data_model::parameter::{BlockParameter, FastpqSourcePolicyV1, Parameter};

        let mut parameters = world.parameters.block();
        let previous = parameters.get().block().fastpq_source();
        let mut intrinsic = previous.intrinsic;
        let usage = atomic_fixture_source_usage(&movements);
        intrinsic.max_deltas = max_deltas;
        intrinsic.max_input_transcript_bytes = intrinsic
            .max_input_transcript_bytes
            .max(u64::try_from(usage.input_transcript_bytes).expect("finite input corpus"));
        intrinsic.max_statement_bytes = intrinsic
            .max_statement_bytes
            .max(u64::try_from(usage.max_statement_bytes).expect("finite statement corpus"));
        intrinsic.max_total_statement_bytes = intrinsic
            .max_total_statement_bytes
            .max(u64::try_from(usage.total_statement_bytes).expect("finite statement total"));
        let profile = FastpqSourcePolicyV1::from_sizing(
            parameters.get().block().execution_output(),
            intrinsic,
            previous.mandatory,
            previous
                .maximum_network_inputs(parameters.get().block().execution_output())
                .expect("original Network source envelope"),
        )
        .expect("finite atomic source profile");
        parameters
            .get_mut()
            .set_parameter(Parameter::Block(BlockParameter::FastpqSource(profile)))
            .expect("valid fixture parameters");
        parameters.commit();
    }
    (
        State::new(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ),
        movements,
        definition,
    )
}
fn atomic_instruction(
    stx: &StateTransaction<'_, '_>,
    movements: Vec<AtomicSettlementMovement>,
) -> SettleAtomic {
    SettleAtomic::new(
        stx.network_id.clone(),
        SettlementId::new(
            movements[0].source.account().clone(),
            "atomic_business".parse().expect("reference"),
        ),
        AtomicSettlementMovements::try_from(movements).expect("canonical vector"),
        AtomicSettlementEscrows::empty(),
        nonzero!(100_u64),
        Metadata::default(),
    )
}
fn install_atomic_consents(
    stx: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: &SettleAtomic,
    omit: Option<usize>,
) {
    stx.tx_call_hash = Some(Hash::new(b"atomic-fixture-carrier"));
    let intent_hash = instruction.intent_hash().expect("complete intent");
    let omitted_source = omit.map(|index| &instruction.movements().as_slice()[index].source);
    let mut granted_sources = BTreeSet::new();
    for movement in instruction.movements().as_slice() {
        if Some(&movement.source) != omitted_source
            && granted_sources.insert(movement.source.clone())
        {
            // Exercise the canonical grant mutation as the source owner. The
            // separate default-executor issuer policy is not bypass-tested here.
            // One source-bucket consent covers every debit in the same intent.
            let permission: Permission = CanExecuteSettlement {
                debited_asset: movement.source.clone(),
                settlement_id: instruction.settlement_id().clone(),
                intent_hash,
            }
            .into();
            Grant::account_permission(permission, authority.clone())
                .execute(movement.source.account(), stx)
                .expect("owner grants exact consent");
        }
    }
}
fn atomic_observable_state(stx: &StateTransaction<'_, '_>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, usize) {
    macro_rules! capture {
        ($field:ident) => {
            norito::encode_canonical(
                &stx.world
                    .$field
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>(),
            )
            .expect("state fixture encoding")
        };
    }
    let assets = stx
        .world
        .assets
        .iter()
        .map(|(key, value)| (key.clone(), value.as_ref().clone()))
        .collect::<Vec<_>>();
    let accounts = stx
        .world
        .accounts
        .iter()
        .map(|(key, value)| (key.clone(), value.metadata().clone()))
        .collect::<Vec<_>>();
    (
        vec![
            norito::encode_canonical(&assets).expect("assets"),
            norito::encode_canonical(&accounts).expect("account controls"),
            capture!(settlement_receipts),
            capture!(asset_definition_assets),
            capture!(asset_definition_asset_counts),
            capture!(assets_by_domain),
            capture!(asset_definition_nonzero_holders),
        ],
        stx.world
            .internal_event_buf
            .iter()
            .map(|event| norito::encode_canonical(event.as_ref()).expect("event bytes"))
            .collect(),
        stx.pending_transfer_transcript_count_for_testing(),
    )
}

#[test]
fn atomic_settlement_executes_three_and_255_exact_payments_once() {
    for count in [3, 255] {
        let (state, movements, definition) = atomic_state(count);
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"atomic-fixture-carrier"));
        let instruction = atomic_instruction(&stx, movements);
        install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
        let transcripts = stx.pending_transfer_transcript_count_for_testing();
        admission_validate_atomic(&CARPENTER_ID, &mut stx, &instruction)
            .expect("same complete admission plan");
        instruction
            .clone()
            .execute(&CARPENTER_ID, &mut stx)
            .expect("atomic execution");
        assert_eq!(
            stx.pending_transfer_transcript_count_for_testing(),
            transcripts + 1
        );
        for movement in instruction.movements().as_slice() {
            assert_eq!(
                asset_balance_or_zero(&stx, &movement.source),
                Quantity::from(9_u32)
            );
        }
        assert_eq!(
            asset_balance_or_zero(&stx, &AssetId::new(definition, CARPENTER_ID.clone())),
            Quantity::from(count as u64)
        );
        let receipt = stx
            .world
            .settlement_receipts
            .get(instruction.settlement_id())
            .expect("one receipt");
        let SettlementDetails::Atomic(iroha_data_model::isi::AtomicSettlementDetails {
            movements,
            intent_hash,
            escrow_ids,
        }) = &receipt.details
        else {
            panic!("atomic details");
        };
        assert!(escrow_ids.is_empty(), "no escrow legs were signed");
        assert_eq!(
            movements,
            &instruction
                .movements()
                .resolve()
                .expect("exact signed movements")
        );
        assert_eq!(
            *intent_hash,
            instruction.intent_hash().expect("complete intent")
        );
        assert_eq!(receipt.details.movements().count(), count);
    }
}

#[test]
fn atomic_settlement_single_global_payment_credits_250000_units_once() {
    let (state, mut movements, definition) = atomic_state_in_scope_with_source_delta_limit(
        1,
        AssetBalanceScope::Global,
        AssetBalancePolicy::Global,
        16,
        Quantity::from(500_000_u32),
    );
    movements[0].quantity = Quantity::from(250_000_u32);
    let source = movements[0].source.clone();
    let recipient = movements[0].destination();
    let authority = source.account().clone();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    block.admit_fastpq_source_for_testing(Hash::new(b"single-payment-retry-carrier"));
    block.admit_fastpq_source_for_testing(Hash::new(b"single-payment-conflicting-carrier"));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"atomic-fixture-carrier"));
    let mut instruction = atomic_instruction(&stx, movements);
    instruction.metadata.insert(
        "payment_reference".parse().expect("metadata key"),
        Json::new("shared-asset-payment-250000"),
    );
    let transcripts = stx.pending_transfer_transcript_count_for_testing();
    admission_validate_atomic(&authority, &mut stx, &instruction)
        .expect("single payer authorizes its exact global debit");
    instruction
        .clone()
        .execute(&authority, &mut stx)
        .expect("single payment uses the existing atomic executor");
    assert_eq!(
        asset_balance_or_zero(&stx, &source),
        Quantity::from(250_000_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &recipient),
        Quantity::from(250_000_u32)
    );
    assert_eq!(recipient, AssetId::new(definition, CARPENTER_ID.clone()));
    assert_eq!(
        stx.pending_transfer_transcript_count_for_testing(),
        transcripts + 1
    );
    let receipt = stx
        .world
        .settlement_receipts
        .get(instruction.settlement_id())
        .expect("one immutable business receipt");
    assert_eq!(receipt.authority, authority);
    assert_eq!(receipt.metadata, instruction.metadata);
    assert!(matches!(&receipt.details,
        SettlementDetails::Atomic(iroha_data_model::isi::AtomicSettlementDetails { movements, intent_hash, escrow_ids })
        if movements == &instruction.movements.resolve().expect("exact movement")
            && *intent_hash == instruction.intent_hash().expect("exact intent")
            && escrow_ids.is_empty()));
    assert_eq!(receipt.details.movements().count(), 1);

    // Distinct admitted component carriers cannot create a second monetary effect,
    // whether they repeat the exact intent or change its amount under the occupied ID.
    let settled = atomic_observable_state(&stx);
    for (amount, carrier) in [
        (250_000_u32, Hash::new(b"single-payment-retry-carrier")),
        (
            125_000_u32,
            Hash::new(b"single-payment-conflicting-carrier"),
        ),
    ] {
        stx.tx_call_hash = Some(carrier);
        let mut replay = instruction.clone();
        let mut changed = replay.movements.as_slice().to_vec();
        changed[0].quantity = Quantity::from(amount);
        replay.movements = AtomicSettlementMovements::try_from(changed).expect("one movement");
        assert!(
            replay
                .execute(&authority, &mut stx)
                .expect_err("occupied business identifier refuses replay and conflicting terms")
                .to_string()
                .contains("already been committed")
        );
        assert_eq!(atomic_observable_state(&stx), settled);
    }
}

#[test]
fn atomic_settlement_missing_consent_at_every_position_changes_nothing() {
    for count in [1, 3, 255] {
        let (state, movements, _) = atomic_state(count);
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        for omit in 0..count {
            let mut stx = block.transaction();
            let instruction = atomic_instruction(&stx, movements.clone());
            install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, Some(omit));
            let before = atomic_observable_state(&stx);
            let error = instruction
                .execute(&CARPENTER_ID, &mut stx)
                .expect_err("one missing owner consent must reject the whole vector");
            assert!(error.to_string().contains("whole-intent consent"));
            assert_eq!(atomic_observable_state(&stx), before);
        }
    }
}

#[test]
fn atomic_settlement_cannot_consume_a_recipient_namespace() {
    let (state, movements, _) = atomic_state(1);
    let payer = movements[0].source.account().clone();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"foreign atomic namespace"));
    let mut instruction = atomic_instruction(&stx, movements);
    instruction.settlement_id.owner = CARPENTER_ID.clone();
    let before = atomic_observable_state(&stx);
    assert!(
        admission_validate_atomic(&payer, &mut stx, &instruction)
            .unwrap_err()
            .to_string()
            .contains("settlement id owner")
    );
    assert!(
        instruction
            .execute(&payer, &mut stx)
            .unwrap_err()
            .to_string()
            .contains("settlement id owner")
    );
    assert_eq!(atomic_observable_state(&stx), before);
}

#[test]
fn atomic_settlement_metadata_or_amount_substitution_requires_fresh_whole_intent_consent() {
    let (state, movements, _) = atomic_state(3);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    for change in 0..2 {
        let mut stx = block.transaction();
        let original = atomic_instruction(&stx, movements.clone());
        install_atomic_consents(&mut stx, &CARPENTER_ID, &original, None);
        let mut changed_movements = movements.clone();
        let mut metadata = Metadata::default();
        if change == 0 {
            changed_movements[2].quantity = Quantity::from(2_u32);
        } else {
            metadata.insert("reference".parse().expect("key"), Json::new("substituted"));
        }
        let changed = SettleAtomic::new(
            stx.network_id.clone(),
            original.settlement_id().clone(),
            AtomicSettlementMovements::try_from(changed_movements).expect("canonical"),
            AtomicSettlementEscrows::empty(),
            *original.expires_at_height(),
            metadata,
        );
        let before = atomic_observable_state(&stx);
        assert!(
            changed
                .execute(&CARPENTER_ID, &mut stx)
                .expect_err("changed whole intent")
                .to_string()
                .contains("whole-intent consent")
        );
        assert_eq!(atomic_observable_state(&stx), before);
    }
}

#[test]
fn atomic_settlement_wrong_network_or_expired_height_changes_nothing() {
    let (state, movements, _) = atomic_state(3);
    let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
    for expired in [false, true] {
        let mut stx = block.transaction();
        let network = if expired {
            stx.network_id.clone()
        } else {
            iroha_data_model::NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"other-network")),
            )
        };
        let instruction = SettleAtomic::new(
            network,
            SettlementId::new(
                movements[0].source.account().clone(),
                "atomic_expiry".parse().expect("reference"),
            ),
            AtomicSettlementMovements::try_from(movements.clone()).expect("canonical"),
            AtomicSettlementEscrows::empty(),
            NonZeroU64::new(if expired { 1 } else { 100 }).expect("expiry"),
            Metadata::default(),
        );
        install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
        let before = atomic_observable_state(&stx);
        let error = instruction
            .execute(&CARPENTER_ID, &mut stx)
            .expect_err("wrong network or expired");
        assert!(
            error
                .to_string()
                .contains(if expired { "expiry" } else { "network" })
        );
        assert_eq!(atomic_observable_state(&stx), before);
    }
}

#[test]
fn atomic_settlement_inclusive_expiry_height_is_accepted() {
    let (state, movements, _) = atomic_state(3);
    let mut block = state.block(BlockHeader::new(nonzero!(100_u64), None, None, 0, 0));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"atomic-fixture-carrier"));
    let instruction = atomic_instruction(&stx, movements);
    install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
    instruction
        .execute(&CARPENTER_ID, &mut stx)
        .expect("inclusive last allowed height");
}

#[test]
fn atomic_settlement_rejects_intrabundle_financing_of_repeated_outgoing_debits() {
    let (state, movements, _) = atomic_state(3);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut stx = block.transaction();
    let earlier = movements[0].source.clone();
    let later = movements[1].source.clone();
    for source in [&earlier, &later] {
        crate::smartcontracts::isi::asset::isi::replace_numeric_asset_balance_for_corruption_test(
            &mut stx.world,
            source,
            Quantity::one(),
        );
    }
    let mut payments = vec![
        AtomicSettlementMovement {
            source: earlier.clone(),
            recipient: later.account().clone(),
            quantity: Quantity::one(),
        },
        AtomicSettlementMovement {
            source: later.clone(),
            recipient: earlier.account().clone(),
            quantity: Quantity::one(),
        },
        AtomicSettlementMovement {
            source: later,
            recipient: CARPENTER_ID.clone(),
            quantity: Quantity::one(),
        },
    ];
    payments.sort_by(|a, b| (&a.source, &a.recipient).cmp(&(&b.source, &b.recipient)));
    let instruction = atomic_instruction(&stx, payments);
    install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
    let before = atomic_observable_state(&stx);
    assert!(matches!(
        instruction.execute(&CARPENTER_ID, &mut stx),
        Err(InstructionExecutionError::Math(
            MathError::NotEnoughQuantity
        ))
    ));
    assert_eq!(atomic_observable_state(&stx), before);
}

#[test]
fn atomic_settlement_final_aggregate_holding_limit_failure_changes_nothing() {
    for count in [3, 255] {
        let (state, movements, definition) = atomic_state(count);
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut stx = block.transaction();
        SetAssetHoldingLimit::new(
            CARPENTER_ID.clone(),
            definition,
            Some(Quantity::from(count as u64 - 1)),
        )
        .execute(&CARPENTER_ID, &mut stx)
        .expect("install aggregate destination limit");
        let instruction = atomic_instruction(&stx, movements);
        install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
        let before = atomic_observable_state(&stx);
        let error = instruction
            .execute(&CARPENTER_ID, &mut stx)
            .expect_err("last aggregated credit exceeds limit");
        assert_holding_limit_error(&error);
        assert_eq!(atomic_observable_state(&stx), before);
    }
}

#[test]
fn atomic_settlement_missing_carrier_identity_changes_nothing() {
    let (state, movements, _) = atomic_state(3);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut stx = block.transaction();
    let instruction = atomic_instruction(&stx, movements);
    install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
    stx.tx_call_hash = None;
    let before = atomic_observable_state(&stx);
    assert!(
        instruction
            .execute(&CARPENTER_ID, &mut stx)
            .expect_err("carrier identity required")
            .to_string()
            .contains("call_hash")
    );
    assert_eq!(atomic_observable_state(&stx), before);
}

#[test]
fn atomic_settlement_exact_signed_owner_needs_no_delegation_for_its_own_bucket() {
    let (state, movements, _) = atomic_state(3);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"atomic-fixture-carrier"));
    let authority = movements[1].source.account().clone();
    let instruction = atomic_instruction(&stx, movements);
    install_atomic_consents(&mut stx, &authority, &instruction, Some(1));
    instruction
        .execute(&authority, &mut stx)
        .expect("signed exact owner plus other owners' exact consents");
}

#[test]
fn atomic_settlement_fresh_carrier_cannot_replay_the_business_identifier() {
    let (state, movements, _) = atomic_state(3);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    block.admit_fastpq_source_for_testing(Hash::new(b"different-valid-carrier"));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"atomic-fixture-carrier"));
    let instruction = atomic_instruction(&stx, movements);
    install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
    instruction
        .clone()
        .execute(&CARPENTER_ID, &mut stx)
        .expect("first execution");
    stx.tx_call_hash = Some(Hash::new(b"different-valid-carrier"));
    let before = atomic_observable_state(&stx);
    assert!(
        instruction
            .execute(&CARPENTER_ID, &mut stx)
            .expect_err("business replay")
            .to_string()
            .contains("already been committed")
    );
    assert_eq!(atomic_observable_state(&stx), before);
}

#[test]
fn atomic_settlement_reference_retention_includes_the_final_movement() {
    let (state, movements, _) = atomic_state(255);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"atomic-fixture-carrier"));
    let instruction = atomic_instruction(&stx, movements);
    install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
    instruction
        .clone()
        .execute(&CARPENTER_ID, &mut stx)
        .expect("atomic execution");
    for index in [0, 127, 254] {
        let before = atomic_observable_state(&stx);
        let account = instruction.movements().as_slice()[index]
            .source
            .account()
            .clone();
        let error = Unregister::account(account)
            .execute(&CARPENTER_ID, &mut stx)
            .expect_err("every committed payer must remain referenced");
        assert!(error.to_string().contains("committed settlement receipt"));
        assert_eq!(atomic_observable_state(&stx), before);
    }
}

#[test]
fn atomic_settlement_source_delta_refusal_preserves_every_observable_effect() {
    let (state, movements, _) = atomic_state_in_scope_with_source_delta_limit(
        255,
        AssetBalanceScope::Global,
        AssetBalancePolicy::Global,
        254,
        Quantity::from(10_u32),
    );
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"atomic-fixture-carrier"));
    let instruction = atomic_instruction(&stx, movements);
    install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
    let before = atomic_observable_state(&stx);
    let error = instruction
        .execute(&CARPENTER_ID, &mut stx)
        .expect_err("one-delta-short profile must refuse the complete atomic batch");
    assert!(matches!(
        error,
        InstructionExecutionError::InvariantViolation(message)
            if message.as_ref() == "FASTPQ source intrinsic limit exceeded"
    ));
    assert_eq!(atomic_observable_state(&stx), before);
}

#[test]
fn atomic_settlement_actual_grant_then_revoke_rejects_without_movement() {
    let (state, movements, _) = atomic_state(255);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    for revoked in [0, 127, 254] {
        let mut stx = block.transaction();
        let instruction = atomic_instruction(&stx, movements.clone());
        install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
        admission_validate_atomic(&CARPENTER_ID, &mut stx, &instruction)
            .expect("all current consents permit admission");
        let source = &instruction.movements().as_slice()[revoked].source;
        let permission: Permission = CanExecuteSettlement {
            debited_asset: source.clone(),
            settlement_id: instruction.settlement_id().clone(),
            intent_hash: instruction.intent_hash().expect("intent"),
        }
        .into();
        Revoke::account_permission(permission, CARPENTER_ID.clone())
            .execute(source.account(), &mut stx)
            .expect("actual owner revokes its grant");
        let before = atomic_observable_state(&stx);
        assert!(
            instruction
                .execute(&CARPENTER_ID, &mut stx)
                .expect_err("current consent must be checked again at execution")
                .to_string()
                .contains("whole-intent consent")
        );
        assert_eq!(atomic_observable_state(&stx), before);
    }
}

#[test]
fn atomic_settlement_other_scope_or_owner_consent_cannot_cover_signed_source() {
    let (state, movements, _) = atomic_state(3);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    for wrong_scope in [false, true] {
        let mut stx = block.transaction();
        let instruction = atomic_instruction(&stx, movements.clone());
        install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, Some(2));
        let source = &instruction.movements().as_slice()[2].source;
        let incorrect = AssetId::with_scope(
            source.definition().clone(),
            if wrong_scope {
                source.account().clone()
            } else {
                CARPENTER_ID.clone()
            },
            if wrong_scope {
                AssetBalanceScope::Dataspace(DataSpaceId::new(7))
            } else {
                *source.scope()
            },
        );
        let permission: Permission = CanExecuteSettlement {
            debited_asset: incorrect.clone(),
            settlement_id: instruction.settlement_id().clone(),
            intent_hash: instruction.intent_hash().expect("intent"),
        }
        .into();
        Grant::account_permission(permission, CARPENTER_ID.clone())
            .execute(incorrect.account(), &mut stx)
            .expect("grant another exact bucket only");
        let before = atomic_observable_state(&stx);
        assert!(
            instruction
                .execute(&CARPENTER_ID, &mut stx)
                .expect_err("no scope or owner inference")
                .to_string()
                .contains("whole-intent consent")
        );
        assert_eq!(atomic_observable_state(&stx), before);
    }
}

#[test]
fn atomic_settlement_signed_scope_must_match_definition_and_execution_policies() {
    for (scope, policy, route, expected) in [
        (
            AssetBalanceScope::Global,
            AssetBalancePolicy::DataspaceRestricted,
            DataSpaceId::UNIVERSAL,
            "requires an exact public balance scope",
        ),
        (
            AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
            AssetBalancePolicy::Global,
            DataSpaceId::UNIVERSAL,
            "requires the global public balance scope",
        ),
        (
            AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
            AssetBalancePolicy::DataspaceRestricted,
            DataSpaceId::new(8),
            "does not match execution dataspace",
        ),
    ] {
        // Deliberately inconsistent State fixtures prove fail-closed policy
        // handling, rather than relying on the source balance being absent.
        let (state, movements, _) = atomic_state_in_scope(3, scope, policy);
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut stx = block.transaction();
        stx.current_dataspace_id = Some(route);
        stx.world.current_dataspace_id = Some(route);
        let instruction = atomic_instruction(&stx, movements);
        install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
        let before = atomic_observable_state(&stx);
        let error = instruction
            .execute(&CARPENTER_ID, &mut stx)
            .expect_err("signed bucket cannot be silently resolved to another partition");
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(atomic_observable_state(&stx), before);
    }
}

#[test]
fn atomic_settlement_restricted_exact_bucket_survives_universal_coordinator_execution() {
    let scope = AssetBalanceScope::Dataspace(DataSpaceId::new(7));
    let (state, movements, definition) =
        atomic_state_in_scope(3, scope, AssetBalancePolicy::DataspaceRestricted);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"atomic-fixture-carrier"));
    stx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    stx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    let instruction = atomic_instruction(&stx, movements);
    install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
    instruction
        .clone()
        .execute(&CARPENTER_ID, &mut stx)
        .expect("explicit restricted bucket on coordinator");
    let receipt = stx
        .world
        .settlement_receipts
        .get(instruction.settlement_id())
        .expect("receipt");
    assert!(receipt.details.movements().all(
        |movement| *movement.source.scope() == scope && *movement.destination.scope() == scope
    ));
    assert_eq!(
        asset_balance_or_zero(
            &stx,
            &AssetId::with_scope(definition.clone(), CARPENTER_ID.clone(), scope)
        ),
        Quantity::from(3_u32)
    );
    assert_eq!(
        asset_balance_or_zero(
            &stx,
            &AssetId::with_scope(definition, CARPENTER_ID.clone(), AssetBalanceScope::Global)
        ),
        Quantity::zero()
    );
}

#[test]
fn atomic_settlement_final_source_or_destination_failure_preserves_all_prior_movements() {
    let (state, movements, _) = atomic_state(255);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    for missing_destination in [false, true] {
        let mut stx = block.transaction();
        let mut payments = movements.clone();
        if missing_destination {
            let missing = AccountId::new(
                KeyPair::try_from_seed(vec![0xEE; 32], Algorithm::Ed25519)
                    .expect("fixture key")
                    .public_key()
                    .clone(),
            );
            assert!(stx.world.accounts.get(&missing).is_none());
            payments.last_mut().expect("255 payments").recipient = missing;
        } else {
            let source = &payments.last().expect("255 payments").source;
            crate::smartcontracts::isi::asset::isi::replace_numeric_asset_balance_for_corruption_test(&mut stx.world, source, Quantity::zero());
        }
        let instruction = atomic_instruction(&stx, payments);
        install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
        let before = atomic_observable_state(&stx);
        let error = instruction
            .execute(&CARPENTER_ID, &mut stx)
            .expect_err("the last failing payment must reject the whole prepared batch");
        if missing_destination {
            assert!(matches!(
                error,
                InstructionExecutionError::Find(FindError::Account(_))
            ));
        } else {
            assert!(matches!(
                error,
                InstructionExecutionError::Math(MathError::NotEnoughQuantity)
            ));
        }
        assert_eq!(atomic_observable_state(&stx), before);
    }
}

#[test]
fn atomic_settlement_bootstrap_delta_limit_refuses_without_movement_or_receipt() {
    use iroha_data_model::parameter::{BlockParameter, FastpqSourcePolicyV1, Parameter};
    let (state, movements, _) = atomic_state(17);
    let mut parameters = state.world.parameters.block();
    parameters
        .get_mut()
        .set_parameter(Parameter::Block(BlockParameter::FastpqSource(
            FastpqSourcePolicyV1::bootstrap(),
        )))
        .expect("valid fixture parameters");
    parameters.commit();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"atomic-fixture-carrier"));
    let instruction = atomic_instruction(&stx, movements);
    install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
    admission_validate_atomic(&CARPENTER_ID, &mut stx, &instruction)
        .expect("complete authority and movement checks precede source admission");
    let before = atomic_observable_state(&stx);
    let error = instruction.execute(&CARPENTER_ID, &mut stx).unwrap_err();
    assert_eq!(
        error,
        InstructionExecutionError::InvariantViolation(
            crate::fastpq::source_reservation::admission::SOURCE_INTRINSIC_REJECTION.into(),
        ),
    );
    assert_eq!(atomic_observable_state(&stx), before);
}

#[test]
fn atomic_fixture_profile_covers_the_complete_canonical_255_payment_corpus() {
    let (state, movements, _) = atomic_state(255);
    let usage = atomic_fixture_source_usage(&movements);
    let intrinsic = state
        .world
        .view()
        .parameters()
        .block()
        .fastpq_source()
        .intrinsic;
    assert_eq!(usage.transcripts, 1);
    assert_eq!(usage.deltas, 255);
    assert_eq!(intrinsic.max_deltas, 255);
    assert!(
        u64::try_from(usage.input_transcript_bytes).unwrap()
            <= intrinsic.max_input_transcript_bytes
    );
    assert!(u64::try_from(usage.max_statement_bytes).unwrap() <= intrinsic.max_statement_bytes);
    assert_eq!(usage.max_statement_bytes, usage.total_statement_bytes);
    assert_eq!(
        iroha_data_model::parameter::FastpqSourcePolicyV1::bootstrap()
            .intrinsic
            .max_deltas,
        16
    );
    println!("Exact canonical 255-payment fixture usage: {usage:?}");
}

/// Bond issuance parties: the investor pays cash, the issuer delivers bonds and
/// receives a retained escrow share released by the attestor.
struct BondEscrowFixture {
    state: State,
    investor: AccountId,
    issuer: AccountId,
    attestor: AccountId,
    cash: AssetDefinitionId,
    bond: AssetDefinitionId,
}

fn bond_account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture key")
            .public_key()
            .clone(),
    )
}

fn bond_escrow_fixture() -> BondEscrowFixture {
    let domain_id = DomainId::try_new("bond_escrow", "universal").expect("domain");
    let cash =
        AssetDefinitionId::derive_from_components(domain_id.clone(), "cash".parse().expect("name"));
    let bond =
        AssetDefinitionId::derive_from_components(domain_id.clone(), "bond".parse().expect("name"));
    let investor = bond_account(0xB1);
    let issuer = bond_account(0xB2);
    let attestor = bond_account(0xB3);
    let accounts = [&investor, &issuer, &attestor, &*CARPENTER_ID]
        .into_iter()
        .map(|id| Account::new(id.clone()).build(&CARPENTER_ID))
        .collect::<Vec<_>>();
    let definition = |id: &AssetDefinitionId, name: &str| {
        AssetDefinition::numeric(
            id.clone(),
            name.to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&CARPENTER_ID)
    };
    let world = World::with_assets(
        [Domain::new(domain_id).build(&CARPENTER_ID)],
        accounts,
        [definition(&cash, "cash"), definition(&bond, "bond")],
        [
            Asset::new(
                AssetId::new(cash.clone(), investor.clone()),
                Quantity::from(100_u32),
            ),
            Asset::new(
                AssetId::new(cash.clone(), CARPENTER_ID.clone()),
                Quantity::from(10_u32),
            ),
            Asset::new(
                AssetId::new(bond.clone(), issuer.clone()),
                Quantity::from(5_u32),
            ),
        ],
        [],
    );
    BondEscrowFixture {
        state: State::new(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ),
        investor,
        issuer,
        attestor,
        cash,
        bond,
    }
}

fn bond_escrow_id(label: &str) -> EscrowId {
    EscrowId::new(Hash::new(format!("bond-escrow:{label}")))
}

impl BondEscrowFixture {
    fn escrow_leg(
        &self,
        source_owner: &AccountId,
        label: &str,
        amount: u32,
        expires_at_ms: u64,
    ) -> AtomicSettlementEscrow {
        self.leg(
            AssetId::new(self.cash.clone(), source_owner.clone()),
            &self.issuer,
            label,
            amount,
            expires_at_ms,
        )
    }

    /// One escrow leg from an exact source bucket to any beneficiary.
    fn leg(
        &self,
        source: AssetId,
        beneficiary: &AccountId,
        label: &str,
        amount: u32,
        expires_at_ms: u64,
    ) -> AtomicSettlementEscrow {
        AtomicSettlementEscrow {
            source,
            escrow_id: bond_escrow_id(label),
            beneficiary: beneficiary.clone(),
            amount: Quantity::from(amount),
            conditions: vec![ConditionalEscrowCondition::Oracle(
                ConditionalEscrowOracleCondition {
                    id: "coupon_paid".parse().expect("condition id"),
                    attestor: self.attestor.clone(),
                    predicate: ConditionalEscrowPredicate::Equals(ConditionalEscrowValue::Bool(
                        true,
                    )),
                    sequence: core::num::NonZeroU32::new(1).expect("sequence"),
                },
            )],
            expires_at_ms,
            evidence_hashes: vec![Hash::new(b"bond-term-sheet")],
        }
    }

    /// The investor pays `paid` cash to the issuer and receives one bond.
    fn settlement(
        &self,
        stx: &StateTransaction<'_, '_>,
        payer: &AccountId,
        paid: u32,
        escrows: Vec<AtomicSettlementEscrow>,
    ) -> SettleAtomic {
        let mut movements = vec![
            AtomicSettlementMovement {
                source: AssetId::new(self.cash.clone(), payer.clone()),
                recipient: self.issuer.clone(),
                quantity: Quantity::from(paid),
            },
            AtomicSettlementMovement {
                source: AssetId::new(self.bond.clone(), self.issuer.clone()),
                recipient: payer.clone(),
                quantity: Quantity::one(),
            },
        ];
        movements.sort_by(|a, b| (&a.source, &a.recipient).cmp(&(&b.source, &b.recipient)));
        let mut escrows = escrows;
        escrows.sort_by_key(|escrow| escrow.escrow_id);
        SettleAtomic::new(
            stx.network_id.clone(),
            SettlementId::new(payer.clone(), "bond_issue_1".parse().expect("reference")),
            AtomicSettlementMovements::try_from(movements).expect("canonical movements"),
            AtomicSettlementEscrows::try_from(escrows).expect("canonical escrows"),
            nonzero!(100_u64),
            Metadata::default(),
        )
    }

    fn consent(
        stx: &mut StateTransaction<'_, '_>,
        owner: &AccountId,
        source: AssetId,
        grantee: &AccountId,
        instruction: &SettleAtomic,
    ) {
        let permission: Permission = CanExecuteSettlement {
            debited_asset: source,
            settlement_id: instruction.settlement_id().clone(),
            intent_hash: instruction.intent_hash().expect("complete intent"),
        }
        .into();
        Grant::account_permission(permission, grantee.clone())
            .execute(owner, stx)
            .expect("owner grants exact consent");
    }

    fn cash_of(&self, stx: &StateTransaction<'_, '_>, account: &AccountId) -> Quantity {
        asset_balance_or_zero(stx, &AssetId::new(self.cash.clone(), account.clone()))
    }
}

#[test]
fn atomic_settlement_opens_consent_bound_escrow_with_exact_custody() {
    let fixture = bond_escrow_fixture();
    let mut block = fixture
        .state
        .block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
    let mut stx = block.transaction_for_callback_testing();
    let leg = fixture.escrow_leg(&fixture.investor, "retention", 10, 1_000_000);
    let escrow_id = leg.escrow_id;
    let instruction = fixture.settlement(&stx, &fixture.investor, 90, vec![leg]);
    BondEscrowFixture::consent(
        &mut stx,
        &fixture.issuer,
        AssetId::new(fixture.bond.clone(), fixture.issuer.clone()),
        &fixture.investor,
        &instruction,
    );
    let custody = crate::smartcontracts::isi::escrow::escrow_custody_account_id(
        &stx.network_id,
        &escrow_id,
        &fixture.cash,
    );
    admission_validate_atomic(&fixture.investor, &mut stx, &instruction)
        .expect("complete admission including escrow funding");
    assert!(
        stx.world.accounts.get(&custody).is_none(),
        "admission must not retain escrow custody"
    );
    instruction
        .clone()
        .execute(&fixture.investor, &mut stx)
        .expect("atomic settlement with escrow leg");
    assert_eq!(fixture.cash_of(&stx, &fixture.investor), Quantity::zero());
    assert_eq!(
        fixture.cash_of(&stx, &fixture.issuer),
        Quantity::from(90_u32)
    );
    assert_eq!(fixture.cash_of(&stx, &custody), Quantity::from(10_u32));
    assert_eq!(
        asset_balance_or_zero(
            &stx,
            &AssetId::new(fixture.bond.clone(), fixture.investor.clone())
        ),
        Quantity::one()
    );
    let record = stx
        .world
        .asset_escrows
        .get(&escrow_id)
        .cloned()
        .expect("escrow opened by the settlement");
    assert_eq!(record.seller, fixture.investor);
    assert_eq!(record.buyer, Some(fixture.issuer.clone()));
    assert_eq!(record.custody, custody);
    assert_eq!(record.status, AssetEscrowStatus::Locked);
    assert_eq!(record.kind, AssetEscrowKind::Conditional);
    assert_eq!(record.remaining_amount, Quantity::from(10_u32));
    assert_eq!(record.expires_at_ms, Some(1_000_000));
    let receipt = stx
        .world
        .settlement_receipts
        .get(instruction.settlement_id())
        .expect("one receipt");
    let SettlementDetails::Atomic(details) = &receipt.details else {
        panic!("atomic details");
    };
    assert_eq!(details.escrow_ids, vec![escrow_id]);
    assert_eq!(
        details.movements,
        instruction.movements().resolve().expect("signed movements")
    );
}

#[test]
fn atomic_settlement_counterparty_consent_binds_the_escrow_terms() {
    let fixture = bond_escrow_fixture();
    let mut block = fixture
        .state
        .block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
    let mut stx = block.transaction_for_callback_testing();
    let consented = fixture.settlement(
        &stx,
        &fixture.investor,
        90,
        vec![fixture.escrow_leg(&fixture.investor, "retention", 10, 1_000_000)],
    );
    BondEscrowFixture::consent(
        &mut stx,
        &fixture.issuer,
        AssetId::new(fixture.bond.clone(), fixture.issuer.clone()),
        &fixture.investor,
        &consented,
    );
    let before = atomic_observable_state(&stx);
    // Omitting or shrinking the retained escrow share is a different intent
    // that the issuer never approved.
    for substituted in [
        fixture.settlement(&stx, &fixture.investor, 90, Vec::new()),
        fixture.settlement(
            &stx,
            &fixture.investor,
            90,
            vec![fixture.escrow_leg(&fixture.investor, "retention", 5, 1_000_000)],
        ),
        fixture.settlement(
            &stx,
            &fixture.investor,
            90,
            vec![fixture.escrow_leg(&fixture.investor, "retention", 10, 999_999)],
        ),
    ] {
        let error = substituted
            .execute(&fixture.investor, &mut stx)
            .expect_err("changed escrow terms need fresh consent");
        assert!(
            error.to_string().contains("whole-intent consent"),
            "{error}"
        );
        assert_eq!(atomic_observable_state(&stx), before);
    }
}

#[test]
fn atomic_settlement_foreign_escrow_source_requires_exact_owner_consent() {
    let fixture = bond_escrow_fixture();
    let mut block = fixture
        .state
        .block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
    let mut stx = block.transaction_for_callback_testing();
    let leg = fixture.escrow_leg(&fixture.investor, "foreign", 10, 1_000_000);
    let escrow_id = leg.escrow_id;
    let instruction = fixture.settlement(&stx, &CARPENTER_ID, 5, vec![leg]);
    BondEscrowFixture::consent(
        &mut stx,
        &fixture.issuer,
        AssetId::new(fixture.bond.clone(), fixture.issuer.clone()),
        &CARPENTER_ID,
        &instruction,
    );
    let before = atomic_observable_state(&stx);
    let error = instruction
        .clone()
        .execute(&CARPENTER_ID, &mut stx)
        .expect_err("a foreign escrow source needs its owner's consent");
    assert!(
        error.to_string().contains("whole-intent consent"),
        "{error}"
    );
    assert_eq!(atomic_observable_state(&stx), before);
    assert!(stx.world.asset_escrows.get(&escrow_id).is_none());
    BondEscrowFixture::consent(
        &mut stx,
        &fixture.investor,
        AssetId::new(fixture.cash.clone(), fixture.investor.clone()),
        &CARPENTER_ID,
        &instruction,
    );
    instruction
        .execute(&CARPENTER_ID, &mut stx)
        .expect("consented foreign escrow source");
    let record = stx
        .world
        .asset_escrows
        .get(&escrow_id)
        .cloned()
        .expect("escrow");
    assert_eq!(
        record.seller, fixture.investor,
        "the source owner, not the signer, opens and is refunded by the escrow"
    );
    assert_eq!(
        fixture.cash_of(&stx, &fixture.investor),
        Quantity::from(90_u32)
    );
    assert_eq!(fixture.cash_of(&stx, &CARPENTER_ID), Quantity::from(5_u32));
}

#[test]
fn atomic_settlement_failing_escrow_leg_rolls_back_every_movement() {
    let fixture = bond_escrow_fixture();
    let mut block = fixture
        .state
        .block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
    let mut stx = block.transaction_for_callback_testing();
    // Pre-existing escrow identifier for the duplicate case.
    OpenConditionalEscrow::new(
        bond_escrow_id("taken"),
        fixture.cash.clone(),
        fixture.issuer.clone(),
        1_u32,
        fixture
            .escrow_leg(&fixture.investor, "taken", 1, 1_000_000)
            .conditions,
        1_000_000,
    )
    .execute(&fixture.investor, &mut stx)
    .expect("existing conditional escrow");
    let cases = [
        // The combined movement and escrow outflow exceeds the prefunded balance:
        // custody creation, both movements and the escrow funding all roll back.
        (
            fixture.escrow_leg(&fixture.investor, "overdrawn", 20, 1_000_000),
            "NotEnoughQuantity",
        ),
        (
            fixture.escrow_leg(&fixture.investor, "expired", 9, 1_000),
            "expiry must be later",
        ),
        (
            fixture.escrow_leg(&fixture.investor, "taken", 9, 1_000_000),
            "escrow already exists",
        ),
    ];
    for (leg, expected) in cases {
        let escrow_id = leg.escrow_id;
        let instruction = fixture.settlement(&stx, &fixture.investor, 90, vec![leg]);
        BondEscrowFixture::consent(
            &mut stx,
            &fixture.issuer,
            AssetId::new(fixture.bond.clone(), fixture.issuer.clone()),
            &fixture.investor,
            &instruction,
        );
        let escrows_before = stx.world.asset_escrows.iter().count();
        let before = atomic_observable_state(&stx);
        let error = instruction
            .execute(&fixture.investor, &mut stx)
            .expect_err("an invalid escrow leg rejects the whole settlement");
        assert!(format!("{error:?}").contains(expected), "{error:?}");
        assert_eq!(atomic_observable_state(&stx), before);
        assert_eq!(stx.world.asset_escrows.iter().count(), escrows_before);
        if expected != "escrow already exists" {
            assert!(stx.world.asset_escrows.get(&escrow_id).is_none());
        }
    }
}

#[test]
fn atomic_settlement_movement_cannot_credit_same_intent_escrow_custody() {
    let fixture = bond_escrow_fixture();
    let mut block = fixture
        .state
        .block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
    let mut stx = block.transaction_for_callback_testing();
    let leg = fixture.escrow_leg(&fixture.investor, "custody-credit", 10, 1_000_000);
    let custody = crate::smartcontracts::isi::escrow::escrow_custody_account_id(
        &stx.network_id,
        &leg.escrow_id,
        &fixture.cash,
    );
    let mut movements = vec![
        AtomicSettlementMovement {
            source: AssetId::new(fixture.cash.clone(), fixture.investor.clone()),
            recipient: custody,
            quantity: Quantity::one(),
        },
        AtomicSettlementMovement {
            source: AssetId::new(fixture.cash.clone(), fixture.investor.clone()),
            recipient: fixture.issuer.clone(),
            quantity: Quantity::one(),
        },
    ];
    movements.sort_by(|a, b| (&a.source, &a.recipient).cmp(&(&b.source, &b.recipient)));
    let instruction = SettleAtomic::new(
        stx.network_id.clone(),
        SettlementId::new(
            fixture.investor.clone(),
            "custody_credit".parse().expect("reference"),
        ),
        AtomicSettlementMovements::try_from(movements).expect("canonical movements"),
        AtomicSettlementEscrows::try_from(vec![leg]).expect("canonical escrows"),
        nonzero!(100_u64),
        Metadata::default(),
    );
    let before = atomic_observable_state(&stx);
    let error = instruction
        .execute(&fixture.investor, &mut stx)
        .expect_err("custody is credited only by its funding leg");
    assert!(
        error.to_string().contains("cannot credit escrow custody"),
        "{error}"
    );
    assert_eq!(atomic_observable_state(&stx), before);
}

#[test]
fn atomic_settlement_escrow_releases_on_attestation_and_refunds_the_opener_at_expiry() {
    let fixture = bond_escrow_fixture();
    let released = bond_escrow_id("released");
    let refunded = bond_escrow_id("refunded");
    {
        let mut block =
            fixture
                .state
                .block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
        let mut stx = block.transaction_for_callback_testing();
        let instruction = fixture.settlement(
            &stx,
            &fixture.investor,
            70,
            vec![
                fixture.escrow_leg(&fixture.investor, "released", 10, 1_000_000),
                fixture.escrow_leg(&fixture.investor, "refunded", 20, 100_000),
            ],
        );
        BondEscrowFixture::consent(
            &mut stx,
            &fixture.issuer,
            AssetId::new(fixture.bond.clone(), fixture.issuer.clone()),
            &fixture.investor,
            &instruction,
        );
        instruction
            .execute(&fixture.investor, &mut stx)
            .expect("settle with two escrow legs");
        assert_eq!(fixture.cash_of(&stx, &fixture.investor), Quantity::zero());
        stx.apply();
        block.commit_world_overlay_for_testing().expect("commit");
    }
    {
        let mut block =
            fixture
                .state
                .block(BlockHeader::new(nonzero!(2_u64), None, None, 2_000, 0));
        let mut stx = block.transaction_for_callback_testing();
        let attest = AttestEscrowCondition::new(
            released,
            "coupon_paid".parse().expect("condition id"),
            ConditionalEscrowValue::Bool(true),
            None,
        );
        let error = attest
            .clone()
            .execute(&fixture.issuer, &mut stx)
            .expect_err("only the configured attestor attests");
        assert!(
            error.to_string().contains("exact configured attestor"),
            "{error}"
        );
        attest
            .execute(&fixture.attestor, &mut stx)
            .expect("final attestation releases custody");
        let record = stx
            .world
            .asset_escrows
            .get(&released)
            .cloned()
            .expect("record");
        assert_eq!(record.status, AssetEscrowStatus::Released);
        assert_eq!(
            fixture.cash_of(&stx, &fixture.issuer),
            Quantity::from(80_u32)
        );
        assert_eq!(fixture.cash_of(&stx, &record.custody), Quantity::zero());
        stx.apply();
        block.commit_world_overlay_for_testing().expect("commit");
    }
    let mut block = fixture
        .state
        .block(BlockHeader::new(nonzero!(3_u64), None, None, 200_000, 0));
    let mut stx = block.transaction_for_callback_testing();
    ExpireConditionalEscrow::new(refunded)
        .execute(&CARPENTER_ID, &mut stx)
        .expect("anyone triggers the expiry refund");
    let record = stx
        .world
        .asset_escrows
        .get(&refunded)
        .cloned()
        .expect("record");
    assert_eq!(record.status, AssetEscrowStatus::Expired);
    assert_eq!(
        fixture.cash_of(&stx, &fixture.investor),
        Quantity::from(20_u32),
        "expiry refunds the investor that funded the escrow"
    );
    assert_eq!(
        fixture.cash_of(&stx, &fixture.issuer),
        Quantity::from(80_u32)
    );
}

fn attest_condition(escrow_id: EscrowId) -> AttestEscrowCondition {
    AttestEscrowCondition::new(
        escrow_id,
        "coupon_paid".parse().expect("condition id"),
        ConditionalEscrowValue::Bool(true),
        None,
    )
}

#[test]
fn atomic_subscription_with_one_fee_movement_and_four_escrow_legs() {
    let fixture = bond_escrow_fixture();
    let investor_cash = AssetId::new(fixture.cash.clone(), fixture.investor.clone());
    let issuer_bond = AssetId::new(fixture.bond.clone(), fixture.issuer.clone());
    let investor_bond = AssetId::new(fixture.bond.clone(), fixture.investor.clone());
    let principal = bond_escrow_id("principal");
    let retention = bond_escrow_id("retention");
    let delivered = bond_escrow_id("delivered-units");
    let returned = bond_escrow_id("returned-units");
    {
        let mut block =
            fixture
                .state
                .block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
        let mut stx = block.transaction_for_callback_testing();
        // The investor pays only the 1% fee directly; principal, retention and
        // both bond-unit tranches are conditional escrow legs of the same intent.
        let fee = AtomicSettlementMovement {
            source: investor_cash.clone(),
            recipient: fixture.issuer.clone(),
            quantity: Quantity::one(),
        };
        let mut legs = vec![
            fixture.leg(
                investor_cash.clone(),
                &fixture.issuer,
                "principal",
                89,
                1_000_000,
            ),
            fixture.leg(
                investor_cash.clone(),
                &fixture.issuer,
                "retention",
                10,
                1_000_000,
            ),
            // Foreign issuer-owned source escrowed for a different beneficiary.
            fixture.leg(
                issuer_bond.clone(),
                &fixture.investor,
                "delivered-units",
                1,
                1_000_000,
            ),
            fixture.leg(
                issuer_bond.clone(),
                &fixture.investor,
                "returned-units",
                1,
                100_000,
            ),
        ];
        legs.sort_by_key(|leg| leg.escrow_id);
        let instruction = SettleAtomic::new(
            stx.network_id.clone(),
            SettlementId::new(
                fixture.investor.clone(),
                "subscription".parse().expect("reference"),
            ),
            AtomicSettlementMovements::try_from(vec![fee]).expect("one fee movement"),
            AtomicSettlementEscrows::try_from(legs).expect("four escrow legs"),
            nonzero!(100_u64),
            Metadata::default(),
        );
        let before = atomic_observable_state(&stx);
        let error = instruction
            .clone()
            .execute(&fixture.investor, &mut stx)
            .expect_err("the issuer's bond-unit legs need its exact consent");
        assert!(
            error.to_string().contains("whole-intent consent"),
            "{error}"
        );
        assert_eq!(atomic_observable_state(&stx), before);
        BondEscrowFixture::consent(
            &mut stx,
            &fixture.issuer,
            issuer_bond.clone(),
            &fixture.investor,
            &instruction,
        );
        admission_validate_atomic(&fixture.investor, &mut stx, &instruction)
            .expect("admission with foreign escrow source");
        instruction
            .clone()
            .execute(&fixture.investor, &mut stx)
            .expect("subscription settles");
        assert_eq!(fixture.cash_of(&stx, &fixture.investor), Quantity::zero());
        assert_eq!(fixture.cash_of(&stx, &fixture.issuer), Quantity::one());
        assert_eq!(
            asset_balance_or_zero(&stx, &issuer_bond),
            Quantity::from(3_u32)
        );
        assert_eq!(
            asset_balance_or_zero(&stx, &investor_bond),
            Quantity::zero()
        );
        for (id, seller, buyer) in [
            (principal, &fixture.investor, &fixture.issuer),
            (retention, &fixture.investor, &fixture.issuer),
            (delivered, &fixture.issuer, &fixture.investor),
            (returned, &fixture.issuer, &fixture.investor),
        ] {
            let record = stx.world.asset_escrows.get(&id).cloned().expect("record");
            assert_eq!(&record.seller, seller, "source owner opens {id:?}");
            assert_eq!(record.buyer.as_ref(), Some(buyer));
            assert_eq!(record.status, AssetEscrowStatus::Locked);
        }
        let receipt = stx
            .world
            .settlement_receipts
            .get(instruction.settlement_id())
            .expect("receipt");
        let SettlementDetails::Atomic(details) = &receipt.details else {
            panic!("atomic details");
        };
        assert_eq!(details.movements.as_slice().len(), 1);
        assert_eq!(details.escrow_ids, instruction.escrows().escrow_ids());
        stx.apply();
        block.commit_world_overlay_for_testing().expect("commit");
    }
    {
        let mut block =
            fixture
                .state
                .block(BlockHeader::new(nonzero!(2_u64), None, None, 2_000, 0));
        let mut stx = block.transaction_for_callback_testing();
        for id in [principal, delivered] {
            attest_condition(id)
                .execute(&fixture.attestor, &mut stx)
                .expect("condition passes");
        }
        // Units reach the buyer only once the condition passes.
        assert_eq!(asset_balance_or_zero(&stx, &investor_bond), Quantity::one());
        assert_eq!(
            fixture.cash_of(&stx, &fixture.issuer),
            Quantity::from(90_u32)
        );
        stx.apply();
        block.commit_world_overlay_for_testing().expect("commit");
    }
    let mut block = fixture
        .state
        .block(BlockHeader::new(nonzero!(3_u64), None, None, 200_000, 0));
    let mut stx = block.transaction_for_callback_testing();
    ExpireConditionalEscrow::new(returned)
        .execute(&CARPENTER_ID, &mut stx)
        .expect("expired units refund");
    assert_eq!(
        asset_balance_or_zero(&stx, &issuer_bond),
        Quantity::from(4_u32),
        "unreleased units return to the issuer that funded the leg"
    );
    assert_eq!(asset_balance_or_zero(&stx, &investor_bond), Quantity::one());
    assert_eq!(
        stx.world
            .asset_escrows
            .get(&retention)
            .map(|record| record.status),
        Some(AssetEscrowStatus::Locked)
    );
}

#[test]
fn atomic_settlement_with_only_two_escrow_legs_and_no_movement() {
    let fixture = bond_escrow_fixture();
    let mut block = fixture
        .state
        .block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
    let mut stx = block.transaction_for_callback_testing();
    let issuer_bond = AssetId::new(fixture.bond.clone(), fixture.issuer.clone());
    let mut legs = vec![
        fixture.escrow_leg(&fixture.investor, "cash-only", 10, 1_000_000),
        fixture.leg(
            issuer_bond.clone(),
            &fixture.investor,
            "units-only",
            1,
            1_000_000,
        ),
    ];
    legs.sort_by_key(|leg| leg.escrow_id);
    let instruction = SettleAtomic::new(
        stx.network_id.clone(),
        SettlementId::new(
            fixture.investor.clone(),
            "escrow_exchange".parse().expect("reference"),
        ),
        AtomicSettlementMovements::try_from(Vec::new()).expect("no movement"),
        AtomicSettlementEscrows::try_from(legs).expect("two escrow legs"),
        nonzero!(100_u64),
        Metadata::default(),
    );
    BondEscrowFixture::consent(
        &mut stx,
        &fixture.issuer,
        issuer_bond.clone(),
        &fixture.investor,
        &instruction,
    );
    instruction
        .execute(&fixture.investor, &mut stx)
        .expect("escrow-only settlement");
    assert_eq!(
        fixture.cash_of(&stx, &fixture.investor),
        Quantity::from(90_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &issuer_bond),
        Quantity::from(4_u32)
    );
    assert!(
        stx.world
            .asset_escrows
            .get(&bond_escrow_id("cash-only"))
            .is_some()
    );
    assert!(
        stx.world
            .asset_escrows
            .get(&bond_escrow_id("units-only"))
            .is_some()
    );
}
