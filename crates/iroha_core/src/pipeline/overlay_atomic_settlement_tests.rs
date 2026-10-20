//! Actual TxOverlay admission, executor authorization and execution of atomic settlements.

use super::*;
use crate::state::{State, StateBlock, World};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::Account,
    asset::{
        Asset, AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId, AssetId,
    },
    domain::Domain,
    fastpq::{TransferDeltaTranscript, TransferSmtWitness, TransferTranscript},
    isi::{
        AtomicSettlementMovement, AtomicSettlementMovements, Grant, Instruction, SettleAtomic,
        SettlementDetails,
    },
    parameter::{BlockParameter, FastpqSourcePolicyV1, Parameter},
    permission::Permission,
};
use iroha_executor_data_model::permission::settlement::CanExecuteSettlement;
use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
use iroha_primitives::numeric::Quantity;
use nonzero_ext::nonzero;

fn owner(index: u16) -> AccountId {
    let mut seed = vec![0xB7; 32];
    seed[..2].copy_from_slice(&index.to_le_bytes());
    AccountId::new(
        KeyPair::try_from_seed(seed, Algorithm::Ed25519)
            .expect("deterministic owner")
            .public_key()
            .clone(),
    )
}

fn expected_transcript(
    movements: &[AtomicSettlementMovement],
    sponsor: &AccountId,
) -> TransferTranscript {
    let mut received = Quantity::zero();
    let deltas = movements
        .iter()
        .map(|movement| {
            let before = received.clone();
            received = received
                .checked_add(&movement.quantity)
                .expect("bounded sum");
            TransferDeltaTranscript {
                from_account: movement.source.account().clone(),
                to_account: sponsor.clone(),
                asset_definition: movement.source.definition().clone(),
                amount: movement.quantity.clone(),
                from_balance_before: Quantity::from(1000_u32),
                from_balance_after: Quantity::from(1000_u32)
                    .checked_sub(&movement.quantity)
                    .expect("prefunded fixture source"),
                to_balance_before: before,
                to_balance_after: received.clone(),
                from_smt_witness: TransferSmtWitness::default(),
                to_smt_witness: TransferSmtWitness::default(),
            }
        })
        .collect();
    TransferTranscript {
        batch_hash: Hash::new(b"atomic-overlay-carrier"),
        authority_digest: crate::fastpq::authority_digest(sponsor),
        poseidon_preimage_digest: None,
        deltas,
    }
}

/// Freeze exact finite corpus framing through the governed source policy.
fn set_source_delta_limit(
    world: &World,
    max_deltas: u32,
    transcript: &TransferTranscript,
) -> FastpqSourcePolicyV1 {
    // Size the complete original occurrence before authenticated genesis installs
    // the policy. Both 254 and 255 delta ceilings use this same 255-movement byte
    // envelope, so the capacity regression isolates the D limit.
    let measured =
        crate::fastpq::source_prefix_lengths::entry::measure_fastpq_source_entry_frame_usage(
            transcript.batch_hash,
            [transcript],
            crate::fastpq::FastpqSourceStatementBuildLimits {
                max_executed_entries: 1,
                max_transcripts: 1,
                max_deltas: transcript.deltas.len(),
                max_input_transcript_bytes: 4 * 1024 * 1024,
                max_statement_bytes: 4 * 1024 * 1024,
                max_total_statement_bytes: 4 * 1024 * 1024,
            },
        )
        .expect("exact atomic fixture fits its bounded sizing corpus");
    assert_eq!(measured.deltas, transcript.deltas.len());
    let mut parameters = world.parameters.block();
    let baseline = parameters.get().block().fastpq_source();
    let mut intrinsic = baseline.intrinsic;
    intrinsic.max_transcripts = intrinsic
        .max_transcripts
        .max(u32::try_from(measured.transcripts).expect("bounded transcript count"));
    intrinsic.max_deltas = max_deltas;
    intrinsic.max_input_transcript_bytes = intrinsic
        .max_input_transcript_bytes
        .max(u64::try_from(measured.input_transcript_bytes).expect("bounded input corpus"));
    intrinsic.max_statement_bytes = intrinsic
        .max_statement_bytes
        .max(u64::try_from(measured.max_statement_bytes).expect("bounded statement corpus"));
    intrinsic.max_total_statement_bytes = intrinsic.max_total_statement_bytes.max(
        u64::try_from(measured.total_statement_bytes).expect("bounded total statement corpus"),
    );
    let profile = FastpqSourcePolicyV1::from_sizing(
        parameters.get().block().execution_output(),
        intrinsic,
        baseline.mandatory,
        FastpqSourcePolicyV1::BOOTSTRAP_NETWORK_INPUTS,
    )
    .expect("explicit finite source profile fits the signed genesis and component corpus");
    assert!(u32::try_from(measured.transcripts).unwrap() <= profile.intrinsic.max_transcripts);
    assert!(
        u64::try_from(measured.input_transcript_bytes).unwrap()
            <= profile.intrinsic.max_input_transcript_bytes
    );
    assert!(
        u64::try_from(measured.max_statement_bytes).unwrap()
            <= profile.intrinsic.max_statement_bytes
    );
    assert!(
        u64::try_from(measured.total_statement_bytes).unwrap()
            <= profile.intrinsic.max_total_statement_bytes
    );
    parameters
        .get_mut()
        .set_parameter(Parameter::Block(BlockParameter::FastpqSource(profile)))
        .expect("valid fixture parameters");
    parameters.commit();
    profile
}

fn fixture(
    count: usize,
    final_scope_mismatch: bool,
) -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    SettleAtomic,
    AccountId,
) {
    fixture_with_source_delta_limit(
        count,
        final_scope_mismatch,
        u32::try_from(count)
            .expect("bounded movement count")
            .max(16),
    )
}

fn fixture_with_source_delta_limit(
    count: usize,
    final_scope_mismatch: bool,
    max_deltas: u32,
) -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    SettleAtomic,
    AccountId,
) {
    let sponsor = owner(u16::MAX);
    let domain_id = DomainId::try_new("atomic_overlay", "universal").expect("domain");
    let definition =
        AssetDefinitionId::derive_from_components(domain_id.clone(), "cash".parse().expect("name"));
    let mut movements = (0..count)
        .map(|index| AtomicSettlementMovement {
            source: AssetId::with_scope(
                definition.clone(),
                owner(u16::try_from(index).expect("fixture value fits u16")),
                AssetBalanceScope::Global,
            ),
            recipient: sponsor.clone(),
            quantity: Quantity::from(index as u64 + 42),
        })
        .collect::<Vec<_>>();
    movements.sort_by(|a, b| (&a.source, &a.recipient).cmp(&(&b.source, &b.recipient)));
    if final_scope_mismatch {
        let last = movements.last_mut().expect("at least three payments");
        last.source = AssetId::with_scope(
            definition.clone(),
            last.source.account().clone(),
            AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
        );
        // AssetId orders account first. The final signed movement remains last,
        // so the failure follows preparation of every earlier valid movement.
        assert!(
            movements
                .windows(2)
                .all(|pair| (&pair[0].source, &pair[0].recipient)
                    < (&pair[1].source, &pair[1].recipient))
        );
    }
    let accounts = std::iter::once(Account::new(sponsor.clone()).build(&sponsor))
        .chain(
            movements
                .iter()
                .map(|movement| Account::new(movement.source.account().clone()).build(&sponsor)),
        )
        .collect::<Vec<_>>();
    let assets = movements
        .iter()
        .map(|movement| Asset::new(movement.source.clone(), Quantity::from(1000_u32)))
        .collect::<Vec<_>>();
    let world = World::with_assets(
        [Domain::new(domain_id).build(&sponsor)],
        accounts,
        [AssetDefinition::numeric(
            definition,
            "cash".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&sponsor)],
        assets,
        [],
    );
    // The 255-movement corpus exceeds bootstrap's sixteen transfer deltas.
    // Reserve its deltas and complete framing before StateBlock freezes its source owner.
    let transcript = expected_transcript(&movements, &sponsor);
    let source_policy = set_source_delta_limit(&world, max_deltas, &transcript);
    let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 0);
    // Genesis installs its signed parameter snapshot. Carry this finite corpus
    // policy in that snapshot so bootstrap defaults cannot replace its owner.
    config
        .genesis_parameters
        .push(iroha_data_model::parameter::Parameter::Block(
            iroha_data_model::parameter::BlockParameter::FastpqSource(source_policy),
        ));
    let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
        .expect("signed atomic settlement corpus policy");
    let instruction = SettleAtomic::new(
        chain.network_id(),
        iroha_data_model::isi::SettlementId::new(
            movements[0].source.account().clone(),
            "overlay_atomic_business".parse().expect("reference"),
        ),
        AtomicSettlementMovements::try_from(movements).expect("canonical full vector"),
        iroha_data_model::isi::AtomicSettlementEscrows::empty(),
        nonzero!(100_u64),
        Metadata::default(),
    );
    (chain, instruction, sponsor)
}

fn next_block(state: &State) -> StateBlock<'_> {
    assert!(
        crate::sumeragi::lanes::routing::committed_root_scope(state.view().world()).is_some(),
        "settlement permission cases require the actual signed genesis root",
    );
    state.block(BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        0,
        0,
    ))
}

fn permission(instruction: &SettleAtomic, source: &AssetId) -> Permission {
    CanExecuteSettlement {
        debited_asset: source.clone(),
        settlement_id: instruction.settlement_id().clone(),
        intent_hash: instruction.intent_hash().expect("full intent"),
    }
    .into()
}

fn grant_consents(
    block: &mut StateBlock<'_>,
    instruction: &SettleAtomic,
    sponsor: &AccountId,
    omit: Option<usize>,
) {
    let intent_hash = instruction
        .intent_hash()
        .expect("full intent once per grant set");
    for (index, movement) in instruction.movements().as_slice().iter().enumerate() {
        if Some(index) == omit {
            continue;
        }
        let mut grant_tx = block.transaction_for_fastpq_testing(Hash::new(index.to_le_bytes()));
        assert!(matches!(
            grant_tx.world.executor.clone(),
            crate::executor::Executor::Initial
        ));
        assert!(
            !crate::executor::is_initial_genesis_context(&grant_tx),
            "actual issuer policy must execute without genesis exceptions"
        );

        let permission: Permission = CanExecuteSettlement {
            debited_asset: movement.source.clone(),
            settlement_id: instruction.settlement_id().clone(),
            intent_hash,
        }
        .into();
        TxOverlay::from_instructions(vec![
            Grant::account_permission(permission, sponsor.clone()).into(),
        ])
        .apply(&mut grant_tx, movement.source.account())
        .expect("runtime executor accepts exact owner-issued consent");
        assert_eq!(grant_tx.pending_transfer_transcript_count_for_testing(), 0);
        grant_tx.apply();
    }
}

fn overlay(instruction: SettleAtomic, direct: bool) -> TxOverlay {
    let boxed = if direct {
        Box::new(instruction).into_instruction_box()
    } else {
        SettlementInstructionBox::Atomic(instruction).into()
    };
    assert_eq!(boxed.as_any().is::<SettleAtomic>(), direct);
    assert_eq!(boxed.as_any().is::<SettlementInstructionBox>(), !direct);
    TxOverlay::from_instructions(vec![boxed])
}

fn observable(state_tx: &StateTransaction<'_, '_>) -> (Vec<Vec<u8>>, usize) {
    macro_rules! capture {
        ($field:ident) => {
            norito::encode_canonical(
                &state_tx
                    .world
                    .$field
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>(),
            )
            .expect("canonical observable state")
        };
    }
    let assets = state_tx
        .world
        .assets
        .iter()
        .map(|(key, value)| (key.clone(), value.as_ref().clone()))
        .collect::<Vec<_>>();
    let events = state_tx
        .world
        .internal_event_buf
        .iter()
        .map(|event| norito::encode_canonical(event.as_ref()).expect("event bytes"))
        .collect::<Vec<_>>();
    (
        vec![
            norito::encode_canonical(&assets).expect("balances"),
            capture!(accounts),
            capture!(account_permissions),
            capture!(asset_definition_assets),
            capture!(asset_definition_asset_counts),
            capture!(assets_by_domain),
            capture!(asset_definition_nonzero_holders),
            capture!(settlement_receipts),
            norito::encode_canonical(&events).expect("event inventory"),
        ],
        state_tx.pending_transfer_transcript_count_for_testing(),
    )
}

#[test]
fn atomic_overlay_direct_and_boxed_execute_exact_owner_consents() {
    for direct in [false, true] {
        for count in [3, 255] {
            let (chain, instruction, sponsor) = fixture(count, false);
            let state = chain.state();
            let mut block = next_block(state);
            grant_consents(&mut block, &instruction, &sponsor, None);
            // Retain the finite direct-component invocation before borrowing its effects.
            // This fixture exercises overlay execution, not network input or publication.
            let mut state_tx =
                block.transaction_for_fastpq_testing(Hash::new(b"atomic-overlay-carrier"));
            assert_eq!(state_tx.pending_transfer_transcript_count_for_testing(), 0);
            let event_count = state_tx.world.internal_event_buf.len();
            overlay(instruction.clone(), direct)
                .apply(&mut state_tx, &sponsor)
                .expect("actual TxOverlay admission and Initial execution");
            assert_eq!(state_tx.pending_transfer_transcript_count_for_testing(), 1);
            assert!(state_tx.world.internal_event_buf.len() > event_count);
            let mut incoming = Quantity::zero();
            for movement in instruction.movements().as_slice() {
                incoming = incoming
                    .checked_add(&movement.quantity)
                    .expect("bounded sum");
                assert_eq!(
                    state_tx
                        .world
                        .assets
                        .get(&movement.source)
                        .expect("source remains")
                        .as_ref(),
                    &Quantity::from(1000_u32)
                        .checked_sub(&movement.quantity)
                        .expect("prefunded")
                );
            }
            let destination = instruction.movements().as_slice()[0].destination();
            assert_eq!(
                state_tx
                    .world
                    .assets
                    .get(&destination)
                    .expect("all credits")
                    .as_ref(),
                &incoming
            );
            let receipt = state_tx
                .world
                .settlement_receipts
                .get(instruction.settlement_id())
                .expect("one full receipt");
            assert_eq!(receipt.authority, sponsor);
            let SettlementDetails::Atomic(iroha_data_model::isi::AtomicSettlementDetails {
                movements,
                intent_hash,
                escrow_ids,
            }) = &receipt.details
            else {
                panic!("atomic receipt");
            };
            assert!(escrow_ids.is_empty(), "no escrow legs were signed");
            assert_eq!(
                movements,
                &instruction.movements().resolve().expect("exact scopes")
            );
            assert_eq!(
                *intent_hash,
                instruction.intent_hash().expect("full intent")
            );
            state_tx.apply();
            let expected = expected_transcript(instruction.movements().as_slice(), &sponsor);
            assert_eq!(
                block
                    .drain_transfer_transcripts()
                    .remove(&expected.batch_hash)
                    .expect("one retained settlement transcript"),
                vec![expected],
                "finite sizing corpus must match the original executed transcript"
            );
        }
    }
}

#[test]
fn atomic_overlay_final_missing_consent_rejects_before_any_movement() {
    for direct in [false, true] {
        let (chain, instruction, sponsor) = fixture(255, false);
        let state = chain.state();
        let mut block = next_block(state);
        grant_consents(&mut block, &instruction, &sponsor, Some(254));
        let mut state_tx =
            block.transaction_for_fastpq_testing(Hash::new(b"missing-final-consent"));
        let before = observable(&state_tx);
        assert_eq!(
            before.1, 0,
            "empty transcript inventory is exact, not a same-count approximation"
        );
        let error = overlay(instruction, direct)
            .apply(&mut state_tx, &sponsor)
            .expect_err("last owner consent is mandatory at actual overlay admission");
        assert!(
            matches!(&error, ValidationFail::InstructionFailed(iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(message)) if message.contains("whole-intent consent")),
            "{error}"
        );
        assert_eq!(observable(&state_tx), before);
    }
}

#[test]
fn atomic_overlay_final_scope_policy_mismatch_rejects_without_partial_execution() {
    for direct in [false, true] {
        let (chain, instruction, sponsor) = fixture(255, true);
        let state = chain.state();
        let mut block = next_block(state);
        grant_consents(&mut block, &instruction, &sponsor, None);
        let mut state_tx = block.transaction_for_fastpq_testing(Hash::new(b"final-scope-policy"));
        let before = observable(&state_tx);
        assert_eq!(before.1, 0);
        let error = overlay(instruction, direct)
            .apply(&mut state_tx, &sponsor)
            .expect_err("final exact signed bucket violates the live definition policy");
        assert!(
            matches!(&error, ValidationFail::InstructionFailed(iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(message)) if message.contains("global asset definition requires the global public balance scope")),
            "{error:?}"
        );
        assert_eq!(observable(&state_tx), before);
    }
}

#[test]
fn atomic_overlay_nonowner_cannot_issue_the_final_owner_consent() {
    let (chain, instruction, sponsor) = fixture(3, false);
    let state = chain.state();
    let mut block = next_block(state);
    let mut state_tx = block.transaction_for_fastpq_testing(Hash::new(b"nonowner-final-consent"));
    assert!(!crate::executor::is_initial_genesis_context(&state_tx));
    let source = &instruction.movements().as_slice()[2].source;
    let grant = TxOverlay::from_instructions(vec![
        Grant::account_permission(permission(&instruction, source), sponsor.clone()).into(),
    ]);
    let before = observable(&state_tx);
    assert_eq!(before.1, 0);
    let error = grant
        .apply(&mut state_tx, &sponsor)
        .expect_err("carrier cannot grant itself a foreign owner's exact consent");
    assert!(matches!(error, ValidationFail::NotPermitted(_)));
    assert_eq!(observable(&state_tx), before);
}

#[test]
fn atomic_overlay_intrinsic_capacity_rejects_without_partial_execution() {
    for direct in [false, true] {
        let (chain, instruction, sponsor) = fixture_with_source_delta_limit(255, false, 254);
        let state = chain.state();
        let mut block = next_block(state);
        grant_consents(&mut block, &instruction, &sponsor, None);
        let mut state_tx = block.transaction_for_fastpq_testing(Hash::new(b"atomic-delta-limit"));
        let before = observable(&state_tx);
        assert_eq!(before.1, 0);
        let error = overlay(instruction, direct)
            .apply(&mut state_tx, &sponsor)
            .expect_err("all 255 deltas must fit the original source owner");
        assert!(
            matches!(&error, ValidationFail::InstructionFailed(iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(message))
                if message.as_ref() == crate::fastpq::source_reservation::admission::SOURCE_INTRINSIC_REJECTION),
            "{error:?}"
        );
        assert_eq!(observable(&state_tx), before);
    }
}
