//! Original native Check history failures abandon the actual signed Network output and fee.

use super::*;
use iroha_data_model::{
    isi::musubi::CheckMusubiPinOutboxV1,
    musubi::{MusubiPinOutboxCheckExpectationV1, MusubiPinOutboxCheckFloorV1},
};
use ivm::error::ExecutionDeferral;

fn check(state: &State) -> CheckMusubiPinOutboxV1 {
    let view = state.view();
    let committed = crate::sumeragi::certified_chain::committed_block(&view, 1).unwrap();
    CheckMusubiPinOutboxV1 {
        network_id: *state.network_id_ref(),
        pin_authority: ALICE_ID.clone(),
        session_id: [0x31; 32],
        inventory_digest: [0x32; 32],
        challenge: [0x33; 32],
        floor: MusubiPinOutboxCheckFloorV1 {
            height: 1,
            block_hash: *committed.block_hash().as_ref(),
            context_id: committed.id(),
        },
        expected: MusubiPinOutboxCheckExpectationV1::Absent,
    }
}

// Restore the original opened inode even when an assertion unwinds. A replaced pathname never
// becomes test authority, and the actual original bytes remain available for the retry control.
enum ChangedHistory {
    Corrupt(std::sync::Arc<Kura>),
    Removed {
        path: std::path::PathBuf,
        original: std::path::PathBuf,
    },
}
impl ChangedHistory {
    fn new(state: &State, kind: &str) -> Self {
        if kind == "corrupt" {
            state
                .kura()
                .corrupt_native_frame_for_test(std::num::NonZeroUsize::MIN);
            return Self::Corrupt(state.kura.clone());
        }
        let path = Kura::canonical_storage_path(&state.kura().store_root()).join("blocks.data");
        let original = path.with_file_name("blocks.data.pin-outbox-original");
        std::fs::rename(&path, &original).unwrap();
        let owner = Self::Removed { path, original };
        let Self::Removed { path, .. } = &owner else {
            unreachable!()
        };
        match kind {
            "missing" => {}
            #[cfg(unix)]
            "fifo" => assert!(
                std::process::Command::new("mkfifo")
                    .arg(path)
                    .status()
                    .unwrap()
                    .success()
            ),
            _ => panic!("unknown physical source control"),
        }
        owner
    }
}
impl Drop for ChangedHistory {
    fn drop(&mut self) {
        match self {
            Self::Corrupt(kura) => kura.corrupt_native_frame_for_test(std::num::NonZeroUsize::MIN),
            Self::Removed { path, original } => {
                if std::fs::symlink_metadata(&*path).is_ok() {
                    std::fs::remove_file(&*path).unwrap();
                }
                std::fs::rename(&*original, &*path).unwrap();
            }
        }
    }
}

#[test]
fn native_pin_outbox_history_failure_has_no_output_gas_fee_or_applied_overlay() {
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    for kind in ["missing", "corrupt"] {
        physical_failure_and_retry(kind);
    }
}

#[cfg(unix)]
#[test]
fn native_pin_outbox_fifo_history_defers_without_reading_or_charging() {
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    physical_failure_and_retry("fifo");
}

fn physical_failure_and_retry(kind: &str) {
    let (state, asset) = priced_fixture(None);
    let original = check(&state);
    let source = carrier(
        &state,
        vec![input(
            &state,
            vec![original.into()],
            payment(&asset, 3),
            false,
        )],
    );
    {
        let (mut block, _recording) = recorded_network_block(&state, &source);
        let before = block.committed_fragment_count();
        let changed = ChangedHistory::new(&state, kind);
        assert!(
            matches!(&(execute(&mut block, &source)), Err(ExecutionOutputAttemptError::Deferred(owner)) if owner.reason() == ExecutionDeferral::CanonicalHistoryUnavailable && owner.phase().is_none() && owner.allocation_refusal().is_none() && owner.decode_refusal().is_none() && owner.verification_refusal().is_none()),
            "{kind}"
        );
        assert_eq!(block.gas_used_in_block, 0);
        assert_eq!(block.committed_fragment_count(), before);
        assert_eq!(balance(&block, &asset, &ALICE_ID), Quantity::from(10_u32));
        assert_eq!(
            balance(&block, &asset, &iroha_test_samples::BOB_ID),
            Quantity::zero()
        );
        assert!(
            block
                .world
                .musubi_pin_outbox_high_waters
                .get(&ALICE_ID)
                .is_none()
        );
        assert!(block.retained_execution_outputs_for_test().is_err());
        assert!(matches!(
            block.execution_output_plan,
            Some(ExecutionOutputPlanState::Poisoned)
        ));
        drop(changed);
    }
    let (mut retry, _recording) = recorded_network_block(&state, &source);
    execute(&mut retry, &source).expect("same original signed source retries after local repair");
    assert!(network_row(&retry, 0).result.is_ok());
    assert!(retry.gas_used_in_block > 0);
    assert!(balance(&retry, &asset, &ALICE_ID) < Quantity::from(10_u32));
    assert!(
        retry
            .world
            .musubi_pin_outbox_high_waters
            .get(&ALICE_ID)
            .is_none()
    );
}

#[test]
fn signed_wrong_floor_hash_is_rejected_before_unavailable_history_and_charged_normally() {
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    let (state, asset) = priced_fixture(None);
    let mut wrong = check(&state);
    wrong.floor.block_hash = [0xe1; 32];
    let source = carrier(
        &state,
        vec![input(&state, vec![wrong.into()], payment(&asset, 3), false)],
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    let changed = ChangedHistory::new(&state, "missing");
    execute(&mut block, &source).expect("signed mismatch is a completed rejection");
    assert!(network_row(&block, 0).result.is_err());
    assert!(block.gas_used_in_block > 0);
    assert!(balance(&block, &asset, &ALICE_ID) < Quantity::from(10_u32));
    drop(changed);
}

#[test]
fn native_pin_outbox_rejects_actual_sealed_reveals_after_valid_commitments() {
    use iroha_data_model::{
        isi::musubi::AdvanceMusubiPinOutboxV1,
        transaction::signed::{
            SealedTransactionCommitmentPayload, SealedTransactionReveal,
            SignedSealedTransactionCommitment, compute_sealed_transaction_commitment,
        },
    };

    let state = fixture(65_536, None);
    let check = check(&state);
    let advance = AdvanceMusubiPinOutboxV1 {
        network_id: check.network_id,
        pin_authority: check.pin_authority.clone(),
        session_id: check.session_id,
        expected_revision: 0,
        expected_inventory_digest: [0; 32],
        inventory_digest: check.inventory_digest,
    };
    let mut commits = Vec::new();
    let mut reveals = Vec::new();
    for (index, instruction) in [InstructionBox::from(advance), check.into()]
        .into_iter()
        .enumerate()
    {
        let TransactionEntrypoint::External(signed) = input(
            &state,
            vec![instruction],
            FeePaymentIntent::authority(vec![], None),
            false,
        ) else {
            unreachable!()
        };
        let salt = [u8::try_from(index + 1).unwrap(); 32];
        let commitment = compute_sealed_transaction_commitment(&state.network_id, &signed, salt, 9);
        let commit = SignedSealedTransactionCommitment::sign(
            SealedTransactionCommitmentPayload::new(
                state.network_id,
                ALICE_ID.clone(),
                commitment,
                3,
                9,
                None,
            ),
            ALICE_KEYPAIR.private_key(),
        );
        commit.verify_signature().unwrap();
        commits.push(TransactionEntrypoint::SealedCommitment(commit));
        reveals.push(TransactionEntrypoint::SealedReveal(
            SealedTransactionReveal::new(commitment, signed, salt),
        ));
    }
    let source = carrier(&state, commits);
    let (mut committing, committing_recording) = recorded_network_block(&state, &source);
    execute(&mut committing, &source).unwrap();
    for index in 0..2 {
        assert!(network_row(&committing, index).result.is_ok());
    }
    // Keep only the writes from the genuine signed commitment execution. No caller creates
    // pending commitment records or invents finalized history for the revealed instruction.
    committing.commit_world_overlay_for_testing().unwrap();
    drop(committing_recording);
    let mut builder = BlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(3).unwrap(),
        Some(source.hash()),
        None,
        u64::try_from(source.header().creation_time().as_millis()).unwrap() + 1,
        0,
    ));
    for reveal in &reveals {
        let TransactionEntrypoint::SealedReveal(reveal) = reveal else {
            unreachable!()
        };
        builder.push_sealed_transaction_reveal(reveal.clone());
    }
    builder.set_execution_context(Some(
        iroha_data_model::block::BlockExecutionContextBundle::new(
            reveals
                .iter()
                .map(|input| {
                    iroha_data_model::block::ExternalExecutionContext::new(
                        input.hash(),
                        iroha_model_base::topology::LaneId::SINGLE,
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    )
                })
                .collect(),
        ),
    ));
    let source = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
    let (mut block, _recording) = recorded_network_block(&state, &source);
    execute(&mut block, &source).unwrap();
    for index in 0..2 {
        let result = &network_row(&block, index).result;
        assert!(result.is_err());
        assert!(
            format!("{result:?}")
                .contains("Musubi pin-outbox requires a sole direct signed External"),
            "{result:?}"
        );
    }
    assert!(
        block
            .world
            .musubi_pin_outbox_high_waters
            .get(&ALICE_ID)
            .is_none()
    );
}
