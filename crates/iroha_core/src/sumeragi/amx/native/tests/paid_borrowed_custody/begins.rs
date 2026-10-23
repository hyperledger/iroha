//! Original successful Begin input survives replay, refused funding and final namespace checks.

use super::*;
use crate::query::native_receipts::begin_amx_relay;
use iroha_data_model::isi::sumeragi_amx::PrepareAmxV1;

#[inline(never)]
fn restarted_paid_begin() -> (Roots, CertifiedTestChain, [u8; 32]) {
    let mut roots = paid_roots();
    let transaction = roots.transaction(100, 0xB7);
    roots.approve_all(&transaction);
    let tx = transaction.id().unwrap();
    let rejected = paid_global_sign(
        &roots.global,
        [
            BeginAmxV1 {
                transaction: transaction.clone(),
            }
            .into(),
            Transfer::asset_quantity(
                AssetId::with_scope(
                    fee_asset(),
                    account(&global_config().genesis_key),
                    AssetBalanceScope::Global,
                ),
                u32::MAX,
                account(&global_config().genesis_key),
            )
            .into(),
        ],
        2_998,
    );
    let applied = paid_global_sign(&roots.global, [BeginAmxV1 { transaction }.into()], 2_999);
    assert_eq!(
        roots.global.commit_at(3_000, vec![rejected, applied]),
        vec![false, true]
    );
    let mut restored = CertifiedTestChain::start(paid_global_config()).unwrap();
    restored.replay_from(&roots.global).unwrap();
    assert_eq!(restored.height(), roots.global.height());
    assert_ne!(
        restored.kura().store_root(),
        roots.global.kura().store_root()
    );
    (roots, restored, tx)
}

fn instruction_prepare(instruction: &InstructionBox) -> &PrepareAmxV1 {
    instruction
        .as_any()
        .downcast_ref::<PrepareAmxV1>()
        .expect("funded Prepare from original Begin")
}

#[test]
fn native_amx_begin_delivery_after_restart_uses_successful_input_and_exact_registered_child() {
    // Keep unrelated State retirement fixed while measuring exact reader/proof refunds.
    // Pin before replay can retire charged generations into the shared epoch collector.
    let _state_retirement = crossbeam_epoch::pin();
    let (mut roots, restored, tx) = restarted_paid_begin();
    let tip = restored.height();
    let budget = restored.state().ivm_execution_budget();
    budget.with_deferred_refund_notifications(|_| {
        let view = restored.state().view();
        let baseline = budget.reserved_bytes();
        let mut read = begin_amx_relay(&view, tip, tx, FIRST).unwrap();
        let intent = read.complete().unwrap();
        let descriptor = *intent.descriptor();
        assert_eq!(descriptor.source_network(), restored.network_id());
        assert_eq!(descriptor.source_height(), tip);
        assert_eq!(
            descriptor.source_carrier(),
            restored.committed(tip).block().hash()
        );
        assert_eq!(
            descriptor.target_network(),
            roots.participants[0].network_id()
        );
        assert_eq!(
            descriptor.target_scope(),
            roots.participants[0]
                .state()
                .view()
                .native_execution_tip()
                .unwrap()
                .root_scope()
        );
        assert_eq!(
            descriptor.target_instance(),
            view.world()
                .sumeragi_amx()
                .dataspace(FIRST)
                .unwrap()
                .tracker
                .instance
        );
        let prepare = instruction_prepare(intent.instruction());
        assert_eq!(prepare.transaction.id().unwrap(), tx);
        assert_eq!(prepare.dataspace, FIRST);
        assert_eq!(prepare.begin.record.tx(), tx);
        let comparison_baseline = budget.reserved_bytes();
        let source = restored.committed(tip);
        let (_, signed) = source.block().external_signed_transaction_at(1).unwrap();
        let Executable::Instructions(instructions) = signed.instructions() else {
            panic!("original signed instructions");
        };
        let original = &instructions[0]
            .as_any()
            .downcast_ref::<BeginAmxV1>()
            .unwrap()
            .transaction;
        assert_eq!(&prepare.transaction, original);
        assert_ne!(
            prepare.transaction.legs.as_ptr(),
            original.legs.as_ptr(),
            "additional Prepare fields are prepaid copies of the retained original"
        );
        // This independent comparison receipt owns its decoded certified result too.
        // Retire it before checking the delivery reader's exact remaining allocation.
        drop(source);
        assert_eq!(budget.reserved_bytes(), comparison_baseline);
        assert!(intent.instruction().amx_proof_admitted_to(&budget));
        assert!(read.complete().is_err());
        let (_, instruction) = intent.into_parts();
        drop(read);
        let bytes = instruction.amx_proof_allocation_bytes().unwrap();
        assert_eq!(budget.reserved_bytes(), baseline + bytes);
        let signed = roots.participants[0].sign(&payer(), [instruction], 3_999);
        assert_eq!(
            roots.participants[0].commit_at(4_000, vec![signed]),
            vec![true]
        );
        let participant = native(&roots.participants[0]);
        assert_eq!(participant.escrows.len(), 1);
        assert_eq!(participant.escrows[0].tx, tx);
        assert_eq!(participant.escrows[0].settled, None);
        assert_eq!(
            balance(
                &roots.participants[0],
                FIRST,
                principal(),
                account(&payer())
            ),
            900_u32.into()
        );
        assert_eq!(
            balance(
                &roots.participants[0],
                FIRST,
                principal(),
                participant.custody
            ),
            100_u32.into()
        );
        assert_eq!(
            balance(
                &roots.participants[0],
                FIRST,
                principal(),
                account(&receiver())
            ),
            Quantity::zero()
        );
        assert_eq!(
            restored.height(),
            tip,
            "original Begin delivery needs no subsequent Global traffic"
        );
        drop(view);
    });
}

#[test]
fn native_amx_begin_delivery_rejects_wrong_source_height_record_and_participant() {
    let (roots, restored, tx) = restarted_paid_begin();
    assert_restarted_begin_refusals(&roots, &restored, tx);
}

// Keep the completed multi-root setup frame out of the original reader checks.
// Debug builds otherwise reserve all reader Result temporaries while constructing
// and replaying four chains, exhausting the ordinary libtest stack.
#[inline(never)]
fn assert_restarted_begin_refusals(roots: &Roots, restored: &CertifiedTestChain, tx: [u8; 32]) {
    let view = restored.state().view();
    assert!(begin_amx_relay(&view, 1, tx, FIRST).is_err());
    assert!(begin_amx_relay(&roots.participants[0].state().view(), 2, tx, FIRST).is_err());
    for (height, id, participant) in [
        (2, tx, FIRST),
        (restored.height(), [0xFE; 32], FIRST),
        (restored.height(), tx, DataSpaceId::new(999)),
    ] {
        let mut read = begin_amx_relay(&view, height, id, participant).unwrap();
        assert!(read.complete().is_err());
        assert!(read.retained_instruction().is_none());
    }
}

#[test]
fn native_amx_begin_delivery_final_namespace_refusal_preserves_original_instruction() {
    // Keep unrelated State retirement fixed while measuring exact reader/proof refunds.
    // Pin before replay can retire charged generations into the shared epoch collector.
    let _state_retirement = crossbeam_epoch::pin();
    let (_, restored, tx) = restarted_paid_begin();
    let budget = restored.state().ivm_execution_budget();
    budget.with_deferred_refund_notifications(|_| {
        let view = restored.state().view();
        let baseline = budget.reserved_bytes();
        let replacement = std::rc::Rc::new(std::cell::RefCell::new(
            IntentNamespaceReplacement::new(&restored),
        ));
        let pointers = std::rc::Rc::new(std::cell::Cell::new(None));
        let mut read = begin_amx_relay(&view, restored.height(), tx, FIRST).unwrap();
        read.probe_instruction_prepared_once({
            let replacement = replacement.clone();
            let pointers = pointers.clone();
            move |instruction| {
                let prepare = instruction_prepare(instruction);
                pointers.set(Some((
                    proof_pointers(&prepare.begin),
                    prepare.transaction.legs.as_ptr(),
                )));
                replacement.borrow_mut().replace();
            }
        });
        let refused = read.complete();
        replacement.borrow_mut().restore();
        assert!(
            refused.is_err(),
            "source namespace must be rechecked after instruction admission"
        );
        let expected = pointers.get().expect("original real Prepare instruction");
        let retained = read
            .retained_instruction()
            .expect("same instruction retained after refusal");
        assert_eq!(
            (
                proof_pointers(&instruction_prepare(retained).begin),
                instruction_prepare(retained).transaction.legs.as_ptr()
            ),
            expected
        );
        assert!(retained.amx_proof_admitted_to(&budget));
        let intent = read.complete().unwrap();
        let delivered = instruction_prepare(intent.instruction());
        assert_eq!(
            (
                proof_pointers(&delivered.begin),
                delivered.transaction.legs.as_ptr()
            ),
            expected
        );
        assert!(read.complete().is_err());
        drop(read);
        assert_eq!(
            budget.reserved_bytes(),
            baseline + intent.instruction().amx_proof_allocation_bytes().unwrap()
        );
        drop(intent);
        assert_eq!(budget.reserved_bytes(), baseline);
        drop(view);
    });
}
