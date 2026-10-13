//! Authenticated borrowed paid AMX admission retains the original persisted proof graph.
//!
//! The original proof graph is physically funded, retained by canonical instruction storage
//! and shared by actual signed/accepted/block clones. This original borrowed control remains
//! mandatory; ordinary envelope/decoder allocations and whole-node relaying are separate gates.

#[path = "paid_borrowed_custody/approval_proof.rs"]
mod approval_proof;
#[path = "paid_borrowed_custody/read_roles.rs"]
mod read_roles;

use super::*;
use crate::{
    state::{StateReadOnly, WorldReadOnly},
    tx::AcceptedTransaction,
};
use iroha_data_model::{
    nexus::FeeDebitSource,
    sumeragi_amx::{AllocatedAmxRecordProofV1, AmxRecordProofV1},
    transaction::{
        Executable, FeeChargeKind, FeeChargeLimit, FeePaymentIntent, SignedTransaction,
        TransactionBuilder, TransactionEntrypoint,
    },
};
use iroha_primitives::time::TimeSource;
use std::{sync::Arc, time::Duration};

const GLOBAL_FEE: u32 = 2;
const GLOBAL_INITIAL: u32 = 1_000_000;

fn paid_global_config() -> TestChainConfig {
    let mut config = global_config();
    let domain = DomainId::try_new(
        "fees",
        iroha_config::parameters::defaults::nexus::DEFAULT_DATASPACE_ALIAS,
    )
    .unwrap();
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.settlement_mode = iroha_config::parameters::actual::NexusFeeSettlementMode::Direct;
    nexus.fees.fee_asset_id = fee_asset().canonical_address();
    nexus.fees.fee_sink_account_id = account(&config.genesis_key).to_string();
    nexus.fees.base_fee = GLOBAL_FEE.into();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    config.nexus = Some(nexus);
    config.genesis_instructions.extend([
        Register::domain(iroha_data_model::domain::Domain::new(domain.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            fee_asset(),
            "AMX global fee",
            AssetBalancePolicy::Global,
            Some(domain),
        ))
        .into(),
        Mint::asset_quantity(
            GLOBAL_INITIAL,
            AssetId::with_scope(
                fee_asset(),
                account(&config.genesis_key),
                AssetBalanceScope::Global,
            ),
        )
        .into(),
        Mint::asset_quantity(
            GLOBAL_INITIAL,
            AssetId::with_scope(
                fee_asset(),
                account(&KeyPair::from_seed(vec![0xCC; 32], Algorithm::Ed25519)),
                AssetBalanceScope::Global,
            ),
        )
        .into(),
    ]);
    config
}

fn paid_global_sign(
    chain: &CertifiedTestChain,
    instructions: impl IntoIterator<Item = InstructionBox>,
    created_ms: u64,
) -> SignedTransaction {
    let key = global_config().genesis_key;
    let intent = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            fee_asset(),
            GLOBAL_FEE.into(),
        )],
        None,
    );
    let mut builder = TransactionBuilder::new(chain.network_id(), account(&key), intent);
    builder.set_creation_time(Duration::from_millis(created_ms));
    // Move the original proof into the sole ordinary instruction graph: no builder clone,
    // second decoder, DTO clone, or accounting wrapper between the reader and admission.
    let signed = builder
        .with_instructions(instructions)
        .sign(key.private_key());
    let view = chain.state().view();
    let quote = crate::executor::quote_nexus_fee_admission(
        view.world(),
        view.nexus(),
        view.pipeline(),
        &view.zk().gas,
        &signed,
        created_ms,
        crate::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
            .expect("original committed fixture time"),
        chain.height() + 1,
        Some(DataSpaceId::UNIVERSAL),
    )
    .expect("the original signed fee policy admits this genuinely funded paid input");
    assert_eq!(quote.debit_source, FeeDebitSource::Account(account(&key)));
    assert_eq!(quote.charges.len(), 1);
    assert_eq!(quote.charges[0].kind, FeeChargeKind::Nexus);
    assert_eq!(quote.charges[0].asset_definition_id, fee_asset());
    assert_eq!(quote.charges[0].max_bound, GLOBAL_FEE.into());
    signed
        .payload()
        .validate_fee_payment_intent()
        .expect("original canonical finite signed fee intent");
    assert_eq!(signed.fee_payment_intent().charge_limits().len(), 1);
    assert_eq!(
        signed.fee_payment_intent().charge_limits()[0].max_amount,
        GLOBAL_FEE.into()
    );
    signed
}

fn global_paid_images(chain: &CertifiedTestChain, paid_inputs: u32) {
    let view = chain.state().view();
    let expected = GLOBAL_INITIAL - GLOBAL_FEE * paid_inputs;
    let clock = account(&KeyPair::from_seed(vec![0xCC; 32], Algorithm::Ed25519));
    let clock_asset = AssetId::with_scope(fee_asset(), clock, AssetBalanceScope::Global);
    assert_eq!(
        view.world().assets().get(&clock_asset).unwrap().as_ref(),
        &Quantity::from(GLOBAL_INITIAL)
    );
    let owner = account(&global_config().genesis_key);
    let asset = AssetId::with_scope(fee_asset(), owner, AssetBalanceScope::Global);
    assert_eq!(
        view.world().assets().get(&asset).unwrap().as_ref(),
        &Quantity::from(expected)
    );
    assert_eq!(
        view.world()
            .asset_definition(&fee_asset())
            .unwrap()
            .total_quantity(),
        &Quantity::from(GLOBAL_INITIAL + expected),
        "actual mandatory direct fees burn supply, without crediting a replacement owner",
    );
}

#[inline(never)]
fn paid_roots() -> Roots {
    let mut global = CertifiedTestChain::start(paid_global_config()).unwrap();
    {
        let view = global.state().view();
        let definition = view.world().asset_definition(&fee_asset()).unwrap();
        assert_eq!(
            definition.balance_scope_policy(),
            AssetBalancePolicy::Global
        );
        let home = definition
            .owning_domain()
            .as_ref()
            .expect("signed fee asset home");
        assert_eq!(
            crate::sns::resolve_active_dataspace_id_by_alias(
                view.world(),
                &view.nexus().dataspace_catalog,
                home.dataspace().as_ref(),
                global.committed(1).block_time_ms(),
            )
            .expect("the actual signed catalog authenticates the fee asset home"),
            DataSpaceId::UNIVERSAL,
        );
    }
    assert_eq!(
        global.validators().len(),
        4,
        "original signed global committee"
    );
    let h2 = paid_global_sign(
        &global,
        [iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "authenticate paid AMX global genesis".into(),
        )
        .into()],
        1_499,
    );
    assert_eq!(global.commit_at(1_500, vec![h2]), vec![true]);
    global_paid_images(&global, 1);
    let participants =
        [FIRST, SECOND].map(|id| CertifiedTestChain::start(private_config(&global, id)).unwrap());
    assert_ne!(participants[0].network_id(), participants[1].network_id());
    assert_ne!(
        participants[0].kura().store_root(),
        participants[1].kura().store_root()
    );
    assert!(
        !participants[0]
            .state()
            .ivm_execution_budget()
            .same_pool(&participants[1].state().ivm_execution_budget())
    );
    for participant in &participants {
        assert_ne!(participant.network_id(), global.network_id());
        assert_ne!(participant.kura().store_root(), global.kura().store_root());
        assert!(
            !participant
                .state()
                .ivm_execution_budget()
                .same_pool(&global.state().ivm_execution_budget())
        );
        assert_eq!(
            participant.validators().len(),
            4,
            "original signed private committee"
        );
    }
    let registrations = [FIRST, SECOND]
        .into_iter()
        .zip(&participants)
        .map(|(id, chain)| {
            RegisterAmxDataspaceV1 {
                dataspace: id,
                instance: chain.instance().0,
                anchor: norito::encode_canonical(
                    &authenticated_genesis(chain.genesis())
                        .map(|genesis| genesis.into_parts().0)
                        .unwrap(),
                )
                .unwrap(),
            }
            .into()
        });
    let signed = paid_global_sign(&global, registrations, 1_999);
    assert_eq!(global.commit_at(2_000, vec![signed]), vec![true]);
    global_paid_images(&global, 2);
    Roots {
        global,
        participants,
    }
}

type ProofPointers = (*const u8, *const u8, *const u8, *const [u8; 32]);

fn proof_pointers(proof: &AmxRecordProofV1) -> ProofPointers {
    assert!(!proof.block.consensus_header.is_empty());
    assert!(!proof.block.commit_qc.is_empty());
    assert!(!proof.block.result_preimage.is_empty());
    assert!(
        !proof.write.siblings.is_empty(),
        "the actual full write tree has real siblings"
    );
    (
        proof.block.consensus_header.as_ptr(),
        proof.block.commit_qc.as_ptr(),
        proof.block.result_preimage.as_ptr(),
        proof.write.siblings.as_ptr(),
    )
}

fn retained_relay<'accepted>(
    accepted: &'accepted AcceptedTransaction<'_>,
) -> &'accepted AmxRecordProofV1 {
    let signed = accepted
        .external()
        .expect("ordinary signed external entrypoint");
    let Executable::Instructions(instructions) = signed.instructions() else {
        panic!("one actual native relay instruction");
    };
    assert_eq!(instructions.len(), 1);
    &instructions[0]
        .as_any()
        .downcast_ref::<RelayAmxPreparedV1>()
        .expect("the actual closed Prepared relay instruction")
        .proof
}

fn authenticate_original_prepared(
    roots: &Roots,
    index: usize,
    proof: &AmxRecordProofV1,
    tx: [u8; 32],
) {
    let chain = &roots.participants[index];
    let id = [FIRST, SECOND][index];
    assert!(matches!(&proof.record, AmxRecordV1::Prepared(record)
        if record.tx == tx && record.participant == id && matches!(&record.vote, AmxVoteV1::Yes(_))));
    let committed = chain.committed(chain.height());
    let certificate = committed.block().commit_certificate().unwrap();
    assert_eq!(
        proof.block.consensus_header.as_slice(),
        certificate.consensus_header()
    );
    assert_eq!(proof.block.commit_qc.as_slice(), certificate.commit_qc());
    assert_eq!(
        proof.block.result_preimage.as_slice(),
        certificate.result_preimage()
    );
    let view = roots.global.state().view();
    let registration = view.world().sumeragi_amx().dataspace(id).unwrap();
    assert_eq!(registration.tracker.instance, chain.instance().0);
    let verified = registration
        .tracker
        .verify_record(proof)
        .expect("genuine exact registered source certificate and writes");
    assert_eq!(verified.height, chain.height());
    assert!(
        verified.height >= 2,
        "original certified non-genesis persisted Prepare"
    );
    proof_pointers(proof);
}

#[inline(never)]
fn paid_original_relay() -> (Roots, AcceptedTransaction<'static>, ProofPointers, [u8; 32]) {
    let mut roots = paid_roots();
    let transaction = roots.transaction(100, 0x63);
    roots.approve_all(&transaction);
    let tx = transaction.id().unwrap();
    let signed = paid_global_sign(
        &roots.global,
        [BeginAmxV1 {
            transaction: transaction.clone(),
        }
        .into()],
        2_999,
    );
    assert_eq!(roots.global.commit_at(3_000, vec![signed]), vec![true]);
    global_paid_images(&roots.global, 3);
    let begin = super::super::super::amx_record_proof(
        &roots.global.state().view(),
        roots.global.height(),
        AmxRecordKind::Begin,
        tx,
    )
    .complete()
    .unwrap()
    .unwrap();
    // Existing preparation is customer-authorized, paid, applied and persisted by the real
    // Worker/Kura/archive path. The reader authenticates the full original write root.
    let first = roots.prepare(0, &transaction, &begin);
    let second = roots.prepare(1, &transaction, &begin);
    authenticate_original_prepared(&roots, 0, first.canonical(), tx);
    authenticate_original_prepared(&roots, 1, second.canonical(), tx);
    for (id, chain) in [FIRST, SECOND].into_iter().zip(&roots.participants) {
        assert_eq!(
            balance(chain, id, principal(), account(&payer())),
            900_u32.into()
        );
        assert_eq!(
            balance(chain, id, principal(), native(chain).custody),
            100_u32.into()
        );
        assert_eq!(
            balance(chain, id, principal(), account(&receiver())),
            Quantity::zero()
        );
        assert!(balance(chain, id, fee_asset(), account(&payer())) < 1_000_000_u32.into());
    }
    // Prove genuine paid target execution before the new clone assertion can fail. This
    // sibling remains only a Yes vote; it cannot manufacture a Decision for the first proof.
    let sibling = paid_global_sign(
        &roots.global,
        [second
            .into_relay()
            .complete(&roots.participants[1].state().ivm_execution_budget())
            .unwrap()],
        4_499,
    );
    assert_eq!(roots.global.commit_at(4_500, vec![sibling]), vec![true]);
    global_paid_images(&roots.global, 4);
    {
        let view = roots.global.state().view();
        let entry = view.world().sumeragi_amx().transaction(&tx).unwrap();
        assert_eq!(entry.yes.len(), 1);
        assert_eq!(entry.yes[0].participant, SECOND);
        assert!(entry.decided.is_none());
    }
    let original = proof_pointers(first.canonical());
    let signed = paid_global_sign(
        &roots.global,
        [first
            .into_relay()
            .complete(&roots.participants[0].state().ivm_execution_budget())
            .unwrap()],
        4_999,
    );
    let (_, clock) = TimeSource::new_mock(Duration::from_millis(5_000));
    let accepted = {
        let view = roots.global.state().view();
        AcceptedTransaction::accept_with_time_source(
            signed,
            &roots.global.network_id(),
            Duration::from_secs(1),
            view.world().parameters().transaction(),
            &view.crypto(),
            &clock,
        )
        .expect("ordinary original network/signature/TTL/NTS transaction admission")
    };
    assert_eq!(
        proof_pointers(retained_relay(&accepted)),
        original,
        "move-only reader-to-signer-to-admission setup"
    );
    (roots, accepted, original, tx)
}

fn commit_original_relay(roots: &mut Roots, accepted: AcceptedTransaction<'static>, tx: [u8; 32]) {
    let TransactionEntrypoint::External(signed) = accepted.into_entrypoint() else {
        panic!("ordinary external relay remained unchanged");
    };
    assert_eq!(roots.global.commit_at(5_000, vec![signed]), vec![true]);
    global_paid_images(&roots.global, 5);
    let decision = super::super::super::amx_record_proof(
        &roots.global.state().view(),
        roots.global.height(),
        AmxRecordKind::Decision,
        tx,
    )
    .complete()
    .unwrap()
    .unwrap();
    assert!(
        matches!(decision.canonical().record, AmxRecordV1::Decision(value)
        if value.tx == tx && value.outcome == AmxOutcomeV1::Commit)
    );
}

#[test]
fn native_amx_persisted_paid_borrowed_prepared_proof_clone_retains_original_graph_and_lifetime() {
    // This fixture executes three actual native roots; use the node's existing
    // configured execution thread, with no stack override or changed resource limit.
    fn original_paid_control() {
        let (mut roots, accepted, original, tx) = paid_original_relay();
        let original_wire = accepted.entrypoint_bytes();
        let original_hash = accepted.hash_as_entrypoint();
        let entrypoint = accepted.into_entrypoint();
        let source_pointer = std::ptr::from_ref(&entrypoint);
        let borrowed =
            {
                let view = roots.global.state().view();
                AcceptedTransaction::accept_borrowed_entrypoint_at_time(
            &entrypoint,
            &roots.global.network_id(),
            Duration::from_secs(1),
            view.world().parameters().transaction(),
            &view.crypto(),
            Duration::from_millis(5_000),
        )
        .expect("the original paid source passes actual borrowed envelope/signature/TTL admission")
            };
        assert_eq!(std::ptr::from_ref(borrowed.entrypoint()), source_pointer);
        assert_eq!(proof_pointers(retained_relay(&borrowed)), original);
        assert_eq!(borrowed.hash_as_entrypoint(), original_hash);
        assert_eq!(
            borrowed.validation_time(),
            Some(Duration::from_millis(5_000))
        );
        let source_wire = borrowed.entrypoint_bytes();
        assert_eq!(source_wire.as_slice(), original_wire.as_slice());
        let clone = borrowed.clone();
        assert_eq!(clone.hash_as_entrypoint(), original_hash);
        assert_eq!(clone.entrypoint(), borrowed.entrypoint());
        assert_eq!(
            norito::encode_canonical(clone.entrypoint()).unwrap(),
            source_wire.as_slice()
        );
        assert!(
            Arc::ptr_eq(&clone.entrypoint_bytes(), &source_wire),
            "the borrowed source's wire cache remains its genuine original"
        );
        assert_eq!(clone.validation_time(), borrowed.validation_time());
        assert_eq!(
            std::ptr::from_ref(clone.entrypoint()),
            source_pointer,
            "cloning a borrowed accepted source must preserve its original owner and lifetime",
        );
        assert_eq!(
            proof_pointers(retained_relay(&clone)),
            original,
            "borrowed AcceptedTransaction clone detached the genuine persisted Prepared proof allocations",
        );
        drop(borrowed);
        assert_eq!(std::ptr::from_ref(clone.entrypoint()), source_pointer);
        assert_eq!(
            proof_pointers(retained_relay(&clone)),
            original,
            "the remaining borrow keeps the original graph while its source owner remains live"
        );
        assert_eq!(clone.hash_as_entrypoint(), original_hash);
        assert_eq!(
            clone.entrypoint_bytes().as_slice(),
            original_wire.as_slice()
        );
        global_paid_images(&roots.global, 4);
        // End every borrowed wrapper before moving the exact source into owned admission.
        // No into_owned conversion of a borrow, replacement decoder or proof clone is used.
        drop(clone);
        let owned = {
            let view = roots.global.state().view();
            AcceptedTransaction::accept_entrypoint_at_time(
            entrypoint,
            &roots.global.network_id(),
            Duration::from_secs(1),
            view.world().parameters().transaction(),
            &view.crypto(),
            Duration::from_millis(5_000),
        )
        .expect(
            "the exact original paid owner passes actual owned envelope/signature/TTL admission",
        )
        };
        assert_eq!(owned.hash_as_entrypoint(), original_hash);
        assert_eq!(
            owned.entrypoint_bytes().as_slice(),
            original_wire.as_slice()
        );
        assert_eq!(proof_pointers(retained_relay(&owned)), original);
        commit_original_relay(&mut roots, owned, tx);
    }
    let thread =
        crate::sumeragi::threads::sumeragi_thread_builder("sumeragi-paid-amx-custody-test")
            .spawn(original_paid_control)
            .expect("spawn paid AMX on the configured native execution thread");
    if let Err(original) = thread.join() {
        std::panic::resume_unwind(original);
    }
}

#[test]
fn native_amx_original_begin_instruction_refusal_preserves_same_pool_and_last_owner_ledger() {
    fn original_control() {
        use iroha_allocation::{AllocationBudget, AllocationRefusal};
        use iroha_data_model::isi::AmxInstructionAdmissionErrorV1;
        let mut roots = paid_roots();
        let transaction = roots.transaction(100, 0x71);
        roots.approve_all(&transaction);
        let tx = transaction.id().unwrap();
        let signed = paid_global_sign(
            &roots.global,
            [BeginAmxV1 {
                transaction: transaction.clone(),
            }
            .into()],
            2_999,
        );
        assert_eq!(roots.global.commit_at(3_000, vec![signed]), vec![true]);
        global_paid_images(&roots.global, 3);
        let proof = super::super::super::amx_record_proof(
            &roots.global.state().view(),
            roots.global.height(),
            AmxRecordKind::Begin,
            tx,
        )
        .complete()
        .unwrap()
        .unwrap();
        let pool = roots.global.state().ivm_execution_budget();
        let original = proof_pointers(proof.canonical());
        let AmxRecordV1::Begin(begin) = &proof.canonical().record else {
            panic!("original Begin");
        };
        let participants = begin.participants.as_ptr();
        let proof_bytes = proof.allocation_bytes().unwrap();
        let before = pool.reserved_bytes();
        let foreign = AllocationBudget::new(pool.limit_bytes());
        let mut pending = proof.into_prepare(FIRST, &transaction);
        let refusal = pending.complete(&foreign).unwrap_err();
        assert!(matches!(refusal, AmxInstructionAdmissionErrorV1::Source));
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(
            proof_pointers(pending.source().unwrap().canonical()),
            original
        );
        assert_eq!(pool.reserved_bytes(), before);
        let mut registration = crate::unit_test_support::release_registration(&pool);
        let baseline = pool.reserved_bytes();
        let pressure = pool
            .try_reserve_bytes(pool.limit_bytes() - baseline)
            .unwrap();
        let refusal = pending.complete(&pool).unwrap_err();
        let AmxInstructionAdmissionErrorV1::Admission(AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        }) = refusal
        else {
            panic!("original instruction owner capacity refusal: {refusal:?}");
        };
        assert_eq!(reserved_bytes, limit_bytes);
        assert_eq!(
            pool.try_reserve_bytes(requested_bytes).unwrap_err(),
            AllocationRefusal::Capacity {
                requested_bytes,
                reserved_bytes,
                limit_bytes,
                release: release.clone(),
            }
        );
        assert_eq!(
            proof_pointers(pending.source().unwrap().canonical()),
            original
        );
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(registration.poll_wait(&release, &mut context).is_pending());
        drop(pressure);
        assert!(registration.poll_wait(&release, &mut context).is_ready());
        assert_eq!(pool.reserved_bytes(), baseline);
        let configured_limit = pool.limit_bytes();
        pool.set_limit_bytes(0);
        // This executes the actual streamed canonical-ID validation before refusing all new
        // backing. Existing proof fields remain charged; an intrinsic refusal grants no credit.
        let refusal = pending.complete(&pool).unwrap_err();
        assert!(matches!(refusal, AmxInstructionAdmissionErrorV1::Admission(
            AllocationRefusal::ExceedsLimit { requested_bytes: bytes, limit_bytes: 0 }
        ) if bytes == requested_bytes));
        assert_eq!(
            proof_pointers(pending.source().unwrap().canonical()),
            original
        );
        assert_eq!(pool.reserved_bytes(), baseline);
        pool.set_limit_bytes(configured_limit);
        let instruction = pending.complete(&pool).unwrap();
        assert!(pending.source().is_none());
        assert!(matches!(
            pending.complete(&pool),
            Err(AmxInstructionAdmissionErrorV1::Source)
        ));
        assert!(instruction.amx_proof_admitted_to(&pool));
        assert_eq!(
            instruction.amx_proof_allocation_bytes(),
            Some(proof_bytes + requested_bytes)
        );
        assert_eq!(pool.reserved_bytes(), baseline + requested_bytes);
        let typed = instruction.as_any().downcast_ref::<PrepareAmxV1>().unwrap();
        assert_eq!(typed.dataspace, FIRST);
        assert_eq!(typed.transaction, transaction);
        assert_eq!(proof_pointers(&typed.begin), original);
        let AmxRecordV1::Begin(begin) = &typed.begin.record else {
            panic!("same original Begin");
        };
        assert_eq!(begin.participants.as_ptr(), participants);
        for (owned, source) in typed.transaction.legs.iter().zip(&transaction.legs) {
            assert_eq!(owned.payload.len(), source.payload.len());
            assert_eq!(owned.payload.capacity(), source.payload.len());
            assert_ne!(
                owned.payload.as_ptr(),
                source.payload.as_ptr(),
                "new Prepare backing was prepaid, not borrowed past its lifetime"
            );
        }
        // This deliberately bare counterfactual checks the unchanged registered type and wire.
        // It is not an admission owner; it is destroyed before exact original-pool checks.
        let bare: InstructionBox = typed.clone().into();
        assert_eq!(bare, instruction);
        assert_eq!(
            norito::encode_canonical(&bare).unwrap(),
            norito::encode_canonical(&instruction).unwrap()
        );
        drop(bare);
        let clone = instruction.clone();
        assert_eq!(instruction, clone);
        assert_eq!(
            norito::encode_canonical(&instruction).unwrap(),
            norito::encode_canonical(&clone).unwrap()
        );
        assert_eq!(
            proof_pointers(&clone.as_any().downcast_ref::<PrepareAmxV1>().unwrap().begin),
            original
        );
        assert_eq!(pool.reserved_bytes(), baseline + requested_bytes);
        drop(instruction);
        assert_eq!(
            pool.reserved_bytes(),
            baseline + requested_bytes,
            "all real fields remain charged through the last InstructionBox"
        );
        drop(clone);
        assert_eq!(
            pool.reserved_bytes(),
            baseline - proof_bytes,
            "fields drop before every proof/Prepare/shared-shell charge refunds exactly once"
        );
        drop(registration);
        assert_eq!(pool.reserved_bytes(), before - proof_bytes);
    }
    let thread = crate::sumeragi::threads::sumeragi_thread_builder(
        "sumeragi-amx-original-instruction-owner",
    )
    .spawn(original_control)
    .expect("configured native execution thread");
    if let Err(original) = thread.join() {
        std::panic::resume_unwind(original);
    }
}

#[test]
fn native_amx_paid_owned_queue_and_payload_clones_retain_original_proof_graph_and_last_owner_charge()
 {
    fn original_control() {
        use crate::queue::Queue;
        use std::num::NonZeroUsize;
        let (roots, accepted, original, _tx) = paid_original_relay();
        let pool = roots.participants[0].state().ivm_execution_budget();
        let Executable::Instructions(instructions) = accepted.external().unwrap().instructions()
        else {
            panic!("original paid instructions");
        };
        assert_eq!(instructions.len(), 1);
        let retained_bytes = instructions[0].amx_proof_allocation_bytes().unwrap();
        assert!(instructions[0].amx_proof_admitted_to(&pool));
        let baseline = pool.reserved_bytes();
        let original_hash = accepted.hash_as_entrypoint();
        let wire = accepted.entrypoint_bytes();
        let owned = accepted.clone();
        assert_eq!(proof_pointers(retained_relay(&owned)), original);
        assert_eq!(owned.hash_as_entrypoint(), original_hash);
        assert_eq!(owned.entrypoint_bytes().as_slice(), wire.as_slice());
        assert_eq!(
            pool.reserved_bytes(),
            baseline,
            "owned admission clone shares the actual funded proof"
        );
        let (_, clock) = TimeSource::new_mock(Duration::from_millis(5_000));
        let queue = Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &clock,
        ));
        queue
            .push(accepted, roots.global.state().view())
            .expect("actual target-root ordinary paid queue admission");
        assert_eq!(queue.active_len(), 1);
        let view = roots.global.state().view();
        let enumerated = queue.all_transactions(&view).collect::<Vec<_>>();
        let pending = queue
            .bounded_pending_snapshot_for_testing(&view, NonZeroUsize::new(1).unwrap())
            .unwrap();
        assert_eq!(enumerated.len(), 1);
        assert_eq!(pending.len(), 1);
        for candidate in [&owned, &enumerated[0], &pending[0]] {
            assert_eq!(candidate.hash_as_entrypoint(), original_hash);
            assert_eq!(candidate.entrypoint_bytes().as_slice(), wire.as_slice());
            assert_eq!(proof_pointers(retained_relay(candidate)), original);
        }
        drop(view);
        let proposal = roots
            .global
            .proposal_entrypoints(vec![pending[0].clone().into_entrypoint()]);
        let source = proposal
            .network_entrypoints()
            .find(|entrypoint| entrypoint.hash() == original_hash)
            .unwrap();
        let TransactionEntrypoint::External(signed) = source else {
            panic!("original ordinary payload input");
        };
        let Executable::Instructions(instructions) = signed.instructions() else {
            panic!("original retained instructions");
        };
        let relay = instructions[0]
            .as_any()
            .downcast_ref::<RelayAmxPreparedV1>()
            .unwrap();
        assert_eq!(
            proof_pointers(&relay.proof),
            original,
            "actual production payload assembly retains the original graph"
        );
        assert!(instructions[0].amx_proof_admitted_to(&pool));
        let cloned = proposal.clone();
        let source = cloned
            .network_entrypoints()
            .find(|entrypoint| entrypoint.hash() == original_hash)
            .unwrap();
        let TransactionEntrypoint::External(signed) = source else {
            panic!("same ordinary payload input");
        };
        let Executable::Instructions(instructions) = signed.instructions() else {
            panic!("same retained instructions");
        };
        assert_eq!(
            proof_pointers(
                &instructions[0]
                    .as_any()
                    .downcast_ref::<RelayAmxPreparedV1>()
                    .unwrap()
                    .proof
            ),
            original
        );
        queue.clear_all();
        assert_eq!(queue.active_len(), 0);
        drop(queue);
        drop(enumerated);
        drop(pending);
        drop(owned);
        assert_eq!(
            pool.reserved_bytes(),
            baseline,
            "retiring queue metadata cannot refund this retained source graph"
        );
        drop(proposal);
        assert_eq!(
            pool.reserved_bytes(),
            baseline,
            "last real cloned payload still owns complete proof backing"
        );
        drop(cloned);
        assert_eq!(
            pool.reserved_bytes(),
            baseline - retained_bytes,
            "exact original proof ledger refunds after the last actual payload owner"
        );
        global_paid_images(&roots.global, 4);
        // This control assembles real pending paid work and tests its final cancellation owner.
        // The existing borrowed control separately certifies, executes, charges and settles it.
    }
    let thread =
        crate::sumeragi::threads::sumeragi_thread_builder("sumeragi-amx-paid-payload-owner")
            .spawn(original_control)
            .expect("configured native execution thread");
    if let Err(original) = thread.join() {
        std::panic::resume_unwind(original);
    }
}

pub(super) fn with_paid_prepare_retry_fixture(
    test: impl FnOnce(&CertifiedTestChain, InstructionBox, KeyPair),
) {
    with_paid_prepare_retry_fixture_with_receiver(false, test);
}

pub(super) fn with_paid_multisig_prepare_retry_fixture(
    test: impl FnOnce(&CertifiedTestChain, InstructionBox, KeyPair),
) {
    with_paid_prepare_retry_fixture_with_receiver(true, test);
}

fn with_paid_prepare_retry_fixture_with_receiver(
    multisig_receiver: bool,
    test: impl FnOnce(&CertifiedTestChain, InstructionBox, KeyPair),
) {
    let mut roots = paid_roots();
    let mut transaction = roots.transaction(100, 0x64);
    if multisig_receiver {
        use iroha_data_model::account::{MultisigMember, MultisigPolicy};
        // Change the canonical receiver before transaction identity, the real
        // signed Begin, its certified write proof and the paid Prepare are made.
        let leg = transaction
            .legs
            .iter_mut()
            .find(|leg| leg.dataspace == FIRST)
            .unwrap();
        let mut transfer = norito::decode_canonical::<AmxTransferLegV1>(&leg.payload).unwrap();
        transfer.destination = AccountId::new_multisig(
            MultisigPolicy::new(
                2,
                vec![
                    MultisigMember::new(payer().public_key().clone(), 1).unwrap(),
                    MultisigMember::new(
                        KeyPair::from_seed(vec![0xD4; 32], Algorithm::Ed25519)
                            .public_key()
                            .clone(),
                        1,
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        );
        leg.payload = norito::encode_canonical(&transfer).unwrap();
    }
    roots.approve_all(&transaction);
    let tx = transaction.id().unwrap();
    let signed = paid_global_sign(
        &roots.global,
        [BeginAmxV1 {
            transaction: transaction.clone(),
        }
        .into()],
        2_999,
    );
    assert_eq!(roots.global.commit_at(3_000, vec![signed]), vec![true]);
    global_paid_images(&roots.global, 3);
    let begin = super::super::super::amx_record_proof(
        &roots.global.state().view(),
        roots.global.height(),
        AmxRecordKind::Begin,
        tx,
    )
    .complete()
    .unwrap()
    .unwrap();
    let instruction = begin
        .into_prepare(FIRST, &transaction)
        .complete(&roots.global.state().ivm_execution_budget())
        .unwrap();
    test(&roots.participants[0], instruction, payer());
}

/// Genuine paid begins and expiry Decision settle/prune a No vote in one private block.
pub(super) fn with_paid_prepare_pruning_fixture(
    test: impl FnOnce(&CertifiedTestChain, [InstructionBox; 3], KeyPair, [[u8; 32]; 2]),
) {
    let mut roots = paid_roots();
    let mut expired = roots.transaction(2_000, 0x65);
    expired.deadline = 5;
    roots.approve_all(&expired);
    let expired_tx = expired.id().unwrap();
    let signed = paid_global_sign(
        &roots.global,
        [BeginAmxV1 {
            transaction: expired.clone(),
        }
        .into()],
        2_999,
    );
    assert_eq!(roots.global.commit_at(3_000, vec![signed]), vec![true]);
    let begin = super::super::super::amx_record_proof(
        &roots.global.state().view(),
        4,
        AmxRecordKind::Begin,
        expired_tx,
    )
    .complete()
    .unwrap()
    .unwrap();
    let expired_instruction = begin
        .into_prepare(FIRST, &expired)
        .complete(&roots.global.state().ivm_execution_budget())
        .unwrap();
    let clock = paid_global_sign(
        &roots.global,
        [iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "actual paid AMX deadline horizon".into(),
        )
        .into()],
        3_999,
    );
    assert_eq!(roots.global.commit_at(4_000, vec![clock]), vec![true]);
    let next = roots.transaction(100, 0x66);
    roots.approve_all(&next);
    let next_tx = next.id().unwrap();
    let signed = paid_global_sign(
        &roots.global,
        [BeginAmxV1 {
            transaction: next.clone(),
        }
        .into()],
        4_999,
    );
    assert_eq!(roots.global.commit_at(5_000, vec![signed]), vec![true]);
    global_paid_images(&roots.global, 5);
    assert_eq!(roots.global.height(), 6);
    let begin = super::super::super::amx_record_proof(
        &roots.global.state().view(),
        6,
        AmxRecordKind::Begin,
        next_tx,
    )
    .complete()
    .unwrap()
    .unwrap();
    let next_instruction = begin
        .into_prepare(FIRST, &next)
        .complete(&roots.global.state().ivm_execution_budget())
        .unwrap();
    let decision = super::super::super::amx_record_proof(
        &roots.global.state().view(),
        6,
        AmxRecordKind::Decision,
        expired_tx,
    )
    .complete()
    .unwrap()
    .unwrap();
    assert!(matches!(decision.canonical().record,
        iroha_data_model::sumeragi_amx::AmxRecordV1::Decision(value)
        if value.outcome == iroha_data_model::sumeragi_amx::AmxOutcomeV1::Abort));
    let settle = decision
        .into_settle(FIRST)
        .complete(&roots.global.state().ivm_execution_budget())
        .unwrap();
    test(
        &roots.participants[0],
        [expired_instruction, settle, next_instruction],
        payer(),
        [expired_tx, next_tx],
    );
}

// Genuine paid commit and native replay, never injected coordinates or a fabricated proof.
#[inline(never)]
fn with_restarted_paid_prepared_intent(
    test: impl FnOnce(&CertifiedTestChain, &AllocatedAmxRecordProofV1, [u8; 32]),
) {
    let mut roots = paid_roots();
    let transaction = roots.transaction(100, 0x78);
    roots.approve_all(&transaction);
    let tx = transaction.id().unwrap();
    let signed = paid_global_sign(
        &roots.global,
        [BeginAmxV1 {
            transaction: transaction.clone(),
        }
        .into()],
        2_999,
    );
    assert_eq!(roots.global.commit_at(3_000, vec![signed]), vec![true]);
    global_paid_images(&roots.global, 3);
    let begin = super::super::super::amx_record_proof(
        &roots.global.state().view(),
        roots.global.height(),
        AmxRecordKind::Begin,
        tx,
    )
    .complete()
    .unwrap()
    .unwrap();
    let original = roots.prepare(0, &transaction, &begin);
    authenticate_original_prepared(&roots, 0, original.canonical(), tx);
    let mut restored = CertifiedTestChain::start(private_config(&roots.global, FIRST)).unwrap();
    restored.replay_from(&roots.participants[0]).unwrap();
    assert_eq!(restored.height(), roots.participants[0].height());
    assert_eq!(restored.network_id(), roots.participants[0].network_id());
    assert_ne!(
        restored.kura().store_root(),
        roots.participants[0].kura().store_root()
    );
    assert!(
        !restored
            .state()
            .ivm_execution_budget()
            .same_pool(&roots.participants[0].state().ivm_execution_budget())
    );
    assert_eq!(
        std::fs::read(prepared_intent_path(&restored)).unwrap(),
        std::fs::read(prepared_intent_path(&roots.participants[0])).unwrap(),
        "actual native replay regenerates the same unresolved durable intent"
    );
    test(&restored, &original, tx);
}
fn prepared_intent_path(chain: &CertifiedTestChain) -> std::path::PathBuf {
    let hash = chain.committed(chain.height()).block().hash();
    chain
        .kura()
        .store_root()
        .join("native-contexts")
        .join(format!(
            "{:020}-{}.ami",
            chain.height(),
            hex::encode(hash.as_ref())
        ))
}
fn instruction_relay(instruction: &InstructionBox) -> &AmxRecordProofV1 {
    &instruction
        .as_any()
        .downcast_ref::<RelayAmxPreparedV1>()
        .expect("actual move-only Prepared relay instruction")
        .proof
}

#[test]
fn restarted_paid_intent_delivers_exact_native_prepared_relay_and_refunds_original_pool() {
    with_restarted_paid_prepared_intent(|chain, expected, tx| {
        let budget = chain.state().ivm_execution_budget();
        budget.with_deferred_refund_notifications(|_| {
            let view = chain.state().view();
            let baseline = budget.reserved_bytes();
            let source_path = prepared_intent_path(chain);
            let original = std::fs::read(&source_path).unwrap();
            let mut read = crate::query::native_receipts::prepared_amx_relays(&view, chain.height()).unwrap();
            let intent = read.complete_next().unwrap().expect("actual restarted committed Prepared row");
            let descriptor = *intent.descriptor();
            assert_eq!(descriptor.source_network(), chain.network_id());
            assert_eq!(descriptor.source_height(), chain.height());
            assert_eq!(descriptor.source_carrier(), chain.committed(chain.height()).block().hash());
            assert_eq!(descriptor.source(), crate::query::native_receipts::NativeAmxRelaySourceV1::Record { key: expected.canonical().record.witness_key() });
            assert_eq!(descriptor.source_scope(), view.native_execution_tip().unwrap().root_scope());
            let parent = view.world().sumeragi_amx_participant().authenticated_parent_source(&budget).unwrap();
            assert_eq!(descriptor.target_network(), parent.participant.global.current.network_id);
            assert_eq!(descriptor.target_scope(), iroha_data_model::block::consensus::SumeragiRootScope::Global);
            assert_eq!(descriptor.target_instance(), parent.participant.global.instance);
            let original_graph = proof_pointers(instruction_relay(intent.instruction()));
            let (moved_descriptor, instruction) = intent.into_parts();
            assert_eq!(moved_descriptor, descriptor);
            assert_eq!(proof_pointers(instruction_relay(&instruction)), original_graph,
                "the service receives the same original graph without decode or replacement");
            let relay = instruction_relay(&instruction);
            assert_eq!(relay, expected.canonical(), "same genuine native certificate, record and original write path");
            assert_eq!(relay.record.tx(), tx);
            assert!(instruction.amx_proof_admitted_to(&budget));
            let bytes = instruction.amx_proof_allocation_bytes().unwrap();
            assert!(bytes > 0 && budget.reserved_bytes() >= baseline + original.len() + bytes,
                "actual intent bytes and complete proof/instruction backing remain simultaneously funded");
            assert!(read.complete_next().unwrap().is_none(), "every distinct original row delivered exactly once");
            assert!(read.complete_next().is_err(), "completed selection cannot silently restart");
            assert_eq!(std::fs::read(source_path).unwrap(), original, "delivery neither signs nor acknowledges/removes durable intent");
            drop(read);
            assert!(instruction.amx_proof_admitted_to(&budget));
            assert_eq!(budget.reserved_bytes(), baseline + bytes, "the delivered original graph owns its exact remaining charge");
            drop(instruction);
            assert_eq!(budget.reserved_bytes(), baseline, "original proof and intent backing refund on explicit retirement");
            drop(view);
        });
    });
}

struct IntentNamespaceReplacement {
    original: std::path::PathBuf,
    held: std::path::PathBuf,
    replaced: bool,
}
impl IntentNamespaceReplacement {
    fn new(chain: &CertifiedTestChain) -> Self {
        Self {
            original: chain.kura().store_root().join("native-contexts"),
            held: chain
                .kura()
                .store_root()
                .join("held-original-intent-namespace"),
            replaced: false,
        }
    }
    fn replace(&mut self) {
        std::fs::rename(&self.original, &self.held).unwrap();
        std::fs::create_dir(&self.original).unwrap();
        self.replaced = true;
    }
    fn restore(&mut self) {
        if self.replaced {
            std::fs::remove_dir(&self.original).unwrap();
            std::fs::rename(&self.held, &self.original).unwrap();
            self.replaced = false;
        }
    }
}
impl Drop for IntentNamespaceReplacement {
    fn drop(&mut self) {
        self.restore();
    }
}

#[test]
fn restarted_paid_intent_final_namespace_refusal_retains_exact_funded_instruction_until_original_retry()
 {
    use crate::query::native_context_archive::NativeContextArchiveError;
    use crate::query::native_receipts::{
        NativeAmxPreparedRelayErrorV1 as Error, NativeAmxPreparedRelayPollV1 as Poll,
    };
    with_restarted_paid_prepared_intent(|chain, expected, _| {
        let budget = chain.state().ivm_execution_budget();
        budget.with_deferred_refund_notifications(|_| {
            let view = chain.state().view();
            let baseline = budget.reserved_bytes();
            let replacement = std::rc::Rc::new(std::cell::RefCell::new(IntentNamespaceReplacement::new(chain)));
            let observed = std::rc::Rc::new(std::cell::Cell::new(None));
            let mut read = crate::query::native_receipts::prepared_amx_relays(&view, chain.height()).unwrap();
            read.probe_instruction_prepared_once({ let replacement = replacement.clone(); let observed = observed.clone(); move |instruction| {
                observed.set(Some(proof_pointers(instruction_relay(instruction))));
                replacement.borrow_mut().replace();
            }});
            let refused = read.complete_next();
            let retained_pointer = read.acquired_frame().unwrap().as_ptr();
            let retained_bytes = read.acquired_frame().unwrap().to_vec();
            let original_pointers = observed.get().expect("real instruction admission completed before the source join");
            let retained = budget.reserved_bytes();
            // Restore before any assertion, including the mutation's intentional failed assertion.
            replacement.borrow_mut().restore();
            assert!(matches!(refused, Err(Error::Archive(NativeContextArchiveError::Io(ref cause))) if cause.kind() == std::io::ErrorKind::Other && cause.to_string() == "native context record identity changed"),
                "completed restarted intent must retain exact funded relay through final original namespace refusal; got {refused:?}");
            let instruction = read.retained_instruction().expect("source refusal retains complete instruction");
            assert!(instruction.amx_proof_admitted_to(&budget));
            assert_eq!(proof_pointers(instruction_relay(instruction)), original_pointers);
            assert!(retained > baseline);
            let Poll::Relay(delivered) = read.poll().unwrap() else { panic!("same original instruction must complete after genuine namespace recovery"); };
            let (_, delivered) = delivered.into_parts();
            assert_eq!(proof_pointers(instruction_relay(&delivered)), original_pointers);
            assert_eq!(instruction_relay(&delivered), expected.canonical());
            assert_eq!(read.acquired_frame().unwrap().as_ptr(), retained_pointer);
            assert_eq!(read.acquired_frame().unwrap(), retained_bytes);
            // Successful delivery retires the original proof reader's .nrt frame,
            // full witness and certified prefix. Only the .ami frame and delivered
            // instruction retain charges; the source guard above retains both unchanged.
            let delivered_bytes = delivered.amx_proof_allocation_bytes().unwrap();
            let after_delivery = baseline + retained_bytes.len() + delivered_bytes;
            assert_eq!(
                budget.reserved_bytes(),
                after_delivery,
                "the exact original intent frame and delivered instruction remain funded",
            );
            assert!(
                retained > after_delivery,
                "successful delivery retires the original proof reader backing",
            );
            drop(read); drop(delivered);
            assert_eq!(budget.reserved_bytes(), baseline);
            drop(view);
        });
    });
}

#[test]
fn restarted_paid_intent_original_pool_refusal_keeps_frame_and_selected_source_without_reread() {
    use crate::execution_attempt::ExecutionAttemptError;
    use crate::query::native_receipts::{
        NativeAmxPreparedRelayErrorV1 as Error, NativeAmxPreparedRelayPollV1 as Poll,
        NativeAmxRecordProofErrorV1,
    };
    // Replay retires charged State Cell generations through the process-wide
    // epoch collector. Keep that separate original custody fixed before creating
    // the fixture, so each exact ledger delta below measures this reader and
    // instruction, not a concurrent retirement of older State generations.
    let retirement_pin = crossbeam_epoch::pin();
    with_restarted_paid_prepared_intent(|chain, expected, _| {
        let budget = chain.state().ivm_execution_budget();
        budget.with_deferred_refund_notifications(|_| {
            let view = chain.state().view();
            let baseline = budget.reserved_bytes();
            let mut read = crate::query::native_receipts::prepared_amx_relays(&view, chain.height()).unwrap();
            while !read.acquired_frame_is_complete() { assert!(matches!(read.poll().unwrap(), Poll::Pending)); }
            let bytes = read.acquired_frame().unwrap().to_vec();
            let pointer = read.acquired_frame().unwrap().as_ptr();
            let before_decode = budget.reserved_bytes();
            let no_depth = norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0);
            let refused = norito::core::with_decode_limits_scope(no_depth, || read.poll());
            assert!(matches!(refused, Err(Error::Decode(ref cause)) if cause.kind() == norito::core::DecodeAttemptErrorKind::EnclosingLimit),
                "actual restarted intent decoding must retain captured original depth refusal, got {refused:?}");
            assert_eq!(read.acquired_frame().unwrap().as_ptr(), pointer);
            assert_eq!(read.acquired_frame().unwrap(), bytes);
            assert_eq!(budget.reserved_bytes(), before_decode);
            let limit = budget.limit_bytes();
            let blocker = budget.try_reserve_bytes(limit - budget.reserved_bytes()).unwrap();
            let before = budget.reserved_bytes();
            let iroha_allocation::AllocationRefusal::Capacity { release: original_release, .. } = budget.try_reserve_bytes(1).unwrap_err() else {
                panic!("genuine occupied original pool supplies its release source");
            };
            let refused = read.poll();
            assert!(matches!(&refused, Err(Error::Proof(NativeAmxRecordProofErrorV1::Chain(ExecutionAttemptError::Deferred(cause))))
                if matches!(cause.allocation_refusal(), Some(iroha_allocation::AllocationRefusal::Capacity { reserved_bytes, limit_bytes, release, .. })
                    if *reserved_bytes == before && *limit_bytes == limit && *release == original_release)),
                "original proof acquisition must retain typed actual pool Capacity, got {refused:?}");
            assert_eq!(read.acquired_frame().unwrap().as_ptr(), pointer);
            assert_eq!(read.acquired_frame().unwrap(), bytes);
            assert_eq!(budget.reserved_bytes(), before);
            drop(blocker);
            let (_, instruction) = read.complete_next().unwrap().unwrap().into_parts();
            assert!(instruction.amx_proof_admitted_to(&budget));
            assert_eq!(instruction_relay(&instruction), expected.canonical());
            assert_eq!(read.acquired_frame().unwrap().as_ptr(), pointer);
            assert_eq!(read.acquired_frame().unwrap(), bytes);
            let instruction_bytes = instruction.amx_proof_allocation_bytes().unwrap();
            assert_eq!(
                budget.reserved_bytes(),
                baseline + bytes.len() + instruction_bytes,
                "only the original intent frame and delivered instruction remain funded",
            );
            drop(read);
            assert_eq!(
                budget.reserved_bytes(),
                baseline + instruction_bytes,
                "reader retirement refunds exactly its original frame",
            );
            drop(instruction);
            assert_eq!(budget.reserved_bytes(), baseline);
            drop(view);
        });
    });
    drop(retirement_pin);
}

#[test]
fn restarted_paid_intent_rejects_substituted_authority_carrier_and_execution_claims() {
    use crate::query::native_context_archive::prepared_intent_test_helpers::rewrite_claims;
    use crate::query::native_receipts::NativeAmxPreparedRelayErrorV1 as Error;
    with_restarted_paid_prepared_intent(|chain, _, _| {
        let budget = chain.state().ivm_execution_budget();
        budget.with_deferred_refund_notifications(|_| {
            let view = chain.state().view();
            let path = prepared_intent_path(chain);
            let original = std::fs::read(&path).unwrap();
            let baseline = budget.reserved_bytes();
            for variant in 0..3 {
                let changed = rewrite_claims(&original, variant);
                assert_ne!(
                    changed, original,
                    "negative must alter the actual canonical source"
                );
                std::fs::write(&path, changed).unwrap();
                let mut read =
                    crate::query::native_receipts::prepared_amx_relays(&view, chain.height())
                        .unwrap();
                let result = read.complete_next();
                std::fs::write(&path, &original).unwrap();
                match variant {
                    0 => assert!(
                        matches!(result, Err(Error::Decode(_))),
                        "nonzero intent byte never supplies outbound authority"
                    ),
                    1 => assert!(
                        matches!(result, Err(Error::Source(_))),
                        "captured carrier selection cannot come from file claims"
                    ),
                    _ => assert!(
                        matches!(result, Err(Error::Source(_))),
                        "canonical intent still requires actual original certified write root"
                    ),
                }
                drop(read);
                assert_eq!(budget.reserved_bytes(), baseline);
            }
            let mut pristine =
                crate::query::native_receipts::prepared_amx_relays(&view, chain.height()).unwrap();
            let (_, delivered) = pristine.complete_next().unwrap().unwrap().into_parts();
            assert!(delivered.amx_proof_admitted_to(&budget));
            drop(pristine);
            drop(delivered);
            assert_eq!(budget.reserved_bytes(), baseline);
            drop(view);
        });
    });
}

#[test]
fn restarted_paid_intent_refuses_authenticated_row_subset_before_any_delivery() {
    use crate::query::native_context_archive::prepared_intent_test_helpers::one_row_subset;
    use crate::query::native_receipts::NativeAmxPreparedRelayErrorV1 as Error;
    let mut roots = paid_roots();
    let transactions = [roots.transaction(40, 0x79), roots.transaction(60, 0x7A)];
    for transaction in &transactions {
        roots.approve_all(transaction);
    }
    let signed = paid_global_sign(
        &roots.global,
        transactions.iter().map(|transaction| {
            BeginAmxV1 {
                transaction: transaction.clone(),
            }
            .into()
        }),
        2_999,
    );
    assert_eq!(roots.global.commit_at(3_000, vec![signed]), vec![true]);
    global_paid_images(&roots.global, 3);
    let prepares: Vec<_> = transactions
        .iter()
        .map(|transaction| {
            super::super::super::amx_record_proof(
                &roots.global.state().view(),
                roots.global.height(),
                AmxRecordKind::Begin,
                transaction.id().unwrap(),
            )
            .complete()
            .unwrap()
            .unwrap()
            .into_prepare(FIRST, transaction)
            .complete(&roots.global.state().ivm_execution_budget())
            .unwrap()
        })
        .collect();
    let signed = roots.participants[0].sign(&payer(), prepares, 3_999);
    assert_eq!(
        roots.participants[0].commit_at(4_000, vec![signed]),
        vec![true]
    );
    let expected = transactions.each_ref().map(|transaction| {
        super::super::super::amx_record_proof(
            &roots.participants[0].state().view(),
            roots.participants[0].height(),
            AmxRecordKind::Prepared,
            transaction.id().unwrap(),
        )
        .complete()
        .unwrap()
        .unwrap()
    });
    for (proof, transaction) in expected.iter().zip(&transactions) {
        authenticate_original_prepared(&roots, 0, proof.canonical(), transaction.id().unwrap());
    }
    let mut restored = CertifiedTestChain::start(private_config(&roots.global, FIRST)).unwrap();
    restored.replay_from(&roots.participants[0]).unwrap();
    assert_eq!(restored.height(), roots.participants[0].height());
    let path = prepared_intent_path(&restored);
    let original = std::fs::read(&path).unwrap();
    assert_eq!(
        original,
        std::fs::read(prepared_intent_path(&roots.participants[0])).unwrap()
    );
    let subset = one_row_subset(&original);
    assert_ne!(
        subset, original,
        "canonical subset must alter the actual two-row source"
    );
    let budget = restored.state().ivm_execution_budget();
    budget.with_deferred_refund_notifications(|_| {
        let view = restored.state().view();
        let baseline = budget.reserved_bytes();
        std::fs::write(&path, subset).unwrap();
        let mut omitted = crate::query::native_receipts::prepared_amx_relays(&view, restored.height()).unwrap();
        let refused = omitted.complete_next();
        // Restore even on the mutation's intentional failure; no bad fixture escapes.
        std::fs::write(&path, &original).unwrap();
        assert!(matches!(refused, Err(Error::Source("intent omits original certified Prepared writes"))),
            "restarted canonical intent must match every authenticated Prepared row before first delivery; got {refused:?}");
        assert!(omitted.retained_instruction().is_none());
        drop(omitted);
        assert_eq!(budget.reserved_bytes(), baseline);
        let mut complete = crate::query::native_receipts::prepared_amx_relays(&view, restored.height()).unwrap();
        let (first_descriptor, first) = complete.complete_next().unwrap().unwrap().into_parts();
        let (second_descriptor, second) = complete.complete_next().unwrap().unwrap().into_parts();
        assert_ne!(first_descriptor.source(), second_descriptor.source());
        assert_ne!(instruction_relay(&first).record.tx(), instruction_relay(&second).record.tx());
        for original in &expected {
            assert!([instruction_relay(&first), instruction_relay(&second)].into_iter().any(|delivered| delivered == original.canonical()));
        }
        assert!(complete.complete_next().unwrap().is_none());
        assert!(first.amx_proof_admitted_to(&budget) && second.amx_proof_admitted_to(&budget));
        drop(complete); drop(first); drop(second);
        assert_eq!(budget.reserved_bytes(), baseline);
        drop(view);
    });
}

#[inline(never)]
fn restarted_paid_decision() -> (Roots, CertifiedTestChain, [u8; 32], u64) {
    let (mut roots, accepted, _, tx) = paid_original_relay();
    let begin_height = roots
        .global
        .state()
        .view()
        .world()
        .sumeragi_amx()
        .transaction(&tx)
        .unwrap()
        .begun_at;
    commit_original_relay(&mut roots, accepted, tx);
    let mut restored = CertifiedTestChain::start(paid_global_config()).unwrap();
    restored.replay_from(&roots.global).unwrap();
    assert_eq!(restored.height(), roots.global.height());
    assert_ne!(
        restored.kura().store_root(),
        roots.global.kura().store_root()
    );
    (roots, restored, tx, begin_height)
}

fn instruction_decision(instruction: &InstructionBox) -> &AmxRecordProofV1 {
    &instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::sumeragi_amx::SettleAmxV1>()
        .expect("actual funded Decision delivery")
        .decision
}

#[test]
fn native_amx_decision_delivery_after_restart_settles_exact_registered_child_at_final_tip() {
    use crate::query::native_receipts::decision_amx_relay;
    let (mut roots, restored, tx, begin_height) = restarted_paid_decision();
    let tip = restored.height();
    let budget = restored.state().ivm_execution_budget();
    budget.with_deferred_refund_notifications(|_| {
        let view = restored.state().view();
        let baseline = budget.reserved_bytes();
        let admitted = decision_amx_relay(&view, begin_height, tip, tx, FIRST).unwrap();
        let job_bytes = budget.reserved_bytes() - baseline;
        assert!(
            job_bytes > 0,
            "retained Decision readers use the original pool"
        );
        drop(admitted);
        assert_eq!(budget.reserved_bytes(), baseline);
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - baseline - job_bytes + 1)
            .unwrap();
        assert!(
            matches!(
                decision_amx_relay(&view, begin_height, tip, tx, FIRST),
                Err(crate::query::native_receipts::NativeAmxDecisionRelayErrorV1::Allocation(
                    iroha_allocation::ChargedBufferError::Admission(
                        iroha_allocation::AllocationRefusal::Capacity { requested_bytes, .. }
                    )
                )) if requested_bytes == job_bytes
            ),
            "Decision delivery must admit both original readers before acquiring a source"
        );
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), baseline);
        let mut read = decision_amx_relay(&view, begin_height, tip, tx, FIRST).unwrap();
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
        assert_ne!(
            descriptor.target_network(),
            roots.participants[1].network_id()
        );
        let pointers = proof_pointers(instruction_decision(intent.instruction()));
        let (_, instruction) = intent.into_parts();
        assert_eq!(proof_pointers(instruction_decision(&instruction)), pointers);
        assert!(instruction.amx_proof_admitted_to(&budget));
        assert!(
            read.complete().is_err(),
            "one original delivery cannot be issued twice"
        );
        drop(read);
        let bytes = instruction.amx_proof_allocation_bytes().unwrap();
        assert_eq!(budget.reserved_bytes(), baseline + bytes);
        let signed = roots.participants[0].sign(&payer(), [instruction], 5_999);
        assert_eq!(
            roots.participants[0].commit_at(6_000, vec![signed]),
            vec![true]
        );
        let participant = native(&roots.participants[0]);
        assert_eq!(participant.escrows[0].settled, Some(AmxOutcomeV1::Commit));
        assert_eq!(
            balance(
                &roots.participants[0],
                FIRST,
                principal(),
                participant.custody
            ),
            Quantity::zero()
        );
        assert_eq!(
            balance(
                &roots.participants[0],
                FIRST,
                principal(),
                account(&receiver())
            ),
            100_u32.into()
        );
        assert_eq!(
            restored.height(),
            tip,
            "Decision proof needs no later Global traffic"
        );
        drop(view);
    });
}

#[test]
fn native_amx_decision_delivery_rejects_absent_begin_wrong_participant_and_foreign_root() {
    use crate::query::native_receipts::decision_amx_relay;
    let (roots, restored, tx, begin_height) = restarted_paid_decision();
    let view = restored.state().view();
    let tip = restored.height();
    assert!(decision_amx_relay(&view, tip, begin_height, tx, FIRST).is_err());
    assert!(
        decision_amx_relay(
            &roots.participants[0].state().view(),
            begin_height,
            tip,
            tx,
            FIRST
        )
        .is_err()
    );
    for (begin, decision, id, participant) in [
        (tip, tip, tx, FIRST),
        (begin_height, begin_height, tx, FIRST),
        (begin_height, tip, [0xFE; 32], FIRST),
        (begin_height, tip, tx, DataSpaceId::new(999)),
    ] {
        let mut read = decision_amx_relay(&view, begin, decision, id, participant).unwrap();
        assert!(
            read.complete().is_err(),
            "claimed coordinates never authorize a delivery"
        );
        assert!(read.retained_instruction().is_none());
    }
}

#[test]
fn native_amx_decision_delivery_final_namespace_refusal_preserves_original_instruction() {
    use crate::query::native_receipts::decision_amx_relay;
    let (_, restored, tx, begin_height) = restarted_paid_decision();
    let budget = restored.state().ivm_execution_budget();
    budget.with_deferred_refund_notifications(|_| {
        let view = restored.state().view();
        let baseline = budget.reserved_bytes();
        let replacement = std::rc::Rc::new(std::cell::RefCell::new(
            IntentNamespaceReplacement::new(&restored),
        ));
        let pointers = std::rc::Rc::new(std::cell::Cell::new(None));
        let mut read =
            decision_amx_relay(&view, begin_height, restored.height(), tx, FIRST).unwrap();
        read.probe_instruction_prepared_once({
            let replacement = replacement.clone();
            let pointers = pointers.clone();
            move |instruction| {
                pointers.set(Some(proof_pointers(instruction_decision(instruction))));
                replacement.borrow_mut().replace();
            }
        });
        let refused = read.complete();
        replacement.borrow_mut().restore();
        assert!(
            refused.is_err(),
            "Decision delivery must recheck original namespace after instruction admission"
        );
        let expected = pointers.get().expect("real original instruction admission");
        let retained = read
            .retained_instruction()
            .expect("original instruction retained on refusal");
        assert_eq!(proof_pointers(instruction_decision(retained)), expected);
        assert!(retained.amx_proof_admitted_to(&budget));
        let intent = read.complete().unwrap();
        assert_eq!(
            proof_pointers(instruction_decision(intent.instruction())),
            expected
        );
        assert!(read.complete().is_err());
        drop(read);
        let bytes = intent.instruction().amx_proof_allocation_bytes().unwrap();
        assert_eq!(budget.reserved_bytes(), baseline + bytes);
        drop(intent);
        assert_eq!(budget.reserved_bytes(), baseline);
        drop(view);
    });
}

#[path = "paid_borrowed_custody/discovery.rs"]
mod discovery;

#[path = "paid_borrowed_custody/route_discovery.rs"]
mod route_discovery;

#[path = "paid_borrowed_custody/begins.rs"]
mod begins;

#[path = "paid_borrowed_custody/handoffs.rs"]
mod handoffs;

#[path = "paid_borrowed_custody/authorization.rs"]
mod authorization;

#[path = "paid_borrowed_custody/idle_expiry.rs"]
mod idle_expiry;

#[path = "paid_borrowed_custody/expiry_recovery.rs"]
mod expiry_recovery;

/// Exact paid Global Begin input before any provisional execution.
pub(super) fn with_paid_global_begin_fixture(
    test: impl FnOnce(&CertifiedTestChain, SignedTransaction),
) {
    let roots = paid_roots();
    let transaction = roots.transaction(100, 0xD8);
    let created_ms = roots
        .global
        .committed(roots.global.height())
        .block_time_ms()
        + roots
            .global
            .state()
            .view()
            .world()
            .parameters()
            .sumeragi()
            .block_cadence_ms()
            .get()
        - 1;
    let signed = paid_global_sign(
        &roots.global,
        [BeginAmxV1 { transaction }.into()],
        created_ms,
    );
    test(&roots.global, signed);
}

#[path = "paid_borrowed_custody/time_expiry.rs"]
mod time_expiry;
