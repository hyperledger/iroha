//! Genuine original lane-history producers preserve their finite pool and decoder refusals.

use super::*;
use crate::execution_attempt::{ExecutionAttemptError as Attempt, ExecutionDeferred};
use iroha_allocation::AllocationRefusal;
use std::task::Context;

fn original_deferred<'a>(error: &'a (dyn std::error::Error + 'static)) -> &'a ExecutionDeferred {
    let Some(Attempt::Deferred(original)) = error.downcast_ref::<Attempt<io::Error>>() else {
        panic!("the original history producer erased its local refusal: {error:?}");
    };
    original
}

fn complete_release(
    original: &ExecutionDeferred,
    budget: &AllocationBudget,
    registration: &mut iroha_allocation::release::ReleaseRegistration,
) {
    let Some(AllocationRefusal::Capacity { release, .. }) = original.allocation_refusal() else {
        panic!("the original pool refusal must retain its release observation");
    };
    let wait = release.clone();
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(registration.poll_wait(&wait, &mut context).is_pending());
    let foreign = AllocationBudget::new(1);
    drop(foreign.try_reserve_bytes(1).unwrap());
    assert!(registration.poll_wait(&wait, &mut context).is_pending());
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
}

#[test]
fn original_archive_read_refusal_preserves_pool_release_and_same_lane_prefix() {
    let (chain, record, _epoch) = super::super::tests::fixed_lane_chain();
    let state = chain.state();
    let budget = state.ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let limit = budget.limit_bytes();
    let mut scan = HistoryScan::open(state, record.lane, record.incarnation)
        .unwrap()
        .unwrap();
    let genesis = chain
        .kura()
        .get_block(
            NonZeroUsize::new(1).unwrap(),
            &chain.state().ivm_execution_budget(),
        )
        .expect("original block read attempt")
        .unwrap();
    // The actual committed carrier is already selected before its original archive read.
    scan.current = Some(Clone::clone(&genesis));
    let path = chain
        .kura()
        .store_root()
        .join("native-contexts")
        .join(format!(
            "{:020}-{}.nrt",
            1,
            hex::encode(genesis.hash().as_ref()),
        ));
    let requested = usize::try_from(std::fs::metadata(&path).unwrap().len()).unwrap();
    let occupied = budget
        .try_reserve_bytes(limit - budget.reserved_bytes())
        .unwrap();
    let error = scan.complete().unwrap_err();
    let original = original_deferred(&error);
    assert!(matches!(original.allocation_refusal(),
        Some(AllocationRefusal::Capacity { requested_bytes, limit_bytes, .. })
            if *requested_bytes == requested && *limit_bytes == limit));
    complete_release(original, &budget, &mut registration);
    assert_eq!(scan.next, 1);
    assert!(!scan.completed);
    assert!(scan.read.is_some());
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        scan.current.as_ref().unwrap(),
        &genesis
    ));
    let Some(AllocationRefusal::Capacity { release, .. }) = original.allocation_refusal() else {
        unreachable!("checked original capacity");
    };
    let wait = release.clone();
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(registration.poll_wait(&wait, &mut context).is_pending());
    let retained = path.with_extension("original-source-refusal");
    std::fs::rename(&path, &retained).unwrap();
    std::fs::write(&path, b"a replacement cannot become this pending read").unwrap();
    drop(occupied);
    assert!(registration.poll_wait(&wait, &mut context).is_ready());
    assert_eq!(budget.limit_bytes(), limit);
    scan.complete().unwrap();
    let authority = scan.finish().expect("same original full prefix completes");
    assert!(authority.belongs_to(&budget));
    drop(authority);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), baseline);
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(retained, path).unwrap();
}

#[test]
fn original_certificate_projection_refusal_preserves_pool_release_and_exact_carrier() {
    let (chain, record, _epoch) = super::super::tests::fixed_lane_chain();
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let limit = budget.limit_bytes();
    let mut scan = HistoryScan::open(chain.state(), record.lane, record.incarnation)
        .unwrap()
        .unwrap();
    let genesis = chain
        .kura()
        .get_block(
            NonZeroUsize::new(1).unwrap(),
            &chain.state().ivm_execution_budget(),
        )
        .expect("original block read attempt")
        .unwrap();
    let archive = scan.archive.as_ref().unwrap();
    let genesis_bytes = archive.read_exact(1, genesis.hash()).unwrap();
    assert!(
        scan.verifier
            .push_height(Clone::clone(&genesis), genesis_bytes.as_slice())
            .unwrap()
            .is_none()
    );
    scan.genesis_bytes = Some(genesis_bytes);
    scan.next = 2;
    let original = chain
        .kura()
        .get_block(
            NonZeroUsize::new(2).unwrap(),
            &chain.state().ivm_execution_budget(),
        )
        .expect("original block read attempt")
        .unwrap();
    scan.current_bytes = Some(archive.read_exact(2, original.hash()).unwrap());
    let pointer = scan.current_bytes.as_ref().unwrap().as_slice().as_ptr();
    scan.current = Some(Clone::clone(&original));
    let occupied = budget
        .try_reserve_bytes(limit - budget.reserved_bytes())
        .unwrap();
    let error = scan.complete().unwrap_err();
    let refusal = original_deferred(&error);
    complete_release(refusal, &budget, &mut registration);
    assert_eq!(scan.next, 2);
    assert!(!scan.completed);
    assert!(scan.artifacts.is_some());
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        scan.current.as_ref().unwrap(),
        &original
    ));
    assert_eq!(
        scan.current_bytes.as_ref().unwrap().as_slice().as_ptr(),
        pointer
    );
    drop(occupied);
    assert_eq!(budget.limit_bytes(), limit);
    scan.complete().unwrap();
    let authority = scan
        .finish()
        .expect("same original certificate prefix completes");
    assert!(authority.belongs_to(&budget));
    drop(authority);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn original_lane_evidence_handoff_preserves_actual_decode_refusal_and_exact_cut() {
    let (chain, record, _epoch) = super::super::tests::npos_fixed_lane_chain_at(4);
    let state = chain.state();
    let budget = state.ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let generation = state.state_view_generation();
    let view = state.view();
    let tip = view.native_execution_tip().unwrap();
    let capture = HistoryCapture::from_view(state, &view, generation)
        .unwrap()
        .unwrap();
    let scope = LaneEvidenceScope {
        lane: record.lane,
        incarnation: record.incarnation,
        created_at: record.created_at,
        admission_parent_height: tip.height(),
        admission_parent_hash: tip.iroha_hash(),
        admission_parent_core_hash: tip.core_hash().0,
        admission_parent_result: tip.result().0,
    };
    drop(view);
    let mut scan = HistoryScan::open_for_evidence(capture, scope).unwrap();
    scan.complete().unwrap();
    let charged = budget.reserved_bytes();
    assert!(charged > baseline);
    let (scan, error) = norito::core::with_decode_limits_scope(
        norito::core::DecodeLimits::new(1024, 1, 4096, 0, 32),
        || {
            scan.finish_evidence()
                .err()
                .expect("actual original custody field refuses")
        },
    );
    let original = original_deferred(&error);
    assert_eq!(
        original.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(
        original.allocation_refusal().is_none(),
        "decoder scope has no pool release"
    );
    assert_eq!(scan.evidence_cut, Some(scope));
    assert_eq!(scan.generation(), generation);
    assert_eq!(budget.reserved_bytes(), charged);
    let context = scan
        .finish_evidence()
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    assert_eq!(context.scope, scope);
    assert!(context.budget.same_pool(&budget));
    drop(context);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn original_lane_commitment_decoder_refusal_survives_payload_and_archive_adapters() {
    use crate::query::native_receipts::lane_payload::LanePayloadError;
    use iroha_data_model::{
        block::consensus::ExecWitness,
        sumeragi_finality::{
            NativeLaneStateProof, NativeLaneStateProofError, SUMERAGI_LANE_STATE_WITNESS_KEY,
        },
    };
    let (chain, _record, _epoch) = super::super::tests::fixed_lane_chain();
    let budget = chain.state().ivm_execution_budget();
    let carrier = chain.committed(2);
    let archive = NativeContextArchive::open_existing(
        chain.kura(),
        budget.clone(),
        chain.kura().native_context_archive_max_bytes(),
    )
    .unwrap();
    let bytes = archive.read_exact(2, carrier.block_hash()).unwrap();
    let projection: crate::state::NativeExecutionProjectionV1 =
        norito::decode_canonical(bytes.as_slice()).unwrap();
    let witness = ExecWitness {
        writes: projection.ordinary_writes,
        ..ExecWitness::default()
    };
    assert_eq!(
        NativeLaneStateProof::from_witness(&witness, &budget).unwrap(),
        carrier.commitment().native_lanes
    );
    let commitment = witness
        .writes
        .iter()
        .find(|write| write.key == SUMERAGI_LANE_STATE_WITNESS_KEY)
        .unwrap();
    let defaults = norito::canonical_decode_limits(commitment.value.len());
    let limits = norito::DecodeLimits::new(
        defaults.max_sequence_elements(),
        defaults.max_field_bytes(),
        defaults.max_total_elements(),
        defaults.max_total_allocated_bytes(),
        0,
    );
    let original_pointer = commitment.value.as_ptr();
    let original_hash = HashOf::new(&witness);
    let retained = budget.reserved_bytes();
    for via_archive in [false, true] {
        let original = norito::with_decode_limits_scope(limits, || {
            NativeLaneStateProof::from_witness(&witness, &budget)
        })
        .unwrap_err();
        assert!(
            matches!(&original, NativeLaneStateProofError::Decode(error) if error.kind() == norito::core::DecodeAttemptErrorKind::EnclosingLimit)
        );
        assert!(original.is_local_refusal());
        let attempt = if via_archive {
            let error = NativeContextArchiveError::Proof(original);
            assert!(error.is_local_refusal());
            archive_error(error)
        } else {
            let error = LanePayloadError::Proof(original);
            assert!(error.is_local_refusal());
            payload_error(error)
        };
        let Attempt::Deferred(original) = attempt else {
            panic!("the history adapter must preserve the captured original decoder refusal")
        };
        assert_eq!(
            original.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(original.allocation_refusal().is_none());
        assert_eq!(commitment.value.as_ptr(), original_pointer);
        assert_eq!(HashOf::new(&witness), original_hash);
        assert_eq!(budget.reserved_bytes(), retained);
    }
    assert_eq!(
        NativeLaneStateProof::from_witness(&witness, &budget).unwrap(),
        carrier.commitment().native_lanes
    );
    assert_eq!(budget.reserved_bytes(), retained);
}
