//! Canonical graph parity, actual nested layouts and original-prefix retry controls.

use super::*;
use crate::account::{
    AccountController, MultisigMember, MultisigPolicy,
    prepared_decode::{MemberParts, MembersDestination},
};
use iroha_allocation::{AllocationRefusal, ChargedBuffer, release::ReleaseRegistration};
use iroha_crypto::PublicKey;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_model_base::domain::DomainId;
use norito::core::{DecodeBudgetContext, DecodeLimits, SequenceSpan};
use std::{
    alloc::Layout,
    task::{Context, Poll, Waker},
};

// The ordinary indirect caller owns only a synchronous decoder attempt. These
// existing parity/cumulative-work tests exercise that same one-shot lifecycle;
// the actual retained Pending owner is tested separately below and in Worker.
struct OneShotLegDecode<'source> {
    source: &'source [u8],
    budget: &'source AllocationBudget,
}
impl<'source> OneShotLegDecode<'source> {
    fn new(source: &'source [u8], budget: &'source AllocationBudget) -> Self {
        Self { source, budget }
    }
    fn original_source(&self) -> &'source [u8] {
        self.source
    }
    fn try_decode(&self) -> Result<AllocatedAmxTransferLegV1, Error> {
        PendingAmxTransferLegDecodeV1::new(self.source, self.budget).try_decode(self.source)
    }
    fn try_decode_retained(&self) -> Result<CompletedAmxTransferLegDecodeV1, Error> {
        PendingAmxTransferLegDecodeV1::new(self.source, self.budget)
            .try_decode_retained(self.source)
    }
}
fn original_span_bytes(leg: &AmxTransferLegV1) -> usize {
    [leg.source.account(), &leg.destination]
        .iter()
        .map(|account| match account.controller() {
            AccountController::Single(_) => 0,
            AccountController::Multisig(policy) => {
                Layout::array::<SequenceSpan>(policy.members().len())
                    .unwrap()
                    .size()
            }
        })
        .sum()
}

fn key(seed: u8) -> PublicKey {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
        .public_key()
        .clone()
}
fn single(seed: u8) -> AccountId {
    AccountId::new(key(seed))
}
fn multisig(seed: u8) -> AccountId {
    AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(key(seed), 1).unwrap(),
                MultisigMember::new(key(seed + 1), 2).unwrap(),
            ],
        )
        .unwrap(),
    )
}
fn leg(source: AccountId, destination: AccountId, amount: Quantity) -> AmxTransferLegV1 {
    AmxTransferLegV1 {
        source: AssetId::with_scope(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("native", "amx").unwrap(),
                "currency".parse().unwrap(),
            ),
            source,
            AssetBalanceScope::Dataspace(DataSpaceId::new(u64::MAX)),
        ),
        destination,
        amount,
    }
}
fn actual_controller_layouts(account: &AccountId) -> usize {
    match account.controller() {
        AccountController::Single(key) => key.retained_allocation_layout().size(),
        AccountController::Multisig(policy) => {
            let count = policy.members().len();
            Layout::array::<MultisigMember>(count).unwrap().size()
                + Layout::array::<AllocationCharge>(count).unwrap().size()
                + policy
                    .members()
                    .iter()
                    .map(|member| member.public_key().retained_allocation_layout().size())
                    .sum::<usize>()
        }
    }
}
fn exact_retained(leg: &AmxTransferLegV1) -> usize {
    actual_controller_layouts(leg.source.account())
        + actual_controller_layouts(&leg.destination)
        + leg.amount.admission_clone_layout().unwrap().size()
}
fn controls() -> usize {
    PreparedDecodeWorkspace::allocation_layouts()
        .iter()
        .map(Layout::size)
        .sum()
}
fn registration() -> ReleaseRegistration {
    let layout = ReleaseRegistration::allocation_layout();
    let pool = AllocationBudget::new(layout.size());
    let mut original = pool.try_reserve(layout).unwrap();
    ReleaseRegistration::from_reservation(&mut original).unwrap()
}

#[test]
fn funded_native_leg_matches_ordinary_canonical_single_multisig_uuid_scope_and_digits() {
    for (source, destination) in [
        (single(1), single(3)),
        (multisig(1), single(5)),
        (single(1), multisig(5)),
        (multisig(1), multisig(5)),
    ] {
        for amount in [
            Quantity::from(0_u32),
            Quantity::from(17_u32),
            Quantity::from(u128::MAX),
        ] {
            let original = leg(source.clone(), destination.clone(), amount);
            let bytes = norito::encode_canonical(&original).unwrap();
            let ordinary = norito::decode_canonical::<AmxTransferLegV1>(&bytes).unwrap();
            let expected = exact_retained(&ordinary);
            // Span scratch is real transient storage and must coexist with the
            // partially built controller. It is absent from the final graph.
            let spans = original_span_bytes(&original);
            let pool = AllocationBudget::new(expected + spans + controls());
            let foreign = AllocationBudget::new(expected + spans + controls());
            let pending = OneShotLegDecode::new(&bytes, &pool);
            assert!(core::ptr::eq(
                pending.original_source().as_ptr(),
                bytes.as_ptr()
            ));
            let decoded = pending.try_decode().unwrap();
            assert_eq!(decoded.canonical(), &ordinary);
            assert_eq!(
                norito::encode_canonical(decoded.canonical()).unwrap(),
                bytes
            );
            assert!(decoded.belongs_to(&pool));
            assert!(!decoded.belongs_to(&foreign));
            assert_eq!(decoded.allocation_bytes(), Some(expected));
            assert_eq!(pool.reserved_bytes(), expected);
            assert_eq!(
                decoded
                    .canonical()
                    .amount
                    .mantissa()
                    .admission_clone_layout()
                    .unwrap(),
                ordinary.amount.mantissa().admission_clone_layout().unwrap()
            );
            let key_sum = |account: &AccountId| actual_controller_layouts(account);
            assert_eq!(
                key_sum(decoded.canonical().source.account()),
                key_sum(ordinary.source.account())
            );
            assert_eq!(
                key_sum(&decoded.canonical().destination),
                key_sum(&ordinary.destination)
            );
            pool.set_limit_bytes(0);
            drop(decoded);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn funded_native_leg_preserves_exact_original_capacity_release_generation_and_final_refund() {
    let original = leg(single(1), single(3), Quantity::from(17_u32));
    let bytes = norito::encode_canonical(&original).unwrap();
    let first = PreparedDecodeWorkspace::allocation_layouts();
    let control_bytes = controls();
    let pool = AllocationBudget::new(control_bytes);
    let foreign = AllocationBudget::new(control_bytes);
    let blocker = ChargedBuffer::<u8>::new(control_bytes, &pool).unwrap();
    let foreign_blocker = ChargedBuffer::<u8>::new(control_bytes, &foreign).unwrap();
    let expected = pool.try_reserve_layouts(first).unwrap_err();
    let unrelated = foreign.try_reserve_layouts(first).unwrap_err();
    let pending = OneShotLegDecode::new(&bytes, &pool);
    let source = (
        pending.original_source().as_ptr(),
        pending.original_source().len(),
    );
    let failure = pending.try_decode().unwrap_err();
    let Error::Allocation(ChargedBufferError::Admission(actual)) = failure else {
        panic!("original Capacity was erased")
    };
    assert_eq!(
        actual, expected,
        "includes the exact original pool and observed release generation"
    );
    assert_ne!(actual, unrelated);
    let AllocationRefusal::Capacity { release, .. } = &actual else {
        panic!("actual occupied pool")
    };
    let mut waiter = registration();
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(waiter.poll_wait(release, &mut context), Poll::Pending);
    drop(foreign_blocker);
    assert_eq!(waiter.poll_wait(release, &mut context), Poll::Pending);
    assert_eq!(
        (
            pending.original_source().as_ptr(),
            pending.original_source().len()
        ),
        source
    );
    assert_eq!(pool.reserved_bytes(), control_bytes);
    drop(blocker);
    assert_eq!(waiter.poll_wait(release, &mut context), Poll::Ready(()));
    assert_eq!(pool.reserved_bytes(), 0);
    let expected = exact_retained(&original);
    pool.set_limit_bytes(expected + controls());
    let owner = pending.try_decode().unwrap();
    assert_eq!(owner.canonical(), &original);
    assert_eq!(pool.reserved_bytes(), expected);
    pool.set_limit_bytes(expected);
    let probe = key(1).retained_allocation_layout();
    let full = pool.try_reserve(probe).unwrap_err();
    let AllocationRefusal::Capacity { release, .. } = &full else {
        panic!("retained graph must occupy exact credit")
    };
    assert_eq!(waiter.poll_wait(release, &mut context), Poll::Pending);
    let same_generation = pool.try_reserve(probe).unwrap_err();
    assert_eq!(same_generation, full);
    pool.set_limit_bytes(0);
    drop(owner);
    assert_eq!(waiter.poll_wait(release, &mut context), Poll::Ready(()));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(
        (
            pending.original_source().as_ptr(),
            pending.original_source().len()
        ),
        source
    );
}

#[test]
fn funded_multisig_members_keep_actual_vector_capacity_key_ledger_and_existing_relation() {
    let account = multisig(1);
    let policy = account.multisig_policy().unwrap();
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let mut body = Vec::new();
    ncore::serialize_to_buffer(policy, &mut body).unwrap();
    let _context = ncore::PayloadCtxGuard::enter(&body);
    let mut offset = 0;
    let _version = ncore::framed_field::<u8>(&body, &mut offset).unwrap();
    let _threshold = ncore::framed_field::<u16>(&body, &mut offset).unwrap();
    let field = ncore::framed_field::<Vec<MultisigMember>>(&body, &mut offset).unwrap();
    let pool = AllocationBudget::new(4096);
    let mut destination = MembersDestination::new(&pool);
    field
        .with_payload(|bytes| {
            destination
                .decode(bytes, &pool, None)
                .map_err(|error| super::destination(error.into()))
        })
        .unwrap();
    let parts = MemberParts::new(
        destination.members.take().unwrap(),
        destination.keys.take().unwrap(),
    );
    drop(destination);
    let count = policy.members().len();
    let values = parts.members.as_ref().unwrap();
    assert_eq!(values.capacity(), count);
    assert_eq!(values.len(), count);
    let original = values.as_ptr();
    assert_eq!(
        parts.charge.layout(),
        Layout::array::<MultisigMember>(values.capacity()).unwrap()
    );
    assert_eq!(parts.keys.capacity(), count);
    assert_eq!(parts.keys.as_slice().len(), count);
    for (member, charge) in values.iter().zip(parts.keys.as_slice()) {
        assert_eq!(
            charge.layout(),
            member.public_key().retained_allocation_layout()
        );
        assert!(charge.belongs_to(&pool));
    }
    let exact = actual_controller_layouts(&account);
    assert_eq!(
        pool.reserved_bytes(),
        exact,
        "span scratch has already dropped"
    );
    let retained = parts.finish(policy.version(), policy.threshold()).unwrap();
    assert_eq!(retained.value, *policy);
    assert!(core::ptr::eq(retained.value.members().as_ptr(), original));
    assert_eq!(pool.reserved_bytes(), exact);
    pool.set_limit_bytes(0);
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);
}

fn replace_amount(frame: &[u8], scale: u32) -> Vec<u8> {
    let view = ncore::from_bytes_view(frame).unwrap();
    let _flags = ncore::DecodeFlagsGuard::enter(view.flags());
    let _context = ncore::PayloadCtxGuard::enter(view.as_bytes());
    let mut offset = 0;
    let _source = ncore::framed_field::<AssetId>(view.as_bytes(), &mut offset).unwrap();
    let _destination = ncore::framed_field::<AccountId>(view.as_bytes(), &mut offset).unwrap();
    let amount_start = offset;
    let amount = ncore::framed_field::<Quantity>(view.as_bytes(), &mut offset).unwrap();
    let mut amount_offset = 0;
    // Quantity delegates directly to Numeric's positional mantissa/scale body,
    // so replace only the exact scale field without decoding/altering mantissa.
    let _mantissa =
        ncore::framed_field::<iroha_primitives::bigint::BigInt>(amount.bytes(), &mut amount_offset)
            .unwrap();
    let mut amount_body = amount.bytes()[..amount_offset].to_vec();
    let mut encoded_scale = Vec::new();
    ncore::serialize_to_buffer(&scale, &mut encoded_scale).unwrap();
    ncore::write_len_to_vec_with_flags(
        &mut amount_body,
        u64::try_from(encoded_scale.len()).unwrap(),
        view.flags(),
    );
    amount_body.extend_from_slice(&encoded_scale);
    let mut body = view.as_bytes()[..amount_start].to_vec();
    ncore::write_len_to_vec_with_flags(
        &mut body,
        u64::try_from(amount_body.len()).unwrap(),
        view.flags(),
    );
    body.extend_from_slice(&amount_body);
    ncore::frame_bare_with_header_flags::<AmxTransferLegV1>(&body, view.flags()).unwrap()
}

#[test]
fn funded_native_leg_cumulative_prefix_refusal_precedes_late_invalid_quantity_without_preview() {
    let original = leg(single(1), single(3), Quantity::from(17_u32));
    let frame = norito::encode_canonical(&original).unwrap();
    let late = replace_amount(&frame, u32::MAX);
    assert!(norito::decode_canonical::<AmxTransferLegV1>(&late).is_err());
    let observation = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 64);
    let first_key = key(1);
    let first_key_frame = norito::encode_canonical(&first_key).unwrap();
    let (decoded_key, first_key_usage) = ncore::with_decode_limits_measured(observation, || {
        norito::decode_canonical::<PublicKey>(&first_key_frame)
    });
    assert_eq!(decoded_key.unwrap(), first_key);
    assert!(first_key_usage.total_elements() > 0);
    let (valid, census) = ncore::with_decode_limits_measured(observation, || {
        norito::decode_canonical::<AmxTransferLegV1>(&frame)
    });
    assert_eq!(valid.unwrap(), original);
    let ceiling = census
        .total_elements()
        .checked_sub(1)
        .expect("both original keys consume successful work");
    assert!(ceiling >= key(1).retained_allocation_layout().size());
    let limits = DecodeLimits::new(usize::MAX, usize::MAX, ceiling, usize::MAX, 64);
    let ordinary = DecodeBudgetContext::new(limits);
    let actual = DecodeBudgetContext::new(limits);
    let shared = actual.clone();
    let pool = AllocationBudget::new(4096);
    let pending = OneShotLegDecode::new(&late, &pool);
    let mut first_prefix = 0;
    for (attempt, context) in [&actual, &shared].into_iter().enumerate() {
        let (expected, original_usage) = ncore::with_decode_limits_measured(observation, || {
            ordinary.with(|| norito::decode_canonical::<AmxTransferLegV1>(&late))
        });
        let expected = expected.unwrap_err();
        let (failure, usage) = ncore::with_decode_limits_measured(observation, || {
            context.with(|| pending.try_decode())
        });
        let failure = failure.unwrap_err();
        let Error::Decode(failure) = failure else {
            panic!("original logical refusal was erased")
        };
        assert_eq!(
            failure.kind(),
            ncore::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert_eq!(
            pool.reserved_bytes(),
            PreparedDecodeWorkspace::allocation_layouts()[0].size(),
            "only the captured original counter remains; graph and second control have retired"
        );
        let failure = failure.into_error();
        assert!(
            failure.is_decode_resource_limit(),
            "late Quantity must not preempt earlier work"
        );
        assert_eq!(
            failure.decode_resource_error(),
            expected.decode_resource_error()
        );
        // Element work is identical. The prepared path intentionally avoids
        // ordinary alignment scratch, so its allocation-byte total differs.
        assert_eq!(usage.total_elements(), original_usage.total_elements());
        if attempt == 0 {
            assert!(
                usage.total_elements() > 0,
                "successful prefix must be consumed before late failure"
            );
            first_prefix = actual.consumed_allocated_bytes();
            assert!(first_prefix > 0);
        } else {
            assert_eq!(
                usage.total_elements(),
                first_key_usage.total_elements(),
                "the outer observer charges the first key before the shared context refuses it"
            );
            assert_eq!(
                actual.consumed_allocated_bytes(),
                first_prefix,
                "failed retry neither replenishes work nor allocates a refused prefix"
            );
        }
        // The opaque original resource error still owns its counter family.
        assert_eq!(
            pool.reserved_bytes(),
            PreparedDecodeWorkspace::allocation_layouts()[0].size()
        );
        drop(failure);
        assert_eq!(
            pool.reserved_bytes(),
            0,
            "physical credit refunds do not reset logical work"
        );
        assert!(core::ptr::eq(
            pending.original_source().as_ptr(),
            late.as_ptr()
        ));
    }
    let failure = pending.try_decode().unwrap_err();
    let Error::Decode(actual) = failure else {
        panic!("original scalar rejection")
    };
    assert_eq!(actual.kind(), ncore::DecodeAttemptErrorKind::Invalid);
    let expected = norito::decode_canonical::<AmxTransferLegV1>(&late).unwrap_err();
    assert_eq!(actual.to_string(), expected.to_string());
    drop(actual);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn funded_native_leg_rejects_original_malformed_frames_flags_and_payload_bound() {
    let original = leg(single(1), single(3), Quantity::from(17_u32));
    let frame = norito::encode_canonical(&original).unwrap();
    let pool = AllocationBudget::new(4096);
    for bytes in [&frame[..frame.len() - 1], &[]] {
        assert!(OneShotLegDecode::new(bytes, &pool).try_decode().is_err());
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let mut corrupted = frame.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    let failure = OneShotLegDecode::new(&corrupted, &pool)
        .try_decode()
        .unwrap_err();
    let Error::Decode(error) = failure else {
        panic!("captured original checksum error")
    };
    assert!(matches!(
        error.into_error(),
        norito::Error::ChecksumMismatch
    ));
    let mut flags = frame.clone();
    flags[ncore::Header::SIZE - 1] = 0x80;
    assert!(OneShotLegDecode::new(&flags, &pool).try_decode().is_err());
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(
        OneShotLegDecode::new(&trailing, &pool)
            .try_decode()
            .is_err()
    );
    let oversized = vec![0; MAX_RESULT_PREIMAGE_BYTES + 1];
    assert!(matches!(
        OneShotLegDecode::new(&oversized, &pool).try_decode(),
        Err(Error::Record(_))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn funded_native_leg_preserves_canonical_header_error_order_without_crc_preview() {
    let original = leg(single(1), single(3), Quantity::from(17_u32));
    let frame = norito::encode_canonical(&original).unwrap();
    let pool = AllocationBudget::new(4096);
    // Header::write puts schema after magic and major/minor; CRC corruption
    // coexists with each earlier error. Ordinary typed admission is the oracle.
    let mut schema_and_crc = frame.clone();
    schema_and_crc[4 + 1 + 1] ^= 1;
    *schema_and_crc.last_mut().unwrap() ^= 1;
    let mut flags_schema_and_crc = schema_and_crc.clone();
    flags_schema_and_crc[ncore::Header::SIZE - 1] = 0x80;
    for bytes in [&schema_and_crc, &flags_schema_and_crc] {
        let ordinary = norito::decode_canonical::<AmxTransferLegV1>(bytes).unwrap_err();
        let failure = OneShotLegDecode::new(bytes, &pool)
            .try_decode()
            .unwrap_err();
        let Error::Decode(captured) = failure else {
            panic!("typed canonical cause must be captured")
        };
        assert_eq!(captured.kind(), ncore::DecodeAttemptErrorKind::Invalid);
        assert_eq!(captured.to_string(), ordinary.to_string());
        assert!(
            !matches!(ordinary, norito::Error::ChecksumMismatch),
            "CRC must not preempt earlier type/flag errors"
        );
        drop(captured);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn funded_native_leg_preserves_original_root_depth_field_and_source_context() {
    let original = leg(single(1), single(3), Quantity::from(17_u32));
    let frame = norito::encode_canonical(&original).unwrap();
    let pool = AllocationBudget::new(4096);
    let pending = OneShotLegDecode::new(&frame, &pool);
    let sentinel = [9_u8, 7, 5];
    let _source = ncore::PayloadCtxGuard::enter(&sentinel);
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let context = ncore::payload_ctx();
    let flags = ncore::get_decode_flags();
    for ceiling in [
        DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, 0),
        DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0),
    ] {
        let ordinary = ncore::with_decode_limits_scope(ceiling, || {
            norito::decode_canonical_for_admission::<AmxTransferLegV1>(
                &frame,
                norito::canonical_decode_limits(frame.len()),
            )
        })
        .unwrap_err();
        let failure =
            ncore::with_decode_limits_scope(ceiling, || pending.try_decode()).unwrap_err();
        let Error::Decode(actual) = failure else {
            panic!("original root refusal")
        };
        assert_eq!(actual.kind(), ordinary.kind());
        assert_eq!(actual.kind(), ncore::DecodeAttemptErrorKind::EnclosingLimit);
        assert_eq!(
            pool.reserved_bytes(),
            PreparedDecodeWorkspace::allocation_layouts()[0].size()
        );
        let actual = actual.into_error();
        assert_eq!(
            actual.decode_resource_error(),
            ordinary.into_error().decode_resource_error()
        );
        assert_eq!(ncore::payload_ctx(), context);
        assert_eq!(ncore::get_decode_flags(), flags);
        assert!(core::ptr::eq(
            pending.original_source().as_ptr(),
            frame.as_ptr()
        ));
        drop(actual);
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let owner = pending.try_decode().unwrap();
    assert_eq!(owner.canonical(), &original);
    assert_eq!(ncore::payload_ctx(), context);
    assert_eq!(ncore::get_decode_flags(), flags);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn funded_native_leg_destination_reset_retains_backing_and_rechecks_original_frame() {
    let original = leg(single(1), single(3), Quantity::from(17_u32));
    let frame = norito::encode_canonical(&original).unwrap();
    let retained = exact_retained(&original);
    let pool = AllocationBudget::new(retained + controls());
    let mut reservation = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    let mut workspace = PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
    drop(reservation);
    let mut destination = LegDestination::new(&pool);
    workspace
        .decode_canonical_into::<AmxTransferLegV1, _>(
            &frame,
            norito::canonical_decode_limits(frame.len()),
            &mut destination,
        )
        .unwrap();
    let backing = core::ptr::from_ref(destination.complete.as_ref().unwrap().canonical());
    let expected = retained + controls();
    assert_eq!(pool.reserved_bytes(), expected);
    destination.reset();
    assert!(!destination.valid);
    assert_eq!(
        core::ptr::from_ref(destination.complete.as_ref().unwrap().canonical()),
        backing
    );
    assert_eq!(
        pool.reserved_bytes(),
        expected,
        "reset does not retire or replace backing"
    );
    workspace
        .decode_canonical_into::<AmxTransferLegV1, _>(
            &frame,
            norito::canonical_decode_limits(frame.len()),
            &mut destination,
        )
        .unwrap();
    assert_eq!(
        core::ptr::from_ref(destination.complete.as_ref().unwrap().canonical()),
        backing
    );
    assert_eq!(pool.reserved_bytes(), expected);
    assert!(
        destination.valid,
        "same original complete graph still passes full canonical comparison"
    );
    pool.set_limit_bytes(0);
    drop(destination);
    assert_eq!(
        pool.reserved_bytes(),
        controls(),
        "values and graph charges precede control retirement"
    );
    drop(workspace);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn completed_native_leg_retains_original_graph_counter_controls_and_last_owner_refund() {
    let original = leg(multisig(1), multisig(5), Quantity::from(u128::MAX));
    let frame = norito::encode_canonical(&original).unwrap();
    let graph = exact_retained(&original);
    let pool = AllocationBudget::new(graph + controls() + original_span_bytes(&original));
    let foreign = AllocationBudget::new(pool.limit_bytes());
    let pending = OneShotLegDecode::new(&frame, &pool);
    let owner = pending.try_decode_retained().unwrap();
    assert_eq!(owner.canonical(), &original);
    assert!(owner.belongs_to(&pool));
    assert!(!owner.belongs_to(&foreign));
    assert_eq!(owner.allocation_bytes(), Some(graph + controls()));
    assert_eq!(pool.reserved_bytes(), graph + controls());
    let AccountController::Multisig(source) = owner.canonical().source.account().controller()
    else {
        panic!("original multisig source");
    };
    let members = source.members().as_ptr();
    let key = source.members()[0].public_key().to_bytes().1.as_ptr();
    let scope = DecodeBudgetContext::new(DecodeLimits::new(usize::MAX, 0, 0, 0, 0));
    scope.with(|| {
        let borrowed = owner.canonical();
        assert_eq!(borrowed, &original);
        let AccountController::Multisig(source) = borrowed.source.account().controller() else {
            panic!("same completed controller");
        };
        assert_eq!(source.members().as_ptr(), members);
        assert_eq!(source.members()[0].public_key().to_bytes().1.as_ptr(), key);
    });
    assert_eq!(pool.reserved_bytes(), graph + controls());
    assert_eq!(pending.original_source().as_ptr(), frame.as_ptr());
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn partial_native_multisig_retains_original_member_ledger_spans_and_key_pointer_through_retry() {
    let original = leg(multisig(1), single(5), Quantity::from(17_u32));
    let frame = norito::encode_canonical(&original).unwrap();
    let graph = exact_retained(&original);
    let span_bytes = original_span_bytes(&original);
    let pool = AllocationBudget::new(graph + controls() + span_bytes);
    let AccountController::Multisig(policy) = original.source.account().controller() else {
        panic!("original multisig");
    };
    let prefix = controls()
        + span_bytes
        + Layout::array::<MultisigMember>(2).unwrap().size()
        + Layout::array::<AllocationCharge>(2).unwrap().size()
        + policy.members()[0]
            .public_key()
            .retained_allocation_layout()
            .size();
    let blocker = pool.try_reserve_bytes(pool.limit_bytes() - prefix).unwrap();
    let mut pending = PendingAmxTransferLegDecodeV1::new(&frame, &pool);
    let failure = pending.decode(&frame).unwrap_err();
    let Error::Allocation(ChargedBufferError::Admission(refusal)) = failure else {
        panic!("original second member key refusal");
    };
    let AllocationRefusal::Capacity { release, .. } = &refusal else {
        panic!("actual occupancy");
    };
    let members = &pending.destination.source.account.policy.members;
    let original_members = members.members.as_ref().unwrap().as_slice().as_ptr();
    let original_ledger = members.keys.as_ref().unwrap().as_slice().as_ptr();
    assert_eq!(members.members.as_ref().unwrap().as_slice().len(), 1);
    let original_key = members.members.as_ref().unwrap().as_slice()[0]
        .public_key()
        .to_bytes()
        .1
        .as_ptr();
    assert_eq!(members.span_allocation_bytes(), Some(span_bytes));
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    let mut waiter = registration();
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(waiter.poll_wait(release, &mut context), Poll::Pending);
    let repeated = pending.decode(&frame).unwrap_err();
    let Error::Allocation(ChargedBufferError::Admission(repeated)) = repeated else {
        panic!("same second member key refusal");
    };
    assert_eq!(repeated, refusal);
    let members = &pending.destination.source.account.policy.members;
    assert_eq!(
        members.members.as_ref().unwrap().as_slice().as_ptr(),
        original_members
    );
    assert_eq!(
        members.keys.as_ref().unwrap().as_slice().as_ptr(),
        original_ledger
    );
    assert_eq!(
        members.members.as_ref().unwrap().as_slice()[0]
            .public_key()
            .to_bytes()
            .1
            .as_ptr(),
        original_key
    );
    assert_eq!(waiter.poll_wait(release, &mut context), Poll::Pending);
    drop(blocker);
    assert_eq!(waiter.poll_wait(release, &mut context), Poll::Ready(()));
    waiter.cancel();
    let complete = pending.try_decode_retained(&frame).unwrap();
    assert_eq!(complete.canonical(), &original);
    let AccountController::Multisig(policy) = complete.canonical().source.account().controller()
    else {
        panic!("same original controller");
    };
    assert_eq!(policy.members().as_ptr(), original_members);
    assert_eq!(
        policy.members()[0].public_key().to_bytes().1.as_ptr(),
        original_key
    );
    assert_eq!(
        pool.reserved_bytes(),
        graph + controls(),
        "transient spans retire only after complete canonical success"
    );
    assert_eq!(
        pending.original_source_identity(),
        (frame.as_ptr() as usize, frame.len())
    );
    drop(complete);
    drop(pending);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn partial_native_member_values_survive_original_ledger_refusal_without_prefix_refund() {
    let original = leg(multisig(1), single(5), Quantity::from(17_u32));
    let frame = norito::encode_canonical(&original).unwrap();
    let span_bytes = original_span_bytes(&original);
    let pool = AllocationBudget::new(exact_retained(&original) + controls() + span_bytes);
    let prefix = controls() + span_bytes + Layout::array::<MultisigMember>(2).unwrap().size();
    let blocker = pool.try_reserve_bytes(pool.limit_bytes() - prefix).unwrap();
    let mut pending = PendingAmxTransferLegDecodeV1::new(&frame, &pool);
    let failure = pending.decode(&frame).unwrap_err();
    let Error::Allocation(ChargedBufferError::Admission(refusal)) = failure else {
        panic!("original key-ledger refusal");
    };
    let members = &pending.destination.source.account.policy.members;
    assert_eq!(members.members.as_ref().unwrap().capacity(), 2);
    assert!(members.members.as_ref().unwrap().as_slice().is_empty());
    assert!(members.keys.is_none());
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    let mut waiter = registration();
    let mut context = Context::from_waker(Waker::noop());
    let AllocationRefusal::Capacity {
        release,
        requested_bytes,
        ..
    } = &refusal
    else {
        panic!("original occupied pool");
    };
    assert_eq!(
        *requested_bytes,
        Layout::array::<AllocationCharge>(2).unwrap().size()
    );
    assert_eq!(waiter.poll_wait(release, &mut context), Poll::Pending);
    drop(blocker);
    assert_eq!(waiter.poll_wait(release, &mut context), Poll::Ready(()));
    waiter.cancel();
    let owner = pending.try_decode_retained(&frame).unwrap();
    assert_eq!(owner.canonical(), &original);
    drop(owner);
    drop(pending);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn partial_native_leg_rejects_substituted_frame_and_retains_original_graph_through_retry() {
    let original = leg(single(1), single(3), Quantity::from(17_u32));
    let frame = norito::encode_canonical(&original).unwrap();
    let pool = AllocationBudget::new(exact_retained(&original) + controls());
    let source_bytes = actual_controller_layouts(original.source.account());
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - controls() - source_bytes)
        .unwrap();
    let mut pending = PendingAmxTransferLegDecodeV1::new(&frame, &pool);
    assert!(pending.decode(&frame).is_err());
    let source_key = pending
        .destination
        .source
        .complete
        .as_ref()
        .unwrap()
        .value
        .account()
        .try_signatory()
        .unwrap()
        .to_bytes()
        .1
        .as_ptr();
    let replacement = frame.clone();
    assert!(matches!(
        pending.decode(&replacement),
        Err(Error::Invariant("original native AMX leg source changed"))
    ));
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    assert!(pending.belongs_to(&pool));
    let foreign = AllocationBudget::new(pool.limit_bytes());
    assert!(!pending.belongs_to(&foreign));
    drop(blocker);
    let complete = pending.try_decode_retained(&frame).unwrap();
    assert_eq!(
        complete
            .canonical()
            .source
            .account()
            .try_signatory()
            .unwrap()
            .to_bytes()
            .1
            .as_ptr(),
        source_key
    );
    assert_eq!(complete.canonical(), &original);
    drop(complete);
    drop(pending);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn partial_native_retry_rechecks_cached_field_and_depth_limits_without_retiring_original_backing() {
    let original = leg(multisig(1), single(5), Quantity::from(17_u32));
    let frame = norito::encode_canonical(&original).unwrap();
    let graph = exact_retained(&original);
    let spans = original_span_bytes(&original);
    let context_bytes = DecodeBudgetContext::allocation_layout().size();
    let pool = AllocationBudget::new(graph + controls() + spans + context_bytes);
    let limits = norito::canonical_decode_limits(frame.len());
    let outer = DecodeBudgetContext::try_new_owned(
        DecodeLimits::new(
            limits.max_sequence_elements(),
            limits.max_field_bytes(),
            limits.max_total_elements().checked_mul(8).unwrap(),
            limits.max_total_allocated_bytes().checked_mul(8).unwrap(),
            limits.max_nesting_depth(),
        ),
        &pool,
    )
    .unwrap();
    let source_bytes = actual_controller_layouts(original.source.account());
    let prefix = context_bytes + controls() + spans + source_bytes;
    let blocker = pool.try_reserve_bytes(pool.limit_bytes() - prefix).unwrap();
    let mut pending = PendingAmxTransferLegDecodeV1::new(&frame, &pool);
    let refusal = outer.with(|| pending.decode(&frame)).unwrap_err();
    let Error::Allocation(ChargedBufferError::Admission(refusal)) = refusal else {
        panic!("receiver key refuses after completed original multisig source");
    };
    let AllocationRefusal::Capacity { release, .. } = &refusal else {
        panic!("actual original occupancy");
    };
    let AccountController::Multisig(source) = pending
        .destination
        .source
        .complete
        .as_ref()
        .unwrap()
        .value
        .account()
        .controller()
    else {
        panic!("retained complete original source");
    };
    let members = source.members().as_ptr();
    let key = source.members()[0].public_key().to_bytes().1.as_ptr();
    let mut waiter = registration();
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(waiter.poll_wait(release, &mut context), Poll::Pending);
    // Source Asset -> Account -> Policy -> member Vec crosses depth four.
    // The unprepared receiver has only Account -> key at this point. Borrowing
    // the completed source must still enter its own original nested boundary.
    for ceiling in [
        DecodeLimits::new(
            usize::MAX,
            0,
            usize::MAX,
            usize::MAX,
            limits.max_nesting_depth(),
        ),
        DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 4),
    ] {
        let expected = outer
            .with(|| {
                ncore::with_decode_limits_scope(ceiling, || {
                    norito::decode_canonical_for_admission::<AmxTransferLegV1>(&frame, limits)
                })
            })
            .unwrap_err();
        let actual = outer
            .with(|| ncore::with_decode_limits_scope(ceiling, || pending.decode(&frame)))
            .unwrap_err();
        let Error::Decode(actual) = actual else {
            panic!("cached canonical field/depth boundary must refuse before receiver allocation");
        };
        assert_eq!(actual.kind(), ncore::DecodeAttemptErrorKind::EnclosingLimit);
        assert_eq!(actual.kind(), expected.kind());
        assert_eq!(
            actual.into_error().decode_resource_error(),
            expected.into_error().decode_resource_error()
        );
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
        let AccountController::Multisig(source) = pending
            .destination
            .source
            .complete
            .as_ref()
            .unwrap()
            .value
            .account()
            .controller()
        else {
            panic!("same retained original controller");
        };
        assert_eq!(source.members().as_ptr(), members);
        assert_eq!(source.members()[0].public_key().to_bytes().1.as_ptr(), key);
        assert_eq!(waiter.poll_wait(release, &mut context), Poll::Pending);
    }
    drop(blocker);
    assert_eq!(waiter.poll_wait(release, &mut context), Poll::Ready(()));
    waiter.cancel();
    let complete = outer.with(|| pending.try_decode_retained(&frame)).unwrap();
    assert_eq!(complete.canonical(), &original);
    let AccountController::Multisig(source) = complete.canonical().source.account().controller()
    else {
        panic!("same completed original source");
    };
    assert_eq!(source.members().as_ptr(), members);
    assert_eq!(source.members()[0].public_key().to_bytes().1.as_ptr(), key);
    assert_eq!(pool.reserved_bytes(), context_bytes + graph + controls());
    drop(complete);
    drop(pending);
    assert_eq!(pool.reserved_bytes(), context_bytes);
    drop(outer);
    assert_eq!(pool.reserved_bytes(), 0);
}

// Locate the actual scalar through the canonical field/element owners. The
// fixture changes no header, length, key encoding or other policy component.
fn invalid_multisig_scalar_frame(frame: &[u8], member_weight: bool, value: u16) -> Vec<u8> {
    let view = ncore::from_bytes_view(frame).unwrap();
    let _flags = ncore::DecodeFlagsGuard::enter(view.flags());
    let _context = ncore::PayloadCtxGuard::enter(view.as_bytes());
    let mut offset = 0;
    let start = view.as_bytes().as_ptr() as usize;
    let position = ncore::framed_field::<AssetId>(view.as_bytes(), &mut offset).unwrap()
        .with_payload(|asset| {
            let mut offset = 0;
            let position = ncore::framed_field::<AccountId>(asset, &mut offset).unwrap()
                .with_payload(|account| {
                    assert_eq!(tag(account).unwrap(), 1);
                    let mut offset = 4;
                    let position = ncore::framed_field::<MultisigPolicy>(account, &mut offset).unwrap()
                        .with_payload(|policy| {
                            let mut offset = 0;
                            let _version = ncore::framed_field::<u8>(policy, &mut offset).unwrap();
                            let threshold = ncore::framed_field::<u16>(policy, &mut offset).unwrap();
                            let position = if member_weight {
                                ncore::framed_field::<Vec<MultisigMember>>(policy, &mut offset).unwrap()
                                    .with_payload(|members| {
                                        let mut spans = [SequenceSpan { start: 0, end: 0 }; 2];
                                        let prepared = ncore::prepare_element_sequence(members, &mut spans).unwrap();
                                        let mut position = None;
                                        prepared.decode_elements::<MultisigMember, std::convert::Infallible>(|index, field| {
                                            field.with_payload(|member| {
                                                let mut offset = 0;
                                                let _key = ncore::framed_field::<PublicKey>(member, &mut offset).unwrap();
                                                let weight = ncore::framed_field::<u16>(member, &mut offset).unwrap();
                                                if index == 0 { position = Some(weight.bytes().as_ptr() as usize - start); }
                                                Ok(())
                                            })
                                        }).unwrap();
                                        Ok::<_, DecodeIntoError<std::convert::Infallible>>(position.unwrap())
                                    }).unwrap()
                            } else {
                                threshold.bytes().as_ptr() as usize - start
                            };
                            Ok::<_, DecodeIntoError<std::convert::Infallible>>(position)
                        }).unwrap();
                    Ok::<_, DecodeIntoError<std::convert::Infallible>>(position)
                }).unwrap();
            Ok::<_, DecodeIntoError<std::convert::Infallible>>(position)
        }).unwrap();
    let mut body = view.as_bytes().to_vec();
    body[position..position + 2].copy_from_slice(&value.to_le_bytes());
    ncore::frame_bare_with_header_flags::<AmxTransferLegV1>(&body, view.flags()).unwrap()
}

#[test]
fn invalid_native_multisig_retains_original_policy_and_member_prefix_on_replay() {
    let original = leg(multisig(1), single(5), Quantity::from(17_u32));
    let valid = norito::encode_canonical(&original).unwrap();
    for member_weight in [false, true] {
        let frame = invalid_multisig_scalar_frame(&valid, member_weight, 0);
        let ordinary = norito::decode_canonical::<AmxTransferLegV1>(&frame).unwrap_err();
        let expected = if member_weight {
            crate::account::MultisigPolicyError::MemberWeightZero
        } else {
            crate::account::MultisigPolicyError::ZeroThreshold
        };
        let norito::Error::Message(ordinary_message) = &ordinary else {
            panic!("canonical intrinsic multisig diagnostic");
        };
        assert_eq!(ordinary_message, &expected.to_string());
        let pool = AllocationBudget::new(
            exact_retained(&original) + controls() + original_span_bytes(&original),
        );
        let mut pending = PendingAmxTransferLegDecodeV1::new(&frame, &pool);
        let assert_cause = |error: Error| {
            let Error::Multisig(error) = error else {
                panic!("original typed canonical policy/member rejection");
            };
            assert_eq!(error, expected);
            assert_eq!(error.to_string(), ordinary.to_string());
        };
        assert_cause(pending.decode(&frame).unwrap_err());
        let members = &pending.destination.source.account.policy.members;
        let values = members.members.as_ref().unwrap();
        let ledger = members.keys.as_ref().unwrap();
        let original_values = values.as_slice().as_ptr();
        let original_ledger = ledger.as_slice().as_ptr();
        assert_eq!(values.capacity(), 2);
        assert_eq!(ledger.capacity(), 2);
        let original_key = if member_weight {
            assert!(values.as_slice().is_empty());
            assert!(ledger.as_slice().is_empty());
            members.key.as_ref().unwrap().get().to_bytes().1.as_ptr()
        } else {
            assert_eq!(values.as_slice().len(), 2);
            assert_eq!(ledger.as_slice().len(), 2);
            assert!(members.key.is_none());
            values.as_slice()[0].public_key().to_bytes().1.as_ptr()
        };
        assert_eq!(
            members.span_allocation_bytes(),
            Some(original_span_bytes(&original))
        );
        let admitted = pool.reserved_bytes();
        assert!(admitted > controls() + original_span_bytes(&original));
        assert_cause(pending.decode(&frame).unwrap_err());
        let members = &pending.destination.source.account.policy.members;
        assert_eq!(
            members.members.as_ref().unwrap().as_slice().as_ptr(),
            original_values
        );
        assert_eq!(
            members.keys.as_ref().unwrap().as_slice().as_ptr(),
            original_ledger
        );
        let key = if member_weight {
            members.key.as_ref().unwrap().get().to_bytes().1.as_ptr()
        } else {
            members.members.as_ref().unwrap().as_slice()[0]
                .public_key()
                .to_bytes()
                .1
                .as_ptr()
        };
        assert_eq!(key, original_key);
        assert_eq!(
            pool.reserved_bytes(),
            admitted,
            "terminal validators must not consume/refund original prefix backing"
        );
        assert!(pending.belongs_to(&pool));
        drop(pending);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

// Each measured replay begins only after the actual original partial graph and
// both canonical controls exist. Independent ordinary diagnostics precede the
// observation; the current source and every retained pointer remain unchanged.
fn assert_multisig_semantic_replay_has_no_diagnostic_allocation(member_weight: bool) {
    use crate::amx_prepare_streaming_allocations::measured;

    let original = leg(multisig(1), single(5), Quantity::from(17_u32));
    let valid = norito::encode_canonical(&original).unwrap();
    let original_policy = original.source.account().multisig_policy().unwrap();
    let total_weight: u32 = original_policy
        .members()
        .iter()
        .map(|member| u32::from(member.weight()))
        .sum();
    let threshold = u16::try_from(total_weight.checked_add(1).unwrap()).unwrap();
    let expected = if member_weight {
        crate::account::MultisigPolicyError::MemberWeightZero
    } else {
        crate::account::MultisigPolicyError::ThresholdExceedsTotal {
            threshold,
            total_weight,
        }
    };
    let frame = invalid_multisig_scalar_frame(
        &valid,
        member_weight,
        if member_weight { 0 } else { threshold },
    );
    let ordinary = norito::decode_canonical::<AmxTransferLegV1>(&frame).unwrap_err();
    let norito::Error::Message(message) = &ordinary else {
        panic!("canonical intrinsic multisig diagnostic");
    };
    assert_eq!(message, &expected.to_string());
    let ordinary_message = ordinary.to_string();
    let original_source = (frame.as_ptr() as usize, frame.len());
    let pool = AllocationBudget::new(
        exact_retained(&original) + controls() + original_span_bytes(&original),
    );
    let mut pending = PendingAmxTransferLegDecodeV1::new(&frame, &pool);
    let failure = pending.decode(&frame).unwrap_err();
    assert_eq!(failure.to_string(), ordinary_message);
    let workspace = std::ptr::from_ref(pending.workspace.as_ref().unwrap());
    assert!(pending.workspace.as_ref().unwrap().belongs_to(&pool));
    let members = &pending.destination.source.account.policy.members;
    let values = members.members.as_ref().unwrap();
    let ledger = members.keys.as_ref().unwrap();
    let values_pointer = values.as_slice().as_ptr();
    let ledger_pointer = ledger.as_slice().as_ptr();
    assert_eq!(values.capacity(), original_policy.members().len());
    assert_eq!(ledger.capacity(), original_policy.members().len());
    let key_pointer = if member_weight {
        assert!(values.as_slice().is_empty());
        assert!(ledger.as_slice().is_empty());
        members.key.as_ref().unwrap().get().to_bytes().1.as_ptr()
    } else {
        assert_eq!(values.as_slice().len(), original_policy.members().len());
        assert_eq!(ledger.as_slice().len(), original_policy.members().len());
        assert!(members.key.is_none());
        values.as_slice()[0].public_key().to_bytes().1.as_ptr()
    };
    assert_eq!(
        members.span_allocation_bytes(),
        Some(original_span_bytes(&original))
    );
    let admitted = pool.reserved_bytes();
    assert!(admitted > controls() + original_span_bytes(&original));
    let occupied_bytes = pool.limit_bytes().checked_sub(admitted).unwrap();
    let occupied = pool.try_reserve_bytes(occupied_bytes).unwrap();
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    for _ in 0..3 {
        let (result, allocations) = measured(|| pending.decode(&frame));
        let failure = result.unwrap_err();
        assert_eq!(failure.to_string(), ordinary_message);
        // This same regression body is valid before and after the typed cause
        // repair. The earlier codec carrier must still classify as intrinsic.
        if let Error::Decode(cause) = &failure {
            assert_eq!(cause.kind(), ncore::DecodeAttemptErrorKind::Invalid);
        }
        assert!(!matches!(
            failure,
            Error::Allocation(_) | Error::Scope(_) | Error::Invariant(_)
        ));
        assert_eq!(pending.original_source_identity(), original_source);
        assert_eq!(
            std::ptr::from_ref(pending.workspace.as_ref().unwrap()),
            workspace
        );
        let members = &pending.destination.source.account.policy.members;
        assert_eq!(
            members.members.as_ref().unwrap().as_slice().as_ptr(),
            values_pointer
        );
        assert_eq!(
            members.keys.as_ref().unwrap().as_slice().as_ptr(),
            ledger_pointer
        );
        let key = if member_weight {
            members.key.as_ref().unwrap().get().to_bytes().1.as_ptr()
        } else {
            members.members.as_ref().unwrap().as_slice()[0]
                .public_key()
                .to_bytes()
                .1
                .as_ptr()
        };
        assert_eq!(key, key_pointer);
        assert_eq!(
            members.span_allocation_bytes(),
            Some(original_span_bytes(&original))
        );
        assert!(pending.belongs_to(&pool));
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
        assert_eq!(
            allocations,
            [0, 0, 0],
            "retained multisig semantic replay must not allocate a diagnostic or replacement backing"
        );
    }
    drop(pending);
    assert_eq!(pool.reserved_bytes(), occupied_bytes);
    drop(occupied);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn invalid_native_multisig_threshold_replay_preserves_original_cause_without_diagnostic_allocations()
 {
    assert_multisig_semantic_replay_has_no_diagnostic_allocation(false);
}

#[test]
fn invalid_native_multisig_member_replay_preserves_original_cause_without_diagnostic_allocations() {
    assert_multisig_semantic_replay_has_no_diagnostic_allocation(true);
}
