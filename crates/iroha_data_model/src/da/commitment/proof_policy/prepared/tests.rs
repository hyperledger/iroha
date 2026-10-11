//! Complete canonical DA policy values, original source and assembly retirement.
use super::*;
use norito::core::{DecodeFlagsGuard, Encoder, SerializePayload, header_flags};
fn fixture() -> DaProofPolicyBundle {
    DaProofPolicyBundle::new(vec![
        DaProofPolicy {
            lane_id: LaneId::new(3),
            dataspace_id: DataSpaceId::new(9),
            alias: "é漢🙂".into(),
            proof_scheme: DaProofScheme::MerkleSha256,
        },
        DaProofPolicy {
            lane_id: LaneId::new(7),
            dataspace_id: DataSpaceId::new(11),
            alias: String::new(),
            proof_scheme: DaProofScheme::MerkleSha256,
        },
    ])
}
fn bytes(value: &impl SerializePayload) -> Vec<u8> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut Encoder::for_buffer(&mut bytes))
        .unwrap();
    bytes
}
fn source(
    value: &DaProofPolicyBundle,
    pool: &AllocationBudget,
) -> (ChargedBuffer<u8>, SequenceSpan) {
    let wire = bytes(value);
    let mut source = ChargedBuffer::new(wire.len() + 9, pool).unwrap();
    source.append(&[0xa5; 9]).unwrap();
    source.append(&wire).unwrap();
    (
        source,
        SequenceSpan {
            start: 9,
            end: 9 + wire.len(),
        },
    )
}
#[test]
fn da_policy_immutable_owner_preserves_complete_wire_json_schema_and_untrusted_claims() {
    #[derive(norito::codec::Encode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::da::commitment::DaProofPolicyBundle")]
    struct SoleWire {
        version: u16,
        policy_hash: Hash,
        policies: Vec<DaProofPolicy>,
    }
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let original = fixture();
        // Preserve even unsupported version, wrong hash and duplicate-lane transport
        // claims. Custody cannot repair them or authorize a DA policy.
        let malformed = DaProofPolicyBundle::from_untrusted_parts(
            9,
            Hash::new(b"wrong ordered policy hash"),
            vec![original.policies()[0].clone(); 2],
        );
        for value in [original, malformed] {
            let policies = value.policies().to_vec();
            let independent = SoleWire {
                version: value.version(),
                policy_hash: value.policy_hash(),
                policies,
            };
            assert_eq!(bytes(&value), bytes(&independent));
            assert_eq!(
                norito::to_bytes(&value).unwrap(),
                norito::to_bytes(&independent).unwrap()
            );
            let pool = AllocationBudget::new(1 << 20);
            let (source, span) = source(&value, &pool);
            let floor = pool.reserved_bytes();
            let mut pending =
                PreparedDaProofPolicyBundle::from_source(&source, span, &pool).unwrap();
            pending.prepare(&source).unwrap();
            let admitted = pending
                .finish(&source)
                .unwrap_or_else(|_| panic!("complete original policy owner"));
            assert_eq!(admitted, value);
            assert!(admitted.admitted_to(&pool));
            assert!(!value.admitted_to(&pool));
            assert_eq!(
                norito::to_bytes(&admitted).unwrap(),
                norito::to_bytes(&value).unwrap()
            );
            let json = norito::json::to_json(&value).unwrap();
            assert_eq!(norito::json::to_json(&admitted).unwrap(), json);
            let decoded: DaProofPolicyBundle = norito::json::from_json(&json).unwrap();
            assert_eq!(decoded, value);
            assert!(!decoded.admitted_to(&pool));
            let ordinary = norito::decode_from_bytes::<DaProofPolicyBundle>(
                &norito::to_bytes(&admitted).unwrap(),
            )
            .unwrap();
            assert_eq!(ordinary, value);
            assert!(!ordinary.admitted_to(&pool));
            let shared = admitted.clone();
            assert!(DaProofPolicyBundle::ptr_eq(&admitted, &shared));
            drop(admitted);
            assert!(shared.admitted_to(&pool));
            drop(shared);
            assert_eq!(pool.reserved_bytes(), floor);
            drop(source);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}
#[test]
fn da_policy_generated_scalar_fields_reject_truncated_scheme_and_invalid_utf8_without_owning_fallback()
 {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let value = fixture();
        let wire = bytes(&value);
        for end in 0..wire.len() {
            let pool = AllocationBudget::new(1 << 20);
            let mut source = ChargedBuffer::new(end, &pool).unwrap();
            source.append(&wire[..end]).unwrap();
            let span = SequenceSpan { start: 0, end };
            let floor = pool.reserved_bytes();
            match PreparedDaProofPolicyBundle::from_source(&source, span, &pool) {
                Ok(mut pending) => assert!(pending.prepare(&source).is_err()),
                Err(_) => {}
            }
            assert_eq!(pool.reserved_bytes(), floor);
            drop(source);
            assert_eq!(pool.reserved_bytes(), 0);
        }
        let pool = AllocationBudget::new(1 << 20);
        let (mut source, span) = source(&value, &pool);
        let offset = source
            .as_slice()
            .windows("é漢🙂".len())
            .position(|part| part == "é漢🙂".as_bytes())
            .unwrap();
        source.as_mut_slice()[offset] = 0xff;
        let mut pending = PreparedDaProofPolicyBundle::from_source(&source, span, &pool).unwrap();
        let error = pending.prepare(&source).unwrap_err();
        let DaProofPolicyCustodyError::Decode(original) = error else {
            panic!("invalid UTF-8 policy must preserve its original decode error");
        };
        assert!(matches!(original.into_error(), norito::Error::InvalidUtf8));
        assert!(pending.values.value.is_none());
        assert!(pending.phase < PreparationPhase::PayloadAdmitted);
        drop(pending);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
        assert!(inline_lane(&bytes(&LaneId::new(0x11223344))).is_ok());
        assert!(inline_dataspace(&bytes(&DataSpaceId::new(0x1122334455667788))).is_ok());
        assert!(inline_lane(&[0]).is_err());
        assert!(inline_dataspace(&[0]).is_err());
    }
}
#[test]
fn da_policy_actual_finish_interruption_destroys_original_children_before_refund() {
    let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    let value = fixture();
    let pool = AllocationBudget::new(1 << 20);
    let (source, span) = source(&value, &pool);
    let floor = pool.reserved_bytes();
    let pointer = source.as_slice().as_ptr();
    let hash = Hash::new(source.as_slice());
    let mut pending = PreparedDaProofPolicyBundle::from_source(&source, span, &pool).unwrap();
    pending.prepare(&source).unwrap();
    assert!(pool.reserved_bytes() > floor);
    ASSEMBLY_PANIC_AFTER.with(|point| point.set(Some(1)));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = pending.finish(&source);
    }));
    ASSEMBLY_PANIC_AFTER.with(|point| point.set(None));
    assert!(outcome.is_err());
    assert_eq!(pool.reserved_bytes(), floor);
    assert_eq!(source.as_slice().as_ptr(), pointer);
    assert_eq!(Hash::new(source.as_slice()), hash);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn da_policy_payload_refusal_keeps_planned_phase_and_original_backings_until_retry() {
    let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    let original = fixture();
    let pool = AllocationBudget::new(1 << 20);
    let (source, span) = source(&original, &pool);
    let source_floor = pool.reserved_bytes();
    let mut pending = PreparedDaProofPolicyBundle::from_source(&source, span, &pool).unwrap();
    assert_eq!(pending.phase, PreparationPhase::Unadmitted);
    let metadata_bytes = pending
        .planning_layouts()
        .unwrap()
        .iter()
        .map(std::alloc::Layout::size)
        .sum::<usize>();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes() - metadata_bytes)
        .unwrap();
    assert!(matches!(
        pending.prepare(&source),
        Err(DaProofPolicyCustodyError::Admission(_))
    ));
    assert_eq!(pending.phase, PreparationPhase::Planned);
    let rows = pending.rows.value.as_ref().unwrap().as_slice().as_ptr();
    let spans = pending.spans.value.as_ref().unwrap().as_slice().as_ptr();
    let refused_reservation = pool.reserved_bytes();
    assert!(pending.prepare(&source).is_err());
    assert_eq!(pending.phase, PreparationPhase::Planned);
    assert_eq!(
        pending.rows.value.as_ref().unwrap().as_slice().as_ptr(),
        rows
    );
    assert_eq!(
        pending.spans.value.as_ref().unwrap().as_slice().as_ptr(),
        spans
    );
    assert_eq!(pool.reserved_bytes(), refused_reservation);
    drop(blocker);
    pending.prepare(&source).unwrap();
    assert_eq!(pending.phase, PreparationPhase::Ready);
    let admitted = pending
        .finish(&source)
        .unwrap_or_else(|_| panic!("complete original owner after exact retry"));
    assert_eq!(admitted, original);
    drop(admitted);
    assert_eq!(pool.reserved_bytes(), source_floor);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}
