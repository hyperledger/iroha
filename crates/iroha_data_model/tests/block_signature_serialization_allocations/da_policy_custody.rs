//! Actual policy-array, alias and control allocation, refusal and last-reader custody.
use super::*;
use iroha_allocation::{
    AllocationBudget, ChargedBuffer, ChargedBufferFromChargeError, SharedFromChargeError,
};
use iroha_crypto::Hash;
use iroha_data_model::da::commitment::{
    DaProofPolicy, DaProofPolicyBundle, DaProofPolicyCustodyError, DaProofScheme,
    PreparedDaProofPolicyBundle,
};
use iroha_model_base::topology::{DataSpaceId, LaneId};
use norito::core::SequenceSpan;
fn fixture() -> DaProofPolicyBundle {
    DaProofPolicyBundle::new(vec![
        DaProofPolicy {
            lane_id: LaneId::new(3),
            dataspace_id: DataSpaceId::new(9),
            alias: "a".repeat(11),
            proof_scheme: DaProofScheme::MerkleSha256,
        },
        DaProofPolicy {
            lane_id: LaneId::new(7),
            dataspace_id: DataSpaceId::new(11),
            alias: "é漢🙂".repeat(3),
            proof_scheme: DaProofScheme::MerkleSha256,
        },
    ])
}
fn source(
    value: &DaProofPolicyBundle,
    pool: &AllocationBudget,
    flags: u8,
) -> (ChargedBuffer<u8>, SequenceSpan) {
    let bytes = bare_bytes(value, flags);
    let mut source = ChargedBuffer::new(bytes.len() + 9, pool).unwrap();
    source.append(&[0xa5; 9]).unwrap();
    source.append(&bytes).unwrap();
    (
        source,
        SequenceSpan {
            start: 9,
            end: 9 + bytes.len(),
        },
    )
}
fn measured<T>(run: impl FnOnce() -> T) -> (T, usize) {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            TRACKING.with(|active| active.set(false));
        }
    }
    TRACKING.with(|active| assert!(!active.replace(true)));
    ALLOCATIONS.with(|count| count.set(0));
    let guard = Restore;
    let value = run();
    let count = ALLOCATIONS.with(Cell::get);
    drop(guard);
    (value, count)
}
fn refused<T>(layout: Layout, run: impl FnOnce() -> T) -> T {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            REFUSE.with(|next| next.set(None));
        }
    }
    REFUSE.with(|next| assert!(next.replace(Some(layout)).is_none()));
    let guard = Restore;
    let value = run();
    assert!(
        REFUSE.with(|next| next.get().is_none()),
        "exact original allocator request was not reached"
    );
    drop(guard);
    value
}
#[test]
fn da_policy_array_utf8_and_control_are_prepaid_before_fill_and_follow_last_reader() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for original in [
            fixture(),
            DaProofPolicyBundle::new(Vec::new()),
            DaProofPolicyBundle::new(vec![DaProofPolicy {
                lane_id: LaneId::SINGLE,
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: String::new(),
                proof_scheme: DaProofScheme::MerkleSha256,
            }]),
        ] {
            let pool = AllocationBudget::new(1 << 20);
            let (source, span) = source(&original, &pool, flags);
            let floor = pool.reserved_bytes();
            let (pending, count) =
                measured(|| PreparedDaProofPolicyBundle::from_source(&source, span, &pool));
            assert_eq!(count, 0);
            let mut pending = pending.unwrap();
            let planning = pending.planning_layouts().unwrap();
            let target = pending.payload_layouts().unwrap();
            let scaffold = planning.iter().map(Layout::size).sum::<usize>();
            let retained = target.iter().map(Layout::size).sum::<usize>()
                + original
                    .policies()
                    .iter()
                    .map(|policy| Layout::array::<u8>(policy.alias.len()).unwrap().size())
                    .sum::<usize>();
            pool.set_limit_bytes(floor + scaffold);
            let (attempt, count) = measured(|| pending.prepare(&source));
            assert!(matches!(
                attempt,
                Err(DaProofPolicyCustodyError::Admission(_))
            ));
            assert_eq!(
                count,
                planning.iter().filter(|layout| layout.size() != 0).count()
            );
            assert_eq!(pool.reserved_bytes(), floor + scaffold);
            pool.set_limit_bytes(floor + scaffold + retained);
            let (filled, count) = measured(|| pending.prepare(&source));
            filled.unwrap();
            assert_eq!(
                count,
                target.iter().filter(|layout| layout.size() != 0).count()
                    + original
                        .policies()
                        .iter()
                        .filter(|policy| !policy.alias.is_empty())
                        .count()
            );
            assert!(pending.belongs_to(&pool));
            assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
            let pointers = (0..original.policies().len())
                .map(|index| {
                    pending
                        .initialized_alias(&source, index)
                        .unwrap()
                        .unwrap()
                        .as_ptr()
                })
                .collect::<Vec<_>>();
            let (same, count) = measured(|| pending.prepare(&source));
            same.unwrap();
            assert_eq!(count, 0);
            let (admitted, count) = measured(|| pending.finish(&source));
            let admitted = admitted.unwrap_or_else(|_| panic!("complete original policy owner"));
            assert_eq!(count, 0);
            assert!(admitted.admitted_to(&pool));
            assert_eq!(pool.reserved_bytes(), floor + retained);
            assert_eq!(admitted, original);
            assert_eq!(
                admitted
                    .policies()
                    .iter()
                    .map(|policy| policy.alias.as_ptr())
                    .collect::<Vec<_>>(),
                pointers
            );
            assert_eq!(
                bare_bytes(&admitted, flags),
                span.get(source.as_slice()).unwrap()
            );
            assert_eq!(
                norito::to_bytes(&admitted).unwrap(),
                norito::to_bytes(&original).unwrap()
            );
            let (reader, count) = measured(|| admitted.clone());
            assert_eq!(count, 0);
            assert!(DaProofPolicyBundle::ptr_eq(&reader, &admitted));
            let array = reader.policies().as_ptr();
            drop(admitted);
            assert_eq!(pool.reserved_bytes(), floor + retained);
            assert_eq!(reader.policies().as_ptr(), array);
            assert_eq!(
                reader
                    .policies()
                    .iter()
                    .map(|policy| policy.alias.as_ptr())
                    .collect::<Vec<_>>(),
                pointers
            );
            drop(reader);
            assert_eq!(pool.reserved_bytes(), floor);
            drop(source);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}
#[test]
fn da_policy_every_physical_refusal_keeps_original_siblings_before_string_fill_and_retry() {
    let flags = header_flags::COMPACT_LEN;
    let _flags = DecodeFlagsGuard::enter(flags);
    let original = fixture();
    for selected in 0..7 {
        let pool = AllocationBudget::new(1 << 20);
        let (source, span) = source(&original, &pool, flags);
        let floor = pool.reserved_bytes();
        let pointer = source.as_slice().as_ptr();
        let hash = Hash::new(source.as_slice());
        let mut pending = PreparedDaProofPolicyBundle::from_source(&source, span, &pool).unwrap();
        let planning = pending.planning_layouts().unwrap();
        let target = pending.payload_layouts().unwrap();
        let aliases = original
            .policies()
            .iter()
            .map(|policy| Layout::array::<u8>(policy.alias.len()).unwrap())
            .collect::<Vec<_>>();
        let layouts = [
            planning[0],
            planning[1],
            target[0],
            target[1],
            aliases[0],
            aliases[1],
            target[2],
        ];
        let error = refused(layouts[selected], || pending.prepare(&source)).unwrap_err();
        if selected == 6 {
            assert!(
                matches!(error,DaProofPolicyCustodyError::Control(SharedFromChargeError::Allocator {layout}) if layout==layouts[selected])
            );
        } else {
            assert!(
                matches!(error,DaProofPolicyCustodyError::Buffer(ChargedBufferFromChargeError::Allocator {layout}) if layout==layouts[selected])
            );
        }
        let expected: usize = if selected < 2 {
            layouts[..2].iter().map(Layout::size).sum()
        } else {
            layouts.iter().map(Layout::size).sum()
        };
        assert_eq!(pool.reserved_bytes(), floor + expected);
        assert!(pending.belongs_to(&pool));
        let pointers = (0..2)
            .map(|index| {
                pending
                    .initialized_alias(&source, index)
                    .unwrap()
                    .map(<[u8]>::as_ptr)
            })
            .collect::<Vec<_>>();
        for index in 0..2 {
            if let Some(alias) = pending.initialized_alias(&source, index).unwrap() {
                assert!(
                    alias.is_empty(),
                    "no alias fill before every physical owner exists"
                );
            }
        }
        assert_eq!(source.as_slice().as_ptr(), pointer);
        assert_eq!(Hash::new(source.as_slice()), hash);
        pending.prepare(&source).unwrap();
        for (index, old) in pointers.into_iter().enumerate() {
            if let Some(old) = old {
                assert_eq!(
                    pending
                        .initialized_alias(&source, index)
                        .unwrap()
                        .unwrap()
                        .as_ptr(),
                    old
                );
            }
        }
        let (admitted, count) = measured(|| pending.finish(&source));
        let admitted = admitted.unwrap_or_else(|_| panic!("same original policy retry"));
        assert_eq!(count, 0);
        assert_eq!(admitted, original);
        assert!(admitted.admitted_to(&pool));
        drop(admitted);
        assert_eq!(pool.reserved_bytes(), floor);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn da_policy_original_source_pool_flags_and_incomplete_finish_fail_closed_without_refund() {
    let flags = header_flags::COMPACT_LEN;
    let _flags = DecodeFlagsGuard::enter(flags);
    let original = fixture();
    let pool = AllocationBudget::new(1 << 20);
    let foreign = AllocationBudget::new(1 << 20);
    let (source, span) = source(&original, &pool, flags);
    let (copy, _) = self::source(&original, &pool, flags);
    let (other, _) = self::source(&original, &foreign, flags);
    let mut pending = PreparedDaProofPolicyBundle::from_source(&source, span, &pool).unwrap();
    let floor = pool.reserved_bytes();
    let (error, count) = measured(|| pending.prepare(&other));
    assert_eq!(count, 0);
    assert!(matches!(error, Err(DaProofPolicyCustodyError::ForeignPool)));
    assert_eq!(pool.reserved_bytes(), floor);
    assert!(matches!(
        pending.prepare(&copy),
        Err(DaProofPolicyCustodyError::SourceChanged)
    ));
    let Err((_, error)) = pending.finish(&source) else {
        panic!("actual incomplete owner");
    };
    assert!(matches!(error, DaProofPolicyCustodyError::Incomplete));
    let mut pending = PreparedDaProofPolicyBundle::from_source(&source, span, &pool).unwrap();
    {
        let _other = DecodeFlagsGuard::enter(0);
        assert!(matches!(
            pending.prepare(&source),
            Err(DaProofPolicyCustodyError::LayoutChanged)
        ));
    }
    pending.prepare(&source).unwrap();
    let before = pool.reserved_bytes();
    let Err((pending, error)) = pending.finish(&copy) else {
        panic!("actual original retained owner");
    };
    assert!(matches!(error, DaProofPolicyCustodyError::SourceChanged));
    assert_eq!(pool.reserved_bytes(), before);
    assert!(pending.belongs_to(&pool));
    drop(pending);
    assert_eq!(pool.reserved_bytes(), floor);
    drop((source, copy, other));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}
