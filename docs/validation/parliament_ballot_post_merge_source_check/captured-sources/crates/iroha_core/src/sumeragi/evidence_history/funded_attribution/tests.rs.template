//! Exact actual graph layouts, original-source movement and partial retirement controls.

use std::alloc::Layout;

use super::*;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use iroha_crypto::{Algorithm, KeyPair, PreparedPublicKeyDecode, PublicKeyDecodeAdmissionError};
use iroha_data_model::block::consensus::EvidenceScope;

fn source() -> KeyPair {
    KeyPair::from_seed(vec![0x95; 32], Algorithm::BlsNormal)
}
fn copy(
    source: &KeyPair,
    budget: &AllocationBudget,
) -> Result<ChargedPublicKey, NativeEvidenceError> {
    let (algorithm, material) = source.public_key().borrowed_parts().unwrap();
    PreparedPublicKeyDecode::try_from_material(algorithm, material, budget).map_err(|error| {
        match error {
            PublicKeyDecodeAdmissionError::Allocation(error) => {
                EvidencePreparationError::from(error).into()
            }
            PublicKeyDecodeAdmissionError::Codec(error) => {
                NativeEvidenceError::Context(error.to_string())
            }
        }
    })
}
fn fields() -> AttributionFields {
    AttributionFields {
        scope: EvidenceScope::Root,
        instance: [1; 32],
        height: 2,
        epoch: 3,
        context_id: [4; 32],
        authority_generation: [5; 32],
        safety_violation: false,
    }
}
fn graph_bytes(count: usize, key_bytes: usize) -> usize {
    if count == 0 {
        return 0;
    }
    Layout::array::<EvidenceOffender>(count).unwrap().size()
        + Layout::array::<AllocationCharge>(count + 1).unwrap().size()
        + count * key_bytes
}

#[test]
fn original_offender_graph_moves_exact_vector_keys_and_ledger_without_allocation() {
    let source = source();
    let pool = AllocationBudget::new(1 << 20);
    let foreign = AllocationBudget::new(1 << 20);
    let exact = graph_bytes(2, source.public_key().retained_allocation_layout().size());
    let original_source = source.public_key().borrowed_parts().unwrap().1.as_ptr();
    let offenders = FundedOffenders::collect(2, [0, 2].into_iter(), &pool, |_, pool| {
        Ok((copy(&source, pool)?, None))
    })
    .unwrap();
    let vector = offenders.as_slice().as_ptr();
    let key = offenders.as_slice()[0]
        .peer_id
        .public_key()
        .borrowed_parts()
        .unwrap()
        .1
        .as_ptr();
    assert_eq!(pool.reserved_bytes(), exact);
    let mut attribution = None;
    assert_eq!(
        allocations_during(|| {
            attribution = Some(offenders.into_attribution(fields()));
        }),
        0
    );
    let attribution = attribution.unwrap();
    assert!(attribution.belongs_to(&pool));
    assert!(!attribution.belongs_to(&foreign));
    assert_eq!(attribution.allocation_bytes(), Some(exact));
    assert_eq!(attribution.offenders.as_ptr(), vector);
    assert_eq!(
        attribution.offenders[0]
            .peer_id
            .public_key()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr(),
        key
    );
    assert_eq!(
        source.public_key().borrowed_parts().unwrap().1.as_ptr(),
        original_source
    );
    drop(attribution);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[test]
fn original_offender_graph_refuses_each_exact_physical_backing_and_retries() {
    let source = source();
    let pool = AllocationBudget::new(1 << 20);
    let key = source.public_key().retained_allocation_layout();
    for layout in [
        key,
        Layout::array::<AllocationCharge>(3).unwrap(),
        Layout::array::<EvidenceOffender>(2).unwrap(),
    ] {
        let (result, refused) = refuse_one_layout_during(layout, || {
            FundedOffenders::collect(2, [0, 1].into_iter(), &pool, |_, pool| {
                Ok((copy(&source, pool)?, None))
            })
        });
        assert!(refused, "the actual requested layout must be observed");
        assert!(matches!(result, Err(NativeEvidenceError::Preparation(
            EvidencePreparationError::Allocator { requested_bytes })) if requested_bytes == layout.size()));
        assert_eq!(
            pool.reserved_bytes(),
            0,
            "retire partial values before refunding their ledger"
        );
        let graph = FundedOffenders::collect(2, [0, 1].into_iter(), &pool, |_, pool| {
            Ok((copy(&source, pool)?, None))
        })
        .unwrap();
        assert_eq!(graph.as_slice().len(), 2);
        drop(graph);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn original_offender_graph_late_capacity_count_foreign_and_unwind_retire_partial_owners() {
    let source = source();
    let pool = AllocationBudget::new(1 << 20);
    let key = source.public_key().retained_allocation_layout();
    let first_prefix = key.size()
        + Layout::array::<AllocationCharge>(3).unwrap().size()
        + Layout::array::<EvidenceOffender>(2).unwrap().size();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - first_prefix)
        .unwrap();
    let original_reserved = pool.reserved_bytes();
    let mut expected = None;
    let result = FundedOffenders::collect(2, [0, 1].into_iter(), &pool, |signer, pool| {
        if signer == 1 {
            expected = Some(pool.try_reserve(key).unwrap_err());
        }
        Ok((copy(&source, pool)?, None))
    });
    assert!(matches!(result, Err(NativeEvidenceError::Preparation(
        EvidencePreparationError::Admission(ref actual))) if Some(actual) == expected.as_ref()));
    assert_eq!(pool.reserved_bytes(), original_reserved);
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), 0);
    for count in [0, 1, 3] {
        let result = FundedOffenders::collect(count, [0, 1].into_iter(), &pool, |_, pool| {
            Ok((copy(&source, pool)?, None))
        });
        assert!(matches!(
            result,
            Err(NativeEvidenceError::Preparation(
                EvidencePreparationError::Invariant
            ))
        ));
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let foreign = AllocationBudget::new(1 << 20);
    let result = FundedOffenders::collect(1, [0].into_iter(), &pool, |_, _| {
        Ok((copy(&source, &foreign)?, None))
    });
    assert!(matches!(
        result,
        Err(NativeEvidenceError::Preparation(
            EvidencePreparationError::Invariant
        ))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        FundedOffenders::collect(2, [0, 1].into_iter(), &pool, |signer, pool| {
            assert!(signer != 1, "late original producer unwind");
            Ok((copy(&source, pool)?, None))
        })
    }));
    assert!(result.is_err());
    assert_eq!(pool.reserved_bytes(), 0);
    let mut empty = None;
    assert_eq!(
        allocations_during(|| {
            empty = Some(
                FundedOffenders::collect(0, std::iter::empty(), &pool, |_, _| {
                    panic!("empty graph must not request a key")
                })
                .unwrap(),
            );
        }),
        0
    );
    let mut metadata = fields();
    metadata.safety_violation = true;
    let empty = empty.unwrap().into_attribution(metadata);
    assert!(empty.offenders.is_empty());
    assert!(
        empty.safety_violation,
        "a certified safety halt does not require an attributable signer"
    );
    assert_eq!(empty.allocation_bytes(), Some(0));
    drop(empty);
    assert_eq!(pool.reserved_bytes(), 0);
}
