//! Canonical effect carrier, inherited resource and source substitution controls.

use super::*;
use crate::backend::{compact_execution_effect_batch::tests::fixture, deep_geometry::QUERY_COUNT};
use iroha_crypto::Hash;
use iroha_data_model::fastpq::execution_effect_statement_digest_v1;

fn policy(count: usize) -> EffectVerificationLimits {
    EffectVerificationLimits {
        public: ExecutionEffectLimits::default(),
        bundle: BundleLimits {
            max_segments: count,
            max_wire_bytes: 16 * 1024 * 1024,
            max_total_segment_bytes: 16 * 1024 * 1024,
            max_total_statement_bytes: 512 * 1024,
            max_total_queries: count * QUERY_COUNT,
            max_total_decode_allocation_charges: 128 * 1024 * 1024,
            segment: VerifyLimits {
                max_queries: QUERY_COUNT,
                ..VerifyLimits::default()
            },
        },
        max_segment_decode_allocation_charges: 64 * 1024 * 1024,
    }
}
#[test]
fn effect_carrier_requires_every_root_and_segment_under_exact_limits() {
    let (source, statement, roots) = fixture();
    let count = statement.effects.effects.len();
    assert_eq!(usize::try_from(source.effect_count).unwrap(), count);
    let mut limits = policy(count).bundle;
    let wire = EffectBundleWire {
        version: 1,
        intermediate_roots: roots,
        segments: vec![vec![0xff]; count],
    };
    let bytes = encode(&wire, count, limits).unwrap();
    let decoded: EffectBundleWire = norito::decode_canonical_with_limits(
        &bytes,
        wire_decode_limits(&bytes, count, limits).unwrap(),
    )
    .unwrap();
    assert_eq!(wire, decoded);
    limits.max_wire_bytes = bytes.len();
    assert_eq!(encode(&wire, count, limits).unwrap(), bytes);
    limits.max_wire_bytes -= 1;
    assert!(encode(&wire, count, limits).is_err());
    limits = policy(count).bundle;
    for mutation in 0..5 {
        let mut changed = wire.clone();
        match mutation {
            0 => changed.version = 0,
            1 => {
                changed.segments.pop();
            }
            2 => changed.segments[0].clear(),
            3 => {
                changed.intermediate_roots.pop();
            }
            4 => changed.intermediate_roots[0][31] &= 0xfe,
            _ => unreachable!(),
        }
        assert!(
            encode(&changed, count, limits).is_err(),
            "carrier mutation {mutation}"
        );
    }
    assert!(
        norito::decode_canonical_with_limits::<AxtBundleWire>(
            &bytes,
            wire_decode_limits(&bytes, count, limits).unwrap()
        )
        .is_err()
    );
    assert!(
        norito::decode_canonical_with_limits::<BundleWire>(
            &bytes,
            wire_decode_limits(&bytes, count, limits).unwrap()
        )
        .is_err()
    );
}
#[test]
fn effect_verification_requires_original_pool_and_independent_source_before_proof() {
    let (source, statement, roots) = fixture();
    let count = statement.effects.effects.len();
    let expected = ExecutionEffectExpectations {
        effects_digest: Hash::from_marked_bytes(source.effects_digest).unwrap(),
        statement_digest: execution_effect_statement_digest_v1(&statement).unwrap(),
        public_inputs: statement.public_inputs,
    };
    let view = SourceExecutionEffectStatement::from_owned(&statement);
    let limit = policy(count);
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let foreign = AllocationBudget::new(64 * 1024 * 1024);
    let mut reservation = foreign.try_reserve_bytes(64 * 1024 * 1024).unwrap();
    assert!(matches!(
        verify(
            &EffectVerificationInputs {
                statement: &view,
                source: &source,
                expected
            },
            &[],
            limit,
            &budget,
            &mut reservation
        ),
        Err(Error::AllocationForeignPool)
    ));
    assert_eq!(budget.peak_reserved_bytes(), 0);
    drop(reservation);
    assert_eq!(foreign.reserved_bytes(), 0);
    let bytes = encode(
        &EffectBundleWire {
            version: 1,
            intermediate_roots: roots,
            segments: vec![vec![0xff]; count],
        },
        count,
        limit.bundle,
    )
    .unwrap();
    let mut altered = source;
    altered.slot = altered.slot.checked_add(1).unwrap();
    let mut reservation = budget.try_reserve_bytes(64 * 1024 * 1024).unwrap();
    assert!(
        matches!(verify(&EffectVerificationInputs {statement:&view,source:&altered,expected},&bytes,limit,&budget,&mut reservation),Err(Error::TransferInvariant {details}) if details.contains("source leaf mismatch"))
    );
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
    let mut reservation = budget.try_reserve_bytes(64 * 1024 * 1024).unwrap();
    assert!(
        verify(
            &EffectVerificationInputs {
                statement: &view,
                source: &source,
                expected
            },
            &bytes,
            limit,
            &budget,
            &mut reservation
        )
        .is_err(),
        "invalid child frames cannot produce even a verified prefix"
    );
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
}
#[test]
fn effect_bundle_cumulative_queries_cannot_be_reset_per_child() {
    let (_, statement, roots) = fixture();
    let count = statement.effects.effects.len();
    assert!(count > 1);
    let wire = EffectBundleWire {
        version: 1,
        intermediate_roots: roots,
        segments: vec![vec![0xff]; count],
    };
    let mut limits = policy(count).bundle;
    encode(&wire, count, limits).unwrap();
    limits.max_total_queries = count * QUERY_COUNT - 1;
    assert!(
        matches!(encode(&wire,count,limits),Err(Error::VerifierLimitExceeded {limit:"max_bundle_queries",actual,max}) if actual==count*QUERY_COUNT && max==actual-1)
    );
}
