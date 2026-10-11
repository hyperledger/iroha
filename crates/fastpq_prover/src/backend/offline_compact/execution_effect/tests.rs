//! Complete-effect API limits, source substitution and original-credit controls.

use super::*;
use crate::backend::{
    compact_bundle::execution_effect::{EffectBundleWire, encode},
    compact_execution_effect_batch::{EffectBatchLimits, ExecutionEffectBatch, tests::fixture},
    compact_public_batch::BatchContextLimits,
};
use iroha_crypto::Hash;
use iroha_data_model::fastpq::{
    FastpqOrdinaryCompactArtifactV1, execution_effect_statement_digest_v1,
};

pub(in crate::backend) fn policy(count: usize) -> ExecutionEffectVerificationLimits {
    let mut limits = ExecutionEffectVerificationLimits::default();
    limits.bundle.max_segments = count;
    limits.bundle.max_total_queries = count * crate::backend::deep_geometry::QUERY_COUNT;
    limits.bundle.max_wire_bytes = 16 * 1024 * 1024;
    limits.bundle.max_total_segment_bytes = 16 * 1024 * 1024;
    limits.transport.max_wire_bytes = 16 * 1024 * 1024;
    limits.transport.max_bundle_frame_bytes = 16 * 1024 * 1024;
    limits
}

#[test]
fn ordinary_defaults_retain_every_existing_proof_and_decode_ceiling() {
    let effect = ExecutionEffectVerificationLimits::default();
    let axt = VerificationLimits::default();
    assert_eq!(format!("{:?}", effect.proof_policy()), format!("{axt:?}"));
    assert_eq!(effect.public_statement, ExecutionEffectLimits::default());
    let mut widened = effect;
    widened.public_statement.max_effects = usize::MAX;
    widened.public_statement.max_rows = usize::MAX;
    widened.public_statement.max_public_bytes = usize::MAX;
    widened.public_statement.max_unique_keys = usize::MAX;
    widened.public_statement.max_allocation_steps = usize::MAX;
    assert_eq!(widened.public_policy(), effect.public_statement);
    assert_ne!(execution_effect_profile_id(), quantity_profile_id());
}
#[test]
fn ordinary_demand_includes_each_preparation_tree_roots_and_both_contexts() {
    let (source, statement, roots) = fixture();
    let n = statement.effects.effects.len();
    let limits = policy(n);
    let proving = ProvingLimits {
        private_smt: TransferSmtBuildLimits::for_update_limit(2 * n).unwrap(),
        ..ProvingLimits::default()
    };
    let view = SourceExecutionEffectStatement::from_owned(&statement);
    let public = preparation_allocation_bytes(&statement.effects, limits.public_policy()).unwrap();
    let batch =
        quantity_ordinary_verification_allocation_bytes(&statement.effects, &limits).unwrap();
    let exact_batch = ExecutionEffectBatch::allocation_bytes(
        &view,
        &source,
        &roots,
        EffectBatchLimits {
            public: limits.public_policy(),
            context: BatchContextLimits {
                max_segments: n,
                max_total_statement_bytes: limits.bundle.max_total_statement_bytes,
            },
        },
    )
    .unwrap();
    assert!(batch >= exact_batch);
    let tree = proving
        .private_smt
        .allocation_bytes(
            2 * n,
            (2 * n)
                .min(limits.public_policy().max_unique_keys)
                .min(proving.private_smt.max_unique_keys),
        )
        .unwrap();
    let demand = quantity_ordinary_allocation_bytes(&statement.effects, proving, &limits).unwrap();
    assert_eq!(
        demand,
        public + tree + array_bytes::<[u8; 32]>(n - 1).unwrap() + 2 * batch
    );
    assert!(add(usize::MAX, 1).is_err());
    assert!(array_bytes::<PublicStatement>(usize::MAX).is_err());
    let mut empty = statement.effects.clone();
    empty.effects.clear();
    assert!(quantity_ordinary_verification_allocation_bytes(&empty, &limits).is_err());
    let mut narrow = limits;
    narrow.bundle.max_segments = n - 1;
    assert!(quantity_ordinary_verification_allocation_bytes(&statement.effects, &narrow).is_err());
}
#[test]
fn full_expected_source_and_statement_are_checked_before_any_child_success() {
    let (source, statement, roots) = fixture();
    let n = statement.effects.effects.len();
    let limits = policy(n);
    let facts = ExecutionEffectExpectations {
        effects_digest: Hash::from_marked_bytes(source.effects_digest).unwrap(),
        statement_digest: execution_effect_statement_digest_v1(&statement).unwrap(),
        public_inputs: statement.public_inputs,
    };
    let model = FastpqOrdinaryCompactArtifactV1 {
        profile_id: execution_effect_profile_id(),
        source: source.clone(),
        statement,
        bundle_frame: encode(
            &EffectBundleWire {
                version: 1,
                intermediate_roots: roots,
                segments: vec![vec![0xff]; n],
            },
            n,
            limits.bundle.internal(),
        )
        .unwrap(),
    };
    let bytes = norito::encode_canonical(&model).unwrap();
    let demand =
        quantity_ordinary_verification_allocation_bytes(&model.statement.effects, &limits).unwrap();
    let budget = AllocationBudget::new(demand);
    // Mutation of position alone is not represented in the statement tape, so
    // this also proves the outer comparison is of the full independently owned leaf.
    for mutation in 0..13 {
        let mut expected_source = source.clone();
        match mutation {
            0 => expected_source.statement_index += 1,
            1 => expected_source.entry_index += 1,
            2 => expected_source.source.height += 1,
            3 => expected_source.slot += 1,
            4 => expected_source.effects_digest[0] ^= 1,
            5 => expected_source.effect_count += 1,
            6 => expected_source.entry_hash = Hash::new(b"other original execution entry"),
            7 => {
                expected_source.execution_kind =
                    iroha_data_model::fastpq::FastpqSourceExecutionKindV1::ProtocolPurpose
            }
            8 => expected_source.dataspace_id = iroha_model_base::topology::DataSpaceId::new(99),
            9 => expected_source.perm_root[0] ^= 1,
            10 => expected_source.tx_set_hash[0] ^= 1,
            11 => {
                expected_source.source.network_id = iroha_data_model::NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                        b"other authenticated network",
                    )),
                )
            }
            12 => {
                expected_source.route = iroha_data_model::fastpq::FastpqSourceRouteV1::Lane(
                    iroha_data_model::fastpq::FastpqSourceLaneV1 {
                        lane_id: iroha_model_base::topology::LaneId::new(9),
                        lane_incarnation: Hash::new(b"other source lane incarnation"),
                    },
                )
            }
            _ => unreachable!(),
        }
        let mut reservation = budget.try_reserve_bytes(demand).unwrap();
        assert!(matches!(
            verify_quantity_ordinary_artifact(
                &bytes,
                ExpectedExecutionEffects {
                    source: &expected_source,
                    statement: facts
                },
                &limits,
                &budget,
                &mut reservation
            ),
            Err(VerificationError::Verify(Error::PublicIoMismatch {
                field: "compact_artifact_execution_source"
            }))
        ));
        assert_eq!(reservation.remaining_bytes(), demand);
        drop(reservation);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let mut bad = facts;
    bad.statement_digest = Hash::new(b"different complete statement");
    let mut reservation = budget.try_reserve_bytes(demand).unwrap();
    assert!(matches!(
        verify_quantity_ordinary_artifact(
            &bytes,
            ExpectedExecutionEffects {
                source: &source,
                statement: bad
            },
            &limits,
            &budget,
            &mut reservation
        ),
        Err(VerificationError::Verify(Error::PublicIoMismatch {
            field: "compact_artifact_public_statement_digest"
        }))
    ));
    assert_eq!(reservation.remaining_bytes(), demand);
    drop(reservation);
    let mut bad_effects = facts;
    bad_effects.effects_digest = Hash::new(b"different original complete effects");
    let mut reservation = budget.try_reserve_bytes(demand).unwrap();
    assert!(matches!(verify_quantity_ordinary_artifact(
        &bytes, ExpectedExecutionEffects { source: &source, statement: bad_effects },
        &limits, &budget, &mut reservation),
        Err(VerificationError::Verify(Error::TransferInvariant { details }))
            if details == "execution effect source digest expectation mismatch"));
    assert_eq!(reservation.remaining_bytes(), demand);
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
    let foreign = AllocationBudget::new(demand);
    let mut reservation = foreign.try_reserve_bytes(demand).unwrap();
    assert!(matches!(
        verify_quantity_ordinary_artifact(
            &[],
            ExpectedExecutionEffects {
                source: &source,
                statement: facts
            },
            &limits,
            &budget,
            &mut reservation
        ),
        Err(VerificationError::Verify(Error::AllocationForeignPool))
    ));
    drop(reservation);
    let mut reservation = budget.try_reserve_bytes(demand).unwrap();
    assert!(
        verify_quantity_ordinary_artifact(
            &bytes,
            ExpectedExecutionEffects {
                source: &source,
                statement: facts
            },
            &limits,
            &budget,
            &mut reservation
        )
        .is_err()
    );
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
}
