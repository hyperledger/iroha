//! The shape selector on every relation shape: the smallest `k` that fits,
//! the shape within the 3.5 KB proof budget, exact proof lengths from the
//! descriptor, row inventories, and the descriptor and key bytes a verifier
//! reconstructs from bytes alone.

mod common;

use common::{
    BUDGET_SHAPE, K11_SHAPE, SMALLEST_SHAPE, budget_shape, folded, pinned_shape, relation_shapes,
    smallest_shape, vesta_prover,
};
use iroha_kagemusha_proof::{
    PROOF_BYTES_GATE, ShapePolicy, SigmaParams, SigmaRelation, SigmaShape, SigmaVerifier,
    limb_bits_for, select_shape,
};
use iroha_pasta::{Ep, Eq, Fp};
use iroha_plonk_gadgets::poseidon::ROWS_PER_PERMUTATION;

fn describe(label: &str, shape: &SigmaShape) -> usize {
    let inventory = shape.inventory::<Fp>().expect("inventory");
    let bytes = shape.proof_length::<Eq>().expect("proof length");
    let descriptor = shape.descriptor::<Eq>().expect("descriptor");
    println!(
        "SHAPE {label} case={} k={} lanes={} limb_bits={} permutations={:?} lane_rows={:?} \
         glue_rows={} range_rows={} cells={} advice_cols={} fixed_cols={} degree={} \
         equality_cols={} proof_bytes={bytes}",
        shape.params.relation().label(),
        shape.k,
        shape.params.lanes(),
        shape.params.limb_bits(),
        inventory.lane_permutations,
        inventory.lane_rows,
        inventory.glue_rows,
        inventory.range_rows,
        inventory.cells,
        descriptor.num_advice_columns,
        descriptor.num_fixed_columns,
        descriptor.degree,
        descriptor.permutation.len(),
    );
    assert_eq!(
        inventory.permutations(),
        shape.params.relation().permutations()
    );
    assert!(inventory.rows() < 1 << shape.k);
    assert_eq!(
        inventory.lane_rows.iter().sum::<usize>(),
        inventory.permutations() * ROWS_PER_PERMUTATION + inventory.glue_rows
    );
    assert_eq!(
        usize::from(descriptor.degree),
        6,
        "Pow5 lanes keep degree 6"
    );
    bytes
}

#[test]
fn selected_shapes_fit_and_meet_the_budget() {
    for relation in relation_shapes() {
        let smallest = smallest_shape(relation);
        let budget = budget_shape(relation);
        describe("smallest_k", &smallest);
        let bytes = describe("budget", &budget);
        assert!(bytes <= PROOF_BYTES_GATE, "{}: {bytes} B", relation.label());
        assert!(smallest.k <= budget.k);
        // Nothing smaller fits.
        if smallest.k > 9 {
            for lanes in 1..=iroha_kagemusha_proof::MAX_LANES {
                let params = SigmaParams::new(
                    relation,
                    lanes,
                    iroha_kagemusha_proof::limb_bits_for(smallest.k - 1),
                )
                .expect("params");
                assert!(
                    SigmaShape::new(params, smallest.k - 1)
                        .inventory::<Fp>()
                        .is_err(),
                    "{} fits k = {} with {lanes} lanes",
                    relation.label(),
                    smallest.k - 1
                );
            }
        }
    }
}

/// The pinned shapes of one relation: the selector's smallest `k` (fewest
/// lanes), its shape within the 3.5 KB budget, the fewest lanes at
/// `k = 11` (none for the quota relations)
/// and every pinned shape's exact proof length.
struct Pinned {
    relation: SigmaRelation,
    smallest: ((u32, usize), usize),
    budget: Option<((u32, usize), usize)>,
    k11: Option<((u32, usize), usize)>,
}

/// The pinned shapes of every relation (folded prefixes).
fn pinned() -> [Pinned; 10] {
    use common::{RECEIVE_BLACKLIST, SEND_BLACKLIST, SEND_EVERY, SEND_LEASE, SEND_QUOTAS};
    let k12_class = |relation, budget_bytes| Pinned {
        relation,
        smallest: (SMALLEST_SHAPE, 5_120),
        budget: Some((BUDGET_SHAPE, budget_bytes)),
        k11: Some((K11_SHAPE, 3_840)),
    };
    // The blacklist gap opening adds a 36-permutation site on one lane
    // (1,332 rows, more than a k = 10 lane holds) and two absorbed
    // prefixes, so no selector column: the smallest k is 11, and the
    // one-lane k = 12 proof is the base length.
    let gap_class = |relation| Pinned {
        relation,
        smallest: ((11, 2), 3_840),
        budget: Some((BUDGET_SHAPE, 3_296)),
        k11: Some((K11_SHAPE, 3_840)),
    };
    // Fixed-array quota charges need k = 12 on four lanes and k = 14
    // on one lane; the latter meets both the 3.5 KB and joint Payment budgets.
    let quota_class = |relation| Pinned {
        relation,
        smallest: ((12, 4), 5_280),
        budget: Some(((14, 1), 3_456)),
        k11: None,
    };
    [
        k12_class(SigmaRelation::SEND, 3_296),
        gap_class(SEND_BLACKLIST),
        k12_class(SEND_LEASE, 3_296),
        quota_class(SEND_QUOTAS),
        quota_class(SigmaRelation::send(3)),
        gap_class(SigmaRelation::send(5)),
        quota_class(SigmaRelation::send(6)),
        quota_class(SEND_EVERY),
        k12_class(SigmaRelation::RECEIVE, 3_296),
        gap_class(RECEIVE_BLACKLIST),
    ]
}

/// The exact proof length of `shape` (the same on both curves).
fn length(shape: &SigmaShape) -> usize {
    let bytes = shape.proof_length::<Eq>().expect("length");
    assert_eq!(Ok(bytes), shape.proof_length::<Ep>());
    bytes
}

#[test]
fn every_relation_selects_the_pinned_shapes() {
    for pin in pinned() {
        let relation = folded(pin.relation);
        let label = relation.label();
        let smallest = smallest_shape(relation);
        assert_eq!(
            ((smallest.k, smallest.params.lanes()), length(&smallest)),
            pin.smallest,
            "{label}"
        );
        assert_eq!(smallest, pinned_shape(relation, pin.smallest.0), "{label}");
        let budget = select_shape::<Eq>(relation, &ShapePolicy::default()).map(|choice| {
            let shape = choice.shape;
            ((shape.k, shape.params.lanes()), length(&shape))
        });
        assert_eq!(budget.ok(), pin.budget, "{label}");
        let k11 = select_shape::<Eq>(
            relation,
            &ShapePolicy {
                min_k: 11,
                max_k: 11,
                max_proof_bytes: None,
                ..ShapePolicy::smallest_k()
            },
        )
        .map(|choice| {
            let shape = choice.shape;
            ((shape.k, shape.params.lanes()), length(&shape))
        });
        assert_eq!(k11.ok(), pin.k11, "{label}");
        // At k = 11 a single lane never fits; two lanes exceed the budget.
        let one_lane = SigmaParams::new(relation, 1, limb_bits_for(11)).expect("params");
        assert!(SigmaShape::new(one_lane, 11).inventory::<Fp>().is_err());
        if let Some((_, bytes)) = pin.k11 {
            assert!(bytes > PROOF_BYTES_GATE, "{bytes}");
        }
        println!(
            "SHAPE pinned case={label} smallest={:?} budget={:?} k11={:?}",
            pin.smallest, pin.budget, pin.k11
        );
    }
}

/// The fixed-array quota relations on one lane meet the joint Payment
/// budget at `k = 14`, including every control and both core time bounds.
#[test]
fn quota_relations_fit_one_lane_at_k14() {
    use common::{SEND_EVERY, SEND_QUOTAS};
    for (relation, rows) in [(SEND_QUOTAS, 12_123), (SEND_EVERY, 13_542)] {
        let relation = folded(relation);
        let shape = pinned_shape(relation, (14, 1));
        let inventory = shape.inventory::<Fp>().expect("fits k = 14");
        assert_eq!(inventory.rows(), rows, "{}", relation.label());
        assert_eq!(length(&shape), 3_456, "{}", relation.label());
        assert!(
            length(&shape) <= 3_541,
            "G1rev4 sigma share of Payment budget"
        );
        let k13 = pinned_shape(relation, (13, 1));
        assert!(k13.inventory::<Fp>().is_err(), "{}", relation.label());
        describe("k14_one_lane", &shape);
    }
}

#[test]
fn verifiers_rebuild_from_descriptor_and_key_bytes() {
    use iroha_kagemusha_proof::{SigmaCircuit, SigmaError};
    use iroha_plonk::{
        cs::{InstanceType, TranscriptV2},
        keys::{KeygenConfig, keygen_pk},
    };
    let shape = smallest_shape(folded(SigmaRelation::RECEIVE));
    let prover = vesta_prover(shape);
    let descriptor = shape.descriptor::<Eq>().expect("descriptor");
    assert_eq!(
        prover.proving_key().binding().encoded(),
        descriptor.encode().expect("encoded")
    );
    let verifier = prover.verifier();
    let rebuilt = SigmaVerifier::<Eq>::from_bytes(
        SigmaRelation::RECEIVE,
        prover.params().clone(),
        verifier.descriptor_bytes(),
        verifier.vk_bytes(),
    )
    .expect("verifier from bytes");
    assert_eq!(rebuilt.vk_bytes(), verifier.vk_bytes());
    assert_eq!(rebuilt.binding(), verifier.binding());
    assert_eq!(rebuilt.relation(), SigmaRelation::RECEIVE);
    assert_eq!(rebuilt.allowlist_entry(), verifier.allowlist_entry());
    // Keys are deterministic.
    let again = vesta_prover(shape);
    assert_eq!(again.verifier().vk_bytes(), verifier.vk_bytes());
    // Sigma admits exactly V2, PIPA-R, Direct, suffix, one Bounded value.
    for change in 0..3 {
        let mut invalid = descriptor.clone();
        match change {
            0 => invalid.transcript = TranscriptV2::KagemushaPoseidonRp57,
            1 => invalid.instance_types = vec![InstanceType::Field],
            _ => invalid.instance_lengths = vec![2],
        }
        assert!(matches!(
            SigmaVerifier::<Eq>::from_bytes(
                SigmaRelation::RECEIVE,
                prover.params().clone(),
                &invalid.encode().expect("valid alternate descriptor"),
                verifier.vk_bytes(),
            ),
            Err(SigmaError::Profile)
        ));
    }
    let retired = keygen_pk(
        prover.params(),
        &SigmaCircuit::<Fp>::keygen(shape.params),
        &KeygenConfig::new(iroha_plonk::cs::TranscriptV1::KagemushaPoseidonRp57),
    )
    .expect("V1 fixture");
    assert!(matches!(
        SigmaVerifier::<Eq>::from_bytes(
            SigmaRelation::RECEIVE,
            prover.params().clone(),
            retired.binding().encoded(),
            retired.vk().to_bytes(),
        ),
        Err(SigmaError::Descriptor(_))
    ));
    assert_eq!(
        descriptor.transcript,
        TranscriptV2::KagemushaPoseidonRp57Base
    );
    assert_eq!(descriptor.instance_types, [InstanceType::Bounded]);
    // Parameters of another k are refused.
    assert!(
        SigmaVerifier::<Eq>::from_bytes(
            SigmaRelation::RECEIVE,
            common::vesta_params(shape.k + 1),
            verifier.descriptor_bytes(),
            verifier.vk_bytes(),
        )
        .is_err()
    );
    let mut truncated = verifier.vk_bytes().to_vec();
    truncated.pop();
    assert!(
        SigmaVerifier::<Eq>::from_bytes(
            SigmaRelation::RECEIVE,
            prover.params().clone(),
            verifier.descriptor_bytes(),
            &truncated,
        )
        .is_err()
    );
}

#[test]
fn commitment_tables_change_no_key_or_proof_byte() {
    use iroha_kagemusha_proof::{KeyOptions, Mutation, SigmaProver, sample_witness};

    let shape = smallest_shape(folded(SigmaRelation::RECEIVE));
    let plain = vesta_prover(shape);
    let tabled = SigmaProver::<Eq>::keygen_with_options(
        shape,
        common::vesta_params(shape.k),
        KeyOptions::WITH_TABLES,
    )
    .expect("keys with tables");
    assert_eq!(KeyOptions::default().commitment_tables, None);
    assert_eq!(
        tabled.proving_key().commitment_tables().present(),
        (true, true)
    );
    assert_eq!(
        plain.proving_key().commitment_tables().present(),
        (false, false)
    );
    assert_eq!(tabled.verifier().vk_bytes(), plain.verifier().vk_bytes());
    let witness = sample_witness::<Fp>(3, SigmaRelation::RECEIVE, Mutation::None);
    let with_tables = tabled
        .prove(&witness, common::recovery(4))
        .expect("proof with tables");
    let without = plain.prove(&witness, common::recovery(4)).expect("proof");
    assert_eq!(with_tables, without);
    assert_eq!(
        plain
            .verifier()
            .verify(&with_tables.public, &with_tables.bytes),
        Ok(())
    );
}

/// Every relation's fewest lanes at each `k` and the exact proof lengths
/// (printed as `SHAPE_TABLE` lines).
#[test]
#[ignore = "probe"]
fn shape_table_probe() {
    for case in (0..=7)
        .map(SigmaRelation::send)
        .chain([SigmaRelation::RECEIVE, common::RECEIVE_BLACKLIST])
    {
        let relation = folded(case);
        for k in 10..=16 {
            for lanes in 1..=iroha_kagemusha_proof::MAX_LANES {
                let params = SigmaParams::new(relation, lanes, limb_bits_for(k)).expect("params");
                let shape = SigmaShape::new(params, k);
                if let Ok(inventory) = shape.inventory::<Fp>() {
                    let bytes = shape.proof_length::<Eq>().expect("length");
                    println!(
                        "SHAPE_TABLE case={} k={k} lanes={lanes} bytes={bytes} perms={:?} rows={:?} glue={} range={}",
                        relation.label(),
                        inventory.lane_permutations,
                        inventory.lane_rows,
                        inventory.glue_rows,
                        inventory.range_rows
                    );
                    break;
                }
            }
        }
    }
}
