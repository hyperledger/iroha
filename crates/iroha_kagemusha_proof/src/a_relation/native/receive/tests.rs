//! Native Receive input, exact original digest and deciding-selection rejection tests.

use super::*;
use crate::a_relation::native::support::{select_pallas, select_vesta};
use crate::a_relation::schedule::OperationTask;
use iroha_plonk_recursion::K;

#[test]
fn installed_transport_and_sigma_descriptors_must_fit_the_exact_payment_budget() {
    let public = crate::a_relation::own::ConsumingProofCells::PUBLIC_BYTES;
    for sigma in 0..=PAYMENT_PROOF_BUDGET {
        let omega = public + PAYMENT_PROOF_BUDGET - sigma;
        assert!(validate_transport_profile(omega, sigma).is_ok());
        assert_eq!(
            validate_transport_profile(omega + 1, sigma),
            Err(Error::Artifact)
        );
        assert_eq!(
            validate_transport_profile(omega, sigma + 1),
            Err(Error::Artifact)
        );
    }
    for (omega, sigma) in [(public - 1, 0), (usize::MAX, usize::MAX)] {
        assert_eq!(
            validate_transport_profile(omega, sigma),
            Err(Error::Artifact)
        );
    }
}

fn incoming() -> IncomingWitness {
    let p = iroha_plonk::transcript::decode_point::<Ep>(
        &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let v = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let p = FoldInput::from_normalized(p, 16, [Fq::ONE; K]).unwrap();
    let v = FoldInput::<Eq>::from_normalized(v, 16, [Fp::ONE; K]).unwrap();
    IncomingWitness {
        public: [Fp::ZERO; 18],
        public_valid: true,
        pallas: AccumulatorT::new(*p.g(), *p.challenges()).unwrap(),
        vesta: AccumulatorT::new(*v.g(), *v.challenges()).unwrap(),
        opening: p.clone(),
        results: [true; 5],
        modes: [IncomingMode::Accept; 4],
        pallas_corrections: [*p.g(); 2],
        vesta_correction: *v.g(),
    }
}

#[test]
fn every_result_and_mode_pattern_obeys_exact_non_discretionary_burn_rule() {
    let mut input = incoming();
    for mask in 0..32 {
        input.results = core::array::from_fn(|i| mask & (1 << i) != 0);
        for code in 0..81 {
            let mut code = code;
            input.modes = core::array::from_fn(|_| {
                let mode = match code % 3 {
                    0 => IncomingMode::Accept,
                    1 => IncomingMode::Trivial,
                    _ => IncomingMode::Corrected,
                };
                code /= 3;
                mode
            });
            let corrections = input
                .modes
                .iter()
                .filter(|m| **m == IncomingMode::Corrected)
                .count();
            let valid = input.results.iter().all(|v| *v) && corrections == 0;
            let expected = corrections <= 1
                && input
                    .modes
                    .iter()
                    .all(|m| (*m == IncomingMode::Accept) == valid);
            assert_eq!(
                validate_modes(&input).is_ok(),
                expected,
                "mask={mask} modes={:?}",
                input.modes
            );
        }
    }
}

#[test]
fn corrected_pallas_retains_challenges_and_requires_a_distinct_deciding_point() {
    let input = incoming();
    let params = PinnedParams::derive(16).unwrap();
    let good = input.pallas.as_input();
    let (x, y) = Option::<(Fp, Fp)>::from(good.g().coordinates()).unwrap();
    let wrong = Option::<EpAffine>::from(EpAffine::from_xy(x, -y)).unwrap();
    let original = FoldInput::from_normalized(wrong, 16, *good.challenges()).unwrap();
    assert!(
        select_pallas(
            &params,
            &original,
            IncomingMode::Accept,
            *good.g(),
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
    assert!(
        select_pallas(
            &params,
            &original,
            IncomingMode::Corrected,
            wrong,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
    let corrected = select_pallas(
        &params,
        &original,
        IncomingMode::Corrected,
        *good.g(),
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    assert_eq!(corrected.challenges(), original.challenges());
    assert_eq!(corrected.g(), good.g());
    assert!(
        select_pallas(
            &params,
            &good,
            IncomingMode::Corrected,
            wrong,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
    let trivial = select_pallas(
        &params,
        &original,
        IncomingMode::Trivial,
        wrong,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    assert_eq!(trivial, good);
}

#[test]
fn corrected_vesta_retains_challenges_and_requires_a_distinct_deciding_point() {
    let input = incoming();
    let params = PinnedParams::derive(16).unwrap();
    let good = input.vesta.as_input();
    let (x, y) = Option::<(Fq, Fq)>::from(good.g().coordinates()).unwrap();
    let wrong = Option::<EqAffine>::from(EqAffine::from_xy(x, -y)).unwrap();
    let original = FoldInput::from_normalized(wrong, 16, *good.challenges()).unwrap();
    assert!(
        select_vesta(
            &params,
            &original,
            IncomingMode::Accept,
            *good.g(),
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
    assert!(
        select_vesta(
            &params,
            &original,
            IncomingMode::Corrected,
            wrong,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
    let corrected = select_vesta(
        &params,
        &original,
        IncomingMode::Corrected,
        *good.g(),
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    assert_eq!(corrected.challenges(), original.challenges());
    assert_eq!(corrected.g(), good.g());
    assert!(
        select_vesta(
            &params,
            &good,
            IncomingMode::Corrected,
            wrong,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
    let trivial = select_vesta(
        &params,
        &original,
        IncomingMode::Trivial,
        wrong,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    assert_eq!(trivial, good);
}

#[test]
fn exact_original_digest_distinguishes_lengths_tails_and_every_signed_limb() {
    let specs =
        ReceiveStagePlan::context_specs(Variant::Receive, MAX_OMEGA_RAW_BYTES, MAX_SIGMA_RAW_BYTES)
            .unwrap();
    let mut objects =
        core::array::from_fn(|i| vec![0; usize::try_from(specs[i].capacity).unwrap()]);
    objects[4] = vec![7; 320 + 3712 + 1088];
    objects[5] = vec![11; 3296];
    let original = object_commitments(&specs, &objects).unwrap();
    for slot in 0..11 {
        for mutation in [0, objects[slot].len() / 2, objects[slot].len() - 1] {
            let mut bad = objects.clone();
            bad[slot][mutation] ^= 1;
            let changed = object_commitments(&specs, &bad).unwrap();
            assert_ne!(changed[slot], original[slot]);
            if slot == 5 {
                assert_ne!(changed[4][0], original[4][0]);
            }
        }
    }
    for slot in [4, 5] {
        let mut bad = objects.clone();
        bad[slot].push(0);
        let changed = object_commitments(&specs, &bad).unwrap();
        assert_ne!(changed[4][0], original[4][0]);
        assert_ne!(changed[slot][1], original[slot][1]);
        assert_ne!(changed[slot][2], original[slot][2]);
    }
    for slot in [0, 1, 2, 6, 7, 8, 9, 10] {
        let mut bad = objects.clone();
        bad[slot].pop();
        assert_eq!(object_commitments(&specs, &bad), Err(Error::Input));
    }
}

#[test]
fn mandatory_owner_schedule_keeps_own_sigma_before_its_later_q_verification() {
    let tasks =
        crate::a_relation::schedule::compiled::OperationSchedule::for_variant(Variant::Receive)
            .tasks()
            .to_vec();
    assert_eq!(tasks.len(), A_STAGE_COUNT);
    assert_eq!(
        tasks[0],
        [
            OperationTask::ReceiveOwnProof,
            OperationTask::ReceiveConsumedEffects,
            OperationTask::ReceiveCreditEffects
        ]
    );
    assert_eq!(tasks[5], [OperationTask::ReceiveAuthorization]);
    assert_eq!(tasks[9], [OperationTask::ReceiveEffects]);
    let mut flat = tasks
        .into_iter()
        .flatten()
        .map(|t| t as u32)
        .collect::<Vec<_>>();
    flat.sort_unstable();
    assert_eq!(flat, [11, 12, 13, 14, 15, 16, 17, 18, 23, 36, 37]);
    assert_eq!((INTERNAL_RANGE_BUSES, TERMINAL_RANGE_BUSES), (4, 3));
}

#[test]
fn native_terminal_matches_current_catalog_profile_and_internal_is_exactly_distinct() {
    let internal =
        super::super::artifact::source_descriptor::<StageCircuit>(INTERNAL_RANGE_BUSES).unwrap();
    let terminal =
        super::super::artifact::source_descriptor::<StageCircuit>(TERMINAL_RANGE_BUSES).unwrap();
    let send =
        super::super::artifact::source_descriptor::<super::super::send::StageCircuit>(()).unwrap();
    assert_eq!(terminal, send);
    assert_ne!(internal, terminal);
    assert_eq!(internal.descriptor().lookups.len(), 5);
    assert_eq!(terminal.descriptor().lookups.len(), 4);
    assert_eq!(internal.descriptor().instance_lengths, [69]);
    assert_eq!(terminal.descriptor().instance_lengths, [69]);
}

#[test]
fn every_admitted_joint_split_and_one_byte_over_boundary_is_exact() {
    let bound = 320 + PAYMENT_PROOF_BUDGET;
    assert_eq!(check_payment_original_sizes(0, 0), Ok(()));
    for sigma in 0..=MAX_SIGMA_RAW_BYTES {
        let omega = bound - sigma;
        assert_eq!(check_payment_original_sizes(omega, sigma), Ok(()));
        assert_eq!(
            check_payment_original_sizes(omega + 1, sigma),
            Err(Error::Input)
        );
        assert_eq!(
            check_payment_original_sizes(omega, sigma + 1),
            Err(Error::Input)
        );
    }
    assert_eq!(
        check_payment_original_sizes(usize::MAX, 1),
        Err(Error::Input)
    );
    assert_eq!(
        check_payment_original_sizes(0, MAX_SIGMA_RAW_BYTES + 1),
        Err(Error::Input)
    );
    assert_eq!(
        check_payment_original_sizes(MAX_OMEGA_RAW_BYTES + 1, 0),
        Err(Error::Input)
    );
}
