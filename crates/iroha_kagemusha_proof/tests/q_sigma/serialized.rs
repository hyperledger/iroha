//! Explicit serialized Q profile diagnostics using the complete unchanged relation.

use super::*;
use iroha_kagemusha_proof::q_sigma::SerializedQSigmaCircuit;
use iroha_pasta::Ep;
use iroha_plonk::{
    ProverConfig, Witness, create_proof_owned_with_claim,
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
};

fn profile(circuit: &QSigmaCircuit, buses: usize) -> SerializedQSigmaCircuit {
    circuit.clone().with_serialized_foreign(buses).unwrap()
}

fn result(circuit: &QSigmaCircuit, buses: usize, public: &[Vec<Fq>], expected: bool) {
    let assigned = synthesize(&profile(circuit, buses), 16, Some(public)).unwrap();
    let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
    assert_eq!(report.is_satisfied(), expected, "{report:?}");
}

fn inventory(circuit: &QSigmaCircuit, buses: usize, public: &[Vec<Fq>], label: &str) -> Protocol {
    let circuit = profile(circuit, buses);
    let assigned = synthesize(&circuit, 16, Some(public)).expect("candidate Q must fit k16");
    let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{report:?}");
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
    assert_eq!(assigned.tables.selectors(), unknown.tables.selectors());
    assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        assigned.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let lanes: Vec<_> = assigned
        .tables
        .advice_assigned()
        .iter()
        .map(|column| {
            column
                .iter()
                .rposition(|assigned| *assigned)
                .map_or(0, |row| row + 1)
        })
        .collect();
    let finalized = assigned
        .cs
        .finalize(assigned.tables.selectors(), true)
        .unwrap();
    let layout = CircuitDescriptorV1::from_constraint_system(
        &finalized,
        DescriptorConfig {
            curve: CurveV1::Pallas,
            k: 16,
            transcript: TranscriptV1::Blake2bChallenge255,
            instance_mode: InstanceModeV1::Direct,
            proof_suffix: ProofSuffixV1::FoldedGenerator,
        },
    )
    .unwrap();
    let descriptor = CircuitDescriptorV2::from_layout(
        layout,
        TranscriptV2::KagemushaPoseidonRp57Base,
        QSigmaPlan::instance_types().to_vec(),
    )
    .unwrap();
    let protocol = Protocol::new(&descriptor).unwrap();
    println!(
        "SERIALIZED_Q_SIGMA {label} buses={buses} lanes={lanes:?} shape={:?} estimated_proof_bytes={} actual_proof=false known_unknown_equal=true qualification=false",
        protocol.shape(),
        protocol.proof_length()
    );
    protocol
}

#[test]
fn serialized_byte_tape_rejects_invalid_fixed_range_bus_count() {
    use iroha_plonk::cs::ConstraintSystem;
    use iroha_plonk_recursion::verifier::VerifierConfig;
    for count in [0, 9, usize::MAX] {
        assert!(
            VerifierConfig::<Ep>::configure_serialized_with_byte_tape(
                &mut ConstraintSystem::default(),
                count,
                32
            )
            .is_err()
        );
        assert!(
            VerifierConfig::<Eq>::configure_serialized_with_byte_tape(
                &mut ConstraintSystem::default(),
                count,
                32
            )
            .is_err()
        );
    }
}

#[test]
#[ignore = "real k12/k14 sigma and complete serialized Q relation; run optimized"]
fn serialized_single_sigma_preserves_byte_and_public_bindings() {
    let params = common::vesta_params(16);
    for (relation, k) in [(SigmaRelation::SEND, 12), (common::SEND_EVERY, 14)] {
        let (class, own, claim) = slot(relation, k, 5);
        let circuit = QSigmaCircuit::new(
            QSigmaPlan::new(class, None, &params).unwrap(),
            QSigmaWitness {
                own,
                incoming: None,
            },
        )
        .unwrap();
        assert!(circuit.clone().with_serialized_foreign(0).is_err());
        assert!(circuit.clone().with_serialized_foreign(9).is_err());
        let public = public(&circuit, &claim, &[5], true);
        for buses in [2, 3] {
            inventory(&circuit, buses, &public, &format!("one-k{k}"));
        }
        for (column, row) in [
            (0, 0),
            (0, 1),
            (0, public[0].len() - 1),
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 0),
        ] {
            let mut forged = public.clone();
            forged[column][row] += Fq::ONE;
            result(&circuit, 2, &forged, false);
        }
        let mut forged = circuit.clone();
        forged.witness.own.length -= 1;
        result(
            &forged,
            2,
            &super::public(&forged, &claim, &[5], true),
            false,
        );
        let mut forged = circuit.clone();
        forged.witness.own.proof[0] ^= 1;
        result(
            &forged,
            2,
            &super::public(&forged, &claim, &[5], true),
            false,
        );
    }
}

#[test]
#[ignore = "real two-sigma plus AS serialized Q proof and mutation corpus; run optimized"]
fn serialized_two_sigmas_fold_and_prove_without_default_key_changes() {
    rayon::ThreadPoolBuilder::new().num_threads(4).build().unwrap().install(|| {
        let params = common::vesta_params(16);
        let (own_class, own, own_claim) = slot(SigmaRelation::RECEIVE, 12, 3);
        let (incoming_class, incoming, incoming_claim) = slot(common::SEND_EVERY, 14, 9);
        let trivial = AccumulatorT::trivial(&params, MemoryBudget::DEFAULT).unwrap();
        let plan = QSigmaPlan::new(own_class, Some(incoming_class), &params).unwrap();
        for valid in [true, false] {
            let selected = if valid { incoming_claim.clone() } else { trivial.as_input() };
            let (fold, part) = create_fold(&params, &[own_claim.clone(), selected, trivial.as_input()],
                Fq::from(73).to_repr(), &FoldConfig::default()).unwrap();
            part.decide(&params, MemoryBudget::DEFAULT).unwrap();
            let mut sigma = incoming.clone();
            if !valid { sigma.proof[0] ^= 1; }
            let circuit = QSigmaCircuit::new(plan.clone(), QSigmaWitness {
                own: own.clone(), incoming: Some(IncomingSigmaWitness { sigma,
                    mode: [valid,!valid,false], corrected: Eq::from(*trivial.g()), fold: fold.to_bytes() })
            }).unwrap();
            let public = public(&circuit, &part.as_input(), &[3,9], valid);
            let protocol = inventory(&circuit, 2, &public, if valid { "two-accept" } else { "two-trivial" });
            let mut forged_public = public.clone();
            forged_public[3][1] = Fq::from(u64::from(!valid));
            result(&circuit, 2, &forged_public, false);
            let mut forged = circuit.clone();
            forged.witness.incoming.as_mut().unwrap().fold[32] ^= 1;
            result(&forged, 2, &public, false);
            let mut forged = circuit.clone();
            forged.witness.incoming.as_mut().unwrap().mode = [true,true,false];
            result(&forged, 2, &super::public(&forged, &part.as_input(), &[3,9], valid), false);
            if valid {
                let params = PinnedParams::<Ep>::derive(16).unwrap();
                let candidate = profile(&circuit, 2);
                let key = keygen_pk_v2(&params, &candidate,
                    &KeygenConfigV2::pipa_r(QSigmaPlan::instance_types().to_vec())).unwrap();
                assert!(Witness::from_circuit(&key, &circuit, &public).is_err());
                let output = create_proof_owned_with_claim(&params, &key,
                    Witness::from_circuit(&key, &candidate, &public).unwrap(),
                    common::recovery(99), ProverConfig::default()).unwrap();
                assert_eq!(output.proof.len(), protocol.proof_length());
                iroha_plonk::verify_full(&params, key.binding(), key.vk(), &public,
                    &output.proof, MemoryBudget::DEFAULT).unwrap();
                assert!(iroha_plonk::verify_full(&params, key.binding(), key.vk(), &forged_public,
                    &output.proof, MemoryBudget::DEFAULT).is_err());
                println!("SERIALIZED_Q_SIGMA_ACTUAL_PROOF buses=2 bytes={} own_k12 incoming_k14=true local_AS=true full_native_verify=true qualification=false", output.proof.len());
            }
        }
    });
}
