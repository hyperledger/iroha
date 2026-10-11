//! Real sigma proofs composed in the `Q_sigma` relation, with byte, key, mode,
//! fold, public-input and known/unknown-shape adversaries.

mod common;
#[path = "q_sigma/serialized.rs"]
mod serialized;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    Mutation, SigmaRelation,
    q_sigma::{
        IncomingSigmaWitness, QSigmaCircuit, QSigmaPlan, QSigmaWitness, SigmaClass,
        SigmaSlotWitness,
    },
    sample_witness,
};
use iroha_pasta::{Eq, Fp, Fq, PastaAffine, PastaField, msm::MemoryBudget};
use iroha_plonk::{
    Protocol,
    check::{CheckMode, check},
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, CurveV1, DescriptorConfig, InstanceModeV1,
        ProofSuffixV1, TranscriptV1, TranscriptV2,
    },
    frontend::{Circuit, synthesize},
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::bytes::tape::{ByteOrder, segment_value};
use iroha_plonk_recursion::{AccumulatorT, FoldConfig, FoldInput, create_fold};

fn scalar(value: Fp) -> Fq {
    Fq::from_canonical_limbs(value.to_canonical_limbs()).unwrap()
}
fn slot(
    relation: SigmaRelation,
    k: u32,
    index: u8,
) -> (SigmaClass, SigmaSlotWitness, FoldInput<Eq>) {
    let prover = common::vesta_prover(common::pinned_shape(common::folded(relation), (k, 1)));
    let witness = sample_witness::<Fp>(common::CHECK_SEED + 2, relation, Mutation::None);
    let proof = prover
        .prove(&witness, common::recovery(37 + index))
        .expect("actual sigma proof");
    let verifier = prover.verifier();
    verifier
        .verify(&proof.public, &proof.bytes)
        .expect("full sigma");
    let claim = accumulate_generator(
        prover.params(),
        verifier.binding(),
        verifier.vk(),
        &[vec![proof.public.statement]],
        &proof.bytes,
        MemoryBudget::DEFAULT,
    )
    .expect("native claim");
    let class = SigmaClass::from_verifiers(&[(index, &verifier)]).unwrap();
    let input = FoldInput::from_opening(*claim.g(), claim.challenges()).unwrap();
    (
        class,
        SigmaSlotWitness {
            key: verifier.vk().clone(),
            statement: proof.public.statement,
            length: u32::try_from(proof.bytes.len()).unwrap(),
            proof: proof.bytes,
        },
        input,
    )
}
fn chunks(witness: &SigmaSlotWitness) -> Vec<Fq> {
    let bytes: Vec<_> = witness
        .length
        .to_le_bytes()
        .into_iter()
        .chain(witness.proof.iter().copied())
        .collect();
    bytes
        .chunks(31)
        .map(|chunk| segment_value(chunk, ByteOrder::Little).unwrap())
        .collect()
}
fn public(
    circuit: &QSigmaCircuit,
    part: &FoldInput<Eq>,
    indices: &[u64],
    incoming_valid: bool,
) -> Vec<Vec<Fq>> {
    let own = &circuit.witness.own;
    let mut bounded = vec![scalar(own.statement)];
    let mut bytes = chunks(own);
    let mut verdicts = vec![Fq::ONE];
    if let Some(incoming) = &circuit.witness.incoming {
        bounded.push(scalar(incoming.sigma.statement));
        bytes.extend(chunks(&incoming.sigma));
        verdicts.push(Fq::from(u64::from(incoming_valid)));
        verdicts.extend(incoming.mode.map(|value| Fq::from(u64::from(value))));
    }
    bounded.extend(bytes);
    bounded.extend(part.challenges().iter().copied().map(scalar));
    let (x, y) = part.g().coordinates().unwrap();
    vec![
        bounded,
        vec![x, y],
        indices.iter().copied().map(Fq::from).collect(),
        verdicts,
        vec![Fq::from(u64::from(part.source_k()))],
    ]
}
fn assert_result(circuit: &QSigmaCircuit, instances: &[Vec<Fq>], expected: bool) {
    let assigned = synthesize(circuit, 16, Some(instances)).expect("Q fits k16");
    let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).expect("check Q");
    assert_eq!(report.is_satisfied(), expected, "{report:?}");
}
fn inventory(circuit: &QSigmaCircuit, instances: &[Vec<Fq>], label: &str) {
    let assigned = synthesize(circuit, 16, Some(instances)).expect("Q fits k16");
    assert!(
        check(&assigned.cs, &assigned.tables, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).expect("unknown Q");
    assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
    assert_eq!(assigned.tables.selectors(), unknown.tables.selectors());
    assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        assigned.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let rows = assigned
        .tables
        .advice_assigned()
        .iter()
        .filter_map(|column| column.iter().rposition(|v| *v).map(|row| row + 1))
        .max()
        .unwrap();
    let lane_rows: Vec<_> = assigned
        .tables
        .advice_assigned()
        .iter()
        .map(|column| {
            column
                .iter()
                .rposition(|value| *value)
                .map_or(0, |row| row + 1)
        })
        .collect();
    println!("Q_SIGMA_LANE_ROWS {label} {lane_rows:?}");
    let cells: usize = assigned
        .tables
        .advice_assigned()
        .iter()
        .map(|column| column.iter().filter(|v| **v).count())
        .sum();
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
    let shape = protocol.shape();
    println!(
        "Q_SIGMA_INVENTORY {label} k16 rows={rows} cells={cells} advice={} fixed={} equality={} lookups={} degree={} estimated_proof_bytes={} actual_outer_proof=false public_lengths={:?} known_unknown_equal=true",
        shape.num_advice,
        shape.num_fixed,
        shape.permutation_columns,
        shape.lookups,
        shape.degree,
        protocol.proof_length(),
        circuit.plan.instance_lengths()
    );
}
#[test]
#[ignore = "real sigma proofs and full Q_sigma constraints; run in release"]
fn single_sigma_byte_key_and_forwarded_obligation() {
    let params = common::vesta_params(16);
    for (relation, k) in [(SigmaRelation::SEND, 12), (common::SEND_EVERY, 14)] {
        let (class, own, claim) = slot(relation, k, 5);
        assert_eq!(class.chunks(), if k == 12 { 107 } else { 112 });
        let class_copy = class.clone();
        let plan = QSigmaPlan::new(class, None, &params).unwrap();
        let circuit = QSigmaCircuit::new(
            plan,
            QSigmaWitness {
                own,
                incoming: None,
            },
        )
        .unwrap();
        let instances = public(&circuit, &claim, &[5], true);
        inventory(&circuit, &instances, &format!("one-k{k}"));
        for (column, row) in [
            (0, 0),
            (0, 1),
            (0, instances[0].len() - 1),
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 0),
        ] {
            let mut forged = instances.clone();
            forged[column][row] += Fq::ONE;
            assert_result(&circuit, &forged, false);
        }
        let mut bad = circuit.clone();
        bad.witness.own.length -= 1;
        assert_result(&bad, &public(&bad, &claim, &[5], true), false);
        let mut bad = circuit.clone();
        bad.witness.own.proof[0] ^= 1;
        assert_result(&bad, &public(&bad, &claim, &[5], true), false);
        let mut bad = circuit.clone();
        bad.witness.own.statement += Fp::ONE;
        assert_result(&bad, &public(&bad, &claim, &[5], true), false);
        let unauthorized =
            SigmaClass::new(class_copy.verifier().clone(), vec![(5, Fq::from(17))]).unwrap();
        let bad = QSigmaCircuit::new(
            QSigmaPlan::new(unauthorized, None, &params).unwrap(),
            circuit.witness.clone(),
        )
        .unwrap();
        assert_result(&bad, &instances, false);
        assert!(SigmaClass::new(class_copy.verifier().clone(), vec![(16, Fq::ONE)]).is_err());
        assert!(
            SigmaClass::new(
                class_copy.verifier().clone(),
                vec![(1, Fq::ONE), (1, Fq::from(2))]
            )
            .is_err()
        );
        assert!(
            SigmaClass::new(
                class_copy.verifier().clone(),
                vec![(1, Fq::ONE), (2, Fq::ONE)]
            )
            .is_err()
        );
        let mut malformed = circuit.witness.clone();
        malformed.own.proof.pop();
        assert!(QSigmaCircuit::new(circuit.plan.clone(), malformed).is_err());
    }
}
#[test]
#[ignore = "real receive+send sigma proofs and full Q fold relation; run in release"]
fn two_sigmas_fold_exact_sources_and_soft_trivial_mode() {
    let params = common::vesta_params(16);
    let (own_class, own, own_claim) = slot(SigmaRelation::RECEIVE, 12, 3);
    let (incoming_class, incoming, incoming_claim) = slot(common::SEND_EVERY, 14, 9);
    let trivial = AccumulatorT::trivial(&params, MemoryBudget::DEFAULT).unwrap();
    let plan = QSigmaPlan::new(own_class, Some(incoming_class), &params).unwrap();
    for is_valid in [true, false] {
        let mut sigma = incoming.clone();
        if !is_valid {
            sigma.proof[0] ^= 1;
        }
        let selected = if is_valid {
            incoming_claim.clone()
        } else {
            trivial.as_input()
        };
        let (fold, part) = create_fold(
            &params,
            &[own_claim.clone(), selected, trivial.as_input()],
            Fq::from(73).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        part.decide(&params, MemoryBudget::DEFAULT).unwrap();
        let incoming = IncomingSigmaWitness {
            sigma,
            mode: [is_valid, !is_valid, false],
            corrected: Eq::from(*trivial.g()),
            fold: fold.to_bytes(),
        };
        let circuit = QSigmaCircuit::new(
            plan.clone(),
            QSigmaWitness {
                own: own.clone(),
                incoming: Some(incoming),
            },
        )
        .unwrap();
        let instances = public(&circuit, &part.as_input(), &[3, 9], is_valid);
        let mut missing = circuit.clone();
        missing.witness.incoming = None;
        assert!(synthesize(&missing, 16, Some(&instances)).is_err());
        if is_valid {
            let mut equal_correction = circuit.clone();
            let input = equal_correction.witness.incoming.as_mut().unwrap();
            input.mode = [false, false, true];
            input.corrected = Eq::from(*incoming_claim.g());
            assert_result(
                &equal_correction,
                &public(&equal_correction, &part.as_input(), &[3, 9], true),
                false,
            );
        }
        inventory(
            &circuit,
            &instances,
            if is_valid {
                "two-accept-k12-k14"
            } else {
                "two-trivial-k12-k14"
            },
        );
        let mut forged = instances.clone();
        forged[3][1] = Fq::from(u64::from(!is_valid));
        assert_result(&circuit, &forged, false);
        let mut bad = circuit.clone();
        bad.witness.incoming.as_mut().unwrap().fold[32] ^= 1;
        assert_result(&bad, &instances, false);
        let mut bad = circuit.clone();
        bad.witness.incoming.as_mut().unwrap().mode = [true, true, false];
        assert_result(
            &bad,
            &public(&bad, &part.as_input(), &[3, 9], is_valid),
            false,
        );
        let mut bad = circuit.clone();
        bad.witness.incoming.as_mut().unwrap().sigma.length -= 1;
        let expected = public(&bad, &part.as_input(), &[3, 9], false);
        assert_result(&bad, &expected, !is_valid);
    }
}

// Explicit producer-side reconstruction evidence. This temporary engine key is
// separate from QSigmaProver; no runtime PK or artifact accessor is exposed.
fn check_producer_rebuild<C: Circuit<Fq>>(
    params: &iroha_plonk::pcs::ipa::PinnedParams<iroha_pasta::Ep>,
    key: &iroha_plonk::ProvingKey<iroha_pasta::Ep>,
    circuit: &C,
    original: &[u8],
) {
    use iroha_plonk::keys::{CosetCachePolicy, SourceBoundVerifyingKeyV2, keygen_pk_from_vk_v2};
    let metadata = SourceBoundVerifyingKeyV2::from_proving_key(key, None).unwrap();
    let rebuilt = keygen_pk_from_vk_v2(
        params,
        &circuit.without_witnesses(),
        &metadata.view(),
        CosetCachePolicy::OnDemand,
    )
    .unwrap();
    assert!(!rebuilt.has_coset_cache());
    assert_eq!(rebuilt.commitment_tables().present(), (false, false));
    assert_eq!(rebuilt.binding(), key.binding());
    assert_eq!(rebuilt.vk().to_bytes(), key.vk().to_bytes());
    assert_eq!(rebuilt.copy_digest(), key.copy_digest());
    assert_eq!(rebuilt.artifact_bytes_v2().unwrap(), original);
}

type RecoveryLog = std::sync::Arc<std::sync::Mutex<Vec<[u8; 32]>>>;
fn recorded_recovery(seed: u8, log: RecoveryLog) -> iroha_plonk::ProverRandomness<'static> {
    use rand_chacha::rand_core::SeedableRng as _;
    iroha_plonk::ProverRandomness::recovery(move |context: &[u8; 32]| {
        log.lock().unwrap().push(*context);
        Ok::<_, std::convert::Infallible>(rand_chacha::ChaCha20Rng::from_seed([seed; 32]))
    })
}
fn no_recovery_draw() -> iroha_plonk::ProverRandomness<'static> {
    iroha_plonk::ProverRandomness::recovery(
        |_: &[u8; 32]| -> Result<rand_chacha::ChaCha20Rng, ()> {
            panic!("refused Q source consumed recovery entropy")
        },
    )
}
fn check_prover_cancellation(
    prover: &iroha_kagemusha_proof::q_sigma::native::QSigmaProverView<'_>,
    prepared: &iroha_kagemusha_proof::q_sigma::native::PreparedQSigma,
) {
    use rand_chacha::rand_core::SeedableRng as _;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let cancelled = iroha_pasta::CancellationToken::new();
    cancelled.cancel();
    let error = prover
        .prove(
            prepared,
            no_recovery_draw(),
            iroha_plonk::ProverConfig {
                cancellation: Some(&cancelled),
                ..iroha_plonk::ProverConfig::default()
            },
        )
        .unwrap_err();
    assert!(error.is_cancelled());
    // Opening the recovery stream follows reconstruction and witness assignment.
    // Cancellation there must discard the temporary key; a later normal proof
    // below reuses this metadata owner, not a partial/cached proving key.
    let after_rebuild = iroha_pasta::CancellationToken::new();
    let signal = after_rebuild.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let randomness = iroha_plonk::ProverRandomness::recovery(move |_: &[u8; 32]| {
        observed.fetch_add(1, Ordering::SeqCst);
        signal.cancel();
        Ok::<_, ()>(rand_chacha::ChaCha20Rng::from_seed([131; 32]))
    });
    let error = prover
        .prove(
            prepared,
            randomness,
            iroha_plonk::ProverConfig {
                cancellation: Some(&after_rebuild),
                ..iroha_plonk::ProverConfig::default()
            },
        )
        .unwrap_err();
    assert!(error.is_cancelled());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
#[ignore = "actual k16 Q_sigma proof over real k12/k14 sigma and local AS; run in release"]
fn actual_two_sigma_q_proof_verifies() {
    use iroha_kagemusha_proof::q_sigma::native::{
        IncomingMode, IncomingSigma, QSigmaProver, QSigmaSource,
    };
    rayon::ThreadPoolBuilder::new().num_threads(4).build().unwrap().install(|| {
        let inner_params = common::vesta_params(16);
        let (own_class, own, _) = slot(SigmaRelation::RECEIVE, 12, 3);
        let (incoming_class, sigma, _) = slot(common::SEND_EVERY, 14, 9);
        let plan = QSigmaPlan::new(own_class, Some(incoming_class), &inner_params).unwrap();
        assert_eq!(plan.slot_count(), 2);
        assert_eq!(plan.chunk_range(0), Some(2..109));
        assert_eq!(plan.chunk_range(1), Some(109..221));
        assert_eq!(plan.chunk_range(2), None);
        assert_eq!(plan.challenge_range(), 221..237);
        assert_eq!(plan.part_source_k(), 16);
        // Installation metadata is created before any prepared operation exists.
        let source = QSigmaSource::new(plan.clone(), own.key.clone(), Some(sigma.key.clone())).unwrap();
        let input = IncomingSigma { sigma, mode: IncomingMode::Accept };
        let prepared = plan.prepare(own.clone(), Some(input.clone()), &inner_params, Fq::from(73), &FoldConfig::default()).unwrap();
        assert_eq!(prepared.instances(), public(prepared.circuit(), prepared.part(), &[3,9],true));
        let mut invalid_own = own.clone(); invalid_own.length -= 1;
        assert!(plan.prepare(invalid_own,Some(input.clone()),&inner_params,Fq::from(73),&FoldConfig::default()).is_err());
        let mut invalid = input.clone(); invalid.sigma.proof[0] ^= 1;
        assert!(plan.prepare(own.clone(),Some(invalid.clone()),&inner_params,Fq::from(73),&FoldConfig::default()).is_err());
        invalid.mode = IncomingMode::Trivial;
        let burned = plan.prepare(own.clone(),Some(invalid),&inner_params,Fq::from(73),&FoldConfig::default()).unwrap();
        assert_eq!(burned.instances()[3],[Fq::ONE,Fq::ZERO,Fq::ZERO,Fq::ONE,Fq::ZERO]);
        assert_result(burned.circuit(),burned.instances(),true);
        // Native total verification must match the circuit for a changed direct
        // instance and a malformed final IPA/suffix message, including nested
        // transcript failures rather than only the first proof commitment.
        for mutation in 0..2 {
            let mut malformed = input.clone();
            malformed.mode = IncomingMode::Trivial;
            if mutation == 0 {
                malformed.sigma.statement = Fp::ZERO;
            } else {
                let end = malformed.sigma.proof.len();
                malformed.sigma.proof[end - 32..].fill(0xff);
            }
            let retained = plan.prepare(own.clone(), Some(malformed), &inner_params, Fq::from(79), &FoldConfig::default()).unwrap();
            assert_eq!(retained.instances()[3], [Fq::ONE,Fq::ZERO,Fq::ZERO,Fq::ONE,Fq::ZERO]);
            assert_result(retained.circuit(), retained.instances(), true);
        }
        let mut not_correctable = input; not_correctable.mode = IncomingMode::Corrected;
        assert!(plan.prepare(own,Some(not_correctable),&inner_params,Fq::from(73),&FoldConfig::default()).is_err());
        let params = iroha_plonk::pcs::ipa::PinnedParams::<iroha_pasta::Ep>::derive(16).unwrap();
        // Artifact production is explicit; the runtime owner retains no PK.
        let mut keygen = iroha_plonk::keys::KeygenConfigV2::pipa_r(QSigmaPlan::instance_types().to_vec());
        keygen.coset_cache = iroha_plonk::keys::CosetCachePolicy::OnDemand;
        let producer = iroha_plonk::keys::keygen_pk_v2(&params, prepared.circuit(), &keygen).unwrap();
        let original = producer.artifact_bytes_v2().unwrap();
        check_producer_rebuild(&params, &producer, prepared.circuit(), &original);
        let installed_vk = producer.vk().to_bytes();
        let descriptor = producer.binding().encoded();
        let config = iroha_plonk::keys::pk::artifact::ReadConfig {
            maximum_bytes: original.len(), maximum_rows: 1 << 16,
            coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        };
        let mount = |bytes: &[u8], selected| QSigmaProver::from_original_artifact(
            &source, params.clone(), descriptor, installed_vk, bytes, selected,
        );
        let mut bounded = config; bounded.maximum_bytes -= 1;
        assert!(matches!(mount(&original, bounded), Err(iroha_kagemusha_proof::q_sigma::native::QSigmaError::Artifact(iroha_plonk::keys::pk::artifact::Error::Length))));
        bounded = config; bounded.maximum_rows -= 1;
        assert!(matches!(mount(&original, bounded), Err(iroha_kagemusha_proof::q_sigma::native::QSigmaError::Artifact(iroha_plonk::keys::pk::artifact::Error::Length))));
        assert!(mount(&original[..original.len()-1], config).is_err());
        let mut corrupted = original.clone(); corrupted[8] ^= 1;
        assert!(mount(&corrupted, config).is_err());
        let vk_len = u32::from_le_bytes(original[40..44].try_into().unwrap()) as usize;
        let tables_start = 44 + vk_len + 32;
        corrupted = original.clone(); corrupted[tables_start..tables_start+32].fill(0xff);
        assert!(mount(&corrupted, config).is_err());
        assert!(QSigmaProver::from_original_artifact(
            &source, params.clone(), &[0;32], installed_vk, &original, config,
        ).is_err());
        assert!(QSigmaProver::from_original_artifact(
            &source, iroha_plonk::pcs::ipa::PinnedParams::derive(14).unwrap(),
            descriptor, installed_vk, &original, config,
        ).is_err());
        let mut wrong_profile = CircuitDescriptorV2::decode(descriptor).unwrap();
        wrong_profile.instance_types[0] = iroha_plonk::cs::InstanceType::Field;
        assert!(matches!(QSigmaProver::from_original_artifact(
            &source, params.clone(), &wrong_profile.encode().unwrap(), installed_vk, &original, config,
        ), Err(iroha_kagemusha_proof::q_sigma::native::QSigmaError::Profile)));
        let mut wrong_vk = installed_vk.to_vec(); wrong_vk[0] ^= 1;
        assert!(QSigmaProver::from_original_artifact(
            &source, params.clone(), descriptor, &wrong_vk, &original, config,
        ).is_err());
        for buses in [0, 9, usize::MAX] {
            assert!(QSigmaProver::from_original_artifact_serialized_foreign(
                &source, params.clone(), descriptor, installed_vk, &original, config, buses,
            ).is_err());
        }
        // The default original must not be reinterpreted under an explicit serialized profile.
        assert!(QSigmaProver::from_original_artifact_serialized_foreign(
            &source, params.clone(), descriptor, installed_vk, &original, config, 4,
        ).is_err());
        // A different selector catalog is a different fixed source even when
        // the representative key and descriptor-sized slot shapes are identical.
        let class = plan.class(0).unwrap();
        let changed_class = SigmaClass::new(class.verifier().clone(), vec![(4,
            prepared.circuit().witness.own.key.kagemusha_digest(class.verifier().binding()).unwrap())]).unwrap();
        let changed_plan = QSigmaPlan::new(changed_class, plan.class(1).cloned(), &inner_params).unwrap();
        let changed_source = QSigmaSource::new(changed_plan.clone(),
            prepared.circuit().witness.own.key.clone(),
            prepared.circuit().witness.incoming.as_ref().map(|slot| slot.sigma.key.clone())).unwrap();
        assert!(matches!(QSigmaProver::from_original_artifact(
            &changed_source, params.clone(), descriptor, installed_vk, &original, config,
        ), Err(iroha_kagemusha_proof::q_sigma::native::QSigmaError::Artifact(
            iroha_plonk::keys::pk::artifact::Error::Source))));
        let prover = mount(&original, config).expect("installed Q original");
        assert_eq!(prover.binding(), producer.binding());
        assert_eq!(prover.verifying_key().to_bytes(), installed_vk);
        let (bound_d,bound_v,seal)=prover.into_metadata().into_parts();
        let view=seal.bind(&bound_d,&bound_v,None).unwrap();
        assert!(core::ptr::eq(view.binding(),&bound_d));
        assert!(core::ptr::eq(view.verifying_key(),&bound_v));
        let prover=iroha_kagemusha_proof::q_sigma::native::QSigmaProverView::from_source_bound(&params,view,&plan,None).unwrap();
        let cancelled = iroha_pasta::CancellationToken::new(); cancelled.cancel();
        assert!(QSigmaProver::from_original_artifact_cancellable(
            &source, params.clone(), descriptor, installed_vk, &original, config, Some(&cancelled)
        ).unwrap_err().is_cancelled());
        let changed_prepared = changed_plan.prepare(
            prepared.circuit().witness.own.clone(),
            prepared.circuit().witness.incoming.as_ref().map(|slot| IncomingSigma {
                sigma: slot.sigma.clone(), mode: IncomingMode::Accept,
            }), &inner_params, Fq::from(73), &FoldConfig::default(),
        ).unwrap();
        assert!(matches!(prover.prove(&changed_prepared, no_recovery_draw(), iroha_plonk::ProverConfig::default()),
            Err(iroha_kagemusha_proof::q_sigma::native::QSigmaError::Rebuild(_))));
        check_prover_cancellation(&prover, &prepared);
        let direct_log = RecoveryLog::default();
        let installed_log = RecoveryLog::default();
        let direct = iroha_plonk::create_proof_owned(
            &params, &producer, iroha_plonk::Witness::from_circuit(&producer, prepared.circuit(), prepared.instances()).unwrap(),
            recorded_recovery(99, direct_log.clone()), iroha_plonk::ProverConfig::default(),
        ).unwrap();
        iroha_plonk::verify_full(&params, producer.binding(), producer.vk(), prepared.instances(), &direct, MemoryBudget::DEFAULT).unwrap();
        let start = std::time::Instant::now();
        let proof = prover.prove(&prepared,recorded_recovery(99, installed_log.clone()),iroha_plonk::ProverConfig::default()).expect("actual Q proof");
        let prove_elapsed = start.elapsed();
        assert_eq!(proof.bytes, direct);
        assert_eq!(proof.instances, prepared.instances());
        assert_eq!(*direct_log.lock().unwrap(), *installed_log.lock().unwrap());
        assert_eq!(installed_log.lock().unwrap().len(), 1);
        assert_eq!(proof.bytes.len(),10_496);
        assert_eq!(proof.part, *prepared.part());
        let mut wrong = proof.instances.clone(); wrong[0][1] += Fq::ONE;
        assert!(iroha_plonk::verify_full(prover.params(),prover.binding(),prover.verifying_key(),&wrong,&proof.bytes,MemoryBudget::DEFAULT).is_err());
        println!("Q_SIGMA_ACTUAL_PROOF k16 sigma_k12_k14 local_fold=true bytes={} synthesis_prove_selfverify_elapsed_diagnostic={prove_elapsed:?} full_native_verification=true qualification=false",proof.bytes.len());
    });
}

#[test]
#[ignore = "genuine installed serialized Q PK and imported proof; run in release"]
fn installed_serialized_q_originals_prove_and_reject_default_profile() {
    use iroha_kagemusha_proof::q_sigma::native::{QSigmaProver, QSigmaSource};
    use iroha_pasta::Ep;
    use iroha_plonk::{
        keys::{CosetCachePolicy, pk::artifact::ReadConfig},
        pcs::ipa::PinnedParams,
    };
    let inner = common::vesta_params(16);
    let (class, own, _) = slot(SigmaRelation::SEND, 12, 5);
    let plan = QSigmaPlan::new(class, None, &inner).unwrap();
    let source = QSigmaSource::new(plan.clone(), own.key.clone(), None).unwrap();
    let prepared = plan
        .prepare(own, None, &inner, Fq::from(97), &FoldConfig::default())
        .unwrap();
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    // Fixture production selects the explicit frozen profile; installation never keygens.
    let circuit = prepared
        .circuit()
        .clone()
        .with_serialized_foreign(2)
        .unwrap();
    let mut keygen =
        iroha_plonk::keys::KeygenConfigV2::pipa_r(QSigmaPlan::instance_types().to_vec());
    keygen.coset_cache = CosetCachePolicy::OnDemand;
    let producer = iroha_plonk::keys::keygen_pk_v2(&params, &circuit, &keygen).unwrap();
    let original = producer.artifact_bytes_v2().unwrap();
    check_producer_rebuild(&params, &producer, &circuit, &original);
    let vk = producer.vk().to_bytes();
    let config = ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let imported = QSigmaProver::from_original_artifact_serialized_foreign(
        &source,
        params.clone(),
        producer.binding().encoded(),
        vk,
        &original,
        config,
        2,
    )
    .expect("genuine installed serialized Q original");
    assert_eq!(imported.binding(), producer.binding());
    assert_eq!(imported.verifying_key().to_bytes(), vk);
    let (bound_d, bound_v, seal) = imported.into_metadata().into_parts();
    let view = seal.bind(&bound_d, &bound_v, None).unwrap();
    assert!(core::ptr::eq(view.binding(), &bound_d));
    assert!(core::ptr::eq(view.verifying_key(), &bound_v));
    let imported = iroha_kagemusha_proof::q_sigma::native::QSigmaProverView::from_source_bound(
        &params,
        view,
        source.plan(),
        Some(2),
    )
    .unwrap();
    assert!(
        iroha_kagemusha_proof::q_sigma::native::QSigmaProverView::from_source_bound(
            &params,
            view,
            source.plan(),
            Some(0)
        )
        .is_err()
    );
    assert!(
        QSigmaProver::from_original_artifact(
            &source,
            params.clone(),
            producer.binding().encoded(),
            vk,
            &original,
            config,
        )
        .is_err()
    );
    assert!(
        QSigmaProver::from_original_artifact_serialized_foreign(
            &source,
            params.clone(),
            producer.binding().encoded(),
            vk,
            &original,
            config,
            3,
        )
        .is_err()
    );
    let cancelled = iroha_pasta::CancellationToken::new();
    cancelled.cancel();
    assert!(
        QSigmaProver::from_original_artifact_serialized_foreign_cancellable(
            &source,
            params.clone(),
            producer.binding().encoded(),
            vk,
            &original,
            config,
            2,
            Some(&cancelled),
        )
        .unwrap_err()
        .is_cancelled()
    );
    check_prover_cancellation(&imported, &prepared);
    let direct_log = RecoveryLog::default();
    let installed_log = RecoveryLog::default();
    let direct = iroha_plonk::create_proof_owned(
        &params,
        &producer,
        iroha_plonk::Witness::from_circuit(&producer, &circuit, prepared.instances()).unwrap(),
        recorded_recovery(82, direct_log.clone()),
        iroha_plonk::ProverConfig::default(),
    )
    .unwrap();
    iroha_plonk::verify_full(
        &params,
        producer.binding(),
        producer.vk(),
        prepared.instances(),
        &direct,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    let proof = imported
        .prove(
            &prepared,
            recorded_recovery(82, installed_log.clone()),
            iroha_plonk::ProverConfig::default(),
        )
        .expect("genuine imported serialized Q proof");
    iroha_plonk::verify_full(
        &params,
        producer.binding(),
        producer.vk(),
        &proof.instances,
        &proof.bytes,
        MemoryBudget::DEFAULT,
    )
    .expect("original installed Q key");
    assert_eq!(proof.bytes, direct);
    assert_eq!(proof.instances, prepared.instances());
    assert_eq!(*direct_log.lock().unwrap(), *installed_log.lock().unwrap());
    assert_eq!(installed_log.lock().unwrap().len(), 1);
    assert_eq!(proof.part, *prepared.part());
    let mut wrong = proof.instances.clone();
    wrong[0][0] += Fq::ONE;
    assert!(
        iroha_plonk::verify_full(
            &params,
            producer.binding(),
            producer.vk(),
            &wrong,
            &proof.bytes,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
}
