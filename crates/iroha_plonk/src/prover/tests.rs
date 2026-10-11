//! End-to-end prover tests: proofs of the test circuits verify on both
//! curves under every protocol option; the constraint checker and the
//! verifier agree on honest and tampered witnesses; proofs do not depend on
//! the thread count; the zero-knowledge budget holds and fresh randomness
//! changes every message; the randomness sources bind what they must; and a
//! malicious prover that commits two advice columns identically is caught
//! by static grouping (S1).

use std::sync::{Arc, Mutex};

use ff::{Field, PrimeField};
use group::Curve;
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaCurve, PastaField, poseidon::PoseidonField};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;

use super::{
    advice::{Advice, InstanceColumns},
    multiopen::Opened,
    quotient::{CompiledExpressions, QuotientInputs},
    vanishing::{commit_quotient, commit_random},
    *,
};
use crate::{
    check::{CheckMode, check_circuit},
    cs::ProofSuffixV1,
    frontend::Circuit,
    pcs::ipa::{IpaError, commit::Secrecy, commit::commit_lagrange, evaluate_polynomial},
    protocol::{Protocol, check_zero_knowledge_budget, evaluate_expression, rotate},
    test_circuits::{
        Arithmetic, BUDGET, CHOICES, Choice, Forgeable, K, Lookups, Permutations, Setup, setup,
    },
    transcript::MESSAGE_BYTES,
    verifier::{VerifyError, accumulate_succinct, verify_full, verify_full_from_bytes},
};

const ARITHMETIC: Arithmetic = Arithmetic {
    start: 3,
    rows: 12,
    tamper: None,
};

const LOOKUPS: Lookups = Lookups {
    rows: 9,
    tamper: None,
    out_of_range: false,
    offset: 0,
};

const PERMUTATIONS: Permutations = Permutations {
    rows: 10,
    tamper: None,
};

/// Proves `circuit` under every choice and checks every verifier entry
/// point.
fn round_trip<C, Ci>(circuit: &Ci, instances: &[Vec<C::ScalarExt>])
where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
    Ci: Circuit<C::ScalarExt>,
{
    for choice in CHOICES {
        let setup = setup::<C, _>(circuit, choice);
        let proof = setup.prove(circuit, instances, 7).expect("proof");
        let protocol = Protocol::new(setup.pk.binding().descriptor()).expect("protocol");
        assert_eq!(proof.len(), protocol.proof_length(), "{choice:?}");
        assert_eq!(setup.verify(instances, &proof), Ok(()), "{choice:?}");
        assert_eq!(
            verify_full_from_bytes(
                &setup.params,
                setup.pk.binding().encoded(),
                setup.pk.vk().to_bytes(),
                instances,
                &proof,
                BUDGET,
            ),
            Ok(()),
            "{choice:?}"
        );
        let succinct = accumulate_succinct(
            &setup.params,
            setup.pk.binding(),
            setup.pk.vk(),
            instances,
            &proof,
            BUDGET,
        );
        if choice.2 == ProofSuffixV1::FoldedGenerator {
            let accumulator = succinct.expect("succinct");
            assert_eq!(
                accumulator.transcript_repr(),
                setup
                    .pk
                    .vk()
                    .transcript_repr()
                    .scalar()
                    .expect("scalar profile")
            );
            assert_eq!(accumulator.decide(&setup.params, BUDGET), Ok(()));
        } else {
            assert_eq!(succinct.err(), Some(VerifyError::SuffixRequired));
        }
    }
}

#[test]
fn arithmetic_proofs_verify_on_both_curves() {
    round_trip::<Ep, _>(&ARITHMETIC, &ARITHMETIC.instances::<Fq>());
    round_trip::<Eq, _>(&ARITHMETIC, &ARITHMETIC.instances::<Fp>());
}

#[test]
fn lookup_proofs_verify_on_both_curves() {
    round_trip::<Ep, _>(&LOOKUPS, &[]);
    round_trip::<Eq, _>(&LOOKUPS, &[]);
}

#[test]
fn permutation_heavy_proofs_verify_on_both_curves() {
    let setup = setup::<Ep, _>(&PERMUTATIONS, CHOICES[0]);
    let shape = *Protocol::new(setup.pk.binding().descriptor())
        .expect("protocol")
        .shape();
    // Degree 3: one column per set, eight linked sets.
    assert_eq!((shape.degree, shape.chunk_len), (3, 1));
    assert_eq!(shape.permutation_sets, 8);
    round_trip::<Ep, _>(&PERMUTATIONS, &PERMUTATIONS.instances::<Fq>());
    round_trip::<Eq, _>(&PERMUTATIONS, &PERMUTATIONS.instances::<Fp>());
}

/// The checker's verdict and the proof's verdict for one witness.
fn verdicts<C, Ci>(setup: &Setup<C>, circuit: &Ci, instances: &[Vec<C::ScalarExt>]) -> (bool, bool)
where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
    Ci: Circuit<C::ScalarExt>,
{
    let checked = check_circuit(circuit, K, instances, CheckMode::Strict)
        .expect("synthesis")
        .is_satisfied();
    let proved = setup
        .prove(circuit, instances, 3)
        .is_ok_and(|proof| setup.verify(instances, &proof).is_ok());
    (checked, proved)
}

#[test]
fn the_constraint_checker_and_the_prover_agree() {
    let arithmetic = setup::<Ep, _>(&ARITHMETIC, CHOICES[0]);
    let instances = ARITHMETIC.instances::<Fq>();
    assert_eq!(verdicts(&arithmetic, &ARITHMETIC, &instances), (true, true));
    for row in [0, 5, 11] {
        let tampered = Arithmetic {
            tamper: Some(row),
            ..ARITHMETIC
        };
        assert_eq!(
            verdicts(&arithmetic, &tampered, &instances),
            (false, false),
            "row {row}"
        );
    }
    let mut wrong_output = instances.clone();
    wrong_output[0][1] += Fq::ONE;
    assert_eq!(
        verdicts(&arithmetic, &ARITHMETIC, &wrong_output),
        (false, false)
    );

    let lookups = setup::<Eq, _>(&LOOKUPS, CHOICES[1]);
    assert_eq!(verdicts(&lookups, &LOOKUPS, &[]), (true, true));
    for tampered in [
        Lookups {
            tamper: Some(4),
            ..LOOKUPS
        },
        Lookups {
            out_of_range: true,
            ..LOOKUPS
        },
    ] {
        assert_eq!(verdicts(&lookups, &tampered, &[]), (false, false));
    }

    let permutations = setup::<Ep, _>(&PERMUTATIONS, CHOICES[2]);
    let instances = PERMUTATIONS.instances::<Fq>();
    assert_eq!(
        verdicts(&permutations, &PERMUTATIONS, &instances),
        (true, true)
    );
    for row in [0, 4, 9] {
        let tampered = Permutations {
            tamper: Some(row),
            ..PERMUTATIONS
        };
        assert_eq!(
            verdicts(&permutations, &tampered, &instances),
            (false, false),
            "row {row}"
        );
    }
}

/// Proves `circuit` in pools of 1, 2, 4 and 7 threads and requires equal
/// bytes.
fn thread_independent<C, Ci>(circuit: &Ci, instances: &[Vec<C::ScalarExt>], choice: Choice)
where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
    Ci: Circuit<C::ScalarExt> + Sync,
{
    let setup = setup::<C, _>(circuit, choice);
    let reference = setup.prove(circuit, instances, 11).expect("proof");
    for threads in [1, 2, 4, 7] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("pool");
        let proof = pool
            .install(|| setup.prove(circuit, instances, 11))
            .expect("proof");
        assert_eq!(proof, reference, "{threads} threads");
    }
    assert_eq!(setup.verify(instances, &reference), Ok(()));
}

#[test]
fn proofs_do_not_depend_on_the_thread_count() {
    thread_independent::<Ep, _>(&ARITHMETIC, &ARITHMETIC.instances::<Fq>(), CHOICES[0]);
    thread_independent::<Eq, _>(&LOOKUPS, &[], CHOICES[1]);
    thread_independent::<Ep, _>(&PERMUTATIONS, &PERMUTATIONS.instances::<Fq>(), CHOICES[3]);
}

/// Compares reusable and consuming witnesses under every protocol option,
/// with a recovery stream bound to the statement and secret witness.
fn owned_proof_parity<C, Ci>(circuit: &Ci, instances: &[Vec<C::ScalarExt>])
where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
    Ci: Circuit<C::ScalarExt> + Sync,
{
    for choice in CHOICES {
        let setup = setup::<C, _>(circuit, choice);
        let witness = Witness::from_circuit(&setup.pk, circuit, instances).expect("witness");
        let context_log = Arc::new(Mutex::new(Vec::new()));
        let randomness =
            || ProverRandomness::recovery(recording_derivation([73; 32], Arc::clone(&context_log)));
        let reference = create_proof(
            &setup.params,
            &setup.pk,
            &witness,
            randomness(),
            ProverConfig::default(),
        )
        .expect("borrowed proof");
        let usable_rows = Protocol::new(setup.pk.binding().descriptor())
            .expect("protocol")
            .shape()
            .usable_rows;
        let digest = witness.digest(usable_rows, None).unwrap();
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .expect("pool");
            let owned = Witness::from_circuit(&setup.pk, circuit, instances).expect("witness");
            let proof = pool
                .install(|| {
                    create_proof_owned(
                        &setup.params,
                        &setup.pk,
                        owned,
                        randomness(),
                        ProverConfig::default(),
                    )
                })
                .expect("owned proof");
            assert_eq!(proof, reference, "{choice:?}, {workers} workers");
            assert_eq!(setup.verify(instances, &proof), Ok(()));
        }
        assert_eq!(witness.digest(usable_rows, None).unwrap(), digest);
        let contexts = context_log.lock().expect("contexts");
        assert_eq!(contexts.len(), 3);
        assert!(contexts.iter().all(|context| *context == contexts[0]));
    }
}

#[test]
fn owned_witness_prover_bytes_identical() {
    owned_proof_parity::<Ep, _>(&ARITHMETIC, &ARITHMETIC.instances::<Fq>());
    owned_proof_parity::<Eq, _>(&ARITHMETIC, &ARITHMETIC.instances::<Fp>());
    owned_proof_parity::<Ep, _>(&LOOKUPS, &[]);
    owned_proof_parity::<Eq, _>(&LOOKUPS, &[]);
    owned_proof_parity::<Ep, _>(&PERMUTATIONS, &PERMUTATIONS.instances::<Fq>());
    owned_proof_parity::<Eq, _>(&PERMUTATIONS, &PERMUTATIONS.instances::<Fp>());
}

#[test]
fn reusable_workspace_proof_bytes_and_bound_both_curves() {
    fn check<C: PastaCurve>()
    where
        C::ScalarExt: PoseidonField,
        C::Base: PoseidonField,
    {
        let mut workspace = QuotientWorkspace::new(1 << 20);
        for profile in 0..=CHOICES.len() {
            for (policy, k) in [
                (crate::keys::CosetCachePolicy::Eager, K),
                (crate::keys::CosetCachePolicy::OnDemand, K + 1),
                (crate::keys::CosetCachePolicy::Eager, K),
            ] {
                let params = PinnedParams::<C>::derive(k).unwrap();
                let pk = CHOICES.get(profile).map_or_else(
                    || {
                        let mut config = crate::keys::KeygenConfigV2::pipa_r(Vec::new());
                        config.coset_cache = policy;
                        crate::keys::keygen_pk_v2(&params, &LOOKUPS, &config).unwrap()
                    },
                    |choice| {
                        let mut config = crate::test_circuits::keygen_config(*choice);
                        config.coset_cache = policy;
                        crate::keys::keygen_pk(&params, &LOOKUPS, &config).unwrap()
                    },
                );
                let setup = Setup { params, pk };
                let witness = Witness::from_circuit(&setup.pk, &LOOKUPS, &[]).unwrap();
                let reference = create_proof(
                    &setup.params,
                    &setup.pk,
                    &witness,
                    ProverRandomness::fixed_seed_for_tests([91; 32]),
                    ProverConfig::default(),
                )
                .unwrap();
                for workers in [1, 4, 1] {
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(workers)
                        .build()
                        .unwrap();
                    let owned = Witness::from_circuit(&setup.pk, &LOOKUPS, &[]).unwrap();
                    let output = pool
                        .install(|| {
                            create_proof_owned_with_workspace(
                                &setup.params,
                                &setup.pk,
                                owned,
                                ProverRandomness::fixed_seed_for_tests([91; 32]),
                                ProverConfig::default(),
                                &mut workspace,
                            )
                        })
                        .unwrap();
                    assert_eq!(output.proof, reference);
                    assert_eq!(output.opening.decide(&setup.params, BUDGET), Ok(()));
                    assert_eq!(setup.verify(&[], &output.proof), Ok(()));
                    assert!(workspace.is_zeroized());
                    assert!(workspace.allocated_bytes() > 0);
                    assert!(workspace.allocated_bytes() <= workspace.maximum_bytes());
                }
                let required = quotient::workspace_elements(
                    &setup.pk,
                    &Protocol::new(setup.pk.binding().descriptor()).unwrap(),
                )
                .unwrap()
                    * size_of::<C::ScalarExt>();
                let mut short = QuotientWorkspace::new(required - 1);
                let owned = Witness::from_circuit(&setup.pk, &LOOKUPS, &[]).unwrap();
                assert!(matches!(
                    create_proof_owned_with_workspace(
                        &setup.params,
                        &setup.pk,
                        owned,
                        ProverRandomness::fixed_seed_for_tests([91; 32]),
                        ProverConfig::default(),
                        &mut short
                    ),
                    Err(ProverError::Workspace(WorkspaceError::Limit { .. }))
                ));
                assert_eq!(short.allocated_bytes(), 0);
            }
        }
        workspace.clear();
        assert_eq!(workspace.allocated_bytes(), 0);
    }
    check::<Ep>();
    check::<Eq>();
}

#[test]
fn owned_witness_buffers_are_transformed_in_place() {
    let setup = setup::<Ep, _>(&ARITHMETIC, CHOICES[1]);
    let witness = Witness::from_circuit(&setup.pk, &ARITHMETIC, &ARITHMETIC.instances::<Fq>())
        .expect("witness");
    let pointers: Vec<_> = witness.advice().iter().map(Vec::as_ptr).collect();
    let evaluations = witness.advice().to_vec();
    let mut input = WitnessInput::Owned(witness);
    let mut advice = Advice {
        values: input.take_advice(),
        polys: Vec::new(),
        blinds: Vec::new(),
    };
    assert!(input.witness().advice().is_empty());
    assert_eq!(
        advice.values.iter().map(Vec::as_ptr).collect::<Vec<_>>(),
        pointers
    );
    advice
        .interpolate_in_place(&setup.pk, None)
        .expect("interpolate");
    assert!(advice.values.is_empty());
    assert_eq!(
        advice.polys.iter().map(Vec::as_ptr).collect::<Vec<_>>(),
        pointers
    );
    for (mut coefficients, expected) in advice.polys.clone().into_iter().zip(evaluations) {
        setup.pk.domain().fft(&mut coefficients).expect("evaluate");
        assert_eq!(coefficients, expected);
    }
}

#[test]
fn advice_buffers_remain_owned_on_transform_failure() {
    let setup = setup::<Ep, _>(&ARITHMETIC, CHOICES[0]);
    let mut advice = Advice {
        values: vec![vec![Fq::ONE; 3]],
        polys: Vec::new(),
        blinds: vec![Fq::ONE],
    };
    let pointer = advice.values[0].as_ptr();
    assert!(matches!(
        advice.interpolate_in_place(&setup.pk, None),
        Err(ProverError::Fft(_))
    ));
    // The error does not leak or discard a secret allocation: the same
    // buffer is still under Advice's zeroizing Drop implementation.
    assert!(advice.values.is_empty());
    assert_eq!(advice.polys[0].as_ptr(), pointer);
    assert_eq!(advice.polys[0], vec![Fq::ONE; 3]);
}

/// Exercises errors before and after the owned advice moves into the prover.
fn owned_errors<C: PastaCurve>()
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let setup = setup::<C, _>(&ARITHMETIC, CHOICES[1]);
    let instances = ARITHMETIC.instances::<C::ScalarExt>();
    let witness = || Witness::from_circuit(&setup.pk, &ARITHMETIC, &instances).expect("witness");
    let larger = PinnedParams::<C>::derive(K + 1).expect("parameters");
    assert_eq!(
        create_proof_owned(
            &larger,
            &setup.pk,
            witness(),
            ProverRandomness::fixed_seed_for_tests([1; 32]),
            ProverConfig::default(),
        ),
        Err(ProverError::ParamsMismatch)
    );
    for malformed in [
        Witness {
            advice: Vec::new(),
            instances: instances.clone(),
        },
        Witness {
            advice: vec![vec![C::ScalarExt::ONE; 3]; 3],
            instances: instances.clone(),
        },
        Witness {
            advice: witness().advice().to_vec(),
            instances: Vec::new(),
        },
    ] {
        let expected = create_proof(
            &setup.params,
            &setup.pk,
            &malformed,
            ProverRandomness::fixed_seed_for_tests([1; 32]),
            ProverConfig::default(),
        );
        assert!(expected.is_err());
        assert_eq!(
            create_proof_owned(
                &setup.params,
                &setup.pk,
                malformed,
                ProverRandomness::fixed_seed_for_tests([1; 32]),
                ProverConfig::default(),
            ),
            expected
        );
    }
    assert_eq!(
        create_proof_owned(
            &setup.params,
            &setup.pk,
            witness(),
            ProverRandomness::recovery(|_: &[u8; 32]| Err::<ChaCha20Rng, _>(())),
            ProverConfig::default(),
        ),
        Err(ProverError::RecoveryStream)
    );
    assert!(matches!(
        create_proof_owned(
            &setup.params,
            &setup.pk,
            witness(),
            ProverRandomness::fixed_seed_for_tests([1; 32]),
            ProverConfig {
                cancellation: None,
                msm_budget: MemoryBudget::new(0),
            },
        ),
        Err(ProverError::Msm(_))
    ));
    let lookup_setup = crate::test_circuits::setup::<C, _>(&LOOKUPS, CHOICES[1]);
    let bad_lookup = Witness::from_circuit(
        &lookup_setup.pk,
        &Lookups {
            out_of_range: true,
            ..LOOKUPS
        },
        &[],
    )
    .expect("witness");
    assert_eq!(
        create_proof_owned(
            &lookup_setup.params,
            &lookup_setup.pk,
            bad_lookup,
            ProverRandomness::fixed_seed_for_tests([1; 32]),
            ProverConfig::default(),
        ),
        Err(ProverError::LookupInputMissing { lookup: 1 })
    );
}

#[test]
fn owned_witness_errors_match_borrowed_and_release_secret_buffers() {
    owned_errors::<Ep>();
    owned_errors::<Eq>();
}

#[test]
fn the_zero_knowledge_budget_holds_for_every_relation() {
    let descriptors = [
        setup::<Ep, _>(&ARITHMETIC, CHOICES[0])
            .pk
            .binding()
            .descriptor()
            .clone(),
        setup::<Eq, _>(&LOOKUPS, CHOICES[1])
            .pk
            .binding()
            .descriptor()
            .clone(),
        setup::<Ep, _>(&PERMUTATIONS, CHOICES[2])
            .pk
            .binding()
            .descriptor()
            .clone(),
    ];
    for descriptor in &descriptors {
        let protocol = Protocol::new(descriptor).expect("protocol");
        assert_eq!(check_zero_knowledge_budget(&protocol), Ok(()));
        // Fewer blinding rows than the masks formula: the plan-derived check
        // catches it independently of descriptor rule 9.
        let mut short = descriptor.clone();
        short.blinding_factors = 3;
        let protocol = Protocol::new(&short).expect("protocol");
        let violation = check_zero_knowledge_budget(&protocol).expect_err("over budget");
        assert_eq!(violation.budget, 2);
        assert!(violation.revealed > violation.budget);
    }
}

/// The 32-byte messages of a proof.
fn messages(proof: &[u8]) -> Vec<&[u8]> {
    proof.chunks(MESSAGE_BYTES).collect()
}

#[test]
fn fresh_randomness_changes_every_message() {
    // Same witness, two seeds: every commitment and every evaluation of the
    // proof changes (spec section 15, zero-knowledge).
    for (circuit, choice) in [(0, CHOICES[0]), (1, CHOICES[1]), (2, CHOICES[3])] {
        let (first, second) = match circuit {
            0 => {
                let setup = setup::<Ep, _>(&ARITHMETIC, choice);
                let instances = ARITHMETIC.instances::<Fq>();
                (
                    setup.prove(&ARITHMETIC, &instances, 1).expect("proof"),
                    setup.prove(&ARITHMETIC, &instances, 2).expect("proof"),
                )
            }
            1 => {
                let setup = setup::<Eq, _>(&LOOKUPS, choice);
                (
                    setup.prove(&LOOKUPS, &[], 1).expect("proof"),
                    setup.prove(&LOOKUPS, &[], 2).expect("proof"),
                )
            }
            _ => {
                let setup = setup::<Ep, _>(&PERMUTATIONS, choice);
                let instances = PERMUTATIONS.instances::<Fq>();
                (
                    setup.prove(&PERMUTATIONS, &instances, 1).expect("proof"),
                    setup.prove(&PERMUTATIONS, &instances, 2).expect("proof"),
                )
            }
        };
        assert_eq!(first.len(), second.len());
        for (index, (a, b)) in messages(&first).iter().zip(messages(&second)).enumerate() {
            assert_ne!(*a, b, "circuit {circuit}, message {index}");
        }
    }
}

/// A recovery derivation that records its contexts.
fn recording_derivation(
    seed: [u8; 32],
    log: Arc<Mutex<Vec<[u8; 32]>>>,
) -> impl FnOnce(&[u8; 32]) -> Result<ChaCha20Rng, ()> + Send {
    move |context: &[u8; 32]| {
        log.lock().map_err(|_| ())?.push(*context);
        let key =
            crate::cs::descriptor::blake2b_personal::<32>(b"recovery-test-v1", &[&seed, context]);
        Ok(ChaCha20Rng::from_seed(key))
    }
}

#[test]
fn recovery_streams_bind_the_witness() {
    let setup = setup::<Ep, _>(&LOOKUPS, CHOICES[0]);
    let other = Lookups {
        offset: 4,
        ..LOOKUPS
    };
    let log = Arc::new(Mutex::new(Vec::new()));
    let prove = |circuit: &Lookups| {
        prove_circuit(
            &setup.params,
            &setup.pk,
            circuit,
            &[],
            ProverRandomness::recovery(recording_derivation([9; 32], Arc::clone(&log))),
            ProverConfig::default(),
        )
        .expect("proof")
    };
    let first = prove(&LOOKUPS);
    let again = prove(&LOOKUPS);
    let different = prove(&other);
    // Deterministic for one witness and statement (recovery).
    assert_eq!(first, again);
    assert_eq!(setup.verify(&[], &first), Ok(()));
    assert_eq!(setup.verify(&[], &different), Ok(()));
    let contexts = log.lock().expect("log").clone();
    assert_eq!(contexts.len(), 3);
    assert_eq!(contexts[0], contexts[1]);
    assert_ne!(contexts[0], contexts[2]);
    // The statement is the same (no instances), so the context separates the
    // witnesses: the R commitment, a pure function of the stream position,
    // differs.
    let protocol = Protocol::new(setup.pk.binding().descriptor()).expect("protocol");
    let shape = protocol.shape();
    let r_index = shape.num_advice + 3 * shape.lookups + shape.permutation_sets;
    assert_ne!(messages(&first)[r_index], messages(&different)[r_index]);
    // A failing derivation is a typed error.
    assert_eq!(
        prove_circuit(
            &setup.params,
            &setup.pk,
            &LOOKUPS,
            &[],
            ProverRandomness::recovery(|_: &[u8; 32]| Err::<ChaCha20Rng, ()>(())),
            ProverConfig::default(),
        ),
        Err(ProverError::RecoveryStream)
    );
}

/// A stream whose every read fails.
struct FailingRng;

impl rand_core_06::RngCore for FailingRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        Err(rand_core_06::Error::from(
            core::num::NonZeroU32::new(rand_core_06::Error::CUSTOM_START).expect("nonzero"),
        ))
    }
}

impl rand_core_06::CryptoRng for FailingRng {}

/// S8 regression (spec section 10): a recovery derivation that ignores its
/// context and returns one constant stream cannot make two witnesses share
/// blinds, because this crate keys the stream it proves with from the
/// context itself. With the context only advisory, both proofs below would
/// reuse every blind (and `C_a - C_b` would be an unblinded commitment to the
/// witness difference).
#[test]
fn a_constant_recovery_derivation_still_separates_witnesses() {
    let setup = setup::<Ep, _>(&LOOKUPS, CHOICES[0]);
    let other = Lookups {
        offset: 4,
        ..LOOKUPS
    };
    let prove = |circuit: &Lookups| {
        prove_circuit(
            &setup.params,
            &setup.pk,
            circuit,
            &[],
            ProverRandomness::recovery(|_: &[u8; 32]| Ok::<_, ()>(ChaCha20Rng::from_seed([0; 32]))),
            ProverConfig::default(),
        )
        .expect("proof")
    };
    let first = prove(&LOOKUPS);
    let again = prove(&LOOKUPS);
    let different = prove(&other);
    assert_eq!(first, again, "recovery stays deterministic per witness");
    assert_eq!(setup.verify(&[], &first), Ok(()));
    assert_eq!(setup.verify(&[], &different), Ok(()));
    // R is drawn at a fixed stream position, so equal streams would give
    // equal R commitments; the bound streams differ. So does every blinded
    // commitment and evaluation of the two proofs.
    let protocol = Protocol::new(setup.pk.binding().descriptor()).expect("protocol");
    let shape = protocol.shape();
    let r_index = shape.num_advice + 3 * shape.lookups + shape.permutation_sets;
    assert_ne!(messages(&first)[r_index], messages(&different)[r_index]);
    for (index, (a, b)) in messages(&first)
        .iter()
        .zip(messages(&different))
        .enumerate()
    {
        assert_ne!(*a, b, "message {index}");
    }
    // A stream that fails is a typed error, not a fallback.
    assert_eq!(
        prove_circuit(
            &setup.params,
            &setup.pk,
            &LOOKUPS,
            &[],
            ProverRandomness::recovery(|_: &[u8; 32]| Ok::<_, ()>(FailingRng)),
            ProverConfig::default(),
        ),
        Err(ProverError::RecoveryStream)
    );
}

#[test]
fn recovery_stream_keys_bind_the_drawn_bytes_and_the_context() {
    // Python: hashlib.blake2b(bytes([1] * 32) + bytes([2] * 32),
    // digest_size=32, person=b"PIPA-v1-RecovKey").
    let key = recovery_stream_key(&[1; 32], &[2; 32]);
    let hex = key.iter().fold(String::new(), |mut out, byte| {
        use core::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    });
    assert_eq!(
        hex,
        "ad11af26d312c03851c876361564593989fa05d1918cf760b9d890e254d781bc"
    );
    assert_ne!(recovery_stream_key(&[1; 32], &[3; 32]), key);
    assert_ne!(recovery_stream_key(&[3; 32], &[2; 32]), key);
    // Distinct from the context persona.
    assert_ne!(recovery_context(&[1; 32], &[2; 32]), key);
}

#[test]
fn production_randomness_sources_prove() {
    let setup = setup::<Eq, _>(&ARITHMETIC, CHOICES[1]);
    let instances = ARITHMETIC.instances::<Fp>();
    let prove = |randomness: ProverRandomness<'_>| {
        prove_circuit(
            &setup.params,
            &setup.pk,
            &ARITHMETIC,
            &instances,
            randomness,
            ProverConfig::default(),
        )
        .expect("proof")
    };
    let hedged = prove(ProverRandomness::hedged());
    let hedged_again = prove(ProverRandomness::hedged());
    let os = prove(ProverRandomness::os());
    for proof in [&hedged, &hedged_again, &os] {
        assert_eq!(setup.verify(&instances, proof), Ok(()));
    }
    assert_ne!(hedged, hedged_again);
    assert!(format!("{:?}", ProverRandomness::hedged()).contains("Hedged"));
}

#[test]
fn the_prover_rejects_mismatched_inputs() {
    let setup = setup::<Ep, _>(&ARITHMETIC, CHOICES[0]);
    let instances = ARITHMETIC.instances::<Fq>();
    assert_eq!(
        Witness::from_circuit(&setup.pk, &ARITHMETIC, &[]).err(),
        Some(ProverError::InstanceColumns {
            expected: 1,
            found: 0
        })
    );
    assert_eq!(
        Witness::from_circuit(&setup.pk, &ARITHMETIC, &[vec![Fq::ONE]]).err(),
        Some(ProverError::InstanceLength {
            column: 0,
            expected: 2,
            found: 1
        })
    );
    assert_eq!(
        Witness::<Fq>::from_columns(&setup.pk, vec![], instances.clone()).err(),
        Some(ProverError::WitnessShape {
            expected: 3,
            found: 0
        })
    );
    assert_eq!(
        Witness::<Fq>::from_columns(&setup.pk, vec![vec![Fq::ZERO; 3]; 3], instances.clone()).err(),
        Some(ProverError::WitnessShape {
            expected: 64,
            found: 3
        })
    );
    // Another circuit shape (fewer rows enables fewer selectors).
    let shorter = Arithmetic {
        rows: 10,
        ..ARITHMETIC
    };
    assert_eq!(
        Witness::from_circuit(&setup.pk, &shorter, &shorter.instances::<Fq>()).err(),
        Some(ProverError::CircuitMismatch)
    );
    // Parameters of another k.
    let witness = Witness::from_circuit(&setup.pk, &ARITHMETIC, &instances).expect("witness");
    let large = PinnedParams::<Ep>::derive(K + 1).expect("params");
    assert_eq!(
        create_proof(
            &large,
            &setup.pk,
            &witness,
            ProverRandomness::fixed_seed_for_tests([1; 32]),
            ProverConfig::default(),
        ),
        Err(ProverError::ParamsMismatch)
    );
    assert!(format!("{witness:?}").contains("advice_columns"));
    assert_eq!(witness.instances(), instances.as_slice());
    // A lookup input outside its table is a prover error.
    let lookups = setup_lookups();
    assert_eq!(
        lookups.prove(
            &Lookups {
                out_of_range: true,
                ..LOOKUPS
            },
            &[],
            1
        ),
        Err(ProverError::LookupInputMissing { lookup: 1 })
    );
    assert!(
        ProverError::LookupInputMissing { lookup: 1 }
            .to_string()
            .contains("lookup 1")
    );
}

fn setup_lookups() -> Setup<Ep> {
    setup::<Ep, _>(&LOOKUPS, CHOICES[0])
}

#[test]
fn oracle_mode_binds_the_injected_repr() {
    let setup = setup::<Eq, _>(&ARITHMETIC, CHOICES[1]);
    let instances = ARITHMETIC.instances::<Fp>();
    let witness = Witness::from_circuit(&setup.pk, &ARITHMETIC, &instances).expect("witness");
    let vendored = Fp::from(0x5eed);
    let proof = create_proof_oracle(
        &setup.params,
        &setup.pk,
        &witness,
        ProverRandomness::fixed_seed_for_tests([4; 32]),
        ProverConfig::default(),
        vendored,
    )
    .expect("proof");
    assert_eq!(
        crate::verifier::verify_full_oracle(
            &setup.params,
            setup.pk.binding(),
            setup.pk.vk(),
            &instances,
            &proof,
            BUDGET,
            vendored,
        ),
        Ok(())
    );
    // Not a production proof, and not for another injected value.
    assert!(setup.verify(&instances, &proof).is_err());
    assert!(
        crate::verifier::verify_full_oracle(
            &setup.params,
            setup.pk.binding(),
            setup.pk.vk(),
            &instances,
            &proof,
            BUDGET,
            vendored + Fp::ONE,
        )
        .is_err()
    );
}

/// The malicious prover of soundness invariant S1: advice columns `a` and
/// `b` are committed to the same polynomial with the same blind, so their
/// commitments are equal. The claim for `b` is honest; the claim for `a` is
/// forged so that the gate identity holds at `x` although `a - b - 1 != 0`.
/// A verifier that grouped openings by commitment value and let the later
/// claim overwrite the earlier one would never check the forged claim; with
/// static grouping both slots are opened and the proof is rejected.
#[test]
fn equal_advice_commitments_with_different_evaluations_are_rejected() {
    let circuit = Forgeable { rows: 8 };
    let setup = setup::<Ep, _>(&circuit, CHOICES[0]);
    let pk = &setup.pk;
    let params = &setup.params;
    let descriptor = pk.binding().descriptor();
    let protocol = Protocol::new(descriptor).expect("protocol");
    let shape = *protocol.shape();
    assert_eq!((shape.permutation_sets, shape.lookups), (0, 0));
    let witness = Witness::from_circuit(pk, &circuit, &[]).expect("witness");
    let mut rng = ChaCha20Rng::seed_from_u64(77);
    let mut transcript =
        TranscriptWriter::<Ep, _>::new(DescriptorHash::<Ep>::production(descriptor.transcript));
    absorb_prelude::<Ep, _>(
        &mut transcript,
        pk.vk().transcript_repr().scalar().expect("scalar profile"),
        &[],
    );
    let instance = InstanceColumns::new(pk, &[], None).expect("instances");

    // Row 1: one blinded column, committed twice.
    let mut values = witness.advice()[0].clone();
    for value in &mut values[shape.usable_rows..] {
        *value = Fq::random(&mut rng);
    }
    let blind = Fq::random(&mut rng);
    let commitment = commit_lagrange(params.params(), &values, &blind, Secrecy::Secret, BUDGET)
        .expect("commit")
        .to_affine();
    transcript.write_point(&commitment).expect("a");
    transcript.write_point(&commitment).expect("b");
    let mut poly = values.clone();
    pk.domain().ifft(&mut poly).expect("ifft");
    let advice = Advice {
        values: vec![values.clone(), values],
        polys: vec![poly.clone(), poly.clone()],
        blinds: vec![blind, blind],
    };
    let theta = transcript.squeeze_challenge();
    let beta = transcript.squeeze_challenge();
    let gamma = transcript.squeeze_challenge();
    let random =
        commit_random(params, pk, &shape, &mut rng, &mut transcript, BUDGET, None).expect("random");
    let y = transcript.squeeze_challenge();
    let compiled = CompiledExpressions::compile(descriptor, true).expect("compile");
    let h = super::quotient::evaluate(
        pk,
        &protocol,
        &compiled,
        &QuotientInputs {
            advice: &advice.polys,
            instance: &instance.polys,
            permutation_products: Vec::new(),
            lookups: Vec::new(),
        },
        Challenges {
            theta,
            beta,
            gamma,
            y,
        },
        &crate::protocol::AllTerms,
    )
    .expect("quotient");
    let quotient = commit_quotient(
        params,
        pk,
        &shape,
        h,
        &mut rng,
        &mut transcript,
        BUDGET,
        None,
    )
    .expect("pieces");
    let x = transcript.squeeze_challenge();
    let xn = x.pow_vartime([shape.n as u64]);
    let combined = quotient.combine(xn);
    let h_at_x = evaluate_polynomial(&combined.coeffs, x);

    // Evaluations: the forged claim for a, the honest one for b.
    let omega = pk.domain().omega();
    let omega_inv = pk.domain().omega_inv();
    let fixed_evals: Vec<Fq> = descriptor
        .fixed_queries
        .iter()
        .map(|query| {
            evaluate_polynomial(
                &pk.fixed_polys()[query.column as usize],
                rotate(x, omega, omega_inv, query.rotation),
            )
        })
        .collect();
    let honest = evaluate_polynomial(&poly, x);
    // The gate is s (a - b - 1); solve s (a* - b - 1) = h(x) (x^n - 1).
    let selector = fixed_evals[0];
    let forged =
        honest + Fq::ONE + h_at_x * (xn - Fq::ONE) * selector.invert().expect("nonzero selector");
    assert_ne!(forged, honest);
    let advice_evals = [forged, honest];
    assert_eq!(
        descriptor
            .advice_queries
            .iter()
            .map(|query| query.column)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    // With the forged claim the gate identity holds at x.
    let gate = evaluate_expression(&descriptor.gates[0][0], &fixed_evals, &advice_evals, &[])
        .expect("gate");
    assert_eq!(gate, h_at_x * (xn - Fq::ONE));
    for value in advice_evals.iter().chain(&fixed_evals) {
        transcript.write_scalar(value);
    }
    transcript.write_scalar(&evaluate_polynomial(&random.coeffs, x));
    let opened = Opened {
        instance: &instance,
        advice: &advice,
        products: &[],
        lookups: &[],
        random: &random,
        quotient: combined,
    };
    let _claim = opened
        .open(
            params,
            pk,
            &protocol,
            x,
            &mut rng,
            &mut transcript,
            BUDGET,
            None,
        )
        .expect("open");
    let proof = transcript.finish();
    assert_eq!(proof.len(), protocol.proof_length());
    assert_eq!(
        verify_full(&setup.params, pk.binding(), pk.vk(), &[], &proof, BUDGET),
        Err(VerifyError::Ipa(IpaError::OpeningFailed))
    );
}

/// How [`Forged`] builds the permuted columns of its target lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ForgedStrategy {
    /// `A' = sort(A)`, `S' = sort(S)` over the usable rows.
    Sorted,
    /// `A' = sort(A)` and `S' = A'`.
    TableCopiesInput,
}

/// The usable rows `(A, S, A', S')` of a forged lookup.
type ForgedColumns<F> = (Vec<F>, Vec<F>, Vec<F>, Vec<F>);

/// A malicious lookup permutation: lookup `target` gets forged columns, every
/// other lookup the vendored permutation. Padding rows are drawn like the
/// vendored ones.
struct Forged<F> {
    target: usize,
    strategy: ForgedStrategy,
    recorded: Vec<ForgedColumns<F>>,
}

impl<F: PastaField> super::lookup::LookupPermutation<F> for Forged<F> {
    fn permute<R: rand_core_06::RngCore>(
        &mut self,
        input: &[F],
        table: &[F],
        usable_rows: usize,
        n: usize,
        lookup: usize,
        rng: &mut R,
    ) -> Result<(Vec<F>, Vec<F>), ProverError> {
        if lookup != self.target {
            return super::lookup::VendoredPermutation.permute(
                input,
                table,
                usable_rows,
                n,
                lookup,
                rng,
            );
        }
        let mut forged_input = input[..usable_rows].to_vec();
        forged_input.sort_unstable();
        let mut forged_table = match self.strategy {
            ForgedStrategy::Sorted => {
                let mut sorted = table[..usable_rows].to_vec();
                sorted.sort_unstable();
                sorted
            }
            ForgedStrategy::TableCopiesInput => forged_input.clone(),
        };
        self.recorded.push((
            input[..usable_rows].to_vec(),
            table[..usable_rows].to_vec(),
            forged_input.clone(),
            forged_table.clone(),
        ));
        forged_input.extend(random_values::<F, _>(rng, n - usable_rows));
        forged_table.extend(random_values::<F, _>(rng, n - usable_rows));
        Ok((forged_input, forged_table))
    }
}

/// A constraint filter that omits the listed terms.
struct Omit(Vec<crate::protocol::ConstraintTerm>);

impl crate::protocol::ConstraintFilter for Omit {
    fn keeps(&self, term: crate::protocol::ConstraintTerm) -> bool {
        !self.0.contains(&term)
    }
}

/// Proves `circuit` with the real prover except for lookup `target`, whose
/// columns `strategy` forges and whose violated constraints `omit` leaves out
/// of the quotient (so the forged `h` is a polynomial). Returns the proof,
/// the forged columns and the setup.
fn forged_lookup_proof<C: PastaCurve>(
    setup: &Setup<C>,
    circuit: &Lookups,
    target: usize,
    strategy: ForgedStrategy,
    omit: &Omit,
) -> (Vec<u8>, Vec<ForgedColumns<C::ScalarExt>>)
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let witness = Witness::from_circuit(&setup.pk, circuit, &[]).expect("witness");
    let mut forged = Forged {
        target,
        strategy,
        recorded: Vec::new(),
    };
    let proof = prove(
        &setup.params,
        &setup.pk,
        WitnessInput::Borrowed(&witness),
        ProverRandomness::fixed_seed_for_tests([21; 32]),
        ProverConfig::default(),
        Mode {
            oracle: false,
            transcript_repr: *setup.pk.vk().transcript_repr(),
        },
        &mut forged,
        omit,
    )
    .expect("the forged permutation does not refuse");
    let protocol = Protocol::new(setup.pk.binding().descriptor()).expect("protocol");
    assert_eq!(proof.len(), protocol.proof_length());
    (proof, forged.recorded)
}

/// The lookup constraints that forged usable columns `(A, S, A', S')`
/// violate: `Start` when `A'_0 != S'_0`; `Step` when that holds or some
/// usable row has `A'_i != S'_i` and `A'_i != A'_{i-1}`; `Last` when `A'` or
/// `S'` is not a permutation of `A` or `S` (the grand product does not close
/// at `l_last`). `First` and `Product` hold by construction of `z`.
fn violated_lookup_terms<F: Ord + Clone>(
    lookup: usize,
    (input, table, forged_input, forged_table): &ForgedColumns<F>,
) -> Vec<crate::protocol::ConstraintTerm> {
    use crate::protocol::{ConstraintTerm, LookupConstraint};
    let start = forged_input[0] != forged_table[0];
    let step = start
        || (1..forged_input.len()).any(|row| {
            forged_input[row] != forged_table[row] && forged_input[row] != forged_input[row - 1]
        });
    let last = different_multisets(input, forged_input) || different_multisets(table, forged_table);
    [
        (start, LookupConstraint::Start),
        (step, LookupConstraint::Step),
        (last, LookupConstraint::Last),
    ]
    .into_iter()
    .filter(|(violated, _)| *violated)
    .map(|(_, part)| ConstraintTerm::Lookup { lookup, part })
    .collect()
}

/// Whether two columns hold different multisets.
fn different_multisets<F: Ord + Clone>(left: &[F], right: &[F]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort_unstable();
    right.sort_unstable();
    left != right
}

/// One malicious-prover case: forges lookup `target` with `strategy`,
/// requires the violated terms to be `expected`, and checks that the real
/// verifier rejects with `OpeningFailed` while a verifier that omits exactly
/// those terms accepts.
fn forged_lookup_case<C: PastaCurve>(
    circuit: &Lookups,
    choice: Choice,
    target: usize,
    strategy: ForgedStrategy,
    expected: &[crate::protocol::LookupConstraint],
) where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let label = format!("{strategy:?} lookup {target}, {choice:?}");
    let setup = setup::<C, _>(circuit, choice);
    // Pass 1 records the forged columns (theta, and so the columns, depend
    // only on the advice commitments and the seed).
    let (_, recorded) = forged_lookup_proof(&setup, circuit, target, strategy, &Omit(Vec::new()));
    let violated = violated_lookup_terms(target, &recorded[0]);
    let expected: Vec<_> = expected
        .iter()
        .map(|part| crate::protocol::ConstraintTerm::Lookup {
            lookup: target,
            part: *part,
        })
        .collect();
    assert_eq!(violated, expected, "{label}");
    // Pass 2: the quotient leaves the violated terms out.
    let omit = Omit(violated);
    let (proof, again) = forged_lookup_proof(&setup, circuit, target, strategy, &omit);
    assert_eq!(again, recorded, "{label}: deterministic columns");
    assert_eq!(
        setup.verify(&[], &proof),
        Err(VerifyError::Ipa(IpaError::OpeningFailed)),
        "{label}"
    );
    assert_eq!(
        crate::verifier::verify_full_filtered(
            &setup.params,
            setup.pk.binding(),
            setup.pk.vk(),
            &[],
            &proof,
            &omit,
        ),
        Ok(()),
        "{label}: without the violated terms the forgery would pass"
    );
}

/// Malicious prover for the halo2 permuted lookup (spec section 2,
/// "Lookup"; spec section 15). The vendored permutation refuses an input
/// missing from its table, so the prover-side refusal never exercises the
/// verifier. Here the prover skips it, commits forged `A'`/`S'`, computes
/// `z` and the opening with the real prover and leaves exactly the violated
/// constraints out of its quotient, so `h` is a genuine polynomial. The
/// verifier must reject with `OpeningFailed`, and a verifier without those
/// constraints would accept: the rejection is attributable to them alone.
///
/// - An input missing from its table (`out_of_range`: `x + 1 = 16` fails
///   the `range` lookup only; the square gate and the pair lookup hold) with
///   `A' = sort(A)` and `S' = sort(S)`: both are permutations, so the grand
///   product closes and only `Step` is violated.
/// - The same input with `S' = A' = sort(A)`: `Start` and `Step` vanish
///   identically and `S'` is not a permutation of `S`, so only `Last`
///   (`l_last (z^2 - z)`) is violated.
/// - An honest witness (every input in its table) with sorted columns: only
///   `Step` is violated; it checks the positional structure, not only
///   membership.
#[test]
fn forged_lookup_permutations_are_rejected_by_the_verifier() {
    use crate::protocol::LookupConstraint::{Last, Step};
    let missing = Lookups {
        out_of_range: true,
        ..LOOKUPS
    };
    // The honest prover refuses the missing input before any message.
    assert_eq!(
        setup::<Ep, _>(&missing, CHOICES[0]).prove(&missing, &[], 21),
        Err(ProverError::LookupInputMissing { lookup: 1 })
    );
    // Harness control: forging and omitting nothing yields an accepted proof.
    let control = setup::<Ep, _>(&LOOKUPS, CHOICES[0]);
    let (proof, recorded) = forged_lookup_proof(
        &control,
        &LOOKUPS,
        usize::MAX,
        ForgedStrategy::Sorted,
        &Omit(Vec::new()),
    );
    assert!(recorded.is_empty());
    assert_eq!(control.verify(&[], &proof), Ok(()));

    for choice in [CHOICES[0], CHOICES[1]] {
        forged_lookup_case::<Ep>(&missing, choice, 1, ForgedStrategy::Sorted, &[Step]);
        forged_lookup_case::<Eq>(
            &missing,
            choice,
            1,
            ForgedStrategy::TableCopiesInput,
            &[Last],
        );
        forged_lookup_case::<Ep>(&LOOKUPS, choice, 0, ForgedStrategy::Sorted, &[Step]);
    }
}

/// The circuit check compares copies through the key's copy digest: a key
/// whose copies differ only by one extra usable-row copy refuses the
/// circuit, the matching key accepts it.
#[test]
fn witnesses_are_checked_against_the_key_copy_digest() {
    let setup = setup::<Ep, _>(&ARITHMETIC, CHOICES[0]);
    let instances = ARITHMETIC.instances::<Fq>();
    assert!(Witness::from_circuit(&setup.pk, &ARITHMETIC, &instances).is_ok());
    let synthesized = crate::frontend::synthesize(&ARITHMETIC, K, None).expect("synthesize");
    let tables = synthesized.tables;
    let mut copies = tables.permutation().clone();
    let column = copies.columns()[0];
    copies
        .copy(column, 0, column, tables.usable_rows() - 1)
        .expect("in the domain");
    let other = crate::keys::keygen_from_tables(
        &setup.params,
        synthesized.cs,
        tables.fixed().to_vec(),
        tables.selectors().to_vec(),
        &copies,
        &crate::test_circuits::keygen_config(CHOICES[0]),
    )
    .expect("pk");
    assert_eq!(other.binding(), setup.pk.binding());
    assert_ne!(other.copy_digest(), setup.pk.copy_digest());
    assert_eq!(
        Witness::from_circuit(&other, &ARITHMETIC, &instances).err(),
        Some(ProverError::CircuitMismatch)
    );
}

/// The digests stream exactly the documented bytes (spec section 10).
#[test]
fn witness_and_statement_digests_stream_the_documented_bytes() {
    let setup = setup::<Ep, _>(&ARITHMETIC, CHOICES[0]);
    let instances = ARITHMETIC.instances::<Fq>();
    let witness = Witness::from_circuit(&setup.pk, &ARITHMETIC, &instances).expect("witness");
    let usable = Protocol::new(setup.pk.binding().descriptor())
        .expect("protocol")
        .shape()
        .usable_rows;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    bytes.extend_from_slice(&u32::try_from(usable).expect("small").to_le_bytes());
    for column in witness.advice() {
        for value in &column[..usable] {
            bytes.extend_from_slice(&value.to_repr());
        }
    }
    assert_eq!(
        witness.digest(usable, None).unwrap(),
        crate::cs::descriptor::blake2b_personal::<32>(WITNESS_PERSONA, &[&bytes])
    );
    let repr = Fq::from(5);
    let mut bytes = vec![7_u8; 32];
    bytes.extend_from_slice(&repr.to_repr());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    for value in &instances[0] {
        bytes.extend_from_slice(&value.to_repr());
    }
    assert_eq!(
        statement_digest(&[7; 32], &repr, &instances),
        crate::cs::descriptor::blake2b_personal::<32>(STATEMENT_PERSONA, &[&bytes])
    );
}

#[test]
fn statement_digests_frame_the_instances() {
    let digest = [3_u8; 32];
    let repr = Fq::from(5);
    let base = statement_digest(&digest, &repr, &[vec![Fq::ONE], vec![]]);
    assert_ne!(
        base,
        statement_digest(&digest, &repr, &[vec![], vec![Fq::ONE]])
    );
    assert_ne!(
        base,
        statement_digest(&digest, &(repr + Fq::ONE), &[vec![Fq::ONE], vec![]])
    );
    assert_eq!(
        base,
        statement_digest(&digest, &repr, &[vec![Fq::ONE], vec![]])
    );
    assert_ne!(
        recovery_context(&[1; 32], &[2; 32]),
        recovery_context(&[2; 32], &[1; 32])
    );
}

#[test]
fn errors_display_their_cause() {
    for error in [
        ProverError::CircuitMismatch,
        ProverError::ParamsMismatch,
        ProverError::Entropy,
        ProverError::RecoveryStream,
        ProverError::DegenerateChallenge,
        ProverError::IdentityInstanceCommitment { column: 1 },
        ProverError::from(TranscriptError::IdentityPoint),
        ProverError::from(MultiopenError::NoQueries),
        ProverError::from(ProtocolError::Overflow),
    ] {
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        ProverError::from(CsError::Overflow),
        ProverError::Synthesis(frontend::Error::ConstraintSystem(Box::new(
            CsError::Overflow
        )))
    );
}

/// Prove and verify timings of the arithmetic chain filling the usable rows
/// (run with `--release -- --ignored --nocapture`).
#[test]
#[ignore = "timing measurement; run in release"]
fn measure_prove_and_verify() {
    use std::time::Instant;

    for k in [10_u32, 12, 14] {
        let n = 1_usize << k;
        let circuit = Arithmetic {
            start: 3,
            rows: n - 8,
            tamper: None,
        };
        let instances = circuit.instances::<Fp>();
        let started = Instant::now();
        let params = PinnedParams::<Eq>::derive(k).expect("params");
        let derive = started.elapsed();
        let started = Instant::now();
        let pk = crate::keys::keygen_pk(
            &params,
            &circuit,
            &crate::test_circuits::keygen_config(CHOICES[0]),
        )
        .expect("pk");
        let keygen = started.elapsed();
        let witness = Witness::from_circuit(&pk, &circuit, &instances).expect("witness");
        for threads in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("pool");
            let started = Instant::now();
            let proof = pool
                .install(|| {
                    create_proof(
                        &params,
                        &pk,
                        &witness,
                        ProverRandomness::fixed_seed_for_tests([1; 32]),
                        ProverConfig::default(),
                    )
                })
                .expect("proof");
            let prove = started.elapsed();
            let started = Instant::now();
            pool.install(|| {
                verify_full(&params, pk.binding(), pk.vk(), &instances, &proof, BUDGET)
            })
            .expect("verify");
            let verify = started.elapsed();
            println!(
                "k={k} threads={threads}: params {derive:?}, keygen {keygen:?}, prove {prove:?}, \
                 verify {verify:?}, proof {} bytes",
                proof.len()
            );
        }
    }
}

#[path = "fixed_only_tests.rs"]
mod fixed_only;
