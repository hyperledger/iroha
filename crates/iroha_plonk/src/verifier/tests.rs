//! Verifier tests: every tamper of the proof bytes is rejected, decoding is
//! canonical with typed reasons, instance shapes are exact in both modes,
//! and the parameters, the verifying key and the descriptor are bound.

use ff::{Field, PrimeField};
use group::{Curve, Group, GroupEncoding};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaCurve, poseidon::PoseidonField};

use super::*;
use crate::{
    cs::descriptor::ExprNodeV1,
    pcs::ipa::accumulator::batch_decide,
    test_circuits::{Arithmetic, BUDGET, CHOICES, K, Lookups, Permutations, Setup, setup},
    transcript::MESSAGE_BYTES,
};

const ARITHMETIC: Arithmetic = Arithmetic {
    start: 5,
    rows: 6,
    tamper: None,
};

const LOOKUPS: Lookups = Lookups {
    rows: 5,
    tamper: None,
    out_of_range: false,
    offset: 0,
};

const PERMUTATIONS: Permutations = Permutations {
    rows: 4,
    tamper: None,
};

/// Flips bit 0 of every byte, and bit 7 of the last byte of every message
/// (a point's sign bit, a scalar's top bit); every result must be rejected.
fn every_flip_is_rejected<C: PastaCurve>(
    setup: &Setup<C>,
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
) where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    assert_eq!(setup.verify(instances, proof), Ok(()));
    let mut tampered = proof.to_vec();
    for index in 0..proof.len() {
        let masks: &[u8] = if index % MESSAGE_BYTES == MESSAGE_BYTES - 1 {
            &[0x01, 0x80]
        } else {
            &[0x01]
        };
        for mask in masks {
            tampered[index] ^= mask;
            assert!(
                setup.verify(instances, &tampered).is_err(),
                "byte {index} mask {mask:#04x} accepted"
            );
            tampered[index] ^= mask;
        }
    }
    assert_eq!(tampered, proof);
}

#[test]
fn every_byte_flip_is_rejected_on_both_curves() {
    let arithmetic = setup::<Ep, _>(&ARITHMETIC, CHOICES[0]);
    let instances = ARITHMETIC.instances::<Fq>();
    let proof = arithmetic.prove(&ARITHMETIC, &instances, 1).expect("proof");
    every_flip_is_rejected(&arithmetic, &instances, &proof);

    let lookups = setup::<Eq, _>(&LOOKUPS, CHOICES[1]);
    let proof = lookups.prove(&LOOKUPS, &[], 2).expect("proof");
    every_flip_is_rejected(&lookups, &[], &proof);
}

#[test]
fn every_byte_flip_is_rejected_with_linked_permutation_sets() {
    let permutations = setup::<Eq, _>(&PERMUTATIONS, CHOICES[3]);
    let instances = PERMUTATIONS.instances::<Fp>();
    let proof = permutations
        .prove(&PERMUTATIONS, &instances, 3)
        .expect("proof");
    every_flip_is_rejected(&permutations, &instances, &proof);
}

/// The message kinds of a proof in order (`true` for a point).
fn message_kinds<C: PastaCurve>(setup: &Setup<C>) -> Vec<bool> {
    let protocol = Protocol::new(setup.pk.binding().descriptor()).expect("protocol");
    let shape = protocol.shape();
    let k = shape.k as usize;
    let mut kinds = Vec::new();
    let mut push = |point: bool, count: usize| kinds.extend(std::iter::repeat_n(point, count));
    push(
        true,
        shape.num_advice + 3 * shape.lookups + shape.permutation_sets + 1,
    );
    push(true, shape.quotient_pieces);
    let instance_evals = if shape.committed_instances {
        shape.instance_queries
    } else {
        0
    };
    push(
        false,
        instance_evals
            + shape.advice_queries
            + shape.fixed_queries
            + 1
            + shape.permutation_columns
            + (3 * shape.permutation_sets).saturating_sub(1)
            + 5 * shape.lookups,
    );
    push(true, 1); // q'
    push(false, protocol.plan().sets().len());
    push(true, 1 + 2 * k); // S, then L_j and R_j
    push(false, 2); // c, f
    if shape.folded_generator_suffix {
        push(true, 1);
    }
    assert_eq!(kinds.len() * MESSAGE_BYTES, protocol.proof_length());
    kinds
}

/// Checks the transcript schedule of `circuit` under every choice (see
/// [`prover_and_verifier_follow_the_transcript_schedule`]).
fn check_schedule<C, Ci>(circuit: &Ci, instances: &[Vec<C::ScalarExt>])
where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
    Ci: crate::frontend::Circuit<C::ScalarExt>,
{
    use crate::{
        protocol::{TranscriptStep, schedule::HashOperation},
        transcript::recording::record,
    };
    for choice in CHOICES {
        let setup = setup::<C, _>(circuit, choice);
        let protocol = Protocol::new(setup.pk.binding().descriptor()).expect("protocol");
        let schedule = protocol.transcript_schedule();
        let expected: Vec<HashOperation> = schedule
            .iter()
            .filter_map(TranscriptStep::hash_operation)
            .collect();
        // The schedule's messages are the proof, kind by kind.
        let kinds: Vec<bool> = schedule
            .iter()
            .filter_map(|step| match step {
                TranscriptStep::Message(message) => Some(message.is_point()),
                TranscriptStep::Suffix => Some(true),
                _ => None,
            })
            .collect();
        assert_eq!(kinds, message_kinds(&setup), "{choice:?}");
        assert_eq!(
            kinds.len() * MESSAGE_BYTES,
            protocol.proof_length(),
            "{choice:?}"
        );
        // The prover and the verifier perform exactly the scheduled hash
        // operations, in order.
        let (proof, prover) = record(|| setup.prove(circuit, instances, 3));
        let proof = proof.expect("proof");
        assert_eq!(prover, expected, "{choice:?}: prover");
        let (verdict, verifier) = record(|| setup.verify(instances, &proof));
        assert_eq!(verdict, Ok(()));
        assert_eq!(verifier, expected, "{choice:?}: verifier");
        // A tampered proof stops on a prefix of the schedule.
        for index in [0, proof.len() / 2, proof.len() - 1] {
            let mut tampered = proof.clone();
            tampered[index] ^= 1;
            let (verdict, operations) = record(|| setup.verify(instances, &tampered));
            assert!(verdict.is_err(), "{choice:?}: byte {index}");
            assert!(
                expected.starts_with(&operations),
                "{choice:?}: byte {index}"
            );
        }
    }
}

/// S11: the native prover and verifier follow the protocol's transcript
/// schedule operation for operation (every absorb and squeeze, in order,
/// prelude included), the schedule's messages are exactly the proof bytes,
/// and a tampered proof stops on a prefix of the schedule. An in-circuit
/// verifier interprets the same table.
#[test]
fn prover_and_verifier_follow_the_transcript_schedule() {
    check_schedule::<Ep, _>(&ARITHMETIC, &ARITHMETIC.instances::<Fq>());
    check_schedule::<Eq, _>(&LOOKUPS, &[]);
    check_schedule::<Ep, _>(&PERMUTATIONS, &PERMUTATIONS.instances::<Fq>());
}

/// The constraint-term table lists the spec section 2 fold: every gate
/// polynomial, the permutation items 1-4 and five terms per lookup.
#[test]
fn constraint_terms_follow_the_spec_fold_order() {
    use crate::protocol::{ConstraintTerm, LookupConstraint};
    let permutations = setup::<Ep, _>(&PERMUTATIONS, CHOICES[0]);
    let protocol = Protocol::new(permutations.pk.binding().descriptor()).expect("protocol");
    let sets = protocol.shape().permutation_sets;
    let gates: usize = permutations
        .pk
        .binding()
        .descriptor()
        .gates
        .iter()
        .map(Vec::len)
        .sum();
    let mut expected: Vec<ConstraintTerm> = (0..gates)
        .map(|polynomial| ConstraintTerm::Gate { polynomial })
        .collect();
    expected.extend([
        ConstraintTerm::PermutationFirst,
        ConstraintTerm::PermutationLast,
    ]);
    expected.extend((1..sets).map(|set| ConstraintTerm::PermutationLink { set }));
    expected.extend((0..sets).map(|set| ConstraintTerm::PermutationProduct { set }));
    assert_eq!(protocol.constraint_terms(), expected.as_slice());

    let lookups = setup::<Eq, _>(&LOOKUPS, CHOICES[1]);
    let protocol = Protocol::new(lookups.pk.binding().descriptor()).expect("protocol");
    assert_eq!(protocol.shape().permutation_sets, 0);
    let terms = protocol.constraint_terms();
    let tail: Vec<_> = (0..2)
        .flat_map(|lookup| {
            LookupConstraint::ALL
                .iter()
                .map(move |part| ConstraintTerm::Lookup {
                    lookup,
                    part: *part,
                })
        })
        .collect();
    assert!(terms.ends_with(&tail));
    assert_eq!(terms.len(), 1 + tail.len(), "one square gate polynomial");
}

#[test]
fn structured_tampers_are_rejected_with_typed_reasons() {
    for choice in [CHOICES[0], CHOICES[1]] {
        let setup = setup::<Ep, _>(&ARITHMETIC, choice);
        let instances = ARITHMETIC.instances::<Fq>();
        let proof = setup.prove(&ARITHMETIC, &instances, 5).expect("proof");
        let kinds = message_kinds(&setup);
        let suffix = choice.2 == ProofSuffixV1::FoldedGenerator;
        let generator = Ep::generator().to_affine().to_bytes();
        let modulus = crate::cs::descriptor::modulus_le_bytes::<Fq>();
        for (index, point) in kinds.iter().enumerate() {
            let range = index * MESSAGE_BYTES..(index + 1) * MESSAGE_BYTES;
            let replace = |bytes: &[u8]| {
                let mut tampered = proof.clone();
                tampered[range.clone()].copy_from_slice(bytes);
                setup.verify(&instances, &tampered)
            };
            if *point {
                assert_eq!(
                    replace(&[0; 32]),
                    Err(VerifyError::Transcript(TranscriptError::IdentityPoint)),
                    "message {index}"
                );
                let last = suffix && index + 1 == kinds.len();
                let other = replace(&generator);
                if last {
                    assert_eq!(
                        other,
                        Err(VerifyError::Ipa(IpaError::FoldedGeneratorMismatch))
                    );
                } else {
                    assert!(other.is_err(), "message {index}");
                }
            } else {
                assert_eq!(
                    replace(&modulus),
                    Err(VerifyError::Transcript(TranscriptError::NonCanonicalScalar)),
                    "message {index}"
                );
                let value =
                    Fq::from_repr(proof[range.clone()].try_into().expect("32")).expect("canonical");
                assert!(
                    replace(&(value + Fq::ONE).to_repr()).is_err(),
                    "message {index}"
                );
            }
        }
    }
}

/// DEV-05 (spec section 14): any length other than the descriptor's, trailing bytes included, is
/// `ProofLength`; the vendored reader ignores trailing input.
#[test]
fn the_proof_length_is_exact() {
    let setup = setup::<Eq, _>(&ARITHMETIC, CHOICES[1]);
    let instances = ARITHMETIC.instances::<Fp>();
    let proof = setup.prove(&ARITHMETIC, &instances, 6).expect("proof");
    let expected = proof.len();
    let mut longer = proof.clone();
    longer.push(0);
    assert_eq!(
        setup.verify(&instances, &longer),
        Err(VerifyError::ProofLength {
            expected,
            actual: expected + 1
        })
    );
    longer.extend_from_slice(&[0; 31]);
    assert_eq!(
        setup.verify(&instances, &longer),
        Err(VerifyError::ProofLength {
            expected,
            actual: expected + 32
        })
    );
    assert_eq!(
        setup.verify(&instances, &proof[..expected - 1]),
        Err(VerifyError::ProofLength {
            expected,
            actual: expected - 1
        })
    );
    assert_eq!(
        setup.verify(&instances, &[]),
        Err(VerifyError::ProofLength {
            expected,
            actual: 0
        })
    );
}

#[test]
fn instance_shapes_are_exact_in_both_modes() {
    for choice in CHOICES {
        let setup = setup::<Ep, _>(&ARITHMETIC, choice);
        assert_eq!(
            setup.pk.binding().descriptor().instance_mode,
            choice.1,
            "{choice:?}"
        );
        let instances = ARITHMETIC.instances::<Fq>();
        let proof = setup.prove(&ARITHMETIC, &instances, 8).expect("proof");
        assert_eq!(setup.verify(&instances, &proof), Ok(()));
        assert_eq!(
            setup.verify(&[], &proof),
            Err(VerifyError::InstanceColumns {
                expected: 1,
                found: 0
            })
        );
        let mut extra = instances.clone();
        extra.push(Vec::new());
        assert_eq!(
            setup.verify(&extra, &proof),
            Err(VerifyError::InstanceColumns {
                expected: 1,
                found: 2
            })
        );
        // A trailing zero would describe the same polynomial; it is still
        // rejected (S4, DEV-04).
        let mut padded = instances.clone();
        padded[0].push(Fq::ZERO);
        assert_eq!(
            setup.verify(&padded, &proof),
            Err(VerifyError::InstanceLength {
                column: 0,
                expected: 2,
                found: 3
            })
        );
        let mut short = instances.clone();
        short[0].pop();
        assert_eq!(
            setup.verify(&short, &proof),
            Err(VerifyError::InstanceLength {
                column: 0,
                expected: 2,
                found: 1
            })
        );
        for position in 0..2 {
            let mut changed = instances.clone();
            changed[0][position] += Fq::ONE;
            assert!(setup.verify(&changed, &proof).is_err(), "{choice:?}");
        }
    }
}

#[test]
fn parameters_and_keys_are_bound() {
    let fixture = setup::<Ep, _>(&ARITHMETIC, CHOICES[0]);
    let instances = ARITHMETIC.instances::<Fq>();
    let proof = fixture.prove(&ARITHMETIC, &instances, 9).expect("proof");
    // Parameters of another k.
    let other = PinnedParams::<Ep>::derive(7).expect("params");
    assert_eq!(
        verify_full(
            &other,
            fixture.pk.binding(),
            fixture.pk.vk(),
            &instances,
            &proof,
            BUDGET
        ),
        Err(VerifyError::ParamsMismatch)
    );
    // A key bound to another descriptor.
    let poseidon = setup::<Ep, _>(&ARITHMETIC, CHOICES[3]);
    assert_eq!(
        verify_full(
            &fixture.params,
            fixture.pk.binding(),
            poseidon.pk.vk(),
            &instances,
            &proof,
            BUDGET
        ),
        Err(VerifyError::KeyMismatch)
    );
    // Malformed descriptor and key bytes.
    assert!(matches!(
        verify_full_from_bytes(
            &fixture.params,
            &[1, 2, 3],
            fixture.pk.vk().to_bytes(),
            &instances,
            &proof,
            BUDGET
        ),
        Err(VerifyError::Descriptor(_))
    ));
    let mut vk = fixture.pk.vk().to_bytes().to_vec();
    vk.push(0);
    assert!(matches!(
        verify_full_from_bytes(
            &fixture.params,
            fixture.pk.binding().encoded(),
            &vk,
            &instances,
            &proof,
            BUDGET
        ),
        Err(VerifyError::VerifyingKey(VkError::Length { .. }))
    ));
}

#[test]
fn the_descriptor_digest_binds_the_transcript() {
    // The same VK bytes read under a descriptor that differs only in one
    // gate constant: the relation changes, so does transcript_repr, and the
    // proof is rejected (hash what you verify).
    let setup = setup::<Ep, _>(&ARITHMETIC, CHOICES[0]);
    let instances = ARITHMETIC.instances::<Fq>();
    let proof = setup.prove(&ARITHMETIC, &instances, 10).expect("proof");
    let mut descriptor = setup.pk.binding().descriptor().clone();
    let scaled = descriptor
        .gates
        .iter_mut()
        .flatten()
        .flatten()
        .find_map(|node| match node {
            ExprNodeV1::Scaled(bytes) => Some(bytes),
            _ => None,
        })
        .expect("the add gate is scaled");
    *scaled = Fq::from(8).to_repr();
    let binding = DescriptorBinding::new(descriptor.arithmetic_layout()).expect("valid descriptor");
    assert_ne!(binding.digest(), setup.pk.binding().digest());
    let vk = VerifyingKey::<Ep>::read(setup.pk.vk().to_bytes(), &binding).expect("same bytes");
    assert_ne!(vk.transcript_repr(), setup.pk.vk().transcript_repr());
    assert_eq!(
        verify_full(&setup.params, &binding, &vk, &instances, &proof, BUDGET),
        Err(VerifyError::Ipa(IpaError::OpeningFailed))
    );
}

#[test]
fn succinct_accumulation_returns_a_pending_accumulator() {
    let setup = setup::<Eq, _>(&PERMUTATIONS, CHOICES[1]);
    let instances = PERMUTATIONS.instances::<Fp>();
    let first = setup.prove(&PERMUTATIONS, &instances, 1).expect("proof");
    let second = setup.prove(&PERMUTATIONS, &instances, 2).expect("proof");
    let succinct = |proof: &[u8]| {
        accumulate_succinct(
            &setup.params,
            setup.pk.binding(),
            setup.pk.vk(),
            &instances,
            proof,
            BUDGET,
        )
    };
    let accumulators = vec![
        succinct(&first).expect("first"),
        succinct(&second).expect("second"),
    ];
    assert_eq!(batch_decide(accumulators, &setup.params, BUDGET), Ok(()));
    // A naive substitution (a valid point that is neither G'_0 nor solved
    // from the equation) already fails the equation; the solved forgery,
    // which the equation cannot catch, is the malicious-prover test below.
    let mut forged = first.clone();
    let start = forged.len() - MESSAGE_BYTES;
    forged[start..].copy_from_slice(&Eq::generator().to_affine().to_bytes());
    assert_eq!(
        succinct(&forged).err(),
        Some(VerifyError::Ipa(IpaError::OpeningFailed))
    );
    assert_eq!(
        verify_full(
            &setup.params,
            setup.pk.binding(),
            setup.pk.vk(),
            &instances,
            &forged,
            BUDGET
        ),
        Err(VerifyError::Ipa(IpaError::FoldedGeneratorMismatch))
    );
}

/// Malicious prover, spec section 15 "`G` substituted after its challenge":
/// the folded-generator suffix `G` is read after every challenge and is not
/// absorbed, so for a false statement the prover keeps well-formed messages
/// (here: an honest proof of other instances) and solves the opening
/// equation for `G = c^-1 (P' + sum_j (u_j^-1 L_j + u_j R_j) - c b(x_3) z U -
/// f W)`. Succinct accumulation returns `Ok` (it is satisfiable for false
/// statements and is never a verdict); `decide`, `batch_decide`,
/// `verify_full` and `batch_verify` all reject.
#[test]
fn a_folded_generator_solved_from_the_equation_is_accumulated_but_never_accepted() {
    for choice in [CHOICES[1], CHOICES[2]] {
        let setup = setup::<Eq, _>(&PERMUTATIONS, choice);
        let (binding, vk) = (setup.pk.binding(), setup.pk.vk());
        let instances = PERMUTATIONS.instances::<Fp>();
        let honest = setup.prove(&PERMUTATIONS, &instances, 1).expect("proof");
        let mut false_statement = instances.clone();
        false_statement[0][1] += Fp::ONE;
        assert!(setup.verify(&false_statement, &honest).is_err());

        // Steps 1-8 against the false statement, then solve for G.
        let read = read_proof(
            &setup.params,
            binding,
            vk,
            &false_statement,
            &honest,
            production(vk),
            BUDGET,
            &AllTerms,
            None,
        )
        .expect("the messages are well formed");
        let (terms, neg_c, _) = read.pending.into_batch_terms(&setup.params);
        let c_inverse = Option::<Fp>::from((-neg_c).invert()).expect("c != 0");
        let solved = (terms.evaluate(BUDGET) * c_inverse).to_affine();
        let mut forged = honest.clone();
        let start = forged.len() - MESSAGE_BYTES;
        forged[start..].copy_from_slice(&solved.to_bytes());

        // 1. Succinct accumulation returns Ok for the false statement.
        let accumulator = accumulate_succinct(
            &setup.params,
            binding,
            vk,
            &false_statement,
            &forged,
            BUDGET,
        )
        .expect("Ok is satisfiable for a false statement");
        assert_eq!(accumulator.g(), &solved, "{choice:?}");
        // 2. Deciding it rejects, alone and in a batch with an honest one.
        assert_eq!(
            accumulator.clone().decide(&setup.params, BUDGET),
            Err(crate::pcs::ipa::accumulator::AccumulatorError::Rejected)
        );
        let genuine = accumulate_succinct(&setup.params, binding, vk, &instances, &honest, BUDGET)
            .expect("honest");
        assert_eq!(
            batch_decide(vec![genuine.clone(), accumulator], &setup.params, BUDGET),
            Err(crate::pcs::ipa::accumulator::AccumulatorError::BatchRejected)
        );
        assert_eq!(genuine.decide(&setup.params, BUDGET), Ok(()));
        // 3. Full verification computes G'_0 and rejects the suffix.
        assert_eq!(
            verify_full(
                &setup.params,
                binding,
                vk,
                &false_statement,
                &forged,
                BUDGET
            ),
            Err(VerifyError::Ipa(IpaError::FoldedGeneratorMismatch))
        );
        // 4. Batch verification decides the suffix through its accumulator item.
        let item = BatchItem {
            params: &setup.params,
            binding,
            vk,
            instances: &false_statement,
            proof: &forged,
        };
        assert_eq!(
            batch_verify(&[item], BUDGET),
            Err(VerifyError::BatchRejected)
        );
    }
}

#[test]
fn errors_convert_to_typed_reasons() {
    assert_eq!(
        VerifyError::from(MultiopenError::Ipa(IpaError::Transcript(
            TranscriptError::IdentityPoint
        ))),
        VerifyError::Transcript(TranscriptError::IdentityPoint)
    );
    assert_eq!(
        VerifyError::from(MultiopenError::DegenerateChallenge),
        VerifyError::Multiopen(MultiopenError::DegenerateChallenge)
    );
    assert_eq!(
        VerifyError::from(IpaError::OpeningFailed),
        VerifyError::Ipa(IpaError::OpeningFailed)
    );
    for error in [
        VerifyError::KeyMismatch,
        VerifyError::ParamsMismatch,
        VerifyError::DegenerateChallenge,
        VerifyError::SuffixRequired,
        VerifyError::IdentityInstanceCommitment { column: 0 },
        VerifyError::from(ProtocolError::Overflow),
        VerifyError::from(VkError::Shape),
    ] {
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn batch_verification_merges_proofs_of_mixed_k() {
    let committed = setup::<Ep, _>(&ARITHMETIC, CHOICES[0]);
    let folded = setup::<Ep, _>(&ARITHMETIC, CHOICES[2]);
    let instances = ARITHMETIC.instances::<Fq>();
    let first = committed.prove(&ARITHMETIC, &instances, 1).expect("proof");
    let second = committed.prove(&ARITHMETIC, &instances, 2).expect("proof");
    let third = folded.prove(&ARITHMETIC, &instances, 3).expect("proof");
    // A k = 7 proof with a FoldedGenerator suffix.
    let params7 = PinnedParams::<Ep>::derive(7).expect("params");
    let pk7 = crate::keys::keygen_pk(
        &params7,
        &ARITHMETIC,
        &crate::test_circuits::keygen_config(CHOICES[1]),
    )
    .expect("pk");
    let fourth = crate::prover::prove_circuit(
        &params7,
        &pk7,
        &ARITHMETIC,
        &instances,
        crate::prover::ProverRandomness::fixed_seed_for_tests([4; 32]),
        crate::prover::ProverConfig::default(),
    )
    .expect("proof");
    let item = |setup: &'static str, proof| -> BatchItem<'_, Ep> {
        let (params, pk) = match setup {
            "committed" => (&committed.params, &committed.pk),
            "folded" => (&folded.params, &folded.pk),
            _ => (&params7, &pk7),
        };
        BatchItem {
            params,
            binding: pk.binding(),
            vk: pk.vk(),
            instances: &instances,
            proof,
        }
    };
    let items = [
        item("committed", first.as_slice()),
        item("committed", second.as_slice()),
        item("folded", third.as_slice()),
        item("k7", fourth.as_slice()),
    ];
    assert_eq!(batch_verify(&items, BUDGET), Ok(()));
    assert_eq!(batch_verify::<Ep>(&[], BUDGET), Ok(()));
    for index in [0, 2, 3] {
        assert_eq!(batch_verify(&[items[index]], BUDGET), Ok(()), "{index}");
    }

    // Another statement for one item: decoding succeeds, the equation fails.
    let mut changed = instances.clone();
    changed[0][1] += Fq::ONE;
    let mut bad = items;
    bad[1].instances = &changed;
    assert_eq!(batch_verify(&bad, BUDGET), Err(VerifyError::BatchRejected));

    // A suffix that is not G'_0 fails through its accumulator item.
    let mut forged = fourth.clone();
    let start = forged.len() - MESSAGE_BYTES;
    forged[start..].copy_from_slice(&Ep::generator().to_affine().to_bytes());
    let mut bad = items;
    bad[3].proof = &forged;
    assert_eq!(batch_verify(&bad, BUDGET), Err(VerifyError::BatchRejected));

    // Steps 1-8 failures name the item.
    let mut bad = items;
    bad[2].proof = &third[..third.len() - 1];
    assert_eq!(
        batch_verify(&bad, BUDGET),
        Err(VerifyError::BatchItem {
            index: 2,
            error: Box::new(VerifyError::ProofLength {
                expected: third.len(),
                actual: third.len() - 1
            })
        })
    );
    assert!(
        VerifyError::BatchItem {
            index: 2,
            error: Box::new(VerifyError::BatchRejected)
        }
        .to_string()
        .contains("item 2")
    );
}

/// DEV-07 (spec section 14): `x = 0` and `x^n = 1` are typed `DegenerateChallenge` rejections; the
/// vendored verifier panics on `x^n = 1`.
#[test]
fn degenerate_challenges_are_typed_rejections() {
    let omega = crate::protocol::omega::<Fq>(K).expect("omega");
    let n = 1_u64 << K;
    for x in [Fq::ZERO, Fq::ONE, omega, omega.square(), -Fq::ONE] {
        assert_eq!(
            check_challenge(x, x.pow_vartime([n])),
            Err(VerifyError::DegenerateChallenge),
            "{x:?}"
        );
    }
    let x = Fq::from(123_456_789);
    assert_eq!(check_challenge(x, x.pow_vartime([n])), Ok(()));
}
