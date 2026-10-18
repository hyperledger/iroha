//! Multiopen round trips, tampering and the static-grouping soundness cases
//! (S1 equal commitments, S3 repeated queries) with the mutations they kill
//! (spec section 15: MV3 group by value, MV8 overwrite evaluations).

use ff::Field;
use group::{Curve, Group};
use iroha_pasta::{
    Ep, EpAffine, Eq, Fp, Fq, PastaCurve, fft::FftDomain, msm::MemoryBudget, params::ParamsIpa,
};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;

use super::{
    MultiopenError, OpeningPlan, OpeningQuery, ShapeItem, Slot, SlotKind,
    prover::{SlotPolynomial, create_proof},
    verifier::verify,
};
use crate::{
    pcs::ipa::{
        IpaError, PinnedParams,
        commit::{Msm, Secrecy, commit},
        evaluate_polynomial,
        verifier::PendingOpening,
    },
    transcript::{
        Blake2bHash, PoseidonHash, Transcript, TranscriptError, TranscriptHash, TranscriptRead,
        TranscriptReader, TranscriptWriter,
    },
};

const BUDGET: MemoryBudget = MemoryBudget::DEFAULT;

/// One committed slot polynomial.
struct Committed<C: PastaCurve> {
    coeffs: Vec<C::ScalarExt>,
    blind: C::ScalarExt,
    commitment: Msm<C>,
}

fn random_poly<C: PastaCurve>(params: &ParamsIpa<C>, rng: &mut ChaCha20Rng) -> Committed<C> {
    let coeffs: Vec<C::ScalarExt> = (0..params.n())
        .map(|_| C::ScalarExt::random(&mut *rng))
        .collect();
    let blind = C::ScalarExt::random(&mut *rng);
    let point = commit(params, &coeffs, &blind, Secrecy::Secret, BUDGET)
        .expect("commit")
        .to_affine();
    Committed {
        coeffs,
        blind,
        commitment: Msm::from_point(point),
    }
}

/// A test opening: plan, points, slot data, claimed evaluations and proof.
struct Case<C: PastaCurve> {
    params: PinnedParams<C>,
    plan: OpeningPlan,
    points: Vec<C::ScalarExt>,
    slots: Vec<Committed<C>>,
    evaluations: Vec<C::ScalarExt>,
}

impl<C: PastaCurve> Case<C> {
    /// Honest evaluations of every query.
    fn honest_evaluations(&self, queries: &[OpeningQuery]) -> Vec<C::ScalarExt> {
        let slot_index = |slot: Slot| {
            self.plan
                .slots()
                .iter()
                .position(|planned| planned.slot == slot)
                .expect("planned slot")
        };
        let rotation_index = |rotation: i32| {
            self.plan
                .rotations()
                .iter()
                .position(|r| *r == rotation)
                .expect("planned rotation")
        };
        queries
            .iter()
            .map(|query| {
                evaluate_polynomial(
                    &self.slots[slot_index(query.slot)].coeffs,
                    self.points[rotation_index(query.rotation)],
                )
            })
            .collect()
    }

    fn polys(&self) -> Vec<SlotPolynomial<'_, C::ScalarExt>> {
        self.slots
            .iter()
            .map(|slot| SlotPolynomial {
                coeffs: &slot.coeffs,
                blind: slot.blind,
            })
            .collect()
    }

    fn commitments(&self) -> Vec<Msm<C>> {
        self.slots
            .iter()
            .map(|slot| slot.commitment.clone())
            .collect()
    }

    fn prove<H: TranscriptHash<C>>(&self, hash: H, seed: u64) -> (Vec<u8>, C::AffineExt) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut transcript = TranscriptWriter::<C, H>::new(hash);
        let folded = create_proof(
            self.params.params(),
            &self.plan,
            &self.points,
            &self.polys(),
            &mut rng,
            &mut transcript,
            BUDGET,
        )
        .expect("prove");
        (transcript.finish(), folded)
    }

    fn read<H: TranscriptHash<C>>(
        &self,
        hash: H,
        proof: &[u8],
        commitments: &[Msm<C>],
        evaluations: &[C::ScalarExt],
    ) -> Result<PendingOpening<C>, MultiopenError> {
        let mut transcript = TranscriptReader::<C, H>::new(hash, proof);
        let pending = verify(
            &self.plan,
            &self.points,
            commitments,
            evaluations,
            self.params.k(),
            &mut transcript,
        )?;
        transcript.finish()?;
        Ok(pending)
    }

    fn verdict<H: TranscriptHash<C>>(
        &self,
        hash: H,
        proof: &[u8],
        commitments: &[Msm<C>],
        evaluations: &[C::ScalarExt],
    ) -> Result<(), MultiopenError> {
        self.read(hash, proof, commitments, evaluations)?
            .verify_full(&self.params, None, BUDGET)
            .map_err(MultiopenError::from)
    }
}

/// The standard query list: three advice columns (one with three
/// rotations), a fixed column, a permutation product and the quotient with
/// the random polynomial, in spec 9.1 order.
fn standard_queries() -> Vec<OpeningQuery> {
    let advice = |index| Slot::new(SlotKind::Advice, index);
    vec![
        OpeningQuery::new(advice(0), 0),
        OpeningQuery::new(advice(0), 1),
        OpeningQuery::new(advice(0), -1),
        OpeningQuery::new(advice(1), 0),
        OpeningQuery::new(advice(2), 0),
        OpeningQuery::new(Slot::new(SlotKind::PermutationProduct, 0), 0),
        OpeningQuery::new(Slot::new(SlotKind::PermutationProduct, 0), 1),
        OpeningQuery::new(Slot::new(SlotKind::Fixed, 0), 0),
        OpeningQuery::new(Slot::new(SlotKind::Fixed, 0), 1),
        OpeningQuery::new(Slot::new(SlotKind::Vanishing, 0), 0),
        OpeningQuery::new(Slot::new(SlotKind::Random, 0), 0),
    ]
}

/// A case over `queries` with random polynomials; the quotient slot (if
/// planned) is committed as two pieces `H_0 + x^n H_1`, as the PLONK verifier
/// builds it.
fn build_case<C: PastaCurve>(k: u32, seed: u64, queries: &[OpeningQuery]) -> Case<C> {
    let params = PinnedParams::<C>::derive(k).expect("params");
    let plan = OpeningPlan::new(queries).expect("plan");
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let x = C::ScalarExt::random(&mut rng);
    let domain = FftDomain::<C::ScalarExt>::new(k).expect("domain");
    let points = plan.points(x, domain.omega());
    let x_n = x.pow_vartime([params.params().n() as u64]);
    let slots = plan
        .slots()
        .iter()
        .map(|planned| {
            if planned.slot.kind == SlotKind::Vanishing {
                let low = random_poly(params.params(), &mut rng);
                let high = random_poly(params.params(), &mut rng);
                let coeffs = low
                    .coeffs
                    .iter()
                    .zip(&high.coeffs)
                    .map(|(l, h)| *l + x_n * h)
                    .collect();
                let mut commitment = high.commitment.clone();
                commitment.scale(&x_n);
                commitment.add_msm(&low.commitment);
                Committed {
                    coeffs,
                    blind: low.blind + x_n * high.blind,
                    commitment,
                }
            } else {
                random_poly(params.params(), &mut rng)
            }
        })
        .collect();
    let mut case = Case {
        params,
        plan,
        points,
        slots,
        evaluations: Vec::new(),
    };
    case.evaluations = case.honest_evaluations(queries);
    case
}

fn honest_round_trip<C: PastaCurve, H: TranscriptHash<C>>(k: u32, fresh: impl Fn() -> H) {
    let case = build_case::<C>(k, u64::from(k) + 100, &standard_queries());
    // {0, 1, -1} for advice 0, {0} for the single-rotation slots, {0, 1}.
    assert_eq!(case.plan.sets().len(), 3);
    let (proof, folded) = case.prove(fresh(), 1);
    let pending = case
        .read(fresh(), &proof, &case.commitments(), &case.evaluations)
        .expect("read");
    assert_eq!(pending.folded_generator(&case.params, BUDGET), Ok(folded));
    pending
        .clone()
        .verify_full(&case.params, Some(&folded), BUDGET)
        .expect("full");
    pending
        .accumulate(&case.params, &folded, &C::ScalarExt::ONE, BUDGET)
        .expect("succinct")
        .decide(&case.params, BUDGET)
        .expect("decide");
}

#[test]
fn honest_openings_verify_on_both_curves_and_transcripts() {
    for k in [3, 5] {
        honest_round_trip::<Ep, _>(k, Blake2bHash::<Ep>::new);
        honest_round_trip::<Eq, _>(k, Blake2bHash::<Eq>::new);
    }
    honest_round_trip::<Ep, _>(4, PoseidonHash::<Ep>::new);
    honest_round_trip::<Eq, _>(4, PoseidonHash::<Eq>::new);
}

#[test]
fn proof_bytes_are_identical_across_thread_pools() {
    let case = build_case::<Eq>(5, 7, &standard_queries());
    let reference = case.prove(Blake2bHash::<Eq>::new(), 3);
    for threads in [1, 2, 4, 7] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("pool");
        let proof = pool.install(|| case.prove(Blake2bHash::<Eq>::new(), 3));
        assert_eq!(proof, reference, "{threads} threads");
    }
    // A different seed changes every blinded message.
    let other = case.prove(Blake2bHash::<Eq>::new(), 4);
    assert_ne!(other.0[..32], reference.0[..32]);
}

#[test]
fn wrong_evaluations_commitments_and_bytes_are_rejected() {
    let case = build_case::<Ep>(3, 11, &standard_queries());
    let (proof, _) = case.prove(Blake2bHash::<Ep>::new(), 5);
    let commitments = case.commitments();
    for query in 0..case.evaluations.len() {
        let mut evaluations = case.evaluations.clone();
        evaluations[query] += Fq::ONE;
        assert_eq!(
            case.verdict(Blake2bHash::<Ep>::new(), &proof, &commitments, &evaluations),
            Err(MultiopenError::Ipa(IpaError::OpeningFailed)),
            "query {query}"
        );
    }
    let mut swapped = commitments.clone();
    swapped.swap(1, 2);
    assert!(
        case.verdict(
            Blake2bHash::<Ep>::new(),
            &proof,
            &swapped,
            &case.evaluations
        )
        .is_err()
    );
    for message in 0..proof.len() / 32 {
        let mut tampered = proof.clone();
        tampered[32 * message + 3] ^= 0x10;
        assert!(
            case.verdict(
                Blake2bHash::<Ep>::new(),
                &tampered,
                &commitments,
                &case.evaluations
            )
            .is_err(),
            "message {message}"
        );
    }
    let mut long = proof.clone();
    long.push(1);
    assert_eq!(
        case.verdict(
            Blake2bHash::<Ep>::new(),
            &long,
            &commitments,
            &case.evaluations
        ),
        Err(MultiopenError::Ipa(IpaError::Transcript(
            TranscriptError::TrailingBytes { remaining: 1 }
        )))
    );
    // The same proof under the other transcript fails.
    assert!(
        case.verdict(
            PoseidonHash::<Ep>::new(),
            &proof,
            &commitments,
            &case.evaluations
        )
        .is_err()
    );
}

#[test]
fn equal_commitments_with_different_evaluations_are_rejected() {
    // S1 / MV3. Advice columns 0 and 1 commit to the same polynomial and
    // blind, so their commitments are equal. The forger claims a false value
    // for column 0 at rotation 0 and the true value for column 1.
    let advice = |index| Slot::new(SlotKind::Advice, index);
    let queries = [
        OpeningQuery::new(advice(0), 0),
        OpeningQuery::new(advice(1), 0),
    ];
    let mut case = build_case::<Eq>(3, 13, &queries);
    let duplicate = Committed {
        coeffs: case.slots[0].coeffs.clone(),
        blind: case.slots[0].blind,
        commitment: case.slots[0].commitment.clone(),
    };
    case.slots[1] = duplicate;
    let honest = case.honest_evaluations(&queries);
    assert_eq!(honest[0], honest[1]);
    let forged = vec![honest[0] + Fp::ONE, honest[1]];

    // A verifier grouping by commitment value would merge the two queries
    // and keep only the later evaluation (the vendored overwrite). Its plan
    // has one slot; a proof for that plan exists, and the false value is
    // never checked.
    let merged_queries = [OpeningQuery::new(advice(0), 0)];
    let mut merged = build_case::<Eq>(3, 13, &merged_queries);
    merged.slots = vec![Committed {
        coeffs: case.slots[0].coeffs.clone(),
        blind: case.slots[0].blind,
        commitment: case.slots[0].commitment.clone(),
    }];
    merged.points = case.points.clone();
    let (merged_proof, _) = merged.prove(Blake2bHash::<Eq>::new(), 2);
    assert_eq!(
        merged.verdict(
            Blake2bHash::<Eq>::new(),
            &merged_proof,
            &merged.commitments(),
            &forged[1..]
        ),
        Ok(())
    );

    // Static grouping keeps both slots: neither the merged proof nor an
    // honestly generated proof makes the forged claim verify.
    let commitments = case.commitments();
    assert!(
        case.verdict(
            Blake2bHash::<Eq>::new(),
            &merged_proof,
            &commitments,
            &forged
        )
        .is_err()
    );
    let (proof, _) = case.prove(Blake2bHash::<Eq>::new(), 2);
    assert_eq!(
        case.verdict(Blake2bHash::<Eq>::new(), &proof, &commitments, &forged),
        Err(MultiopenError::Ipa(IpaError::OpeningFailed))
    );
    assert_eq!(
        case.verdict(Blake2bHash::<Eq>::new(), &proof, &commitments, &honest),
        Ok(())
    );
}

#[test]
fn repeated_queries_must_agree_bit_for_bit() {
    // S3 / MV8: a repeat is dropped only when its evaluation is identical.
    let advice = Slot::new(SlotKind::Advice, 0);
    let fixed = Slot::new(SlotKind::Fixed, 0);
    let queries = [
        OpeningQuery::new(advice, 0),
        OpeningQuery::new(fixed, 1),
        OpeningQuery::new(advice, 0),
    ];
    let case = build_case::<Ep>(3, 17, &queries);
    let (proof, _) = case.prove(Blake2bHash::<Ep>::new(), 6);
    let commitments = case.commitments();
    assert_eq!(
        case.verdict(
            Blake2bHash::<Ep>::new(),
            &proof,
            &commitments,
            &case.evaluations
        ),
        Ok(())
    );
    let mut conflicting = case.evaluations.clone();
    conflicting[2] += Fq::ONE;
    assert_eq!(
        case.verdict(Blake2bHash::<Ep>::new(), &proof, &commitments, &conflicting),
        Err(MultiopenError::ConflictingEvaluations { query: 2 })
    );
    // An overwrite (keeping only the later value) would have checked the
    // repeat instead of the first claim; here the first claim is checked.
    let mut first_false = case.evaluations.clone();
    first_false[0] += Fq::ONE;
    first_false[2] = first_false[0];
    assert_eq!(
        case.verdict(Blake2bHash::<Ep>::new(), &proof, &commitments, &first_false),
        Err(MultiopenError::Ipa(IpaError::OpeningFailed))
    );
}

#[test]
fn malformed_inputs_are_typed_rejections() {
    let case = build_case::<Ep>(3, 19, &standard_queries());
    let (proof, _) = case.prove(Blake2bHash::<Ep>::new(), 7);
    let commitments = case.commitments();
    let check = |points: &[Fq], commitments: &[Msm<Ep>], evaluations: &[Fq]| {
        let mut transcript = TranscriptReader::<Ep, _>::new(Blake2bHash::new(), &proof);
        verify(
            &case.plan,
            points,
            commitments,
            evaluations,
            3,
            &mut transcript,
        )
        .err()
    };
    assert_eq!(
        check(&case.points[1..], &commitments, &case.evaluations),
        Some(MultiopenError::Shape {
            what: ShapeItem::Points,
            expected: 3,
            actual: 2
        })
    );
    let mut colliding = case.points.clone();
    colliding[2] = colliding[0];
    assert_eq!(
        check(&colliding, &commitments, &case.evaluations),
        Some(MultiopenError::PointCollision)
    );
    assert_eq!(
        check(&case.points, &commitments[1..], &case.evaluations),
        Some(MultiopenError::Shape {
            what: ShapeItem::Slots,
            expected: commitments.len(),
            actual: commitments.len() - 1
        })
    );
    assert_eq!(
        check(&case.points, &commitments, &case.evaluations[1..]),
        Some(MultiopenError::Shape {
            what: ShapeItem::Evaluations,
            expected: case.evaluations.len(),
            actual: case.evaluations.len() - 1
        })
    );
    // The prover checks coefficient counts.
    let short = vec![Fq::ONE; 7];
    let mut polys = case.polys();
    polys[0].coeffs = &short;
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let mut transcript = TranscriptWriter::<Ep, _>::new(Blake2bHash::new());
    assert_eq!(
        create_proof(
            case.params.params(),
            &case.plan,
            &case.points,
            &polys,
            &mut rng,
            &mut transcript,
            BUDGET
        )
        .err(),
        Some(MultiopenError::Shape {
            what: ShapeItem::Coefficients,
            expected: 8,
            actual: 7
        })
    );
}

/// A transcript that returns scripted challenges, a fixed point and fixed
/// scalars (injected degenerate challenges).
struct Scripted {
    challenges: Vec<Fq>,
}

impl Transcript<Ep> for Scripted {
    fn squeeze_challenge(&mut self) -> Fq {
        if self.challenges.is_empty() {
            Fq::from(3)
        } else {
            self.challenges.remove(0)
        }
    }
    fn common_point(&mut self, _point: &EpAffine) -> Result<(), TranscriptError> {
        Ok(())
    }
    fn common_scalar(&mut self, _scalar: &Fq) {}
}

impl TranscriptRead<Ep> for Scripted {
    fn read_point(&mut self) -> Result<EpAffine, TranscriptError> {
        Ok(Ep::generator().to_affine())
    }
    fn read_scalar(&mut self) -> Result<Fq, TranscriptError> {
        Ok(Fq::ONE)
    }
}

#[test]
fn x3_on_an_opening_point_is_rejected() {
    let mut case = build_case::<Ep>(3, 23, &standard_queries());
    // A generic caller may supply the mapped x3 itself; structured PLONK rotations cannot.
    let raw_x3 = Fq::from(7);
    case.points[1] = crate::transcript::pipa_r::multiopening_challenge(raw_x3);
    let mut transcript = Scripted {
        challenges: vec![Fq::from(2), Fq::from(5), raw_x3],
    };
    assert_eq!(
        verify(
            &case.plan,
            &case.points,
            &case.commitments(),
            &case.evaluations,
            3,
            &mut transcript
        )
        .err(),
        Some(MultiopenError::DegenerateChallenge)
    );
    assert!(
        MultiopenError::DegenerateChallenge
            .to_string()
            .contains("x_3")
    );
}
