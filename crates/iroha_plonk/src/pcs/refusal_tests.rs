//! Force formerly exceptional raw challenges through actual native PCS owners.
use crate::{
    pcs::{
        ipa::{
            self, PinnedParams,
            commit::{Msm, Secrecy, commit},
            evaluate_polynomial,
        },
        multiopen::{
            self, MultiopenError, OpeningPlan, OpeningQuery, Slot, SlotKind, prover::SlotPolynomial,
        },
    },
    transcript::{
        Transcript, TranscriptError, TranscriptRead, TranscriptWrite, decode_point, encode_point,
        pipa_r,
    },
};
use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Eq, PastaCurve, msm::MemoryBudget};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;

struct Script<C: PastaCurve> {
    challenges: Vec<C::ScalarExt>,
    cursor: usize,
    events: Vec<&'static str>,
    points: Vec<C::AffineExt>,
    scalars: Vec<C::ScalarExt>,
    point_cursor: usize,
    scalar_cursor: usize,
}
impl<C: PastaCurve> Script<C> {
    fn new(challenges: Vec<C::ScalarExt>) -> Self {
        Self {
            challenges,
            cursor: 0,
            events: Vec::new(),
            points: Vec::new(),
            scalars: Vec::new(),
            point_cursor: 0,
            scalar_cursor: 0,
        }
    }
    fn reader(&self) -> Self {
        Self {
            points: self.points.clone(),
            scalars: self.scalars.clone(),
            ..Self::new(self.challenges.clone())
        }
    }
}
impl<C: PastaCurve> Transcript<C> for Script<C> {
    fn squeeze_challenge(&mut self) -> C::ScalarExt {
        self.events.push("challenge");
        let value = self.challenges[self.cursor];
        self.cursor += 1;
        value
    }
    fn common_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError> {
        decode_point::<C>(&encode_point::<C>(point)).map(|_| ())
    }
    fn common_scalar(&mut self, _: &C::ScalarExt) {}
}
impl<C: PastaCurve> TranscriptWrite<C> for Script<C> {
    fn write_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError> {
        self.common_point(point)?;
        self.events.push("point");
        self.points.push(*point);
        Ok(())
    }
    fn write_scalar(&mut self, value: &C::ScalarExt) {
        self.events.push("scalar");
        self.scalars.push(*value);
    }
}
impl<C: PastaCurve> TranscriptRead<C> for Script<C> {
    fn read_point(&mut self) -> Result<C::AffineExt, TranscriptError> {
        self.events.push("point");
        let point = self.points[self.point_cursor];
        self.point_cursor += 1;
        decode_point::<C>(&encode_point::<C>(&point))
    }
    fn read_scalar(&mut self) -> Result<C::ScalarExt, TranscriptError> {
        self.events.push("scalar");
        let scalar = self.scalars[self.scalar_cursor];
        self.scalar_cursor += 1;
        Ok(scalar)
    }
}

fn xi_and_round_maps<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(3).unwrap();
    let polynomial = vec![C::ScalarExt::ONE; 8];
    let blind = C::ScalarExt::ONE;
    let point = C::ScalarExt::from(9);
    let commitment = commit(
        params.params(),
        &polynomial,
        &blind,
        Secrecy::Public,
        MemoryBudget::DEFAULT,
    )
    .unwrap()
    .to_affine();
    for challenges in [
        vec![C::ScalarExt::ZERO; 5],
        vec![
            C::ScalarExt::ONE,
            C::ScalarExt::ONE,
            C::ScalarExt::ZERO,
            C::ScalarExt::ONE,
            C::ScalarExt::ZERO,
        ],
    ] {
        let mut writer = Script::<C>::new(challenges);
        let mut rng = ChaCha20Rng::from_seed([41; 32]);
        let claimed = ipa::prover::create_proof_with_claim(
            params.params(),
            &mut rng,
            &mut writer,
            &polynomial,
            &blind,
            &point,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        let mut reader = writer.reader();
        let pending = ipa::verifier::read_opening(
            3,
            Msm::<C>::from_point(commitment),
            &mut reader,
            &point,
            &evaluate_polynomial(&polynomial, point),
        )
        .unwrap();
        assert_eq!(pending.challenges(), &[C::ScalarExt::ONE; 3]);
        pending
            .check_claim(&params, claimed.g(), MemoryBudget::DEFAULT)
            .unwrap();
        claimed.decide(&params, MemoryBudget::DEFAULT).unwrap();
        let mut expected = vec!["point", "challenge", "challenge"];
        for _ in 0..3 {
            expected.extend(["point", "point", "challenge"]);
        }
        expected.extend(["scalar", "scalar"]);
        assert_eq!(writer.events, expected);
        assert_eq!(reader.events, expected);
        assert_eq!(reader.cursor, 5);
    }
}

fn x3_maps<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(3).unwrap();
    let plan = OpeningPlan::new(&[
        OpeningQuery::new(Slot::new(SlotKind::Advice, 0), 0),
        OpeningQuery::new(Slot::new(SlotKind::Advice, 0), 1),
    ])
    .unwrap();
    let x = pipa_r::evaluation_challenge(C::ScalarExt::from(2));
    let mut root = C::ScalarExt::ROOT_OF_UNITY;
    for _ in 3..C::ScalarExt::S {
        root = root.square();
    }
    let points = [x, x * root];
    let polynomial: Vec<_> = (1..=8).map(C::ScalarExt::from).collect();
    let polys = [SlotPolynomial {
        coeffs: &polynomial,
        blind: C::ScalarExt::ONE,
    }];
    let evaluations: Vec<_> = points
        .iter()
        .map(|point| evaluate_polynomial(&polynomial, *point))
        .collect();
    let commitment = commit(
        params.params(),
        &polynomial,
        &C::ScalarExt::ONE,
        Secrecy::Public,
        MemoryBudget::DEFAULT,
    )
    .unwrap()
    .to_affine();
    for raw in [
        C::ScalarExt::ONE,
        root,
        points[0],
        points[1],
        C::ScalarExt::ZERO,
    ] {
        let mut challenges = vec![
            C::ScalarExt::from(5),
            C::ScalarExt::from(7),
            raw,
            C::ScalarExt::from(11),
        ];
        challenges.extend([C::ScalarExt::ZERO; 5]);
        let mut writer = Script::<C>::new(challenges);
        let mut rng = ChaCha20Rng::from_seed([43; 32]);
        let generator = multiopen::prover::create_proof(
            params.params(),
            &plan,
            &points,
            &polys,
            &mut rng,
            &mut writer,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        let mut reader = writer.reader();
        let pending = multiopen::verifier::verify(
            &plan,
            &points,
            &[Msm::<C>::from_point(commitment)],
            &evaluations,
            3,
            &mut reader,
        )
        .unwrap();
        pending
            .check_claim(&params, &generator, MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(
            pending
                .folded_generator(&params, MemoryBudget::DEFAULT)
                .unwrap(),
            generator
        );
        let mut expected = vec![
            "challenge",
            "challenge",
            "point",
            "challenge",
            "scalar",
            "challenge",
            "point",
            "challenge",
            "challenge",
        ];
        for _ in 0..3 {
            expected.extend(["point", "point", "challenge"]);
        }
        expected.extend(["scalar", "scalar"]);
        assert_eq!(writer.events, expected);
        assert_eq!(reader.events, expected);
        assert_eq!(reader.cursor, 9);
    }
    // The low-level API accepts arbitrary points, so it still rejects a caller
    // supplying the mapped challenge itself. Only structured PLONK rotations
    // receive the unconditional disjoint-coset guarantee.
    let arbitrary = [
        pipa_r::multiopening_challenge(C::ScalarExt::ZERO),
        points[1],
    ];
    let mut writer = Script::<C>::new(vec![
        C::ScalarExt::ONE,
        C::ScalarExt::ONE,
        C::ScalarExt::ZERO,
    ]);
    let mut rng = ChaCha20Rng::from_seed([43; 32]);
    assert_eq!(
        multiopen::prover::create_proof(
            params.params(),
            &plan,
            &arbitrary,
            &polys,
            &mut rng,
            &mut writer,
            MemoryBudget::DEFAULT
        )
        .err(),
        Some(MultiopenError::DegenerateChallenge)
    );
    let mut reader = writer.reader();
    let evals: Vec<_> = arbitrary
        .iter()
        .map(|p| evaluate_polynomial(&polynomial, *p))
        .collect();
    assert_eq!(
        multiopen::verifier::verify(
            &plan,
            &arbitrary,
            &[Msm::<C>::from_point(commitment)],
            &evals,
            3,
            &mut reader
        )
        .err(),
        Some(MultiopenError::DegenerateChallenge)
    );
    assert_eq!(writer.events, reader.events);
}
#[test]
fn pallas_xi_and_round_zero_answers_map_without_retry() {
    xi_and_round_maps::<Ep>();
}
#[test]
fn vesta_xi_and_round_zero_answers_map_without_retry() {
    xi_and_round_maps::<Eq>();
}
#[test]
fn pallas_x3_total_rotations_and_arbitrary_point_refusal() {
    x3_maps::<Ep>();
}
#[test]
fn vesta_x3_total_rotations_and_arbitrary_point_refusal() {
    x3_maps::<Eq>();
}

fn collapsed_endpoint<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(3).unwrap();
    let x = pipa_r::multiopening_challenge(C::ScalarExt::from(3));
    let rounds: Vec<_> = [4_u64, 2, 1]
        .into_iter()
        .map(|power| x.pow_vartime([power]).invert().unwrap())
        .collect();
    for offset in [1_u64, 19] {
        let polynomial: Vec<_> = (offset..offset + 8).map(C::ScalarExt::from).collect();
        let blind = C::ScalarExt::from(7);
        let commitment = commit(
            params.params(),
            &polynomial,
            &blind,
            Secrecy::Public,
            MemoryBudget::DEFAULT,
        )
        .unwrap()
        .to_affine();
        let mut challenges = vec![C::ScalarExt::ONE, C::ScalarExt::from(3)];
        challenges.extend_from_slice(&rounds);
        let mut writer = Script::<C>::new(challenges);
        let mut rng = ChaCha20Rng::from_seed([57; 32]);
        let claim = ipa::prover::create_proof_with_claim(
            params.params(),
            &mut rng,
            &mut writer,
            &polynomial,
            &blind,
            &x,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        assert_eq!(claim.challenges(), rounds);
        assert_eq!(writer.scalars.len(), 2);
        assert_eq!(
            writer.scalars[0],
            C::ScalarExt::ZERO,
            "rank collapse forces c=0 for every honest polynomial"
        );
        let mut reader = writer.reader();
        let pending = ipa::verifier::read_opening(
            3,
            Msm::<C>::from_point(commitment),
            &mut reader,
            &x,
            &evaluate_polynomial(&polynomial, x),
        )
        .unwrap();
        pending
            .check_claim(&params, claim.g(), MemoryBudget::DEFAULT)
            .unwrap();
        claim.decide(&params, MemoryBudget::DEFAULT).unwrap();
        let mut changed_f = writer.reader();
        changed_f.scalars[1] += C::ScalarExt::ONE;
        let changed = ipa::verifier::read_opening(
            3,
            Msm::<C>::from_point(commitment),
            &mut changed_f,
            &x,
            &evaluate_polynomial(&polynomial, x),
        )
        .unwrap();
        assert!(
            changed
                .check_claim(&params, claim.g(), MemoryBudget::DEFAULT)
                .is_err(),
            "f is fixed by the matched path and c"
        );
        assert_eq!(reader.events, writer.events);
    }
}
#[test]
fn pallas_rank_collapse_forces_zero_c_and_unique_f() {
    collapsed_endpoint::<Ep>();
}
#[test]
fn vesta_rank_collapse_forces_zero_c_and_unique_f() {
    collapsed_endpoint::<Eq>();
}
