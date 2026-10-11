//! Cancellation at assignment, original-key import and public IPA boundaries.

use crate::{
    cs::{Advice, Column, ConstraintSystem, Rotation},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value},
    keys::{CosetCachePolicy, KeygenConfigV2, ProvingKey, keygen_pk_v2, pk::artifact},
    pcs::ipa::{
        IpaError, PinnedParams,
        commit::{msm_complete, msm_complete_cancellable},
        prover::create_proof_with_claim_cancellable,
    },
    transcript::{Blake2bHash, Transcript, TranscriptError, TranscriptWrite, TranscriptWriter},
};
use ff::Field;
use iroha_pasta::{
    CancellationToken, Ep, Eq, PastaCurve, PastaField,
    msm::{MemoryBudget, SharedMemoryBudget},
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

#[derive(Clone)]
struct AssignmentProbe {
    signal: CancellationToken,
    stop: bool,
}
impl<F: PastaField> Circuit<F> for AssignmentProbe {
    type Config = Column<Advice>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = meta.advice_column();
        meta.create_gate("bit", |cells| {
            let value = cells.query_advice(advice, Rotation::cur());
            vec![value.clone() * (value - crate::cs::Expression::Constant(F::ONE))]
        });
        advice
    }
    fn synthesize(
        &self,
        advice: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter
            .assign_region(
                || "cancel between actual assignments",
                |mut region| {
                    region.assign_advice(advice, 0, Value::known(F::ONE))?;
                    if self.stop {
                        self.signal.cancel();
                    }
                    region.assign_advice(advice, 1, Value::known(F::ONE))?;
                    Ok(())
                },
            )
            .map_err(|_| Error::Synthesis)
    }
}
fn assignment_and_import<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let source = AssignmentProbe {
        signal: CancellationToken::new(),
        stop: false,
    };
    let key = keygen_pk_v2(&params, &source, &KeygenConfigV2::pipa_r(vec![])).unwrap();
    let bytes = key.artifact_bytes_v2().unwrap();
    let read = artifact::ReadConfig {
        maximum_bytes: bytes.len(),
        maximum_rows: 64,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    for workers in [1, 4] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        let signal = CancellationToken::new();
        let cancelled_source = AssignmentProbe {
            signal: signal.clone(),
            stop: true,
        };
        let outcome = pool.install(|| {
            crate::Witness::from_circuit_cancellable(&key, &cancelled_source, &[], Some(&signal))
        });
        assert!(matches!(outcome, Err(crate::ProverError::Cancelled)));
        let signal = CancellationToken::new();
        let cancelled_source = AssignmentProbe {
            signal: signal.clone(),
            stop: true,
        };
        let outcome = pool.install(|| {
            ProvingKey::<C>::from_artifact_v2_cancellable(
                &bytes,
                key.binding(),
                &params,
                &cancelled_source,
                read,
                Some(&signal),
            )
        });
        assert_eq!(outcome.err(), Some(artifact::Error::Cancelled));
        let fresh = CancellationToken::new();
        let imported = pool
            .install(|| {
                ProvingKey::<C>::from_artifact_v2_cancellable(
                    &bytes,
                    key.binding(),
                    &params,
                    &source,
                    read,
                    Some(&fresh),
                )
            })
            .unwrap();
        assert_eq!(imported.artifact_bytes_v2().unwrap(), bytes);
        assert_eq!(imported.fixed_polys(), key.fixed_polys());
        assert_eq!(imported.mask_polys(), key.mask_polys());
    }
}
#[test]
fn cancellation_during_assignment_aborts_witness_and_original_import_then_retries() {
    assignment_and_import::<Ep>();
    assignment_and_import::<Eq>();
}

struct CancelAfterPoint<C: PastaCurve> {
    writer: TranscriptWriter<C, Blake2bHash<C>>,
    signal: CancellationToken,
}
impl<C: PastaCurve> Transcript<C> for CancelAfterPoint<C> {
    fn squeeze_challenge(&mut self) -> C::ScalarExt {
        self.writer.squeeze_challenge()
    }
    fn common_point(&mut self, value: &C::AffineExt) -> Result<(), TranscriptError> {
        self.writer.common_point(value)
    }
    fn common_scalar(&mut self, value: &C::ScalarExt) {
        self.writer.common_scalar(value);
    }
}
impl<C: PastaCurve> TranscriptWrite<C> for CancelAfterPoint<C> {
    fn write_point(&mut self, value: &C::AffineExt) -> Result<(), TranscriptError> {
        self.writer.write_point(value)?;
        self.signal.cancel();
        Ok(())
    }
    fn write_scalar(&mut self, value: &C::ScalarExt) {
        self.writer.write_scalar(value);
    }
}
fn ipa_retry<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let poly: Vec<_> = (1..=64).map(C::ScalarExt::from).collect();
    let blind = C::ScalarExt::from(29);
    let point = C::ScalarExt::from(13);
    let run = |signal: Option<&CancellationToken>| {
        let mut transcript = TranscriptWriter::<C, _>::new(Blake2bHash::new());
        let mut rng = ChaCha20Rng::from_seed([198; 32]);
        let claim = create_proof_with_claim_cancellable(
            params.params(),
            &mut rng,
            &mut transcript,
            &poly,
            &blind,
            &point,
            MemoryBudget::DEFAULT,
            signal,
        )
        .unwrap();
        (claim, transcript.finish())
    };
    let expected = run(None);
    let signal = CancellationToken::new();
    let mut transcript = CancelAfterPoint::<C> {
        writer: TranscriptWriter::new(Blake2bHash::new()),
        signal: signal.clone(),
    };
    let mut rng = ChaCha20Rng::from_seed([198; 32]);
    let result = create_proof_with_claim_cancellable(
        params.params(),
        &mut rng,
        &mut transcript,
        &poly,
        &blind,
        &point,
        MemoryBudget::DEFAULT,
        Some(&signal),
    );
    assert_eq!(result, Err(IpaError::Cancelled));
    assert!(
        !transcript.writer.finish().is_empty(),
        "cancel after a genuine written message"
    );
    let fresh = CancellationToken::new();
    assert_eq!(
        run(Some(&fresh)),
        expected,
        "fresh transcript and RNG preserve exact proof bytes"
    );
    expected
        .0
        .decide_cancellable(&params, MemoryBudget::DEFAULT, Some(&fresh))
        .unwrap();
}
#[test]
fn cancelled_ipa_requires_fresh_transcript_and_rng_for_exact_retry() {
    ipa_retry::<Ep>();
    ipa_retry::<Eq>();
}

fn complete_kernel<C: PastaCurve>() {
    let signal = CancellationToken::new();
    signal.cancel();
    let fresh = CancellationToken::new();
    let point = C::generator().to_affine();
    let bases = [point, -point, C::identity().to_affine(), point];
    let scalars = [
        C::ScalarExt::ONE,
        C::ScalarExt::ONE,
        C::ScalarExt::from(7),
        -C::ScalarExt::ONE,
    ];
    for budget in [MemoryBudget::new(0), MemoryBudget::DEFAULT] {
        let shared = SharedMemoryBudget::new(budget.bytes());
        assert_eq!(
            msm_complete_cancellable::<C>(&scalars, &bases, budget, &shared, Some(&signal)),
            Err(iroha_pasta::Cancelled)
        );
        let actual =
            msm_complete_cancellable::<C>(&scalars, &bases, budget, &shared, Some(&fresh)).unwrap();
        assert_eq!(actual, msm_complete::<C>(&scalars, &bases, budget));
        assert_eq!(shared.in_use_bytes(), 0);
    }
}
#[test]
fn complete_verifier_kernel_cancellation_and_budget_fallback_remain_total() {
    complete_kernel::<Ep>();
    complete_kernel::<Eq>();
}
