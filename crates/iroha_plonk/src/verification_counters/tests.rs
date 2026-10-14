//! Verifier work counts: one entry per started verification or decide, one
//! `<s(u), g>` MSM behind each, counted on the calling thread only.

use iroha_pasta::{CancellationToken, Ep, Eq, Fq, PastaCurve, poseidon::PoseidonField};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;

use super::*;
use crate::{
    PinnedParams,
    pcs::ipa::accumulator::{batch_decide, honest_accumulator},
    test_circuits::{Arithmetic, BUDGET, CHOICES, K, setup},
    verifier::{
        BatchItem, accumulate_generator, accumulate_succinct, batch_verify, verify_full_cancellable,
    },
};

const CIRCUIT: Arithmetic = Arithmetic {
    start: 5,
    rows: 6,
    tamper: None,
};

const N: u64 = 1 << K;

fn current() -> VerificationCounts {
    VerificationCounts::current_thread()
}

fn counts(
    verify_full: u64,
    decides: u64,
    batches: u64,
    generator_msms: u64,
    generator_msm_bases: u64,
) -> VerificationCounts {
    VerificationCounts {
        verify_full,
        decides,
        batches,
        generator_msms,
        generator_msm_bases,
    }
}

fn verifications_count_calls_and_generator_msms<C: PastaCurve>()
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    // Without a suffix: one verify_full, one 2^k folded-generator MSM.
    let plain = setup::<C, _>(&CIRCUIT, CHOICES[0]);
    let instances = CIRCUIT.instances::<C::ScalarExt>();
    let proof = plain.prove(&CIRCUIT, &instances, 1).expect("proof");
    let start = current();
    assert_eq!(plain.verify(&instances, &proof), Ok(()));
    assert_eq!(current().since(start), counts(1, 0, 0, 1, N));

    // A rejected statement is still one started verification.
    let mut wrong = instances.clone();
    wrong[0][0] += C::ScalarExt::from(1_u64);
    assert!(plain.verify(&wrong, &proof).is_err());
    assert_eq!(current().since(start).verify_full, 2);

    // A cancelled verification is counted and computes no MSM.
    let before = current();
    let token = CancellationToken::new();
    token.cancel();
    assert!(
        verify_full_cancellable(
            &plain.params,
            plain.pk.binding(),
            plain.pk.vk(),
            &instances,
            &proof,
            BUDGET,
            Some(&token),
        )
        .is_err()
    );
    assert_eq!(current().since(before), counts(1, 0, 0, 0, 0));

    // With a FoldedGenerator suffix, verify_full still computes G'_0 once;
    // the succinct paths compute no MSM and each decide computes one.
    let folded = setup::<C, _>(&CIRCUIT, CHOICES[1]);
    let proof = folded.prove(&CIRCUIT, &instances, 2).expect("proof");
    let start = current();
    assert_eq!(folded.verify(&instances, &proof), Ok(()));
    assert_eq!(current().since(start), counts(1, 0, 0, 1, N));
    let pending = accumulate_succinct(
        &folded.params,
        folded.pk.binding(),
        folded.pk.vk(),
        &instances,
        &proof,
        BUDGET,
    )
    .expect("pending");
    let claim = accumulate_generator(
        &folded.params,
        folded.pk.binding(),
        folded.pk.vk(),
        &instances,
        &proof,
        BUDGET,
    )
    .expect("claim");
    assert_eq!(current().since(start), counts(1, 0, 0, 1, N));
    assert_eq!(pending.decide(&folded.params, BUDGET), Ok(()));
    assert_eq!(current().since(start), counts(1, 1, 0, 2, 2 * N));
    assert_eq!(claim.decide(&folded.params, BUDGET), Ok(()));
    assert_eq!(current().since(start), counts(1, 2, 0, 3, 3 * N));

    // A batch of two proofs is one batch and one merged generator MSM.
    let other = Arithmetic {
        start: 7,
        ..CIRCUIT
    };
    let other_instances = other.instances::<C::ScalarExt>();
    let other_proof = folded.prove(&other, &other_instances, 3).expect("proof");
    let before = current();
    let item = |instances, proof| BatchItem {
        params: &folded.params,
        binding: folded.pk.binding(),
        vk: folded.pk.vk(),
        instances,
        proof,
    };
    assert_eq!(
        batch_verify(
            &[
                item(&instances, &proof),
                item(&other_instances, &other_proof)
            ],
            BUDGET
        ),
        Ok(())
    );
    assert_eq!(current().since(before), counts(0, 0, 1, 1, N));
}

#[test]
fn verifications_count_calls_and_generator_msms_on_both_curves() {
    verifications_count_calls_and_generator_msms::<Eq>();
    verifications_count_calls_and_generator_msms::<Ep>();
}

#[test]
fn batch_decide_is_one_batch_and_one_merged_msm() {
    let params = PinnedParams::<Ep>::derive(5).expect("params");
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let batch: Vec<_> = [2_usize, 5, 3]
        .iter()
        .map(|k| {
            let challenges = (0..*k)
                .map(|_| <Fq as ff::Field>::random(&mut rng))
                .collect();
            honest_accumulator(&params, challenges, Fq::from(*k as u64))
        })
        .collect();
    let start = current();
    assert_eq!(batch_decide(batch.clone(), &params, BUDGET), Ok(()));
    assert_eq!(current().since(start), counts(0, 0, 1, 1, 32));
    let single = batch.into_iter().next().expect("item");
    assert_eq!(single.decide(&params, BUDGET), Ok(()));
    assert_eq!(current().since(start), counts(0, 1, 1, 2, 36));
}

#[test]
fn counts_stay_on_the_recording_thread() {
    let start = current();
    record_decide();
    record_generator_msm(8);
    let elsewhere = std::thread::spawn(|| {
        let start = current();
        record_verify_full();
        record_batch();
        current().since(start)
    })
    .join()
    .expect("thread");
    assert_eq!(elsewhere, counts(1, 0, 1, 0, 0));
    assert_eq!(current().since(start), counts(0, 1, 0, 1, 8));
}

#[test]
fn since_saturates_at_zero() {
    let later = counts(3, 2, 1, 4, 64);
    assert_eq!(later.since(counts(1, 2, 0, 1, 16)), counts(2, 0, 1, 3, 48));
    assert_eq!(
        counts(0, 0, 0, 0, 0).since(later),
        VerificationCounts::default()
    );
}
