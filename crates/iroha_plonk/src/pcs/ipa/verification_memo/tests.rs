//! Success-only, exact-input, owner-bound and bounded reuse of verification work.

use iroha_pasta::{Ep, Eq, poseidon::PoseidonField};

use super::*;
use crate::{
    VerificationCounts,
    pcs::ipa::{GeneratorClaim, accumulator::honest_accumulator, verifier::folded_generator_of},
    test_circuits::{Arithmetic, BUDGET, CHOICES, K, Setup, setup},
    verifier::{
        VerifyError, accumulate_generator, verify_full_cancellable, verify_full_opening_cancellable,
    },
};

const CIRCUIT: Arithmetic = Arithmetic {
    start: 5,
    rows: 6,
    tamper: None,
};

fn current() -> VerificationCounts {
    VerificationCounts::current_thread()
}

fn verify<C: PastaCurve>(
    params: &PinnedParams<C>,
    setup: &Setup<C>,
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    cancellation: Option<&CancellationToken>,
) -> Result<(), VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    verify_full_cancellable(
        params,
        setup.pk.binding(),
        setup.pk.vk(),
        instances,
        proof,
        BUDGET,
        cancellation,
    )
}

fn full_verification_reuse<C: PastaCurve>()
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    for choice in [CHOICES[0], CHOICES[1]] {
        let folded = setup::<C, _>(&CIRCUIT, choice);
        let params = &folded.params;
        let instances = CIRCUIT.instances::<C::ScalarExt>();
        let proof = folded.prove(&CIRCUIT, &instances, 1).expect("proof");

        // Rejections and cancellations are never remembered.
        let mut wrong = instances.clone();
        wrong[0][0] += C::ScalarExt::ONE;
        assert!(verify(params, &folded, &wrong, &proof, None).is_err());
        let token = CancellationToken::new();
        token.cancel();
        assert_eq!(
            verify(params, &folded, &instances, &proof, Some(&token)),
            Err(VerifyError::Cancelled)
        );
        assert_eq!(params.verification_memo_sizes(), (0, 0));

        // The first acceptance computes; byte-identical inputs on this owner and its
        // clones reuse it.
        let start = current();
        assert_eq!(verify(params, &folded, &instances, &proof, None), Ok(()));
        let first = current().since(start);
        assert_eq!(
            (
                first.verify_full,
                first.generator_msms,
                first.reused_verifications
            ),
            (1, 1, 0)
        );
        assert_eq!(params.verification_memo_sizes(), (1, 1));
        let clone = params.clone();
        assert!(clone.shares_verification_memo(params));
        let start = current();
        assert_eq!(verify(&clone, &folded, &instances, &proof, None), Ok(()));
        assert_eq!(
            current().since(start),
            VerificationCounts {
                verify_full: 1,
                reused_verifications: 1,
                ..VerificationCounts::default()
            }
        );
        // A cancelled call on a remembered input still has no verdict.
        assert_eq!(
            verify(params, &folded, &instances, &proof, Some(&token)),
            Err(VerifyError::Cancelled)
        );

        // Any changed byte of the statement or proof is verified in full and rejects.
        let start = current();
        assert!(verify(params, &folded, &wrong, &proof, None).is_err());
        for index in [0, proof.len() / 2, proof.len() - 1] {
            let mut changed = proof.clone();
            changed[index] ^= 1;
            assert!(verify(params, &folded, &instances, &changed, None).is_err());
        }
        let mut longer = proof.clone();
        longer.push(0);
        assert!(matches!(
            verify(params, &folded, &instances, &longer, None),
            Err(VerifyError::ProofLength { .. })
        ));
        let mut extra = instances.clone();
        extra.push(Vec::new());
        assert!(verify(params, &folded, &extra, &proof, None).is_err());
        assert_eq!(current().since(start).reused_verifications, 0);

        // Another key or descriptor never reuses this acceptance.
        let other = setup::<C, _>(&Arithmetic { rows: 5, ..CIRCUIT }, choice);
        assert_ne!(other.pk.vk().to_bytes(), folded.pk.vk().to_bytes());
        let mut pairs = vec![
            (folded.pk.binding(), other.pk.vk()),
            (other.pk.binding(), other.pk.vk()),
        ];
        if other.pk.binding().digest() != folded.pk.binding().digest() {
            pairs.push((other.pk.binding(), folded.pk.vk()));
        }
        for (binding, vk) in pairs {
            assert!(
                verify_full_cancellable(params, binding, vk, &instances, &proof, BUDGET, None)
                    .is_err()
            );
        }
        assert_eq!(current().since(start).reused_verifications, 0);

        // An independently derived owner of the same curve and k shares nothing.
        let independent = PinnedParams::<C>::derive(K).expect("params");
        assert!(!independent.shares_verification_memo(params));
        let start = current();
        assert_eq!(
            verify(&independent, &folded, &instances, &proof, None),
            Ok(())
        );
        let work = current().since(start);
        assert_eq!((work.generator_msms, work.reused_verifications), (1, 0));

        // A poisoned memo is ignored: full verification runs and nothing is retained.
        params.poison_verification_memo();
        let start = current();
        assert_eq!(verify(params, &folded, &instances, &proof, None), Ok(()));
        let work = current().since(start);
        assert_eq!((work.generator_msms, work.reused_verifications), (1, 0));
        assert_eq!(params.verification_memo_sizes(), (0, 0));
    }
}

#[test]
fn full_verifications_reuse_only_accepted_exact_inputs_on_the_same_owner() {
    full_verification_reuse::<Eq>();
    full_verification_reuse::<Ep>();
}

fn verified_opening<C: PastaCurve>()
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let plain = setup::<C, _>(&CIRCUIT, CHOICES[0]);
    let instances = CIRCUIT.instances::<C::ScalarExt>();
    let proof = plain.prove(&CIRCUIT, &instances, 2).expect("proof");
    assert_eq!(
        verify_full_opening_cancellable(
            &plain.params,
            plain.pk.binding(),
            plain.pk.vk(),
            &instances,
            &proof,
            BUDGET,
            None,
        ),
        Err(VerifyError::SuffixRequired)
    );

    let folded = setup::<C, _>(&CIRCUIT, CHOICES[1]);
    let params = &folded.params;
    let proof = folded.prove(&CIRCUIT, &instances, 3).expect("proof");
    let opening = |instances: &[Vec<C::ScalarExt>], proof: &[u8]| {
        verify_full_opening_cancellable(
            params,
            folded.pk.binding(),
            folded.pk.vk(),
            instances,
            proof,
            BUDGET,
            None,
        )
    };
    let mut wrong = instances.clone();
    wrong[0][1] += C::ScalarExt::ONE;
    assert!(opening(&wrong, &proof).is_err());
    assert_eq!(params.verification_memo_sizes(), (0, 0));

    // One read and one generator MSM; the opening is the proof's own decided claim.
    let start = current();
    let verified = opening(&instances, &proof).expect("verified opening");
    let work = current().since(start);
    assert_eq!((work.verify_full, work.generator_msms), (1, 1));
    let claim = accumulate_generator(
        params,
        folded.pk.binding(),
        folded.pk.vk(),
        &instances,
        &proof,
        BUDGET,
    )
    .expect("claim");
    assert!(verified.matches(&claim));
    assert_eq!(verified.g(), claim.g());
    assert_eq!(verified.challenges(), claim.challenges());
    assert_eq!(verified.k(), K);

    // Deciding the same opening, or fully verifying the same bytes, computes nothing more.
    let start = current();
    assert_eq!(claim.decide(params, BUDGET), Ok(()));
    assert_eq!(verify(params, &folded, &instances, &proof, None), Ok(()));
    assert_eq!(
        current().since(start),
        VerificationCounts {
            verify_full: 1,
            decides: 1,
            reused_verifications: 1,
            reused_generators: 1,
            ..VerificationCounts::default()
        }
    );

    // The same challenges with another G never decide, and a mismatching claim never matches.
    let forged =
        GeneratorClaim::new(K, params.params().g()[1], claim.challenges().to_vec()).expect("claim");
    assert!(!verified.matches(&forged));
    assert_eq!(forged.decide(params, BUDGET), Err(IpaError::OpeningFailed));
    let accumulator = honest_accumulator(params, claim.challenges().to_vec(), C::ScalarExt::ONE);
    assert_eq!(accumulator.clone().decide(params, BUDGET), Ok(()));
    let wrong_g = crate::pcs::ipa::accumulator::PendingAccumulator::new(
        C::ScalarExt::ONE,
        K,
        params.params().g()[1],
        claim.challenges().to_vec(),
    );
    assert!(wrong_g.decide(params, BUDGET).is_err());
}

#[test]
fn verified_openings_are_read_once_and_reuse_only_their_exact_generator() {
    verified_opening::<Eq>();
    verified_opening::<Ep>();
}

fn generator_memo<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(4).expect("params");
    let u: Vec<C::ScalarExt> = (3..7_u64).map(C::ScalarExt::from).collect();
    let expected = folded_generator_of(&params, &u, BUDGET).to_affine();
    // Values that only compute, and decisions that reject or cancel, retain nothing.
    assert_eq!(
        params.folded_generator_cancellable(&u, BUDGET, None),
        Ok(expected)
    );
    assert_eq!(
        params.decide_folded_generator_cancellable(&u, &params.params().g()[0], BUDGET, None),
        Err(IpaError::OpeningFailed)
    );
    let token = CancellationToken::new();
    token.cancel();
    assert_eq!(
        params.decide_folded_generator_cancellable(&u, &expected, BUDGET, Some(&token)),
        Err(IpaError::Cancelled)
    );
    assert_eq!(
        params.decide_folded_generator_cancellable(&u, &expected, BUDGET, None),
        Ok(())
    );
    assert_eq!(params.verification_memo_sizes(), (1, 0));
    // A remembered value still answers every comparison exactly.
    let start = current();
    assert_eq!(
        params.decide_folded_generator_cancellable(&u, &params.params().g()[0], BUDGET, None),
        Err(IpaError::OpeningFailed)
    );
    assert_eq!(
        params.decide_folded_generator_cancellable(&u, &expected, BUDGET, None),
        Ok(())
    );
    assert_eq!(
        params.folded_generator_cancellable(&u, BUDGET, None),
        Ok(expected)
    );
    assert_eq!(
        params.decide_folded_generator_cancellable(&u, &expected, BUDGET, Some(&token)),
        Err(IpaError::Cancelled)
    );
    let work = current().since(start);
    assert_eq!((work.generator_msms, work.reused_generators), (0, 3));
    // A prefix or extension of the challenges is another key.
    let start = current();
    let shorter = folded_generator_of(&params, &u[1..], BUDGET).to_affine();
    assert_eq!(
        params.decide_folded_generator_cancellable(&u[1..], &shorter, BUDGET, None),
        Ok(())
    );
    assert_eq!(
        params.decide_folded_generator_cancellable(&u[1..], &expected, BUDGET, None),
        Err(IpaError::OpeningFailed)
    );
    assert_eq!(current().since(start).reused_generators, 1);
    assert_eq!(
        params.folded_generator_cancellable(&[C::ScalarExt::ONE; 5], BUDGET, None),
        Err(IpaError::ParamsTooSmall {
            needed: 5,
            available: 4
        })
    );
}

#[test]
fn folded_generators_are_retained_only_after_accepted_decisions() {
    generator_memo::<Ep>();
    generator_memo::<Eq>();
}

#[test]
fn memos_evict_the_least_recently_used_entry_at_their_bound() {
    let mut lru = Lru::<[u8; 32], u8>::new(3);
    for key in 0..3_u8 {
        lru.insert([key; 32], key);
    }
    assert_eq!(lru.get(&[0; 32]), Some(0));
    lru.insert([3; 32], 3);
    assert_eq!(lru.len(), 3);
    assert_eq!(lru.get(&[1; 32]), None, "least recently used is evicted");
    assert_eq!(lru.get(&[0; 32]), Some(0));
    lru.insert([0; 32], 9);
    assert_eq!(
        lru.get(&[0; 32]),
        Some(0),
        "an existing exact entry is kept"
    );
    for key in 4..20_u8 {
        lru.insert([key; 32], key);
        assert!(lru.len() <= 3);
        assert_eq!(lru.entries.len(), lru.recency.len());
    }
    assert_eq!(
        generator_key(&[iroha_pasta::Fq::ONE; 2]).len(),
        1 + 2 * 32,
        "k and every canonical challenge"
    );
    assert_eq!(GENERATOR_ENTRIES, 256);
    assert_eq!(PROOF_ENTRIES, 256);
}

/// Real k6 stand-ins for the wallet's proofs: an Omega-like Pallas proof with
/// its carried Pallas and Vesta claims, and Vesta step proofs (sigma).
struct WalletStandIns {
    omega: Setup<Ep>,
    omega_proof: Vec<u8>,
    acc_p: crate::pcs::ipa::accumulator::PendingAccumulator<Ep>,
    vesta: PinnedParams<Eq>,
    acc_v: crate::pcs::ipa::accumulator::PendingAccumulator<Eq>,
    sigma: Setup<Eq>,
    released: Vec<u8>,
    next: Vec<u8>,
    payer: Vec<u8>,
}

impl WalletStandIns {
    fn new() -> Self {
        let omega = setup::<Ep, _>(&CIRCUIT, CHOICES[1]);
        let omega_proof = omega
            .prove(&CIRCUIT, &CIRCUIT.instances(), 11)
            .expect("proof");
        let sigma = setup::<Eq, _>(&CIRCUIT, CHOICES[1]);
        let prove = |seed| {
            sigma
                .prove(&CIRCUIT, &CIRCUIT.instances(), seed)
                .expect("proof")
        };
        let (released, next, payer) = (prove(12), prove(13), prove(14));
        let vesta = PinnedParams::<Eq>::derive(K).expect("params");
        let acc_p = honest_accumulator(
            &omega.params,
            (21..27_u64).map(iroha_pasta::Fq::from).collect(),
            iroha_pasta::Fq::ONE,
        );
        let acc_v = honest_accumulator(
            &vesta,
            (31..37_u64).map(iroha_pasta::Fp::from).collect(),
            iroha_pasta::Fp::ONE,
        );
        Self {
            omega,
            omega_proof,
            acc_p,
            vesta,
            acc_v,
            sigma,
            released,
            next,
            payer,
        }
    }

    /// `verify_lineage`: full verification of Omega, then the Pallas and Vesta decides.
    fn lineage(&self) {
        let instances = CIRCUIT.instances();
        assert_eq!(
            verify(
                &self.omega.params,
                &self.omega,
                &instances,
                &self.omega_proof,
                None
            ),
            Ok(())
        );
        self.carried();
    }

    fn carried(&self) {
        assert_eq!(
            self.acc_p.clone().decide(&self.omega.params, BUDGET),
            Ok(())
        );
        assert_eq!(self.acc_v.clone().decide(&self.vesta, BUDGET), Ok(()));
    }

    fn sigma(&self, proof: &[u8]) {
        let instances = CIRCUIT.instances();
        assert_eq!(
            verify(&self.sigma.params, &self.sigma, &instances, proof, None),
            Ok(())
        );
    }

    /// Fold completion after this change: Omega prepare's carried decides, `prove`'s
    /// single-read self-verification, and the coordinator's one `verify_lineage`.
    fn completion(&self) {
        self.carried();
        let opening = verify_full_opening_cancellable(
            &self.omega.params,
            self.omega.pk.binding(),
            self.omega.pk.vk(),
            &CIRCUIT.instances(),
            &self.omega_proof,
            BUDGET,
            None,
        )
        .expect("opening");
        assert_eq!(opening.k(), K);
        self.carried();
        self.lineage();
    }

    /// One Send/Unload/Retiring execute: six `verify_lineage(Omega(pred))`, four
    /// verifications of the released sigma and two of the new sigma.
    fn send(&self) {
        for _ in 0..6 {
            self.lineage();
        }
        for _ in 0..4 {
            self.sigma(&self.released);
        }
        for _ in 0..2 {
            self.sigma(&self.next);
        }
    }

    /// One Receive execute: four payer-Omega lineages, four released and four payer sigma
    /// verifications, and two of the new sigma.
    fn receive(&self) {
        for _ in 0..4 {
            self.lineage();
            self.sigma(&self.released);
            self.sigma(&self.payer);
        }
        for _ in 0..2 {
            self.sigma(&self.next);
        }
    }
}

fn work(operation: impl FnOnce()) -> VerificationCounts {
    let start = current();
    operation();
    current().since(start)
}

fn line(counts: VerificationCounts) -> String {
    format!(
        "verify_full={} reused_verifications={} computed_verify_full={} decides={} \
         generator_msms={} reused_generators={}",
        counts.verify_full,
        counts.reused_verifications,
        counts.verify_full - counts.reused_verifications,
        counts.decides,
        counts.generator_msms,
        counts.reused_generators
    )
}

#[test]
fn wallet_call_sequences_compute_each_proof_and_claim_once_per_owner() {
    // Fold completion in a fresh process: the carried claims are decided once, Omega is
    // fully computed once by `prove`, and the coordinator's verification reuses both.
    let wallet = WalletStandIns::new();
    let completion = work(|| wallet.completion());
    assert_eq!(
        (
            completion.verify_full,
            completion.reused_verifications,
            completion.decides,
            completion.generator_msms
        ),
        (2, 1, 6, 3)
    );
    // The released sigma was verified when its operation committed.
    wallet.sigma(&wallet.released);
    let send = work(|| wallet.send());
    assert_eq!(
        (
            send.verify_full,
            send.reused_verifications,
            send.decides,
            send.generator_msms
        ),
        (12, 11, 12, 1),
        "only the new sigma is computed"
    );

    // After a restart (fresh parameter owners), opening the owner verifies the recorded
    // Omega once; the first Send computes the released and the new sigma once each.
    let restarted = WalletStandIns::new();
    let reopen = work(|| restarted.lineage());
    assert_eq!((reopen.verify_full, reopen.generator_msms), (1, 3));
    let send_after_restart = work(|| restarted.send());
    assert_eq!(
        (
            send_after_restart.verify_full,
            send_after_restart.reused_verifications,
            send_after_restart.generator_msms
        ),
        (12, 10, 2)
    );

    // A Receive verifies the incoming payer Omega and sigma in full once each.
    let receiver = WalletStandIns::new();
    receiver.sigma(&receiver.released);
    let receive = work(|| receiver.receive());
    assert_eq!(
        (
            receive.verify_full,
            receive.reused_verifications,
            receive.decides,
            receive.generator_msms
        ),
        (14, 11, 8, 5)
    );
    eprintln!(
        "VERIFY_AFTER_REPLAY fold_completion: {}\nVERIFY_AFTER_REPLAY send_warm: {}\n\
         VERIFY_AFTER_REPLAY owner_open: {}\nVERIFY_AFTER_REPLAY send_after_restart: {}\n\
         VERIFY_AFTER_REPLAY receive_warm: {}",
        line(completion),
        line(send),
        line(reopen),
        line(send_after_restart),
        line(receive)
    );
}
