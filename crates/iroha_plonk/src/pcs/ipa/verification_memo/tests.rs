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

// Memo-on/memo-off differential (DEC-41 evidence): for every input and every memo state the
// memoized verifier returns exactly the verdict of the production checklist without memos, so
// owners with and without these memos (phones and validators) never disagree.

/// One full-verification input of the differential corpus.
struct Statement<'a, C: PastaCurve> {
    label: String,
    binding: &'a crate::keys::DescriptorBinding,
    vk: crate::keys::VerifyingKey<C>,
    instances: Vec<Vec<C::ScalarExt>>,
    proof: Vec<u8>,
}

impl<C: PastaCurve> Statement<'_, C>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    fn memo_off(&self, params: &PinnedParams<C>) -> Result<(), VerifyError> {
        crate::verifier::verify_full_unmemoized(
            params,
            self.binding,
            &self.vk,
            &self.instances,
            &self.proof,
            None,
        )
    }

    fn memo_on(
        &self,
        params: &PinnedParams<C>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), VerifyError> {
        verify_full_cancellable(
            params,
            self.binding,
            &self.vk,
            &self.instances,
            &self.proof,
            BUDGET,
            cancellation,
        )
    }

    fn opening(&self, params: &PinnedParams<C>) -> Result<(), VerifyError> {
        verify_full_opening_cancellable(
            params,
            self.binding,
            &self.vk,
            &self.instances,
            &self.proof,
            BUDGET,
            None,
        )
        .map(|_| ())
    }
}

/// Four valid statements (two proofs, another public input, another key) and every class of
/// change to proof bytes, public inputs, verifying key, descriptor binding and transcript
/// representation.
fn corpus<'a, C: PastaCurve>(main: &'a Setup<C>, other: &'a Setup<C>) -> Vec<Statement<'a, C>>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let instances = CIRCUIT.instances::<C::ScalarExt>();
    let proof = main.prove(&CIRCUIT, &instances, 41).expect("proof");
    let second = main.prove(&CIRCUIT, &instances, 42).expect("proof");
    assert_ne!(proof, second);
    let shifted = Arithmetic {
        start: 9,
        ..CIRCUIT
    };
    let shifted_instances = shifted.instances::<C::ScalarExt>();
    let shifted_proof = main.prove(&shifted, &shifted_instances, 43).expect("proof");
    let other_circuit = Arithmetic { rows: 5, ..CIRCUIT };
    let other_instances = other_circuit.instances::<C::ScalarExt>();
    let other_proof = other
        .prove(&other_circuit, &other_instances, 44)
        .expect("proof");
    let main_vk = main.pk.vk();
    let statement = |label: String,
                     binding: &'a crate::keys::DescriptorBinding,
                     vk: &crate::keys::VerifyingKey<C>,
                     instances: &[Vec<C::ScalarExt>],
                     proof: &[u8]| Statement {
        label,
        binding,
        vk: vk.clone(),
        instances: instances.to_vec(),
        proof: proof.to_vec(),
    };
    let main_statement = |label: &str, instances: &[Vec<C::ScalarExt>], proof: &[u8]| {
        statement(label.into(), main.pk.binding(), main_vk, instances, proof)
    };
    let mut all = vec![
        main_statement("valid", &instances, &proof),
        main_statement("valid second proof", &instances, &second),
        main_statement("valid other public input", &shifted_instances, &shifted_proof),
        statement(
            "valid other key".into(),
            other.pk.binding(),
            other.pk.vk(),
            &other_instances,
            &other_proof,
        ),
    ];

    // Proof bytes: single bits across every region (including the suffix), whole words,
    // truncation, extension and proofs of other statements.
    let length = proof.len();
    let mut offsets = vec![
        0,
        1,
        31,
        32,
        33,
        length / 3,
        length / 2,
        length - 65,
        length - 64,
        length - 33,
        length - 32,
        length - 1,
    ];
    offsets.sort_unstable();
    offsets.dedup();
    for offset in offsets {
        let mut changed = proof.clone();
        changed[offset] ^= 1;
        all.push(main_statement(
            &format!("proof bit at {offset}"),
            &instances,
            &changed,
        ));
    }
    for offset in [0, length / 2 / 32 * 32, length - 32] {
        let mut changed = proof.clone();
        changed[offset..offset + 32].fill(255);
        all.push(main_statement(
            &format!("proof word at {offset}"),
            &instances,
            &changed,
        ));
    }
    all.push(main_statement(
        "truncated proof",
        &instances,
        &proof[..length - 1],
    ));
    let mut extended = proof.clone();
    extended.push(0);
    all.push(main_statement("extended proof", &instances, &extended));
    all.push(main_statement("empty proof", &instances, &[]));
    all.push(main_statement(
        "proof of another public input",
        &shifted_instances,
        &proof,
    ));
    all.push(main_statement(
        "another key's proof",
        &other_instances,
        &other_proof,
    ));

    // Public inputs: each value, a negation, and every shape change.
    for row in 0..instances[0].len() {
        let mut changed = instances.clone();
        changed[0][row] += C::ScalarExt::ONE;
        all.push(main_statement(
            &format!("public input {row}"),
            &changed,
            &proof,
        ));
    }
    let mut negated = instances.clone();
    negated[0][0] = -negated[0][0];
    all.push(main_statement("negated public input", &negated, &proof));
    let mut longer = instances.clone();
    longer[0].push(C::ScalarExt::ONE);
    all.push(main_statement("extra public value", &longer, &proof));
    let mut extra = instances.clone();
    extra.push(Vec::new());
    all.push(main_statement("extra public column", &extra, &proof));
    all.push(main_statement("no public columns", &[], &proof));

    // Key identity: another VK, another binding, and the same VK bytes under another
    // transcript representation (the oracle-only constructor).
    all.push(statement(
        "other verifying key".into(),
        main.pk.binding(),
        other.pk.vk(),
        &instances,
        &proof,
    ));
    if other.pk.binding().digest() != main.pk.binding().digest() {
        all.push(statement(
            "other descriptor binding".into(),
            other.pk.binding(),
            main_vk,
            &instances,
            &proof,
        ));
        all.push(statement(
            "other binding and key".into(),
            other.pk.binding(),
            other.pk.vk(),
            &instances,
            &proof,
        ));
    }
    let foreign_repr = main_vk
        .clone()
        .with_transcript_repr_for_oracle(C::ScalarExt::from(7));
    assert_eq!(foreign_repr.to_bytes(), main_vk.to_bytes());
    all.push(statement(
        "same key bytes under another transcript representation".into(),
        main.pk.binding(),
        &foreign_repr,
        &instances,
        &proof,
    ));
    all
}

fn cancelled() -> CancellationToken {
    let token = CancellationToken::new();
    token.cancel();
    token
}

fn full_verification_differential<C: PastaCurve>()
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    for choice in [CHOICES[0], CHOICES[1]] {
        let main = setup::<C, _>(&CIRCUIT, choice);
        let other = setup::<C, _>(&Arithmetic { rows: 5, ..CIRCUIT }, choice);
        let corpus = corpus(&main, &other);
        // Memo off: the unmemoized checklist on its own owner, which it never fills.
        let reference_owner = PinnedParams::<C>::derive(K).expect("params");
        let reference: Vec<_> = corpus
            .iter()
            .map(|statement| statement.memo_off(&reference_owner))
            .collect();
        assert_eq!(reference_owner.verification_memo_sizes(), (0, 0));
        let accepted = reference.iter().filter(|verdict| verdict.is_ok()).count();
        assert_eq!(accepted, 4, "exactly the four valid statements accept");
        let token = cancelled();

        // Memo on, cold: every input once in corpus order. A cancelled call before and after
        // each verdict has no verdict and fills nothing.
        let owner = PinnedParams::<C>::derive(K).expect("params");
        for (statement, expected) in corpus.iter().zip(&reference) {
            assert_eq!(
                statement.memo_on(&owner, Some(&token)),
                Err(VerifyError::Cancelled)
            );
            assert_eq!(
                &statement.memo_on(&owner, None),
                expected,
                "cold: {}",
                statement.label
            );
            assert_eq!(
                statement.memo_on(&owner, Some(&token)),
                Err(VerifyError::Cancelled)
            );
        }
        assert_eq!(owner.verification_memo_sizes().1, accepted);

        // Memo on, warm: every acceptance remembered; every input again in reverse order, on the
        // owner and on a clone sharing its memo. Only accepted exact inputs are answered from the
        // memo, and the unmemoized checklist on the warm owner still agrees.
        let clone = owner.clone();
        for params in [&owner, &clone] {
            for (statement, expected) in corpus.iter().zip(&reference).rev() {
                let start = current();
                assert_eq!(
                    &statement.memo_on(params, None),
                    expected,
                    "warm: {}",
                    statement.label
                );
                assert_eq!(
                    current().since(start).reused_verifications,
                    u64::from(expected.is_ok()),
                    "warm reuse: {}",
                    statement.label
                );
                assert_eq!(&statement.memo_off(params), expected);
            }
        }
        assert_eq!(owner.verification_memo_sizes().1, accepted);

        // The single-read opening verification decides exactly the same, cold and warm.
        if choice.2 == crate::cs::ProofSuffixV1::FoldedGenerator {
            let fresh = PinnedParams::<C>::derive(K).expect("params");
            for params in [&fresh, &fresh, &owner] {
                for (statement, expected) in corpus.iter().zip(&reference) {
                    assert_eq!(
                        &statement.opening(params),
                        expected,
                        "opening: {}",
                        statement.label
                    );
                }
            }
            assert_eq!(fresh.verification_memo_sizes().1, accepted);
        }

        // A restart (an independent owner) and a poisoned owner agree without reusing anything;
        // the poisoned owner retains nothing.
        let restarted = PinnedParams::<C>::derive(K).expect("params");
        let poisoned = PinnedParams::<C>::derive(K).expect("params");
        poisoned.poison_verification_memo();
        for params in [&restarted, &poisoned, &poisoned] {
            let start = current();
            for (statement, expected) in corpus.iter().zip(&reference) {
                assert_eq!(
                    &statement.memo_on(params, None),
                    expected,
                    "restart/poison: {}",
                    statement.label
                );
            }
            if std::ptr::eq(params, &poisoned) {
                assert_eq!(current().since(start).reused_verifications, 0);
            }
        }
        assert_eq!(poisoned.verification_memo_sizes(), (0, 0));
        assert!(!restarted.shares_verification_memo(&owner));
    }
}

#[test]
fn memoized_full_verification_matches_the_unmemoized_checklist_for_every_input_and_state() {
    full_verification_differential::<Eq>();
    full_verification_differential::<Ep>();
}

fn generator_differential<C: PastaCurve>() {
    let owner = PinnedParams::<C>::derive(K).expect("params");
    let honest: Vec<C::ScalarExt> = (3..3 + u64::from(K)).map(C::ScalarExt::from).collect();
    // Challenge vectors: the honest one, each challenge changed, a prefix and a suffix.
    let mut vectors = vec![honest.clone()];
    for round in 0..honest.len() {
        let mut changed = honest.clone();
        changed[round] += C::ScalarExt::ONE;
        vectors.push(changed);
    }
    vectors.push(honest[1..].to_vec());
    vectors.push(honest[..honest.len() - 1].to_vec());
    // Memo off: each true point directly from the complete kernel.
    let points: Vec<C::AffineExt> = vectors
        .iter()
        .map(|challenges| folded_generator_of(&owner, challenges, BUDGET).to_affine())
        .collect();
    let mut claims = Vec::new();
    for (challenges, point) in vectors.iter().zip(&points) {
        for g in [*point, -*point, owner.params().g()[0], points[0]] {
            claims.push((challenges.clone(), g, g == *point));
        }
    }
    let honest_point = points[0];
    assert!(claims.iter().any(|claim| !claim.2));
    let token = cancelled();
    let check = |params: &PinnedParams<C>, challenges: &[C::ScalarExt], g, accepts: bool| {
        let expected = if accepts {
            Ok(())
        } else {
            Err(IpaError::OpeningFailed)
        };
        let k = u32::try_from(challenges.len()).expect("k");
        assert_eq!(
            params.decide_folded_generator_cancellable(challenges, &g, BUDGET, None),
            expected
        );
        let claim = GeneratorClaim::new(k, g, challenges.to_vec()).expect("claim");
        assert_eq!(claim.decide(params, BUDGET), expected);
        assert_eq!(
            claim.decide_cancellable(params, BUDGET, Some(&token)),
            Err(IpaError::Cancelled)
        );
        let accumulator = crate::pcs::ipa::accumulator::PendingAccumulator::new(
            C::ScalarExt::ONE,
            k,
            g,
            challenges.to_vec(),
        );
        assert_eq!(accumulator.decide(params, BUDGET).is_ok(), accepts);
        // The value path returns the exact point whatever the memo holds.
        let index = vectors
            .iter()
            .position(|vector| vector.as_slice() == challenges)
            .expect("vector");
        assert_eq!(
            params.folded_generator_cancellable(challenges, BUDGET, None),
            Ok(points[index])
        );
    };
    // Cold in claim order, warm in reverse order, then on a clone sharing the memo.
    let clone = owner.clone();
    for (round, params) in [&owner, &owner, &clone].into_iter().enumerate() {
        let ordered: Vec<_> = if round == 1 {
            claims.iter().rev().collect()
        } else {
            claims.iter().collect()
        };
        for (challenges, g, accepts) in ordered {
            check(params, challenges, *g, *accepts);
        }
    }
    // Only accepted challenge vectors are remembered: one per distinct vector.
    assert_eq!(owner.verification_memo_sizes(), (vectors.len(), 0));
    // A restarted owner decides identically from nothing.
    let restarted = PinnedParams::<C>::derive(K).expect("params");
    for (challenges, g, accepts) in claims.iter().rev() {
        check(&restarted, challenges, *g, *accepts);
    }
    assert_eq!(
        restarted.decide_folded_generator_cancellable(&honest, &honest_point, BUDGET, None),
        Ok(())
    );
}

#[test]
fn memoized_decides_match_the_direct_kernel_for_every_claim_and_state() {
    generator_differential::<Ep>();
    generator_differential::<Eq>();
}

#[test]
fn eviction_at_the_proof_bound_never_changes_a_verdict() {
    // PROOF_ENTRIES + 1 distinct accepted statements (one public input each) on one owner.
    let main = setup::<Eq, _>(&CIRCUIT, CHOICES[0]);
    let owner = &main.params;
    let statements: Vec<_> = (0..=PROOF_ENTRIES)
        .map(|index| {
            let circuit = Arithmetic {
                start: 5 + index as u64,
                ..CIRCUIT
            };
            let instances = circuit.instances::<iroha_pasta::Fp>();
            let proof = main.prove(&circuit, &instances, 1).expect("proof");
            (instances, proof)
        })
        .collect();
    for (instances, proof) in &statements {
        assert_eq!(verify(owner, &main, instances, proof, None), Ok(()));
    }
    assert_eq!(owner.verification_memo_sizes().1, PROOF_ENTRIES);
    // The least recently used acceptance was forgotten: it is verified in full again and
    // accepted, and a changed copy of it still rejects whatever the memo holds.
    let (instances, proof) = &statements[0];
    let start = current();
    assert_eq!(verify(owner, &main, instances, proof, None), Ok(()));
    let work = current().since(start);
    assert_eq!((work.reused_verifications, work.generator_msms), (0, 1));
    let mut changed = proof.clone();
    changed[0] ^= 1;
    assert_eq!(
        verify(owner, &main, instances, &changed, None),
        crate::verifier::verify_full_unmemoized(
            owner,
            main.pk.binding(),
            main.pk.vk(),
            instances,
            &changed,
            None
        )
    );
    // The most recent acceptances are still answered from the memo.
    let (instances, proof) = statements.last().expect("statement");
    let start = current();
    assert_eq!(verify(owner, &main, instances, proof, None), Ok(()));
    assert_eq!(current().since(start).reused_verifications, 1);
    assert_eq!(owner.verification_memo_sizes().1, PROOF_ENTRIES);
}
