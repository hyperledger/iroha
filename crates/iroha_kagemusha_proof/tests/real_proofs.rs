//! The relation checks as real PIPA-v1 proofs (KAGEMUSHA step format on
//! Vesta, at the shape within the 3,520-byte sigma budget):
//!
//! - an honest witness is proved and verified, also through the
//!   verifying-key allowlist by its `(tag, mask)` selector; a wrong public
//!   input is rejected; each fresh attempt changes the proof bytes and
//!   retained originals remain verifiable;
//! - a mutated witness (overdraft, a debit that ignores the lineage
//!   `burned_total`, newer policy epoch, early accepted time, a Send at the
//!   lease expiry, `u128` overflow) is refused by
//!   [`SigmaProver::prove`] with its violation, and the engine itself
//!   refuses it (a limb lookup input is missing from its table);
//! - a forger who zeroes the failing range checks so every lookup passes
//!   gets a proof from the engine, and the verifier rejects it (the zeroed
//!   check breaks the copy from the checked value);
//! - the honest proof of the same seed does not verify for the mutated
//!   statement.
//!
//! Every byte of a proof, flipped, is rejected; a proof on Pallas verifies
//! too; a forged identity proves only its own head; a proof under one
//! selector does not verify under another; the quota rule's violations
//! have no accepted proof; the full mask proves and
//! verifies at its single-lane `k = 14` shape; keys and verification of retained
//! proof bytes do not depend on the Rayon pool size. Genuine-proof tests are
//! explicitly ignored for an optimized invocation; the source-inventory pin is ordinary.

mod common;

use core::fmt::Write as _;

use common::{
    CHECK_SEED, RELATION_CASES, RELATION_CHECK_CASES, SEND_EVERY, SEND_LEASE, SEND_QUOTAS,
    budget_shape, case_label, folded, forged_witness, fresh_randomness, pinned_shape,
    relation_shapes, vesta_params, vesta_prover,
};
use ff::Field;
use iroha_data_model::kagemusha::kagemusha_wallet_v1::KAGEMUSHA_WALLET_SIGMA_PROOF_CAP_V1;
use iroha_kagemusha_proof::{
    ConsumerError, Mutation, SigmaAllowlist, SigmaError, SigmaProver, SigmaRelation, StepRelation,
    VerifyingKeyEntry, Violation, check_send, lineage_view_of, sample_witness,
    wallet_monetary_shape,
};
use iroha_pasta::{Ep, Eq, Fp, Fq};
use iroha_plonk::{ProverConfig, ProverError, create_proof, prove_circuit};
use rayon::prelude::*;

#[test]
#[ignore = "20 cases with real proofs; run in release"]
fn relation_checks_as_real_proofs() {
    let mut cases = 0;
    for relation in relation_shapes() {
        let shape = budget_shape(relation);
        if relation == folded(relation.relation) {
            assert_eq!(shape, wallet_monetary_shape(relation.relation).unwrap());
        }
        let prover = vesta_prover(shape);
        let verifier = prover.verifier();
        let honest = sample_witness::<Fp>(CHECK_SEED, relation.relation, Mutation::None);
        let honest_proof = prover
            .prove(&honest, fresh_randomness())
            .expect("honest proof");
        for (case, mutation, expected) in RELATION_CASES {
            if case != relation.relation {
                continue;
            }
            let label = case_label(relation, mutation);
            let witness = sample_witness::<Fp>(CHECK_SEED, case, mutation);
            if expected {
                let proof = prover.prove(&witness, fresh_randomness()).expect("proof");
                assert_eq!(
                    proof.bytes.len(),
                    shape.proof_length::<Eq>().expect("length")
                );
                assert!(proof.bytes.len() <= KAGEMUSHA_WALLET_SIGMA_PROOF_CAP_V1);
                assert_eq!(
                    verifier.verify(&proof.public, &proof.bytes),
                    Ok(()),
                    "{label}"
                );
                let mut wrong = proof.public;
                wrong.statement += Fp::ONE;
                assert!(verifier.verify(&wrong, &proof.bytes).is_err(), "{label}");
                let fresh = prover
                    .prove(&witness, fresh_randomness())
                    .expect("fresh proof");
                verifier
                    .verify(&fresh.public, &fresh.bytes)
                    .expect("fresh proof verifies");
                assert_ne!(fresh.bytes, proof.bytes, "{label}: fresh entropy");
                let retained = proof.bytes.clone();
                verifier
                    .verify(&proof.public, &retained)
                    .expect("retained original verifies");
                assert_eq!(retained, proof.bytes, "{label}: immutable original");
                assert_ne!(honest_proof.bytes, proof.bytes, "{label}: fresh blinds");
                println!(
                    "M12_REAL case={} k={} lanes={} mutation={mutation:?} accepted=true bytes={}",
                    relation.label(),
                    shape.k,
                    shape.params.lanes(),
                    proof.bytes.len()
                );
            } else {
                // The library refuses the witness with its violation.
                match prover.prove(&witness, fresh_randomness()) {
                    Err(SigmaError::RelationViolated(violations)) => {
                        assert!(!violations.is_empty(), "{label}");
                    }
                    other => panic!("{label}: {other:?}"),
                }
                // The engine refuses it too: a limb is missing from its table.
                let circuit = prover.circuit(&witness).expect("circuit");
                let claimed = witness.evaluate(relation.relation).public();
                let engine = prove_circuit(
                    prover.params(),
                    prover.proving_key(),
                    &circuit,
                    &[claimed.instance()],
                    fresh_randomness(),
                    ProverConfig::default(),
                );
                assert!(
                    matches!(engine, Err(ProverError::LookupInputMissing { lookup: 0 })),
                    "{label}: {engine:?}"
                );
                // A forger zeroes the failing range checks: the engine proves,
                // the verifier rejects.
                let (forged, instance, failures) = forged_witness(&prover, &witness);
                let forged_proof = create_proof(
                    prover.params(),
                    prover.proving_key(),
                    &forged,
                    fresh_randomness(),
                    ProverConfig::default(),
                )
                .expect("the engine proves the forged witness");
                let verdict = verifier.verify(&claimed, &forged_proof);
                assert!(verdict.is_err(), "{label}: forged proof accepted");
                assert_eq!(claimed.instance(), instance);
                // The honest proof does not verify for the mutated statement.
                assert!(
                    verifier.verify(&claimed, &honest_proof.bytes).is_err(),
                    "{label}"
                );
                println!(
                    "M12_REAL case={} k={} lanes={} mutation={mutation:?} accepted=false \
                     prove=refused engine=LookupInputMissing forged={verdict:?} \
                     checker_failures={}",
                    relation.label(),
                    shape.k,
                    shape.params.lanes(),
                    failures.len()
                );
            }
            cases += 1;
        }
    }
    assert_eq!(cases, RELATION_CHECK_CASES);
}

/// Every byte of a proof, flipped in its lowest and highest bit, is rejected.
fn every_byte_is_bound(relation: iroha_kagemusha_proof::RelationShape) -> usize {
    let shape = budget_shape(relation);
    let prover = vesta_prover(shape);
    let verifier = prover.verifier();
    let witness = sample_witness::<Fp>(CHECK_SEED, relation.relation, Mutation::None);
    let proof = prover.prove(&witness, fresh_randomness()).expect("proof");
    assert_eq!(verifier.verify(&proof.public, &proof.bytes), Ok(()));
    let accepted: Vec<(usize, u8)> = (0..proof.bytes.len())
        .into_par_iter()
        .flat_map_iter(|index| [(index, 0x01_u8), (index, 0x80_u8)])
        .filter(|(index, mask)| {
            let mut tampered = proof.bytes.clone();
            tampered[*index] ^= mask;
            verifier.verify(&proof.public, &tampered).is_ok()
        })
        .collect();
    assert!(
        accepted.is_empty(),
        "{}: accepted {accepted:?}",
        relation.label()
    );
    // Truncated and extended proofs are rejected too.
    let mut longer = proof.bytes.clone();
    longer.push(0);
    assert!(verifier.verify(&proof.public, &longer).is_err());
    assert!(
        verifier
            .verify(&proof.public, &proof.bytes[..proof.bytes.len() - 1])
            .is_err()
    );
    proof.bytes.len()
}

#[test]
#[ignore = "two flips per proof byte, each a full verification; run in release"]
fn every_proof_byte_is_bound() {
    for case in (0..=3)
        .map(SigmaRelation::send)
        .chain([SigmaRelation::RECEIVE])
    {
        let relation = folded(case);
        let bytes = every_byte_is_bound(relation);
        println!(
            "M12_TAMPER_BYTES case={} bytes={bytes} flips={} accepted=0",
            relation.label(),
            2 * bytes
        );
    }
}

#[test]
#[ignore = "real proofs on Pallas; run in release"]
fn pallas_step_proofs_verify() {
    for case in [SigmaRelation::SEND, SigmaRelation::RECEIVE] {
        let shape = budget_shape(folded(case));
        let prover = SigmaProver::<Ep>::keygen(shape).expect("Pallas keys");
        let witness = sample_witness::<Fq>(CHECK_SEED, case, Mutation::None);
        let proof = prover
            .prove(&witness, fresh_randomness())
            .expect("Pallas proof");
        assert_eq!(
            prover.verifier().verify(&proof.public, &proof.bytes),
            Ok(())
        );
        assert_eq!(
            proof.bytes.len(),
            shape.proof_length::<Ep>().expect("length")
        );
        let mutated = sample_witness::<Fq>(
            CHECK_SEED,
            case,
            match case.step() {
                StepRelation::Send => Mutation::Overdraft,
                StepRelation::Receive => Mutation::Overflow,
            },
        );
        assert!(matches!(
            prover.prove(&mutated, fresh_randomness()),
            Err(SigmaError::RelationViolated(violations))
                if violations.contains(&Violation::Overdraft)
                    || violations.contains(&Violation::BalanceOverflow)
        ));
    }
}

/// A witness of the other step is refused before proving, and a proof
/// verifies only under its own selector of the allowlist.
#[test]
#[ignore = "key generation and genuine proofs for all five selectors; run in release"]
fn proofs_verify_only_under_their_selector() {
    let mut allowlist = SigmaAllowlist::<Eq>::new();
    let mut provers = Vec::new();
    for case in (0..=3)
        .map(SigmaRelation::send)
        .chain([SigmaRelation::RECEIVE])
    {
        let shape = wallet_monetary_shape(case).expect("monetary shape");
        assert_eq!(shape, budget_shape(folded(case)));
        let prover = vesta_prover(shape);
        allowlist
            .insert(prover.verifier())
            .expect("one per selector");
        provers.push((case, prover));
    }
    // One entry per selector, ascending, with the exact proof length.
    let entries = allowlist.entries().expect("entries");
    assert_eq!(
        entries
            .iter()
            .map(VerifyingKeyEntry::selector)
            .collect::<Vec<_>>(),
        vec![(3, 0), (3, 1), (3, 2), (3, 3), (4, 0)]
    );
    for (entry, (_, prover)) in entries.iter().zip(&provers) {
        let length = prover.shape().proof_length::<Eq>().expect("length");
        assert_eq!(usize::try_from(entry.proof_bytes).expect("u32"), length);
        assert!(length <= KAGEMUSHA_WALLET_SIGMA_PROOF_CAP_V1);
        assert_eq!(entry.transcript()[5..37], entry.verifying_key_digest);
        println!(
            "M12_ALLOWLIST selector={:?} proof_bytes={} vk_digest={}",
            entry.selector(),
            entry.proof_bytes,
            entry
                .verifying_key_digest
                .iter()
                .fold(String::new(), |mut out, byte| {
                    let _ = write!(out, "{byte:02x}");
                    out
                })
        );
    }
    // The verifying keys differ per selector.
    for (index, entry) in entries.iter().enumerate() {
        for other in &entries[index + 1..] {
            assert_ne!(entry.verifying_key_digest, other.verifying_key_digest);
        }
    }
    assert!(matches!(
        allowlist.insert(provers[0].1.verifier()),
        Err(SigmaError::DuplicateSelector((3, 0)))
    ));
    for (case, prover) in &provers {
        let witness = sample_witness::<Fp>(1, *case, Mutation::None);
        let proof = prover.prove(&witness, fresh_randomness()).expect("proof");
        assert_eq!(
            proof.bytes.len(),
            prover.shape().proof_length::<Eq>().unwrap()
        );
        assert!(proof.bytes.len() <= KAGEMUSHA_WALLET_SIGMA_PROOF_CAP_V1);
        for (other, _) in &provers {
            let verdict = allowlist.verify(*other, &proof.public, &proof.bytes);
            assert_eq!(verdict.is_ok(), other == case, "{case:?} under {other:?}");
        }
        // Every monetary selector rejects a changed public statement and exact-length
        // framing errors, including the k14 quota profiles.
        let mut wrong_public = proof.public;
        wrong_public.statement += Fp::ONE;
        assert!(
            allowlist
                .verify(*case, &wrong_public, &proof.bytes)
                .is_err()
        );
        assert!(
            allowlist
                .verify(*case, &proof.public, &proof.bytes[..proof.bytes.len() - 1])
                .is_err(),
            "{case:?}: truncated proof"
        );
        let mut extended = proof.bytes.clone();
        extended.push(0);
        assert!(
            allowlist.verify(*case, &proof.public, &extended).is_err(),
            "{case:?}: extended proof"
        );
        // A witness of the other step is refused.
        let other_step = match case.step() {
            StepRelation::Send => SigmaRelation::RECEIVE,
            StepRelation::Receive => SigmaRelation::SEND,
        };
        let foreign = sample_witness::<Fp>(1, other_step, Mutation::None);
        assert_eq!(
            prover
                .prove(&foreign, fresh_randomness())
                .map(|proof| proof.bytes),
            Err(SigmaError::WrongRelation {
                expected: case.step(),
                found: other_step.step(),
            })
        );
    }
    // An undefined mask has no verifier.
    assert!(matches!(
        allowlist.select(SigmaRelation::send(4)),
        Err(SigmaError::NoVerifier((3, 4)))
    ));
}

/// A refused witness sent directly to the engine: the relation's sole running-sum
/// lookup (index zero) fails, or an emitted proof is rejected by the full verifier.
/// Infrastructure, cancellation, and unrelated proving errors never count as refusal.
fn engine_refuses(
    prover: &SigmaProver<Eq>,
    witness: &iroha_kagemusha_proof::StepWitness<Fp>,
    label: &str,
) {
    let relation = prover.shape().params.relation().relation;
    assert_eq!(
        prover.proving_key().binding().descriptor().lookups.len(),
        1,
        "sigma has exactly its running-sum lookup at index zero"
    );
    let circuit = prover.circuit(witness).expect("circuit");
    let claimed = witness.evaluate(relation).public();
    let engine = prove_circuit(
        prover.params(),
        prover.proving_key(),
        &circuit,
        &[claimed.instance()],
        fresh_randomness(),
        ProverConfig::default(),
    );
    match engine {
        Err(ProverError::LookupInputMissing { lookup: 0 }) => {
            println!("M12_REFUSED case={label} engine=LookupInputMissing lookup=0");
        }
        Err(error) => panic!("{label}: unexpected prover error, not a relation refusal: {error:?}"),
        Ok(proof) => {
            assert!(
                prover.verifier().verify(&claimed, &proof).is_err(),
                "{label}: the engine's proof of a refused witness verifies"
            );
            println!("M12_REFUSED case={label} engine=proved verdict=rejected");
        }
    }
}

/// The quota relation and the full mask at their single-lane `k = 14`
/// shape: honest proofs verify; an exceeded window and an untouched kind are
/// refused by the library and the engine, and a forger who zeroes the
/// exceeded window's failing range check gets a rejected proof.
#[test]
#[ignore = "k = 14 keys and proofs; run in release"]
fn quota_relations_prove_at_k14() {
    for case in [SEND_QUOTAS, SEND_EVERY] {
        let shape = pinned_shape(folded(case), (14, 1));
        assert_eq!(shape, wallet_monetary_shape(case).unwrap());
        let prover = vesta_prover(shape);
        let verifier = prover.verifier();
        let honest = sample_witness::<Fp>(CHECK_SEED + 1, case, Mutation::None);
        let proof = prover
            .prove(&honest, fresh_randomness())
            .expect("honest proof");
        assert_eq!(verifier.verify(&proof.public, &proof.bytes), Ok(()));
        assert_eq!(
            proof.bytes.len(),
            shape.proof_length::<Eq>().expect("length")
        );
        assert!(proof.bytes.len() <= KAGEMUSHA_WALLET_SIGMA_PROOF_CAP_V1);

        // The production k14 profile must retain the exact expiry and interval-width
        // bounds, including the additional lease control in the full mask.
        let iroha_kagemusha_proof::StepInputs::Send(send) = &honest.inputs else {
            panic!("a Send witness");
        };
        let upper = send.accepted_upper;
        let span = upper
            .checked_sub(send.accepted_lower)
            .expect("ordered interval");
        assert!(span > 0, "nonempty boundary fixture");
        let mut boundary = honest.clone();
        boundary.predecessor.core.controls.quota_share_expires_at_ms =
            upper.checked_add(1).expect("expiry boundary");
        boundary
            .predecessor
            .core
            .controls
            .time_anchor_max_response_ms = span;
        if case == SEND_EVERY {
            boundary.predecessor.core.controls.lease_expires_at_ms =
                upper.checked_add(1).expect("lease boundary");
        }
        let boundary_proof = prover
            .prove(&boundary, fresh_randomness())
            .expect("honest boundary proof");
        assert_eq!(
            verifier.verify(&boundary_proof.public, &boundary_proof.bytes),
            Ok(())
        );
        assert_eq!(
            boundary_proof.bytes.len(),
            shape.proof_length::<Eq>().unwrap()
        );
        assert!(boundary_proof.bytes.len() <= KAGEMUSHA_WALLET_SIGMA_PROOF_CAP_V1);

        let mut expired = boundary.clone();
        expired.predecessor.core.controls.quota_share_expires_at_ms = upper;
        let mut too_wide = boundary.clone();
        too_wide
            .predecessor
            .core
            .controls
            .time_anchor_max_response_ms = span - 1;
        let mut boundaries = vec![
            ("share expiry", expired, Violation::QuotaShareExpired),
            ("interval width", too_wide, Violation::SendSpan),
        ];
        if case == SEND_EVERY {
            let mut lease_expired = boundary.clone();
            lease_expired.predecessor.core.controls.lease_expires_at_ms = upper;
            boundaries.push(("lease expiry", lease_expired, Violation::LeaseExpired));
        }
        let invalid_boundary_count = boundaries.len();
        for (name, witness, violation) in boundaries {
            let label = format!("{} {name}", case.label());
            assert_eq!(
                witness.evaluate(case).violations,
                vec![violation],
                "{label}"
            );
            assert_eq!(
                prover
                    .prove(&witness, fresh_randomness())
                    .map(|proof| proof.bytes),
                Err(SigmaError::RelationViolated(vec![violation])),
                "{label}"
            );
            engine_refuses(&prover, &witness, &label);
            assert!(
                verifier
                    .verify(&witness.evaluate(case).public(), &boundary_proof.bytes)
                    .is_err(),
                "{label}: honest boundary proof under an invalid statement"
            );
        }
        println!(
            "M12_QUOTA_BOUNDARIES case={} k={} lanes={} bytes={} valid=1 invalid={} share_expiry=refused send_span=refused lease_expiry={}",
            case.label(),
            shape.k,
            shape.params.lanes(),
            boundary_proof.bytes.len(),
            invalid_boundary_count,
            if case == SEND_EVERY {
                "refused"
            } else {
                "disabled"
            },
        );
        for (mutation, violation) in [
            (Mutation::QuotaExceeded, Violation::QuotaExceeded),
            (Mutation::QuotaUntouched, Violation::QuotaKindUntouched),
        ] {
            let witness = sample_witness::<Fp>(CHECK_SEED, case, mutation);
            let label = format!("{} {mutation:?}", case.label());
            assert_eq!(
                prover
                    .prove(&witness, fresh_randomness())
                    .map(|proof| proof.bytes),
                Err(SigmaError::RelationViolated(vec![violation])),
                "{label}"
            );
            engine_refuses(&prover, &witness, &label);
            assert!(
                verifier
                    .verify(&witness.evaluate(case).public(), &proof.bytes)
                    .is_err()
            );
        }
        let exceeded = sample_witness::<Fp>(CHECK_SEED, case, Mutation::QuotaExceeded);
        let (forged, instance, _) = forged_witness(&prover, &exceeded);
        let forged_proof = create_proof(
            prover.params(),
            prover.proving_key(),
            &forged,
            fresh_randomness(),
            ProverConfig::default(),
        )
        .expect("the engine proves the forged witness");
        let claimed = exceeded.evaluate(case).public();
        assert_eq!(claimed.instance(), instance);
        assert!(verifier.verify(&claimed, &forged_proof).is_err());
        println!(
            "M12_QUOTA case={} k=14 lanes=1 bytes={} exceeded=refused untouched=refused forged=rejected",
            case.label(),
            proof.bytes.len()
        );
    }
}

/// A forger proves a Send from a state with a substituted asset (consistent:
/// the circuit recomputes everything). The proof verifies for its own
/// statement, whose predecessor is not the real head; the statement the
/// consumer builds for the real head does not verify.
#[test]
#[ignore = "real proofs of forged identities; run in release"]
fn forged_identities_prove_only_their_own_head() {
    for case in [SigmaRelation::SEND, SEND_LEASE] {
        let relation = folded(case);
        let prover = vesta_prover(budget_shape(relation));
        let verifier = prover.verifier();
        let honest = sample_witness::<Fp>(CHECK_SEED, case, Mutation::None);
        let view = lineage_view_of(&honest).expect("send witness");
        let mut forged = honest.clone();
        forged.predecessor.core.identity.asset_digest[0] ^= 0xa5;
        let proof = prover
            .prove(&forged, fresh_randomness())
            .expect("forged proof");
        assert_eq!(verifier.verify(&proof.public, &proof.bytes), Ok(()));
        let request = forged.request_body();
        let own = forged.statement(case).expect("statement");
        assert_eq!(
            check_send(&view, &request, &own),
            Err(ConsumerError::Predecessor)
        );
        let mut claim = own;
        claim.predecessor = view.head;
        let accepted = check_send(&view, &request, &claim).expect("the consumer's statement");
        assert_eq!(accepted.relation, case);
        assert!(verifier.verify(&accepted.public, &proof.bytes).is_err());
        println!(
            "M12_FORGED case={} asset=substituted verdict=rejected",
            relation.label()
        );
    }
}

/// Keys and verification of one retained proof are identical on 1, 2, 4
/// and 7 Rayon threads; each fresh proving attempt draws independent entropy.
#[test]
#[ignore = "key generation and proofs on four pool sizes; run in release"]
fn keys_and_retained_proof_verification_do_not_depend_on_the_pool_size() {
    for case in [SigmaRelation::SEND, SigmaRelation::RECEIVE] {
        let shape = budget_shape(folded(case));
        let witness = sample_witness::<Fp>(CHECK_SEED, case, Mutation::None);
        let mut seen: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = None;
        for threads in [1, 2, 4, 7] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("pool");
            let (vk, descriptor, proof) = pool.install(|| {
                let prover = SigmaProver::<Eq>::keygen_with_params(shape, vesta_params(shape.k))
                    .expect("keys");
                let proof = prover.prove(&witness, fresh_randomness()).expect("proof");
                let verifier = prover.verifier();
                assert_eq!(verifier.verify(&proof.public, &proof.bytes), Ok(()));
                if let Some((_, _, retained)) = &seen {
                    verifier
                        .verify(&proof.public, retained)
                        .expect("same retained original at each pool size");
                }
                (
                    verifier.vk_bytes().to_vec(),
                    verifier.descriptor_bytes().to_vec(),
                    proof.bytes,
                )
            });
            match &seen {
                None => seen = Some((vk, descriptor, proof)),
                Some(first) => {
                    assert_eq!(
                        (&first.0, &first.1),
                        (&vk, &descriptor),
                        "{case:?}: {threads} threads"
                    );
                    assert_ne!(first.2, proof, "fresh attempt on {threads} threads");
                }
            }
        }
        println!(
            "M12_POOLS relation={} threads=1,2,4,7 keys_equal=true retained_proof_verified=true fresh_entropy=true",
            case.label()
        );
    }
}

#[test]
#[ignore = "genuine imported sigma proofs on both Pasta curves; run in release"]
fn installed_sigma_originals_prove_and_preserve_key_continuity() {
    use iroha_pasta::{PastaCurve, msm::MemoryBudget, poseidon::PoseidonField};
    use iroha_plonk::{
        keys::{CosetCachePolicy, pk::artifact::ReadConfig},
        pcs::ipa::PinnedParams,
    };
    fn run<C: PastaCurve>()
    where
        C::ScalarExt: PoseidonField,
    {
        for relation in [SigmaRelation::SEND, SigmaRelation::RECEIVE] {
            let shape = budget_shape(folded(relation));
            let params = PinnedParams::<C>::derive(shape.k).unwrap();
            // Test fixture production is explicit keygen. Runtime intake below imports only.
            let producer = SigmaProver::keygen_with_params(shape, params.clone()).unwrap();
            let original = producer.proving_key().artifact_bytes_v2().unwrap();
            let verifier = producer.verifier();
            let table_bytes = (producer.proving_key().fixed_values().len()
                + producer.proving_key().permutation_values().len())
                * producer.proving_key().binding().n()
                * 32;
            assert_eq!(original.len(), 108 + verifier.vk_bytes().len());
            // Measure the runtime import with only its compact original and public
            // metadata retained; fixture key generation is a separate phase.
            drop(producer);
            let read = ReadConfig {
                maximum_bytes: original.len(),
                maximum_rows: 1 << shape.k,
                coset_cache: CosetCachePolicy::OnDemand,
                msm_budget: MemoryBudget::DEFAULT,
            };
            let started = std::time::Instant::now();
            let metadata = SigmaProver::<C>::admit_original_artifact_cancellable(
                shape,
                params.clone(),
                verifier.descriptor_bytes(),
                verifier.vk_bytes(),
                &original,
                read,
                None,
            )
            .expect("compact sigma metadata admission");
            let admission_ms = started.elapsed().as_millis();
            assert_eq!(metadata.binding(), verifier.binding());
            assert_eq!(metadata.verifying_key().to_bytes(), verifier.vk_bytes());
            drop(metadata);
            let started = std::time::Instant::now();
            let imported = SigmaProver::from_original_artifact(
                shape,
                params,
                verifier.descriptor_bytes(),
                verifier.vk_bytes(),
                &original,
                read,
            )
            .expect("installed sigma original");
            let import_ms = started.elapsed().as_millis();
            assert!(!imported.proving_key().has_coset_cache());
            assert_eq!(
                imported.proving_key().artifact_bytes_v2().unwrap(),
                original
            );
            assert_eq!(imported.verifier().vk_bytes(), verifier.vk_bytes());
            assert_eq!(imported.verifier().binding(), verifier.binding());
            let witness = sample_witness::<C::ScalarExt>(CHECK_SEED, relation, Mutation::None);
            let started = std::time::Instant::now();
            let proof = imported
                .prove(&witness, fresh_randomness())
                .expect("genuine imported sigma proof");
            let prove_ms = started.elapsed().as_millis();
            verifier
                .verify(&proof.public, &proof.bytes)
                .expect("original installed key");
            let mut wrong = proof.public;
            wrong.statement += C::ScalarExt::ONE;
            assert!(verifier.verify(&wrong, &proof.bytes).is_err());
            println!(
                "COMPACT_SIGMA curve={:?} relation={} k={} original_bytes={} reconstructed_table_bytes={} admission_ms={} post_admission_import_ms={} prove_ms={}",
                verifier.binding().descriptor().curve,
                relation.label(),
                shape.k,
                original.len(),
                table_bytes,
                admission_ms,
                import_ms,
                prove_ms,
            );
        }
    }
    run::<Eq>();
    run::<Ep>();
}

#[test]
#[ignore = "genuine sigma PK import refusal against actual source tables; run in release"]
fn installed_sigma_originals_reject_substitution_bounds_and_wrong_source() {
    use iroha_pasta::msm::MemoryBudget;
    use iroha_plonk::{
        keys::{
            CosetCachePolicy,
            pk::artifact::{Error as ArtifactError, ReadConfig},
        },
        pcs::ipa::PinnedParams,
    };
    fn mount_source<C: iroha_pasta::PastaCurve>(
        shape: iroha_kagemusha_proof::SigmaShape,
        params: PinnedParams<C>,
        descriptor: &[u8],
        vk: &[u8],
        original: &[u8],
        config: ReadConfig,
    ) -> Result<SigmaProver<C>, SigmaError>
    where
        C::ScalarExt: iroha_pasta::poseidon::PoseidonField,
    {
        let metadata = SigmaProver::admit_original_artifact_cancellable(
            shape,
            params.clone(),
            descriptor,
            vk,
            original,
            config,
            None,
        );
        let full =
            SigmaProver::from_original_artifact(shape, params, descriptor, vk, original, config);
        assert_eq!(metadata.as_ref().err(), full.as_ref().err());
        full
    }
    let shape = budget_shape(folded(SigmaRelation::SEND));
    let params = common::vesta_params(shape.k);
    let producer = SigmaProver::keygen_with_params(shape, params.clone()).unwrap();
    let original = producer.proving_key().artifact_bytes_v2().unwrap();
    let verifier = producer.verifier();
    let config = ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 1 << shape.k,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let mount = |bytes: &[u8], selected: ReadConfig| {
        mount_source(
            shape,
            params.clone(),
            verifier.descriptor_bytes(),
            verifier.vk_bytes(),
            bytes,
            selected,
        )
    };
    let mut bounded = config;
    bounded.maximum_bytes -= 1;
    assert!(matches!(
        mount(&original, bounded),
        Err(SigmaError::Artifact(ArtifactError::Length))
    ));
    bounded = config;
    bounded.maximum_rows -= 1;
    assert!(matches!(
        mount(&original, bounded),
        Err(SigmaError::Artifact(ArtifactError::Length))
    ));
    assert!(matches!(
        mount(&original[..original.len() - 1], config),
        Err(SigmaError::Artifact(ArtifactError::Length))
    ));
    let mut extra = original.clone();
    extra.push(0);
    assert!(matches!(
        mount(&extra, config),
        Err(SigmaError::Artifact(ArtifactError::Length))
    ));
    let mut corrupted = original.clone();
    corrupted[8] ^= 1;
    assert!(matches!(
        mount(&corrupted, config),
        Err(SigmaError::Artifact(ArtifactError::Encoding))
    ));
    let vk_len = u32::from_le_bytes(original[40..44].try_into().unwrap()) as usize;
    let source_digest_start = 44 + vk_len + 32;
    corrupted = original.clone();
    corrupted[source_digest_start..source_digest_start + 32].fill(0xff);
    assert!(matches!(
        mount(&corrupted, config),
        Err(SigmaError::Artifact(ArtifactError::Source))
    ));
    let other_source = budget_shape(folded(SigmaRelation::RECEIVE));
    assert!(matches!(
        mount_source(
            other_source,
            params.clone(),
            verifier.descriptor_bytes(),
            verifier.vk_bytes(),
            &original,
            config,
        ),
        Err(SigmaError::Artifact(
            ArtifactError::Profile | ArtifactError::Source
        ))
    ));
    let other_key = SigmaProver::keygen_with_params(other_source, params.clone())
        .unwrap()
        .verifier();
    assert!(matches!(
        mount_source(
            shape,
            params.clone(),
            verifier.descriptor_bytes(),
            other_key.vk_bytes(),
            &original,
            config,
        ),
        Err(SigmaError::ArtifactKeyMismatch | SigmaError::VerifyingKey(_))
    ));
    assert!(matches!(
        mount_source(
            shape,
            common::vesta_params(6),
            verifier.descriptor_bytes(),
            verifier.vk_bytes(),
            &original,
            config,
        ),
        Err(SigmaError::ParamsK { .. })
    ));
    assert!(matches!(
        mount_source(
            shape,
            params.clone(),
            &[0; 32],
            verifier.vk_bytes(),
            &original,
            config,
        ),
        Err(SigmaError::Descriptor(_))
    ));
    let mut wrong_profile =
        iroha_plonk::cs::CircuitDescriptorV2::decode(verifier.descriptor_bytes()).unwrap();
    wrong_profile.instance_types[0] = iroha_plonk::cs::InstanceType::Field;
    assert!(matches!(
        mount_source(
            shape,
            params.clone(),
            &wrong_profile.encode().unwrap(),
            verifier.vk_bytes(),
            &original,
            config,
        ),
        Err(SigmaError::Profile)
    ));
    assert!(
        mount_source::<Ep>(
            shape,
            PinnedParams::<Ep>::derive(shape.k).unwrap(),
            verifier.descriptor_bytes(),
            verifier.vk_bytes(),
            &original,
            config,
        )
        .is_err()
    );
}

/// D5: a qualified wallet rebuilds a σ proving key from the seal that admission
/// minted, as Q/A/W/Ω do, instead of importing the original again. At the k12
/// budget shapes and the k14 quota shape the rebuild is the exact original key and
/// its proofs verify under the installed verifier. Another compiled source of the
/// same `k`, other parameters and cancellation return no key; nothing falls back.
#[test]
#[ignore = "sealed k12 and k14 sigma rebuilds with real proofs; run in release"]
fn sealed_sigma_sources_rebuild_exact_keys_for_the_installed_verifier() {
    use iroha_pasta::{CancellationToken, msm::MemoryBudget};
    use iroha_plonk::keys::{CosetCachePolicy, RebuildError, pk::artifact::ReadConfig};
    for (case, shape, other, seed) in [
        (
            SigmaRelation::SEND,
            budget_shape(folded(SigmaRelation::SEND)),
            budget_shape(folded(SigmaRelation::RECEIVE)),
            CHECK_SEED,
        ),
        (
            SigmaRelation::RECEIVE,
            budget_shape(folded(SigmaRelation::RECEIVE)),
            budget_shape(folded(SigmaRelation::SEND)),
            CHECK_SEED,
        ),
        (
            SEND_EVERY,
            pinned_shape(folded(SEND_EVERY), (14, 1)),
            pinned_shape(folded(SEND_QUOTAS), (14, 1)),
            CHECK_SEED + 1,
        ),
    ] {
        assert_eq!(other.k, shape.k, "{}: same-k foreign source", case.label());
        let params = vesta_params(shape.k);
        let producer = vesta_prover(shape);
        let original = producer.proving_key().artifact_bytes_v2().unwrap();
        let verifier = producer.verifier();
        drop(producer);
        let read = ReadConfig {
            maximum_bytes: original.len(),
            maximum_rows: 1 << shape.k,
            coset_cache: CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        };
        let admitted = SigmaProver::<Eq>::admit_original_artifact_cancellable(
            shape,
            params.clone(),
            verifier.descriptor_bytes(),
            verifier.vk_bytes(),
            &original,
            read,
            None,
        )
        .expect("strict sigma admission");
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            SigmaProver::from_source_view_cancellable(
                shape,
                params.clone(),
                admitted.view(),
                CosetCachePolicy::OnDemand,
                Some(&cancelled),
            )
            .is_err_and(|error| error.is_cancelled())
        );
        assert!(matches!(
            SigmaProver::from_source_view_cancellable(
                shape,
                vesta_params(6),
                admitted.view(),
                CosetCachePolicy::OnDemand,
                None,
            ),
            Err(SigmaError::ParamsK { .. })
        ));
        assert!(
            matches!(
                SigmaProver::from_source_view_cancellable(
                    other,
                    params.clone(),
                    admitted.view(),
                    CosetCachePolicy::OnDemand,
                    None,
                ),
                Err(SigmaError::Rebuild(
                    RebuildError::Profile | RebuildError::Source
                ))
            ),
            "{}: another compiled source",
            case.label()
        );
        let rebuilt = SigmaProver::from_source_view_cancellable(
            shape,
            params,
            admitted.view(),
            CosetCachePolicy::OnDemand,
            None,
        )
        .expect("sealed sigma rebuild");
        assert!(!rebuilt.proving_key().has_coset_cache());
        assert_eq!(rebuilt.proving_key().artifact_bytes_v2().unwrap(), original);
        assert_eq!(rebuilt.proving_key().binding(), verifier.binding());
        assert_eq!(rebuilt.proving_key().vk().to_bytes(), verifier.vk_bytes());
        let witness = sample_witness::<Fp>(seed, case, Mutation::None);
        let proof = rebuilt
            .prove(&witness, fresh_randomness())
            .expect("sealed sigma proof");
        assert_eq!(verifier.verify(&proof.public, &proof.bytes), Ok(()));
        let mut wrong = proof.public;
        wrong.statement += Fp::ONE;
        assert!(verifier.verify(&wrong, &proof.bytes).is_err());
        println!(
            "SEALED_SIGMA relation={} k={} original_bytes={} exact_original=true installed_verifier=true strict_reimport=false",
            case.label(),
            shape.k,
            original.len(),
        );
    }
}

/// Pins compact Send's measured public-source geometry and hashes.
/// This synthesizes public source and hashes it, but grants no source authority.
#[test]
fn compact_send_descriptor_support_inventory() {
    use iroha_kagemusha_proof::{SigmaCircuit, wallet_monetary_shape};
    use iroha_plonk::{
        Protocol,
        cs::{InstanceType, descriptor::ColumnKindV1},
        frontend::synthesize,
        keys::{DescriptorBinding, KeygenConfigV2, source_fingerprint_v2},
        pcs::ipa::PinnedParams,
    };
    use sha2::{Digest as _, Sha256};

    let shape = wallet_monetary_shape(SigmaRelation::SEND).expect("wallet shape");
    let descriptor = shape.descriptor::<Eq>().expect("descriptor");
    let binding = DescriptorBinding::new_v2(descriptor.clone()).expect("binding");
    let protocol = Protocol::new(&descriptor).expect("protocol");
    let advice: Vec<_> = descriptor
        .advice_queries
        .iter()
        .map(|query| (query.column, query.rotation))
        .collect();
    let fixed: Vec<_> = descriptor
        .fixed_queries
        .iter()
        .map(|query| (query.column, query.rotation))
        .collect();
    let equality: Vec<_> = descriptor
        .permutation
        .iter()
        .map(|column| (column.kind, column.index))
        .collect();
    let selector_map: Vec<_> = descriptor
        .selectors
        .entries
        .iter()
        .map(|entry| (entry.max_degree, entry.combination, entry.root))
        .collect();
    assert_eq!(descriptor.k, 12);
    assert_eq!(descriptor.degree, 10);
    assert_eq!(descriptor.blinding_factors, 5);
    assert_eq!(descriptor.permutation_chunk_len, 4);
    assert_eq!(descriptor.quotient_pieces, 9);
    assert_eq!(descriptor.num_advice_columns, 5);
    assert_eq!(descriptor.num_fixed_columns, 22);
    assert_eq!(descriptor.instance_lengths, vec![1]);
    assert_eq!(descriptor.lookups.len(), 1);
    assert_eq!(
        advice,
        vec![
            (0, 0),
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 0),
            (4, 1),
            (4, -1),
            (0, 1),
            (1, 1),
            (2, 1),
            (3, 1)
        ]
    );
    let expected_fixed: Vec<_> = [
        6, 7, 8, 9, 10, 11, 12, 13, 14, 0, 1, 2, 3, 4, 5, 15, 16, 17, 18, 19, 20, 21,
    ]
    .into_iter()
    .map(|index| (index, 0))
    .collect();
    assert_eq!(fixed, expected_fixed);
    assert_eq!(
        equality,
        vec![
            (ColumnKindV1::Advice, 0),
            (ColumnKindV1::Advice, 1),
            (ColumnKindV1::Advice, 2),
            (ColumnKindV1::Advice, 3),
            (ColumnKindV1::Fixed, 6),
            (ColumnKindV1::Advice, 4),
            (ColumnKindV1::Instance, 0)
        ]
    );
    assert!(descriptor.selectors.compress);
    assert_eq!(descriptor.selectors.first_column, 15);
    assert_eq!(
        selector_map,
        vec![
            (3, 2, 1),
            (3, 2, 2),
            (3, 2, 3),
            (0, 0, 1),
            (0, 1, 1),
            (3, 2, 4),
            (6, 3, 1),
            (6, 3, 2),
            (6, 4, 1),
            (6, 4, 2),
            (6, 5, 1),
            (2, 2, 5),
            (2, 5, 2),
            (2, 6, 1),
            (2, 6, 2),
            (2, 6, 3)
        ]
    );
    assert_eq!(protocol.shape().usable_rows, 4090);
    assert_eq!(protocol.shape().permutation_sets, 2);
    assert_eq!(protocol.plan().rotations(), &[0, 1, -1, -6]);
    assert_eq!(protocol.plan().sets().len(), 5);
    assert_eq!(
        format!("{:x}", Sha256::digest(binding.encoded())),
        "3caa2db67ee50fa917ea344d967c477b5f9122b5a6225533033568fd6a6ea24d"
    );

    let circuit = SigmaCircuit::<Fp>::keygen(shape.params);
    let source = synthesize(&circuit, shape.k, None).expect("native source");
    let selectors = source.tables.selectors();
    assert_eq!(selectors.len(), 16);
    let usable = protocol.shape().usable_rows;
    for (selector, active) in selectors.iter().enumerate() {
        assert!(active[usable..].iter().all(|value| !value));
        if [3, 6, 7, 8, 9].contains(&selector) {
            assert!(
                active
                    .iter()
                    .enumerate()
                    .all(|(row, value)| !value || row + 1 < usable)
            );
        }
        if selector == 5 {
            assert!(!active[0], "range previous rotation cannot wrap");
        }
    }
    let packed: Vec<_> = selectors
        .iter()
        .flat_map(|rows| {
            rows.chunks(8).map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0_u8, |byte, (bit, value)| byte | (u8::from(*value) << bit))
            })
        })
        .collect();
    assert_eq!(
        format!("{:x}", Sha256::digest(&packed)),
        "298f11fbfd998fad9de3239fd15c12487710b741466bba82693e8f96e175594c"
    );
    assert_eq!(
        source.tables.permutation().mapping_digest(),
        [
            22, 158, 89, 91, 44, 130, 45, 79, 84, 1, 182, 8, 32, 143, 29, 151, 131, 115, 10, 138,
            164, 64, 122, 200, 113, 167, 77, 218, 242, 187, 145, 49
        ]
    );
    let params = PinnedParams::<Eq>::for_domain(shape.k).expect("pinned parameters");
    let fingerprint = source_fingerprint_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]),
        None,
    )
    .expect("source fingerprint");
    assert_eq!(fingerprint.binding(), &binding);
    assert_eq!(
        fingerprint.digest(),
        &[
            146, 3, 147, 201, 52, 41, 213, 191, 244, 177, 68, 30, 199, 113, 227, 137, 146, 137,
            201, 179, 26, 131, 17, 249, 194, 209, 134, 6, 255, 39, 97, 168
        ]
    );
    println!(
        "COMPACT_SEND_SOURCE descriptor={:x} selectors={:x} source={:?} queries={:?} groups={:?} selector_map={selector_map:?}",
        Sha256::digest(binding.encoded()),
        Sha256::digest(packed),
        fingerprint.digest(),
        protocol.queries(),
        protocol.plan().slots()
    );
}

/// Print every pinned public-source input before updating the inventory's golden values.
/// This probe neither generates a proof nor grants authority to a source or key.
#[test]
#[ignore = "public compact Send descriptor/source probe"]
fn compact_send_source_probe() {
    use iroha_kagemusha_proof::SigmaCircuit;
    use iroha_plonk::{
        Protocol,
        cs::InstanceType,
        frontend::synthesize,
        keys::{DescriptorBinding, KeygenConfigV2, source_fingerprint_v2},
        pcs::ipa::PinnedParams,
    };
    use sha2::{Digest as _, Sha256};

    let shape = wallet_monetary_shape(SigmaRelation::SEND).unwrap();
    let descriptor = shape.descriptor::<Eq>().unwrap();
    let binding = DescriptorBinding::new_v2(descriptor.clone()).unwrap();
    let protocol = Protocol::new(&descriptor).unwrap();
    let circuit = SigmaCircuit::<Fp>::keygen(shape.params);
    let source = synthesize(&circuit, shape.k, None).unwrap();
    let packed: Vec<_> = source
        .tables
        .selectors()
        .iter()
        .flat_map(|rows| {
            rows.chunks(8).map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0_u8, |byte, (bit, value)| byte | (u8::from(*value) << bit))
            })
        })
        .collect();
    let params = PinnedParams::<Eq>::for_domain(shape.k).unwrap();
    let fingerprint = source_fingerprint_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]),
        None,
    )
    .unwrap();
    println!(
        "COMPACT_SOURCE_PROBE k={} degree={} blinds={} permutation_chunk={} quotient_pieces={} advice_columns={} fixed_columns={} instances={:?} lookups={} usable_rows={} permutation_sets={} rotations={:?} sets={}",
        descriptor.k,
        descriptor.degree,
        descriptor.blinding_factors,
        descriptor.permutation_chunk_len,
        descriptor.quotient_pieces,
        descriptor.num_advice_columns,
        descriptor.num_fixed_columns,
        descriptor.instance_lengths,
        descriptor.lookups.len(),
        protocol.shape().usable_rows,
        protocol.shape().permutation_sets,
        protocol.plan().rotations(),
        protocol.plan().sets().len()
    );
    println!(
        "COMPACT_SOURCE_PROBE advice={:?} fixed={:?} equality={:?}",
        descriptor
            .advice_queries
            .iter()
            .map(|q| (q.column, q.rotation))
            .collect::<Vec<_>>(),
        descriptor
            .fixed_queries
            .iter()
            .map(|q| (q.column, q.rotation))
            .collect::<Vec<_>>(),
        descriptor
            .permutation
            .iter()
            .map(|c| (c.kind, c.index))
            .collect::<Vec<_>>()
    );
    println!(
        "COMPACT_SOURCE_PROBE compressed={} first_column={} selector_map={:?} selectors={}",
        descriptor.selectors.compress,
        descriptor.selectors.first_column,
        descriptor
            .selectors
            .entries
            .iter()
            .map(|e| (e.max_degree, e.combination, e.root))
            .collect::<Vec<_>>(),
        source.tables.selectors().len()
    );
    println!(
        "COMPACT_SOURCE_PROBE descriptor={:x} selector_bits={:x} permutation={:?} source={:?}",
        Sha256::digest(binding.encoded()),
        Sha256::digest(packed),
        source.tables.permutation().mapping_digest(),
        fingerprint.digest()
    );
}
