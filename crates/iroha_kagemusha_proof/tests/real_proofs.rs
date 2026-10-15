//! The relation checks as real PIPA-v1 proofs (KAGEMUSHA step format on
//! Vesta, at the shape within the 3.5 KB budget):
//!
//! - an honest witness is proved and verified, also through the
//!   verifying-key allowlist by its `(tag, mask)` selector; a wrong public
//!   input is rejected; each fresh attempt changes the proof bytes and
//!   retained originals remain verifiable;
//! - a mutated witness (overdraft, a debit that ignores the lineage
//!   `burned_total`, newer policy epoch, early accepted time, a blacklist
//!   older than the maximum age or issued after the accepted time, a Send at
//!   the lease expiry, `u128` overflow) is refused by
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
//! selector does not verify under another; a listed counterparty and the
//! quota rule's violations have no accepted proof; the full mask proves and
//! verifies at its single-lane `k = 14` shape; keys and verification of retained
//! proof bytes do not depend on the Rayon pool size. All tests here prove for real and are ignored in
//! debug builds.

mod common;

use core::fmt::Write as _;

use common::{
    CHECK_SEED, RECEIVE_BLACKLIST, RELATION_CASES, RELATION_CHECK_CASES, RELATIONS, SEND_BLACKLIST,
    SEND_EVERY, SEND_QUOTAS, budget_shape, case_label, folded, forged_witness, fresh_randomness,
    pinned_shape, relation_shapes, vesta_params, vesta_prover,
};
use ff::Field;
use iroha_kagemusha_proof::{
    ConsumerError, Mutation, SigmaAllowlist, SigmaError, SigmaProver, SigmaRelation, StepRelation,
    VerifyingKeyEntry, Violation, check_send, lineage_view_of, sample_witness,
};
use iroha_pasta::{Ep, Eq, Fp, Fq};
use iroha_plonk::{ProverConfig, ProverError, create_proof, prove_circuit};
use rayon::prelude::*;

#[test]
#[ignore = "30 cases with real proofs; run in release"]
fn relation_checks_as_real_proofs() {
    let mut cases = 0;
    for relation in relation_shapes() {
        let shape = budget_shape(relation);
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
    for case in RELATIONS {
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
#[ignore = "key generation for five selectors; run in release"]
fn proofs_verify_only_under_their_selector() {
    let mut allowlist = SigmaAllowlist::<Eq>::new();
    let mut provers = Vec::new();
    for case in RELATIONS {
        let prover = vesta_prover(budget_shape(folded(case)));
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
        vec![(3, 0), (3, 1), (3, 4), (4, 0), (4, 1)]
    );
    for (entry, (_, prover)) in entries.iter().zip(&provers) {
        let length = prover.shape().proof_length::<Eq>().expect("length");
        assert_eq!(usize::try_from(entry.proof_bytes).expect("u32"), length);
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
    assert_ne!(
        entries[0].verifying_key_digest,
        entries[1].verifying_key_digest
    );
    assert!(matches!(
        allowlist.insert(provers[0].1.verifier()),
        Err(SigmaError::DuplicateSelector((3, 0)))
    ));
    for (case, prover) in &provers {
        let witness = sample_witness::<Fp>(1, *case, Mutation::None);
        let proof = prover.prove(&witness, fresh_randomness()).expect("proof");
        for (other, _) in &provers {
            let verdict = allowlist.verify(*other, &proof.public, &proof.bytes);
            assert_eq!(verdict.is_ok(), other == case, "{case:?} under {other:?}");
        }
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
    // A mask without an allowlisted relation has no verifier.
    assert!(matches!(
        allowlist.select(SigmaRelation::send(2)),
        Err(SigmaError::NoVerifier((3, 2)))
    ));
}

/// A refused witness the engine is asked to prove anyway: it errs, or its
/// proof is rejected.
fn engine_refuses(
    prover: &SigmaProver<Eq>,
    witness: &iroha_kagemusha_proof::StepWitness<Fp>,
    label: &str,
) {
    let relation = prover.shape().params.relation().relation;
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
        Err(error) => println!("M12_REFUSED case={label} engine={error:?}"),
        Ok(proof) => {
            assert!(
                prover.verifier().verify(&claimed, &proof).is_err(),
                "{label}: the engine's proof of a refused witness verifies"
            );
            println!("M12_REFUSED case={label} engine=proved verdict=rejected");
        }
    }
}

/// A listed counterparty has no accepted proof under either step's
/// blacklist relation; with no list held the same account is proved.
#[test]
#[ignore = "real proofs of the blacklist relations; run in release"]
fn a_listed_counterparty_has_no_accepted_proof() {
    for case in [SEND_BLACKLIST, RECEIVE_BLACKLIST] {
        let prover = vesta_prover(budget_shape(folded(case)));
        let listed = sample_witness::<Fp>(CHECK_SEED, case, Mutation::Listed);
        assert_eq!(
            prover
                .prove(&listed, fresh_randomness())
                .map(|proof| proof.bytes),
            Err(SigmaError::RelationViolated(vec![
                Violation::BlacklistListed
            ]))
        );
        engine_refuses(&prover, &listed, &case.label());
        let mut unheld = listed;
        unheld.predecessor.core.controls.blacklist_version = 0;
        let unheld_prover = match &mut unheld.inputs {
            iroha_kagemusha_proof::StepInputs::Send(_) => prover,
            iroha_kagemusha_proof::StepInputs::Receive(receive) => {
                receive.request.receiver_blacklist_version = 0;
                receive.request.receiver_blacklist_root = [0; 32];
                vesta_prover(budget_shape(folded(SigmaRelation::RECEIVE)))
            }
        };
        let proof = unheld_prover
            .prove(&unheld, fresh_randomness())
            .expect("no list held");
        assert_eq!(
            unheld_prover.verifier().verify(&proof.public, &proof.bytes),
            Ok(())
        );
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
    for case in [SigmaRelation::SEND, SEND_BLACKLIST] {
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

/// Pins compact Send's source support to an independently retained public archive.
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
    assert_eq!(descriptor.degree, 6);
    assert_eq!(descriptor.blinding_factors, 5);
    assert_eq!(descriptor.permutation_chunk_len, 4);
    assert_eq!(descriptor.quotient_pieces, 5);
    assert_eq!(descriptor.num_advice_columns, 5);
    assert_eq!(descriptor.num_fixed_columns, 24);
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
        6, 7, 8, 9, 10, 11, 12, 13, 14, 0, 1, 2, 3, 4, 5, 15, 16, 17, 18, 19, 20, 21, 22, 23,
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
            (6, 4, 1),
            (6, 5, 1),
            (6, 6, 1),
            (6, 7, 1),
            (2, 8, 1),
            (2, 8, 2),
            (2, 8, 3),
            (2, 8, 4),
            (2, 8, 5)
        ]
    );
    assert_eq!(protocol.shape().usable_rows, 4090);
    assert_eq!(protocol.shape().permutation_sets, 2);
    assert_eq!(protocol.plan().rotations(), &[0, 1, -1, -6]);
    assert_eq!(protocol.plan().sets().len(), 5);
    assert_eq!(
        format!("{:x}", Sha256::digest(binding.encoded())),
        "e320f8c818ac562bc909db4158bce72b8f7b237ae0ef5d5396580b492bb1af75"
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
        "726eec3eae129cb012871bb0abba0eae768f1f5c585d1963ba9441d46542fdff"
    );
    assert_eq!(
        source.tables.permutation().mapping_digest(),
        [
            58, 11, 95, 52, 222, 174, 85, 166, 7, 214, 168, 130, 107, 100, 63, 35, 43, 18, 204,
            244, 175, 157, 149, 120, 218, 47, 50, 24, 227, 189, 225, 63
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
            133, 195, 148, 39, 153, 72, 16, 127, 156, 62, 109, 158, 70, 155, 33, 25, 156, 159, 172,
            5, 192, 29, 87, 26, 254, 188, 13, 203, 188, 74, 83, 134
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
