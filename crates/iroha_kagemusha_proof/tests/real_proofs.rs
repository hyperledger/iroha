//! The relation checks as real PIPA-v1 proofs (KAGEMUSHA step format on
//! Vesta, at the shape within the 3.5 KB budget):
//!
//! - an honest witness is proved and verified, also through the
//!   verifying-key allowlist by its `(tag, mask)` selector; a wrong public
//!   input is rejected; a fixed recovery stream reproduces the proof bytes
//!   and a different one changes them;
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
//! verifies at its single-lane `k = 14` shape; keys and proofs do not depend
//! on the Rayon pool size. All tests here prove for real and are ignored in
//! debug builds.

mod common;

use core::fmt::Write as _;

use common::{
    CHECK_SEED, RECEIVE_BLACKLIST, RELATION_CASES, RELATION_CHECK_CASES, RELATIONS, SEND_BLACKLIST,
    SEND_EVERY, SEND_QUOTAS, budget_shape, case_label, folded, forged_witness, pinned_shape,
    recovery, relation_shapes, vesta_params, vesta_prover,
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
        let honest_proof = prover.prove(&honest, recovery(1)).expect("honest proof");
        for (case, mutation, expected) in RELATION_CASES {
            if case != relation.relation {
                continue;
            }
            let label = case_label(relation, mutation);
            let witness = sample_witness::<Fp>(CHECK_SEED, case, mutation);
            if expected {
                let proof = prover.prove(&witness, recovery(2)).expect("proof");
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
                assert_eq!(
                    prover.prove(&witness, recovery(2)).expect("proof").bytes,
                    proof.bytes,
                    "{label}: a fixed stream reproduces the proof"
                );
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
                match prover.prove(&witness, recovery(2)) {
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
                    recovery(3),
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
                    recovery(4),
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
    let proof = prover.prove(&witness, recovery(9)).expect("proof");
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
        let proof = prover.prove(&witness, recovery(5)).expect("Pallas proof");
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
            prover.prove(&mutated, recovery(5)),
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
        let proof = prover.prove(&witness, recovery(1)).expect("proof");
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
            prover.prove(&foreign, recovery(1)).map(|proof| proof.bytes),
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
        recovery(3),
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
            prover.prove(&listed, recovery(2)).map(|proof| proof.bytes),
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
            .prove(&unheld, recovery(2))
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
        let proof = prover.prove(&honest, recovery(2)).expect("honest proof");
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
                prover.prove(&witness, recovery(2)).map(|proof| proof.bytes),
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
            recovery(4),
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
        let proof = prover.prove(&forged, recovery(6)).expect("forged proof");
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

/// Keys and proofs (with a fixed recovery stream) are identical on 1, 2, 4
/// and 7 Rayon threads.
#[test]
#[ignore = "key generation and proofs on four pool sizes; run in release"]
fn keys_and_proofs_do_not_depend_on_the_pool_size() {
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
                let proof = prover.prove(&witness, recovery(7)).expect("proof");
                let verifier = prover.verifier();
                assert_eq!(verifier.verify(&proof.public, &proof.bytes), Ok(()));
                (
                    verifier.vk_bytes().to_vec(),
                    verifier.descriptor_bytes().to_vec(),
                    proof.bytes,
                )
            });
            match &seen {
                None => seen = Some((vk, descriptor, proof)),
                Some(first) => assert_eq!(
                    first,
                    &(vk, descriptor, proof),
                    "{case:?}: {threads} threads"
                ),
            }
        }
        println!(
            "M12_POOLS relation={} threads=1,2,4,7 identical=true",
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
            let imported = SigmaProver::from_original_artifact(
                shape,
                params,
                verifier.descriptor_bytes(),
                verifier.vk_bytes(),
                &original,
                ReadConfig {
                    maximum_bytes: original.len(),
                    maximum_rows: 1 << shape.k,
                    coset_cache: CosetCachePolicy::OnDemand,
                    msm_budget: MemoryBudget::DEFAULT,
                },
            )
            .expect("installed sigma original");
            assert!(!imported.proving_key().has_coset_cache());
            assert_eq!(
                imported.proving_key().artifact_bytes_v2().unwrap(),
                original
            );
            assert_eq!(imported.verifier().vk_bytes(), verifier.vk_bytes());
            assert_eq!(imported.verifier().binding(), verifier.binding());
            let witness = sample_witness::<C::ScalarExt>(CHECK_SEED, relation, Mutation::None);
            let proof = imported
                .prove(&witness, recovery(81))
                .expect("genuine imported sigma proof");
            verifier
                .verify(&proof.public, &proof.bytes)
                .expect("original installed key");
            let mut wrong = proof.public;
            wrong.statement += C::ScalarExt::ONE;
            assert!(verifier.verify(&wrong, &proof.bytes).is_err());
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
        SigmaProver::from_original_artifact(
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
    let tables_start = 44 + vk_len + 32;
    corrupted = original.clone();
    corrupted[tables_start..tables_start + 32].fill(0xff);
    assert!(matches!(
        mount(&corrupted, config),
        Err(SigmaError::Artifact(ArtifactError::Encoding))
    ));
    let other_source = budget_shape(folded(SigmaRelation::RECEIVE));
    assert!(matches!(
        SigmaProver::from_original_artifact(
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
        SigmaProver::from_original_artifact(
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
        SigmaProver::from_original_artifact(
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
        SigmaProver::from_original_artifact(
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
        SigmaProver::from_original_artifact(
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
        SigmaProver::<Ep>::from_original_artifact(
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
