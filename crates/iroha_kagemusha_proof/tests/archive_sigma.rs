//! Complete `ArchiveSent` sigma state effects and genuine imported-key proofs.

#[path = "common/bootstrap.rs"]
mod bootstrap;
mod common;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    admin_sigma::{
        ArchiveCircuit, ArchiveWitness, BOOTSTRAP_K, BootstrapCircuit, ConsumingWitness,
        LoadCircuit, LoadWitness, RetiringCircuit, StateWitness, UnloadCircuit,
        native::{
            AdminSigmaError, ArchiveProver, BootstrapProver, LoadProver, RetiringProver,
            UnloadProver,
        },
    },
    operation_relation::map_effects::PENDING_DOMAIN,
    tree::IndexedTree,
    witness::{CORE_DOMAIN, REST_DOMAIN, core_index as core},
};
use iroha_pasta::{Eq, Fp, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    ProverConfig, ProvingKey,
    check::{CheckMode, check_circuit},
    frontend::{Circuit, synthesize},
    keys::{
        CosetCachePolicy, KeygenConfigV2, keygen_pk_v2,
        pk::artifact::{Error as ArtifactError, ReadConfig},
    },
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};

fn rebind(w: &mut ArchiveWitness) {
    for state in [&mut w.predecessor, &mut w.successor] {
        let mut preimage = state.core.to_vec();
        preimage.push(hash_with_domain(REST_DOMAIN, &state.rest));
        state.lineage[5] = hash_with_domain(CORE_DOMAIN, &preimage);
        state.lineage[1..3].copy_from_slice(&state.core[core::SCHEME..=core::SCHEME + 1]);
        state.lineage[6..8].copy_from_slice(&state.core[core::WALLET..core::WALLET + 2]);
        state.lineage[8] = state.core[core::CREDENTIAL];
        state.lineage[13] = state.core[core::LIFECYCLE]
            + Fp::from(256) * state.core[core::POLICY_EPOCH]
            + Fp::from_u128(1 << 72) * state.core[core::ENABLED_CONTROLS];
    }
    w.statement[1..3].copy_from_slice(&w.successor.lineage[3..5]);
    w.statement[3..7].copy_from_slice(&w.successor.core[core::SCHEME..core::ASSET + 2]);
    for (field, index) in [
        (7, core::CREDENTIAL),
        (8, core::LIFECYCLE),
        (9, core::SEQUENCE),
        (10, core::NEXT_LOAD),
    ] {
        w.statement[field] = w.successor.core[index];
    }
    w.statement[11] = w.predecessor.core[core::ENABLED_CONTROLS];
    w.statement[14] = w.predecessor.lineage[5];
    w.statement[15] = w.successor.lineage[5];
}

fn witness(retiring: bool) -> ArchiveWitness {
    let initial = bootstrap::witness();
    let mut before = StateWitness::from(&initial);
    before.core[core::LIFECYCLE] = Fp::from(if retiring { 2 } else { 1 });
    before.core[core::BALANCE] = Fp::from(70);
    before.core[core::SEQUENCE] = Fp::from(4);
    before.core[core::NEXT_SEND] = Fp::ONE;
    before.core[core::BURNED_TOTAL] = Fp::from(2);
    before.lineage[14] = Fp::from(10);
    let descriptor = [20, 2, 3, 0, 12, 3, 77].map(Fp::from);
    let mut pending = IndexedTree::new();
    pending
        .insert(descriptor[0], hash_with_domain(PENDING_DOMAIN, &descriptor))
        .unwrap();
    before.core[core::PENDING_OUTGOING_ROOT] = pending.root();
    // The step starts from the core root, not an adjusted lineage root.
    pending.insert(Fp::from(30), Fp::from(99)).unwrap();
    before.lineage[15] = pending.root();
    let mut after = before;
    after.core[core::SEQUENCE] += Fp::ONE;
    after.core[core::STATE_NONCE] += Fp::ONE;
    after.core[core::PENDING_OUTGOING_ROOT] = IndexedTree::<Fp>::new().root();
    let mut statement = initial.statement;
    statement[12..14].fill(Fp::ZERO);
    statement[16] = Fp::from(5);
    statement[17..].fill(Fp::ZERO);
    statement[17] = descriptor[0];
    statement[18] = Fp::from(99);
    let mut result = ArchiveWitness {
        predecessor: before,
        successor: after,
        statement,
    };
    rebind(&mut result);
    result
}

fn accepts(w: &ArchiveWitness) -> bool {
    let circuit = ArchiveCircuit::new(w);
    check_circuit(
        &circuit,
        BOOTSTRAP_K,
        &circuit.instances(),
        CheckMode::Strict,
    )
    .is_ok_and(|result| result.is_satisfied())
}
fn config(original: &[u8]) -> ReadConfig {
    ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 1 << BOOTSTRAP_K,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}

#[test]
fn archive_sigma_preserves_all_unrelated_core_rest_and_lineage_values() {
    for retiring in [false, true] {
        let honest = witness(retiring);
        assert!(accepts(&honest));
        for index in 0..honest.successor.core.len() {
            if matches!(index, core::STATE_NONCE | core::PENDING_OUTGOING_ROOT) {
                continue;
            }
            let mut wrong = honest;
            wrong.successor.core[index] += Fp::ONE;
            rebind(&mut wrong);
            assert!(
                !accepts(&wrong),
                "retiring={retiring}, rehashed core {index}"
            );
        }
        for index in 0..honest.successor.rest.len() {
            let mut wrong = honest;
            wrong.successor.rest[index] += Fp::ONE;
            rebind(&mut wrong);
            assert!(
                !accepts(&wrong),
                "retiring={retiring}, rehashed rest {index}"
            );
        }
        for index in [3, 4, 9, 10, 11, 12, 14, 16, 17] {
            let mut wrong = honest;
            wrong.successor.lineage[index] += Fp::ONE;
            rebind(&mut wrong);
            assert!(!accepts(&wrong), "retiring={retiring}, lineage {index}");
        }
        let mut zero_nonce = honest;
        zero_nonce.successor.core[core::STATE_NONCE] = Fp::ZERO;
        rebind(&mut zero_nonce);
        assert!(!accepts(&zero_nonce));
        let mut overflow = honest;
        overflow.predecessor.core[core::SEQUENCE] = Fp::from_u128(u128::MAX);
        overflow.successor.core[core::SEQUENCE] = Fp::ZERO;
        rebind(&mut overflow);
        assert!(!accepts(&overflow));
    }
}

#[test]
fn archive_sigma_binds_tag5_complete_openings_and_fixed_layout() {
    let honest = witness(false);
    let circuit = ArchiveCircuit::new(&honest);
    let known = synthesize(&circuit, BOOTSTRAP_K, Some(&circuit.instances())).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), BOOTSTRAP_K, None).unwrap();
    let retiring = ArchiveCircuit::new(&witness(true));
    let other = synthesize(&retiring, BOOTSTRAP_K, Some(&retiring.instances())).unwrap();
    for alternate in [&unknown, &other] {
        assert_eq!(known.tables.fixed(), alternate.tables.fixed());
        assert_eq!(known.tables.selectors(), alternate.tables.selectors());
        assert_eq!(known.tables.permutation(), alternate.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            alternate.tables.advice_assigned()
        );
    }
    let rows: Vec<_> = known
        .tables
        .advice_assigned()
        .iter()
        .map(|column| {
            column
                .iter()
                .rposition(|value| *value)
                .map_or(0, |row| row + 1)
        })
        .collect();
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().all(|row| *row < 1 << BOOTSTRAP_K));
    eprintln!("ArchiveSent sigma k{BOOTSTRAP_K} rows={rows:?}");
    for index in (0..17).chain(19..26) {
        let mut wrong = honest;
        wrong.statement[index] += Fp::ONE;
        assert!(!accepts(&wrong), "statement {index}");
    }
    for index in [17, 18] {
        let mut wrong = honest;
        wrong.statement[index] = Fp::ZERO;
        assert!(!accepts(&wrong), "zero effect digest {index}");
    }
    for predecessor in [false, true] {
        for rest in [false, true] {
            let mut wrong = honest;
            let state = if predecessor {
                &mut wrong.predecessor
            } else {
                &mut wrong.successor
            };
            if rest {
                state.rest[1] += Fp::ONE;
            } else {
                state.core[core::STATE_NONCE] += Fp::ONE;
            }
            // Do not rehash: the original commitment must still bind every word.
            assert!(
                !accepts(&wrong),
                "opening predecessor={predecessor} rest={rest}"
            );
        }
    }
}

#[test]
fn installed_archive_sigma_proves_both_lifecycles_and_rejects_refund() {
    let circuit = ArchiveCircuit::new(&witness(false));
    let params = common::vesta_params(BOOTSTRAP_K);
    let key = keygen_pk_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(ArchiveCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let original = key.artifact_bytes_v2().unwrap();
    let installed = ArchiveProver::from_original_artifact(
        params,
        key.binding().encoded(),
        key.vk().to_bytes(),
        &original,
        config(&original),
    )
    .unwrap();
    assert_eq!(installed.binding(), key.binding());
    assert_eq!(installed.verifying_key().to_bytes(), key.vk().to_bytes());
    assert_eq!(
        installed.proving_key().artifact_bytes_v2().unwrap(),
        original
    );
    for (retiring, seed) in [(false, 210), (true, 211)] {
        let witness = witness(retiring);
        let proof = installed
            .prove(&witness, common::recovery(seed), ProverConfig::default())
            .unwrap();
        assert_eq!(proof.instances, ArchiveCircuit::new(&witness).instances());
        let opening = accumulate_generator(
            installed.params(),
            installed.binding(),
            installed.verifying_key(),
            &proof.instances,
            &proof.bytes,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        opening
            .decide(installed.params(), MemoryBudget::DEFAULT)
            .unwrap();
        let mut wrong = proof.instances.clone();
        wrong[0][0] += Fp::ONE;
        assert!(
            accumulate_generator(
                installed.params(),
                installed.binding(),
                installed.verifying_key(),
                &wrong,
                &proof.bytes,
                MemoryBudget::DEFAULT,
            )
            .is_err()
        );
        let mut corrupted = proof.bytes.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert!(
            accumulate_generator(
                installed.params(),
                installed.binding(),
                installed.verifying_key(),
                &proof.instances,
                &corrupted,
                MemoryBudget::DEFAULT,
            )
            .is_err()
        );
        eprintln!(
            "ArchiveSent imported sigma retiring={retiring}: {} proof bytes",
            proof.bytes.len()
        );
    }
    let mut refund = witness(false);
    refund.successor.core[core::BALANCE] += Fp::from(12);
    rebind(&mut refund);
    assert!(
        installed
            .prove(&refund, common::recovery(212), ProverConfig::default())
            .is_err()
    );
}

#[test]
fn installed_archive_sigma_rejects_other_operation_originals_and_bounds() {
    let params = common::vesta_params(BOOTSTRAP_K);
    let mut key_config = KeygenConfigV2::pipa_r(ArchiveCircuit::instance_types().to_vec());
    key_config.compress_selectors = false;
    let archive = keygen_pk_v2(
        &params,
        &ArchiveCircuit::new(&witness(false)).without_witnesses(),
        &key_config,
    )
    .unwrap();
    let source = bootstrap::witness();
    let state = StateWitness::from(&source);
    let load = LoadWitness {
        predecessor: state,
        successor: state,
        statement: source.statement,
    };
    let consuming = ConsumingWitness {
        predecessor: state,
        successor: state,
        statement: source.statement,
    };
    let others = [
        keygen_pk_v2(
            &params,
            &BootstrapCircuit::new(&source).without_witnesses(),
            &key_config,
        )
        .unwrap(),
        keygen_pk_v2(
            &params,
            &LoadCircuit::new(&load).without_witnesses(),
            &key_config,
        )
        .unwrap(),
        keygen_pk_v2(
            &params,
            &UnloadCircuit::new(&consuming).without_witnesses(),
            &key_config,
        )
        .unwrap(),
        keygen_pk_v2(
            &params,
            &RetiringCircuit::new(&consuming).without_witnesses(),
            &key_config,
        )
        .unwrap(),
    ];
    let mount = |key: &ProvingKey<Eq>, original: &[u8], selected: ReadConfig| {
        ArchiveProver::from_original_artifact(
            params.clone(),
            key.binding().encoded(),
            key.vk().to_bytes(),
            original,
            selected,
        )
    };
    for key in &others {
        assert_eq!(archive.binding(), key.binding());
        let original = key.artifact_bytes_v2().unwrap();
        assert!(matches!(
            mount(key, &original, config(&original)),
            Err(AdminSigmaError::Artifact(ArtifactError::Source))
        ));
    }
    let original = archive.artifact_bytes_v2().unwrap();
    let selected = config(&original);
    // Both directions must reject, even with an identical administrative descriptor.
    macro_rules! reject_archive_as {
        ($owner:ident) => {
            assert!(matches!(
                $owner::from_original_artifact(
                    params.clone(),
                    archive.binding().encoded(),
                    archive.vk().to_bytes(),
                    &original,
                    selected,
                ),
                Err(AdminSigmaError::Artifact(ArtifactError::Source))
            ));
        };
    }
    reject_archive_as!(BootstrapProver);
    reject_archive_as!(LoadProver);
    reject_archive_as!(UnloadProver);
    reject_archive_as!(RetiringProver);
    mount(&archive, &original, selected).unwrap();
    for limited in [
        ReadConfig {
            maximum_bytes: original.len() - 1,
            ..selected
        },
        ReadConfig {
            maximum_rows: (1 << BOOTSTRAP_K) - 1,
            ..selected
        },
    ] {
        assert!(matches!(
            mount(&archive, &original, limited),
            Err(AdminSigmaError::Artifact(ArtifactError::Length))
        ));
    }
    assert!(mount(&archive, &original[..original.len() - 1], selected).is_err());
    assert!(matches!(
        ArchiveProver::from_original_artifact(
            PinnedParams::derive(11).unwrap(),
            archive.binding().encoded(),
            archive.vk().to_bytes(),
            &original,
            selected,
        ),
        Err(AdminSigmaError::Parameters)
    ));
    assert!(matches!(
        ArchiveProver::from_original_artifact(
            params,
            archive.binding().encoded(),
            others[0].vk().to_bytes(),
            &original,
            selected,
        ),
        Err(AdminSigmaError::UnauthorizedKey)
    ));
}
