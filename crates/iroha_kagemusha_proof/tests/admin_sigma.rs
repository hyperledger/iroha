//! Real Bootstrap state-effect sigma: hostile rehashed states and native proof.

#[path = "common/bootstrap.rs"]
mod bootstrap;
mod common;

use ff::Field;
use iroha_kagemusha_proof::{
    a_relation::bootstrap::BootstrapPolicy,
    admin_sigma::{BOOTSTRAP_K, BootstrapCircuit},
    witness::core_index,
};
use iroha_pasta::{Fp, msm::MemoryBudget};
use iroha_plonk::{
    ProverConfig, Witness,
    check::{CheckMode, check_circuit},
    create_proof_owned_with_claim,
    frontend::{Circuit, configure, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2},
    verifier::accumulate_generator,
};

#[test]
fn bootstrap_policy_rejects_invalid_fixed_artifacts() {
    use iroha_plonk_gadgets::p256::native::{Affine, P};
    assert!(BootstrapPolicy::new([3, 4], Affine::GENERATOR).is_ok());
    assert!(BootstrapPolicy::new([0; 2], Affine::GENERATOR).is_err());
    assert!(BootstrapPolicy::new([3, 4], Affine { x: P, y: [0; 4] }).is_err());
}

#[test]
fn bootstrap_initial_state_and_rehashed_invalid_states() {
    let witness = bootstrap::witness();
    let circuit = BootstrapCircuit::new(&witness);
    let instances = circuit.instances();
    assert!(
        check_circuit(&circuit, BOOTSTRAP_K, &instances, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let known = synthesize(&circuit, BOOTSTRAP_K, Some(&instances)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), BOOTSTRAP_K, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let lanes: Vec<_> = known
        .tables
        .advice_assigned()
        .iter()
        .map(|column| column.iter().rposition(|v| *v).map_or(0, |row| row + 1))
        .collect();
    eprintln!(
        "genuine Bootstrap sigma k{BOOTSTRAP_K}: rows={lanes:?}, cells={}",
        known
            .tables
            .advice_assigned()
            .iter()
            .flatten()
            .filter(|v| **v)
            .count()
    );
    assert_eq!(lanes.len(), 5);
    let (cs, _) = configure::<Fp, BootstrapCircuit>(&circuit).unwrap();
    assert_eq!(cs.instance_lengths(), &[1]);
    for index in (core_index::BALANCE..=core_index::BLACKLIST_ISSUED_AT).chain([
        core_index::POLICY_EPOCH,
        core_index::TIME_FLOOR,
        core_index::STATE_NONCE,
    ]) {
        let mut wrong = witness;
        if index == core_index::STATE_NONCE {
            wrong.core[index] = Fp::ZERO;
        } else {
            wrong.core[index] += Fp::ONE;
        }
        bootstrap::rebind(&mut wrong);
        let bad = BootstrapCircuit::new(&wrong);
        assert!(
            !check_circuit(&bad, BOOTSTRAP_K, &bad.instances(), CheckMode::Strict)
                .is_ok_and(|r| r.is_satisfied()),
            "rehashed core {index}"
        );
    }
    for index in 1..8 {
        let mut wrong = witness;
        wrong.rest[index] += Fp::ONE;
        bootstrap::rebind(&mut wrong);
        let bad = BootstrapCircuit::new(&wrong);
        assert!(
            !check_circuit(&bad, BOOTSTRAP_K, &bad.instances(), CheckMode::Strict)
                .is_ok_and(|r| r.is_satisfied()),
            "rehashed rest {index}"
        );
    }
    let mut wrong = instances;
    wrong[0][0] += Fp::ONE;
    assert!(
        !check_circuit(&circuit, BOOTSTRAP_K, &wrong, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}

#[test]
fn native_bootstrap_sigma_proof_and_complete_opening() {
    let circuit = BootstrapCircuit::new(&bootstrap::witness());
    let instances = circuit.instances();
    let params = common::vesta_params(BOOTSTRAP_K);
    let key = keygen_pk_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(BootstrapCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, &circuit, &instances).unwrap(),
        common::recovery(188),
        ProverConfig::default(),
    )
    .unwrap();
    let opening = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        &instances,
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    opening.decide(&params, MemoryBudget::DEFAULT).unwrap();
    assert_eq!(opening.g(), proof.opening.g());
    eprintln!("genuine Bootstrap sigma: {} proof bytes", proof.proof.len());
    let mut wrong = instances;
    wrong[0][0] += Fp::ONE;
    assert!(
        accumulate_generator(
            &params,
            key.binding(),
            key.vk(),
            &wrong,
            &proof.proof,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
}

fn load_witness() -> iroha_kagemusha_proof::admin_sigma::LoadWitness {
    use iroha_kagemusha_proof::admin_sigma::{LoadWitness, StateWitness};
    let before = bootstrap::witness();
    let mut after = before;
    after.core[core_index::BALANCE] = Fp::from(100);
    after.core[core_index::NEXT_LOAD] = Fp::ONE;
    after.core[core_index::SEQUENCE] = Fp::ONE;
    after.core[core_index::STATE_NONCE] += Fp::ONE;
    // A must prove the recovery insertion; sigma binds this carried root.
    after.core[core_index::LOAD_REDEEM_ROOT] = Fp::from(99);
    bootstrap::rebind(&mut after);
    let mut statement = after.statement;
    statement[14] = before.lineage[5];
    statement[16] = Fp::from(2);
    statement[17..].fill(Fp::ZERO);
    statement[17] = Fp::from(55);
    statement[19] = Fp::from(100);
    statement[20] = Fp::from(3);
    LoadWitness {
        predecessor: StateWitness::from(&before),
        successor: StateWitness::from(&after),
        statement,
    }
}
fn rebind_load(w: &mut iroha_kagemusha_proof::admin_sigma::LoadWitness) {
    use iroha_kagemusha_proof::witness::{CORE_DOMAIN, REST_DOMAIN};
    use iroha_pasta::poseidon::hash_with_domain;
    for state in [&mut w.predecessor, &mut w.successor] {
        let mut preimage = state.core.to_vec();
        preimage.push(hash_with_domain(REST_DOMAIN, &state.rest));
        state.lineage[5] = hash_with_domain(CORE_DOMAIN, &preimage);
        state.lineage[1..3].copy_from_slice(&state.core[1..3]);
        state.lineage[6..8].copy_from_slice(&state.core[5..7]);
        state.lineage[8] = state.core[7];
        state.lineage[13] = state.core[0]
            + Fp::from(256) * state.core[30]
            + Fp::from(2).pow_vartime([72]) * state.core[21];
    }
    w.statement[3..7].copy_from_slice(&w.successor.core[1..5]);
    for (field, index) in [(7, 7), (8, 0), (9, 10), (10, 12)] {
        w.statement[field] = w.successor.core[index];
    }
    w.statement[14] = w.predecessor.lineage[5];
    w.statement[15] = w.successor.lineage[5];
}
#[test]
fn load_sigma_constrains_value_continuity_and_exact_changes() {
    use iroha_kagemusha_proof::admin_sigma::LoadCircuit;
    let witness = load_witness();
    let circuit = LoadCircuit::new(&witness);
    let instances = circuit.instances();
    assert!(
        check_circuit(&circuit, 12, &instances, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let known = synthesize(&circuit, 12, Some(&instances)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 12, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let lanes: Vec<_> = known
        .tables
        .advice_assigned()
        .iter()
        .map(|column| column.iter().rposition(|v| *v).map_or(0, |row| row + 1))
        .collect();
    eprintln!(
        "Load sigma k12 rows={lanes:?}, cells={}",
        known
            .tables
            .advice_assigned()
            .iter()
            .flatten()
            .filter(|v| **v)
            .count()
    );
    assert_eq!(lanes.len(), 5);
    for index in 0..33 {
        if [core_index::STATE_NONCE, core_index::LOAD_REDEEM_ROOT].contains(&index) {
            continue;
        }
        let mut wrong = witness;
        wrong.successor.core[index] += Fp::ONE;
        rebind_load(&mut wrong);
        let bad = LoadCircuit::new(&wrong);
        assert!(
            !check_circuit(&bad, 12, &bad.instances(), CheckMode::Strict)
                .is_ok_and(|r| r.is_satisfied()),
            "rehashed Load core{index}"
        );
    }
    for index in 0..8 {
        let mut wrong = witness;
        wrong.successor.rest[index] += Fp::ONE;
        rebind_load(&mut wrong);
        let bad = LoadCircuit::new(&wrong);
        assert!(
            !check_circuit(&bad, 12, &bad.instances(), CheckMode::Strict)
                .is_ok_and(|r| r.is_satisfied()),
            "rehashed Load rest{index}"
        );
    }
    let mut wrong = witness;
    wrong.statement[18] = Fp::ONE;
    let bad = LoadCircuit::new(&wrong);
    assert!(
        !check_circuit(&bad, 12, &bad.instances(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}
#[test]
fn native_load_sigma_proof_and_complete_opening() {
    use iroha_kagemusha_proof::admin_sigma::LoadCircuit;
    let circuit = LoadCircuit::new(&load_witness());
    let instances = circuit.instances();
    let params = common::vesta_params(12);
    let key = keygen_pk_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(LoadCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, &circuit, &instances).unwrap(),
        common::recovery(189),
        ProverConfig::default(),
    )
    .unwrap();
    let opening = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        &instances,
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    opening.decide(&params, MemoryBudget::DEFAULT).unwrap();
    eprintln!("Load sigma proof {} bytes", proof.proof.len());
    let mut wrong = instances;
    wrong[0][0] += Fp::ONE;
    assert!(
        accumulate_generator(
            &params,
            key.binding(),
            key.vk(),
            &wrong,
            &proof.proof,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
}

fn admin_read_config(original: &[u8]) -> iroha_plonk::keys::pk::artifact::ReadConfig {
    iroha_plonk::keys::pk::artifact::ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 1 << BOOTSTRAP_K,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}

fn check_imported_admin_proof(
    params: &iroha_plonk::pcs::ipa::PinnedParams<iroha_pasta::Eq>,
    key: &iroha_plonk::ProvingKey<iroha_pasta::Eq>,
    expected: &[Vec<Fp>; 1],
    proof: &iroha_kagemusha_proof::admin_sigma::native::AdminSigmaProof,
) {
    assert_eq!(&proof.instances, expected);
    let opening = accumulate_generator(
        params,
        key.binding(),
        key.vk(),
        &proof.instances,
        &proof.bytes,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    opening.decide(params, MemoryBudget::DEFAULT).unwrap();
    let mut wrong = proof.instances.clone();
    wrong[0][0] += Fp::ONE;
    assert!(
        accumulate_generator(
            params,
            key.binding(),
            key.vk(),
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
            params,
            key.binding(),
            key.vk(),
            &proof.instances,
            &corrupted,
            MemoryBudget::DEFAULT,
        )
        .is_err()
    );
}

#[test]
fn installed_admin_sigma_originals_prove_bootstrap_and_reject_rehashed_value() {
    use iroha_kagemusha_proof::admin_sigma::native::BootstrapProver;
    let witness = bootstrap::witness();
    let circuit = BootstrapCircuit::new(&witness);
    let params = common::vesta_params(BOOTSTRAP_K);
    let key = keygen_pk_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(BootstrapCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let original = key.artifact_bytes_v2().unwrap();
    let installed = BootstrapProver::from_original_artifact(
        params,
        key.binding().encoded(),
        key.vk().to_bytes(),
        &original,
        admin_read_config(&original),
    )
    .unwrap();
    assert_eq!(installed.binding(), key.binding());
    assert_eq!(installed.verifying_key().to_bytes(), key.vk().to_bytes());
    let proof = installed
        .prove(&witness, common::recovery(201), ProverConfig::default())
        .unwrap();
    check_imported_admin_proof(
        installed.params(),
        installed.proving_key(),
        &circuit.instances(),
        &proof,
    );
    let mut wrong = witness;
    wrong.core[core_index::BALANCE] = Fp::ONE;
    bootstrap::rebind(&mut wrong);
    assert!(
        installed
            .prove(&wrong, common::recovery(202), ProverConfig::default())
            .is_err()
    );
}

#[test]
fn installed_admin_sigma_originals_prove_load_and_reject_rehashed_value() {
    use iroha_kagemusha_proof::admin_sigma::{LoadCircuit, native::LoadProver};
    let witness = load_witness();
    let circuit = LoadCircuit::new(&witness);
    let params = common::vesta_params(BOOTSTRAP_K);
    let key = keygen_pk_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(LoadCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let original = key.artifact_bytes_v2().unwrap();
    let installed = LoadProver::from_original_artifact(
        params,
        key.binding().encoded(),
        key.vk().to_bytes(),
        &original,
        admin_read_config(&original),
    )
    .unwrap();
    assert_eq!(installed.binding(), key.binding());
    assert_eq!(installed.verifying_key().to_bytes(), key.vk().to_bytes());
    let proof = installed
        .prove(&witness, common::recovery(203), ProverConfig::default())
        .unwrap();
    check_imported_admin_proof(
        installed.params(),
        installed.proving_key(),
        &circuit.instances(),
        &proof,
    );
    let mut wrong = witness;
    wrong.successor.core[core_index::BALANCE] += Fp::ONE;
    rebind_load(&mut wrong);
    assert!(
        installed
            .prove(&wrong, common::recovery(204), ProverConfig::default())
            .is_err()
    );
}

#[test]
fn installed_admin_sigma_originals_reject_cross_operation_profile_and_original_mutations() {
    use iroha_kagemusha_proof::admin_sigma::{
        ConsumingWitness, LoadCircuit, RetiringCircuit, StateWitness, UnloadCircuit,
        native::{AdminSigmaError, BootstrapProver, LoadProver, RetiringProver, UnloadProver},
    };
    use iroha_plonk::{
        cs::{
            CircuitDescriptorV2, CurveV1, InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV2,
        },
        keys::pk::artifact::{Error as ArtifactError, ReadConfig},
    };
    let params = common::vesta_params(BOOTSTRAP_K);
    let before = bootstrap::witness();
    let blank = ConsumingWitness {
        predecessor: StateWitness::from(&before),
        successor: StateWitness::from(&before),
        statement: before.statement,
    };
    let mut key_config = KeygenConfigV2::pipa_r(BootstrapCircuit::instance_types().to_vec());
    // Keep the common descriptor explicit; fixed operation data must still reject swaps.
    key_config.compress_selectors = false;
    let keys = [
        keygen_pk_v2(
            &params,
            &BootstrapCircuit::new(&before).without_witnesses(),
            &key_config,
        )
        .unwrap(),
        keygen_pk_v2(
            &params,
            &LoadCircuit::new(&load_witness()).without_witnesses(),
            &key_config,
        )
        .unwrap(),
        keygen_pk_v2(
            &params,
            &UnloadCircuit::new(&blank).without_witnesses(),
            &key_config,
        )
        .unwrap(),
        keygen_pk_v2(
            &params,
            &RetiringCircuit::new(&blank).without_witnesses(),
            &key_config,
        )
        .unwrap(),
    ];
    let mount = |operation: usize,
                 key: &iroha_plonk::ProvingKey<iroha_pasta::Eq>,
                 bytes: &[u8],
                 config: ReadConfig| {
        let args = (
            params.clone(),
            key.binding().encoded(),
            key.vk().to_bytes(),
            bytes,
            config,
        );
        match operation {
            0 => BootstrapProver::from_original_artifact(args.0, args.1, args.2, args.3, args.4)
                .map(|_| ()),
            1 => LoadProver::from_original_artifact(args.0, args.1, args.2, args.3, args.4)
                .map(|_| ()),
            2 => UnloadProver::from_original_artifact(args.0, args.1, args.2, args.3, args.4)
                .map(|_| ()),
            3 => RetiringProver::from_original_artifact(args.0, args.1, args.2, args.3, args.4)
                .map(|_| ()),
            _ => unreachable!("fixed test operation"),
        }
    };
    for (source, key) in keys.iter().enumerate() {
        assert_eq!(
            key.binding(),
            keys[0].binding(),
            "same administrative descriptor"
        );
        let original = key.artifact_bytes_v2().unwrap();
        for target in 0..keys.len() {
            let result = mount(target, key, &original, admin_read_config(&original));
            if target == source {
                result.unwrap();
            } else {
                assert!(
                    matches!(
                        result,
                        Err(AdminSigmaError::Artifact(ArtifactError::Source))
                    ),
                    "source {source} substituted for target {target}"
                );
            }
        }
    }
    let key = &keys[0];
    let original = key.artifact_bytes_v2().unwrap();
    let config = admin_read_config(&original);
    let mut bounded = config;
    bounded.maximum_bytes -= 1;
    assert!(matches!(
        mount(0, key, &original, bounded),
        Err(AdminSigmaError::Artifact(ArtifactError::Length))
    ));
    bounded = config;
    bounded.maximum_rows -= 1;
    assert!(matches!(
        mount(0, key, &original, bounded),
        Err(AdminSigmaError::Artifact(ArtifactError::Length))
    ));
    assert!(mount(0, key, &original[..original.len() - 1], config).is_err());
    let mut corrupted = original.clone();
    corrupted.push(0);
    assert!(
        mount(
            0,
            key,
            &corrupted,
            ReadConfig {
                maximum_bytes: corrupted.len(),
                ..config
            }
        )
        .is_err()
    );
    for offset in [0, 8] {
        corrupted = original.clone();
        corrupted[offset] ^= 1;
        assert!(matches!(
            mount(0, key, &corrupted, config),
            Err(AdminSigmaError::Artifact(ArtifactError::Encoding))
        ));
    }
    corrupted = original.clone();
    let copy_start = 44 + key.vk().to_bytes().len();
    corrupted[copy_start] ^= 1;
    assert!(matches!(
        mount(0, key, &corrupted, config),
        Err(AdminSigmaError::Artifact(ArtifactError::Source))
    ));
    corrupted = original.clone();
    corrupted[copy_start + 32..copy_start + 64].fill(0xff);
    assert!(matches!(
        mount(0, key, &corrupted, config),
        Err(AdminSigmaError::Artifact(ArtifactError::Encoding))
    ));
    let import = |descriptor: &[u8], vk: &[u8]| {
        BootstrapProver::from_original_artifact(params.clone(), descriptor, vk, &original, config)
    };
    assert!(import(&[], key.vk().to_bytes()).is_err());
    assert!(import(&vec![0; (1 << 20) + 1], key.vk().to_bytes()).is_err());
    assert!(import(key.binding().encoded(), &[]).is_err());
    assert!(import(key.binding().encoded(), &vec![0; (1 << 18) + 1]).is_err());
    let mut descriptor = key.binding().encoded().to_vec();
    descriptor.push(0);
    assert!(import(&descriptor, key.vk().to_bytes()).is_err());
    let mut vk = key.vk().to_bytes().to_vec();
    vk[0] ^= 1;
    assert!(import(key.binding().encoded(), &vk).is_err());
    assert!(matches!(
        import(key.binding().encoded(), keys[1].vk().to_bytes()),
        Err(AdminSigmaError::UnauthorizedKey)
    ));
    assert!(matches!(
        BootstrapProver::from_original_artifact(
            common::vesta_params(11),
            key.binding().encoded(),
            key.vk().to_bytes(),
            &original,
            config,
        ),
        Err(AdminSigmaError::Parameters)
    ));
    let descriptor = CircuitDescriptorV2::decode(key.binding().encoded()).unwrap();
    for change in 0..6 {
        let mut wrong = descriptor.clone();
        match change {
            0 => wrong.instance_types[0] = InstanceType::Field,
            1 => wrong.transcript = TranscriptV2::KagemushaPoseidonRp57,
            2 => wrong.instance_mode = InstanceModeV1::Committed,
            3 => wrong.proof_suffix = ProofSuffixV1::None,
            4 => wrong.instance_lengths[0] = 2,
            5 => {
                wrong.curve = CurveV1::Pallas;
                std::mem::swap(&mut wrong.base_modulus, &mut wrong.scalar_modulus);
                wrong.params_digest =
                    iroha_plonk::cs::descriptor::pinned_params_digest(CurveV1::Pallas, BOOTSTRAP_K)
                        .unwrap();
            }
            _ => unreachable!(),
        }
        let result = import(&wrong.encode().unwrap(), key.vk().to_bytes());
        if matches!(change, 2 | 3) {
            // PIPA-R itself rejects committed instances or a missing suffix.
            assert!(matches!(result, Err(AdminSigmaError::Descriptor(_))));
        } else {
            assert!(
                matches!(result, Err(AdminSigmaError::Profile)),
                "profile mutation {change}"
            );
        }
    }
}
