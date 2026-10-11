//! Fixed k12 `RefreshPolicy` sigma, genuine shared-original proofs and hostile effects.

#[path = "common/bootstrap.rs"]
mod bootstrap;
mod common;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    admin_sigma::{
        REFRESH_K, RefreshCircuit, RefreshKind, RefreshUpdateWitness, RefreshWitness, StateWitness,
    },
    operation_relation::state::rest_index as rest,
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
    verifier::accumulate_generator,
};

const KINDS: [RefreshKind; 5] = [
    RefreshKind::Credential,
    RefreshKind::SchemePolicy,
    RefreshKind::Blacklist,
    RefreshKind::QuotaShare,
    RefreshKind::TimeAnchor,
];

fn rebind(w: &mut RefreshWitness) {
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

fn witness(kind: RefreshKind) -> RefreshWitness {
    let initial = bootstrap::witness();
    let mut before = StateWitness::from(&initial);
    before.core[core::BALANCE] = Fp::from(100);
    before.core[core::TIME_FLOOR] = Fp::from(30);
    before.core[core::TIME_ANCHOR_MAX_RESPONSE] = Fp::from(5);
    before.core[core::LEASE_EXPIRY] = Fp::from(1000);
    before.rest[rest::PERMITTED] = Fp::from(5);
    let mut after = before;
    after.core[core::SEQUENCE] += Fp::ONE;
    after.core[core::STATE_NONCE] += Fp::ONE;
    let mut update = RefreshUpdateWitness {
        kind,
        digest: Fp::from(80),
        scheme: [Fp::ZERO; 2],
        asset: [Fp::ZERO; 2],
        wallet: [Fp::ZERO; 2],
        counter: Fp::ZERO,
        issued_at_ms: Fp::ZERO,
        expires_at_ms: Fp::ZERO,
        root: Fp::ZERO,
        controls: Fp::ZERO,
        fee_schedule: Fp::ZERO,
    };
    if kind != RefreshKind::Credential {
        update.scheme = [Fp::ONE, Fp::from(2)];
    }
    if kind != RefreshKind::SchemePolicy {
        update.issued_at_ms = Fp::from(40);
        after.core[core::TIME_FLOOR] = Fp::from(40);
    }
    match kind {
        RefreshKind::Credential => {
            update.expires_at_ms = Fp::from(2000);
            after.core[core::CREDENTIAL] = update.digest;
            after.core[core::LEASE_EXPIRY] = update.expires_at_ms;
        }
        RefreshKind::SchemePolicy => {
            update.asset = [Fp::from(3), Fp::from(4)];
            update.counter = Fp::from(2);
            update.controls = Fp::from(7);
            update.fee_schedule = Fp::from(90);
            after.core[core::POLICY_EPOCH] = update.counter;
            after.core[core::ENABLED_CONTROLS] = Fp::from(5);
            after.rest[rest::SCHEME_POLICY] = update.digest;
            after.rest[rest::FEE_SCHEDULE] = update.fee_schedule;
        }
        RefreshKind::Blacklist => {
            update.counter = Fp::from(2);
            update.root = Fp::from(89);
            after.core[core::BLACKLIST_VERSION] = update.counter;
            after.core[core::BLACKLIST_ROOT] = update.root;
            after.core[core::BLACKLIST_ISSUED_AT] = update.issued_at_ms;
            after.rest[rest::BLACKLIST] = update.digest;
            // A must prove the exact insertion; sigma owns only the selected gate.
            after.rest[rest::BLACKLIST_HISTORY] = Fp::from(99);
        }
        RefreshKind::QuotaShare => {
            update.asset = [Fp::from(3), Fp::from(4)];
            update.wallet = [Fp::from(5), Fp::from(6)];
            update.counter = Fp::from(2);
            update.expires_at_ms = Fp::from(100);
            update.root = Fp::from(89);
            after.rest[rest::QUOTA_SHARE] = update.digest;
            after.rest[rest::QUOTA_SHARE_ID] = update.counter;
            after.core[core::QUOTA_WINDOWS_ROOT] = update.root;
            after.core[core::QUOTA_SHARE_EXPIRY] = update.expires_at_ms;
            // A must prove the complete array rebuild, preserving prior usage.
            after.core[core::QUOTA_USAGE_ROOT] = Fp::from(99);
        }
        RefreshKind::TimeAnchor => {
            update.wallet = [Fp::from(5), Fp::from(6)];
            after.rest[rest::TIME_ANCHOR] = update.digest;
        }
    }
    let mut statement = initial.statement;
    statement[12..14].fill(Fp::ZERO);
    statement[16] = Fp::from(7);
    statement[17..].fill(Fp::ZERO);
    statement[17] = Fp::from(kind as u64);
    statement[18] = update.digest;
    statement[19] = after.core[core::TIME_FLOOR];
    let mut w = RefreshWitness {
        predecessor: before,
        successor: after,
        statement,
        update,
    };
    rebind(&mut w);
    w
}

fn accepts(w: &RefreshWitness) -> bool {
    let circuit = RefreshCircuit::new(w);
    check_circuit(&circuit, REFRESH_K, &circuit.instances(), CheckMode::Strict)
        .is_ok_and(|result| result.is_satisfied())
}

#[test]
fn refresh_sigma_k12_and_five_kind_layout_are_fixed() {
    let source = RefreshCircuit::new(&witness(KINDS[0]));
    let known = synthesize(&source, REFRESH_K, Some(&source.instances())).unwrap();
    for kind in KINDS {
        let w = witness(kind);
        assert!(accepts(&w), "{kind:?}");
        let circuit = RefreshCircuit::new(&w);
        for candidate in [
            synthesize(&circuit, REFRESH_K, Some(&circuit.instances())).unwrap(),
            synthesize(&circuit.without_witnesses(), REFRESH_K, None).unwrap(),
        ] {
            assert_eq!(known.tables.fixed(), candidate.tables.fixed(), "{kind:?}");
            assert_eq!(
                known.tables.selectors(),
                candidate.tables.selectors(),
                "{kind:?}"
            );
            assert_eq!(
                known.tables.permutation(),
                candidate.tables.permutation(),
                "{kind:?}"
            );
            assert_eq!(
                known.tables.advice_assigned(),
                candidate.tables.advice_assigned(),
                "{kind:?}"
            );
        }
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
    let fixed_rows: Vec<_> = known
        .tables
        .fixed_assigned()
        .iter()
        .map(|column| {
            column
                .iter()
                .rposition(|value| *value)
                .map_or(0, |row| row + 1)
        })
        .collect();
    let selector_rows: Vec<_> = known
        .tables
        .selectors()
        .iter()
        .map(|column| {
            column
                .iter()
                .rposition(|value| *value)
                .map_or(0, |row| row + 1)
        })
        .collect();
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().all(|row| *row < 1 << REFRESH_K));
    eprintln!(
        "RefreshPolicy sigma fixed domain k{REFRESH_K}: advice_rows={rows:?}; fixed_assigned_rows={fixed_rows:?}; selector_rows={selector_rows:?}; blinding_factors={}; production_k={REFRESH_K}",
        known.cs.blinding_factors()
    );
}

#[test]
fn refresh_sigma_preserves_every_unselected_field_and_lineage_value() {
    for kind in KINDS {
        let honest = witness(kind);
        assert!(accepts(&honest));
        for index in 0..honest.successor.core.len() {
            if index == core::STATE_NONCE
                || (kind == RefreshKind::QuotaShare && index == core::QUOTA_USAGE_ROOT)
            {
                continue;
            }
            let mut wrong = honest;
            wrong.successor.core[index] += Fp::ONE;
            rebind(&mut wrong);
            assert!(!accepts(&wrong), "{kind:?}, rehashed core {index}");
        }
        for index in 0..honest.successor.rest.len() {
            if kind == RefreshKind::Blacklist && index == rest::BLACKLIST_HISTORY {
                continue;
            }
            let mut wrong = honest;
            wrong.successor.rest[index] += Fp::ONE;
            rebind(&mut wrong);
            assert!(!accepts(&wrong), "{kind:?}, rehashed rest {index}");
        }
        for index in [3, 4, 9, 10, 11, 12, 14, 15, 16, 17] {
            let mut wrong = honest;
            wrong.successor.lineage[index] += Fp::ONE;
            rebind(&mut wrong);
            assert!(!accepts(&wrong), "{kind:?}, lineage {index}");
        }
        let mut nonce = honest;
        nonce.successor.core[core::STATE_NONCE] = Fp::ZERO;
        rebind(&mut nonce);
        assert!(!accepts(&nonce));
        let mut overflow = honest;
        overflow.predecessor.core[core::SEQUENCE] = Fp::from_u128(u128::MAX);
        overflow.successor.core[core::SEQUENCE] = Fp::ZERO;
        rebind(&mut overflow);
        assert!(!accepts(&overflow));
    }
}

#[test]
fn refresh_sigma_binds_actual_kind_statement_and_complete_openings() {
    for kind in KINDS {
        let honest = witness(kind);
        for index in 0..26 {
            let mut wrong = honest;
            wrong.statement[index] += Fp::ONE;
            assert!(!accepts(&wrong), "{kind:?}, statement {index}");
        }
        for bad_kind in [0, 6, 7, 8] {
            let mut wrong = honest;
            wrong.statement[17] = Fp::from(bad_kind);
            assert!(!accepts(&wrong), "{kind:?}, unknown kind {bad_kind}");
        }
        for other in KINDS {
            if other == kind {
                continue;
            }
            let mut wrong = honest;
            wrong.update.kind = other;
            assert!(!accepts(&wrong), "typed kind {kind:?} -> {other:?}");
        }
        let mut zero = honest;
        zero.update.digest = Fp::ZERO;
        zero.statement[18] = Fp::ZERO;
        assert!(!accepts(&zero));
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
                assert!(
                    !accepts(&wrong),
                    "opening {kind:?}, predecessor={predecessor}, rest={rest}"
                );
            }
        }
        let circuit = RefreshCircuit::new(&honest);
        let mut public = circuit.instances();
        public[0][0] += Fp::ONE;
        assert!(
            !check_circuit(&circuit, REFRESH_K, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
}

fn mutate_projection(update: &mut RefreshUpdateWitness, index: usize) {
    match index {
        0 => update.digest += Fp::ONE,
        1..=2 => update.scheme[index - 1] += Fp::ONE,
        3..=4 => update.asset[index - 3] += Fp::ONE,
        5..=6 => update.wallet[index - 5] += Fp::ONE,
        7 => update.counter += Fp::ONE,
        8 => update.issued_at_ms += Fp::ONE,
        9 => update.expires_at_ms += Fp::ONE,
        10 => update.root += Fp::ONE,
        11 => update.controls += Fp::ONE,
        12 => update.fee_schedule += Fp::ONE,
        _ => unreachable!(),
    }
}

#[test]
fn refresh_sigma_rejects_bad_projections_counters_masks_and_time_rules() {
    for kind in KINDS {
        let honest = witness(kind);
        for index in 0..13 {
            let mut wrong = honest;
            mutate_projection(&mut wrong.update, index);
            assert!(!accepts(&wrong), "{kind:?}, projected word {index}");
        }
        if kind != RefreshKind::SchemePolicy {
            let mut overflow = honest;
            overflow.update.issued_at_ms = Fp::from_u128(1 << 64);
            assert!(!accepts(&overflow));
            // Older authenticated objects preserve the floor, never move it back.
            let mut older = honest;
            older.update.issued_at_ms = Fp::from(20);
            older.successor.core[core::TIME_FLOOR] = Fp::from(30);
            older.statement[19] = Fp::from(30);
            if kind == RefreshKind::Blacklist {
                older.successor.core[core::BLACKLIST_ISSUED_AT] = Fp::from(20);
            }
            rebind(&mut older);
            assert!(accepts(&older), "older signed time {kind:?}");
        }
    }
    for kind in [
        RefreshKind::SchemePolicy,
        RefreshKind::Blacklist,
        RefreshKind::QuotaShare,
    ] {
        let mut stale = witness(kind);
        stale.update.counter = Fp::ZERO;
        assert!(!accepts(&stale), "stale {kind:?}");
        stale.update.counter = Fp::from_u128(1 << 64);
        assert!(!accepts(&stale), "counter range {kind:?}");
    }
    let mut repeated = witness(RefreshKind::TimeAnchor);
    repeated.predecessor.rest[rest::TIME_ANCHOR] = repeated.update.digest;
    rebind(&mut repeated);
    assert!(!accepts(&repeated));
    let mut short = witness(RefreshKind::QuotaShare);
    short.update.expires_at_ms = short.update.issued_at_ms;
    short.successor.core[core::QUOTA_SHARE_EXPIRY] = short.update.expires_at_ms;
    rebind(&mut short);
    assert!(!accepts(&short));
    let mut escalated = witness(RefreshKind::SchemePolicy);
    escalated.successor.core[core::ENABLED_CONTROLS] = Fp::from(7);
    rebind(&mut escalated);
    assert!(!accepts(&escalated));
    let mut reserved = witness(RefreshKind::SchemePolicy);
    reserved.update.controls = Fp::from(8);
    assert!(!accepts(&reserved));
}

fn read_config(original: &[u8]) -> ReadConfig {
    ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 1 << REFRESH_K,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}

#[test]
fn installed_refresh_sigma_one_original_proves_all_five_kinds_and_refuses_refunds() {
    use iroha_kagemusha_proof::admin_sigma::native::RefreshProver;
    let params = common::vesta_params(REFRESH_K);
    // Generate the test original once from one kind, then destroy the generation
    // owner and use only the imported owner for every kind. Production has no keygen.
    let key = keygen_pk_v2(
        &params,
        &RefreshCircuit::new(&witness(RefreshKind::Credential)),
        &KeygenConfigV2::pipa_r(RefreshCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let original = key.artifact_bytes_v2().unwrap();
    let installed = RefreshProver::from_original_artifact(
        params,
        key.binding().encoded(),
        key.vk().to_bytes(),
        &original,
        read_config(&original),
    )
    .unwrap();
    assert_eq!(installed.binding(), key.binding());
    assert_eq!(installed.verifying_key().to_bytes(), key.vk().to_bytes());
    assert_eq!(
        installed.proving_key().artifact_bytes_v2().unwrap(),
        original
    );
    drop(key);
    for kind in KINDS {
        let source = witness(kind);
        let proof = installed
            .prove(
                &source,
                common::recovery(220 + kind as u8),
                ProverConfig::default(),
            )
            .unwrap();
        assert_eq!(proof.instances, RefreshCircuit::new(&source).instances());
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
        let mut refund = source;
        refund.successor.core[core::BALANCE] += Fp::ONE;
        rebind(&mut refund);
        assert!(
            installed
                .prove(
                    &refund,
                    common::recovery(230 + kind as u8),
                    ProverConfig::default()
                )
                .is_err()
        );
        eprintln!(
            "RefreshPolicy imported single-key sigma {kind:?}: {} proof bytes",
            proof.bytes.len()
        );
    }
}

#[test]
fn installed_refresh_sigma_rejects_cross_operation_originals_profiles_and_bounds() {
    use iroha_kagemusha_proof::admin_sigma::{
        ArchiveCircuit, ArchiveWitness, BootstrapCircuit, ConsumingWitness, LoadCircuit,
        LoadWitness, RetiringCircuit, UnloadCircuit,
        native::{
            AdminSigmaError, ArchiveProver, BootstrapProver, LoadProver, RefreshProver,
            RetiringProver, UnloadProver,
        },
    };
    use iroha_plonk::cs::{
        CircuitDescriptorV2, CurveV1, InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV2,
    };
    let params = common::vesta_params(REFRESH_K);
    let mut config = KeygenConfigV2::pipa_r(RefreshCircuit::instance_types().to_vec());
    // Keep the descriptor identical across operations so source-table custody,
    // rather than merely differing compressed selector metadata, rejects swaps.
    config.compress_selectors = false;
    let key = keygen_pk_v2(
        &params,
        &RefreshCircuit::new(&witness(KINDS[0])).without_witnesses(),
        &config,
    )
    .unwrap();
    let initial = bootstrap::witness();
    let state = StateWitness::from(&initial);
    let load = LoadWitness {
        predecessor: state,
        successor: state,
        statement: initial.statement,
    };
    let archive = ArchiveWitness {
        predecessor: state,
        successor: state,
        statement: initial.statement,
    };
    let consuming = ConsumingWitness {
        predecessor: state,
        successor: state,
        statement: initial.statement,
    };
    let others = [
        keygen_pk_v2(
            &params,
            &BootstrapCircuit::new(&initial).without_witnesses(),
            &config,
        )
        .unwrap(),
        keygen_pk_v2(
            &params,
            &LoadCircuit::new(&load).without_witnesses(),
            &config,
        )
        .unwrap(),
        keygen_pk_v2(
            &params,
            &ArchiveCircuit::new(&archive).without_witnesses(),
            &config,
        )
        .unwrap(),
        keygen_pk_v2(
            &params,
            &UnloadCircuit::new(&consuming).without_witnesses(),
            &config,
        )
        .unwrap(),
        keygen_pk_v2(
            &params,
            &RetiringCircuit::new(&consuming).without_witnesses(),
            &config,
        )
        .unwrap(),
    ];
    let mount = |key: &ProvingKey<Eq>, original: &[u8], selected: ReadConfig| {
        RefreshProver::from_original_artifact(
            params.clone(),
            key.binding().encoded(),
            key.vk().to_bytes(),
            original,
            selected,
        )
    };
    for other in &others {
        assert_eq!(key.binding(), other.binding());
        let original = other.artifact_bytes_v2().unwrap();
        assert!(matches!(
            mount(other, &original, read_config(&original)),
            Err(AdminSigmaError::Artifact(ArtifactError::Source))
        ));
    }
    let original = key.artifact_bytes_v2().unwrap();
    let selected = read_config(&original);
    mount(&key, &original, selected).unwrap();
    macro_rules! reject_as {
        ($owner:ident) => {
            assert!(matches!(
                $owner::from_original_artifact(
                    params.clone(),
                    key.binding().encoded(),
                    key.vk().to_bytes(),
                    &original,
                    selected
                ),
                Err(AdminSigmaError::Artifact(ArtifactError::Source))
            ));
        };
    }
    reject_as!(BootstrapProver);
    reject_as!(LoadProver);
    reject_as!(ArchiveProver);
    reject_as!(UnloadProver);
    reject_as!(RetiringProver);
    for limited in [
        ReadConfig {
            maximum_bytes: original.len() - 1,
            ..selected
        },
        ReadConfig {
            maximum_rows: (1 << REFRESH_K) - 1,
            ..selected
        },
    ] {
        assert!(matches!(
            mount(&key, &original, limited),
            Err(AdminSigmaError::Artifact(ArtifactError::Length))
        ));
    }
    assert!(mount(&key, &original[..original.len() - 1], selected).is_err());
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(
        mount(
            &key,
            &trailing,
            ReadConfig {
                maximum_bytes: trailing.len(),
                ..selected
            }
        )
        .is_err()
    );
    let mut changed = original.clone();
    changed[0] ^= 1;
    assert!(matches!(
        mount(&key, &changed, selected),
        Err(AdminSigmaError::Artifact(ArtifactError::Encoding))
    ));
    let copy_start = 44 + key.vk().to_bytes().len();
    changed = original.clone();
    changed[copy_start] ^= 1;
    assert!(matches!(
        mount(&key, &changed, selected),
        Err(AdminSigmaError::Artifact(ArtifactError::Source))
    ));
    let import = |descriptor: &[u8], vk: &[u8]| {
        RefreshProver::from_original_artifact(params.clone(), descriptor, vk, &original, selected)
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
        import(key.binding().encoded(), others[0].vk().to_bytes()),
        Err(AdminSigmaError::UnauthorizedKey)
    ));
    assert!(matches!(
        RefreshProver::from_original_artifact(
            common::vesta_params(REFRESH_K - 1),
            key.binding().encoded(),
            key.vk().to_bytes(),
            &original,
            selected
        ),
        Err(AdminSigmaError::Parameters)
    ));
    let descriptor = CircuitDescriptorV2::decode(key.binding().encoded()).unwrap();
    for change in 0..7 {
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
                    iroha_plonk::cs::descriptor::pinned_params_digest(CurveV1::Pallas, REFRESH_K)
                        .unwrap();
            }
            6 => {
                wrong.k = 14;
                wrong.params_digest =
                    iroha_plonk::cs::descriptor::pinned_params_digest(CurveV1::Vesta, 14).unwrap();
            }
            _ => unreachable!(),
        }
        let result = import(&wrong.encode().unwrap(), key.vk().to_bytes());
        if matches!(change, 2 | 3) {
            assert!(matches!(result, Err(AdminSigmaError::Descriptor(_))));
        } else {
            assert!(
                matches!(result, Err(AdminSigmaError::Profile)),
                "profile mutation {change}"
            );
        }
    }
}

#[test]
#[ignore = "five genuine k16 Q-sigma proofs over the shared tag7 leaf; run optimized"]
fn genuine_refresh_q_sigma_keeps_one_class_key_and_every_opening() {
    use iroha_kagemusha_proof::{
        a_relation::schedule::sigma_selector,
        q_sigma::{QSigmaPlan, SigmaClass, SigmaSlotWitness, native::QSigmaProver},
    };
    use iroha_pasta::{Ep, Fq};
    use iroha_plonk::{Witness, create_proof_owned_with_claim, pcs::ipa::PinnedParams};
    use iroha_plonk_recursion::{FoldConfig, verifier::VerifierPlan};

    let leaf_params = common::vesta_params(REFRESH_K);
    let outer_vesta = common::vesta_params(16);
    let outer_pallas = PinnedParams::<Ep>::derive(16).unwrap();
    let first = RefreshCircuit::new(&witness(RefreshKind::Credential));
    let leaf_key = keygen_pk_v2(
        &leaf_params,
        &first,
        &KeygenConfigV2::pipa_r(RefreshCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let plan = QSigmaPlan::new(
        SigmaClass::new(
            VerifierPlan::new(leaf_key.binding().clone(), leaf_params.clone()).unwrap(),
            vec![(
                sigma_selector(7, 0).unwrap(),
                leaf_key.vk().kagemusha_digest(leaf_key.binding()).unwrap(),
            )],
        )
        .unwrap(),
        None,
        &outer_vesta,
    )
    .unwrap();
    let mut prover: Option<QSigmaProver> = None;
    for kind in KINDS {
        let circuit = RefreshCircuit::new(&witness(kind));
        let public = circuit.instances();
        let sigma = create_proof_owned_with_claim(
            &leaf_params,
            &leaf_key,
            Witness::from_circuit(&leaf_key, &circuit, &public).unwrap(),
            common::recovery(kind as u8 + 50),
            ProverConfig::default(),
        )
        .unwrap();
        let prepared = plan
            .prepare(
                SigmaSlotWitness {
                    key: leaf_key.vk().clone(),
                    statement: public[0][0],
                    length: u32::try_from(sigma.proof.len()).unwrap(),
                    proof: sigma.proof.clone(),
                },
                None,
                &outer_vesta,
                Fq::from(71 + kind as u64),
                &FoldConfig::default(),
            )
            .unwrap();
        prepared
            .part()
            .decide(&outer_vesta, MemoryBudget::DEFAULT)
            .unwrap();
        if prover.is_none() {
            prover = Some(
                QSigmaProver::keygen_serialized_foreign(&prepared, outer_pallas.clone(), 2)
                    .unwrap(),
            );
        }
        let q = prover.as_ref().unwrap();
        let proof = q
            .prove(
                &prepared,
                common::recovery(kind as u8 + 60),
                ProverConfig::default(),
            )
            .unwrap();
        let opening = accumulate_generator(
            &outer_pallas,
            q.binding(),
            q.verifying_key(),
            &proof.instances,
            &proof.bytes,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        opening
            .decide(&outer_pallas, MemoryBudget::DEFAULT)
            .unwrap();
        eprintln!(
            "REFRESH_SHARED_Q kind={kind:?} sigma={} Q={} full_opening=true shared_keys=true",
            sigma.proof.len(),
            proof.bytes.len()
        );
        let mut wrong = proof.instances;
        wrong[0][0] += Fq::ONE;
        assert!(
            accumulate_generator(
                &outer_pallas,
                q.binding(),
                q.verifying_key(),
                &wrong,
                &proof.bytes,
                MemoryBudget::DEFAULT
            )
            .is_err()
        );
    }
}
